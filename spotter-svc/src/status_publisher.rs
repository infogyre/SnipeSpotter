//! Service startup wiring for the status snapshot and automatic scheduler.
//!
//! Connects the FSM status/schedule watch channels to real publication
//! points: settings activation bumps the configuration generation and arms
//! the scheduler; sync completion retains its generation. The Windows-only
//! service loop consumes these on startup; Linux builds compile the pieces
//! through this module for verification.
// pattern: Imperative Shell

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::fsm::FsmHandle;
use crate::scheduler::{ScheduleInput, run_scheduler};
use crate::status::PublicStatusSnapshot;

/// Shared publication side owned by the service owner loop.
///
/// The publisher is the single writer of the status snapshot and the
/// scheduler-input watches. Status snapshots are published by the owner at
/// real activations; the scheduler publishes schedule projections through
/// the FSM handle.
#[derive(Clone)]
pub struct StatusPublisher {
    status_sender: watch::Sender<PublicStatusSnapshot>,
    schedule_sender: watch::Sender<ScheduleInput>,
    schedule_receiver: watch::Receiver<ScheduleInput>,
    current_generation: Arc<std::sync::atomic::AtomicU64>,
}

impl StatusPublisher {
    /// Construct the publisher, attach its watches to the handle, and spawn
    /// the automatic-sync scheduler task. Arming happens when the owner
    /// publishes the startup activation.
    pub(crate) fn new(handle: &FsmHandle) -> Self {
        let initial = PublicStatusSnapshot {
            state: String::from("Unconfigured"),
            last_sync: None,
            snipeit_url: String::new(),
            matched_asset: None,
            monitors: Vec::new(),
            configured: false,
            config_generation: 0,
        };
        let status_sender = watch::channel(initial).0;
        let (schedule_sender_for_input, schedule_receiver_initial) =
            watch::channel(ScheduleInput {
                configured: false,
                interval: Duration::ZERO,
                generation: 0,
            });
        let publisher = Self {
            status_sender,
            schedule_sender: schedule_sender_for_input.clone(),
            schedule_receiver: schedule_receiver_initial,
            current_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        publisher.attach_watches(handle);
        // The scheduler owns the automatic deadline exclusively from startup.
        spawn_scheduler(handle.clone(), publisher.schedule_receiver());
        publisher
    }

    /// Watch side carrying the scheduler input for the spawned scheduler task.
    #[cfg(any(windows, feature = "test-support"))]
    pub(crate) fn schedule_receiver(&self) -> watch::Receiver<ScheduleInput> {
        self.schedule_receiver.clone()
    }

    /// Registers the publisher's watch senders on the FSM handle so status
    /// reads take the snapshot path and the scheduler publishes projections.
    fn attach_watches(&self, handle: &FsmHandle) {
        handle.attach_status_publication(self.status_sender.clone());
        handle.attach_schedule_input(self.schedule_sender.clone());
    }

    /// Publish committed state as the latest snapshot at a real activation.
    ///
    /// No-op saves do not advance the generation: the schedule projection
    /// keeps its existing generation so an armed deadline is not stale.
    pub(crate) fn publish(
        &self,
        state: &str,
        snipeit_url: &str,
        configured: bool,
        persisted: &spotter_core::state::ServiceState,
    ) {
        let generation = self
            .current_generation
            .load(std::sync::atomic::Ordering::Acquire);
        self.status_sender
            .send_replace(PublicStatusSnapshot::from_parts(
                state,
                snipeit_url,
                configured,
                generation,
                persisted,
            ));
    }

    /// Publishes the startup committed-state snapshot from settings loaded at
    /// boot, before any command runs, and arms the scheduler input.
    #[cfg_attr(not(windows), expect(dead_code))]
    pub(crate) fn publish_startup_activation(
        &self,
        configured: bool,
        snipeit_url: &str,
        interval: Duration,
        persisted: &spotter_core::state::ServiceState,
    ) {
        // The startup activation is the first generation advance; a schedule
        // projection armed by the scheduler then matches this generation.
        self.activate_configuration(configured, interval);
        let state = if configured { "Idle" } else { "Unconfigured" };
        self.publish(state, snipeit_url, configured, persisted);
    }

    /// Advance the configuration generation and republish the scheduler input
    /// after settings persist and activate.
    #[cfg_attr(not(windows), expect(dead_code))]
    pub(crate) fn activate_configuration(&self, configured: bool, interval: Duration) -> u64 {
        let generation = self
            .current_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;
        self.schedule_sender.send_replace(ScheduleInput {
            configured,
            interval,
            generation,
        });
        generation
    }
}

/// Spawn the automatic-sync scheduler task for a running service.
pub(crate) fn spawn_scheduler(handle: FsmHandle, schedule_input: watch::Receiver<ScheduleInput>) {
    tokio::spawn(run_scheduler(handle, schedule_input));
}
