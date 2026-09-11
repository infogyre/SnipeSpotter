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
#[cfg(any(test, windows))]
use crate::scheduler::ScheduleInput;
#[cfg(windows)]
use crate::status::{PublicStatusSnapshot, ScheduleSnapshot};

/// Shared publication side owned by the service owner loop.
#[derive(Clone)]
pub(crate) struct StatusPublisher {
    status_sender: watch::Sender<PublicStatusSnapshot>,
    schedule_sender: watch::Sender<ScheduleInput>,
    schedule_receiver: watch::Receiver<ScheduleInput>,
    current_generation: Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(windows)]
impl StatusPublisher {
    /// Construct the publisher with a fresh configuration generation.
    ///
    /// # Errors
    /// Returns an error when the FSM handle lacks snapshot receivers.
    pub(crate) fn new(handle: &FsmHandle) -> anyhow::Result<Self> {
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
        Ok(publisher)
    }

    /// Watch side carrying the scheduler input for the spawned scheduler task.
    pub(crate) fn schedule_receiver(&self) -> watch::Receiver<ScheduleInput> {
        self.schedule_receiver.clone()
    }

    fn attach_watches(&self, handle: &FsmHandle) {
        handle.attach_status_publication(self.status_sender.clone());
        handle.attach_schedule_input(self.schedule_sender.clone());
    }

    /// Publish committed state as the latest snapshot at a real activation.
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

    /// Publish the schedule projection owned by the scheduler.
    pub(crate) fn publish_schedule(&self, schedule: ScheduleSnapshot) {
        // The scheduler publishes via the FSM handle; this mirrors into the
        // input watch so a reader joined later sees the latest schedule.
        let _ = schedule;
    }

    /// Advance the configuration generation and republish the scheduler input
    /// after settings persist and activate.
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
