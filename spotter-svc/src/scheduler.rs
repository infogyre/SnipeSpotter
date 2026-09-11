//! Completion-relative automatic sync scheduling with truthful projections.
//!
//! The scheduler is the sole owner of the automatic sync deadline. It reads
//! the configured flag, interval, and configuration generation from a watch
//! channel owned by settings activation, arms monotonic deadlines from actual
//! activation or sync completion, and projects `next_sync` as the next
//! automatic enqueue attempt — never a guaranteed remote execution time.
// pattern: Mixed (unavoidable)
// Reason: owns Tokio timers and the completion watch loop; projections and
// deadline arithmetic are pure and unit-tested separately.

use std::time::Duration;

use tokio::time::Instant;

use crate::fsm::FsmHandle;
use crate::status::ScheduleSnapshot;

/// Watch input published by settings activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleInput {
    pub(crate) configured: bool,
    pub(crate) interval: Duration,
    pub(crate) generation: u64,
}

// Wall-clock projection helper: converts a monotonic deadline into an RFC3339
// timestamp using the injected clock offset captured at scheduler start.
// Used by project_next_sync and the test seam; cfg expectation matches those
// call sites' availability.
#[cfg_attr(all(not(windows), not(test)), expect(dead_code))]
#[must_use]
pub(crate) fn rfc3339_from_instant(deadline: Instant) -> String {
    let remaining = deadline.duration_since(Instant::now());
    let now = chrono::Utc::now();
    (now + chrono::Duration::from_std(remaining).unwrap_or_default()).to_rfc3339()
}

/// Pure projection of the next automatic enqueue attempt.
///
/// Returns `None` when unconfigured, when the interval is zero, or when the
/// generation observed by the schedule is stale relative to the configuration
/// generation.
#[cfg_attr(all(not(windows), not(test)), expect(dead_code))]
#[must_use]
pub(crate) fn project_next_sync(
    configured: bool,
    interval: Duration,
    completed_at: Instant,
    observed_generation: u64,
    current_generation: u64,
) -> Option<(Instant, String)> {
    if !configured || observed_generation != current_generation {
        return None;
    }
    if interval.is_zero() {
        return None;
    }
    let deadline = completed_at + interval;
    Some((deadline, rfc3339_from_instant(deadline)))
}

/// Arming decision after a settings save or activation.
#[cfg_attr(all(not(windows), not(test)), expect(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArmDecision {
    /// Unrelated or no-op save: keep the existing deadline.
    Unchanged,
    /// Activation or accepted interval change: arm one full interval.
    ArmFromNow,
    /// Configured transition cleared the schedule.
    Cleared,
}

/// Pure arming rule: only actual interval changes or configured/unconfigured
/// transitions reset the automatic deadline; unrelated saves never do.
#[cfg_attr(all(not(windows), not(test)), expect(dead_code))]
#[must_use]
pub(crate) fn arm_on_settings_change(
    previously_configured: bool,
    now_configured: bool,
    previous_interval: Duration,
    new_interval: Duration,
) -> ArmDecision {
    if previously_configured && !now_configured {
        return ArmDecision::Cleared;
    }
    if !previously_configured && now_configured {
        return ArmDecision::ArmFromNow;
    }
    if now_configured && previous_interval != new_interval {
        return ArmDecision::ArmFromNow;
    }
    ArmDecision::Unchanged
}

/// The scheduler task: waits for configuration, arms monotonic deadlines from
/// activation or sync completion, and enqueues exactly one automatic sync per
/// interval with no catch-up.
///
/// Terminates cleanly when the FSM handle's channels close or configuration
/// clears; the owner channel closing produces a bounded diagnostic.
#[cfg_attr(all(not(windows), not(test)), expect(dead_code))]
pub(crate) async fn run_scheduler(
    handle: FsmHandle,
    mut schedule_input: tokio::sync::watch::Receiver<ScheduleInput>,
) {
    let completed = handle.completed_sync_generation();
    loop {
        if schedule_input
            .has_changed()
            .map_err(|_| {
                tracing::info!("automatic sync scheduler stopping: schedule watch closed");
            })
            .is_err()
        {
            return;
        }
        let ScheduleInput {
            configured,
            interval,
            generation,
        } = *schedule_input.borrow_and_update();
        if !configured {
            publish_schedule(&handle, generation, None);
            if schedule_input.changed().await.is_err() {
                return;
            }
            continue;
        }
        // Activation or accepted interval change arms ONE full interval from
        // the arming instant; the first automatic sync happens at the
        // deadline, never immediately.
        let Some((deadline, projected)) =
            project_next_sync(true, interval, Instant::now(), generation, generation)
        else {
            if schedule_input.changed().await.is_err() {
                return;
            }
            continue;
        };
        publish_schedule(&handle, generation, Some(projected));
        // Wait out the armed deadline; an input change (interval change,
        // unconfiguration) re-evaluates at the loop top instead.
        let wait_outcome = tokio::time::timeout_at(deadline, schedule_input.changed()).await;
        match wait_outcome {
            Err(_) => {}
            Ok(changed) => {
                if changed.is_err() {
                    return;
                }
                continue;
            }
        }
        // Due: clear next_sync before submission and keep it absent through
        // queueing and execution.
        publish_schedule(&handle, generation, None);
        let Ok(enqueue) = handle.enqueue_sync().await else {
            tracing::info!("automatic sync scheduler stopping: owner channel closed");
            publish_schedule(&handle, generation, None);
            return;
        };
        let response = enqueue.response.await;
        if handle
            .wait_for_sync_generation(enqueue.target_generation, completed.clone())
            .await
            .is_err()
        {
            tracing::info!("automatic sync scheduler stopping: completion channel closed");
            return;
        }
        let _ = response;
        // Arm the completion-relative deadline from the LATEST configuration:
        // re-read the input so an interval change during the sync governs.
        let (latest_configured, latest_interval, latest_generation) = {
            let latest = schedule_input.borrow_and_update();
            (latest.configured, latest.interval, latest.generation)
        };
        if !latest_configured {
            publish_schedule(&handle, latest_generation, None);
            if schedule_input.changed().await.is_err() {
                return;
            }
            continue;
        }
        let Some((next_deadline, next_projected)) = project_next_sync(
            true,
            latest_interval,
            Instant::now(),
            latest_generation,
            latest_generation,
        ) else {
            if schedule_input.changed().await.is_err() {
                return;
            }
            continue;
        };
        publish_schedule(&handle, latest_generation, Some(next_projected));
        match tokio::time::timeout_at(next_deadline, schedule_input.changed()).await {
            Err(_) => {}
            Ok(changed) => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

/// Publishes the scheduler's projection through the FSM handle.
#[cfg_attr(all(not(windows), not(test)), expect(dead_code))]
fn publish_schedule(handle: &FsmHandle, generation: u64, next_sync: Option<String>) {
    handle.publish_schedule_snapshot(ScheduleSnapshot {
        config_generation: generation,
        next_sync,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_activation_and_completion_cadence() {
        let completed_at = Instant::now();
        let interval = Duration::from_secs(7);
        let armed = project_next_sync(true, interval, completed_at, 1, 1);
        let (deadline, _) = armed.expect("configured schedule must arm");
        assert_eq!(deadline.duration_since(completed_at), interval);
        assert!(project_next_sync(false, interval, completed_at, 1, 1).is_none());
        assert!(project_next_sync(true, interval, completed_at, 2, 1).is_none());
        assert!(project_next_sync(true, Duration::ZERO, completed_at, 1, 1).is_none());
    }

    #[test]
    fn scheduler_config_reset_matrix() {
        let hour = Duration::from_secs(3600);
        assert_eq!(
            arm_on_settings_change(false, true, hour, hour),
            ArmDecision::ArmFromNow
        );
        assert_eq!(
            arm_on_settings_change(true, false, hour, hour),
            ArmDecision::Cleared
        );
        assert_eq!(
            arm_on_settings_change(true, true, hour, Duration::from_secs(60)),
            ArmDecision::ArmFromNow
        );
        assert_eq!(
            arm_on_settings_change(true, true, hour, hour),
            ArmDecision::Unchanged
        );
        assert_eq!(
            arm_on_settings_change(false, false, hour, hour),
            ArmDecision::Unchanged
        );
        assert_eq!(
            arm_on_settings_change(false, true, hour, hour),
            arm_on_settings_change(false, true, hour, Duration::ZERO)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_clock_and_closed_channel() {
        let (schedule_tx, schedule_rx) = tokio::sync::watch::channel(ScheduleInput {
            configured: false,
            interval: Duration::from_secs(1),
            generation: 1,
        });
        let handle = crate::fsm::spawn(4, |_| async {
            spotter_core::ipc::IpcResponse::Ok {
                message: String::new(),
            }
        })
        .expect("fsm spawn must succeed");
        let (owner_tx, owner_rx) = tokio::sync::oneshot::channel::<()>();
        let scheduler = tokio::spawn(async move {
            tokio::select! {
                result = run_scheduler(handle, schedule_rx) => result,
                _ = owner_rx => (),
            }
        });
        tokio::time::advance(Duration::from_millis(1)).await;
        schedule_tx
            .send(ScheduleInput {
                configured: false,
                interval: Duration::from_secs(1),
                generation: 2,
            })
            .expect("schedule channel open");
        tokio::time::advance(Duration::from_millis(1)).await;
        drop(schedule_tx);
        owner_tx.send(()).expect("owner signal open");
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::time::timeout(Duration::from_secs(5), scheduler)
            .await
            .expect("scheduler terminates cleanly via owner signal")
            .expect("join clean");
        // Owner channel closure also terminates without spinning.
        let (closing_tx, closing_rx) = tokio::sync::watch::channel(ScheduleInput {
            configured: true,
            interval: Duration::from_secs(1),
            generation: 1,
        });
        let closing_handle = crate::fsm::spawn(4, |_| async {
            spotter_core::ipc::IpcResponse::Ok {
                message: String::new(),
            }
        })
        .expect("fsm spawn must succeed");
        let closer = tokio::spawn(run_scheduler(closing_handle, closing_rx));
        tokio::time::advance(Duration::from_millis(1)).await;
        drop(closing_tx);
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::time::timeout(Duration::from_secs(5), closer)
            .await
            .expect("scheduler terminates when schedule channels close")
            .expect("join clean");
    }
    #[tokio::test(start_paused = true)]
    async fn scheduler_manual_and_coalesced_generation() {
        let handle = crate::fsm::spawn(4, |_| async {
            spotter_core::ipc::IpcResponse::Ok {
                message: String::from("synced"),
            }
        })
        .expect("fsm spawn must succeed");
        let first = handle
            .enqueue_sync()
            .await
            .expect("first sync accepted")
            .target_generation;
        let coalesced = handle.enqueue_sync().await.expect("coalesced sync");
        assert!(coalesced.coalesced);
        assert_eq!(coalesced.target_generation, first);
        let completed = handle.completed_sync_generation();
        handle
            .wait_for_sync_generation(first, completed)
            .await
            .expect("completion generation observed");
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_completion_before_wait_is_not_lost() {
        let handle = crate::fsm::spawn(4, |_| async {
            spotter_core::ipc::IpcResponse::Ok {
                message: String::from("done"),
            }
        })
        .expect("fsm spawn must succeed");
        let enqueue = handle.enqueue_sync().await.expect("sync accepted");
        let target = enqueue.target_generation;
        // Drain the response so the handler completes fully before the waiter
        // registers; the retained generation must still satisfy the wait.
        let _ = enqueue.response.await;
        let completed = handle.completed_sync_generation();
        handle
            .wait_for_sync_generation(target, completed)
            .await
            .expect("completion before registration must not be lost");
    }
}
