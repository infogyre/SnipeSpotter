// pattern: Functional Core

//! Immutable public-status snapshots and side-effect-free response projection.

use spotter_core::ipc::{IpcResponse, MonitorStatus};
use spotter_core::state::AssetSummary;

/// The committed data and transient state exposed by the public status commands.
///
/// This type deliberately contains no settings ciphertext, journal records, or candidate payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicStatusSnapshot {
    pub(crate) state: String,
    pub(crate) last_sync: Option<String>,
    pub(crate) snipeit_url: String,
    pub(crate) matched_asset: Option<AssetSummary>,
    pub(crate) monitors: Vec<MonitorStatus>,
    pub(crate) configured: bool,
    pub(crate) config_generation: u64,
}

/// Scheduler-owned projection paired with the configuration generation it observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleSnapshot {
    pub(crate) config_generation: u64,
    pub(crate) next_sync: Option<String>,
}

impl PublicStatusSnapshot {
    /// Build a public snapshot from committed state and nonsecret configuration fields.
    #[cfg_attr(all(not(windows), not(feature = "test-support")), expect(dead_code))]
    #[must_use]
    pub(crate) fn from_parts(
        state: impl Into<String>,
        snipeit_url: impl Into<String>,
        configured: bool,
        config_generation: u64,
        persisted: &spotter_core::state::ServiceState,
    ) -> Self {
        let monitors = persisted
            .known_monitors
            .iter()
            .map(|monitor| MonitorStatus {
                serial: monitor.serial.clone(),
                asset_id: monitor.snipeit_asset_id,
                checked_out: monitor.checked_out,
                absent_since: monitor.absent_since.map(|value| value.to_rfc3339()),
            })
            .collect();
        Self {
            state: state.into(),
            last_sync: persisted.last_sync_time.clone(),
            snipeit_url: snipeit_url.into(),
            matched_asset: persisted.matched_asset.clone(),
            monitors,
            configured,
            config_generation,
        }
    }
}

/// Project a committed status and scheduler snapshot into the existing wire response.
#[must_use]
pub(crate) fn project_status(
    status: &PublicStatusSnapshot,
    schedule: &ScheduleSnapshot,
    full: bool,
) -> IpcResponse {
    let next_sync = if status.configured && status.config_generation == schedule.config_generation {
        schedule.next_sync.clone()
    } else {
        None
    };
    if full {
        IpcResponse::StatusFull {
            state: status.state.clone(),
            last_sync: status.last_sync.clone(),
            next_sync,
            snipeit_url: status.snipeit_url.clone(),
            matched_asset: status.matched_asset.clone(),
            monitors: status.monitors.clone(),
        }
    } else {
        IpcResponse::Status {
            state: status.state.clone(),
            last_sync: status.last_sync.clone(),
            next_sync,
            snipeit_url: status.snipeit_url.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshot_schedule_generation_consistency_suppresses_stale_next_sync() {
        let status = super::PublicStatusSnapshot {
            state: String::from("Idle"),
            last_sync: Some(String::from("old")),
            snipeit_url: String::from("https://example.test"),
            matched_asset: None,
            monitors: Vec::new(),
            configured: true,
            config_generation: 2,
        };
        let schedule = super::ScheduleSnapshot {
            config_generation: 1,
            next_sync: Some(String::from("stale")),
        };
        let response = super::project_status(&status, &schedule, false);
        assert!(matches!(
            response,
            spotter_core::ipc::IpcResponse::Status {
                next_sync: None,
                ..
            }
        ));
    }

    #[test]
    fn unconfigured_status_suppresses_schedule_even_when_generations_match() {
        let status = super::PublicStatusSnapshot {
            state: String::from("Unconfigured"),
            last_sync: None,
            snipeit_url: String::new(),
            matched_asset: None,
            monitors: Vec::new(),
            configured: false,
            config_generation: 3,
        };
        let schedule = super::ScheduleSnapshot {
            config_generation: 3,
            next_sync: Some(String::from("must-not-leak")),
        };
        let response = super::project_status(&status, &schedule, true);
        assert!(matches!(
            response,
            spotter_core::ipc::IpcResponse::StatusFull {
                next_sync: None,
                ..
            }
        ));
    }
}
