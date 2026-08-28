// pattern: Imperative Shell

//! Service orchestration shell for `SnipeSpotter`.

pub mod atomic_file;
pub mod config_io;
pub mod discovery;
pub mod fsm;
pub mod gather;
pub mod ipc_server;
pub mod logging;
pub mod operation_journal;
#[cfg(windows)]
pub mod owner_ports;
pub mod ports;
#[cfg(windows)]
pub mod service;

#[cfg(all(windows, feature = "test-support"))]
/// Test-only construction of the production command owner.
#[doc(hidden)]
pub mod test_support {
    use std::path::PathBuf;

    use anyhow::Result;
    use spotter_core::{Settings, state::ServiceState};
    use tokio::sync::Mutex;

    pub use crate::owner_ports::{
        Clock, HardwareDiscovery, RemoteFactory, RemotePort, SecretProtector, SettingsStore,
        StateStore,
    };

    /// Complete external dependency bundle used by [`spawn_owner`].
    pub struct OwnerPorts {
        pub secret_protector: Box<dyn SecretProtector>,
        pub settings_store: Box<dyn SettingsStore>,
        pub state_store: Box<dyn StateStore>,
        pub remote: Box<dyn RemotePort>,
        pub remote_factory: Box<dyn RemoteFactory>,
        pub discovery: Box<dyn HardwareDiscovery>,
        pub clock: Box<dyn Clock>,
    }

    /// Construct the real owner and route commands through the production FSM.
    ///
    /// The test constructor accepts all filesystem locations explicitly so integration tests never
    /// touch the fixed `ProgramData` root or the installed SCM identity.
    ///
    /// # Errors
    /// Returns an error when the FSM channel capacity is zero.
    pub fn spawn_owner(
        capacity: usize,
        journal_path: impl Into<PathBuf>,
        settings: Settings,
        persisted_state: ServiceState,
        ports: OwnerPorts,
    ) -> Result<crate::fsm::FsmHandle> {
        spawn_owner_inner(
            capacity,
            journal_path.into(),
            settings,
            persisted_state,
            ports,
        )
    }

    /// Recover pending owner work before exposing the owner through the production FSM.
    ///
    /// This is the same startup ordering used by the Windows service, with test-injected ports
    /// replacing platform and network adapters.
    ///
    /// # Errors
    /// Returns an error when recovery or the FSM channel setup fails.
    pub async fn spawn_owner_with_recovery(
        capacity: usize,
        journal_path: impl Into<PathBuf>,
        settings: Settings,
        mut persisted_state: ServiceState,
        mut ports: OwnerPorts,
    ) -> Result<crate::fsm::FsmHandle> {
        let journal_path = journal_path.into();
        crate::service::recover_owner_state(
            &journal_path,
            ports.state_store.as_ref(),
            &mut *ports.remote,
            &mut persisted_state,
        )
        .await?;
        spawn_owner_inner(capacity, journal_path, settings, persisted_state, ports)
    }

    fn spawn_owner_inner(
        capacity: usize,
        journal_path: PathBuf,
        settings: Settings,
        persisted_state: ServiceState,
        ports: OwnerPorts,
    ) -> Result<crate::fsm::FsmHandle> {
        let (polling_sender, _polling_receiver) =
            tokio::sync::watch::channel(settings.polling.interval_hours);
        let owner = std::sync::Arc::new(Mutex::new(crate::service::CommandOwner::from_test_ports(
            journal_path,
            settings,
            persisted_state,
            polling_sender,
            ports,
        )));
        crate::fsm::spawn(capacity, move |command| {
            let owner = std::sync::Arc::clone(&owner);
            async move { owner.lock().await.handle(command).await }
        })
    }

    /// Enqueue a production owner command while retaining control of its response consumer.
    ///
    /// This test-support-only wrapper exercises the same FSM sender and owner handler as
    /// [`crate::fsm::FsmHandle::request`], but lets integration tests drop the receiver after the
    /// command has been accepted.
    ///
    /// # Errors
    /// Returns an error when the service loop has stopped.
    pub async fn enqueue_owner_request(
        fsm: &crate::fsm::FsmHandle,
        command: spotter_core::ipc::ServiceCommand,
    ) -> Result<tokio::sync::oneshot::Receiver<spotter_core::ipc::IpcResponse>> {
        fsm.enqueue(command).await
    }
}
pub mod snipeit_client;
pub mod state_io;
pub mod sync_engine;
#[cfg(windows)]
pub mod windows_acl;

use spotter_core::{
    config::{Settings, config_status},
    ipc::{IpcResponse, ServiceCommand},
};
#[cfg(any(windows, test))]
use spotter_core::{ipc::MonitorStatus, state::ServiceState as PersistedServiceState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsmState {
    Bootstrap,
    LoadConfig,
    Unconfigured,
    Decrypt,
    ValidateConfig,
    Idle,
    Syncing,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncFailure {
    Transient,
    Authentication,
    Permission,
}

/// Advance the service lifecycle from gathered conditions.
#[must_use]
pub fn transition(
    state: FsmState,
    configured: bool,
    result: Option<Result<(), SyncFailure>>,
) -> FsmState {
    match state {
        FsmState::Bootstrap => FsmState::LoadConfig,
        FsmState::LoadConfig if configured => FsmState::Decrypt,
        FsmState::Decrypt => FsmState::ValidateConfig,
        FsmState::ValidateConfig if configured => FsmState::Idle,
        FsmState::LoadConfig | FsmState::Unconfigured | FsmState::ValidateConfig => {
            FsmState::Unconfigured
        }
        FsmState::Idle => FsmState::Syncing,
        FsmState::Syncing => match result {
            Some(Ok(())) => FsmState::Idle,
            Some(Err(SyncFailure::Authentication | SyncFailure::Permission)) => {
                FsmState::Unconfigured
            }
            Some(Err(SyncFailure::Transient)) | None => FsmState::Error,
        },
        FsmState::Error => FsmState::Idle,
    }
}

pub struct ServiceController {
    pub state: FsmState,
    pub settings: Settings,
    sync_pending: bool,
}

/// Project persisted owner data into the public status response without performing I/O.
#[cfg(any(windows, test))]
#[must_use]
pub(crate) fn service_status_projection(
    state: FsmState,
    settings: &Settings,
    persisted_state: &PersistedServiceState,
    full: bool,
) -> IpcResponse {
    let state = format!("{state:?}");
    if !full {
        return IpcResponse::Status {
            state,
            last_sync: persisted_state.last_sync_time.clone(),
            next_sync: None,
            snipeit_url: settings.snipeit.url.clone(),
        };
    }
    let monitors = persisted_state
        .known_monitors
        .iter()
        .map(|monitor| MonitorStatus {
            serial: monitor.serial.clone(),
            asset_id: monitor.snipeit_asset_id,
            checked_out: monitor.checked_out,
            absent_since: monitor.absent_since.map(|value| value.to_rfc3339()),
        })
        .collect();
    IpcResponse::StatusFull {
        state,
        last_sync: persisted_state.last_sync_time.clone(),
        next_sync: None,
        snipeit_url: settings.snipeit.url.clone(),
        matched_asset: persisted_state.matched_asset.clone(),
        monitors,
    }
}

impl ServiceController {
    #[must_use]
    pub fn new(settings: Settings) -> Self {
        Self {
            state: FsmState::Bootstrap,
            settings,
            sync_pending: false,
        }
    }

    /// Process one IPC command under the single-owner ordering contract.
    #[must_use]
    pub fn handle(&mut self, command: &ServiceCommand) -> IpcResponse {
        match command {
            ServiceCommand::GetConfig => IpcResponse::Config {
                settings: spotter_core::ipc::redact_settings(&self.settings),
                missing: config_status(&self.settings)
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            ServiceCommand::GetStatus | ServiceCommand::GetStatusFull => IpcResponse::Status {
                state: format!("{:?}", self.state),
                last_sync: None,
                next_sync: None,
                snipeit_url: self.settings.snipeit.url.clone(),
            },
            ServiceCommand::TriggerSync => {
                if self.state == FsmState::Syncing || self.sync_pending {
                    IpcResponse::Ok {
                        message: String::from("sync already queued"),
                    }
                } else {
                    self.sync_pending = true;
                    IpcResponse::Ok {
                        message: String::from("sync queued"),
                    }
                }
            }
            ServiceCommand::SetConfig { .. } | ServiceCommand::SetToken { .. } => IpcResponse::Ok {
                message: String::from("configuration update accepted"),
            },
            ServiceCommand::CheckinAll | ServiceCommand::CheckinSerial { .. } => {
                IpcResponse::CheckinResult {
                    checked_in: Vec::new(),
                }
            }
        }
    }

    #[must_use]
    pub fn take_sync_request(&mut self) -> bool {
        std::mem::take(&mut self.sync_pending)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum JournalRecord {
    Prepared { operation_id: String },
    Confirmed { operation_id: String },
}

/// Return operation IDs prepared but not confirmed, preserving deterministic order.
#[must_use]
pub fn pending_operations(records: &[JournalRecord]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut pending = BTreeSet::new();
    for record in records {
        match record {
            JournalRecord::Prepared { operation_id } => {
                pending.insert(operation_id.clone());
            }
            JournalRecord::Confirmed { operation_id } => {
                pending.remove(operation_id);
            }
        }
    }
    pending.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_and_auth_failure() {
        assert_eq!(
            transition(FsmState::Bootstrap, false, None),
            FsmState::LoadConfig
        );
        assert_eq!(
            transition(FsmState::LoadConfig, false, None),
            FsmState::Unconfigured
        );
        assert_eq!(
            transition(
                FsmState::Syncing,
                true,
                Some(Err(SyncFailure::Authentication))
            ),
            FsmState::Unconfigured
        );
    }
    #[test]
    fn duplicate_sync_coalesces() {
        let mut controller = ServiceController::new(Settings::default());
        assert!(matches!(
            controller.handle(&ServiceCommand::TriggerSync),
            IpcResponse::Ok { .. }
        ));
        assert!(
            matches!(controller.handle(&ServiceCommand::TriggerSync), IpcResponse::Ok { message } if message.contains("already"))
        );
        assert!(controller.take_sync_request());
        assert!(!controller.take_sync_request());
    }
    #[test]
    fn service_status_projection_preserves_persisted_full_status() {
        use chrono::{DateTime, TimeZone as _, Utc};
        use spotter_core::{monitors::MonitorSyncEntry, state::AssetSummary};

        let seen = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .unwrap_or(DateTime::UNIX_EPOCH);
        let mut settings = Settings::default();
        settings.snipeit.url = String::from("https://example.test");
        let persisted = PersistedServiceState {
            last_sync_time: Some(String::from("2026-01-01T00:00:00Z")),
            matched_asset: Some(AssetSummary {
                id: 7,
                name: String::from("computer"),
                serial: Some(String::from("SYS")),
                asset_tag: None,
            }),
            known_monitors: vec![MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(8),
                last_seen: seen,
                absent_since: None,
                checked_out: true,
            }],
            ..PersistedServiceState::default()
        };
        let response = service_status_projection(FsmState::Idle, &settings, &persisted, true);
        assert!(matches!(response, IpcResponse::StatusFull { .. }));
        if let IpcResponse::StatusFull {
            state,
            matched_asset,
            monitors,
            ..
        } = response
        {
            assert_eq!(state, "Idle");
            assert_eq!(matched_asset.map(|asset| asset.id), Some(7));
            assert_eq!(monitors.len(), 1);
            assert_eq!(monitors[0].asset_id, Some(8));
            assert!(monitors[0].checked_out);
        }
    }

    #[test]
    fn journal_recovery_is_deterministic() {
        let records = vec![
            JournalRecord::Prepared {
                operation_id: String::from("b"),
            },
            JournalRecord::Prepared {
                operation_id: String::from("a"),
            },
            JournalRecord::Confirmed {
                operation_id: String::from("b"),
            },
        ];
        assert_eq!(pending_operations(&records), vec![String::from("a")]);
    }
}
