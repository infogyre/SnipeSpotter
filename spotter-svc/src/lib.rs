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
pub mod ports;
#[cfg(windows)]
pub mod service;
pub mod snipeit_client;
pub mod state_io;
pub mod sync_engine;

use spotter_core::{
    config::{Settings, config_status},
    ipc::{IpcResponse, ServiceCommand},
};

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
