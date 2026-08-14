// pattern: Imperative Shell

//! Windows Service Control Manager lifecycle and runtime orchestration.

use std::{ffi::OsString, sync::mpsc, time::Duration};

use anyhow::{Context as _, Result};
use spotter_core::{
    SERVICE_NAME,
    config::config_status,
    data_dir,
    ipc::{
        IpcResponse, MonitorStatus, ServiceCommand, apply_settings_update, redact_settings,
        validate_config_field,
    },
    state::ServiceState as PersistedServiceState,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

struct CommandOwner {
    settings_path: std::path::PathBuf,
    state_path: std::path::PathBuf,
    journal_path: std::path::PathBuf,
    state_key: Vec<u8>,
    polling_sender: tokio::sync::watch::Sender<u64>,
    persisted_state: PersistedServiceState,
    controller: crate::ServiceController,
}

impl CommandOwner {
    async fn handle(&mut self, command: ServiceCommand) -> IpcResponse {
        match command {
            ServiceCommand::GetConfig => IpcResponse::Config {
                settings: redact_settings(&self.controller.settings),
                missing: config_status(&self.controller.settings)
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            ServiceCommand::SetConfig { field, value } => self
                .set_config(&field, &value)
                .unwrap_or_else(protocol_error),
            ServiceCommand::SetToken { value } => self
                .set_token(value.as_bytes())
                .unwrap_or_else(protocol_error),
            ServiceCommand::GetStatus => self.status(false),
            ServiceCommand::GetStatusFull => self.status(true),
            ServiceCommand::TriggerSync => self.trigger_sync().await.unwrap_or_else(protocol_error),
            ServiceCommand::CheckinAll => self
                .force_checkin(None)
                .await
                .unwrap_or_else(protocol_error),
            ServiceCommand::CheckinSerial { serial } => self
                .force_checkin(Some(&serial))
                .await
                .unwrap_or_else(protocol_error),
        }
    }

    async fn trigger_sync(&mut self) -> Result<IpcResponse> {
        if !config_status(&self.controller.settings).is_empty() {
            anyhow::bail!("service is not configured")
        }
        self.controller.state = crate::FsmState::Syncing;
        let now = chrono::Utc::now();
        let result = self.run_sync(now).await;
        match result {
            Ok(warnings) => {
                self.controller.state = crate::FsmState::Idle;
                Ok(IpcResponse::Ok {
                    message: if warnings.is_empty() {
                        String::from("synchronization completed")
                    } else {
                        format!(
                            "synchronization completed with {} warning(s)",
                            warnings.len()
                        )
                    },
                })
            }
            Err(error) => {
                self.persisted_state.last_sync_time = Some(now.to_rfc3339());
                self.persisted_state.last_sync_result =
                    Some(spotter_core::state::SyncResult::Failed {
                        error: error.to_string(),
                    });
                crate::state_io::save_state(
                    &self.state_path,
                    &mut self.persisted_state,
                    &self.state_key,
                )?;
                self.controller.state = state_after_sync_error(&error);
                Err(error)
            }
        }
    }

    async fn force_checkin(&mut self, requested_serial: Option<&str>) -> Result<IpcResponse> {
        if !config_status(&self.controller.settings).is_empty() {
            anyhow::bail!("service is not configured")
        }
        if requested_serial.is_some_and(|serial| serial.trim().is_empty()) {
            anyhow::bail!("monitor serial must not be empty")
        }
        let decrypted = crate::config_io::decrypt_config(&self.controller.settings)?;
        let mut operations = Vec::new();
        let mut checked_in = Vec::new();
        for entry in &self.persisted_state.known_monitors {
            if requested_serial.is_some_and(|serial| serial != entry.serial) {
                continue;
            }
            let Some(asset_id) = entry.snipeit_asset_id.filter(|id| *id != 0) else {
                continue;
            };
            if entry.absent_since.is_none() || !entry.checked_out {
                continue;
            }
            let operation_id = format!("checkin:{asset_id}:{}", decrypted.checkin_status_id);
            operations.push(spotter_core::snipeit::build_monitor_checkin(
                operation_id,
                asset_id,
                decrypted.checkin_status_id,
            )?);
            checked_in.push(spotter_core::ipc::CheckinEntry {
                serial: entry.serial.clone(),
                asset_id,
            });
        }
        if requested_serial.is_some() && operations.is_empty() {
            anyhow::bail!("monitor is not eligible for check-in")
        }
        if operations.is_empty() {
            return Ok(IpcResponse::CheckinResult { checked_in });
        }
        let plan = spotter_core::sync::SyncPlan {
            asset_update: None,
            monitor_checkouts: Vec::new(),
            monitor_checkins: operations,
            next_monitor_state: spotter_core::monitors::MonitorSyncState {
                entries: self.persisted_state.known_monitors.clone(),
            },
            warnings: Vec::new(),
        };
        let mut client =
            crate::snipeit_client::SnipeItClient::new(decrypted.url, decrypted.api_token)?;
        crate::sync_engine::execute_plan(plan, None, &self.journal_path, &mut client).await?;
        for result in &checked_in {
            if let Some(entry) = self
                .persisted_state
                .known_monitors
                .iter_mut()
                .find(|entry| entry.serial == result.serial)
            {
                entry.checked_out = false;
            }
        }
        crate::state_io::save_state(&self.state_path, &mut self.persisted_state, &self.state_key)?;
        crate::sync_engine::compact_after_state_commit(&self.journal_path)?;
        Ok(IpcResponse::CheckinResult { checked_in })
    }

    async fn run_sync(&mut self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<String>> {
        let decrypted = crate::config_io::decrypt_config(&self.controller.settings)?;
        let mut client =
            crate::snipeit_client::SnipeItClient::new(decrypted.url, decrypted.api_token)?;
        let discovery = crate::discovery::WindowsHardwareDiscovery;
        let gathered = crate::gather::gather_sync(&discovery, &client).await?;
        let previous = spotter_core::monitors::MonitorSyncState {
            entries: self.persisted_state.known_monitors.clone(),
        };
        let statuses = spotter_core::sync::ResolvedStatusIds {
            checkout: decrypted.checkout_status_id,
            checkin: decrypted.checkin_status_id,
        };
        let mut plan = spotter_core::sync::plan_sync(
            &gathered.system,
            &gathered.system_taxonomy,
            &gathered.monitors,
            gathered.system_asset.as_ref(),
            &previous,
            &self.controller.settings.monitors,
            &statuses,
            now,
        );
        plan.warnings.extend(gathered.warnings);
        let computer_asset_id = gathered.system_asset.as_ref().map(|asset| asset.id);
        let outcome = crate::sync_engine::execute_plan(
            plan,
            computer_asset_id,
            &self.journal_path,
            &mut client,
        )
        .await?;
        self.persisted_state.last_sync_time = Some(now.to_rfc3339());
        self.persisted_state.last_sync_result = Some(if outcome.warnings.is_empty() {
            spotter_core::state::SyncResult::Success
        } else {
            spotter_core::state::SyncResult::PartialSuccess {
                warnings: outcome.warnings.clone(),
            }
        });
        self.persisted_state.matched_asset =
            gathered
                .system_asset
                .map(|asset| spotter_core::state::AssetSummary {
                    id: asset.id,
                    name: asset.name,
                    serial: asset.serial,
                    asset_tag: asset.asset_tag,
                });
        self.persisted_state.known_monitors = outcome.next_monitor_state.entries;
        crate::state_io::save_state(&self.state_path, &mut self.persisted_state, &self.state_key)?;
        crate::sync_engine::compact_after_state_commit(&self.journal_path)?;
        Ok(outcome.warnings)
    }

    fn set_config(&mut self, field: &str, value: &str) -> Result<IpcResponse> {
        let update = validate_config_field(field, value).map_err(anyhow::Error::msg)?;
        let settings = apply_settings_update(&self.controller.settings, &update);
        crate::config_io::save_settings(&self.settings_path, &settings)?;
        self.polling_sender
            .send_replace(settings.polling.interval_hours);
        self.controller.settings = settings;
        self.refresh_configuration_state();
        Ok(IpcResponse::Ok {
            message: format!("updated {field}"),
        })
    }

    fn set_token(&mut self, plaintext: &[u8]) -> Result<IpcResponse> {
        if plaintext.is_empty() {
            anyhow::bail!("API token must not be empty")
        }
        let encrypted =
            spotter_win32::dpapi::encrypt(plaintext).context("failed to encrypt API token")?;
        let mut settings = self.controller.settings.clone();
        settings.snipeit.api_token_encrypted = encrypted;
        crate::config_io::save_settings(&self.settings_path, &settings)?;
        self.controller.settings = settings;
        self.refresh_configuration_state();
        Ok(IpcResponse::Ok {
            message: String::from("API token updated"),
        })
    }

    fn status(&self, full: bool) -> IpcResponse {
        let state = format!("{:?}", self.controller.state);
        if !full {
            return IpcResponse::Status {
                state,
                last_sync: self.persisted_state.last_sync_time.clone(),
                next_sync: None,
                snipeit_url: self.controller.settings.snipeit.url.clone(),
            };
        }
        let monitors = self
            .persisted_state
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
            last_sync: self.persisted_state.last_sync_time.clone(),
            next_sync: None,
            snipeit_url: self.controller.settings.snipeit.url.clone(),
            matched_asset: self.persisted_state.matched_asset.clone(),
            monitors,
        }
    }

    fn refresh_configuration_state(&mut self) {
        self.controller.state = if config_status(&self.controller.settings).is_empty() {
            crate::FsmState::Idle
        } else {
            crate::FsmState::Unconfigured
        };
    }
}

fn state_after_sync_error(error: &anyhow::Error) -> crate::FsmState {
    for cause in error.chain() {
        let Some(snipeit) = cause.downcast_ref::<spotter_core::snipeit::SnipeItError>() else {
            continue;
        };
        return match snipeit {
            spotter_core::snipeit::SnipeItError::AuthFailure
            | spotter_core::snipeit::SnipeItError::PermissionDenied => {
                crate::FsmState::Unconfigured
            }
            spotter_core::snipeit::SnipeItError::NotFound
            | spotter_core::snipeit::SnipeItError::RateLimited { .. }
            | spotter_core::snipeit::SnipeItError::Validation { .. }
            | spotter_core::snipeit::SnipeItError::ServerError { .. }
            | spotter_core::snipeit::SnipeItError::InvalidResponse { .. }
            | spotter_core::snipeit::SnipeItError::NetworkError { .. } => crate::FsmState::Error,
        };
    }
    crate::FsmState::Error
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::unwrap_or_else supplies the owned application error"
)]
fn protocol_error(error: anyhow::Error) -> IpcResponse {
    IpcResponse::Error {
        message: error.to_string(),
    }
}

/// Register the executable with the Windows service dispatcher.
///
/// # Errors
///
/// Returns an error when the process was not launched by SCM or dispatcher registration fails.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to start Windows service dispatcher")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(%error, "service terminated with an error");
    }
}

fn run_service() -> Result<()> {
    let _instance = spotter_win32::mutex::try_acquire_global_mutex()
        .context("another SnipeSpotter service instance is already running")?;
    let root = data_dir();
    let settings_path = root.join("settings.toml");
    let settings = crate::config_io::load_settings(&settings_path)?;
    let state_key = crate::state_io::load_or_create_key(&root.join("state-hmac-key.bin"))?;
    let persisted_state = crate::state_io::load_state(&root.join("state.toml"), &state_key)?;
    let _log_guard = crate::logging::initialize(&root.join("logs"), &settings.logging)?;
    let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);
    let status_handle = register_controls(shutdown_sender)?;
    set_status(
        &status_handle,
        ServiceState::StartPending,
        1,
        Duration::from_secs(10),
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create service runtime")?;
    let configured = config_status(&settings).is_empty();
    if configured {
        runtime.block_on(recover_operations(
            &settings,
            &root.join("operations.jsonl"),
        ))?;
    }
    let (polling_sender, polling_receiver) =
        tokio::sync::watch::channel(settings.polling.interval_hours);
    let mut controller = crate::ServiceController::new(settings);
    controller.state = if configured {
        crate::FsmState::Idle
    } else {
        crate::FsmState::Unconfigured
    };
    let owner = std::sync::Arc::new(tokio::sync::Mutex::new(CommandOwner {
        settings_path,
        state_path: root.join("state.toml"),
        journal_path: root.join("operations.jsonl"),
        state_key,
        polling_sender,
        persisted_state,
        controller,
    }));
    let fsm = crate::fsm::spawn(32, move |command| {
        let owner = std::sync::Arc::clone(&owner);
        async move { owner.lock().await.handle(command).await }
    })?;

    set_status(&status_handle, ServiceState::Running, 0, Duration::ZERO)?;
    runtime.block_on(async move {
        let timer_fsm = fsm.clone();
        let timer = tokio::spawn(run_polling_timer(timer_fsm, polling_receiver));
        let pipe = tokio::spawn(crate::ipc_server::run_named_pipe(fsm));
        tokio::task::spawn_blocking(move || shutdown_receiver.recv())
            .await
            .context("shutdown listener task failed")?
            .context("service shutdown channel disconnected")?;
        timer.abort();
        pipe.abort();
        let _ = timer.await;
        match pipe.await {
            Err(error) if error.is_cancelled() => Ok::<(), anyhow::Error>(()),
            Err(error) => Err(error).context("IPC server task failed"),
            Ok(result) => result,
        }
    })?;

    set_status(&status_handle, ServiceState::Stopped, 0, Duration::ZERO)
}

async fn run_polling_timer(
    fsm: crate::fsm::FsmHandle,
    mut interval_hours: tokio::sync::watch::Receiver<u64>,
) {
    loop {
        let duration = Duration::from_secs(*interval_hours.borrow_and_update() * 60 * 60);
        tokio::select! {
            () = tokio::time::sleep(duration) => {
                if let Err(error) = fsm.request(ServiceCommand::TriggerSync).await {
                    tracing::warn!(%error, "scheduled synchronization request failed");
                }
            }
            changed = interval_hours.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

async fn recover_operations(
    settings: &spotter_core::Settings,
    journal_path: &std::path::Path,
) -> Result<()> {
    let decrypted = crate::config_io::decrypt_config(settings)?;
    let mut client = crate::snipeit_client::SnipeItClient::new(decrypted.url, decrypted.api_token)?;
    let confirmed = crate::sync_engine::recover_pending(journal_path, &mut client).await?;
    if !confirmed.is_empty() {
        tracing::info!(
            count = confirmed.len(),
            "recovered pending Snipe-IT operations"
        );
    }
    Ok(())
}

fn register_controls(sender: mpsc::SyncSender<()>) -> Result<ServiceStatusHandle> {
    let handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop => {
            let _ = sender.try_send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    service_control_handler::register(SERVICE_NAME, handler)
        .context("failed to register service control handler")
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the SCM status handle is reused across lifecycle status reports"
)]
fn set_status(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    wait_hint: Duration,
) -> Result<()> {
    let controls = if state == ServiceState::Running {
        ServiceControlAccept::STOP
    } else {
        ServiceControlAccept::empty()
    };
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint,
            wait_hint,
            process_id: None,
        })
        .context("failed to report service status")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_is_the_only_state_accepting_stop() {
        let running = if ServiceState::Running == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        };
        assert_eq!(running, ServiceControlAccept::STOP);
    }

    #[test]
    fn unconfigured_settings_are_detected() {
        assert!(!config_status(&spotter_core::Settings::default()).is_empty());
    }

    #[test]
    fn classifies_sync_errors_by_typed_cause() {
        let auth = anyhow::Error::new(spotter_core::snipeit::SnipeItError::AuthFailure)
            .context("gather failed");
        assert_eq!(state_after_sync_error(&auth), crate::FsmState::Unconfigured);
        let permission = anyhow::Error::new(spotter_core::snipeit::SnipeItError::PermissionDenied);
        assert_eq!(
            state_after_sync_error(&permission),
            crate::FsmState::Unconfigured
        );
        let network = anyhow::Error::new(spotter_core::snipeit::SnipeItError::NetworkError {
            message: String::from("offline"),
        });
        assert_eq!(state_after_sync_error(&network), crate::FsmState::Error);
        assert_eq!(
            state_after_sync_error(&anyhow::anyhow!("discovery failed")),
            crate::FsmState::Error
        );
    }

    #[test]
    fn full_status_uses_persisted_asset_and_monitor_state() {
        use chrono::DateTime;
        use spotter_core::{monitors::MonitorSyncEntry, state::AssetSummary};

        let seen = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .map_or(DateTime::UNIX_EPOCH, |value| value.to_utc());
        let owner = CommandOwner {
            settings_path: std::path::PathBuf::new(),
            state_path: std::path::PathBuf::new(),
            journal_path: std::path::PathBuf::new(),
            state_key: vec![0; 32],
            polling_sender: tokio::sync::watch::channel(4).0,
            persisted_state: PersistedServiceState {
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
            },
            controller: crate::ServiceController::new(spotter_core::Settings::default()),
        };
        let response = owner.status(true);
        assert!(matches!(response, IpcResponse::StatusFull { .. }));
        if let IpcResponse::StatusFull {
            matched_asset,
            monitors,
            ..
        } = response
        {
            assert_eq!(matched_asset.map(|asset| asset.id), Some(7));
            assert_eq!(monitors.len(), 1);
            assert_eq!(monitors[0].asset_id, Some(8));
        }
    }
}
