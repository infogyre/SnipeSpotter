// pattern: Imperative Shell

//! Windows Service Control Manager lifecycle and runtime orchestration.

use std::{ffi::OsString, fs, path::Path, sync::mpsc, time::Duration};

use crate::owner_ports::{
    Clock, HardwareDiscovery, RemoteFactory, RemotePort, SecretProtector, SettingsStore, StateStore,
};
use anyhow::{Context as _, Result};
use spotter_core::{
    ServiceRuntimeOptions,
    config::config_status,
    ipc::{
        IpcResponse, ServiceCommand, apply_settings_update, redact_settings, validate_config_field,
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

fn runtime_options(arguments: &[OsString]) -> Result<ServiceRuntimeOptions> {
    let arguments = arguments
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("service launch argument is not valid UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    let arguments = arguments
        .first()
        .filter(|argument| !argument.starts_with("--"))
        .map_or_else(|| arguments.as_slice(), |_| &arguments[1..]);
    ServiceRuntimeOptions::from_arguments(arguments)
        .map_err(|error| anyhow::anyhow!("invalid service runtime arguments: {error}"))
}

fn runtime_options_for_service_process(
    process_arguments: &[OsString],
    callback_arguments: &[OsString],
) -> Result<ServiceRuntimeOptions> {
    let runtime = runtime_options(process_arguments)?;
    if let Some(callback_name) = callback_arguments
        .first()
        .and_then(|argument| argument.to_str())
        && !callback_name.starts_with("--")
        && callback_name != runtime.service_name
    {
        anyhow::bail!(
            "service callback name {callback_name} does not match registered service {}",
            runtime.service_name
        )
    }
    Ok(runtime)
}

#[derive(Debug)]
struct SavedCandidateError(anyhow::Error);

impl std::fmt::Display for SavedCandidateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "state candidate saved but journal commit failed: {}",
            self.0
        )
    }
}

impl std::error::Error for SavedCandidateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.root_cause())
    }
}

define_windows_service!(ffi_service_main, service_main);

pub(crate) struct CommandOwner {
    journal_path: std::path::PathBuf,
    polling_sender: tokio::sync::watch::Sender<u64>,
    persisted_state: PersistedServiceState,
    controller: crate::ServiceController,
    secret_protector: Box<dyn SecretProtector>,
    settings_store: Box<dyn SettingsStore>,
    state_store: Box<dyn StateStore>,
    remote: Box<dyn RemotePort>,
    remote_factory: Box<dyn RemoteFactory>,
    discovery: Box<dyn HardwareDiscovery>,
    clock: Box<dyn Clock>,
}

impl CommandOwner {
    #[cfg(all(windows, feature = "test-support"))]
    pub(crate) fn from_test_ports(
        journal_path: std::path::PathBuf,
        settings: spotter_core::Settings,
        persisted_state: PersistedServiceState,
        polling_sender: tokio::sync::watch::Sender<u64>,
        ports: crate::test_support::OwnerPorts,
    ) -> Self {
        let mut controller = crate::ServiceController::new(settings);
        controller.state = if config_status(&controller.settings).is_empty() {
            crate::FsmState::Idle
        } else {
            crate::FsmState::Unconfigured
        };
        Self {
            journal_path,
            polling_sender,
            persisted_state,
            controller,
            secret_protector: ports.secret_protector,
            settings_store: ports.settings_store,
            state_store: ports.state_store,
            remote: ports.remote,
            remote_factory: ports.remote_factory,
            discovery: ports.discovery,
            clock: ports.clock,
        }
    }

    pub(crate) async fn handle(&mut self, command: ServiceCommand) -> IpcResponse {
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
        let now = self.clock.now();
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
            Err(error) if error.downcast_ref::<SavedCandidateError>().is_some() => {
                self.controller.state = crate::FsmState::Error;
                Err(error)
            }
            Err(error) => {
                let mut candidate_state = self.persisted_state.clone();
                candidate_state.last_sync_time = Some(now.to_rfc3339());
                candidate_state.last_sync_result = Some(spotter_core::state::SyncResult::Failed {
                    error: error.to_string(),
                });
                self.state_store.save(&mut candidate_state)?;
                self.persisted_state = candidate_state;
                self.controller.state = state_after_sync_error(&error);
                Err(error)
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "forced check-in preflight and orchestration"
    )]
    async fn force_checkin(&mut self, requested_serial: Option<&str>) -> Result<IpcResponse> {
        if !config_status(&self.controller.settings).is_empty() {
            anyhow::bail!("service is not configured")
        }
        if requested_serial.is_some_and(|serial| serial.trim().is_empty()) {
            anyhow::bail!("monitor serial must not be empty")
        }
        if let Some(serial) = requested_serial {
            let entry = self
                .persisted_state
                .known_monitors
                .iter()
                .find(|entry| entry.serial == serial)
                .ok_or_else(|| anyhow::anyhow!("monitor {serial} is unknown"))?;
            match spotter_core::monitors::forced_checkin_ineligibility(entry) {
                Some(spotter_core::monitors::ForcedCheckinIneligibility::Present) => {
                    anyhow::bail!("monitor {serial} is present and cannot be checked in")
                }
                Some(spotter_core::monitors::ForcedCheckinIneligibility::AlreadyCheckedIn) => {
                    anyhow::bail!("monitor {serial} is already checked in")
                }
                Some(spotter_core::monitors::ForcedCheckinIneligibility::Unmapped) => {
                    anyhow::bail!("monitor {serial} has no Snipe-IT asset mapping")
                }
                None => {}
            }
        }
        let token = self
            .secret_protector
            .decrypt(&self.controller.settings.snipeit.api_token_encrypted)?;
        let decrypted = crate::config_io::DecryptedConfig {
            url: self.controller.settings.snipeit.url.clone(),
            api_token: token,
            checkout_status_id: self.controller.settings.snipeit.checkout_status_id,
            checkin_status_id: self.controller.settings.snipeit.checkin_status_id,
        };
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
        let serials: Vec<String> = checked_in
            .iter()
            .map(|entry| entry.serial.clone())
            .collect();
        let current_monitor_state = spotter_core::monitors::MonitorSyncState {
            entries: self.persisted_state.known_monitors.clone(),
        };
        let candidate_monitor_state =
            spotter_core::monitors::apply_forced_checkin_serials(&current_monitor_state, &serials);
        let plan = spotter_core::sync::SyncPlan {
            asset_update: None,
            monitor_checkouts: Vec::new(),
            monitor_checkins: operations,
            next_monitor_state: candidate_monitor_state,
            warnings: Vec::new(),
        };
        let mut candidate_state = self.persisted_state.clone();
        candidate_state.known_monitors = plan.next_monitor_state.entries.clone();
        let outcome = crate::sync_engine::execute_plan_with_candidate(
            plan,
            None,
            &self.journal_path,
            self.remote.as_mut(),
            &self.persisted_state,
            &candidate_state,
        )
        .await?;
        candidate_state.known_monitors = outcome.next_monitor_state.entries;
        self.state_store.save(&mut candidate_state)?;
        self.persisted_state = candidate_state.clone();
        crate::sync_engine::commit_after_state_save(
            &self.journal_path,
            &outcome.confirmed_operations,
        )
        .map_err(|error| anyhow::Error::new(SavedCandidateError(error)))?;
        Ok(IpcResponse::CheckinResult { checked_in })
    }

    async fn run_sync(&mut self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<String>> {
        let token = self
            .secret_protector
            .decrypt(&self.controller.settings.snipeit.api_token_encrypted)?;
        let decrypted = crate::config_io::DecryptedConfig {
            url: self.controller.settings.snipeit.url.clone(),
            api_token: token,
            checkout_status_id: self.controller.settings.snipeit.checkout_status_id,
            checkin_status_id: self.controller.settings.snipeit.checkin_status_id,
        };
        let gathered =
            crate::gather::gather_sync(self.discovery.as_ref(), self.remote.as_ref()).await?;
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
        let mut candidate_state = self.persisted_state.clone();
        candidate_state.last_sync_time = Some(now.to_rfc3339());
        candidate_state.last_sync_result = Some(if plan.warnings.is_empty() {
            spotter_core::state::SyncResult::Success
        } else {
            spotter_core::state::SyncResult::PartialSuccess {
                warnings: plan.warnings.clone(),
            }
        });
        candidate_state.matched_asset =
            gathered
                .system_asset
                .as_ref()
                .map(|asset| spotter_core::state::AssetSummary {
                    id: asset.id,
                    name: asset.name.clone(),
                    serial: asset.serial.clone(),
                    asset_tag: asset.asset_tag.clone(),
                });
        candidate_state.known_monitors = plan.next_monitor_state.entries.clone();
        let outcome = crate::sync_engine::execute_plan_with_candidate(
            plan,
            computer_asset_id,
            &self.journal_path,
            self.remote.as_mut(),
            &self.persisted_state,
            &candidate_state,
        )
        .await?;
        candidate_state.known_monitors = outcome.next_monitor_state.entries;
        candidate_state.matched_asset = outcome.matched_asset;
        self.state_store.save(&mut candidate_state)?;
        self.persisted_state = candidate_state.clone();
        crate::sync_engine::commit_after_state_save(
            &self.journal_path,
            &outcome.confirmed_operations,
        )
        .map_err(|error| anyhow::Error::new(SavedCandidateError(error)))?;
        Ok(outcome.warnings)
    }

    fn set_config(&mut self, field: &str, value: &str) -> Result<IpcResponse> {
        let update = validate_config_field(field, value).map_err(anyhow::Error::msg)?;
        let settings = apply_settings_update(&self.controller.settings, &update);
        let remote = if config_status(&settings).is_empty() {
            Some(self.remote_factory.build(&settings)?)
        } else {
            None
        };
        self.settings_store.save(&settings)?;
        self.polling_sender
            .send_replace(settings.polling.interval_hours);
        self.controller.settings = settings;
        if let Some(remote) = remote {
            self.remote = remote;
        }
        self.refresh_configuration_state();
        Ok(IpcResponse::Ok {
            message: format!("updated {field}"),
        })
    }

    fn set_token(&mut self, plaintext: &[u8]) -> Result<IpcResponse> {
        if plaintext.is_empty() {
            anyhow::bail!("API token must not be empty")
        }
        let encrypted = self
            .secret_protector
            .encrypt(plaintext)
            .context("failed to encrypt API token")?;
        let mut settings = self.controller.settings.clone();
        settings.snipeit.api_token_encrypted = encrypted;
        let remote = if config_status(&settings).is_empty() {
            Some(self.remote_factory.build(&settings)?)
        } else {
            None
        };
        self.settings_store.save(&settings)?;
        self.controller.settings = settings;
        if let Some(remote) = remote {
            self.remote = remote;
        }
        self.refresh_configuration_state();
        Ok(IpcResponse::Ok {
            message: String::from("API token updated"),
        })
    }

    fn status(&self, full: bool) -> IpcResponse {
        crate::service_status_projection(
            self.controller.state,
            &self.controller.settings,
            &self.persisted_state,
            full,
        )
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
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let runtime = runtime_options(&arguments)?;
    run_dispatcher_with_runtime(&runtime)
}

/// Register the service dispatcher for an explicit runtime identity.
///
/// This entry point is intended for isolated integration-service registrations. The production
/// executable calls [`run_dispatcher`], which retains the fixed product identity.
///
/// # Errors
/// Returns an error when dispatcher registration fails.
pub fn run_dispatcher_with_runtime(runtime: &ServiceRuntimeOptions) -> Result<()> {
    service_dispatcher::start(&runtime.service_name, ffi_service_main)
        .context("failed to start Windows service dispatcher")
}

fn apply_runtime_acl_contract(root: &Path) -> Result<()> {
    for path in [
        root.join("settings.toml"),
        root.join("state.toml"),
        root.join("state-hmac-key.bin"),
        root.join("operations.jsonl"),
        root.join("logs"),
    ] {
        apply_acl_if_present(&path)?;
    }

    let logs_dir = root.join("logs");
    let entries = match fs::read_dir(&logs_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect runtime log directory {}",
                    logs_dir.display()
                )
            });
        }
    };
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect runtime log directory {}",
                logs_dir.display()
            )
        })?;
        let file_type = entry.file_type().with_context(|| {
            format!(
                "failed to inspect runtime artifact {}",
                entry.path().display()
            )
        })?;
        if file_type.is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with(crate::logging::SERVICE_LOG_PREFIX)
        {
            apply_acl_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn apply_acl_if_present(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(_) => crate::windows_acl::apply_acl_contract(path)
            .with_context(|| format!("failed to apply protected data ACL to {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect runtime artifact {}", path.display())),
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "windows-service::define_windows_service! requires an owned Vec<OsString> callback"
)]
fn service_main(callback_arguments: Vec<OsString>) {
    let process_arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Err(error) = run_service(&process_arguments, &callback_arguments) {
        tracing::error!(%error, "service terminated with an error");
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "service startup with diagnostic tracing for elevated lane debugging"
)]
fn run_service(process_arguments: &[OsString], callback_arguments: &[OsString]) -> Result<()> {
    let runtime = runtime_options_for_service_process(process_arguments, callback_arguments)?;
    tracing::info!(service = %runtime.service_name, "SnipeSpotter service starting");
    let _instance = spotter_win32::mutex::try_acquire_named_mutex(&runtime.mutex_name)
        .context("another SnipeSpotter service instance is already running")?;
    tracing::info!("acquired global mutex");
    let root = runtime.data_root.clone();
    tracing::info!(root = %root.display(), "using data directory");
    crate::windows_acl::apply_acl_contract(&root).context("failed to apply protected data ACL")?;
    apply_runtime_acl_contract(&root)?;
    crate::atomic_file::recover_stale_temporary_files(&root, std::process::id(), 300).inspect_err(
        |e| tracing::warn!(%e, root = %root.display(), "stale temporary-file recovery failed"),
    )?;
    let settings_path = root.join("settings.toml");
    let settings = crate::config_io::load_settings(&settings_path).inspect_err(
        |e| tracing::error!(%e, path = %settings_path.display(), "failed to load settings"),
    )?;
    tracing::info!(url = %settings.snipeit.url, "settings loaded");
    let state_key = crate::state_io::load_or_create_key(&root.join("state-hmac-key.bin"))
        .inspect_err(|e| tracing::error!(%e, "failed to load state key"))?;
    tracing::info!("state key loaded");
    let persisted_state = crate::state_io::load_state(&root.join("state.toml"), &state_key)
        .inspect_err(|e| tracing::error!(%e, "failed to load state"))?;
    tracing::info!("persisted state loaded");
    let _log_guard = crate::logging::initialize(&root.join("logs"), &settings.logging)
        .inspect_err(|e| tracing::error!(%e, "failed to initialize logging"))?;
    apply_runtime_acl_contract(&root)?;
    tracing::info!("logging initialized");
    let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);
    let status_handle = register_controls(&runtime.service_name, shutdown_sender)
        .inspect_err(|e| tracing::error!(%e, "failed to register controls"))?;
    tracing::info!("controls registered");
    set_status(
        &status_handle,
        ServiceState::StartPending,
        1,
        Duration::from_secs(10),
    )
    .inspect_err(|e| tracing::error!(%e, "failed to set StartPending"))?;
    tracing::info!("StartPending reported");

    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create service runtime")?;
    tracing::info!("runtime created");
    let _runtime_guard = tokio_runtime.enter();
    tracing::info!("runtime entered");
    let configured = config_status(&settings).is_empty();
    let state_path = root.join("state.toml");
    let journal_path = root.join("operations.jsonl");
    let mut persisted_state = persisted_state;
    if configured {
        tokio_runtime.block_on(recover_operations(
            &settings,
            &state_path,
            &journal_path,
            &state_key,
            &mut persisted_state,
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
    let remote: Box<dyn RemotePort> = if configured {
        let decrypted = crate::config_io::decrypt_config(&controller.settings)?;
        Box::new(crate::snipeit_client::SnipeItClient::new(
            decrypted.url,
            decrypted.api_token,
        )?)
    } else {
        Box::new(crate::owner_ports::UnavailableRemote)
    };
    let owner = std::sync::Arc::new(tokio::sync::Mutex::new(CommandOwner {
        journal_path,
        polling_sender,
        persisted_state,
        controller,
        secret_protector: Box::new(crate::owner_ports::DpapiProtector),
        settings_store: Box::new(crate::owner_ports::FileSettingsStore {
            path: settings_path,
        }),
        state_store: Box::new(crate::owner_ports::FileStateStore {
            path: state_path,
            key: state_key,
        }),
        remote,
        remote_factory: Box::new(crate::owner_ports::SnipeItRemoteFactory),
        discovery: Box::new(crate::discovery::WindowsHardwareDiscovery),
        clock: Box::new(crate::owner_ports::SystemClock),
    }));
    let fsm = crate::fsm::spawn(32, move |command| {
        let owner = std::sync::Arc::clone(&owner);
        async move { owner.lock().await.handle(command).await }
    })
    .inspect_err(|e| tracing::error!(%e, "failed to spawn FSM"))?;
    tracing::info!("FSM spawned");

    set_status(&status_handle, ServiceState::Running, 0, Duration::ZERO)
        .inspect_err(|e| tracing::error!(%e, "failed to set Running"))?;
    tracing::info!("Running reported; entering main loop");
    tokio_runtime.block_on(async move {
        let timer_fsm = fsm.clone();
        let timer = tokio::spawn(run_polling_timer(timer_fsm, polling_receiver));
        let pipe_endpoint = runtime.pipe_endpoint.clone();
        let pipe = tokio::spawn(crate::ipc_server::run_named_pipe_at(fsm, pipe_endpoint));
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

pub(crate) async fn recover_owner_state(
    journal_path: &std::path::Path,
    state_store: &dyn StateStore,
    remote: &mut dyn RemotePort,
    persisted_state: &mut PersistedServiceState,
) -> Result<()> {
    let confirmed = crate::sync_engine::recover_pending(journal_path, remote).await?;
    if confirmed.is_empty() {
        return Ok(());
    }

    let records = crate::operation_journal::load(journal_path)?;
    let mut candidate_state = persisted_state.clone();
    crate::sync_engine::apply_recovered_candidate_states(
        &mut candidate_state,
        &records,
        &confirmed,
    )?;
    state_store.save(&mut candidate_state)?;
    crate::sync_engine::commit_after_state_save(journal_path, &confirmed)?;
    *persisted_state = candidate_state;
    tracing::info!(
        count = confirmed.len(),
        "recovered pending Snipe-IT operations"
    );
    Ok(())
}

async fn recover_operations(
    settings: &spotter_core::Settings,
    state_path: &std::path::Path,
    journal_path: &std::path::Path,
    state_key: &[u8],
    persisted_state: &mut PersistedServiceState,
) -> Result<()> {
    let decrypted = crate::config_io::decrypt_config(settings)?;
    let mut client = crate::snipeit_client::SnipeItClient::new(decrypted.url, decrypted.api_token)?;
    let state_store = crate::owner_ports::FileStateStore {
        path: state_path.to_path_buf(),
        key: state_key.to_vec(),
    };
    recover_owner_state(journal_path, &state_store, &mut client, persisted_state).await
}

fn register_controls(
    service_name: &str,
    sender: mpsc::SyncSender<()>,
) -> Result<ServiceStatusHandle> {
    let handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop => {
            let _ = sender.try_send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    service_control_handler::register(service_name, handler)
        .context("failed to register service control handler")
}

fn service_controls_for(state: ServiceState) -> ServiceControlAccept {
    if state == ServiceState::Running {
        ServiceControlAccept::STOP
    } else {
        ServiceControlAccept::empty()
    }
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
    let controls = service_controls_for(state);
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
    use std::sync::{Arc, Mutex};

    struct RecordingProtector {
        encrypted: Vec<u8>,
        calls: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl SecretProtector for RecordingProtector {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            self.calls
                .lock()
                .map_err(|_| anyhow::anyhow!("recording protector lock poisoned"))?
                .push(plaintext.to_vec());
            Ok(self.encrypted.clone())
        }

        fn decrypt(&self, _ciphertext: &[u8]) -> Result<secrecy::SecretString> {
            Ok(secrecy::SecretString::from(String::from("token")))
        }
    }

    struct RecordingSettingsStore {
        saved: Arc<Mutex<Vec<spotter_core::Settings>>>,
    }

    struct UnavailableFactory;

    impl RemoteFactory for UnavailableFactory {
        fn build(&self, _settings: &spotter_core::Settings) -> Result<Box<dyn RemotePort>> {
            Ok(Box::new(crate::owner_ports::UnavailableRemote))
        }
    }

    struct FailingFactory;

    impl RemoteFactory for FailingFactory {
        fn build(&self, _settings: &spotter_core::Settings) -> Result<Box<dyn RemotePort>> {
            anyhow::bail!("factory failed")
        }
    }

    impl SettingsStore for RecordingSettingsStore {
        fn save(&self, settings: &spotter_core::Settings) -> Result<()> {
            self.saved
                .lock()
                .map_err(|_| anyhow::anyhow!("recording settings store lock poisoned"))?
                .push(settings.clone());
            Ok(())
        }
    }

    #[test]
    fn service_runtime_arguments_roundtrip_and_reject_invalid_values() -> Result<()> {
        let runtime = ServiceRuntimeOptions::new(
            "SnipeSpotter-test",
            std::path::PathBuf::from(r"C:\Temp\SnipeSpotter-test"),
            r"\\.\pipe\SnipeSpotter-test",
            r"Global\SnipeSpotter-test",
        )
        .map_err(anyhow::Error::msg)?;
        let arguments = runtime
            .launch_arguments()
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        assert_eq!(runtime_options(&arguments)?, runtime);
        let mut prefixed = vec![OsString::from("SnipeSpotter-test")];
        prefixed.extend(arguments.iter().cloned());
        assert_eq!(runtime_options(&prefixed)?, runtime);
        assert!(runtime_options(&[OsString::from("--data-root")]).is_err());
        assert!(
            runtime_options_for_service_process(&arguments, &[OsString::from("wrong-service")])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn service_identity_comes_from_process_arguments_not_callback_prefix() -> Result<()> {
        let runtime = ServiceRuntimeOptions::new(
            "SnipeSpotter-test",
            std::path::PathBuf::from(r"C:\Temp\SnipeSpotter-test"),
            r"\\.\pipe\SnipeSpotter-test",
            r"Global\SnipeSpotter-test",
        )
        .map_err(anyhow::Error::msg)?;
        let process_arguments = runtime
            .launch_arguments()
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let callback_arguments = vec![OsString::from("SnipeSpotter-test")];

        assert_eq!(
            runtime_options_for_service_process(&process_arguments, &callback_arguments)?,
            runtime
        );
        Ok(())
    }

    #[test]
    fn factory_failure_preserves_active_settings() {
        let mut settings = spotter_core::Settings::default();
        settings.snipeit.url = String::from("https://old.example");
        settings.snipeit.api_token_encrypted = vec![0x42];
        settings.snipeit.checkout_status_id = 5;
        settings.snipeit.checkin_status_id = 6;
        let original = settings.clone();
        let mut owner = CommandOwner {
            journal_path: std::path::PathBuf::new(),
            polling_sender: tokio::sync::watch::channel(4).0,
            persisted_state: PersistedServiceState::default(),
            controller: crate::ServiceController::new(settings),
            secret_protector: Box::new(RecordingProtector {
                encrypted: vec![0xAA],
                calls: Arc::new(Mutex::new(Vec::new())),
            }),
            settings_store: Box::new(RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
            }),
            state_store: Box::new(crate::owner_ports::FileStateStore {
                path: std::path::PathBuf::new(),
                key: vec![0; 32],
            }),
            remote: Box::new(crate::owner_ports::UnavailableRemote),
            remote_factory: Box::new(FailingFactory),
            discovery: Box::new(crate::owner_ports::UnavailableRemote),
            clock: Box::new(crate::owner_ports::SystemClock),
        };
        assert!(
            owner
                .set_config("snipeit.url", "https://new.example")
                .is_err()
        );
        assert_eq!(owner.controller.settings, original);
    }

    #[test]
    fn set_token_uses_injected_secret_and_settings_ports() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let saved = Arc::new(Mutex::new(Vec::new()));
        let mut owner = CommandOwner {
            journal_path: std::path::PathBuf::new(),
            polling_sender: tokio::sync::watch::channel(4).0,
            persisted_state: PersistedServiceState::default(),
            controller: crate::ServiceController::new(spotter_core::Settings::default()),
            secret_protector: Box::new(RecordingProtector {
                encrypted: vec![0xAA, 0x55],
                calls: Arc::clone(&calls),
            }),
            settings_store: Box::new(RecordingSettingsStore {
                saved: Arc::clone(&saved),
            }),
            state_store: Box::new(crate::owner_ports::FileStateStore {
                path: std::path::PathBuf::new(),
                key: vec![0; 32],
            }),
            remote: Box::new(crate::owner_ports::UnavailableRemote),
            remote_factory: Box::new(UnavailableFactory),
            discovery: Box::new(crate::owner_ports::UnavailableRemote),
            clock: Box::new(crate::owner_ports::SystemClock),
        };

        let response = owner
            .set_token(b"test-token")
            .expect("injected token ports should succeed");

        assert!(matches!(response, IpcResponse::Ok { .. }));
        assert_eq!(
            calls.lock().expect("calls lock").as_slice(),
            [b"test-token"]
        );
        let saved = saved.lock().expect("saved settings lock");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].snipeit.api_token_encrypted, [0xAA, 0x55]);
        assert_eq!(
            owner.controller.settings.snipeit.api_token_encrypted,
            [0xAA, 0x55]
        );
    }

    #[test]
    fn status_projection_exposes_stop_controls_only_for_running_state() {
        for (state, accepts_stop) in [
            (ServiceState::StartPending, false),
            (ServiceState::Running, true),
            (ServiceState::Stopped, false),
        ] {
            let projected = crate::service_status_projection(
                crate::FsmState::Idle,
                &spotter_core::Settings::default(),
                &PersistedServiceState::default(),
                false,
            );
            let controls = service_controls_for(state);
            assert_eq!(controls.contains(ServiceControlAccept::STOP), accepts_stop);
            assert!(matches!(projected, IpcResponse::Status { .. }));
        }
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
            journal_path: std::path::PathBuf::new(),
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
            secret_protector: Box::new(crate::owner_ports::DpapiProtector),
            settings_store: Box::new(crate::owner_ports::FileSettingsStore {
                path: std::path::PathBuf::new(),
            }),
            state_store: Box::new(crate::owner_ports::FileStateStore {
                path: std::path::PathBuf::new(),
                key: vec![0; 32],
            }),
            remote: Box::new(crate::owner_ports::UnavailableRemote),
            remote_factory: Box::new(UnavailableFactory),
            discovery: Box::new(crate::owner_ports::UnavailableRemote),
            clock: Box::new(crate::owner_ports::SystemClock),
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
