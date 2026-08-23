// pattern: Imperative Shell

//! Windows Service Control Manager lifecycle and runtime orchestration.

use std::{
    ffi::OsString,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

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

use crate::ports::{
    Clock, HardwareDiscovery, PortFuture, RemoteMutations, RemoteReads, SecretProtector,
    SettingsStore, StateStore,
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
    secret: Box<dyn SecretProtector>,
    settings_store: Box<dyn SettingsStore>,
    state_store: Box<dyn StateStore>,
    discovery: Box<dyn HardwareDiscovery>,
    remote: Box<dyn RemoteReads>,
    remote_mutations: Box<dyn RemoteMutations>,
    clock: Box<dyn Clock>,
    settings_snapshot: Option<Arc<Mutex<spotter_core::Settings>>>,
    settings_path: std::path::PathBuf,
    state_path: std::path::PathBuf,
    journal_path: std::path::PathBuf,
    state_key: Vec<u8>,
    polling_sender: tokio::sync::watch::Sender<u64>,
    persisted_state: PersistedServiceState,
    controller: crate::ServiceController,
}

impl CommandOwner {
    #[cfg(any(test, feature = "test-support"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "the test seam explicitly injects each external boundary"
    )]
    pub(crate) fn new_test(
        secret: impl SecretProtector + 'static,
        settings_store: impl SettingsStore + 'static,
        state_store: impl StateStore + 'static,
        discovery: impl HardwareDiscovery + 'static,
        remote: impl RemoteReads + 'static,
        remote_mutations: impl RemoteMutations + 'static,
        clock: impl Clock + 'static,
        settings_snapshot: Option<Arc<Mutex<spotter_core::Settings>>>,
        settings_path: std::path::PathBuf,
        state_path: std::path::PathBuf,
        journal_path: std::path::PathBuf,
        state_key: Vec<u8>,
        polling_sender: tokio::sync::watch::Sender<u64>,
        persisted_state: PersistedServiceState,
        controller: crate::ServiceController,
    ) -> Self {
        Self {
            secret: Box::new(secret),
            settings_store: Box::new(settings_store),
            state_store: Box::new(state_store),
            discovery: Box::new(discovery),
            remote: Box::new(remote),
            remote_mutations: Box::new(remote_mutations),
            clock: Box::new(clock),
            settings_snapshot,
            settings_path,
            state_path,
            journal_path,
            state_key,
            polling_sender,
            persisted_state,
            controller,
        }
    }

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
            Err(error) => {
                self.persisted_state.last_sync_time = Some(now.to_rfc3339());
                self.persisted_state.last_sync_result =
                    Some(spotter_core::state::SyncResult::Failed {
                        error: error.to_string(),
                    });
                self.state_store.save(
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
        let decrypted = decrypt_config(&*self.secret, &self.controller.settings)?;
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
        self.remote_mutations
            .execute_plan(plan, None, &self.journal_path)
            .await?;
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
        self.state_store
            .save(&self.state_path, &mut self.persisted_state, &self.state_key)?;
        self.remote_mutations
            .compact_after_state_commit(&self.journal_path)
            .await?;
        Ok(IpcResponse::CheckinResult { checked_in })
    }

    async fn run_sync(&mut self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<String>> {
        let decrypted = decrypt_config(&*self.secret, &self.controller.settings)?;
        let gathered = crate::gather::gather_sync(&*self.discovery, &*self.remote).await?;
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
        let outcome = self
            .remote_mutations
            .execute_plan(plan, computer_asset_id, &self.journal_path)
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
        self.state_store
            .save(&self.state_path, &mut self.persisted_state, &self.state_key)?;
        self.remote_mutations
            .compact_after_state_commit(&self.journal_path)
            .await?;
        Ok(outcome.warnings)
    }

    fn set_config(&mut self, field: &str, value: &str) -> Result<IpcResponse> {
        let update = validate_config_field(field, value).map_err(anyhow::Error::msg)?;
        let settings = apply_settings_update(&self.controller.settings, &update);
        self.settings_store.save(&self.settings_path, &settings)?;
        self.polling_sender
            .send_replace(settings.polling.interval_hours);
        self.update_settings_snapshot(&settings);
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
        let encrypted = self
            .secret
            .encrypt(plaintext)
            .context("failed to encrypt API token")?;
        let mut settings = self.controller.settings.clone();
        settings.snipeit.api_token_encrypted = encrypted;
        self.settings_store.save(&self.settings_path, &settings)?;
        self.update_settings_snapshot(&settings);
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

    fn update_settings_snapshot(&self, settings: &spotter_core::Settings) {
        let Some(snapshot) = &self.settings_snapshot else {
            return;
        };
        if let Ok(mut current) = snapshot.lock() {
            *current = settings.clone();
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

fn decrypt_config(
    secret: &dyn SecretProtector,
    settings: &spotter_core::Settings,
) -> Result<crate::config_io::DecryptedConfig> {
    let token = secret.decrypt(&settings.snipeit.api_token_encrypted)?;
    let token = secrecy::SecretString::from(
        String::from_utf8(token).context("decrypted API token is not UTF-8")?,
    );
    Ok(crate::config_io::DecryptedConfig {
        url: settings.snipeit.url.clone(),
        api_token: token,
        checkout_status_id: settings.snipeit.checkout_status_id,
        checkin_status_id: settings.snipeit.checkin_status_id,
    })
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

#[cfg(windows)]
struct DpapiSecretProtector;

#[cfg(windows)]
impl SecretProtector for DpapiSecretProtector {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        spotter_win32::dpapi::encrypt(plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        spotter_win32::dpapi::decrypt(ciphertext)
    }
}

struct FileSettingsStore;

impl SettingsStore for FileSettingsStore {
    fn save(&self, path: &std::path::Path, settings: &spotter_core::Settings) -> Result<()> {
        crate::config_io::save_settings(path, settings)
    }

    fn load(&self, path: &std::path::Path) -> Result<spotter_core::Settings> {
        crate::config_io::load_settings(path)
    }
}

struct FileStateStore;

impl StateStore for FileStateStore {
    fn save(
        &self,
        path: &std::path::Path,
        state: &mut PersistedServiceState,
        key: &[u8],
    ) -> Result<()> {
        crate::state_io::save_state(path, state, key)
    }

    fn load(&self, path: &std::path::Path, key: &[u8]) -> Result<PersistedServiceState> {
        crate::state_io::load_state(path, key)
    }

    fn load_or_create_key(&self, path: &std::path::Path) -> Result<Vec<u8>> {
        crate::state_io::load_or_create_key(path)
    }
}

#[cfg(windows)]
struct WindowsDiscovery;

#[cfg(windows)]
impl HardwareDiscovery for WindowsDiscovery {
    fn discover(
        &self,
    ) -> PortFuture<
        '_,
        (
            spotter_core::smbios::SystemInfo,
            Vec<spotter_core::monitors::MonitorInfo>,
        ),
    > {
        Box::pin(async move {
            crate::discovery::HardwareDiscovery::discover(
                &crate::discovery::WindowsHardwareDiscovery,
            )
        })
    }
}

#[cfg(windows)]
struct ProductionRemote {
    settings: Arc<Mutex<spotter_core::Settings>>,
}

#[cfg(windows)]
impl ProductionRemote {
    fn client(&self) -> Result<crate::snipeit_client::SnipeItClient> {
        let settings = self
            .settings
            .lock()
            .map_err(|_| anyhow::anyhow!("production settings lock poisoned"))?
            .clone();
        let decrypted = decrypt_config(&DpapiSecretProtector, &settings)?;
        crate::snipeit_client::SnipeItClient::new(decrypted.url, decrypted.api_token)
    }
}

#[cfg(windows)]
impl RemoteReads for ProductionRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        Box::pin(async move {
            let client = self.client()?;
            crate::ports::RemoteReads::find_asset_by_serial(&client, serial).await
        })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        manufacturer: &'a str,
        model: &'a str,
    ) -> PortFuture<'a, spotter_core::sync::ResolvedTaxonomy> {
        Box::pin(async move {
            let client = self.client()?;
            crate::ports::RemoteReads::resolve_taxonomy(&client, manufacturer, model).await
        })
    }
}

#[cfg(windows)]
impl RemoteMutations for ProductionRemote {
    fn execute_plan<'a>(
        &'a self,
        plan: spotter_core::sync::SyncPlan,
        computer_asset_id: Option<u64>,
        journal_path: &'a std::path::Path,
    ) -> PortFuture<'a, crate::ports::SyncOutcome> {
        Box::pin(async move {
            let mut client = self.client()?;
            crate::sync_engine::execute_plan(plan, computer_asset_id, journal_path, &mut client)
                .await
        })
    }

    fn recover_pending<'a>(
        &'a self,
        journal_path: &'a std::path::Path,
    ) -> PortFuture<'a, Vec<String>> {
        Box::pin(async move {
            let mut client = self.client()?;
            crate::sync_engine::recover_pending(journal_path, &mut client).await
        })
    }

    fn compact_after_state_commit<'a>(
        &'a self,
        journal_path: &'a std::path::Path,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move { crate::sync_engine::compact_after_state_commit(journal_path) })
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::unwrap_or_else supplies the owned application error"
)]
#[cfg(windows)]
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
    let settings_store = FileSettingsStore;
    let state_store = FileStateStore;
    let settings = settings_store.load(&settings_path)?;
    let state_key = state_store.load_or_create_key(&root.join("state-hmac-key.bin"))?;
    let persisted_state = state_store.load(&root.join("state.toml"), &state_key)?;
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
    let settings_snapshot = Arc::new(Mutex::new(settings.clone()));
    let remote = ProductionRemote {
        settings: Arc::clone(&settings_snapshot),
    };
    if configured {
        runtime.block_on(recover_operations(&remote, &root.join("operations.jsonl")))?;
    }
    let (polling_sender, polling_receiver) =
        tokio::sync::watch::channel(settings.polling.interval_hours);
    let mut controller = crate::ServiceController::new(settings);
    controller.state = if configured {
        crate::FsmState::Idle
    } else {
        crate::FsmState::Unconfigured
    };
    let owner = Arc::new(tokio::sync::Mutex::new(CommandOwner {
        secret: Box::new(DpapiSecretProtector),
        settings_store: Box::new(settings_store),
        state_store: Box::new(state_store),
        discovery: Box::new(WindowsDiscovery),
        remote: Box::new(remote),
        remote_mutations: Box::new(ProductionRemote {
            settings: Arc::clone(&settings_snapshot),
        }),
        clock: Box::new(SystemClock),
        settings_snapshot: Some(settings_snapshot),
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
    remote: &dyn RemoteMutations,
    journal_path: &std::path::Path,
) -> Result<()> {
    let confirmed = remote.recover_pending(journal_path).await?;
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

    // ---- Configurable shared fakes ----

    use std::sync::{Arc, Mutex};

    use spotter_core::{
        monitors::{MonitorInfo, MonitorSyncEntry},
        smbios::{ChassisType, SystemInfo},
        snipeit::{Asset, AssetModel, SnipeItError},
        sync::{ResolvedTaxonomy, TaxonomyResolution},
    };

    /// Identity secret protector — ciphertext equals plaintext.
    struct IdentitySecret;
    impl SecretProtector for IdentitySecret {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(plaintext.to_vec())
        }
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            Ok(ciphertext.to_vec())
        }
    }

    /// Settings store that records saves into a shared buffer.
    struct RecordingSettingsStore {
        saved: Arc<Mutex<Vec<spotter_core::Settings>>>,
        fail: Arc<Mutex<bool>>,
    }
    impl SettingsStore for RecordingSettingsStore {
        fn save(&self, _: &std::path::Path, settings: &spotter_core::Settings) -> Result<()> {
            if *self.fail.lock().unwrap() {
                anyhow::bail!("simulated settings save failure");
            }
            self.saved.lock().unwrap().push(settings.clone());
            Ok(())
        }
        fn load(&self, _: &std::path::Path) -> Result<spotter_core::Settings> {
            Ok(spotter_core::Settings::default())
        }
    }

    /// In-memory state store that always succeeds.
    struct MemoryStateStore;
    impl StateStore for MemoryStateStore {
        fn save(&self, _: &std::path::Path, _: &mut PersistedServiceState, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn load(&self, _: &std::path::Path, _: &[u8]) -> Result<PersistedServiceState> {
            Ok(PersistedServiceState::default())
        }
        fn load_or_create_key(&self, _: &std::path::Path) -> Result<Vec<u8>> {
            Ok(vec![0; 32])
        }
    }

    /// Configurable discovery that can succeed or fail.
    struct TestDiscovery {
        fail: Arc<Mutex<bool>>,
    }
    impl HardwareDiscovery for TestDiscovery {
        fn discover(&self) -> PortFuture<'_, (SystemInfo, Vec<MonitorInfo>)> {
            let fail = *self.fail.lock().unwrap();
            Box::pin(async move {
                if fail {
                    anyhow::bail!("simulated discovery failure");
                }
                Ok((
                    SystemInfo {
                        manufacturer: String::from("TestCo"),
                        model: String::from("TestModel"),
                        serial: String::from("TESTSYS"),
                        asset_tag: String::new(),
                        chassis_type: ChassisType(3),
                    },
                    vec![],
                ))
            })
        }
    }

    /// Configurable remote reads that can return success or typed errors.
    struct TestReads {
        taxonomy_error: Arc<Mutex<Option<SnipeItError>>>,
    }
    impl RemoteReads for TestReads {
        fn find_asset_by_serial<'a>(&'a self, _: &'a str) -> PortFuture<'a, Option<Asset>> {
            Box::pin(async {
                Ok(Some(Asset {
                    id: 100,
                    name: String::from("test-computer"),
                    serial: Some(String::from("TESTSYS")),
                    asset_tag: Some(String::from("TAG1")),
                    model: Some(AssetModel {
                        id: 4,
                        ..AssetModel::default()
                    }),
                    ..Asset::default()
                }))
            })
        }
        fn resolve_taxonomy<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> PortFuture<'a, ResolvedTaxonomy> {
            let err = self.taxonomy_error.lock().unwrap().take();
            Box::pin(async move {
                if let Some(error) = err {
                    return Err(anyhow::Error::new(error));
                }
                Ok(ResolvedTaxonomy {
                    manufacturer: TaxonomyResolution::Resolved { id: 1 },
                    category: TaxonomyResolution::Resolved { id: 2 },
                    model: TaxonomyResolution::Resolved { id: 4 },
                    normalized_manufacturer: String::from("TestCo"),
                    normalized_model: String::from("TestModel"),
                })
            })
        }
    }

    /// Remote mutations that always succeed.
    struct SuccessMutations;
    impl RemoteMutations for SuccessMutations {
        fn execute_plan<'a>(
            &'a self,
            plan: spotter_core::sync::SyncPlan,
            _: Option<u64>,
            _: &'a std::path::Path,
        ) -> PortFuture<'a, crate::ports::SyncOutcome> {
            Box::pin(async {
                Ok(crate::sync_engine::ExecutionOutcome {
                    next_monitor_state: plan.next_monitor_state,
                    warnings: plan.warnings,
                    confirmed_operations: Vec::new(),
                })
            })
        }
        fn recover_pending<'a>(&'a self, _: &'a std::path::Path) -> PortFuture<'a, Vec<String>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn compact_after_state_commit<'a>(&'a self, _: &'a std::path::Path) -> PortFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Fixed clock returning a deterministic timestamp.
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .map_or(chrono::DateTime::UNIX_EPOCH, |value| value.to_utc())
        }
    }

    /// Build configured settings with all required fields filled.
    fn configured_settings() -> spotter_core::Settings {
        let mut s = spotter_core::Settings::default();
        s.snipeit.url = String::from("https://snipeit.test");
        s.snipeit.checkout_status_id = 5;
        s.snipeit.checkin_status_id = 6;
        s.snipeit.api_token_encrypted = b"test-token".to_vec();
        s
    }

    /// Build a `CommandOwner` with configurable fakes and temp paths.
    fn make_owner(
        settings: spotter_core::Settings,
        settings_store: RecordingSettingsStore,
        discovery: TestDiscovery,
        reads: TestReads,
        persisted_state: PersistedServiceState,
    ) -> (CommandOwner, Arc<RecordingSettingsStore>) {
        let dir = tempfile::tempdir()
            .unwrap_or_else(|_| panic!("failed to create temp directory for test owner"));
        // Leak the tempdir so it persists for the owner's lifetime.
        // It will be cleaned up when the process exits.
        let root = dir.path().to_path_buf();
        std::mem::forget(dir);

        let store = Arc::new(settings_store);
        let owner = CommandOwner::new_test(
            IdentitySecret,
            RecordingSettingsStore {
                saved: Arc::clone(&store.saved),
                fail: Arc::clone(&store.fail),
            },
            MemoryStateStore,
            discovery,
            reads,
            SuccessMutations,
            FixedClock,
            None,
            root.join("settings.toml"),
            root.join("state.toml"),
            root.join("operations.jsonl"),
            vec![0; 32],
            tokio::sync::watch::channel(4).0,
            persisted_state,
            crate::ServiceController::new(settings),
        );
        (owner, store)
    }

    // ---- Existing baseline test (preserved) ----

    #[test]
    fn full_status_uses_persisted_asset_and_monitor_state() {
        use chrono::DateTime;
        use spotter_core::state::AssetSummary;

        let seen = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .map_or(DateTime::UNIX_EPOCH, |value| value.to_utc());
        let owner = CommandOwner::new_test(
            IdentitySecret,
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            MemoryStateStore,
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            SuccessMutations,
            FixedClock,
            None,
            std::path::PathBuf::new(),
            std::path::PathBuf::new(),
            std::path::PathBuf::new(),
            vec![0; 32],
            tokio::sync::watch::channel(4).0,
            PersistedServiceState {
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
            crate::ServiceController::new(spotter_core::Settings::default()),
        );
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

    // ---- Configuration command tests ----

    #[tokio::test]
    async fn set_config_persists_and_reloads_before_response() {
        let (mut owner, store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let response = owner
            .handle(ServiceCommand::SetConfig {
                field: String::from("polling.interval_hours"),
                value: String::from("12"),
            })
            .await;
        assert!(matches!(response, IpcResponse::Ok { .. }));
        let saved = store.saved.lock().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].polling.interval_hours, 12);
    }

    #[tokio::test]
    async fn set_config_save_failure_preserves_active_settings() {
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(true)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let original_interval = owner.controller.settings.polling.interval_hours;
        let response = owner
            .handle(ServiceCommand::SetConfig {
                field: String::from("polling.interval_hours"),
                value: String::from("12"),
            })
            .await;
        assert!(matches!(response, IpcResponse::Error { .. }));
        assert_eq!(
            owner.controller.settings.polling.interval_hours,
            original_interval
        );
    }

    #[tokio::test]
    async fn set_token_encrypts_and_persists_ciphertext_only() {
        let (mut owner, store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let token = b"my-secret-api-token";
        let response = owner
            .handle(ServiceCommand::SetToken {
                value: String::from_utf8_lossy(token).into_owned(),
            })
            .await;
        assert!(matches!(response, IpcResponse::Ok { .. }));
        let saved = store.saved.lock().unwrap();
        assert_eq!(saved.len(), 1);
        // IdentitySecret: ciphertext == plaintext bytes
        assert_eq!(saved[0].snipeit.api_token_encrypted, token.to_vec());
        // The token string must not appear as-is in a serialized form
        let toml_text = toml::to_string(&saved[0]).unwrap_or_default();
        assert!(
            !toml_text.contains("my-secret-api-token"),
            "plaintext token must not appear in serialized settings"
        );
    }

    #[tokio::test]
    async fn set_token_rejects_empty_token() {
        let (mut owner, store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let response = owner
            .handle(ServiceCommand::SetToken {
                value: String::new(),
            })
            .await;
        assert!(matches!(response, IpcResponse::Error { .. }));
        let saved = store.saved.lock().unwrap();
        assert!(saved.is_empty(), "no save should occur for empty token");
    }

    #[tokio::test]
    async fn get_config_is_redacted_after_token_update() {
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        owner
            .handle(ServiceCommand::SetToken {
                value: String::from("new-secret-token"),
            })
            .await;
        let response = owner.handle(ServiceCommand::GetConfig).await;
        if let IpcResponse::Config { settings, .. } = response {
            assert!(
                settings.snipeit.api_token_encrypted.is_empty(),
                "GetConfig must redact the encrypted token"
            );
        } else {
            panic!("GetConfig must return IpcResponse::Config");
        }
    }

    // ---- Sync orchestration tests ----

    #[tokio::test]
    async fn trigger_sync_success_returns_ok() {
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let response = owner.handle(ServiceCommand::TriggerSync).await;
        assert!(matches!(response, IpcResponse::Ok { .. }));
    }

    #[tokio::test]
    async fn trigger_sync_auth_failure_results_in_unconfigured() {
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(Some(SnipeItError::AuthFailure))),
            },
            PersistedServiceState::default(),
        );
        let _ = owner.handle(ServiceCommand::TriggerSync).await;
        assert_eq!(owner.controller.state, crate::FsmState::Unconfigured);
    }

    #[tokio::test]
    async fn trigger_sync_transient_failure_results_in_error() {
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(true)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let _ = owner.handle(ServiceCommand::TriggerSync).await;
        assert_eq!(owner.controller.state, crate::FsmState::Error);
    }

    #[tokio::test]
    async fn trigger_sync_when_unconfigured_returns_error() {
        let (mut owner, _store) = make_owner(
            spotter_core::Settings::default(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let response = owner.handle(ServiceCommand::TriggerSync).await;
        assert!(matches!(response, IpcResponse::Error { .. }));
    }

    // ---- Forced check-in tests ----

    #[tokio::test]
    async fn checkin_all_selects_only_absent_checked_out_with_asset_ids() {
        let seen = FixedClock.now();
        let state = PersistedServiceState {
            known_monitors: vec![
                // Eligible: absent, checked out, has asset ID
                MonitorSyncEntry {
                    serial: String::from("ELIG"),
                    snipeit_asset_id: Some(200),
                    last_seen: seen,
                    absent_since: Some(seen),
                    checked_out: true,
                },
                // Not eligible: not absent
                MonitorSyncEntry {
                    serial: String::from("PRESENT"),
                    snipeit_asset_id: Some(201),
                    last_seen: seen,
                    absent_since: None,
                    checked_out: true,
                },
                // Not eligible: not checked out
                MonitorSyncEntry {
                    serial: String::from("RETURNED"),
                    snipeit_asset_id: Some(202),
                    last_seen: seen,
                    absent_since: Some(seen),
                    checked_out: false,
                },
                // Not eligible: no asset ID
                MonitorSyncEntry {
                    serial: String::from("NOMAP"),
                    snipeit_asset_id: None,
                    last_seen: seen,
                    absent_since: Some(seen),
                    checked_out: true,
                },
            ],
            ..PersistedServiceState::default()
        };
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            state,
        );
        let response = owner.handle(ServiceCommand::CheckinAll).await;
        if let IpcResponse::CheckinResult { checked_in } = response {
            assert_eq!(checked_in.len(), 1);
            assert_eq!(checked_in[0].serial, "ELIG");
            assert_eq!(checked_in[0].asset_id, 200);
        } else {
            panic!("CheckinAll must return IpcResponse::CheckinResult");
        }
    }

    #[tokio::test]
    async fn checkin_serial_rejects_unknown_monitor() {
        let (mut owner, _store) = make_owner(
            configured_settings(),
            RecordingSettingsStore {
                saved: Arc::new(Mutex::new(Vec::new())),
                fail: Arc::new(Mutex::new(false)),
            },
            TestDiscovery {
                fail: Arc::new(Mutex::new(false)),
            },
            TestReads {
                taxonomy_error: Arc::new(Mutex::new(None)),
            },
            PersistedServiceState::default(),
        );
        let response = owner
            .handle(ServiceCommand::CheckinSerial {
                serial: String::from("UNKNOWN"),
            })
            .await;
        assert!(matches!(response, IpcResponse::Error { .. }));
    }
}
