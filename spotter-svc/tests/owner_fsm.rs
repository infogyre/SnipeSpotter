#![cfg(all(windows, feature = "test-support"))]

use std::sync::{Arc, Mutex, mpsc};

use anyhow::Result;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use spotter_core::{
    Settings,
    ipc::{IpcResponse, ServiceCommand},
    smbios::{ChassisType, SystemInfo},
    state::ServiceState,
    sync::{ResolvedTaxonomy, TaxonomyResolution},
};
use spotter_svc::{
    ports::{HardwareDiscovery, PortFuture, RemoteReads},
    test_support::{
        Clock, OwnerPorts, RemoteFactory, RemotePort, SecretProtector, SettingsStore, StateStore,
        enqueue_owner_request, spawn_owner, spawn_owner_with_recovery,
    },
};

fn resolved_taxonomy() -> ResolvedTaxonomy {
    ResolvedTaxonomy {
        manufacturer: TaxonomyResolution::Resolved { id: 1 },
        category: TaxonomyResolution::Resolved { id: 2 },
        model: TaxonomyResolution::Resolved { id: 3 },
        normalized_manufacturer: String::from("maker"),
        normalized_model: String::from("model"),
    }
}

fn missing_taxonomy() -> ResolvedTaxonomy {
    ResolvedTaxonomy {
        manufacturer: TaxonomyResolution::Missing,
        category: TaxonomyResolution::Missing,
        model: TaxonomyResolution::Missing,
        normalized_manufacturer: String::new(),
        normalized_model: String::new(),
    }
}

struct FakeProtector;

impl SecretProtector for FakeProtector {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ 0xA5).collect())
    }

    fn decrypt(&self, _ciphertext: &[u8]) -> Result<SecretString> {
        Ok(SecretString::from(String::from("test-token")))
    }
}

struct CiphertextSensitiveProtector {
    decrypted_tokens: Arc<Mutex<Vec<String>>>,
}

impl SecretProtector for CiphertextSensitiveProtector {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<SecretString> {
        let token = match ciphertext {
            [0x11] => "old-token",
            [byte, ..] if *byte == b'n' => "new-token",
            _ => "unexpected-token",
        };
        self.decrypted_tokens
            .lock()
            .map_err(|_| anyhow::anyhow!("decrypted token lock poisoned"))?
            .push(String::from(token));
        Ok(SecretString::from(String::from(token)))
    }
}

struct MemorySettingsStore {
    saves: Arc<Mutex<Vec<Settings>>>,
}

impl SettingsStore for MemorySettingsStore {
    fn save(&self, settings: &Settings) -> Result<()> {
        self.saves
            .lock()
            .map_err(|_| anyhow::anyhow!("settings save lock poisoned"))?
            .push(settings.clone());
        Ok(())
    }
}

struct MemoryStateStore {
    saves: Arc<Mutex<Vec<ServiceState>>>,
}

impl StateStore for MemoryStateStore {
    fn save(&self, state: &mut ServiceState) -> Result<()> {
        self.saves
            .lock()
            .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?
            .push(state.clone());
        Ok(())
    }
}

struct SaveObservation {
    pending_operations: usize,
    pending_remote_outcomes: usize,
}

struct OrderedStateStore {
    saves: Arc<Mutex<Vec<ServiceState>>>,
    journal_path: std::path::PathBuf,
    observed: Mutex<Option<tokio::sync::oneshot::Sender<SaveObservation>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl StateStore for OrderedStateStore {
    fn save(&self, state: &mut ServiceState) -> Result<()> {
        let records = spotter_svc::operation_journal::load(&self.journal_path)?;
        let pending = spotter_svc::operation_journal::pending_with_evidence(&records)?;
        let pending_remote_outcomes = pending
            .iter()
            .filter(|operation| operation.remote_outcome.is_some())
            .count();
        let sender = self
            .observed
            .lock()
            .map_err(|_| anyhow::anyhow!("save observation lock poisoned"))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("save observation was already sent"))?;
        sender
            .send(SaveObservation {
                pending_operations: pending.len(),
                pending_remote_outcomes,
            })
            .map_err(|_| anyhow::anyhow!("save observation receiver dropped"))?;
        let receiver = self
            .release
            .lock()
            .map_err(|_| anyhow::anyhow!("save release lock poisoned"))?
            .take()
            .ok_or_else(|| anyhow::anyhow!("state save release was already consumed"))?;
        receiver
            .recv()
            .map_err(|_| anyhow::anyhow!("save release sender dropped"))?;
        self.saves
            .lock()
            .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?
            .push(state.clone());
        Ok(())
    }
}

#[derive(Default)]
struct BoundaryCalls {
    decrypt: usize,
    remote_reads: usize,
    remote_mutations: usize,
    remote_factory: usize,
}

struct RejectingProtector {
    calls: Arc<Mutex<BoundaryCalls>>,
}

impl SecretProtector for RejectingProtector {
    fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("encryption was unexpectedly requested")
    }

    fn decrypt(&self, _ciphertext: &[u8]) -> Result<SecretString> {
        self.calls
            .lock()
            .map_err(|_| anyhow::anyhow!("boundary calls lock poisoned"))?
            .decrypt += 1;
        anyhow::bail!("decryption was unexpectedly requested")
    }
}

struct RejectingFactory {
    calls: Arc<Mutex<BoundaryCalls>>,
}

impl RemoteFactory for RejectingFactory {
    fn build(&self, _settings: &Settings) -> Result<Box<dyn RemotePort>> {
        self.calls
            .lock()
            .map_err(|_| anyhow::anyhow!("boundary calls lock poisoned"))?
            .remote_factory += 1;
        anyhow::bail!("remote factory was unexpectedly requested")
    }
}

struct RejectingRemote {
    calls: Arc<Mutex<BoundaryCalls>>,
}

impl RemoteReads for RejectingRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remote_reads += 1;
        }
        Box::pin(async { anyhow::bail!("remote read was unexpectedly requested") })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remote_reads += 1;
        }
        Box::pin(async { anyhow::bail!("remote read was unexpectedly requested") })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for RejectingRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remote_mutations += 1;
        }
        Box::pin(async { anyhow::bail!("remote mutation was unexpectedly requested") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remote_mutations += 1;
        }
        Box::pin(async { anyhow::bail!("remote mutation was unexpectedly requested") })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.remote_mutations += 1;
        }
        Box::pin(async { anyhow::bail!("remote mutation was unexpectedly requested") })
    }
}

fn assert_no_remote_or_decrypt_calls(calls: &Arc<Mutex<BoundaryCalls>>) -> Result<()> {
    let calls = calls
        .lock()
        .map_err(|_| anyhow::anyhow!("boundary calls lock poisoned"))?;
    assert_eq!(calls.decrypt, 0);
    assert_eq!(calls.remote_reads, 0);
    assert_eq!(calls.remote_mutations, 0);
    assert_eq!(calls.remote_factory, 0);
    Ok(())
}

struct FailingSettingsStore;

impl SettingsStore for FailingSettingsStore {
    fn save(&self, _settings: &Settings) -> Result<()> {
        anyhow::bail!("injected settings save failure")
    }
}

struct FailingStateStore;

impl StateStore for FailingStateStore {
    fn save(&self, _state: &mut ServiceState) -> Result<()> {
        anyhow::bail!("injected state save failure")
    }
}

struct CandidateStateStore {
    saved: Arc<Mutex<Option<ServiceState>>>,
    journal_path: std::path::PathBuf,
}

impl StateStore for CandidateStateStore {
    fn save(&self, state: &mut ServiceState) -> Result<()> {
        self.saved
            .lock()
            .map_err(|_| anyhow::anyhow!("candidate state lock poisoned"))?
            .replace(state.clone());
        let mut permissions = std::fs::metadata(&self.journal_path)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&self.journal_path, permissions)?;
        Ok(())
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid fixed test time")
            .to_utc()
    }
}

struct RemotePortUnavailable;

struct FixedFactory;

impl RemoteFactory for FixedFactory {
    fn build(&self, _settings: &Settings) -> Result<Box<dyn RemotePort>> {
        Ok(Box::new(RemotePortUnavailable))
    }
}

struct FixedDiscovery;

impl HardwareDiscovery for FixedDiscovery {
    fn discover(&self) -> PortFuture<'_, (SystemInfo, Vec<spotter_core::monitors::MonitorInfo>)> {
        Box::pin(async {
            Ok((
                SystemInfo {
                    manufacturer: String::from("Maker"),
                    model: String::from("Model"),
                    serial: String::from("SYS-1"),
                    asset_tag: String::from("TAG-1"),
                    chassis_type: ChassisType(3),
                },
                Vec::new(),
            ))
        })
    }
}

#[derive(Clone)]
struct TypedFailureRemote {
    error: spotter_core::snipeit::SnipeItError,
}

impl RemoteReads for TypedFailureRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        let error = self.error.clone();
        Box::pin(async move { Err(anyhow::Error::from(error)) })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        let error = self.error.clone();
        Box::pin(async move { Err(anyhow::Error::from(error)) })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for TypedFailureRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { anyhow::bail!("remote mutation was not expected") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("remote mutation was not expected") })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("remote mutation was not expected") })
    }
}

struct FailingDiscovery;

impl HardwareDiscovery for FailingDiscovery {
    fn discover(&self) -> PortFuture<'_, (SystemInfo, Vec<spotter_core::monitors::MonitorInfo>)> {
        Box::pin(async { anyhow::bail!("hardware discovery failed") })
    }
}

#[tokio::test]
async fn saved_candidate_survives_journal_commit_failure() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let saved = Arc::new(Mutex::new(None));
    let journal_path = directory.path().join("operations.jsonl");
    let mut settings = Settings::default();
    settings.snipeit.url = String::from("https://example.test");
    settings.snipeit.api_token_encrypted = vec![0x42];
    settings.snipeit.checkout_status_id = 1;
    settings.snipeit.checkin_status_id = 2;
    let ports = OwnerPorts {
        secret_protector: Box::new(FakeProtector),
        settings_store: Box::new(MemorySettingsStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        state_store: Box::new(CandidateStateStore {
            saved: Arc::clone(&saved),
            journal_path: journal_path.clone(),
        }),
        remote: Box::new(SuccessfulRemote),
        remote_factory: Box::new(FixedFactory),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    };
    let fsm = spawn_owner(
        8,
        journal_path.clone(),
        settings,
        ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON-1"),
                snipeit_asset_id: Some(1),
                last_seen: DateTime::UNIX_EPOCH,
                absent_since: Some(DateTime::UNIX_EPOCH),
                checked_out: true,
            }],
            ..ServiceState::default()
        },
        ports,
    )?;

    let response = fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message.contains("state candidate saved"))
    );
    let saved = saved
        .lock()
        .map_err(|_| anyhow::anyhow!("candidate state lock poisoned"))?
        .clone()
        .ok_or_else(|| anyhow::anyhow!("state candidate was not saved"))?;
    let status = fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull { last_sync, .. } = status else {
        anyhow::bail!("expected full status response");
    };
    assert_eq!(last_sync, saved.last_sync_time);
    assert!(!spotter_svc::operation_journal::load(&journal_path)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn set_config_save_failure_preserves_redacted_active_settings() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut settings = Settings::default();
    settings.snipeit.url = String::from("https://before.example");
    settings.snipeit.api_token_encrypted = vec![0x42];
    let ports = OwnerPorts {
        secret_protector: Box::new(FakeProtector),
        settings_store: Box::new(FailingSettingsStore),
        state_store: Box::new(MemoryStateStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        remote: Box::new(RemotePortUnavailable),
        remote_factory: Box::new(FixedFactory),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    };
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        settings,
        ServiceState::default(),
        ports,
    )?;

    let response = fsm
        .request(ServiceCommand::SetConfig {
            field: String::from("snipeit.url"),
            value: String::from("https://after.example"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message.contains("settings save failure"))
    );

    let IpcResponse::Config { settings, .. } = fsm.request(ServiceCommand::GetConfig).await? else {
        anyhow::bail!("expected redacted config response");
    };
    assert_eq!(settings.snipeit.url, "https://before.example");
    assert!(settings.snipeit.api_token_encrypted.is_empty());
    Ok(())
}

#[tokio::test]
async fn set_token_save_failure_preserves_active_token_and_never_redacts_plaintext() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let decrypted_tokens = Arc::new(Mutex::new(Vec::new()));
    let mut settings = Settings::default();
    settings.snipeit.url = String::from("https://example.test");
    settings.snipeit.api_token_encrypted = vec![0x11];
    settings.snipeit.checkout_status_id = 1;
    settings.snipeit.checkin_status_id = 2;
    let ports = OwnerPorts {
        secret_protector: Box::new(CiphertextSensitiveProtector {
            decrypted_tokens: Arc::clone(&decrypted_tokens),
        }),
        settings_store: Box::new(FailingSettingsStore),
        state_store: Box::new(MemoryStateStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        remote: Box::new(RemotePortUnavailable),
        remote_factory: Box::new(FixedFactory),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    };
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        settings,
        ServiceState::default(),
        ports,
    )?;

    let response = fsm
        .request(ServiceCommand::SetToken {
            value: String::from("new-plaintext-token"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message.contains("settings save failure"))
    );

    let IpcResponse::Config { settings, .. } = fsm.request(ServiceCommand::GetConfig).await? else {
        anyhow::bail!("expected redacted config response");
    };
    assert!(settings.snipeit.api_token_encrypted.is_empty());
    let rendered = serde_json::to_string(&settings)?;
    assert!(!rendered.contains("new-plaintext-token"));

    let response = fsm.request(ServiceCommand::TriggerSync).await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message.contains("authentication"))
    );
    assert_eq!(
        decrypted_tokens
            .lock()
            .map_err(|_| anyhow::anyhow!("decrypted token lock poisoned"))?
            .as_slice(),
        ["old-token"]
    );
    Ok(())
}

#[tokio::test]
async fn sync_state_save_failure_returns_error_and_preserves_previous_status() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut settings = Settings::default();
    settings.snipeit.url = String::from("https://example.test");
    settings.snipeit.api_token_encrypted = vec![0x42];
    settings.snipeit.checkout_status_id = 1;
    settings.snipeit.checkin_status_id = 2;
    let previous = ServiceState {
        last_sync_time: Some(String::from("before")),
        last_sync_result: Some(spotter_core::state::SyncResult::Success),
        ..ServiceState::default()
    };
    let ports = OwnerPorts {
        secret_protector: Box::new(FakeProtector),
        settings_store: Box::new(MemorySettingsStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        state_store: Box::new(FailingStateStore),
        remote: Box::new(RemotePortUnavailable),
        remote_factory: Box::new(FixedFactory),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    };
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        settings,
        previous,
        ports,
    )?;

    let response = fsm.request(ServiceCommand::TriggerSync).await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message.contains("state save failure"))
    );
    let IpcResponse::StatusFull {
        state,
        last_sync,
        matched_asset,
        ..
    } = fsm.request(ServiceCommand::GetStatusFull).await?
    else {
        anyhow::bail!("expected full status response");
    };
    assert_eq!(state, "syncing");
    assert_eq!(last_sync.as_deref(), Some("before"));
    assert!(matched_asset.is_none());
    Ok(())
}

#[tokio::test]
async fn real_owner_commands_execute_through_fsm() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let saves = Arc::new(Mutex::new(Vec::new()));
    let state_saves = Arc::new(Mutex::new(Vec::new()));
    let mut settings = Settings::default();
    settings.snipeit.url = String::from("https://example.test");
    settings.snipeit.api_token_encrypted = vec![0x42];
    settings.snipeit.checkout_status_id = 1;
    settings.snipeit.checkin_status_id = 2;
    let ports = OwnerPorts {
        secret_protector: Box::new(FakeProtector),
        settings_store: Box::new(MemorySettingsStore {
            saves: Arc::clone(&saves),
        }),
        state_store: Box::new(MemoryStateStore {
            saves: Arc::clone(&state_saves),
        }),
        remote: Box::new(RemotePortUnavailable),
        remote_factory: Box::new(FixedFactory),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    };
    let fsm = spawn_owner(
        8,
        directory.path().join("operations.jsonl"),
        settings,
        ServiceState::default(),
        ports,
    )?;

    let commands = [
        ServiceCommand::GetConfig,
        ServiceCommand::SetConfig {
            field: String::from("snipeit.url"),
            value: String::from("https://example.test"),
        },
        ServiceCommand::SetToken {
            value: String::from("test-token"),
        },
        ServiceCommand::GetStatus,
        ServiceCommand::GetStatusFull,
        ServiceCommand::TriggerSync,
        ServiceCommand::CheckinAll,
        ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        },
    ];

    assert!(matches!(
        fsm.request(commands[0].clone()).await?,
        IpcResponse::Config { .. }
    ));
    assert!(matches!(
        fsm.request(commands[1].clone()).await?,
        IpcResponse::Ok { ref message } if message == "updated snipeit.url"
    ));
    assert!(matches!(
        fsm.request(commands[2].clone()).await?,
        IpcResponse::Ok { ref message } if message == "API token updated"
    ));
    assert!(matches!(
        fsm.request(commands[3].clone()).await?,
        IpcResponse::Status { .. }
    ));
    assert!(matches!(
        fsm.request(commands[4].clone()).await?,
        IpcResponse::StatusFull { .. }
    ));
    assert!(matches!(
        fsm.request(commands[5].clone()).await?,
        IpcResponse::Error { ref message } if message.contains("authentication")
    ));
    assert!(matches!(
        fsm.request(commands[6].clone()).await?,
        IpcResponse::CheckinResult { ref checked_in } if checked_in.is_empty()
    ));
    assert!(matches!(
        fsm.request(commands[7].clone()).await?,
        IpcResponse::Error { ref message } if message == "monitor MON-1 is unknown"
    ));

    assert_eq!(
        saves
            .lock()
            .map_err(|_| anyhow::anyhow!("save lock poisoned"))?
            .len(),
        2
    );
    let state_saves = state_saves
        .lock()
        .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?;
    assert_eq!(state_saves.len(), 1);
    assert_eq!(
        state_saves[0].last_sync_time.as_deref(),
        Some("2026-01-01T00:00:00+00:00")
    );
    assert!(matches!(
        state_saves[0].last_sync_result,
        Some(spotter_core::state::SyncResult::Failed { .. })
    ));
    Ok(())
}

async fn assert_sync_failure(
    discovery: Box<dyn HardwareDiscovery>,
    remote: Box<dyn RemotePort>,
    expected_state: &str,
    expected_message: &str,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let state_saves = Arc::new(Mutex::new(Vec::new()));
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        checkin_settings(),
        ServiceState::default(),
        OwnerPorts {
            secret_protector: Box::new(FakeProtector),
            settings_store: Box::new(MemorySettingsStore {
                saves: Arc::new(Mutex::new(Vec::new())),
            }),
            state_store: Box::new(MemoryStateStore {
                saves: Arc::clone(&state_saves),
            }),
            remote,
            remote_factory: Box::new(FixedFactory),
            discovery,
            clock: Box::new(FixedClock),
        },
    )?;

    let response = fsm.request(ServiceCommand::TriggerSync).await?;
    assert_eq!(
        response,
        IpcResponse::Error {
            message: String::from(expected_message),
        }
    );

    let IpcResponse::StatusFull {
        state, last_sync, ..
    } = fsm.request(ServiceCommand::GetStatusFull).await?
    else {
        anyhow::bail!("expected full status response after sync failure");
    };
    assert_eq!(state, expected_state);
    assert_eq!(last_sync.as_deref(), Some("2026-01-01T00:00:00+00:00"));

    let state_saves = state_saves
        .lock()
        .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?;
    assert_eq!(state_saves.len(), 1);
    assert_eq!(
        state_saves[0].last_sync_time.as_deref(),
        Some("2026-01-01T00:00:00+00:00")
    );
    assert_eq!(
        state_saves[0].last_sync_result,
        Some(spotter_core::state::SyncResult::Failed {
            error: String::from(expected_message),
        })
    );
    Ok(())
}

#[tokio::test]
async fn trigger_sync_classifies_typed_failures_and_persists_the_returned_cause() -> Result<()> {
    for (label, error, expected_state, expected_message) in [
        (
            "authentication",
            spotter_core::snipeit::SnipeItError::AuthFailure,
            "Unconfigured",
            "failed to resolve Snipe-IT asset: Snipe-IT authentication failed",
        ),
        (
            "permission",
            spotter_core::snipeit::SnipeItError::PermissionDenied,
            "Unconfigured",
            "failed to resolve Snipe-IT asset: Snipe-IT permission denied",
        ),
        (
            "rate limit",
            spotter_core::snipeit::SnipeItError::RateLimited {
                retry_after: Some(7),
            },
            "Error",
            "failed to resolve Snipe-IT asset: Snipe-IT rate limit exceeded",
        ),
        (
            "network",
            spotter_core::snipeit::SnipeItError::NetworkError {
                message: String::from("connection reset"),
            },
            "Error",
            "failed to resolve Snipe-IT asset: Snipe-IT network error: connection reset",
        ),
        (
            "server",
            spotter_core::snipeit::SnipeItError::ServerError {
                status: 503,
                message: String::from("temporarily unavailable"),
            },
            "Error",
            "failed to resolve Snipe-IT asset: Snipe-IT server error 503: temporarily unavailable",
        ),
    ] {
        assert_sync_failure(
            Box::new(FixedDiscovery),
            Box::new(TypedFailureRemote { error }),
            expected_state,
            expected_message,
        )
        .await
        .map_err(|error| anyhow::anyhow!("{label} case failed: {error}"))?;
    }

    assert_sync_failure(
        Box::new(FailingDiscovery),
        Box::new(SuccessfulRemote),
        "Error",
        "hardware discovery failed",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn trigger_sync_persists_partial_success_warnings_and_returns_idle() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let state_saves = Arc::new(Mutex::new(Vec::new()));
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        checkin_settings(),
        ServiceState::default(),
        OwnerPorts {
            secret_protector: Box::new(FakeProtector),
            settings_store: Box::new(MemorySettingsStore {
                saves: Arc::new(Mutex::new(Vec::new())),
            }),
            state_store: Box::new(MemoryStateStore {
                saves: Arc::clone(&state_saves),
            }),
            remote: Box::new(SuccessfulRemote),
            remote_factory: Box::new(FixedFactory),
            discovery: Box::new(FixedDiscovery),
            clock: Box::new(FixedClock),
        },
    )?;

    let response = fsm.request(ServiceCommand::TriggerSync).await?;
    assert_eq!(
        response,
        IpcResponse::Ok {
            message: String::from("synchronization completed with 2 warning(s)"),
        }
    );

    let IpcResponse::StatusFull {
        state, last_sync, ..
    } = fsm.request(ServiceCommand::GetStatusFull).await?
    else {
        anyhow::bail!("expected full status response after partial sync");
    };
    assert_eq!(state, "Idle");
    assert_eq!(last_sync.as_deref(), Some("2026-01-01T00:00:00+00:00"));

    let state_saves = state_saves
        .lock()
        .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?;
    assert_eq!(state_saves.len(), 1);
    assert_eq!(
        state_saves[0].last_sync_result,
        Some(spotter_core::state::SyncResult::PartialSuccess {
            warnings: vec![
                String::from("computer asset is missing; asset update suppressed"),
                String::from("computer SYS-1 has no matching Snipe-IT asset"),
            ],
        })
    );
    Ok(())
}

fn checkin_settings() -> Settings {
    let mut settings = Settings::default();
    settings.snipeit.url = String::from("https://example.test");
    settings.snipeit.api_token_encrypted = vec![0x42];
    settings.snipeit.checkout_status_id = 1;
    settings.snipeit.checkin_status_id = 2;
    settings
}

fn single_monitor_state(
    serial: &str,
    snipeit_asset_id: Option<u64>,
    absent_since: Option<DateTime<Utc>>,
    checked_out: bool,
) -> ServiceState {
    ServiceState {
        known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
            serial: String::from(serial),
            snipeit_asset_id,
            last_seen: DateTime::UNIX_EPOCH,
            absent_since,
            checked_out,
        }],
        ..ServiceState::default()
    }
}

fn rejecting_checkin_ports(calls: Arc<Mutex<BoundaryCalls>>) -> OwnerPorts {
    OwnerPorts {
        secret_protector: Box::new(RejectingProtector {
            calls: Arc::clone(&calls),
        }),
        settings_store: Box::new(MemorySettingsStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        state_store: Box::new(MemoryStateStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        remote: Box::new(RejectingRemote {
            calls: Arc::clone(&calls),
        }),
        remote_factory: Box::new(RejectingFactory { calls }),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    }
}

fn checkin_owner_ports(
    state_store: Box<dyn StateStore>,
    remote: Box<dyn RemotePort>,
) -> OwnerPorts {
    OwnerPorts {
        secret_protector: Box::new(FakeProtector),
        settings_store: Box::new(MemorySettingsStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        state_store,
        remote,
        remote_factory: Box::new(FixedFactory),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    }
}

fn monitor_entry(
    serial: &str,
    snipeit_asset_id: Option<u64>,
    absent_since: Option<DateTime<Utc>>,
    checked_out: bool,
) -> spotter_core::monitors::MonitorSyncEntry {
    spotter_core::monitors::MonitorSyncEntry {
        serial: String::from(serial),
        snipeit_asset_id,
        last_seen: DateTime::UNIX_EPOCH,
        absent_since,
        checked_out,
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "this integration test verifies the complete CheckinAll state transition"
)]
async fn checkin_all_selects_only_absent_checked_out_nonzero_assets() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("operations.jsonl");
    let state_saves = Arc::new(Mutex::new(Vec::new()));
    let checkins = Arc::new(Mutex::new(Vec::new()));
    let initial_state = ServiceState {
        known_monitors: vec![
            monitor_entry("MON-ELIGIBLE-A", Some(11), Some(DateTime::UNIX_EPOCH), true),
            monitor_entry("MON-PRESENT", Some(12), None, true),
            monitor_entry(
                "MON-ALREADY-IN",
                Some(13),
                Some(DateTime::UNIX_EPOCH),
                false,
            ),
            monitor_entry("MON-UNMAPPED", None, Some(DateTime::UNIX_EPOCH), true),
            monitor_entry("MON-ZERO", Some(0), Some(DateTime::UNIX_EPOCH), true),
            monitor_entry("MON-ELIGIBLE-B", Some(22), Some(DateTime::UNIX_EPOCH), true),
        ],
        ..ServiceState::default()
    };
    let fsm = spawn_owner(
        4,
        journal_path.clone(),
        checkin_settings(),
        initial_state,
        checkin_owner_ports(
            Box::new(MemoryStateStore {
                saves: Arc::clone(&state_saves),
            }),
            Box::new(RecordingCheckinRemote {
                checkins: Arc::clone(&checkins),
            }),
        ),
    )?;

    let response = fsm.request(ServiceCommand::CheckinAll).await?;
    let IpcResponse::CheckinResult { checked_in } = response else {
        anyhow::bail!("expected successful CheckinAll response");
    };
    assert_eq!(
        checked_in,
        vec![
            spotter_core::ipc::CheckinEntry {
                serial: String::from("MON-ELIGIBLE-A"),
                asset_id: 11,
            },
            spotter_core::ipc::CheckinEntry {
                serial: String::from("MON-ELIGIBLE-B"),
                asset_id: 22,
            },
        ]
    );
    assert_eq!(
        *checkins
            .lock()
            .map_err(|_| anyhow::anyhow!("check-in recorder lock poisoned"))?,
        vec![(11, 2), (22, 2)]
    );

    let saved_state = {
        let state_saves = state_saves
            .lock()
            .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?;
        state_saves
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("state candidate was not saved"))?
    };
    assert_eq!(
        saved_state.known_monitors,
        vec![
            monitor_entry(
                "MON-ELIGIBLE-A",
                Some(11),
                Some(DateTime::UNIX_EPOCH),
                false
            ),
            monitor_entry("MON-PRESENT", Some(12), None, true),
            monitor_entry(
                "MON-ALREADY-IN",
                Some(13),
                Some(DateTime::UNIX_EPOCH),
                false,
            ),
            monitor_entry("MON-UNMAPPED", None, Some(DateTime::UNIX_EPOCH), true),
            monitor_entry("MON-ZERO", Some(0), Some(DateTime::UNIX_EPOCH), true),
            monitor_entry(
                "MON-ELIGIBLE-B",
                Some(22),
                Some(DateTime::UNIX_EPOCH),
                false
            ),
        ]
    );

    let status = fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull {
        state, monitors, ..
    } = status
    else {
        anyhow::bail!("expected full status response after CheckinAll");
    };
    assert_eq!(state, "Idle");
    assert_eq!(
        monitors
            .iter()
            .map(|monitor| (monitor.serial.as_str(), monitor.checked_out))
            .collect::<Vec<_>>(),
        vec![
            ("MON-ELIGIBLE-A", false),
            ("MON-PRESENT", true),
            ("MON-ALREADY-IN", false),
            ("MON-UNMAPPED", true),
            ("MON-ZERO", true),
            ("MON-ELIGIBLE-B", false),
        ]
    );
    let records = spotter_svc::operation_journal::load(&journal_path)?;
    assert!(
        records.is_empty(),
        "successful CheckinAll must compact terminal journal records"
    );
    assert!(spotter_svc::operation_journal::pending_with_evidence(&records)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn checkin_reports_state_save_failure_and_retains_remote_evidence() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("operations.jsonl");
    let checkins = Arc::new(Mutex::new(Vec::new()));
    let fsm = spawn_owner(
        4,
        journal_path.clone(),
        checkin_settings(),
        single_monitor_state("MON-1", Some(11), Some(DateTime::UNIX_EPOCH), true),
        checkin_owner_ports(
            Box::new(FailingStateStore),
            Box::new(RecordingCheckinRemote {
                checkins: Arc::clone(&checkins),
            }),
        ),
    )?;

    let response = fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message.contains("injected state save failure")),
        "state save failure must never return a success response: {response:?}"
    );
    assert_eq!(
        *checkins
            .lock()
            .map_err(|_| anyhow::anyhow!("check-in recorder lock poisoned"))?,
        vec![(11, 2)]
    );

    let status = fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull { monitors, .. } = status else {
        anyhow::bail!("expected full status response after state save failure");
    };
    assert_eq!(monitors.len(), 1);
    assert!(monitors[0].checked_out);

    let records = spotter_svc::operation_journal::load(&journal_path)?;
    assert_eq!(records.len(), 2, "pending evidence must not be compacted");
    assert!(matches!(
        &records[0],
        spotter_svc::operation_journal::JournalRecord::Prepared { operation_id, .. }
            if operation_id == "checkin:11:2"
    ));
    assert!(matches!(
        &records[1],
        spotter_svc::operation_journal::JournalRecord::RemoteOutcomeObserved {
            operation_id,
            outcome,
            candidate_state: Some(_),
        } if operation_id == "checkin:11:2"
            && outcome.get("status").and_then(serde_json::Value::as_str) == Some("applied")
    ));
    let pending = spotter_svc::operation_journal::pending_with_evidence(&records)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, "checkin:11:2");
    assert_eq!(
        pending[0].operation["operation"]["operation_id"],
        serde_json::json!("checkin:11:2")
    );
    assert_eq!(
        pending[0].operation["operation"]["source_asset_id"],
        serde_json::json!(11)
    );
    assert_eq!(
        pending[0]
            .remote_outcome
            .as_ref()
            .and_then(|outcome| { outcome.get("status").and_then(serde_json::Value::as_str) }),
        Some("applied")
    );
    let candidate_state = pending[0]
        .candidate_state
        .as_ref()
        .and_then(|candidate| candidate.get("state"))
        .ok_or_else(|| anyhow::anyhow!("remote outcome did not retain candidate state"))?;
    assert!(
        !candidate_state["known_monitors"][0]["checked_out"]
            .as_bool()
            .unwrap_or(true)
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "this integration test verifies restart recovery and idempotence"
)]
async fn restart_recovers_observed_checkin_without_repeating_mutation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("operations.jsonl");
    let initial_state = single_monitor_state("MON-1", Some(11), Some(DateTime::UNIX_EPOCH), true);
    let first_checkins = Arc::new(Mutex::new(Vec::new()));
    let first_fsm = spawn_owner(
        4,
        journal_path.clone(),
        checkin_settings(),
        initial_state.clone(),
        checkin_owner_ports(
            Box::new(FailingStateStore),
            Box::new(RecordingCheckinRemote {
                checkins: Arc::clone(&first_checkins),
            }),
        ),
    )?;

    let response = first_fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(matches!(
        response,
        IpcResponse::Error { ref message } if message.contains("injected state save failure")
    ));
    assert_eq!(
        *first_checkins
            .lock()
            .map_err(|_| anyhow::anyhow!("first check-in recorder lock poisoned"))?,
        vec![(11, 2)]
    );
    let first_status = first_fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull { monitors, .. } = first_status else {
        anyhow::bail!("expected full status after failed first owner save");
    };
    assert_eq!(monitors.len(), 1);
    assert!(monitors[0].checked_out);
    let first_records = spotter_svc::operation_journal::load(&journal_path)?;
    assert_eq!(first_records.len(), 2);
    assert!(matches!(
        &first_records[0],
        spotter_svc::operation_journal::JournalRecord::Prepared { operation_id, .. }
            if operation_id == "checkin:11:2"
    ));
    assert!(matches!(
        &first_records[1],
        spotter_svc::operation_journal::JournalRecord::RemoteOutcomeObserved {
            operation_id,
            candidate_state: Some(candidate_state),
            ..
        } if operation_id == "checkin:11:2"
            && candidate_state["state"]["known_monitors"][0]["checked_out"] == false
    ));
    drop(first_fsm);

    let recovered_saves = Arc::new(Mutex::new(Vec::new()));
    let recovery_calls = Arc::new(Mutex::new(RecoveryCalls::default()));
    let second_fsm = spawn_owner_with_recovery(
        4,
        journal_path.clone(),
        checkin_settings(),
        initial_state,
        checkin_owner_ports(
            Box::new(MemoryStateStore {
                saves: Arc::clone(&recovered_saves),
            }),
            Box::new(ReconciliationRemote {
                calls: Arc::clone(&recovery_calls),
            }),
        ),
    )
    .await?;

    let status = second_fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull { monitors, .. } = status else {
        anyhow::bail!("expected full status after restart recovery");
    };
    assert_eq!(monitors.len(), 1);
    assert!(!monitors[0].checked_out);
    {
        let recovered_states = recovered_saves
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery state save lock poisoned"))?;
        assert_eq!(recovered_states.len(), 1);
        assert_eq!(recovered_states[0].known_monitors.len(), 1);
        assert!(!recovered_states[0].known_monitors[0].checked_out);
        assert_eq!(
            recovered_states[0].known_monitors[0].snipeit_asset_id,
            Some(11)
        );
    }
    {
        let recovery_observations = recovery_calls
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery calls lock poisoned"))?;
        assert_eq!(recovery_observations.mutations, 0);
        assert_eq!(recovery_observations.reconciliation_reads, 1);
    }
    assert!(spotter_svc::operation_journal::load(&journal_path)?.is_empty());

    let second_status = second_fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull { monitors, .. } = second_status else {
        anyhow::bail!("expected full status after repeated recovery");
    };
    assert_eq!(monitors.len(), 1);
    assert!(!monitors[0].checked_out);
    assert_eq!(
        recovered_saves
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery state save lock poisoned"))?
            .len(),
        1
    );
    let recovery_observations = recovery_calls
        .lock()
        .map_err(|_| anyhow::anyhow!("recovery calls lock poisoned"))?;
    assert_eq!(recovery_observations.mutations, 0);
    assert_eq!(recovery_observations.reconciliation_reads, 1);
    Ok(())
}

#[tokio::test]
async fn checkin_serial_rejects_present_monitor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(Mutex::new(BoundaryCalls::default()));
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        checkin_settings(),
        single_monitor_state("MON-1", Some(1), None, true),
        rejecting_checkin_ports(Arc::clone(&calls)),
    )?;

    let response = fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message == "monitor MON-1 is present and cannot be checked in")
    );
    assert_no_remote_or_decrypt_calls(&calls)?;
    Ok(())
}

#[tokio::test]
async fn checkin_serial_rejects_already_checked_in_monitor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(Mutex::new(BoundaryCalls::default()));
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        checkin_settings(),
        single_monitor_state("MON-1", Some(1), Some(DateTime::UNIX_EPOCH), false),
        rejecting_checkin_ports(Arc::clone(&calls)),
    )?;

    let response = fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message == "monitor MON-1 is already checked in")
    );
    assert_no_remote_or_decrypt_calls(&calls)?;
    Ok(())
}

#[tokio::test]
async fn checkin_serial_rejects_unmapped_monitor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(Mutex::new(BoundaryCalls::default()));
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        checkin_settings(),
        single_monitor_state("MON-1", None, Some(DateTime::UNIX_EPOCH), true),
        rejecting_checkin_ports(Arc::clone(&calls)),
    )?;

    let response = fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message == "monitor MON-1 has no Snipe-IT asset mapping")
    );
    assert_no_remote_or_decrypt_calls(&calls)?;
    Ok(())
}

#[tokio::test]
async fn checkin_serial_rejects_unknown_monitor_before_remote_boundaries() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(Mutex::new(BoundaryCalls::default()));
    let fsm = spawn_owner(
        4,
        directory.path().join("operations.jsonl"),
        checkin_settings(),
        ServiceState::default(),
        rejecting_checkin_ports(Arc::clone(&calls)),
    )?;

    let response = fsm
        .request(ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        })
        .await?;
    assert!(
        matches!(response, IpcResponse::Error { ref message } if message == "monitor MON-1 is unknown")
    );
    assert_no_remote_or_decrypt_calls(&calls)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checkin_serial_success_commits_state_before_response() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("operations.jsonl");
    let state_saves = Arc::new(Mutex::new(Vec::new()));
    let (saved_sender, saved_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let fsm = spawn_owner(
        4,
        journal_path.clone(),
        checkin_settings(),
        single_monitor_state("MON-1", Some(1), Some(DateTime::UNIX_EPOCH), true),
        OwnerPorts {
            secret_protector: Box::new(FakeProtector),
            settings_store: Box::new(MemorySettingsStore {
                saves: Arc::new(Mutex::new(Vec::new())),
            }),
            state_store: Box::new(OrderedStateStore {
                saves: Arc::clone(&state_saves),
                journal_path: journal_path.clone(),
                observed: Mutex::new(Some(saved_sender)),
                release: Mutex::new(Some(release_receiver)),
            }),
            remote: Box::new(SuccessfulRemote),
            remote_factory: Box::new(FixedFactory),
            discovery: Box::new(FixedDiscovery),
            clock: Box::new(FixedClock),
        },
    )?;

    let request = tokio::spawn({
        let fsm = fsm.clone();
        async move {
            fsm.request(ServiceCommand::CheckinSerial {
                serial: String::from("MON-1"),
            })
            .await
        }
    });
    let observation = saved_receiver
        .await
        .map_err(|_| anyhow::anyhow!("state save observation was cancelled"))?;
    assert_eq!(observation.pending_operations, 1);
    assert_eq!(observation.pending_remote_outcomes, 1);
    assert!(!request.is_finished());
    release_sender
        .send(())
        .map_err(|_| anyhow::anyhow!("failed to release state save"))?;
    let response = request.await??;
    let IpcResponse::CheckinResult { checked_in } = response else {
        anyhow::bail!("expected successful check-in response");
    };
    assert_eq!(
        checked_in,
        vec![spotter_core::ipc::CheckinEntry {
            serial: String::from("MON-1"),
            asset_id: 1,
        }]
    );

    let state_saves = state_saves
        .lock()
        .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?;
    assert_eq!(state_saves.len(), 1);
    assert_eq!(state_saves[0].known_monitors.len(), 1);
    assert!(!state_saves[0].known_monitors[0].checked_out);

    let records = spotter_svc::operation_journal::load(&journal_path)?;
    assert!(spotter_svc::operation_journal::pending_with_evidence(&records)?.is_empty());
    assert!(records.is_empty());
    Ok(())
}

struct SuccessfulRemote;

impl RemoteReads for SuccessfulRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        Box::pin(async { Ok(None) })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        Box::pin(async { Ok(resolved_taxonomy()) })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for SuccessfulRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { Ok(spotter_core::snipeit::Asset::default()) })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
struct RecoveryCalls {
    reconciliation_reads: usize,
    mutations: usize,
}

struct ReconciliationRemote {
    calls: Arc<Mutex<RecoveryCalls>>,
}

impl RemoteReads for ReconciliationRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        Box::pin(async { Ok(None) })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        Box::pin(async { Ok(missing_taxonomy()) })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for ReconciliationRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { anyhow::bail!("unexpected asset patch") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("unexpected monitor checkout") })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls
                .lock()
                .map_err(|_| anyhow::anyhow!("recovery calls lock poisoned"))?
                .reconciliation_reads += 1;
            Ok(())
        })
    }
}

struct RecordingCheckinRemote {
    checkins: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl RemoteReads for RecordingCheckinRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        Box::pin(async { Ok(None) })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        Box::pin(async { Ok(resolved_taxonomy()) })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for RecordingCheckinRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { anyhow::bail!("unexpected asset patch") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("unexpected monitor checkout") })
    }

    fn checkin<'a>(
        &'a mut self,
        operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        let checkins = Arc::clone(&self.checkins);
        let asset_id = operation.source_asset_id;
        let status_id = operation.request.status_id;
        Box::pin(async move {
            checkins
                .lock()
                .map_err(|_| anyhow::anyhow!("check-in recorder lock poisoned"))?
                .push((asset_id, status_id));
            Ok(())
        })
    }
}

impl RemoteReads for RemotePortUnavailable {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        Box::pin(async { anyhow::bail!("remote unavailable") })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        Box::pin(async { anyhow::bail!("remote unavailable") })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for RemotePortUnavailable {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { anyhow::bail!("remote unavailable") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("remote unavailable") })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("remote unavailable") })
    }
}

struct SyncGate {
    started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

struct RecordingRemote {
    url: String,
    observed_urls: Arc<Mutex<Vec<String>>>,
    gate: Option<Arc<SyncGate>>,
}

impl RecordingRemote {
    fn record_read(&self) {
        self.observed_urls
            .lock()
            .expect("recorded remote URLs lock")
            .push(self.url.clone());
    }
}

impl RemoteReads for RecordingRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> PortFuture<'a, Option<spotter_core::snipeit::Asset>> {
        self.record_read();
        let release = self.gate.as_ref().and_then(|gate| {
            let sender = gate.started.lock().expect("sync gate started lock").take();
            if let Some(sender) = sender {
                let _ = sender.send(());
            }
            gate.release.lock().expect("sync gate release lock").take()
        });
        Box::pin(async move {
            if let Some(release) = release {
                let _ = release.await;
            }
            Ok(None)
        })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        _manufacturer: &'a str,
        _model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy> {
        self.record_read();
        Box::pin(async { Ok(resolved_taxonomy()) })
    }
}

impl spotter_svc::sync_engine::RemoteMutations for RecordingRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { anyhow::bail!("unexpected asset patch") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("unexpected monitor checkout") })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("unexpected monitor check-in") })
    }
}

struct RecordingFactory {
    built_urls: Arc<Mutex<Vec<String>>>,
    observed_urls: Arc<Mutex<Vec<String>>>,
}

impl RemoteFactory for RecordingFactory {
    fn build(&self, settings: &Settings) -> Result<Box<dyn RemotePort>> {
        self.built_urls
            .lock()
            .map_err(|_| anyhow::anyhow!("recorded factory URLs lock poisoned"))?
            .push(settings.snipeit.url.clone());
        Ok(Box::new(RecordingRemote {
            url: settings.snipeit.url.clone(),
            observed_urls: Arc::clone(&self.observed_urls),
            gate: None,
        }))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "this integration test verifies queued configuration and the next sync"
)]
async fn config_update_queued_during_sync_is_used_by_next_operation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("operations.jsonl");
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let gate = Arc::new(SyncGate {
        started: Mutex::new(Some(started_sender)),
        release: Mutex::new(Some(release_receiver)),
    });
    let built_urls = Arc::new(Mutex::new(Vec::new()));
    let observed_urls = Arc::new(Mutex::new(Vec::new()));
    let mut settings = checkin_settings();
    settings.snipeit.url = String::from("https://old.example");
    let settings_saves = Arc::new(Mutex::new(Vec::new()));
    let ports = OwnerPorts {
        secret_protector: Box::new(FakeProtector),
        settings_store: Box::new(MemorySettingsStore {
            saves: Arc::clone(&settings_saves),
        }),
        state_store: Box::new(MemoryStateStore {
            saves: Arc::new(Mutex::new(Vec::new())),
        }),
        remote: Box::new(RecordingRemote {
            url: settings.snipeit.url.clone(),
            observed_urls: Arc::clone(&observed_urls),
            gate: Some(gate),
        }),
        remote_factory: Box::new(RecordingFactory {
            built_urls: Arc::clone(&built_urls),
            observed_urls: Arc::clone(&observed_urls),
        }),
        discovery: Box::new(FixedDiscovery),
        clock: Box::new(FixedClock),
    };
    let fsm = spawn_owner(8, journal_path, settings, ServiceState::default(), ports)?;

    let sync_request = tokio::spawn({
        let fsm = fsm.clone();
        async move { fsm.request(ServiceCommand::TriggerSync).await }
    });
    started_receiver
        .await
        .map_err(|_| anyhow::anyhow!("sync did not reach the remote read barrier"))?;

    let mut config_response = enqueue_owner_request(
        &fsm,
        ServiceCommand::SetConfig {
            field: String::from("snipeit.url"),
            value: String::from("https://new.example"),
        },
    )
    .await?;
    assert!(matches!(
        config_response.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        built_urls
            .lock()
            .map_err(|_| anyhow::anyhow!("recorded factory URLs lock poisoned"))?
            .is_empty()
    );

    release_sender
        .send(())
        .map_err(|()| anyhow::anyhow!("failed to release sync read barrier"))?;
    assert!(
        matches!(sync_request.await??, IpcResponse::Ok { ref message } if message.contains("completed"))
    );
    assert!(matches!(
        config_response.await?,
        IpcResponse::Ok { ref message } if message == "updated snipeit.url"
    ));
    {
        let settings_saves = settings_saves
            .lock()
            .map_err(|_| anyhow::anyhow!("settings save lock poisoned"))?;
        assert_eq!(settings_saves.len(), 1);
        assert_eq!(settings_saves[0].snipeit.url, "https://new.example");
    }
    assert_eq!(
        built_urls
            .lock()
            .map_err(|_| anyhow::anyhow!("recorded factory URLs lock poisoned"))?
            .as_slice(),
        ["https://new.example"]
    );

    let read_count_before_next_sync = observed_urls
        .lock()
        .map_err(|_| anyhow::anyhow!("recorded remote URLs lock poisoned"))?
        .len();
    assert!(matches!(
        fsm.request(ServiceCommand::TriggerSync).await?,
        IpcResponse::Ok { ref message } if message.contains("completed")
    ));
    let observed_urls = observed_urls
        .lock()
        .map_err(|_| anyhow::anyhow!("recorded remote URLs lock poisoned"))?;
    assert!(observed_urls.len() > read_count_before_next_sync);
    assert!(
        observed_urls[read_count_before_next_sync..]
            .iter()
            .all(|url| url == "https://new.example")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_response_does_not_skip_state_commit_or_journal_compaction() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("operations.jsonl");
    let state_saves = Arc::new(Mutex::new(Vec::new()));
    let (saved_sender, saved_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let fsm = spawn_owner(
        4,
        journal_path.clone(),
        checkin_settings(),
        single_monitor_state("MON-1", Some(1), Some(DateTime::UNIX_EPOCH), true),
        OwnerPorts {
            secret_protector: Box::new(FakeProtector),
            settings_store: Box::new(MemorySettingsStore {
                saves: Arc::new(Mutex::new(Vec::new())),
            }),
            state_store: Box::new(OrderedStateStore {
                saves: Arc::clone(&state_saves),
                journal_path: journal_path.clone(),
                observed: Mutex::new(Some(saved_sender)),
                release: Mutex::new(Some(release_receiver)),
            }),
            remote: Box::new(SuccessfulRemote),
            remote_factory: Box::new(FixedFactory),
            discovery: Box::new(FixedDiscovery),
            clock: Box::new(FixedClock),
        },
    )?;

    let response = enqueue_owner_request(
        &fsm,
        ServiceCommand::CheckinSerial {
            serial: String::from("MON-1"),
        },
    )
    .await?;
    let observation = saved_receiver
        .await
        .map_err(|_| anyhow::anyhow!("state save observation was cancelled"))?;
    assert_eq!(observation.pending_operations, 1);
    assert_eq!(observation.pending_remote_outcomes, 1);
    let pending = spotter_svc::operation_journal::pending_with_evidence(
        &spotter_svc::operation_journal::load(&journal_path)?,
    )?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, "checkin:1:2");
    assert!(pending[0].remote_outcome.is_some());
    drop(response);

    release_sender
        .send(())
        .map_err(|_| anyhow::anyhow!("failed to release state save"))?;
    let status = fsm.request(ServiceCommand::GetStatusFull).await?;
    let IpcResponse::StatusFull { monitors, .. } = status else {
        anyhow::bail!("expected full status after cancelled response");
    };
    assert_eq!(monitors.len(), 1);
    assert!(!monitors[0].checked_out);
    let state_saves = state_saves
        .lock()
        .map_err(|_| anyhow::anyhow!("state save lock poisoned"))?;
    assert_eq!(state_saves.len(), 1);
    let monitor = state_saves[0]
        .known_monitors
        .iter()
        .find(|monitor| monitor.serial == "MON-1")
        .ok_or_else(|| anyhow::anyhow!("saved state did not contain MON-1"))?;
    assert!(!monitor.checked_out);
    let records = spotter_svc::operation_journal::load(&journal_path)?;
    assert!(records.is_empty());
    assert!(spotter_svc::operation_journal::pending_with_evidence(&records)?.is_empty());
    Ok(())
}
