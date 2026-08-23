//! Narrow ports used by the Windows service orchestration shell.

use std::{future::Future, path::Path, pin::Pin};

use anyhow::Result;
use chrono::{DateTime, Utc};
use spotter_core::{
    config::Settings,
    monitors::MonitorInfo,
    smbios::SystemInfo,
    snipeit::Asset,
    state::ServiceState as PersistedServiceState,
    sync::{ResolvedTaxonomy, SyncPlan},
};

/// The outcome returned by journal-backed synchronization execution.
pub type SyncOutcome = crate::sync_engine::ExecutionOutcome;

/// An object-safe boxed future returned by an asynchronous port.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Encrypt and decrypt secrets (DPAPI in production).
pub trait SecretProtector: Send + Sync {
    /// Encrypt plaintext bytes.
    ///
    /// # Errors
    /// Returns an error when the production protector rejects the input.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext bytes.
    ///
    /// # Errors
    /// Returns an error when the ciphertext cannot be decrypted.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Persist and load settings.
pub trait SettingsStore: Send + Sync {
    /// Save settings at `path`.
    ///
    /// # Errors
    /// Returns an error when settings cannot be serialized or persisted.
    fn save(&self, path: &Path, settings: &Settings) -> Result<()>;

    /// Load settings from `path`.
    ///
    /// # Errors
    /// Returns an error when settings cannot be read or parsed.
    fn load(&self, path: &Path) -> Result<Settings>;
}

/// Persist and load signed service state.
pub trait StateStore: Send + Sync {
    /// Sign and save state at `path`.
    ///
    /// # Errors
    /// Returns an error when state cannot be signed or persisted.
    fn save(&self, path: &Path, state: &mut PersistedServiceState, key: &[u8]) -> Result<()>;

    /// Load and verify state from `path`.
    ///
    /// # Errors
    /// Returns an error when state cannot be read or authenticated.
    fn load(&self, path: &Path, key: &[u8]) -> Result<PersistedServiceState>;

    /// Load an existing state key or create one at `path`.
    ///
    /// # Errors
    /// Returns an error when the key cannot be read, generated, or persisted.
    fn load_or_create_key(&self, path: &Path) -> Result<Vec<u8>>;
}

/// Discover local hardware.
pub trait HardwareDiscovery: Send + Sync {
    /// Discover system and connected-monitor inventory.
    fn discover(&self) -> PortFuture<'_, (SystemInfo, Vec<MonitorInfo>)>;
}

/// Read-side Snipe-IT operations used during gathering.
pub trait RemoteReads: Send + Sync {
    /// Find an asset by exact serial, returning `None` for a missing asset.
    fn find_asset_by_serial<'a>(&'a self, serial: &'a str) -> PortFuture<'a, Option<Asset>>;

    /// Resolve manufacturer, category, and model taxonomy for a name pair.
    fn resolve_taxonomy<'a>(
        &'a self,
        manufacturer: &'a str,
        model: &'a str,
    ) -> PortFuture<'a, ResolvedTaxonomy>;
}

/// Write-side Snipe-IT operations used by synchronization and recovery.
pub trait RemoteMutations: Send + Sync {
    /// Execute a synchronization plan using the supplied journal.
    fn execute_plan<'a>(
        &'a self,
        plan: SyncPlan,
        computer_asset_id: Option<u64>,
        journal_path: &'a Path,
    ) -> PortFuture<'a, SyncOutcome>;

    /// Recover pending operations from the supplied journal.
    fn recover_pending<'a>(&'a self, journal_path: &'a Path) -> PortFuture<'a, Vec<String>>;

    /// Compact a journal after state has been committed.
    fn compact_after_state_commit<'a>(&'a self, journal_path: &'a Path) -> PortFuture<'a, ()>;
}

/// Supply the current time to the service.
pub trait Clock: Send + Sync {
    /// Return the current UTC timestamp.
    fn now(&self) -> DateTime<Utc>;
}
