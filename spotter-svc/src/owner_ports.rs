// pattern: Imperative Shell

//! Narrow dependency ports for the production command owner.

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use spotter_core::{Settings, state::ServiceState};

use crate::{discovery::HardwareDiscovery, gather::RemoteReads, sync_engine::RemoteMutations};

/// Encrypts and decrypts the API token at the platform boundary.
pub trait SecretProtector: Send + Sync {
    /// Encrypt plaintext for durable settings storage.
    ///
    /// # Errors
    /// Returns an error when the platform protector rejects the plaintext.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext into a protected API token.
    ///
    /// # Errors
    /// Returns an error when the ciphertext cannot be decrypted or decoded.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<SecretString>;
}

/// Persists settings candidates before they become active.
pub trait SettingsStore: Send + Sync {
    /// Persist one complete settings candidate.
    ///
    /// # Errors
    /// Returns an error when the candidate cannot be durably saved.
    fn save(&self, settings: &Settings) -> Result<()>;
}

/// Persists signed service-state candidates before they become active.
pub trait StateStore: Send + Sync {
    /// Persist one complete state candidate.
    ///
    /// # Errors
    /// Returns an error when the candidate cannot be durably saved.
    fn save(&self, state: &mut ServiceState) -> Result<()>;
}

/// Supplies the wall-clock instant required by state and journal transitions.
pub trait Clock: Send + Sync {
    /// Return the current UTC instant.
    fn now(&self) -> DateTime<Utc>;
}

/// Production wall-clock adapter.
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub(crate) struct DpapiProtector;

impl SecretProtector for DpapiProtector {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        spotter_win32::dpapi::encrypt(plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<SecretString> {
        let plaintext = spotter_win32::dpapi::decrypt(ciphertext)
            .context("failed to decrypt API token with DPAPI")?;
        let token = String::from_utf8(plaintext).context("decrypted API token is not UTF-8")?;
        Ok(SecretString::from(token))
    }
}

pub(crate) struct FileSettingsStore {
    pub(crate) path: std::path::PathBuf,
}

impl SettingsStore for FileSettingsStore {
    fn save(&self, settings: &Settings) -> Result<()> {
        crate::config_io::save_settings(&self.path, settings)
    }
}

pub(crate) struct FileStateStore {
    pub(crate) path: std::path::PathBuf,
    pub(crate) key: Vec<u8>,
}

impl StateStore for FileStateStore {
    fn save(&self, state: &mut ServiceState) -> Result<()> {
        crate::state_io::save_state(&self.path, state, &self.key)
    }
}

/// Combines the narrow read and mutation views over one authenticated client.
pub trait RemotePort: RemoteReads + RemoteMutations {}

impl<T> RemotePort for T where T: RemoteReads + RemoteMutations {}

/// Constructs an authenticated remote port from committed settings.
pub trait RemoteFactory: Send + Sync {
    /// Build a remote client for a complete settings candidate.
    fn build(&self, settings: &Settings) -> Result<Box<dyn RemotePort>>;
}

pub(crate) struct SnipeItRemoteFactory;

impl RemoteFactory for SnipeItRemoteFactory {
    fn build(&self, settings: &Settings) -> Result<Box<dyn RemotePort>> {
        let decrypted = crate::config_io::decrypt_config(settings)?;
        Ok(Box::new(crate::snipeit_client::SnipeItClient::new(
            decrypted.url,
            decrypted.api_token,
        )?))
    }
}

pub(crate) struct UnavailableRemote;

impl RemoteReads for UnavailableRemote {
    fn find_asset_by_serial<'a>(
        &'a self,
        _serial: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        spotter_core::snipeit::Asset,
                        spotter_core::snipeit::SnipeItError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(spotter_core::snipeit::SnipeItError::AuthFailure) })
    }

    fn find_manufacturers<'a>(
        &'a self,
        _name: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Vec<spotter_core::snipeit::Manufacturer>,
                        spotter_core::snipeit::SnipeItError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(spotter_core::snipeit::SnipeItError::AuthFailure) })
    }

    fn find_models<'a>(
        &'a self,
        _name: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Vec<spotter_core::snipeit::AssetModel>,
                        spotter_core::snipeit::SnipeItError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(spotter_core::snipeit::SnipeItError::AuthFailure) })
    }
}

impl HardwareDiscovery for UnavailableRemote {
    fn discover(
        &self,
    ) -> Result<(
        spotter_core::smbios::SystemInfo,
        Vec<spotter_core::monitors::MonitorInfo>,
    )> {
        anyhow::bail!("hardware discovery is unavailable")
    }
}

impl RemoteMutations for UnavailableRemote {
    fn patch_asset<'a>(
        &'a mut self,
        _asset_id: u64,
        _request: &'a spotter_core::snipeit::AssetPatchRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<spotter_core::snipeit::Asset>> + Send + 'a>,
    > {
        Box::pin(async { anyhow::bail!("remote client is unavailable") })
    }

    fn checkout<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckout,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("remote client is unavailable") })
    }

    fn checkin<'a>(
        &'a mut self,
        _operation: &'a spotter_core::snipeit::MonitorCheckin,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("remote client is unavailable") })
    }
}
