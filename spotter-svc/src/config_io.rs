// pattern: Imperative Shell

//! Crash-resistant settings persistence and secret decryption.

use std::{fs, path::Path};

use anyhow::{Context as _, Result};
use secrecy::SecretString;
use spotter_core::config::{BLANK_SETTINGS_TOML, Settings};

#[derive(Debug)]
pub struct DecryptedConfig {
    pub url: String,
    pub api_token: SecretString,
    pub checkout_status_id: u64,
    pub checkin_status_id: u64,
}

/// Load settings, creating the blank template when absent.
///
/// # Errors
/// Returns an error when the file cannot be created, read, or parsed.
pub fn load_settings(path: &Path) -> Result<Settings> {
    if !path.exists() {
        atomic_write(path, BLANK_SETTINGS_TOML.as_bytes())?;
    }
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

/// Atomically replace the settings file with serialized settings.
///
/// # Errors
/// Returns an error when serialization or replacement fails.
pub fn save_settings(path: &Path, settings: &Settings) -> Result<()> {
    let text = toml::to_string_pretty(settings).context("failed to serialize settings")?;
    atomic_write(path, text.as_bytes())
}

/// Decrypt the API token into a secret wrapper.
///
/// # Errors
/// Returns an error when DPAPI decryption fails or plaintext is not UTF-8.
#[cfg(windows)]
pub fn decrypt_config(settings: &Settings) -> Result<DecryptedConfig> {
    let token = spotter_win32::dpapi::decrypt(&settings.snipeit.api_token_encrypted)?;
    let token = String::from_utf8(token).context("decrypted API token is not UTF-8")?;
    Ok(DecryptedConfig {
        url: settings.snipeit.url.clone(),
        api_token: SecretString::from(token),
        checkout_status_id: settings.snipeit.checkout_status_id,
        checkin_status_id: settings.snipeit.checkin_status_id,
    })
}

/// Report that DPAPI decryption is unavailable on non-Windows hosts.
///
/// # Errors
/// Always returns an unsupported-platform error.
#[cfg(not(windows))]
pub fn decrypt_config(_settings: &Settings) -> Result<DecryptedConfig> {
    anyhow::bail!("DPAPI decryption is only available on Windows")
}

#[must_use]
pub fn censored_display(settings: &Settings) -> Vec<(String, String)> {
    vec![
        (String::from("snipeit.url"), settings.snipeit.url.clone()),
        (
            String::from("snipeit.api_token_encrypted"),
            if settings.snipeit.api_token_encrypted.is_empty() {
                String::from("<not set>")
            } else {
                String::from("<configured>")
            },
        ),
        (
            String::from("polling.interval_hours"),
            settings.polling.interval_hours.to_string(),
        ),
    ]
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::atomic_file::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_roundtrip_and_template_creation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("settings.toml");
        let blank = load_settings(&path)?;
        assert!(blank.snipeit.url.is_empty());
        let mut configured = blank;
        configured.snipeit.url = String::from("https://example.test");
        save_settings(&path, &configured)?;
        assert_eq!(load_settings(&path)?.snipeit.url, "https://example.test");
        Ok(())
    }

    #[test]
    fn malformed_settings_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("settings.toml");
        fs::write(&path, b"[snipeit\nurl = \"unterminated\"")?;
        assert!(load_settings(&path).is_err());
        Ok(())
    }

    #[test]
    fn censored_display_reveals_only_token_presence() {
        let mut settings = Settings::default();
        settings.snipeit.url = String::from("https://example.test");
        settings.snipeit.api_token_encrypted = b"do-not-log-me".to_vec();
        let display = censored_display(&settings);
        assert!(display.iter().any(|(key, value)| {
            key == "snipeit.api_token_encrypted" && value == "<configured>"
        }));
        assert!(
            display
                .iter()
                .all(|(_, value)| !value.contains("do-not-log-me"))
        );
    }
}
