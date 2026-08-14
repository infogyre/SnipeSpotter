//! Signed, serializable state shared by the service and its clients.
// pattern: Functional Core

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::monitors::MonitorSyncEntry;

type HmacSha256 = Hmac<Sha256>;

/// The result of the most recent synchronization attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SyncResult {
    /// Synchronization completed without warnings.
    Success,
    /// Synchronization completed with one or more warnings.
    PartialSuccess { warnings: Vec<String> },
    /// Synchronization failed.
    Failed { error: String },
}

/// A Snipe-IT asset selected by synchronization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSummary {
    /// The Snipe-IT asset identifier.
    pub id: u64,
    /// The asset's display name.
    pub name: String,
    /// The asset's optional serial number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// The asset's optional asset tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_tag: Option<String>,
}

/// Persisted service state and its authentication tag.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceState {
    /// The timestamp of the most recent synchronization attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,
    /// The result of the most recent synchronization attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_result: Option<SyncResult>,
    /// The asset matched by the most recent synchronization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_asset: Option<AssetSummary>,
    /// Monitors known to the service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub known_monitors: Vec<MonitorSyncEntry>,
    /// The lower-case hexadecimal HMAC-SHA256 authentication tag.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hmac: String,
}

/// Errors produced while authenticating service state.
#[derive(Debug, Error)]
pub enum StateAuthError {
    /// The signable state could not be serialized.
    #[error("failed to serialize service state: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The signing key was empty or could not be accepted by HMAC.
    #[error("invalid signing key")]
    InvalidKey,
    /// The stored authentication tag is not valid hexadecimal.
    #[error("invalid HMAC hexadecimal encoding")]
    InvalidHex,
}

#[derive(Serialize)]
struct SignableServiceState<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sync_time: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sync_result: Option<&'a SyncResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_asset: Option<&'a AssetSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    known_monitors: &'a Vec<MonitorSyncEntry>,
}

impl ServiceState {
    /// Serializes the state deterministically, excluding its authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`StateAuthError::Serialization`] if canonical JSON encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StateAuthError> {
        let signable = SignableServiceState {
            last_sync_time: self.last_sync_time.as_deref(),
            last_sync_result: self.last_sync_result.as_ref(),
            matched_asset: self.matched_asset.as_ref(),
            known_monitors: &self.known_monitors,
        };

        serde_json::to_vec(&signable).map_err(StateAuthError::from)
    }

    /// Computes and stores an HMAC-SHA256 authentication tag for this state.
    ///
    /// # Errors
    ///
    /// Returns [`StateAuthError`] when the key is empty or canonical encoding fails.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), StateAuthError> {
        validate_key(key)?;
        let canonical = self.canonical_bytes()?;
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| StateAuthError::InvalidKey)?;
        mac.update(&canonical);
        self.hmac = encode_hex(&mac.finalize().into_bytes());
        Ok(())
    }

    /// Verifies the stored authentication tag against the supplied key.
    ///
    /// # Errors
    ///
    /// Returns [`StateAuthError`] for an empty key, malformed tag, or encoding failure.
    pub fn verify(&self, key: &[u8]) -> Result<bool, StateAuthError> {
        validate_key(key)?;
        let expected = decode_hex(&self.hmac)?;
        let canonical = self.canonical_bytes()?;
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| StateAuthError::InvalidKey)?;
        mac.update(&canonical);
        Ok(mac.verify_slice(&expected).is_ok())
    }
}

fn validate_key(key: &[u8]) -> Result<(), StateAuthError> {
    if key.is_empty() {
        Err(StateAuthError::InvalidKey)
    } else {
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, StateAuthError> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(StateAuthError::InvalidHex);
    }

    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or(StateAuthError::InvalidHex)?;
            let low = hex_digit(pair[1]).ok_or(StateAuthError::InvalidHex)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AssetSummary, ServiceState, SyncResult};

    fn sample_state() -> ServiceState {
        ServiceState {
            last_sync_time: Some(String::from("2025-01-01T00:00:00Z")),
            last_sync_result: Some(SyncResult::Success),
            matched_asset: Some(AssetSummary {
                id: 42,
                name: String::from("Laptop"),
                serial: Some(String::from("SERIAL-42")),
                asset_tag: Some(String::from("ASSET-42")),
            }),
            known_monitors: Vec::new(),
            hmac: String::new(),
        }
    }

    #[test]
    fn canonical_bytes_exclude_and_ignore_hmac() {
        let mut first_state = sample_state();
        let mut second_state = sample_state();
        first_state.hmac = String::from("first");
        second_state.hmac = String::from("second");

        let first = first_state.canonical_bytes().ok();
        let second = second_state.canonical_bytes().ok();
        assert!(first.is_some());
        assert_eq!(first, second);
    }

    #[test]
    fn sign_and_verify() {
        let mut state = sample_state();
        assert!(state.sign(b"correct-key").is_ok());
        assert!(!state.hmac.is_empty());
        assert!(matches!(state.verify(b"correct-key"), Ok(true)));
    }

    #[test]
    fn tampering_fails_verification() {
        let mut state = sample_state();
        assert!(state.sign(b"correct-key").is_ok());
        state.last_sync_time = Some(String::from("2025-01-02T00:00:00Z"));
        assert!(matches!(state.verify(b"correct-key"), Ok(false)));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let mut state = sample_state();
        assert!(state.sign(b"correct-key").is_ok());
        assert!(matches!(state.verify(b"wrong-key"), Ok(false)));
    }

    #[test]
    fn missing_newer_fields_use_defaults() {
        let parsed: Result<ServiceState, _> = serde_json::from_str(r#"{"hmac":""}"#);
        assert!(parsed.is_ok());
        if let Ok(state) = parsed {
            assert!(state.last_sync_time.is_none());
            assert!(state.last_sync_result.is_none());
            assert!(state.matched_asset.is_none());
            assert!(state.known_monitors.is_empty());
            assert!(state.hmac.is_empty());
        }
    }
}
