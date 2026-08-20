// pattern: Imperative Shell

//! Signed service-state and HMAC-key persistence.

use std::{fs, path::Path, sync::Mutex};

use anyhow::{Result, bail};
use getrandom::fill as random_fill;
use spotter_core::state::ServiceState;

static STATE_MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// Load or create a 32-byte state authentication key.
///
/// # Errors
/// Returns an error for file or random-source failures.
pub fn load_or_create_key(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        let key = fs::read(path)?;
        if key.len() != 32 {
            bail!("state HMAC key has invalid length")
        }
        return Ok(key);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut key = vec![0_u8; 32];
    random_fill(&mut key)
        .map_err(|error| anyhow::anyhow!("failed to generate state HMAC key: {error}"))?;
    atomic_write(path, &key)?;
    Ok(key)
}

/// Load and verify signed state. Missing state returns the default.
///
/// # Errors
/// Returns an error for malformed, unreadable, or unauthenticated state.
pub fn load_state(path: &Path, key: &[u8]) -> Result<ServiceState> {
    if !path.exists() {
        return Ok(ServiceState::default());
    }
    let state: ServiceState = toml::from_str(&fs::read_to_string(path)?)?;
    if !state.verify(key)? {
        bail!("service state authentication failed")
    }
    Ok(state)
}

/// Sign and atomically replace state under the mutation lock.
///
/// # Errors
/// Returns an error for signing, serialization, lock poisoning, or replacement failure.
pub fn save_state(path: &Path, state: &mut ServiceState, key: &[u8]) -> Result<()> {
    let _guard = STATE_MUTATION_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("state mutation lock poisoned"))?;
    state.sign(key)?;
    atomic_write(path, toml::to_string_pretty(state)?.as_bytes())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::atomic_file::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_and_signed_state_roundtrip() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let key = load_or_create_key(&dir.path().join("key.bin"))?;
        let path = dir.path().join("state.toml");
        let mut state = ServiceState {
            last_sync_time: Some(String::from("2026-01-01T00:00:00Z")),
            ..ServiceState::default()
        };
        save_state(&path, &mut state, &key)?;
        assert_eq!(
            load_state(&path, &key)?.last_sync_time,
            state.last_sync_time
        );
        let mut bytes = fs::read(&path)?;
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        fs::write(&path, bytes)?;
        assert!(load_state(&path, &key).is_err());
        Ok(())
    }

    #[test]
    fn missing_state_defaults_and_invalid_key_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state_path = dir.path().join("state.toml");
        let state = load_state(&state_path, &[1; 32])?;
        assert!(state.last_sync_time.is_none());
        assert!(state.known_monitors.is_empty());
        let key_path = dir.path().join("key.bin");
        fs::write(&key_path, [0_u8; 31])?;
        assert!(load_or_create_key(&key_path).is_err());
        Ok(())
    }

    #[test]
    fn malformed_state_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.toml");
        fs::write(&path, b"not = [valid")?;
        assert!(load_state(&path, &[1; 32]).is_err());
        Ok(())
    }
}
