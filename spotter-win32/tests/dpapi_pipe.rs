#![cfg(windows)]

use anyhow::Result;

#[test]
fn dpapi_roundtrip_preserves_utf8_token() -> Result<()> {
    let plaintext = "SnipeSpotter test token";
    let ciphertext = spotter_win32::dpapi::encrypt(plaintext.as_bytes())?;

    assert!(!ciphertext.is_empty());
    assert_ne!(ciphertext, plaintext.as_bytes());
    assert_eq!(
        spotter_win32::dpapi::decrypt(&ciphertext)?,
        plaintext.as_bytes()
    );
    Ok(())
}

#[test]
fn dpapi_rejects_corrupt_truncated_and_random_ciphertext() -> Result<()> {
    let ciphertext = spotter_win32::dpapi::encrypt(b"token")?;
    let mut corrupt = ciphertext.clone();
    corrupt[0] ^= 0xFF;
    assert!(spotter_win32::dpapi::decrypt(&corrupt).is_err());
    assert!(spotter_win32::dpapi::decrypt(&ciphertext[..ciphertext.len() - 1]).is_err());
    assert!(spotter_win32::dpapi::decrypt(&[0x01, 0x02, 0x03, 0x04]).is_err());
    Ok(())
}

#[test]
fn dpapi_preserves_invalid_utf8_as_bytes_for_config_layer() -> Result<()> {
    let ciphertext = spotter_win32::dpapi::encrypt(&[0xFF, 0xFE])?;
    assert_eq!(spotter_win32::dpapi::decrypt(&ciphertext)?, [0xFF, 0xFE]);
    Ok(())
}
