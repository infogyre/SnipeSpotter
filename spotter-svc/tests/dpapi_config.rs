#![cfg(windows)]

use anyhow::Result;
use secrecy::ExposeSecret;

#[test]
fn decrypt_config_roundtrips_fields_and_token_without_exposing_ciphertext() -> Result<()> {
    let token = b"config-test-token";
    let ciphertext = spotter_win32::dpapi::encrypt(token)?;
    let settings = spotter_core::Settings {
        snipeit: spotter_core::config::SnipeItSettings {
            url: String::from("https://example.test"),
            api_token_encrypted: ciphertext.clone(),
            checkout_status_id: 11,
            checkin_status_id: 12,
        },
        ..spotter_core::Settings::default()
    };

    let decrypted = spotter_svc::config_io::decrypt_config(&settings)?;
    assert_eq!(decrypted.url, "https://example.test");
    assert_eq!(decrypted.api_token.expose_secret(), "config-test-token");
    assert_eq!(decrypted.checkout_status_id, 11);
    assert_eq!(decrypted.checkin_status_id, 12);
    let display = spotter_svc::config_io::censored_display(&settings);
    let rendered = format!("{display:?}");
    assert!(!rendered.contains("config-test-token"));
    assert!(!rendered.contains(&format!("{ciphertext:?}")));
    Ok(())
}

#[test]
fn decrypt_config_rejects_dpapi_encrypted_invalid_utf8_without_leaking_bytes() -> Result<()> {
    let plaintext = [0xFF, 0xFE, 0xFD];
    let ciphertext = spotter_win32::dpapi::encrypt(&plaintext)?;
    let settings = spotter_core::Settings {
        snipeit: spotter_core::config::SnipeItSettings {
            api_token_encrypted: ciphertext.clone(),
            ..spotter_core::config::SnipeItSettings::default()
        },
        ..spotter_core::Settings::default()
    };

    let error = spotter_svc::config_io::decrypt_config(&settings)
        .expect_err("invalid decrypted UTF-8 must be rejected");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("not UTF-8"));
    assert!(!rendered.contains("config-test-token"));
    assert!(!rendered.contains(&format!("{ciphertext:?}")));
    Ok(())
}
