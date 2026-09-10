// pattern: Functional Core

//! Configuration types and pure validation helpers for `SnipeSpotter`.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Settings file template shipped for first-run configuration.
pub const BLANK_SETTINGS_TOML: &str = r#"[snipeit]
url = ""
api_token_encrypted = ""
checkout_status_id = 0
checkin_status_id = 0

[polling]
interval_hours = 4

[logging]
level = "info"
max_size_mb = 10
max_files = 5

[monitors]
checkin_policy = "manual"
checkin_threshold_hours = 24
"#;

/// Complete application settings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub snipeit: SnipeItSettings,
    pub polling: PollingSettings,
    pub logging: LoggingSettings,
    pub monitors: MonitorSettings,
}

/// Snipe-IT connection and status settings.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnipeItSettings {
    pub url: String,
    #[serde(with = "base64_bytes")]
    pub api_token_encrypted: Vec<u8>,
    pub checkout_status_id: u64,
    pub checkin_status_id: u64,
}

/// Polling schedule settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PollingSettings {
    pub interval_hours: u64,
}

impl Default for PollingSettings {
    fn default() -> Self {
        Self { interval_hours: 4 }
    }
}

/// Log rotation settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingSettings {
    pub level: String,
    pub max_size_mb: u64,
    pub max_files: u32,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: String::from("info"),
            max_size_mb: 10,
            max_files: 5,
        }
    }
}

/// Monitor check-in policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckinPolicy {
    #[default]
    Manual,
    AutoNonPortable,
}

/// Monitor behavior settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorSettings {
    pub checkin_policy: CheckinPolicy,
    pub checkin_threshold_hours: u64,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            checkin_policy: CheckinPolicy::Manual,
            checkin_threshold_hours: 24,
        }
    }
}

/// A value-level settings validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SettingsValidationError {
    #[error("invalid Snipe-IT URL")]
    SnipeItUrl,
    #[error("partial Snipe-IT identity")]
    SnipeItPartialIdentity,
    #[error("invalid Snipe-IT status ID")]
    SnipeItStatusId,
    #[error("invalid polling interval")]
    PollingInterval,
    #[error("invalid logging level")]
    LoggingLevel,
    #[error("invalid logging size limit")]
    LoggingMaxSize,
    #[error("invalid logging file limit")]
    LoggingMaxFiles,
    #[error("invalid monitor check-in threshold")]
    CheckinThreshold,
}

/// Validate settings loaded from disk or assembled as an activation candidate.
///
/// Blank Snipe-IT fields are accepted for the installer-created unconfigured state. A candidate
/// may be a staged partial identity only while it is still unconfigured as a whole
/// ([`config_status`] nonempty); each supplied field must already satisfy its own bounds and a
/// nonblank URL must parse as an HTTP(S) URL. Completing the identity activates the full
/// blank-or-complete contract: a candidate with no missing required settings must have a valid,
/// complete identity. Staged persistence never activates: callers keep the service
/// Unconfigured until the candidate is complete.
///
/// # Errors
/// Returns a fixed, value-free category for the first invalid setting.
/// Validate a supplied Snipe-IT endpoint without contacting it.
///
/// The endpoint must be an HTTPS URL with a valid authority, no credentials, query, or fragment.
/// Empty input is accepted by this field-level helper so staged installer settings remain valid.
///
/// # Errors
///
/// Returns [`SettingsValidationError::SnipeItUrl`] when the supplied endpoint violates the policy.
pub fn validate_snipeit_url(value: &str) -> Result<(), SettingsValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return Err(SettingsValidationError::SnipeItUrl);
    };
    if scheme != "https"
        || remainder.is_empty()
        || remainder
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SettingsValidationError::SnipeItUrl);
    }
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || remainder[authority_end..].contains(['?', '#']) {
        return Err(SettingsValidationError::SnipeItUrl);
    }
    if authority.contains('@') {
        return Err(SettingsValidationError::SnipeItUrl);
    }
    let host_and_port = if let Some(rest) = authority.strip_prefix('[') {
        let Some(closing_bracket) = rest.find(']') else {
            return Err(SettingsValidationError::SnipeItUrl);
        };
        let host = &rest[..closing_bracket];
        if host.parse::<std::net::Ipv6Addr>().is_err() || host.is_empty() {
            return Err(SettingsValidationError::SnipeItUrl);
        }
        let suffix = &rest[closing_bracket + 1..];
        if !suffix.is_empty() && !suffix.strip_prefix(':').is_some_and(is_valid_port) {
            return Err(SettingsValidationError::SnipeItUrl);
        }
        return Ok(());
    } else {
        authority
    };
    if let Some((host, port)) = host_and_port.rsplit_once(':') {
        if host.is_empty() || host.contains(':') || !is_valid_port(port) {
            return Err(SettingsValidationError::SnipeItUrl);
        }
    }
    if host_and_port.starts_with(':') || host_and_port.ends_with(':') {
        return Err(SettingsValidationError::SnipeItUrl);
    }
    if host_and_port.contains(':') {
        return Err(SettingsValidationError::SnipeItUrl);
    }
    Ok(())
}

pub fn validate_settings(settings: &Settings) -> Result<(), SettingsValidationError> {
    let url = settings.snipeit.url.trim();
    let token_is_blank = settings.snipeit.api_token_encrypted.is_empty();
    let statuses_are_blank =
        settings.snipeit.checkout_status_id == 0 && settings.snipeit.checkin_status_id == 0;
    let identity_is_blank = url.is_empty() && token_is_blank && statuses_are_blank;
    let identity_is_complete = !url.is_empty()
        && !token_is_blank
        && settings.snipeit.checkout_status_id != 0
        && settings.snipeit.checkin_status_id != 0;
    if identity_is_complete {
        validate_snipeit_url(url)?;
    } else if !identity_is_blank && config_status(settings).is_empty() {
        // An activation candidate (no missing required settings) can no longer be
        // partial; this branch is unreachable by construction but stays as a
        // defense-in-depth guard for future field additions.
        return Err(SettingsValidationError::SnipeItPartialIdentity);
    }
    validate_snipeit_url(url)?;
    if !(1..=168).contains(&settings.polling.interval_hours) {
        return Err(SettingsValidationError::PollingInterval);
    }
    if !matches!(
        settings.logging.level.as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        return Err(SettingsValidationError::LoggingLevel);
    }
    if !(1..=10_240).contains(&settings.logging.max_size_mb) {
        return Err(SettingsValidationError::LoggingMaxSize);
    }
    if !(1..=1_000).contains(&settings.logging.max_files) {
        return Err(SettingsValidationError::LoggingMaxFiles);
    }
    if !(1..=8_760).contains(&settings.monitors.checkin_threshold_hours) {
        return Err(SettingsValidationError::CheckinThreshold);
    }
    Ok(())
}

fn is_valid_port(port: &str) -> bool {
    // Reject empty ports and reject port 0; the remaining digits must parse as
    // a u16 so ports like 65536 or 999999999 fail closed.
    match port.parse::<u16>() {
        Ok(parsed) => parsed != 0,
        Err(_) => false,
    }
}

/// Convert a polling interval to a duration without overflowing.
#[must_use]
pub fn poll_duration(interval_hours: u64) -> Option<Duration> {
    interval_hours.checked_mul(60 * 60).map(Duration::from_secs)
}

/// Return required settings that still contain their invalid defaults.
#[must_use]
pub fn config_status(settings: &Settings) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if settings.snipeit.url.trim().is_empty() {
        missing.push("snipeit.url");
    }
    if settings.snipeit.api_token_encrypted.is_empty() {
        missing.push("snipeit.api_token_encrypted");
    }
    if settings.snipeit.checkout_status_id == 0 {
        missing.push("snipeit.checkout_status_id");
    }
    if settings.snipeit.checkin_status_id == 0 {
        missing.push("snipeit.checkin_status_id");
    }
    missing
}

/// Serialize encrypted token bytes as standard base64.
mod base64_bytes {
    use super::BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        BASE64
            .decode(encoded)
            .map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_settings() -> Settings {
        Settings {
            snipeit: SnipeItSettings {
                url: String::from("https://snipe-it.example.com"),
                api_token_encrypted: b"secret".to_vec(),
                checkout_status_id: 1,
                checkin_status_id: 2,
            },
            ..Settings::default()
        }
    }

    #[test]
    fn defaults_match_contract() -> Result<(), Box<dyn std::error::Error>> {
        let settings = Settings::default();
        assert_eq!(settings.polling.interval_hours, 4);
        assert_eq!(settings.logging.level, "info");
        assert_eq!(settings.monitors.checkin_policy, CheckinPolicy::Manual);
        assert_eq!(settings.monitors.checkin_threshold_hours, 24);
        assert_eq!(
            serde_json::to_value(CheckinPolicy::AutoNonPortable)?,
            serde_json::json!("auto_non_portable")
        );
        Ok(())
    }

    #[test]
    fn config_status_reports_required_defaults() {
        assert_eq!(
            config_status(&Settings::default()),
            vec![
                "snipeit.url",
                "snipeit.api_token_encrypted",
                "snipeit.checkout_status_id",
                "snipeit.checkin_status_id",
            ]
        );
        assert!(config_status(&complete_settings()).is_empty());
    }

    #[test]
    fn token_serializes_as_base64() -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&complete_settings())?;
        assert!(json.contains("api_token_encrypted\":\"c2VjcmV0\""));
        let parsed: Settings = serde_json::from_str(&json)?;
        assert_eq!(parsed.snipeit.api_token_encrypted, b"secret".to_vec());
        Ok(())
    }

    #[test]
    fn blank_template_has_exact_tables() -> Result<(), Box<dyn std::error::Error>> {
        let parsed: Settings = toml::from_str(BLANK_SETTINGS_TOML)?;
        assert_eq!(parsed, Settings::default());
        assert!(BLANK_SETTINGS_TOML.contains("[snipeit]"));
        assert!(BLANK_SETTINGS_TOML.contains("[polling]"));
        assert!(BLANK_SETTINGS_TOML.contains("[logging]"));
        assert!(BLANK_SETTINGS_TOML.contains("[monitors]"));
        assert!(BLANK_SETTINGS_TOML.contains("checkin_policy = \"manual\""));
        Ok(())
    }

    #[test]
    fn old_settings_with_missing_sections_use_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let settings: Settings = toml::from_str(
            r#"[snipeit]
url = "https://snipe-it.example.com"
api_token_encrypted = "c2VjcmV0"
checkout_status_id = 1
checkin_status_id = 2
"#,
        )?;
        assert_eq!(settings.snipeit.url, "https://snipe-it.example.com");
        assert_eq!(settings.polling, PollingSettings::default());
        assert_eq!(settings.logging, LoggingSettings::default());
        assert_eq!(settings.monitors, MonitorSettings::default());
        Ok(())
    }

    #[test]
    fn partial_section_settings_fill_field_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let settings: Settings = toml::from_str(
            r"[polling]
interval_hours = 12
",
        )?;
        assert_eq!(settings.polling.interval_hours, 12);
        assert_eq!(settings.logging, LoggingSettings::default());
        assert_eq!(settings.monitors, MonitorSettings::default());
        assert!(settings.snipeit.url.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_nested_settings_rejected() {
        for text in [
            "future_option = true",
            "[snipeit]\nfuture_option = true",
            "[polling]\nfuture_option = true",
            "[logging]\nfuture_retention_mode = \"size\"",
            "[monitors]\nfuture_option = true",
        ] {
            assert!(
                toml::from_str::<Settings>(text).is_err(),
                "accepted {text:?}"
            );
        }
    }

    #[test]
    fn settings_load_validation_matrix() {
        let mut settings = complete_settings();
        assert_eq!(validate_settings(&settings), Ok(()));

        settings.polling.interval_hours = 0;
        assert_eq!(
            validate_settings(&settings),
            Err(SettingsValidationError::PollingInterval)
        );
        settings.polling.interval_hours = 169;
        assert_eq!(
            validate_settings(&settings),
            Err(SettingsValidationError::PollingInterval)
        );
        settings.polling.interval_hours = 4;
        settings.logging.level = String::from("verbose");
        assert_eq!(
            validate_settings(&settings),
            Err(SettingsValidationError::LoggingLevel)
        );
        settings.logging.level = String::from("info");
        settings.logging.max_size_mb = 0;
        assert_eq!(
            validate_settings(&settings),
            Err(SettingsValidationError::LoggingMaxSize)
        );
        settings.logging.max_size_mb = 10;
        settings.logging.max_files = 0;
        assert_eq!(
            validate_settings(&settings),
            Err(SettingsValidationError::LoggingMaxFiles)
        );
        settings.logging.max_files = 5;
        settings.monitors.checkin_threshold_hours = 0;
        assert_eq!(
            validate_settings(&settings),
            Err(SettingsValidationError::CheckinThreshold)
        );
    }

    #[test]
    fn blank_installer_settings_remain_configurable() {
        assert_eq!(validate_settings(&Settings::default()), Ok(()));
    }

    #[test]
    fn settings_partial_identity_rejected_at_activation() {
        let mut cases = Vec::new();

        let mut url_only = Settings::default();
        url_only.snipeit.url = String::from("https://snipe-it.example.com");
        cases.push(url_only);

        let mut token_only = Settings::default();
        token_only.snipeit.api_token_encrypted = b"secret".to_vec();
        cases.push(token_only);

        let mut status_only = Settings::default();
        status_only.snipeit.checkout_status_id = 1;
        status_only.snipeit.checkin_status_id = 2;
        cases.push(status_only);

        let mut url_and_token = Settings::default();
        url_and_token.snipeit.url = String::from("https://snipe-it.example.com");
        url_and_token.snipeit.api_token_encrypted = b"secret".to_vec();
        cases.push(url_and_token);

        // Staged partial identities are valid only while the candidate remains
        // unconfigured (missing required settings); they must never activate.
        for settings in &cases {
            assert!(
                !config_status(settings).is_empty(),
                "staged identity unexpectedly complete: {settings:?}"
            );
            assert_eq!(
                validate_settings(settings),
                Ok(()),
                "staged identity must persist while unconfigured: {settings:?}"
            );
        }
    }

    #[test]
    fn settings_partial_identity_cannot_activate() {
        // A candidate with no missing required settings must be complete and
        // valid; any future field addition that makes config_status empty while
        // identity stays partial must fail closed.
        let mut settings = complete_settings();
        assert!(config_status(&settings).is_empty());
        assert_eq!(validate_settings(&settings), Ok(()));
        settings.snipeit.api_token_encrypted = Vec::new();
        assert!(!config_status(&settings).is_empty());
    }

    #[test]
    fn settings_malformed_url_rejected() {
        for url in [
            "https://",
            "http://",
            "https:///missing-host",
            "https://host with spaces",
            "https://host:abc",
            "https://host:",
            "https://host:0",
            "https://host:65536",
            "https://host:99999999999",
            "https://user:password@host.example",
            "https://host.example/path?query=secret",
            "https://host.example/path#fragment",
            "https://[not-an-ipv6-address]",
            "https://host:443:444",
            "ftp://snipe-it.example.com",
        ] {
            let mut settings = complete_settings();
            settings.snipeit.url = String::from(url);
            assert_eq!(
                validate_settings(&settings),
                Err(SettingsValidationError::SnipeItUrl),
                "accepted malformed Snipe-IT URL: {url:?}"
            );
        }
    }

    #[test]
    fn poll_duration_checked() {
        assert_eq!(
            poll_duration(4),
            Some(std::time::Duration::from_secs(14_400))
        );
        assert_eq!(poll_duration(u64::MAX), None);
    }
}
