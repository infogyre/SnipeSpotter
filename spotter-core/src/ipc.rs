// pattern: Functional Core

//! JSON-over-newline IPC protocol and pure client-side validation.

use serde::{Deserialize, Serialize};

use crate::{
    config::{CheckinPolicy, Settings},
    state::AssetSummary,
};

/// Maximum accepted IPC request or response line length.
pub const IPC_MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ServiceCommand {
    GetConfig,
    SetConfig { field: String, value: String },
    SetToken { value: String },
    GetStatus,
    GetStatusFull,
    TriggerSync,
    CheckinAll,
    CheckinSerial { serial: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckinEntry {
    pub serial: String,
    pub asset_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MonitorStatus {
    pub serial: String,
    pub asset_id: Option<u64>,
    pub checked_out: bool,
    pub absent_since: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    Config {
        settings: Settings,
        missing: Vec<String>,
    },
    Status {
        state: String,
        last_sync: Option<String>,
        next_sync: Option<String>,
        snipeit_url: String,
    },
    StatusFull {
        state: String,
        last_sync: Option<String>,
        next_sync: Option<String>,
        snipeit_url: String,
        matched_asset: Option<AssetSummary>,
        monitors: Vec<MonitorStatus>,
    },
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
    CheckinResult {
        checked_in: Vec<CheckinEntry>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "field", rename_all = "snake_case")]
pub enum SettingsUpdate {
    #[serde(rename = "snipeit.url")]
    SnipeItUrl { value: String },
    #[serde(rename = "snipeit.checkout_status_id")]
    CheckoutStatusId { value: u64 },
    #[serde(rename = "snipeit.checkin_status_id")]
    CheckinStatusId { value: u64 },
    #[serde(rename = "polling.interval_hours")]
    PollingIntervalHours { value: u64 },
    #[serde(rename = "logging.level")]
    LoggingLevel { value: String },
    #[serde(rename = "logging.max_size_mb")]
    LoggingMaxSizeMb { value: u64 },
    #[serde(rename = "logging.max_files")]
    LoggingMaxFiles { value: u32 },
    #[serde(rename = "monitors.checkin_policy")]
    MonitorCheckinPolicy { value: CheckinPolicy },
    #[serde(rename = "monitors.checkin_threshold_hours")]
    MonitorCheckinThresholdHours { value: u64 },
}

/// Parse and validate a dotted configuration field update.
///
/// # Errors
///
/// Returns a human-readable message for unknown fields or invalid values.
pub fn validate_config_field(field: &str, value: &str) -> Result<SettingsUpdate, String> {
    match field {
        "snipeit.url" => validate_url(value).map(|()| SettingsUpdate::SnipeItUrl {
            value: value.to_owned(),
        }),
        "snipeit.checkout_status_id" => {
            parse_u64(value, 1, u64::MAX).map(|value| SettingsUpdate::CheckoutStatusId { value })
        }
        "snipeit.checkin_status_id" => {
            parse_u64(value, 1, u64::MAX).map(|value| SettingsUpdate::CheckinStatusId { value })
        }
        "polling.interval_hours" => {
            parse_u64(value, 1, 168).map(|value| SettingsUpdate::PollingIntervalHours { value })
        }
        "logging.level" if matches!(value, "trace" | "debug" | "info" | "warn" | "error") => {
            Ok(SettingsUpdate::LoggingLevel {
                value: value.to_owned(),
            })
        }
        "logging.level" => Err(String::from(
            "logging.level must be trace, debug, info, warn, or error",
        )),
        "logging.max_size_mb" => {
            parse_u64(value, 1, 10_240).map(|value| SettingsUpdate::LoggingMaxSizeMb { value })
        }
        "logging.max_files" => {
            parse_u32(value, 1, 1_000).map(|value| SettingsUpdate::LoggingMaxFiles { value })
        }
        "monitors.checkin_policy" => match value {
            "manual" => Ok(SettingsUpdate::MonitorCheckinPolicy {
                value: CheckinPolicy::Manual,
            }),
            "auto_non_portable" => Ok(SettingsUpdate::MonitorCheckinPolicy {
                value: CheckinPolicy::AutoNonPortable,
            }),
            _ => Err(String::from(
                "monitors.checkin_policy must be manual or auto_non_portable",
            )),
        },
        "monitors.checkin_threshold_hours" => parse_u64(value, 1, 8_760)
            .map(|value| SettingsUpdate::MonitorCheckinThresholdHours { value }),
        "snipeit.api_token_encrypted" => Err(String::from(
            "use the set-token command to update the API token",
        )),
        _ => Err(format!("unknown configuration field: {field}")),
    }
}

/// Return settings with one validated typed update applied.
#[must_use]
pub fn apply_settings_update(settings: &Settings, update: &SettingsUpdate) -> Settings {
    let mut updated = settings.clone();
    match update {
        SettingsUpdate::SnipeItUrl { value } => updated.snipeit.url.clone_from(value),
        SettingsUpdate::CheckoutStatusId { value } => {
            updated.snipeit.checkout_status_id = *value;
        }
        SettingsUpdate::CheckinStatusId { value } => {
            updated.snipeit.checkin_status_id = *value;
        }
        SettingsUpdate::PollingIntervalHours { value } => {
            updated.polling.interval_hours = *value;
        }
        SettingsUpdate::LoggingLevel { value } => updated.logging.level.clone_from(value),
        SettingsUpdate::LoggingMaxSizeMb { value } => updated.logging.max_size_mb = *value,
        SettingsUpdate::LoggingMaxFiles { value } => updated.logging.max_files = *value,
        SettingsUpdate::MonitorCheckinPolicy { value } => {
            updated.monitors.checkin_policy = *value;
        }
        SettingsUpdate::MonitorCheckinThresholdHours { value } => {
            updated.monitors.checkin_threshold_hours = *value;
        }
    }
    updated
}

/// Clone settings with encrypted token material removed.
#[must_use]
pub fn redact_settings(settings: &Settings) -> Settings {
    let mut redacted = settings.clone();
    redacted.snipeit.api_token_encrypted.clear();
    redacted
}

fn validate_url(value: &str) -> Result<(), String> {
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| String::from("snipeit.url must use http or https"))?;
    if authority.is_empty()
        || authority.starts_with('/')
        || authority.chars().any(char::is_whitespace)
    {
        return Err(String::from("snipeit.url must include a valid host"));
    }
    Ok(())
}

fn parse_u64(value: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| String::from("value must be an unsigned integer"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!("value must be between {minimum} and {maximum}"));
    }
    Ok(parsed)
}

fn parse_u32(value: &str, minimum: u32, maximum: u32) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| String::from("value must be an unsigned integer"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!("value must be between {minimum} and {maximum}"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_and_responses_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let commands = [
            ServiceCommand::GetConfig,
            ServiceCommand::SetConfig {
                field: String::from("polling.interval_hours"),
                value: String::from("4"),
            },
            ServiceCommand::SetToken {
                value: String::from("secret"),
            },
            ServiceCommand::GetStatus,
            ServiceCommand::GetStatusFull,
            ServiceCommand::TriggerSync,
            ServiceCommand::CheckinAll,
            ServiceCommand::CheckinSerial {
                serial: String::from("MON"),
            },
        ];
        for command in commands {
            let json = serde_json::to_string(&command)?;
            assert_eq!(serde_json::from_str::<ServiceCommand>(&json)?, command);
        }
        let response = IpcResponse::CheckinResult {
            checked_in: vec![CheckinEntry {
                serial: String::from("MON"),
                asset_id: 1,
            }],
        };
        let json = serde_json::to_string(&response)?;
        assert_eq!(serde_json::from_str::<IpcResponse>(&json)?, response);
        Ok(())
    }

    #[test]
    fn validates_boundaries_and_rejects_secret_field() {
        assert!(validate_config_field("snipeit.url", "https://example.test").is_ok());
        assert!(validate_config_field("snipeit.url", "ftp://example.test").is_err());
        assert!(validate_config_field("polling.interval_hours", "1").is_ok());
        assert!(validate_config_field("polling.interval_hours", "168").is_ok());
        assert!(validate_config_field("polling.interval_hours", "0").is_err());
        assert!(validate_config_field("polling.interval_hours", "169").is_err());
        assert!(validate_config_field("logging.level", "verbose").is_err());
        assert!(validate_config_field("monitors.checkin_policy", "auto_non_portable").is_ok());
        assert!(validate_config_field("snipeit.api_token_encrypted", "secret").is_err());
        assert!(validate_config_field("unknown", "x").is_err());
    }

    #[test]
    fn typed_update_returns_changed_clone() {
        let settings = Settings::default();
        let updated = apply_settings_update(
            &settings,
            &SettingsUpdate::PollingIntervalHours { value: 12 },
        );
        assert_eq!(updated.polling.interval_hours, 12);
        assert_eq!(settings.polling.interval_hours, 4);

        let updated = apply_settings_update(
            &updated,
            &SettingsUpdate::MonitorCheckinPolicy {
                value: CheckinPolicy::AutoNonPortable,
            },
        );
        assert_eq!(
            updated.monitors.checkin_policy,
            CheckinPolicy::AutoNonPortable
        );
    }

    #[test]
    fn redaction_removes_ciphertext_without_mutating_source() {
        let mut settings = Settings::default();
        settings.snipeit.api_token_encrypted = vec![1, 2, 3];
        let redacted = redact_settings(&settings);
        assert!(redacted.snipeit.api_token_encrypted.is_empty());
        assert_eq!(settings.snipeit.api_token_encrypted, vec![1, 2, 3]);
    }
}
