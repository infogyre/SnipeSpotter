// pattern: Functional Core

//! Pure field selection and terminal rendering for the CLI.

use std::fmt::Write as _;

use anyhow::{Result, bail};
use serde_json::Value;
use spotter_core::ipc::{IpcResponse, MonitorStatus};
use spotter_core::{CheckinPolicy, Settings};

const SELECTABLE_FIELDS: [&str; 9] = [
    "snipeit.url",
    "snipeit.checkout_status_id",
    "snipeit.checkin_status_id",
    "polling.interval_hours",
    "logging.level",
    "logging.max_size_mb",
    "logging.max_files",
    "monitors.checkin_policy",
    "monitors.checkin_threshold_hours",
];

/// Validate a client-side config selector without exposing arbitrary input.
pub fn validate_selector(selector: &str) -> Result<()> {
    if SELECTABLE_FIELDS.contains(&selector) {
        return Ok(());
    }
    if selector == "snipeit.api_token_encrypted" {
        bail!("use the set-token command to update the API token")
    }
    bail!("unknown configuration field")
}

/// Select one non-secret setting as a typed JSON scalar.
///
/// # Errors
/// Returns an error when `selector` is not one of the nine selectable fields.
pub fn select_setting(settings: &Settings, selector: &str) -> Result<Value> {
    validate_selector(selector)?;
    let value = match selector {
        "snipeit.url" => Value::String(settings.snipeit.url.clone()),
        "snipeit.checkout_status_id" => Value::from(settings.snipeit.checkout_status_id),
        "snipeit.checkin_status_id" => Value::from(settings.snipeit.checkin_status_id),
        "polling.interval_hours" => Value::from(settings.polling.interval_hours),
        "logging.level" => Value::String(settings.logging.level.clone()),
        "logging.max_size_mb" => Value::from(settings.logging.max_size_mb),
        "logging.max_files" => Value::from(settings.logging.max_files),
        "monitors.checkin_policy" => {
            Value::String(String::from(match settings.monitors.checkin_policy {
                CheckinPolicy::Manual => "manual",
                CheckinPolicy::AutoNonPortable => "auto_non_portable",
            }))
        }
        "monitors.checkin_threshold_hours" => {
            Value::from(settings.monitors.checkin_threshold_hours)
        }
        _ => unreachable!("validate_selector accepts only known selectors"),
    };
    Ok(value)
}

/// Render a redacted config response for a human terminal or JSON output.
pub fn render_config(
    settings: &Settings,
    missing: &[String],
    selector: Option<&str>,
    json: bool,
) -> Result<String> {
    if let Some(selector) = selector {
        let value = select_setting(settings, selector)?;
        if json {
            return serde_json::to_string_pretty(&value).map_err(Into::into);
        }
        return Ok(format!("{selector}: {}", human_json_scalar(&value)));
    }
    if json {
        let response = IpcResponse::Config {
            settings: spotter_core::ipc::redact_settings(settings),
            missing: missing.to_vec(),
        };
        return serde_json::to_string_pretty(&response).map_err(Into::into);
    }
    let mut output = String::new();
    for (field, value) in all_settings(settings) {
        output.push_str(field);
        output.push_str(": ");
        output.push_str(&escape_terminal(&value));
        output.push('\n');
    }
    output.push_str("missing: ");
    if missing.is_empty() {
        output.push_str("<none>");
    } else {
        let mut ordered_missing = missing.to_vec();
        ordered_missing.sort();
        for (index, field) in ordered_missing.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(&escape_terminal(field));
        }
    }
    Ok(output)
}

/// Render a status response with fixed ordering and explicit absent-value placeholders.
pub fn render_status(response: &IpcResponse, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(response).map_err(Into::into);
    }
    match response {
        IpcResponse::Status {
            state,
            last_sync,
            next_sync,
            snipeit_url,
        } => Ok(render_status_lines(
            state,
            snipeit_url,
            last_sync.as_deref(),
            next_sync.as_deref(),
            None,
            &[],
            false,
        )),
        IpcResponse::StatusFull {
            state,
            last_sync,
            next_sync,
            snipeit_url,
            matched_asset,
            monitors,
        } => Ok(render_status_lines(
            state,
            snipeit_url,
            last_sync.as_deref(),
            next_sync.as_deref(),
            matched_asset.as_ref(),
            monitors,
            true,
        )),
        _ => bail!("unexpected response for status command"),
    }
}

fn all_settings(settings: &Settings) -> [(&'static str, String); 9] {
    [
        ("snipeit.url", settings.snipeit.url.clone()),
        (
            "snipeit.checkout_status_id",
            settings.snipeit.checkout_status_id.to_string(),
        ),
        (
            "snipeit.checkin_status_id",
            settings.snipeit.checkin_status_id.to_string(),
        ),
        (
            "polling.interval_hours",
            settings.polling.interval_hours.to_string(),
        ),
        ("logging.level", settings.logging.level.clone()),
        (
            "logging.max_size_mb",
            settings.logging.max_size_mb.to_string(),
        ),
        ("logging.max_files", settings.logging.max_files.to_string()),
        (
            "monitors.checkin_policy",
            match settings.monitors.checkin_policy {
                CheckinPolicy::Manual => String::from("manual"),
                CheckinPolicy::AutoNonPortable => String::from("auto_non_portable"),
            },
        ),
        (
            "monitors.checkin_threshold_hours",
            settings.monitors.checkin_threshold_hours.to_string(),
        ),
    ]
}

fn render_status_lines(
    state: &str,
    snipeit_url: &str,
    last_sync: Option<&str>,
    next_sync: Option<&str>,
    matched_asset: Option<&spotter_core::state::AssetSummary>,
    monitors: &[MonitorStatus],
    full: bool,
) -> String {
    let mut output = format!(
        "State: {}\nSnipe-IT Instance: {}\nLast Sync: {}\nNext Sync: {}",
        escape_terminal(state),
        display_optional(snipeit_url),
        display_optional(last_sync.unwrap_or("")),
        display_optional(next_sync.unwrap_or("")),
    );
    if full {
        output.push_str("\nMatched Asset: ");
        if let Some(asset) = matched_asset {
            let _ = write!(
                output,
                "{} (ID {}, serial {}, asset tag {})",
                escape_terminal(&asset.name),
                asset.id,
                display_optional(asset.serial.as_deref().unwrap_or("")),
                display_optional(asset.asset_tag.as_deref().unwrap_or("")),
            );
        } else {
            output.push_str("<none>");
        }
        output.push_str("\nMonitors:");
        if monitors.is_empty() {
            output.push_str("\n  <none>");
        } else {
            let mut ordered = monitors.to_vec();
            ordered.sort_by(|left, right| left.serial.cmp(&right.serial));
            for monitor in ordered {
                let _ = write!(
                    output,
                    "\n  {}: asset {}, checked out {}, absent since {}",
                    escape_terminal(&monitor.serial),
                    monitor
                        .asset_id
                        .map_or_else(|| String::from("<none>"), |id| id.to_string()),
                    monitor.checked_out,
                    display_optional(monitor.absent_since.as_deref().unwrap_or("")),
                );
            }
        }
    }
    output
}

fn display_optional(value: &str) -> String {
    if value.is_empty() {
        String::from("<none>")
    } else {
        escape_terminal(value)
    }
}

fn escape_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn human_json_scalar(value: &Value) -> String {
    match value {
        Value::String(value) => escape_terminal(value),
        Value::Number(value) => value.to_string(),
        _ => String::from("<unsupported>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spotter_core::state::AssetSummary;

    fn settings() -> Settings {
        let mut settings = Settings::default();
        settings.snipeit.url = String::from("https://example.test/\u{1b}[31m");
        settings.snipeit.checkout_status_id = 11;
        settings.snipeit.checkin_status_id = 12;
        settings.polling.interval_hours = 7;
        settings.logging.level = String::from("debug\nnext");
        settings.logging.max_size_mb = 20;
        settings.logging.max_files = 4;
        settings.monitors.checkin_policy = CheckinPolicy::AutoNonPortable;
        settings.monitors.checkin_threshold_hours = 48;
        settings
    }

    #[test]
    fn cli_config_selection_matrix() {
        for field in SELECTABLE_FIELDS {
            assert!(validate_selector(field).is_ok());
        }
        assert_eq!(
            validate_selector("snipeit.api_token_encrypted")
                .expect_err("encrypted token selector must fail")
                .to_string(),
            "use the set-token command to update the API token"
        );
        assert_eq!(
            validate_selector("logging.level\u{1b}[31m")
                .expect_err("unknown selector must fail")
                .to_string(),
            "unknown configuration field"
        );
    }

    #[test]
    fn cli_json_backward_compatibility_and_typed_scalars() -> Result<()> {
        assert_eq!(
            select_setting(&settings(), "snipeit.url")?,
            Value::String(String::from("https://example.test/\u{1b}[31m"))
        );
        assert_eq!(
            select_setting(&settings(), "polling.interval_hours")?,
            Value::from(7)
        );
        assert_eq!(
            select_setting(&settings(), "monitors.checkin_policy")?,
            Value::String(String::from("auto_non_portable"))
        );
        Ok(())
    }

    #[test]
    fn cli_human_config_output_is_complete_and_deterministic() -> Result<()> {
        let settings = settings();
        let json = render_config(&settings, &[String::from("snipeit.url")], None, true)?;
        let value: Value = serde_json::from_str(&json)?;
        assert_eq!(value["type"], "config");
        assert_eq!(
            value["data"]["settings"]["snipeit"]["api_token_encrypted"],
            ""
        );
        assert_eq!(value["data"]["missing"][0], "snipeit.url");

        let human = render_config(&settings, &[], None, false)?;
        assert!(human.contains("snipeit.url: https://example.test/\\u{1b}[31m"));
        assert!(human.contains("logging.level: debug\\nnext"));
        assert!(human.ends_with("missing: <none>"));
        Ok(())
    }

    #[test]
    fn cli_human_status_full_matrix() -> Result<()> {
        let response = IpcResponse::StatusFull {
            state: String::from("Sync\u{1b}[31ming"),
            last_sync: None,
            next_sync: Some(String::from("2026-01-02T00:00:00Z\nunsafe")),
            snipeit_url: String::from("https://example.test\u{1b}[2J"),
            matched_asset: Some(AssetSummary {
                id: 42,
                name: String::from("Laptop\n42"),
                serial: Some(String::from("SERIAL")),
                asset_tag: None,
            }),
            monitors: vec![
                MonitorStatus {
                    serial: String::from("B"),
                    asset_id: None,
                    checked_out: false,
                    absent_since: None,
                },
                MonitorStatus {
                    serial: String::from("A"),
                    asset_id: Some(7),
                    checked_out: true,
                    absent_since: Some(String::from("2026\t")),
                },
            ],
        };
        let human = render_status(&response, false)?;
        assert!(human.contains("State: Sync\\u{1b}[31ming"));
        assert!(human.contains("Last Sync: <none>"));
        assert!(
            human.contains("Matched Asset: Laptop\\n42 (ID 42, serial SERIAL, asset tag <none>)")
        );
        assert!(human.find("  A:").expect("A monitor") < human.find("  B:").expect("B monitor"));
        assert!(human.contains("absent since 2026\\t"));
        Ok(())
    }
}
