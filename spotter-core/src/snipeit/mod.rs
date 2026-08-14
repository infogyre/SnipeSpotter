// pattern: Functional Core

//! Pure Snipe-IT wire models, request builders, and response classification.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct Asset {
    pub id: u64,
    pub name: String,
    pub serial: Option<String>,
    pub asset_tag: Option<String>,
    pub status_label: Option<NamedReference>,
    pub assigned_to: Option<NamedReference>,
    pub model: Option<AssetModel>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct NamedReference {
    pub id: u64,
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct AssetModel {
    pub id: u64,
    pub name: String,
    pub manufacturer: Option<Manufacturer>,
    pub category: Option<Category>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct Manufacturer {
    pub id: u64,
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct Category {
    pub id: u64,
    pub name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssetChanges {
    pub name: Option<String>,
    pub serial: Option<String>,
    pub asset_tag: Option<String>,
    pub model_id: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetPatchRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckoutRequest {
    pub checkout_to_type: String,
    pub assigned_asset: u64,
    pub status_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckinRequest {
    pub status_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MonitorCheckout {
    pub operation_id: String,
    pub source_asset_id: u64,
    pub request: CheckoutRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MonitorCheckin {
    pub operation_id: String,
    pub source_asset_id: u64,
    pub request: CheckinRequest,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SnipeItError {
    #[error("Snipe-IT resource not found")]
    NotFound,
    #[error("Snipe-IT authentication failed")]
    AuthFailure,
    #[error("Snipe-IT permission denied")]
    PermissionDenied,
    #[error("Snipe-IT rate limit exceeded")]
    RateLimited { retry_after: Option<u64> },
    #[error("Snipe-IT validation failed: {message}")]
    Validation { message: String },
    #[error("Snipe-IT server error {status}: {message}")]
    ServerError { status: u16, message: String },
    #[error("invalid Snipe-IT response: {message}")]
    InvalidResponse { message: String },
    #[error("Snipe-IT network error: {message}")]
    NetworkError { message: String },
}

#[must_use]
pub fn build_asset_patch(changes: &AssetChanges) -> AssetPatchRequest {
    AssetPatchRequest {
        name: changes.name.clone(),
        serial: changes.serial.clone(),
        asset_tag: changes.asset_tag.clone(),
        model_id: changes.model_id,
    }
}

/// Build a monitor checkout operation.
///
/// # Errors
///
/// Returns [`SnipeItError::Validation`] when an operation or asset/status ID is invalid.
pub fn build_monitor_checkout(
    operation_id: impl Into<String>,
    source_asset_id: u64,
    target_asset_id: u64,
    checkout_status_id: u64,
) -> Result<MonitorCheckout, SnipeItError> {
    let operation_id = operation_id.into();
    validate_operation(&operation_id, source_asset_id, checkout_status_id)?;
    if target_asset_id == 0 {
        return Err(validation("target asset ID must be nonzero"));
    }
    Ok(MonitorCheckout {
        operation_id,
        source_asset_id,
        request: CheckoutRequest {
            checkout_to_type: String::from("asset"),
            assigned_asset: target_asset_id,
            status_id: checkout_status_id,
        },
    })
}

/// Build a monitor check-in operation.
///
/// # Errors
///
/// Returns [`SnipeItError::Validation`] when an operation or asset/status ID is invalid.
pub fn build_monitor_checkin(
    operation_id: impl Into<String>,
    source_asset_id: u64,
    checkin_status_id: u64,
) -> Result<MonitorCheckin, SnipeItError> {
    let operation_id = operation_id.into();
    validate_operation(&operation_id, source_asset_id, checkin_status_id)?;
    Ok(MonitorCheckin {
        operation_id,
        source_asset_id,
        request: CheckinRequest {
            status_id: checkin_status_id,
        },
    })
}

/// Parse a by-serial lookup response.
///
/// # Errors
///
/// Returns [`SnipeItError`] when HTTP status or response content indicates failure.
pub fn parse_asset_by_serial(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<Asset, SnipeItError> {
    let value = parse_success(status, body, retry_after)?;
    if has_not_found_message(&value) {
        return Err(SnipeItError::NotFound);
    }
    if let Some(rows) = value.get("rows").and_then(Value::as_array) {
        let first = rows.first().ok_or(SnipeItError::NotFound)?;
        return decode_asset(first.clone());
    }
    decode_asset(value)
}

/// Parse an asset PATCH response.
///
/// # Errors
///
/// Returns [`SnipeItError`] when HTTP status or response content indicates failure.
pub fn parse_asset_patch(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<Asset, SnipeItError> {
    let value = parse_success(status, body, retry_after)?;
    let payload = value.get("payload").cloned().unwrap_or(value);
    if payload.is_null() {
        return Err(invalid("PATCH response payload is null"));
    }
    decode_asset(payload)
}

/// Parse a monitor checkout response.
///
/// # Errors
///
/// Returns [`SnipeItError`] when HTTP status or response content indicates failure.
pub fn parse_checkout_response(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<(), SnipeItError> {
    parse_mutation_response(status, body, retry_after)
}

/// Parse a monitor check-in response.
///
/// # Errors
///
/// Returns [`SnipeItError`] when HTTP status or response content indicates failure.
pub fn parse_checkin_response(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<(), SnipeItError> {
    parse_mutation_response(status, body, retry_after)
}

fn parse_mutation_response(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<(), SnipeItError> {
    let value = parse_success(status, body, retry_after)?;
    if value.get("payload").is_some_and(Value::is_null) {
        return Err(invalid("mutation response payload is null"));
    }
    if value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("error"))
    {
        return Err(validation(&message_text(&value)));
    }
    if value.get("rows").is_none() && value.get("status").is_none() {
        return Err(invalid("mutation response has neither rows nor status"));
    }
    Ok(())
}

fn parse_success(status: u16, body: &str, retry_after: Option<u64>) -> Result<Value, SnipeItError> {
    let value: Value = serde_json::from_str(body).map_err(|error| invalid(&error.to_string()))?;
    match status {
        200..=299 => Ok(value),
        401 => Err(SnipeItError::AuthFailure),
        403 => Err(SnipeItError::PermissionDenied),
        404 => Err(SnipeItError::NotFound),
        429 => Err(SnipeItError::RateLimited { retry_after }),
        400 | 409 | 422 => Err(validation(&message_text(&value))),
        500..=599 => Err(SnipeItError::ServerError {
            status,
            message: message_text(&value),
        }),
        _ => Err(invalid(&format!("unexpected HTTP status {status}"))),
    }
}

fn validate_operation(
    operation_id: &str,
    source_asset_id: u64,
    status_id: u64,
) -> Result<(), SnipeItError> {
    if operation_id.trim().is_empty() {
        return Err(validation("operation ID must not be blank"));
    }
    if source_asset_id == 0 {
        return Err(validation("source asset ID must be nonzero"));
    }
    if status_id == 0 {
        return Err(validation("status ID must be nonzero"));
    }
    Ok(())
}

fn decode_asset(value: Value) -> Result<Asset, SnipeItError> {
    let asset: Asset =
        serde_json::from_value(value).map_err(|error| invalid(&error.to_string()))?;
    if asset.id == 0 {
        return Err(invalid("asset response has zero ID"));
    }
    Ok(asset)
}

fn has_not_found_message(value: &Value) -> bool {
    let message = message_text(value).to_ascii_lowercase();
    message.contains("not found") || message.contains("no asset")
}

fn message_text(value: &Value) -> String {
    let message = value.get("message").or_else(|| value.get("messages"));
    message
        .map(flatten_message)
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| String::from("unspecified error"))
}

fn flatten_message(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(values) => values
            .iter()
            .map(flatten_message)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("; "),
        Value::Object(values) => values
            .values()
            .map(flatten_message)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("; "),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn validation(message: &str) -> SnipeItError {
    SnipeItError::Validation {
        message: String::from(message),
    }
}

fn invalid(message: &str) -> SnipeItError {
    SnipeItError::InvalidResponse {
        message: String::from(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_collection_and_not_found() -> Result<(), SnipeItError> {
        assert_eq!(
            parse_asset_by_serial(200, r#"{"id":1,"serial":"A"}"#, None)?.id,
            1
        );
        assert_eq!(
            parse_asset_by_serial(200, r#"{"rows":[{"id":2,"serial":"B"}]}"#, None)?.id,
            2
        );
        assert_eq!(
            parse_asset_by_serial(200, r#"{"message":"Asset not found"}"#, None),
            Err(SnipeItError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn classifies_errors_and_validation_shapes() {
        assert_eq!(
            parse_asset_by_serial(401, "{}", None),
            Err(SnipeItError::AuthFailure)
        );
        assert_eq!(
            parse_asset_by_serial(403, "{}", None),
            Err(SnipeItError::PermissionDenied)
        );
        assert_eq!(
            parse_asset_by_serial(429, "{}", Some(7)),
            Err(SnipeItError::RateLimited {
                retry_after: Some(7)
            })
        );
        assert_eq!(
            parse_checkout_response(
                422,
                r#"{"messages":{"serial":["required"],"status":"invalid"}}"#,
                None
            ),
            Err(SnipeItError::Validation {
                message: String::from("required; invalid")
            })
        );
    }

    #[test]
    fn builders_preserve_source_target_and_status() -> Result<(), SnipeItError> {
        let checkout = build_monitor_checkout("checkout-1", 10, 20, 30)?;
        assert_eq!(checkout.source_asset_id, 10);
        assert_eq!(checkout.request.assigned_asset, 20);
        assert_eq!(checkout.request.status_id, 30);
        assert_eq!(checkout.request.checkout_to_type, "asset");
        let checkin = build_monitor_checkin("checkin-1", 10, 40)?;
        assert_eq!(checkin.source_asset_id, 10);
        assert_eq!(checkin.request.status_id, 40);
        assert!(build_monitor_checkout("", 1, 2, 3).is_err());
        assert!(build_monitor_checkin("x", 1, 0).is_err());
        Ok(())
    }

    #[test]
    fn parses_patch_and_rows_mutations() -> Result<(), SnipeItError> {
        assert_eq!(
            parse_asset_patch(200, r#"{"payload":{"id":9,"name":"Updated"}}"#, None)?.id,
            9
        );
        parse_checkout_response(200, r#"{"rows":[{"id":1}]}"#, None)?;
        parse_checkin_response(200, r#"{"status":"success","payload":{"id":1}}"#, None)?;
        assert!(parse_checkin_response(200, r#"{"payload":null}"#, None).is_err());
        Ok(())
    }
}
