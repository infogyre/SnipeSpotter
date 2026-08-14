// pattern: Functional Core

//! Bounds-safe parsing of SMBIOS system and chassis structures.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Local system identity discovered from SMBIOS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfo {
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub asset_tag: String,
    pub chassis_type: ChassisType,
}

/// Numeric SMBIOS chassis type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChassisType(pub u8);

impl ChassisType {
    /// Return whether this chassis is conventionally portable.
    #[must_use]
    pub const fn is_portable(self) -> bool {
        matches!(self.0, 8 | 9 | 10 | 11 | 12 | 14 | 30 | 31 | 32)
    }
}

/// Failure to parse a complete SMBIOS table set.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SmbiosParseError {
    #[error("SMBIOS data is empty")]
    Empty,
    #[error("SMBIOS structure is truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("SMBIOS structure has invalid length at offset {offset}")]
    InvalidLength { offset: usize },
    #[error("SMBIOS string table is unterminated at offset {offset}")]
    UnterminatedStrings { offset: usize },
    #[error("required SMBIOS system information is missing")]
    MissingSystem,
    #[error("required SMBIOS chassis information is missing")]
    MissingChassis,
}

#[derive(Default)]
struct PartialSystem {
    manufacturer: String,
    model: String,
    serial: String,
    asset_tag: String,
    chassis_type: Option<ChassisType>,
}

/// Parse table-only bytes or a `RawSMBIOSData` buffer returned by Windows.
///
/// # Errors
///
/// Returns [`SmbiosParseError`] when structures are malformed, truncated, or
/// omit required system or chassis information.
pub fn parse_smbios_tables(raw: &[u8]) -> Result<SystemInfo, SmbiosParseError> {
    if raw.is_empty() {
        return Err(SmbiosParseError::Empty);
    }
    let tables = table_payload(raw);
    let mut system = PartialSystem::default();
    let mut offset = 0;

    while offset < tables.len() {
        if tables.len().saturating_sub(offset) < 4 {
            return Err(SmbiosParseError::Truncated { offset });
        }
        let kind = tables[offset];
        let length = usize::from(tables[offset + 1]);
        if length < 4 {
            return Err(SmbiosParseError::InvalidLength { offset });
        }
        let formatted_end = offset
            .checked_add(length)
            .filter(|end| *end <= tables.len())
            .ok_or(SmbiosParseError::Truncated { offset })?;
        let strings_end = find_strings_end(tables, formatted_end)
            .ok_or(SmbiosParseError::UnterminatedStrings { offset })?;
        let formatted = &tables[offset..formatted_end];
        let strings = &tables[formatted_end..strings_end - 2];

        match kind {
            1 if length >= 8 => {
                system.manufacturer = indexed_string(strings, formatted[4]);
                system.model = indexed_string(strings, formatted[5]);
                system.serial = indexed_string(strings, formatted[7]);
            }
            2 if length >= 8 => {
                fill_if_empty(
                    &mut system.manufacturer,
                    indexed_string(strings, formatted[4]),
                );
                fill_if_empty(&mut system.model, indexed_string(strings, formatted[5]));
                fill_if_empty(&mut system.serial, indexed_string(strings, formatted[7]));
            }
            3 if length >= 9 => {
                system.chassis_type = Some(ChassisType(formatted[5] & 0x7f));
                system.asset_tag = indexed_string(strings, formatted[8]);
            }
            127 => break,
            _ => {}
        }
        offset = strings_end;
    }

    if system.manufacturer.is_empty() || system.model.is_empty() || system.serial.is_empty() {
        return Err(SmbiosParseError::MissingSystem);
    }
    let chassis_type = system
        .chassis_type
        .ok_or(SmbiosParseError::MissingChassis)?;
    Ok(SystemInfo {
        manufacturer: system.manufacturer,
        model: system.model,
        serial: system.serial,
        asset_tag: system.asset_tag,
        chassis_type,
    })
}

fn table_payload(raw: &[u8]) -> &[u8] {
    if raw.len() >= 8 && raw[1] >= 2 {
        let declared = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        if declared > 0 && declared <= raw.len() - 8 {
            return &raw[8..8 + declared];
        }
    }
    raw
}

fn find_strings_end(tables: &[u8], start: usize) -> Option<usize> {
    if start >= tables.len() {
        return None;
    }
    let mut cursor = start;
    while cursor + 1 < tables.len() {
        if tables[cursor] == 0 && tables[cursor + 1] == 0 {
            return Some(cursor + 2);
        }
        cursor += 1;
    }
    None
}

fn indexed_string(strings: &[u8], index: u8) -> String {
    if index == 0 {
        return String::new();
    }
    strings
        .split(|byte| *byte == 0)
        .nth(usize::from(index - 1))
        .map(|value| String::from_utf8_lossy(value).trim().to_owned())
        .unwrap_or_default()
}

fn fill_if_empty(destination: &mut String, fallback: String) {
    if destination.is_empty() {
        *destination = fallback;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn structure(kind: u8, mut formatted: Vec<u8>, strings: &[&str]) -> Vec<u8> {
        formatted[0] = kind;
        formatted[1] = u8::try_from(formatted.len()).unwrap_or(u8::MAX);
        let mut bytes = formatted;
        for value in strings {
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
        if strings.is_empty() {
            bytes.push(0);
        }
        bytes.push(0);
        bytes
    }

    fn fixture(manufacturer: &str, model: &str, serial: &str, asset: &str, chassis: u8) -> Vec<u8> {
        let mut system = vec![0; 8];
        system[4] = 1;
        system[5] = 2;
        system[7] = 3;
        let mut chassis_data = vec![0; 9];
        chassis_data[5] = chassis;
        chassis_data[8] = 1;
        let mut bytes = structure(1, system, &[manufacturer, model, serial]);
        bytes.extend(structure(3, chassis_data, &[asset]));
        bytes.extend(structure(127, vec![0; 4], &[]));
        bytes
    }

    #[test]
    fn parses_three_hardware_fixtures_and_header() -> Result<(), SmbiosParseError> {
        for (manufacturer, model, chassis) in [
            ("Dell Inc.", "Latitude 7440", 10),
            ("LENOVO", "ThinkPad T14", 9),
            ("HP", "EliteDesk 800", 3),
        ] {
            let table = fixture(manufacturer, model, "SERIAL", "ASSET", chassis);
            let parsed = parse_smbios_tables(&table)?;
            assert_eq!(parsed.manufacturer, manufacturer);
            assert_eq!(parsed.model, model);
            assert_eq!(parsed.serial, "SERIAL");
            assert_eq!(parsed.asset_tag, "ASSET");

            let mut with_header = vec![0, 3, 2, 0];
            with_header.extend_from_slice(&u32::try_from(table.len()).unwrap_or(0).to_le_bytes());
            with_header.extend_from_slice(&table);
            assert_eq!(parse_smbios_tables(&with_header)?, parsed);
        }
        Ok(())
    }

    #[test]
    fn portable_codes_match_contract() {
        for code in 0..=u8::MAX {
            assert_eq!(
                ChassisType(code).is_portable(),
                matches!(code, 8 | 9 | 10 | 11 | 12 | 14 | 30 | 31 | 32)
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = parse_smbios_tables(&bytes);
        }
    }
}
