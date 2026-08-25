#![cfg(all(windows, feature = "test-support"))]
#![expect(
    unsafe_code,
    reason = "Hosted-runner SMBIOS tests call GetSystemFirmwareTable directly"
)]

// pattern: Imperative Shell

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use chrono::Datelike as _;
use spotter_core::{
    monitors::MonitorInfo,
    smbios::{ChassisType, SystemInfo, parse_smbios_tables},
};
use spotter_svc::discovery::{HardwareDiscovery, WindowsHardwareDiscovery};

#[derive(Debug)]
struct SmbiosHeader {
    structure_type: u8,
}

fn discover_hosted_hardware() -> Result<(SystemInfo, Vec<MonitorInfo>)> {
    HardwareDiscovery::discover(&WindowsHardwareDiscovery)
}

fn read_smbios_raw() -> Result<Vec<u8>> {
    use windows::Win32::System::SystemInformation::{
        FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable,
    };

    const RSMB: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(u32::from_be_bytes(*b"RSMB"));

    // SAFETY: The first call uses no output buffer to query the required size.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, None) };
    if size == 0 {
        bail!("GetSystemFirmwareTable size query failed");
    }
    let mut bytes = vec![0_u8; usize::try_from(size)?];
    // SAFETY: `bytes` is writable for exactly `size` bytes and remains live through the call.
    let written = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(bytes.as_mut_slice())) };
    if written != size {
        bail!("GetSystemFirmwareTable returned {written} of {size} bytes");
    }
    Ok(bytes)
}

fn smbios_table_payload(raw: &[u8]) -> Result<&[u8]> {
    if raw.len() < 8 {
        bail!("RawSMBIOSData header is truncated");
    }
    let declared_length = usize::try_from(u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]))?;
    let end = 8_usize
        .checked_add(declared_length)
        .context("RawSMBIOSData length overflowed")?;
    if end > raw.len() {
        bail!(
            "RawSMBIOSData declares {declared_length} bytes, but only {} are available",
            raw.len() - 8
        );
    }
    Ok(&raw[8..end])
}

fn parse_smbios_structure_headers(raw: &[u8]) -> Result<Vec<SmbiosHeader>> {
    let tables = smbios_table_payload(raw)?;
    let mut headers = Vec::new();
    let mut offset = 0_usize;

    while offset < tables.len() {
        if tables.len() - offset < 4 {
            bail!("SMBIOS structure header is truncated at offset {offset}");
        }
        let structure_type = tables[offset];
        let structure_length = usize::from(tables[offset + 1]);
        if structure_length < 4 {
            bail!("SMBIOS structure has invalid length at offset {offset}");
        }
        let formatted_end = offset
            .checked_add(structure_length)
            .context("SMBIOS structure length overflowed")?;
        if formatted_end > tables.len() {
            bail!("SMBIOS structure is truncated at offset {offset}");
        }

        let mut strings_end = formatted_end;
        let mut terminated = false;
        while strings_end.saturating_add(1) < tables.len() {
            if tables[strings_end] == 0 && tables[strings_end + 1] == 0 {
                strings_end += 2;
                terminated = true;
                break;
            }
            strings_end += 1;
        }
        if !terminated {
            bail!("SMBIOS string table is unterminated at offset {offset}");
        }

        headers.push(SmbiosHeader { structure_type });
        offset = strings_end;
        if structure_type == 127 {
            break;
        }
    }

    Ok(headers)
}

fn assert_monitor_bounds(monitors: &[MonitorInfo]) -> Result<()> {
    assert!(
        monitors.len() <= 1,
        "hosted runner returned {} active monitors",
        monitors.len()
    );
    let current_year = u32::try_from(chrono::Utc::now().year())?;
    for monitor in monitors {
        assert!(
            monitor.manufacturer_code.len() <= 16,
            "manufacturer code is too long: {} bytes",
            monitor.manufacturer_code.len()
        );
        assert!(
            monitor.product_code.len() <= 16,
            "product code is too long: {} bytes",
            monitor.product_code.len()
        );
        assert!(
            monitor.serial.len() <= 16,
            "monitor serial is too long: {} bytes",
            monitor.serial.len()
        );
        assert!(
            monitor.manufacture_week <= 53,
            "manufacture week is invalid: {}",
            monitor.manufacture_week
        );
        assert!(
            u32::from(monitor.manufacture_year) <= current_year + 1,
            "manufacture year is too far in the future: {}",
            monitor.manufacture_year
        );
    }
    Ok(())
}

#[test]
fn smbios_acquisition_succeeds_on_hosted_runner() {
    let result = HardwareDiscovery::discover(&WindowsHardwareDiscovery);
    assert!(
        result.is_ok(),
        "Windows hardware discovery failed: {result:?}"
    );
}

#[test]
fn smbios_structure_count_and_type_histogram_match_hosted_shape() -> Result<()> {
    let _ = discover_hosted_hardware()?;
    let raw = read_smbios_raw()?;
    let _: SystemInfo = parse_smbios_tables(&raw).context("SMBIOS parser rejected hosted data")?;
    let headers = parse_smbios_structure_headers(&raw)?;
    let mut histogram = BTreeMap::new();
    for header in &headers {
        *histogram.entry(header.structure_type).or_insert(0_usize) += 1;
    }

    assert_eq!(
        headers.len(),
        15,
        "unexpected hosted SMBIOS structure count"
    );
    assert_eq!(
        histogram,
        BTreeMap::from([
            (0_u8, 1_usize),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 1),
            (11, 1),
            (16, 1),
            (17, 2),
            (19, 2),
            (20, 2),
            (32, 1),
            (127, 1),
        ])
    );
    Ok(())
}

#[test]
fn wmi_monitor_query_succeeds_and_returns_bounded_count() -> Result<()> {
    let (_, monitors) = discover_hosted_hardware()?;
    assert!(
        monitors.len() <= 1,
        "hosted runner returned {} active monitors",
        monitors.len()
    );
    Ok(())
}

#[test]
fn wmi_array_lengths_are_bounded() -> Result<()> {
    let (_, monitors) = discover_hosted_hardware()?;
    assert_monitor_bounds(&monitors)
}

#[test]
fn chassis_is_non_portable_on_hosted_runner() -> Result<()> {
    let (system, _) = discover_hosted_hardware()?;
    assert_eq!(system.chassis_type, ChassisType(3));
    assert!(!system.chassis_type.is_portable());
    Ok(())
}

#[test]
fn all_hardware_apis_succeed_in_direct_context() -> Result<()> {
    let (system, monitors) = discover_hosted_hardware()?;
    assert!(!system.manufacturer.is_empty(), "manufacturer is missing");
    assert!(!system.model.is_empty(), "model is missing");
    assert!(!system.serial.is_empty(), "system serial is missing");
    assert_eq!(system.chassis_type, ChassisType(3));
    assert!(!system.chassis_type.is_portable());
    assert_monitor_bounds(&monitors)?;
    Ok(())
}
