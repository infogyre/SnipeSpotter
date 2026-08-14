#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "SMBIOS discovery requires narrowly scoped GetSystemFirmwareTable calls"
    )
)]
// pattern: Imperative Shell

//! Hardware discovery ports and platform adapters.

use anyhow::Result;
use spotter_core::{monitors::MonitorInfo, smbios::SystemInfo};

pub trait HardwareDiscovery: Send + Sync {
    /// Discover system and connected-monitor inventory.
    ///
    /// # Errors
    /// Returns an error when firmware or monitor discovery fails.
    fn discover(&self) -> Result<(SystemInfo, Vec<MonitorInfo>)>;
}

#[cfg(windows)]
pub struct WindowsHardwareDiscovery;

#[cfg(windows)]
impl HardwareDiscovery for WindowsHardwareDiscovery {
    fn discover(&self) -> Result<(SystemInfo, Vec<MonitorInfo>)> {
        let raw = read_smbios()?;
        let system = spotter_core::smbios::parse_smbios_tables(&raw)?;
        let monitors = read_monitors()?;
        Ok((system, monitors))
    }
}

#[cfg(any(windows, test))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WmiMonitorId {
    active: bool,
    manufacturer_name: Vec<u16>,
    product_code_id: Vec<u16>,
    serial_number_id: Vec<u16>,
    week_of_manufacture: u8,
    year_of_manufacture: u16,
}

#[cfg(windows)]
fn read_monitors() -> Result<Vec<MonitorInfo>> {
    let connection = wmi::WMIConnection::with_namespace_path("ROOT\\WMI")
        .map_err(|error| anyhow::anyhow!("failed to connect to ROOT\\WMI: {error}"))?;
    let rows: Vec<WmiMonitorId> = connection
        .raw_query(
            "SELECT Active, ManufacturerName, ProductCodeID, SerialNumberID, WeekOfManufacture, YearOfManufacture FROM WmiMonitorID",
        )
        .map_err(|error| anyhow::anyhow!("failed to query WmiMonitorID: {error}"))?;
    Ok(rows.iter().filter_map(convert_monitor).collect())
}

#[cfg(any(windows, test))]
fn convert_monitor(row: &WmiMonitorId) -> Option<MonitorInfo> {
    if !row.active {
        return None;
    }
    let serial = decode_wmi_string(&row.serial_number_id);
    if serial.is_empty() {
        return None;
    }
    Some(MonitorInfo {
        manufacturer_code: decode_wmi_string(&row.manufacturer_name),
        product_code: decode_wmi_string(&row.product_code_id),
        serial,
        manufacture_week: row.week_of_manufacture,
        manufacture_year: row.year_of_manufacture,
    })
}

#[cfg(any(windows, test))]
fn decode_wmi_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end]).trim().to_owned()
}

#[cfg(windows)]
fn read_smbios() -> Result<Vec<u8>> {
    use windows::Win32::System::SystemInformation::{
        FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable,
    };
    const RSMB: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(u32::from_le_bytes(*b"RSMB"));
    // SAFETY: The first call uses no output buffer to query the required size.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, None) };
    if size == 0 {
        anyhow::bail!("GetSystemFirmwareTable size query failed")
    }
    let mut bytes = vec![0_u8; usize::try_from(size)?];
    // SAFETY: `bytes` is writable for exactly `size` bytes and remains live through the call.
    let written = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(bytes.as_mut_slice())) };
    if written != size {
        anyhow::bail!("GetSystemFirmwareTable returned {written} of {size} bytes")
    }
    Ok(bytes)
}

#[cfg(test)]
type DiscoveryResult = Result<(SystemInfo, Vec<MonitorInfo>), String>;

#[cfg(test)]
pub struct FakeDiscovery {
    pub result: std::sync::Mutex<Option<DiscoveryResult>>,
}

#[cfg(test)]
impl HardwareDiscovery for FakeDiscovery {
    fn discover(&self) -> Result<(SystemInfo, Vec<MonitorInfo>)> {
        let mut guard = self
            .result
            .lock()
            .map_err(|_| anyhow::anyhow!("fake discovery lock poisoned"))?;
        match guard.take() {
            Some(Ok(value)) => Ok(value),
            Some(Err(error)) => anyhow::bail!(error),
            None => anyhow::bail!("fake discovery result exhausted"),
        }
    }
}

#[cfg(test)]
mod monitor_tests {
    use super::*;

    fn encoded(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0, u16::from(b'X')]).collect()
    }

    fn row(active: bool, serial: &str) -> WmiMonitorId {
        WmiMonitorId {
            active,
            manufacturer_name: encoded(" DEL "),
            product_code_id: encoded("1234"),
            serial_number_id: encoded(serial),
            week_of_manufacture: 7,
            year_of_manufacture: 2025,
        }
    }

    #[test]
    fn converts_active_monitor_and_trims_zero_terminated_fields() {
        let monitor = convert_monitor(&row(true, " SERIAL "));
        assert_eq!(
            monitor,
            Some(MonitorInfo {
                manufacturer_code: String::from("DEL"),
                product_code: String::from("1234"),
                serial: String::from("SERIAL"),
                manufacture_week: 7,
                manufacture_year: 2025,
            })
        );
    }

    #[test]
    fn suppresses_inactive_or_unidentified_monitors() {
        assert!(convert_monitor(&row(false, "SERIAL")).is_none());
        assert!(convert_monitor(&row(true, "  ")).is_none());
    }
}
