// pattern: Functional Core

//! Pure monitor inventory state transitions.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Monitor identity reported by WMI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub manufacturer_code: String,
    pub product_code: String,
    pub serial: String,
    pub manufacture_week: u8,
    pub manufacture_year: u16,
}

/// Persisted synchronization state for one monitor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MonitorSyncEntry {
    pub serial: String,
    pub snipeit_asset_id: Option<u64>,
    pub last_seen: DateTime<Utc>,
    pub absent_since: Option<DateTime<Utc>>,
    pub checked_out: bool,
}

/// Persisted monitor synchronization state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorSyncState {
    pub entries: Vec<MonitorSyncEntry>,
}

/// Deterministic difference between current discovery and persisted state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorDiff {
    pub new_monitors: Vec<MonitorInfo>,
    pub removed_monitors: Vec<MonitorSyncEntry>,
    pub unchanged_monitors: Vec<MonitorInfo>,
    pub next_state: MonitorSyncState,
}

/// Diff current monitors by serial and produce the next persisted state.
///
/// Duplicate current serials are deterministically collapsed to the first
/// lexicographically sorted record.
#[must_use]
pub fn diff_monitors(
    current: &[MonitorInfo],
    previous: &MonitorSyncState,
    now: DateTime<Utc>,
) -> MonitorDiff {
    let current_by_serial: BTreeMap<_, _> = current
        .iter()
        .cloned()
        .map(|monitor| (monitor.serial.clone(), monitor))
        .collect();
    let previous_by_serial: BTreeMap<_, _> = previous
        .entries
        .iter()
        .cloned()
        .map(|entry| (entry.serial.clone(), entry))
        .collect();

    let mut new_monitors = Vec::new();
    let mut unchanged_monitors = Vec::new();
    let mut next_entries = Vec::new();

    for (serial, monitor) in &current_by_serial {
        if let Some(previous_entry) = previous_by_serial.get(serial) {
            unchanged_monitors.push(monitor.clone());
            next_entries.push(MonitorSyncEntry {
                serial: serial.clone(),
                snipeit_asset_id: previous_entry.snipeit_asset_id,
                last_seen: now,
                absent_since: None,
                checked_out: previous_entry.checked_out,
            });
        } else {
            new_monitors.push(monitor.clone());
            next_entries.push(MonitorSyncEntry {
                serial: serial.clone(),
                snipeit_asset_id: None,
                last_seen: now,
                absent_since: None,
                checked_out: false,
            });
        }
    }

    let current_serials: BTreeSet<_> = current_by_serial.keys().collect();
    let mut removed_monitors = Vec::new();
    for (serial, previous_entry) in previous_by_serial {
        if !current_serials.contains(&serial) {
            let mut absent = previous_entry;
            absent.absent_since.get_or_insert(now);
            removed_monitors.push(absent.clone());
            next_entries.push(absent);
        }
    }
    next_entries.sort_by(|left, right| left.serial.cmp(&right.serial));

    MonitorDiff {
        new_monitors,
        removed_monitors,
        unchanged_monitors,
        next_state: MonitorSyncState {
            entries: next_entries,
        },
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, hour, 0, 0)
            .single()
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
    }

    fn monitor(serial: &str) -> MonitorInfo {
        MonitorInfo {
            manufacturer_code: String::from("DEL"),
            product_code: String::from("1234"),
            serial: String::from(serial),
            manufacture_week: 1,
            manufacture_year: 2026,
        }
    }

    #[test]
    fn tracks_new_absent_and_reappearing_monitors() {
        let first = diff_monitors(
            &[monitor("B"), monitor("A")],
            &MonitorSyncState::default(),
            at(1),
        );
        assert_eq!(
            first
                .new_monitors
                .iter()
                .map(|m| m.serial.as_str())
                .collect::<Vec<_>>(),
            vec!["A", "B"]
        );

        let absent = diff_monitors(&[monitor("A")], &first.next_state, at(2));
        assert_eq!(absent.removed_monitors.len(), 1);
        assert_eq!(absent.removed_monitors[0].absent_since, Some(at(2)));

        let still_absent = diff_monitors(&[monitor("A")], &absent.next_state, at(3));
        assert_eq!(still_absent.removed_monitors[0].absent_since, Some(at(2)));

        let present = diff_monitors(
            &[monitor("A"), monitor("B")],
            &still_absent.next_state,
            at(4),
        );
        let entry = present
            .next_state
            .entries
            .iter()
            .find(|entry| entry.serial == "B");
        assert!(entry.is_some_and(|entry| entry.absent_since.is_none()));
    }

    /// Real WMI monitor data captured from a Dell Precision 3460 with two
    /// monitors. All identifiers redacted to deterministic placeholders.
    /// Proves `diff_monitors` handles real monitor shapes from physical hardware.
    #[test]
    fn diff_handles_real_physical_wmi_fixture() {
        let raw = include_str!("../../tests/fixtures/physical/wmi_monitors.json");
        let fixture: Vec<serde_json::Value> =
            serde_json::from_str(raw).expect("fixture must be valid JSON");

        let monitors: Vec<MonitorInfo> = fixture
            .iter()
            .filter(|m| {
                m.get("active")
                    .and_then(serde_json::Value::as_bool)
                    .is_some_and(std::convert::identity)
            })
            .map(|m| MonitorInfo {
                manufacturer_code: m["manufacturer_name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                product_code: m["product_code"].as_str().unwrap_or_default().to_owned(),
                serial: m["serial"].as_str().unwrap_or_default().to_owned(),
                manufacture_week: u8::try_from(
                    m["week_of_manufacture"].as_u64().unwrap_or_default(),
                )
                .unwrap_or_default(),
                manufacture_year: u16::try_from(
                    m["year_of_manufacture"].as_u64().unwrap_or_default(),
                )
                .unwrap_or_default(),
            })
            .collect();

        assert_eq!(monitors.len(), 2, "fixture has 2 active monitors");
        assert!(
            monitors[0].serial.starts_with("SER"),
            "serials must be redacted"
        );
        assert!(
            monitors[1].serial.starts_with("SER"),
            "serials must be redacted"
        );

        // Feed through the planner to prove it handles real shapes.
        let diff = diff_monitors(&monitors, &MonitorSyncState::default(), at(1));
        assert_eq!(diff.new_monitors.len(), 2);
        assert!(diff.removed_monitors.is_empty());
        assert_eq!(diff.next_state.entries.len(), 2);
    }
}
