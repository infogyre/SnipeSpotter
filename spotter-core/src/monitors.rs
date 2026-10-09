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
    /// The computer asset named by the last confirmed checkout operation.
    /// Omission preserves the canonical bytes of legacy signed states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkout_asset_id: Option<u64>,
}

/// Persisted monitor synchronization state.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorSyncState {
    pub entries: Vec<MonitorSyncEntry>,
}

/// Reason a specifically requested monitor cannot be forcibly checked in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForcedCheckinIneligibility {
    Present,
    AlreadyCheckedIn,
    Unmapped,
    UnknownOwner,
}

/// Classify whether a monitor can be forcibly checked in.
#[must_use]
pub fn forced_checkin_ineligibility(
    entry: &MonitorSyncEntry,
) -> Option<ForcedCheckinIneligibility> {
    if entry.absent_since.is_none() {
        return Some(ForcedCheckinIneligibility::Present);
    }
    if !entry.checked_out {
        return Some(ForcedCheckinIneligibility::AlreadyCheckedIn);
    }
    if entry.snipeit_asset_id.is_none_or(|asset_id| asset_id == 0) {
        return Some(ForcedCheckinIneligibility::Unmapped);
    }
    if entry.checkout_asset_id.is_none_or(|asset_id| asset_id == 0) {
        return Some(ForcedCheckinIneligibility::UnknownOwner);
    }
    None
}

/// Deterministic difference between current discovery and persisted state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorDiff {
    pub new_monitors: Vec<MonitorInfo>,
    pub removed_monitors: Vec<MonitorSyncEntry>,
    pub unchanged_monitors: Vec<MonitorInfo>,
    pub next_state: MonitorSyncState,
}

/// Build a candidate monitor state with selected successfully checked-in serials cleared.
///
/// The input is never mutated, so callers can persist the candidate only after the corresponding
/// remote mutations have succeeded.
#[must_use]
pub fn apply_forced_checkin_serials(
    state: &MonitorSyncState,
    serials: &[String],
) -> MonitorSyncState {
    let mut candidate = state.clone();
    for entry in &mut candidate.entries {
        if serials.iter().any(|serial| serial == &entry.serial) {
            entry.checked_out = false;
            entry.checkout_asset_id = None;
        }
    }
    candidate
}

/// Diff current monitors by serial and produce the next persisted state.
///
/// Duplicate current serials are represented by the lexicographically smallest complete monitor
/// record for that serial. Presence is tracked once per serial; callers decide whether ambiguity
/// suppresses other work.
#[must_use]
pub fn diff_monitors(
    current: &[MonitorInfo],
    previous: &MonitorSyncState,
    now: DateTime<Utc>,
) -> MonitorDiff {
    let mut ordered_current = current.to_vec();
    ordered_current.sort_by(|left, right| {
        (
            &left.serial,
            &left.manufacturer_code,
            &left.product_code,
            left.manufacture_year,
            left.manufacture_week,
        )
            .cmp(&(
                &right.serial,
                &right.manufacturer_code,
                &right.product_code,
                right.manufacture_year,
                right.manufacture_week,
            ))
    });
    let current_by_serial: BTreeMap<_, _> = ordered_current
        .into_iter()
        .rev()
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
                checkout_asset_id: previous_entry.checkout_asset_id,
            });
        } else {
            new_monitors.push(monitor.clone());
            next_entries.push(MonitorSyncEntry {
                serial: serial.clone(),
                snipeit_asset_id: None,
                last_seen: now,
                absent_since: None,
                checked_out: false,
                checkout_asset_id: None,
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

    #[test]
    fn forced_checkin_eligibility_reports_each_rejection_reason() {
        let mut entry = MonitorSyncEntry {
            serial: String::from("MON-1"),
            snipeit_asset_id: Some(1),
            last_seen: at(1),
            absent_since: None,
            checked_out: true,
            checkout_asset_id: Some(100),
        };
        assert_eq!(
            forced_checkin_ineligibility(&entry),
            Some(ForcedCheckinIneligibility::Present)
        );

        entry.absent_since = Some(at(1));
        entry.checked_out = false;
        assert_eq!(
            forced_checkin_ineligibility(&entry),
            Some(ForcedCheckinIneligibility::AlreadyCheckedIn)
        );

        entry.checked_out = true;
        entry.snipeit_asset_id = None;
        assert_eq!(
            forced_checkin_ineligibility(&entry),
            Some(ForcedCheckinIneligibility::Unmapped)
        );

        entry.snipeit_asset_id = Some(1);
        entry.checkout_asset_id = None;
        assert_eq!(
            forced_checkin_ineligibility(&entry),
            Some(ForcedCheckinIneligibility::UnknownOwner)
        );
        entry.checkout_asset_id = Some(0);
        assert_eq!(
            forced_checkin_ineligibility(&entry),
            Some(ForcedCheckinIneligibility::UnknownOwner)
        );
        entry.checkout_asset_id = Some(100);
        assert_eq!(forced_checkin_ineligibility(&entry), None);
    }

    #[test]
    fn forced_checkin_candidate_clears_selected_checkout_flags_transactionally() {
        let state = MonitorSyncState {
            entries: vec![
                MonitorSyncEntry {
                    serial: String::from("MON-1"),
                    snipeit_asset_id: Some(1),
                    last_seen: at(1),
                    absent_since: Some(at(1)),
                    checked_out: true,
                    checkout_asset_id: Some(100),
                },
                MonitorSyncEntry {
                    serial: String::from("MON-2"),
                    snipeit_asset_id: Some(2),
                    last_seen: at(1),
                    absent_since: Some(at(1)),
                    checked_out: true,
                    checkout_asset_id: Some(100),
                },
            ],
        };

        let candidate = apply_forced_checkin_serials(&state, &[String::from("MON-1")]);

        assert!(!candidate.entries[0].checked_out);
        assert_eq!(candidate.entries[0].checkout_asset_id, None);
        assert!(candidate.entries[1].checked_out);
        assert_eq!(candidate.entries[1].checkout_asset_id, Some(100));
        assert!(state.entries[0].checked_out);
        assert_eq!(state.entries[0].checkout_asset_id, Some(100));
    }

    #[test]
    fn checkout_owner_survives_presence_changes() {
        let previous = MonitorSyncState {
            entries: vec![MonitorSyncEntry {
                serial: String::from("MON-1"),
                snipeit_asset_id: Some(1),
                last_seen: at(1),
                absent_since: None,
                checked_out: true,
                checkout_asset_id: Some(100),
            }],
        };
        let absent = diff_monitors(&[], &previous, at(2));
        assert_eq!(absent.removed_monitors[0].checkout_asset_id, Some(100));
        assert_eq!(absent.next_state.entries[0].checkout_asset_id, Some(100));
        let present = diff_monitors(&[monitor("MON-1")], &absent.next_state, at(3));
        assert_eq!(present.next_state.entries[0].checkout_asset_id, Some(100));
        assert!(present.next_state.entries[0].absent_since.is_none());
    }

    #[test]
    fn legacy_monitor_owner_defaults_to_none_and_is_omitted() -> Result<(), serde_json::Error> {
        let legacy = serde_json::json!({
            "serial": "MON-1",
            "snipeit_asset_id": 1,
            "last_seen": "2026-01-01T01:00:00Z",
            "absent_since": null,
            "checked_out": true,
        });
        let entry: MonitorSyncEntry = serde_json::from_value(legacy.clone())?;
        assert_eq!(entry.checkout_asset_id, None);
        assert_eq!(serde_json::to_value(entry)?, legacy);
        Ok(())
    }
}
