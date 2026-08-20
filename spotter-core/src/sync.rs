// pattern: Functional Core

//! Deterministic synchronization planning.

use chrono::{DateTime, Duration, Utc};

use crate::{
    config::{CheckinPolicy, MonitorSettings},
    monitors::{MonitorInfo, MonitorSyncState, diff_monitors},
    smbios::SystemInfo,
    snipeit::{
        Asset, AssetChanges, AssetPatchRequest, MonitorCheckin, MonitorCheckout, build_asset_patch,
        build_monitor_checkin, build_monitor_checkout,
    },
};

/// Result of strict Snipe-IT taxonomy lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaxonomyResolution {
    Resolved { id: u64 },
    Missing,
    Ambiguous,
}

/// Resolved taxonomy needed to assign a Snipe-IT model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTaxonomy {
    pub manufacturer: TaxonomyResolution,
    pub category: TaxonomyResolution,
    pub model: TaxonomyResolution,
    pub normalized_manufacturer: String,
    pub normalized_model: String,
}

/// A discovered monitor plus its Snipe-IT asset and taxonomy resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMonitor {
    pub monitor: MonitorInfo,
    pub asset_id: Option<u64>,
    pub taxonomy: ResolvedTaxonomy,
}

/// Validated status IDs used for monitor assignment operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedStatusIds {
    pub checkout: u64,
    pub checkin: u64,
}

/// Side-effect-free plan for one synchronization generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPlan {
    pub asset_update: Option<AssetPatchRequest>,
    pub monitor_checkouts: Vec<MonitorCheckout>,
    pub monitor_checkins: Vec<MonitorCheckin>,
    pub next_monitor_state: MonitorSyncState,
    pub warnings: Vec<String>,
}

/// Build a synchronization plan from gathered local and remote state.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the approved pure planner exposes each gathered input explicitly"
)]
pub fn plan_sync(
    system: &SystemInfo,
    system_taxonomy: &ResolvedTaxonomy,
    monitors: &[ResolvedMonitor],
    snipeit_asset: Option<&Asset>,
    monitor_state: &MonitorSyncState,
    policy: &MonitorSettings,
    statuses: &ResolvedStatusIds,
    now: DateTime<Utc>,
) -> SyncPlan {
    let mut warnings = Vec::new();
    let asset_update = plan_system_update(system, system_taxonomy, snipeit_asset, &mut warnings);
    let current: Vec<_> = monitors
        .iter()
        .map(|resolved| resolved.monitor.clone())
        .collect();
    let diff = diff_monitors(&current, monitor_state, now);
    let computer_id = snipeit_asset.map(|asset| asset.id).filter(|id| *id != 0);
    let mut checkouts = Vec::new();

    for resolved in monitors {
        let Some(source_id) = resolved.asset_id.filter(|id| *id != 0) else {
            warnings.push(format!(
                "monitor {} has no matching Snipe-IT asset",
                resolved.monitor.serial
            ));
            continue;
        };
        if !taxonomy_resolved(&resolved.taxonomy) {
            warnings.push(format!(
                "monitor {} taxonomy is unresolved",
                resolved.monitor.serial
            ));
            continue;
        }
        let already_checked_out = monitor_state
            .entries
            .iter()
            .find(|entry| entry.serial == resolved.monitor.serial)
            .is_some_and(|entry| entry.checked_out);
        if already_checked_out {
            continue;
        }
        let Some(target_id) = computer_id else {
            warnings.push(String::from(
                "computer asset is missing; monitor checkout suppressed",
            ));
            break;
        };
        let operation_id = format!("checkout:{source_id}:{target_id}:{}", statuses.checkout);
        match build_monitor_checkout(operation_id, source_id, target_id, statuses.checkout) {
            Ok(operation) => checkouts.push(operation),
            Err(error) => warnings.push(error.to_string()),
        }
    }

    let mut checkins = Vec::new();
    if policy.checkin_policy == CheckinPolicy::AutoNonPortable && !system.chassis_type.is_portable()
    {
        let threshold_hours = i64::try_from(policy.checkin_threshold_hours).unwrap_or(i64::MAX);
        let threshold = Duration::hours(threshold_hours);
        for entry in &diff.removed_monitors {
            let eligible = entry.checked_out
                && entry.snipeit_asset_id.is_some()
                && entry.absent_since.is_some_and(|absent_since| {
                    now.signed_duration_since(absent_since) >= threshold
                });
            if !eligible {
                continue;
            }
            if let Some(source_id) = entry.snipeit_asset_id {
                let operation_id = format!("checkin:{source_id}:{}", statuses.checkin);
                match build_monitor_checkin(operation_id, source_id, statuses.checkin) {
                    Ok(operation) => checkins.push(operation),
                    Err(error) => warnings.push(error.to_string()),
                }
            }
        }
    }

    let mut next_monitor_state = diff.next_state;
    for entry in &mut next_monitor_state.entries {
        if let Some(resolved) = monitors
            .iter()
            .find(|resolved| resolved.monitor.serial == entry.serial)
        {
            entry.snipeit_asset_id = resolved.asset_id;
        }
        if checkouts
            .iter()
            .any(|operation| Some(operation.source_asset_id) == entry.snipeit_asset_id)
        {
            entry.checked_out = true;
        }
        if checkins
            .iter()
            .any(|operation| Some(operation.source_asset_id) == entry.snipeit_asset_id)
        {
            entry.checked_out = false;
        }
    }

    SyncPlan {
        asset_update,
        monitor_checkouts: checkouts,
        monitor_checkins: checkins,
        next_monitor_state,
        warnings,
    }
}

fn plan_system_update(
    system: &SystemInfo,
    taxonomy: &ResolvedTaxonomy,
    asset: Option<&Asset>,
    warnings: &mut Vec<String>,
) -> Option<AssetPatchRequest> {
    let Some(asset) = asset else {
        warnings.push(String::from(
            "computer asset is missing; asset update suppressed",
        ));
        return None;
    };
    if !taxonomy_resolved(taxonomy) {
        warnings.push(String::from(
            "computer taxonomy is unresolved; asset update suppressed",
        ));
        return None;
    }
    let TaxonomyResolution::Resolved { id: model_id } = taxonomy.model else {
        return None;
    };
    let mut changes = AssetChanges::default();
    if asset.serial.as_deref() != Some(system.serial.as_str()) {
        changes.serial = Some(system.serial.clone());
    }
    if asset.asset_tag.as_deref() != Some(system.asset_tag.as_str()) {
        changes.asset_tag = Some(system.asset_tag.clone());
    }
    if asset.model.as_ref().map(|model| model.id) != Some(model_id) {
        changes.model_id = Some(model_id);
    }
    if changes == AssetChanges::default() {
        None
    } else {
        Some(build_asset_patch(&changes))
    }
}

fn taxonomy_resolved(taxonomy: &ResolvedTaxonomy) -> bool {
    matches!(taxonomy.manufacturer, TaxonomyResolution::Resolved { id } if id != 0)
        && matches!(taxonomy.category, TaxonomyResolution::Resolved { id } if id != 0)
        && matches!(taxonomy.model, TaxonomyResolution::Resolved { id } if id != 0)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::{monitors::MonitorSyncEntry, smbios::ChassisType, snipeit::AssetModel};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0)
            .single()
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
    }

    fn taxonomy(model_id: u64) -> ResolvedTaxonomy {
        ResolvedTaxonomy {
            manufacturer: TaxonomyResolution::Resolved { id: 1 },
            category: TaxonomyResolution::Resolved { id: 2 },
            model: TaxonomyResolution::Resolved { id: model_id },
            normalized_manufacturer: String::from("maker"),
            normalized_model: String::from("model"),
        }
    }

    fn system(chassis: u8) -> SystemInfo {
        SystemInfo {
            manufacturer: String::from("Maker"),
            model: String::from("Model"),
            serial: String::from("SYS"),
            asset_tag: String::from("TAG"),
            chassis_type: ChassisType(chassis),
        }
    }

    fn asset() -> Asset {
        Asset {
            id: 100,
            serial: Some(String::from("OLD")),
            asset_tag: Some(String::from("TAG")),
            model: Some(AssetModel {
                id: 3,
                ..AssetModel::default()
            }),
            ..Asset::default()
        }
    }

    fn matching_asset() -> Asset {
        Asset {
            serial: Some(String::from("SYS")),
            model: Some(AssetModel {
                id: 4,
                ..AssetModel::default()
            }),
            ..asset()
        }
    }

    fn monitor(serial: &str) -> MonitorInfo {
        MonitorInfo {
            manufacturer_code: String::from("DEL"),
            product_code: String::from("1"),
            serial: String::from(serial),
            manufacture_week: 1,
            manufacture_year: 2026,
        }
    }

    fn resolved_monitor(serial: &str, asset_id: Option<u64>) -> ResolvedMonitor {
        ResolvedMonitor {
            monitor: monitor(serial),
            asset_id,
            taxonomy: taxonomy(4),
        }
    }

    #[test]
    fn patches_resolved_model_and_preserves_checkout_ids() {
        let monitor = ResolvedMonitor {
            monitor: MonitorInfo {
                manufacturer_code: String::from("DEL"),
                product_code: String::from("1"),
                serial: String::from("MON"),
                manufacture_week: 1,
                manufacture_year: 2026,
            },
            asset_id: Some(200),
            taxonomy: taxonomy(4),
        };
        let plan = plan_sync(
            &system(3),
            &taxonomy(4),
            &[monitor],
            Some(&asset()),
            &MonitorSyncState::default(),
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );
        assert_eq!(
            plan.asset_update.as_ref().and_then(|patch| patch.model_id),
            Some(4)
        );
        assert_eq!(plan.monitor_checkouts[0].source_asset_id, 200);
        assert_eq!(plan.monitor_checkouts[0].request.assigned_asset, 100);
        assert_eq!(plan.next_monitor_state.entries.len(), 1);
        assert_eq!(
            plan.next_monitor_state.entries[0].snipeit_asset_id,
            Some(200)
        );
        assert!(plan.next_monitor_state.entries[0].checked_out);
    }

    #[test]
    fn no_changes_produce_empty_plan() {
        let monitor_state = MonitorSyncState {
            entries: vec![MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(200),
                last_seen: now(),
                absent_since: None,
                checked_out: true,
            }],
        };
        let plan = plan_sync(
            &system(3),
            &taxonomy(4),
            &[resolved_monitor("MON", Some(200))],
            Some(&matching_asset()),
            &monitor_state,
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );

        assert!(plan.asset_update.is_none());
        assert!(plan.monitor_checkouts.is_empty());
        assert!(plan.monitor_checkins.is_empty());
        assert!(plan.warnings.is_empty());
        assert_eq!(plan.next_monitor_state, monitor_state);
    }

    #[test]
    fn missing_computer_asset_suppresses_monitor_checkout() {
        let plan = plan_sync(
            &system(3),
            &taxonomy(4),
            &[resolved_monitor("MON", Some(200))],
            None,
            &MonitorSyncState::default(),
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );

        assert!(plan.asset_update.is_none());
        assert!(plan.monitor_checkouts.is_empty());
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("computer asset is missing"))
        );
        assert_eq!(
            plan.next_monitor_state.entries[0].snipeit_asset_id,
            Some(200)
        );
        assert!(!plan.next_monitor_state.entries[0].checked_out);
    }

    #[test]
    fn missing_monitor_asset_suppresses_checkout() {
        let plan = plan_sync(
            &system(3),
            &taxonomy(4),
            &[resolved_monitor("MON", None)],
            Some(&matching_asset()),
            &MonitorSyncState::default(),
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );

        assert!(plan.asset_update.is_none());
        assert!(plan.monitor_checkouts.is_empty());
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("has no matching Snipe-IT asset"))
        );
        assert_eq!(plan.next_monitor_state.entries[0].snipeit_asset_id, None);
    }

    #[test]
    fn already_checked_out_monitor_is_not_checked_out_again() {
        let monitor_state = MonitorSyncState {
            entries: vec![MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(200),
                last_seen: now(),
                absent_since: None,
                checked_out: true,
            }],
        };
        let plan = plan_sync(
            &system(3),
            &taxonomy(4),
            &[resolved_monitor("MON", Some(200))],
            Some(&matching_asset()),
            &monitor_state,
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );

        assert!(plan.monitor_checkouts.is_empty());
        assert!(plan.warnings.is_empty());
        assert!(plan.next_monitor_state.entries[0].checked_out);
    }

    #[test]
    fn checkin_policy_honors_threshold_and_portability() {
        let absent_since = now() - Duration::hours(24);
        let state = MonitorSyncState {
            entries: vec![MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(200),
                last_seen: absent_since,
                absent_since: Some(absent_since),
                checked_out: true,
            }],
        };
        let policy = MonitorSettings {
            checkin_policy: CheckinPolicy::AutoNonPortable,
            checkin_threshold_hours: 24,
        };
        let statuses = ResolvedStatusIds {
            checkout: 5,
            checkin: 6,
        };
        let below = plan_sync(
            &system(3),
            &taxonomy(3),
            &[],
            Some(&asset()),
            &state,
            &policy,
            &statuses,
            now() - Duration::seconds(1),
        );
        assert!(below.monitor_checkins.is_empty());
        let desktop = plan_sync(
            &system(3),
            &taxonomy(3),
            &[],
            Some(&asset()),
            &state,
            &policy,
            &statuses,
            now(),
        );
        assert_eq!(desktop.monitor_checkins.len(), 1);
        let above = plan_sync(
            &system(3),
            &taxonomy(3),
            &[],
            Some(&asset()),
            &state,
            &policy,
            &statuses,
            now() + Duration::seconds(1),
        );
        assert_eq!(above.monitor_checkins.len(), 1);
        let laptop = plan_sync(
            &system(10),
            &taxonomy(3),
            &[],
            Some(&asset()),
            &state,
            &policy,
            &statuses,
            now(),
        );
        assert!(laptop.monitor_checkins.is_empty());
        let manual = plan_sync(
            &system(3),
            &taxonomy(3),
            &[],
            Some(&asset()),
            &state,
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );
        assert!(manual.monitor_checkins.is_empty());
    }

    #[test]
    fn unresolved_taxonomy_suppresses_mutations() {
        let unresolved = ResolvedTaxonomy {
            manufacturer: TaxonomyResolution::Missing,
            category: TaxonomyResolution::Missing,
            model: TaxonomyResolution::Ambiguous,
            normalized_manufacturer: String::new(),
            normalized_model: String::new(),
        };
        let plan = plan_sync(
            &system(3),
            &unresolved,
            &[],
            Some(&asset()),
            &MonitorSyncState::default(),
            &MonitorSettings::default(),
            &ResolvedStatusIds {
                checkout: 5,
                checkin: 6,
            },
            now(),
        );
        assert!(plan.asset_update.is_none());
        assert!(!plan.warnings.is_empty());
    }
}
