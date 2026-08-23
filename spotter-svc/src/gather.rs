// pattern: Imperative Shell

//! Hardware and Snipe-IT gathering with strict taxonomy resolution.

use anyhow::{Context as _, Result};
use spotter_core::{
    smbios::SystemInfo,
    snipeit::{Asset, AssetModel, SnipeItError},
    sync::{ResolvedMonitor, ResolvedTaxonomy, TaxonomyResolution},
};

use crate::{
    ports::{HardwareDiscovery, RemoteReads},
    snipeit_client::SnipeItClient,
};

/// Fully gathered remote and local inputs required by the pure sync planner.
pub struct GatheredSync {
    pub system: SystemInfo,
    pub system_asset: Option<Asset>,
    pub system_taxonomy: ResolvedTaxonomy,
    pub monitors: Vec<ResolvedMonitor>,
    pub warnings: Vec<String>,
}

/// Discover local hardware and resolve matching Snipe-IT assets and taxonomy.
///
/// Missing assets are represented as `None`; missing and ambiguous taxonomy remain explicit values.
/// Authentication, permission, network, rate-limit, server, and malformed-response failures abort
/// gathering rather than being converted into a misleading missing result.
///
/// # Errors
///
/// Returns an error when local discovery or a non-not-found Snipe-IT operation fails.
pub async fn gather_sync(
    discovery: &(impl HardwareDiscovery + ?Sized),
    remote: &(impl RemoteReads + ?Sized),
) -> Result<GatheredSync> {
    let (system, monitor_info) = discovery.discover().await?;
    let system_asset = optional_asset(remote.find_asset_by_serial(&system.serial).await)?;
    let system_taxonomy = remote
        .resolve_taxonomy(&system.manufacturer, &system.model)
        .await?;
    let mut monitors = Vec::with_capacity(monitor_info.len());
    let mut warnings = Vec::new();
    for monitor in monitor_info {
        let asset = optional_asset(remote.find_asset_by_serial(&monitor.serial).await)?;
        if asset.is_none() {
            warnings.push(format!(
                "monitor {} has no matching Snipe-IT asset",
                monitor.serial
            ));
        }
        let taxonomy = remote
            .resolve_taxonomy(&monitor.manufacturer_code, &monitor.product_code)
            .await?;
        monitors.push(ResolvedMonitor {
            asset_id: asset.map(|value| value.id).filter(|id| *id != 0),
            monitor,
            taxonomy,
        });
    }
    if system_asset.is_none() {
        warnings.push(format!(
            "computer {} has no matching Snipe-IT asset",
            system.serial
        ));
    }
    Ok(GatheredSync {
        system,
        system_asset,
        system_taxonomy,
        monitors,
        warnings,
    })
}

fn optional_asset(result: Result<Option<Asset>>) -> Result<Option<Asset>> {
    match result {
        Ok(Some(asset)) if asset.id != 0 => Ok(Some(asset)),
        Ok(None | Some(_)) => Ok(None),
        Err(error) if error.downcast_ref::<SnipeItError>() == Some(&SnipeItError::NotFound) => {
            Ok(None)
        }
        Err(error) => Err(error).context("failed to resolve Snipe-IT asset"),
    }
}

impl RemoteReads for SnipeItClient {
    fn find_asset_by_serial<'a>(
        &'a self,
        serial: &'a str,
    ) -> crate::ports::PortFuture<'a, Option<Asset>> {
        Box::pin(async move {
            self.find_asset_by_serial(serial)
                .await
                .map(Some)
                .or_else(|error| {
                    if error == SnipeItError::NotFound {
                        Ok(None)
                    } else {
                        Err(error)
                    }
                })
                .map_err(anyhow::Error::from)
        })
    }

    fn resolve_taxonomy<'a>(
        &'a self,
        manufacturer_name: &'a str,
        model_name: &'a str,
    ) -> crate::ports::PortFuture<'a, ResolvedTaxonomy> {
        Box::pin(async move {
            let normalized_manufacturer = normalize(manufacturer_name);
            let normalized_model = normalize(model_name);
            let manufacturers = self.find_manufacturers(manufacturer_name).await?;
            let manufacturer = resolve_named(
                manufacturers
                    .iter()
                    .map(|value| (value.id, value.name.as_str())),
                &normalized_manufacturer,
            );
            let models = self.find_models(model_name).await?;
            let matching_models =
                matching_models(&models, &normalized_model, resolved_id(&manufacturer));
            let model = resolution_from_ids(matching_models.iter().map(|value| value.id));
            let category = resolution_from_ids(
                matching_models
                    .iter()
                    .filter_map(|value| value.category.as_ref().map(|category| category.id)),
            );
            Ok(ResolvedTaxonomy {
                manufacturer,
                category,
                model,
                normalized_manufacturer,
                normalized_model,
            })
        })
    }
}

fn matching_models<'a>(
    models: &'a [AssetModel],
    normalized_name: &str,
    manufacturer_id: Option<u64>,
) -> Vec<&'a AssetModel> {
    models
        .iter()
        .filter(|model| normalize(&model.name) == normalized_name)
        .filter(|model| {
            manufacturer_id.is_none_or(|id| {
                model
                    .manufacturer
                    .as_ref()
                    .is_some_and(|manufacturer| manufacturer.id == id)
            })
        })
        .collect()
}

fn resolve_named<'a>(
    values: impl IntoIterator<Item = (u64, &'a str)>,
    normalized_name: &str,
) -> TaxonomyResolution {
    resolution_from_ids(
        values
            .into_iter()
            .filter(|(_, name)| normalize(name) == normalized_name)
            .map(|(id, _)| id),
    )
}

fn resolution_from_ids(ids: impl IntoIterator<Item = u64>) -> TaxonomyResolution {
    let mut ids = ids.into_iter().filter(|id| *id != 0).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    match ids.as_slice() {
        [] => TaxonomyResolution::Missing,
        [id] => TaxonomyResolution::Resolved { id: *id },
        _ => TaxonomyResolution::Ambiguous,
    }
}

fn resolved_id(resolution: &TaxonomyResolution) -> Option<u64> {
    match resolution {
        TaxonomyResolution::Resolved { id } => Some(*id),
        TaxonomyResolution::Missing | TaxonomyResolution::Ambiguous => None,
    }
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use spotter_core::snipeit::{Category, Manufacturer};

    #[test]
    fn strict_name_resolution_distinguishes_missing_unique_and_ambiguous() {
        let values = [
            Manufacturer {
                id: 2,
                name: String::from("Dell Inc."),
            },
            Manufacturer {
                id: 3,
                name: String::from("Dell Inc."),
            },
        ];
        assert_eq!(
            resolve_named(
                values.iter().map(|value| (value.id, value.name.as_str())),
                "hp"
            ),
            TaxonomyResolution::Missing
        );
        assert_eq!(
            resolve_named(
                values[..1]
                    .iter()
                    .map(|value| (value.id, value.name.as_str())),
                "dell inc."
            ),
            TaxonomyResolution::Resolved { id: 2 }
        );
        assert_eq!(
            resolve_named(
                values.iter().map(|value| (value.id, value.name.as_str())),
                "dell inc."
            ),
            TaxonomyResolution::Ambiguous
        );
    }

    #[test]
    fn model_matching_requires_exact_normalized_name_and_manufacturer() {
        let models = vec![
            AssetModel {
                id: 10,
                name: String::from("Latitude 7450"),
                manufacturer: Some(Manufacturer {
                    id: 2,
                    name: String::from("Dell"),
                }),
                category: Some(Category {
                    id: 4,
                    name: String::from("Laptop"),
                }),
            },
            AssetModel {
                id: 11,
                name: String::from("Latitude 7450 Plus"),
                manufacturer: Some(Manufacturer {
                    id: 2,
                    name: String::from("Dell"),
                }),
                category: None,
            },
        ];
        let matches = matching_models(&models, "latitude 7450", Some(2));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, 10);
        assert_eq!(
            resolution_from_ids(
                matches
                    .iter()
                    .filter_map(|model| model.category.as_ref().map(|c| c.id))
            ),
            TaxonomyResolution::Resolved { id: 4 }
        );
    }

    #[test]
    fn normalization_collapses_case_and_whitespace() {
        assert_eq!(normalize("  Dell   INC. "), "dell inc.");
    }

    #[test]
    fn not_found_asset_is_optional_but_other_errors_propagate() {
        assert!(matches!(
            optional_asset(Err(SnipeItError::NotFound.into())),
            Ok(None)
        ));
        assert!(optional_asset(Err(SnipeItError::AuthFailure.into())).is_err());
    }
}
