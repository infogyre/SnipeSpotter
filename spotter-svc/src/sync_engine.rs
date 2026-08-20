// pattern: Imperative Shell

//! Journal-backed synchronization-plan execution.

use std::{future::Future, path::Path, pin::Pin};

use anyhow::{Context as _, Result};
use spotter_core::{
    monitors::MonitorSyncState,
    snipeit::{Asset, AssetPatchRequest, MonitorCheckin, MonitorCheckout},
    sync::SyncPlan,
};

use crate::operation_journal::{self, JournalRecord};

pub trait RemoteMutations {
    /// Reconcile and apply a computer asset patch.
    fn patch_asset<'a>(
        &'a mut self,
        asset_id: u64,
        request: &'a AssetPatchRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    /// Reconcile and apply a monitor checkout.
    fn checkout<'a>(
        &'a mut self,
        operation: &'a MonitorCheckout,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    /// Reconcile and apply a monitor check-in.
    fn checkin<'a>(
        &'a mut self,
        operation: &'a MonitorCheckin,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

impl RemoteMutations for crate::snipeit_client::SnipeItClient {
    fn patch_asset<'a>(
        &'a mut self,
        asset_id: u64,
        request: &'a AssetPatchRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let current = self.get_asset(asset_id).await?;
            if patch_is_applied(&current, request) {
                return Ok(());
            }
            crate::snipeit_client::SnipeItClient::patch_asset(self, asset_id, request)
                .await
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
    }

    fn checkout<'a>(
        &'a mut self,
        operation: &'a MonitorCheckout,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let current = self.get_asset(operation.source_asset_id).await?;
            if checkout_is_applied(&current, operation) {
                return Ok(());
            }
            self.checkout_asset(operation.source_asset_id, &operation.request)
                .await
                .map_err(anyhow::Error::from)
        })
    }

    fn checkin<'a>(
        &'a mut self,
        operation: &'a MonitorCheckin,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let current = self.get_asset(operation.source_asset_id).await?;
            if checkin_is_applied(&current, operation) {
                return Ok(());
            }
            self.checkin_asset(operation.source_asset_id, &operation.request)
                .await
                .map_err(anyhow::Error::from)
        })
    }
}

fn patch_is_applied(asset: &Asset, request: &AssetPatchRequest) -> bool {
    request
        .name
        .as_ref()
        .is_none_or(|value| asset.name == *value)
        && request
            .serial
            .as_ref()
            .is_none_or(|value| asset.serial.as_ref() == Some(value))
        && request
            .asset_tag
            .as_ref()
            .is_none_or(|value| asset.asset_tag.as_ref() == Some(value))
        && request
            .model_id
            .is_none_or(|id| asset.model.as_ref().is_some_and(|model| model.id == id))
}

fn checkout_is_applied(asset: &Asset, operation: &MonitorCheckout) -> bool {
    asset
        .assigned_to
        .as_ref()
        .is_some_and(|assigned| assigned.id == operation.request.assigned_asset)
        && asset
            .status_label
            .as_ref()
            .is_some_and(|status| status.id == operation.request.status_id)
}

fn checkin_is_applied(asset: &Asset, operation: &MonitorCheckin) -> bool {
    asset.assigned_to.is_none()
        && asset
            .status_label
            .as_ref()
            .is_some_and(|status| status.id == operation.request.status_id)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    pub next_monitor_state: MonitorSyncState,
    pub warnings: Vec<String>,
    pub confirmed_operations: Vec<String>,
}

/// Execute planned mutations with prepare-before-remote and confirm-after-success ordering.
///
/// # Errors
/// Returns on the first journal or remote failure, leaving prepared work recoverable.
pub async fn execute_plan(
    plan: SyncPlan,
    computer_asset_id: Option<u64>,
    journal_path: &Path,
    remote: &mut impl RemoteMutations,
) -> Result<ExecutionOutcome> {
    let mut confirmed = Vec::new();
    if let (Some(request), Some(asset_id)) = (&plan.asset_update, computer_asset_id) {
        let operation_id = format!("patch:{asset_id}:{}", serialize_operation(request)?);
        prepare(journal_path, &operation_id, request)?;
        remote.patch_asset(asset_id, request).await?;
        confirm(journal_path, &operation_id)?;
        confirmed.push(operation_id);
    }
    for operation in &plan.monitor_checkouts {
        prepare(journal_path, &operation.operation_id, operation)?;
        remote.checkout(operation).await?;
        confirm(journal_path, &operation.operation_id)?;
        confirmed.push(operation.operation_id.clone());
    }
    for operation in &plan.monitor_checkins {
        prepare(journal_path, &operation.operation_id, operation)?;
        remote.checkin(operation).await?;
        confirm(journal_path, &operation.operation_id)?;
        confirmed.push(operation.operation_id.clone());
    }
    Ok(ExecutionOutcome {
        next_monitor_state: plan.next_monitor_state,
        warnings: plan.warnings,
        confirmed_operations: confirmed,
    })
}

fn prepare<T: serde::Serialize>(
    journal_path: &Path,
    operation_id: &str,
    operation: &T,
) -> Result<()> {
    let value = serde_json::to_value(operation).context("failed to encode operation")?;
    operation_journal::append(
        journal_path,
        &JournalRecord::Prepared {
            operation_id: operation_id.to_owned(),
            operation: value,
        },
    )
}

fn confirm(journal_path: &Path, operation_id: &str) -> Result<()> {
    operation_journal::append(
        journal_path,
        &JournalRecord::Confirmed {
            operation_id: operation_id.to_owned(),
        },
    )
}

/// Compact operations after their confirmed outcomes have been committed to signed state.
///
/// # Errors
/// Returns an error when the journal cannot be loaded or atomically compacted.
pub fn compact_after_state_commit(journal_path: &Path) -> Result<()> {
    let records = operation_journal::load(journal_path)?;
    operation_journal::compact(journal_path, &records)
}

/// Reconcile and replay every prepared but unconfirmed journal operation.
///
/// Operations are processed in deterministic operation-ID order. Each successful reconciliation or
/// mutation is durably confirmed before the next record begins, then the journal is compacted.
///
/// # Errors
///
/// Returns an error for malformed or unknown records, remote failures, or journal persistence
/// failures. Unconfirmed records remain recoverable after failure.
pub async fn recover_pending(
    journal_path: &Path,
    remote: &mut impl RemoteMutations,
) -> Result<Vec<String>> {
    let records = operation_journal::load(journal_path)?;
    let pending = operation_journal::pending(&records);
    let mut confirmed = Vec::with_capacity(pending.len());
    for (operation_id, operation) in pending {
        replay_one(&operation_id, operation, remote).await?;
        confirm(journal_path, &operation_id)?;
        confirmed.push(operation_id);
    }
    let records = operation_journal::load(journal_path)?;
    operation_journal::compact(journal_path, &records)?;
    Ok(confirmed)
}

async fn replay_one(
    operation_id: &str,
    operation: serde_json::Value,
    remote: &mut impl RemoteMutations,
) -> Result<()> {
    if let Some(asset_id) = patch_asset_id(operation_id)? {
        let request: AssetPatchRequest =
            serde_json::from_value(operation).context("invalid prepared asset patch operation")?;
        return remote.patch_asset(asset_id, &request).await;
    }
    if operation_id.starts_with("checkout:") {
        let operation: MonitorCheckout = serde_json::from_value(operation)
            .context("invalid prepared monitor checkout operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("prepared checkout operation ID does not match payload")
        }
        return remote.checkout(&operation).await;
    }
    if operation_id.starts_with("checkin:") {
        let operation: MonitorCheckin = serde_json::from_value(operation)
            .context("invalid prepared monitor check-in operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("prepared check-in operation ID does not match payload")
        }
        return remote.checkin(&operation).await;
    }
    anyhow::bail!("unknown prepared operation kind: {operation_id}")
}

fn patch_asset_id(operation_id: &str) -> Result<Option<u64>> {
    let Some(rest) = operation_id.strip_prefix("patch:") else {
        return Ok(None);
    };
    let asset_id = rest
        .split_once(':')
        .map(|(asset_id, _)| asset_id)
        .ok_or_else(|| anyhow::anyhow!("malformed prepared patch operation ID"))?
        .parse::<u64>()
        .context("invalid asset ID in prepared patch operation")?;
    if asset_id == 0 {
        anyhow::bail!("prepared patch asset ID must be nonzero")
    }
    Ok(Some(asset_id))
}

fn serialize_operation<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spotter_core::{
        monitors::MonitorSyncState,
        snipeit::{CheckinRequest, CheckoutRequest, MonitorCheckin, MonitorCheckout},
    };

    #[derive(Default)]
    struct FakeRemote {
        fail_checkout: bool,
        fail_checkin: bool,
        calls: Vec<String>,
    }
    impl RemoteMutations for FakeRemote {
        fn patch_asset<'a>(
            &'a mut self,
            asset_id: u64,
            _: &'a AssetPatchRequest,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.push(format!("patch:{asset_id}"));
                Ok(())
            })
        }
        fn checkout<'a>(
            &'a mut self,
            operation: &'a MonitorCheckout,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.push(operation.operation_id.clone());
                if self.fail_checkout {
                    anyhow::bail!("injected failure")
                }
                Ok(())
            })
        }
        fn checkin<'a>(
            &'a mut self,
            operation: &'a MonitorCheckin,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.push(operation.operation_id.clone());
                if self.fail_checkin {
                    anyhow::bail!("injected check-in failure")
                }
                Ok(())
            })
        }
    }

    fn checkout_plan() -> SyncPlan {
        SyncPlan {
            asset_update: None,
            monitor_checkouts: vec![MonitorCheckout {
                operation_id: String::from("checkout:1"),
                source_asset_id: 1,
                request: CheckoutRequest {
                    checkout_to_type: String::from("asset"),
                    assigned_asset: 2,
                    status_id: 3,
                },
            }],
            monitor_checkins: Vec::new(),
            next_monitor_state: MonitorSyncState::default(),
            warnings: Vec::new(),
        }
    }

    fn checkin_operation() -> MonitorCheckin {
        MonitorCheckin {
            operation_id: String::from("checkin:1"),
            source_asset_id: 1,
            request: CheckinRequest { status_id: 4 },
        }
    }

    #[test]
    fn desired_state_predicates_compare_only_requested_fields() {
        use spotter_core::snipeit::{AssetModel, CheckinRequest, NamedReference};

        let asset = Asset {
            id: 1,
            name: String::from("name"),
            serial: Some(String::from("serial")),
            asset_tag: Some(String::from("tag")),
            status_label: Some(NamedReference {
                id: 4,
                name: String::new(),
            }),
            assigned_to: None,
            model: Some(AssetModel {
                id: 5,
                ..AssetModel::default()
            }),
        };
        assert!(patch_is_applied(
            &asset,
            &AssetPatchRequest {
                serial: Some(String::from("serial")),
                model_id: Some(5),
                ..AssetPatchRequest::default()
            }
        ));
        assert!(!patch_is_applied(
            &asset,
            &AssetPatchRequest {
                asset_tag: Some(String::from("other")),
                ..AssetPatchRequest::default()
            }
        ));
        assert!(checkin_is_applied(
            &asset,
            &MonitorCheckin {
                operation_id: String::from("checkin"),
                source_asset_id: 1,
                request: CheckinRequest { status_id: 4 },
            }
        ));
    }

    #[tokio::test]
    async fn recovery_replays_in_operation_id_order_and_compacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let checkout = checkout_plan().monitor_checkouts.remove(0);
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: checkout.operation_id.clone(),
                operation: serde_json::to_value(&checkout)?,
            },
        )?;
        let patch_id = String::from("patch:9:{\"serial\":\"SYS\"}");
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: patch_id.clone(),
                operation: serde_json::to_value(AssetPatchRequest {
                    serial: Some(String::from("SYS")),
                    ..AssetPatchRequest::default()
                })?,
            },
        )?;
        let mut remote = FakeRemote::default();
        let confirmed = recover_pending(&path, &mut remote).await?;
        assert_eq!(confirmed, vec![checkout.operation_id.clone(), patch_id]);
        assert_eq!(
            remote.calls,
            vec![checkout.operation_id, String::from("patch:9")]
        );
        assert!(operation_journal::load(&path)?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn recovery_rejects_payload_id_mismatch_and_keeps_pending() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let mut checkout = checkout_plan().monitor_checkouts.remove(0);
        let journal_id = checkout.operation_id.clone();
        checkout.operation_id = String::from("checkout:different");
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: journal_id,
                operation: serde_json::to_value(checkout)?,
            },
        )?;
        assert!(
            recover_pending(&path, &mut FakeRemote::default())
                .await
                .is_err()
        );
        assert_eq!(
            operation_journal::pending(&operation_journal::load(&path)?).len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn remote_failure_leaves_prepared_record() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut remote = FakeRemote {
            fail_checkout: true,
            ..FakeRemote::default()
        };
        assert!(
            execute_plan(checkout_plan(), Some(2), &path, &mut remote)
                .await
                .is_err()
        );
        assert_eq!(
            operation_journal::pending(&operation_journal::load(&path)?).len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn real_client_adapter_executes_checkout() -> Result<()> {
        use secrecy::SecretString;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_json, method, path},
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1,
                "assigned_to": null,
                "status_label": {"id": 99, "name": "old"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hardware/1/checkout"))
            .and(body_json(serde_json::json!({
                "checkout_to_type": "asset",
                "assigned_asset": 2,
                "status_id": 3
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rows": {"id": 1}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut client = crate::snipeit_client::SnipeItClient::new(
            server.uri(),
            SecretString::from(String::from("token")),
        )?;
        client
            .checkout(&checkout_plan().monitor_checkouts[0])
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn real_client_skips_already_applied_checkout() -> Result<()> {
        use secrecy::SecretString;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1,
                "assigned_to": {"id": 2, "name": "computer"},
                "status_label": {"id": 3, "name": "deployed"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut client = crate::snipeit_client::SnipeItClient::new(
            server.uri(),
            SecretString::from(String::from("token")),
        )?;
        client
            .checkout(&checkout_plan().monitor_checkouts[0])
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn execute_plan_orders_patch_checkout_and_checkin() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut plan = checkout_plan();
        plan.asset_update = Some(AssetPatchRequest {
            serial: Some(String::from("SYS")),
            ..AssetPatchRequest::default()
        });
        plan.monitor_checkins.push(checkin_operation());
        let mut remote = FakeRemote::default();
        let outcome = execute_plan(plan, Some(9), &path, &mut remote).await?;

        assert_eq!(
            remote.calls,
            vec![
                String::from("patch:9"),
                String::from("checkout:1"),
                String::from("checkin:1"),
            ]
        );
        assert_eq!(
            outcome.confirmed_operations,
            vec![
                String::from("patch:9:{\"serial\":\"SYS\"}"),
                String::from("checkout:1"),
                String::from("checkin:1"),
            ]
        );
        assert!(operation_journal::pending(&operation_journal::load(&path)?).is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn checkin_failure_leaves_only_failing_operation_prepared() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut plan = checkout_plan();
        plan.monitor_checkins.push(checkin_operation());
        let mut remote = FakeRemote {
            fail_checkin: true,
            ..FakeRemote::default()
        };
        assert!(
            execute_plan(plan, Some(2), &path, &mut remote)
                .await
                .is_err()
        );
        let pending = operation_journal::pending(&operation_journal::load(&path)?);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "checkin:1");
        Ok(())
    }

    #[tokio::test]
    async fn recovery_replays_checkin_and_compacts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let operation = checkin_operation();
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: operation.operation_id.clone(),
                operation: serde_json::to_value(&operation)?,
            },
        )?;
        let mut remote = FakeRemote::default();
        let confirmed = recover_pending(&path, &mut remote).await?;
        assert_eq!(confirmed, vec![String::from("checkin:1")]);
        assert_eq!(remote.calls, vec![String::from("checkin:1")]);
        assert!(operation_journal::load(&path)?.is_empty());
        Ok(())
    }

    #[test]
    fn desired_checkout_and_checkin_state_require_both_assignment_fields() {
        use spotter_core::snipeit::NamedReference;

        let checkout = checkout_plan().monitor_checkouts[0].clone();
        let assigned_only = Asset {
            assigned_to: Some(NamedReference {
                id: 2,
                name: String::from("computer"),
            }),
            ..Asset::default()
        };
        assert!(!checkout_is_applied(&assigned_only, &checkout));
        let checked_out = Asset {
            assigned_to: Some(NamedReference {
                id: 2,
                name: String::from("computer"),
            }),
            status_label: Some(NamedReference {
                id: 3,
                name: String::from("deployed"),
            }),
            ..Asset::default()
        };
        assert!(checkout_is_applied(&checked_out, &checkout));

        let checkin = checkin_operation();
        let available = Asset {
            status_label: Some(NamedReference {
                id: 4,
                name: String::from("available"),
            }),
            ..Asset::default()
        };
        assert!(checkin_is_applied(&available, &checkin));
        let wrong_status = Asset {
            status_label: Some(NamedReference {
                id: 5,
                name: String::from("ready"),
            }),
            ..Asset::default()
        };
        assert!(!checkin_is_applied(&wrong_status, &checkin));
    }

    #[tokio::test]
    async fn success_retains_confirmation_until_state_commit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut remote = FakeRemote::default();
        let outcome = execute_plan(checkout_plan(), Some(2), &path, &mut remote).await?;
        assert_eq!(
            outcome.confirmed_operations,
            vec![String::from("checkout:1")]
        );
        let records = operation_journal::load(&path)?;
        assert_eq!(records.len(), 2);
        assert!(operation_journal::pending(&records).is_empty());
        compact_after_state_commit(&path)?;
        assert!(operation_journal::load(&path)?.is_empty());
        Ok(())
    }
}
