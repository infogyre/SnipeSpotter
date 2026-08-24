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

pub trait RemoteMutations: Send + Sync {
    /// Reconcile and apply a computer asset patch.
    fn patch_asset<'a>(
        &'a mut self,
        asset_id: u64,
        request: &'a AssetPatchRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Asset>> + Send + 'a>>;
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
    ) -> Pin<Box<dyn Future<Output = Result<Asset>> + Send + 'a>> {
        Box::pin(async move {
            let current = self.get_asset(asset_id).await?;
            if patch_is_applied(&current, request) {
                return Ok(current);
            }
            crate::snipeit_client::SnipeItClient::patch_asset(self, asset_id, request)
                .await
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
    pub matched_asset: Option<spotter_core::state::AssetSummary>,
    pub warnings: Vec<String>,
    pub confirmed_operations: Vec<String>,
}

/// Execute planned mutations with prepare-before-remote and outcome-observation-after-success ordering.
///
/// The returned operation IDs remain uncommitted until the caller persists the candidate state and
/// invokes [`commit_after_state_save`].
///
/// # Errors
/// Returns on the first journal or remote failure, leaving prepared work recoverable.
pub async fn execute_plan<R: RemoteMutations + ?Sized>(
    plan: SyncPlan,
    computer_asset_id: Option<u64>,
    journal_path: &Path,
    remote: &mut R,
) -> Result<ExecutionOutcome> {
    let candidate = spotter_core::state::ServiceState {
        known_monitors: plan.next_monitor_state.entries.clone(),
        ..spotter_core::state::ServiceState::default()
    };
    execute_plan_inner(
        plan,
        computer_asset_id,
        journal_path,
        remote,
        &spotter_core::state::ServiceState::default(),
        &candidate,
    )
    .await
}

/// Execute a plan while journaling the complete signed-state candidate for every mutation.
///
/// # Errors
/// Returns on the first journal or remote failure, leaving the complete candidate recoverable.
pub async fn execute_plan_with_candidate<R: RemoteMutations + ?Sized>(
    plan: SyncPlan,
    computer_asset_id: Option<u64>,
    journal_path: &Path,
    remote: &mut R,
    base_state: &spotter_core::state::ServiceState,
    candidate_state: &spotter_core::state::ServiceState,
) -> Result<ExecutionOutcome> {
    execute_plan_inner(
        plan,
        computer_asset_id,
        journal_path,
        remote,
        base_state,
        candidate_state,
    )
    .await
}

async fn execute_plan_inner<R: RemoteMutations + ?Sized>(
    plan: SyncPlan,
    computer_asset_id: Option<u64>,
    journal_path: &Path,
    remote: &mut R,
    base_state: &spotter_core::state::ServiceState,
    final_state: &spotter_core::state::ServiceState,
) -> Result<ExecutionOutcome> {
    let mut confirmed = Vec::new();
    let mut current_state = base_state.clone();
    current_state
        .last_sync_time
        .clone_from(&final_state.last_sync_time);
    current_state
        .last_sync_result
        .clone_from(&final_state.last_sync_result);
    let mut matched_asset = final_state.matched_asset.clone();
    if let (Some(request), Some(asset_id)) = (&plan.asset_update, computer_asset_id) {
        let operation_id = format!("patch:{asset_id}:{}", serialize_operation(request)?);
        let prepared_state =
            state_after_operation(&current_state, final_state, &plan, &operation_id, None);
        prepare(
            journal_path,
            &operation_id,
            request,
            Some(complete_candidate_state(&operation_id, &prepared_state)),
        )?;
        let patched_asset = remote.patch_asset(asset_id, request).await?;
        matched_asset = Some(asset_summary(&patched_asset));
        current_state.matched_asset = matched_asset.clone();
        observe_remote_outcome(
            journal_path,
            &operation_id,
            serde_json::json!({"status":"applied"}),
            Some(complete_candidate_state(&operation_id, &current_state)),
        )?;
        confirmed.push(operation_id);
    }
    for operation in &plan.monitor_checkouts {
        let candidate_state = state_after_operation(
            &current_state,
            final_state,
            &plan,
            &operation.operation_id,
            None,
        );
        prepare(
            journal_path,
            &operation.operation_id,
            operation,
            Some(complete_candidate_state(
                &operation.operation_id,
                &candidate_state,
            )),
        )?;
        remote.checkout(operation).await?;
        current_state = candidate_state;
        observe_remote_outcome(
            journal_path,
            &operation.operation_id,
            serde_json::json!({"status":"applied"}),
            Some(complete_candidate_state(
                &operation.operation_id,
                &current_state,
            )),
        )?;
        confirmed.push(operation.operation_id.clone());
    }
    for operation in &plan.monitor_checkins {
        let candidate_state = state_after_operation(
            &current_state,
            final_state,
            &plan,
            &operation.operation_id,
            None,
        );
        prepare(
            journal_path,
            &operation.operation_id,
            operation,
            Some(complete_candidate_state(
                &operation.operation_id,
                &candidate_state,
            )),
        )?;
        remote.checkin(operation).await?;
        current_state = candidate_state;
        observe_remote_outcome(
            journal_path,
            &operation.operation_id,
            serde_json::json!({"status":"applied"}),
            Some(complete_candidate_state(
                &operation.operation_id,
                &current_state,
            )),
        )?;
        confirmed.push(operation.operation_id.clone());
    }
    Ok(ExecutionOutcome {
        next_monitor_state: plan.next_monitor_state,
        matched_asset,
        warnings: plan.warnings,
        confirmed_operations: confirmed,
    })
}

fn state_after_operation(
    base_state: &spotter_core::state::ServiceState,
    final_state: &spotter_core::state::ServiceState,
    plan: &SyncPlan,
    operation_id: &str,
    patched_asset: Option<&Asset>,
) -> spotter_core::state::ServiceState {
    state_after_operation_with_asset(base_state, final_state, plan, operation_id, patched_asset)
}

fn state_after_operation_with_asset(
    base_state: &spotter_core::state::ServiceState,
    final_state: &spotter_core::state::ServiceState,
    plan: &SyncPlan,
    operation_id: &str,
    patched_asset: Option<&Asset>,
) -> spotter_core::state::ServiceState {
    let mut state = base_state.clone();
    state.last_sync_time.clone_from(&final_state.last_sync_time);
    state
        .last_sync_result
        .clone_from(&final_state.last_sync_result);
    if let Some(patched_asset) = patched_asset {
        state.matched_asset = Some(asset_summary(patched_asset));
    }

    if let (Some(request), Some(asset_id)) = (
        &plan.asset_update,
        computer_asset_id_from_plan(plan, operation_id),
    ) {
        if patched_asset.is_none() {
            state.matched_asset =
                projected_asset_summary(base_state, final_state, asset_id, request);
        }
        return state;
    }

    for operation in &plan.monitor_checkouts {
        apply_monitor_transition(&mut state, final_state, operation.source_asset_id, true);
        if operation.operation_id == operation_id {
            return state;
        }
    }
    for operation in &plan.monitor_checkins {
        apply_monitor_transition(&mut state, final_state, operation.source_asset_id, false);
        if operation.operation_id == operation_id {
            return state;
        }
    }
    state
}

fn computer_asset_id_from_plan(plan: &SyncPlan, operation_id: &str) -> Option<u64> {
    if !operation_id.starts_with("patch:") || plan.asset_update.is_none() {
        return None;
    }
    operation_id
        .strip_prefix("patch:")
        .and_then(|value| value.split_once(':'))
        .and_then(|(id, _)| id.parse().ok())
}

fn projected_asset_summary(
    base_state: &spotter_core::state::ServiceState,
    final_state: &spotter_core::state::ServiceState,
    asset_id: u64,
    request: &AssetPatchRequest,
) -> Option<spotter_core::state::AssetSummary> {
    let mut summary = base_state
        .matched_asset
        .clone()
        .or_else(|| final_state.matched_asset.clone())?;
    summary.id = asset_id;
    if let Some(name) = &request.name {
        summary.name.clone_from(name);
    }
    if request.serial.is_some() {
        summary.serial.clone_from(&request.serial);
    }
    if request.asset_tag.is_some() {
        summary.asset_tag.clone_from(&request.asset_tag);
    }
    Some(summary)
}

fn asset_summary(asset: &Asset) -> spotter_core::state::AssetSummary {
    spotter_core::state::AssetSummary {
        id: asset.id,
        name: asset.name.clone(),
        serial: asset.serial.clone(),
        asset_tag: asset.asset_tag.clone(),
    }
}

fn apply_monitor_transition(
    state: &mut spotter_core::state::ServiceState,
    final_state: &spotter_core::state::ServiceState,
    asset_id: u64,
    checked_out: bool,
) {
    let prior_serial = state
        .known_monitors
        .iter()
        .find(|entry| entry.snipeit_asset_id == Some(asset_id))
        .map(|entry| entry.serial.clone());
    let final_entry = prior_serial
        .as_deref()
        .and_then(|serial| {
            final_state
                .known_monitors
                .iter()
                .find(|entry| entry.serial == serial)
        })
        .or_else(|| {
            final_state
                .known_monitors
                .iter()
                .find(|entry| entry.snipeit_asset_id == Some(asset_id))
        });
    let Some(final_entry) = final_entry else {
        state.known_monitors.retain(|candidate| {
            candidate.snipeit_asset_id != Some(asset_id)
                && prior_serial
                    .as_deref()
                    .is_none_or(|serial| candidate.serial != serial)
        });
        return;
    };
    let mut entry = final_entry.clone();
    entry.checked_out = checked_out;
    state.known_monitors.retain(|candidate| {
        candidate.serial != entry.serial && candidate.snipeit_asset_id != Some(asset_id)
    });
    state.known_monitors.push(entry);
}

fn complete_candidate_state(
    operation_id: &str,
    state: &spotter_core::state::ServiceState,
) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "kind": "service_state",
        "operation_id": operation_id,
        "state": {
            "last_sync_time": state.last_sync_time,
            "last_sync_result": state.last_sync_result,
            "matched_asset": state.matched_asset,
            "known_monitors": state.known_monitors,
        },
    })
}

fn prepare<T: serde::Serialize>(
    journal_path: &Path,
    operation_id: &str,
    operation: &T,
    candidate_state: Option<serde_json::Value>,
) -> Result<()> {
    let operation = serde_json::to_value(operation).context("failed to encode operation")?;
    let operation = if let Some(candidate_state) = candidate_state {
        serde_json::json!({
            "version": 1,
            "operation": operation,
            "candidate_state": candidate_state,
        })
    } else {
        operation
    };
    operation_journal::append(
        journal_path,
        &JournalRecord::Prepared {
            operation_id: operation_id.to_owned(),
            operation,
        },
    )
}

fn observe_remote_outcome(
    journal_path: &Path,
    operation_id: &str,
    outcome: serde_json::Value,
    candidate_state: Option<serde_json::Value>,
) -> Result<()> {
    operation_journal::append(
        journal_path,
        &JournalRecord::RemoteOutcomeObserved {
            operation_id: operation_id.to_owned(),
            outcome,
            candidate_state,
        },
    )
}

/// Append state-commit evidence for operations and compact only after state persistence succeeds.
///
/// # Errors
/// Returns an error when the journal cannot be loaded, appended, or atomically compacted.
pub fn commit_after_state_save(journal_path: &Path, operation_ids: &[String]) -> Result<()> {
    for operation_id in operation_ids {
        operation_journal::append(
            journal_path,
            &JournalRecord::StateCommitted {
                operation_id: operation_id.clone(),
            },
        )?;
    }
    compact_after_state_commit(journal_path)
}

/// Compact operations after their outcomes have been committed to signed state.
///
/// # Errors
/// Returns an error when the journal cannot be loaded or atomically compacted.
pub fn compact_after_state_commit(journal_path: &Path) -> Result<()> {
    let records = operation_journal::load(journal_path)?;
    operation_journal::compact(journal_path, &records)
}

/// Reconcile and replay every prepared operation without durable state-commit evidence.
///
/// Operations are processed in durable `Prepared` record order, never lexical operation-ID order.
/// Each successful reconciliation or mutation is durably recorded as an observed remote outcome.
/// The caller must persist the corresponding candidate state and invoke
/// [`commit_after_state_save`] before compaction.
///
/// # Errors
///
/// Returns an error for malformed or unknown records, remote failures, or journal persistence
/// failures. Uncommitted records remain recoverable after failure.
pub async fn recover_pending<R: RemoteMutations + ?Sized>(
    journal_path: &Path,
    remote: &mut R,
) -> Result<Vec<String>> {
    let records = operation_journal::load(journal_path)?;
    let pending = operation_journal::pending_with_evidence(&records)?;
    let mut observed = Vec::with_capacity(pending.len());
    for pending in pending {
        let operation_id = pending.operation_id;
        let prepared = pending.operation;
        let (operation, prepared_candidate_state) =
            decode_prepared_operation(&operation_id, &prepared)?;
        let candidate_state = pending.candidate_state.or(prepared_candidate_state);
        if let Some(candidate_state) = &candidate_state {
            validate_candidate_state(&operation_id, candidate_state)?;
        }
        let had_remote_outcome = pending.remote_outcome.is_some();
        let authoritative_asset = replay_one(&operation_id, operation.clone(), remote).await?;
        let candidate_state = merge_recovered_asset(candidate_state, authoritative_asset.as_ref())?;
        if !had_remote_outcome {
            observe_remote_outcome(
                journal_path,
                &operation_id,
                serde_json::json!({"status":"reconciled"}),
                candidate_state,
            )?;
        }
        observed.push(operation_id);
    }
    Ok(observed)
}

/// Apply validated remote-outcome evidence to a cloned service state transactionally.
///
/// The caller should persist the resulting state before appending terminal journal records.
/// If any operation is missing evidence or contains an invalid candidate state, the input state
/// remains unchanged.
///
/// # Errors
///
/// Returns an error when an operation has no matching journal evidence, no observed remote
/// outcome, or an invalid/unsupported candidate-state payload.
pub fn apply_recovered_candidate_states(
    state: &mut spotter_core::state::ServiceState,
    records: &[JournalRecord],
    operation_ids: &[String],
) -> Result<()> {
    let pending = operation_journal::pending_with_evidence(records)?;
    let mut candidate = state.clone();
    let mut applied = std::collections::HashSet::new();
    for evidence in &pending {
        let operation_id = &evidence.operation_id;
        if !operation_ids
            .iter()
            .any(|expected| expected == operation_id)
        {
            continue;
        }
        let remote_outcome = evidence.remote_outcome.as_ref().ok_or_else(|| {
            anyhow::anyhow!("recovered operation outcome is missing: {operation_id}")
        })?;
        if remote_outcome
            .get("status")
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            anyhow::bail!("recovered operation outcome is invalid: {operation_id}")
        }
        if let Some(candidate_state) = evidence.candidate_state.as_ref() {
            apply_candidate_state(&mut candidate, operation_id, candidate_state)?;
        } else {
            let (operation, prepared_candidate_state) =
                decode_prepared_operation(operation_id, &evidence.operation)?;
            if let Some(candidate_state) = prepared_candidate_state {
                apply_candidate_state(&mut candidate, operation_id, &candidate_state)?;
            } else {
                apply_legacy_operation_delta(&mut candidate, operation_id, &operation)?;
            }
        }
        applied.insert(operation_id.as_str());
    }
    for operation_id in operation_ids {
        if !applied.contains(operation_id.as_str()) {
            anyhow::bail!("recovered operation evidence is missing: {operation_id}");
        }
    }
    *state = candidate;
    Ok(())
}

fn apply_candidate_state(
    state: &mut spotter_core::state::ServiceState,
    operation_id: &str,
    candidate: &serde_json::Value,
) -> Result<()> {
    validate_candidate_state(operation_id, candidate)?;
    let snapshot = candidate
        .get("state")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("candidate state snapshot is missing"))?;
    let candidate: spotter_core::state::ServiceState =
        serde_json::from_value(snapshot).context("invalid complete candidate state")?;
    *state = candidate;
    Ok(())
}

fn apply_legacy_operation_delta(
    state: &mut spotter_core::state::ServiceState,
    operation_id: &str,
    operation: &serde_json::Value,
) -> Result<()> {
    if let Some(asset_id) = patch_asset_id(operation_id)? {
        let request: AssetPatchRequest = serde_json::from_value(operation.clone())
            .context("invalid legacy prepared asset patch operation")?;
        let Some(asset) = state.matched_asset.as_mut() else {
            anyhow::bail!("legacy patch recovery requires a matched asset: {operation_id}");
        };
        if asset.id != asset_id {
            anyhow::bail!("legacy patch asset ID does not match persisted state: {operation_id}");
        }
        if let Some(name) = request.name {
            asset.name = name;
        }
        if request.serial.is_some() {
            asset.serial = request.serial;
        }
        if request.asset_tag.is_some() {
            asset.asset_tag = request.asset_tag;
        }
        return Ok(());
    }

    if operation_id.starts_with("checkout:") {
        let operation: MonitorCheckout = serde_json::from_value(operation.clone())
            .context("invalid legacy prepared monitor checkout operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("legacy checkout operation ID does not match payload");
        }
        apply_monitor_delta(state, operation.source_asset_id, true)?;
        return Ok(());
    }
    if operation_id.starts_with("checkin:") {
        let operation: MonitorCheckin = serde_json::from_value(operation.clone())
            .context("invalid legacy prepared monitor check-in operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("legacy check-in operation ID does not match payload");
        }
        apply_monitor_delta(state, operation.source_asset_id, false)?;
        return Ok(());
    }
    anyhow::bail!("unknown legacy prepared operation kind: {operation_id}")
}

fn apply_monitor_delta(
    state: &mut spotter_core::state::ServiceState,
    asset_id: u64,
    checked_out: bool,
) -> Result<()> {
    let Some(entry) = state
        .known_monitors
        .iter_mut()
        .find(|entry| entry.snipeit_asset_id == Some(asset_id))
    else {
        anyhow::bail!("legacy monitor recovery found no asset mapping: {asset_id}");
    };
    entry.checked_out = checked_out;
    Ok(())
}

fn decode_prepared_operation(
    operation_id: &str,
    prepared: &serde_json::Value,
) -> Result<(serde_json::Value, Option<serde_json::Value>)> {
    let Some(version) = prepared.get("version").and_then(serde_json::Value::as_u64) else {
        let operation = prepared.clone();
        validate_legacy_operation(operation_id, &operation)?;
        return Ok((operation, None));
    };
    if version != 1 {
        anyhow::bail!("unsupported prepared operation version: {version}");
    }
    let operation = prepared
        .get("operation")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("prepared operation payload is missing: {operation_id}"))?;
    validate_operation_id_binding(operation_id, &operation)?;
    let candidate_state = prepared
        .get("candidate_state")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("prepared candidate state is missing: {operation_id}"))?;
    validate_candidate_state(operation_id, &candidate_state)?;
    Ok((operation, Some(candidate_state)))
}

fn validate_operation_id_binding(operation_id: &str, operation: &serde_json::Value) -> Result<()> {
    if let Some(asset_id) = patch_asset_id(operation_id)? {
        let request: AssetPatchRequest = serde_json::from_value(operation.clone())
            .context("invalid prepared asset patch operation")?;
        let expected = format!("patch:{asset_id}:{}", serialize_operation(&request)?);
        if expected != operation_id {
            anyhow::bail!("prepared patch operation ID does not match payload");
        }
        return Ok(());
    }
    if operation_id.starts_with("checkout:") {
        let operation: MonitorCheckout = serde_json::from_value(operation.clone())
            .context("invalid prepared monitor checkout operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("prepared checkout operation ID does not match payload");
        }
        return Ok(());
    }
    if operation_id.starts_with("checkin:") {
        let operation: MonitorCheckin = serde_json::from_value(operation.clone())
            .context("invalid prepared monitor check-in operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("prepared check-in operation ID does not match payload");
        }
        return Ok(());
    }
    anyhow::bail!("unknown prepared operation kind: {operation_id}")
}

fn validate_legacy_operation(operation_id: &str, operation: &serde_json::Value) -> Result<()> {
    if let Some(asset_id) = patch_asset_id(operation_id)? {
        serde_json::from_value::<AssetPatchRequest>(operation.clone())
            .context("invalid legacy prepared asset patch operation")?;
        if operation.get("operation_id").is_some() {
            anyhow::bail!("ambiguous legacy patch operation payload: {operation_id}");
        }
        if asset_id == 0 {
            anyhow::bail!("legacy patch asset ID must be nonzero");
        }
        return Ok(());
    }
    if operation_id.starts_with("checkout:") {
        let operation: MonitorCheckout = serde_json::from_value(operation.clone())
            .context("invalid legacy prepared monitor checkout operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("legacy checkout operation ID does not match payload");
        }
        return Ok(());
    }
    if operation_id.starts_with("checkin:") {
        let operation: MonitorCheckin = serde_json::from_value(operation.clone())
            .context("invalid legacy prepared monitor check-in operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("legacy check-in operation ID does not match payload");
        }
        return Ok(());
    }
    anyhow::bail!("unknown legacy prepared operation kind: {operation_id}")
}

fn validate_candidate_state(operation_id: &str, candidate: &serde_json::Value) -> Result<()> {
    let candidate_operation_id = candidate
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("candidate state is missing operation ID"))?;
    if candidate_operation_id.is_empty() || candidate_operation_id != operation_id {
        anyhow::bail!("candidate state operation ID does not match journal operation");
    }
    if candidate.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || candidate.get("kind").and_then(serde_json::Value::as_str) != Some("service_state")
    {
        anyhow::bail!("candidate state is not a supported complete snapshot");
    }
    let state = candidate
        .get("state")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("candidate state snapshot is missing"))?;
    for field in [
        "last_sync_time",
        "last_sync_result",
        "matched_asset",
        "known_monitors",
    ] {
        if !state
            .as_object()
            .is_some_and(|state| state.contains_key(field))
        {
            anyhow::bail!("candidate state is missing signed field: {field}");
        }
    }
    let state: spotter_core::state::ServiceState =
        serde_json::from_value(state).context("invalid complete candidate state")?;
    if state
        .known_monitors
        .iter()
        .any(|entry| entry.serial.is_empty())
    {
        anyhow::bail!("candidate state contains an empty monitor serial");
    }
    Ok(())
}

fn merge_recovered_asset(
    candidate: Option<serde_json::Value>,
    authoritative_asset: Option<&Asset>,
) -> Result<Option<serde_json::Value>> {
    let Some(authoritative_asset) = authoritative_asset else {
        return Ok(candidate);
    };
    let Some(mut candidate) = candidate else {
        return Ok(None);
    };
    let state = candidate
        .get_mut("state")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("recovered candidate state is missing state object"))?;
    state.insert(
        String::from("matched_asset"),
        serde_json::to_value(asset_summary(authoritative_asset))?,
    );
    Ok(Some(candidate))
}

async fn replay_one<R: RemoteMutations + ?Sized>(
    operation_id: &str,
    operation: serde_json::Value,
    remote: &mut R,
) -> Result<Option<Asset>> {
    if let Some(asset_id) = patch_asset_id(operation_id)? {
        let request: AssetPatchRequest =
            serde_json::from_value(operation).context("invalid prepared asset patch operation")?;
        return remote.patch_asset(asset_id, &request).await.map(Some);
    }
    if operation_id.starts_with("checkout:") {
        let operation: MonitorCheckout = serde_json::from_value(operation)
            .context("invalid prepared monitor checkout operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("prepared checkout operation ID does not match payload")
        }
        remote.checkout(&operation).await?;
        return Ok(None);
    }
    if operation_id.starts_with("checkin:") {
        let operation: MonitorCheckin = serde_json::from_value(operation)
            .context("invalid prepared monitor check-in operation")?;
        if operation.operation_id != operation_id {
            anyhow::bail!("prepared check-in operation ID does not match payload")
        }
        remote.checkin(&operation).await?;
        return Ok(None);
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
        ) -> Pin<Box<dyn Future<Output = Result<Asset>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.push(format!("patch:{asset_id}"));
                Ok(Asset {
                    id: asset_id,
                    name: String::from("patched-computer"),
                    serial: Some(String::from("PATCHED-SYS")),
                    asset_tag: Some(String::from("PATCHED-TAG")),
                    ..Asset::default()
                })
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

    fn prepared_record<T: serde::Serialize>(operation_id: &str, operation: &T) -> JournalRecord {
        JournalRecord::Prepared {
            operation_id: operation_id.to_owned(),
            operation: serde_json::json!({
                "version": 1,
                "operation": serde_json::to_value(operation).expect("test operation serializes"),
                "candidate_state": complete_candidate_state(
                    operation_id,
                    &spotter_core::state::ServiceState::default(),
                ),
            }),
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
    async fn observed_outcomes_are_reconciled_before_recovery_commit() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let checkout = checkout_plan().monitor_checkouts.remove(0);
        let candidate = spotter_core::state::ServiceState::default();
        let candidate = complete_candidate_state(&checkout.operation_id, &candidate);
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: checkout.operation_id.clone(),
                operation: serde_json::json!({
                    "version": 1,
                    "operation": serde_json::to_value(&checkout)?,
                    "candidate_state": candidate,
                }),
            },
        )?;
        operation_journal::append(
            &path,
            &JournalRecord::RemoteOutcomeObserved {
                operation_id: checkout.operation_id.clone(),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: Some(complete_candidate_state(
                    &checkout.operation_id,
                    &spotter_core::state::ServiceState::default(),
                )),
            },
        )?;

        let before = operation_journal::load(&path)?.len();
        let mut remote = FakeRemote::default();
        recover_pending(&path, &mut remote).await?;
        assert_eq!(remote.calls, vec![checkout.operation_id]);
        assert_eq!(operation_journal::load(&path)?.len(), before);
        Ok(())
    }

    #[tokio::test]
    async fn mutation_evidence_contains_complete_candidate_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let candidate = spotter_core::state::ServiceState {
            last_sync_time: Some(String::from("2026-01-01T00:00:00Z")),
            last_sync_result: Some(spotter_core::state::SyncResult::Success),
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("computer"),
                serial: Some(String::from("SYS")),
                asset_tag: Some(String::from("TAG")),
            }),
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(1),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: true,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let mut remote = FakeRemote::default();
        execute_plan_with_candidate(
            checkout_plan(),
            None,
            &path,
            &mut remote,
            &spotter_core::state::ServiceState::default(),
            &candidate,
        )
        .await?;
        let records = operation_journal::load(&path)?;
        let evidence = records.iter().find_map(|record| match record {
            JournalRecord::RemoteOutcomeObserved {
                candidate_state: Some(candidate),
                ..
            } => Some(candidate),
            _ => None,
        });
        let evidence = evidence.ok_or_else(|| anyhow::anyhow!("missing candidate evidence"))?;
        assert_eq!(
            evidence.get("kind").and_then(serde_json::Value::as_str),
            Some("service_state")
        );
        assert_eq!(
            evidence.get("version").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert!(
            evidence
                .get("state")
                .and_then(|state| state.get("last_sync_time"))
                .is_some()
        );
        assert!(
            evidence
                .get("state")
                .and_then(|state| state.get("matched_asset"))
                .is_some()
        );
        assert!(
            evidence
                .get("state")
                .and_then(|state| state.get("known_monitors"))
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_reports_candidate_state_for_startup_commit() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let checkout = checkout_plan().monitor_checkouts.remove(0);
        operation_journal::append(&path, &prepared_record(&checkout.operation_id, &checkout))?;

        let mut remote = FakeRemote::default();
        let recovered = recover_pending(&path, &mut remote).await?;
        assert_eq!(recovered, vec![checkout.operation_id]);
        let records = operation_journal::load(&path)?;
        let pending = operation_journal::pending_with_evidence(&records)?;
        assert_eq!(pending.len(), 1);
        assert!(pending[0].remote_outcome.is_some());
        assert!(pending[0].candidate_state.is_some());
        Ok(())
    }

    #[test]
    fn recovered_candidate_states_require_evidence_and_apply_transactionally() -> Result<()> {
        let mut state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(7),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let records = vec![JournalRecord::Prepared {
            operation_id: String::from("checkout:7"),
            operation: serde_json::json!({
                "version":1,
                "operation": {},
                "candidate_state": {"version":1,"kind":"service_state","operation_id":"checkout:7","state":{}}
            }),
        }];
        assert!(
            apply_recovered_candidate_states(&mut state, &records, &[String::from("checkout:7")],)
                .is_err()
        );
        assert!(!state.known_monitors[0].checked_out);

        let records = vec![
            prepared_record("checkout:7", &serde_json::json!({})),
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("checkout:7"),
                outcome: serde_json::json!({"status":"reconciled"}),
                candidate_state: Some(serde_json::json!({
                    "version":1,
                    "kind":"service_state",
                    "operation_id":"checkout:7",
                    "state": {"last_sync_time":null,"last_sync_result":null,"matched_asset":null,"known_monitors": [{"serial":"MON","snipeit_asset_id":7,"last_seen":"1970-01-01T00:00:00Z","checked_out":true}]}
                })),
            },
        ];
        apply_recovered_candidate_states(&mut state, &records, &[String::from("checkout:7")])?;
        assert!(state.known_monitors[0].checked_out);
        Ok(())
    }

    #[test]
    fn recovered_monitor_snapshot_replaces_signed_monitor_state() -> Result<()> {
        let mut state = spotter_core::state::ServiceState::default();
        let records = vec![
            prepared_record("checkout:7", &serde_json::json!({})),
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("checkout:7"),
                outcome: serde_json::json!({"status":"reconciled"}),
                candidate_state: Some(serde_json::json!({
                    "version": 1,
                    "kind": "service_state",
                    "operation_id": "checkout:7",
                    "state": {"last_sync_time":null,"last_sync_result":null,"matched_asset":null,"known_monitors": [{
                        "serial": "MON",
                        "snipeit_asset_id": 7,
                        "last_seen": "2026-01-01T00:00:00Z",
                        "checked_out": true
                    }]}
                })),
            },
        ];
        apply_recovered_candidate_states(&mut state, &records, &[String::from("checkout:7")])?;
        assert_eq!(state.known_monitors.len(), 1);
        assert_eq!(state.known_monitors[0].serial, "MON");
        assert!(state.known_monitors[0].checked_out);
        Ok(())
    }

    #[test]
    fn recovered_asset_patch_updates_signed_match() -> Result<()> {
        let mut state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("computer"),
                serial: Some(String::from("OLD")),
                asset_tag: Some(String::from("TAG")),
            }),
            ..spotter_core::state::ServiceState::default()
        };
        let records = vec![
            prepared_record("patch:9:serialized", &serde_json::json!({})),
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("patch:9:serialized"),
                outcome: serde_json::json!({"status":"reconciled"}),
                candidate_state: Some(serde_json::json!({
                    "version": 1,
                    "kind": "service_state",
                    "operation_id": "patch:9:serialized",
                    "state": {"last_sync_time":null,"last_sync_result":null,"matched_asset": {"id":9,"name":"computer","serial":"NEW","asset_tag":"TAG"},"known_monitors":[]}
                })),
            },
        ];
        apply_recovered_candidate_states(
            &mut state,
            &records,
            &[String::from("patch:9:serialized")],
        )?;
        assert_eq!(
            state
                .matched_asset
                .as_ref()
                .and_then(|asset| asset.serial.as_deref()),
            Some("NEW")
        );
        Ok(())
    }

    #[test]
    fn candidate_state_applies_monitor_assignment_by_asset_id() -> Result<()> {
        let mut state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(7),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        apply_candidate_state(
            &mut state,
            "checkout:7",
            &serde_json::json!({
                "version":1,
                "kind":"service_state",
                "operation_id":"checkout:7",
                "state":{"last_sync_time":null,"last_sync_result":null,"matched_asset":null,"known_monitors":[{"serial":"MON","snipeit_asset_id":7,"last_seen":"1970-01-01T00:00:00Z","checked_out":true}]}
            }),
        )?;
        assert!(state.known_monitors[0].checked_out);
        Ok(())
    }

    #[test]
    fn recovered_candidate_state_must_bind_to_journal_operation() {
        let mut state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(7),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let records = vec![
            prepared_record("checkout:7", &serde_json::json!({})),
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("checkout:7"),
                outcome: serde_json::json!({"status":"reconciled"}),
                candidate_state: Some(serde_json::json!({
                    "version": 1,
                    "kind": "service_state",
                    "operation_id": "checkin:7",
                    "state": {"entries": []}
                })),
            },
        ];

        assert!(
            apply_recovered_candidate_states(&mut state, &records, &[String::from("checkout:7")],)
                .is_err()
        );
        assert!(!state.known_monitors[0].checked_out);
    }

    #[test]
    fn recovered_candidate_snapshots_follow_durable_journal_order() {
        let mut state = spotter_core::state::ServiceState::default();
        let z_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 1,
                name: String::from("z-state"),
                serial: Some(String::from("Z")),
                asset_tag: None,
            }),
            ..spotter_core::state::ServiceState::default()
        };
        let a_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 2,
                name: String::from("a-state"),
                serial: Some(String::from("A")),
                asset_tag: None,
            }),
            ..spotter_core::state::ServiceState::default()
        };
        let records = vec![
            prepared_record("z-operation", &serde_json::json!({})),
            prepared_record("a-operation", &serde_json::json!({})),
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("z-operation"),
                outcome: serde_json::json!({"status":"reconciled"}),
                candidate_state: Some(complete_candidate_state("z-operation", &z_state)),
            },
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("a-operation"),
                outcome: serde_json::json!({"status":"reconciled"}),
                candidate_state: Some(complete_candidate_state("a-operation", &a_state)),
            },
        ];

        apply_recovered_candidate_states(
            &mut state,
            &records,
            &[String::from("a-operation"), String::from("z-operation")],
        )
        .expect("recovered candidate snapshots should apply");

        assert_eq!(state.matched_asset, a_state.matched_asset);
    }

    #[tokio::test]
    async fn recovery_replays_in_durable_prepared_order_and_compacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let checkout = checkout_plan().monitor_checkouts.remove(0);
        operation_journal::append(&path, &prepared_record(&checkout.operation_id, &checkout))?;
        let patch_id = String::from("patch:9:{\"serial\":\"SYS\"}");
        let patch_request = AssetPatchRequest {
            serial: Some(String::from("SYS")),
            ..AssetPatchRequest::default()
        };
        operation_journal::append(&path, &prepared_record(&patch_id, &patch_request))?;
        let mut remote = FakeRemote::default();
        let confirmed = recover_pending(&path, &mut remote).await?;
        assert_eq!(confirmed, vec![checkout.operation_id.clone(), patch_id]);
        assert_eq!(
            remote.calls,
            vec![checkout.operation_id, String::from("patch:9")]
        );
        let records = operation_journal::load(&path)?;
        assert_eq!(operation_journal::pending_with_evidence(&records)?.len(), 2);
        assert!(records.iter().all(|record| matches!(
            record,
            JournalRecord::Prepared { .. } | JournalRecord::RemoteOutcomeObserved { .. }
        )));
        commit_after_state_save(&path, &confirmed)?;
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
            operation_journal::pending_with_evidence(&operation_journal::load(&path)?)?.len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn versioned_patch_payload_must_match_operation_id() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let operation_id = String::from("patch:9:{\"serial\":\"EXPECTED\"}");
        let request = AssetPatchRequest {
            serial: Some(String::from("ACTUAL")),
            ..AssetPatchRequest::default()
        };
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: operation_id.clone(),
                operation: serde_json::json!({
                    "version": 1,
                    "operation": request,
                    "candidate_state": complete_candidate_state(
                        &operation_id,
                        &spotter_core::state::ServiceState::default(),
                    ),
                }),
            },
        )?;

        assert!(
            recover_pending(&path, &mut FakeRemote::default())
                .await
                .is_err()
        );
        assert_eq!(
            operation_journal::pending_with_evidence(&operation_journal::load(&path)?)?.len(),
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
            operation_journal::pending_with_evidence(&operation_journal::load(&path)?)?.len(),
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
        let records = operation_journal::load(&path)?;
        assert_eq!(operation_journal::pending_with_evidence(&records)?.len(), 3);
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record, JournalRecord::RemoteOutcomeObserved { .. }))
                .count(),
            3
        );
        commit_after_state_save(&path, &outcome.confirmed_operations)?;
        assert!(operation_journal::load(&path)?.is_empty());
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
        let records = operation_journal::load(&path)?;
        let pending = operation_journal::pending_with_evidence(&records)?;
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].operation_id, "checkout:1");
        assert_eq!(pending[1].operation_id, "checkin:1");
        assert!(records.iter().any(|record| matches!(
            record,
            JournalRecord::RemoteOutcomeObserved { operation_id, .. }
                if operation_id == "checkout:1"
        )));
        Ok(())
    }

    #[tokio::test]
    async fn recovery_replays_checkin_and_waits_for_state_commit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let operation = checkin_operation();
        operation_journal::append(&path, &prepared_record(&operation.operation_id, &operation))?;
        let mut remote = FakeRemote::default();
        let confirmed = recover_pending(&path, &mut remote).await?;
        assert_eq!(confirmed, vec![String::from("checkin:1")]);
        assert_eq!(remote.calls, vec![String::from("checkin:1")]);
        let records = operation_journal::load(&path)?;
        assert_eq!(operation_journal::pending_with_evidence(&records)?.len(), 1);
        commit_after_state_save(&path, &confirmed)?;
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
    async fn successful_mutation_records_operation_specific_monitor_delta() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut plan = checkout_plan();
        plan.monitor_checkouts.push(MonitorCheckout {
            operation_id: String::from("checkout:2"),
            source_asset_id: 2,
            request: CheckoutRequest {
                checkout_to_type: String::from("asset"),
                assigned_asset: 3,
                status_id: 3,
            },
        });
        plan.next_monitor_state = MonitorSyncState {
            entries: vec![
                spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-1"),
                    snipeit_asset_id: Some(1),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: true,
                },
                spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-2"),
                    snipeit_asset_id: Some(2),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: true,
                },
            ],
        };
        let mut remote = FakeRemote::default();
        execute_plan(plan, Some(2), &path, &mut remote).await?;
        let records = operation_journal::load(&path)?;
        let candidate = records.iter().find_map(|record| match record {
            JournalRecord::RemoteOutcomeObserved {
                operation_id,
                candidate_state: Some(candidate),
                ..
            } if operation_id == "checkout:1" => Some(candidate),
            _ => None,
        });
        assert_eq!(
            candidate.and_then(|value| value.get("kind")),
            Some(&serde_json::json!("service_state"))
        );
        assert_eq!(
            candidate.and_then(|value| value.get("operation_id")),
            Some(&serde_json::json!("checkout:1"))
        );
        assert!(candidate.and_then(|value| value.get("state")).is_some());
        Ok(())
    }

    #[tokio::test]
    async fn successful_checkin_records_cleared_candidate_state() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut plan = checkout_plan();
        plan.monitor_checkouts.clear();
        plan.monitor_checkins = vec![checkin_operation()];
        plan.next_monitor_state = MonitorSyncState {
            entries: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(1),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: Some(chrono::DateTime::UNIX_EPOCH),
                checked_out: false,
            }],
        };
        let mut remote = FakeRemote::default();
        execute_plan(plan, None, &path, &mut remote).await?;
        let records = operation_journal::load(&path)?;
        let candidate = records.iter().find_map(|record| match record {
            JournalRecord::RemoteOutcomeObserved {
                operation_id,
                candidate_state: Some(candidate),
                ..
            } if operation_id == "checkin:1" => Some(candidate),
            _ => None,
        });
        assert_eq!(
            candidate.and_then(|value| value.get("kind")),
            Some(&serde_json::json!("service_state"))
        );
        assert_eq!(
            candidate.and_then(|value| value.get("operation_id")),
            Some(&serde_json::json!("checkin:1"))
        );
        let candidate_state: spotter_core::state::ServiceState = serde_json::from_value(
            candidate
                .and_then(|value| value.get("state"))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing check-in candidate state"))?,
        )?;
        assert!(!candidate_state.known_monitors[0].checked_out);
        Ok(())
    }

    #[tokio::test]
    async fn each_operation_journals_only_state_reached_by_that_operation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let mut plan = checkout_plan();
        plan.monitor_checkouts.push(MonitorCheckout {
            operation_id: String::from("checkout:2"),
            source_asset_id: 2,
            request: CheckoutRequest {
                checkout_to_type: String::from("asset"),
                assigned_asset: 3,
                status_id: 3,
            },
        });
        plan.next_monitor_state = MonitorSyncState {
            entries: vec![
                spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-1"),
                    snipeit_asset_id: Some(1),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: true,
                },
                spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-2"),
                    snipeit_asset_id: Some(2),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: true,
                },
            ],
        };
        let final_state = spotter_core::state::ServiceState {
            known_monitors: plan.next_monitor_state.entries.clone(),
            ..spotter_core::state::ServiceState::default()
        };
        let mut remote = FakeRemote::default();

        execute_plan_with_candidate(
            plan,
            Some(2),
            &path,
            &mut remote,
            &spotter_core::state::ServiceState {
                known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-1"),
                    snipeit_asset_id: Some(1),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: false,
                }],
                ..spotter_core::state::ServiceState::default()
            },
            &final_state,
        )
        .await?;

        let records = operation_journal::load(&path)?;
        let snapshot_for = |operation_id: &str| {
            records.iter().find_map(|record| match record {
                JournalRecord::RemoteOutcomeObserved {
                    operation_id: candidate_operation_id,
                    candidate_state: Some(candidate),
                    ..
                } if candidate_operation_id == operation_id => Some(candidate),
                _ => None,
            })
        };
        let first =
            snapshot_for("checkout:1").ok_or_else(|| anyhow::anyhow!("missing first snapshot"))?;
        let second =
            snapshot_for("checkout:2").ok_or_else(|| anyhow::anyhow!("missing second snapshot"))?;
        let first_state: spotter_core::state::ServiceState = serde_json::from_value(
            first
                .get("state")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing first state"))?,
        )?;
        let second_state: spotter_core::state::ServiceState = serde_json::from_value(
            second
                .get("state")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing second state"))?,
        )?;
        assert_eq!(first_state.known_monitors.len(), 1);
        assert!(first_state.known_monitors[0].checked_out);
        assert_eq!(second_state.known_monitors.len(), 2);
        assert!(
            second_state
                .known_monitors
                .iter()
                .all(|entry| entry.checked_out)
        );
        Ok(())
    }

    #[test]
    fn candidate_monitor_transition_replaces_same_serial_asset_identity() {
        let base_state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(7),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let final_state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(8),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: true,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let plan = SyncPlan {
            asset_update: None,
            monitor_checkouts: vec![MonitorCheckout {
                operation_id: String::from("checkout:8"),
                source_asset_id: 8,
                request: CheckoutRequest {
                    checkout_to_type: String::from("asset"),
                    assigned_asset: 9,
                    status_id: 3,
                },
            }],
            monitor_checkins: Vec::new(),
            next_monitor_state: MonitorSyncState {
                entries: final_state.known_monitors.clone(),
            },
            warnings: Vec::new(),
        };

        let state = state_after_operation(&base_state, &final_state, &plan, "checkout:8", None);

        assert_eq!(state.known_monitors.len(), 1);
        assert_eq!(state.known_monitors[0].serial, "MON");
        assert_eq!(state.known_monitors[0].snipeit_asset_id, Some(8));
        assert!(state.known_monitors[0].checked_out);
    }

    #[test]
    fn candidate_monitor_transition_reconciles_by_serial_when_asset_id_changes() {
        let base_state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(7),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let final_state = spotter_core::state::ServiceState {
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(8),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let plan = SyncPlan {
            asset_update: None,
            monitor_checkouts: vec![MonitorCheckout {
                operation_id: String::from("checkout:7"),
                source_asset_id: 7,
                request: CheckoutRequest {
                    checkout_to_type: String::from("asset"),
                    assigned_asset: 9,
                    status_id: 3,
                },
            }],
            monitor_checkins: Vec::new(),
            next_monitor_state: MonitorSyncState {
                entries: final_state.known_monitors.clone(),
            },
            warnings: Vec::new(),
        };

        let state = state_after_operation(&base_state, &final_state, &plan, "checkout:7", None);

        assert_eq!(state.known_monitors.len(), 1);
        assert_eq!(state.known_monitors[0].serial, "MON");
        assert_eq!(state.known_monitors[0].snipeit_asset_id, Some(8));
        assert!(state.known_monitors[0].checked_out);
    }

    #[test]
    fn monitor_snapshot_retains_returned_patch_metadata() {
        let base_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("old-computer"),
                serial: Some(String::from("OLD-SYS")),
                asset_tag: Some(String::from("OLD-TAG")),
            }),
            ..spotter_core::state::ServiceState::default()
        };
        let final_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("gathered-computer"),
                serial: Some(String::from("GATHERED-SYS")),
                asset_tag: Some(String::from("GATHERED-TAG")),
            }),
            ..base_state.clone()
        };
        let plan = SyncPlan {
            asset_update: Some(AssetPatchRequest {
                serial: Some(String::from("PATCHED-SYS")),
                asset_tag: Some(String::from("PATCHED-TAG")),
                ..AssetPatchRequest::default()
            }),
            monitor_checkouts: vec![MonitorCheckout {
                operation_id: String::from("checkout:2"),
                source_asset_id: 2,
                request: CheckoutRequest {
                    checkout_to_type: String::from("asset"),
                    assigned_asset: 9,
                    status_id: 3,
                },
            }],
            monitor_checkins: Vec::new(),
            next_monitor_state: MonitorSyncState::default(),
            warnings: Vec::new(),
        };
        let patched_asset = Asset {
            id: 9,
            name: String::from("patched-computer"),
            serial: Some(String::from("PATCHED-SYS")),
            asset_tag: Some(String::from("PATCHED-TAG")),
            ..Asset::default()
        };

        let state = state_after_operation(
            &base_state,
            &final_state,
            &plan,
            "checkout:2",
            Some(&patched_asset),
        );

        assert_eq!(
            state.matched_asset,
            Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("patched-computer"),
                serial: Some(String::from("PATCHED-SYS")),
                asset_tag: Some(String::from("PATCHED-TAG")),
            })
        );
    }

    #[test]
    fn operation_snapshot_follows_explicit_transition_order() {
        let base_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("old-computer"),
                serial: Some(String::from("OLD-SYS")),
                asset_tag: Some(String::from("OLD-TAG")),
            }),
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("OLD-MON"),
                snipeit_asset_id: Some(1),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: false,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let final_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("new-computer"),
                serial: Some(String::from("NEW-SYS")),
                asset_tag: Some(String::from("NEW-TAG")),
            }),
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("NEW-MON"),
                snipeit_asset_id: Some(2),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: true,
            }],
            ..spotter_core::state::ServiceState::default()
        };
        let plan = SyncPlan {
            asset_update: Some(AssetPatchRequest {
                serial: Some(String::from("NEW-SYS")),
                asset_tag: Some(String::from("NEW-TAG")),
                ..AssetPatchRequest::default()
            }),
            monitor_checkouts: vec![MonitorCheckout {
                operation_id: String::from("checkout:2"),
                source_asset_id: 2,
                request: CheckoutRequest {
                    checkout_to_type: String::from("asset"),
                    assigned_asset: 9,
                    status_id: 3,
                },
            }],
            monitor_checkins: vec![MonitorCheckin {
                operation_id: String::from("checkin:1"),
                source_asset_id: 1,
                request: CheckinRequest { status_id: 4 },
            }],
            next_monitor_state: MonitorSyncState {
                entries: final_state.known_monitors.clone(),
            },
            warnings: Vec::new(),
        };

        let patch_state = state_after_operation(
            &base_state,
            &final_state,
            &plan,
            "patch:9:{\"serial\":\"NEW-SYS\",\"asset_tag\":\"NEW-TAG\"}",
            None,
        );
        assert_eq!(
            patch_state.matched_asset,
            Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("old-computer"),
                serial: Some(String::from("NEW-SYS")),
                asset_tag: Some(String::from("NEW-TAG")),
            })
        );
        assert_eq!(patch_state.known_monitors, base_state.known_monitors);

        let checkout_state =
            state_after_operation(&base_state, &final_state, &plan, "checkout:2", None);
        assert_eq!(
            checkout_state.matched_asset,
            Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("old-computer"),
                serial: Some(String::from("OLD-SYS")),
                asset_tag: Some(String::from("OLD-TAG")),
            })
        );
        assert_eq!(
            checkout_state.known_monitors,
            vec![
                base_state.known_monitors[0].clone(),
                final_state.known_monitors[0].clone(),
            ]
        );

        let checkin_state =
            state_after_operation(&base_state, &final_state, &plan, "checkin:1", None);
        assert_eq!(checkin_state.matched_asset, base_state.matched_asset);
        assert_eq!(
            checkin_state.known_monitors,
            vec![final_state.known_monitors[0].clone()]
        );
    }

    #[tokio::test]
    async fn successful_patch_records_remote_asset_metadata() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let plan = SyncPlan {
            asset_update: Some(AssetPatchRequest {
                serial: Some(String::from("PATCHED-SYS")),
                asset_tag: Some(String::from("PATCHED-TAG")),
                ..AssetPatchRequest::default()
            }),
            monitor_checkouts: Vec::new(),
            monitor_checkins: Vec::new(),
            next_monitor_state: MonitorSyncState::default(),
            warnings: Vec::new(),
        };
        let base_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("old-computer"),
                serial: Some(String::from("OLD-SYS")),
                asset_tag: Some(String::from("OLD-TAG")),
            }),
            ..spotter_core::state::ServiceState::default()
        };
        let final_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("gathered-computer"),
                serial: Some(String::from("GATHERED-SYS")),
                asset_tag: Some(String::from("GATHERED-TAG")),
            }),
            ..base_state.clone()
        };
        let mut remote = FakeRemote::default();
        execute_plan_with_candidate(plan, Some(9), &path, &mut remote, &base_state, &final_state)
            .await?;
        let records = operation_journal::load(&path)?;
        let candidate = records.iter().find_map(|record| match record {
            JournalRecord::RemoteOutcomeObserved {
                candidate_state: Some(candidate),
                ..
            } => Some(candidate),
            _ => None,
        });
        let state: spotter_core::state::ServiceState = serde_json::from_value(
            candidate
                .and_then(|value| value.get("state"))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing patch candidate state"))?,
        )?;
        assert_eq!(
            state.matched_asset,
            Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("patched-computer"),
                serial: Some(String::from("PATCHED-SYS")),
                asset_tag: Some(String::from("PATCHED-TAG")),
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn prepared_patch_recovery_records_authoritative_asset_metadata() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let operation_id = String::from("patch:9:{\"serial\":\"SYS\"}");
        let prepared_state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("gathered-computer"),
                serial: Some(String::from("GATHERED-SYS")),
                asset_tag: Some(String::from("GATHERED-TAG")),
            }),
            ..spotter_core::state::ServiceState::default()
        };
        let request = AssetPatchRequest {
            serial: Some(String::from("SYS")),
            ..AssetPatchRequest::default()
        };
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: operation_id.clone(),
                operation: serde_json::json!({
                    "version": 1,
                    "operation": request,
                    "candidate_state": complete_candidate_state(&operation_id, &prepared_state),
                }),
            },
        )?;

        recover_pending(&path, &mut FakeRemote::default()).await?;

        let records = operation_journal::load(&path)?;
        let pending = operation_journal::pending_with_evidence(&records)?;
        let candidate = pending[0]
            .candidate_state
            .as_ref()
            .and_then(|value| value.get("state"))
            .and_then(|state| state.get("matched_asset"));
        assert_eq!(
            candidate.and_then(|asset| asset.get("name")),
            Some(&serde_json::json!("patched-computer"))
        );
        assert_eq!(
            candidate.and_then(|asset| asset.get("serial")),
            Some(&serde_json::json!("PATCHED-SYS"))
        );
        assert_eq!(
            candidate.and_then(|asset| asset.get("asset_tag")),
            Some(&serde_json::json!("PATCHED-TAG"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn raw_legacy_prepared_records_are_recoverable() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let operation = checkout_plan().monitor_checkouts.remove(0);
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: operation.operation_id.clone(),
                operation: serde_json::to_value(&operation)?,
            },
        )?;
        let mut remote = FakeRemote::default();
        let recovered = recover_pending(&path, &mut remote).await?;
        assert_eq!(recovered, vec![operation.operation_id]);
        assert_eq!(remote.calls, vec![String::from("checkout:1")]);
        Ok(())
    }

    #[tokio::test]
    async fn raw_legacy_patch_and_checkin_records_are_recoverable() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let patch_id = String::from("patch:9:{\"serial\":\"SYS\"}");
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: patch_id.clone(),
                operation: serde_json::json!({"serial":"SYS"}),
            },
        )?;
        let checkin = checkin_operation();
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: checkin.operation_id.clone(),
                operation: serde_json::to_value(&checkin)?,
            },
        )?;
        let mut remote = FakeRemote::default();
        let recovered = recover_pending(&path, &mut remote).await?;
        assert_eq!(recovered, vec![patch_id, checkin.operation_id]);
        assert_eq!(
            remote.calls,
            vec![String::from("patch:9"), String::from("checkin:1")]
        );
        Ok(())
    }

    #[tokio::test]
    async fn legacy_recovery_preserves_unrelated_persisted_state() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let operation = checkout_plan().monitor_checkouts.remove(0);
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: operation.operation_id.clone(),
                operation: serde_json::to_value(&operation)?,
            },
        )?;

        let mut remote = FakeRemote::default();
        let recovered = recover_pending(&path, &mut remote).await?;
        let mut state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("computer"),
                serial: Some(String::from("SYS")),
                asset_tag: Some(String::from("TAG")),
            }),
            known_monitors: vec![
                spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-1"),
                    snipeit_asset_id: Some(1),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: false,
                },
                spotter_core::monitors::MonitorSyncEntry {
                    serial: String::from("MON-2"),
                    snipeit_asset_id: Some(2),
                    last_seen: chrono::DateTime::UNIX_EPOCH,
                    absent_since: None,
                    checked_out: true,
                },
            ],
            ..spotter_core::state::ServiceState::default()
        };
        let before_unrelated_asset = state.matched_asset.clone();
        let before_unrelated_monitor = state.known_monitors[1].clone();

        let records = operation_journal::load(&path)?;
        apply_recovered_candidate_states(&mut state, &records, &recovered)?;

        assert_eq!(state.matched_asset, before_unrelated_asset);
        assert_eq!(state.known_monitors.len(), 2);
        assert!(state.known_monitors[0].checked_out);
        assert_eq!(state.known_monitors[1], before_unrelated_monitor);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_patch_and_checkin_apply_only_operation_deltas() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        let patch_id = String::from("patch:9:{\"serial\":\"NEW-SYS\"}");
        let checkin = checkin_operation();
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: patch_id.clone(),
                operation: serde_json::json!({"serial":"NEW-SYS"}),
            },
        )?;
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: checkin.operation_id.clone(),
                operation: serde_json::to_value(&checkin)?,
            },
        )?;

        let mut remote = FakeRemote::default();
        let recovered = recover_pending(&path, &mut remote).await?;
        let records = operation_journal::load(&path)?;
        let mut state = spotter_core::state::ServiceState {
            matched_asset: Some(spotter_core::state::AssetSummary {
                id: 9,
                name: String::from("computer"),
                serial: Some(String::from("OLD-SYS")),
                asset_tag: Some(String::from("TAG")),
            }),
            known_monitors: vec![spotter_core::monitors::MonitorSyncEntry {
                serial: String::from("MON"),
                snipeit_asset_id: Some(1),
                last_seen: chrono::DateTime::UNIX_EPOCH,
                absent_since: None,
                checked_out: true,
            }],
            ..spotter_core::state::ServiceState::default()
        };

        apply_recovered_candidate_states(&mut state, &records, &recovered)?;

        assert_eq!(
            state
                .matched_asset
                .as_ref()
                .and_then(|asset| asset.serial.as_deref()),
            Some("NEW-SYS")
        );
        assert_eq!(
            state
                .matched_asset
                .as_ref()
                .and_then(|asset| asset.asset_tag.as_deref()),
            Some("TAG")
        );
        assert!(!state.known_monitors[0].checked_out);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_unknown_and_mismatched_records_are_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal");
        operation_journal::append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("checkout:1"),
                operation: serde_json::to_value(MonitorCheckout {
                    operation_id: String::from("checkout:other"),
                    ..checkout_plan().monitor_checkouts[0].clone()
                })?,
            },
        )?;
        assert!(
            recover_pending(&path, &mut FakeRemote::default())
                .await
                .is_err()
        );
        Ok(())
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
        assert_eq!(operation_journal::pending_with_evidence(&records)?.len(), 1);
        assert!(records.iter().any(|record| matches!(
            record,
            JournalRecord::RemoteOutcomeObserved { operation_id, .. }
                if operation_id == "checkout:1"
        )));
        commit_after_state_save(&path, &outcome.confirmed_operations)?;
        assert!(operation_journal::load(&path)?.is_empty());
        Ok(())
    }
}
