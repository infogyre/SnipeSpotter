// pattern: Imperative Shell

//! Ownership-bound HTTP and durable replay regressions for monitor check-ins.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use secrecy::SecretString;
use serde_json::{Value, json};
use spotter_core::snipeit::{CheckinRequest, build_monitor_checkin};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{body_json, method, path},
};

use super::*;
use crate::snipeit_client::SnipeItClient;

const MONITOR_ID: u64 = 11;
const ORIGINAL_OWNER: u64 = 22;
const OTHER_OWNER: u64 = 33;
const CHECKIN_STATUS: u64 = 4;

fn operation() -> MonitorCheckin {
    MonitorCheckin {
        operation_id: String::from("checkin:ownership-regression"),
        source_asset_id: MONITOR_ID,
        expected_asset_id: ORIGINAL_OWNER,
        request: CheckinRequest {
            status_id: CHECKIN_STATUS,
        },
    }
}

fn plan(operation: MonitorCheckin) -> SyncPlan {
    SyncPlan {
        asset_update: None,
        monitor_checkouts: Vec::new(),
        monitor_checkins: vec![operation],
        next_monitor_state: MonitorSyncState::default(),
        warnings: Vec::new(),
    }
}

fn assigned(owner: u64) -> Value {
    json!({"id": owner, "name": "computer", "type": "asset"})
}

fn snapshot(assigned_to: &Value, status_id: u64) -> Value {
    json!({
        "id": MONITOR_ID,
        "name": "monitor",
        "assigned_to": assigned_to,
        "status_label": {"id": status_id, "name": "status"},
    })
}

fn successful_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"status": "success"}))
}

/// Change the remote assignment when the write arrives, before its response is delivered.
/// This also models a committed write whose successful response is lost to a timeout.
async fn http_server(
    initial: Value,
    after_post: Option<Value>,
    post_response: ResponseTemplate,
) -> MockServer {
    let server = MockServer::start().await;
    let remote_state = Arc::new(Mutex::new(initial));
    let get_state = Arc::clone(&remote_state);
    Mock::given(method("GET"))
        .and(path("/api/v1/hardware/11"))
        .respond_with(move |_: &Request| {
            ResponseTemplate::new(200)
                .set_body_json(get_state.lock().expect("remote state lock").clone())
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/hardware/11/checkin"))
        .and(body_json(json!({"status_id": CHECKIN_STATUS})))
        .respond_with(move |_: &Request| {
            if let Some(after_post) = &after_post {
                *remote_state.lock().expect("remote state lock") = after_post.clone();
            }
            post_response.clone()
        })
        .mount(&server)
        .await;
    server
}

fn client(server: &MockServer) -> Result<SnipeItClient> {
    SnipeItClient::new_loopback_http_for_test(
        server.uri(),
        SecretString::from(String::from("test-token")),
    )
}

fn impatient_client(server: &MockServer) -> Result<SnipeItClient> {
    SnipeItClient::with_timeout_and_loopback_http_for_test(
        server.uri(),
        SecretString::from(String::from("test-token")),
        Duration::from_millis(250),
    )
}

async fn assert_requests(server: &MockServer, expected_methods: &[&str]) {
    let requests = server.received_requests().await.expect("request recording");
    let methods: Vec<_> = requests
        .iter()
        .map(|request| request.method.as_str())
        .collect();
    assert_eq!(methods, expected_methods);
    for request in requests {
        let expected_path = if request.method.as_str() == "POST" {
            "/api/v1/hardware/11/checkin"
        } else {
            "/api/v1/hardware/11"
        };
        assert_eq!(request.url.path(), expected_path);
        if request.method.as_str() == "POST" {
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).expect("JSON check-in body"),
                json!({"status_id": CHECKIN_STATUS})
            );
        }
    }
}

fn assert_only_prepared(journal_path: &Path) -> Result<()> {
    let records = operation_journal::load(journal_path)?;
    assert!(matches!(
        records.as_slice(),
        [JournalRecord::Prepared { .. }]
    ));
    let pending = operation_journal::pending_with_evidence(&records)?;
    assert_eq!(pending.len(), 1);
    assert!(pending[0].remote_outcome.is_none());
    Ok(())
}

fn append_prepared(journal_path: &Path, payload: &Value, wrapped: bool) -> Result<()> {
    let operation_id = payload["operation_id"].as_str().expect("operation ID");
    let candidate = spotter_core::state::ServiceState {
        // A different matched computer must never replace the operation's durable owner.
        matched_asset: Some(spotter_core::state::AssetSummary {
            id: OTHER_OWNER,
            name: String::from("newly matched computer"),
            serial: None,
            asset_tag: None,
        }),
        ..spotter_core::state::ServiceState::default()
    };
    prepare(
        journal_path,
        operation_id,
        payload,
        wrapped.then(|| complete_candidate_state(operation_id, &candidate)),
    )
}

#[tokio::test]
async fn matching_asset_owner_is_checked_fresh_before_direct_checkin() -> Result<()> {
    let server = http_server(
        snapshot(&assigned(ORIGINAL_OWNER), CHECKIN_STATUS),
        None,
        successful_response(),
    )
    .await;
    let mut remote = client(&server)?;
    remote.checkin(&operation()).await?;
    assert_requests(&server, &["GET", "POST"]).await;
    Ok(())
}

#[tokio::test]
async fn direct_checkin_suppresses_changed_or_ambiguous_owner() -> Result<()> {
    for owner in [
        assigned(OTHER_OWNER),
        json!({"id": ORIGINAL_OWNER, "name": "person", "type": "user"}),
        json!({"id": ORIGINAL_OWNER, "name": "location", "type": "location"}),
        json!({"id": ORIGINAL_OWNER, "name": "unknown"}),
        json!({"id": ORIGINAL_OWNER, "name": "unknown", "type": null}),
        json!({"id": ORIGINAL_OWNER, "name": "unknown", "type": ""}),
        json!({"id": ORIGINAL_OWNER, "name": "unknown", "type": "Asset"}),
    ] {
        let server = http_server(
            snapshot(&owner, CHECKIN_STATUS),
            None,
            successful_response(),
        )
        .await;
        let error = client(&server)?
            .checkin(&operation())
            .await
            .expect_err("ambiguous or different ownership must suppress check-in");
        assert!(error.to_string().contains("suppressed"), "{owner}: {error}");
        assert_requests(&server, &["GET"]).await;
    }
    Ok(())
}

#[tokio::test]
async fn unassigned_checkin_is_idempotent_only_at_requested_status() -> Result<()> {
    for status_id in [CHECKIN_STATUS, 99] {
        let server = http_server(
            snapshot(&Value::Null, status_id),
            None,
            successful_response(),
        )
        .await;
        let outcome = client(&server)?.checkin(&operation()).await;
        if status_id == CHECKIN_STATUS {
            outcome?;
        } else {
            let error = outcome.expect_err("unassigned status changes require reconciliation");
            assert!(error.to_string().contains("suppressed"));
        }
        assert_requests(&server, &["GET"]).await;
    }
    Ok(())
}

#[tokio::test]
async fn zero_expected_owner_is_rejected_before_direct_http() -> Result<()> {
    assert!(build_monitor_checkin("checkin:zero", MONITOR_ID, 0, CHECKIN_STATUS).is_err());
    let server = MockServer::start().await;
    let mut invalid = operation();
    invalid.expected_asset_id = 0;
    let error = client(&server)?
        .checkin(&invalid)
        .await
        .expect_err("zero owner must be rejected");
    assert!(error.to_string().contains("suppressed"));
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("journal");
    assert!(
        execute_plan(
            plan(invalid),
            Some(ORIGINAL_OWNER),
            &journal_path,
            &mut client(&server)?,
        )
        .await
        .is_err()
    );
    assert!(operation_journal::load(&journal_path)?.is_empty());
    assert_requests(&server, &[]).await;
    Ok(())
}

#[tokio::test]
async fn direct_retry_rechecks_owner_after_failed_write() -> Result<()> {
    let server = http_server(
        snapshot(&assigned(ORIGINAL_OWNER), 3),
        Some(snapshot(&assigned(OTHER_OWNER), 3)),
        ResponseTemplate::new(503),
    )
    .await;
    let mut remote = client(&server)?;
    assert!(remote.checkin(&operation()).await.is_err());
    let error = remote
        .checkin(&operation())
        .await
        .expect_err("retry must preserve the original owner guard");
    assert!(error.to_string().contains("suppressed"));
    assert_requests(&server, &["GET", "POST", "GET"]).await;
    Ok(())
}

#[tokio::test]
async fn execute_plan_suppresses_owner_changed_since_planning() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("journal");
    let planned = plan(operation());
    let server = http_server(
        snapshot(&assigned(OTHER_OWNER), 3),
        None,
        successful_response(),
    )
    .await;
    let error = execute_plan(
        planned,
        Some(ORIGINAL_OWNER),
        &journal_path,
        &mut client(&server)?,
    )
    .await
    .expect_err("stale plans must not check in another computer's monitor");
    assert!(error.to_string().contains("suppressed"));
    assert_requests(&server, &["GET"]).await;
    assert_only_prepared(&journal_path)?;
    Ok(())
}

#[tokio::test]
async fn restart_preserves_prepared_owner_even_when_matched_computer_changes() -> Result<()> {
    for current_owner in [ORIGINAL_OWNER, OTHER_OWNER] {
        let directory = tempfile::tempdir()?;
        let journal_path = directory.path().join("journal");
        let original = operation();
        append_prepared(&journal_path, &serde_json::to_value(&original)?, true)?;
        let records = operation_journal::load(&journal_path)?;
        let JournalRecord::Prepared { operation, .. } = &records[0] else {
            panic!("prepared operation missing");
        };
        assert_eq!(operation["operation"]["expected_asset_id"], ORIGINAL_OWNER);
        let server = http_server(
            snapshot(&assigned(current_owner), 3),
            None,
            successful_response(),
        )
        .await;
        let outcome = recover_pending(&journal_path, &mut client(&server)?).await;
        if current_owner == ORIGINAL_OWNER {
            assert_eq!(outcome?, vec![original.operation_id]);
            assert_requests(&server, &["GET", "POST"]).await;
        } else {
            let error = outcome.expect_err("replay must use the journal's original owner");
            assert!(error.to_string().contains("suppressed"));
            assert_requests(&server, &["GET"]).await;
            assert_only_prepared(&journal_path)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn failed_or_lost_write_response_then_reassignment_never_posts_twice() -> Result<()> {
    for lose_response in [false, true] {
        let directory = tempfile::tempdir()?;
        let journal_path = directory.path().join("journal");
        let response = if lose_response {
            successful_response().set_delay(Duration::from_secs(2))
        } else {
            ResponseTemplate::new(503)
        };
        let server = http_server(
            snapshot(&assigned(ORIGINAL_OWNER), 3),
            Some(snapshot(&assigned(OTHER_OWNER), 3)),
            response,
        )
        .await;
        let mut first_client = impatient_client(&server)?;
        let first_error = execute_plan(
            plan(operation()),
            Some(ORIGINAL_OWNER),
            &journal_path,
            &mut first_client,
        )
        .await
        .expect_err("the first write must fail or lose its response");
        let expected_error = if lose_response { "timed out" } else { "503" };
        assert!(first_error.to_string().contains(expected_error));
        assert_only_prepared(&journal_path)?;
        assert_requests(&server, &["GET", "POST"]).await;
        drop(first_client);
        let mut restarted_client = client(&server)?;
        let error = recover_pending(&journal_path, &mut restarted_client)
            .await
            .expect_err("reassigned monitor must not be checked in on restart");
        assert!(error.to_string().contains("suppressed"));
        assert_requests(&server, &["GET", "POST", "GET"]).await;
        assert_only_prepared(&journal_path)?;
    }
    Ok(())
}

#[tokio::test]
async fn applied_checkin_is_not_duplicated_after_success_or_lost_response() -> Result<()> {
    for lose_response in [false, true] {
        let directory = tempfile::tempdir()?;
        let journal_path = directory.path().join("journal");
        let response = if lose_response {
            successful_response().set_delay(Duration::from_secs(2))
        } else {
            successful_response()
        };
        let server = http_server(
            snapshot(&assigned(ORIGINAL_OWNER), 3),
            Some(snapshot(&Value::Null, CHECKIN_STATUS)),
            response,
        )
        .await;
        let mut first_client = impatient_client(&server)?;
        let outcome = execute_plan(
            plan(operation()),
            Some(ORIGINAL_OWNER),
            &journal_path,
            &mut first_client,
        )
        .await;
        assert_eq!(outcome.is_err(), lose_response);
        drop(first_client);
        let recovered = recover_pending(&journal_path, &mut client(&server)?).await?;
        assert_eq!(recovered, vec![operation().operation_id]);
        assert_requests(&server, &["GET", "POST", "GET"]).await;
        let records = operation_journal::load(&journal_path)?;
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record, JournalRecord::RemoteOutcomeObserved { .. }))
                .count(),
            1
        );
        commit_after_state_save(&journal_path, &recovered)?;
        assert!(
            operation_journal::pending_with_evidence(&operation_journal::load(&journal_path)?)?
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
async fn recovery_rejects_missing_or_zero_owner_before_http() -> Result<()> {
    for wrapped in [false, true] {
        for missing_owner in [false, true] {
            let directory = tempfile::tempdir()?;
            let journal_path = directory.path().join("journal");
            let mut payload = serde_json::to_value(operation())?;
            if missing_owner {
                payload
                    .as_object_mut()
                    .expect("operation object")
                    .remove("expected_asset_id");
            } else {
                payload["expected_asset_id"] = json!(0);
            }
            append_prepared(&journal_path, &payload, wrapped)?;
            let server = MockServer::start().await;
            let error = recover_pending(&journal_path, &mut client(&server)?)
                .await
                .expect_err("unbound legacy check-ins must require operator reconciliation");
            let message = format!("{error:#}");
            assert!(message.contains("expected_asset_id") || message.contains("suppressed"));
            assert_requests(&server, &[]).await;
            assert_only_prepared(&journal_path)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn direct_and_planned_tag_patches_are_blocked_before_http_or_prepare() -> Result<()> {
    for tag in ["OPERATOR-TAG", ""] {
        let server = MockServer::start().await;
        let request = AssetPatchRequest {
            name: Some(String::from("allowed-name-change")),
            asset_tag: Some(String::from(tag)),
            ..AssetPatchRequest::default()
        };
        let error = RemoteMutations::patch_asset(&mut client(&server)?, ORIGINAL_OWNER, &request)
            .await
            .expect_err("tag-bearing patches must fail closed at the adapter boundary");
        assert!(error.to_string().contains("suppressed"));
        let directory = tempfile::tempdir()?;
        let journal_path = directory.path().join("journal");
        let mut patch_plan = plan(operation());
        patch_plan.monitor_checkins.clear();
        patch_plan.asset_update = Some(request);
        assert!(
            execute_plan(
                patch_plan,
                Some(ORIGINAL_OWNER),
                &journal_path,
                &mut client(&server)?,
            )
            .await
            .is_err()
        );
        assert!(operation_journal::load(&journal_path)?.is_empty());
        assert_requests(&server, &[]).await;
    }
    Ok(())
}

#[tokio::test]
async fn legacy_and_wrapped_tag_patches_are_blocked_before_recovery_http() -> Result<()> {
    for wrapped in [false, true] {
        let directory = tempfile::tempdir()?;
        let journal_path = directory.path().join("journal");
        let request = AssetPatchRequest {
            asset_tag: Some(String::from("LEGACY-TAG")),
            ..AssetPatchRequest::default()
        };
        let operation_id = format!("patch:{ORIGINAL_OWNER}:{}", serialize_operation(&request)?);
        prepare(
            &journal_path,
            &operation_id,
            &request,
            wrapped.then(|| {
                complete_candidate_state(
                    &operation_id,
                    &spotter_core::state::ServiceState::default(),
                )
            }),
        )?;
        let server = MockServer::start().await;
        let error = recover_pending(&journal_path, &mut client(&server)?)
            .await
            .expect_err("recovery must not resurrect legacy asset-tag writes");
        assert!(error.to_string().contains("suppressed"));
        assert_requests(&server, &[]).await;
        assert_only_prepared(&journal_path)?;
    }
    Ok(())
}

#[tokio::test]
async fn checkout_does_not_overwrite_foreign_or_ambiguous_assignments() -> Result<()> {
    let checkout = spotter_core::snipeit::build_monitor_checkout(
        "checkout:ownership-regression",
        MONITOR_ID,
        ORIGINAL_OWNER,
        3,
    )?;
    for owner in [
        assigned(OTHER_OWNER),
        json!({"id": ORIGINAL_OWNER, "name": "person", "type": "user"}),
        json!({"id": ORIGINAL_OWNER, "name": "location", "type": "location"}),
        json!({"id": ORIGINAL_OWNER, "name": "unknown"}),
        json!({"id": ORIGINAL_OWNER, "name": "unknown", "type": "unknown"}),
    ] {
        let server = http_server(snapshot(&owner, 3), None, successful_response()).await;
        let error = client(&server)?
            .checkout(&checkout)
            .await
            .expect_err("checkout must not overwrite an incompatible assignment");
        assert!(error.to_string().contains("suppressed"), "{owner}: {error}");
        assert_requests(&server, &["GET"]).await;
    }
    Ok(())
}

#[tokio::test]
async fn checkin_and_checkout_reject_mismatched_remote_asset_identity() -> Result<()> {
    let checkout = spotter_core::snipeit::build_monitor_checkout(
        "checkout:wrong-identity",
        MONITOR_ID,
        ORIGINAL_OWNER,
        CHECKIN_STATUS,
    )?;
    for assigned_to in [assigned(ORIGINAL_OWNER), Value::Null] {
        let mut wrong_asset = snapshot(&assigned_to, CHECKIN_STATUS);
        wrong_asset["id"] = json!(999);
        let server = http_server(wrong_asset, None, successful_response()).await;
        let mut remote = client(&server)?;
        let checkin_error = remote
            .checkin(&operation())
            .await
            .expect_err("check-in must reject a different asset, even when already applied");
        assert!(checkin_error.to_string().contains("identity mismatch"));
        let checkout_error = remote
            .checkout(&checkout)
            .await
            .expect_err("checkout must reject a different asset, even when already applied");
        assert!(checkout_error.to_string().contains("identity mismatch"));
        assert_requests(&server, &["GET", "GET"]).await;
    }
    Ok(())
}

#[tokio::test]
async fn recovery_suppresses_unassigned_monitor_with_wrong_status() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let journal_path = directory.path().join("journal");
    append_prepared(&journal_path, &serde_json::to_value(operation())?, true)?;
    let server = http_server(snapshot(&Value::Null, 99), None, successful_response()).await;
    let error = recover_pending(&journal_path, &mut client(&server)?)
        .await
        .expect_err("unassigned monitors at another status need operator reconciliation");
    assert!(error.to_string().contains("suppressed"));
    assert_requests(&server, &["GET"]).await;
    assert_only_prepared(&journal_path)?;
    Ok(())
}
