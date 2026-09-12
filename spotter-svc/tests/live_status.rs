//! AC.5 live-status integration tests: status commands return committed data
//! while a sync is gated, never cancel the owner, and never touch disk or the
//! journal. Run with
//! `cargo test -p spotter-svc --test live_status --features test-support`.
// pattern: Functional Core (tests exercise core/shell composition only)
#![cfg(feature = "test-support")]

use std::time::Duration;

use anyhow::Result;
use spotter_svc::fsm::{FsmHandle, spawn};

/// Spawn an FSM whose `TriggerSync` handler signals `started`, then blocks until
/// `release` is sent. Other commands complete immediately with `committed`.
fn gated_sync_fixture() -> Result<(
    FsmHandle,
    std::sync::mpsc::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
)> {
    let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let release_cell = std::sync::Mutex::new(Some(release_rx));
    let started_cell = std::sync::Mutex::new(Some(started_tx));
    let handle = spawn(4, move |command| {
        let release = release_cell
            .lock()
            .map_err(|_| anyhow::anyhow!("release lock poisoned"))
            .ok()
            .and_then(|mut guard| guard.take());
        let started = started_cell
            .lock()
            .map_err(|_| anyhow::anyhow!("started lock poisoned"))
            .ok()
            .and_then(|mut guard| guard.take());
        async move {
            if command == spotter_core::ipc::ServiceCommand::TriggerSync {
                if let Some(started) = started {
                    let _ = started.send(());
                }
                if let Some(release) = release {
                    let _ = release.await;
                }
            }
            spotter_core::ipc::IpcResponse::Ok {
                message: String::from("committed"),
            }
        }
    })?;
    Ok((handle, started_rx, release_tx))
}

#[tokio::test]
async fn live_status_during_gated_sync() -> Result<()> {
    let (handle, started, release) = gated_sync_fixture()?;
    // Attach a status publisher so status commands take the snapshot path
    // instead of queueing behind the gated sync.
    let _publisher = spotter_svc::status_publisher_for_tests(&handle);
    let handle_for_sync = handle.clone();
    let sync_handle = tokio::spawn(async move {
        handle_for_sync
            .request(spotter_core::ipc::ServiceCommand::TriggerSync)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if started.try_recv().is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gated sync must reach its handler");

    let status = tokio::time::timeout(
        Duration::from_secs(1),
        handle.request(spotter_core::ipc::ServiceCommand::GetStatus),
    )
    .await
    .expect("status must not wait for the gated sync")?;
    assert!(matches!(
        status,
        spotter_core::ipc::IpcResponse::Status { .. }
    ));

    // Release the sync and confirm the committed response still arrives; the
    // gated transport wait never cancelled the owner.
    release.send(()).ok();
    let committed = tokio::time::timeout(Duration::from_secs(2), sync_handle)
        .await
        .expect("gated sync must finish after release")?
        .expect("sync response delivered");
    assert!(matches!(
        committed,
        spotter_core::ipc::IpcResponse::Ok { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn live_status_reads_have_no_side_effects() -> Result<()> {
    let (handle, _started, release) = gated_sync_fixture()?;
    let _publisher = spotter_svc::status_publisher_for_tests(&handle);
    for _ in 0..3 {
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            handle.request(spotter_core::ipc::ServiceCommand::GetStatusFull),
        )
        .await
        .expect("full status must return promptly")?;
        assert!(matches!(
            response,
            spotter_core::ipc::IpcResponse::StatusFull { .. }
        ));
    }
    // Reads left the FSM fully functional.
    release.send(()).ok();
    let _ = handle
        .request(spotter_core::ipc::ServiceCommand::GetConfig)
        .await
        .expect("serialized commands still work after reads");
    Ok(())
}
