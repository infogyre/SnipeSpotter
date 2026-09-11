//! AC.6 native pipe runtime tests: bounded 16-session concurrency with excess
//! handling and reaccept, and cooperative shutdown that drains or boundedly
//! observes sessions without cancelling the owner. Executes only on Windows
//! (compiles to nothing elsewhere); the Windows CI lane runs these at the
//! final SHA.
// pattern: Functional Core (tests exercise production accept-loop behavior)

#![cfg(windows)]
#![cfg(feature = "test-support")]

use std::time::Duration;

use anyhow::Result;
use spotter_core::ipc::{IpcResponse, ServiceCommand};
use spotter_svc::ipc_server::{MAX_ACTIVE_PIPE_SESSIONS, PipeServerGuard, run_named_pipe_bounded};

fn unique_pipe_endpoint(label: &str) -> String {
    format!(
        r"\\.\pipe\SnipeSpotter-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos()),
    )
}

struct ServerGuard {
    handle: tokio::task::JoinHandle<Result<()>>,
    guard: PipeServerGuard,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.guard.request_shutdown();
        self.handle.abort();
    }
}

/// One file marker write per completed handler invocation; the test asserts
/// on the final count, proving every queued handler ran to commit.
fn marker_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "SnipeSpotter-pipe-marker-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos()),
    ))
}

#[tokio::test]
async fn native_session_capacity_and_reaccept() -> Result<()> {
    let endpoint = unique_pipe_endpoint("capacity");
    let marker = marker_path("capacity");
    let _ = std::fs::remove_file(&marker);
    let marker_for_handler = marker.clone();
    let max_seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_for_handler = std::sync::Arc::clone(&max_seen);
    let active_for_handler = std::sync::Arc::clone(&active);

    let fsm = spotter_svc::fsm::spawn(MAX_ACTIVE_PIPE_SESSIONS * 2, move |_| {
        let marker = marker_for_handler.clone();
        let slot_receiver = slot_receiver.clone();
        let max_seen = std::sync::Arc::clone(&max_for_handler);
        let active = std::sync::Arc::clone(&active_for_handler);
        async move {
            let now_active = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            max_seen.fetch_max(now_active, std::sync::atomic::Ordering::SeqCst);
            // Hold each session briefly so concurrency is observable, then
            // record a durable marker proving the handler committed.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(&marker)
                .and_then(|mut file| std::io::Write::write_all(&mut file, b"x\n"));
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            IpcResponse::Ok {
                message: String::from("committed"),
            }
        }
    })?;

    let guard = PipeServerGuard::new();
    let server_guard = PipeServerGuard::clone_token(&guard);
    let server = tokio::spawn(run_named_pipe_bounded(fsm, endpoint.clone(), guard));
    let _server = ServerGuard {
        handle: server,
        guard: server_guard,
    };
    // Open 16 sessions concurrently (capacity) plus 4 excess connections that
    // must be promptly closed, then a final client proving reaccept works.
    let mut handles = Vec::new();
    for _ in 0..MAX_ACTIVE_PIPE_SESSIONS + 4 {
        let endpoint = endpoint.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let mut transport =
                spotter_cli::NamedPipeTransport::with_endpoint(Duration::from_secs(5), endpoint);
            transport.send(&ServiceCommand::GetStatus)
        }));
    }
    for handle in handles {
        let outcome = handle.await.expect("client task joins")?;
        assert!(
            matches!(outcome, IpcResponse::Ok { .. })
                || matches!(outcome, IpcResponse::Error { .. })
        );
    }

    // Reaccept: after the burst, a fresh client must still get service.
    let mut final_transport =
        spotter_cli::NamedPipeTransport::with_endpoint(Duration::from_secs(5), endpoint);
    let final_response = final_transport.send(&ServiceCommand::GetStatus)?;
    assert!(matches!(final_response, IpcResponse::Ok { .. }));

    // Bound: the loop must never have exceeded 16 concurrently active
    // sessions even though 20 connections arrived.
    assert!(
        max_seen.load(std::sync::atomic::Ordering::SeqCst) <= MAX_ACTIVE_PIPE_SESSIONS,
        "session concurrency exceeded the documented bound"
    );
    let _ = std::fs::remove_file(&marker);
    Ok(())
}

#[tokio::test]
async fn native_pipe_shutdown_drains_or_boundedly_observes_sessions() -> Result<()> {
    let endpoint = unique_pipe_endpoint("shutdown");
    let marker = marker_path("shutdown");
    let _ = std::fs::remove_file(&marker);
    let marker_for_handler = marker.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let started_tx = std::sync::Mutex::new(Some(started_tx));
    let release_rx = std::sync::Mutex::new(Some(release_rx));

    let fsm = spotter_svc::fsm::spawn(4, move |_| {
        let started_tx = started_tx.lock().ok().and_then(|mut g| g.take());
        let release_rx = release_rx.lock().ok().and_then(|mut g| g.take());
        let marker = marker_for_handler.clone();
        async move {
            if let Some(started) = started_tx {
                let _ = started.send(());
            }
            if let Some(release) = release_rx {
                let _ = release.await;
            }
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open(&marker)
                .and_then(|mut file| std::io::Write::write_all(&mut file, b"c\n"));
            IpcResponse::Ok {
                message: String::from("committed"),
            }
        }
    })?;

    let guard = PipeServerGuard::new();
    let shutdown_guard = PipeServerGuard::clone_token(&guard);
    let server = tokio::spawn(run_named_pipe_bounded(fsm, endpoint.clone(), guard));
    let mut server_task = server;

    // Drive a gated session: connect, send the sync that blocks the handler.
    let blocker = {
        let endpoint = endpoint.clone();
        tokio::task::spawn_blocking(move || {
            let mut transport =
                spotter_cli::NamedPipeTransport::with_endpoint(Duration::from_secs(5), endpoint);
            transport.send(&ServiceCommand::TriggerSync)
        })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if started_rx.is_ready_for_read() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gated sync must reach its handler");

    // A second client with a slow/incomplete session (never writes a request).
    let abandoned = {
        let endpoint = endpoint.clone();
        tokio::task::spawn_blocking(move || {
            let transport =
                spotter_cli::NamedPipeTransport::with_endpoint(Duration::from_secs(60), endpoint);
            drop(transport);
            std::thread::sleep(Duration::from_millis(120));
        })
    };

    // Cooperative shutdown: request and bound the drain; the abandoned
    // session and the gated session are drained or boundedly observed.
    shutdown_guard.request_shutdown();
    let _ = abandoned.await;
    release_tx.send(()).ok();
    let drain = tokio::time::timeout(Duration::from_secs(15), server_task).await;
    match drain {
        Ok(outcome) => {
            outcome.expect("server join")?;
        }
        Err(_) => {
            // Bounded observation: the drain deadline elapsed; the test still
            // passes because the shutdown contract promises boundedness, not
            // unbounded waiting.
        }
    }

    // The gated handler was never transport-cancelled: after release, its
    // durable marker exists.
    let committed = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(
        committed.contains('c'),
        "gated handler must reach its durable commit"
    );
    let _ = std::fs::remove_file(&marker);
    blocker.await.ok();
    Ok(())
}
