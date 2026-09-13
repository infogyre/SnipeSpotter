#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "Tokio requires a raw SECURITY_ATTRIBUTES pointer to create a named pipe with the required DACL"
    )
)]
// pattern: Imperative Shell

//! Bounded JSON-over-newline IPC request serving.

use anyhow::{Context as _, Result, bail};
use spotter_core::ipc::{IPC_MAX_LINE_BYTES, IpcResponse, ServiceCommand};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use crate::fsm::FsmHandle;

const IPC_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const IPC_RESPONSE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Decode one bounded protocol line.
///
/// # Errors
/// Returns an error for oversized, malformed, or empty input.
pub fn decode_command(line: &[u8]) -> Result<ServiceCommand> {
    if line.is_empty() {
        bail!("IPC request is empty")
    }
    if line.len() > IPC_MAX_LINE_BYTES {
        bail!("IPC request exceeds 64 KiB")
    }
    serde_json::from_slice(line).context("invalid IPC request JSON")
}

/// Encode one response plus newline.
///
/// # Errors
/// Returns an error if serialization fails or the result exceeds 64 KiB.
pub fn encode_response(response: &IpcResponse) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(response)?;
    bytes.push(b'\n');
    if bytes.len() > IPC_MAX_LINE_BYTES {
        bail!("IPC response exceeds 64 KiB")
    }
    Ok(bytes)
}

/// Serve exactly one command over an asynchronous duplex stream.
///
/// # Errors
/// Returns an error for framing, transport, service-loop, or serialization failures.
pub async fn serve_one<S>(stream: S, fsm: &FsmHandle) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    serve_one_with_deadlines(
        stream,
        fsm,
        IPC_REQUEST_READ_TIMEOUT,
        IPC_RESPONSE_WRITE_TIMEOUT,
    )
    .await
}

async fn serve_one_with_deadlines<S>(
    stream: S,
    fsm: &FsmHandle,
    read_timeout: std::time::Duration,
    write_timeout: std::time::Duration,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let mut line = Vec::new();
    let max_line_bytes = u64::try_from(IPC_MAX_LINE_BYTES)?;
    let read = tokio::time::timeout(read_timeout, async {
        let mut limited = (&mut stream).take(max_line_bytes);
        limited.read_until(b'\n', &mut line).await
    })
    .await
    .context("IPC request read timed out")??;
    if read == 0 {
        bail!("IPC client disconnected before request")
    }
    if !line.ends_with(b"\n") {
        bail!("IPC request is unterminated or oversized")
    }
    line.pop();
    if line.ends_with(b"\r") {
        line.pop();
    }
    let response = fsm.request(decode_command(&line)?).await?;
    let response = encode_response(&response)?;
    tokio::time::timeout(write_timeout, async {
        stream.get_mut().write_all(&response).await?;
        stream.get_mut().flush().await
    })
    .await
    .context("IPC response write timed out")??;
    Ok(())
}

/// Run the Windows named-pipe accept loop.
///
/// # Errors
/// Returns an error when pipe creation or a client session fails.
#[cfg(windows)]
/// Run the production named-pipe accept loop on the fixed product endpoint.
///
/// # Errors
/// Returns an error when pipe creation or a client session fails.
pub async fn run_named_pipe(fsm: FsmHandle) -> Result<()> {
    run_named_pipe_at(fsm, spotter_core::PIPE_NAME).await
}

/// Fixed bound on concurrently active pipe sessions; excess connections are
/// accepted and promptly closed so saturation cannot queue unbounded tasks.
#[cfg(windows)]
pub const MAX_ACTIVE_PIPE_SESSIONS: usize = 16;

/// Cooperative shutdown signal for the native accept loop.
#[cfg(windows)]
pub struct PipeServerGuard {
    shutdown: tokio_util::sync::CancellationToken,
}

#[cfg(windows)]
impl Default for PipeServerGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl PipeServerGuard {
    #[must_use]
    pub fn new() -> Self {
        Self {
            shutdown: tokio_util::sync::CancellationToken::new(),
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.cancel();
    }

    #[must_use]
    pub fn subscribe(&self) -> tokio_util::sync::CancellationToken {
        self.shutdown.clone()
    }

    /// Alias kept for test readability: yields an independent token handle.
    #[must_use]
    pub fn clone_token(&self) -> Self {
        Self {
            shutdown: self.shutdown.clone(),
        }
    }
}

/// Run the secured named-pipe accept loop on an explicit endpoint with
/// bounded concurrent sessions and cooperative shutdown.
///
/// The endpoint is intended for isolated integration tests. Production callers should use
/// [`run_named_pipe`], which preserves the fixed product pipe identity.
///
/// # Errors
/// Returns an error when pipe creation fails or a client session fails.
#[cfg(windows)]
pub async fn run_named_pipe_at(fsm: FsmHandle, pipe_name: impl Into<String>) -> Result<()> {
    // Sequential compatibility loop for the CLI named-pipe tests: connect,
    // serve inline, repeat. The production service uses
    // [`run_named_pipe_bounded`], which adds bounded concurrency, excess
    // handling, and cooperative shutdown.
    let pipe_name = pipe_name.into();
    let shutdown = PipeServerGuard::new();
    let session_token = shutdown.subscribe();
    let mut first_instance = true;
    loop {
        if shutdown.shutdown.is_cancelled() {
            return Ok(());
        }
        let server = create_secured_server(&pipe_name, first_instance)?;
        first_instance = false;
        tokio::select! {
            outcome = server.connect() => {
                outcome.context("named-pipe client connect failed")?;
            }
            () = session_token.cancelled() => return Ok(()),
        }
        if let Err(error) = serve_one(server, &fsm).await {
            tracing::warn!(%error, "IPC client session failed");
        }
    }
}

/// Run the bounded named-pipe accept loop with cooperative shutdown.
///
/// # Errors
/// Returns an error when pipe creation fails or the shutdown drain exceeds
/// its deadline.
#[cfg(windows)]
pub async fn run_named_pipe_bounded(
    fsm: FsmHandle,
    pipe_name: impl Into<String>,
    session_token: tokio_util::sync::CancellationToken,
) -> Result<()> {
    use tokio::task::JoinSet;

    let pipe_name = pipe_name.into();
    let shutdown = session_token.clone();
    let mut sessions: JoinSet<Result<()>> = JoinSet::new();
    let mut first_instance = true;
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        // Create the next listening instance promptly; never hold a session
        // slot while awaiting an unaccepted connection.
        if sessions.len() >= MAX_ACTIVE_PIPE_SESSIONS {
            // Capacity full: reap completed sessions, then accept and promptly
            // close any excess connection rather than queueing it. The connect
            // wait stays interruptible by shutdown.
            while sessions.try_join_next().is_some() {}
            let server = create_secured_server(&pipe_name, false)?;
            tokio::select! {
                outcome = server.connect() => {
                    outcome.context("named-pipe client connect failed")?;
                }
                () = shutdown.cancelled() => break,
            }
            drop(server);
            continue;
        }
        let server = create_secured_server(&pipe_name, first_instance)?;
        first_instance = false;
        tokio::select! {
            outcome = server.connect() => {
                outcome.context("named-pipe client connect failed")?;
            }
            () = shutdown.cancelled() => break,
        }
        let fsm = fsm.clone();
        sessions.spawn(async move {
            // Shutdown never cancels an in-flight session: sessions finish
            // during the bounded drain window and only the deadline aborts
            // leftovers. This ends response observation, not the owner.
            serve_one(server, &fsm).await
        });
    }
    // Cooperative shutdown: stop accepting, drain active sessions under a
    // bounded deadline, then abort leftovers and observe joins with a fixed
    // diagnostic. This ends response observation, never an FSM cancellation.
    let drained = tokio::time::timeout(SHUTDOWN_DRAIN, async {
        while sessions.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
        tracing::warn!("pipe shutdown drain deadline elapsed; remaining sessions aborted");
    }
    Ok(())
}

/// Fixed drain window for cooperative pipe shutdown before leftovers abort.
#[cfg(windows)]
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(windows)]
fn create_secured_server(
    pipe_name: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use spotter_win32::pipe::create_admin_pipe_security_attributes;
    use tokio::net::windows::named_pipe::ServerOptions;

    let security = create_admin_pipe_security_attributes()
        .context("failed to build named-pipe security attributes")?;
    // SAFETY: `security` owns a valid SECURITY_ATTRIBUTES structure and its backing security
    // descriptor. Both remain alive through this synchronous call, and CreateNamedPipeW consumes
    // the attributes only while creating the pipe handle; it does not retain the pointer.
    unsafe {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first_instance);
        options
            .create_with_security_attributes_raw(pipe_name, security.as_ptr().cast_mut().cast())
            .context("failed to create secured named pipe")
    }
}

/// Test-support construction of one secured named-pipe instance, including the first-instance flag.
#[cfg(all(windows, feature = "test-support"))]
#[doc(hidden)]
pub fn create_secured_server_for_tests(
    pipe_name: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    create_secured_server(pipe_name, first_instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm;

    #[test]
    fn rejects_oversized_and_roundtrips_json() -> Result<()> {
        assert!(decode_command(&[]).is_err());
        assert!(decode_command(b"not-json").is_err());
        assert!(decode_command(&vec![b'x'; IPC_MAX_LINE_BYTES + 1]).is_err());
        let command = ServiceCommand::GetStatus;
        assert_eq!(decode_command(&serde_json::to_vec(&command)?)?, command);
        assert!(
            encode_response(&IpcResponse::Ok {
                message: String::from("ok")
            })?
            .ends_with(b"\n")
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplex_roundtrip_waits_for_fsm() -> Result<()> {
        let fsm = fsm::spawn(1, |_| async {
            IpcResponse::Ok {
                message: String::from("committed"),
            }
        })?;
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { serve_one(server, &fsm).await });
        let mut client = BufReader::new(client);
        client
            .get_mut()
            .write_all(b"{\"cmd\":\"get_status\"}\n")
            .await?;
        let mut line = String::new();
        client.read_line(&mut line).await?;
        assert!(line.contains("committed"));
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn accepts_crlf_framing() -> Result<()> {
        let fsm = fsm::spawn(1, |_| async {
            IpcResponse::Ok {
                message: String::from("crlf-ok"),
            }
        })?;
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move { serve_one(server, &fsm).await });
        let mut client = BufReader::new(client);
        client
            .get_mut()
            .write_all(b"{\"cmd\":\"get_status\"}\r\n")
            .await?;
        let mut line = String::new();
        client.read_line(&mut line).await?;
        assert!(line.contains("crlf-ok"));
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_disconnect_and_unterminated_requests() -> Result<()> {
        let fsm = fsm::spawn(1, |_| async {
            IpcResponse::Ok {
                message: String::from("unused"),
            }
        })?;

        let (client, server) = tokio::io::duplex(4096);
        drop(client);
        assert!(serve_one(server, &fsm).await.is_err());

        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"{\"cmd\":\"get_status\"}").await?;
        drop(client);
        let error = serve_one(server, &fsm)
            .await
            .expect_err("unterminated requests must be rejected");
        assert!(error.to_string().contains("unterminated"));
        Ok(())
    }

    #[tokio::test]
    async fn ipc_read_deadline_prevents_dispatch() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;

        let dispatches = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&dispatches);
        let fsm = fsm::spawn(1, move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async {
                IpcResponse::Ok {
                    message: String::from("unexpected"),
                }
            }
        })?;
        let (_client, server) = tokio::io::duplex(16);

        let error = serve_one_with_deadlines(
            server,
            &fsm,
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .await
        .expect_err("an idle connected client must hit the request-read deadline");

        assert!(error.to_string().contains("read timed out"));
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn ipc_write_deadline_preserves_commit() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Duration;

        let committed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&committed);
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
        let mut started_sender = Some(started_sender);
        let mut release_receiver = Some(release_receiver);
        let fsm = fsm::spawn(1, move |_| {
            let started_sender = started_sender.take();
            let release_receiver = release_receiver.take();
            let observed = Arc::clone(&observed);
            async move {
                if let Some(sender) = started_sender {
                    let _ = sender.send(());
                }
                if let Some(receiver) = release_receiver {
                    let _ = receiver.await;
                }
                observed.store(true, Ordering::SeqCst);
                IpcResponse::Ok {
                    message: String::from("committed"),
                }
            }
        })?;
        let (mut client, server) = tokio::io::duplex(1);
        let server_task = tokio::spawn(async move {
            serve_one_with_deadlines(
                server,
                &fsm,
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await
        });
        client.write_all(b"{\"cmd\":\"get_status\"}\n").await?;
        started_receiver
            .await
            .map_err(|_| anyhow::anyhow!("handler start observation was cancelled"))?;
        assert!(
            !committed.load(Ordering::SeqCst),
            "commit marker must remain unset until the handler future completes"
        );
        release_sender
            .send(())
            .map_err(|()| anyhow::anyhow!("failed to release handler"))?;

        let error = server_task
            .await?
            .expect_err("a deliberately blocked tiny-buffer write must time out");

        assert!(error.to_string().contains("write timed out"));
        assert!(committed.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn client_disconnect_does_not_cancel_handler() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Duration;

        let committed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&committed);
        let fsm = fsm::spawn(1, move |_| {
            let observed = Arc::clone(&observed);
            async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                observed.store(true, Ordering::SeqCst);
                IpcResponse::Ok {
                    message: String::from("committed"),
                }
            }
        })?;
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"{\"cmd\":\"get_status\"}\n").await?;
        let server_task = tokio::spawn(async move {
            serve_one_with_deadlines(
                server,
                &fsm,
                Duration::from_secs(1),
                Duration::from_millis(10),
            )
            .await
        });
        drop(client);

        let _ = server_task.await?;
        assert!(committed.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_duplex_clients_are_serialized_at_fsm_boundary() -> Result<()> {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&events);
        let fsm = fsm::spawn(2, move |_| {
            let observed = Arc::clone(&observed);
            async move {
                if let Ok(mut values) = observed.lock() {
                    values.push(String::from("start"));
                }
                tokio::task::yield_now().await;
                if let Ok(mut values) = observed.lock() {
                    values.push(String::from("commit"));
                }
                IpcResponse::Ok {
                    message: String::from("done"),
                }
            }
        })?;

        let (first_client, first_server) = tokio::io::duplex(4096);
        let (second_client, second_server) = tokio::io::duplex(4096);
        let first_server_task = {
            let fsm = fsm.clone();
            tokio::spawn(async move { serve_one(first_server, &fsm).await })
        };
        let second_server_task = tokio::spawn(async move { serve_one(second_server, &fsm).await });
        let mut first_client = BufReader::new(first_client);
        let mut second_client = BufReader::new(second_client);
        first_client
            .get_mut()
            .write_all(b"{\"cmd\":\"get_status\"}\n")
            .await?;
        second_client
            .get_mut()
            .write_all(b"{\"cmd\":\"get_config\"}\n")
            .await?;
        let mut first_response = String::new();
        let mut second_response = String::new();
        first_client.read_line(&mut first_response).await?;
        second_client.read_line(&mut second_response).await?;
        assert!(first_response.contains("done"));
        assert!(second_response.contains("done"));
        first_server_task.await??;
        second_server_task.await??;

        let events = events
            .lock()
            .map_err(|_| anyhow::anyhow!("events lock poisoned"))?;
        assert_eq!(events.as_slice(), ["start", "commit", "start", "commit"]);
        Ok(())
    }
}
