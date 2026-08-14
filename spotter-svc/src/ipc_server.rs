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
    let mut stream = BufReader::new(stream);
    let mut line = Vec::new();
    let read = {
        let mut limited = (&mut stream).take(u64::try_from(IPC_MAX_LINE_BYTES)?);
        limited.read_until(b'\n', &mut line).await?
    };
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
    stream
        .get_mut()
        .write_all(&encode_response(&response)?)
        .await?;
    stream.get_mut().flush().await?;
    Ok(())
}

/// Run the Windows named-pipe accept loop.
///
/// # Errors
/// Returns an error when pipe creation or a client session fails.
#[cfg(windows)]
pub async fn run_named_pipe(fsm: FsmHandle) -> Result<()> {
    loop {
        let server = create_secured_server()?;
        server.connect().await?;
        if let Err(error) = serve_one(server, &fsm).await {
            tracing::warn!(%error, "IPC client session failed");
        }
    }
}

#[cfg(windows)]
fn create_secured_server() -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use spotter_core::PIPE_NAME;
    use spotter_win32::pipe::create_admin_pipe_security_attributes;
    use tokio::net::windows::named_pipe::ServerOptions;

    let security = create_admin_pipe_security_attributes()
        .context("failed to build named-pipe security attributes")?;
    // SAFETY: `security` owns a valid SECURITY_ATTRIBUTES structure and its backing security
    // descriptor. Both remain alive through this synchronous call, and CreateNamedPipeW consumes
    // the attributes only while creating the pipe handle; it does not retain the pointer.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(false)
            .create_with_security_attributes_raw(PIPE_NAME, security.as_ptr().cast_mut().cast())
            .context("failed to create secured named pipe")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm;

    #[test]
    fn rejects_oversized_and_roundtrips_json() -> Result<()> {
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
}
