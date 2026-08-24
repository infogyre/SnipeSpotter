#![cfg(windows)]

use std::time::Duration;

use anyhow::Result;
use spotter_cli::{IpcTransport, NamedPipeTransport};
use spotter_core::ipc::{IpcResponse, ServiceCommand};

fn unique_pipe_endpoint() -> String {
    format!(
        r"\\.\pipe\SnipeSpotter-test-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("main")
    )
}

#[tokio::test]
async fn secured_server_and_production_client_roundtrip_on_unique_pipe() -> Result<()> {
    let endpoint = unique_pipe_endpoint();
    let fsm = spotter_svc::fsm::spawn(1, |_| async {
        IpcResponse::Ok {
            message: String::from("pipe-committed"),
        }
    })?;
    let server = tokio::spawn(spotter_svc::ipc_server::run_named_pipe_at(
        fsm,
        endpoint.clone(),
    ));

    let response = tokio::task::spawn_blocking(move || {
        let mut transport = NamedPipeTransport::with_endpoint(Duration::from_secs(5), endpoint);
        transport.send(&ServiceCommand::GetStatus)
    })
    .await??;

    assert_eq!(
        response,
        IpcResponse::Ok {
            message: String::from("pipe-committed")
        }
    );
    server.abort();
    let _ = server.await;
    Ok(())
}
