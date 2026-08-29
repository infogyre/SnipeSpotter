#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "The Windows named-pipe readiness probe calls WaitNamedPipeW directly"
)]

use std::process::{Command, Output};

#[cfg(all(windows, feature = "test-support"))]
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[cfg(all(windows, feature = "test-support"))]
use spotter_core::ipc::IpcResponse;

fn run_cli<I, S>(arguments: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_spotter-cli"))
        .args(arguments)
        .output()
        .expect("the built spotter-cli executable should start")
}

#[cfg(all(windows, feature = "test-support"))]
struct TestIdentity {
    service_name: String,
    data_root: PathBuf,
    pipe_endpoint: String,
    mutex_name: String,
    service_executable: PathBuf,
}

#[cfg(all(windows, feature = "test-support"))]
impl TestIdentity {
    fn cli_arguments(&self, command: &[&str]) -> Vec<String> {
        let mut arguments = vec![
            String::from("--test-service-name"),
            self.service_name.clone(),
            String::from("--test-data-root"),
            self.data_root.to_string_lossy().into_owned(),
            String::from("--test-pipe-endpoint"),
            self.pipe_endpoint.clone(),
            String::from("--test-mutex-name"),
            self.mutex_name.clone(),
            String::from("--test-service-executable"),
            self.service_executable.to_string_lossy().into_owned(),
        ];
        arguments.extend(command.iter().map(|argument| (*argument).to_owned()));
        arguments
    }
}

#[cfg(all(windows, feature = "test-support"))]
fn test_identity() -> TestIdentity {
    let unique = format!("{}-{}", std::process::id(), unique_nonce());
    TestIdentity {
        service_name: format!("SnipeSpotter-binary-{unique}"),
        data_root: std::env::temp_dir().join(format!("SnipeSpotter-binary-{unique}")),
        pipe_endpoint: format!(r"\\.\pipe\SnipeSpotter-binary-{unique}"),
        mutex_name: format!(r"Global\SnipeSpotter-binary-{unique}"),
        service_executable: PathBuf::from(r"C:\SnipeSpotter\spotter-svc.exe"),
    }
}

#[cfg(all(windows, feature = "test-support"))]
fn unique_nonce() -> u64 {
    static NEXT_NONCE: AtomicU64 = AtomicU64::new(0);
    NEXT_NONCE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(all(windows, feature = "test-support"))]
fn assert_json_status(stdout: &[u8]) {
    let response: IpcResponse =
        serde_json::from_slice(stdout).expect("actual binary stdout must be JSON IPC response");
    assert_eq!(
        response,
        IpcResponse::Status {
            state: String::from("Idle"),
            last_sync: None,
            next_sync: None,
            snipeit_url: String::from("https://snipe.example.test"),
        }
    );
}

#[cfg(all(windows, feature = "test-support"))]
async fn wait_for_pipe(endpoint: &str) {
    let endpoint = endpoint.to_owned();
    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if pipe_is_available(&endpoint) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "named pipe did not become available before the deadline"
            );
            // Tokio exposes no readiness event for a newly created named-pipe instance, so use a
            // bounded Windows API poll rather than an unbounded wait or a fixed startup delay.
            std::thread::sleep(Duration::from_millis(25));
        }
    })
    .await
    .expect("pipe readiness task must not panic");
}

#[cfg(all(windows, feature = "test-support"))]
fn pipe_is_available(endpoint: &str) -> bool {
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::HSTRING;

    let endpoint = HSTRING::from(endpoint);
    // SAFETY: `endpoint` is a valid nul-terminated Windows string owned by `HSTRING`; a zero
    // timeout only probes the current pipe state and never blocks this readiness poll.
    unsafe { WaitNamedPipeW(&endpoint, 0).as_bool() }
}

#[cfg(all(windows, feature = "test-support"))]
struct ServerGuard {
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

#[cfg(all(windows, feature = "test-support"))]
struct ReleaseGuard(Option<tokio::sync::oneshot::Sender<()>>);

#[cfg(all(windows, feature = "test-support"))]
impl ReleaseGuard {
    fn release(mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(all(windows, feature = "test-support"))]
impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(all(windows, feature = "test-support"))]
impl ServerGuard {
    fn spawn(fsm: spotter_svc::fsm::FsmHandle, endpoint: String) -> Self {
        Self {
            task: Some(tokio::spawn(spotter_svc::ipc_server::run_named_pipe_at(
                fsm, endpoint,
            ))),
        }
    }

    async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(all(windows, feature = "test-support"))]
impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(all(windows, feature = "test-support"))]
#[tokio::test]
async fn actual_binary_status_roundtrips_on_isolated_service_endpoint() {
    let identity = test_identity();
    let fsm = spotter_svc::fsm::spawn(1, |_| async {
        spotter_core::ipc::IpcResponse::Status {
            state: String::from("Idle"),
            last_sync: None,
            next_sync: None,
            snipeit_url: String::from("https://snipe.example.test"),
        }
    })
    .expect("test FSM must start");
    let server = ServerGuard::spawn(fsm, identity.pipe_endpoint.clone());
    wait_for_pipe(&identity.pipe_endpoint).await;

    let arguments = identity.cli_arguments(&["--json", "status"]);
    let output = tokio::task::spawn_blocking(move || run_cli(&arguments))
        .await
        .expect("actual binary task must not panic");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_json_status(&output.stdout);

    server.shutdown().await;
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn actual_binary_unbound_endpoint_is_deterministically_unavailable() {
    let identity = test_identity();
    assert!(!pipe_is_available(&identity.pipe_endpoint));

    let arguments = identity.cli_arguments(&["status"]);
    let output = run_cli(arguments.iter().map(String::as_str).collect::<Vec<_>>());

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("error: "));
    assert!(stderr.ends_with(": service is not running\n"));
    assert_eq!(stderr.matches('\n').count(), 1);
}

#[cfg(all(windows, feature = "test-support"))]
#[tokio::test]
async fn connected_nonresponsive_service_times_out_as_generic_error() {
    let identity = test_identity();
    let (received_sender, received) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let release_guard = ReleaseGuard(Some(release_sender));
    let mut received_sender = Some(received_sender);
    let mut release_receiver = Some(release_receiver);
    let fsm = spotter_svc::fsm::spawn(1, move |_| {
        let received_sender = received_sender.take();
        let release_receiver = release_receiver.take();
        async move {
            if let Some(received_sender) = received_sender {
                let _ = received_sender.send(());
            }
            if let Some(release_receiver) = release_receiver {
                let _ = release_receiver.await;
            }
            IpcResponse::Ok {
                message: String::from("released"),
            }
        }
    })
    .expect("test FSM must start");
    let server = ServerGuard::spawn(fsm, identity.pipe_endpoint.clone());
    wait_for_pipe(&identity.pipe_endpoint).await;

    let mut arguments = identity.cli_arguments(&["status"]);
    arguments.splice(
        0..0,
        [
            String::from("--test-transport-timeout-ms"),
            String::from("200"),
        ],
    );
    let output = tokio::task::spawn_blocking(move || run_cli(arguments))
        .await
        .expect("actual binary task must not panic");
    tokio::time::timeout(Duration::from_secs(1), received)
        .await
        .expect("server must receive the request before the timeout assertion")
        .expect("server receive signal must not be cancelled");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"error: service request timed out\n");
    release_guard.release();
    server.shutdown().await;
}

#[test]
fn help_is_served_by_the_actual_binary() {
    let output = run_cli(["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: spotter-cli"));
    assert!(stdout.contains("config"));
    assert!(stdout.contains("service"));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_arguments_use_clap_error_contract() {
    let output = run_cli(["--not-a-real-option"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("error:"));
    assert!(stderr.contains("Usage: spotter-cli"));
}

#[test]
fn unavailable_service_uses_exit_code_two_and_stderr_only() {
    let output = run_cli(["status"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("service is not running"));
}

#[test]
fn malformed_command_reports_generic_cli_error_without_stdout() {
    let output = run_cli(["checkin"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("error:"));
    assert!(stderr.contains("specify --all or a monitor serial"));
}
