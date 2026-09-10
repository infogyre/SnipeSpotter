#![cfg(windows)]

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
    #[expect(
        unsafe_code,
        reason = "The Windows named-pipe readiness probe calls WaitNamedPipeW directly"
    )]
    unsafe {
        WaitNamedPipeW(&endpoint, 0).as_bool()
    }
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
#[tokio::test]
async fn actual_binary_config_selection_and_status_outputs_match_contract() {
    let identity = test_identity();
    let mut settings = spotter_core::Settings::default();
    settings.snipeit.url = String::from("https://example.test/\u{1b}[31m");
    settings.snipeit.api_token_encrypted = vec![0x41, 0x42];
    settings.snipeit.checkout_status_id = 11;
    settings.snipeit.checkin_status_id = 12;
    settings.polling.interval_hours = 7;
    settings.logging.level = String::from("debug\nnext");
    settings.logging.max_size_mb = 20;
    settings.logging.max_files = 4;
    settings.monitors.checkin_policy = spotter_core::CheckinPolicy::AutoNonPortable;
    settings.monitors.checkin_threshold_hours = 48;
    let fsm = spotter_svc::fsm::spawn(4, move |command| {
        let settings = settings.clone();
        async move {
            match command {
                spotter_core::ipc::ServiceCommand::GetConfig => {
                    spotter_core::ipc::IpcResponse::Config {
                        settings: spotter_core::ipc::redact_settings(&settings),
                        missing: vec![String::from("snipeit.url")],
                    }
                }
                spotter_core::ipc::ServiceCommand::GetStatus => {
                    spotter_core::ipc::IpcResponse::Status {
                        state: String::from("Syncing\u{1b}[31m"),
                        last_sync: None,
                        next_sync: Some(String::from("2026-01-02T00:00:00Z\nunsafe")),
                        snipeit_url: String::from("https://status.example\u{1b}[2J"),
                    }
                }
                spotter_core::ipc::ServiceCommand::GetStatusFull => {
                    spotter_core::ipc::IpcResponse::StatusFull {
                        state: String::from("Idle"),
                        last_sync: Some(String::from("2026-01-01T00:00:00Z")),
                        next_sync: None,
                        snipeit_url: String::from("https://status.example"),
                        matched_asset: Some(spotter_core::state::AssetSummary {
                            id: 42,
                            name: String::from("Laptop"),
                            serial: Some(String::from("SERIAL")),
                            asset_tag: None,
                        }),
                        monitors: vec![
                            spotter_core::ipc::MonitorStatus {
                                serial: String::from("MON-B"),
                                asset_id: None,
                                checked_out: false,
                                absent_since: None,
                            },
                            spotter_core::ipc::MonitorStatus {
                                serial: String::from("MON-A"),
                                asset_id: Some(7),
                                checked_out: true,
                                absent_since: Some(String::from("2026-01-03")),
                            },
                        ],
                    }
                }
                _ => spotter_core::ipc::IpcResponse::Ok {
                    message: String::from("ok"),
                },
            }
        }
    })
    .expect("test FSM must start");
    let server = ServerGuard::spawn(fsm, identity.pipe_endpoint.clone());
    wait_for_pipe(&identity.pipe_endpoint).await;

    let selected = identity.cli_arguments(&["--json", "config", "get", "polling.interval_hours"]);
    let selected = tokio::task::spawn_blocking(move || run_cli(&selected))
        .await
        .expect("selected config task must not panic");
    assert!(selected.status.success());
    assert!(selected.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&selected.stdout).expect("scalar JSON"),
        7
    );

    let complete = identity.cli_arguments(&["--json", "config", "get"]);
    let complete = tokio::task::spawn_blocking(move || run_cli(&complete))
        .await
        .expect("complete config task must not panic");
    assert!(complete.status.success());
    let complete_json: serde_json::Value =
        serde_json::from_slice(&complete.stdout).expect("config envelope JSON");
    assert_eq!(complete_json["type"], "config");
    assert_eq!(complete_json["data"]["missing"][0], "snipeit.url");
    assert_eq!(
        complete_json["data"]["settings"]["snipeit"]["api_token_encrypted"],
        ""
    );

    let human_config = identity.cli_arguments(&["config", "get"]);
    let human_config = tokio::task::spawn_blocking(move || run_cli(&human_config))
        .await
        .expect("human config task must not panic");
    assert!(human_config.status.success());
    let human_config = String::from_utf8(human_config.stdout).expect("human config UTF-8");
    assert!(human_config.contains("snipeit.url: https://example.test/\\u{1b}[31m"));
    assert!(human_config.contains("logging.level: debug\\nnext"));
    assert!(human_config.contains("missing: snipeit.url"));
    assert!(!human_config.contains("4142") && !human_config.contains("configured"));

    let status = identity.cli_arguments(&["status"]);
    let status = tokio::task::spawn_blocking(move || run_cli(&status))
        .await
        .expect("status task must not panic");
    assert!(status.status.success());
    let status = String::from_utf8(status.stdout).expect("human status UTF-8");
    assert!(status.contains("State: Syncing\\u{1b}[31m"));
    assert!(status.contains("Last Sync: <none>"));
    assert!(status.contains("Next Sync: 2026-01-02T00:00:00Z\\nunsafe"));
    assert!(!status.contains("Matched Asset:"));

    let full = identity.cli_arguments(&["status", "--full"]);
    let full = tokio::task::spawn_blocking(move || run_cli(&full))
        .await
        .expect("full status task must not panic");
    assert!(full.status.success());
    let full = String::from_utf8(full.stdout).expect("human full status UTF-8");
    assert!(full.contains("Matched Asset: Laptop (ID 42, serial SERIAL, asset tag <none>)"));
    assert!(full.find("  MON-A:").expect("MON-A") < full.find("  MON-B:").expect("MON-B"));
    assert!(full.contains("MON-A: asset 7, checked out true, absent since 2026-01-03"));

    server.shutdown().await;
}

#[cfg(all(windows, feature = "test-support"))]
#[tokio::test]
async fn actual_binary_empty_full_status_uses_explicit_placeholders() {
    let identity = test_identity();
    let fsm = spotter_svc::fsm::spawn(1, |_| async {
        spotter_core::ipc::IpcResponse::StatusFull {
            state: String::from("Idle"),
            last_sync: None,
            next_sync: None,
            snipeit_url: String::new(),
            matched_asset: None,
            monitors: Vec::new(),
        }
    })
    .expect("test FSM must start");
    let server = ServerGuard::spawn(fsm, identity.pipe_endpoint.clone());
    wait_for_pipe(&identity.pipe_endpoint).await;

    let arguments = identity.cli_arguments(&["status", "--full"]);
    let output = tokio::task::spawn_blocking(move || run_cli(&arguments))
        .await
        .expect("empty full status task must not panic");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("empty full status UTF-8");
    assert!(stdout.contains("Snipe-IT Instance: <none>"));
    assert!(stdout.contains("Last Sync: <none>"));
    assert!(stdout.contains("Next Sync: <none>"));
    assert!(stdout.contains("Matched Asset: <none>"));
    assert!(stdout.contains("Monitors:\n  <none>"));

    server.shutdown().await;
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn actual_binary_rejects_secret_and_unknown_selectors_before_transport() {
    let identity = test_identity();
    for selector in [
        "snipeit.api_token_encrypted",
        "logging.level\\u{1b}[31m-arbitrary-input",
    ] {
        let arguments = identity.cli_arguments(&["config", "get", selector]);
        let output = run_cli(arguments.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).expect("selector error UTF-8");
        assert!(stderr.starts_with("error: "));
        assert!(!stderr.contains(selector));
        if selector == "snipeit.api_token_encrypted" {
            assert_eq!(
                stderr,
                "error: use the set-token command to update the API token\\n"
            );
        } else {
            assert_eq!(stderr, "error: unknown configuration field\\n");
        }
    }
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
    assert_eq!(
        output.stderr,
        b"error: service request timed out: timed out waiting on channel\n"
    );
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
