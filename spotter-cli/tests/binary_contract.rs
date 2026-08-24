#![cfg(windows)]

use std::process::{Command, Output};

fn run_cli(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_spotter-cli"))
        .args(arguments)
        .output()
        .expect("the built spotter-cli executable should start")
}

#[test]
fn help_is_served_by_the_actual_binary() {
    let output = run_cli(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: spotter-cli"));
    assert!(stdout.contains("config"));
    assert!(stdout.contains("service"));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_arguments_use_clap_error_contract() {
    let output = run_cli(&["--not-a-real-option"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("error:"));
    assert!(stderr.contains("Usage: spotter-cli"));
}

#[test]
fn unavailable_service_uses_exit_code_two_and_stderr_only() {
    let output = run_cli(&["status"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("service is not running"));
}

#[test]
fn malformed_command_reports_generic_cli_error_without_stdout() {
    let output = run_cli(&["checkin"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("error:"));
    assert!(stderr.contains("specify --all or a monitor serial"));
}
