use std::path::PathBuf;

use clap::Parser as _;
use spotter_cli::{Cli, ServiceRegistrationOptions};
use spotter_core::identity::ServiceRuntimeOptions;

#[test]
fn registration_options_preserve_isolated_runtime_identity() {
    let runtime = ServiceRuntimeOptions::new(
        "SnipeSpotter-test",
        PathBuf::from(r"C:\Temp\SnipeSpotter-test"),
        r"\\.\pipe\SnipeSpotter-test",
        r"Global\SnipeSpotter-test",
    )
    .expect("test runtime identity must be valid");
    let options =
        ServiceRegistrationOptions::new(runtime.clone(), PathBuf::from(r"C:\bin\spotter-svc.exe"));

    assert_eq!(options.runtime, runtime);
    assert_eq!(
        options.executable_path,
        PathBuf::from(r"C:\bin\spotter-svc.exe")
    );
    let registrar = spotter_cli::WindowsServiceRegistrar::new(options.clone());
    assert_eq!(registrar.options(), &options);
    assert_eq!(
        ServiceRegistrationOptions::production().runtime,
        ServiceRuntimeOptions::production()
    );
}

#[test]
fn production_cli_does_not_accept_runtime_identity_overrides() {
    let result = Cli::try_parse_from([
        "spotter-cli",
        "--service-name",
        "SnipeSpotter-test",
        "service",
        "install",
    ]);
    assert!(result.is_err());
}

#[cfg(feature = "test-support")]
#[test]
fn test_support_cli_builds_explicit_registration_options() {
    let cli = Cli::try_parse_from([
        "spotter-cli",
        "--test-service-name",
        "SnipeSpotter-test",
        "--test-data-root",
        r"C:\Temp\SnipeSpotter-test",
        "--test-pipe-endpoint",
        r"\\.\pipe\SnipeSpotter-test",
        "--test-mutex-name",
        r"Global\SnipeSpotter-test",
        "--test-service-executable",
        r"C:\bin\spotter-svc.exe",
        "service",
        "install",
    ])
    .expect("test-support runtime arguments must parse");

    let options = spotter_cli::registration_options(&cli)
        .expect("test-support runtime arguments must build options");
    assert_eq!(options.runtime.service_name, "SnipeSpotter-test");
    assert_eq!(
        options.runtime.data_root,
        PathBuf::from(r"C:\Temp\SnipeSpotter-test")
    );
    assert_eq!(options.runtime.pipe_endpoint, r"\\.\pipe\SnipeSpotter-test");
    assert_eq!(options.runtime.mutex_name, r"Global\SnipeSpotter-test");
    assert_eq!(
        options.executable_path,
        PathBuf::from(r"C:\bin\spotter-svc.exe")
    );
}

#[cfg(feature = "test-support")]
#[test]
fn test_support_cli_selects_the_isolated_pipe_endpoint() {
    let cli = Cli::try_parse_from([
        "spotter-cli",
        "--test-service-name",
        "SnipeSpotter-test",
        "--test-data-root",
        r"C:\Temp\SnipeSpotter-test",
        "--test-pipe-endpoint",
        r"\\.\pipe\SnipeSpotter-test",
        "--test-mutex-name",
        r"Global\SnipeSpotter-test",
        "--test-service-executable",
        r"C:\bin\spotter-svc.exe",
        "status",
    ])
    .expect("test-support runtime arguments must parse");

    assert_eq!(
        spotter_cli::transport_endpoint(&cli),
        Some(r"\\.\pipe\SnipeSpotter-test".to_owned())
    );
}

#[cfg(feature = "test-support")]
#[test]
fn test_support_overrides_are_all_or_none() {
    let options = [
        ("--test-service-name", "SnipeSpotter-test"),
        ("--test-data-root", r"C:\Temp\SnipeSpotter-test"),
        ("--test-pipe-endpoint", r"\\.\pipe\SnipeSpotter-test"),
        ("--test-mutex-name", r"Global\SnipeSpotter-test"),
        ("--test-service-executable", r"C:\bin\spotter-svc.exe"),
    ];

    for omitted in 0..options.len() {
        let mut arguments = vec!["spotter-cli"];
        for (index, (name, value)) in options.iter().enumerate() {
            if index != omitted {
                arguments.extend([*name, *value]);
            }
        }
        arguments.extend(["service", "install"]);
        let cli = Cli::try_parse_from(arguments).expect("partial override set must parse");
        let error = spotter_cli::registration_options(&cli)
            .expect_err("partial override set must be rejected");
        assert!(error.to_string().contains("every runtime option"));
    }
}

#[cfg(feature = "test-support")]
#[test]
fn test_support_empty_executable_is_rejected_by_clap_before_registration() {
    let error = Cli::try_parse_from([
        "spotter-cli",
        "--test-service-name",
        "SnipeSpotter-test",
        "--test-data-root",
        r"C:\Temp\SnipeSpotter-test",
        "--test-pipe-endpoint",
        r"\\.\pipe\SnipeSpotter-test",
        "--test-mutex-name",
        r"Global\SnipeSpotter-test",
        "--test-service-executable",
        "",
        "service",
        "install",
    ])
    .expect_err("Clap must reject an empty executable value before registration");

    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
}

#[cfg(feature = "test-support")]
#[test]
fn test_support_without_overrides_preserves_production_registration() {
    let cli = Cli::try_parse_from(["spotter-cli", "service", "install"])
        .expect("production arguments must parse in test-support builds");
    let options = spotter_cli::registration_options(&cli)
        .expect("production registration must remain available in test-support builds");

    assert_eq!(options.runtime, ServiceRuntimeOptions::production());
    assert_eq!(options, ServiceRegistrationOptions::production());
    assert_eq!(spotter_cli::transport_endpoint(&cli), None);
}
