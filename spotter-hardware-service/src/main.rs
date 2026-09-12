// On Windows with hardware-experiment, the session query uses unsafe.
#![cfg_attr(all(windows, feature = "hardware-experiment"), allow(unsafe_code))]
// pattern: Imperative Shell

//! Temporary Windows service host for the privacy-safe hardware experiment.

#[cfg(any(test, all(windows, feature = "hardware-experiment")))]
mod path_policy;

#[cfg(all(windows, feature = "hardware-experiment"))]
mod windows_path_policy;

#[cfg(all(windows, feature = "hardware-experiment"))]
mod windows_service_host {
    use std::{
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };

    use super::{path_policy, windows_path_policy};
    use windows_path_policy::{RetainedHandle, inspect_path};

    use serde::Deserialize;
    use windows::Win32::System::{
        RemoteDesktop::ProcessIdToSessionId, Threading::GetCurrentProcessId,
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const SERVICE_NAME_ARGUMENT: &str = "--service-name";
    const CONFIG_ARGUMENT: &str = "--config";

    #[derive(Debug, Deserialize)]
    struct ServiceConfig {
        service_name: String,
        collector: PathBuf,
        image: String,
        image_alias: String,
        context: String,
        repetition: u32,
        key_path: PathBuf,
        output_path: PathBuf,
        pwsh_path: PathBuf,
        staging_root: PathBuf,
    }

    struct LaunchBound {
        collector: RetainedHandle,
        key: RetainedHandle,
        output_directory: RetainedHandle,
        pwsh: RetainedHandle,
        _service_executable: RetainedHandle,
        _root: RetainedHandle,
    }

    struct RunningCollector {
        process: std::process::Child,
        _launch_bound: LaunchBound,
    }

    pub fn run() -> Result<(), String> {
        let arguments = env::args_os().skip(1).collect::<Vec<_>>();
        let service_name = argument_value(&arguments, SERVICE_NAME_ARGUMENT)?;
        let config_path = argument_value(&arguments, CONFIG_ARGUMENT)?;
        validate_service_name(&service_name)?;
        validate_config_path(&config_path)?;
        service_dispatcher::start(service_name, ffi_service_main)
            .map_err(|error| format!("failed to start hardware service dispatcher: {error}"))
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        let arguments = env::args_os().skip(1).collect::<Vec<_>>();
        if let Err(error) = run_service(&arguments) {
            eprintln!("hardware service failed: {error}");
        }
    }

    fn run_service(arguments: &[OsString]) -> Result<(), String> {
        let service_name = argument_value(arguments, SERVICE_NAME_ARGUMENT)?;
        let config_path = argument_value(arguments, CONFIG_ARGUMENT)?;
        let config = load_config(&config_path)?;
        if config.service_name != service_name {
            return Err("service name does not match service configuration".to_owned());
        }
        let launch_bound = validate_launch_inputs(&config)?;

        let (stop_sender, stop_receiver) = mpsc::sync_channel(1);
        let status_handle =
            service_control_handler::register(&service_name, move |control| match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = stop_sender.try_send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .map_err(|error| format!("failed to register hardware service controls: {error}"))?;
        set_status(
            status_handle,
            ServiceState::StartPending,
            1,
            Duration::from_secs(30),
        )?;
        set_status(status_handle, ServiceState::Running, 0, Duration::ZERO)?;

        let mut collector = spawn_collector(&config, launch_bound)?;
        let service_result = loop {
            if let Some(status) = collector
                .process
                .try_wait()
                .map_err(|error| format!("failed to query hardware collector: {error}"))?
            {
                break if status.success() {
                    Ok(())
                } else {
                    Err(format!("hardware collector exited with status {status}"))
                };
            }
            match stop_receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => {
                    let _ = collector.process.kill();
                    let _ = collector.process.wait();
                    break Err("hardware collector stopped by SCM".to_owned());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = collector.process.kill();
                    let _ = collector.process.wait();
                    break Err("hardware service control channel disconnected".to_owned());
                }
            }
        };
        set_status(status_handle, ServiceState::Stopped, 0, Duration::ZERO)?;
        service_result
    }

    fn validate_launch_inputs(config: &ServiceConfig) -> Result<LaunchBound, String> {
        let root = inspect_path(
            &config.staging_root,
            &config.staging_root,
            path_policy::PathPurpose::StagingRoot,
        )?;
        let collector = inspect_path(
            &config.staging_root,
            &config.collector,
            path_policy::PathPurpose::Collector,
        )?;
        let key = inspect_path(
            &config.staging_root,
            &config.key_path,
            path_policy::PathPurpose::Key,
        )?;
        let output_directory_path = config
            .output_path
            .parent()
            .ok_or_else(|| "output path has no protected parent directory".to_owned())?;
        let output_directory = inspect_path(
            &config.staging_root,
            output_directory_path,
            path_policy::PathPurpose::OutputDirectory,
        )?;
        let output_file_name = output_file_name(config);
        if Path::new(&output_file_name).components().count() != 1
            || output_file_name == "."
            || output_file_name == ".."
        {
            return Err(
                "output path must name a single file in the protected output directory".to_owned(),
            );
        }
        let pwsh = inspect_path(
            &config.staging_root,
            &config.pwsh_path,
            path_policy::PathPurpose::PowerShellHost,
        )?;
        let service_executable = inspect_path(
            &config.staging_root,
            &current_executable_path()?,
            path_policy::PathPurpose::ServiceExecutable,
        )?;
        Ok(LaunchBound {
            collector,
            key,
            output_directory,
            pwsh,
            _service_executable: service_executable,
            _root: root,
        })
    }

    fn spawn_collector(
        config: &ServiceConfig,
        launch_bound: LaunchBound,
    ) -> Result<RunningCollector, String> {
        let session_id = current_session_id()?;
        let child = Command::new(launch_bound.pwsh.final_path())
            .arg("-NoLogo")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(launch_bound.collector.final_path())
            .arg("-Image")
            .arg(&config.image)
            .arg("-ImageAlias")
            .arg(&config.image_alias)
            .arg("-Context")
            .arg(&config.context)
            .arg("-Repetition")
            .arg(config.repetition.to_string())
            .arg("-SessionId")
            .arg(session_id.to_string())
            .arg("-HmacKeyPath")
            .arg(launch_bound.key.final_path())
            .arg("-OutputPath")
            .arg(
                launch_bound
                    .output_directory
                    .final_path()
                    .join(output_file_name(config)),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("failed to launch hardware collector: {error}"))?;
        Ok(RunningCollector {
            process: child,
            _launch_bound: launch_bound,
        })
    }

    fn output_file_name(config: &ServiceConfig) -> String {
        config.output_path.file_name().map_or_else(
            || "hardware-report.json".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        )
    }

    fn current_executable_path() -> Result<PathBuf, String> {
        env::current_exe().map_err(|error| format!("failed to resolve service executable: {error}"))
    }

    fn load_config(path: &str) -> Result<ServiceConfig, String> {
        let config_path = Path::new(path);
        let staging_root = config_path
            .parent()
            .ok_or_else(|| "service config has no protected parent directory".to_owned())?;
        let _config_handle =
            inspect_path(staging_root, config_path, path_policy::PathPurpose::Config)?;
        let bytes = fs::read(config_path)
            .map_err(|error| format!("failed to read service config: {error}"))?;
        let config = serde_json::from_slice::<ServiceConfig>(&bytes)
            .map_err(|error| format!("failed to parse service config: {error}"))?;
        validate_config(&config)?;
        if config.staging_root != staging_root {
            return Err(
                "service config is not directly beneath its protected staging root".to_owned(),
            );
        }
        Ok(config)
    }

    fn validate_config(config: &ServiceConfig) -> Result<(), String> {
        validate_service_name(&config.service_name)?;
        if config
            .collector
            .extension()
            .and_then(|value| value.to_str())
            .is_none_or(|value| !value.eq_ignore_ascii_case("ps1"))
        {
            return Err("collector must be a PowerShell script".to_owned());
        }
        if config.image != config.image_alias {
            return Err("image alias does not match image".to_owned());
        }
        if config.context != "LocalSystem" {
            return Err("hardware service context must be LocalSystem".to_owned());
        }
        if !config.pwsh_path.is_absolute()
            || config
                .pwsh_path
                .extension()
                .and_then(|value| value.to_str())
                .is_none_or(|value| !value.eq_ignore_ascii_case("exe"))
        {
            return Err("PowerShell host must be an absolute executable path".to_owned());
        }
        if !config.staging_root.is_absolute()
            || config.staging_root == config.staging_root.parent().unwrap_or(Path::new(""))
        {
            return Err("protected staging root must be an absolute per-cell directory".to_owned());
        }
        for (name, path) in [("collector", &config.collector), ("key", &config.key_path)] {
            if path.is_dir() || path.parent() != Some(config.staging_root.as_path()) {
                return Err(format!(
                    "{name} must be a direct child of the protected staging root"
                ));
            }
        }
        let output_directory = config
            .output_path
            .parent()
            .ok_or_else(|| "output path has no protected parent directory".to_owned())?;
        if !path_policy::is_output_file_path(
            &config.staging_root.to_string_lossy(),
            &config.output_path.to_string_lossy(),
        ) || config.output_path.is_dir()
        {
            return Err(
                "output path must name a file in the protected output directory".to_owned(),
            );
        }
        if output_directory.parent() != Some(config.staging_root.as_path()) {
            return Err(
                "output directory must be a direct child of the protected staging root".to_owned(),
            );
        }
        if !(1..=3).contains(&config.repetition) {
            return Err("repetition must be between 1 and 3".to_owned());
        }
        Ok(())
    }

    fn argument_value(arguments: &[OsString], name: &str) -> Result<String, String> {
        let position = arguments
            .iter()
            .position(|argument| argument == name)
            .ok_or_else(|| format!("missing required argument: {name}"))?;
        let value = arguments
            .get(position + 1)
            .ok_or_else(|| format!("missing value for argument: {name}"))?;
        value
            .to_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("invalid value for argument: {name}"))
    }

    fn validate_service_name(name: &str) -> Result<(), String> {
        if name.is_empty()
            || name.len() > 256
            || name
                .chars()
                .any(|character| character.is_control() || character == '/')
        {
            return Err("service name is empty or contains unsupported characters".to_owned());
        }
        Ok(())
    }

    #[cfg(test)]
    mod config_tests {
        use super::*;

        fn config_with_output(output_path: &str) -> ServiceConfig {
            ServiceConfig {
                service_name: "SpotterHardware".to_owned(),
                collector: PathBuf::from(r"C:\ProgramData\Cell\collector.ps1"),
                image: "windows-2022".to_owned(),
                image_alias: "windows-2022".to_owned(),
                context: "LocalSystem".to_owned(),
                repetition: 1,
                key_path: PathBuf::from(r"C:\ProgramData\Cell\hmac.key"),
                output_path: PathBuf::from(output_path),
                pwsh_path: PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe"),
                staging_root: PathBuf::from(r"C:\ProgramData\Cell"),
            }
        }

        #[test]
        fn accepts_output_file_inside_protected_output_directory() {
            assert!(
                validate_config(&config_with_output(
                    r"C:\ProgramData\Cell\output\report.json"
                ))
                .is_ok()
            );
        }

        #[test]
        fn rejects_output_file_outside_protected_output_directory() {
            assert!(
                validate_config(&config_with_output(r"C:\ProgramData\Cell\report.json")).is_err()
            );
            assert!(
                validate_config(&config_with_output(
                    r"C:\ProgramData\Cell\other\report.json"
                ))
                .is_err()
            );
        }
    }

    fn validate_config_path(path: &str) -> Result<(), String> {
        if path.len() > 32_768 || path.contains('\0') {
            return Err("service config path is invalid".to_owned());
        }
        Ok(())
    }

    fn current_session_id() -> Result<u32, String> {
        let mut session_id = 0_u32;
        // SAFETY: The process ID is returned by Windows, and `session_id` is valid writable storage.
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), std::ptr::addr_of_mut!(session_id)) }
            .map_err(|error| format!("failed to query service session ID: {error}"))?;
        Ok(session_id)
    }

    fn set_status(
        handle: windows_service::service_control_handler::ServiceStatusHandle,
        state: ServiceState,
        checkpoint: u32,
        wait_hint: Duration,
    ) -> Result<(), String> {
        let controls = if state == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        };
        handle
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: controls,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint,
                wait_hint,
                process_id: None,
            })
            .map_err(|error| format!("failed to report service status: {error}"))
    }
}

#[cfg(all(windows, feature = "hardware-experiment"))]
fn main() -> std::process::ExitCode {
    match windows_service_host::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(windows, feature = "hardware-experiment")))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "error: spotter-hardware-service requires Windows and the hardware-experiment feature"
    );
    std::process::ExitCode::FAILURE
}
