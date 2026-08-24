// pattern: Imperative Shell

//! Testable command-line shell for `SnipeSpotter`.

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand};
#[cfg(windows)]
use spotter_core::ipc::IPC_MAX_LINE_BYTES;
use spotter_core::ipc::{IpcResponse, ServiceCommand, validate_config_field};

/// Exit status used when the Windows service IPC endpoint is unavailable.
pub const EXIT_SERVICE_UNAVAILABLE: i32 = 2;

/// Error marker used to classify a missing or unreachable service endpoint.
#[derive(Debug)]
pub struct ServiceUnavailable;

impl std::fmt::Display for ServiceUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("service is not running")
    }
}

impl std::error::Error for ServiceUnavailable {}

#[derive(Debug, Parser)]
#[command(name = "spotter-cli", version, about)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Config(ConfigArgs),
    Status {
        #[arg(long)]
        full: bool,
    },
    Sync,
    Checkin(CheckinArgs),
    Service(ServiceArgs),
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Set { field: String, value: String },
    Get { field: Option<String> },
    SetToken,
}

#[derive(Debug, Args)]
pub struct CheckinArgs {
    #[arg(long, conflicts_with = "serial")]
    pub all: bool,
    pub serial: Option<String>,
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommandArgs,
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommandArgs {
    Install,
    Uninstall,
}

pub trait IpcTransport {
    /// Send one command to the service.
    ///
    /// # Errors
    /// Returns an error when the service is unavailable or the protocol fails.
    fn send(&mut self, command: &ServiceCommand) -> Result<IpcResponse>;
}

pub trait TokenReader {
    /// Read an API token without persisting it.
    ///
    /// # Errors
    /// Returns an error when input cannot be read.
    fn read_token(&mut self) -> Result<String>;
}

pub trait ServiceRegistrar {
    /// Install and configure automatic service startup.
    ///
    /// # Errors
    /// Returns an error when SCM registration fails.
    fn install(&mut self) -> Result<()>;
    /// Stop and remove the service registration.
    ///
    /// # Errors
    /// Returns an error when SCM removal fails.
    fn uninstall(&mut self) -> Result<()>;
}

pub trait ElevationChecker {
    /// Return whether the process has an elevated administrator token.
    fn is_elevated(&self) -> bool;
}

pub trait ConfirmationReader {
    /// Ask the operator to confirm a destructive action.
    ///
    /// # Errors
    /// Returns an error when confirmation input cannot be read.
    fn confirm(&mut self, prompt: &str) -> Result<bool>;
}

/// Dispatch one parsed CLI command through injected side-effect ports.
///
/// # Errors
/// Returns an error for invalid arguments, rejected confirmation, or failed ports.
pub fn dispatch(
    cli: &Cli,
    transport: &mut impl IpcTransport,
    tokens: &mut impl TokenReader,
    registrar: &mut impl ServiceRegistrar,
    elevation: &impl ElevationChecker,
    confirmation: &mut impl ConfirmationReader,
) -> Result<String> {
    if !elevation.is_elevated() {
        bail!("administrator privileges are required")
    }
    let response = match &cli.command {
        Command::Config(args) => match &args.command {
            ConfigCommand::Set { field, value } => {
                validate_config_field(field, value).map_err(anyhow::Error::msg)?;
                Some(transport.send(&ServiceCommand::SetConfig {
                    field: field.clone(),
                    value: value.clone(),
                })?)
            }
            ConfigCommand::Get { .. } => Some(transport.send(&ServiceCommand::GetConfig)?),
            ConfigCommand::SetToken => Some(transport.send(&ServiceCommand::SetToken {
                value: tokens.read_token()?,
            })?),
        },
        Command::Status { full } => Some(transport.send(if *full {
            &ServiceCommand::GetStatusFull
        } else {
            &ServiceCommand::GetStatus
        })?),
        Command::Sync => Some(transport.send(&ServiceCommand::TriggerSync)?),
        Command::Checkin(args) => {
            if !args.all && args.serial.is_none() {
                bail!("specify --all or a monitor serial");
            }
            if !args.yes
                && !confirmation.confirm("Check in the selected monitor asset(s)? [y/N] ")?
            {
                bail!("check-in cancelled");
            }
            if args.all {
                Some(transport.send(&ServiceCommand::CheckinAll)?)
            } else if let Some(serial) = &args.serial {
                Some(transport.send(&ServiceCommand::CheckinSerial {
                    serial: serial.clone(),
                })?)
            } else {
                bail!("specify --all or a monitor serial")
            }
        }
        Command::Service(args) => {
            match args.command {
                ServiceCommandArgs::Install => registrar.install()?,
                ServiceCommandArgs::Uninstall => registrar.uninstall()?,
            }
            None
        }
    };
    match response {
        None => Ok(String::from("ok")),
        Some(IpcResponse::Error { message }) => bail!(message),
        Some(response) => render(&response, cli.json),
    }
}

fn render(response: &IpcResponse, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(response).map_err(Into::into);
    }
    Ok(match response {
        IpcResponse::Status {
            state, snipeit_url, ..
        }
        | IpcResponse::StatusFull {
            state, snipeit_url, ..
        } => format!("State: {state}\nSnipe-IT Instance: {snipeit_url}"),
        IpcResponse::Ok { message } | IpcResponse::Error { message } => message.clone(),
        IpcResponse::Config { missing, .. } => {
            format!("Configuration loaded; missing: {}", missing.join(", "))
        }
        IpcResponse::CheckinResult { checked_in } => {
            format!("Checked in {} monitor(s)", checked_in.len())
        }
    })
}

/// Blocking production IPC transport with a bounded overall request deadline.
pub struct NamedPipeTransport {
    #[cfg(windows)]
    timeout: Duration,
    #[cfg(windows)]
    endpoint: String,
}

impl NamedPipeTransport {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        #[cfg(not(windows))]
        let _ = timeout;
        Self {
            #[cfg(windows)]
            timeout,
            #[cfg(windows)]
            endpoint: String::from(spotter_core::PIPE_NAME),
        }
    }

    /// Construct a transport for an explicit Windows named-pipe endpoint.
    #[cfg(windows)]
    #[must_use]
    pub fn with_endpoint(timeout: Duration, endpoint: impl Into<String>) -> Self {
        Self {
            timeout,
            endpoint: endpoint.into(),
        }
    }
}

impl Default for NamedPipeTransport {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

#[cfg(windows)]
impl IpcTransport for NamedPipeTransport {
    fn send(&mut self, command: &ServiceCommand) -> Result<IpcResponse> {
        let command = command.clone();
        let endpoint = self.endpoint.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = sender.send(exchange_named_pipe(&command, &endpoint));
        });
        receiver
            .recv_timeout(self.timeout)
            .context("service request timed out")?
    }
}

#[cfg(not(windows))]
impl IpcTransport for NamedPipeTransport {
    fn send(&mut self, _command: &ServiceCommand) -> Result<IpcResponse> {
        Err(ServiceUnavailable.into())
    }
}

#[cfg(windows)]
fn exchange_named_pipe(command: &ServiceCommand, endpoint: &str) -> Result<IpcResponse> {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};

    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .map_err(|error| anyhow::Error::new(ServiceUnavailable).context(error))?;
    let mut request = serde_json::to_vec(command).context("failed to encode service request")?;
    request.push(b'\n');
    if request.len() > IPC_MAX_LINE_BYTES {
        bail!("service request exceeds 64 KiB")
    }

    let mut pipe = BufReader::new(pipe);
    pipe.get_mut()
        .write_all(&request)
        .context("failed to write service request")?;
    pipe.get_mut()
        .flush()
        .context("failed to flush service request")?;

    let mut response = Vec::new();
    let read = pipe
        .take(u64::try_from(IPC_MAX_LINE_BYTES)?)
        .read_until(b'\n', &mut response)
        .context("failed to read service response")?;
    if read == 0 || !response.ends_with(b"\n") {
        bail!("service response is empty, unterminated, or oversized")
    }
    response.pop();
    if response.ends_with(b"\r") {
        response.pop();
    }
    serde_json::from_slice(&response).context("invalid service response JSON")
}

/// Production no-echo token reader.
pub struct ConsoleTokenReader;

impl TokenReader for ConsoleTokenReader {
    fn read_token(&mut self) -> Result<String> {
        use std::io::IsTerminal as _;

        let token = if std::io::stdin().is_terminal() {
            rpassword::prompt_password("Snipe-IT API token: ")
                .context("failed to read API token")?
        } else {
            read_piped_token(std::io::stdin().lock())?
        };
        if token.is_empty() {
            bail!("API token must not be empty")
        }
        Ok(token)
    }
}

fn read_piped_token(mut input: impl std::io::BufRead) -> Result<String> {
    use std::io::Read as _;

    const MAX_TOKEN_BYTES: u64 = 16 * 1024;
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read API token from stdin")?;
    if bytes.len() > usize::try_from(MAX_TOKEN_BYTES)? {
        bytes.fill(0);
        bail!("API token input exceeds 16 KiB")
    }
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    match String::from_utf8(bytes) {
        Ok(token) => Ok(token),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.fill(0);
            bail!("API token must be UTF-8")
        }
    }
}

/// Production terminal confirmation reader.
pub struct ConsoleConfirmationReader;

impl ConfirmationReader for ConsoleConfirmationReader {
    fn confirm(&mut self, prompt: &str) -> Result<bool> {
        use std::io::Write as _;

        eprint!("{prompt}");
        std::io::stderr()
            .flush()
            .context("failed to flush confirmation prompt")?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
}

/// Production process-token elevation checker.
pub struct ProcessElevationChecker;

impl ElevationChecker for ProcessElevationChecker {
    fn is_elevated(&self) -> bool {
        #[cfg(windows)]
        {
            spotter_win32::elevation::is_elevated()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

/// Production Windows Service Control Manager adapter.
pub struct WindowsServiceRegistrar;

#[cfg(windows)]
impl ServiceRegistrar for WindowsServiceRegistrar {
    fn install(&mut self) -> Result<()> {
        use std::ffi::OsString;
        use windows_service::{
            service::{
                ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
            },
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("failed to connect to the Windows Service Control Manager")?;
        let executable = std::env::current_exe()
            .context("failed to locate spotter-cli executable")?
            .with_file_name("spotter-svc.exe");
        if !executable.is_file() {
            bail!("service executable not found: {}", executable.display())
        }
        let info = ServiceInfo {
            name: OsString::from(spotter_core::SERVICE_NAME),
            display_name: OsString::from(spotter_core::PRODUCT_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable,
            launch_arguments: Vec::new(),
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .context("failed to install SnipeSpotter service")?;
        service
            .set_description("Synchronizes local hardware inventory with Snipe-IT")
            .context("failed to set SnipeSpotter service description")?;
        Ok(())
    }

    fn uninstall(&mut self) -> Result<()> {
        use windows_service::{
            service::{ServiceAccess, ServiceState},
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("failed to connect to the Windows Service Control Manager")?;
        let service = manager
            .open_service(
                spotter_core::SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .context("failed to open SnipeSpotter service")?;
        if service
            .query_status()
            .context("failed to query SnipeSpotter service")?
            .current_state
            != ServiceState::Stopped
        {
            service
                .stop()
                .context("failed to stop SnipeSpotter service")?;
        }
        service
            .delete()
            .context("failed to remove SnipeSpotter service")?;
        Ok(())
    }
}

#[cfg(not(windows))]
impl ServiceRegistrar for WindowsServiceRegistrar {
    fn install(&mut self) -> Result<()> {
        bail!("service registration is supported only on Windows")
    }

    fn uninstall(&mut self) -> Result<()> {
        bail!("service registration is supported only on Windows")
    }
}

/// Map a dispatch error to the stable CLI exit-code contract.
#[must_use]
pub fn exit_code(error: &anyhow::Error) -> i32 {
    if error
        .chain()
        .any(<dyn std::error::Error>::is::<ServiceUnavailable>)
    {
        EXIT_SERVICE_UNAVAILABLE
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        sent: Vec<ServiceCommand>,
    }
    impl IpcTransport for Fake {
        fn send(&mut self, command: &ServiceCommand) -> Result<IpcResponse> {
            self.sent.push(command.clone());
            Ok(IpcResponse::Ok {
                message: String::from("done"),
            })
        }
    }

    struct ResponseTransport {
        sent: Vec<ServiceCommand>,
        response: IpcResponse,
    }
    impl IpcTransport for ResponseTransport {
        fn send(&mut self, command: &ServiceCommand) -> Result<IpcResponse> {
            self.sent.push(command.clone());
            Ok(self.response.clone())
        }
    }

    struct RecordingRegistrar {
        installs: usize,
        uninstalls: usize,
    }
    impl ServiceRegistrar for RecordingRegistrar {
        fn install(&mut self) -> Result<()> {
            self.installs += 1;
            Ok(())
        }

        fn uninstall(&mut self) -> Result<()> {
            self.uninstalls += 1;
            Ok(())
        }
    }
    impl TokenReader for Fake {
        fn read_token(&mut self) -> Result<String> {
            Ok(String::from("secret"))
        }
    }
    impl ServiceRegistrar for Fake {
        fn install(&mut self) -> Result<()> {
            Ok(())
        }
        fn uninstall(&mut self) -> Result<()> {
            Ok(())
        }
    }
    struct Elevated(bool);
    impl ElevationChecker for Elevated {
        fn is_elevated(&self) -> bool {
            self.0
        }
    }
    struct Confirmation {
        answer: bool,
        prompts: usize,
    }
    impl ConfirmationReader for Confirmation {
        fn confirm(&mut self, _prompt: &str) -> Result<bool> {
            self.prompts += 1;
            Ok(self.answer)
        }
    }
    #[test]
    fn parses_and_dispatches_sync() -> Result<()> {
        let cli = Cli::try_parse_from(["spotter-cli", "sync"])?;
        let mut transport = Fake { sent: Vec::new() };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        assert_eq!(
            dispatch(
                &cli,
                &mut transport,
                &mut tokens,
                &mut registrar,
                &Elevated(true),
                &mut confirmation,
            )?,
            "done"
        );
        assert_eq!(transport.sent, vec![ServiceCommand::TriggerSync]);
        Ok(())
    }

    #[test]
    fn elevation_is_checked_before_side_effects() -> Result<()> {
        let cli = Cli::try_parse_from(["spotter-cli", "sync"])?;
        let mut transport = Fake { sent: Vec::new() };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        assert!(
            dispatch(
                &cli,
                &mut transport,
                &mut tokens,
                &mut registrar,
                &Elevated(false),
                &mut confirmation,
            )
            .is_err()
        );
        assert!(transport.sent.is_empty());
        Ok(())
    }

    #[test]
    fn checkin_confirmation_and_yes_bypass_are_enforced() -> Result<()> {
        let mut transport = Fake { sent: Vec::new() };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut denied = Confirmation {
            answer: false,
            prompts: 0,
        };
        let interactive = Cli::try_parse_from(["spotter-cli", "checkin", "MON-1"])?;
        assert!(
            dispatch(
                &interactive,
                &mut transport,
                &mut tokens,
                &mut registrar,
                &Elevated(true),
                &mut denied,
            )
            .is_err()
        );
        assert_eq!(denied.prompts, 1);
        assert!(transport.sent.is_empty());

        let forced = Cli::try_parse_from(["spotter-cli", "checkin", "MON-1", "-y"])?;
        dispatch(
            &forced,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut denied,
        )?;
        assert_eq!(denied.prompts, 1);
        assert_eq!(
            transport.sent,
            vec![ServiceCommand::CheckinSerial {
                serial: String::from("MON-1")
            }]
        );
        Ok(())
    }

    #[test]
    fn service_error_response_is_a_cli_error() -> Result<()> {
        struct ErrorTransport;
        impl IpcTransport for ErrorTransport {
            fn send(&mut self, _command: &ServiceCommand) -> Result<IpcResponse> {
                Ok(IpcResponse::Error {
                    message: String::from("rejected"),
                })
            }
        }
        let cli = Cli::try_parse_from(["spotter-cli", "status"])?;
        let mut transport = ErrorTransport;
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        let error = dispatch(
            &cli,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )
        .expect_err("error response must fail dispatch");
        assert_eq!(error.to_string(), "rejected");
        Ok(())
    }

    #[test]
    fn piped_token_is_trimmed_and_bounded() -> Result<()> {
        assert_eq!(read_piped_token(&b"secret\r\n"[..])?, "secret");
        assert!(read_piped_token(&vec![b'x'; 16 * 1024 + 1][..]).is_err());
        assert!(read_piped_token(&[0xff][..]).is_err());
        Ok(())
    }

    #[test]
    fn unavailable_service_has_stable_exit_code() {
        let error = anyhow::Error::new(ServiceUnavailable);
        assert_eq!(exit_code(&error), EXIT_SERVICE_UNAVAILABLE);
        assert_eq!(exit_code(&anyhow::anyhow!("other")), 1);
    }

    #[test]
    fn config_commands_validate_and_send_typed_requests() -> Result<()> {
        let cli = Cli::try_parse_from([
            "spotter-cli",
            "config",
            "set",
            "polling.interval_hours",
            "12",
        ])?;
        let mut transport = Fake { sent: Vec::new() };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        dispatch(
            &cli,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )?;
        assert_eq!(
            transport.sent,
            vec![ServiceCommand::SetConfig {
                field: String::from("polling.interval_hours"),
                value: String::from("12"),
            }]
        );

        let invalid = Cli::try_parse_from([
            "spotter-cli",
            "config",
            "set",
            "polling.interval_hours",
            "0",
        ])?;
        let error = dispatch(
            &invalid,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )
        .expect_err("invalid setting must be rejected before transport");
        assert!(error.to_string().contains("between 1 and 168"));
        assert_eq!(transport.sent.len(), 1);
        Ok(())
    }

    #[test]
    fn status_full_and_json_render_expected_fields() -> Result<()> {
        let response = IpcResponse::StatusFull {
            state: String::from("Idle"),
            last_sync: Some(String::from("2026-01-02T00:00:00Z")),
            next_sync: None,
            snipeit_url: String::from("https://snipe.example.test"),
            matched_asset: None,
            monitors: Vec::new(),
        };
        let mut transport = ResponseTransport {
            sent: Vec::new(),
            response,
        };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        let cli = Cli::try_parse_from(["spotter-cli", "status", "--full"])?;
        let output = dispatch(
            &cli,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )?;
        assert!(output.contains("State: Idle"));
        assert!(output.contains("Snipe-IT Instance: https://snipe.example.test"));
        assert_eq!(transport.sent, vec![ServiceCommand::GetStatusFull]);

        let json_cli = Cli::try_parse_from(["spotter-cli", "--json", "status"])?;
        let json = dispatch(
            &json_cli,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )?;
        assert!(json.contains("\"type\": \"status_full\""));
        Ok(())
    }

    #[test]
    fn checkin_all_yes_sends_force_command_without_prompt() -> Result<()> {
        let cli = Cli::try_parse_from(["spotter-cli", "checkin", "--all", "-y"])?;
        let mut transport = Fake { sent: Vec::new() };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: false,
            prompts: 0,
        };
        dispatch(
            &cli,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )?;
        assert_eq!(confirmation.prompts, 0);
        assert_eq!(transport.sent, vec![ServiceCommand::CheckinAll]);
        Ok(())
    }

    #[test]
    fn service_commands_call_the_matching_registrar_operation() -> Result<()> {
        let mut transport = Fake { sent: Vec::new() };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = RecordingRegistrar {
            installs: 0,
            uninstalls: 0,
        };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        let install = Cli::try_parse_from(["spotter-cli", "service", "install"])?;
        assert_eq!(
            dispatch(
                &install,
                &mut transport,
                &mut tokens,
                &mut registrar,
                &Elevated(true),
                &mut confirmation,
            )?,
            "ok"
        );
        let uninstall = Cli::try_parse_from(["spotter-cli", "service", "uninstall"])?;
        dispatch(
            &uninstall,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )?;
        assert_eq!(registrar.installs, 1);
        assert_eq!(registrar.uninstalls, 1);
        assert!(transport.sent.is_empty());
        Ok(())
    }
}
