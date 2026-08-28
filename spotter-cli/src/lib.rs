// pattern: Imperative Shell

//! Testable command-line shell for `SnipeSpotter`.

use std::{path::PathBuf, time::Duration};
#[cfg(windows)]
use std::{thread, time::Instant};

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
    #[cfg(feature = "test-support")]
    #[arg(long, global = true, hide = true)]
    pub test_service_name: Option<String>,
    #[cfg(feature = "test-support")]
    #[arg(long, global = true, hide = true)]
    pub test_data_root: Option<PathBuf>,
    #[cfg(feature = "test-support")]
    #[arg(long, global = true, hide = true)]
    pub test_pipe_endpoint: Option<String>,
    #[cfg(feature = "test-support")]
    #[arg(long, global = true, hide = true)]
    pub test_mutex_name: Option<String>,
    #[cfg(feature = "test-support")]
    #[arg(long, global = true, hide = true)]
    pub test_service_executable: Option<PathBuf>,
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
    #[must_use]
    #[cfg(windows)]
    pub fn with_endpoint(timeout: Duration, endpoint: impl Into<String>) -> Self {
        Self {
            timeout,
            endpoint: endpoint.into(),
        }
    }

    /// Construct a transport for an explicit endpoint on a non-Windows host.
    #[must_use]
    #[cfg(not(windows))]
    pub fn with_endpoint(timeout: Duration, endpoint: impl Into<String>) -> Self {
        let _ = endpoint.into();
        Self::new(timeout)
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

/// Configuration needed to register one isolated Windows service instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRegistrationOptions {
    /// Runtime identity passed to the service executable.
    pub runtime: spotter_core::identity::ServiceRuntimeOptions,
    /// Executable registered with the Service Control Manager.
    pub executable_path: PathBuf,
}

impl ServiceRegistrationOptions {
    /// Construct registration options without performing filesystem or SCM I/O.
    #[must_use]
    pub fn new(
        runtime: spotter_core::identity::ServiceRuntimeOptions,
        executable_path: PathBuf,
    ) -> Self {
        Self {
            runtime,
            executable_path,
        }
    }

    #[cfg(any(windows, feature = "test-support", test))]
    fn validate(&self) -> Result<()> {
        if self.executable_path.as_os_str().is_empty() {
            bail!("service executable path must not be empty")
        }
        if self.runtime.service_name.trim().is_empty() {
            bail!("service name must not be empty")
        }
        if self.runtime.data_root.as_os_str().is_empty() {
            bail!("service data root must not be empty")
        }
        if self.runtime.pipe_endpoint.trim().is_empty() {
            bail!("pipe endpoint must not be empty")
        }
        if !self.runtime.pipe_endpoint.starts_with(r"\\.\pipe\") {
            bail!("pipe endpoint must use the Windows named-pipe namespace")
        }
        if self.runtime.mutex_name.trim().is_empty() {
            bail!("mutex name must not be empty")
        }
        if self.runtime.service_name.contains('\0')
            || self.runtime.pipe_endpoint.contains('\0')
            || self.runtime.mutex_name.contains('\0')
            || self.runtime.data_root.to_string_lossy().contains('\0')
            || self.executable_path.to_string_lossy().contains('\0')
        {
            bail!("service registration values must not contain NUL bytes")
        }
        Ok(())
    }

    /// Return registration options for the fixed production service identity.
    #[must_use]
    pub fn production() -> Self {
        let executable_path = std::env::current_exe().map_or_else(
            |_| PathBuf::from("spotter-svc.exe"),
            |path| path.with_file_name("spotter-svc.exe"),
        );
        Self::new(
            spotter_core::identity::ServiceRuntimeOptions::production(),
            executable_path,
        )
    }
}

/// Build the service registration identity selected by the parsed CLI.
///
/// The production build always returns the fixed product registration. Test-support builds require
/// all isolated identity fields together, preventing a test service from accidentally sharing one of
/// the production resources.
///
/// # Errors
/// Returns an error when test-support overrides are incomplete or invalid.
#[cfg(feature = "test-support")]
pub fn registration_options(cli: &Cli) -> Result<ServiceRegistrationOptions> {
    let values = (
        cli.test_service_name.as_deref(),
        cli.test_data_root.as_deref(),
        cli.test_pipe_endpoint.as_deref(),
        cli.test_mutex_name.as_deref(),
        cli.test_service_executable.as_deref(),
    );
    if values.0.is_none()
        && values.1.is_none()
        && values.2.is_none()
        && values.3.is_none()
        && values.4.is_none()
    {
        return Ok(ServiceRegistrationOptions::production());
    }
    let (
        Some(service_name),
        Some(data_root),
        Some(pipe_endpoint),
        Some(mutex_name),
        Some(executable),
    ) = values
    else {
        bail!("test service registration requires every runtime option")
    };
    let runtime = spotter_core::identity::ServiceRuntimeOptions::new(
        service_name,
        data_root.to_path_buf(),
        pipe_endpoint,
        mutex_name,
    )
    .map_err(|error| anyhow::anyhow!("invalid test service runtime options: {error}"))?;
    let options = ServiceRegistrationOptions::new(runtime, executable.to_path_buf());
    options.validate()?;
    Ok(options)
}

#[cfg(feature = "test-support")]
/// Return the explicit test-support pipe endpoint, when selected.
#[must_use]
pub fn transport_endpoint(cli: &Cli) -> Option<String> {
    cli.test_pipe_endpoint.clone()
}

#[cfg(not(feature = "test-support"))]
/// Return no endpoint override for the fixed production transport.
#[must_use]
pub const fn transport_endpoint(_cli: &Cli) -> Option<String> {
    None
}

#[cfg(not(feature = "test-support"))]
/// Return the fixed production registration identity.
///
/// # Errors
/// This fallback never fails; the `Result` preserves the test-support API shape.
pub fn registration_options(_cli: &Cli) -> Result<ServiceRegistrationOptions> {
    Ok(ServiceRegistrationOptions::production())
}

/// Production Windows Service Control Manager adapter.
#[cfg(windows)]
const SCM_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
#[cfg(windows)]
const SCM_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScmErrorClass {
    Missing,
    AlreadyExists,
    AccessDenied,
    MarkedForDelete,
    Other,
}

#[cfg(any(windows, test))]
fn classify_scm_error_code(code: Option<i32>) -> ScmErrorClass {
    match code {
        Some(5) => ScmErrorClass::AccessDenied,
        Some(1060) => ScmErrorClass::Missing,
        Some(1072) => ScmErrorClass::MarkedForDelete,
        Some(1073) => ScmErrorClass::AlreadyExists,
        _ => ScmErrorClass::Other,
    }
}

#[cfg(windows)]
fn classify_scm_error(error: &windows_service::Error) -> ScmErrorClass {
    match error {
        windows_service::Error::Winapi(io_error) => {
            classify_scm_error_code(io_error.raw_os_error())
        }
        _ => ScmErrorClass::Other,
    }
}

pub struct WindowsServiceRegistrar {
    options: ServiceRegistrationOptions,
}

impl WindowsServiceRegistrar {
    /// Construct a registrar for an explicit service identity and executable.
    #[must_use]
    pub fn new(options: ServiceRegistrationOptions) -> Self {
        Self { options }
    }

    /// Construct a registrar using the fixed production service identity.
    #[must_use]
    pub fn production() -> Self {
        Self::default()
    }

    /// Return the registration options used by this registrar.
    #[must_use]
    pub const fn options(&self) -> &ServiceRegistrationOptions {
        &self.options
    }
}

impl Default for WindowsServiceRegistrar {
    fn default() -> Self {
        Self::new(ServiceRegistrationOptions::production())
    }
}

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

        self.options.validate()?;
        if !self.options.executable_path.is_file() {
            bail!(
                "service executable not found: {}",
                self.options.executable_path.display()
            )
        }
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("failed to connect to the Windows Service Control Manager")?;
        match manager.open_service(
            &self.options.runtime.service_name,
            ServiceAccess::QUERY_STATUS,
        ) {
            Ok(_) => bail!(
                "service {} is already installed",
                self.options.runtime.service_name
            ),
            Err(error) => match classify_scm_error(&error) {
                ScmErrorClass::Missing => {}
                ScmErrorClass::MarkedForDelete => bail!(
                    "service {} is marked for deletion",
                    self.options.runtime.service_name
                ),
                _ => {
                    return Err(anyhow::Error::new(error).context(format!(
                        "failed to determine whether service {} is installed",
                        self.options.runtime.service_name
                    )));
                }
            },
        }
        let info = ServiceInfo {
            name: OsString::from(&self.options.runtime.service_name),
            display_name: OsString::from(&self.options.runtime.service_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: self.options.executable_path.clone(),
            launch_arguments: self
                .options
                .runtime
                .launch_arguments()
                .into_iter()
                .map(OsString::from)
                .collect(),
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG)
            .with_context(|| {
                format!(
                    "failed to install {} service",
                    self.options.runtime.service_name
                )
            })?;
        service
            .set_description("Synchronizes local hardware inventory with Snipe-IT")
            .with_context(|| {
                format!(
                    "failed to set {} service description",
                    self.options.runtime.service_name
                )
            })?;
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
                &self.options.runtime.service_name,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(|error| match classify_scm_error(&error) {
                ScmErrorClass::Missing => anyhow::anyhow!(
                    "service {} is not installed",
                    self.options.runtime.service_name
                ),
                _ => anyhow::Error::new(error).context(format!(
                    "failed to open service {} for uninstall",
                    self.options.runtime.service_name
                )),
            })?;
        if service
            .query_status()
            .context("failed to query service status")?
            .current_state
            != ServiceState::Stopped
        {
            service.stop().context("failed to stop service")?;
            wait_for_service_state(&service, ServiceState::Stopped)?;
        }
        service.delete().context("failed to remove service")?;
        drop(service);
        wait_for_service_removed(&manager, &self.options.runtime.service_name)?;
        Ok(())
    }
}

#[cfg(windows)]
fn wait_for_service_state(
    service: &windows_service::service::Service,
    expected: windows_service::service::ServiceState,
) -> Result<()> {
    let deadline = Instant::now() + SCM_WAIT_TIMEOUT;
    loop {
        let status = service
            .query_status()
            .context("failed to query service status while waiting")?;
        if status.current_state == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("service did not reach {expected:?} before the timeout")
        }
        thread::sleep(SCM_POLL_INTERVAL);
    }
}

#[cfg(windows)]
fn wait_for_service_removed(
    manager: &windows_service::service_manager::ServiceManager,
    service_name: &str,
) -> Result<()> {
    let deadline = Instant::now() + SCM_WAIT_TIMEOUT;
    loop {
        match manager.open_service(
            service_name,
            windows_service::service::ServiceAccess::QUERY_STATUS,
        ) {
            Ok(_) if Instant::now() < deadline => thread::sleep(SCM_POLL_INTERVAL),
            Ok(_) => bail!("service {service_name} remained registered after the timeout"),
            Err(error) => match classify_scm_error(&error) {
                ScmErrorClass::Missing => return Ok(()),
                ScmErrorClass::MarkedForDelete if Instant::now() < deadline => {
                    thread::sleep(SCM_POLL_INTERVAL);
                }
                ScmErrorClass::MarkedForDelete => {
                    bail!("service {service_name} remained marked for deletion after the timeout")
                }
                _ => {
                    return Err(anyhow::Error::new(error).context(format!(
                        "failed to query service {service_name} while waiting for removal"
                    )));
                }
            },
        }
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
    fn scm_error_codes_have_distinct_lifecycle_classifications() {
        assert_eq!(classify_scm_error_code(Some(1060)), ScmErrorClass::Missing);
        assert_eq!(
            classify_scm_error_code(Some(1073)),
            ScmErrorClass::AlreadyExists
        );
        assert_eq!(
            classify_scm_error_code(Some(5)),
            ScmErrorClass::AccessDenied
        );
        assert_eq!(
            classify_scm_error_code(Some(1072)),
            ScmErrorClass::MarkedForDelete
        );
        assert_eq!(classify_scm_error_code(Some(1722)), ScmErrorClass::Other);
        assert_eq!(classify_scm_error_code(None), ScmErrorClass::Other);
    }

    #[test]
    fn service_registration_rejects_empty_executable_path() {
        let runtime = spotter_core::ServiceRuntimeOptions::production();
        let options = ServiceRegistrationOptions::new(runtime, PathBuf::new());
        assert!(options.validate().is_err());
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
