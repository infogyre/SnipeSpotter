// pattern: Imperative Shell

//! Testable command-line shell for `SnipeSpotter`.

use std::{path::PathBuf, time::Duration};
#[cfg(windows)]
use std::{thread, time::Instant};

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand};
use secrecy::{ExposeSecret as _, SecretString};
#[cfg(any(windows, test))]
use spotter_core::ipc::IPC_MAX_LINE_BYTES;
use spotter_core::ipc::{IpcResponse, ServiceCommand, validate_config_field};
#[cfg(any(windows, test))]
use zeroize::Zeroizing;

use cli_output::{render_config, render_status, validate_selector};

mod cli_output;
mod command_line;

pub use command_line::executable_from_command_line;

#[cfg(windows)]
use spotter_win32::pipe::{NativeServerIdentityQuery, ServerIdentityQuery, ServiceIdentityError};

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

const PRODUCTION_TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "test-support")]
const TEST_TRANSPORT_TIMEOUT_MIN_MS: u64 = 1;
#[cfg(feature = "test-support")]
const TEST_TRANSPORT_TIMEOUT_MAX_MS: u64 = 30_000;

#[cfg(feature = "test-support")]
fn parse_test_transport_timeout_ms(value: &str) -> std::result::Result<u64, String> {
    let millis = value
        .parse::<u64>()
        .map_err(|_| String::from("must be an integer number of milliseconds"))?;
    if (TEST_TRANSPORT_TIMEOUT_MIN_MS..=TEST_TRANSPORT_TIMEOUT_MAX_MS).contains(&millis) {
        Ok(millis)
    } else {
        Err(format!(
            "must be between {TEST_TRANSPORT_TIMEOUT_MIN_MS} and {TEST_TRANSPORT_TIMEOUT_MAX_MS} milliseconds"
        ))
    }
}

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
    #[arg(long, global = true, hide = true, value_parser = parse_test_transport_timeout_ms)]
    pub test_transport_timeout_ms: Option<u64>,
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
    fn read_token(&mut self) -> Result<SecretString>;
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
            ConfigCommand::Get { field } => {
                if let Some(field) = field {
                    validate_selector(field)?;
                }
                Some(transport.send(&ServiceCommand::GetConfig)?)
            }
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
    let selector = match &cli.command {
        Command::Config(ConfigArgs {
            command: ConfigCommand::Get { field },
        }) => field.as_deref(),
        _ => None,
    };
    match response {
        None => Ok(String::from("ok")),
        Some(IpcResponse::Error { message }) => bail!(message),
        Some(IpcResponse::Config { settings, missing }) => {
            render_config(&settings, &missing, selector, cli.json)
        }
        Some(response @ (IpcResponse::Status { .. } | IpcResponse::StatusFull { .. })) => {
            render_status(&response, cli.json)
        }
        Some(response) => render(&response, cli.json),
    }
}

fn render(response: &IpcResponse, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(response).map_err(Into::into);
    }
    Ok(match response {
        IpcResponse::Ok { message } | IpcResponse::Error { message } => message.clone(),
        IpcResponse::CheckinResult { checked_in } => {
            format!("Checked in {} monitor(s)", checked_in.len())
        }
        IpcResponse::Config { .. }
        | IpcResponse::Status { .. }
        | IpcResponse::StatusFull { .. } => {
            unreachable!("special responses are rendered before the generic renderer")
        }
    })
}

/// Blocking production IPC transport with a bounded overall request deadline.
pub struct NamedPipeTransport {
    #[cfg(windows)]
    timeout: Duration,
    #[cfg(windows)]
    endpoint: String,
    #[cfg(windows)]
    identity_query: std::sync::Arc<dyn ServerIdentityQuery>,
    #[cfg(windows)]
    service_name: String,
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
            #[cfg(windows)]
            identity_query: std::sync::Arc::new(NativeServerIdentityQuery),
            #[cfg(windows)]
            service_name: String::from(spotter_core::identity::SERVICE_NAME),
        }
    }

    /// Construct a transport for an explicit Windows named-pipe endpoint.
    #[must_use]
    #[cfg(windows)]
    pub fn with_endpoint(timeout: Duration, endpoint: impl Into<String>) -> Self {
        Self {
            timeout,
            endpoint: endpoint.into(),
            identity_query: std::sync::Arc::new(NativeServerIdentityQuery),
            service_name: String::from(spotter_core::identity::SERVICE_NAME),
        }
    }

    /// Construct a transport for an explicit endpoint and service identity.
    ///
    /// Test-support builds use this so the identity gate authenticates against
    /// the isolated test service registration instead of the production name.
    #[must_use]
    #[cfg(all(windows, feature = "test-support"))]
    pub fn with_endpoint_and_service(
        timeout: Duration,
        endpoint: impl Into<String>,
        service_name: impl Into<String>,
    ) -> Self {
        Self {
            timeout,
            endpoint: endpoint.into(),
            identity_query: std::sync::Arc::new(NativeServerIdentityQuery),
            service_name: service_name.into(),
        }
    }

    /// Construct an endpoint transport with an injected identity query for test-support builds.
    #[must_use]
    #[cfg(all(windows, feature = "test-support"))]
    pub fn with_identity_query(
        timeout: Duration,
        endpoint: impl Into<String>,
        service_name: impl Into<String>,
        identity_query: impl ServerIdentityQuery + 'static,
    ) -> Self {
        Self {
            timeout,
            endpoint: endpoint.into(),
            identity_query: std::sync::Arc::new(identity_query),
            service_name: service_name.into(),
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
        let identity_query = std::sync::Arc::clone(&self.identity_query);
        let service_name = self.service_name.clone();
        std::thread::spawn(move || {
            let _ = sender.send(exchange_named_pipe(
                &command,
                &endpoint,
                &service_name,
                identity_query.as_ref(),
            ));
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

#[cfg(any(windows, test))]
fn exchange_request<A, S, W, R, B>(
    command: &ServiceCommand,
    authenticate: A,
    serialize: S,
    write: W,
    read_response: R,
) -> Result<IpcResponse>
where
    A: FnOnce() -> Result<()>,
    S: FnOnce(&ServiceCommand) -> Result<B>,
    W: FnOnce(&[u8]) -> Result<()>,
    R: FnOnce() -> Result<Vec<u8>>,
    B: AsRef<[u8]>,
{
    authenticate()?;
    let request = serialize(command)?;
    write(request.as_ref())?;
    let mut response = read_response()?;
    if response.is_empty() || !response.ends_with(b"\n") {
        bail!("service response is empty, unterminated, or oversized")
    }
    response.pop();
    if response.ends_with(b"\r") {
        response.pop();
    }
    serde_json::from_slice(&response).context("invalid service response JSON")
}

#[cfg(any(windows, test))]
fn authenticate_serialize_write<A, S, W, B>(
    command: &ServiceCommand,
    authenticate: A,
    serialize: S,
    write: W,
) -> Result<()>
where
    A: FnOnce() -> Result<()>,
    S: FnOnce(&ServiceCommand) -> Result<B>,
    W: FnOnce(&[u8]) -> Result<()>,
    B: AsRef<[u8]>,
{
    authenticate()?;
    let request = serialize(command)?;
    write(request.as_ref())
}

#[cfg(windows)]
fn read_bounded_pipe_response(pipe: &mut impl std::io::BufRead, max_bytes: u64) -> Result<Vec<u8>> {
    use std::io::{BufRead as _, Read as _};

    let mut response = Vec::new();
    (&mut *pipe)
        .take(max_bytes)
        .read_until(b'\n', &mut response)
        .context("failed to read service response")?;
    Ok(response)
}

#[cfg(windows)]
fn write_bounded_pipe_request(
    pipe: &mut std::io::BufReader<std::fs::File>,
    request: &[u8],
) -> Result<()> {
    // BufReader does not implement Write on the pinned toolchain; the underlying
    // File does, so writes flush through get_mut().
    let file = pipe.get_mut();
    std::io::Write::write_all(file, request).context("failed to write service request")?;
    std::io::Write::flush(file).context("failed to flush service request")?;
    Ok(())
}

#[cfg(windows)]
fn exchange_named_pipe(
    command: &ServiceCommand,
    endpoint: &str,
    service_name: &str,
    identity_query: &dyn ServerIdentityQuery,
) -> Result<IpcResponse> {
    use std::io::BufReader;

    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::{Foundation::HANDLE, Storage::FileSystem::SECURITY_IDENTIFICATION};

    // Identification SQOS limits a pipe server's impersonation level; the identity query below
    // authenticates the connected server before any command bytes are serialized or written.
    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .security_qos_flags(SECURITY_IDENTIFICATION.0)
        .open(endpoint)
        .map_err(|error| anyhow::Error::new(ServiceUnavailable).context(error))?;
    let mut pipe = BufReader::new(pipe);
    let pipe_handle = HANDLE(pipe.get_ref().as_raw_handle());
    // Auth precedes serialization; the closures capture disjoint state so the
    // pipe is borrowed by exactly one of the sequential helpers at a time.
    authenticate_serialize_write(
        command,
        || {
            identity_query
                .query(pipe_handle, service_name)
                .map(|_| ())
                .map_err(anyhow::Error::new)
                .context("service identity authentication failed")
        },
        |command: &ServiceCommand| {
            let mut request = Zeroizing::new(
                serde_json::to_vec(command).context("failed to encode service request")?,
            );
            request.push(b'\n');
            if request.len() > IPC_MAX_LINE_BYTES {
                bail!("service request exceeds 64 KiB")
            }
            Ok(request)
        },
        |request: &[u8]| write_bounded_pipe_request(&mut pipe, request),
    )?;
    let mut response = read_bounded_pipe_response(&mut pipe, u64::try_from(IPC_MAX_LINE_BYTES)?)?;
    if response.is_empty() || !response.ends_with(b"\n") {
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
    fn read_token(&mut self) -> Result<SecretString> {
        use std::io::IsTerminal as _;

        let token = if std::io::stdin().is_terminal() {
            SecretString::from(
                rpassword::prompt_password("Snipe-IT API token: ")
                    .context("failed to read API token")?,
            )
        } else {
            read_piped_token(std::io::stdin().lock())?
        };
        if token.expose_secret().is_empty() {
            bail!("API token must not be empty")
        }
        Ok(token)
    }
}

fn read_piped_token(mut input: impl std::io::BufRead) -> Result<SecretString> {
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
        Ok(token) => Ok(SecretString::from(token)),
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
    ///
    /// # Errors
    /// Returns an error when the current executable cannot be resolved to an absolute path.
    pub fn production() -> Result<Self> {
        registration_options_from_current_exe(std::env::current_exe())
    }
}

fn registration_options_from_current_exe(
    current_exe: std::io::Result<PathBuf>,
) -> Result<ServiceRegistrationOptions> {
    let current_exe = current_exe.context("failed to resolve current executable")?;
    if !current_exe.is_absolute() {
        bail!("current executable path must be absolute")
    }
    Ok(ServiceRegistrationOptions::new(
        spotter_core::identity::ServiceRuntimeOptions::production(),
        current_exe.with_file_name("spotter-svc.exe"),
    ))
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
        return ServiceRegistrationOptions::production();
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

#[cfg(feature = "test-support")]
/// Build the transport implied by test-support overrides (endpoint + service name),
/// or `None` when production defaults apply.
#[must_use]
pub fn transport_transport(cli: &Cli, timeout: Duration) -> Option<NamedPipeTransport> {
    #[cfg(windows)]
    {
        let endpoint = cli.test_pipe_endpoint.clone()?;
        Some(NamedPipeTransport::with_endpoint_and_service(
            timeout,
            endpoint,
            cli.test_service_name
                .clone()
                .unwrap_or_else(|| String::from(spotter_core::identity::SERVICE_NAME)),
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = (cli, timeout);
        None
    }
}

#[cfg(feature = "test-support")]
/// Return the validated transport timeout selected by test support, or the production default.
#[must_use]
pub fn transport_timeout(cli: &Cli) -> Duration {
    match cli.test_transport_timeout_ms {
        Some(milliseconds)
            if (TEST_TRANSPORT_TIMEOUT_MIN_MS..=TEST_TRANSPORT_TIMEOUT_MAX_MS)
                .contains(&milliseconds) =>
        {
            Duration::from_millis(milliseconds)
        }
        _ => PRODUCTION_TRANSPORT_TIMEOUT,
    }
}

#[cfg(not(feature = "test-support"))]
/// Return `None`: the production transport uses the fixed default identity.
#[must_use]
pub const fn transport_transport(_cli: &Cli, _timeout: Duration) -> Option<NamedPipeTransport> {
    None
}

#[cfg(not(feature = "test-support"))]
/// Return no endpoint override for the fixed production transport.
#[must_use]
pub const fn transport_endpoint(_cli: &Cli) -> Option<String> {
    None
}

#[cfg(not(feature = "test-support"))]
/// Return the fixed production transport timeout.
#[must_use]
pub const fn transport_timeout(_cli: &Cli) -> Duration {
    PRODUCTION_TRANSPORT_TIMEOUT
}

#[cfg(not(feature = "test-support"))]
/// Return the fixed production registration identity.
///
/// # Errors
/// Returns an error when the current executable cannot be resolved to an absolute path.
pub fn registration_options(_cli: &Cli) -> Result<ServiceRegistrationOptions> {
    ServiceRegistrationOptions::production()
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
    ///
    /// # Errors
    /// Returns an error when production registration options cannot be resolved safely.
    pub fn production() -> Result<Self> {
        Ok(Self::new(ServiceRegistrationOptions::production()?))
    }

    /// Return the registration options used by this registrar.
    #[must_use]
    pub const fn options(&self) -> &ServiceRegistrationOptions {
        &self.options
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
    if error.chain().any(|cause| {
        cause.is::<ServiceUnavailable>() || {
            #[cfg(windows)]
            {
                cause.is::<ServiceIdentityError>()
            }
            #[cfg(not(windows))]
            {
                false
            }
        }
    }) {
        EXIT_SERVICE_UNAVAILABLE
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

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

    struct DropObservedRequest {
        bytes: Zeroizing<Vec<u8>>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl AsRef<[u8]> for DropObservedRequest {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for DropObservedRequest {
        fn drop(&mut self) {
            use zeroize::Zeroize as _;

            self.bytes.zeroize();
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn drop_observed_request(
        bytes: Vec<u8>,
        dropped: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> DropObservedRequest {
        DropObservedRequest {
            bytes: Zeroizing::new(bytes),
            dropped: std::sync::Arc::clone(dropped),
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
        fn read_token(&mut self) -> Result<SecretString> {
            Ok(SecretString::from("secret"))
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
    #[cfg(feature = "test-support")]
    #[test]
    fn test_transport_timeout_override_is_positive_and_bounded() {
        assert!(
            Cli::try_parse_from(["spotter-cli", "--test-transport-timeout-ms", "1", "status",])
                .is_ok()
        );
        assert!(
            Cli::try_parse_from(["spotter-cli", "--test-transport-timeout-ms", "0", "status",])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "spotter-cli",
                "--test-transport-timeout-ms",
                "30001",
                "status",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "spotter-cli",
                "--test-transport-timeout-ms",
                "not-a-duration",
                "status",
            ])
            .is_err()
        );

        let cli = Cli::try_parse_from([
            "spotter-cli",
            "--test-transport-timeout-ms",
            "200",
            "status",
        ])
        .expect("bounded timeout must parse");
        assert_eq!(transport_timeout(&cli), Duration::from_millis(200));
        let cli =
            Cli::try_parse_from(["spotter-cli", "status"]).expect("production timeout must parse");
        assert_eq!(transport_timeout(&cli), PRODUCTION_TRANSPORT_TIMEOUT);
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
        use secrecy::ExposeSecret as _;

        assert_eq!(
            read_piped_token(&b"secret\r\n"[..])?.expose_secret(),
            "secret"
        );
        assert!(read_piped_token(&vec![b'x'; 16 * 1024 + 1][..]).is_err());
        assert!(read_piped_token(&[0xff][..]).is_err());
        Ok(())
    }

    fn ipc_serialization_failure(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = exchange_request(
            command,
            || Ok(()),
            |_| -> Result<DropObservedRequest> { bail!("injected serialization failure") },
            |_| Ok(()),
            || Ok(br#"{\"type\":\"ok\",\"data\":{\"message\":\"ok\"}}\n"#.to_vec()),
        )
        .expect_err("serialization failure must reject");
        assert!(error.to_string().contains("injected serialization failure"));
        assert!(!dropped.load(Ordering::SeqCst));
    }

    fn ipc_oversized_request(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = authenticate_serialize_write(
            command,
            || Ok(()),
            |_| {
                let mut bytes = vec![b'x'; IPC_MAX_LINE_BYTES];
                bytes.push(b'\n');
                Ok(drop_observed_request(bytes, &dropped))
            },
            |_| bail!("oversized request rejected"),
        )
        .expect_err("oversized request must reject before write");
        assert!(error.to_string().contains("oversized request"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn ipc_unterminated_request(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = exchange_request(
            command,
            || Ok(()),
            |_| Ok(drop_observed_request(b"unterminated".to_vec(), &dropped)),
            |_| Ok(()),
            || Ok(Vec::new()),
        )
        .expect_err("unterminated response must reject");
        assert!(error.to_string().contains("unterminated"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn ipc_write_failure(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = authenticate_serialize_write(
            command,
            || Ok(()),
            |_| Ok(drop_observed_request(b"request\n".to_vec(), &dropped)),
            |_| bail!("injected write failure"),
        )
        .expect_err("write failure must reject");
        assert!(error.to_string().contains("injected write failure"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn ipc_flush_failure(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = authenticate_serialize_write(
            command,
            || Ok(()),
            |_| Ok(drop_observed_request(b"request\n".to_vec(), &dropped)),
            |_| bail!("injected flush failure"),
        )
        .expect_err("flush failure must reject");
        assert!(error.to_string().contains("injected flush failure"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn ipc_read_timeout(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = exchange_request(
            command,
            || Ok(()),
            |_| Ok(drop_observed_request(b"request\n".to_vec(), &dropped)),
            |_| Ok(()),
            || bail!("injected read timeout"),
        )
        .expect_err("read timeout must reject");
        assert!(error.to_string().contains("injected read timeout"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn ipc_malformed_response(command: &ServiceCommand) {
        let dropped = Arc::new(AtomicBool::new(false));
        let error = exchange_request(
            command,
            || Ok(()),
            |_| Ok(drop_observed_request(b"request\n".to_vec(), &dropped)),
            |_| Ok(()),
            || Ok(b"not-json\n".to_vec()),
        )
        .expect_err("malformed response must reject");
        assert!(error.to_string().contains("invalid service response JSON"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn ipc_secret_buffer_exit_path_table() {
        let command = ServiceCommand::SetToken {
            value: SecretString::from("table-secret"),
        };
        ipc_serialization_failure(&command);
        ipc_oversized_request(&command);
        ipc_unterminated_request(&command);
        ipc_write_failure(&command);
        ipc_flush_failure(&command);
        ipc_read_timeout(&command);
        ipc_malformed_response(&command);
    }

    #[test]
    fn authentication_precedes_serialization() {
        use std::sync::{Arc, Mutex};
        use zeroize::Zeroizing;

        let events = Arc::new(Mutex::new(Vec::new()));
        let auth_events = Arc::clone(&events);
        let serialize_events = Arc::clone(&events);
        let write_events = Arc::clone(&events);
        let error = authenticate_serialize_write(
            &ServiceCommand::SetToken {
                value: SecretString::from("must-not-be-serialized"),
            },
            move || {
                auth_events.lock().expect("event lock").push("auth");
                bail!("fixture authentication failed")
            },
            move |_| {
                serialize_events
                    .lock()
                    .expect("event lock")
                    .push("serialize");
                Ok(Zeroizing::new(vec![b'\n']))
            },
            move |_| {
                write_events.lock().expect("event lock").push("write");
                Ok(())
            },
        )
        .expect_err("failed authentication must reject before serialization");
        assert!(error.to_string().contains("fixture authentication failed"));
        assert_eq!(
            *events.lock().expect("event lock"),
            vec!["auth"],
            "authentication failure must perform zero serialization and zero writes"
        );
    }

    #[test]
    fn unavailable_service_has_stable_exit_code() {
        let error = anyhow::Error::new(ServiceUnavailable);
        assert_eq!(exit_code(&error), EXIT_SERVICE_UNAVAILABLE);
        #[cfg(windows)]
        {
            let identity_error = anyhow::Error::new(ServiceIdentityError::ServiceRestarting);
            assert_eq!(exit_code(&identity_error), EXIT_SERVICE_UNAVAILABLE);
        }
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
    fn registration_path_fail_closed() {
        let resolution_error = registration_options_from_current_exe(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "injected current executable failure",
        )))
        .expect_err("current executable resolution failure must be fatal");
        assert!(resolution_error.to_string().contains("current executable"));

        let relative_error =
            registration_options_from_current_exe(Ok(PathBuf::from("relative/spotter-cli.exe")))
                .expect_err("relative current executable paths must be rejected");
        assert!(relative_error.to_string().contains("absolute"));

        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\SnipeSpotter\spotter-cli.exe")
        } else {
            PathBuf::from("/opt/snipe-spotter/spotter-cli")
        };
        let options = registration_options_from_current_exe(Ok(absolute))
            .expect("absolute current executable path must resolve");
        assert!(options.executable_path.is_absolute());
        assert_eq!(
            options.executable_path.file_name(),
            Some(std::ffi::OsStr::new("spotter-svc.exe"))
        );
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
    fn cli_output_redaction_and_control_escaping() -> Result<()> {
        for field in [
            "snipeit.api_token_encrypted",
            "logging.level\\u{1b}[31m-arbitrary-input",
        ] {
            let cli = Cli::try_parse_from(["spotter-cli", "config", "get", field])?;
            let mut transport = Fake { sent: Vec::new() };
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
            .expect_err("invalid selector must fail locally");
            assert!(!error.to_string().contains(field));
            assert!(transport.sent.is_empty());
        }
        Ok(())
    }

    #[test]
    fn config_get_selector_is_rendered_as_one_typed_scalar() -> Result<()> {
        let mut settings = spotter_core::Settings::default();
        settings.polling.interval_hours = 7;
        let mut transport = ResponseTransport {
            sent: Vec::new(),
            response: IpcResponse::Config {
                settings,
                missing: Vec::new(),
            },
        };
        let mut tokens = Fake { sent: Vec::new() };
        let mut registrar = Fake { sent: Vec::new() };
        let mut confirmation = Confirmation {
            answer: true,
            prompts: 0,
        };
        let cli = Cli::try_parse_from(["spotter-cli", "config", "get", "polling.interval_hours"])?;
        let output = dispatch(
            &cli,
            &mut transport,
            &mut tokens,
            &mut registrar,
            &Elevated(true),
            &mut confirmation,
        )?;
        assert_eq!(output, "polling.interval_hours: 7");
        assert_eq!(transport.sent, vec![ServiceCommand::GetConfig]);
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
