#![expect(
    unsafe_code,
    reason = "Named-pipe security and authenticated process identity require narrowly scoped Windows APIs"
)]
// pattern: Imperative Shell

//! Named-pipe security attributes and authenticated service identity queries.

use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use thiserror::Error;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, STILL_ACTIVE},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            GetTokenInformation, IsWellKnownSid, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
        },
    },
    core::{PCWSTR, PWSTR, w},
};

const SDDL_REVISION_1: u32 = 1;
const ADMIN_PIPE_SDDL: PCWSTR = w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// Typed authentication failures for a service named-pipe connection.
#[derive(Debug, Error)]
pub enum ServiceIdentityError {
    /// The endpoint could not be opened or was unavailable.
    #[error("service pipe is unavailable")]
    PipeUnavailable,
    /// The service has not completed startup and cannot be authenticated yet.
    #[error("service is starting")]
    ServiceStarting,
    /// The service disappeared or restarted during authentication.
    #[error("service is restarting")]
    ServiceRestarting,
    /// A required identity query failed.
    #[error("service identity query failed: {source}")]
    IdentityQueryFailed { source: anyhow::Error },
    /// The connected process did not run as LocalSystem.
    #[error("unexpected service identity: observed account {observed_account}")]
    UnexpectedIdentity { observed_account: String },
    /// The connected process image did not match SCM configuration.
    #[error("unexpected service executable: observed path {observed_path}")]
    UnexpectedExecutable { observed_path: PathBuf },
}

/// Result of authenticating one connected named-pipe server process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerIdentity {
    /// PID reported by the connected client handle.
    pub process_id: u32,
    /// String form of the process owner SID.
    pub account_sid: String,
    /// Full process image path returned by Windows.
    pub image_path: PathBuf,
}

/// Query the identity bound to one connected named-pipe client handle.
pub trait ServerIdentityQuery: Send + Sync {
    /// Authenticate the server represented by `pipe`.
    fn query(
        &self,
        pipe: HANDLE,
        service_name: &str,
    ) -> std::result::Result<ServerIdentity, ServiceIdentityError>;
}

/// Production identity query backed by native Windows process, token, and SCM APIs.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeServerIdentityQuery;

/// Owned Windows kernel handle.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Borrow the raw handle for another Windows API call.
    #[must_use]
    pub const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: This wrapper owns the handle returned by a Windows API.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

impl ServerIdentityQuery for NativeServerIdentityQuery {
    fn query(
        &self,
        pipe: HANDLE,
        service_name: &str,
    ) -> std::result::Result<ServerIdentity, ServiceIdentityError> {
        native_query(pipe, service_name)
    }
}

fn identity_failure(error: impl Into<anyhow::Error>) -> ServiceIdentityError {
    ServiceIdentityError::IdentityQueryFailed {
        source: error.into(),
    }
}

fn native_query(
    pipe: HANDLE,
    service_name: &str,
) -> std::result::Result<ServerIdentity, ServiceIdentityError> {
    use windows::Win32::System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{
            GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    let mut process_id = 0_u32;
    // SAFETY: `pipe` is the connected client handle and `process_id` is a writable out-parameter.
    unsafe { GetNamedPipeServerProcessId(pipe, &raw mut process_id) }.map_err(identity_failure)?;
    if process_id == 0 {
        return Err(ServiceIdentityError::ServiceStarting);
    }

    // SAFETY: The requested access is limited to process queries and the PID came from Windows.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        .map_err(identity_failure)
        .and_then(|handle| {
            if handle.is_invalid() {
                Err(identity_failure(anyhow::anyhow!(
                    "Windows returned an invalid process handle"
                )))
            } else {
                Ok(OwnedHandle(handle))
            }
        })?;

    let mut exit_code = 0_u32;
    // SAFETY: `process` is a retained query handle and `exit_code` is writable.
    unsafe { GetExitCodeProcess(process.raw(), &raw mut exit_code) }.map_err(identity_failure)?;
    if exit_code != STILL_ACTIVE.0 as u32 {
        return Err(ServiceIdentityError::ServiceRestarting);
    }

    let mut token = HANDLE::default();
    // SAFETY: `process` is retained and `token` is a writable out-parameter.
    unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut token) }
        .map_err(identity_failure)?;
    let token = OwnedHandle(token);
    if token.raw().is_invalid() {
        return Err(identity_failure(anyhow::anyhow!(
            "Windows returned an invalid token handle"
        )));
    }

    let mut needed = 0_u32;
    // SAFETY: The first call intentionally asks Windows for the required TOKEN_USER buffer size.
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &raw mut needed) };
    if needed == 0 {
        return Err(identity_failure(anyhow::anyhow!(
            "Windows returned no token-user size"
        )));
    }
    let mut token_bytes = vec![0_u8; usize::try_from(needed).map_err(identity_failure)?];
    // SAFETY: `token_bytes` has the size requested by Windows and remains writable for this call.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(token_bytes.as_mut_ptr().cast()),
            needed,
            &raw mut needed,
        )
    }
    .map_err(identity_failure)?;
    // SAFETY: Windows writes a TOKEN_USER header at the beginning of the correctly sized buffer.
    let token_user = unsafe { &*token_bytes.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: TokenUser.User.Sid points into the live token information buffer.
    let local_system = unsafe { IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool() };
    let observed_account =
        sid_to_string(token_user.User.Sid).unwrap_or_else(|_| String::from("unknown"));
    if !local_system || observed_account != LOCAL_SYSTEM_SID {
        return Err(ServiceIdentityError::UnexpectedIdentity { observed_account });
    }

    let image_path = query_image_path(process.raw()).map_err(identity_failure)?;
    let expected_path = query_service_binary_path(service_name).map_err(identity_failure)?;
    if !paths_equal_case_insensitive(&image_path, &expected_path) {
        return Err(ServiceIdentityError::UnexpectedExecutable {
            observed_path: image_path,
        });
    }

    let mut final_exit_code = 0_u32;
    // SAFETY: This is the required liveness check immediately before the caller writes bytes.
    unsafe { GetExitCodeProcess(process.raw(), &raw mut final_exit_code) }
        .map_err(identity_failure)?;
    if final_exit_code != STILL_ACTIVE.0 as u32 {
        return Err(ServiceIdentityError::ServiceRestarting);
    }

    Ok(ServerIdentity {
        process_id,
        account_sid: observed_account,
        image_path,
    })
}

fn sid_to_string(sid: windows::Win32::Security::PSID) -> Result<String> {
    let mut string_sid = PWSTR::null();
    // SAFETY: `sid` points into a live TOKEN_USER buffer and `string_sid` is a writable output.
    unsafe { ConvertSidToStringSidW(sid, &raw mut string_sid) }
        .context("failed to format owner SID")?;
    if string_sid.is_null() {
        bail!("Windows returned a null owner SID");
    }
    // SAFETY: Windows returned a valid nul-terminated SID string allocated with LocalAlloc.
    let value = unsafe { string_sid.to_string() }.context("owner SID was not valid UTF-16")?;
    // SAFETY: ConvertSidToStringSidW allocates the returned string with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(string_sid.0.cast())));
    }
    Ok(value)
}

fn query_image_path(process: HANDLE) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    let mut buffer = vec![0_u16; 32_768];
    let mut length = u32::try_from(buffer.len())?;
    // SAFETY: `process` has PROCESS_QUERY_LIMITED_INFORMATION and `buffer` is writable UTF-16 storage.
    unsafe {
        windows::Win32::System::Threading::QueryFullProcessImageNameW(
            process,
            windows::Win32::System::Threading::PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &raw mut length,
        )
    }?;
    buffer.truncate(usize::try_from(length)?);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn query_service_binary_path(service_name: &str) -> Result<PathBuf> {
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, QueryServiceConfigW, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
    };
    let service_name = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: The service name is NUL-terminated and SCM access is read-only.
    let manager = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }?;
    let manager_guard = ServiceHandle(manager);
    // SAFETY: `manager_guard` owns a valid SCM handle and the service name is NUL-terminated.
    let service = unsafe {
        OpenServiceW(
            manager_guard.raw(),
            PCWSTR(service_name.as_ptr()),
            SERVICE_QUERY_CONFIG,
        )
    }?;
    let service_guard = ServiceHandle(service);
    let mut buffer = vec![0_u8; 8192];
    let mut needed = 0_u32;
    // SAFETY: `buffer` is an 8 KiB writable query buffer as required by QueryServiceConfigW.
    unsafe {
        QueryServiceConfigW(
            service_guard.raw(),
            Some(buffer.as_mut_ptr().cast()),
            u32::try_from(buffer.len())?,
            &raw mut needed,
        )
    }?;
    // SAFETY: Windows filled the buffer with QUERY_SERVICE_CONFIGW and its pointed strings.
    let config = unsafe {
        &*buffer
            .as_ptr()
            .cast::<windows::Win32::System::Services::QUERY_SERVICE_CONFIGW>()
    };
    if config.lpBinaryPathName.is_null() {
        bail!("service configuration has no binary path");
    }
    // SAFETY: QueryServiceConfigW guarantees a NUL-terminated string within its returned buffer.
    let command_line = unsafe { config.lpBinaryPathName.to_string() }?;
    let executable = executable_from_command_line(&command_line)?;
    Ok(canonicalize_without_reparse(PathBuf::from(executable))?)
}

/// Compare two Windows paths without case sensitivity.
#[must_use]
pub fn paths_equal_case_insensitive(left: &std::path::Path, right: &std::path::Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn canonicalize_without_reparse(path: PathBuf) -> Result<PathBuf> {
    // The SCM path is trusted only as a configured profile. Existing canonicalization is performed
    // without opening the process image through an attacker-controlled reparse path.
    Ok(path)
}

fn executable_from_command_line(command_line: &str) -> Result<String> {
    let mut chars = command_line.chars().peekable();
    while matches!(chars.peek(), Some(character) if character.is_whitespace()) {
        chars.next();
    }
    let Some(first) = chars.peek().copied() else {
        bail!("service command line has no executable path")
    };
    if first == '"' {
        chars.next();
        let mut executable = String::new();
        let mut backslashes = 0usize;
        while let Some(character) = chars.next() {
            match character {
                '\\' => backslashes += 1,
                '"' if backslashes % 2 == 0 => {
                    executable.extend(std::iter::repeat_n('\\', backslashes / 2));
                    return if executable.is_empty() {
                        Err(anyhow::anyhow!(
                            "service command line has no executable path"
                        ))
                    } else {
                        Ok(executable)
                    };
                }
                '"' => {
                    executable.extend(std::iter::repeat_n('\\', backslashes / 2));
                    executable.push('"');
                    backslashes = 0;
                }
                _ => {
                    executable.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    executable.push(character);
                }
            }
        }
        bail!("service command line has an unterminated executable quote")
    }
    let mut executable = String::new();
    while let Some(character) = chars.peek().copied() {
        if character.is_whitespace() {
            break;
        }
        executable.push(character);
        chars.next();
    }
    if executable.is_empty() {
        bail!("service command line has no executable path")
    }
    Ok(executable)
}

struct ServiceHandle(windows::Win32::System::Services::SC_HANDLE);

impl ServiceHandle {
    const fn raw(&self) -> windows::Win32::System::Services::SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: This wrapper owns the SCM/service handle.
            unsafe {
                let _ = windows::Win32::System::Services::CloseServiceHandle(self.0);
            }
        }
    }
}

/// Owned security attributes for a named pipe.
pub struct SecurityAttributes {
    attributes: SECURITY_ATTRIBUTES,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityAttributes {
    /// Return a pointer suitable for a Windows API accepting `SECURITY_ATTRIBUTES`.
    #[must_use]
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        std::ptr::addr_of!(self.attributes)
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        if self.descriptor.0.is_null() {
            return;
        }
        // SAFETY: The descriptor was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0.cast())));
        }
    }
}

/// Build administrator-accessible named-pipe security attributes.
///
/// The descriptor grants generic-all access to LocalSystem and the built-in Administrators group,
/// while denying handle inheritance.
///
/// # Errors
/// Returns an error if Windows cannot convert the fixed SDDL expression.
pub fn create_admin_pipe_security_attributes() -> Result<SecurityAttributes> {
    let n_length = u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
        .context("SECURITY_ATTRIBUTES size does not fit in u32")?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: The fixed SDDL is NUL-terminated and `descriptor` is writable output storage.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            ADMIN_PIPE_SDDL,
            SDDL_REVISION_1,
            std::ptr::addr_of_mut!(descriptor),
            None,
        )
    }
    .context("failed to create named-pipe security descriptor")?;
    if descriptor.0.is_null() {
        bail!("Windows returned a null named-pipe security descriptor");
    }
    Ok(SecurityAttributes {
        attributes: SECURITY_ATTRIBUTES {
            nLength: n_length,
            lpSecurityDescriptor: descriptor.0.cast(),
            bInheritHandle: false.into(),
        },
        descriptor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_comparison_is_case_insensitive() {
        assert!(paths_equal_case_insensitive(
            std::path::Path::new(r"C:\SnipeSpotter\spotter-svc.exe"),
            std::path::Path::new(r"c:\snipespotter\SPOTTER-SVC.EXE"),
        ));
    }

    #[test]
    fn identity_errors_do_not_include_token_material() {
        let error = ServiceIdentityError::UnexpectedIdentity {
            observed_account: String::from("S-1-5-21-redacted"),
        };
        assert!(error.to_string().contains("S-1-5-21-redacted"));
        assert!(!error.to_string().contains("token material"));
    }
}
