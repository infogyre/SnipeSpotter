#![cfg(all(windows, feature = "test-support"))]
#![expect(
    unsafe_code,
    reason = "Live named-pipe ACL inspection requires narrowly scoped Windows security descriptor calls"
)]

use std::{
    fs::OpenOptions, io::Write as _, os::windows::io::AsRawHandle as _, sync::mpsc, time::Duration,
};

use anyhow::{Context as _, Result};
use spotter_cli::{IpcTransport, NamedPipeTransport};
use spotter_core::ipc::{IpcResponse, ServiceCommand};
use spotter_win32::pipe::{ServerIdentity, ServerIdentityQuery, ServiceIdentityError};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, ERROR_SUCCESS, HANDLE, HLOCAL,
            LocalFree,
        },
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_IMPERSONATION_LEVEL,
            SecurityIdentification, TOKEN_QUERY, TokenImpersonationLevel,
        },
        Storage::FileSystem::{PIPE_ACCESS_DUPLEX, ReadFile, WriteFile},
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
                PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{GetCurrentThread, OpenThreadToken},
        },
    },
    core::{PCWSTR, PWSTR},
};

// Windows canonicalizes generic-all from the authored SDDL to file-all on a pipe kernel object.
const EXPECTED_PIPE_ACL_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
const SDDL_REVISION_1: u32 = 1;

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `GetSecurityInfo` allocated this descriptor with LocalAlloc, and this guard
            // is its sole owner until drop.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn live_pipe_acl_sddl(endpoint: &str) -> Result<String> {
    let pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .context("failed to open live named pipe for ACL inspection")?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        // SAFETY: `pipe` owns a live named-pipe handle for the duration of this call, the security
        // descriptor pointer is a writable out-parameter, and all optional SID/ACL outputs are
        // intentionally omitted.
        GetSecurityInfo(
            HANDLE(pipe.as_raw_handle()),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(std::ptr::addr_of_mut!(descriptor)),
        )
    };
    if result != ERROR_SUCCESS {
        anyhow::bail!(
            "failed to read live named-pipe security descriptor: Win32 error {}",
            result.0
        );
    }
    let descriptor = OwnedSecurityDescriptor(descriptor);
    if descriptor.0.is_invalid() {
        anyhow::bail!("Windows returned an invalid live named-pipe security descriptor");
    }

    let mut text = PWSTR::null();
    // SAFETY: `descriptor` keeps the security descriptor alive for this call, `text` is a writable
    // out-parameter, and the returned string is released with LocalFree below.
    let rendered = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::addr_of_mut!(text),
            None,
        )
    }
    .context("failed to render live named-pipe security descriptor")
    .and_then(|()| {
        unsafe { text.to_string() }.context("invalid rendered live named-pipe security descriptor")
    });
    // SAFETY: Windows allocated `text` for the conversion above; `LocalFree` is the matching
    // deallocator, and conversion errors are handled after releasing it.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    rendered
}

fn unique_pipe_endpoint() -> String {
    format!(
        r"\\.\pipe\SnipeSpotter-test-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("main")
    )
}

#[cfg(feature = "test-support")]
#[derive(Clone)]
struct FixtureIdentityQuery {
    result: std::result::Result<(), FixtureIdentityFailure>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug)]
enum FixtureIdentityFailure {
    Query,
    ProcessExit,
    PidMismatch,
    UnexpectedSid,
    UnexpectedPath,
}

#[cfg(feature = "test-support")]
impl ServerIdentityQuery for FixtureIdentityQuery {
    fn query(
        &self,
        _pipe: HANDLE,
        _service_name: &str,
    ) -> std::result::Result<ServerIdentity, ServiceIdentityError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.result {
            Ok(()) => Ok(ServerIdentity {
                process_id: std::process::id(),
                account_sid: String::from("S-1-5-18"),
                image_path: std::path::PathBuf::from(r"C:\SnipeSpotter\spotter-svc.exe"),
            }),
            Err(FixtureIdentityFailure::Query) => Err(ServiceIdentityError::IdentityQueryFailed {
                source: anyhow::anyhow!("fixture query failure"),
            }),
            Err(FixtureIdentityFailure::ProcessExit) => {
                Err(ServiceIdentityError::ServiceRestarting)
            }
            Err(FixtureIdentityFailure::PidMismatch) => {
                Err(ServiceIdentityError::IdentityQueryFailed {
                    source: anyhow::anyhow!("fixture PID mismatch"),
                })
            }
            Err(FixtureIdentityFailure::UnexpectedSid) => {
                Err(ServiceIdentityError::UnexpectedIdentity {
                    observed_account: String::from("S-1-5-21-fixture"),
                })
            }
            Err(FixtureIdentityFailure::UnexpectedPath) => {
                Err(ServiceIdentityError::UnexpectedExecutable {
                    observed_path: std::path::PathBuf::from(r"C:\fixture\counterfeit.exe"),
                })
            }
        }
    }
}

#[cfg(feature = "test-support")]
fn fixture_transport(endpoint: String, query: FixtureIdentityQuery) -> NamedPipeTransport {
    NamedPipeTransport::with_identity_query(
        Duration::from_secs(5),
        endpoint,
        "SnipeSpotter-fixture",
        query,
    )
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: This guard uniquely owns a Windows kernel handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: The guard is created only after this thread successfully impersonates the pipe
        // client, and it is dropped synchronously on that same dedicated OS thread.
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

fn observe_client_impersonation_level(
    endpoint: &str,
    ready: &mpsc::SyncSender<()>,
) -> Result<SECURITY_IMPERSONATION_LEVEL> {
    let endpoint = endpoint
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let security = spotter_win32::pipe::create_admin_pipe_security_attributes()
        .context("failed to build test named-pipe security attributes")?;
    // SAFETY: The endpoint is NUL-terminated and `security` keeps the restrictive descriptor alive
    // through pipe creation. The returned handle is immediately placed under RAII ownership.
    let pipe = OwnedHandle(unsafe {
        CreateNamedPipeW(
            PCWSTR(endpoint.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(security.as_ptr()),
        )
    });
    if pipe.0.is_invalid() {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to create SQOS test named pipe");
    }
    ready
        .send(())
        .map_err(|_| anyhow::anyhow!("failed to announce ready SQOS named pipe"))?;
    // SAFETY: `pipe` owns a listening synchronous named-pipe server handle.
    if let Err(error) = unsafe { ConnectNamedPipe(pipe.0, None) }
        && error.code() != ERROR_PIPE_CONNECTED.to_hresult()
    {
        return Err(error).context("failed to connect SQOS test named pipe");
    }

    let mut request = [0_u8; 4096];
    let mut bytes_read = 0;
    // SAFETY: The buffer and byte-count out-parameter are writable for this synchronous call.
    unsafe { ReadFile(pipe.0, Some(&mut request), Some(&raw mut bytes_read), None) }
        .context("failed to read SQOS client request")?;

    // SAFETY: The connected server handle has just received a client request. All impersonation,
    // token query, and reversion operations remain synchronous on this dedicated OS thread.
    unsafe { ImpersonateNamedPipeClient(pipe.0) }
        .context("failed to impersonate named-pipe client")?;
    let _impersonation = ImpersonationGuard;
    let mut token = HANDLE::default();
    // SAFETY: The current thread is impersonating and `token` is a writable out-parameter.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, &raw mut token) }
        .context("failed to open impersonation token")?;
    let token = OwnedHandle(token);
    let mut level = SECURITY_IMPERSONATION_LEVEL::default();
    let mut returned = 0;
    // SAFETY: `level` is correctly sized for TokenImpersonationLevel and remains writable.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenImpersonationLevel,
            Some(std::ptr::addr_of_mut!(level).cast()),
            u32::try_from(std::mem::size_of_val(&level))?,
            &raw mut returned,
        )
    }
    .context("failed to query client impersonation level")?;

    let response = b"{\"type\":\"ok\",\"data\":{\"message\":\"observed\"}}\n";
    let mut bytes_written = 0;
    // SAFETY: `response` remains readable and the byte-count out-parameter writable during this
    // synchronous write.
    unsafe { WriteFile(pipe.0, Some(response), Some(&raw mut bytes_written), None) }
        .context("failed to write SQOS test response")?;
    Ok(level)
}

#[test]
fn named_pipe_client_limits_impersonation_level() -> Result<()> {
    let endpoint = unique_pipe_endpoint();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let server_endpoint = endpoint.clone();
    let server = std::thread::spawn(move || {
        observe_client_impersonation_level(&server_endpoint, &ready_sender)
    });
    ready_receiver
        .recv_timeout(Duration::from_secs(5))
        .context("SQOS server thread did not start")?;

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut transport = fixture_transport(
        endpoint,
        FixtureIdentityQuery {
            result: Ok(()),
            calls: std::sync::Arc::clone(&calls),
        },
    );
    let response = transport.send(&ServiceCommand::GetStatus)?;
    assert_eq!(
        response,
        IpcResponse::Ok {
            message: String::from("observed")
        }
    );
    let level = server
        .join()
        .map_err(|_| anyhow::anyhow!("SQOS server thread panicked"))??;
    assert_eq!(level, SecurityIdentification);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "client-timeout ordering needs explicit accept, release, and cleanup phases"
)]
async fn client_timeout_does_not_cancel_handler() -> Result<()> {
    struct MarkerGuard(std::path::PathBuf);

    impl Drop for MarkerGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    struct ServerGuard(tokio::task::JoinHandle<Result<()>>);

    impl Drop for ServerGuard {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let endpoint = unique_pipe_endpoint();
    let marker_path = std::env::temp_dir().join(format!(
        "SnipeSpotter-timeout-marker-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos()),
    ));
    let _marker = MarkerGuard(marker_path.clone());
    let (accepted_sender, accepted_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let (completed_sender, completed_receiver) = tokio::sync::oneshot::channel();
    let mut accepted_sender = Some(accepted_sender);
    let mut release_receiver = Some(release_receiver);
    let mut completed_sender = Some(completed_sender);
    let handler_marker_path = marker_path.clone();
    let fsm = spotter_svc::fsm::spawn(1, move |_| {
        let accepted_sender = accepted_sender.take();
        let release_receiver = release_receiver.take();
        let completed_sender = completed_sender.take();
        let marker_path = handler_marker_path.clone();
        async move {
            if let Some(sender) = accepted_sender {
                let _ = sender.send(());
            }
            if let Some(receiver) = release_receiver {
                let _ = receiver.await;
            }
            let durable = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&marker_path)
                .and_then(|mut marker| {
                    marker.write_all(b"durably committed")?;
                    marker.sync_all()
                });
            match durable {
                Ok(()) => {
                    if let Some(sender) = completed_sender {
                        let _ = sender.send(());
                    }
                    IpcResponse::Ok {
                        message: String::from("durably committed"),
                    }
                }
                Err(_) => IpcResponse::Error {
                    message: String::from("durable mutation failed"),
                },
            }
        }
    })?;
    let server = tokio::spawn(spotter_svc::ipc_server::run_named_pipe_at(
        fsm,
        endpoint.clone(),
    ));
    let mut server = ServerGuard(server);

    let client_endpoint = endpoint;
    let client = tokio::task::spawn_blocking(move || {
        let mut transport = fixture_transport(
            client_endpoint,
            FixtureIdentityQuery {
                result: Ok(()),
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            },
        );
        transport.send(&ServiceCommand::GetStatus)
    });
    tokio::time::timeout(Duration::from_secs(5), accepted_receiver)
        .await
        .context("named-pipe handler did not accept the request")?
        .context("named-pipe handler acceptance was cancelled")?;
    let send_result = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .context("named-pipe client timeout observation exceeded its bound")??;
    let timeout_error = send_result.expect_err("short named-pipe client deadline must expire");
    assert!(timeout_error.to_string().contains("timed out"));
    assert!(!marker_path.exists());

    release_sender
        .send(())
        .map_err(|()| anyhow::anyhow!("failed to release named-pipe handler"))?;
    tokio::time::timeout(Duration::from_secs(5), completed_receiver)
        .await
        .context("durable mutation did not complete after client timeout")?
        .context("durable mutation completion was cancelled")?;
    assert_eq!(std::fs::read(&marker_path)?, b"durably committed");

    server.0.abort();
    // Cancellation is the expected terminal state for an aborted server task; any
    // other outcome (timeout, panic, clean exit, other error) fails the test.
    match tokio::time::timeout(Duration::from_secs(5), &mut server.0).await {
        Ok(Err(error)) if error.is_cancelled() => {}
        Ok(Err(error)) => {
            return Err(anyhow::Error::new(error).context("named-pipe server task panicked"));
        }
        Ok(Ok(Ok(()))) => {
            anyhow::bail!("named-pipe server exited unexpectedly without cancellation")
        }
        Ok(Ok(Err(error))) => return Err(error.context("named-pipe server exited with an error")),
        Err(_elapsed) => anyhow::bail!("named-pipe server cleanup exceeded its bound"),
    }
    Ok(())
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

    // Retry connecting until the server has created the pipe instance, then inspect the DACL on
    // that live object before exercising the production client path.
    let (live_acl, response) = tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match live_pipe_acl_sddl(&endpoint) {
                Ok(rendered) => {
                    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let mut transport = fixture_transport(
                        endpoint.clone(),
                        FixtureIdentityQuery {
                            result: Ok(()),
                            calls,
                        },
                    );
                    match transport.send(&ServiceCommand::GetStatus) {
                        Ok(response) => return Ok((rendered, response)),
                        Err(_) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??;

    assert_eq!(live_acl, EXPECTED_PIPE_ACL_SDDL);
    for broad_principal in ["BU", "WD", "AU"] {
        assert!(!live_acl.contains(&format!(";;;{broad_principal}")));
    }

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

#[cfg(feature = "test-support")]
fn receive_request_bytes(endpoint: &str, ready: &mpsc::SyncSender<()>) -> Result<usize> {
    let endpoint = endpoint
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let security = spotter_win32::pipe::create_admin_pipe_security_attributes()?;
    let pipe = OwnedHandle(unsafe {
        CreateNamedPipeW(
            PCWSTR(endpoint.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(security.as_ptr()),
        )
    });
    if pipe.0.is_invalid() {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }
    ready
        .send(())
        .map_err(|_| anyhow::anyhow!("failed to announce byte-counting server"))?;
    let mut request = [0_u8; 4096];
    let mut bytes_read = 0;
    unsafe { ConnectNamedPipe(pipe.0, None) }.or_else(|error| {
        if error.code() == ERROR_PIPE_CONNECTED.to_hresult() {
            Ok(())
        } else {
            Err(error)
        }
    })?;
    match unsafe { ReadFile(pipe.0, Some(&mut request), Some(&raw mut bytes_read), None) } {
        Ok(()) => Ok(bytes_read as usize),
        Err(error) if error.code() == ERROR_BROKEN_PIPE.to_hresult() => Ok(bytes_read as usize),
        Err(error) => Err(error.into()),
    }
}

#[cfg(feature = "test-support")]
#[test]
fn server_identity_failures_reject_before_write() -> Result<()> {
    for failure in [
        FixtureIdentityFailure::Query,
        FixtureIdentityFailure::PidMismatch,
        FixtureIdentityFailure::ProcessExit,
        FixtureIdentityFailure::UnexpectedSid,
        FixtureIdentityFailure::UnexpectedPath,
    ] {
        let endpoint = unique_pipe_endpoint();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let server_endpoint = endpoint.clone();
        let server =
            std::thread::spawn(move || receive_request_bytes(&server_endpoint, &ready_sender));
        ready_receiver
            .recv_timeout(Duration::from_secs(5))
            .with_context(|| format!("byte-counting server did not start for {failure:?}"))?;

        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut transport = fixture_transport(
            endpoint,
            FixtureIdentityQuery {
                result: Err(failure),
                calls: std::sync::Arc::clone(&calls),
            },
        );
        let error = transport
            .send(&ServiceCommand::SetToken {
                value: String::from("must-not-be-serialized"),
            })
            .expect_err("identity failures must reject the request");
        assert!(
            error
                .to_string()
                .contains("service identity authentication failed")
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        drop(transport);
        let received = server
            .join()
            .map_err(|_| anyhow::anyhow!("byte-counting server panicked"))??;
        assert_eq!(received, 0, "identity failure must send zero request bytes");
    }
    Ok(())
}
