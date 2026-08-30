#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "Live named-pipe ACL inspection requires narrowly scoped Windows security descriptor calls"
)]

use std::{fs::OpenOptions, os::windows::io::AsRawHandle as _, time::Duration};

use anyhow::{Context as _, Result};
use spotter_cli::{IpcTransport, NamedPipeTransport};
use spotter_core::ipc::{IpcResponse, ServiceCommand};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    },
    core::PWSTR,
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
                    let mut transport =
                        NamedPipeTransport::with_endpoint(Duration::from_secs(5), endpoint.clone());
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
