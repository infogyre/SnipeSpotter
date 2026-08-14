#![expect(
    unsafe_code,
    reason = "Named-pipe security requires narrowly scoped Windows security descriptor calls"
)]
// pattern: Imperative Shell

//! Security attributes for administrator-accessible named pipes.

use anyhow::{Context as _, Result};
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES},
    },
    core::{PCWSTR, w},
};

const SDDL_REVISION_1: u32 = 1;
const ADMIN_PIPE_SDDL: PCWSTR = w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)");

/// Owned security attributes for a named pipe.
///
/// The security descriptor returned by `ConvertStringSecurityDescriptorToSecurityDescriptorW` is
/// retained for the full lifetime of this value, so a caller can safely borrow the attributes for
/// a subsequent `CreateNamedPipeW` call.
pub struct SecurityAttributes {
    attributes: SECURITY_ATTRIBUTES,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityAttributes {
    /// Return a pointer suitable for a Windows API accepting `SECURITY_ATTRIBUTES`.
    ///
    /// The pointer is valid until this value is dropped and must not be retained by the caller
    /// beyond that lifetime.
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

        // SAFETY: The descriptor was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
        // and remains owned by this wrapper until this destructor runs.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0.cast())));
        }
    }
}

/// Build administrator-accessible named-pipe security attributes.
///
/// The descriptor grants generic-all access to `LocalSystem` (`SY`) and the built-in Administrators
/// group (`BA`), while denying handle inheritance through `bInheritHandle == false`.
///
/// # Errors
///
/// Returns an error if Windows cannot convert the fixed SDDL expression into a security descriptor.
pub fn create_admin_pipe_security_attributes() -> Result<SecurityAttributes> {
    let n_length = u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
        .context("SECURITY_ATTRIBUTES size does not fit in u32")?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    // SAFETY: `ADMIN_PIPE_SDDL` is a valid nul-terminated UTF-16 SDDL string, `descriptor` is a
    // writable out-parameter, and the optional size output is not needed.
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
        anyhow::bail!("Windows returned a null named-pipe security descriptor");
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: n_length,
        lpSecurityDescriptor: descriptor.0.cast(),
        bInheritHandle: false.into(),
    };

    Ok(SecurityAttributes {
        attributes,
        descriptor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_have_noninheritable_descriptor() -> Result<()> {
        let attributes = create_admin_pipe_security_attributes()?;
        let pointer = attributes.as_ptr();

        assert!(!pointer.is_null());
        // SAFETY: `pointer` came from `attributes` and is valid until the end of this scope.
        let attributes_ref = unsafe { &*pointer };
        assert!(!attributes_ref.lpSecurityDescriptor.is_null());
        assert!(!attributes_ref.bInheritHandle.as_bool());
        Ok(())
    }
}
