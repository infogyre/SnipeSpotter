#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "Windows ACL contract requires narrowly scoped security descriptor API calls"
)]
// pattern: Imperative Shell

//! The service data-directory ACL contract shared by installation and runtime writes.

use std::{os::windows::ffi::OsStrExt as _, path::Path};

use anyhow::{Context as _, Result};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree},
        Security::{
            ACL,
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT,
                SetNamedSecurityInfoW,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        },
    },
    core::PCWSTR,
};

#[cfg(feature = "test-support")]
use windows::{
    Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    },
    core::PWSTR,
};

/// The non-inherited data contract: only SYSTEM and built-in Administrators get full control.
pub const DATA_ACL_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";
const SDDL_REVISION_1: u32 = 1;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Apply the protected data ACL to one existing file or directory.
///
/// The same helper is used by service startup and atomic replacement. It deliberately replaces the
/// complete DACL rather than merging inherited entries, so a standard user cannot regain access
/// through the parent directory or a stale allow rule.
///
/// # Errors
/// Returns an error when Windows cannot parse or apply the fixed security descriptor.
pub fn apply_acl_contract(path: &Path) -> Result<()> {
    let descriptor = OwnedDescriptor(descriptor_from_sddl()?);
    let dacl = descriptor_dacl(descriptor.0)?;
    let path = wide(path);
    let result = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.cast_const()),
            None,
        )
    };
    if result != ERROR_SUCCESS {
        anyhow::bail!(
            "failed to apply protected data ACL: Win32 error {}",
            result.0
        );
    }
    Ok(())
}

/// Read the canonical SDDL for a path's current DACL.
///
/// This is a test-support inspection seam; production callers should use [`apply_acl_contract`]
/// rather than inspect security descriptors.
///
/// # Errors
/// Returns an error when Windows cannot read or render the path's DACL.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn read_acl_sddl(path: &Path) -> Result<String> {
    let path = wide(path);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            std::ptr::addr_of_mut!(descriptor),
        )
    };
    if result != ERROR_SUCCESS {
        anyhow::bail!("failed to read path ACL: Win32 error {}", result.0);
    }
    let descriptor = OwnedDescriptor(descriptor);
    let mut text = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::addr_of_mut!(text),
            None,
        )
    }
    .context("failed to render path ACL")?;
    let rendered = unsafe { text.to_string() }.context("invalid rendered path ACL")?;
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    Ok(rendered)
}

fn descriptor_dacl(descriptor: PSECURITY_DESCRIPTOR) -> Result<*mut ACL> {
    if descriptor.is_invalid() {
        anyhow::bail!("Windows returned an invalid security descriptor");
    }
    let mut present = false.into();
    let mut dacl = std::ptr::null_mut();
    let mut defaulted = false.into();
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            std::ptr::addr_of_mut!(present),
            std::ptr::addr_of_mut!(dacl),
            std::ptr::addr_of_mut!(defaulted),
        )
    }
    .context("failed to read security descriptor DACL")?;
    if !present.as_bool() || dacl.is_null() {
        anyhow::bail!("security descriptor does not contain a DACL");
    }
    Ok(dacl)
}

fn descriptor_from_sddl() -> Result<PSECURITY_DESCRIPTOR> {
    let sddl: Vec<u16> = DATA_ACL_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            std::ptr::addr_of_mut!(descriptor),
            None,
        )
    }
    .context("failed to create protected data security descriptor")?;
    if descriptor.is_invalid() {
        anyhow::bail!("Windows returned an invalid protected data security descriptor");
    }
    Ok(descriptor)
}

/// Free a descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
struct OwnedDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    #[test]
    fn data_acl_contract_is_protected_and_narrow() -> Result<()> {
        let descriptor = OwnedDescriptor(descriptor_from_sddl()?);
        let dacl = descriptor_dacl(descriptor.0)?;
        assert_ne!(dacl.cast_const(), descriptor.0.0.cast::<ACL>().cast_const());
        let mut text = PWSTR::null();
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::addr_of_mut!(text),
                None,
            )
        }
        .context("failed to render protected data security descriptor")?;
        let rendered =
            unsafe { text.to_string() }.context("invalid rendered security descriptor")?;
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        assert!(rendered.contains("D:P"));
        assert!(rendered.contains("A;OICI;GA;;;SY"));
        assert!(rendered.contains("A;OICI;GA;;;BA"));
        assert!(!rendered.contains(";;;WD"));
        assert!(!rendered.contains(";;;BU"));
        assert!(!rendered.contains(";;;AU"));
        Ok(())
    }
}
