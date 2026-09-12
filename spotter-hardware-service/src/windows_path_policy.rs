// pattern: Imperative Shell

//! Windows handle-backed facts for the protected hardware-host path policy.

#![expect(
    unsafe_code,
    reason = "protected hardware-host validation requires narrowly scoped Windows handle and ACL APIs"
)]

use std::{
    os::windows::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree},
        Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        Security::{
            ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
            GetAce, GetSecurityDescriptorDacl, IsWellKnownSid, OBJECT_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
            WinLocalSystemSid,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TAG_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FileAttributeTagInfo, GetFileInformationByHandleEx,
            GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
        },
    },
    core::{PCWSTR, PWSTR},
};

use crate::path_policy::{
    self, AceFact, ObjectKind, Owner, PathFacts, PathPurpose, PolicyError, Principal,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const WRITE_MASK: u32 = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x10000 | 0x20000 | 0x40000 | 0x80000;
const REPARSE_TAG_NONE: u32 = 0;
const MAX_FINAL_PATH: usize = 32_768;
const TRUSTED_INSTALLER_SID: &str = "S-1-5-80-956008885-3418522649-1831038044-185329263-2271478464";

/// A protected handle retained until the child consuming the validated object exits.
///
/// The handle is opened with read sharing only. That permits the child to read the validated
/// collector/key while denying subsequent write, delete, and rename opens to the object.
pub(crate) struct RetainedHandle {
    handle: HANDLE,
    final_path: PathBuf,
}

impl Drop for RetainedHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: this wrapper owns the handle returned by CreateFileW.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl RetainedHandle {
    /// Return the final path obtained from this handle during validation.
    pub(crate) fn final_path(&self) -> &Path {
        &self.final_path
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn component_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut current = PathBuf::new();
    let mut paths = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                current.push(name);
                paths.push(current.clone());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(format!(
                    "path contains navigation component: {}",
                    path.display()
                ));
            }
        }
    }
    if paths.is_empty() {
        return Err(format!(
            "path has no openable components: {}",
            path.display()
        ));
    }
    Ok(paths)
}

fn close_handles(handles: impl IntoIterator<Item = HANDLE>) {
    for handle in handles {
        if !handle.is_invalid() {
            // SAFETY: each handle was opened by this function and has exactly one owner here.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}

fn open_no_follow(path: &Path) -> Result<HANDLE, String> {
    let path = wide(path);
    let desired_access = READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0;
    // FILE_SHARE_READ lets the validated reader consume the object. Omitting write/delete share
    // prevents replacement, rename, and mutation while the handle is retained.
    let share_mode = FILE_SHARE_READ;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    // SAFETY: `path` is a valid nul-terminated UTF-16 buffer; all other arguments are constants.
    unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            desired_access,
            share_mode,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|error| {
        format!("failed to open protected path without following reparse points: {error}")
    })
}

fn final_path(handle: HANDLE) -> Result<PathBuf, String> {
    let mut buffer = vec![0_u16; MAX_FINAL_PATH];
    // SAFETY: buffer is writable and its length is supplied to the Windows API.
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, VOLUME_NAME_DOS) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("failed to resolve final path from protected handle".to_owned());
    }
    String::from_utf16(&buffer[..length])
        .map(PathBuf::from)
        .map_err(|_| "final path was not valid UTF-16".to_owned())
}

fn tag_info(handle: HANDLE) -> Result<FILE_ATTRIBUTE_TAG_INFO, String> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `info` has the exact type and size required by FileAttributeTagInfo.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            std::ptr::addr_of_mut!(info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|error| format!("failed to read file attribute tag: {error}"))?;
    Ok(info)
}

fn sid_string(sid: PSID) -> Result<String, String> {
    let mut string_sid = PWSTR::null();
    // SAFETY: `sid` is borrowed from the live descriptor and `string_sid` is writable output.
    unsafe {
        windows::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut string_sid)
    }
    .map_err(|error| format!("failed to convert SID to text: {error}"))?;
    let result = unsafe { string_sid.to_string() }
        .map_err(|error| format!("failed to decode SID text: {error}"));
    // SAFETY: ConvertSidToStringSidW allocates the returned string with LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(string_sid.0.cast())));
    }
    result
}

fn classify_sid(sid: PSID) -> Result<Principal, String> {
    if sid.0.is_null() {
        return Err("ACL entry has no trustee SID".to_owned());
    }
    // SAFETY: `sid` is borrowed from the live security descriptor.
    if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() } {
        return Ok(Principal::Administrators);
    }
    // SAFETY: `sid` is borrowed from the live security descriptor.
    if unsafe { IsWellKnownSid(sid, WinLocalSystemSid).as_bool() } {
        return Ok(Principal::System);
    }
    Ok(Principal::Other)
}

fn classify_owner(sid: PSID, allow_trusted_installer: bool) -> Result<Owner, String> {
    if sid.0.is_null() {
        return Err("protected path has no owner".to_owned());
    }
    // SAFETY: `sid` is borrowed from the live security descriptor.
    if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool() } {
        return Ok(Owner::Administrators);
    }
    // SAFETY: `sid` is borrowed from the live security descriptor.
    if unsafe { IsWellKnownSid(sid, WinLocalSystemSid).as_bool() } {
        return Ok(Owner::System);
    }
    if allow_trusted_installer && sid_string(sid)?.eq_ignore_ascii_case(TRUSTED_INSTALLER_SID) {
        return Ok(Owner::TrustedInstaller);
    }
    Ok(Owner::Other)
}

fn ace_facts(dacl: *const ACL) -> Result<Vec<AceFact>, String> {
    if dacl.is_null() {
        return Err("protected path has no DACL".to_owned());
    }
    // SAFETY: ACL is a fixed header followed by ACEs; the API validates each returned pointer.
    let count = unsafe { (*dacl).AceCount };
    let mut facts = Vec::with_capacity(count as usize);
    for index in 0..u32::from(count) {
        let mut ace = std::ptr::null_mut();
        // SAFETY: dacl is borrowed from the live security descriptor and index is bounded.
        unsafe { GetAce(dacl, index, &mut ace) }
            .map_err(|error| format!("failed to read ACL entry {index}: {error}"))?;
        if ace.is_null() {
            return Err("Windows returned a null ACL entry".to_owned());
        }
        // SAFETY: GetAce returned an ACE_HEADER-aligned pointer valid for this ACL entry.
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        let (mask, sid, allow) = match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {
                // SAFETY: an allowed ACE starts with the common header and mask/SID fields.
                let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
                let sid = PSID(std::ptr::addr_of!(allowed.SidStart).cast_mut().cast());
                (allowed.Mask, sid, true)
            }
            ACCESS_DENIED_ACE_TYPE => {
                // SAFETY: a denied ACE starts with the common header and mask/SID fields.
                let denied = unsafe { &*(ace.cast::<ACCESS_DENIED_ACE>()) };
                let sid = PSID(std::ptr::addr_of!(denied.SidStart).cast_mut().cast());
                (denied.Mask, sid, false)
            }
            other => {
                return Err(format!("unsupported ACL entry type {other}"));
            }
        };
        facts.push(AceFact {
            principal: classify_sid(sid)?,
            grants_write: mask & WRITE_MASK != 0,
            allow,
        });
    }
    Ok(facts)
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: GetSecurityInfo allocates the descriptor with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }
}

fn security_facts(
    handle: HANDLE,
    allow_trusted_installer: bool,
) -> Result<(Owner, Vec<AceFact>), String> {
    let mut owner = PSID::default();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let security: OBJECT_SECURITY_INFORMATION =
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    // SAFETY: all output pointers are valid for this call; descriptor is released by RAII.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            security,
            Some(std::ptr::addr_of_mut!(owner)),
            None,
            Some(std::ptr::addr_of_mut!(dacl)),
            None,
            Some(std::ptr::addr_of_mut!(descriptor)),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(format!(
            "failed to read protected handle security: {}",
            result.0
        ));
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mut present = false.into();
    let mut descriptor_dacl = std::ptr::null_mut();
    let mut defaulted = false.into();
    // SAFETY: descriptor is valid for this scope and outputs are writable.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut present,
            &mut descriptor_dacl,
            &mut defaulted,
        )
    }
    .map_err(|error| format!("failed to read protected handle DACL: {error}"))?;
    if !present.as_bool() || descriptor_dacl.is_null() || descriptor_dacl != dacl {
        return Err("protected handle has an absent or inconsistent DACL".to_owned());
    }
    // SAFETY: owner is borrowed from the descriptor returned by GetSecurityInfo.
    let owner = classify_owner(owner, allow_trusted_installer)?;
    Ok((owner, ace_facts(descriptor_dacl)?))
}

fn format_policy_error(path: &Path, error: PolicyError) -> String {
    format!("unsafe hardware-host path {}: {error}", path.display())
}

/// Inspect every path component without following reparse points and retain the final handle.
pub(crate) fn inspect_path(
    root: &Path,
    path: &Path,
    purpose: PathPurpose,
) -> Result<RetainedHandle, String> {
    let components = component_paths(path)?;
    let mut handles = Vec::with_capacity(components.len());
    let mut standard_user_writable_ancestor = false;

    for (index, component) in components.iter().enumerate() {
        let handle = match open_no_follow(component) {
            Ok(handle) => handle,
            Err(error) => {
                close_handles(handles);
                return Err(error);
            }
        };
        let info = match tag_info(handle) {
            Ok(info) => info,
            Err(error) => {
                close_handles(handles.into_iter().chain(std::iter::once(handle)));
                return Err(error);
            }
        };
        // Check the tag before using this component as an ancestor. This is the critical ordering
        // that prevents a reparse point from redirecting any subsequent component lookup.
        if info.ReparseTag != REPARSE_TAG_NONE {
            let error = format_policy_error(path, PolicyError::ReparseTag(info.ReparseTag));
            close_handles(handles.into_iter().chain(std::iter::once(handle)));
            return Err(error);
        }
        let final_path = match final_path(handle) {
            Ok(path) => path,
            Err(error) => {
                close_handles(handles.into_iter().chain(std::iter::once(handle)));
                return Err(error);
            }
        };
        let (owner, aces) = match security_facts(handle, purpose == PathPurpose::PowerShellHost) {
            Ok(facts) => facts,
            Err(error) => {
                close_handles(handles.into_iter().chain(std::iter::once(handle)));
                return Err(error);
            }
        };
        if index + 1 != components.len() {
            standard_user_writable_ancestor |= aces.iter().any(|ace| {
                ace.allow
                    && ace.grants_write
                    && !matches!(ace.principal, Principal::Administrators | Principal::System)
            });
        } else {
            let facts = PathFacts {
                final_path: final_path.to_string_lossy().into_owned(),
                reparse_tag: info.ReparseTag,
                ancestor_reparse: false,
                owner,
                aces,
                standard_user_writable_ancestor,
                object_kind: if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
                exists: true,
            };
            // The pure policy is evaluated against the handle-derived final path, not the input
            // pathname. This is the containment check that closes link and rewrite escapes.
            if let Err(error) = path_policy::validate_path(&root.to_string_lossy(), &facts, purpose)
            {
                close_handles(handles.into_iter().chain(std::iter::once(handle)));
                return Err(format_policy_error(path, error));
            }
            close_handles(handles);
            return Ok(RetainedHandle { handle, final_path });
        }
        handles.push(handle);
    }

    close_handles(handles);
    Err(format!("path has no final component: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_include_no_follow_and_no_share_contract() {
        assert_eq!(FILE_FLAG_OPEN_REPARSE_POINT.0, 0x0020_0000);
        assert_eq!(FILE_SHARE_READ.0, 1);
        assert_eq!(FileAttributeTagInfo.0, 9);
    }

    #[test]
    fn write_access_mask_includes_delete_and_write_rights() {
        assert_ne!(WRITE_MASK & 0x0002, 0);
        assert_ne!(WRITE_MASK & 0x0004, 0);
        assert_ne!(WRITE_MASK & 0x0001_0000, 0);
    }
}
