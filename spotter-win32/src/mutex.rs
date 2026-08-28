#![expect(
    unsafe_code,
    reason = "The single-process guard is backed by the Windows mutex API"
)]
// pattern: Imperative Shell

//! Cross-session process coordination through a named Windows mutex.

use anyhow::{Context as _, Result, bail};
use spotter_core::MUTEX_NAME;
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE},
        System::Threading::{CreateMutexW, ReleaseMutex},
    },
    core::PCWSTR,
};

/// A successfully acquired process-wide mutex.
///
/// Dropping this guard closes the owned Windows handle and releases the named mutex when no
/// other handle remains open.
pub struct MutexGuard {
    handle: HANDLE,
}

impl Drop for MutexGuard {
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }

        // SAFETY: `handle` was returned by CreateMutexW and is owned exclusively by this guard;
        // this Drop implementation runs on the owning thread because MutexGuard is not Send.
        unsafe {
            let _ = ReleaseMutex(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Attempt to acquire the global `SnipeSpotter` instance mutex.
///
/// # Errors
///
/// Returns a distinct error when another process already owns the named mutex. Other failures
/// include inability to create the mutex or a Windows API failure while querying the last error.
pub fn try_acquire_global_mutex() -> Result<MutexGuard> {
    try_acquire_named_mutex(MUTEX_NAME)
}

/// Attempt to acquire a named global Windows mutex.
///
/// # Errors
///
/// Returns a distinct error when another process already owns the named mutex. Other failures
/// include inability to create the mutex or a Windows API failure while querying the last error.
pub fn try_acquire_named_mutex(name: &str) -> Result<MutexGuard> {
    if name.is_empty() || name.contains('\0') {
        bail!("mutex name must not be empty or contain NUL bytes")
    }
    let name = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let name = PCWSTR::from_raw(name.as_ptr());

    // SAFETY: Passing no security attributes requests the default mutex security descriptor; the
    // UTF-16 buffer remains alive for the duration of this call.
    let handle = unsafe { CreateMutexW(None, true, name) }.context("failed to create mutex")?;
    let already_exists = {
        // SAFETY: GetLastError reads the thread-local result immediately after CreateMutexW.
        unsafe { GetLastError() == ERROR_ALREADY_EXISTS }
    };

    if already_exists {
        // Keep the handle alive only until this branch, then close it before returning the semantic
        // already-running error. This avoids leaking the second process's mutex handle.
        // SAFETY: `handle` is the owned valid handle returned by CreateMutexW.
        unsafe {
            let _ = CloseHandle(handle);
        }
        bail!("SnipeSpotter is already running")
    }

    Ok(MutexGuard { handle })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquisition_is_exclusive_and_released_on_drop() -> Result<()> {
        let first = try_acquire_global_mutex()?;
        let second = try_acquire_global_mutex();

        assert!(second.is_err());
        drop(first);
        let reacquired = try_acquire_global_mutex()?;
        drop(reacquired);
        Ok(())
    }

    #[test]
    fn isolated_mutex_names_are_supported() -> Result<()> {
        let name = format!("Global\\SnipeSpotter-test-{}", std::process::id());
        let first = try_acquire_named_mutex(&name)?;
        assert!(try_acquire_named_mutex(&name).is_err());
        drop(first);
        try_acquire_named_mutex(&name).map(|_| ())
    }
}
