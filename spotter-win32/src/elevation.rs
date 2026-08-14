#![expect(
    unsafe_code,
    reason = "Token elevation is queried through narrowly scoped Windows security calls"
)]
// pattern: Imperative Shell

//! Windows access-token elevation detection.

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Return whether the current process token is elevated.
///
/// API failures are treated as not elevated because this helper is intentionally a boolean policy
/// check; the token handle is closed before the function returns on every successful open path.
#[must_use]
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns the pseudo-handle for this process, `TOKEN_QUERY` is the
    // minimum access required by GetTokenInformation, and `token` is a writable out-parameter.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            std::ptr::addr_of_mut!(token),
        )
    };
    if opened.is_err() || token.is_invalid() {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned_length = 0_u32;
    // SAFETY: `token` is a valid handle owned by this function, `elevation` is correctly typed
    // writable storage, and the supplied length matches that storage.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::addr_of_mut!(elevation).cast()),
            u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            std::ptr::addr_of_mut!(returned_length),
        )
    };
    // SAFETY: `token` was returned by OpenProcessToken and is owned by this function.
    unsafe {
        let _ = CloseHandle(token);
    }

    queried.is_ok()
        && returned_length >= u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX)
        && elevation.TokenIsElevated != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_query_returns_a_boolean() {
        let _ = is_elevated();
    }
}
