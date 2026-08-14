#![expect(
    unsafe_code,
    reason = "DPAPI requires narrowly scoped calls into the Windows cryptography API"
)]
// pattern: Imperative Shell

//! Windows Data Protection API helpers for encrypted application secrets.

use std::slice;

use anyhow::{Context as _, Result, bail};
use spotter_core::PRODUCT_NAME;
use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB as DATA_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
    },
    core::PCWSTR,
};

/// Encrypt plaintext with the machine-scoped Windows Data Protection API.
///
/// The caller retains ownership of `plaintext`; this function does not persist a copy of it.
/// The output buffer allocated by DPAPI is copied into a Rust-owned vector and released with
/// [`LocalFree`] before this function returns.
///
/// # Errors
///
/// Returns an error if the input is too large for the Windows API or DPAPI rejects the request.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    protect(
        plaintext,
        CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
    )
}

/// Decrypt a machine-scoped DPAPI ciphertext.
///
/// The output buffer allocated by DPAPI is copied into a Rust-owned vector and released with
/// [`LocalFree`] before this function returns.
///
/// # Errors
///
/// Returns an error if the ciphertext is too large for the Windows API or DPAPI rejects it.
pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let input = data_blob(ciphertext).context("failed to prepare DPAPI ciphertext")?;
    let mut output = DATA_BLOB::default();

    // SAFETY: `input` points at the borrowed ciphertext for the duration of this call, `output`
    // is writable storage owned by this function, and all optional pointer arguments are null.
    let result = unsafe {
        CryptUnprotectData(
            std::ptr::addr_of!(input),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            std::ptr::addr_of_mut!(output),
        )
    };
    let output_guard = LocalFreeGuard::new(output.pbData);
    result.context("failed to decrypt data with DPAPI")?;

    copy_output(&output, output_guard)
}

fn protect(plaintext: &[u8], flags: u32) -> Result<Vec<u8>> {
    let input = data_blob(plaintext).context("failed to prepare DPAPI plaintext")?;
    let description = wide_null(PRODUCT_NAME);
    let description = PCWSTR::from_raw(description.as_ptr());
    let mut output = DATA_BLOB::default();

    // SAFETY: `input` references the caller's slice for the duration of this call, `description`
    // references a live nul-terminated UTF-16 buffer, `output` is writable local storage, and
    // all optional pointer arguments are null.
    let result = unsafe {
        CryptProtectData(
            std::ptr::addr_of!(input),
            description,
            None,
            None,
            None,
            flags,
            std::ptr::addr_of_mut!(output),
        )
    };
    let output_guard = LocalFreeGuard::new(output.pbData);
    result.context("failed to encrypt data with DPAPI")?;

    copy_output(&output, output_guard)
}

fn data_blob(data: &[u8]) -> Result<DATA_BLOB> {
    let cb_data = u32::try_from(data.len()).context("DPAPI input is too large")?;
    Ok(DATA_BLOB {
        cbData: cb_data,
        // DATA_BLOB uses a mutable pointer in the Windows ABI, but DPAPI does not mutate input.
        // A zero-length slice is permitted because the API receives cbData == 0.
        pbData: data.as_ptr().cast_mut(),
    })
}

fn copy_output(output: &DATA_BLOB, _output_guard: LocalFreeGuard) -> Result<Vec<u8>> {
    let length = usize::try_from(output.cbData).context("DPAPI output length is invalid")?;
    if length != 0 && output.pbData.is_null() {
        bail!("DPAPI returned a null output buffer");
    }
    if length == 0 {
        return Ok(Vec::new());
    }

    // SAFETY: DPAPI initialized `pbData` to a valid allocation containing `cbData` bytes, and the
    // guard remains alive until after this copy, so the borrowed view cannot outlive the allocation.
    Ok(unsafe { slice::from_raw_parts(output.pbData, length) }.to_vec())
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct LocalFreeGuard(*mut u8);

impl LocalFreeGuard {
    fn new(pointer: *mut u8) -> Self {
        Self(pointer)
    }
}

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }

        // SAFETY: DPAPI allocated this pointer, and this guard owns the one required LocalFree call.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.cast())));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonempty_plaintext_roundtrips_to_nonempty_ciphertext() -> Result<()> {
        let plaintext = b"SnipeSpotter DPAPI test secret";
        let ciphertext = encrypt(plaintext)?;

        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
        assert_eq!(decrypt(&ciphertext)?, plaintext);
        Ok(())
    }

    #[test]
    fn empty_plaintext_roundtrips() -> Result<()> {
        let ciphertext = encrypt(&[])?;

        assert!(!ciphertext.is_empty());
        assert_eq!(decrypt(&ciphertext)?, Vec::<u8>::new());
        Ok(())
    }
}
