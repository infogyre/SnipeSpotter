#![cfg_attr(
    windows,
    expect(
        unsafe_code,
        reason = "crash-safe Windows replacement requires narrowly scoped file-system API calls"
    )
)]
// pattern: Imperative Shell

//! Same-directory durable writes with Windows-safe destination replacement.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};

/// Flush bytes to a same-directory temporary file and atomically replace the destination.
///
/// # Errors
/// Returns an error when directory creation, writing, flushing, or replacement fails.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = temporary_path(path);
    let result = (|| -> Result<()> {
        let mut file = fs::File::create(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        replace(&temporary, path)?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(not(windows))]
fn replace(temporary: &Path, destination: &Path) -> Result<()> {
    fs::rename(temporary, destination)
        .with_context(|| format!("failed to replace {}", destination.display()))
}

#[cfg(windows)]
fn replace(temporary: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows::{
        Win32::Storage::FileSystem::{
            MOVE_FILE_FLAGS, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
        },
        core::PCWSTR,
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let destination_exists = destination.exists();
    let temporary = wide(temporary);
    let destination = wide(destination);
    let temporary = PCWSTR(temporary.as_ptr());
    let destination = PCWSTR(destination.as_ptr());
    if destination_exists {
        // SAFETY: Both path buffers are live, nul-terminated UTF-16 strings for this call. Optional
        // backup and exclusion arguments are null, and no handles escape the function.
        unsafe {
            ReplaceFileW(
                destination,
                temporary,
                PCWSTR::null(),
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
        }
        .with_context(|| "failed to replace existing destination with ReplaceFileW")?;
    } else {
        let flags = MOVE_FILE_FLAGS(MOVEFILE_REPLACE_EXISTING.0 | MOVEFILE_WRITE_THROUGH.0);
        // SAFETY: Both path buffers are live, nul-terminated UTF-16 strings for this call.
        unsafe { MoveFileExW(temporary, destination, flags) }
            .with_context(|| "failed to install destination with MoveFileExW")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_destination() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        write(&path, b"first")?;
        write(&path, b"second")?;
        assert_eq!(fs::read(path)?, b"second");
        Ok(())
    }
}
