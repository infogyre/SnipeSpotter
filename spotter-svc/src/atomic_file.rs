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
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};

#[cfg(test)]
use std::sync::Arc;

static TEMPORARY_NONCE: AtomicU64 = AtomicU64::new(0);

/// Flush bytes to a same-directory temporary file and atomically replace the destination.
///
/// # Errors
/// Returns an error when directory creation, writing, flushing, or replacement fails.
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    write_with_controller(path, bytes, &NoopFaultController)
}

trait FaultController: Send + Sync {
    fn before_temporary_creation(&self) -> Result<()>;
    fn after_temporary_write(&self) -> Result<()>;
    fn before_temporary_flush(&self) -> Result<()>;
    fn before_replace(&self) -> Result<()>;
    fn after_replace(&self) -> Result<()>;
    fn before_directory_flush(&self) -> Result<()>;
}

struct NoopFaultController;

impl FaultController for NoopFaultController {
    fn before_temporary_creation(&self) -> Result<()> {
        Ok(())
    }

    fn after_temporary_write(&self) -> Result<()> {
        Ok(())
    }

    fn before_temporary_flush(&self) -> Result<()> {
        Ok(())
    }

    fn before_replace(&self) -> Result<()> {
        Ok(())
    }

    fn after_replace(&self) -> Result<()> {
        Ok(())
    }

    fn before_directory_flush(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(all(windows, feature = "test-support"))]
pub mod test_support {
    use super::{FaultController, Path, Result};

    /// Deterministic stages at which an atomic write can fail.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum FaultPoint {
        /// Fail before creating the temporary file.
        CreateTemporary,
        /// Fail after writing the temporary file but before flushing it.
        WriteTemporary,
        /// Fail before flushing the temporary file.
        FlushTemporary,
        /// Fail after the temporary file is flushed but before replacement.
        BeforeReplace,
        /// Fail after the destination has been replaced.
        AfterReplace,
        /// Fail immediately before the best-effort directory flush.
        DirectoryFlush,
    }

    struct InjectedFault(FaultPoint);

    impl FaultController for InjectedFault {
        fn before_temporary_creation(&self) -> Result<()> {
            if self.0 == FaultPoint::CreateTemporary {
                anyhow::bail!("injected failure during temporary creation");
            }
            Ok(())
        }

        fn after_temporary_write(&self) -> Result<()> {
            if self.0 == FaultPoint::WriteTemporary {
                anyhow::bail!("injected failure during temporary write");
            }
            Ok(())
        }

        fn before_temporary_flush(&self) -> Result<()> {
            if self.0 == FaultPoint::FlushTemporary {
                anyhow::bail!("injected failure during temporary flush");
            }
            Ok(())
        }

        fn before_replace(&self) -> Result<()> {
            if self.0 == FaultPoint::BeforeReplace {
                anyhow::bail!("injected failure before replacement");
            }
            Ok(())
        }

        fn after_replace(&self) -> Result<()> {
            if self.0 == FaultPoint::AfterReplace {
                anyhow::bail!("injected failure after replacement");
            }
            Ok(())
        }

        fn before_directory_flush(&self) -> Result<()> {
            if self.0 == FaultPoint::DirectoryFlush {
                anyhow::bail!("injected failure during directory flush");
            }
            Ok(())
        }
    }

    /// Execute one atomic write with a deterministic injected fault.
    ///
    /// # Errors
    /// Returns the injected error or an underlying file-system error.
    pub fn write_with_fault(path: &Path, bytes: &[u8], point: FaultPoint) -> Result<()> {
        super::write_with_controller(path, bytes, &InjectedFault(point))
    }
}

#[cfg(test)]
impl FaultController for Arc<tests::AtomicFaultController> {
    fn before_temporary_creation(&self) -> Result<()> {
        self.as_ref().before_temporary_creation()
    }

    fn after_temporary_write(&self) -> Result<()> {
        self.as_ref().after_temporary_write()
    }

    fn before_temporary_flush(&self) -> Result<()> {
        self.as_ref().before_temporary_flush()
    }

    fn before_replace(&self) -> Result<()> {
        self.as_ref().before_replace()
    }

    fn after_replace(&self) -> Result<()> {
        self.as_ref().after_replace()
    }

    fn before_directory_flush(&self) -> Result<()> {
        self.as_ref().before_directory_flush()
    }
}

fn write_with_controller(
    path: &Path,
    bytes: &[u8],
    controller: &impl FaultController,
) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = temporary_path(path);
    let result = (|| -> Result<()> {
        controller.before_temporary_creation()?;
        let mut file = fs::File::create(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        controller.after_temporary_write()?;
        controller.before_temporary_flush()?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        drop(file);
        controller.before_replace()?;
        replace(&temporary, path)?;
        controller.after_replace()?;
        controller.before_directory_flush()?;
        if let Ok(directory) = fs::File::open(parent) {
            directory
                .sync_all()
                .with_context(|| format!("failed to flush directory {}", parent.display()))?;
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
    let nonce = TEMPORARY_NONCE.fetch_add(1, Ordering::Relaxed);
    name.push(format!(".tmp.{}.{}", std::process::id(), nonce));
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
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    #[test]
    fn replaces_existing_destination() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        write(&path, b"first")?;
        write(&path, b"second")?;
        assert_eq!(fs::read(path)?, b"second");
        Ok(())
    }

    #[test]
    fn temporary_names_have_unique_nonces() {
        let path = Path::new("state.toml");
        assert_ne!(temporary_path(path), temporary_path(path));
    }

    #[test]
    fn failed_replacement_cleans_temporary_file() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        fs::create_dir(&path)?;
        assert!(write(&path, b"cannot replace directory").is_err());
        let temporary_files = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("state.toml.tmp.")
            })
            .count();
        assert_eq!(temporary_files, 0);
        Ok(())
    }

    pub(super) struct AtomicFaultController {
        barrier: Arc<Barrier>,
    }

    impl AtomicFaultController {
        fn before_replace(barrier: Arc<Barrier>) -> Self {
            Self { barrier }
        }
    }

    impl FaultController for AtomicFaultController {
        fn before_temporary_creation(&self) -> Result<()> {
            Ok(())
        }

        fn after_temporary_write(&self) -> Result<()> {
            Ok(())
        }

        fn before_temporary_flush(&self) -> Result<()> {
            Ok(())
        }

        fn before_replace(&self) -> Result<()> {
            self.barrier.wait();
            anyhow::bail!("injected failure before replacement")
        }

        fn after_replace(&self) -> Result<()> {
            Ok(())
        }

        fn before_directory_flush(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn replacement_fault_is_deterministic_and_preserves_destination() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        write(&path, b"before")?;
        let barrier = Arc::new(Barrier::new(2));
        let controller = Arc::new(AtomicFaultController::before_replace(Arc::clone(&barrier)));
        let worker_path = path.clone();
        let worker_controller = Arc::clone(&controller);
        let worker = thread::spawn(move || {
            write_with_controller(&worker_path, b"after", &worker_controller)
        });
        barrier.wait();
        let error = worker
            .join()
            .map_err(|_| anyhow::anyhow!("atomic writer panicked"))?
            .expect_err("fault controller must fail before replacement");
        assert!(error.to_string().contains("before replacement"));
        assert_eq!(fs::read(&path)?, b"before");
        let temporary_files = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("state.toml.tmp.")
            })
            .count();
        assert_eq!(temporary_files, 0);
        Ok(())
    }
}
