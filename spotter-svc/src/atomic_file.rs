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
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use getrandom::fill as random_fill;

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
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{Arc, Barrier},
    };

    use super::{FaultController, Result};

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

    /// Barrier stages used by a helper process that is terminated during a write.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum BarrierPoint {
        /// Wait immediately before destination replacement.
        BeforeReplace,
        /// Wait immediately after destination replacement.
        AfterReplace,
    }

    struct BarrierController {
        point: BarrierPoint,
        barrier: Arc<Barrier>,
        marker: PathBuf,
    }

    impl FaultController for BarrierController {
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
            if self.point == BarrierPoint::BeforeReplace {
                fs::write(&self.marker, "before-replace")?;
                self.barrier.wait();
            }
            Ok(())
        }

        fn after_replace(&self) -> Result<()> {
            if self.point == BarrierPoint::AfterReplace {
                fs::write(&self.marker, "after-replace")?;
                self.barrier.wait();
            }
            Ok(())
        }

        fn before_directory_flush(&self) -> Result<()> {
            Ok(())
        }
    }

    /// Execute an atomic write while synchronizing at a replacement barrier.
    ///
    /// # Errors
    /// Returns an underlying file-system error.
    pub fn write_with_barriers(
        path: &Path,
        bytes: &[u8],
        point: BarrierPoint,
        barrier: Arc<Barrier>,
        marker: impl Into<PathBuf>,
    ) -> Result<()> {
        super::write_with_controller(
            path,
            bytes,
            &BarrierController {
                point,
                barrier,
                marker: marker.into(),
            },
        )
    }

    /// Create a test-only owned temporary file with an explicit process identity and nonce.
    ///
    /// # Errors
    /// Returns an error when the temporary file cannot be created or its metadata cannot be saved.
    pub fn create_owned_temporary_for_test(
        path: &Path,
        owner_pid: u32,
        nonce: u64,
    ) -> Result<PathBuf> {
        let temporary = super::temporary_path_with_identity(path, owner_pid, nonce);
        fs::write(&temporary, b"test temporary")?;
        fs::write(
            super::owner_metadata_path(&temporary),
            format!("{owner_pid}:{nonce}"),
        )?;
        Ok(temporary)
    }

    pub use super::recover_stale_temporary_files;
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
    controller.before_temporary_creation()?;
    let (temporary, owner_metadata) = create_temporary_identity(path)?;
    let result = (|| -> Result<()> {
        #[cfg(windows)]
        crate::windows_acl::apply_acl_contract(&temporary)
            .context("failed to secure atomic temporary file")?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&temporary)
            .with_context(|| format!("failed to open {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        controller.after_temporary_write()?;
        controller.before_temporary_flush()?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        drop(file);
        controller.before_replace()?;
        replace(&temporary, path)?;
        #[cfg(windows)]
        crate::windows_acl::apply_acl_contract(path)
            .context("failed to preserve destination ACL after atomic replacement")?;
        controller.after_replace()?;
        controller.before_directory_flush()?;
        if let Ok(directory) = File::open(parent) {
            directory
                .sync_all()
                .with_context(|| format!("failed to flush directory {}", parent.display()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_file(&owner_metadata);
    } else {
        fs::remove_file(&owner_metadata).with_context(|| {
            format!(
                "failed to remove owner metadata for {}",
                temporary.display()
            )
        })?;
    }
    result
}

fn create_temporary_identity(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let owner_pid = std::process::id();
    for _ in 0..16 {
        let nonce = next_temporary_nonce()?;
        let temporary = temporary_path_with_identity(path, owner_pid, nonce);
        let owner_metadata = owner_metadata_path(&temporary);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(_) => {
                #[cfg(windows)]
                if let Err(error) = crate::windows_acl::apply_acl_contract(&temporary) {
                    let _ = fs::remove_file(&temporary);
                    return Err(error).context("failed to secure atomic temporary file");
                }
                match create_owner_metadata(&owner_metadata, owner_pid, nonce) {
                    Ok(()) => return Ok((temporary, owner_metadata)),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                        let _ = fs::remove_file(&temporary);
                    }
                    Err(error) => {
                        let _ = fs::remove_file(&temporary);
                        let _ = fs::remove_file(&owner_metadata);
                        return Err(error).with_context(|| {
                            format!("failed to create {}", owner_metadata.display())
                        });
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", temporary.display()));
            }
        }
    }
    anyhow::bail!(
        "failed to allocate a unique temporary file for {}",
        path.display()
    )
}

fn create_owner_metadata(path: &Path, owner_pid: u32, nonce: u64) -> std::io::Result<()> {
    let mut metadata = OpenOptions::new().write(true).create_new(true).open(path)?;
    write!(metadata, "{owner_pid}:{nonce}")?;
    metadata.sync_all()
}

fn next_temporary_nonce() -> Result<u64> {
    let counter = TEMPORARY_NONCE.fetch_add(1, Ordering::Relaxed);
    let mut random = [0_u8; 8];
    random_fill(&mut random)
        .map_err(|error| anyhow::anyhow!("failed to generate a temporary-file nonce: {error}"))?;
    Ok(u64::from_le_bytes(random) ^ counter)
}

#[cfg(test)]
fn temporary_path(path: &Path) -> PathBuf {
    temporary_path_with_identity(
        path,
        std::process::id(),
        TEMPORARY_NONCE.fetch_add(1, Ordering::Relaxed),
    )
}

fn temporary_path_with_identity(path: &Path, owner_pid: u32, nonce: u64) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{owner_pid}.{nonce}"));
    path.with_file_name(name)
}

fn owner_metadata_path(temporary: &Path) -> PathBuf {
    let mut name = temporary.file_name().unwrap_or_default().to_os_string();
    name.push(".owner");
    temporary.with_file_name(name)
}

fn temporary_identity(path: &Path) -> Option<(u32, u64)> {
    let name = path.file_name()?.to_str()?;
    let (_, suffix) = name.rsplit_once(".tmp.")?;
    let mut parts = suffix.split('.');
    let pid = parts.next()?.parse().ok()?;
    let nonce = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((pid, nonce))
}

fn orphan_temporary_path(owner_metadata: &Path) -> Option<PathBuf> {
    let name = owner_metadata.file_name()?.to_str()?;
    let temporary_name = name.strip_suffix(".owner")?;
    let temporary = owner_metadata.with_file_name(temporary_name);
    temporary_identity(&temporary)?;
    Some(temporary)
}

#[cfg(test)]
fn is_temporary_path(path: &Path) -> bool {
    temporary_identity(path).is_some()
}

#[cfg(windows)]
fn is_invalid_pid_error(error: windows::core::HRESULT) -> bool {
    use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;

    error == ERROR_INVALID_PARAMETER.to_hresult()
}

fn owner_is_dead(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::{
            Foundation::CloseHandle,
            Foundation::STILL_ACTIVE,
            System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            let error = windows::core::Error::from_thread();
            return is_invalid_pid_error(error.code());
        };
        let mut exit_code = 0_u32;
        // SAFETY: `process` is a valid handle returned by OpenProcess and `exit_code` is writable.
        let query = unsafe { GetExitCodeProcess(process, std::ptr::addr_of_mut!(exit_code)) };
        // SAFETY: `process` is the owned valid handle returned by OpenProcess. Closing it here
        // covers both successful and failed exit-code queries.
        unsafe {
            let _ = CloseHandle(process);
        }
        query.is_ok() && exit_code != STILL_ACTIVE.0 as u32
    }
    #[cfg(not(windows))]
    {
        pid != std::process::id() && !PathBuf::from(format!("/proc/{pid}")).exists()
    }
}

/// Remove conservative stale temporary files from one atomic-write directory.
///
/// Only regular files with matching owner metadata, a dead owner, and sufficient age are removed.
/// Missing or malformed metadata is left untouched so recovery cannot delete an unrelated file.
/// Orphan owner metadata is removed only when its corresponding temporary file is absent.
///
/// # Errors
/// Returns an error when the directory cannot be enumerated.
pub fn recover_stale_temporary_files(
    directory: &Path,
    current_pid: u32,
    minimum_age_seconds: u64,
) -> Result<usize> {
    if !directory.exists() {
        return Ok(0);
    }
    let entries = fs::read_dir(directory)
        .with_context(|| format!("failed to enumerate {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut removed = 0;

    for entry in &entries {
        let path = entry.path();
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(temporary) = orphan_temporary_path(&path) else {
            continue;
        };
        if temporary.exists() {
            continue;
        }
        let Some((pid, nonce)) = temporary_identity(&temporary) else {
            continue;
        };
        if pid == current_pid || !owner_is_dead(pid) {
            continue;
        }
        let age = entry
            .metadata()?
            .modified()?
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        if age < minimum_age_seconds {
            continue;
        }
        let Ok(owner) = fs::read_to_string(&path) else {
            continue;
        };
        if owner.trim() != format!("{pid}:{nonce}") {
            continue;
        }
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove stale {}", path.display()))?;
        removed += 1;
    }

    for entry in entries {
        let path = entry.path();
        let Some((pid, nonce)) = temporary_identity(&path) else {
            continue;
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !file_type.is_file() {
            continue;
        }
        if pid == current_pid || !owner_is_dead(pid) {
            continue;
        }
        let age = entry
            .metadata()?
            .modified()?
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        if age < minimum_age_seconds {
            continue;
        }
        let metadata_path = owner_metadata_path(&path);
        let Ok(owner) = fs::read_to_string(&metadata_path) else {
            continue;
        };
        if owner.trim() != format!("{pid}:{nonce}") {
            continue;
        }
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove stale {}", path.display()))?;
        if let Err(error) = fs::remove_file(&metadata_path)
            && error.kind() != ErrorKind::NotFound
        {
            return Err(error)
                .with_context(|| format!("failed to remove stale {}", metadata_path.display()));
        }
        removed += 1;
    }
    Ok(removed)
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
    fn owner_is_dead_closes_open_process_handle() {
        let source = include_str!("atomic_file.rs");
        let owner_start = source
            .find("fn owner_is_dead(pid: u32) -> bool {")
            .expect("owner_is_dead must remain defined in this module");
        let owner_end = source[owner_start..]
            .find("/// Remove conservative stale temporary files")
            .map(|offset| owner_start + offset)
            .expect("owner_is_dead must remain before stale-file recovery");
        let owner = &source[owner_start..owner_end];
        let query = owner
            .find("let query = unsafe { GetExitCodeProcess")
            .expect("owner_is_dead must query the process exit code");
        let close = owner
            .find("CloseHandle(process)")
            .expect("owner_is_dead must close the process handle");
        assert!(
            query < close,
            "the process handle must be closed after querying the exit code"
        );
    }

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
    fn stale_recovery_removes_orphan_owner_sidecar_after_temporary_disappears() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        let temporary = temporary_path_with_identity(&path, u32::MAX, 9);
        let metadata_path = owner_metadata_path(&temporary);
        fs::write(&metadata_path, "4294967295:9")?;

        let removed = recover_stale_temporary_files(directory.path(), std::process::id(), 0)?;

        assert_eq!(removed, 1);
        assert!(!temporary.exists());
        assert!(!metadata_path.exists());
        Ok(())
    }

    #[test]
    fn stale_recovery_round_trips_destination_names_containing_tmp_marker() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("archive.tmp.state");
        let temporary = temporary_path_with_identity(&path, u32::MAX, 10);
        let metadata_path = owner_metadata_path(&temporary);
        fs::write(&temporary, b"test temporary")?;
        fs::write(&metadata_path, "4294967295:10")?;

        let removed = recover_stale_temporary_files(directory.path(), std::process::id(), 0)?;

        assert_eq!(removed, 1);
        assert!(!temporary.exists());
        assert!(!metadata_path.exists());
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

    #[test]
    fn failed_write_cleans_temporary_sidecar() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        fs::create_dir(&path)?;

        assert!(write(&path, b"cannot replace directory").is_err());

        let temporary_entries = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .filter(|entry| {
                let path = entry.path();
                is_temporary_path(&path)
                    || path
                        .extension()
                        .is_some_and(|extension| extension == "owner")
            })
            .count();
        assert_eq!(temporary_entries, 0);
        Ok(())
    }

    #[test]
    fn temporary_identity_is_shared_by_name_and_metadata() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("state.toml");
        fs::create_dir(&path)?;
        assert!(write(&path, b"cannot replace directory").is_err());

        let temporary = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .find(|entry| is_temporary_path(&entry.path()))
            .map(|entry| entry.path());
        assert!(temporary.is_none(), "temporary file was not cleaned up");
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

    #[cfg(windows)]
    #[test]
    fn invalid_pid_error_matches_only_the_typed_win32_code() {
        use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};

        assert!(is_invalid_pid_error(ERROR_INVALID_PARAMETER.to_hresult()));
        assert!(!is_invalid_pid_error(ERROR_ACCESS_DENIED.to_hresult()));
    }
}
