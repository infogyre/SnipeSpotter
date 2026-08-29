#![cfg(all(windows, feature = "test-support"))]

use std::{
    fs,
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};

use anyhow::Result;
use spotter_svc::{
    atomic_file::{
        test_support::{
            FaultPoint, create_owned_temporary_for_test, recover_stale_temporary_files,
            write_with_fault,
        },
        write,
    },
    windows_acl::read_acl_sddl,
};

fn assert_old_or_new(path: &std::path::Path, old: &[u8], new: &[u8]) -> Result<()> {
    let contents = fs::read(path)?;
    assert!(contents == old || contents == new);
    Ok(())
}

#[test]
fn first_create_applies_the_protected_data_acl() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");

    write(&path, b"new-state")?;

    assert_acl_contract(&path)
}

#[test]
fn existing_replacement_preserves_the_protected_data_acl() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    write(&path, b"new-state")?;

    assert_acl_contract(&path)
}

fn assert_acl_contract(path: &Path) -> Result<()> {
    let sddl = read_acl_sddl(path)?;
    validate_file_acl_contract(&sddl)
        .map_err(|error| anyhow::anyhow!("invalid ACL for {}: {error}", path.display()))
}

#[test]
fn canonical_file_acl_contract_is_accepted() {
    for sddl in [
        "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)",
        "D:PAI(A;;FA;;;BA)(A;;FA;;;SY)",
    ] {
        validate_file_acl_contract(sddl)
            .unwrap_or_else(|error| panic!("canonical Windows file ACL was rejected: {error}"));
    }
}

#[test]
fn file_acl_contract_rejects_broad_extra_or_non_file_aces() {
    for sddl in [
        "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)",
        "D:PAI(A;;GA;;;SY)(A;;FA;;;BA)",
        "D:PAI(A;OICI;GA;;;SY)(A;;FA;;;BA)",
        "D:PAI(A;;FA;;;SY)(A;;FA;;;SY)",
        "D:PAI(A;;FA;;;BA)(A;;FA;;;BA)",
        "D:(A;;FA;;;SY)(A;;FA;;;BA)",
    ] {
        assert!(
            validate_file_acl_contract(sddl).is_err(),
            "ACL must not satisfy the file contract: {sddl}"
        );
    }
}

fn validate_file_acl_contract(sddl: &str) -> std::result::Result<(), &'static str> {
    let dacl = sddl.strip_prefix("D:").ok_or("missing DACL prefix")?;
    let first_ace = dacl.find('(').ok_or("DACL contains no ACEs")?;
    if !dacl[..first_ace].starts_with('P') {
        return Err("DACL is not protected");
    }

    let mut remaining = &dacl[first_ace..];
    let mut principals = [false; 2];
    let mut ace_count = 0;
    while !remaining.is_empty() {
        if !remaining.starts_with('(') {
            return Err("DACL contains trailing data");
        }
        let end = remaining.find(')').ok_or("ACE is unterminated")?;
        let fields = remaining[1..end].split(';').collect::<Vec<_>>();
        let [kind, flags, rights, object, inherit_object, principal] = fields.as_slice() else {
            return Err("ACE does not contain six fields");
        };
        if *kind != "A" {
            return Err("DACL contains a non-allow ACE");
        }
        if !flags.is_empty() || *rights != "FA" || !object.is_empty() || !inherit_object.is_empty()
        {
            return Err("ACE is not a canonical full-file allow");
        }
        let principal_index = match *principal {
            "SY" => 0,
            "BA" => 1,
            _ => return Err("DACL contains an unauthorized principal"),
        };
        if principals[principal_index] {
            return Err("DACL contains a duplicate required principal");
        }
        principals[principal_index] = true;
        ace_count += 1;
        remaining = &remaining[end + 1..];
    }
    if ace_count != 2 || !principals.iter().all(|present| *present) {
        return Err("DACL must contain exactly SYSTEM and Administrators");
    }
    Ok(())
}

#[test]
fn fault_before_replacement_preserves_old_complete_content() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    let error = write_with_fault(&path, b"new-state", FaultPoint::BeforeReplace)
        .expect_err("before-replace fault must fail");

    assert!(error.to_string().contains("before replacement"));
    assert_eq!(fs::read(&path)?, b"old-state");
    Ok(())
}

#[test]
fn fault_after_replacement_reports_new_complete_content() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    let error = write_with_fault(&path, b"new-state", FaultPoint::AfterReplace)
        .expect_err("after-replace fault must fail");

    assert!(error.to_string().contains("after replacement"));
    assert_old_or_new(&path, b"old-state", b"new-state")?;
    assert_eq!(fs::read(&path)?, b"new-state");
    Ok(())
}

#[test]
fn directory_flush_failure_keeps_complete_destination() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    let error = write_with_fault(&path, b"new-state", FaultPoint::DirectoryFlush)
        .expect_err("directory-flush fault must fail");

    assert!(error.to_string().contains("directory flush"));
    assert_old_or_new(&path, b"old-state", b"new-state")?;
    Ok(())
}

#[test]
fn temporary_creation_failure_preserves_existing_destination() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    let error = write_with_fault(&path, b"new-state", FaultPoint::CreateTemporary)
        .expect_err("temporary-create fault must fail");

    assert!(error.to_string().contains("temporary creation"));
    assert_eq!(fs::read(&path)?, b"old-state");
    Ok(())
}

#[test]
fn temporary_write_failure_preserves_existing_destination() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    let error = write_with_fault(&path, b"new-state", FaultPoint::WriteTemporary)
        .expect_err("temporary-write fault must fail");

    assert!(error.to_string().contains("temporary write"));
    assert_eq!(fs::read(&path)?, b"old-state");
    Ok(())
}

#[test]
fn temporary_flush_failure_preserves_existing_destination() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;

    let error = write_with_fault(&path, b"new-state", FaultPoint::FlushTemporary)
        .expect_err("temporary-flush fault must fail");

    assert!(error.to_string().contains("temporary flush"));
    assert_eq!(fs::read(&path)?, b"old-state");
    Ok(())
}

#[test]
fn stale_recovery_removes_only_dead_owned_temporary_files() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    let mut dead_owner = Command::new("cmd.exe")
        .args(["/C", "exit", "0"])
        .spawn()
        .expect("short-lived dead-owner process must start");
    let dead_owner_pid = dead_owner.id();
    let dead_owner_status = dead_owner.wait()?;
    assert!(
        dead_owner_status.success(),
        "short-lived dead-owner process failed: {dead_owner_status}"
    );
    let dead = create_owned_temporary_for_test(&path, dead_owner_pid, 7)?;
    let live = create_owned_temporary_for_test(&path, std::process::id(), 8)?;

    let removed = recover_stale_temporary_files(directory.path(), std::process::id(), 0)?;

    assert_eq!(removed, 1);
    assert!(!dead.exists());
    assert!(live.exists());
    Ok(())
}

#[test]
fn barrier_write_leaves_complete_old_or_new_content() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;
    let marker = directory.path().join("marker.txt");
    let child = marker_child(&path, &marker, "before-replace");
    let result = wait_for_marker(&marker, "before-replace");
    if result.is_ok() {
        terminate(child)?;
    } else {
        let _ = terminate(child);
    }
    result?;
    assert_eq!(fs::read(&path)?, b"old-state");
    let removed = recover_stale_temporary_files(directory.path(), std::process::id(), 0)?;
    assert_eq!(removed, 1);
    Ok(())
}

#[test]
fn after_replace_barrier_can_be_terminated_with_complete_content() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.toml");
    fs::write(&path, b"old-state")?;
    let marker = directory.path().join("marker.txt");
    let child = marker_child(&path, &marker, "after-replace");
    let result = wait_for_marker(&marker, "after-replace-complete");
    if result.is_ok() {
        terminate(child)?;
    } else {
        let _ = terminate(child);
    }
    result?;
    assert_old_or_new(&path, b"old-state", b"new-state")?;
    let removed = recover_stale_temporary_files(directory.path(), std::process::id(), 0)?;
    assert_eq!(removed, 0);
    assert_eq!(fs::read(&path)?, b"new-state");
    Ok(())
}

fn marker_child(path: &Path, marker: &Path, point: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_spotter-atomic-helper"))
        .args([
            path.to_string_lossy().as_ref(),
            marker.to_string_lossy().as_ref(),
            point,
        ])
        .spawn()
        .expect("atomic helper process must start")
}

fn wait_for_marker(marker: &Path, expected: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fs::read_to_string(marker)
            .map(|value| value.trim() == expected)
            .unwrap_or(false)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for atomic marker {expected}")
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn terminate(mut child: Child) -> Result<()> {
    child.kill()?;
    let _ = child.wait()?;
    Ok(())
}
