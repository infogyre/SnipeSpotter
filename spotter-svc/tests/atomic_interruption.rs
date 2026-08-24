#![cfg(all(windows, feature = "test-support"))]

use std::fs;

use anyhow::Result;
use spotter_svc::atomic_file::test_support::{FaultPoint, write_with_fault};

fn assert_old_or_new(path: &std::path::Path, old: &[u8], new: &[u8]) -> Result<()> {
    let contents = fs::read(path)?;
    assert!(contents == old || contents == new);
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
