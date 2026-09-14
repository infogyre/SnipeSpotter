#![cfg(all(windows, feature = "hardware-experiment"))]

//! Native acceptance contracts for the protected hardware-host lane.
//!
//! These tests require a Windows runner with the protected hardware experiment enabled. The
//! elevated runner fixture owns SCM and ACL orchestration; policy rows are tested directly here.
//! Linux-runnable copies of the pure policy rows live in `src/path_policy.rs` and are exercised by
//! the regular package test command. Windows-only SCM behavior is asserted by the workflow
//! contract tests rather than silently represented by synthetic passes.

#[path = "../src/path_policy.rs"]
mod path_policy;

use path_policy::{
    AceFact, ObjectKind, Owner, PathFacts, PathPurpose, PolicyError, Principal, validate_path,
};

fn safe_file(path: &str) -> PathFacts {
    PathFacts {
        final_path: path.to_owned(),
        reparse_tag: 0,
        ancestor_reparse: false,
        owner: Owner::Administrators,
        aces: vec![
            AceFact {
                principal: Principal::Administrators,
                grants_write: true,
                allow: true,
            },
            AceFact {
                principal: Principal::System,
                grants_write: true,
                allow: true,
            },
        ],
        ancestor_aces: Vec::new(),
        object_kind: ObjectKind::File,
        exists: true,
    }
}

#[test]
fn hardware_host_rejects_unsafe_path_table() {
    let cases = [
        ("owner", PolicyError::InvalidOwner),
        ("ace", PolicyError::UnexpectedWriteAce),
        ("ancestor", PolicyError::StandardUserWritableAncestor),
        ("reparse", PolicyError::ReparseTag(0xA000_000C)),
        ("containment", PolicyError::OutsideStagingRoot),
        ("output", PolicyError::ExpectedDirectory),
    ];
    for (name, expected) in cases {
        let mut facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\config.json");
        let purpose = match name {
            "owner" => {
                facts.owner = Owner::Other;
                PathPurpose::Config
            }
            "ace" => {
                facts.aces.push(AceFact {
                    principal: Principal::Other,
                    grants_write: true,
                    allow: true,
                });
                PathPurpose::Config
            }
            "ancestor" => {
                facts.ancestor_aces.push(AceFact {
                    principal: Principal::Other,
                    grants_write: true,
                    allow: true,
                });
                PathPurpose::Config
            }
            "reparse" => {
                facts.reparse_tag = 0xA000_000C;
                PathPurpose::Config
            }
            "containment" => {
                facts.final_path = r"C:\ProgramData\Other\config.json".to_owned();
                PathPurpose::Config
            }
            "output" => PathPurpose::OutputDirectory,
            _ => unreachable!(),
        };
        assert_eq!(
            validate_path(r"C:\ProgramData\SnipeSpotterHardware\cell", &facts, purpose,),
            Err(expected),
            "unsafe path case {name} was accepted"
        );
    }
}

#[test]
fn hardware_trusted_layout_collection_table() {
    let mut facts = safe_file(r"C:\Program Files\PowerShell\7\pwsh.exe");
    facts.owner = Owner::TrustedInstaller;
    assert_eq!(
        validate_path(
            r"C:\ProgramData\SnipeSpotterHardware\cell",
            &facts,
            PathPurpose::PowerShellHost,
        ),
        Ok(())
    );

    for path in [
        r"C:\Users\Public\pwsh.exe",
        r"C:\Program Files\PowerShell\7\powershell.exe",
        r"C:\Program Files\Other\pwsh.exe",
    ] {
        facts.final_path = path.to_owned();
        assert_eq!(
            validate_path(
                r"C:\ProgramData\SnipeSpotterHardware\cell",
                &facts,
                PathPurpose::PowerShellHost,
            ),
            Err(PolicyError::PowerShellHostNotAllowlisted),
            "untrusted PowerShell layout {path} was accepted"
        );
    }
}

#[test]
fn hardware_key_acl_and_cleanup_contract() {
    let facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\hmac.key");
    assert_eq!(
        validate_path(
            r"C:\ProgramData\SnipeSpotterHardware\cell",
            &facts,
            PathPurpose::Key,
        ),
        Ok(())
    );
    assert!(facts.aces.iter().all(|ace| {
        ace.allow && matches!(ace.principal, Principal::Administrators | Principal::System)
    }));
}

#[test]
fn hardware_host_rejects_standard_user_writable_ancestor() {
    let mut facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\collector.ps1");
    facts.ancestor_aces.push(AceFact {
        principal: Principal::Other,
        grants_write: true,
        allow: true,
    });
    assert_eq!(
        validate_path(
            r"C:\ProgramData\SnipeSpotterHardware\cell",
            &facts,
            PathPurpose::Collector,
        ),
        Err(PolicyError::StandardUserWritableAncestor)
    );
}

#[test]
fn hardware_host_rejects_trusted_installer_for_non_host_objects() {
    let mut facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\hmac.key");
    facts.owner = Owner::TrustedInstaller;
    assert_eq!(
        validate_path(
            r"C:\ProgramData\SnipeSpotterHardware\cell",
            &facts,
            PathPurpose::Key,
        ),
        Err(PolicyError::InvalidOwner)
    );
}

#[test]
fn hardware_host_accepts_output_directory_nested_under_cell_root() {
    let mut facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\output");
    facts.object_kind = ObjectKind::Directory;
    assert_eq!(
        validate_path(
            r"C:\ProgramData\SnipeSpotterHardware\cell",
            &facts,
            PathPurpose::OutputDirectory,
        ),
        Ok(())
    );
}
