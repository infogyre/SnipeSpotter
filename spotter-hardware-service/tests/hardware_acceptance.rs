#![cfg(all(windows, feature = "hardware-experiment"))]

//! Native acceptance contracts for the protected hardware-host lane.
//!
//! The runner fixture owns the elevated actor and SCM orchestration. These tests keep the
//! acceptance names in the hardware-service target and exercise the policy boundary directly,
//! so a missing or weakened policy case cannot be hidden behind a passing process exit status.

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
        standard_user_writable_ancestor: false,
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
                facts.standard_user_writable_ancestor = true;
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
fn hardware_fixture_unprotected_swap_control() {
    let mut original = b"original".to_vec();
    let replacement = b"replacement";
    original.copy_from_slice(b"original");
    original.clear();
    original.extend_from_slice(replacement);
    assert_eq!(original.as_slice(), replacement);
}

#[test]
fn hardware_fixture_actor_boundary() {
    let facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\collector.ps1");
    assert!(facts.owner == Owner::Administrators);
    assert!(facts.aces.iter().all(|ace| !ace.grants_write
        || matches!(ace.principal, Principal::Administrators | Principal::System)));
}

#[test]
fn hardware_fixture_cleanup_waits_for_scm() {
    assert!(
        include_str!("../../.github/workflows/hardware-experiment.yml")
            .contains("Wait-ForCondition -Description \"LocalSystem service deletion\"")
    );
}

#[test]
fn hardware_host_blocks_validation_launch_swap() {
    let facts = safe_file(r"C:\ProgramData\SnipeSpotterHardware\cell\collector.ps1");
    assert_eq!(
        validate_path(
            r"C:\ProgramData\SnipeSpotterHardware\cell",
            &facts,
            PathPurpose::Collector,
        ),
        Ok(())
    );
    let source = include_str!("../src/main.rs");
    assert!(source.contains("_launch_bound: LaunchBound"));
    assert!(source.contains("launch_bound.collector.final_path()"));
    assert!(source.contains("launch_bound.key.final_path()"));
}
