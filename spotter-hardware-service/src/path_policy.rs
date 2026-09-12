// pattern: Functional Core

//! Platform-neutral decisions for protected hardware-host paths.

use std::fmt;

/// Principals that may own protected hardware-host objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owner {
    Administrators,
    System,
    TrustedInstaller,
    Other,
}

/// Principals that may receive write access on a protected object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Principal {
    Administrators,
    System,
    Other,
}

/// A normalized ACE fact gathered by the platform-specific security shell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AceFact {
    pub(crate) principal: Principal,
    pub(crate) grants_write: bool,
    pub(crate) allow: bool,
}

/// The kind of object being validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PathPurpose {
    StagingRoot,
    Config,
    Collector,
    ServiceExecutable,
    Key,
    OutputDirectory,
    OutputObject,
    PowerShellHost,
}

/// The observed object kind for a protected path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectKind {
    File,
    Directory,
}

/// Security and identity facts for one path and its parent chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PathFacts {
    pub(crate) final_path: String,
    pub(crate) reparse_tag: u32,
    pub(crate) ancestor_reparse: bool,
    pub(crate) owner: Owner,
    pub(crate) aces: Vec<AceFact>,
    pub(crate) standard_user_writable_ancestor: bool,
    pub(crate) object_kind: ObjectKind,
    pub(crate) exists: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyError {
    Missing,
    ReparseTag(u32),
    AncestorReparse,
    OutsideStagingRoot,
    InvalidOwner,
    UnexpectedWriteAce,
    StandardUserWritableAncestor,
    ExpectedDirectory,
    ExpectedFile,
    PowerShellHostNotAllowlisted,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("path does not exist"),
            Self::ReparseTag(tag) => write!(formatter, "path contains reparse tag {tag:#x}"),
            Self::AncestorReparse => formatter.write_str("path has a reparse-point ancestor"),
            Self::OutsideStagingRoot => {
                formatter.write_str("path is outside the protected staging root")
            }
            Self::InvalidOwner => formatter.write_str("path owner is not allowlisted"),
            Self::UnexpectedWriteAce => {
                formatter.write_str("path grants write access to an unallowlisted principal")
            }
            Self::StandardUserWritableAncestor => {
                formatter.write_str("path has a standard-user-writable ancestor")
            }
            Self::ExpectedDirectory => formatter.write_str("path is not a directory"),
            Self::ExpectedFile => formatter.write_str("path is not a file"),
            Self::PowerShellHostNotAllowlisted => {
                formatter.write_str("PowerShell host is not in an allowlisted system layout")
            }
        }
    }
}

/// Convert a Windows path into safe, case-insensitive components.
///
/// The function intentionally rejects `.` and `..` instead of resolving them. Resolving would
/// make a caller-provided path appear contained before the handle-backed final path is checked.
fn path_components(path: &str) -> Option<Vec<String>> {
    let mut path = path.replace('/', "\\");
    if let Some(stripped) = path.strip_prefix(r"\\?\") {
        path = stripped.to_owned();
    } else if let Some(stripped) = path.strip_prefix(r"\\.\") {
        path = stripped.to_owned();
    }
    if path.is_empty() {
        return None;
    }

    let mut components = Vec::new();
    let mut remainder = path.as_str();
    if remainder.len() >= 2 && remainder.as_bytes()[1] == b':' {
        components.push(remainder[..2].to_ascii_lowercase());
        remainder = &remainder[2..];
    }

    for component in remainder.split('\\') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            return None;
        }
        components.push(component.to_ascii_lowercase());
    }
    (!components.is_empty()).then_some(components)
}

/// Return whether `candidate` is the root or a descendant of `root`.
#[must_use]
pub(crate) fn is_contained_path(root: &str, candidate: &str) -> bool {
    let Some(root) = path_components(root) else {
        return false;
    };
    let Some(candidate) = path_components(candidate) else {
        return false;
    };
    candidate.len() >= root.len() && candidate[..root.len()] == root[..]
}

/// Return whether a PowerShell executable path belongs to an approved OS layout.
#[must_use]
pub(crate) fn is_allowlisted_powershell_layout(path: &str) -> bool {
    let Some(components) = path_components(path) else {
        return false;
    };
    if components.len() < 4 {
        return false;
    }
    let program_files = components[1] == "program files";
    let powershell_directory = matches!(components[2].as_str(), "powershell" | "powershell-core");
    program_files
        && powershell_directory
        && components.last().is_some_and(|name| name == "pwsh.exe")
}

/// Evaluate facts collected from no-follow Windows handles.
///
/// This function deliberately treats unknown write grants as unsafe, and it requires every
/// ordinary host object to remain under the protected root. The PowerShell host is the only
/// external object permitted by the reviewed system-layout allowlist.
pub(crate) fn validate_path(
    root: &str,
    facts: &PathFacts,
    purpose: PathPurpose,
) -> Result<(), PolicyError> {
    if !facts.exists {
        return Err(PolicyError::Missing);
    }
    if facts.reparse_tag != 0 {
        return Err(PolicyError::ReparseTag(facts.reparse_tag));
    }
    if facts.ancestor_reparse {
        return Err(PolicyError::AncestorReparse);
    }
    if facts.standard_user_writable_ancestor {
        return Err(PolicyError::StandardUserWritableAncestor);
    }

    if purpose == PathPurpose::PowerShellHost {
        if !is_allowlisted_powershell_layout(&facts.final_path) {
            return Err(PolicyError::PowerShellHostNotAllowlisted);
        }
    } else if !is_contained_path(root, &facts.final_path) {
        return Err(PolicyError::OutsideStagingRoot);
    }

    let owner_allowed = match purpose {
        PathPurpose::PowerShellHost => matches!(
            facts.owner,
            Owner::Administrators | Owner::System | Owner::TrustedInstaller
        ),
        _ => matches!(facts.owner, Owner::Administrators | Owner::System),
    };
    if !owner_allowed {
        return Err(PolicyError::InvalidOwner);
    }

    if facts.aces.iter().any(|ace| {
        ace.allow
            && ace.grants_write
            && !matches!(ace.principal, Principal::Administrators | Principal::System)
    }) {
        return Err(PolicyError::UnexpectedWriteAce);
    }

    match purpose {
        PathPurpose::StagingRoot | PathPurpose::OutputDirectory => {
            if facts.object_kind != ObjectKind::Directory {
                return Err(PolicyError::ExpectedDirectory);
            }
        }
        PathPurpose::Config
        | PathPurpose::Collector
        | PathPurpose::ServiceExecutable
        | PathPurpose::Key
        | PathPurpose::OutputObject
        | PathPurpose::PowerShellHost => {
            if facts.object_kind != ObjectKind::File {
                return Err(PolicyError::ExpectedFile);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn containment_is_component_bounded_and_case_insensitive() {
        assert!(is_contained_path(
            r"C:\ProgramData\Cell",
            r"c:/programdata/cell/config.json"
        ));
        assert!(is_contained_path(
            r"C:\ProgramData\Cell",
            r"\\?\C:\ProgramData\Cell\config.json"
        ));
        assert!(!is_contained_path(
            r"C:\ProgramData\Cell",
            r"C:\ProgramData\Cell-Evil\config.json"
        ));
        assert!(!is_contained_path(
            r"C:\ProgramData\Cell",
            r"C:\ProgramData\Other\config.json"
        ));
    }

    #[test]
    fn unsafe_path_table_reports_each_policy_boundary() {
        let cases = [
            (
                "owner",
                safe_file(r"C:\ProgramData\Cell\config.json"),
                PolicyError::InvalidOwner,
            ),
            (
                "ace",
                safe_file(r"C:\ProgramData\Cell\config.json"),
                PolicyError::UnexpectedWriteAce,
            ),
            (
                "ancestor",
                safe_file(r"C:\ProgramData\Cell\config.json"),
                PolicyError::StandardUserWritableAncestor,
            ),
            (
                "ancestor-reparse",
                safe_file(r"C:\ProgramData\Cell\config.json"),
                PolicyError::AncestorReparse,
            ),
            (
                "reparse",
                safe_file(r"C:\ProgramData\Cell\config.json"),
                PolicyError::ReparseTag(0xA000_000C),
            ),
            (
                "containment",
                safe_file(r"C:\ProgramData\Other\config.json"),
                PolicyError::OutsideStagingRoot,
            ),
            (
                "output",
                safe_file(r"C:\ProgramData\Cell\output.json"),
                PolicyError::ExpectedDirectory,
            ),
        ];
        for (name, mut facts, expected) in cases {
            match name {
                "owner" => facts.owner = Owner::Other,
                "ace" => facts.aces.push(AceFact {
                    principal: Principal::Other,
                    grants_write: true,
                    allow: true,
                }),
                "ancestor" => facts.standard_user_writable_ancestor = true,
                "ancestor-reparse" => facts.ancestor_reparse = true,
                "reparse" => facts.reparse_tag = 0xA000_000C,
                "containment" | "output" => {}
                _ => unreachable!(),
            }
            let purpose = if name == "output" {
                PathPurpose::OutputDirectory
            } else {
                PathPurpose::Config
            };
            assert_eq!(
                validate_path(r"C:\ProgramData\Cell", &facts, purpose),
                Err(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn trusted_installer_is_only_allowed_for_allowlisted_powershell_layout() {
        let mut facts = safe_file(r"C:\Program Files\PowerShell\7\pwsh.exe");
        facts.owner = Owner::TrustedInstaller;
        assert!(validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::PowerShellHost).is_ok());
        facts.final_path = r"C:\Users\Public\pwsh.exe".to_owned();
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::PowerShellHost),
            Err(PolicyError::PowerShellHostNotAllowlisted)
        );
        facts.final_path = r"C:\Program Files\PowerShell\..\pwsh.exe".to_owned();
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::PowerShellHost),
            Err(PolicyError::PowerShellHostNotAllowlisted)
        );
        facts.final_path = r"C:\Program Files\PowerShell\7\powershell.exe".to_owned();
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::PowerShellHost),
            Err(PolicyError::PowerShellHostNotAllowlisted)
        );
    }

    #[test]
    fn policy_table_rejects_missing_and_wrong_object_types() {
        let mut facts = safe_file(r"C:\ProgramData\Cell\config.json");
        facts.exists = false;
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::Config),
            Err(PolicyError::Missing)
        );
        facts.exists = true;
        facts.object_kind = ObjectKind::Directory;
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::Config),
            Err(PolicyError::ExpectedFile)
        );
        facts.object_kind = ObjectKind::File;
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::OutputDirectory),
            Err(PolicyError::ExpectedDirectory)
        );
    }

    #[test]
    fn policy_accepts_system_owner_for_every_protected_file_purpose() {
        let mut facts = safe_file(r"C:\ProgramData\Cell\object");
        facts.owner = Owner::System;
        for purpose in [
            PathPurpose::Config,
            PathPurpose::Collector,
            PathPurpose::ServiceExecutable,
            PathPurpose::Key,
            PathPurpose::OutputObject,
        ] {
            assert_eq!(
                validate_path(r"C:\ProgramData\Cell", &facts, purpose),
                Ok(())
            );
        }
    }

    #[test]
    fn policy_accepts_protected_directories_for_root_and_output() {
        let mut facts = safe_file(r"C:\ProgramData\Cell");
        facts.object_kind = ObjectKind::Directory;
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::StagingRoot),
            Ok(())
        );
        facts.final_path.push_str(r"\output");
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::OutputDirectory),
            Ok(())
        );
    }

    #[test]
    fn policy_accepts_non_write_and_explicit_deny_aces_but_rejects_unknown_allows() {
        let mut facts = safe_file(r"C:\ProgramData\Cell\config.json");
        facts.aces.push(AceFact {
            principal: Principal::Other,
            grants_write: false,
            allow: true,
        });
        facts.aces.push(AceFact {
            principal: Principal::Other,
            grants_write: true,
            allow: false,
        });
        assert!(validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::Config).is_ok());
        facts.aces.push(AceFact {
            principal: Principal::Other,
            grants_write: true,
            allow: true,
        });
        assert_eq!(
            validate_path(r"C:\ProgramData\Cell", &facts, PathPurpose::Config),
            Err(PolicyError::UnexpectedWriteAce)
        );
    }

    #[test]
    fn containment_rejects_empty_root_and_dot_or_parent_escape() {
        assert!(!is_contained_path("", r"C:\config.json"));
        assert!(!is_contained_path(
            r"C:\ProgramData\Cell",
            r"C:\ProgramData\Cell\..\Other\config.json"
        ));
        assert!(!is_contained_path(
            r"C:\ProgramData\Cell",
            r"C:\ProgramData\Cell.\config.json"
        ));
    }
}
