// pattern: Imperative Shell

//! Durable prepared/outcome/state-commit operation journal.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

/// Why a journal cannot be admitted as clean durable evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryReason {
    IncompleteUnterminatedSuffix,
    MalformedFinalRecord,
    MalformedMiddleRecord,
    InvalidPhaseSequence,
    BlockedMarkerPresent,
    UnreadableJournal,
}

impl std::fmt::Display for RecoveryReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::IncompleteUnterminatedSuffix => "incomplete unterminated journal suffix",
            Self::MalformedFinalRecord => "malformed final journal record",
            Self::MalformedMiddleRecord => "malformed middle journal record",
            Self::InvalidPhaseSequence => "invalid journal phase sequence",
            Self::BlockedMarkerPresent => "journal recovery is already blocked",
            Self::UnreadableJournal => "journal could not be read",
        };
        formatter.write_str(value)
    }
}

/// The durable result of classifying the journal bytes.
#[derive(Debug)]
pub enum RecoveryOutcome {
    Clean { records: Vec<JournalRecord> },
    NeedsOperatorRecovery(OperatorRecovery),
    PreservationFailed(PreservationFailure),
    Corrupt { reason: RecoveryReason },
}

/// Redacted, non-replayable summary of evidence requiring operator action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorRecovery {
    reason: RecoveryReason,
    evidence_paths: Vec<std::path::PathBuf>,
    validated_record_count: usize,
}

impl OperatorRecovery {
    #[must_use]
    pub fn reason(&self) -> &RecoveryReason {
        &self.reason
    }

    #[must_use]
    pub fn evidence_paths(&self) -> &[std::path::PathBuf] {
        &self.evidence_paths
    }

    #[must_use]
    pub fn validated_record_count(&self) -> usize {
        self.validated_record_count
    }
}

/// Which durable preservation operation failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreservationFailure {
    QuarantineWrite,
    MarkerWrite,
    Replacement,
}

impl std::fmt::Display for PreservationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::QuarantineWrite => "quarantine write failed",
            Self::MarkerWrite => "recovery marker write failed",
            Self::Replacement => "journal replacement failed",
        })
    }
}

/// One durable phase in an operation's state transition.
///
/// New records always follow `Prepared` -> `RemoteOutcomeObserved` ->
/// `StateCommitted`. `Confirmed` is retained only as a read-compatible alias for
/// journals written by older service versions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum JournalRecord {
    Prepared {
        operation_id: String,
        operation: serde_json::Value,
    },
    RemoteOutcomeObserved {
        operation_id: String,
        outcome: serde_json::Value,
        #[serde(default)]
        candidate_state: Option<serde_json::Value>,
    },
    StateCommitted {
        operation_id: String,
    },
    #[serde(rename = "confirmed")] // compatibility with pre-seam journals
    Confirmed {
        operation_id: String,
    },
}

/// Reconstructed operation evidence that has not reached durable state commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOperation {
    pub operation_id: String,
    pub operation: serde_json::Value,
    pub remote_outcome: Option<serde_json::Value>,
    pub candidate_state: Option<serde_json::Value>,
}

#[derive(Debug)]
struct ClassifiedBytes {
    outcome: RecoveryOutcome,
    normalize_terminal_newline: bool,
}

fn classify_bytes_internal(bytes: &[u8]) -> ClassifiedBytes {
    if bytes.is_empty() {
        return ClassifiedBytes {
            outcome: RecoveryOutcome::Clean {
                records: Vec::new(),
            },
            normalize_terminal_newline: false,
        };
    }

    let terminal_newline = bytes.ends_with(b"\n");
    let lines = bytes.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    let record_lines = if terminal_newline {
        &lines[..lines.len().saturating_sub(1)]
    } else {
        lines.as_slice()
    };
    let mut records = Vec::with_capacity(record_lines.len());
    for (index, line) in record_lines.iter().enumerate() {
        match serde_json::from_slice::<JournalRecord>(line) {
            Ok(record) => records.push(record),
            Err(error)
                if !terminal_newline && index + 1 == record_lines.len() && error.is_eof() =>
            {
                return ClassifiedBytes {
                    outcome: RecoveryOutcome::NeedsOperatorRecovery(OperatorRecovery {
                        reason: RecoveryReason::IncompleteUnterminatedSuffix,
                        evidence_paths: Vec::new(),
                        validated_record_count: records.len(),
                    }),
                    normalize_terminal_newline: false,
                };
            }
            Err(_) if index + 1 == record_lines.len() => {
                return ClassifiedBytes {
                    outcome: RecoveryOutcome::Corrupt {
                        reason: RecoveryReason::MalformedFinalRecord,
                    },
                    normalize_terminal_newline: false,
                };
            }
            Err(_) => {
                return ClassifiedBytes {
                    outcome: RecoveryOutcome::Corrupt {
                        reason: RecoveryReason::MalformedMiddleRecord,
                    },
                    normalize_terminal_newline: false,
                };
            }
        }
    }

    if pending_with_evidence(&records).is_err() {
        return ClassifiedBytes {
            outcome: RecoveryOutcome::Corrupt {
                reason: RecoveryReason::InvalidPhaseSequence,
            },
            normalize_terminal_newline: false,
        };
    }
    ClassifiedBytes {
        outcome: RecoveryOutcome::Clean { records },
        normalize_terminal_newline: !terminal_newline,
    }
}

/// Classify journal bytes without reading or mutating the filesystem.
#[must_use]
pub fn classify_bytes(bytes: &[u8]) -> RecoveryOutcome {
    classify_bytes_internal(bytes).outcome
}

const MARKER_SUFFIX: &str = ".recovery-blocked";
const QUARANTINE_PREFIX: &str = ".quarantine-";

type QuarantineWriter = dyn Fn(&Path, &[u8]) -> Result<PathBuf>;
type MarkerWriter = dyn Fn(&Path, &RecoveryReason, &[PathBuf]) -> Result<()>;
type JournalReplacer = dyn Fn(&Path, &[u8]) -> Result<()>;

/// Return the sticky blocked-marker path associated with an active journal.
#[must_use]
pub fn blocked_marker_path(journal_path: &Path) -> PathBuf {
    let mut name = journal_path.file_name().unwrap_or_default().to_os_string();
    name.push(MARKER_SUFFIX);
    journal_path.with_file_name(name)
}

/// Format bounded, redacted startup diagnostics for a journal recovery outcome.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(
        dead_code,
        reason = "the production caller is Windows-only; Linux tests exercise the formatter directly"
    )
)]
#[must_use]
pub(crate) fn recovery_notice(journal_path: &Path, outcome: &RecoveryOutcome) -> String {
    let journal_name = journal_path.file_name().map_or_else(
        || String::from("operations.jsonl"),
        |name| name.to_string_lossy().into_owned(),
    );
    match outcome {
        RecoveryOutcome::NeedsOperatorRecovery(recovery) => {
            let evidence_paths = recovery
                .evidence_paths()
                .iter()
                .map(|path| {
                    path.file_name().map_or_else(
                        || String::from("unknown"),
                        |name| name.to_string_lossy().into_owned(),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "journal={journal_name}; reason={}; evidence_paths={evidence_paths}; validated_record_count={}",
                recovery.reason(),
                recovery.validated_record_count()
            )
        }
        RecoveryOutcome::PreservationFailed(failure) => format!(
            "journal={journal_name}; preservation_failure={failure}; evidence_paths=unavailable; validated_record_count=0"
        ),
        RecoveryOutcome::Corrupt { reason } => format!(
            "journal={journal_name}; reason={reason}; evidence_paths=unavailable; validated_record_count=0"
        ),
        RecoveryOutcome::Clean { .. } => String::from("clean"),
    }
}

/// Classify and, when safe, durably repair a journal before any replay.
///
/// A blocked marker is checked first and remains authoritative across restarts. The only active-path
/// repair performed here is adding a terminal newline to a fully parsed, phase-valid final record;
/// ambiguous or malformed bytes are retained in a quarantine artifact and never become replayable.
///
/// # Errors
/// Returns an error only when the journal cannot be read. Durable preservation failures are returned
/// as [`RecoveryOutcome::PreservationFailed`] so callers cannot accidentally continue startup.
pub fn recover_journal(journal_path: &Path) -> Result<RecoveryOutcome> {
    let marker_path = blocked_marker_path(journal_path);
    if recovery_marker_present(journal_path)? {
        return Ok(RecoveryOutcome::NeedsOperatorRecovery(OperatorRecovery {
            reason: RecoveryReason::BlockedMarkerPresent,
            evidence_paths: vec![marker_path],
            validated_record_count: 0,
        }));
    }
    let bytes = match fs::read(journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RecoveryOutcome::Clean {
                records: Vec::new(),
            });
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read operation journal {}",
                    journal_path.display()
                )
            });
        }
    };
    Ok(recover_journal_with(
        journal_path,
        &bytes,
        &marker_path,
        &write_quarantine,
        &write_blocked_marker,
        &crate::atomic_file::write,
    ))
}

fn recover_journal_with(
    journal_path: &Path,
    bytes: &[u8],
    marker_path: &Path,
    write_quarantine_fn: &QuarantineWriter,
    write_marker_fn: &MarkerWriter,
    replace_fn: &JournalReplacer,
) -> RecoveryOutcome {
    let ClassifiedBytes {
        outcome,
        normalize_terminal_newline,
    } = classify_bytes_internal(bytes);
    let RecoveryOutcome::Clean { records } = outcome else {
        return preserve_non_clean(
            journal_path,
            bytes,
            outcome,
            marker_path,
            write_quarantine_fn,
            write_marker_fn,
        );
    };
    if !normalize_terminal_newline {
        return RecoveryOutcome::Clean { records };
    }

    let Ok(quarantine) = write_quarantine_fn(journal_path, bytes) else {
        return RecoveryOutcome::PreservationFailed(PreservationFailure::QuarantineWrite);
    };
    let mut normalized = bytes.to_vec();
    normalized.push(b'\n');
    if replace_fn(journal_path, &normalized).is_err() {
        return RecoveryOutcome::PreservationFailed(PreservationFailure::Replacement);
    }
    if let RecoveryOutcome::Clean { records } = classify_bytes_internal(&normalized).outcome {
        RecoveryOutcome::Clean { records }
    } else {
        let _ = quarantine;
        RecoveryOutcome::PreservationFailed(PreservationFailure::Replacement)
    }
}

fn preserve_non_clean(
    journal_path: &Path,
    bytes: &[u8],
    outcome: RecoveryOutcome,
    marker_path: &Path,
    write_quarantine_fn: &QuarantineWriter,
    write_marker_fn: &MarkerWriter,
) -> RecoveryOutcome {
    let (reason, validated_record_count) = match outcome {
        RecoveryOutcome::NeedsOperatorRecovery(recovery) => {
            (recovery.reason.clone(), recovery.validated_record_count)
        }
        RecoveryOutcome::Corrupt { reason } => (reason, 0),
        RecoveryOutcome::PreservationFailed(failure) => {
            return RecoveryOutcome::PreservationFailed(failure);
        }
        RecoveryOutcome::Clean { .. } => {
            unreachable!("clean outcome is handled before preservation")
        }
    };
    let Ok(quarantine) = write_quarantine_fn(journal_path, bytes) else {
        return RecoveryOutcome::PreservationFailed(PreservationFailure::QuarantineWrite);
    };
    if reason == RecoveryReason::IncompleteUnterminatedSuffix
        && write_marker_fn(marker_path, &reason, std::slice::from_ref(&quarantine)).is_err()
    {
        return RecoveryOutcome::PreservationFailed(PreservationFailure::MarkerWrite);
    }
    if reason == RecoveryReason::IncompleteUnterminatedSuffix {
        RecoveryOutcome::NeedsOperatorRecovery(OperatorRecovery {
            reason,
            evidence_paths: vec![quarantine, marker_path.to_path_buf()],
            validated_record_count,
        })
    } else {
        RecoveryOutcome::Corrupt { reason }
    }
}

fn write_quarantine(journal_path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let parent = journal_path.parent().unwrap_or_else(|| Path::new("."));
    ensure_safe_parent(parent)?;
    journal_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("operation journal has no file name"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let digest = sha256_hex(bytes);
    let digest = &digest[..16];
    for nonce in 0_u64..64 {
        let path = quarantine_path(journal_path, timestamp, digest, nonce);

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                flush_parent(parent)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("failed to allocate a unique journal quarantine path")
}

fn quarantine_path(journal_path: &Path, timestamp: u128, digest: &str, nonce: u64) -> PathBuf {
    let parent = journal_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = journal_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let suffix = if nonce == 0 {
        format!("{QUARANTINE_PREFIX}{timestamp}-{digest}")
    } else {
        format!("{QUARANTINE_PREFIX}{timestamp}-{digest}-{nonce:016x}")
    };
    parent.join(format!("{file_name}{suffix}"))
}

fn write_blocked_marker(path: &Path, reason: &RecoveryReason, evidence: &[PathBuf]) -> Result<()> {
    ensure_safe_parent(path.parent().unwrap_or_else(|| Path::new(".")))?;
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut body = format!("reason={reason}\ntimestamp={timestamp}\nevidence_paths=\n");
    for evidence_path in evidence {
        body.push_str(&evidence_path.to_string_lossy());
        body.push('\n');
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(body.as_bytes())?;
            file.sync_all()?;
            flush_parent(path.parent().unwrap_or_else(|| Path::new(".")))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn recovery_marker_present(journal_path: &Path) -> Result<bool> {
    let marker_path = blocked_marker_path(journal_path);
    match fs::symlink_metadata(&marker_path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect recovery marker {}",
                marker_path.display()
            )
        }),
    }
}

fn ensure_safe_parent(parent: &Path) -> Result<()> {
    if fs::symlink_metadata(parent)?.file_type().is_symlink() {
        anyhow::bail!("journal parent directory is a reparse point")
    }
    Ok(())
}

fn flush_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .with_context(|| format!("failed to open journal parent {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to flush journal parent {}", parent.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[expect(
    clippy::unreadable_literal,
    reason = "standardized SHA-256 round constants are conventionally represented as hex words"
)]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes(chunk[offset..offset + 4].try_into().unwrap_or([0; 4]));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut working = state;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(majority);
            let next = [
                temp1.wrapping_add(temp2),
                working[0],
                working[1],
                working[2],
                working[3].wrapping_add(temp1),
                working[4],
                working[5],
                working[6],
            ];
            working = next;
        }
        for (target, value) in state.iter_mut().zip(working) {
            *target = target.wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

/// Return whether a settings candidate changes the remote operation identity.
#[must_use]
pub fn remote_identity_changed(
    current: &spotter_core::Settings,
    candidate: &spotter_core::Settings,
) -> bool {
    current.snipeit.url != candidate.snipeit.url
        || current.snipeit.checkout_status_id != candidate.snipeit.checkout_status_id
        || current.snipeit.checkin_status_id != candidate.snipeit.checkin_status_id
}

/// Reject a remote identity change while valid pending evidence exists.
///
/// # Errors
/// Returns a fixed fail-closed error for malformed/invalid journal phases or pending evidence.
pub fn guard_remote_identity_change(
    path: &Path,
    current: &spotter_core::Settings,
    candidate: &spotter_core::Settings,
) -> Result<()> {
    if !remote_identity_changed(current, candidate) {
        return Ok(());
    }
    let records = match recover_journal(path).map_err(|_| {
        anyhow::anyhow!("cannot change remote identity while operation journal is invalid")
    })? {
        RecoveryOutcome::Clean { records } => records,
        RecoveryOutcome::NeedsOperatorRecovery(_)
        | RecoveryOutcome::PreservationFailed(_)
        | RecoveryOutcome::Corrupt { .. } => {
            anyhow::bail!(
                "cannot change remote identity while operation journal recovery is blocked"
            )
        }
    };
    let pending = pending_with_evidence(&records).map_err(|_| {
        anyhow::anyhow!("cannot change remote identity while operation journal is invalid")
    })?;
    if !pending.is_empty() {
        anyhow::bail!("cannot change remote identity while operations are pending")
    }
    Ok(())
}

/// Append and flush one journal record.
///
/// # Errors
/// Returns an error when encoding or durable append fails.
pub fn append(path: &Path, record: &JournalRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if recovery_marker_present(path)? {
        anyhow::bail!("operation journal recovery is blocked")
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    serde_json::to_writer(&mut file, record).context("failed to encode journal record")?;
    file.write_all(b"\n")?;
    file.sync_all().context("failed to flush operation journal")
}

/// Load every complete journal record.
///
/// # Errors
/// Returns an error for unreadable or malformed records.
pub fn load(path: &Path) -> Result<Vec<JournalRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    BufReader::new(fs::File::open(path)?)
        .lines()
        .map(|line| {
            let line = line?;
            serde_json::from_str(&line).context("invalid operation journal record")
        })
        .collect()
}

/// Reconstruct pending operations and preserve remote outcome/recovery evidence.
///
/// # Errors
/// Returns an error when a record appears before its preparation, repeats an observed outcome, or
/// commits without an observed outcome.
pub fn pending_with_evidence(records: &[JournalRecord]) -> Result<Vec<PendingOperation>> {
    let mut pending = Vec::new();
    let mut indexes = HashMap::new();
    let mut terminal_ids = std::collections::HashSet::new();
    for record in records {
        match record {
            JournalRecord::Prepared {
                operation_id,
                operation,
            } => {
                if terminal_ids.contains(operation_id) {
                    anyhow::bail!("prepared operation follows terminal commit: {operation_id}");
                }
                if indexes.contains_key(operation_id) {
                    anyhow::bail!("duplicate prepared operation: {operation_id}");
                }
                let index = pending.len();
                indexes.insert(operation_id.clone(), index);
                pending.push(PendingOperation {
                    operation_id: operation_id.clone(),
                    operation: operation.clone(),
                    remote_outcome: None,
                    candidate_state: None,
                });
            }
            JournalRecord::RemoteOutcomeObserved {
                operation_id,
                outcome,
                candidate_state,
            } => {
                let Some(index) = indexes.get(operation_id).copied() else {
                    anyhow::bail!(
                        "remote outcome observed before prepared operation: {operation_id}"
                    );
                };
                if pending[index].remote_outcome.is_some() {
                    anyhow::bail!("duplicate remote outcome observed: {operation_id}");
                }
                pending[index].remote_outcome = Some(outcome.clone());
                pending[index].candidate_state.clone_from(candidate_state);
            }
            JournalRecord::StateCommitted { operation_id }
            | JournalRecord::Confirmed { operation_id } => {
                let Some(index) = indexes.get(operation_id).copied() else {
                    anyhow::bail!("state committed before prepared operation: {operation_id}");
                };
                if pending[index].remote_outcome.is_none() {
                    anyhow::bail!("state committed before remote outcome: {operation_id}");
                }
                indexes.remove(operation_id);
                terminal_ids.insert(operation_id.clone());
                pending.remove(index);
                for other_index in indexes.values_mut() {
                    if *other_index > index {
                        *other_index -= 1;
                    }
                }
            }
        }
    }
    Ok(pending)
}

/// Atomically compact the journal to uncommitted operation evidence.
///
/// Compaction is safe before state commit only because it retains every pending
/// prepared record and any observed remote outcome/candidate state. Callers must
/// still invoke it only after the associated state commit in the normal path.
///
/// # Errors
/// Returns an error when replacement fails.
pub fn compact(path: &Path, records: &[JournalRecord]) -> Result<()> {
    if recovery_marker_present(path)? {
        anyhow::bail!("operation journal recovery is blocked")
    }
    let mut bytes = Vec::new();
    for pending in pending_with_evidence(records)? {
        serde_json::to_writer(
            &mut bytes,
            &JournalRecord::Prepared {
                operation_id: pending.operation_id.clone(),
                operation: pending.operation,
            },
        )
        .context("failed to encode compacted journal record")?;
        bytes.push(b'\n');
        if let Some(outcome) = pending.remote_outcome {
            serde_json::to_writer(
                &mut bytes,
                &JournalRecord::RemoteOutcomeObserved {
                    operation_id: pending.operation_id,
                    outcome,
                    candidate_state: pending.candidate_state,
                },
            )
            .context("failed to encode compacted remote outcome")?;
            bytes.push(b'\n');
        }
    }
    crate::atomic_file::write(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_journal_blocks_identity_changes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let mut current = spotter_core::Settings::default();
        current.snipeit.url = String::from("https://old.example");
        current.snipeit.checkout_status_id = 5;
        current.snipeit.checkin_status_id = 6;
        let mut token_only = current.clone();
        token_only.snipeit.api_token_encrypted = vec![9];
        assert!(!remote_identity_changed(&current, &token_only));

        append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("x"),
                operation: serde_json::json!({}),
            },
        )?;
        for candidate in [
            {
                let mut value = current.clone();
                value.snipeit.url = String::from("https://new.example");
                value
            },
            {
                let mut value = current.clone();
                value.snipeit.checkout_status_id = 7;
                value
            },
            {
                let mut value = current.clone();
                value.snipeit.checkin_status_id = 8;
                value
            },
        ] {
            assert!(remote_identity_changed(&current, &candidate));
            assert!(guard_remote_identity_change(&path, &current, &candidate).is_err());
        }
        guard_remote_identity_change(&path, &current, &token_only)?;

        fs::write(&path, b"")?;
        let mut changed = current.clone();
        changed.snipeit.url = String::from("https://new.example");
        guard_remote_identity_change(&path, &current, &changed)?;

        append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("x"),
                operation: serde_json::json!({}),
            },
        )?;
        append(
            &path,
            &JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("x"),
                outcome: serde_json::json!({}),
                candidate_state: None,
            },
        )?;
        append(
            &path,
            &JournalRecord::StateCommitted {
                operation_id: String::from("x"),
            },
        )?;
        guard_remote_identity_change(&path, &current, &changed)?;

        fs::write(&path, b"malformed\n")?;
        assert!(guard_remote_identity_change(&path, &current, &changed).is_err());
        Ok(())
    }

    #[test]
    fn durable_replay_and_compaction() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("operations.jsonl");
        append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("b"),
                operation: serde_json::json!({"x":2}),
            },
        )?;
        append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("a"),
                operation: serde_json::json!({"x":1}),
            },
        )?;
        for (operation_id, next) in [("b", 2), ("a", 1)] {
            append(
                &path,
                &JournalRecord::RemoteOutcomeObserved {
                    operation_id: String::from(operation_id),
                    outcome: serde_json::json!({"status":"applied"}),
                    candidate_state: Some(serde_json::json!({"next":next})),
                },
            )?;
        }
        let records = load(&path)?;
        assert_eq!(pending_with_evidence(&records)?.len(), 2);
        compact(&path, &records)?;
        let compacted = load(&path)?;
        assert_eq!(compacted.len(), 4);
        assert!(matches!(
            compacted.last(),
            Some(JournalRecord::RemoteOutcomeObserved {
                operation_id,
                candidate_state: Some(candidate_state),
                ..
            }) if operation_id == "a" && candidate_state == &serde_json::json!({"next":1})
        ));
        for operation_id in ["a", "b"] {
            append(
                &path,
                &JournalRecord::StateCommitted {
                    operation_id: String::from(operation_id),
                },
            )?;
        }
        let records = load(&path)?;
        compact(&path, &records)?;
        assert_eq!(load(&path)?.len(), 0);
        Ok(())
    }

    #[test]
    fn observed_outcome_remains_recoverable_until_state_commit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("operations.jsonl");
        append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({"serial":"MON"}),
            },
        )?;
        append(
            &path,
            &JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("operation"),
                outcome: serde_json::json!({"status":"unknown"}),
                candidate_state: Some(serde_json::json!({"monitor":"MON"})),
            },
        )?;
        let records = load(&path)?;
        let pending = pending_with_evidence(&records)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].operation_id, "operation");
        assert_eq!(
            pending[0].candidate_state,
            Some(serde_json::json!({"monitor":"MON"}))
        );
        Ok(())
    }

    #[test]
    fn pending_rejects_invalid_phase_sequences() {
        let records = vec![
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("operation"),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: None,
            },
            JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({}),
            },
        ];

        assert!(pending_with_evidence(&records).is_err());

        let records = vec![
            JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({}),
            },
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("operation"),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: None,
            },
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("operation"),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: None,
            },
        ];
        assert!(pending_with_evidence(&records).is_err());

        let records = vec![JournalRecord::StateCommitted {
            operation_id: String::from("operation"),
        }];
        assert!(pending_with_evidence(&records).is_err());
    }

    #[test]
    fn pending_rejects_duplicate_and_post_terminal_prepared_records() {
        let records = vec![
            JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({"attempt":1}),
            },
            JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({"attempt":1}),
            },
        ];
        assert!(pending_with_evidence(&records).is_err());

        let records = vec![
            JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({}),
            },
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("operation"),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: None,
            },
            JournalRecord::StateCommitted {
                operation_id: String::from("operation"),
            },
            JournalRecord::Prepared {
                operation_id: String::from("operation"),
                operation: serde_json::json!({}),
            },
        ];
        assert!(pending_with_evidence(&records).is_err());
    }

    #[test]
    fn pending_preserves_durable_prepared_order() -> Result<()> {
        let records = vec![
            JournalRecord::Prepared {
                operation_id: String::from("z-operation"),
                operation: serde_json::json!({"state":"z"}),
            },
            JournalRecord::Prepared {
                operation_id: String::from("a-operation"),
                operation: serde_json::json!({"state":"a"}),
            },
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("z-operation"),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: None,
            },
            JournalRecord::RemoteOutcomeObserved {
                operation_id: String::from("a-operation"),
                outcome: serde_json::json!({"status":"applied"}),
                candidate_state: None,
            },
        ];

        assert_eq!(
            pending_with_evidence(&records)?
                .into_iter()
                .map(|pending| pending.operation_id)
                .collect::<Vec<_>>(),
            vec![String::from("z-operation"), String::from("a-operation")]
        );
        Ok(())
    }

    #[test]
    fn malformed_and_partial_records_are_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("operations.jsonl");
        fs::write(&path, b"{\"phase\":\"prepared\"}\nnot-json\n")?;
        assert!(load(&path).is_err());

        fs::write(
            &path,
            b"{\"phase\":\"prepared\",\"operation_id\":\"a\",\"operation\":{}}\n",
        )?;
        assert_eq!(load(&path)?.len(), 1);
        Ok(())
    }

    #[test]
    fn journal_truncation_prefix_property() {
        let record = br#"{"phase":"prepared","operation_id":"a","operation":{}}
{"phase":"remote_outcome_observed","operation_id":"a","outcome":{"status":"applied"}}
{"phase":"state_committed","operation_id":"a"}
"#;
        for cut in 0..=record.len() {
            let bytes = &record[..cut];
            let outcome = classify_bytes(bytes);
            if let RecoveryOutcome::Clean { records } = outcome {
                let complete_lines = bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .count();
                assert!(records.len() <= complete_lines, "cut={cut}");
            }
        }
    }

    #[test]
    fn recovery_notice_survives_pre_subscriber_window() {
        let journal_path = Path::new("/var/lib/SnipeSpotter/operations.jsonl");
        let quarantine =
            journal_path.with_file_name("operations.jsonl.quarantine-1234-deadbeefdeadbeef");
        let marker = blocked_marker_path(journal_path);
        let outcome = RecoveryOutcome::NeedsOperatorRecovery(OperatorRecovery {
            reason: RecoveryReason::IncompleteUnterminatedSuffix,
            evidence_paths: vec![quarantine, marker],
            validated_record_count: 3,
        });

        let notice = recovery_notice(journal_path, &outcome);
        assert!(!notice.is_empty());
        assert!(notice.len() < 512);
        assert!(notice.contains("reason=incomplete unterminated journal suffix"));
        assert!(notice.contains(
            "evidence_paths=operations.jsonl.quarantine-1234-deadbeefdeadbeef,operations.jsonl.recovery-blocked"
        ));
        assert!(notice.contains("validated_record_count=3"));
        assert!(!notice.contains("var/lib"));
        assert!(!notice.contains('/'));
    }

    #[test]
    fn journal_recovery_classification_table() {
        let prepared = b"{\"phase\":\"prepared\",\"operation_id\":\"a\",\"operation\":{}}\n";
        assert!(
            matches!(classify_bytes(prepared), RecoveryOutcome::Clean { records } if records.len() == 1)
        );

        let incomplete = b"{\"phase\":\"prepared\",\"operation_id\":\"a\",\"operation\":{";
        let outcome = classify_bytes(incomplete);
        assert!(matches!(outcome, RecoveryOutcome::NeedsOperatorRecovery(_)));
        if let RecoveryOutcome::NeedsOperatorRecovery(recovery) = outcome {
            assert_eq!(recovery.validated_record_count(), 0);
            assert!(recovery.evidence_paths().is_empty());
        }

        let complete_without_newline = prepared.strip_suffix(b"\\n").unwrap_or(prepared);
        assert!(
            matches!(classify_bytes(complete_without_newline), RecoveryOutcome::Clean { records } if records.len() == 1)
        );
    }

    #[test]
    fn unterminated_complete_record_retains_evidence() {
        let bytes = b"{\"phase\":\"prepared\",\"operation_id\":\"a\",\"operation\":{}}";
        let outcome = classify_bytes(bytes);
        assert!(matches!(outcome, RecoveryOutcome::Clean { records } if records.len() == 1));
    }

    #[test]
    fn journal_preservation_failure_is_closed() {
        let incomplete = br#"{"phase":"prepared","operation_id":"a","operation":{} }
{"#;
        let complete = br#"{"phase":"prepared","operation_id":"a","operation":{}}"#;
        let marker_path = Path::new("operations.jsonl.recovery-blocked");
        let journal_path = Path::new("operations.jsonl");
        let failure_cases = [
            (
                "quarantine",
                incomplete.as_slice(),
                PreservationFailure::QuarantineWrite,
            ),
            (
                "marker",
                incomplete.as_slice(),
                PreservationFailure::MarkerWrite,
            ),
            (
                "replacement",
                complete.as_slice(),
                PreservationFailure::Replacement,
            ),
        ];
        for (stage, original, expected) in failure_cases {
            let quarantine = move |_path: &Path, _bytes: &[u8]| -> Result<PathBuf> {
                if stage == "quarantine" {
                    anyhow::bail!("injected quarantine failure")
                }
                Ok(PathBuf::from("operations.jsonl.quarantine-test"))
            };
            let marker = move |_path: &Path,
                               _reason: &RecoveryReason,
                               _evidence: &[PathBuf]|
                  -> Result<()> {
                if stage == "marker" {
                    anyhow::bail!("injected marker failure")
                }
                Ok(())
            };
            let replace = move |_path: &Path, _bytes: &[u8]| -> Result<()> {
                if stage == "replacement" {
                    anyhow::bail!("injected replacement failure")
                }
                Ok(())
            };
            let outcome = recover_journal_with(
                journal_path,
                original,
                marker_path,
                &quarantine,
                &marker,
                &replace,
            );
            assert!(
                matches!(outcome, RecoveryOutcome::PreservationFailed(failure) if failure == expected)
            );
        }
    }

    #[test]
    fn journal_recovery_crash_boundary_table() {
        let incomplete = br#"{"phase":"prepared","operation_id":"a","operation":{} }
{"#;
        let complete = br#"{"phase":"prepared","operation_id":"a","operation":{}}"#;
        let journal_path = Path::new("operations.jsonl");
        let marker_path = Path::new("operations.jsonl.recovery-blocked");
        let boundaries = [
            (
                "preserve",
                incomplete.as_slice(),
                true,
                false,
                false,
                PreservationFailure::QuarantineWrite,
            ),
            (
                "marker",
                incomplete.as_slice(),
                false,
                true,
                false,
                PreservationFailure::MarkerWrite,
            ),
            (
                "normalize",
                complete.as_slice(),
                false,
                false,
                true,
                PreservationFailure::Replacement,
            ),
        ];
        for (boundary, original, fail_quarantine, fail_marker, fail_replace, expected) in boundaries
        {
            let quarantine = move |_path: &Path, _bytes: &[u8]| -> Result<PathBuf> {
                if fail_quarantine {
                    anyhow::bail!("crash boundary: {boundary} preserve")
                }
                Ok(PathBuf::from("operations.jsonl.quarantine-test"))
            };
            let marker = move |_path: &Path,
                               _reason: &RecoveryReason,
                               _evidence: &[PathBuf]|
                  -> Result<()> {
                if fail_marker {
                    anyhow::bail!("crash boundary: {boundary} marker")
                }
                Ok(())
            };
            let replace = move |_path: &Path, _bytes: &[u8]| -> Result<()> {
                if fail_replace {
                    anyhow::bail!("crash boundary: {boundary} normalize")
                }
                Ok(())
            };
            let outcome = recover_journal_with(
                journal_path,
                original,
                marker_path,
                &quarantine,
                &marker,
                &replace,
            );
            assert!(
                matches!(outcome, RecoveryOutcome::PreservationFailed(failure) if failure == expected),
                "boundary={boundary}"
            );
        }
    }

    #[test]
    fn normalization_quarantines_exact_original_and_replaces_atomically() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let original = br#"{"phase":"prepared","operation_id":"secret-token","operation":{"token":"never-log"}}"#;
        fs::write(&path, original)?;

        let outcome = recover_journal(&path)?;
        assert!(matches!(outcome, RecoveryOutcome::Clean { records } if records.len() == 1));
        let mut expected = original.to_vec();
        expected.push(b'\n');
        assert_eq!(fs::read(&path)?, expected);
        let quarantine = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| candidate != &path)
            .ok_or_else(|| anyhow::anyhow!("quarantine artifact was not created"))?;
        assert!(
            quarantine
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("operations.jsonl.quarantine-"))
        );
        assert_eq!(fs::read(quarantine)?, original);
        Ok(())
    }

    #[test]
    fn incomplete_tail_creates_sticky_redacted_marker() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let original = br#"{"phase":"prepared","operation_id":"secret-token","operation":{"token":"never-log"}}
{"#;
        fs::write(&path, original)?;

        let first = recover_journal(&path)?;
        assert!(matches!(first, RecoveryOutcome::NeedsOperatorRecovery(_)));
        let marker = blocked_marker_path(&path);
        let marker_bytes = fs::read(&marker)?;
        let marker_text = String::from_utf8(marker_bytes)?;
        assert!(marker_text.contains("incomplete unterminated journal suffix"));
        assert!(!marker_text.contains("secret-token"));
        assert!(!marker_text.contains("never-log"));
        assert_eq!(fs::read(&path)?, original);

        let second = recover_journal(&path)?;
        assert!(
            matches!(second, RecoveryOutcome::NeedsOperatorRecovery(recovery) if recovery.reason() == &RecoveryReason::BlockedMarkerPresent)
        );
        Ok(())
    }

    #[test]
    fn blocked_marker_survives_restart_with_valid_looking_prefix() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let original = br#"{"phase":"prepared","operation_id":"checkout:1","operation":{"operation_id":"checkout:1"}}
{"#;
        fs::write(&path, original)?;

        let first = recover_journal(&path)?;
        assert!(matches!(first, RecoveryOutcome::NeedsOperatorRecovery(_)));
        let marker = blocked_marker_path(&path);
        assert!(marker.exists());

        // A restart cannot make the prefix admissible by rewriting the journal bytes.
        fs::write(&path, br#"{"phase":"prepared","operation_id":"checkout:1","operation":{"operation_id":"checkout:1"}}
"#)?;
        for _ in 0..3 {
            let outcome = recover_journal(&path)?;
            assert!(matches!(
                outcome,
                RecoveryOutcome::NeedsOperatorRecovery(recovery)
                    if recovery.reason() == &RecoveryReason::BlockedMarkerPresent
            ));
        }
        assert!(marker.exists());
        Ok(())
    }

    #[test]
    fn quarantine_name_contains_exactly_sixteen_digest_hex_digits() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        fs::write(
            &path,
            br#"{"phase":"prepared","operation_id":"a","operation":{}}"#,
        )?;

        recover_journal(&path)?;
        let quarantine = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| candidate != &path)
            .ok_or_else(|| anyhow::anyhow!("quarantine artifact was not created"))?;
        let name = quarantine
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("quarantine name is not UTF-8"))?;
        let digest = name
            .strip_prefix("operations.jsonl.quarantine-")
            .and_then(|suffix| suffix.split_once('-'))
            .map(|(_, digest)| digest)
            .ok_or_else(|| anyhow::anyhow!("quarantine name has no digest"))?;
        assert_eq!(digest.len(), 16);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn active_append_refuses_a_sticky_recovery_marker() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        fs::write(&path, b"")?;
        fs::write(blocked_marker_path(&path), b"operator recovery\n")?;

        let error = append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("must-not-write"),
                operation: serde_json::json!({}),
            },
        )
        .expect_err("a blocked journal must reject active appends");
        assert!(error.to_string().contains("recovery is blocked"));
        assert!(fs::read(&path)?.is_empty());
        Ok(())
    }

    #[test]
    fn compaction_refuses_a_sticky_recovery_marker() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        append(
            &path,
            &JournalRecord::Prepared {
                operation_id: String::from("must-not-compact"),
                operation: serde_json::json!({}),
            },
        )?;
        let before = fs::read(&path)?;
        fs::write(blocked_marker_path(&path), b"operator recovery\n")?;

        let records = load(&path)?;
        let error = compact(&path, &records).expect_err("a blocked journal must reject compaction");
        assert!(error.to_string().contains("recovery is blocked"));
        assert_eq!(fs::read(&path)?, before);
        Ok(())
    }

    #[test]
    fn malformed_journal_quarantines_original_without_leaking_summary_data() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let original = br#"{"phase":"prepared","operation_id":"sensitive-id","operation":{"token":"sensitive-body"}}
not-json
{"phase":"state_committed","operation_id":"sensitive-id"}
"#;
        fs::write(&path, original)?;

        let outcome = recover_journal(&path)?;
        assert!(matches!(
            outcome,
            RecoveryOutcome::Corrupt {
                reason: RecoveryReason::MalformedMiddleRecord
            }
        ));
        assert_eq!(fs::read(&path)?, original);
        let quarantine = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| candidate != &path)
            .ok_or_else(|| anyhow::anyhow!("quarantine artifact was not created"))?;
        assert_eq!(fs::read(quarantine)?, original);
        Ok(())
    }

    #[test]
    fn journal_quarantine_collision_preserves_original() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operations.jsonl");
        let original = b"evidence bytes";
        fs::write(&path, original)?;
        let digest = &sha256_hex(original)[..16];
        let first = quarantine_path(&path, 42, digest, 0);
        fs::write(&first, b"existing evidence")?;

        let second = write_quarantine_at(&path, original, 42, digest)?;
        assert_ne!(second, first);
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(fs::read(first)?, b"existing evidence");
        assert_eq!(fs::read(second)?, original);
        Ok(())
    }

    fn write_quarantine_at(
        journal_path: &Path,
        bytes: &[u8],
        timestamp: u128,
        digest: &str,
    ) -> Result<PathBuf> {
        let parent = journal_path.parent().unwrap_or_else(|| Path::new("."));
        ensure_safe_parent(parent)?;
        for nonce in 0_u64..64 {
            let path = quarantine_path(journal_path, timestamp, digest, nonce);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    flush_parent(parent)?;
                    return Ok(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("failed to allocate a unique journal quarantine path")
    }
}
