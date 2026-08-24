// pattern: Imperative Shell

//! Durable prepared/outcome/state-commit operation journal.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::Path,
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

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

/// Append and flush one journal record.
///
/// # Errors
/// Returns an error when encoding or durable append fails.
pub fn append(path: &Path, record: &JournalRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
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
}
