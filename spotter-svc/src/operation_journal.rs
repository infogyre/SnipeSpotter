// pattern: Imperative Shell

//! Durable prepared/confirmed operation journal.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::Path,
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum JournalRecord {
    Prepared {
        operation_id: String,
        operation: serde_json::Value,
    },
    Confirmed {
        operation_id: String,
    },
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

#[must_use]
pub fn pending(records: &[JournalRecord]) -> Vec<(String, serde_json::Value)> {
    let mut values = BTreeMap::new();
    for record in records {
        match record {
            JournalRecord::Prepared {
                operation_id,
                operation,
            } => {
                values.insert(operation_id.clone(), operation.clone());
            }
            JournalRecord::Confirmed { operation_id } => {
                values.remove(operation_id);
            }
        }
    }
    values.into_iter().collect()
}

/// Atomically compact the journal to pending prepared operations.
///
/// # Errors
/// Returns an error when replacement fails.
pub fn compact(path: &Path, records: &[JournalRecord]) -> Result<()> {
    let mut bytes = Vec::new();
    for (operation_id, operation) in pending(records) {
        serde_json::to_writer(
            &mut bytes,
            &JournalRecord::Prepared {
                operation_id,
                operation,
            },
        )
        .context("failed to encode compacted journal record")?;
        bytes.push(b'\n');
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
        append(
            &path,
            &JournalRecord::Confirmed {
                operation_id: String::from("b"),
            },
        )?;
        let records = load(&path)?;
        assert_eq!(pending(&records).len(), 1);
        compact(&path, &records)?;
        assert_eq!(load(&path)?.len(), 1);
        Ok(())
    }
}
