// pattern: Imperative Shell

//! File-based service logging initialization and retention cleanup.

use std::{fs, path::Path};

use anyhow::{Context as _, Result, bail};
use spotter_core::config::LoggingSettings;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

pub(crate) const SERVICE_LOG_PREFIX: &str = "spotter-svc.log";

/// Initialize daily rolling service logs and remove files beyond the configured retention count.
///
/// The returned guard must remain alive for the process lifetime so buffered records are flushed.
/// `max_size_mb` is reserved for a future size-aware writer; daily rotation is the currently
/// enforced boundary and `max_files` controls startup retention.
///
/// # Errors
///
/// Returns an error when the directory cannot be created, retention cleanup fails, the configured
/// level is invalid, or a global tracing subscriber has already been installed.
pub fn initialize(log_dir: &Path, settings: &LoggingSettings) -> Result<WorkerGuard> {
    fs::create_dir_all(log_dir)
        .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;
    prune_logs(log_dir, settings.max_files)?;
    let filter = EnvFilter::try_new(&settings.level)
        .with_context(|| format!("invalid logging level {}", settings.level))?;
    let appender = tracing_appender::rolling::daily(log_dir, SERVICE_LOG_PREFIX);
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer),
        )
        .try_init()
        .context("failed to initialize service logging")?;
    Ok(guard)
}

fn prune_logs(log_dir: &Path, max_files: u32) -> Result<()> {
    if max_files == 0 {
        bail!("logging.max_files must be nonzero")
    }
    let mut logs = fs::read_dir(log_dir)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(SERVICE_LOG_PREFIX)
        })
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect::<Vec<_>>();
    logs.sort_by_key(|(modified, path)| (*modified, path.clone()));
    let keep = usize::try_from(max_files)?;
    let remove = logs.len().saturating_sub(keep);
    for (_, path) in logs.into_iter().take(remove) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove old log {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_removes_oldest_matching_logs_only() -> Result<()> {
        let directory = tempfile::tempdir()?;
        for name in [
            "spotter-svc.log.1",
            "spotter-svc.log.2",
            "spotter-svc.log.3",
        ] {
            fs::write(directory.path().join(name), name)?;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        fs::write(directory.path().join("other.log"), "keep")?;
        prune_logs(directory.path(), 2)?;
        let matching = fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("spotter-svc.log")
            })
            .count();
        assert_eq!(matching, 2);
        assert!(directory.path().join("other.log").exists());
        Ok(())
    }

    #[test]
    fn zero_retention_is_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        assert!(prune_logs(directory.path(), 0).is_err());
        Ok(())
    }
}
