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
    use std::{
        future::Future,
        io,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tracing::instrument::WithSubscriber as _;

    #[derive(Clone)]
    struct BoundedWriter {
        state: Arc<CaptureState>,
    }

    struct CaptureState {
        bytes: Mutex<Vec<u8>>,
        capacity: usize,
        overflowed: AtomicBool,
    }

    impl io::Write for BoundedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let mut bytes = self
                .state
                .bytes
                .lock()
                .map_err(|_| io::Error::other("capture lock poisoned"))?;
            if bytes.len().saturating_add(buffer.len()) > self.state.capacity {
                self.state.overflowed.store(true, Ordering::Release);
                return Err(io::Error::other("capture capacity exceeded"));
            }
            bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for BoundedWriter {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    struct TestCapture {
        state: Arc<CaptureState>,
        dispatcher: tracing::Dispatch,
    }

    impl TestCapture {
        fn new(capacity: usize) -> Self {
            let state = Arc::new(CaptureState {
                bytes: Mutex::new(Vec::new()),
                capacity,
                overflowed: AtomicBool::new(false),
            });
            let subscriber = tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_target(false)
                    .with_writer(BoundedWriter {
                        state: Arc::clone(&state),
                    }),
            );
            Self {
                state,
                dispatcher: tracing::Dispatch::new(subscriber),
            }
        }

        async fn run<T>(&self, future: impl Future<Output = T>) -> T {
            future.with_subscriber(self.dispatcher.clone()).await
        }

        fn finish(&self) -> Result<String> {
            if self.state.overflowed.load(Ordering::Acquire) {
                anyhow::bail!("trace capture overflowed")
            }
            let bytes = self
                .state
                .bytes
                .lock()
                .map_err(|_| anyhow::anyhow!("capture lock poisoned"))?
                .clone();
            String::from_utf8(bytes).context("trace capture was not UTF-8")
        }
    }

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

    #[tokio::test]
    async fn tracing_capture_isolated_and_bounded() -> Result<()> {
        let first = TestCapture::new(256);
        let second = TestCapture::new(256);
        let ((), ()) = tokio::join!(
            first.run(async { tracing::info!(marker = "first-only", "captured event") }),
            second.run(async { tracing::info!(marker = "second-only", "captured event") }),
        );
        let first_text = first.finish()?;
        let second_text = second.finish()?;
        assert!(first_text.contains("first-only"));
        assert!(!first_text.contains("second-only"));
        assert!(second_text.contains("second-only"));
        assert!(!second_text.contains("first-only"));

        let overflow = TestCapture::new(8);
        overflow
            .run(async { tracing::info!(marker = "too-large", "captured event") })
            .await;
        assert!(overflow.finish().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn upstream_errors_do_not_escape_to_ipc_state_logs() -> Result<()> {
        use secrecy::SecretString;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let sentinel = "UPSTREAM_SENTINEL_SECRET";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string(sentinel))
            .mount(&server)
            .await;
        let client = crate::snipeit_client::SnipeItClient::new_loopback_http_for_test(
            format!("http://127.0.0.1:{}/api", server.address().port()),
            SecretString::from(String::from("token")),
        )?;
        let capture = TestCapture::new(4096);
        let error = capture
            .run(async {
                let error = client.get_asset(7).await.expect_err("server must fail");
                tracing::warn!(%error, "remote request failed");
                error
            })
            .await;
        let display = error.to_string();
        let ipc = serde_json::to_string(&spotter_core::ipc::IpcResponse::Error {
            message: display.clone(),
        })?;
        let state = serde_json::to_string(&spotter_core::state::ServiceState {
            last_sync_result: Some(spotter_core::state::SyncResult::Failed {
                error: display.clone(),
            }),
            ..Default::default()
        })?;
        let logs = capture.finish()?;
        for output in [&display, &ipc, &state, &logs] {
            assert!(!output.contains(sentinel));
            assert!(output.len() < 4096);
        }
        assert!(display.contains("500"));
        assert!(logs.contains("remote request failed"));
        Ok(())
    }

    #[tokio::test]
    async fn network_errors_do_not_escape_to_ipc_state_logs() -> Result<()> {
        use secrecy::SecretString;
        use tokio::net::TcpListener;

        let sentinel = "NETWORK_SENTINEL_SECRET";
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        let client = crate::snipeit_client::SnipeItClient::new_loopback_http_for_test(
            format!("http://{address}/"),
            SecretString::from(String::from("token")),
        )?;
        let capture = TestCapture::new(4096);
        let error = capture
            .run(async {
                let error = client
                    .get_asset(7)
                    .await
                    .expect_err("closed endpoint must fail");
                tracing::warn!(%error, "remote request failed");
                error
            })
            .await;
        let display = error.to_string();
        let ipc = serde_json::to_string(&spotter_core::ipc::IpcResponse::Error {
            message: display.clone(),
        })?;
        let state = serde_json::to_string(&spotter_core::state::ServiceState {
            last_sync_result: Some(spotter_core::state::SyncResult::Failed {
                error: display.clone(),
            }),
            ..Default::default()
        })?;
        let logs = capture.finish()?;
        for output in [&display, &ipc, &state, &logs] {
            assert!(!output.contains(sentinel));
            assert!(output.len() < 4096);
        }
        assert!(display.starts_with("Snipe-IT network error: network "));
        assert!(logs.contains("remote request failed"));
        Ok(())
    }

    #[test]
    fn zero_retention_is_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        assert!(prune_logs(directory.path(), 0).is_err());
        Ok(())
    }
}
