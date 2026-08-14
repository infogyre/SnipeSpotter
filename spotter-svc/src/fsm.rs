// pattern: Imperative Shell

//! Bounded, single-owner asynchronous service command processor.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Result, bail};
use spotter_core::ipc::{IpcResponse, ServiceCommand};
use tokio::sync::{mpsc, oneshot};

pub struct FsmRequest {
    pub command: ServiceCommand,
    response: oneshot::Sender<IpcResponse>,
}

#[derive(Clone)]
pub struct FsmHandle {
    sender: mpsc::Sender<FsmRequest>,
    sync_pending: Arc<AtomicBool>,
}

impl FsmHandle {
    /// Enqueue one command and await the committed response.
    ///
    /// # Errors
    /// Returns an error when the service loop has stopped or the response is cancelled.
    pub async fn request(&self, command: ServiceCommand) -> Result<IpcResponse> {
        let is_sync = command == ServiceCommand::TriggerSync;
        if is_sync
            && self
                .sync_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Ok(IpcResponse::Ok {
                message: String::from("sync already queued"),
            });
        }
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(FsmRequest { command, response })
            .await
            .is_err()
        {
            if is_sync {
                self.sync_pending.store(false, Ordering::Release);
            }
            return Err(anyhow::anyhow!("service command loop is unavailable"));
        }
        receiver
            .await
            .map_err(|_| anyhow::anyhow!("service command response was cancelled"))
    }
}

/// Spawn a bounded command loop whose handler completes persistence before returning.
///
/// # Errors
/// Returns an error when the requested channel capacity is zero.
pub fn spawn<H, Fut>(capacity: usize, mut handler: H) -> Result<FsmHandle>
where
    H: FnMut(ServiceCommand) -> Fut + Send + 'static,
    Fut: Future<Output = IpcResponse> + Send + 'static,
{
    if capacity == 0 {
        bail!("FSM channel capacity must be nonzero")
    }
    let (sender, mut receiver) = mpsc::channel::<FsmRequest>(capacity);
    let sync_pending = Arc::new(AtomicBool::new(false));
    let loop_sync_pending = Arc::clone(&sync_pending);
    tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            let is_sync = request.command == ServiceCommand::TriggerSync;
            let response = handler(request.command).await;
            if is_sync {
                loop_sync_pending.store(false, Ordering::Release);
            }
            let _ = request.response.send(response);
        }
    });
    Ok(FsmHandle {
        sender,
        sync_pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn serializes_commands_and_responds_after_commit() -> Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&events);
        let handle = spawn(2, move |command| {
            let observed = Arc::clone(&observed);
            async move {
                let name = format!("{command:?}");
                if let Ok(mut values) = observed.lock() {
                    values.push(format!("start:{name}"));
                }
                tokio::task::yield_now().await;
                if let Ok(mut values) = observed.lock() {
                    values.push(format!("commit:{name}"));
                }
                IpcResponse::Ok { message: name }
            }
        })?;
        let first = handle.request(ServiceCommand::GetStatus);
        let second = handle.request(ServiceCommand::GetConfig);
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_ok() && second.is_ok());
        let values = events
            .lock()
            .map_err(|_| anyhow::anyhow!("events lock poisoned"))?;
        assert_eq!(values.len(), 4);
        assert!(values[1].starts_with("commit:"));
        assert!(values[2].starts_with("start:"));
        Ok(())
    }

    #[tokio::test]
    async fn coalesces_sync_until_committed_handler_finishes() -> Result<()> {
        let (started, mut started_receiver) = mpsc::channel(1);
        let (release, release_receiver) = oneshot::channel();
        let mut release_receiver = Some(release_receiver);
        let handle = spawn(2, move |command| {
            let started = started.clone();
            let release_receiver = release_receiver.take();
            async move {
                if release_receiver.is_some() {
                    let _ = started.send(command.clone()).await;
                }
                if let Some(receiver) = release_receiver {
                    let _ = receiver.await;
                }
                IpcResponse::Ok {
                    message: String::from("committed"),
                }
            }
        })?;
        let first_handle = handle.clone();
        let first =
            tokio::spawn(async move { first_handle.request(ServiceCommand::TriggerSync).await });
        assert_eq!(
            started_receiver.recv().await,
            Some(ServiceCommand::TriggerSync)
        );
        assert_eq!(
            handle.request(ServiceCommand::TriggerSync).await?,
            IpcResponse::Ok {
                message: String::from("sync already queued")
            }
        );
        release
            .send(())
            .map_err(|()| anyhow::anyhow!("failed to release sync handler"))?;
        assert_eq!(
            first.await??,
            IpcResponse::Ok {
                message: String::from("committed")
            }
        );
        assert_eq!(
            handle.request(ServiceCommand::TriggerSync).await?,
            IpcResponse::Ok {
                message: String::from("committed")
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(
            spawn(0, |_| async {
                IpcResponse::Ok {
                    message: String::new(),
                }
            })
            .is_err()
        );
    }
}
