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
use tokio::sync::{mpsc, oneshot, watch};

use crate::scheduler::ScheduleInput;
use crate::status::{PublicStatusSnapshot, ScheduleSnapshot, project_status};

pub struct FsmRequest {
    pub command: ServiceCommand,
    response: oneshot::Sender<IpcResponse>,
    sync_generation: Option<u64>,
}

#[derive(Clone)]
pub struct FsmHandle {
    sender: mpsc::Sender<FsmRequest>,
    sync_pending: Arc<AtomicBool>,
    next_sync_generation: Arc<std::sync::atomic::AtomicU64>,
    pending_generation: Arc<std::sync::atomic::AtomicU64>,
    completed_sync_generation: watch::Sender<u64>,
    status_receiver: Option<watch::Receiver<PublicStatusSnapshot>>,
    schedule_receiver: Option<watch::Receiver<ScheduleSnapshot>>,
    schedule_sender: Option<watch::Sender<ScheduleSnapshot>>,
    attached_status_sender: Arc<std::sync::Mutex<Option<watch::Sender<PublicStatusSnapshot>>>>,
    #[cfg_attr(not(any(windows, feature = "test-support")), expect(dead_code))]
    attached_schedule_sender: Arc<std::sync::Mutex<Option<watch::Sender<ScheduleInput>>>>,
}

/// Result of accepting or coalescing a synchronization request.
#[derive(Debug)]
pub(crate) struct SyncEnqueue {
    pub(crate) response: oneshot::Receiver<IpcResponse>,
    pub(crate) target_generation: u64,
    #[allow(dead_code, reason = "read on Windows native lane and by tests")]
    pub(crate) coalesced: bool,
}

impl FsmHandle {
    /// Enqueue one command and await the committed response.
    ///
    /// # Errors
    /// Returns an error when the service loop has stopped or the response is cancelled.
    pub async fn request(&self, command: ServiceCommand) -> Result<IpcResponse> {
        if matches!(
            command,
            ServiceCommand::GetStatus | ServiceCommand::GetStatusFull
        ) {
            return self
                .request_status(command == ServiceCommand::GetStatusFull)
                .await;
        }
        self.enqueue(command)
            .await?
            .await
            .map_err(|_| anyhow::anyhow!("service command response was cancelled"))
    }

    async fn request_status(&self, full: bool) -> Result<IpcResponse> {
        // Prefer an attached publication channel (service startup), falling
        // back to the handle's snapshot receiver, then to the serialized
        // queue for plain spawns without a publisher.
        let attached = self
            .attached_status_sender
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(watch::Sender::subscribe));
        let status_receiver = match (self.status_receiver.as_ref(), attached) {
            (_, Some(receiver)) => receiver,
            (Some(receiver), _) => receiver.clone(),
            (None, None) => {
                return self
                    .enqueue(if full {
                        ServiceCommand::GetStatusFull
                    } else {
                        ServiceCommand::GetStatus
                    })
                    .await?
                    .await
                    .map_err(|_| anyhow::anyhow!("service command response was cancelled"));
            }
        };
        let status = status_receiver.borrow().clone();
        let schedule = match self.schedule_receiver.as_ref() {
            Some(receiver) => receiver.borrow().clone(),
            None => ScheduleSnapshot {
                config_generation: status.config_generation,
                next_sync: None,
            },
        };
        Ok(project_status(&status, &schedule, full))
    }

    #[cfg_attr(not(windows), expect(dead_code))]
    async fn enqueue_serialized(
        &self,
        command: ServiceCommand,
    ) -> Result<oneshot::Receiver<IpcResponse>> {
        self.enqueue(command).await
    }

    /// Enqueue one command and return its response receiver before waiting for completion.
    ///
    /// This is crate-visible so the test-support owner harness can exercise a disconnected
    /// response consumer while retaining the production enqueue and ordering path.
    ///
    /// # Errors
    /// Returns an error when the service loop has stopped.
    pub(crate) async fn enqueue(
        &self,
        command: ServiceCommand,
    ) -> Result<oneshot::Receiver<IpcResponse>> {
        Ok(self.enqueue_with_generation(command).await?.response)
    }

    pub(crate) async fn enqueue_sync(&self) -> Result<SyncEnqueue> {
        self.enqueue_with_generation(ServiceCommand::TriggerSync)
            .await
    }

    async fn enqueue_with_generation(&self, command: ServiceCommand) -> Result<SyncEnqueue> {
        let is_sync = command == ServiceCommand::TriggerSync;
        let target_generation = if is_sync {
            // Allocate a unique generation for every sync request BEFORE the
            // pending claim: fetch_add is atomic, so each caller owns its
            // generation without any window where a coalesced caller could
            // observe a stale value.
            let allocated = self.next_sync_generation.fetch_add(1, Ordering::AcqRel) + 1;
            if self
                .sync_pending
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // Pending claim already held: coalesce onto the accepted
                // sync's generation, which the accepted caller stored before
                // the pending flag became observable to us.
                let (response, receiver) = oneshot::channel();
                let _ = response.send(IpcResponse::Ok {
                    message: String::from("sync already queued"),
                });
                return Ok(SyncEnqueue {
                    response: receiver,
                    target_generation: self.pending_target_generation(),
                    coalesced: true,
                });
            }
            // First store of the claim: the accepted generation is published
            // before any coalesced caller can observe sync_pending=true.
            self.pending_generation.store(allocated, Ordering::Release);
            allocated
        } else {
            0
        };
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(FsmRequest {
                command,
                response,
                sync_generation: is_sync.then_some(target_generation),
            })
            .await
            .is_err()
        {
            if is_sync {
                self.sync_pending.store(false, Ordering::Release);
            }
            return Err(anyhow::anyhow!("service command loop is unavailable"));
        }
        Ok(SyncEnqueue {
            response: receiver,
            target_generation,
            coalesced: false,
        })
    }

    pub(crate) fn completed_sync_generation(&self) -> watch::Receiver<u64> {
        self.completed_sync_generation.subscribe()
    }

    /// The generation of the currently pending sync: stored by the accepted
    /// caller immediately after claiming pending, before any coalesced
    /// caller can observe the claim. Coalesced callers read this so their
    /// target always matches the in-flight sync.
    fn pending_target_generation(&self) -> u64 {
        self.pending_generation.load(Ordering::Acquire)
    }

    /// Registers a status publication channel owned by the service startup.
    #[cfg_attr(not(any(windows, feature = "test-support")), expect(dead_code))]
    pub(crate) fn attach_status_publication(&self, sender: watch::Sender<PublicStatusSnapshot>) {
        self.attached_status_sender
            .lock()
            .map(|mut guard| *guard = Some(sender))
            .map_err(|_| anyhow::anyhow!("status publication lock poisoned"))
            .ok();
    }

    /// Registers a scheduler-input channel owned by the service startup.
    #[cfg_attr(not(any(windows, feature = "test-support")), expect(dead_code))]
    pub(crate) fn attach_schedule_input(&self, sender: watch::Sender<ScheduleInput>) {
        self.attached_schedule_sender
            .lock()
            .map(|mut guard| *guard = Some(sender))
            .map_err(|_| anyhow::anyhow!("schedule input lock poisoned"))
            .ok();
    }

    /// Publishes a scheduler-owned schedule projection for status readers.
    pub(crate) fn publish_schedule_snapshot(&self, schedule: ScheduleSnapshot) {
        if let Some(schedule_sender) = self.schedule_sender.as_ref() {
            schedule_sender.send_replace(schedule);
        }
    }

    pub(crate) async fn wait_for_sync_generation(
        &self,
        target_generation: u64,
        mut completed: watch::Receiver<u64>,
    ) -> Result<()> {
        loop {
            if *completed.borrow() >= target_generation {
                return Ok(());
            }
            completed
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("sync completion channel is unavailable"))?;
        }
    }
}

/// Spawn a bounded command loop whose handler completes persistence before returning.
///
/// # Errors
/// Returns an error when the requested channel capacity is zero.
pub fn spawn<H, Fut>(capacity: usize, handler: H) -> Result<FsmHandle>
where
    H: FnMut(ServiceCommand) -> Fut + Send + 'static,
    Fut: Future<Output = IpcResponse> + Send + 'static,
{
    spawn_with_status(capacity, handler, None, None)
}

pub(crate) fn spawn_with_status<H, Fut>(
    capacity: usize,
    mut handler: H,
    status_receiver: Option<watch::Receiver<PublicStatusSnapshot>>,
    schedule_receiver: Option<watch::Receiver<ScheduleSnapshot>>,
) -> Result<FsmHandle>
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
    let (completed_sync_generation, _) = watch::channel(0_u64);
    let loop_completed_sync_generation = completed_sync_generation.clone();
    let (schedule_sender, schedule_receiver_for_handle) = watch::channel(ScheduleSnapshot {
        config_generation: 0,
        next_sync: None,
    });
    tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            let is_sync = request.command == ServiceCommand::TriggerSync;
            let response = handler(request.command).await;
            if is_sync {
                loop_sync_pending.store(false, Ordering::Release);
                if let Some(generation) = request.sync_generation {
                    loop_completed_sync_generation.send_replace(generation);
                }
            }
            let _ = request.response.send(response);
        }
    });
    Ok(FsmHandle {
        sender,
        sync_pending,
        next_sync_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        pending_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        completed_sync_generation,
        status_receiver,
        schedule_receiver: schedule_receiver.or(Some(schedule_receiver_for_handle)),
        schedule_sender: Some(schedule_sender),
        attached_status_sender: Arc::new(std::sync::Mutex::new(None)),
        attached_schedule_sender: Arc::new(std::sync::Mutex::new(None)),
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
    async fn scheduler_completion_before_wait_is_not_lost() -> Result<()> {
        let handle = spawn(2, |_| async {
            IpcResponse::Ok {
                message: String::from("committed"),
            }
        })?;
        let first = handle.enqueue_sync().await?;
        let target = first.target_generation;
        let completed = handle.completed_sync_generation();
        let _ = first.response.await?;
        handle.wait_for_sync_generation(target, completed).await?;
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

    #[tokio::test]
    async fn reports_unavailable_loop_when_sender_is_closed() -> Result<()> {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let (completed_sync_generation, _) = watch::channel(0_u64);
        let handle = FsmHandle {
            sender,
            sync_pending: Arc::new(AtomicBool::new(false)),
            next_sync_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pending_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            completed_sync_generation,
            status_receiver: None,
            schedule_receiver: None,
            schedule_sender: None,
            attached_status_sender: Arc::new(std::sync::Mutex::new(None)),
            attached_schedule_sender: Arc::new(std::sync::Mutex::new(None)),
        };

        let error = handle
            .request(ServiceCommand::GetStatus)
            .await
            .expect_err("closed loop");
        assert!(error.to_string().contains("unavailable"));
        Ok(())
    }
}
