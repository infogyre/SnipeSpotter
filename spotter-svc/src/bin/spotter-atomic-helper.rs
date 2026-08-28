// pattern: Imperative Shell

#[cfg(windows)]
use std::{
    env,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

#[cfg(windows)]
use anyhow::{Context as _, bail};
#[cfg(windows)]
use spotter_svc::atomic_file::test_support::{BarrierPoint, write_with_barriers};

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let path = arguments
        .next()
        .map(PathBuf::from)
        .context("atomic helper requires a destination path")?;
    let marker = arguments
        .next()
        .map(PathBuf::from)
        .context("atomic helper requires a marker path")?;
    let point = match arguments.next().as_deref().and_then(|value| value.to_str()) {
        Some("before-replace") => BarrierPoint::BeforeReplace,
        Some("after-replace") => BarrierPoint::AfterReplace,
        Some(value) => bail!("unknown atomic helper barrier: {value}"),
        None => bail!("atomic helper requires a barrier point"),
    };
    if arguments.next().is_some() {
        bail!("atomic helper received unexpected arguments")
    }

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);
    let worker_path = path.clone();
    let worker = thread::spawn(move || {
        write_with_barriers(&worker_path, b"new-state", point, worker_barrier, marker)
    });
    barrier.wait();
    thread::sleep(Duration::from_secs(30));
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("atomic helper writer panicked"))??;
    Ok(())
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("error: atomic interruption helper is supported only on Windows");
    std::process::ExitCode::FAILURE
}
