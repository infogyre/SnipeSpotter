// pattern: Imperative Shell

//! `SnipeSpotter` service executable entry point.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match spotter_svc::service::run_dispatcher() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("error: spotter-svc is supported only on Windows");
    std::process::ExitCode::FAILURE
}
