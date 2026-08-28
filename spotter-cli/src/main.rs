// pattern: Imperative Shell

//! `SnipeSpotter` CLI executable entry point.

use std::process::ExitCode;

use clap::Parser as _;
use spotter_cli::{
    Cli, ConsoleConfirmationReader, ConsoleTokenReader, NamedPipeTransport,
    ProcessElevationChecker, WindowsServiceRegistrar, dispatch, exit_code,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut transport = spotter_cli::transport_endpoint(&cli)
        .map_or_else(NamedPipeTransport::default, |endpoint| {
            NamedPipeTransport::with_endpoint(std::time::Duration::from_secs(30), endpoint)
        });
    let mut tokens = ConsoleTokenReader;
    let registration = match spotter_cli::registration_options(&cli) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error:#}");
            return ExitCode::from(1);
        }
    };
    let mut registrar = WindowsServiceRegistrar::new(registration);
    let elevation = ProcessElevationChecker;
    let mut confirmation = ConsoleConfirmationReader;

    match dispatch(
        &cli,
        &mut transport,
        &mut tokens,
        &mut registrar,
        &elevation,
        &mut confirmation,
    ) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(u8::try_from(exit_code(&error)).unwrap_or(1))
        }
    }
}
