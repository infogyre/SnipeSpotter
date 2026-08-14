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
    let mut transport = NamedPipeTransport::default();
    let mut tokens = ConsoleTokenReader;
    let mut registrar = WindowsServiceRegistrar;
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
