//! The `ouro-fixture` binary. See the crate documentation for the contract.

use clap::Parser;

use ouro_fixture::cli::Cli;
use ouro_fixture::report::Reporter;
use ouro_fixture::{EXIT_EXPECTATION_FAILED, EXIT_OK, EXIT_USAGE, ops};

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let reporter = if cli.no_report {
        Reporter::silent()
    } else {
        Reporter::to_fd(cli.report_fd)
    };

    match ops::run(cli.mode, &reporter) {
        Ok(true) => std::process::ExitCode::from(EXIT_OK as u8),
        Ok(false) => std::process::ExitCode::from(EXIT_EXPECTATION_FAILED as u8),
        Err(usage) => {
            eprintln!("ouro-fixture: {usage}");
            std::process::ExitCode::from(EXIT_USAGE as u8)
        }
    }
}
