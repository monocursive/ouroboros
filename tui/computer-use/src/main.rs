//! `ouro-computer-use`: the native macOS helper for Ouroboros Computer Use (doc §7).
//!
//! It is host-privileged I/O behind a private JSON-RPC protocol, spawned like a language
//! server — never registered as an MCP server, never deciding allow or deny. The BEAM stays
//! authoritative for policy, ledger, and approvals; this process owns pixels, accessibility
//! trees, and injected input, and does only what a request tells it to.
//!
//! Two entry points:
//!   * `serve` — read requests from stdin, write responses to stdout. The mode
//!     `Native.Desktop.Pool` spawns.
//!   * `doctor` — probe host permissions with no side effects, print the doctor JSON, exit.
//!     The mode `ouro desktop doctor` shells out to.
//!
//! Phase 0 is the contract and a real `doctor`. `windows` / `state` / `act` are honest stubs
//! ("not implemented in phase 0"); no capture, accessibility walk, or input injection exists
//! yet. Those land in Phase 1+.

mod args;
mod codec;
mod doctor;
mod server;

// The key grammar and coordinate arithmetic are complete and unit-tested now (doc §5.3,
// §7.3), but their only runtime consumers are Phase 1's `state`/`act` — which are still
// stubs. `allow(dead_code)` is scoped to exactly these two forward-looking modules, never
// the wired ones (codec, server, doctor, args, macos), so real dead code there is not hidden.
#[allow(dead_code)]
mod geometry;
#[allow(dead_code)]
mod keys;

#[cfg(target_os = "macos")]
mod macos;

use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match args::parse(std::env::args().skip(1)) {
        Ok(args) => run(args).await,
        Err(args::ParseError::Help) => {
            print!("{}", args::USAGE);
            ExitCode::SUCCESS
        }
        Err(args::ParseError::Message(message)) => {
            eprintln!("ouro-computer-use: {message}\n\n{}", args::USAGE);
            // 2 is the conventional "usage error" exit.
            ExitCode::from(2)
        }
    }
}

async fn run(args: args::Args) -> ExitCode {
    match args.command {
        args::Command::Doctor => {
            println!("{}", doctor::report_pretty());
            ExitCode::SUCCESS
        }
        args::Command::Serve => {
            let server = server::Server::new(args.deny_apps);
            let reader = tokio::io::BufReader::new(tokio::io::stdin());
            let writer = tokio::io::stdout();
            match server::run(server, reader, writer, args.max_frame_bytes).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("ouro-computer-use: serve ended on I/O error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
