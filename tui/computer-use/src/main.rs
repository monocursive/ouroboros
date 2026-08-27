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
//! Phase 2 makes `doctor`, `windows`, `state`, and `act` real on macOS.
//!
//! macOS is the only platform this helper runs on. A non-macOS build compiles honest
//! "unsupported platform" stubs; the pure shaping modules still compile and are tested.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod act;
mod args;
mod codec;
mod doctor;
mod geometry;
mod keys;
mod screenshot;
mod server;
mod state;
mod tree;
mod windows;

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
