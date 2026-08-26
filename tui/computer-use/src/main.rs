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
//! Phase 1 makes `doctor`, `windows`, and `state` real on macOS (CGWindowList enumeration, a
//! ScreenCaptureKit screenshot, and an AXUIElement tree, all shaped by pure, TCC-free modules).
//! `act` — input injection — is still an honest stub ("not implemented in phase 2").
//!
//! macOS is the only platform this helper runs on. A non-macOS build compiles honest
//! "unsupported platform" stubs for `windows`/`state`; the pure shaping modules those stubs
//! would feed still compile (and are exercised by tests) but go unused there, so a non-macOS
//! build allows dead code. macOS stays the strict gate — `clippy -D warnings` is clean there.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod args;
mod codec;
mod doctor;
mod screenshot;
mod server;
mod state;
mod tree;
mod windows;

// `geometry` and `keys` are complete and unit-tested, but each still has runtime consumers that
// only land in Phase 2's `act`: the point-mapping in `geometry` (`map_point`/`map_point_uniform`,
// for translating a model's click coordinate back onto a window) and the whole key grammar. Phase
// 1 wires only `geometry::image_scale`. `allow(dead_code)` is scoped to exactly these two
// forward-looking modules, never the fully wired ones (codec, server, doctor, args, screenshot,
// windows, tree, state, macos), so real dead code there is not hidden.
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
