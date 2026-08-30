//! `ouro-sandbox` — the Ouroboros native-session sandbox helper.
//!
//! One command, one policy, one process. The daemon spawns this binary in place of the
//! command it wants to run; this binary applies the policy to *itself* and then `execve`s
//! the command, so the command inherits the containment and this process ceases to exist.
//! There is no supervisor, no protocol loop, and nothing left running to be killed.
//!
//! That shape is the reason it is a helper binary and not a NIF. The enforcement here is
//! raw `syscall(2)` against namespaces, Landlock, and seccomp — a segfault surface — and
//! it works by *irreversibly restricting the calling process*, which is exactly what must
//! never happen to a BEAM scheduler thread. The runtime's Forge admission policy bans
//! `load_nif` for the first reason; the second would still rule it out.
//!
//! # Exit status
//!
//! On success this process is replaced, so the command's status is the status. A failure
//! to apply the policy exits `125` with a message on stderr prefixed `ouro-sandbox: `.
//! Both halves of that matter: `125` is outside the range a shell command produces for
//! ordinary failure, and the prefix is what
//! `Ouroboros.Provider.Native.Sandbox.backend_failure/3` matches to tell "this node could
//! not sandbox your command" apart from "your command failed".

// On a non-Linux build `linux.rs` is not compiled, which leaves the portable `mountinfo`
// and `seccomp` cores with no caller. They are still compiled and still fully unit-tested
// here, which is the entire reason they were kept portable, so the dead-code warning
// describes a deliberate arrangement rather than a finding. The same `cfg_attr` is what
// the `computer-use` member uses for its own inverted case.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod args;
mod doctor;
#[cfg(target_os = "linux")]
mod linux;
mod mountinfo;
mod plan;
mod request;
mod seccomp;

use args::{Command, Source};
use std::io::Read;
use std::process::ExitCode;

/// The exit status for "the policy could not be applied".
const EXIT_BACKEND_FAILURE: u8 = 125;
/// The exit status for a malformed invocation.
const EXIT_USAGE: u8 = 2;

/// The environment variable naming the `fs_filter.c` shared object, if the daemon built
/// one. It arrives out of band rather than in the JSON request because it is a property of
/// the *installation* — where the release put its `priv/` — not of the policy.
const FS_FILTER_ENV: &str = "OUROBOROS_FS_FILTER_LIBRARY";

fn main() -> ExitCode {
    match args::parse(std::env::args().skip(1)) {
        Ok(Command::Help) => {
            println!("{}", args::USAGE);
            ExitCode::SUCCESS
        }

        Ok(Command::Version) => {
            println!("ouro-sandbox {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }

        Ok(Command::Doctor) => {
            println!("{}", doctor::report());
            ExitCode::SUCCESS
        }

        Ok(Command::Exec { source, target }) => match exec(source, &target) {
            Ok(never) => match never {},
            Err(message) => {
                fail(&message);
                ExitCode::from(EXIT_BACKEND_FAILURE)
            }
        },

        Err(usage) => {
            fail(&usage.to_string());
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Every diagnostic this helper emits, in the one shape the daemon can recognise.
///
/// `eprintln!` and not `println!`: the command's own stdout is the caller's data, and a
/// helper that writes into it corrupts a `bash` tool result even when it succeeds.
fn fail(message: &str) {
    eprintln!("ouro-sandbox: {message}");
}

fn exec(source: Source, target: &[String]) -> Result<std::convert::Infallible, String> {
    let raw = read_request(source)?;
    let policy = request::Policy::from_json(&raw).map_err(|error| error.to_string())?;

    // The request wins; the environment is the hand-run fallback.
    let library = policy
        .fs_filter_library
        .clone()
        .or_else(|| std::env::var(FS_FILTER_ENV).ok().filter(|p| !p.is_empty()));
    let plan = plan::Plan::compile(&policy, library.as_deref());

    // The mode is named in every failure: "could not mount X" is a different problem
    // under `read_only` than under `workspace_write`, and the operator reading this in a
    // tool result has no other way to tell which policy was being applied.
    let mode = policy.mode.as_str();

    #[cfg(target_os = "linux")]
    {
        linux::run(&plan, target).map_err(|failure| format!("{} (mode: {mode})", failure.0))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plan, target);
        Err(format!(
            "this helper enforces with Linux user namespaces, Landlock, and seccomp, and \
             this is {}. Refusing to exec the command under mode {mode}: running it \
             unsandboxed under a sandbox's name is the one thing this binary must never do.",
            std::env::consts::OS
        ))
    }
}

fn read_request(source: Source) -> Result<String, String> {
    match source {
        Source::Inline(json) => Ok(json),

        Source::File(path) => std::fs::read_to_string(&path)
            .map_err(|error| format!("could not read request file {path}: {error}")),

        Source::Stdin => read_one_line_from_stdin(),
    }
}

/// Reads a single newline-terminated line from file descriptor 0, one byte at a time.
///
/// Two things here are deliberate and neither is optional.
///
/// The single-byte reads are the obvious one: the command this helper is about to become
/// inherits this very descriptor, so over-reading past the newline would leave those bytes
/// in a buffer that is destroyed when this process is replaced, silently eating the
/// command's own input.
///
/// The less obvious one is that this goes to the raw descriptor rather than through
/// `std::io::stdin()`. `Stdin` is a `BufReader` with an 8 KiB buffer underneath, so
/// `stdin().read(&mut [0u8; 1])` still issues an 8 KiB `read(2)` and keeps the remainder —
/// which is exactly the bug the previous paragraph describes, arriving through the
/// standard library instead of through a loop this file wrote. It was caught by
/// `the_request_can_arrive_on_stdin_without_eating_the_commands_own_input`, which is why
/// that test drives a real `cat` rather than asserting on the parsed request.
#[cfg(unix)]
fn read_one_line_from_stdin() -> Result<String, String> {
    use std::os::fd::FromRawFd;

    // `ManuallyDrop`: this borrows descriptor 0, it does not own it. Letting the `File`
    // drop would close stdin out from under the command.
    let mut stdin = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    let mut line = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        match stdin.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(error) => return Err(format!("could not read the request from stdin: {error}")),
        }
    }

    if line.is_empty() {
        return Err("the request on stdin was empty".to_string());
    }

    String::from_utf8(line).map_err(|error| format!("the request on stdin was not UTF-8: {error}"))
}

#[cfg(not(unix))]
fn read_one_line_from_stdin() -> Result<String, String> {
    Err(
        "reading the request from stdin needs an unnamed file descriptor 0; use \
         --request or --request-file on this platform"
            .to_string(),
    )
}
