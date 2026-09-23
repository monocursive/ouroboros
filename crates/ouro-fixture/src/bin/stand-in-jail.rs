//! A stand-in for `ouro-jail`, for testing the harness before the real jail
//! exists.
//!
//! It does the four things the harness plumbs: it writes a prepared receipt,
//! announces `prepared` on the control channel, reads the gate to EOF and
//! validates it against jail-v1 §8.2, then execs the target argv. It contains
//! no containment, no observation and no policy: it proves the *harness*, and
//! a test that uses it must not claim anything about the jail.
//!
//! It is a separate binary of the test-only `ouro-fixture` crate and is never
//! packaged. The integrator may delete it once `crates/ouro-jail` lands, at
//! the cost of the §8.2 frame-rejection coverage it carries.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};

const GATE_SCHEMA: &str = "ouro.jail.gate/1";
const CONTROL_SCHEMA: &str = "ouro.jail.control/1";
const RECEIPT_SCHEMA: &str = "ouro.jail.receipt/1";
const GATE_MAX_BYTES: usize = 1024;

/// Exit code for a refusal before the target ran, jail-v1 §6.4.
const EXIT_REFUSED: i32 = 125;
const EXIT_TOOL_ERROR: i32 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "stand-in-jail",
    about = "Test stand-in for ouro-jail: gate plumbing only"
)]
struct Cli {
    #[arg(long, value_name = "FD")]
    control_fd: Option<i32>,
    #[arg(long, value_name = "FD")]
    gate_fd: Option<i32>,
    #[arg(long, value_name = "FD")]
    trace_fd: Option<i32>,
    /// Exercise harness backpressure with more data than a pipe can hold.
    #[arg(long, default_value_t = 0)]
    trace_lines: usize,
    #[arg(long)]
    malformed_trace: bool,
    #[arg(long)]
    malformed_control: bool,
    #[arg(long, value_name = "PATH")]
    receipt: Option<PathBuf>,
    #[arg(long, default_value = "att_00000000-0000-4000-8000-000000000001")]
    attempt_id: String,
    #[arg(
        long,
        default_value = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )]
    policy_digest: String,
    #[arg(
        long,
        default_value = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )]
    argv_digest: String,
    #[arg(last = true, num_args = 0.., value_name = "ARGV")]
    argv: Vec<OsString>,
}

/// The §8.2 frame, strictly. `deny_unknown_fields` rejects extra keys and
/// serde's own derived code rejects a duplicate key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    schema: String,
    action: String,
    attempt_id: String,
    policy_digest: String,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let control = match cli.control_fd.map(checked_writer) {
        Some(Ok(w)) => Some(w),
        Some(Err(e)) => return fail(&format!("invalid_fd: --control-fd: {e}")),
        None => None,
    };
    let trace = match cli.trace_fd.map(checked_writer) {
        Some(Ok(w)) => Some(w),
        Some(Err(e)) => return fail(&format!("invalid_fd: --trace-fd: {e}")),
        None => None,
    };
    let gate = match cli.gate_fd.map(checked_reader) {
        Some(Ok(r)) => Some(r),
        Some(Err(e)) => return fail(&format!("invalid_fd: --gate-fd: {e}")),
        None => None,
    };

    let receipt = json!({
        "schema": RECEIPT_SCHEMA,
        "attempt_id": cli.attempt_id,
        "revision": 1,
        "phase": "prepared",
        "jail": { "component": "stand-in-jail", "version": "0.0.0-test" },
        "policy": { "name": "stand-in", "digest": cli.policy_digest },
        "argv_digest": cli.argv_digest,
        "argc": cli.argv.len(),
    });
    if let Some(path) = &cli.receipt
        && let Err(e) = write_json(path, &receipt)
    {
        return fail(&format!("state_write_failed: --receipt: {e}"));
    }
    if let Some(dir) = std::env::var_os("OURO_DATA_DIR") {
        let attempt = PathBuf::from(dir).join("attempts").join(&cli.attempt_id);
        if std::fs::create_dir_all(&attempt).is_ok() {
            let _ = write_json(&attempt.join("jail.json"), &receipt);
        }
    }

    let mut control = control;
    if cli.malformed_control
        && let Some(file) = &mut control
    {
        writeln!(file, "not-json").expect("malformed control write");
    }
    let mut seq = 0u64;
    if let Some(w) = control.as_mut() {
        let msg = json!({
            "schema": CONTROL_SCHEMA,
            "attempt_id": cli.attempt_id,
            "seq": seq,
            "kind": "prepared",
            "receipt_phase": "prepared",
            "receipt_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "outcome": Value::Null,
            "error": Value::Null,
        });
        seq += 1;
        if writeln!(w, "{msg}").is_err() {
            return std::process::ExitCode::from(EXIT_TOOL_ERROR as u8);
        }
        let _ = w.flush();
    }
    if let Some(mut w) = trace {
        for _ in 0..cli.trace_lines {
            writeln!(w, "{{\"padding\":\"{}\"}}", "x".repeat(1024)).expect("trace pressure write");
        }
        if cli.malformed_trace {
            writeln!(w, "not-json").expect("malformed trace write");
        }
        let event = json!({
            "schema": "ouro.event/1",
            "source": "wrapper",
            "stage": "attempt",
            "attempt_id": cli.attempt_id,
            "fields": { "kind": "lifecycle", "note": "stand-in prepared" },
        });
        let _ = writeln!(w, "{event}");
        // jail-v1 §13.3: a complete trace ends on the `jail.receipt` note of
        // the attempt's final receipt, which for this stand-in is the one
        // prepared receipt it writes. Named as the real jail names it.
        if let Ok((phase, digest)) =
            ouro_fixture::harness::receipt_note_of(receipt_bytes(&receipt).as_bytes())
        {
            let note = json!({
                "schema": "ouro.event/1",
                "source": "wrapper",
                "operation": "jail.receipt",
                "stage": "result",
                "attempt_id": cli.attempt_id,
                "fields": { "phase": phase, "receipt_digest": digest },
            });
            let _ = writeln!(w, "{note}");
        }
        let _ = w.flush();
    }

    if let Some(gate) = gate
        && let Err(reason) = read_and_check_gate(gate, &cli.attempt_id, &cli.policy_digest)
    {
        if let Some(w) = control.as_mut() {
            let msg = json!({
                "schema": CONTROL_SCHEMA,
                "attempt_id": cli.attempt_id,
                "seq": seq,
                "kind": "refused",
                "receipt_phase": "refused",
                "receipt_digest": Value::Null,
                "outcome": Value::Null,
                "error": {
                    "code": reason.code,
                    "stage": "gating",
                    "message": reason.message,
                    "remediation_category": "configuration",
                },
            });
            let _ = writeln!(w, "{msg}");
            let _ = w.flush();
        }
        eprintln!(
            "stand-in-jail: error {} at gating [configuration]: {}",
            reason.code, reason.message
        );
        return std::process::ExitCode::from(EXIT_REFUSED as u8);
    }

    if cli.argv.is_empty() {
        if let Some(w) = control.as_mut() {
            let msg = json!({
                "schema": CONTROL_SCHEMA,
                "attempt_id": cli.attempt_id,
                "seq": seq,
                "kind": "settled",
                "receipt_phase": "settled",
                "receipt_digest": Value::Null,
                "outcome": { "kind": "exited", "code": 0 },
                "error": Value::Null,
            });
            let _ = writeln!(w, "{msg}");
        }
        return std::process::ExitCode::SUCCESS;
    }

    // The gate and control channels never reach the target: announce the exec
    // and drop both descriptors before replacing this image.
    //
    // §8.3: "All other fds close before exec". The real jail owns that rule;
    // this stand-in has to mirror it, because a descriptor the *environment*
    // handed to the test process (a CI runner routinely does) would otherwise
    // reach the target through this process and look like a harness leak.
    if let Some(w) = control.as_mut() {
        let msg = json!({
            "schema": CONTROL_SCHEMA,
            "attempt_id": cli.attempt_id,
            "seq": seq,
            "kind": "exec_confirmed",
            "receipt_phase": "enforced",
            "receipt_digest": Value::Null,
            "outcome": Value::Null,
            "error": Value::Null,
        });
        let _ = writeln!(w, "{msg}");
        let _ = w.flush();
    }
    drop(control);
    close_extra_descriptors();

    let err = exec(&cli.argv);
    eprintln!("stand-in-jail: error exec_failed at launching [configuration]: {err}");
    std::process::ExitCode::from(EXIT_REFUSED as u8)
}

struct Refusal {
    code: &'static str,
    message: String,
}

fn read_and_check_gate(fd: OwnedFd, attempt_id: &str, policy_digest: &str) -> Result<(), Refusal> {
    use std::io::Read as _;
    let mut file = std::fs::File::from(fd);
    let mut buf = Vec::new();
    // Read through EOF before deciding, so a second frame or trailing bytes
    // cannot be accepted after the first line looked fine (§8.2).
    if let Err(e) = file.read_to_end(&mut buf) {
        return Err(Refusal {
            code: "gate_invalid",
            message: format!("gate could not be read: {e}"),
        });
    }

    let invalid = |message: String| {
        Err(Refusal {
            code: "gate_invalid",
            message,
        })
    };

    if buf.is_empty() {
        return Err(Refusal {
            code: "gate_closed",
            message: "gate closed with no frame".into(),
        });
    }
    if buf.len() > GATE_MAX_BYTES {
        return invalid(format!(
            "frame is {} bytes, over the {GATE_MAX_BYTES}-byte cap",
            buf.len()
        ));
    }
    if buf.contains(&b'\r') {
        return invalid("frame contains CR".into());
    }
    if buf.last() != Some(&b'\n') {
        return invalid("frame does not end in LF".into());
    }
    if buf.iter().filter(|b| **b == b'\n').count() != 1 {
        return invalid("frame is not exactly one line".into());
    }

    let body = &buf[..buf.len() - 1];
    let frame: Frame = match serde_json::from_slice(body) {
        Ok(f) => f,
        Err(e) => return invalid(format!("frame is not a valid gate object: {e}")),
    };
    if frame.schema != GATE_SCHEMA {
        return invalid(format!("wrong schema `{}`", frame.schema));
    }
    if frame.action != "release" {
        return invalid(format!("wrong action `{}`", frame.action));
    }
    if frame.attempt_id != attempt_id {
        return invalid("frame names a different attempt".into());
    }
    if frame.policy_digest != policy_digest {
        return invalid("frame names a different policy digest".into());
    }
    Ok(())
}

/// Close every descriptor above stderr, so the target inherits only validated
/// stdio (jail-v1 §8.3). Called immediately before the exec, after every
/// channel this process owns has been dropped.
fn close_extra_descriptors() {
    #[cfg(target_os = "linux")]
    {
        // `close_range` is one syscall and cannot miss a descriptor.
        const SYS_CLOSE_RANGE: libc::c_long = 436;
        // SAFETY: closing a range of descriptor numbers this process owns;
        // stdio is excluded and nothing below is used afterwards except the
        // exec itself.
        let rc = unsafe { libc::syscall(SYS_CLOSE_RANGE, 3u32, u32::MAX, 0u32) };
        if rc == 0 {
            return;
        }
        // Kernels before 5.9 have no `close_range`; fall through.
    }
    for fd in enumerate_descriptors() {
        if fd > 2 {
            // SAFETY: a descriptor number this process owns, closed once.
            unsafe { libc::close(fd) };
        }
    }
}

/// The open descriptor numbers, from the kernel where it lists them and from a
/// bounded probe otherwise.
fn enumerate_descriptors() -> Vec<libc::c_int> {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut out: Vec<libc::c_int> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
            .collect();
        out.sort_unstable();
        return out;
    }
    // SAFETY: `rl` is a live rlimit struct, which is what `getrlimit` writes.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let limit = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) } == 0 {
        libc::c_int::try_from(rl.rlim_cur).unwrap_or(65_536)
    } else {
        65_536
    };
    (0..limit.min(65_536)).collect()
}

fn exec(argv: &[OsString]) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.exec()
}

fn checked_writer(fd: i32) -> Result<std::fs::File, String> {
    check_access(fd, true)?;
    // SAFETY: the descriptor was inherited for this process, verified open and
    // writable just above, and is owned from here on.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn checked_reader(fd: i32) -> Result<OwnedFd, String> {
    check_access(fd, false)?;
    // SAFETY: as `checked_writer`, for a readable descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn check_access(fd: i32, want_write: bool) -> Result<(), String> {
    // SAFETY: `F_GETFL` only reads the status flags of a descriptor number.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!("fd {fd} is not open"));
    }
    let access = flags & libc::O_ACCMODE;
    let writable = access == libc::O_WRONLY || access == libc::O_RDWR;
    let readable = access == libc::O_RDONLY || access == libc::O_RDWR;
    if want_write && !writable {
        return Err(format!("fd {fd} is not writable"));
    }
    if !want_write && !readable {
        return Err(format!("fd {fd} is not readable"));
    }
    Ok(())
}

/// The bytes a receipt file of this stand-in holds.
fn receipt_bytes(value: &Value) -> String {
    format!("{value}\n")
}

fn write_json(path: &std::path::Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, receipt_bytes(value))
}

fn fail(message: &str) -> std::process::ExitCode {
    eprintln!("stand-in-jail: {message}");
    std::process::ExitCode::from(EXIT_REFUSED as u8)
}
