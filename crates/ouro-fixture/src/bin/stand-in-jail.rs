//! A stand-in for `ouro-jail`, for testing the harness without the real jail.
//!
//! It does the things the harness plumbs: it writes a prepared receipt,
//! announces `prepared` on the control channel, reads the gate to EOF and
//! validates it with the product's own §8.2 parser (`ouro_records`), then
//! writes the next receipt, announces it and execs the target argv. Every
//! receipt, control message, trace note and error it writes is built from
//! the `ouro_records` types, so it cannot drift from the wire vocabulary.
//!
//! It contains no containment, no observation and no policy, and its
//! receipts say so (`containment: none`, every coverage class unsupported).
//! It proves the *harness*: a test that uses it must not claim anything about
//! the jail. It announces the exec before replacing its image, because after
//! the exec nothing of it is left to announce anything.
//!
//! It is a separate binary of the test-only `ouro-fixture` crate and is never
//! packaged.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Parser;
use ouro_records::records::semantic::receipt_digest;
use ouro_records::records::{
    Applied, AppliedNetwork, AttemptRecord, Containment, ControlKind, ControlMessage, Coverage,
    ErrorCode, ErrorStage, EvidenceMode, GateExpectation, JailError, JailRecord, Lifetime,
    ObserveMode, ObserverRecord, Os, Outcome, OutcomeKind, Phase, PlatformRecord, PolicyRecord,
    Receipt, Remediation, SCHEMA_CONTROL, SCHEMA_EVENT, SourceHealth, SourceStatus, StateCleanup,
    read_release,
};
use serde_json::json;

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

/// The attempt's account: no boundary, no observer, nothing applied.
fn attempt(cli: &Cli) -> AttemptRecord {
    let now = SystemTime::now();
    AttemptRecord {
        attempt_id: cli.attempt_id.clone(),
        revision: 1,
        platform: PlatformRecord {
            os: if cfg!(target_os = "linux") {
                Os::Linux
            } else {
                Os::Macos
            },
            arch: std::env::consts::ARCH.to_owned(),
            kernel: "unknown".to_owned(),
        },
        jail: JailRecord {
            component: "stand-in-jail".to_owned(),
            version: "0.0.0-test".to_owned(),
            backend: None,
            backend_version: None,
        },
        policy: PolicyRecord {
            name: "stand-in".to_owned(),
            digest: cli.policy_digest.clone(),
            observe: ObserveMode::Off,
            evidence: EvidenceMode::BestEffort,
            requirements: Vec::new(),
            grants: Vec::new(),
        },
        containment: Containment::None,
        exec_observed: false,
        argv_digest: Some(cli.argv_digest.clone()),
        applied: Applied {
            filesystem: None,
            network: AppliedNetwork {
                mode: "none".to_owned(),
                mechanism: None,
                allowed_hosts: Vec::new(),
                tls_only: Vec::new(),
            },
            syscalls: None,
            limits: Vec::new(),
            environment_names: Vec::new(),
            removed_environment_names: Vec::new(),
        },
        observer: ObserverRecord {
            backend: None,
            set: None,
            attached: false,
            sources: SourceHealth {
                wrapper: SourceStatus::Unsupported,
                audit: SourceStatus::Unsupported,
                proxy: SourceStatus::Unsupported,
            },
            gaps: Vec::new(),
        },
        coverage: Coverage::all_unsupported(),
        process: None,
        lifetime: Lifetime::pending(),
        outcome: Outcome::pending(),
        state_cleanup: StateCleanup::NotNeeded,
        cleanup_error: None,
        created_at: now,
        updated_at: now,
        errors: Vec::new(),
        credentials: Vec::new(),
    }
}

/// Where the stand-in reports: the receipt files, the control channel and
/// the trace, each written as the real jail writes it.
struct Reporter<'a> {
    cli: &'a Cli,
    record: AttemptRecord,
    control: Option<std::fs::File>,
    trace: Option<std::fs::File>,
    seq: u64,
}

impl Reporter<'_> {
    /// Write the receipt for `phase` to every receipt file, then announce it
    /// with `kind` and end the trace (so far) on its `jail.receipt` note
    /// (§13.3). A receipt that cannot be written is fatal, as it is for the
    /// jail; a closed control or trace reader is the harness's business.
    fn record(&mut self, phase: Phase, kind: ControlKind) -> Result<(), JailError> {
        let receipt = self.record.receipt(phase);
        let state_write = |what: &str, error: &dyn std::fmt::Display| {
            JailError::new(
                ErrorCode::StateWriteFailed,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("{what}: {error}"),
            )
        };
        if let Some(path) = &self.cli.receipt {
            write_receipt(path, &receipt).map_err(|e| state_write("--receipt", &e))?;
        }
        if let Some(dir) = std::env::var_os("OURO_DATA_DIR") {
            let path = PathBuf::from(dir)
                .join("attempts")
                .join(&self.cli.attempt_id)
                .join("jail.json");
            write_receipt(&path, &receipt).map_err(|e| state_write("jail.json", &e))?;
        }
        let value = serde_json::to_value(&receipt).map_err(|e| state_write("receipt", &e))?;
        let digest = receipt_digest(&value).map_err(|e| state_write("receipt digest", &e))?;
        if let Some(w) = self.control.as_mut() {
            let message = ControlMessage {
                schema: SCHEMA_CONTROL.to_owned(),
                attempt_id: self.cli.attempt_id.clone(),
                seq: self.seq,
                kind,
                receipt_phase: phase,
                receipt_digest: digest.clone(),
                outcome: receipt.outcome.clone(),
                error: receipt.outcome.error.clone(),
            };
            self.seq += 1;
            if let Ok(frame) = message.to_frame() {
                let _ = w.write_all(&frame);
                let _ = w.flush();
            }
        }
        if let Some(w) = self.trace.as_mut() {
            let note = json!({
                "schema": SCHEMA_EVENT,
                "source": "wrapper",
                "operation": "jail.receipt",
                "stage": "result",
                "attempt_id": self.cli.attempt_id,
                "fields": { "phase": receipt.phase, "receipt_digest": digest },
            });
            let _ = writeln!(w, "{note}");
            let _ = w.flush();
        }
        Ok(())
    }

    /// Refuse before the target ran: the refused receipt, its message, and
    /// the jail's one-line diagnostic.
    fn refuse(&mut self, error: &JailError) -> std::process::ExitCode {
        self.record.outcome = Outcome::refused(error);
        self.record.errors.push(error.to_object());
        self.record.revision += 1;
        if let Err(written) = self.record(Phase::Refused, ControlKind::Refused) {
            return fail(&written);
        }
        fail(error)
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let invalid_fd = |flag: &str, why: String| {
        JailError::new(
            ErrorCode::InvalidFd,
            ErrorStage::Resolving,
            Remediation::Configuration,
            format!("{flag}: {why}"),
        )
    };
    let control = match cli.control_fd.map(checked_writer).transpose() {
        Ok(w) => w,
        Err(why) => return fail(&invalid_fd("--control-fd", why)),
    };
    let trace = match cli.trace_fd.map(checked_writer).transpose() {
        Ok(w) => w,
        Err(why) => return fail(&invalid_fd("--trace-fd", why)),
    };
    let gate = match cli.gate_fd.map(checked_reader).transpose() {
        Ok(r) => r,
        Err(why) => return fail(&invalid_fd("--gate-fd", why)),
    };

    let mut reporter = Reporter {
        record: attempt(&cli),
        cli: &cli,
        control,
        trace,
        seq: 0,
    };
    if cli.malformed_control
        && let Some(w) = reporter.control.as_mut()
    {
        writeln!(w, "not-json").expect("malformed control write");
    }
    if let Some(w) = reporter.trace.as_mut() {
        for _ in 0..cli.trace_lines {
            writeln!(w, "{{\"padding\":\"{}\"}}", "x".repeat(1024)).expect("trace pressure write");
        }
        if cli.malformed_trace {
            writeln!(w, "not-json").expect("malformed trace write");
        }
        let event = json!({
            "schema": SCHEMA_EVENT,
            "source": "wrapper",
            "stage": "attempt",
            "attempt_id": cli.attempt_id,
            "fields": { "kind": "lifecycle", "note": "stand-in prepared" },
        });
        let _ = writeln!(w, "{event}");
    }
    if let Err(error) = reporter.record(Phase::Prepared, ControlKind::Prepared) {
        return fail(&error);
    }

    if let Some(gate) = gate {
        let expected = GateExpectation {
            attempt_id: cli.attempt_id.clone(),
            policy_digest: cli.policy_digest.clone(),
        };
        if let Err(error) = read_release(&mut std::fs::File::from(gate), &expected) {
            return reporter.refuse(&error);
        }
    }

    reporter.record.revision += 1;
    if cli.argv.is_empty() {
        // Nothing to run: settled at once, with nothing that ran.
        reporter.record.outcome = Outcome {
            kind: OutcomeKind::Exited,
            code: Some(0),
            signal: None,
            cause: None,
            error: None,
        };
        if let Err(error) = reporter.record(Phase::Settled, ControlKind::Settled) {
            return fail(&error);
        }
        return std::process::ExitCode::SUCCESS;
    }

    // The gate and control channels never reach the target: announce the exec
    // and drop every descriptor before replacing this image.
    //
    // §8.3: "All other fds close before exec". The real jail owns that rule;
    // this stand-in has to mirror it, because a descriptor the *environment*
    // handed to the test process (a CI runner routinely does) would otherwise
    // reach the target through this process and look like a harness leak.
    if let Err(error) = reporter.record(Phase::Enforced, ControlKind::ExecConfirmed) {
        return fail(&error);
    }
    drop(reporter);
    close_extra_descriptors();

    let err = exec(&cli.argv);
    fail(&JailError::new(
        ErrorCode::ExecFailed,
        ErrorStage::Released,
        Remediation::Configuration,
        err.to_string(),
    ))
}

/// Close every descriptor above stderr, so the target inherits only validated
/// stdio (jail-v1 §8.3). Called immediately before the exec, after every
/// channel this process owns has been dropped.
fn close_extra_descriptors() {
    #[cfg(target_os = "linux")]
    {
        // `close_range` is one syscall and cannot miss a descriptor.
        // SAFETY: closing a range of descriptor numbers this process owns;
        // stdio is excluded and nothing below is used afterwards except the
        // exec itself.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
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
    if let Some(numbers) = ouro_fixture::ops::open_fd_numbers() {
        return numbers;
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
    let access =
        ouro_fixture::report::open_for(fd).ok_or_else(|| format!("fd {fd} is not open"))?;
    if want_write && !access.writable {
        return Err(format!("fd {fd} is not writable"));
    }
    if !want_write && !access.readable {
        return Err(format!("fd {fd} is not readable"));
    }
    Ok(())
}

/// Replace a receipt file, one JSON document, through a sibling temporary
/// file and a rename, as §7 replaces `jail.json`.
fn write_receipt(path: &Path, receipt: &Receipt) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec(receipt)?;
    bytes.push(b'\n');
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)
}

/// The jail's one-line diagnostic for `error`, and its exit status.
fn fail(error: &JailError) -> std::process::ExitCode {
    eprintln!("stand-in-jail: {error}");
    std::process::ExitCode::from(u8::try_from(error.refusal_exit_code()).unwrap_or(1))
}
