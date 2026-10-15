//! One owned launch, from spawning the jail to recording its outcome, as
//! named steps: spawn, supervise (admission happens inside), finish the
//! streams, corroborate the terminal evidence, record it.
use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    os::{
        fd::{AsRawFd as _, OwnedFd, RawFd},
        unix::{
            fs::OpenOptionsExt as _,
            net::UnixStream,
            process::{CommandExt as _, ExitStatusExt as _},
        },
    },
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use ukai_records::records::{self, ControlKind, ControlMessage, GateFrame, Phase, Receipt};

use super::{
    Capture, EXIT_POLL, FORWARDING_GRACE, Frames, HEARTBEAT, OwnedChild, RunOptions, RunResult,
    Tee, argv_capture, check_prepared, error, evidence::Evidence, exit_descriptor,
    forwarding_grace, image_command, image_digest, output_pipe, read_receipt, record_unknown,
    terminate, unknown_body, wait_readable,
};
use crate::{
    daemon::Client,
    protocol::{ClaimedOwner, Result, RunRecord},
};

/// How long the jail may take to prepare before the owner gives up.
const PREPARATION_LIMIT: Duration = Duration::from_secs(30);
/// How long the jail's streams may take to end after it exits, and the jail
/// to exit after its terminal control.
const WIND_DOWN_LIMIT: Duration = Duration::from_secs(5);

/// The steps between the jail's prepared control and an open gate, in the
/// only order they may run. Each consumes the proof the previous step
/// returned, so the gate cannot be released before the writer has durably
/// admitted the attempt, and admission cannot be requested for a receipt or
/// an executing image nobody checked.
mod admission {
    use super::*;

    /// The jail's prepared receipt, matched against the reserved run.
    pub(super) struct Prepared {
        receipt: Value,
        receipt_digest: String,
        policy_digest: String,
    }

    /// ...and the jail executing now is the image the request was prepared
    /// with.
    pub(super) struct ImageBound(Prepared);

    /// ...and the admission intent is complete, any selected argv capture
    /// already durable.
    pub(super) struct Requested {
        body: Value,
        policy_digest: String,
    }

    /// ...and the writer durably recorded the admission.
    pub(super) struct Admitted {
        policy_digest: String,
    }

    impl Prepared {
        pub(super) fn check(
            receipt_path: &Path,
            message: &ControlMessage,
            run: &RunRecord,
        ) -> Result<Self> {
            let receipt = read_receipt(receipt_path, "prepared")?;
            let typed = check_prepared(&receipt, message, run)?;
            Ok(Self {
                receipt,
                receipt_digest: message.receipt_digest.clone(),
                policy_digest: typed.policy.digest,
            })
        }

        /// Native Linux exec holds the executing inode against writes
        /// (ETXTBSY), so the live jail image `pid` runs is bound here.
        pub(super) fn bind_image(self, pid: u32, expected: &str) -> Result<ImageBound> {
            let executing = File::open(format!("/proc/{pid}/exe"))
                .map_err(|e| error(format!("binding prepared jail image for pid {pid}: {e}")))?;
            if image_digest(&executing)? != expected {
                return Err(error(
                    "executing jail image differs from the prepared image digest",
                ));
            }
            Ok(ImageBound(self))
        }
    }

    impl ImageBound {
        /// Capture the exact requested argv only now, after preparation,
        /// and bind its metadata into the admission. A partial write or sync
        /// failure fails the launch with incomplete metadata and a closed gate.
        pub(super) fn request(
            self,
            options: &RunOptions,
            run_dir: &Path,
            argv_capture: &mut Value,
        ) -> Result<Requested> {
            let Prepared {
                receipt,
                receipt_digest,
                policy_digest,
            } = self.0;
            let mut body = json!({"receipt":receipt,"receipt_digest":receipt_digest});
            if options.captures.iter().any(|s| s == "argv") {
                argv_capture::save(run_dir, &options.argv, options.capture_limit, argv_capture)?;
                body["capture"] = json!({
                    "stdout":{"state":"not_captured"},
                    "stderr":{"state":"not_captured"},
                    "argv":argv_capture,
                });
            }
            Ok(Requested {
                body,
                policy_digest,
            })
        }
    }

    impl Requested {
        /// The durable admission, then the local journal that best-effort
        /// evidence needs from now on.
        pub(super) fn admit(
            self,
            client: &mut Client,
            run: &RunRecord,
            claim: &ClaimedOwner,
            evidence: &mut Evidence,
        ) -> Result<Admitted> {
            client.append_owner(
                &run.run_id,
                "admission",
                "admitted",
                None,
                &self.body,
                &claim.owner_token,
            )?;
            evidence.admitted()?;
            Ok(Admitted {
                policy_digest: self.policy_digest,
            })
        }
    }

    impl Admitted {
        /// Release the gate: the jail may now exec the target.
        pub(super) fn release(self, gate: &mut UnixStream, attempt_id: &str) -> Result<()> {
            let release = GateFrame {
                schema: records::SCHEMA_GATE.into(),
                action: "release".into(),
                attempt_id: attempt_id.into(),
                policy_digest: self.policy_digest,
            };
            let mut frame = serde_json::to_vec(&release)?;
            frame.push(b'\n');
            gate.write_all(&frame)?;
            gate.shutdown(std::net::Shutdown::Write)?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn admission_binds_only_the_executing_image_the_request_was_prepared_with() {
            let program = "/bin/sleep";
            let prepared = || Prepared {
                receipt: Value::Null,
                receipt_digest: String::new(),
                policy_digest: String::new(),
            };
            let image = image_digest(&File::open(program).unwrap()).unwrap();
            let other = format!("sha256:{}", "0".repeat(64));
            assert_ne!(image, other);
            let mut child = std::process::Command::new(program)
                .arg("30")
                .spawn()
                .unwrap();
            let pid = child.id();
            let bound = prepared().bind_image(pid, &image).map(drop);
            let refused = prepared().bind_image(pid, &other).map(drop);
            child.kill().unwrap();
            child.wait().unwrap();
            bound.unwrap();
            assert_eq!(
                refused.unwrap_err().message(),
                "executing jail image differs from the prepared image digest"
            );
        }
    }
}

/// What the owner holds and has learned while it supervises one jail.
struct Launch<'a> {
    options: &'a RunOptions,
    run: &'a RunRecord,
    claim: &'a ClaimedOwner,
    client: &'a mut Client,
    evidence: Evidence,
    expected_image: &'a str,
    run_dir: PathBuf,
    /// The jail's canonical receipt. Its copy fence forbids an additional
    /// `--receipt` inside DATA; the unified DATA root protects the ledger too.
    receipt_path: PathBuf,
    child: OwnedChild,
    /// Readable once the jail exits, where pidfds exist.
    exited: Option<OwnedFd>,
    trace: Frames,
    control: Frames,
    /// The gate socket, kept open until the launch ends or fails.
    gate: Option<UnixStream>,
    /// Whether the gate may still be released.
    gate_open: bool,
    captures: Vec<Capture>,
    admitted: bool,
    argv_capture: Value,
    terminal: Option<ControlMessage>,
    terminal_seen: Option<Instant>,
    control_seq: u64,
    last_trace: Option<Value>,
    last_heartbeat: Instant,
    exit: Option<ExitStatus>,
    exit_seen: Option<Instant>,
    preparation_deadline: Instant,
    cancel_sent: bool,
}

pub(super) fn run_owned(
    options: &RunOptions,
    image: &File,
    expected_image: &str,
    run: &RunRecord,
    claim: &ClaimedOwner,
    client: &mut Client,
    local_exit_saved: &mut bool,
) -> Result<RunResult> {
    let evidence = Evidence::new(options, run, claim)?;
    let mut launch = Launch::spawn(options, image, expected_image, run, claim, client, evidence)?;
    let mut failure = launch.supervise().err();
    if failure.is_some() {
        launch.abandon();
    }
    let capture = launch.finish_streams(&mut failure);
    if let Some(problem) = failure {
        // An unreachable writer supplies no acknowledgement. A later orphan
        // reconciliation says unknown.
        launch.record_unknown("owner-failure", "owner_or_evidence_failure", &capture);
        return Err(problem);
    }
    let (kind, body, final_control) = launch.corroborate(capture)?;
    let completion = launch
        .evidence
        .finish(launch.client, kind, body, final_control);
    *local_exit_saved = launch.evidence.local_exit_saved;
    completion?;
    let record = launch.client.show(&run.run_id)?;
    let exit_code = launch.exit.map_or(1, |s| {
        s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
    });
    Ok(RunResult { record, exit_code })
}

impl<'a> Launch<'a> {
    /// Start the jail with its trace, control and gate descriptors, and the
    /// output pipes the run captures or forwards. A jail that cannot start
    /// is a durable refusal.
    fn spawn(
        options: &'a RunOptions,
        image: &File,
        expected_image: &'a str,
        run: &'a RunRecord,
        claim: &'a ClaimedOwner,
        client: &'a mut Client,
        evidence: Evidence,
    ) -> Result<Self> {
        let run_dir = options.data.join("ledger").join(&run.run_id);
        let receipt_path = options
            .data
            .join("attempts")
            .join(&claim.attempt_id)
            .join("jail.json");
        let (trace_parent, trace_child) = UnixStream::pair()?;
        let (control_parent, control_child) = UnixStream::pair()?;
        let (gate_parent, gate_child) = UnixStream::pair()?;
        let mut command = image_command(image);
        command
            .arg("run")
            .args(&options.policy_args)
            .arg("--attempt-id")
            .arg(&claim.attempt_id)
            .arg("--trace-fd")
            .arg(trace_child.as_raw_fd().to_string())
            .arg("--control-fd")
            .arg(control_child.as_raw_fd().to_string())
            .arg("--gate-fd")
            .arg(gate_child.as_raw_fd().to_string())
            .arg("--")
            .args(&options.argv)
            .env("UKAI_DATA_DIR", &options.data);
        command.stdin(if options.batch {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
        let mut captures = Vec::new();
        for name in ["stdout", "stderr"] {
            if options.batch || options.captures.iter().any(|s| s == name) {
                // Socket stdio would be host-socket authority; the jail
                // rejects it. Keep the child write end blocking and drain a pipe.
                let (parent, child) = output_pipe()?;
                let selected = options.captures.iter().any(|s| s == name);
                let file = if selected {
                    Some(
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                            .open(run_dir.join(format!("artifacts/{name}.bin")))?,
                    )
                } else {
                    None
                };
                if name == "stdout" {
                    command.stdout(Stdio::from(child));
                } else {
                    command.stderr(Stdio::from(child));
                }
                captures.push(Capture {
                    stream: parent,
                    file,
                    observed: 0,
                    stored: 0,
                    limit: options.capture_limit,
                    eof: false,
                    name,
                    tee: if options.batch {
                        None
                    } else {
                        Some(Tee::stdio(name)?)
                    },
                });
            } else if name == "stdout" {
                command.stdout(Stdio::inherit());
            } else {
                command.stderr(Stdio::inherit());
            }
        }
        let fds = [
            trace_child.as_raw_fd(),
            control_child.as_raw_fd(),
            gate_child.as_raw_fd(),
        ];
        let parent_pid = std::process::id() as libc::pid_t;
        // SAFETY: async-signal-safe syscalls only; no allocation or locks after fork.
        unsafe {
            command.pre_exec(move || {
                for fd in fds {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        let child = match command.spawn() {
            Ok(child) => OwnedChild(child),
            Err(e) => {
                client.append_owner(
                    &run.run_id,
                    "spawn-refused",
                    "denied",
                    None,
                    &json!({"reason":"jail_spawn_failed"}),
                    &claim.owner_token,
                )?;
                return Err(e.into());
            }
        };
        drop(command);
        drop(trace_child);
        drop(control_child);
        drop(gate_child);
        Ok(Self {
            options,
            run,
            claim,
            client,
            evidence,
            expected_image,
            run_dir,
            receipt_path,
            exited: exit_descriptor(child.0.id()),
            child,
            trace: Frames::new(trace_parent)?,
            control: Frames::new(control_parent)?,
            gate: Some(gate_parent),
            gate_open: true,
            captures,
            admitted: false,
            argv_capture: json!({"state":"not_captured"}),
            terminal: None,
            terminal_seen: None,
            control_seq: 0,
            last_trace: None,
            last_heartbeat: Instant::now(),
            exit: None,
            exit_seen: None,
            preparation_deadline: Instant::now() + PREPARATION_LIMIT,
            cancel_sent: false,
        })
    }

    /// Serve the jail until it has exited and every stream has ended.
    fn supervise(&mut self) -> Result<()> {
        loop {
            self.forward_cancellation()?;
            for value in self.control.drain()? {
                self.on_control(serde_json::from_value(value)?)?;
            }
            for event in self.trace.drain()? {
                self.evidence.source(self.client, &event)?;
                self.last_trace = Some(event);
            }
            for capture in &mut self.captures {
                capture.drain()?;
            }
            if self.last_heartbeat.elapsed() >= HEARTBEAT {
                self.evidence.heartbeat(self.client)?;
                self.last_heartbeat = Instant::now();
            }
            if self.exit.is_none() {
                self.exit = self.child.0.try_wait()?;
                if self.exit.is_some() {
                    self.exit_seen = Some(Instant::now());
                }
            }
            if self.exit.is_some()
                && self.trace.eof
                && self.control.eof
                && self.captures.iter().all(|c| c.eof)
            {
                return Ok(());
            }
            self.check_deadlines()?;
            self.wait();
        }
    }

    /// A detached owner asked to cancel: close the gate unopened and ask the
    /// jail to stop. Never twice.
    fn forward_cancellation(&mut self) -> Result<()> {
        if !self.options.detached || self.cancel_sent || !crate::service::cancel_requested() {
            return Ok(());
        }
        self.cancel_sent = true;
        if self.gate_open {
            self.gate_open = false;
            if let Some(gate) = &self.gate {
                gate.shutdown(std::net::Shutdown::Write)?;
            }
        }
        if self.child.0.try_wait()?.is_none() {
            // SAFETY: kill takes scalars; the direct child is unreaped, so its
            // pid cannot have been reused.
            unsafe {
                libc::kill(self.child.0.id() as i32, libc::SIGTERM);
            }
        }
        Ok(())
    }

    fn on_control(&mut self, message: ControlMessage) -> Result<()> {
        if message.schema != records::SCHEMA_CONTROL
            || message.attempt_id != self.run.attempt_id
            || message.seq != self.control_seq + 1
        {
            return Err(error("invalid jail control identity or sequence"));
        }
        self.control_seq = message.seq;
        if self.terminal.is_some() {
            return Err(error("jail emitted control after its terminal record"));
        }
        match message.kind {
            ControlKind::Prepared => {
                if self.cancel_sent {
                    return Ok(());
                }
                if self.admitted {
                    return Err(error("duplicate prepared control"));
                }
                self.admit(&message)
            }
            ControlKind::ExecConfirmed if !self.admitted => {
                Err(error("exec before durable admission"))
            }
            ControlKind::ExecConfirmed => Ok(()),
            ControlKind::Refused | ControlKind::Settled | ControlKind::Unsettled => {
                self.terminal = Some(message);
                self.terminal_seen = Some(Instant::now());
                Ok(())
            }
        }
    }

    /// Admission, in its one order (see [`admission`]).
    fn admit(&mut self, message: &ControlMessage) -> Result<()> {
        let admitted = admission::Prepared::check(&self.receipt_path, message, self.run)?
            .bind_image(self.child.0.id(), self.expected_image)?
            .request(self.options, &self.run_dir, &mut self.argv_capture)?
            .admit(self.client, self.run, self.claim, &mut self.evidence)?;
        let gate = self
            .gate
            .as_mut()
            .filter(|_| self.gate_open)
            .ok_or_else(|| error("gate already consumed"))?;
        self.gate_open = false;
        admitted.release(gate, &self.claim.attempt_id)?;
        self.admitted = true;
        Ok(())
    }

    fn check_deadlines(&self) -> Result<()> {
        if self.control.eof && self.terminal.is_none() && self.exit.is_none() {
            return Err(error(
                "jail closed control without terminal lifecycle evidence",
            ));
        }
        if !self.admitted && Instant::now() >= self.preparation_deadline {
            return Err(error("jail preparation exceeded thirty seconds"));
        }
        if self
            .exit_seen
            .is_some_and(|t| t.elapsed() > WIND_DOWN_LIMIT)
        {
            return Err(error("jail exited without bounded final stream drain"));
        }
        if self
            .terminal_seen
            .is_some_and(|t| t.elapsed() > WIND_DOWN_LIMIT)
            && self.exit.is_none()
        {
            return Err(error(
                "jail did not exit within five seconds of terminal control",
            ));
        }
        Ok(())
    }

    /// Sleep until a stream has bytes, the jail exits, or the next heartbeat
    /// or deadline is due.
    fn wait(&self) {
        let now = Instant::now();
        let due = [
            Some(self.last_heartbeat + HEARTBEAT),
            (!self.admitted).then_some(self.preparation_deadline),
            self.exit_seen.map(|t| t + WIND_DOWN_LIMIT),
            self.terminal_seen.map(|t| t + WIND_DOWN_LIMIT),
        ]
        .into_iter()
        .flatten()
        .min()
        .map_or(Duration::ZERO, |due| due.saturating_duration_since(now));
        let mut fds: Vec<RawFd> = [
            (&self.control, self.control.eof),
            (&self.trace, self.trace.eof),
        ]
        .into_iter()
        .filter(|(_, eof)| !eof)
        .map(|(frames, _)| frames.stream.as_raw_fd())
        .collect();
        fds.extend(
            self.captures
                .iter()
                .filter(|c| !c.eof)
                .map(|c| c.stream.as_raw_fd()),
        );
        let due = match (&self.exited, self.exit) {
            (Some(exited), None) => {
                fds.push(exited.as_raw_fd());
                due
            }
            (None, None) => due.min(EXIT_POLL),
            (_, Some(_)) => due,
        };
        wait_readable(&fds, due);
    }

    /// The launch failed: close the gate for good and stop the jail.
    fn abandon(&mut self) {
        self.gate_open = false;
        self.gate = None;
        terminate(&mut self.child.0);
    }

    /// Let forwarding finish within its grace, then finalize every capture
    /// and make the artifacts durable. The first problem becomes the
    /// launch's failure.
    fn finish_streams(&mut self, failure: &mut Option<crate::protocol::LedgerError>) -> Value {
        let (evidence, client) = (&mut self.evidence, &mut *self.client);
        forwarding_grace(
            &mut self.captures,
            FORWARDING_GRACE,
            &mut self.last_heartbeat,
            failure,
            || evidence.heartbeat(client),
        );
        let mut capture = serde_json::Map::new();
        capture.insert("argv".into(), self.argv_capture.clone());
        let complete = failure.is_none();
        for item in &mut self.captures {
            match item.finish(complete) {
                Ok(value) => {
                    capture.insert(item.name.into(), value);
                }
                Err(problem) => {
                    failure.get_or_insert(problem);
                    capture.insert(
                        item.name.into(),
                        json!({"state":"incomplete","observed_bytes":item.observed,"stored_bytes":item.stored}),
                    );
                }
            }
        }
        for name in ["stdout", "stderr"] {
            capture
                .entry(name)
                .or_insert_with(|| json!({"state":"not_captured"}));
        }
        if let Err(problem) =
            File::open(self.run_dir.join("artifacts")).and_then(|dir| dir.sync_all())
        {
            failure.get_or_insert(problem.into());
        }
        Value::Object(capture)
    }

    /// The terminal receipt, control and trace must corroborate one another;
    /// they decide the recorded outcome. Anything else records unknown.
    fn corroborate(&mut self, capture: Value) -> Result<(&'static str, Value, ControlMessage)> {
        let finalized: Result<_> = (|| {
            let receipt = read_receipt(&self.receipt_path, "terminal")?;
            let typed: Receipt = serde_json::from_value(receipt.clone())?;
            let digest =
                records::semantic::receipt_digest(&receipt).map_err(|e| error(e.to_string()))?;
            let final_control = self
                .terminal
                .take()
                .ok_or_else(|| error("jail exited without a terminal control record"))?;
            Ok((receipt, typed, digest, final_control))
        })();
        let (receipt, typed, digest, final_control) = match finalized {
            Ok(values) => values,
            Err(problem) => {
                self.record_unknown("finalization-failed", "finalization_failed", &capture);
                return Err(problem);
            }
        };
        if typed.attempt_id != self.run.attempt_id
            || digest != final_control.receipt_digest
            || typed.phase != final_control.receipt_phase
            || !records::semantic::receipt(&receipt).is_empty()
            || self.last_trace.as_ref().is_none_or(|event| {
                !records::semantic::trace_ends_with(std::slice::from_ref(event), &receipt)
                    .is_empty()
            })
        {
            self.record_unknown("invalid-final", "final_receipt_or_trace_mismatch", &capture);
            return Err(error("terminal receipt/control/trace did not corroborate"));
        }
        let kind = if !self.admitted && typed.phase == Phase::Refused {
            "denied"
        } else if typed.phase == Phase::Settled && typed.lifetime.tree_empty == Some(true)
            || self.admitted
                && typed.phase == Phase::Refused
                && typed.outcome.kind == records::OutcomeKind::ExecError
                && !typed.exec_observed
                && typed.lifetime.tree_empty == Some(true)
                && typed.lifetime.integrity == "verified"
                && typed.lifetime.verification_scope.as_deref() == Some("attempt_tree")
        {
            "settled"
        } else {
            "outcome_unknown"
        };
        let body = json!({"receipt":receipt,"receipt_digest":digest,"outcome":typed.outcome,
            "coverage":typed.coverage,"capture":capture});
        Ok((kind, body, final_control))
    }

    fn record_unknown(&mut self, request_id: &str, reason: &str, capture: &Value) {
        record_unknown(
            self.options,
            self.run,
            self.client,
            &self.claim.owner_token,
            request_id,
            &unknown_body(reason, capture.as_object()),
        );
    }
}
