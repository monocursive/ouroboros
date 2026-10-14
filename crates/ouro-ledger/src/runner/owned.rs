//! One owned launch, from spawning the jail to recording its outcome.
use std::os::unix::process::ExitStatusExt;

use records::GateFrame;

use super::*;

pub(super) fn run_owned(
    options: &RunOptions,
    image: &File,
    expected_image: &str,
    run: &RunRecord,
    claim: &ClaimedOwner,
    client: &mut Client,
    local_exit_saved: &mut bool,
) -> Result<RunResult> {
    let mut evidence = evidence::Evidence::new(options, run, claim)?;
    let run_dir = options.data.join("ledger").join(&run.run_id);
    // Read the jail's canonical receipt. Its copy fence correctly forbids an
    // additional --receipt inside DATA; the unified DATA root protects the ledger too.
    let receipt_path = options
        .data
        .join("attempts")
        .join(&claim.attempt_id)
        .join("jail.json");
    let (trace_parent, trace_child) = UnixStream::pair()?;
    let (control_parent, control_child) = UnixStream::pair()?;
    let (mut gate_parent, gate_child) = UnixStream::pair()?;
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
        .env("OURO_DATA_DIR", &options.data);
    command.stdin(if options.batch {
        Stdio::null()
    } else {
        Stdio::inherit()
    });
    let mut captures = Vec::new();
    for name in ["stdout", "stderr"] {
        if options.batch || options.captures.iter().any(|s| s == name) {
            // Socket stdio would be host-socket authority; the jail correctly
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
    let mut child = OwnedChild(match command.spawn() {
        Ok(c) => c,
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
    });
    drop(command);
    drop(trace_child);
    drop(control_child);
    drop(gate_child);
    let exited = exit_descriptor(child.0.id());
    let mut trace = Frames::new(trace_parent)?;
    let mut control = Frames::new(control_parent)?;
    let mut gate = Some(&mut gate_parent);
    let mut admitted = false;
    let mut argv_capture = json!({"state":"not_captured"});
    let mut terminal: Option<ControlMessage> = None;
    let mut terminal_seen = None;
    let mut control_seq = 0_u64;
    let mut last_trace: Option<Value> = None;
    let mut last_heartbeat = Instant::now();
    let mut failure = None;
    let mut exit = None;
    let preparation_deadline = Instant::now() + Duration::from_secs(30);
    let mut exit_seen = None;
    let mut cancel_sent = false;
    let result: Result<()> = (|| {
        loop {
            if options.detached && crate::service::cancel_requested() && !cancel_sent {
                cancel_sent = true;
                if let Some(pipe) = gate.take() {
                    pipe.shutdown(std::net::Shutdown::Write)?;
                }
                if child.0.try_wait()?.is_none() {
                    // SAFETY: kill takes scalars; the direct child is unreaped,
                    // so its pid cannot have been reused.
                    unsafe {
                        libc::kill(child.0.id() as i32, libc::SIGTERM);
                    }
                }
            }
            for value in control.drain()? {
                let message: ControlMessage = serde_json::from_value(value)?;
                if message.schema != records::SCHEMA_CONTROL
                    || message.attempt_id != run.attempt_id
                    || message.seq != control_seq + 1
                {
                    return Err(error("invalid jail control identity or sequence"));
                }
                control_seq = message.seq;
                if terminal.is_some() {
                    return Err(error("jail emitted control after its terminal record"));
                }
                match message.kind {
                    ControlKind::Prepared => {
                        if cancel_sent {
                            continue;
                        }
                        if admitted {
                            return Err(error("duplicate prepared control"));
                        }
                        let receipt = read_receipt(&receipt_path, "prepared")?;
                        let typed = check_prepared(&receipt, &message, run)?;
                        // Native Linux exec holds the executing inode against writes
                        // (ETXTBSY). Bind the actual live jail image before durable admission.
                        let executing =
                            File::open(format!("/proc/{}/exe", child.0.id())).map_err(|e| {
                                error(format!(
                                    "binding prepared jail image for pid {}: {e}",
                                    child.0.id()
                                ))
                            })?;
                        if image_digest(&executing)? != expected_image {
                            return Err(error(
                                "executing jail image differs from the prepared image digest",
                            ));
                        }
                        // Capture the exact requested argv only after preparation,
                        // and durably bind its metadata before releasing exec.
                        // Any partial write/sync failure takes the normal failure
                        // path with incomplete metadata and an unopened gate.
                        let mut admission =
                            json!({"receipt":receipt,"receipt_digest":message.receipt_digest});
                        if options.captures.iter().any(|s| s == "argv") {
                            argv_capture::save(
                                &run_dir,
                                &options.argv,
                                options.capture_limit,
                                &mut argv_capture,
                            )?;
                            admission["capture"] = json!({
                                "stdout":{"state":"not_captured"},
                                "stderr":{"state":"not_captured"},
                                "argv":argv_capture,
                            });
                        }
                        client.append_owner(
                            &run.run_id,
                            "admission",
                            "admitted",
                            None,
                            &admission,
                            &claim.owner_token,
                        )?;
                        evidence.admitted()?;
                        let release = GateFrame {
                            schema: records::SCHEMA_GATE.into(),
                            action: "release".into(),
                            attempt_id: claim.attempt_id.clone(),
                            policy_digest: typed.policy.digest,
                        };
                        let mut frame = serde_json::to_vec(&release)?;
                        frame.push(b'\n');
                        let pipe = gate.take().ok_or_else(|| error("gate already consumed"))?;
                        pipe.write_all(&frame)?;
                        pipe.shutdown(std::net::Shutdown::Write)?;
                        admitted = true;
                    }
                    ControlKind::ExecConfirmed => {
                        if !admitted {
                            return Err(error("exec before durable admission"));
                        }
                    }
                    ControlKind::Refused | ControlKind::Settled | ControlKind::Unsettled => {
                        terminal = Some(message);
                        terminal_seen = Some(Instant::now());
                    }
                }
            }
            for event in trace.drain()? {
                evidence.source(client, &event)?;
                last_trace = Some(event);
            }
            for capture in &mut captures {
                capture.drain()?;
            }
            if last_heartbeat.elapsed() >= HEARTBEAT {
                evidence.heartbeat(client)?;
                last_heartbeat = Instant::now();
            }
            if exit.is_none() {
                exit = child.0.try_wait()?;
                if exit.is_some() {
                    exit_seen = Some(Instant::now());
                }
            }
            if exit.is_some() && trace.eof && control.eof && captures.iter().all(|c| c.eof) {
                break;
            }
            if control.eof && terminal.is_none() && exit.is_none() {
                return Err(error(
                    "jail closed control without terminal lifecycle evidence",
                ));
            }
            if !admitted && Instant::now() >= preparation_deadline {
                return Err(error("jail preparation exceeded thirty seconds"));
            }
            if exit_seen.is_some_and(|t| t.elapsed() > Duration::from_secs(5)) {
                return Err(error("jail exited without bounded final stream drain"));
            }
            if terminal_seen.is_some_and(|t| t.elapsed() > Duration::from_secs(5)) && exit.is_none()
            {
                return Err(error(
                    "jail did not exit within five seconds of terminal control",
                ));
            }
            // Sleep until a stream has bytes, the jail exits, or the next
            // heartbeat or deadline is due.
            let now = Instant::now();
            let due = [
                Some(last_heartbeat + HEARTBEAT),
                (!admitted).then_some(preparation_deadline),
                exit_seen.map(|t| t + Duration::from_secs(5)),
                terminal_seen.map(|t| t + Duration::from_secs(5)),
            ]
            .into_iter()
            .flatten()
            .min()
            .map_or(Duration::ZERO, |due| due.saturating_duration_since(now));
            let mut fds: Vec<RawFd> = [(&control, control.eof), (&trace, trace.eof)]
                .into_iter()
                .filter(|(_, eof)| !eof)
                .map(|(frames, _)| frames.stream.as_raw_fd())
                .collect();
            fds.extend(
                captures
                    .iter()
                    .filter(|c| !c.eof)
                    .map(|c| c.stream.as_raw_fd()),
            );
            let due = match (&exited, exit) {
                (Some(exited), None) => {
                    fds.push(exited.as_raw_fd());
                    due
                }
                (None, None) => due.min(EXIT_POLL),
                (_, Some(_)) => due,
            };
            wait_readable(&fds, due);
        }
        Ok(())
    })();
    if let Err(e) = result {
        failure = Some(e);
        gate.take();
        drop(gate_parent);
        terminate(&mut child.0);
    }
    forwarding_grace(
        &mut captures,
        FORWARDING_GRACE,
        &mut last_heartbeat,
        &mut failure,
        || evidence.heartbeat(client),
    );
    let mut capture = serde_json::Map::new();
    capture.insert("argv".into(), argv_capture);
    let complete = failure.is_none();
    for item in &mut captures {
        match item.finish(complete) {
            Ok(value) => {
                capture.insert(item.name.into(), value);
            }
            Err(problem) => {
                failure.get_or_insert(problem);
                capture.insert(item.name.into(), json!({"state":"incomplete","observed_bytes":item.observed,"stored_bytes":item.stored}));
            }
        }
    }
    for name in ["stdout", "stderr"] {
        capture
            .entry(name)
            .or_insert_with(|| json!({"state":"not_captured"}));
    }
    if let Err(problem) = File::open(run_dir.join("artifacts")).and_then(|dir| dir.sync_all()) {
        failure.get_or_insert(problem.into());
    }
    if let Some(problem) = failure {
        // An unreachable writer supplies no acknowledgement. A later orphan reconciliation says unknown.
        record_unknown(
            options,
            run,
            client,
            &claim.owner_token,
            "owner-failure",
            &unknown_body("owner_or_evidence_failure", Some(&capture)),
        );
        return Err(problem);
    }
    let finalized: Result<_> = (|| {
        let receipt = read_receipt(&receipt_path, "terminal")?;
        let typed: Receipt = serde_json::from_value(receipt.clone())?;
        let digest =
            records::semantic::receipt_digest(&receipt).map_err(|e| error(e.to_string()))?;
        let final_control =
            terminal.ok_or_else(|| error("jail exited without a terminal control record"))?;
        Ok((receipt, typed, digest, final_control))
    })();
    let (receipt, typed, digest, final_control) = match finalized {
        Ok(values) => values,
        Err(problem) => {
            record_unknown(
                options,
                run,
                client,
                &claim.owner_token,
                "finalization-failed",
                &unknown_body("finalization_failed", Some(&capture)),
            );
            return Err(problem);
        }
    };
    if typed.attempt_id != run.attempt_id
        || digest != final_control.receipt_digest
        || typed.phase != final_control.receipt_phase
        || !records::semantic::receipt(&receipt).is_empty()
        || last_trace.as_ref().is_none_or(|event| {
            !records::semantic::trace_ends_with(std::slice::from_ref(event), &receipt).is_empty()
        })
    {
        record_unknown(
            options,
            run,
            client,
            &claim.owner_token,
            "invalid-final",
            &unknown_body("final_receipt_or_trace_mismatch", Some(&capture)),
        );
        return Err(error("terminal receipt/control/trace did not corroborate"));
    }
    let kind = if !admitted && typed.phase == Phase::Refused {
        "denied"
    } else if typed.phase == Phase::Settled && typed.lifetime.tree_empty == Some(true)
        || admitted
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
    let completion = evidence.finish(client, kind, json!({"receipt":receipt,"receipt_digest":digest,"outcome":typed.outcome,"coverage":typed.coverage,"capture":capture}), final_control);
    *local_exit_saved = evidence.local_exit_saved;
    completion?;
    let record = client.show(&run.run_id)?;
    let exit_code = exit.map_or(1, |s| {
        s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
    });
    Ok(RunResult { record, exit_code })
}
