use super::*;
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd as _, RawFd},
        unix::process::CommandExt,
    },
};
const CONTROL: RawFd = 198;

fn attach(command: &mut Command, fd: RawFd) {
    command.args(["--control-fd", "198"]);
    // SAFETY: the source stays owned until spawn; dup2 is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, CONTROL) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
fn pipe() -> (File, File) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}
fn parse(bytes: &[u8]) -> RunRecord {
    assert!(bytes.len() <= ouro_ledger::protocol::MAX_FRAME_BYTES);
    assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn real_control_separates_child_streams_closes_inherited_fds_and_preserves_exit_codes() {
    let Some(jail) = live_jail() else {
        return;
    };
    for profile in ["tool", "none"] {
        for sink in ["file", "pipe", "socket"] {
            let mut fixture = Fixture::new(&jail);
            // The result socket must reach EOF despite a newly started writer remaining alive.
            fixture.writer.kill();
            fixture.on_demand = true;
            let mut command = fixture.command_with_profile("control-exit", false, profile);
            command.args(["--json", "--capture", "stdout", "--capture", "stderr"]);
            let path = fixture._temp.path().join("control.json");
            let (send, receive): (File, Option<Box<dyn Read + Send>>) = match sink {
                "file" => (File::create(&path).unwrap(), None),
                "pipe" => {
                    let (r, w) = pipe();
                    (w, Some(Box::new(r)))
                }
                _ => {
                    let (w, r) = UnixStream::pair().unwrap();
                    r.set_read_timeout(Some(COMMAND_LIMIT)).unwrap();
                    (File::from(OwnedFd::from(w)), Some(Box::new(r)))
                }
            };
            attach(&mut command, send.as_raw_fd());
            command.args(["--", "/bin/sh", "-c", "test ! -e /proc/self/fd/198 || exit 99; printf 'out\\033\\377'; printf 'err\\000' >&2; exit 7"]);
            let reader = receive.map(collect);
            let mut process = Process::spawn(&mut command, true);
            drop(send);
            let output = process.finish();
            assert_eq!(
                output.status.code(),
                Some(7),
                "{profile}/{sink}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"out\x1b\xff");
            assert_eq!(output.stderr, b"err\0");
            let bytes = reader
                .map(|r| r.join().unwrap())
                .unwrap_or_else(|| fs::read(path).unwrap());
            let run = parse(&bytes);
            assert_eq!(run.state, "settled");
            assert_eq!(run.payload["io"]["control"], "separate_fd");
            assert_eq!(run.payload["io"]["mode"], "foreground");
            assert_eq!(run.outcome.as_ref().unwrap()["code"], 7);
            assert_eq!(
                serde_json::to_value(&run).unwrap(),
                serde_json::to_value(fixture.client().show(&run.run_id).unwrap()).unwrap()
            );
            assert_eq!(
                run.child_protection,
                if profile == "tool" {
                    "enforced"
                } else {
                    "unprotected"
                }
            );
            println!(
                "control/{profile}/{sink}: child bytes intact, fd isolated, nonzero exit and durable result preserved"
            );
        }
    }
}

#[test]
fn real_control_disconnect_and_backpressure_do_not_rewrite_outcome_or_repeat_execution() {
    let Some(jail) = live_jail() else {
        return;
    };
    for profile in ["tool", "none"] {
        for fault in ["disconnect", "stalled", "nonblocking-stalled"] {
            let fixture = Fixture::new(&jail);
            let (reader, mut sender) = pipe();
            if fault != "disconnect" {
                assert_eq!(
                    unsafe { libc::fcntl(sender.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
                    0
                );
                loop {
                    match sender.write(&[0; 8192]) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        other => panic!("cannot fill pipe: {other:?}"),
                    }
                }
                if fault == "stalled" {
                    assert_eq!(
                        unsafe { libc::fcntl(sender.as_raw_fd(), libc::F_SETFL, 0) },
                        0
                    );
                }
            }
            let make = |fd| {
                let mut command = fixture.command_with_profile("control-failure", false, profile);
                attach(&mut command, fd);
                command.args(["--", "/bin/sh", "-c", "printf x >> executions; touch started; while test ! -f finish; do sleep 0.02; done; printf child-done"]);
                command
            };
            let mut process = Process::spawn(&mut make(sender.as_raw_fd()), true);
            drop(sender);
            let run = fixture.wait_started(&mut process);
            // Disconnect only after admission; an already-dead consumer refuses earlier.
            let retained_reader = if fault == "disconnect" {
                drop(reader);
                None
            } else {
                Some(reader)
            };
            fs::write(fixture.workspace.join("finish"), b"").unwrap();
            let start = Instant::now();
            let output = process.finish();
            assert_eq!(output.status.code(), Some(1));
            assert!(start.elapsed() < Duration::from_secs(6));
            assert_eq!(output.stdout, b"child-done");
            assert!(String::from_utf8_lossy(&output.stderr).contains("result delivery failed"));
            assert!(String::from_utf8_lossy(&output.stderr).contains(&run.run_id));
            let settled = fixture.client().show(&run.run_id).unwrap();
            assert_eq!(settled.state, "settled");
            assert_eq!(settled.outcome.as_ref().unwrap()["code"], 0);
            fixture.assert_tree_stopped(&settled);
            let canonical = fixture.events(&settled);
            drop(retained_reader);
            let result = fixture._temp.path().join("retry.json");
            let file = File::create(&result).unwrap();
            let replay = Process::spawn(&mut make(file.as_raw_fd()), true).finish();
            assert!(replay.status.success());
            assert!(replay.stdout.is_empty());
            assert!(replay.stderr.is_empty());
            assert_eq!(parse(&fs::read(result).unwrap()).run_id, run.run_id);
            assert_eq!(fixture.events(&settled), canonical);
            assert_eq!(
                fs::read(fixture.workspace.join("executions")).unwrap(),
                b"x"
            );
            println!(
                "control/{profile}/{fault}: bounded delivery failure, settled outcome, same-request replay, one execution"
            );
        }
    }
}

#[test]
fn real_control_implies_json_and_batch_control_has_no_stdout_response() {
    let Some(jail) = live_jail() else {
        return;
    };
    for batch in [false, true] {
        let fixture = Fixture::new(&jail);
        let path = fixture._temp.path().join("result.json");
        let file = File::create(&path).unwrap();
        let mut command = fixture.command("control-mode", batch);
        attach(&mut command, file.as_raw_fd());
        command.args(["--", "/bin/sh", "-c", "printf child-output"]);
        let result = Process::spawn(&mut command, true).finish();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            result.stdout,
            if batch {
                b"".as_slice()
            } else {
                b"child-output".as_slice()
            }
        );
        assert!(result.stderr.is_empty());
        assert_eq!(parse(&fs::read(path).unwrap()).state, "settled");
    }
    println!(
        "control/modes: foreground without --json and batch both use only the separate result fd"
    );
}
