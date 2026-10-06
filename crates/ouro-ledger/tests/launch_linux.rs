//! Real jail launches: durable admission, one execution, bounded I/O and conservative recovery.
#![cfg(target_os = "linux")]

use std::{
    fs,
    io::Read,
    os::{
        fd::{FromRawFd as _, OwnedFd},
        unix::{fs::PermissionsExt as _, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::OnceLock,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use ouro_fixture::harness;
use ouro_ledger::{
    daemon::{self, Client},
    protocol::RunRecord,
};
use ouro_records::records;
use serde_json::Value;

const COMMAND_LIMIT: Duration = Duration::from_secs(20);

fn live_jail() -> Option<PathBuf> {
    static JAIL: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    let result = JAIL.get_or_init(|| {
        let path = std::env::var_os("OURO_JAIL_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_BIN_EXE_ouro-ledger")).with_file_name("ouro-jail")
            });
        let mut command = Command::new(&path);
        command.args(["doctor", "--json"]);
        let output = Process::try_spawn(&mut command, true)
            .map_err(|error| format!("real ouro-jail doctor unavailable: {error}"))?
            .finish();
        let doctor: Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("real ouro-jail doctor did not return JSON: {error}"))?;
        if !output.status.success() || doctor["component"] != "ouro-jail" || doctor["ready"] != true
        {
            return Err(
                "real ouro-jail doctor does not have the required live capabilities".into(),
            );
        }
        Ok(path)
    });
    match result {
        Ok(path) => Some(path.clone()),
        Err(reason) => {
            harness::skip_or_fail(reason);
            None
        }
    }
}

struct Process {
    child: Child,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

fn collect(reader: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.take(2 * 1_048_576).read_to_end(&mut bytes).unwrap();
        bytes
    })
}

impl Process {
    fn spawn(command: &mut Command, drain_stdout: bool) -> Self {
        Self::try_spawn(command, drain_stdout).unwrap()
    }

    fn try_spawn(command: &mut Command, drain_stdout: bool) -> std::io::Result<Self> {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self::from_child(child, drain_stdout))
    }

    fn from_child(mut child: Child, drain_stdout: bool) -> Self {
        let stdout = drain_stdout.then(|| collect(child.stdout.take().unwrap()));
        let stderr = Some(collect(child.stderr.take().unwrap()));
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn finish(&mut self) -> Output {
        let deadline = Instant::now() + COMMAND_LIMIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "ledger command did not terminate within {COMMAND_LIMIT:?}"
            );
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = if let Some(reader) = self.stdout.take() {
            reader.join().unwrap()
        } else if let Some(stdout) = self.child.stdout.take() {
            let mut bytes = Vec::new();
            stdout.take(2 * 1_048_576).read_to_end(&mut bytes).unwrap();
            bytes
        } else {
            Vec::new()
        };
        Output {
            status,
            stdout,
            stderr: self.stderr.take().unwrap().join().unwrap(),
        }
    }

    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    workspace: PathBuf,
    jail: PathBuf,
    writer: Process,
    on_demand: bool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.on_demand {
            let result = stop_on_demand_writer(&self.data);
            if !thread::panicking() {
                result.expect("on-demand fixture writer must stop before its data is removed");
            }
        }
        if self.writer.child.try_wait().ok().flatten().is_none() {
            let _ = self.writer.child.kill();
            let _ = self.writer.child.wait();
        }
    }
}

impl Fixture {
    fn new(jail: &Path) -> Self {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let data = temp.path().join("data");
        let config = temp.path().join("config");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&config).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&workspace).unwrap();
        // A development build may be group writable. Install the exact bytes privately
        // so the launcher's executable-permission guard is exercised honestly.
        let pinned = temp.path().join("ouro-jail");
        fs::copy(jail, &pinned).unwrap();
        fs::set_permissions(&pinned, fs::Permissions::from_mode(0o700)).unwrap();
        let writer = Self::start_writer(&data);
        Self {
            _temp: temp,
            data,
            config,
            workspace,
            jail: pinned,
            writer,
            on_demand: false,
        }
    }

    fn start_writer(data: &Path) -> Process {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
        command.arg("--data-dir").arg(data).arg("serve");
        let mut writer = Process::spawn(&mut command, true);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(mut client) = Client::connect(data) {
                client.ping().unwrap();
                return writer;
            }
            assert!(
                writer.child.try_wait().unwrap().is_none(),
                "writer refused its private fixture"
            );
            assert!(Instant::now() < deadline, "writer did not become ready");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn command(&self, request: &str, batch: bool) -> Command {
        self.command_with_profile(request, batch, "tool")
    }

    fn command_with_profile(&self, request: &str, batch: bool, profile: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
        // Real launches must use this fixture's operator configuration. In
        // particular, `none` correctly refuses ambient trusted launch profiles.
        command.env("OURO_CONFIG_DIR", &self.config);
        command
            .arg("--data-dir")
            .arg(&self.data)
            .arg("run")
            .arg("--request-id")
            .arg(request)
            .arg("--jail-bin")
            .arg(&self.jail)
            .arg("--workspace")
            .arg(&self.workspace)
            .args(["--jail", profile, "--limit", "wall=10s"]);
        if batch {
            command.args(["--io", "batch", "--json"]);
        }
        command
    }

    fn run(&self, command: &mut Command) -> (Output, RunRecord) {
        let output = Process::spawn(command, true).finish();
        let record = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "run did not return a record ({error}): status {} stderr {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output, record)
    }

    fn client(&self) -> Client {
        Client::connect(&self.data).unwrap()
    }

    fn events(&self, record: &RunRecord) -> Vec<Value> {
        fs::read(
            self.data
                .join("ledger")
                .join(&record.run_id)
                .join("events-0001.ndjson"),
        )
        .unwrap()
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
    }

    fn wait_started(&self, process: &mut Process) -> RunRecord {
        let deadline = Instant::now() + COMMAND_LIMIT;
        loop {
            if self.workspace.join("started").exists() {
                let runs = self.client().runs().unwrap();
                assert_eq!(runs.len(), 1);
                assert_eq!(
                    runs[0].state, "admitted",
                    "target marker must follow durable admission"
                );
                return runs.into_iter().next().unwrap();
            }
            if process.child.try_wait().unwrap().is_some() {
                let output = process.finish();
                panic!(
                    "launch exited before its target marker: {} stdout {} stderr {}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(Instant::now() < deadline, "target did not start");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_unknown(&self, run_id: &str) -> RunRecord {
        let record = self.client().show(run_id).unwrap();
        assert_eq!(record.state, "outcome_unknown", "{record:?}");
        assert_eq!(record.outcome.as_ref().unwrap()["unknown"], true);
        assert!(
            !record
                .receipts
                .iter()
                .any(|receipt| receipt["phase"] == "settled")
        );
        record
    }

    fn assert_tree_stopped(&self, run: &RunRecord) {
        let path = self.receipt_path(run);
        let deadline = Instant::now() + COMMAND_LIMIT;
        loop {
            if let Ok(bytes) = fs::read(&path)
                && let Ok(receipt) = serde_json::from_slice::<Value>(&bytes)
                && matches!(receipt["phase"].as_str(), Some("settled" | "unsettled"))
            {
                assert_eq!(receipt["attempt_id"], run.attempt_id);
                assert!(records::semantic::receipt(&receipt).is_empty(), "{receipt}");
                assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt}");
                assert_eq!(receipt["lifetime"]["integrity"], "verified", "{receipt}");
                assert!(receipt["lifetime"]["verified_at"].is_string());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "jail did not corroborate termination of {} within {COMMAND_LIMIT:?}",
                run.attempt_id
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn receipt_path(&self, run: &RunRecord) -> PathBuf {
        self.data
            .join("attempts")
            .join(&run.attempt_id)
            .join("jail.json")
    }
}

fn stop_on_demand_writer(data: &Path) -> Result<(), String> {
    let stream = match UnixStream::connect(data.join("ledger/serve.sock")) {
        Ok(stream) => stream,
        Err(_) => return Ok(()), // Startup itself may have refused before creating a writer.
    };
    let peer = daemon::peer_credentials(&stream).map_err(|error| error.to_string())?;
    let command =
        fs::read(format!("/proc/{}/cmdline", peer.pid)).map_err(|error| error.to_string())?;
    let argv: Vec<&[u8]> = command
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    assert!(argv.windows(2).any(|pair| pair
        == [
            b"--data-dir".as_slice(),
            data.as_os_str().as_encoded_bytes()
        ]));
    assert_eq!(argv.last().copied(), Some(b"serve".as_slice()));
    // Pin the live server before signaling; never signal a cached/recycled numeric PID.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid as libc::pid_t, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    if !daemon::peer_alive(&peer) {
        return Err("on-demand writer birth changed before cleanup".into());
    }
    use std::os::fd::AsRawFd as _;
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, 2000) } != 1 {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        if unsafe { libc::poll(&mut poll, 1, 2000) } != 1 {
            return Err("on-demand writer did not stop within its cleanup bound".into());
        }
    }
    Ok(())
}

#[test]
fn durable_admission_precedes_real_exec_and_replay_never_executes_twice() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let script = "printf x >> executions; printf done; kill -TERM $$";
    let make = || {
        let mut command = fixture.command("one-execution", true);
        command.args(["--capture", "stdout", "--", "/bin/sh", "-c", script]);
        command
    };
    let (first_output, first) = fixture.run(&mut make());
    assert_eq!(first_output.status.code(), Some(143), "{first:?}");
    assert_eq!(first.state, "settled");
    assert_eq!(first.child_protection, "enforced");
    assert_eq!(
        first.receipts.last().unwrap()["lifetime"]["tree_empty"],
        true
    );
    let events = fixture.events(&first);
    let admission = events
        .iter()
        .position(|event| event["kind"] == "admitted")
        .unwrap();
    let exec = events
        .iter()
        .position(|event| event["operation"] == "proc.exec" && event["stage"] == "result")
        .unwrap();
    assert!(admission < exec);
    assert_eq!(first.capture["stderr"]["state"], "not_captured");
    let (replay_output, replay) = fixture.run(&mut make());
    assert_eq!(replay_output.status.code(), first_output.status.code());
    assert_eq!(first.run_id, replay.run_id);
    assert_eq!(first.attempt_id, replay.attempt_id);
    assert_eq!(first.chain.head_seq, replay.chain.head_seq);
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
    assert!(fixture.client().verify(Some(&first.run_id)).unwrap()[0].local_consistency);
}

#[test]
fn contained_child_cannot_read_or_mutate_the_ledger_or_connect_to_its_writer() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let probe = fixture.workspace.join("ouro-fixture");
    fs::copy(harness::fixture_path(), &probe).unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(fixture.data.join("sentinel"), b"private ledger sentinel").unwrap();
    let script = r#"
        touch started
        while [ ! -f target-receipt ]; do sleep 0.02; done
        read -r receipt < target-receipt
        if ls "$1/ledger" || cat "$1/sentinel"; then exit 91; fi
        if (printf forged > "$1/ledger/injected"); then exit 92; fi
        if cat "$receipt" || (printf forged > "$receipt"); then exit 93; fi
        if ./ouro-fixture unix-connect "$1/ledger/serve.sock"; then exit 94; fi
        printf private-state-blocked
    "#;
    let mut command = fixture.command("private-ledger", true);
    command
        .args([
            "--capture",
            "stdout",
            "--",
            "/bin/sh",
            "-c",
            script,
            "probe",
        ])
        .arg(&fixture.data);
    let mut owner = Process::spawn(&mut command, true);
    let prepared = fixture.wait_started(&mut owner);
    let receipt = fixture.receipt_path(&prepared);
    assert!(
        receipt.is_file(),
        "probe must attempt the actual existing jail receipt"
    );
    fs::write(
        fixture.workspace.join("target-receipt"),
        format!("{}\n", receipt.display()),
    )
    .unwrap();
    let output = owner.finish();
    let run: RunRecord = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output.status.success(), "{run:?}");
    assert_eq!(run.state, "settled");
    assert_eq!(run.child_protection, "enforced");
    assert_eq!(
        fs::read(fixture.data.join("sentinel")).unwrap(),
        b"private ledger sentinel"
    );
    assert!(!fixture.data.join("ledger/injected").exists());
    let capture = fs::read(
        fixture
            .data
            .join("ledger")
            .join(&run.run_id)
            .join("artifacts/stdout.bin"),
    )
    .unwrap();
    let text = String::from_utf8(capture).unwrap();
    assert!(text.contains("private-state-blocked"));
    let socket_report: Value = text
        .lines()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .unwrap();
    assert_eq!(socket_report["op"], "socket");
    assert_eq!(socket_report["errno"], "EPERM");
    assert!(fixture.client().verify(Some(&run.run_id)).unwrap()[0].local_consistency);
}

#[test]
fn explicit_none_profile_remains_unprotected_after_real_launch_and_verification() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command_with_profile("explicit-none", true, "none");
    command.args(["--", "/bin/sh", "-c", "printf plain > plain-executed"]);
    let (output, run) = fixture.run(&mut command);
    assert!(output.status.success(), "{run:?}");
    assert_eq!(run.state, "settled");
    assert_eq!(run.child_protection, "unprotected");
    assert_eq!(
        fs::read(fixture.workspace.join("plain-executed")).unwrap(),
        b"plain"
    );
    let verify = fixture.client().verify(Some(&run.run_id)).unwrap();
    assert!(verify[0].local_consistency);
    assert_eq!(verify[0].child_protection, "unprotected");
}

#[test]
fn failed_exec_retains_corroborated_error_without_a_second_attempt() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let make = || {
        let mut command = fixture.command("missing-image", true);
        command.args(["--", "/ouro-ledger-test-no-such-executable"]);
        command
    };
    let (output, run) = fixture.run(&mut make());
    assert_eq!(output.status.code(), Some(125));
    // The existing jail resolves this image by attempting exec after gate release.
    // Preserve the actual admission and refused receipt while recording the
    // corroborated exec failure as the ledger's known terminal outcome.
    assert_eq!(run.state, "settled");
    assert_eq!(run.outcome.as_ref().unwrap()["kind"], "exec_error");
    let receipt = run.receipts.last().unwrap();
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["outcome"]["kind"], "exec_error");
    assert_eq!(receipt["outcome"]["cause"], "ENOENT");
    assert_eq!(receipt["exec_observed"], false);
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    assert!(
        fixture
            .events(&run)
            .iter()
            .any(|event| event["kind"] == "admitted")
    );
    let (retry, replay) = fixture.run(&mut make());
    assert_eq!(retry.status.code(), output.status.code());
    assert_eq!(replay.run_id, run.run_id);
    assert_eq!(replay.attempt_id, run.attempt_id);
    assert_eq!(run.chain.head_seq, replay.chain.head_seq);
    assert_eq!(
        fs::read_dir(fixture.data.join("attempts")).unwrap().count(),
        1
    );
}

#[test]
fn invalid_inherited_stdout_is_denied_before_admission_and_never_executes() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command("invalid-inherited-output", false);
    command.args(["--", "/bin/sh", "-c", "touch must-not-execute"]);
    let (_reader, writer) = UnixStream::pair().unwrap();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
        .stderr(Stdio::piped());
    let first = Process::from_child(command.spawn().unwrap(), false).finish();
    assert_eq!(first.status.code(), Some(125));
    let runs = fixture.client().runs().unwrap();
    assert_eq!(runs.len(), 1);
    let run = &runs[0];
    assert_eq!(run.state, "denied");
    assert_eq!(
        run.receipts.last().unwrap()["outcome"]["error"]["code"],
        "invalid_fd"
    );
    assert!(
        !fixture
            .events(run)
            .iter()
            .any(|event| event["kind"] == "admitted")
    );
    assert!(!fixture.workspace.join("must-not-execute").exists());
    let replay = Process::from_child(command.spawn().unwrap(), false).finish();
    assert_eq!(replay.status.code(), first.status.code());
    assert_eq!(
        fixture.client().show(&run.run_id).unwrap().chain.head_seq,
        run.chain.head_seq
    );
}

#[test]
fn opted_capture_stops_storing_at_the_cap_and_keeps_draining_the_real_child() {
    let Some(jail) = live_jail() else {
        return;
    };
    let mut fixture = Fixture::new(&jail);
    // Exercise the production on-demand path, then identify/stop its exact
    // detached writer through the private socket and a pinned Linux pidfd.
    fixture.writer.kill();
    fixture.on_demand = true;
    let mut command = fixture.command("bounded-capture", true);
    command.args([
        "--capture",
        "stdout",
        "--capture-limit",
        "64",
        "--",
        "/bin/sh",
        "-c",
        "printf '%05000d' 0",
    ]);
    let (output, run) = fixture.run(&mut command);
    assert!(output.status.success(), "{run:?}");
    assert_eq!(run.state, "settled");
    assert_eq!(run.capture["stdout"]["observed_bytes"], 5000);
    assert_eq!(run.capture["stdout"]["stored_bytes"], 64);
    assert_eq!(run.capture["stdout"]["truncated"], true);
    let artifact = fixture
        .data
        .join("ledger")
        .join(run.run_id)
        .join("artifacts/stdout.bin");
    assert_eq!(fs::metadata(artifact).unwrap().len(), 64);
}

#[test]
fn owner_death_is_reconciled_as_unknown_and_never_relaunched() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command("dead-owner", true);
    command.args([
        "--",
        "/bin/sh",
        "-c",
        "printf x >> executions; touch started; sleep 30",
    ]);
    let mut owner = Process::spawn(&mut command, true);
    let run = fixture.wait_started(&mut owner);
    owner.kill();
    fixture.assert_tree_stopped(&run);
    fixture.client().settle_orphans().unwrap();
    fixture.assert_unknown(&run.run_id);
    let retry = Process::spawn(&mut command, true).finish();
    assert!(!retry.status.success());
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
}

#[test]
fn writer_death_stops_the_owner_and_recovery_remains_unknown() {
    let Some(jail) = live_jail() else {
        return;
    };
    let mut fixture = Fixture::new(&jail);
    let mut command = fixture.command("dead-writer", true);
    command.args([
        "--",
        "/bin/sh",
        "-c",
        "printf x >> executions; touch started; sleep 30",
    ]);
    let mut owner = Process::spawn(&mut command, true);
    let run = fixture.wait_started(&mut owner);
    fixture.writer.kill();
    assert!(!owner.finish().status.success());
    fixture.assert_tree_stopped(&run);
    fixture.writer = Fixture::start_writer(&fixture.data);
    fixture.client().settle_orphans().unwrap();
    fixture.assert_unknown(&run.run_id);
    let retry = Process::spawn(&mut command, true).finish();
    assert!(!retry.status.success());
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
}

#[test]
fn an_unread_foreground_capture_sink_cannot_hold_the_launch_owner_forever() {
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command("stalled-forwarding", false);
    command.args([
        "--capture",
        "stdout",
        "--capture-limit",
        "8",
        "--",
        "/bin/sh",
        "-c",
        "head -c 2097152 /dev/zero; sleep 30",
    ]);
    let started = Instant::now();
    let output = Process::spawn(&mut command, false).finish();
    assert!(!output.status.success());
    assert!(started.elapsed() < COMMAND_LIMIT);
    let runs = fixture.client().runs().unwrap();
    assert_eq!(runs.len(), 1);
    let run = fixture.assert_unknown(&runs[0].run_id);
    fixture.assert_tree_stopped(&run);
    assert_eq!(run.capture["stdout"]["state"], "incomplete");
    assert!(run.capture["stdout"]["stored_bytes"].as_u64().unwrap() <= 8);
}

fn detached_fixture() -> Option<Fixture> {
    let jail = live_jail()?;
    let readiness = ouro_ledger::service::probe();
    if readiness["available"] != true {
        harness::skip_or_fail(&format!("independent owner unavailable: {readiness}"));
        return None;
    }
    let mut fixture = Fixture::new(&jail);
    fixture.writer.kill();
    fixture.on_demand = true;
    Some(fixture)
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + COMMAND_LIMIT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "missing fixture marker {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn signal_birth(peer: &ouro_ledger::protocol::Peer, signal: i32) {
    use std::os::fd::AsRawFd as _;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid as libc::pid_t, 0) };
    assert!(fd >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    assert!(daemon::peer_alive(peer));
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
}

#[test]
fn detached_submitter_exit_preserves_owner_output_and_one_execution() {
    let Some(fixture) = detached_fixture() else {
        return;
    };
    let make = || {
        let mut command = fixture.command("detached-one-execution", true);
        command.env("OURO_TEST_LAUNCH_SECRET", "bootstrap-only-canary-289101");
        command.args(["--detach", "--capture", "stdout", "--capture-limit", "64", "--", "/bin/sh", "-c",
            "printf x >> executions; touch started; sleep 1; printf '%05000d' 0; printf done > finished"]);
        command
    };
    let (output, first) = fixture.run(&mut make());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(first.payload["owner_lifetime"], "systemd_user_service");
    wait_for_file(&fixture.workspace.join("started"));
    let peer = first.owner.as_ref().unwrap();
    let writer_peer = daemon::peer_credentials(
        &UnixStream::connect(fixture.data.join("ledger/serve.sock")).unwrap(),
    )
    .unwrap();
    assert!(
        daemon::peer_alive(peer),
        "the owner must outlive the submitter"
    );
    let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", peer.pid)).unwrap();
    assert!(cgroup.contains("ouro-ledger-owner-") && cgroup.contains(".service"));
    let cmdline = fs::read(format!("/proc/{}/cmdline", peer.pid)).unwrap();
    assert!(!String::from_utf8_lossy(&cmdline).contains("printf"));
    assert!(!String::from_utf8_lossy(&cmdline).contains("bootstrap-only-canary"));
    let (_, replay) = fixture.run(&mut make());
    assert_eq!(first.run_id, replay.run_id);
    assert_eq!(first.owner, replay.owner);
    let mut wait = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
    wait.arg("--data-dir")
        .arg(&fixture.data)
        .arg("wait")
        .arg(&first.run_id)
        .args(["--timeout", "15", "--json"]);
    let output = Process::spawn(&mut wait, true).finish();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settled: RunRecord = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(settled.run_id, first.run_id);
    assert_eq!(settled.state, "settled");
    assert!(
        daemon::peer_alive(&writer_peer),
        "the writer must outlive an owner service"
    );
    assert_eq!(settled.capture["stdout"]["observed_bytes"], 5000);
    assert_eq!(settled.capture["stdout"]["stored_bytes"], 64);
    assert_eq!(settled.capture["stdout"]["truncated"], true);
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
    assert_eq!(
        fs::read(fixture.workspace.join("finished")).unwrap(),
        b"done"
    );
    assert_eq!(
        fs::read(
            fixture
                .data
                .join("ledger")
                .join(&first.run_id)
                .join("artifacts/stdout.bin")
        )
        .unwrap()
        .len(),
        64
    );
    assert!(
        !serde_json::to_string(&fixture.events(&settled))
            .unwrap()
            .contains("bootstrap-only-canary")
    );
    assert!(fixture.client().verify(Some(&first.run_id)).unwrap()[0].local_consistency);
    assert_eq!(fixture.run(&mut make()).1.run_id, first.run_id);
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
}

#[test]
fn detached_lost_client_output_does_not_cancel_or_duplicate_the_attempt() {
    let Some(fixture) = detached_fixture() else {
        return;
    };
    let make = || {
        let mut command = fixture.command("detached-lost-reply", true);
        command.args([
            "--detach",
            "--",
            "/bin/sh",
            "-c",
            "printf x >> executions; sleep 1; touch finished",
        ]);
        command
    };
    let mut child = make()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take()); // The submitting terminal cannot receive the run id.
    let output = Process::from_child(child, false).finish();
    assert!(!output.status.success());
    let (_, replay) = fixture.run(&mut make());
    let settled = ouro_ledger::service::wait(&fixture.data, &replay.run_id, COMMAND_LIMIT).unwrap();
    assert_eq!(settled.state, "settled");
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
    assert_eq!(fixture.client().runs().unwrap().len(), 1);
}

#[test]
fn detached_cancel_requests_stop_then_waits_for_verified_settlement() {
    let Some(fixture) = detached_fixture() else {
        return;
    };
    let mut command = fixture.command("detached-cancel", true);
    command.args([
        "--detach",
        "--",
        "/bin/sh",
        "-c",
        "touch started; sleep 8; touch must-not-finish",
    ]);
    let (_, run) = fixture.run(&mut command);
    wait_for_file(&fixture.workspace.join("started"));
    let mut cancel = Command::new(env!("CARGO_BIN_EXE_ouro-ledger"));
    cancel
        .arg("--data-dir")
        .arg(&fixture.data)
        .arg("cancel")
        .arg(&run.run_id)
        .arg("--json");
    let output = Process::spawn(&mut cancel, true).finish();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["status"],
        "stop_requested"
    );
    let settled = ouro_ledger::service::wait(&fixture.data, &run.run_id, COMMAND_LIMIT).unwrap();
    assert_eq!(settled.state, "settled", "{settled:?}");
    assert_eq!(
        settled.receipts.last().unwrap()["lifetime"]["tree_empty"],
        true
    );
    assert!(!fixture.workspace.join("must-not-finish").exists());
    assert_eq!(
        ouro_ledger::service::cancel(&fixture.data, &run.run_id).unwrap()["status"],
        "already_terminal"
    );
}

#[test]
fn detached_owner_death_stops_tree_and_replay_preserves_unknown() {
    let Some(fixture) = detached_fixture() else {
        return;
    };
    let make = || {
        let mut command = fixture.command("detached-owner-loss", true);
        command.args([
            "--detach",
            "--",
            "/bin/sh",
            "-c",
            "printf x >> executions; touch started; sleep 8; touch must-not-finish",
        ]);
        command
    };
    let (_, run) = fixture.run(&mut make());
    wait_for_file(&fixture.workspace.join("started"));
    signal_birth(run.owner.as_ref().unwrap(), libc::SIGKILL);
    fixture.assert_tree_stopped(&run);
    fixture.client().settle_orphans().unwrap();
    fixture.assert_unknown(&run.run_id);
    let (_, replay) = fixture.run(&mut make());
    assert_eq!(replay.run_id, run.run_id);
    assert_eq!(replay.state, "outcome_unknown");
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
    assert!(!fixture.workspace.join("must-not-finish").exists());
}

#[test]
fn detached_mode_refuses_a_session_bound_existing_writer() {
    let Some(jail) = live_jail() else {
        return;
    };
    if ouro_ledger::service::probe()["available"] != true {
        harness::skip_or_fail("independent user manager absent");
        return;
    }
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command("unsafe-writer", true);
    command.args(["--detach", "--", "/bin/sh", "-c", "touch must-not-execute"]);
    let output = Process::spawn(&mut command, true).finish();
    assert!(!output.status.success());
    assert!(!fixture.workspace.join("must-not-execute").exists());
    assert!(fixture.client().runs().unwrap().is_empty());
}

#[test]
fn detached_writer_death_fails_closed_without_starting_a_session_writer() {
    let Some(fixture) = detached_fixture() else {
        return;
    };
    let mut command = fixture.command("detached-writer-loss", true);
    command.args([
        "--detach",
        "--",
        "/bin/sh",
        "-c",
        "touch started; sleep 8; touch must-not-finish",
    ]);
    let (_, run) = fixture.run(&mut command);
    wait_for_file(&fixture.workspace.join("started"));
    stop_on_demand_writer(&fixture.data).unwrap();
    fixture.assert_tree_stopped(&run);
    assert!(!fixture.workspace.join("must-not-finish").exists());
    assert!(
        Client::connect(&fixture.data).is_err(),
        "strict evidence must not silently replace the writer"
    );
    let deadline = Instant::now() + COMMAND_LIMIT;
    while daemon::peer_alive(run.owner.as_ref().unwrap()) {
        assert!(
            Instant::now() < deadline,
            "owner stayed alive after evidence loss"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let _writer = Fixture::start_writer(&fixture.data);
    fixture.client().settle_orphans().unwrap();
    fixture.assert_unknown(&run.run_id);
}

#[test]
fn operator_intents_and_live_tail_preserve_real_jail_ownership_and_source_bytes() {
    use ouro_ledger::protocol::{OperatorIntent, TailRequest};
    use serde_json::json;
    let Some(jail) = live_jail() else {
        return;
    };
    let fixture = Fixture::new(&jail);
    let mut command = fixture.command("operator-tail-real", true);
    command.args(["--", "/bin/sh", "-c", "printf started > started; while test ! -f release; do sleep 0.05; done; printf x >> executions"]);
    let mut process = Process::spawn(&mut command, true);
    let run = fixture.wait_started(&mut process);
    let mut client = fixture.client();
    for kind in ["admitted", "settled"] {
        client
            .append(&OperatorIntent {
                run_id: run.run_id.clone(),
                request_id: format!("external-{kind}"),
                kind: kind.into(),
                effect_id: Some("external-work".into()),
                body: json!({"operator_assertion":true}),
            })
            .unwrap();
    }
    let still_running = client.show(&run.run_id).unwrap();
    assert_eq!(still_running.state, "admitted");
    assert_eq!(still_running.owner, run.owner);
    assert!(process.child.try_wait().unwrap().is_none());
    let mut request = TailRequest {
        run_id: run.run_id.clone(),
        cursor: None,
    };
    let mut streamed = String::new();
    loop {
        let page = client.tail(&request).unwrap();
        streamed.push_str(&page.ndjson);
        request.cursor = Some(page.next_cursor);
        if page.caught_up {
            break;
        }
    }
    fs::write(fixture.workspace.join("release"), b"go").unwrap();
    let output = process.finish();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settled: RunRecord = serde_json::from_slice(&output.stdout).unwrap();
    loop {
        let page = client.tail(&request).unwrap();
        assert_eq!(page.child_protection, "enforced");
        assert_eq!(page.state, "settled");
        assert!(page.local_consistency);
        streamed.push_str(&page.ndjson);
        request.cursor = Some(page.next_cursor);
        if page.caught_up {
            break;
        }
    }
    let original = fs::read(
        fixture
            .data
            .join("ledger")
            .join(&run.run_id)
            .join("events-0001.ndjson"),
    )
    .unwrap();
    assert_eq!(streamed.as_bytes(), original);
    let events = fixture.events(&settled);
    assert!(events.iter().any(
        |event| event["operation"] == "proc.exec" && event["provenance"]["role"] == "producer"
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "operator_intent")
            .count(),
        2
    );
    assert_eq!(events.last().unwrap()["kind"], "settled");
    assert_eq!(events.last().unwrap()["provenance"]["role"], "owner");
    assert_eq!(
        fs::read(fixture.workspace.join("executions")).unwrap(),
        b"x"
    );
    assert!(client.verify(Some(&run.run_id)).unwrap()[0].local_consistency);
}
