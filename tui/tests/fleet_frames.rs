//! `--frames`, driven on stdio the way the runtime's broker drives it.
//!
//! `docs/proposals/fleet-kiss.md` §8. `setup` is the operation this can run end to end
//! without a second machine: it needs no SSH, it asks exactly one question (the review),
//! and everything it changes is inside the scratch data directory. What is proven here
//! is the wire the Elixir broker slice writes the other half of — the frame names, the
//! respond shape, the terminal `done` frame, the exit code, and where stderr goes.
//!
//! The `add` and `leave --machine` halves of the same front end share this code path
//! exactly; what differs is the steps between the review and the `done`.

mod fleet_ports;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

const OURO: &str = env!("CARGO_BIN_EXE_ouro");

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn scratch(label: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!(
        "ouro-frames-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("a private scratch directory");
    path
}

/// `ouro` refuses a data directory anyone else can read.
fn private_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).expect("a data directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("a private data directory");
}

/// Two free loopback ports outside every production port space, so a test fleet never
/// collides with a live same-host lab — and claimed, so no other test process in this
/// run is handed the same number in the window between choosing it and binding it.
fn test_ports() -> (u16, u16) {
    fleet_ports::reserve()
}

/// One `ouro fleet … --frames` process, spoken to the way a port program is.
struct Frames {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<std::process::ChildStdout>,
    log: PathBuf,
}

impl Frames {
    fn start(data_dir: &Path, log: &Path, args: &[&str]) -> Self {
        let (gateway, dist) = test_ports();
        let errors = std::fs::File::create(log).expect("a stderr log");
        let mut child = Command::new(OURO)
            .args(args)
            .arg("--frames")
            .env("OUROBOROS_DATA_DIR", data_dir)
            .env("OUROBOROS_TEST_GATEWAY_PORT", gateway.to_string())
            .env("OUROBOROS_TEST_DIST_PORT", dist.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(errors))
            .spawn()
            .expect("a frames process");
        let input = child.stdin.take().expect("an open stdin");
        let output = BufReader::new(child.stdout.take().expect("an open stdout"));
        Self {
            child,
            input: Some(input),
            output,
            log: log.to_path_buf(),
        }
    }

    /// The next frame, or `None` at end of output.
    fn next(&mut self) -> Option<Value> {
        let mut line = String::new();
        loop {
            line.clear();
            if self.output.read_line(&mut line).expect("readable stdout") == 0 {
                return None;
            }
            if line.trim().is_empty() {
                continue;
            }
            return Some(
                serde_json::from_str(&line)
                    .unwrap_or_else(|error| panic!("one JSON object per line: {error}: {line}")),
            );
        }
    }

    fn send(&mut self, frame: Value) {
        let input = self.input.as_mut().expect("an open stdin");
        writeln!(input, "{frame}").expect("a process still reading");
        input.flush().expect("a flushed frame");
    }

    fn close_stdin(&mut self) {
        self.input.take();
    }

    fn finish(mut self) -> (i32, String) {
        self.close_stdin();
        let status = self.child.wait().expect("a finished process");
        let stderr = std::fs::read_to_string(&self.log).unwrap_or_default();
        (status.code().unwrap_or(-1), stderr)
    }
}

/// §8's whole out/in vocabulary for one operation, and the exit code a broker reads.
#[test]
fn a_frames_setup_asks_one_review_and_reports_a_terminal_done() {
    let root = scratch("setup");
    let data = root.join("data");
    private_dir(&data);
    let log = root.join("stderr.log");
    let mut frames = Frames::start(
        &data,
        &log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
        ],
    );

    // The first frame says the operation is running, before anything is asked.
    let first = frames.next().expect("a first frame");
    assert_eq!(first["event"], "state");
    assert_eq!(first["state"], "running");

    // Then exactly one challenge: the review.
    let mut challenge = None;
    let mut operation = None;
    let mut states = vec![first["state"].as_str().unwrap_or_default().to_string()];
    while let Some(frame) = frames.next() {
        match frame["event"].as_str() {
            Some("challenge") => {
                assert_eq!(frame["kind"], "review", "{frame}");
                assert!(
                    frame["expires_at"].is_string(),
                    "a challenge carries its own deadline: {frame}"
                );
                // §6's review lines, in order, are what a person reads.
                let lines: Vec<&str> = frame["metadata"]["lines"]
                    .as_array()
                    .expect("the plan lines")
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                assert!(
                    lines[0].starts_with("Create a fleet on this machine as lab"),
                    "{lines:?}"
                );
                operation = frame["metadata"]["plan"]["operation"]
                    .as_str()
                    .map(str::to_string);
                challenge = frame["challenge"].as_str().map(str::to_string);
                break;
            }
            Some("state") => states.push(frame["state"].as_str().unwrap_or_default().to_string()),
            Some("log") => {}
            other => panic!("unexpected frame before the review: {other:?} in {frame}"),
        }
    }
    let challenge = challenge.expect("a review challenge");
    let operation = operation.expect("the operation id");

    // §8: `accept` answers host trust and review alike.
    frames.send(serde_json::json!({
        "op": "respond",
        "challenge": challenge,
        "accept": true,
    }));

    // Steps, then exactly one terminal `done`.
    let mut steps = Vec::new();
    let mut done = None;
    while let Some(frame) = frames.next() {
        match frame["event"].as_str() {
            Some("step") => steps.push((
                frame["step"].as_str().unwrap_or_default().to_string(),
                frame["state"].as_str().unwrap_or_default().to_string(),
            )),
            Some("state") => states.push(frame["state"].as_str().unwrap_or_default().to_string()),
            Some("log") => {}
            Some("done") => {
                done = Some(frame);
                break;
            }
            other => panic!("unexpected frame: {other:?} in {frame}"),
        }
    }
    let done = done.expect("a done frame");
    assert_eq!(done["state"], "completed", "{done}");
    assert_eq!(done["operation"], operation.as_str());

    // §6 and §8 are one vocabulary: every `state` frame of a whole operation, and the
    // `done` that ends it, is one of five words. The engine sequences through more
    // phases than that — inspecting, deploying, restarting this host — and none of them
    // is allowed out here, because the readers on the other end of this pipe have words
    // for five states and for nothing else.
    states.push(done["state"].as_str().unwrap_or_default().to_string());
    for state in &states {
        assert!(
            ["running", "waiting", "completed", "failed", "cancelled"].contains(&state.as_str()),
            "a frame carried `{state}`, which is not one of §8's five: {states:?}"
        );
    }
    assert!(
        states.iter().any(|state| state == "waiting"),
        "the review is a question, and a question is `waiting`: {states:?}"
    );
    assert!(done["summary"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
    assert!(
        frames.next().is_none(),
        "`done` is the last frame on stdout"
    );

    // §6's `setup` steps.
    let names: Vec<&str> = steps.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"create"), "{names:?}");

    let (code, stderr) = frames.finish();
    assert_eq!(code, 0, "a completed operation exits 0: {stderr}");

    // The machine really was set up, and the journal is schema 2.
    let profile: Value = serde_json::from_str(
        &std::fs::read_to_string(data.join("fleet").join("profile.json")).expect("a profile"),
    )
    .expect("a decodable profile");
    assert_eq!(profile["schema"], 2);
    assert_eq!(profile["machine"], "lab");
    assert!(profile["dist_port"].is_number());
    assert!(profile.get("tombstones").is_none());
    assert!(profile.get("roster_revision").is_none());
    assert!(profile.get("epmd_port").is_none());

    let journal: Value = serde_json::from_str(
        &std::fs::read_to_string(data.join("deploy").join(format!("{operation}.json")))
            .expect("a journal"),
    )
    .expect("a decodable journal");
    assert_eq!(journal["schema"], 2);
    // The journal's own word, read off disk. It is the same vocabulary as the wire's:
    // §6's `state` is one of five, so a reader of this file needs no second table.
    assert_eq!(journal["state"], "completed");
    assert!(
        ["running", "waiting", "completed", "failed", "cancelled"]
            .contains(&journal["state"].as_str().unwrap_or_default()),
        "{journal}"
    );
    assert!(journal["plan"].is_array(), "§6: the plan is the lines read");
    assert!(journal.get("plan_digest").is_none());
    assert!(journal.get("owner").is_none());
    assert!(journal.get("roster").is_none());
    for step in journal["steps"].as_array().expect("steps") {
        assert!(step["step"].is_string(), "{step}");
        assert!(step["state"].is_string(), "§6 names it `state`: {step}");
        assert!(step["at"].is_string(), "{step}");
    }
}

/// A declined review is a `cancelled`-shaped refusal, and nothing is written.
#[test]
fn a_declined_review_changes_nothing_and_exits_non_zero() {
    let root = scratch("declined");
    let data = root.join("data");
    private_dir(&data);
    let log = root.join("stderr.log");
    let mut frames = Frames::start(
        &data,
        &log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
        ],
    );

    let mut challenge = None;
    while let Some(frame) = frames.next() {
        if frame["event"] == "challenge" {
            challenge = frame["challenge"].as_str().map(str::to_string);
            break;
        }
    }
    frames.send(serde_json::json!({
        "op": "respond",
        "challenge": challenge.expect("a review challenge"),
        "accept": false,
    }));

    let mut done = None;
    while let Some(frame) = frames.next() {
        if frame["event"] == "done" {
            done = Some(frame);
            break;
        }
    }
    let done = done.expect("a done frame");
    assert_eq!(done["state"], "failed", "{done}");
    assert_eq!(done["reason"], "review_declined", "{done}");
    assert!(
        done["operation"]
            .as_str()
            .is_some_and(|id| id.starts_with("op-")),
        "every terminal frame names its operation: {done}"
    );

    let (code, stderr) = frames.finish();
    assert_ne!(code, 0, "a refused operation exits non-zero");
    // §8: stderr is diagnostics, and stdout is frames. Nothing that is not a frame
    // reached stdout, which the parse above already proved.
    assert!(!stderr.is_empty(), "the refusal is explained on stderr");
    assert!(
        !data.join("fleet").exists(),
        "a declined review installs nothing"
    );
}

/// §8: `{"op":"cancel"}` stops the operation at the next step boundary.
#[test]
fn a_cancel_frame_stops_the_operation() {
    let root = scratch("cancel");
    let data = root.join("data");
    private_dir(&data);
    let log = root.join("stderr.log");
    let mut frames = Frames::start(
        &data,
        &log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
        ],
    );

    while let Some(frame) = frames.next() {
        if frame["event"] == "challenge" {
            break;
        }
    }
    frames.send(serde_json::json!({ "op": "cancel" }));

    let mut done = None;
    while let Some(frame) = frames.next() {
        if frame["event"] == "done" {
            done = Some(frame);
            break;
        }
    }
    let done = done.expect("a done frame");
    assert!(
        done["state"] == "cancelled" || done["state"] == "failed",
        "a cancelled operation is terminal: {done}"
    );
    let (code, _stderr) = frames.finish();
    assert_ne!(code, 0);
    assert!(!data.join("fleet").exists(), "nothing was installed");
}

/// A malformed frame is answered with a `log` line rather than taken as an answer, and
/// the operation keeps waiting for a real one.
#[test]
fn a_malformed_request_is_reported_and_never_treated_as_an_answer() {
    let root = scratch("malformed");
    let data = root.join("data");
    private_dir(&data);
    let log = root.join("stderr.log");
    let mut frames = Frames::start(
        &data,
        &log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
        ],
    );

    let mut challenge = None;
    while let Some(frame) = frames.next() {
        if frame["event"] == "challenge" {
            challenge = frame["challenge"].as_str().map(str::to_string);
            break;
        }
    }
    let challenge = challenge.expect("a review challenge");

    // Not JSON, then an unknown op, then an answer to a challenge that does not exist.
    frames.send(serde_json::json!("not an object"));
    frames.send(serde_json::json!({ "op": "explode" }));
    frames.send(serde_json::json!({
        "op": "respond",
        "challenge": "0123456789abcdef0123456789abcdef",
        "accept": true,
    }));

    let mut logs = 0;
    while logs < 3 {
        let frame = frames.next().expect("a frame");
        if frame["event"] == "log" {
            logs += 1;
        }
        assert_ne!(
            frame["event"], "done",
            "a malformed frame must not end the operation: {frame}"
        );
    }

    // And the real answer still works.
    frames.send(serde_json::json!({
        "op": "respond",
        "challenge": challenge,
        "accept": true,
    }));
    let mut done = None;
    while let Some(frame) = frames.next() {
        if frame["event"] == "done" {
            done = Some(frame);
            break;
        }
    }
    assert_eq!(done.expect("a done frame")["state"], "completed");
    let (code, _stderr) = frames.finish();
    assert_eq!(code, 0);
}

/// Nothing a `respond` carries reaches stdout, stderr or the journal.
#[test]
fn a_secret_in_a_respond_frame_never_appears_anywhere() {
    let root = scratch("residue");
    let data = root.join("data");
    private_dir(&data);
    let log = root.join("stderr.log");
    let mut frames = Frames::start(
        &data,
        &log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
        ],
    );

    const SECRET: &str = "correct-horse-battery-staple";
    let mut challenge = None;
    let mut transcript = String::new();
    while let Some(frame) = frames.next() {
        transcript.push_str(&frame.to_string());
        if frame["event"] == "challenge" {
            challenge = frame["challenge"].as_str().map(str::to_string);
            break;
        }
    }
    // A secret sent to a review challenge is refused, and is still never echoed.
    frames.send(serde_json::json!({
        "op": "respond",
        "challenge": challenge.clone().expect("a challenge"),
        "secret": SECRET,
    }));
    frames.send(serde_json::json!({
        "op": "respond",
        "challenge": challenge.expect("a challenge"),
        "accept": true,
    }));
    while let Some(frame) = frames.next() {
        transcript.push_str(&frame.to_string());
        if frame["event"] == "done" {
            break;
        }
    }
    let (_code, stderr) = frames.finish();

    assert!(!transcript.contains(SECRET), "a secret reached stdout");
    assert!(!stderr.contains(SECRET), "a secret reached stderr");
    for entry in std::fs::read_dir(data.join("deploy")).expect("a deploy directory") {
        let path = entry.expect("an entry").path();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !text.contains(SECRET),
            "a secret reached {}",
            path.display()
        );
    }
    // And the fleet directory holds credentials, not transcripts.
    let cookie =
        std::fs::read_to_string(data.join("fleet").join("cookie")).expect("a fleet cookie");
    assert!(!transcript.contains(cookie.trim()), "the cookie was framed");
    assert!(!stderr.contains(cookie.trim()), "the cookie reached stderr");
}

/// Hostile text in a machine name is refused before anything is written, and what comes
/// back is a frame rather than a terminal escape.
#[test]
fn hostile_names_are_refused_without_reaching_stdout_as_control_characters() {
    for hostile in [
        "lab\u{1b}[2J",
        "../../etc/passwd",
        "lab;rm -rf /",
        "lab\nmachine",
    ] {
        let root = scratch("hostile");
        let data = root.join("data");
        private_dir(&data);
        let log = root.join("stderr.log");
        let output = Command::new(OURO)
            .args(["fleet", "setup", "--machine", hostile])
            .args(["--address", "127.0.0.1", "--no-service", "--frames"])
            .env("OUROBOROS_DATA_DIR", &data)
            .stdin(Stdio::null())
            .output()
            .expect("a frames process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains('\u{1b}'),
            "a control character reached stdout for {hostile:?}: {stdout}"
        );
        for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("one JSON object per line ({error}): {line}"));
        }
        assert_ne!(output.status.code(), Some(0), "{hostile:?} must be refused");
        assert!(
            !data.join("fleet").exists(),
            "{hostile:?} installed something"
        );
        let _ = std::fs::remove_file(&log);
    }
}

/// `--dry-run --frames`: the broker's smoke test that the worker it is about to run
/// really is this `ouro` speaking §8.
///
/// It runs before any operation does, against a throwaway data directory, so it must
/// ask nothing and write nothing. What comes back for every kind is `state running`
/// first, §8 events and nothing else on stdout, and a terminal `done` — and the data
/// directory afterwards holds exactly what it held before.
///
/// `setup` is the kind that can resolve a whole plan here, because it needs no second
/// machine: it is the one asserted all the way to `done completed`, exit 0, with the
/// plan's own lines as `log` frames. A dry-run `add` over frames against a machine that
/// really answers is in `fleet_setup_engine.rs`, where there is an `sshd` to answer it;
/// the one here is pointed at a closed loopback port, so it resolves nothing and asks
/// nothing, and what it proves is that the frames are still §8's and nothing was
/// written. Deliberately not port 22: a suite that needs no network must not go
/// knocking on the developer's own `sshd`.
#[test]
fn a_dry_run_over_frames_prints_the_plan_asks_nothing_and_writes_nothing() {
    let (closed, _) = test_ports();
    let closed = closed.to_string();
    for (label, args) in [
        (
            "setup",
            vec![
                "fleet",
                "setup",
                "--machine",
                "lab",
                "--address",
                "127.0.0.1",
                "--no-service",
            ],
        ),
        (
            "add",
            vec![
                "fleet",
                "add",
                "me@127.0.0.1",
                "--machine",
                "pi",
                "--port",
                &closed,
                "--no-service",
            ],
        ),
        (
            "leave",
            vec!["fleet", "leave", "--machine", "pi", "--user", "me"],
        ),
    ] {
        let root = scratch(&format!("dry-{label}"));
        let data = root.join("data");
        private_dir(&data);
        let log = root.join("stderr.log");

        // `add` and `leave` plan against a fleet, so there has to be one here first —
        // and `setup` is what makes it, through this same binary.
        if label != "setup" {
            let (gateway, dist) = test_ports();
            let made = Command::new(OURO)
                .args(["fleet", "setup", "--machine", "lab"])
                .args(["--address", "127.0.0.1", "--no-service", "--yes", "--json"])
                .env("OUROBOROS_DATA_DIR", &data)
                .env("OUROBOROS_TEST_GATEWAY_PORT", gateway.to_string())
                .env("OUROBOROS_TEST_DIST_PORT", dist.to_string())
                .stdin(Stdio::null())
                .output()
                .expect("a fleet to plan against");
            assert!(
                made.status.success(),
                "{label}: {}",
                String::from_utf8_lossy(&made.stderr)
            );
        }

        let before = listing(&data);
        let before_deploy = listing(&data.join("deploy"));
        let mut dry = args.clone();
        dry.push("--dry-run");
        let mut frames = Frames::start(&data, &log, &dry);
        // A dry run needs nothing from stdin, and §8 says EOF finishes the operation.
        frames.close_stdin();

        let mut seen: Vec<Value> = Vec::new();
        while let Some(frame) = frames.next() {
            seen.push(frame);
        }
        let (code, stderr) = frames.finish();

        // Every line is one of §8's five events, and nothing else.
        for frame in &seen {
            let event = frame["event"].as_str().unwrap_or_default();
            assert!(
                matches!(event, "state" | "step" | "log" | "challenge" | "done"),
                "{label}: `{event}` is not one of §8's five events: {frame}"
            );
        }
        assert_eq!(seen[0]["event"], "state", "{label}: {seen:?}");
        assert_eq!(seen[0]["state"], "running", "{label}: {seen:?}");
        assert!(
            !seen.iter().any(|frame| frame["event"] == "challenge"),
            "{label}: a dry run asks nobody anything: {seen:?}"
        );
        let done = seen.last().expect("a done frame");
        assert_eq!(done["event"], "done", "{label}: {seen:?}");
        assert!(
            done["operation"].as_str().is_some_and(|id| id.len() == 15),
            "{label}: every terminal frame names its operation: {done}"
        );

        // `setup` resolves its whole plan here, so it is the one taken to the end.
        if label == "setup" {
            assert_eq!(code, 0, "{label}: a completed dry run exits 0\n{stderr}");
            assert_eq!(done["state"], "completed", "{label}: {done}");
            assert!(
                done["summary"]
                    .as_str()
                    .is_some_and(|summary| summary.starts_with("dry run: nothing was changed")),
                "{label}: {done}"
            );
            let logged: Vec<&str> = seen
                .iter()
                .filter(|frame| frame["event"] == "log")
                .filter_map(|frame| frame["line"].as_str())
                .collect();
            assert!(
                logged
                    .first()
                    .is_some_and(|line| line.starts_with("Create a fleet on this machine as lab")),
                "{label}: the plan's lines are the log frames: {logged:?}"
            );
        }

        // Nothing was written: not one new name in the data directory, not one new
        // journal or lock in the deployment namespace, and no fleet where there was
        // none. `setup` starts with no namespace at all and must still have none —
        // the other two are run against the fleet the setup above really did make, so
        // for them the claim is that the namespace did not gain anything.
        assert_eq!(
            before,
            listing(&data),
            "{label}: a dry run wrote into the data directory"
        );
        assert_eq!(
            before_deploy,
            listing(&data.join("deploy")),
            "{label}: a dry run wrote into the deployment namespace"
        );
        if label == "setup" {
            assert!(
                !data.join("deploy").exists(),
                "a dry run on a machine that has never deployed made the namespace"
            );
        }
        assert_eq!(
            data.join("fleet").exists(),
            label != "setup",
            "{label}: a dry run changed what fleet is here"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// A second process on one operation id is refused promptly, and writes nothing.
///
/// §8's lock is per operation, not per host: two different deployments from one machine
/// are not a conflict, and the one thing that must never happen is two processes writing
/// one journal. The first process here is parked on its review challenge — which is
/// where a real operation spends most of its life — and the second must not clear its
/// error, connect to anything, or ask anybody a question on the way to finding out it
/// cannot run. It says so in frames and exits non-zero.
#[test]
fn a_second_process_on_one_operation_is_refused_with_operation_in_progress() {
    let root = scratch("inprogress");
    let data = root.join("data");
    private_dir(&data);
    let operation = "op-0000000000aa";

    // The first process, parked on its review: it holds the lock for as long as it runs.
    let first_log = root.join("first.log");
    let mut first = Frames::start(
        &data,
        &first_log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
            "--operation",
            operation,
        ],
    );
    let mut challenge = None;
    while let Some(frame) = first.next() {
        if frame["event"] == "challenge" {
            challenge = frame["challenge"].as_str().map(str::to_string);
            break;
        }
    }
    let challenge = challenge.expect("the first process reached its review");
    let journal = data.join("deploy").join(format!("{operation}.json"));
    let held = std::fs::read(&journal).expect("the first process journalled");

    // The second, on the same id, while the first still holds the lock.
    let second_log = root.join("second.log");
    let started = std::time::Instant::now();
    let mut second = Frames::start(
        &data,
        &second_log,
        &[
            "fleet",
            "setup",
            "--machine",
            "lab",
            "--address",
            "127.0.0.1",
            "--no-service",
            "--operation",
            operation,
        ],
    );
    second.close_stdin();
    let mut seen: Vec<Value> = Vec::new();
    while let Some(frame) = second.next() {
        seen.push(frame);
    }
    let (code, stderr) = second.finish();
    let elapsed = started.elapsed();

    assert_eq!(
        seen.first().map(|frame| frame["event"].clone()),
        Some(Value::from("state")),
        "{seen:?}"
    );
    assert_eq!(seen[0]["state"], "running", "{seen:?}");
    let done = seen.last().expect("a done frame");
    assert_eq!(done["event"], "done", "{seen:?}");
    assert_eq!(done["state"], "failed", "{done}");
    assert_eq!(done["operation"], operation, "{done}");
    assert_eq!(
        done["reason"], "operation_in_progress",
        "the reason a broker branches on: {done}"
    );
    assert!(
        !seen.iter().any(|frame| frame["event"] == "challenge"),
        "the second process asked somebody a question: {seen:?}"
    );
    assert_ne!(code, 0, "a refused second process exits non-zero\n{stderr}");
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "the refusal has to be prompt, not a review's five minutes: {elapsed:?}"
    );
    assert_eq!(
        std::fs::read(&journal).expect("the journal"),
        held,
        "the second process wrote to a journal it does not own"
    );

    // The first process is still the one that owns the operation, and finishes it.
    first.send(serde_json::json!({
        "op": "respond",
        "challenge": challenge,
        "accept": true,
    }));
    let (first_code, first_stderr) = first.finish();
    assert_eq!(first_code, 0, "{first_stderr}");
    assert!(data.join("fleet").exists(), "the first process ran");
}

fn listing(directory: &Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}
