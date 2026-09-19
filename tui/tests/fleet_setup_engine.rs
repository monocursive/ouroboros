//! `ouro fleet setup`, `ouro fleet add` and `ouro fleet leave --machine`, end to end,
//! through the real command line and over a real unprivileged `sshd` on loopback.
//!
//! Two data directories on one host, the debug `ouro` this test was compiled beside as
//! *both* the issuer and the target, and a real OpenSSH client and server between them.
//! Nothing in here calls the engine in process: what is being proved is the packaged
//! shape — that the operator's flags reach the engine, that the bundle crosses the SSH
//! channel and lands as mode-0600 files on the far side, that the journal names §6's
//! steps in §6's order, that an interrupted operation resumes from its durable
//! boundary, and that no secret is anywhere afterwards.
//!
//! ## Why the target's `ouro` is a wrapper script
//!
//! `--install-path` names an absolute path that already holds an `ouro`, and the engine
//! runs it as `exec /usr/bin/env OUROBOROS_DATA_DIR=<dir> <path> fleet helper`. Pointing
//! it at a two-line `/bin/sh` script that records its argv and its environment and then
//! `exec`s the real binary gives this test two things it cannot get any other way: the
//! exact command line and environment of every child the rig spawned on the target
//! (which is what the secret-residue test needs to look at), and a way to hand the
//! helper an isolated service manager without changing the shared `sshd` fixture.
//!
//! ## Why no runtime is ever started
//!
//! The debug `ouro` carries no embedded release, so nothing here can boot a BEAM. §6's
//! `start` and `connect` are therefore either skipped — `--no-service`, which is what
//! the main flow uses — or driven into a deliberate failure against a fake service
//! manager. Both leave the credentials on the target, and both are asserted from the
//! journal rather than inferred.

mod fleet_setup_support;

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use fleet_setup_support::{account, scratch, write_script, Sshd, OURO};
use ouro::fleet;
use ouro::fleet_setup::journal::{Journal, Record};
use ouro::fleet_setup::trust::{self, Tools, Trust};
use ouro::fleet_setup::{known_hosts_path, OperationKind, OperationState};

/// A password that appears in no other fixture, so a grep for it is unambiguous.
const PASSWORD: &str = "kr2-frames-password-9f31c7";

/// `fleet::ephemeral_ports` binds to find free ports, so two threads that call it at the
/// same moment can be handed the same number. Every test here that chooses ports holds
/// this for its duration.
static PORTS: Mutex<()> = Mutex::new(());

fn ephemeral() -> fleet::Ports {
    let _held = PORTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fleet::ephemeral_ports()
}

fn data_dir(label: &str) -> PathBuf {
    let path = scratch(label);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("a private data directory");
    path
}

// --------------------------------------------------------------------------- the lab

/// One `sshd`, one issuer data directory with a fleet in it, one target data directory,
/// and the wrapper the target's helper is started through.
struct Lab {
    rig: Sshd,
    issuer: PathBuf,
    issuer_ports: fleet::Ports,
    target: PathBuf,
    target_ports: fleet::Ports,
    /// A scratch `HOME` for every `ouro` this test starts locally, so the operator's own
    /// `~/.ssh/known_hosts` is never read and no unit can reach their agents directory.
    home: PathBuf,
    /// The `--install-path` handed to `add`: a script that records and then execs `ouro`.
    wrapper: PathBuf,
    argv_log: PathBuf,
    env_log: PathBuf,
    work: PathBuf,
}

impl Lab {
    fn new(label: &str, machine: &str) -> Self {
        Self::with_helper_env(label, machine, &[])
    }

    /// The same, with extra environment variables exported into the target's helper.
    fn with_helper_env(label: &str, machine: &str, helper_env: &[(&str, &Path)]) -> Self {
        let rig = Sshd::start(label);
        let issuer = data_dir(&format!("{label}i"));
        let target = data_dir(&format!("{label}t"));
        let work = scratch(&format!("{label}w"));
        let home = work.join("home");
        fs::create_dir_all(&home).expect("a scratch home");

        let argv_log = work.join("child-argv");
        let env_log = work.join("child-env");
        let wrapper = work.join("ouro-wrapper");
        // The fence, always: whatever else the helper is told, no unit it writes can
        // leave the rig's own contained `HOME`. `sshd` hands the session that `HOME`
        // through `SetEnv`, so without this a `service` op would reach the developer's
        // real `~/Library/LaunchAgents`.
        let mut exports = format!("export OUROBOROS_SERVICE_ROOT='{}'\n", rig.home.display());
        for (name, value) in helper_env {
            exports.push_str(&format!("export {name}='{}'\n", value.display()));
        }
        write_script(
            &wrapper,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{argv}'\nenv >> '{env}'\n{exports}exec '{ouro}' \"$@\"\n",
                argv = argv_log.display(),
                env = env_log.display(),
                ouro = OURO,
            ),
        );

        let lab = Self {
            rig,
            issuer,
            issuer_ports: ephemeral(),
            target,
            target_ports: ephemeral(),
            home,
            wrapper,
            argv_log,
            env_log,
            work,
        };
        lab.setup(machine);
        lab.trust_the_rig();
        lab
    }

    /// `ouro fleet setup` on the issuer's data directory: no service, no prompt.
    fn setup(&self, machine: &str) {
        let done = self.ouro(
            &self.issuer,
            self.issuer_ports,
            &[
                "fleet",
                "setup",
                "--machine",
                machine,
                "--address",
                "127.0.0.1",
                "--no-service",
                "--yes",
                "--json",
            ],
            &[],
        );
        assert!(
            done.success(),
            "`ouro fleet setup` failed:\n{}\n{}",
            done.stdout,
            done.stderr
        );
        let document: Value = done.json();
        assert_eq!(document["state"], json!("completed"), "{document:#}");
    }

    /// Record the rig's host key in the issuer's private store, the way an accepted
    /// `host_trust` challenge would.
    ///
    /// `--yes` deliberately does not answer host trust, and these runs have no terminal,
    /// so a noninteractive `add` needs the trust established first. That is the
    /// documented contract, not a shortcut: `terminal.rs` refuses `host_unknown` without
    /// a tty.
    fn trust_the_rig(&self) -> String {
        let store = known_hosts_path(&self.issuer);
        fs::create_dir_all(store.parent().expect("a deploy directory")).expect("a directory");
        let scan = self.work.join("scan");
        fs::create_dir_all(&scan).expect("a scan directory");
        fs::set_permissions(&scan, fs::Permissions::from_mode(0o700))
            .expect("a private scan directory");
        match trust::examine(
            &tools(),
            std::slice::from_ref(&store),
            "127.0.0.1",
            self.rig.port,
            &scan,
        )
        .expect("a host-key scan")
        {
            Trust::Unknown { keys } => {
                let key = keys.first().expect("a scanned key");
                trust::accept(&store, key).expect("recording trust");
                key.fingerprint.clone()
            }
            Trust::Known { fingerprint, .. } => fingerprint,
            other => panic!("a fresh store cannot say {other:?}"),
        }
    }

    /// Run the built `ouro` with the environment every test here needs.
    fn ouro(
        &self,
        data_dir: &Path,
        ports: fleet::Ports,
        args: &[&str],
        extra: &[(&str, &str)],
    ) -> Finished {
        let output = self
            .command(data_dir, ports, args, extra)
            .stdin(Stdio::null())
            .output()
            .expect("the built ouro binary");
        Finished {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn command(
        &self,
        data_dir: &Path,
        ports: fleet::Ports,
        args: &[&str],
        extra: &[(&str, &str)],
    ) -> Command {
        let mut command = Command::new(OURO);
        command
            .args(args)
            .env("OUROBOROS_DATA_DIR", data_dir)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .env("OUROBOROS_SERVICE_ROOT", &self.home)
            // The network client is never consulted for an address that is already an
            // address, but `add` still asks it for a node key. A program that runs and
            // fails is the fast, deterministic answer, and it is absolute so the
            // override is honoured rather than discarded.
            .env("OUROBOROS_TAILSCALE", "/usr/bin/false")
            .env_remove("OUROBOROS_GATEWAY_ADDR")
            .env_remove("SSH_AUTH_SOCK");
        if let Some(gateway) = ports.gateway {
            command.env("OUROBOROS_TEST_GATEWAY_PORT", gateway.to_string());
        }
        if let Some(dist) = ports.dist {
            command.env("OUROBOROS_TEST_DIST_PORT", dist.to_string());
        }
        for (name, value) in extra {
            command.env(name, value);
        }
        command
    }

    /// The arguments `ouro fleet add` takes for this rig, minus the ones a test varies.
    fn add_args(&self, machine: &str, operation: &str) -> Vec<String> {
        vec![
            "fleet".into(),
            "add".into(),
            format!("{}@127.0.0.1", account()),
            "--machine".into(),
            machine.into(),
            "--port".into(),
            self.rig.port.to_string(),
            "--key".into(),
            self.rig.client_key.display().to_string(),
            "--install-path".into(),
            self.wrapper.display().to_string(),
            "--data-dir".into(),
            self.target.display().to_string(),
            "--operation".into(),
            operation.into(),
        ]
    }

    fn journal(&self, operation: &str) -> Record {
        Journal::read(&self.issuer, operation)
            .expect("a readable journal")
            .expect("a written journal")
    }

    fn issuer_profile(&self) -> fleet::Profile {
        fleet::load(&self.issuer)
            .expect("a readable issuer profile")
            .expect("an issuer profile")
    }

    /// Every argv the target's wrapper was handed, and everything in its environment.
    fn child_argv(&self) -> String {
        fs::read_to_string(&self.argv_log).unwrap_or_default()
    }

    fn child_env(&self) -> String {
        fs::read_to_string(&self.env_log).unwrap_or_default()
    }
}

impl std::fmt::Debug for Lab {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Lab")
            .field("issuer", &self.issuer)
            .field("target", &self.target)
            .field("ssh port", &self.rig.port)
            .finish()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.issuer);
        let _ = fs::remove_dir_all(&self.target);
        let _ = fs::remove_dir_all(&self.work);
    }
}

fn tools() -> Tools {
    Tools {
        keyscan: PathBuf::from("/usr/bin/ssh-keyscan"),
        keygen: PathBuf::from("/usr/bin/ssh-keygen"),
    }
}

struct Finished {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Finished {
    fn success(&self) -> bool {
        self.code == Some(0)
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("stdout is one JSON document: {error}\n{}", self.stdout))
    }
}

// ----------------------------------------------------------------- reading the journal

/// Every `<step>:<outcome>` the journal recorded, in the order it recorded them.
fn steps(record: &Record) -> Vec<String> {
    record
        .steps
        .iter()
        .map(|step| format!("{}:{}", step.step, step.outcome))
        .collect()
}

fn step_detail(record: &Record, name: &str) -> String {
    record
        .steps
        .iter()
        .find(|step| step.step == name)
        .unwrap_or_else(|| panic!("a `{name}` step in {:?}", steps(record)))
        .detail
        .clone()
        .unwrap_or_default()
}

/// Assert `names` appear among `recorded`, in this order and with these outcomes.
fn in_order(recorded: &[String], names: &[&str]) {
    let mut cursor = 0;
    for (index, want) in names.iter().enumerate() {
        let found = recorded[cursor..]
            .iter()
            .position(|step| step == want)
            .unwrap_or_else(|| {
                panic!(
                    "`{want}` does not follow {:?}\nrecorded: {recorded:?}",
                    &names[..index]
                )
            });
        cursor += found + 1;
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// Every file under `root` whose bytes contain `needle`, so a failure names the file.
fn grep_tree(root: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(grep_tree(&path, needle));
        } else if let Ok(bytes) = fs::read(&path) {
            if String::from_utf8_lossy(&bytes).contains(needle) {
                found.push(path);
            }
        }
    }
    found
}

/// The fleet cookie and a line of the CA key: two strings that must be nowhere.
fn secrets(data_dir: &Path) -> (String, String) {
    let cookie = fs::read_to_string(data_dir.join("fleet/cookie"))
        .expect("the fleet cookie")
        .trim()
        .to_string();
    assert!(cookie.len() >= 32, "a cookie worth searching for");
    let ca_key = fs::read_to_string(data_dir.join("fleet/ca-key.pem")).expect("the CA key");
    let body = ca_key
        .lines()
        .find(|line| !line.starts_with("-----") && line.len() > 20)
        .expect("a line of key material")
        .to_string();
    (cookie, body)
}

// =============================================================== the packaged-shape flow

/// §6's `add`, end to end, through the command line and over real SSH.
#[test]
fn a_machine_joins_over_real_ssh_and_leaves_again() {
    let lab = Lab::new("kr2add", "studio");
    let operation = "op-0000000000a1";

    let mut args: Vec<String> = lab.add_args("vps", operation);
    args.extend(["--no-service".into(), "--yes".into(), "--json".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let added = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[]);
    assert!(
        added.success(),
        "`ouro fleet add` failed:\n{}\n{}",
        added.stdout,
        added.stderr
    );
    let document = added.json();
    assert_eq!(document["state"], json!("completed"), "{document:#}");

    // ---- the target holds a schema-2 profile with both members
    let installed = fleet::load(&lab.target)
        .expect("a readable target profile")
        .expect("an installed target profile");
    assert_eq!(installed.schema, 2);
    assert_eq!(installed.machine, "vps");
    assert_eq!(installed.host, "127.0.0.1");
    assert_eq!(installed.node, "ouro-vps@127.0.0.1");
    assert_eq!(installed.dist_port, lab.target_ports.dist.expect("a port"));
    let mut members: Vec<&str> = installed
        .members
        .iter()
        .map(|member| member.machine.as_str())
        .collect();
    members.sort_unstable();
    assert_eq!(members, vec!["studio", "vps"]);

    // ---- its own leaf is signed by the issuer's CA, and the shared halves are identical
    let ca_cert = fs::read(lab.issuer.join("fleet/ca-cert.pem")).expect("the issuer CA");
    assert_eq!(
        fs::read(lab.target.join("fleet/ca-cert.pem")).expect("the target CA"),
        ca_cert,
        "one fleet is one CA certificate"
    );
    for shared in ["cookie", "ca-key.pem"] {
        assert_eq!(
            fs::read(lab.issuer.join("fleet").join(shared)).expect("the issuer's copy"),
            fs::read(lab.target.join("fleet").join(shared)).expect("the target's copy"),
            "§1: `{shared}` is the fleet's, byte for byte, on every member"
        );
    }
    // The leaf is this machine's own, generated there, and it verifies against the CA.
    assert_ne!(
        fs::read(lab.issuer.join("fleet/node-key.pem")).expect("the issuer's key"),
        fs::read(lab.target.join("fleet/node-key.pem")).expect("the target's key"),
        "§2: a node key is generated on its own machine and never sent anywhere"
    );
    let verified = Command::new("/usr/bin/openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(lab.issuer.join("fleet/ca-cert.pem"))
        .arg(lab.target.join("fleet/node-cert.pem"))
        .output()
        .expect("openssl verify");
    assert!(
        verified.status.success(),
        "the target's leaf must verify against the issuer's CA: {}{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    let subject = Command::new("/usr/bin/openssl")
        .args(["x509", "-noout", "-text", "-in"])
        .arg(lab.target.join("fleet/node-cert.pem"))
        .output()
        .expect("openssl x509");
    let text = String::from_utf8_lossy(&subject.stdout);
    assert!(text.contains("ouro-vps@127.0.0.1"), "{text}");

    // ---- §2's modes
    for private in ["node-key.pem", "cookie", "ca-key.pem"] {
        assert_eq!(
            mode(&lab.target.join("fleet").join(private)),
            0o600,
            "{private} on the target"
        );
    }

    // ---- the issuer's own profile gained the member, and nothing else changed
    let issuer = lab.issuer_profile();
    assert_eq!(issuer.machine, "studio");
    assert!(
        issuer
            .members
            .iter()
            .any(|member| member.machine == "vps" && member.host == "127.0.0.1"),
        "{:?}",
        issuer.members
    );

    // ---- §6's steps, in order, with the outcomes this run intended
    let record = lab.journal(operation);
    assert_eq!(record.schema, 2);
    assert_eq!(record.kind, OperationKind::Add);
    assert_eq!(record.state, OperationState::Completed);
    let recorded = steps(&record);
    in_order(
        &recorded,
        &[
            "install:skipped",
            "inspect:ok",
            "join:ok",
            "service:skipped",
            "start:skipped",
            "remember:ok",
            "connect:skipped",
        ],
    );
    assert!(
        step_detail(&record, "install").contains("already has ouro"),
        "{recorded:?}"
    );
    // The three steps this run did not take say exactly why, and the credentials are on
    // the target regardless: a machine that was not started is still a member.
    assert!(
        step_detail(&record, "service").contains("--no-service"),
        "{recorded:?}"
    );
    assert!(
        step_detail(&record, "start").contains("--no-service"),
        "{recorded:?}"
    );
    assert!(
        step_detail(&record, "connect").contains("not started from here"),
        "{recorded:?}"
    );
    assert!(record.last_error.is_none(), "{:?}", record.last_error);
    assert_eq!(
        record.paths.install_path.as_deref(),
        Some(lab.wrapper.display().to_string().as_str())
    );
    assert_eq!(
        record.paths.data_dir.as_deref(),
        Some(lab.target.display().to_string().as_str())
    );
    // And the operation the CLI reports names the unobserved connection rather than
    // claiming one.
    assert!(
        document["unknown"]
            .as_array()
            .expect("an unknown list")
            .iter()
            .any(|note| note
                .as_str()
                .is_some_and(|note| note.contains("manual startup was chosen"))),
        "{document:#}"
    );

    // ---- and `leave --machine` takes it out again
    let left = lab.ouro(
        &lab.issuer,
        lab.target_ports,
        &[
            "fleet",
            "leave",
            "--machine",
            "vps",
            "--user",
            &account(),
            "--port",
            &lab.rig.port.to_string(),
            "--key",
            &lab.rig.client_key.display().to_string(),
            "--yes",
            "--json",
            "--operation",
            "op-0000000000a2",
        ],
        &[],
    );
    assert!(
        left.success(),
        "`ouro fleet leave --machine` failed:\n{}\n{}",
        left.stdout,
        left.stderr
    );
    assert_eq!(left.json()["state"], json!("completed"));

    assert!(
        !lab.target.join("fleet").exists(),
        "the target's fleet directory is gone"
    );
    assert!(
        fleet::load(&lab.target)
            .expect("a readable target")
            .is_none(),
        "the target is standalone again"
    );
    let issuer = lab.issuer_profile();
    assert!(
        !issuer
            .members
            .iter()
            .any(|member| fleet::same_name(&member.machine, "vps")),
        "the issuer's members no longer name it: {:?}",
        issuer.members
    );
    // Its own entry is still there: `leave --machine` removes one member, not the fleet.
    assert!(issuer
        .members
        .iter()
        .any(|member| member.machine == "studio"));

    let removal = lab.journal("op-0000000000a2");
    assert_eq!(removal.kind, OperationKind::Leave);
    assert_eq!(removal.state, OperationState::Completed);
    in_order(&steps(&removal), &["stop:ok", "remove:ok", "forget:ok"]);
}

// ============================================================================== --frames

/// One `ouro fleet … --frames` process, spoken to the way the broker's port program is.
struct Frames {
    child: Child,
    input: Option<std::process::ChildStdin>,
    reader: Option<std::thread::JoinHandle<Vec<Value>>>,
    errors: Option<std::thread::JoinHandle<String>>,
    received: std::sync::mpsc::Receiver<Value>,
}

impl Frames {
    fn start(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the built ouro binary");
        let input = child.stdin.take().expect("a piped stdin");
        let output = child.stdout.take().expect("a piped stdout");
        // Drained on its own thread: a process whose stderr pipe fills stops writing
        // frames, and this suite would then wait ninety seconds for one that is stuck
        // behind a full buffer.
        let mut handle = child.stderr.take().expect("a piped stderr");
        let errors = std::thread::spawn(move || {
            use std::io::Read as _;
            let mut text = String::new();
            let _ = handle.read_to_string(&mut text);
            text
        });
        let (sender, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                let frame: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|error| panic!("a frame is one JSON object: {error}: {line}"));
                seen.push(frame.clone());
                if sender.send(frame).is_err() {
                    break;
                }
            }
            seen
        });
        Self {
            child,
            input: Some(input),
            reader: Some(reader),
            errors: Some(errors),
            received,
        }
    }

    /// The next frame, or a panic naming how long it waited.
    fn next(&self) -> Value {
        self.received
            .recv_timeout(Duration::from_secs(90))
            .expect("a frame within ninety seconds")
    }

    /// Frames until one matching `event` arrives, answering nothing.
    fn until(&self, event: &str) -> Vec<Value> {
        let mut seen = Vec::new();
        loop {
            let frame = self.next();
            let matched = frame["event"] == json!(event);
            seen.push(frame);
            if matched {
                return seen;
            }
        }
    }

    fn send(&mut self, request: Value) {
        let input = self.input.as_mut().expect("an open stdin");
        writeln!(input, "{request}").expect("a process still reading");
        input.flush().expect("a flushed request");
    }

    /// Read frames until `done`, answering every challenge `answer` recognises.
    ///
    /// A challenge nobody answers is not an error — it expires on its own five-minute
    /// clock (§8) — so a test that stops answering halfway through a retry budget waits
    /// out that clock once per unanswered attempt. Answering every attempt keeps the
    /// suite's wall clock the operation's, not the challenge lifetime's.
    fn answer_until_done(&mut self, answer: impl Fn(&Value) -> Option<Value>) -> Vec<Value> {
        let mut seen = Vec::new();
        loop {
            let frame = self.next();
            seen.push(frame.clone());
            match frame["event"].as_str() {
                Some("done") => return seen,
                Some("challenge") => {
                    if let Some(response) = answer(&frame) {
                        self.send(response);
                    }
                }
                _ => {}
            }
        }
    }

    /// Close stdin and collect everything: the frames, the exit code, and stderr.
    fn finish(mut self) -> (Vec<Value>, Option<i32>, String) {
        drop(self.input.take());
        let status = self.child.wait().expect("the frames process exits").code();
        let frames = self
            .reader
            .take()
            .expect("a reader thread")
            .join()
            .expect("the reader thread finishes");
        let stderr = self
            .errors
            .take()
            .expect("a stderr thread")
            .join()
            .expect("the stderr thread finishes");
        (frames, status, stderr)
    }
}

/// §8's frame order for a whole `add`: `state running` first, every `challenge`
/// followed by `state waiting`, `done` last, and exit 0 only on `completed`.
#[test]
fn the_frames_front_end_asks_host_trust_then_review_and_ends_with_done() {
    // No pre-seeded trust here: over frames the host key *is* answerable, and answering
    // it is half of what this test is for.
    let lab = Lab::new("kr2frm", "studio");
    fs::remove_file(known_hosts_path(&lab.issuer)).expect("an unseeded trust store");

    let operation = "op-0000000000b1";
    let mut args = lab.add_args("vps", operation);
    args.extend(["--no-service".into(), "--frames".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut frames = Frames::start(lab.command(&lab.issuer, lab.target_ports, &borrowed, &[]));

    assert_eq!(
        frames.next(),
        json!({"event": "state", "state": "running"}),
        "the first frame is `state running`"
    );

    // Two challenges, each immediately followed by `state waiting`.
    for kind in ["host_trust", "review"] {
        let opened = frames.until("challenge");
        let challenge = opened.last().expect("a challenge frame").clone();
        assert_eq!(challenge["kind"], json!(kind), "{challenge:#}");
        assert!(
            challenge["expires_at"].is_string(),
            "a challenge names its expiry: {challenge:#}"
        );
        assert_eq!(
            frames.next(),
            json!({"event": "state", "state": "waiting"}),
            "a `{kind}` challenge is followed by `state waiting`"
        );
        if kind == "host_trust" {
            let metadata = &challenge["metadata"];
            assert_eq!(metadata["address"], json!("127.0.0.1"), "{challenge:#}");
            assert_eq!(metadata["port"], json!(lab.rig.port), "{challenge:#}");
            assert!(
                metadata["sha256_fingerprint"]
                    .as_str()
                    .is_some_and(|print| print.starts_with("SHA256:")),
                "{challenge:#}"
            );
        }
        frames.send(json!({
            "op": "respond",
            "challenge": challenge["challenge"],
            "accept": true,
        }));
    }

    let (seen, code, stderr) = frames.finish();
    assert_eq!(code, Some(0), "exit 0 on `completed`:\n{stderr}");

    let events: Vec<&str> = seen
        .iter()
        .filter_map(|frame| frame["event"].as_str())
        .collect();
    assert_eq!(events.first(), Some(&"state"));
    assert_eq!(seen[0]["state"], json!("running"));
    assert_eq!(
        events.last(),
        Some(&"done"),
        "`done` is the last frame: {events:?}"
    );
    assert_eq!(
        seen.last().expect("a done frame")["state"],
        json!("completed")
    );
    assert_eq!(
        seen.last().expect("a done frame")["operation"],
        json!(operation),
        "every terminal frame names its operation"
    );
    assert_eq!(
        events.iter().filter(|event| **event == "done").count(),
        1,
        "exactly one `done`: {events:?}"
    );
    // Every challenge is followed by a `state waiting`, and by nothing else first.
    for (index, event) in events.iter().enumerate() {
        if *event == "challenge" {
            assert_eq!(
                events.get(index + 1),
                Some(&"state"),
                "a challenge is followed by a state frame: {events:?}"
            );
            assert_eq!(seen[index + 1]["state"], json!("waiting"), "{events:?}");
        }
    }
    // And the operation really happened.
    assert_eq!(
        fleet::load(&lab.target)
            .expect("a readable target")
            .expect("an installed target")
            .machine,
        "vps"
    );
    assert_eq!(lab.journal(operation).state, OperationState::Completed);
}

/// A `password` challenge over frames, answered through the askpass bridge.
///
/// An unprivileged `sshd` cannot check a password, so the client is the same fake `ssh`
/// shape `fleet_setup_ssh.rs` uses: it answers `-G` by running the real one, and
/// otherwise asks `$SSH_ASKPASS` for a password exactly as OpenSSH does. What that
/// proves here is the whole chain — the engine raises a `password` challenge, the frames
/// front end emits it and waits, a `respond` carrying a `secret` answers it, and the
/// secret reaches the `ssh` child through the bridge and through nothing else.
#[test]
fn a_password_challenge_is_answered_by_a_respond_frame_and_reaches_no_command_line() {
    let lab = Lab::new("kr2pw", "studio");
    let shim_dir = lab.work.join("bin");
    fs::create_dir_all(&shim_dir).expect("a shim directory");
    let trace = lab.work.join("ssh-trace");
    write_script(
        &shim_dir.join("ssh"),
        &format!(
            r#"#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then
    exec /usr/bin/ssh "$@"
  fi
done
printf 'argv: %s\n' "$*" >> '{trace}'
printf 'env-hits: %s\n' "$(env | grep -c '{password}')" >> '{trace}'
answer=$("$SSH_ASKPASS" "{user}@127.0.0.1's password: ")
if [ "$answer" = "{password}" ]; then
  printf 'the secret arrived intact\n' >> '{trace}'
else
  printf 'the secret did not arrive\n' >> '{trace}'
fi
echo "Permission denied, please try again." >&2
exit 255
"#,
            trace = trace.display(),
            password = PASSWORD,
            user = account(),
        ),
    );

    let operation = "op-0000000000b2";
    let mut args = lab.add_args("vps", operation);
    // `--ask-password` replaces `--key`, which `add_args` put in.
    let key = args
        .iter()
        .position(|arg| arg == "--key")
        .expect("a --key flag");
    args.drain(key..key + 2);
    args.extend([
        "--ask-password".into(),
        "--no-service".into(),
        "--frames".into(),
    ]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let path = format!(
        "{}:{}",
        shim_dir.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );
    let mut frames = Frames::start(lab.command(
        &lab.issuer,
        lab.target_ports,
        &borrowed,
        &[("PATH", path.as_str())],
    ));

    assert_eq!(frames.next(), json!({"event": "state", "state": "running"}));

    let opened = frames.until("challenge");
    let challenge = opened.last().expect("a challenge").clone();
    assert_eq!(challenge["kind"], json!("password"), "{challenge:#}");
    assert_eq!(
        frames.next(),
        json!({"event": "state", "state": "waiting"}),
        "a password challenge is followed by `state waiting`"
    );
    let metadata = &challenge["metadata"];
    assert_eq!(metadata["attempt"], json!(1), "{challenge:#}");
    assert_eq!(metadata["max_attempts"], json!(3), "{challenge:#}");
    assert_eq!(metadata["user"], json!(account()), "{challenge:#}");
    assert!(
        metadata.get("prompt").is_none(),
        "a challenge carries no prompt text the far end composed: {challenge:#}"
    );

    frames.send(json!({
        "op": "respond",
        "challenge": challenge["challenge"],
        "secret": PASSWORD,
    }));

    // The fake `ssh` refuses every attempt, so OpenSSH's retry budget raises two more
    // password challenges. Each is answered the same way: the point being proved is the
    // channel the secret travels on, and the attempt counter climbing.
    let pumped = frames.answer_until_done(|frame| {
        (frame["kind"] == json!("password")).then(|| {
            json!({
                "op": "respond",
                "challenge": frame["challenge"],
                "secret": PASSWORD,
            })
        })
    });
    let attempts: Vec<u64> = pumped
        .iter()
        .filter(|frame| frame["kind"] == json!("password"))
        .filter_map(|frame| frame["metadata"]["attempt"].as_u64())
        .collect();
    assert_eq!(
        attempts,
        vec![2, 3],
        "the attempt counter climbs to the cap and stops: {attempts:?}"
    );

    let (seen, code, stderr) = frames.finish();
    // The fake `ssh` refuses every attempt, so this operation fails — and §8's exit code
    // is 0 only on `completed`.
    assert_ne!(code, Some(0), "a failed operation does not exit 0");
    let done = seen.last().expect("a done frame");
    assert_eq!(done["event"], json!("done"));
    assert_eq!(done["state"], json!("failed"), "{done:#}");
    assert_eq!(done["operation"], json!(operation));

    let recorded = fs::read_to_string(&trace).expect("the shim's trace");
    assert!(
        recorded.contains("the secret arrived intact"),
        "the answer reached the ssh child: {recorded}"
    );
    assert!(
        !recorded.contains(&format!("argv: {PASSWORD}")) && !recorded.contains(PASSWORD),
        "the password must not appear in the ssh child's arguments: {recorded}"
    );
    assert!(
        recorded.contains("env-hits: 0"),
        "the password must not appear in the ssh child's environment: {recorded}"
    );
    // Nor anywhere this operation wrote, nor on the way out.
    assert!(
        !stderr.contains(PASSWORD),
        "the password reached stderr: {stderr}"
    );
    assert!(
        !seen
            .iter()
            .any(|frame| frame.to_string().contains(PASSWORD)),
        "the password was echoed back on stdout"
    );
    let left = grep_tree(&lab.issuer, PASSWORD);
    assert!(left.is_empty(), "the password is in {left:?}");
}

// ================================================================================ resume

/// §6's resume: a step recorded `ok` is not repeated.
///
/// The operation is killed the moment its journal records `install ok`, and rerun with
/// the same `--operation`. What has to hold is that the binary is not installed a second
/// time — the release it was approved with is restored from the journal and re-verified
/// by checksum — and that the rest of the operation completes.
#[test]
fn an_interrupted_add_resumes_without_installing_the_binary_again() {
    let lab = Lab::new("kr2res", "studio");
    let operation = "op-0000000000c1";

    // A relative install path is what makes `install` a step that really runs: the
    // target has no `ouro` at `.local/bin/ouro`, so the engine has to put one there.
    // The "release" is the binary this test was compiled beside, served over loopback.
    let bytes = fs::read(OURO).expect("the built ouro");
    let version = env!("CARGO_PKG_VERSION");
    let triple = ouro::update::release::target_triple(
        std::env::consts::OS,
        &uname_machine(),
        &system_version(),
    )
    .expect("this machine is on the supported release matrix");
    let asset = ouro::update::release::asset_name(version, &triple);
    let server = fleet_setup_support::ReleaseServer::start(version, &asset, bytes.clone());

    let mut args = lab.add_args("vps", operation);
    // Replace the wrapper with a relative path under the rig's contained HOME.
    let install = args
        .iter()
        .position(|arg| arg == "--install-path")
        .expect("an --install-path flag");
    args[install + 1] = ".local/bin/ouro".into();
    args.extend(["--no-service".into(), "--yes".into(), "--json".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    // The loopback origin override, by its real name. Getting this wrong is not a
    // failing test — it is a test that quietly downloads the *official* release and
    // then asserts against it, which is how this one first "failed".
    let origin = (ouro::update::release::BASE_URL_ENV, server.base.as_str());

    // ---- run it once, and kill it as soon as `install` is recorded `ok`
    let mut child = lab
        .command(&lab.issuer, lab.target_ports, &borrowed, &[origin])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the built ouro binary");
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut interrupted = false;
    while Instant::now() < deadline {
        if Journal::read(&lab.issuer, operation)
            .ok()
            .flatten()
            .is_some_and(|record| record.completed("vps", "install"))
        {
            let _ = child.kill();
            let _ = child.wait();
            interrupted = true;
            break;
        }
        if child.try_wait().expect("a waitable child").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        interrupted,
        "the operation never recorded `install ok`: {:?}",
        Journal::read(&lab.issuer, operation)
            .ok()
            .flatten()
            .map(|record| steps(&record))
    );

    let installed = lab.rig.home.join(".local/bin/ouro");
    assert!(
        installed.is_file(),
        "the release landed at {}",
        installed.display()
    );
    assert_eq!(mode(&installed), 0o755);
    let landed = fs::read(&installed).expect("the installed bytes");
    assert_eq!(
        fleet_setup_support::ReleaseServer::sha256_of(&landed),
        fleet_setup_support::ReleaseServer::sha256_of(&bytes),
        "the installed bytes are the ones whose checksum was verified, and they came \
         from the loopback origin rather than the official one ({} bytes landed, {} served)",
        landed.len(),
        bytes.len(),
    );
    // And what landed there really answers the protocol, so a resume that talks to it
    // is talking to a helper rather than to a truncated file.
    let mut probe = Command::new(&installed)
        .args(["fleet", "helper"])
        .env("OUROBOROS_DATA_DIR", &lab.target)
        .env("HOME", &lab.rig.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the installed ouro");
    {
        let stdin = probe.stdin.as_mut().expect("a piped stdin");
        writeln!(stdin, r#"{{"v":1,"id":"probe","op":"hello"}}"#).expect("a helper reading");
    }
    let spoken = probe.wait_with_output().expect("the probe exits");
    let first = String::from_utf8_lossy(&spoken.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let reply: Value = serde_json::from_str(&first).unwrap_or_else(|error| {
        panic!(
            "the installed ouro answered `{first}` ({error}); stderr: {}",
            String::from_utf8_lossy(&spoken.stderr)
        )
    });
    assert_eq!(
        reply["version"],
        json!(env!("CARGO_PKG_VERSION")),
        "the installed ouro is this build: {reply}"
    );
    let before = fs::metadata(&installed).expect("the installed file");

    // A killed operation leaves the target standalone: `install` is the binary, not the
    // credentials, and `join` had not run.
    assert!(fleet::load(&lab.target)
        .expect("a readable target")
        .is_none());

    // ---- rerun with the same operation id
    let resumed = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[origin]);
    assert!(
        resumed.success(),
        "the resumed operation failed:\n{}\n{}",
        resumed.stdout,
        resumed.stderr
    );
    assert_eq!(resumed.json()["state"], json!("completed"));

    let record = lab.journal(operation);
    assert_eq!(record.state, OperationState::Completed);
    // `install` happened once. The resume verified the checksum of what is there rather
    // than downloading and writing it again.
    assert_eq!(
        record
            .steps
            .iter()
            .filter(|step| step.step == "install" && step.outcome == "ok")
            .count(),
        1,
        "{:?}",
        steps(&record)
    );
    assert!(
        step_detail(&record, "install").contains("verified the previously installed release"),
        "the resume re-verified rather than reinstalled: {:?}",
        steps(&record)
    );
    let after = fs::metadata(&installed).expect("the installed file");
    assert_eq!(
        before
            .modified()
            .expect("a modification time")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a time"),
        after
            .modified()
            .expect("a modification time")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a time"),
        "the binary was not written a second time"
    );
    // And the rest completed.
    in_order(&steps(&record), &["install:ok", "inspect:ok", "join:ok"]);
    assert_eq!(
        fleet::load(&lab.target)
            .expect("a readable target")
            .expect("an installed target")
            .machine,
        "vps"
    );
}

fn uname_machine() -> String {
    let output = Command::new("/usr/bin/uname")
        .arg("-m")
        .output()
        .expect("uname -m");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn system_version() -> String {
    if cfg!(target_os = "macos") {
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .expect("sw_vers");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        let output = Command::new("/usr/bin/getconf")
            .arg("GNU_LIBC_VERSION")
            .output()
            .expect("getconf");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
}

// ================================================================ a start that will not

/// §6's `start` is its own step, and a `start` that fails keeps the credentials.
///
/// The debug `ouro` has no embedded release, so nothing can actually come up here. What
/// this drives instead is a fake service manager on the *target*, handed to the helper
/// through the wrapper `--install-path` names: it accepts the detection probe and the
/// bootstrap and refuses the kickstart. The property is the one that matters after a
/// partial deployment — the bundle is on the target, the target is on this machine's
/// roster, `connect` was not attempted, and the journal says `start:failed` rather than
/// losing the whole operation.
#[test]
fn a_start_that_the_manager_refuses_keeps_the_credentials_and_says_so() {
    let fakes = scratch("kr2fake");
    let launchctl = fakes.join("launchctl");
    write_script(
        &launchctl,
        "#!/bin/sh\ncase \"$1\" in\n  print) case \"$2\" in gui/*/*) echo 'Could not find service' >&2; exit 113 ;; gui/*) exit 0 ;; esac ;;\n  bootout) exit 0 ;;\n  bootstrap) exit 0 ;;\n  kickstart) echo 'Kickstart failed: 125: Domain does not support specified action' >&2; exit 125 ;;\nesac\nexit 0\n",
    );
    let systemctl = fakes.join("systemctl");
    write_script(
        &systemctl,
        "#!/bin/sh\nshift\ncase \"$1\" in\n  show) case \"$2\" in --property=Version) echo Version=255 ;; *) printf 'LoadState=not-found\\nActiveState=inactive\\nSubState=dead\\nMainPID=0\\n' ;; esac; exit 0 ;;\n  daemon-reload|enable) exit 0 ;;\n  start) echo 'Failed to start' >&2; exit 1 ;;\nesac\nexit 0\n",
    );
    let loginctl = fakes.join("loginctl");
    write_script(&loginctl, "#!/bin/sh\necho Linger=yes\nexit 0\n");

    let lab = Lab::with_helper_env(
        "kr2nost",
        "studio",
        &[
            ("OUROBOROS_LAUNCHCTL", &launchctl),
            ("OUROBOROS_SYSTEMCTL", &systemctl),
            ("OUROBOROS_LOGINCTL", &loginctl),
        ],
    );

    let operation = "op-0000000000d1";
    let mut args = lab.add_args("vps", operation);
    args.extend(["--yes".into(), "--json".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let attempted = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[]);

    // The operation is incomplete, and says so with a nonzero exit.
    assert!(
        !attempted.success(),
        "a failed start is not a completed operation:\n{}\n{}",
        attempted.stdout,
        attempted.stderr
    );

    let record = lab.journal(operation);
    let recorded = steps(&record);
    in_order(
        &recorded,
        &[
            "join:ok",
            "service:ok",
            "start:failed",
            "remember:ok",
            "connect:skipped",
        ],
    );
    assert_eq!(record.state, OperationState::Interrupted, "{recorded:?}");
    // The credentials are on the target, and the target is on this machine's list.
    let installed = fleet::load(&lab.target)
        .expect("a readable target")
        .expect("the credentials stay on a machine that would not start");
    assert_eq!(installed.machine, "vps");
    assert_eq!(mode(&lab.target.join("fleet/cookie")), 0o600);
    assert!(lab
        .issuer_profile()
        .members
        .iter()
        .any(|member| member.machine == "vps"));
    // The unit really was written, and inside the rig's own contained HOME.
    let agents = lab.rig.home.join("Library/LaunchAgents");
    assert!(
        listing(&agents).iter().any(|name| name.ends_with(".plist")),
        "the service step installed a unit: {:?}",
        listing(&agents)
    );
    let _ = fs::remove_dir_all(&fakes);
}

// ============================================================================== residue

/// After a whole run, none of the three secrets is anywhere it could be read.
///
/// The cookie and the CA key are the fleet's; the password is the operator's. The places
/// checked are the ones an operator, a broker or a support engineer actually looks at:
/// the journal, `deploy/*.log`, everything else under either `deploy/` directory, the
/// argv and the environment of every child the rig spawned on the target, and the error
/// strings the commands printed.
#[test]
fn no_secret_survives_a_run_in_a_journal_a_log_an_argv_or_an_error() {
    let lab = Lab::new("kr2sec", "studio");
    let operation = "op-0000000000e1";
    let mut args = lab.add_args("vps", operation);
    args.extend(["--no-service".into(), "--yes".into(), "--json".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let added = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[]);
    assert!(added.success(), "{}\n{}", added.stdout, added.stderr);

    let (cookie, ca_key) = secrets(&lab.issuer);
    for (label, needle) in [
        ("the fleet cookie", cookie.as_str()),
        ("the CA key", ca_key.as_str()),
        ("the password", PASSWORD),
    ] {
        for root in [
            ouro::fleet_setup::deploy_dir(&lab.issuer),
            ouro::fleet_setup::deploy_dir(&lab.target),
        ] {
            let found = grep_tree(&root, needle);
            assert!(found.is_empty(), "{label} appears in {found:?}");
        }
        assert!(
            !lab.child_argv().contains(needle),
            "{label} reached the argv of a child on the target:\n{}",
            lab.child_argv()
        );
        assert!(
            !lab.child_env().contains(needle),
            "{label} reached the environment of a child on the target"
        );
        assert!(!added.stdout.contains(needle), "{label} reached stdout");
        assert!(!added.stderr.contains(needle), "{label} reached stderr");
    }

    // The journal is a document an operator and a broker both read; its whole shape is
    // names, times and outcomes.
    let encoded = serde_json::to_string(&lab.journal(operation)).expect("an encodable journal");
    for forbidden in ["PRIVATE KEY", "cookie", "password", "passphrase"] {
        assert!(
            !encoded.to_lowercase().contains(forbidden),
            "the journal must not mention `{forbidden}`: {encoded}"
        );
    }

    // And the log the operation's own stderr funnel writes, if it wrote one.
    let log = ouro::fleet_setup::log_path(&lab.issuer, operation);
    if log.exists() {
        assert_eq!(mode(&log), 0o600);
        let text = fs::read_to_string(&log).expect("the operation log");
        for needle in [cookie.as_str(), ca_key.as_str(), PASSWORD] {
            assert!(!text.contains(needle), "a secret is in {}", log.display());
        }
    }

    // The bundle really did cross this connection, so the search above was not looking
    // for something that was never sent.
    assert_eq!(
        fs::read_to_string(lab.target.join("fleet/cookie"))
            .expect("the target's cookie")
            .trim(),
        cookie
    );
}

// ========================================================================= hostile names

/// A machine name over the limit, and a `hello`/`inspect` reply carrying control
/// characters, are both refused with a stable reason and reach no command line.
#[test]
fn hostile_names_are_refused_with_a_stable_reason_and_reach_no_command_line() {
    let lab = Lab::new("kr2hos", "studio");

    // ---- a name over the limit never leaves this machine
    let long = "v".repeat(200);
    let mut args = lab.add_args(&long, "op-0000000000f1");
    args.extend(["--no-service".into(), "--yes".into(), "--json".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let refused = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[]);
    assert!(!refused.success(), "{}", refused.stdout);
    let document: Value = serde_json::from_str(&refused.stdout).unwrap_or_else(|error| {
        panic!(
            "a --json refusal is one document: {error}\n{}",
            refused.stdout
        )
    });
    assert_eq!(document["state"], json!("failed"));
    assert_eq!(document["reason"], json!("invalid_request"), "{document:#}");
    assert!(
        lab.child_argv().is_empty(),
        "an over-long name reached the target: {}",
        lab.child_argv()
    );
    assert!(
        Journal::read(&lab.issuer, "op-0000000000f1")
            .expect("a readable deploy directory")
            .is_none_or(|record| record.state == OperationState::Failed),
        "a refused name journals a failure at most"
    );

    // ---- a name carrying control characters is refused before anything is written
    for hostile in [
        "vps\u{1b}[31mred",
        "vps\nnewline",
        "../escape",
        "vps;rm -rf /",
    ] {
        let mut args = lab.add_args(hostile, "op-0000000000f2");
        args.extend(["--no-service".into(), "--yes".into(), "--json".into()]);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let refused = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[]);
        assert!(
            !refused.success(),
            "`{}` was accepted",
            hostile.escape_debug()
        );
        assert!(
            !refused.stdout.contains('\u{1b}') && !refused.stderr.contains('\u{1b}'),
            "a control character reached a terminal for `{}`",
            hostile.escape_debug()
        );
        assert!(
            lab.child_argv().is_empty(),
            "`{}` reached a command line on the target: {}",
            hostile.escape_debug(),
            lab.child_argv()
        );
    }

    // ---- and what a *remote* says is sanitized before it is shown
    //
    // The helper's replies are data. A `hello` that answers with control characters and
    // a version that is not ours has to produce a `version_mismatch` an operator can
    // read, with nothing in it a terminal will interpret.
    let hostile_helper = lab.work.join("hostile-helper");
    write_script(
        &hostile_helper,
        &format!(
            r#"#!/bin/sh
# The JSON escapes below are two characters each, written into a variable rather
# than into a printf format, so no shell's printf has to interpret anything.
esc='9.9.9\u001b[31;5mSYSTEM\u0007 COMPROMISED'
case "$*" in
  *"fleet helper"*)
    while IFS= read -r line; do
      id=$(printf '%s' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
      case "$line" in
        *'"op":"hello"'*)
          printf '%s\n' "{{\"v\":1,\"id\":\"$id\",\"ok\":true,\"version\":\"$esc\",\"os\":\"linux\",\"arch\":\"x86_64\"}}" ;;
        *'"op":"bye"'*) exit 0 ;;
        *)
          printf '%s\n' "{{\"v\":1,\"id\":\"$id\",\"ok\":false,\"reason\":\"failed\",\"detail\":\"$esc\"}}" ;;
      esac
    done
    exit 0 ;;
esac
exec '{ouro}' "$@"
"#,
            ouro = OURO,
        ),
    );
    {
        // The fixture has to be a fixture: a `hello` whose `version` carries the JSON
        // escapes `\u001b` and `\u0007`, which is valid JSON that decodes to control
        // characters — not a raw control byte, which would only prove that a malformed
        // frame is refused.
        let mut probe = Command::new("/bin/sh")
            .arg(&hostile_helper)
            .args(["fleet", "helper"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the hostile helper");
        writeln!(
            probe.stdin.as_mut().expect("a piped stdin"),
            r#"{{"v":1,"id":"q1","op":"hello"}}"#
        )
        .expect("a helper reading");
        let spoken = probe.wait_with_output().expect("the probe exits");
        let first = String::from_utf8_lossy(&spoken.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        assert!(
            first.contains(r"\u001b"),
            "the fixture must emit the two-character JSON escape, not a raw byte: {}",
            first.escape_debug()
        );
        let decoded: Value = serde_json::from_str(&first).unwrap_or_else(|error| {
            panic!(
                "the fixture is valid JSON: {error}: {}",
                first.escape_debug()
            )
        });
        assert!(decoded["version"]
            .as_str()
            .is_some_and(|version| version.contains('\u{1b}')));
    }

    let mut args = lab.add_args("vps", "op-0000000000f3");
    let install = args
        .iter()
        .position(|arg| arg == "--install-path")
        .expect("an --install-path");
    args[install + 1] = hostile_helper.display().to_string();
    args.extend(["--no-service".into(), "--yes".into(), "--json".into()]);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let refused = lab.ouro(&lab.issuer, lab.target_ports, &borrowed, &[]);

    assert!(!refused.success(), "{}", refused.stdout);
    let document: Value = serde_json::from_str(&refused.stdout).unwrap_or_else(|error| {
        panic!(
            "a --json refusal is one document: {error}\n{}",
            refused.stdout
        )
    });
    assert_eq!(
        document["reason"],
        json!("version_mismatch"),
        "a remote that is not our version is named, not accommodated: {document:#}"
    );
    let printed = format!("{}{}", refused.stdout, refused.stderr);
    assert!(
        !printed.contains('\u{1b}') && !printed.contains('\u{7}'),
        "a remote's control characters reached a terminal: {}",
        printed.escape_debug()
    );
    // Nothing was installed on the target by a version we refused.
    assert!(fleet::load(&lab.target)
        .expect("a readable target")
        .is_none());
}

// =============================================================== the rig's own isolation

/// The proof that a whole run of this binary writes nothing into the account's own
/// service directory, or its own `~/.ssh`.
#[test]
fn this_binary_leaves_the_accounts_own_directories_untouched() {
    if std::env::var_os("OUROBOROS_KR2_NESTED").is_some() {
        return;
    }
    let home = dirs::home_dir().expect("a home directory");
    let watched = [home.join("Library/LaunchAgents"), home.join(".ssh")];
    let before: Vec<BTreeSet<String>> = watched.iter().map(|path| listing(path)).collect();
    let known_hosts = home.join(".ssh/known_hosts");
    let known_before = fs::read(&known_hosts).ok();

    let output = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--skip",
            "this_binary_leaves_the_accounts_own_directories",
            "--test-threads",
            "2",
        ])
        .env("OUROBOROS_KR2_NESTED", "1")
        .output()
        .expect("a nested run of this binary");
    assert!(
        output.status.success(),
        "the nested run failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for (path, before) in watched.iter().zip(before) {
        assert_eq!(
            before,
            listing(path),
            "a test in this file wrote into {}",
            path.display()
        );
    }
    assert_eq!(
        known_before,
        fs::read(&known_hosts).ok(),
        "a test in this file edited the account's own known_hosts"
    );
}

fn listing(directory: &Path) -> BTreeSet<String> {
    fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}
