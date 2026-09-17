//! The detached worker: its IPC, its challenge binding, and the one property the whole
//! design exists for — that it outlives whatever started it.
//!
//! The proposal is explicit that independence is a spawn mechanism rather than a
//! promise: a worker started as a BEAM port child dies with the port. So the worker is
//! started through a launcher that `setsid`s it into its own session, and this test
//! kills the *spawner's entire process group* and then drives the operation to
//! completion over the socket. If the worker were a child of that group, nothing after
//! the kill would happen.

mod fleet_setup_support;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use fleet_setup_support::{scratch, OURO};
use ouro::fleet;
use ouro::fleet_setup::journal::Journal;
use ouro::fleet_setup::{OperationKind, OperationRequest, OperationState, PortPolicy};

/// One client of the worker's socket, speaking seam S3.
struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u32,
}

impl Client {
    fn connect(socket: &Path) -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(socket) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(30)))
                        .expect("a bounded read");
                    return Self {
                        reader: BufReader::new(stream.try_clone().expect("a cloned socket")),
                        writer: stream,
                        next_id: 0,
                    };
                }
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("connecting to {}: {error}", socket.display()),
            }
        }
    }

    /// Send a request and return the reply, skipping any unsolicited events that arrive
    /// first (events carry `event`, replies carry `id`).
    fn ask(&mut self, op: &str, mut fields: Value) -> Value {
        self.next_id += 1;
        let id = format!("c{}", self.next_id);
        fields["v"] = json!(1);
        fields["id"] = json!(id);
        fields["op"] = json!(op);
        writeln!(self.writer, "{fields}").expect("a worker still reading");
        self.writer.flush().expect("a flushed frame");
        loop {
            let frame = self.read_frame();
            if frame.get("id").and_then(Value::as_str) == Some(id.as_str()) {
                return frame;
            }
        }
    }

    fn read_frame(&mut self) -> Value {
        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .expect("a frame from the worker");
        assert!(read > 0, "the worker closed the connection");
        serde_json::from_str(line.trim()).expect("a frame is one JSON object")
    }

    /// Wait for one unsolicited event of the given name.
    fn await_event(&mut self, event: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let frame = self.read_frame();
            if frame.get("event").and_then(Value::as_str) == Some(event) {
                return frame;
            }
            assert!(
                Instant::now() < deadline,
                "no `{event}` event arrived; last was {frame}"
            );
        }
    }
}

fn data_dir(label: &str) -> PathBuf {
    let path = scratch(label);
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("a private data directory");
    path
}

fn ephemeral() -> PortPolicy {
    let ports = fleet::ephemeral_ports();
    PortPolicy {
        gateway: ports.gateway,
        dist: ports.dist,
        epmd: ports.epmd,
    }
}

/// Write the request the broker would write before starting a worker.
fn write_request(data_dir: &Path, request: &OperationRequest) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = ouro::fleet_setup::ensure_deploy_dir(data_dir).expect("a deploy directory");
    let path = dir.join(format!("{}.request.json", request.operation));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(request).expect("an encodable request"),
    )
    .expect("a written request");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("a private request");
}

/// Start the worker through a shell that is a process-group leader, so the test can kill
/// the whole group the way a stopping BEAM takes its port children with it.
struct Spawner {
    pid: i32,
    socket: PathBuf,
    instance: String,
}

fn spawn_detached(data_dir: &Path, operation: &str) -> Spawner {
    use std::os::unix::process::CommandExt as _;

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "exec {ouro} fleet worker start --operation {operation} --data-dir {dir}",
            ouro = OURO,
            dir = data_dir.display()
        ))
        .env("OUROBOROS_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("the built ouro binary");

    let pid = child.id() as i32;
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("a piped stdout"))
        .read_line(&mut line)
        .expect("the socket line");
    let status = child.wait().expect("the launcher to exit");
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        use std::io::Read as _;
        let _ = handle.read_to_string(&mut stderr);
    }
    assert!(
        status.success(),
        "`fleet worker start` failed: {stderr} {line}"
    );
    let started: Value = serde_json::from_str(line.trim())
        .unwrap_or_else(|error| panic!("the socket line is JSON: {error}: {line}"));
    Spawner {
        pid,
        socket: PathBuf::from(
            started["socket"]
                .as_str()
                .expect("the socket line names a socket"),
        ),
        instance: started["instance"]
            .as_str()
            .expect("the socket line names an instance")
            .to_string(),
    }
}

/// The whole point: a worker that outlives its spawner's process group, and an operation
/// driven to completion over the socket after that group is gone.
#[test]
fn the_worker_outlives_its_spawner_and_finishes_the_operation() {
    let data = data_dir("wkr");
    let operation = "op-000000009001";
    let mut request = OperationRequest::new(operation, OperationKind::Setup, "studio");
    request.address = Some("127.0.0.1".into());
    request.service = false;
    request.ports = Some(ephemeral());
    write_request(&data, &request);

    let spawner = spawn_detached(&data, operation);
    assert!(
        spawner.socket.exists(),
        "the worker is listening at {}",
        spawner.socket.display()
    );
    assert_eq!(
        spawner.instance.len(),
        32,
        "an instance id is 16 random bytes"
    );

    // Seam S2's reconciliation: the request file has served its purpose by the time the
    // socket line is printed, and does not lie around describing the target.
    assert!(
        !ouro::fleet_setup::request_path(&data, operation).exists(),
        "the request file is consumed once the worker is listening"
    );
    // And the journal already names what the operation is for.
    let early = Journal::read(&data, operation)
        .expect("a readable journal")
        .expect("a journal written before the child started");
    assert_eq!(
        early.target.as_ref().map(|target| target.machine.as_str()),
        Some("studio")
    );

    // Kill the spawner's entire process group. A worker that was a child of it would go
    // with it, and nothing below would happen.
    // SAFETY: the pid is this test's own child, a process-group leader it created.
    unsafe {
        libc::kill(-spawner.pid, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(100));

    let capability = std::fs::read_to_string(ouro::fleet_setup::capability_path(&data, operation))
        .expect("a capability file")
        .trim()
        .to_string();
    assert_eq!(capability.len(), 64, "32 random bytes, hex");

    let mut client = Client::connect(&spawner.socket);

    // A frame before `attach` is refused, and the capability is what admits one.
    let early = client.ask("status", json!({}));
    assert_eq!(early["ok"], json!(false));
    assert_eq!(early["reason"], json!("not_attached"));

    let wrong = client.ask(
        "attach",
        json!({"cap": "0".repeat(64), "subject": "operator", "session": "s1"}),
    );
    assert_eq!(wrong["ok"], json!(false));
    assert_eq!(wrong["reason"], json!("bad_capability"));

    let attached = client.ask(
        "attach",
        json!({"cap": capability, "subject": "operator", "session": "s1"}),
    );
    assert_eq!(attached["ok"], json!(true), "{attached}");
    assert_eq!(attached["operation"], json!(operation));
    assert_eq!(attached["instance"], json!(spawner.instance));
    assert_eq!(
        attached["owner"],
        json!("operator"),
        "the first client to attach owns the operation"
    );
    assert_eq!(
        Journal::read(&data, operation)
            .expect("a readable journal")
            .expect("a written journal")
            .owner
            .as_deref(),
        Some("operator"),
        "and that is durable, because the worker outlives the session that started it"
    );

    // A second *subject* is not handed this one's operation, or its challenges.
    let mut stranger = Client::connect(&spawner.socket);
    let refused = stranger.ask(
        "attach",
        json!({"cap": capability, "subject": "somebody-else", "session": "s9"}),
    );
    assert_eq!(refused["ok"], json!(false), "{refused}");
    assert_eq!(refused["reason"], json!("not_owner"));
    assert_eq!(
        stranger.ask("status", json!({}))["reason"],
        json!("not_attached"),
        "a refused attach leaves the connection unattached"
    );

    // The operation is waiting for its review, and the challenge is bound to this
    // session.
    let challenge = client.await_event("challenge");
    assert_eq!(challenge["kind"], json!("review"));
    let id = challenge["challenge"]
        .as_str()
        .expect("a challenge id")
        .to_string();
    let digest = challenge["metadata"]["plan_digest"]
        .as_str()
        .expect("the digest the approval binds to")
        .to_string();

    // Another session of the same subject can attach, and still cannot answer the first
    // session's challenge.
    let mut intruder = Client::connect(&spawner.socket);
    let second = intruder.ask(
        "attach",
        json!({"cap": capability, "subject": "operator", "session": "other-tab"}),
    );
    assert_eq!(second["ok"], json!(true), "{second}");
    assert_eq!(second["owner"], json!("operator"));
    assert_eq!(
        intruder.ask("status", json!({}))["owner"],
        json!("operator"),
        "every status snapshot names the owner"
    );
    let stolen = intruder.ask(
        "respond",
        json!({"challenge": id, "response": {"approve": true, "plan_digest": digest}}),
    );
    assert_eq!(stolen["ok"], json!(false));
    assert_eq!(stolen["reason"], json!("challenge_not_bound"), "{stolen}");

    // The session it was issued to can, once.
    let approved = client.ask(
        "respond",
        json!({"challenge": id, "response": {"approve": true, "plan_digest": digest}}),
    );
    assert_eq!(approved["ok"], json!(true), "{approved}");
    let replay = client.ask(
        "respond",
        json!({"challenge": id, "response": {"approve": true, "plan_digest": digest}}),
    );
    assert_eq!(replay["ok"], json!(false));
    assert_eq!(replay["reason"], json!("challenge_consumed"));

    let done = client.await_event("done");
    assert_eq!(done["ok"], json!(true), "{done}");
    assert_eq!(done["state"], json!("completed"));

    // The machine really was set up, by a process whose spawner has been dead the whole
    // time.
    let profile = fleet::load(&data)
        .expect("a readable profile")
        .expect("a created profile");
    assert_eq!(profile.machine, "studio");
    assert_eq!(profile.host, "127.0.0.1");

    let record = Journal::read(&data, operation)
        .expect("a readable journal")
        .expect("a written journal");
    assert_eq!(record.state, OperationState::Completed);
    assert!(record.completed("studio", "create"));

    // And a takeover is allowed, explicit, and written down with both names.
    let mut successor = Client::connect(&spawner.socket);
    let taken = successor.ask(
        "attach",
        json!({
            "cap": capability, "subject": "somebody-else", "session": "s10",
            "takeover": true
        }),
    );
    assert_eq!(taken["ok"], json!(true), "{taken}");
    assert_eq!(taken["owner"], json!("somebody-else"));
    let record = Journal::read(&data, operation)
        .expect("a readable journal")
        .expect("a written journal");
    assert_eq!(record.owner.as_deref(), Some("somebody-else"));
    let takeover = record
        .steps
        .iter()
        .find(|step| step.step == "takeover")
        .expect("a recorded takeover");
    let detail = takeover.detail.clone().unwrap_or_default();
    assert!(detail.contains("somebody-else"), "{detail}");
    assert!(detail.contains("operator"), "{detail}");
    assert_eq!(successor.ask("bye", json!({}))["ok"], json!(true));
    // `stranger` never attached, so it has nothing to say goodbye to: seam S3's first
    // frame is always `attach`, and it stays refused until one succeeds.
    assert_eq!(
        stranger.ask("bye", json!({}))["reason"],
        json!("not_attached")
    );
    drop(stranger);

    // Both clients say goodbye; the worker exits once nothing is attached rather than
    // waiting out its linger.
    assert_eq!(client.ask("bye", json!({}))["ok"], json!(true));
    assert_eq!(intruder.ask("bye", json!({}))["ok"], json!(true));

    // The worker cleans up after itself.
    let deadline = Instant::now() + Duration::from_secs(30);
    while spawner.socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!spawner.socket.exists(), "the worker removed its socket");
    assert!(
        !ouro::fleet_setup::capability_path(&data, operation).exists(),
        "the worker removed its capability file"
    );
}

/// A worker refuses to start without a private request describing what to do.
#[test]
fn a_worker_without_a_private_request_refuses_by_name() {
    let data = data_dir("wkrq");
    let operation = "op-000000009002";
    ouro::fleet_setup::ensure_deploy_dir(&data).expect("a deploy directory");

    let missing = start_output(&data, operation);
    assert!(!missing.0, "a worker with no request does not start");
    assert!(
        missing.1.contains("no request"),
        "the refusal says what is missing: {}",
        missing.1
    );

    // A request any other account could read is not a private request.
    let mut request = OperationRequest::new(operation, OperationKind::Setup, "studio");
    request.address = Some("127.0.0.1".into());
    write_request(&data, &request);
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            ouro::fleet_setup::request_path(&data, operation),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("a loose mode");
    }
    let loose = start_output(&data, operation);
    assert!(!loose.0, "a world-readable request is not read");
    assert!(
        loose.1.contains("mode 0600"),
        "the refusal names the requirement: {}",
        loose.1
    );

    // And a document that is not a deployment request at all.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = ouro::fleet_setup::request_path(&data, operation);
        std::fs::write(&path, b"{\"schema\":1,\"nope\":true}").expect("a written file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("a private mode");
    }
    let malformed = start_output(&data, operation);
    assert!(!malformed.0);
    assert!(
        malformed.1.contains("not a deployment request"),
        "{}",
        malformed.1
    );
}

/// Run `fleet worker start` and return (success, stderr).
fn start_output(data_dir: &Path, operation: &str) -> (bool, String) {
    let output = Command::new(OURO)
        .args(["fleet", "worker", "start", "--operation", operation])
        .arg("--data-dir")
        .arg(data_dir)
        .env("OUROBOROS_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .output()
        .expect("the built ouro binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// `ouro fleet askpass` refuses to run outside an operation.
#[test]
fn the_askpass_helper_is_useless_without_its_operation() {
    let output = Command::new(OURO)
        .args(["fleet", "askpass", "Password: "])
        .env_remove("OUROBOROS_ASKPASS_SOCKET")
        .stdin(Stdio::null())
        .output()
        .expect("the built ouro binary");
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a refusal prints nothing on stdout, which ssh reads as no answer"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("OUROBOROS_ASKPASS_SOCKET"),
        "the refusal says why: {stderr}"
    );
}
