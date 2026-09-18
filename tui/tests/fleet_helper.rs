//! `ouro fleet helper` as the process an issuer actually talks to.
//!
//! Every frame here crosses a real pipe into a real `ouro` started the way `ssh host
//! ouro fleet helper` starts one: no terminal, no arguments, and a data directory it
//! learns from its environment rather than from the request. The library half of
//! admission is unit-tested in `src/fleet.rs`; what these tests are for is the wire —
//! the envelope, the refusal reasons an orchestrator branches on, the frame cap, and
//! the fact that a machine admitted entirely through this protocol is one
//! `ouro fleet doctor` calls healthy.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};

const OURO: &str = env!("CARGO_BIN_EXE_ouro");
/// Every exchange here is one small computation. Twenty seconds is orders of magnitude
/// more than any of them needs and short enough that a hang fails rather than waits.
const REPLY_DEADLINE: Duration = Duration::from_secs(20);

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// `fleet::ephemeral_ports` picks free loopback ports by binding them and letting them
/// go, so two threads that call it at the same moment can be handed the same number:
/// the second is still holding the listener when the first probes the port, and
/// `create` correctly refuses a port with something unexplained on it. Every test here
/// that chooses ports holds this for its duration, so within this binary the choosing
/// and the using never overlap. It is a test-harness fact, not a property of the code
/// under test.
static FLEET_PORTS: Mutex<()> = Mutex::new(());

fn fleet_ports() -> MutexGuard<'static, ()> {
    FLEET_PORTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ouro-fleet-helper-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("a writable scratch directory");
    // A data directory handed to `ouro` is a private same-user boundary.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("a chmodable directory");
    path
}

/// One `ouro fleet helper` process, spoken to over its own stdin and stdout.
struct Session {
    child: Child,
    input: Option<ChildStdin>,
    replies: Receiver<String>,
    next_id: u32,
}

impl Session {
    fn start(data_dir: &Path) -> Self {
        let mut child = Command::new(OURO)
            .args(["fleet", "helper"])
            .env("OUROBOROS_DATA_DIR", data_dir)
            .env_remove("OUROBOROS_GATEWAY_ADDR")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the built ouro binary");
        let input = child.stdin.take().expect("a piped stdin");
        let output = child.stdout.take().expect("a piped stdout");
        let (sender, replies) = channel();
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            replies,
            next_id: 0,
        }
    }

    fn send_raw(&mut self, line: &str) {
        let input = self.input.as_mut().expect("an open stdin");
        input
            .write_all(line.as_bytes())
            .and_then(|()| input.write_all(b"\n"))
            .and_then(|()| input.flush())
            .expect("a helper still reading its stdin");
    }

    fn read_reply(&mut self) -> Value {
        let line = self
            .replies
            .recv_timeout(REPLY_DEADLINE)
            .expect("a reply frame within the deadline");
        serde_json::from_str(&line).expect("a reply frame is one JSON object")
    }

    /// Ask one operation, with an id this session generates and checks came back.
    fn ask(&mut self, request: Value) -> Value {
        let mut request = match request {
            Value::Object(map) => map,
            other => panic!("a request must be an object: {other}"),
        };
        self.next_id += 1;
        let id = format!("r{}", self.next_id);
        request.insert("v".to_string(), json!(1));
        request.insert("id".to_string(), Value::String(id.clone()));
        self.send_raw(&Value::Object(request).to_string());
        let reply = self.read_reply();
        assert_eq!(
            reply["v"],
            json!(1),
            "every reply names the envelope version"
        );
        assert_eq!(
            reply["id"],
            json!(id),
            "a reply answers the request it was for"
        );
        reply
    }

    fn ok(&mut self, request: Value) -> Value {
        let reply = self.ask(request);
        assert_eq!(reply["ok"], json!(true), "expected success, got {reply}");
        reply
    }

    fn refused(&mut self, request: Value) -> Value {
        let reply = self.ask(request);
        assert_eq!(reply["ok"], json!(false), "expected a refusal, got {reply}");
        assert!(
            reply["detail"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "a refusal explains itself to a person: {reply}"
        );
        reply
    }

    fn reason(&mut self, request: Value) -> String {
        self.refused(request)["reason"]
            .as_str()
            .expect("a refusal names a stable reason")
            .to_string()
    }

    /// Send a line over the 1 MiB cap; the helper refuses it and stops reading.
    fn send_oversized_frame(&mut self) {
        let oversized = format!(
            "{{\"v\":1,\"id\":\"big\",\"op\":\"hello\",\"pad\":\"{}\"}}",
            "x".repeat(ouro::fleet_helper::MAX_FRAME_BYTES)
        );
        self.send_raw(&oversized);
        let reply = self.read_reply();
        assert_eq!(reply["ok"], json!(false), "{reply}");
        assert_eq!(reply["reason"], json!("frame_too_large"), "{reply}");
        assert_eq!(
            reply["id"],
            Value::Null,
            "a frame that was never parsed has no id to echo"
        );
    }

    /// Close stdin, wait for the exit, and return the code with anything on stderr.
    fn finish(mut self) -> (i32, String) {
        drop(self.input.take());
        let status = self.child.wait().expect("the helper to exit");
        let mut stderr = String::new();
        if let Some(mut handle) = self.child.stderr.take() {
            let _ = handle.read_to_string(&mut stderr);
        }
        (status.code().unwrap_or(-1), stderr)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The subset of a reply that is an admission request, without the envelope around it.
fn admission_request(reply: &Value) -> ouro::fleet::AdmissionRequest {
    let mut fields: Map<String, Value> = reply.as_object().expect("an object reply").clone();
    for envelope in ["v", "id", "ok"] {
        fields.remove(envelope);
    }
    serde_json::from_value(Value::Object(fields)).expect("a reply that is an admission request")
}

/// A fleet on the issuer, with ports that never touch the production spaces.
fn issuer_fleet(label: &str) -> PathBuf {
    let data = scratch(label);
    ouro::fleet::create(
        &data,
        Some("the lab"),
        "studio",
        "127.0.0.1",
        ouro::fleet::ephemeral_ports(),
    )
    .expect("a created fleet");
    data
}

fn ephemeral_ports_value() -> Value {
    let ports = ouro::fleet::ephemeral_ports();
    json!({"gateway": ports.gateway, "dist": ports.dist, "epmd": ports.epmd})
}

fn doctor(data_dir: &Path) -> (bool, String) {
    let output = Command::new(OURO)
        .args(["fleet", "doctor"])
        .env("OUROBOROS_DATA_DIR", data_dir)
        .output()
        .expect("the built ouro binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// A whole machine admitted over the wire, and nothing else.
///
/// The issuer's half runs in this process because it is the half that holds the CA key
/// and never speaks the protocol; everything the target does crosses the pipe.
#[test]
fn a_machine_joins_a_fleet_entirely_through_the_helper_and_doctor_calls_it_healthy() {
    let _ports = fleet_ports();
    let issuer = issuer_fleet("e2e-issuer");
    let target = scratch("e2e-target");
    let operation = "op-e2e-00000001";
    let mut helper = Session::start(&target);

    let hello = helper.ok(json!({"op": "hello"}));
    assert_eq!(hello["helper"], json!(ouro::fleet_helper::HELPER_VERSION));
    assert_eq!(hello["wire"], json!(ouro::fleet_helper::WIRE_VERSION));
    // Seam C1: the revision and the build metadata arrive with the protocol module.
    assert_eq!(
        hello["protocol"],
        serde_json::json!(ouro::fleet_protocol::FLEET_PROTOCOL_REVISION)
    );

    let before = helper.ok(json!({"op": "inspect"}));
    assert_eq!(before["fleet"], Value::Null);
    assert_eq!(
        before["build"]["fleet_protocol_revision"],
        serde_json::json!(ouro::fleet_protocol::FLEET_PROTOCOL_REVISION),
        "seam C1: inspect carries the build contract"
    );
    assert!(before["build"]["ouroboros_version"].is_string(), "seam C1");
    assert_eq!(before["runtime_running"], json!(false));
    assert_eq!(before["data_dir"], json!(target.display().to_string()));
    assert_eq!(before["os"], json!(std::env::consts::OS));
    assert_eq!(before["pending_operations"], json!([]));

    let prepared = helper.ok(json!({
        "op": "prepare",
        "operation": operation,
        "machine": "vps",
        "host": "127.0.0.1",
    }));
    assert_eq!(prepared["node"], json!("ouro-vps@127.0.0.1"));
    let request = admission_request(&prepared);
    assert!(
        !prepared.to_string().contains("PRIVATE KEY"),
        "the key stays on the target: {prepared}"
    );
    assert_eq!(
        helper.ok(json!({"op": "inspect"}))["pending_operations"],
        json!([operation]),
        "a prepared operation is visible to the orchestrator that has to resume it"
    );

    // The issuer's side: the only step that reads the CA key, on the machine it lives
    // on, with no wire involved.
    let materials =
        ouro::fleet::issue_member_certificate(&issuer, &request).expect("issued materials");
    let encoded = serde_json::to_value(&materials).expect("encodable materials");
    assert!(
        !encoded.to_string().contains("PRIVATE KEY"),
        "nothing with a private key is put on the wire"
    );

    let installed = helper.ok(json!({
        "op": "install",
        "operation": operation,
        "materials": encoded.clone(),
        "ports": ephemeral_ports_value(),
    }));
    assert_eq!(installed["node"], json!("ouro-vps@127.0.0.1"));
    assert_eq!(installed["members"], json!(["studio", "vps"]));

    let after = helper.ok(json!({"op": "inspect"}));
    assert_eq!(after["fleet"]["node"], json!("ouro-vps@127.0.0.1"));
    assert_eq!(after["fleet"]["name"], json!("the lab"));
    assert_eq!(after["pending_operations"], json!([]));
    let cookie = fs::read_to_string(target.join("fleet/cookie")).expect("an installed cookie");
    assert!(
        !after.to_string().contains(cookie.trim()),
        "inspection carries no secret"
    );
    assert!(
        !target
            .join("fleet")
            .join("ca-key.pem")
            .try_exists()
            .expect("a readable fleet directory"),
        "an admitted machine is given a CA certificate, never the CA key"
    );

    let receipt = helper.ok(json!({"op": "receipt", "operation": operation}));
    let steps: Vec<String> = receipt["receipt"]["steps"]
        .as_array()
        .expect("recorded steps")
        .iter()
        .map(|step| step["step"].as_str().expect("a step name").to_string())
        .collect();
    assert_eq!(steps, vec!["prepare", "install_staged", "install"]);
    assert!(!receipt.to_string().contains(cookie.trim()));

    let appended = helper.ok(json!({
        "op": "receipt",
        "operation": operation,
        "append": {"step": "service_started", "outcome": "ok", "detail": "by the operator"},
    }));
    assert_eq!(
        appended["receipt"]["steps"]
            .as_array()
            .expect("recorded steps")
            .len(),
        4
    );

    // The roster op, on the machine that was just admitted.
    let revision = after["fleet"]["roster_revision"]
        .as_u64()
        .expect("a roster revision");
    let added = helper.ok(json!({
        "op": "roster",
        "operation": "op-e2e-roster-001",
        "expected_revision": revision,
        "change": {"kind": "add", "machine": "laptop", "host": "127.0.0.1"},
    }));
    assert_eq!(added["roster_revision"], json!(revision + 1));
    assert_eq!(added["member"]["node"], json!("ouro-laptop@127.0.0.1"));

    let conflict = helper.refused(json!({
        "op": "roster",
        "operation": "op-e2e-roster-002",
        "expected_revision": revision,
        "change": {"kind": "remove", "machine": "laptop"},
    }));
    assert_eq!(conflict["reason"], json!("roster_conflict"));
    assert_eq!(
        conflict["roster_revision"],
        json!(revision + 1),
        "the refusal hands back the revision the caller has to re-read"
    );

    // Installing the same materials again is the answer to a lost connection, not a
    // second identity.
    let repeated = helper.ok(json!({
        "op": "install",
        "operation": operation,
        "materials": encoded,
        "ports": ephemeral_ports_value(),
    }));
    assert_eq!(repeated["node"], json!("ouro-vps@127.0.0.1"));

    let goodbye = helper.ok(json!({"op": "bye"}));
    assert_eq!(goodbye["ok"], json!(true));
    let (code, _stderr) = helper.finish();
    assert_eq!(code, 0, "`bye` ends the session cleanly");

    let (healthy, text) = doctor(&target);
    assert!(
        healthy,
        "an admitted machine must pass local doctor:\n{text}"
    );
    assert!(text.contains("ouro-vps@127.0.0.1"), "{text}");
}

/// Every refusal an orchestrator has to branch on, over the wire, and a connection
/// that survives all of them.
#[test]
fn every_refusal_names_a_stable_reason_and_none_of_them_drops_the_connection() {
    let _ports = fleet_ports();
    let target = scratch("reasons-target");
    let issuer = issuer_fleet("reasons-issuer");
    let mut helper = Session::start(&target);

    assert_eq!(
        helper.reason(json!({"op": "upload", "path": "/bin/ouro"})),
        "unsupported_op"
    );
    assert_eq!(
        helper.reason(
            json!({"op": "prepare", "operation": "../../etc", "machine": "vps", "host": "127.0.0.1"})
        ),
        "invalid_request"
    );
    assert_eq!(
        helper.reason(
            json!({"op": "prepare", "operation": "op-reasons-0001", "machine": "not a machine", "host": "127.0.0.1"})
        ),
        "invalid_request"
    );
    assert_eq!(
        helper.reason(json!({"op": "prepare", "operation": "op-reasons-0001"})),
        "failed",
        "a missing field is explained rather than given a coded reason"
    );
    assert_eq!(
        helper.reason(json!({"op": "inspect", "data_dir": "/etc"})),
        "invalid_path"
    );
    assert_eq!(
        helper.reason(json!({"op": "inspect", "data_dir": "relative/path"})),
        "invalid_path"
    );
    assert_eq!(
        helper.reason(
            json!({"op": "receipt", "operation": "op-reasons-9999", "append": {"step": "x", "outcome": "ok"}})
        ),
        "unknown_operation"
    );
    assert_eq!(
        helper.ok(json!({"op": "receipt", "operation": "op-reasons-9999"}))["receipt"],
        Value::Null,
        "reading an operation this machine never saw is an empty answer, not a refusal"
    );

    let prepared = helper.ok(json!({
        "op": "prepare",
        "operation": "op-reasons-0003",
        "machine": "vps",
        "host": "127.0.0.1",
    }));
    let request = admission_request(&prepared);
    assert_eq!(
        helper.reason(json!({
            "op": "prepare",
            "operation": "op-reasons-0004",
            "machine": "vps",
            "host": "127.0.0.1",
        })),
        "operation_in_progress"
    );
    assert_eq!(
        helper.reason(json!({
            "op": "prepare",
            "operation": "op-reasons-0003",
            "machine": "laptop",
            "host": "127.0.0.1",
        })),
        "identity_mismatch"
    );

    let materials =
        ouro::fleet::issue_member_certificate(&issuer, &request).expect("issued materials");
    let encoded = serde_json::to_value(&materials).expect("encodable materials");

    assert_eq!(
        helper.reason(json!({
            "op": "install",
            "operation": "op-reasons-0005",
            "materials": encoded.clone(),
        })),
        "failed",
        "materials for one operation do not install under another"
    );

    // A sender that adds the authority to sign is refused by the shape of the message
    // it is trying to fill.
    let mut smuggled = encoded.as_object().expect("an object").clone();
    smuggled.insert(
        "ca_key_pem".to_string(),
        json!("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
    );
    let refusal = helper.refused(json!({
        "op": "install",
        "operation": "op-reasons-0003",
        "materials": Value::Object(smuggled),
    }));
    assert!(
        refusal["detail"]
            .as_str()
            .expect("a detail")
            .contains("ca_key_pem"),
        "the refusal names the field that does not belong: {refusal}"
    );

    let mut hidden = encoded.as_object().expect("an object").clone();
    hidden.insert(
        "ca_cert_pem".to_string(),
        json!(format!(
            "{}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            materials.ca_cert_pem
        )),
    );
    assert_eq!(
        helper.reason(json!({
            "op": "install",
            "operation": "op-reasons-0003",
            "materials": Value::Object(hidden),
        })),
        "materials_carry_private_key"
    );

    // A roster op on a machine that has no roster yet.
    assert_eq!(
        helper.reason(json!({
            "op": "roster",
            "operation": "op-reasons-0006",
            "expected_revision": 1,
            "change": {"kind": "remove", "machine": "studio"},
        })),
        "no_fleet"
    );

    // A machine that never prepared has no key for these credentials to belong to.
    let stranger = scratch("reasons-stranger");
    let mut other = Session::start(&stranger);
    assert_eq!(
        other.reason(json!({
            "op": "install",
            "operation": "op-reasons-0003",
            "materials": encoded,
            "ports": ephemeral_ports_value(),
        })),
        "staging_missing"
    );
    other.ok(json!({"op": "bye"}));

    // And the whole session is still answering.
    assert_eq!(helper.ok(json!({"op": "hello"}))["ok"], json!(true));
    helper.ok(json!({"op": "bye"}));
    assert_eq!(helper.finish().0, 0);
}

/// A helper on a machine that already has a fleet refuses to prepare another identity.
#[test]
fn a_helper_on_a_machine_that_already_has_a_fleet_refuses_to_prepare_another() {
    let _ports = fleet_ports();
    let issuer = issuer_fleet("occupied-issuer");
    let mut helper = Session::start(&issuer);

    let inspected = helper.ok(json!({"op": "inspect"}));
    assert_eq!(inspected["fleet"]["machine"], json!("studio"));
    assert_eq!(inspected["fleet"]["members"], json!(["studio"]));

    assert_eq!(
        helper.reason(json!({
            "op": "prepare",
            "operation": "op-occupied-0001",
            "machine": "vps",
            "host": "127.0.0.1",
        })),
        "fleet_exists"
    );

    assert_eq!(
        helper.ok(json!({"op": "inspect"}))["fleet"]["machine"],
        json!("studio"),
        "and nothing about the machine changed"
    );
    helper.ok(json!({"op": "bye"}));
}

/// The envelope rules over the pipe: malformed input is answered and survived, and a
/// line over the cap ends the session rather than being buffered.
#[test]
fn malformed_input_is_survivable_and_an_oversized_frame_ends_the_session() {
    let target = scratch("frames-target");
    let mut helper = Session::start(&target);

    for line in [
        "this is not JSON",
        "[1, 2, 3]",
        r#""a string is not a request""#,
        r#"{"v":1,"op":"hello"}"#,
        r#"{"v":1,"id":7,"op":"hello"}"#,
    ] {
        helper.send_raw(line);
        let reply = helper.read_reply();
        assert_eq!(reply["ok"], json!(false), "{line}");
        assert_eq!(reply["reason"], json!("bad_request"), "{line}");
        assert_eq!(
            reply["id"],
            Value::Null,
            "a reply never echoes an id the request did not carry: {line}"
        );
    }

    // A frame that named itself but nothing else is answered with its own id: the
    // request was readable, and only the operation was missing.
    helper.send_raw(r#"{"v":1,"id":"named","op":42}"#);
    let reply = helper.read_reply();
    assert_eq!(reply["reason"], json!("bad_request"));
    assert_eq!(reply["id"], json!("named"));

    // Blank lines are not frames and are not answered.
    helper.send_raw("");
    helper.send_raw("   ");
    assert_eq!(helper.ok(json!({"op": "hello"}))["ok"], json!(true));

    helper.send_oversized_frame();
    let (code, _stderr) = helper.finish();
    assert_eq!(
        code, 0,
        "an oversized frame is refused by name, and then the helper exits"
    );
}

/// An unknown envelope version is its own answer, and a helper started without a
/// terminal writes frames on stdout and prose on stderr.
#[test]
fn stdout_carries_frames_only_and_the_envelope_version_is_checked() {
    let target = scratch("stdout-target");
    let mut helper = Session::start(&target);

    helper.send_raw(r#"{"v":99,"id":"z","op":"hello"}"#);
    let reply = helper.read_reply();
    assert_eq!(reply["reason"], json!("unsupported_version"));
    assert_eq!(reply["id"], json!("z"));

    // Three requests, three reply lines, and no banner, prompt or progress line
    // between them: the process on the other end parses every byte of this stream.
    helper.ok(json!({"op": "hello"}));
    helper.ok(json!({"op": "inspect"}));
    let goodbye = helper.ok(json!({"op": "bye"}));
    assert_eq!(goodbye["ok"], json!(true));

    let (code, stderr) = helper.finish();
    assert_eq!(code, 0);
    assert!(
        !stderr.contains('{'),
        "diagnostics are prose on stderr, never frames: {stderr}"
    );
}

/// End of input is end of session: the helper exits 0 rather than waiting for a
/// connection that is already gone.
#[test]
fn closing_stdin_ends_the_session_without_a_frame() {
    let target = scratch("eof-target");
    let mut helper = Session::start(&target);
    helper.ok(json!({"op": "hello"}));

    let (code, _stderr) = helper.finish();
    assert_eq!(code, 0);
}

/// The helper is not a command an operator types, and nothing about the machine being
/// admitted may reach a command line that `ps` publishes to every process on the host.
#[test]
fn the_helper_is_hidden_from_help_and_accepts_no_arguments() {
    let data_dir = scratch("hidden-help");
    let listing = Command::new(OURO)
        .args(["fleet", "--help"])
        .env("OUROBOROS_DATA_DIR", &data_dir)
        .stdin(Stdio::null())
        .output()
        .expect("the built ouro binary");
    let text = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.status.success(), "{text}");
    assert!(
        text.contains("doctor") && text.contains("status"),
        "the operator's fleet commands are still listed:\n{text}"
    );
    assert!(
        !text.contains("helper"),
        "the setup helper is a protocol endpoint, not an operator command:\n{text}"
    );

    for arguments in [
        vec!["fleet", "helper", "--data-dir", "/tmp"],
        vec!["fleet", "helper", "--operation", "op-12345678"],
        vec!["fleet", "helper", "--machine", "vps"],
        vec!["fleet", "helper", "--cookie", "secret"],
        vec!["fleet", "helper", "prepare"],
    ] {
        let refused = Command::new(OURO)
            .args(&arguments)
            .env("OUROBOROS_DATA_DIR", &data_dir)
            .stdin(Stdio::null())
            .output()
            .expect("the built ouro binary");
        assert!(
            !refused.status.success(),
            "`ouro {}` must not be accepted: a flag here is a secret or an identity in \
             every process's view of this host",
            arguments.join(" ")
        );
    }
}

/// A refusal is written for a person to read, and the thing it refused holds the
/// fleet's cookie. No refusal may quote one back.
#[test]
fn a_refused_install_never_quotes_the_secrets_it_was_handed() {
    let _ports = fleet_ports();
    let issuer = issuer_fleet("leak-issuer");
    let target = scratch("leak-target");
    let operation = "op-leak-00000001";
    let mut helper = Session::start(&target);

    let prepared = helper.ok(json!({
        "op": "prepare",
        "operation": operation,
        "machine": "vps",
        "host": "127.0.0.1",
    }));
    let request = admission_request(&prepared);
    let materials =
        ouro::fleet::issue_member_certificate(&issuer, &request).expect("issued materials");
    let cookie = materials.cookie.clone();
    let encoded = serde_json::to_value(&materials).expect("encodable materials");
    let base = encoded.as_object().expect("an object").clone();
    assert!(
        base["cookie"] == json!(cookie),
        "the materials really do carry the cookie these refusals are handed"
    );

    for (field, value) in [
        ("fleet_id", json!("not-a-fleet-id")),
        ("roster_revision", json!(0)),
        ("fleet_name", json!("")),
        ("node", json!("ouro-elsewhere@127.0.0.1")),
        ("cookie", json!("this is not a cookie")),
        ("schema", json!(99)),
    ] {
        let mut wrong = base.clone();
        wrong.insert(field.to_string(), value);
        let refusal = helper.refused(json!({
            "op": "install",
            "operation": operation,
            "materials": Value::Object(wrong),
        }));
        let text = refusal.to_string();
        assert!(
            !text.contains(&cookie),
            "a refusal over `{field}` quoted the cookie it was handed: {refusal}"
        );
        assert!(
            !text.contains("this is not a cookie"),
            "a refusal over `{field}` echoed the value it refused: {refusal}"
        );
        assert!(
            !text.contains("PRIVATE KEY"),
            "a refusal over `{field}` quoted key material: {refusal}"
        );
    }

    assert!(
        !target
            .join("fleet")
            .try_exists()
            .expect("a readable data directory"),
        "not one of those refusals published a fleet directory"
    );
    helper.ok(json!({"op": "bye"}));
}

/// The two headline findings of the adversarial review, over the real pipe.
///
/// H1: a machine the operator declared gone for good asked again as `Vps` and the wire
/// prepared it without complaint; the issuer minted for it, it installed, and
/// `ouro fleet doctor` called it a healthy member. H2: the peer filled its own receipt
/// with `receipt append` frames, and the install then renamed the fleet directory into
/// place and reported `receipt_full` — for ever, on every retry, with the machine
/// admitted and healthy the whole time.
#[test]
fn a_banned_machine_cannot_come_back_under_a_shift_key_and_a_full_receipt_admits_nobody() {
    let _ports = fleet_ports();
    let issuer = issuer_fleet("headline-issuer");

    // H1. Admit `vps` normally, then declare it gone for good.
    let first = scratch("headline-target-1");
    let mut helper = Session::start(&first);
    let prepared = helper.ok(json!({
        "op": "prepare", "operation": "op-head-00000001",
        "machine": "vps", "host": "127.0.0.1",
    }));
    let request = admission_request(&prepared);
    ouro::fleet::issue_member_certificate(&issuer, &request).expect("issued once");
    ouro::fleet::add_member(&issuer, "vps", "127.0.0.1", None).expect("the roster add");
    ouro::fleet::forget_machine(&issuer, "vps").expect("a tombstone");
    helper.ok(json!({"op": "bye"}));

    let second = scratch("headline-target-2");
    let mut helper = Session::start(&second);
    let refusal = helper.refused(json!({
        "op": "prepare", "operation": "op-head-00000002",
        "machine": "Vps", "host": "127.0.0.1",
    }));
    assert_eq!(refusal["reason"], json!("invalid_request"));
    assert!(
        refusal["detail"]
            .as_str()
            .expect("a detail")
            .contains("lower case"),
        "{refusal}"
    );
    // And the lower-case spelling is refused by the issuer, because the tombstone is
    // about the machine and not about how it was typed.
    let prepared = helper.ok(json!({
        "op": "prepare", "operation": "op-head-00000002",
        "machine": "vps", "host": "127.0.0.1",
    }));
    let request = admission_request(&prepared);
    let error = ouro::fleet::issue_member_certificate(&issuer, &request)
        .expect_err("a machine declared gone for good does not come back");
    assert_eq!(
        ouro::fleet::admission_error(&error)
            .expect("a declared refusal")
            .reason,
        "machine_known"
    );
    helper.ok(json!({"op": "bye"}));

    // One address is one node name too.
    let third = scratch("headline-target-3");
    let mut helper = Session::start(&third);
    let prepared = helper.ok(json!({
        "op": "prepare", "operation": "op-head-00000003",
        "machine": "vps", "host": "LOCALHOST",
    }));
    assert_eq!(
        prepared["node"],
        json!("ouro-vps@localhost"),
        "the spelling that gets minted is the canonical one"
    );
    assert_eq!(prepared["host"], json!("localhost"));
    assert_eq!(
        helper.reason(json!({
            "op": "prepare", "operation": "op-head-00000004",
            "machine": "vps", "host": "127.1",
        })),
        "invalid_request",
        "and a spelling only a resolver would recognise is not a host"
    );
    helper.ok(json!({"op": "bye"}));

    // H2. The peer pads its own receipt to one step short of the cap and asks to install.
    let target = scratch("headline-target-4");
    let operation = "op-head-00000005";
    let mut helper = Session::start(&target);
    let prepared = helper.ok(json!({
        "op": "prepare", "operation": operation,
        "machine": "vps", "host": "127.0.0.1",
    }));
    let request = admission_request(&prepared);
    for index in 0..62 {
        helper.ok(json!({
            "op": "receipt", "operation": operation,
            "append": {"step": format!("probe-{index}"), "outcome": "ok"},
        }));
    }
    let materials =
        ouro::fleet::issue_member_certificate(&issuer_fleet("headline-issuer-2"), &request)
            .expect("issued materials");
    let encoded = serde_json::to_value(&materials).expect("encodable materials");
    let refusal = helper.refused(json!({
        "op": "install", "operation": operation,
        "materials": encoded,
        "ports": ephemeral_ports_value(),
    }));
    assert_eq!(refusal["reason"], json!("receipt_full"));

    // A refusal means the machine was not admitted, and this one was refused.
    let inspected = helper.ok(json!({"op": "inspect"}));
    assert_eq!(inspected["fleet"], Value::Null);
    let (healthy, text) = doctor(&target);
    assert!(
        !healthy && text.contains(operation),
        "and doctor names the operation that is still pending:\n{text}"
    );
    helper.ok(json!({"op": "bye"}));
}

/// A clean install says so, and says it in a field an orchestrator can read.
#[test]
fn the_install_reply_carries_an_empty_warning_list_when_nothing_went_wrong() {
    let _ports = fleet_ports();
    let issuer = issuer_fleet("warnings-issuer");
    let target = scratch("warnings-target");
    let operation = "op-warn-00000001";
    let mut helper = Session::start(&target);

    let prepared = helper.ok(json!({
        "op": "prepare", "operation": operation,
        "machine": "vps", "host": "127.0.0.1",
    }));
    let request = admission_request(&prepared);
    let materials =
        ouro::fleet::issue_member_certificate(&issuer, &request).expect("issued materials");
    let installed = helper.ok(json!({
        "op": "install", "operation": operation,
        "materials": serde_json::to_value(&materials).expect("encodable materials"),
        "ports": ephemeral_ports_value(),
    }));
    assert_eq!(
        installed["warnings"],
        json!([]),
        "an empty list is the difference between `nothing went wrong` and `this helper \
         is too old to tell you`: {installed}"
    );

    // A roster change naming a machine in anything but lower case is refused here too.
    let revision = installed["roster_revision"]
        .as_u64()
        .expect("a roster revision");
    assert_eq!(
        helper.reason(json!({
            "op": "roster", "operation": "op-warn-00000002",
            "expected_revision": revision,
            "change": {"kind": "add", "machine": "Laptop", "host": "127.0.0.1"},
        })),
        "invalid_request"
    );
    helper.ok(json!({"op": "bye"}));
}
