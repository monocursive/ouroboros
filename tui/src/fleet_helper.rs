//! `ouro fleet helper`: the typed operations an issuer drives over SSH stdin/stdout.
//!
//! The proposal's connectivity contract is blunt about why this exists
//! (`docs/proposals/fleet-network-onboarding.md`, "Connectivity and identity
//! contract"): SSH eventually invokes a remote shell, so a locally built argument
//! array is not on its own protection against remote-shell injection. The fixed
//! command is `ouro fleet helper` and every variable thing — an operation id, a
//! machine name, a path, a certificate — arrives as a framed JSON value that is
//! parsed, validated and used as data. Nothing read here is ever executed, expanded,
//! or interpolated into a command line.
//!
//! The wire is seam C3 of the wave contract: one JSON object per line in, one per line
//! out, at most 1 MiB per line, a 60 second idle timeout, and exit 0 after `bye` or
//! EOF. A request is `{"v":1,"id":"<string>","op":"<name>", ...}`; a reply is
//! `{"v":1,"id":"<same>","ok":true, ...}` or `{"v":1,"id":"<same>","ok":false,
//! "reason":"<stable_snake_case>","detail":"<human>"}`. `reason` is what an
//! orchestrator branches on and it does not change; `detail` is for a person.
//!
//! No listener is opened, no subprocess is started, and stdout carries frames and
//! nothing else — diagnostics go to stderr, because the process on the other end of
//! this pipe is parsing every byte of stdout.

use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::fleet;

/// The request/reply envelope version. Bumped only for an incompatible envelope.
pub const WIRE_VERSION: u64 = 1;
/// This helper's own version, answered by `hello`.
pub const HELPER_VERSION: u64 = 1;
/// Seam C3: a line over this is refused and the helper exits rather than buffering
/// whatever a peer decides to send.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Seam C3: an SSH connection that stops speaking does not leave a helper resident.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Seam C1: `fleet_protocol::FLEET_PROTOCOL_REVISION` is the single source of truth
/// for the machine-management protocol revision, pinned to `lib/ouroboros/cluster.ex`
/// by that module's drift test. The helper reports it rather than a second copy.
pub const HELPER_PROTOCOL: Option<u64> =
    Some(crate::fleet_protocol::FLEET_PROTOCOL_REVISION as u64);

/// Bounded identifiers: an `id` is echoed into a reply, so it is checked before it is.
const MAX_ID_BYTES: usize = 128;

pub struct Helper {
    data_dir: PathBuf,
}

/// What the reader thread hands the loop.
enum Frame {
    Line(String),
    TooLarge,
    Failed(String),
}

/// Serve the helper protocol on this process's own stdin and stdout.
pub fn serve(data_dir: PathBuf) -> Result<()> {
    let helper = Helper::new(data_dir);
    let (sender, receiver) = sync_channel::<Frame>(1);
    thread::Builder::new()
        .name("fleet-helper-stdin".to_string())
        .spawn(move || read_frames(BufReader::new(std::io::stdin()), &sender))
        .context("starting the helper's input reader")?;
    let output = std::io::stdout();
    run(&helper, &receiver, &mut output.lock(), IDLE_TIMEOUT)
}

/// The loop itself, over any frame source and any sink, so the timeout and the exit
/// conditions are testable without a terminal or a pipe.
fn run(
    helper: &Helper,
    receiver: &Receiver<Frame>,
    output: &mut impl Write,
    idle: Duration,
) -> Result<()> {
    loop {
        match receiver.recv_timeout(idle) {
            Ok(Frame::Line(line)) => {
                let (reply, keep_going) = helper.handle(&line);
                writeln!(output, "{reply}").context("writing a helper reply")?;
                output.flush().context("flushing a helper reply")?;
                if !keep_going {
                    return Ok(());
                }
            }
            Ok(Frame::TooLarge) => {
                let reply = refusal(
                    Value::Null,
                    "frame_too_large",
                    format!("a request line over {MAX_FRAME_BYTES} bytes is not read"),
                    None,
                );
                writeln!(output, "{reply}").context("writing a helper reply")?;
                output.flush().context("flushing a helper reply")?;
                return Ok(());
            }
            Ok(Frame::Failed(detail)) => {
                eprintln!("ouro fleet helper: {detail}");
                return Ok(());
            }
            // EOF closes the sender; an idle connection times out. Both exit 0: there
            // is nothing to report and nothing left to do.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {
                eprintln!(
                    "ouro fleet helper: no request for {} seconds; exiting",
                    idle.as_secs()
                );
                return Ok(());
            }
        }
    }
}

/// Read newline-framed lines with a hard cap, without ever holding more than one
/// frame plus the reader's own buffer.
fn read_frames(mut input: impl BufRead, sender: &SyncSender<Frame>) {
    loop {
        let mut buffer = Vec::new();
        let complete = loop {
            let (consumed, finished) = {
                let available = match input.fill_buf() {
                    Ok(available) => available,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = sender.send(Frame::Failed(format!("reading stdin: {error}")));
                        return;
                    }
                };
                if available.is_empty() {
                    break false;
                }
                match available.iter().position(|byte| *byte == b'\n') {
                    Some(index) => {
                        buffer.extend_from_slice(&available[..index]);
                        (index + 1, true)
                    }
                    None => {
                        buffer.extend_from_slice(available);
                        (available.len(), false)
                    }
                }
            };
            input.consume(consumed);
            if buffer.len() > MAX_FRAME_BYTES {
                let _ = sender.send(Frame::TooLarge);
                return;
            }
            if finished {
                break true;
            }
        };

        let line = String::from_utf8_lossy(&buffer)
            .trim_end_matches('\r')
            .to_string();
        if !line.trim().is_empty() && sender.send(Frame::Line(line)).is_err() {
            return;
        }
        if !complete {
            // End of input with nothing further to frame.
            return;
        }
    }
}

fn envelope(id: Value, ok: bool) -> Map<String, Value> {
    let mut reply = Map::new();
    reply.insert("v".to_string(), json!(WIRE_VERSION));
    reply.insert("id".to_string(), id);
    reply.insert("ok".to_string(), json!(ok));
    reply
}

fn success(id: Value, fields: Value) -> String {
    let mut reply = envelope(id, true);
    if let Value::Object(fields) = fields {
        for (key, value) in fields {
            reply.insert(key, value);
        }
    }
    Value::Object(reply).to_string()
}

fn refusal(
    id: Value,
    reason: &str,
    detail: impl Into<String>,
    roster_revision: Option<u64>,
) -> String {
    let mut reply = envelope(id, false);
    reply.insert("reason".to_string(), json!(reason));
    reply.insert("detail".to_string(), json!(detail.into()));
    if let Some(revision) = roster_revision {
        reply.insert("roster_revision".to_string(), json!(revision));
    }
    Value::Object(reply).to_string()
}

/// Turn a library error into a refusal, preferring the stable reason it declared.
fn refused(id: Value, error: &anyhow::Error) -> String {
    match fleet::admission_error(error) {
        Some(declared) => refusal(
            id,
            declared.reason,
            declared.detail.clone(),
            declared.roster_revision,
        ),
        None => refusal(id, "failed", format!("{error:#}"), None),
    }
}

/// A path that arrived in a request, checked before anything opens it.
///
/// Absolute, free of `..`, and inside the directory this helper was started with.
/// A relative path would resolve against whatever working directory sshd happened to
/// give this process, and `..` would resolve outside the boundary entirely.
fn validate_request_path(text: &str, root: &Path) -> Result<PathBuf> {
    let path = Path::new(text);
    if !path.is_absolute() {
        anyhow::bail!("`{text}` must be an absolute path");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!("`{text}` must not contain `..`");
    }
    if path != root && !path.starts_with(root) {
        anyhow::bail!(
            "`{text}` is outside the data directory this helper was started with ({})",
            root.display()
        );
    }
    Ok(path.to_path_buf())
}

fn required_str(object: &Map<String, Value>, field: &str) -> Result<String> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => anyhow::bail!("`{field}` must be a string"),
        None => anyhow::bail!("`{field}` is required"),
    }
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64> {
    match object.get(field) {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("`{field}` must be a non-negative whole number")),
        Some(_) => anyhow::bail!("`{field}` must be a number"),
        None => anyhow::bail!("`{field}` is required"),
    }
}

fn optional_port(object: &Map<String, Value>, field: &str) -> Result<Option<u16>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("`{field}` must be a TCP port")),
        Some(_) => anyhow::bail!("`{field}` must be a number"),
    }
}

impl Helper {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// Answer one request line. The flag is false exactly when the helper should exit.
    pub fn handle(&self, line: &str) -> (String, bool) {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                return (
                    refusal(
                        Value::Null,
                        "bad_request",
                        format!("a request must be one JSON object per line: {error}"),
                        None,
                    ),
                    true,
                )
            }
        };
        let Some(object) = value.as_object() else {
            return (
                refusal(
                    Value::Null,
                    "bad_request",
                    "a request must be a JSON object",
                    None,
                ),
                true,
            );
        };

        let id = match object.get("id") {
            Some(Value::String(id))
                if !id.is_empty()
                    && id.len() <= MAX_ID_BYTES
                    && !id.chars().any(char::is_control) =>
            {
                Value::String(id.clone())
            }
            _ => {
                return (
                    refusal(
                        Value::Null,
                        "bad_request",
                        format!("`id` must be a string of 1 to {MAX_ID_BYTES} characters"),
                        None,
                    ),
                    true,
                )
            }
        };

        match object.get("v") {
            Some(Value::Number(version)) if version.as_u64() == Some(WIRE_VERSION) => {}
            None => {}
            Some(_) => {
                return (
                    refusal(
                        id,
                        "unsupported_version",
                        format!("this helper speaks envelope version {WIRE_VERSION}"),
                        None,
                    ),
                    true,
                )
            }
        }

        let Some(Value::String(op)) = object.get("op") else {
            return (
                refusal(id, "bad_request", "`op` must be a string", None),
                true,
            );
        };
        let op = op.clone();

        if op == "bye" {
            return (success(id, json!({})), false);
        }

        let data_dir = match self.request_data_dir(object) {
            Ok(data_dir) => data_dir,
            Err(error) => {
                return (
                    refusal(id, "invalid_path", format!("{error:#}"), None),
                    true,
                )
            }
        };

        let answer = match op.as_str() {
            "hello" => Ok(json!({
                "helper": HELPER_VERSION,
                "wire": WIRE_VERSION,
                "protocol": HELPER_PROTOCOL,
            })),
            "inspect" => self.inspect(&data_dir),
            "prepare" => self.prepare(&data_dir, object),
            "install" => self.install(&data_dir, object),
            "roster" => self.roster(&data_dir, object),
            "receipt" => self.receipt(&data_dir, object),
            _ => {
                return (
                    refusal(
                        id,
                        "unsupported_op",
                        format!("`{op}` is not an operation this helper answers"),
                        None,
                    ),
                    true,
                )
            }
        };

        match answer {
            Ok(fields) => (success(id, fields), true),
            Err(error) => (refused(id, &error), true),
        }
    }

    /// The data directory a request names, which must be the one this helper serves.
    fn request_data_dir(&self, object: &Map<String, Value>) -> Result<PathBuf> {
        let Some(value) = object.get("data_dir") else {
            return Ok(self.data_dir.clone());
        };
        let Value::String(text) = value else {
            anyhow::bail!("`data_dir` must be a string");
        };
        let path = validate_request_path(text, &self.data_dir)?;
        if path != self.data_dir {
            anyhow::bail!(
                "`{text}` is not the data directory this helper was started with ({})",
                self.data_dir.display()
            );
        }
        Ok(path)
    }

    fn inspect(&self, data_dir: &Path) -> Result<Value> {
        let inspection = fleet::inspect_local(data_dir)?;
        let mut value =
            serde_json::to_value(&inspection).context("encoding this machine's inspection")?;
        if let Value::Object(fields) = &mut value {
            // Seam C1: the build contract an orchestrator compares before any credential
            // leaves the issuer. Unknown facts inside it are null, never guessed.
            fields.insert(
                "build".to_string(),
                serde_json::to_value(crate::fleet_protocol::build_metadata())
                    .context("encoding this build's metadata")?,
            );
        }
        Ok(value)
    }

    fn prepare(&self, data_dir: &Path, object: &Map<String, Value>) -> Result<Value> {
        let operation = required_str(object, "operation")?;
        let machine = required_str(object, "machine")?;
        let host = required_str(object, "host")?;
        let request = fleet::prepare_admission(data_dir, &operation, &machine, &host)?;
        serde_json::to_value(&request).context("encoding the admission request")
    }

    fn install(&self, data_dir: &Path, object: &Map<String, Value>) -> Result<Value> {
        let operation = required_str(object, "operation")?;
        let Some(raw) = object.get("materials") else {
            anyhow::bail!("`materials` is required");
        };
        let materials: fleet::AdmissionMaterials = serde_json::from_value(raw.clone())
            .map_err(|error| anyhow::anyhow!("`materials` is not admission materials: {error}"))?;
        if materials.operation != operation {
            anyhow::bail!(
                "the materials name operation {}, and this request names {operation}",
                materials.operation
            );
        }
        // Port overrides stay available because a second machine on one host, or an
        // operator with a занятый range, needs them; they are numbers, validated the
        // same way `ouro fleet create --gateway-port` is.
        let ports = match object.get("ports") {
            None | Some(Value::Null) => fleet::Ports::DEFAULT,
            Some(Value::Object(ports)) => fleet::Ports {
                gateway: optional_port(ports, "gateway")?,
                dist: optional_port(ports, "dist")?,
                epmd: optional_port(ports, "epmd")?,
            },
            Some(_) => anyhow::bail!("`ports` must be an object"),
        };
        let profile = fleet::install_admission(data_dir, &materials, ports)?;
        Ok(json!({
            "operation": operation,
            "machine": profile.machine,
            "node": profile.node,
            "fleet_id": profile.fleet_id,
            "roster_revision": profile.roster_revision,
            "members": profile
                .members
                .iter()
                .map(|member| member.machine.clone())
                .collect::<Vec<_>>(),
        }))
    }

    fn roster(&self, data_dir: &Path, object: &Map<String, Value>) -> Result<Value> {
        let operation = required_str(object, "operation")?;
        let expected = required_u64(object, "expected_revision")?;
        let Some(raw) = object.get("change") else {
            anyhow::bail!("`change` is required");
        };
        let change: fleet::RosterChange = serde_json::from_value(raw.clone())
            .map_err(|error| anyhow::anyhow!("`change` is not a roster change: {error}"))?;
        let outcome = fleet::apply_roster_change(data_dir, &operation, expected, &change)?;
        Ok(json!({
            "operation": operation,
            "roster_revision": outcome.roster_revision,
            "changed": outcome.changed,
            "member": {
                "machine": outcome.member.machine,
                "host": outcome.member.host,
                "node": outcome.member.node,
            },
        }))
    }

    fn receipt(&self, data_dir: &Path, object: &Map<String, Value>) -> Result<Value> {
        let operation = required_str(object, "operation")?;
        match object.get("append") {
            None | Some(Value::Null) => {
                let receipt = fleet::read_receipt(data_dir, &operation)?;
                Ok(json!({
                    "operation": operation,
                    "receipt": receipt.map(|receipt| serde_json::to_value(&receipt)).transpose()
                        .context("encoding the operation receipt")?,
                }))
            }
            Some(Value::Object(step)) => {
                let name = required_str(step, "step")?;
                let outcome = required_str(step, "outcome")?;
                let detail = match step.get("detail") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(detail)) => Some(detail.clone()),
                    Some(_) => anyhow::bail!("`append.detail` must be a string"),
                };
                let receipt = fleet::append_receipt_step(
                    data_dir,
                    &operation,
                    &name,
                    &outcome,
                    detail.as_deref(),
                )?;
                Ok(json!({
                    "operation": operation,
                    "receipt": serde_json::to_value(&receipt)
                        .context("encoding the operation receipt")?,
                }))
            }
            Some(_) => anyhow::bail!("`append` must be an object"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> Helper {
        Helper::new(PathBuf::from("/tmp/ouro-helper-root"))
    }

    fn decode(frame: &str) -> Value {
        serde_json::from_str(frame).expect("a JSON reply frame")
    }

    /// The envelope is the contract: a reply always names the version, echoes the id
    /// it was given, and says whether the operation happened.
    #[test]
    fn hello_answers_the_envelope_and_states_the_protocol_it_cannot_yet_read() {
        let (frame, keep_going) = helper().handle(r#"{"v":1,"id":"a1","op":"hello"}"#);
        let reply = decode(&frame);

        assert!(keep_going);
        assert_eq!(reply["v"], json!(WIRE_VERSION));
        assert_eq!(reply["id"], json!("a1"));
        assert_eq!(reply["ok"], json!(true));
        assert_eq!(reply["helper"], json!(HELPER_VERSION));
        // Seam C1: the one revision the runtime advertises.
        assert_eq!(
            reply["protocol"],
            json!(crate::fleet_protocol::FLEET_PROTOCOL_REVISION)
        );
    }

    /// `bye` is the only op that stops the loop, and it still answers first.
    #[test]
    fn bye_answers_and_stops_and_every_other_unknown_op_is_named() {
        let helper = helper();

        let (frame, keep_going) = helper.handle(r#"{"v":1,"id":"b","op":"bye"}"#);
        assert!(!keep_going);
        assert_eq!(decode(&frame)["ok"], json!(true));

        let (frame, keep_going) = helper.handle(r#"{"v":1,"id":"c","op":"upload"}"#);
        let reply = decode(&frame);
        assert!(
            keep_going,
            "an unknown op is a refusal, not a reason to drop the connection"
        );
        assert_eq!(reply["reason"], json!("unsupported_op"));
        assert_eq!(reply["id"], json!("c"));
    }

    /// Malformed input is answered and the helper keeps reading: one corrupt frame on
    /// a long-lived SSH pipe must not cost the operation.
    #[test]
    fn malformed_frames_are_refused_without_exiting_and_never_carry_an_invented_id() {
        let helper = helper();

        for line in [
            "not json at all",
            "[1,2,3]",
            r#"{"v":1,"op":"hello"}"#,
            r#"{"v":1,"id":42,"op":"hello"}"#,
            r#"{"v":1,"id":"","op":"hello"}"#,
        ] {
            let (frame, keep_going) = helper.handle(line);
            let reply = decode(&frame);
            assert!(keep_going, "{line}");
            assert_eq!(reply["ok"], json!(false), "{line}");
            assert_eq!(reply["reason"], json!("bad_request"), "{line}");
            assert_eq!(
                reply["id"],
                Value::Null,
                "a reply cannot echo an id the request did not carry: {line}"
            );
        }

        let (frame, _) = helper.handle(r#"{"v":1,"id":"x","op":42}"#);
        assert_eq!(decode(&frame)["reason"], json!("bad_request"));
    }

    /// An envelope version this helper does not speak is named rather than guessed at.
    #[test]
    fn an_unknown_envelope_version_is_refused_by_name() {
        let (frame, _) = helper().handle(r#"{"v":2,"id":"v","op":"hello"}"#);
        let reply = decode(&frame);

        assert_eq!(reply["reason"], json!("unsupported_version"));
        assert_eq!(reply["id"], json!("v"));
    }

    /// A path in a request is data, and the only directory this helper serves is the
    /// one it was started with.
    #[test]
    fn a_path_in_a_request_must_be_absolute_inside_the_root_and_free_of_parent_links() {
        let root = Path::new("/tmp/ouro-helper-root");

        assert!(validate_request_path("/tmp/ouro-helper-root", root).is_ok());
        assert!(validate_request_path("/tmp/ouro-helper-root/fleet", root).is_ok());
        for hostile in [
            "relative/path",
            "/tmp/ouro-helper-root/../../etc",
            "/etc/passwd",
            "/tmp/ouro-helper-rootlike",
        ] {
            assert!(
                validate_request_path(hostile, root).is_err(),
                "{hostile} must not be accepted as a helper path"
            );
        }
    }

    /// The `data_dir` field may name the helper's own directory and nothing else.
    #[test]
    fn a_request_cannot_redirect_the_helper_at_another_data_directory() {
        let helper = helper();

        let (frame, keep_going) = helper
            .handle(r#"{"v":1,"id":"d","op":"inspect","data_dir":"/tmp/somebody-elses-data"}"#);
        let reply = decode(&frame);
        assert!(keep_going);
        assert_eq!(reply["reason"], json!("invalid_path"));

        let (frame, _) = helper
            .handle(r#"{"v":1,"id":"e","op":"inspect","data_dir":"/tmp/ouro-helper-root/fleet"}"#);
        assert_eq!(
            decode(&frame)["reason"],
            json!("invalid_path"),
            "a directory inside the root is still not the root"
        );
    }

    /// A line over the cap is refused with the stable reason and stops the loop, and
    /// the reply is a complete envelope even though no request was ever parsed.
    #[test]
    fn an_oversized_frame_is_refused_by_name_and_ends_the_session() {
        let (sender, receiver) = sync_channel::<Frame>(1);
        sender.send(Frame::TooLarge).expect("a queued frame");
        drop(sender);
        let mut output = Vec::new();

        run(&helper(), &receiver, &mut output, Duration::from_secs(1)).expect("a clean exit");

        let reply = decode(String::from_utf8(output).expect("utf-8").trim());
        assert_eq!(reply["ok"], json!(false));
        assert_eq!(reply["reason"], json!("frame_too_large"));
        assert_eq!(reply["v"], json!(WIRE_VERSION));
        assert_eq!(reply["id"], Value::Null);
    }

    /// The reader stops at the cap rather than buffering whatever arrives, and the
    /// caller learns which of the two happened.
    #[test]
    fn the_reader_caps_a_line_and_frames_the_ones_below_it() {
        let (sender, receiver) = sync_channel::<Frame>(4);
        read_frames(
            BufReader::new(std::io::Cursor::new(b"{\"a\":1}\r\n\n{\"b\":2}\n".to_vec())),
            &sender,
        );
        drop(sender);
        let frames: Vec<String> = receiver
            .into_iter()
            .map(|frame| match frame {
                Frame::Line(line) => line,
                Frame::TooLarge => "too-large".to_string(),
                Frame::Failed(detail) => detail,
            })
            .collect();
        assert_eq!(
            frames,
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()],
            "blank lines are skipped and a trailing carriage return is not part of a frame"
        );

        let (sender, receiver) = sync_channel::<Frame>(4);
        let mut oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
        oversized.push(b'\n');
        read_frames(BufReader::new(std::io::Cursor::new(oversized)), &sender);
        drop(sender);
        assert!(
            matches!(receiver.into_iter().next(), Some(Frame::TooLarge)),
            "a line over the cap is reported as such and nothing after it is read"
        );
    }

    /// An idle connection does not leave a helper resident on the target.
    #[test]
    fn an_idle_connection_exits_without_writing_a_frame() {
        let (sender, receiver) = sync_channel::<Frame>(1);
        let mut output = Vec::new();

        run(&helper(), &receiver, &mut output, Duration::from_millis(50)).expect("a clean exit");
        drop(sender);

        assert!(
            output.is_empty(),
            "a timeout is reported on stderr; stdout carries frames only"
        );
    }
}
