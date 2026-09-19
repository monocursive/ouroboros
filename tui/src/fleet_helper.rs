//! `ouro fleet helper`: the typed operations an operator's `ouro` drives over SSH.
//!
//! The connectivity contract is blunt about why this exists
//! (`docs/proposals/fleet-network-onboarding.md`, "Connectivity and identity
//! contract"): SSH eventually invokes a remote shell, so a locally built argument
//! array is not on its own protection against remote-shell injection. The fixed
//! command is `ouro fleet helper` and every variable thing — a machine name, a path, a
//! bundle — arrives as a framed JSON value that is parsed, validated and used as data.
//! Nothing read here is ever executed, expanded, or interpolated into a command line.
//!
//! The wire is one JSON object per line in, one per line out, at most 1 MiB per line, a
//! 60 second idle timeout, and exit 0 after `bye` or EOF. A request is
//! `{"v":1,"id":"<string>","op":"<name>", ...}`; a reply is `{"v":1,"id":"<same>",
//! "ok":true, ...}` or `{"v":1,"id":"<same>","ok":false,"reason":"<stable_snake_case>",
//! "detail":"<human>"}`. `reason` is what an orchestrator branches on and it does not
//! change; `detail` is for a person.
//!
//! The operations are `docs/proposals/fleet-kiss.md` §7, and that table is the contract:
//! `hello`, `inspect`, `install`, `service`, `start`, `status`, `leave`, `bye`. The
//! per-member certificate ceremony it replaced — `prepare`, `roster`, `receipt` — is
//! gone with the authority model that needed it (§1).
//!
//! Note, for whoever writes the other half: a request object with the same key twice is
//! **last wins**, because that is what `serde_json` does and this makes no attempt to
//! reject it. An orchestrator that builds frames by concatenation must therefore not
//! assume the first spelling of a field is the one that takes effect.
//!
//! No listener is opened, and stdout carries frames and nothing else — diagnostics go to
//! stderr, because the process on the other end of this pipe is parsing every byte of
//! stdout.

use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::fleet;

/// The request/reply envelope version. Bumped only for an incompatible envelope.
pub const WIRE_VERSION: u64 = 1;
/// This helper's own version, answered by `hello`.
pub const HELPER_VERSION: u64 = 1;
/// A line over this is refused and the helper exits rather than buffering whatever a
/// peer decides to send.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// An SSH connection that stops speaking does not leave a helper resident.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
                // An `install` frame carries the fleet cookie and the CA key, so the
                // line it arrived on is treated as the secret it is: zeroized when this
                // iteration ends rather than left in a freed allocation. This is not
                // perfect erasure — `serde_json` makes its own copies while parsing and
                // the kernel pipe buffer is not ours — and the bundle is on its way to
                // mode-0600 files either way. It is the part this code can actually do.
                let line = Zeroizing::new(line);
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

fn refusal(id: Value, reason: &str, detail: impl Into<String>) -> String {
    let mut reply = envelope(id, false);
    reply.insert("reason".to_string(), json!(reason));
    reply.insert("detail".to_string(), json!(detail.into()));
    Value::Object(reply).to_string()
}

/// Turn a library error into a refusal, preferring the stable reason it declared.
fn refused(id: Value, error: &anyhow::Error) -> String {
    match fleet::refusal(error) {
        Some(declared) => refusal(id, declared.reason, declared.detail.clone()),
        None => refusal(id, "failed", format!("{error:#}")),
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

fn optional_bool(object: &Map<String, Value>, field: &str) -> Result<Option<bool>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => anyhow::bail!("`{field}` must be a boolean"),
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
        let mut value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                return (
                    refusal(
                        Value::Null,
                        "bad_request",
                        format!("a request must be one JSON object per line: {error}"),
                    ),
                    true,
                )
            }
        };
        let Some(object) = value.as_object_mut() else {
            return (
                refusal(
                    Value::Null,
                    "bad_request",
                    "a request must be a JSON object",
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
                    ),
                    true,
                )
            }
        }

        let Some(Value::String(op)) = object.get("op") else {
            return (refusal(id, "bad_request", "`op` must be a string"), true);
        };
        let op = op.clone();

        if op == "bye" {
            return (success(id, json!({})), false);
        }

        let data_dir = match self.request_data_dir(object) {
            Ok(data_dir) => data_dir,
            Err(error) => return (refusal(id, "invalid_path", format!("{error:#}")), true),
        };

        let answer = match op.as_str() {
            "hello" => self.hello(&data_dir),
            "inspect" => self.inspect(&data_dir),
            "install" => self.install(&data_dir, object),
            "service" => self.service(&data_dir, object),
            "start" => self.start(&data_dir),
            "status" => self.status(&data_dir, object),
            "leave" => self.leave(&data_dir),
            _ => {
                return (
                    refusal(
                        id,
                        "unsupported_op",
                        format!("`{op}` is not an operation this helper answers"),
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

    /// §7 `hello`. The version comparison §12 makes the compatibility fence is this
    /// `version`; the rest is what a plan line needs to name the target honestly.
    fn hello(&self, data_dir: &Path) -> Result<Value> {
        Ok(json!({
            "helper": HELPER_VERSION,
            "wire": WIRE_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "data_dir": data_dir.display().to_string(),
            "home": std::env::var("HOME").ok(),
            "build": serde_json::to_value(crate::fleet_protocol::build_metadata())
                .context("encoding this build's metadata")?,
        }))
    }

    /// §7 `inspect`: is there a fleet here, is a runtime up, is a service installed.
    ///
    /// A profile this build cannot read — a schema-1 one, most usefully — is reported as
    /// `fleet_unreadable` rather than as "no fleet", because installing over it would
    /// overwrite somebody's identity.
    fn inspect(&self, data_dir: &Path) -> Result<Value> {
        let fleet = match fleet::load(data_dir) {
            Ok(Some(profile)) => json!({
                "fleet_id": profile.fleet_id,
                "name": profile.name,
                "machine": profile.machine,
                "host": profile.host,
                "node": profile.node,
                "dist_port": profile.dist_port,
            }),
            Ok(None) => Value::Null,
            Err(error) => {
                return Err(fleet::Refusal {
                    reason: "fleet_unreadable",
                    detail: format!("{error:#}"),
                }
                .into())
            }
        };
        let service = match crate::fleet_service::Plan::for_this_machine(data_dir) {
            Ok(plan) => match crate::fleet_service::Programs::from_env()
                .and_then(|programs| crate::fleet_service::status(&plan, &programs))
            {
                Ok(report) => json!({
                    "installed": report.installed,
                    "running": report.running,
                }),
                Err(_) => Value::Null,
            },
            Err(_) => Value::Null,
        };
        Ok(json!({
            "fleet": fleet,
            "runtime_running": crate::runtime::read_live_publication(data_dir)
                .ok()
                .flatten()
                .is_some(),
            "service": service,
            // The build contract §12 compares, so the operator can refuse a mismatch
            // before a credential leaves.
            "build": serde_json::to_value(crate::fleet_protocol::build_metadata())
                .context("encoding this build's metadata")?,
        }))
    }

    /// §7 `install`: mint this machine's leaf from the bundle's CA and write the fleet
    /// directory. The bundle is the whole secret set; nothing is sent back.
    fn install(&self, data_dir: &Path, object: &mut Map<String, Value>) -> Result<Value> {
        let machine = required_str(object, "machine")?;
        let host = required_str(object, "host")?;
        let replace = optional_bool(object, "replace")?.unwrap_or(false);
        let Some(raw) = object.get_mut("bundle") else {
            anyhow::bail!("`bundle` is required");
        };
        // Taken, not cloned: the request `Value` stops holding the cookie and the CA key
        // here, and the only copies left are inside `Bundle`, which zeroizes on drop.
        let bundle: fleet::Bundle = serde_json::from_value(raw.take())
            .map_err(|error| anyhow::anyhow!("`bundle` is not a fleet bundle: {error}"))?;
        // Port overrides stay available because a second machine on one host, or an
        // operator with an occupied port, needs them; they are numbers, validated the
        // same way `ouro fleet create --gateway-port` is.
        let ports = match object.get("ports") {
            None | Some(Value::Null) => fleet::Ports::DEFAULT,
            Some(Value::Object(ports)) => fleet::Ports {
                gateway: optional_port(ports, "gateway")?,
                dist: optional_port(ports, "dist")?,
            },
            Some(_) => anyhow::bail!("`ports` must be an object"),
        };

        if replace {
            // The operator asked for whatever is here to be replaced. `leave` is the
            // only thing that removes a fleet directory, and it is stop-gated, so a
            // running runtime still refuses.
            fleet::leave(data_dir).map_err(|error| fleet::Refusal {
                reason: "fleet_present",
                detail: format!(
                    "the existing fleet directory could not be removed before replacing it: {error:#}"
                ),
            })?;
        }

        let profile = fleet::join(data_dir, &bundle, &machine, &host, ports)?;
        Ok(json!({
            "machine": profile.machine,
            "node": profile.node,
            "fleet_id": profile.fleet_id,
            "dist_port": profile.dist_port,
        }))
    }

    /// §7 `service`: the startup service, over the same library `ouro fleet service`
    /// calls. `install: true` writes and loads this data directory's unit; `install:
    /// false` only reports it. Nothing in the request names a path, a program or a unit.
    fn service(&self, data_dir: &Path, object: &Map<String, Value>) -> Result<Value> {
        let install = match object.get("install") {
            Some(Value::Bool(install)) => *install,
            None => anyhow::bail!("`install` is required"),
            Some(_) => anyhow::bail!("`install` must be a boolean"),
        };
        let plan =
            crate::fleet_service::Plan::for_this_machine(data_dir).map_err(service_refusal)?;
        let programs = crate::fleet_service::Programs::from_env().map_err(service_refusal)?;
        let report = if install {
            crate::fleet_service::install(&plan, &programs, false)
        } else {
            crate::fleet_service::status(&plan, &programs)
        }
        .map_err(service_refusal)?;
        Ok(json!({
            "installed": report.installed,
            "running": report.running,
            "supported": report.supervisor != crate::fleet_service::SupervisorCode::Unsupported,
            "report": serde_json::to_value(&report).context("encoding the service report")?,
        }))
    }

    /// §7 `start`: start the daemon from *this* `ouro`.
    ///
    /// A managed unit is started through its manager, because that is what will restart
    /// it later. Without one — `--no-service` — the daemon is started directly, detached
    /// from this SSH session, so it survives the helper exiting.
    fn start(&self, data_dir: &Path) -> Result<Value> {
        let plan =
            crate::fleet_service::Plan::for_this_machine(data_dir).map_err(service_refusal)?;
        let programs = crate::fleet_service::Programs::from_env().map_err(service_refusal)?;
        match crate::fleet_service::start(&plan, &programs) {
            Ok(report) => Ok(json!({
                "pid": report.pid,
                "via": "service",
                "running": report.running,
            })),
            Err(error)
                if crate::fleet_service::service_error(&error)
                    .is_some_and(|declared| declared.reason == "not_installed") =>
            {
                let pid = spawn_detached_daemon(data_dir)?;
                Ok(json!({ "pid": pid, "via": "daemon", "running": Value::Null }))
            }
            Err(error) => Err(service_refusal(error)),
        }
    }

    /// §7 `status`: what this machine's own runtime says about itself.
    ///
    /// `connected_to` is read from the target's own `fleet.status`, so `add` observes the
    /// join from the machine that joined rather than inferring it from the operator's
    /// side of the mesh. A runtime that is not up is a fact, not an error.
    fn status(&self, data_dir: &Path, object: &Map<String, Value>) -> Result<Value> {
        let peer = match object.get("peer") {
            None | Some(Value::Null) => None,
            Some(Value::String(peer)) => Some(peer.clone()),
            Some(_) => anyhow::bail!("`peer` must be a string"),
        };
        let running = crate::runtime::read_live_publication(data_dir)
            .ok()
            .flatten()
            .is_some();
        let mut connected: Vec<String> = Vec::new();
        if running {
            let gateway = crate::fleet_setup::gateway::LocalGateway::new(
                data_dir,
                &data_dir.join(crate::runtime::TOKEN_FILE),
            );
            if let Ok(Some(status)) =
                crate::fleet_setup::gateway::Gateway::call(&gateway, "fleet.status", json!({}))
            {
                connected = connected_nodes(&status, peer.as_deref());
            }
        }
        Ok(json!({
            "runtime_running": running,
            "connected_to": connected,
            "version": env!("CARGO_PKG_VERSION"),
        }))
    }

    /// §7 `leave`: the same `fleet::leave` the local command runs, after the runtime has
    /// been stopped through its idle gate and the managed service taken away.
    ///
    /// Sessions, workspaces and attachments are not touched. Nothing is written on any
    /// other machine — there is no roster to replicate (§1).
    fn leave(&self, data_dir: &Path) -> Result<Value> {
        let mut removed: Vec<String> = Vec::new();
        let token_file = data_dir.join(crate::runtime::TOKEN_FILE);
        match crate::fleet_setup::gateway::stop_require_idle(data_dir, &token_file) {
            Ok(crate::fleet_setup::gateway::StopOutcome::NotRunning) => {}
            Ok(crate::fleet_setup::gateway::StopOutcome::RemovedStale { pid }) => {
                removed.push(format!("stale gateway publication for pid {pid}"));
            }
            Ok(crate::fleet_setup::gateway::StopOutcome::Stopped { pid }) => {
                removed.push(format!("stopped runtime pid {pid}"));
            }
            Err(error) => {
                return Err(fleet::Refusal {
                    reason: "runtime_running",
                    detail: format!("{error:#}"),
                }
                .into())
            }
        }

        if let (Ok(plan), Ok(programs)) = (
            crate::fleet_service::Plan::for_this_machine(data_dir),
            crate::fleet_service::Programs::from_env(),
        ) {
            match crate::fleet_service::remove(&plan, &programs) {
                Ok(report) if report.steps.is_empty() => {}
                Ok(_) => removed.push(format!("startup service {}", plan.label())),
                // A machine with no supervisor, or one whose unit was never ours, has
                // nothing of ours to remove; the credentials still go.
                Err(_) => {}
            }
        }

        let removal = fleet::leave(data_dir)?;
        let machine = removal.as_ref().and_then(|removal| removal.machine.clone());
        if let Some(removal) = &removal {
            removed.extend(removal.removed.iter().cloned());
        }
        Ok(json!({
            "machine": machine,
            "removed": removed,
            "already_standalone": removal.is_none(),
        }))
    }
}

/// The nodes a `fleet.status` document reports as connected, optionally narrowed to one
/// peer by machine name or node name.
fn connected_nodes(status: &Value, peer: Option<&str>) -> Vec<String> {
    let mut nodes = Vec::new();
    for key in ["machines", "members", "nodes"] {
        let Some(entries) = status.get(key).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            let connected = entry
                .get("connected")
                .and_then(Value::as_bool)
                .or_else(|| {
                    entry
                        .get("state")
                        .and_then(Value::as_str)
                        .map(|state| state == "connected" || state == "up")
                })
                .unwrap_or(false);
            if !connected {
                continue;
            }
            let machine = entry
                .get("machine")
                .or_else(|| entry.get("name"))
                .and_then(Value::as_str);
            let node = entry.get("node").and_then(Value::as_str);
            if let Some(peer) = peer {
                let matches = machine.is_some_and(|machine| fleet::same_name(machine, peer))
                    || node.is_some_and(|node| fleet::same_name(node, peer));
                if !matches {
                    continue;
                }
            }
            if let Some(node) = node.or(machine) {
                nodes.push(node.to_string());
            }
        }
        if !nodes.is_empty() {
            break;
        }
    }
    nodes.sort();
    nodes.dedup();
    nodes
}

/// Start `ouro daemon` for this data directory, detached from the SSH session.
///
/// `setsid` is what makes the child outlive the helper: an sshd session that goes away
/// takes its process group with it, and a machine that was told to start must stay
/// started. Nothing from the request reaches this command line.
fn spawn_detached_daemon(data_dir: &Path) -> Result<u32> {
    use std::os::unix::process::CommandExt as _;

    let executable = std::env::current_exe().context("locating this ouro executable")?;
    let mut command = Command::new(executable);
    command
        .arg("daemon")
        .env("OUROBOROS_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `setsid` is async-signal-safe and this closure runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().context("starting `ouro daemon`")?;
    Ok(child.id())
}

/// Carry a service refusal's stable reason onto the wire unchanged. The helper's one
/// refusal shape is `fleet::Refusal`; this is the translation, and a failure that
/// declared no reason stays an ordinary `failed`.
fn service_refusal(error: anyhow::Error) -> anyhow::Error {
    match crate::fleet_service::service_error(&error) {
        Some(declared) => fleet::Refusal {
            reason: declared.reason,
            detail: declared.detail.clone(),
        }
        .into(),
        None => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_nodes_reads_the_roster_name_or_the_node_name() {
        let status = json!({
            "machines": [
                {"machine": "studio", "node": "ouro-studio@100.64.0.1", "connected": true},
                {"machine": "pi", "node": "ouro-pi@100.64.0.2", "connected": false},
            ]
        });
        assert_eq!(
            connected_nodes(&status, None),
            vec!["ouro-studio@100.64.0.1"]
        );
        assert!(connected_nodes(&status, Some("pi")).is_empty());
        assert_eq!(
            connected_nodes(&status, Some("studio")),
            vec!["ouro-studio@100.64.0.1"]
        );
    }

    /// A path outside the helper's own data directory is refused before anything opens
    /// it, and so is every spelling that would resolve outside it.
    #[test]
    fn a_request_path_stays_inside_the_directory_this_helper_serves() {
        let root = Path::new("/tmp/ouro-helper-root");
        assert!(validate_request_path("/tmp/ouro-helper-root", root).is_ok());
        for hostile in [
            "relative/path",
            "/tmp/ouro-helper-root/../elsewhere",
            "/etc/passwd",
        ] {
            assert!(
                validate_request_path(hostile, root).is_err(),
                "{hostile} must be refused"
            );
        }
    }
}
