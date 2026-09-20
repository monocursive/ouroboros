//! Speaking seam C3 to `ouro fleet helper` on the other end of an `ssh` pipe.
//!
//! The remote side is [`crate::fleet_helper`]. This side owns the `ssh` child, frames
//! requests, enforces a reply deadline, and turns `{"ok": false, "reason": …}` back into
//! an error carrying that stable reason, so the engine branches on the same codes
//! whether a step ran locally or across the network.
//!
//! Two command strings exist, and both are fixed shapes with exactly one variable each,
//! shell-quoted. `ssh` runs whatever it is given through the remote login shell, so the
//! quoting — not the fact that this process built an argument array — is what keeps a
//! path from being read as shell source.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use super::ssh::{shell_quote, Runner};
use super::{refuse, sanitize_remote_text, SetupError};

/// A helper that stops answering has failed; the operation does not wait for a network.
pub const REPLY_DEADLINE: Duration = Duration::from_secs(60);

/// The remote command that starts the helper.
///
/// With no explicit data directory: `exec <ouro> fleet helper`. With one:
/// `exec /usr/bin/env OUROBOROS_DATA_DIR=<dir> <ouro> fleet helper`, because the helper
/// deliberately takes no `--data-dir` flag — a data directory on a command line would be
/// published to every process on the target by `ps`, and `tui/src/cli.rs`'s
/// `no_subcommand_accepts_a_token_on_the_command_line` pins that.
pub fn helper_command(executable: &str, data_dir: Option<&str>) -> String {
    match data_dir {
        Some(data_dir) => format!(
            "exec /usr/bin/env OUROBOROS_DATA_DIR={} {} fleet helper",
            shell_quote(data_dir),
            shell_quote(executable)
        ),
        None => format!("exec {} fleet helper", shell_quote(executable)),
    }
}

/// An open helper conversation over one `ssh` child.
pub struct Session {
    child: std::process::Child,
    /// The askpass window this connection opened. Dropped with the session, so a prompt
    /// can only arrive while the `ssh` it belongs to is alive.
    armed: Option<super::askpass::Armed>,
    input: Option<std::process::ChildStdin>,
    replies: Receiver<Result<String, ()>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    next_id: u64,
    label: String,
    executable: String,
    finished: bool,
    cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl Session {
    /// Start `ssh <dest> <helper command>` and hold its pipes.
    ///
    /// `executable` is remembered so a refusal can name *which* `ouro` answered: the
    /// commonest way this fails is an older release at that path, and "unrecognized
    /// subcommand 'helper'" plus a usage dump is not an answer an operator can act on.
    pub fn open(runner: &Runner, executable: &str, data_dir: Option<&str>) -> Result<Self> {
        let command = helper_command(executable, data_dir);
        let (mut child, armed) = runner.spawn(&command)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("the ssh child has no stdin"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("the ssh child has no stdout"))?;
        let errors = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("the ssh child has no stderr"))?;

        let (sender, replies) = sync_channel::<Result<String, ()>>(4);
        std::thread::Builder::new()
            .name("ouro-helper-stdout".to_string())
            .spawn(move || {
                let mut reader = BufReader::new(output);
                loop {
                    let mut line = Vec::new();
                    let read = reader
                        .by_ref()
                        .take(super::MAX_FRAME_BYTES as u64 + 1)
                        .read_until(b'\n', &mut line);
                    if !matches!(read, Ok(n) if n > 0) {
                        return;
                    }
                    if line.len() > super::MAX_FRAME_BYTES {
                        let _ = sender.send(Err(()));
                        return;
                    }
                    let text = String::from_utf8_lossy(&line).trim_end().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    if sender.send(Ok(text)).is_err() {
                        return;
                    }
                }
            })
            .context("reading helper replies")?;

        let stderr = Arc::new(Mutex::new(Vec::new()));
        {
            let sink = Arc::clone(&stderr);
            std::thread::Builder::new()
                .name("ouro-helper-stderr".to_string())
                .spawn(move || {
                    use std::io::Read as _;
                    let mut buffer = [0_u8; 8 * 1024];
                    let mut errors = errors;
                    while let Ok(read) = errors.read(&mut buffer) {
                        if read == 0 {
                            return;
                        }
                        let mut held = sink.lock().unwrap_or_else(|p| p.into_inner());
                        if held.len() < 64 * 1024 {
                            held.extend_from_slice(&buffer[..read]);
                        }
                    }
                })
                .context("reading ssh diagnostics")?;
        }

        Ok(Self {
            child,
            armed,
            input: Some(input),
            replies,
            stderr,
            next_id: 0,
            label: runner.destination.label(),
            executable: executable.to_string(),
            finished: false,
            cancelled: runner.cancelled.clone(),
        })
    }

    /// Whatever `ssh` itself said, sanitized. Used to explain a session that never
    /// started: an authentication refusal, a changed host key, an unreachable address.
    pub fn diagnostics(&self) -> String {
        let held = self.stderr.lock().unwrap_or_else(|p| p.into_inner());
        sanitize_remote_text(&String::from_utf8_lossy(&held), 300)
    }

    /// Send one request and return the reply's fields, or an error carrying the
    /// helper's own stable reason.
    pub fn discard_preparation(&mut self, operation: &str) -> Result<Map<String, Value>> {
        let cancelled = self.cancelled.take();
        let result = self.ask(
            "discard_preparation",
            serde_json::json!({"operation": operation}),
        );
        self.cancelled = cancelled;
        result
    }

    pub fn ask(&mut self, op: &str, fields: Value) -> Result<Map<String, Value>> {
        let reply = self.ask_raw(op, fields)?;
        if reply.get("ok").and_then(Value::as_bool) == Some(true) {
            let mut fields = reply;
            for envelope in ["v", "id", "ok"] {
                fields.remove(envelope);
            }
            return Ok(fields);
        }
        let reason = reply
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("helper_refused")
            .to_string();
        let detail = reply
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("the remote helper refused without a reason");
        Err(SetupError {
            // The remote's reason is data, so it is checked against the codes this
            // client knows rather than leaked into a `&'static str` by transmuting a
            // remote string into one.
            reason: known_reason(&reason),
            detail: format!(
                "{} refused `{op}`: {} ({reason})",
                self.label,
                sanitize_remote_text(detail, 2_000)
            ),
        }
        .into())
    }

    fn ask_raw(&mut self, op: &str, fields: Value) -> Result<Map<String, Value>> {
        self.next_id += 1;
        let id = format!("q{}", self.next_id);
        // The envelope is inserted last, so a caller's field cannot displace `op` or
        // `id`, and a `Map` cannot emit a duplicate key at all — the helper reads
        // duplicates last-wins, so never producing one is the only safe rule.
        let mut request = Map::new();
        if let Value::Object(fields) = fields {
            for (key, value) in fields {
                request.insert(key, value);
            }
        }
        request.insert("v".to_string(), json!(1));
        request.insert("id".to_string(), json!(id));
        request.insert("op".to_string(), json!(op));
        let line = Value::Object(request).to_string();
        if line.len() + 1 > super::MAX_FRAME_BYTES {
            return refuse(
                "frame_too_large",
                format!("the `{op}` request does not fit the helper's frame limit"),
            );
        }
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the helper session is closed"))?;
        input
            .write_all(line.as_bytes())
            .and_then(|()| input.write_all(b"\n"))
            .and_then(|()| input.flush())
            .map_err(|error| {
                SetupError {
                    reason: "helper_unavailable",
                    detail: format!(
                        "{} stopped reading the setup protocol ({error}). {}",
                        self.label,
                        self.diagnostics()
                    ),
                }
                .into_anyhow()
            })?;

        let deadline = std::time::Instant::now() + REPLY_DEADLINE;
        let reply = loop {
            if self.cancelled.as_ref().is_some_and(|flag| flag()) {
                self.abort();
                return refuse("cancelled", "the operation was cancelled");
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return refuse(
                    "helper_timeout",
                    format!(
                        "{} did not answer `{op}` within {} seconds",
                        self.label,
                        REPLY_DEADLINE.as_secs()
                    ),
                );
            }
            let slice = (deadline - now).min(Duration::from_millis(100));
            match self.replies.recv_timeout(slice) {
                Ok(Ok(reply)) => break reply,
                Ok(Err(())) => {
                    self.abort();
                    return refuse(
                        "frame_too_large",
                        "the remote helper exceeded the reply frame limit; its connection was closed",
                    );
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    let diagnostics = self.diagnostics();
                    // An `ouro` too old to speak this protocol answers with clap's
                    // "unrecognized subcommand" and a usage page. That is a specific,
                    // actionable situation — upgrade that machine — and it deserves a
                    // reason of its own rather than a wall of remote usage text.
                    if looks_unsupported(&diagnostics) {
                        return refuse(
                            "helper_unsupported",
                            format!(
                                "{} answered `{}` with `unrecognized subcommand`: the Ouroboros there is too old to run fleet setup verbs. Upgrade that machine's Ouroboros, or point this command at the right executable with --remote-executable",
                                self.label, self.executable
                            ),
                        );
                    }
                    return refuse(
                        "helper_unavailable",
                        format!(
                            "{} closed the setup protocol before answering `{op}`. {diagnostics}",
                            self.label,
                        ),
                    );
                }
            }
        };
        let value: Value = serde_json::from_str(&reply).map_err(|error| {
            SetupError {
                reason: "helper_protocol",
                detail: format!(
                    "{} answered `{op}` with something that is not a frame: {error}",
                    self.label
                ),
            }
            .into_anyhow()
        })?;
        let Value::Object(reply) = value else {
            return refuse(
                "helper_protocol",
                format!(
                    "{} answered `{op}` with a JSON value that is not an object",
                    self.label
                ),
            );
        };
        if reply.get("id").and_then(Value::as_str) != Some(id.as_str()) {
            return refuse(
                "helper_protocol",
                format!(
                    "{} answered a request this session did not send",
                    self.label
                ),
            );
        }
        Ok(reply)
    }

    /// Say goodbye and reap the `ssh` child. Best effort: the point is not to leave a
    /// helper resident on the target, and the helper exits on EOF anyway.
    pub fn close(mut self) {
        self.close_in_place();
    }

    fn abort(&mut self) {
        self.finished = true;
        drop(self.input.take());
        // SAFETY: the pid names this process's own unreaped child, which `Runner::spawn`
        // placed in its own process group.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.wait();
        self.armed = None;
    }

    fn close_in_place(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.input.is_some() {
            let _ = self.ask_raw("bye", json!({}));
        }
        drop(self.input.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.armed = None;
                    return;
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break,
            }
        }
        // SAFETY: the pid names this process's own unreaped child, which `Runner::spawn`
        // placed in its own process group.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.wait();
        // Last, so the window is open for as long as the connection is and not a moment
        // longer.
        self.armed = None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close_in_place();
    }
}

impl SetupError {
    fn into_anyhow(self) -> anyhow::Error {
        self.into()
    }
}

/// Whether a remote's diagnostics are an `ouro` that does not know this subcommand.
///
/// clap's own wording, matched on the part that does not change with the locale or the
/// binary's name. The usage page that follows it is exactly the remote output
/// [`sanitize_remote_text`] exists for and is deliberately not repeated at an operator.
fn looks_unsupported(diagnostics: &str) -> bool {
    let lowered = diagnostics.to_ascii_lowercase();
    lowered.contains("unrecognized subcommand")
        || lowered.contains("unrecognised subcommand")
        || (lowered.contains("usage: ouro") && lowered.contains("error:"))
}

/// Map a reason string that arrived from a remote onto one this client declares.
///
/// A remote's `reason` is data: it decides which branch is taken, so it is matched
/// against a closed list. An unrecognized code becomes `helper_refused`, and the
/// original text stays in the human `detail`.
fn known_reason(reason: &str) -> &'static str {
    /// The envelope's own refusals, from `serve` before any op runs, plus the fallback
    /// a library error with no declared reason arrives under.
    const PROTOCOL: &[&str] = &[
        "bad_request",
        "unsupported_op",
        "unsupported_version",
        "frame_too_large",
        "invalid_path",
        "failed",
    ];
    /// What §7's seven ops refuse with.
    ///
    /// This list was the *withdrawn* design's: `no_ca_key`, `machine_already_issued`,
    /// `csr_identity_mismatch`, `roster_conflict`, `roster_too_large`,
    /// `materials_differ`, `operation_replayed` — every one of them a code from the
    /// per-member PKI and the replicated roster §1 deleted, and not one of them
    /// produced anywhere in this build. Meanwhile the codes §7 *does* name —
    /// `already_installed`, `bundle_invalid`, `fleet_present`, `fleet_unreadable`,
    /// `runtime_running` — were absent, so a helper that said "that machine is already
    /// in this fleet under this name" reached the engine as `helper_refused`: the one
    /// idempotent, retry-into-me answer in the protocol, flattened into the answer for
    /// a code nobody understands.
    const OPS: &[&str] = &[
        "identity_mismatch",
        // `install`
        "already_installed",
        "bundle_invalid",
        "fleet_present",
        "invalid_request",
        "unusable_host",
        // `inspect`
        "fleet_unreadable",
        // `install`, `service`, `start`, `leave`: this machine is not stopped.
        "runtime_running",
    ];
    if let Some(known) = PROTOCOL.iter().chain(OPS).find(|known| **known == reason) {
        return known;
    }
    // §7's `service` and `start` answer with the service slice's own codes, so that
    // catalogue is consulted rather than copied into this one. Its own fallback means
    // "not a service code", which here is just "not a code this client knows".
    match super::service::known_service_reason(reason) {
        "service_refused" => "helper_refused",
        service => service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One fixed shape per variable, and the variable is quoted. A path with a quote,
    /// a space or a `$(…)` in it is a path, not shell source.
    #[test]
    fn the_helper_command_quotes_its_one_variable() {
        assert_eq!(
            helper_command("/home/me/.local/bin/ouro", None),
            "exec '/home/me/.local/bin/ouro' fleet helper"
        );
        assert_eq!(
            helper_command("/home/me/.local/bin/ouro", Some("/home/me/.ouroboros")),
            "exec /usr/bin/env OUROBOROS_DATA_DIR='/home/me/.ouroboros' '/home/me/.local/bin/ouro' fleet helper"
        );
        let hostile = helper_command("/tmp/x; rm -rf ~", Some("$(id)"));
        assert!(hostile.contains("'/tmp/x; rm -rf ~'"), "{hostile}");
        assert!(hostile.contains("'$(id)'"), "{hostile}");
        assert!(
            !hostile.contains("; rm -rf ~ "),
            "the metacharacters stay inside the quotes: {hostile}"
        );
    }

    /// An `ouro` too old to have `fleet helper` is a specific situation with a specific
    /// repair, not a generic "the helper went away".
    #[test]
    fn an_old_remote_ouro_is_recognized_rather_than_quoted_at_the_operator() {
        assert!(looks_unsupported(
            "error: unrecognized subcommand 'helper' Usage: ouro [OPTIONS] [COMMAND]"
        ));
        assert!(looks_unsupported("error: unrecognised subcommand 'helper'"));
        assert!(!looks_unsupported("bash: ouro: command not found"));
        assert!(!looks_unsupported("Permission denied (publickey)."));
        assert!(!looks_unsupported(""));
    }

    /// A remote decides which branch this client takes, so its reason is matched against
    /// a closed list rather than trusted as a code.
    ///
    /// The list is §7's, and §7 is the whole of what a helper can say. It used to be the
    /// withdrawn design's — the per-member PKI's `no_ca_key` and `csr_identity_mismatch`,
    /// the replicated roster's `roster_conflict` and `machine_already_issued` — none of
    /// which any build since §1 can produce, while §7's own codes fell through to
    /// `helper_refused`.
    #[test]
    fn a_remote_reason_is_matched_against_the_codes_this_client_knows() {
        // §7's `install`, including the idempotent replay a resume retries into.
        for reason in [
            "already_installed",
            "bundle_invalid",
            "fleet_present",
            "fleet_unreadable",
            "runtime_running",
            "invalid_request",
            "unusable_host",
        ] {
            assert_eq!(known_reason(reason), reason, "§7 names {reason}");
        }
        // The envelope's own refusals.
        for reason in ["bad_request", "unsupported_op", "frame_too_large", "failed"] {
            assert_eq!(known_reason(reason), reason);
        }
        // `service` and `start` answer with the service slice's codes, through its own
        // catalogue rather than a second copy of it.
        for reason in ["not_installed", "manager_refused", "unsupported_platform"] {
            assert_eq!(known_reason(reason), reason);
        }
        // The withdrawn design's codes are not codes any more. A remote that sends one
        // is a remote this client does not understand, and says so.
        for gone in [
            "materials_differ",
            "lock_unavailable",
            "roster_conflict",
            "no_ca_key",
            "machine_already_issued",
            "csr_identity_mismatch",
            "operation_replayed",
        ] {
            assert_eq!(known_reason(gone), "helper_refused", "{gone} is withdrawn");
        }
        assert_eq!(known_reason("something_new"), "helper_refused");
        assert_eq!(known_reason(""), "helper_refused");
    }
}
