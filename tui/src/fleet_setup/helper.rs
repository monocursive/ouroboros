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

use std::io::{BufRead, BufReader, Write};
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
    input: Option<std::process::ChildStdin>,
    replies: Receiver<String>,
    stderr: Arc<Mutex<Vec<u8>>>,
    next_id: u64,
    label: String,
    finished: bool,
}

impl Session {
    /// Start `ssh <dest> <helper command>` and hold its pipes.
    pub fn open(runner: &Runner, executable: &str, data_dir: Option<&str>) -> Result<Self> {
        let command = helper_command(executable, data_dir);
        let mut child = runner.spawn(&command)?;
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

        let (sender, replies) = sync_channel::<String>(4);
        std::thread::Builder::new()
            .name("ouro-helper-stdout".to_string())
            .spawn(move || {
                for line in BufReader::new(output).split(b'\n') {
                    let Ok(line) = line else { return };
                    if line.len() > super::MAX_FRAME_BYTES {
                        return;
                    }
                    let text = String::from_utf8_lossy(&line).trim_end().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    if sender.send(text).is_err() {
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
            input: Some(input),
            replies,
            stderr,
            next_id: 0,
            label: runner.destination.label(),
            finished: false,
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
                sanitize_remote_text(detail, 300)
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

        let reply = match self.replies.recv_timeout(REPLY_DEADLINE) {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                return refuse(
                    "helper_timeout",
                    format!(
                        "{} did not answer `{op}` within {} seconds",
                        self.label,
                        REPLY_DEADLINE.as_secs()
                    ),
                )
            }
            Err(RecvTimeoutError::Disconnected) => {
                return refuse(
                    "helper_unavailable",
                    format!(
                        "{} closed the setup protocol before answering `{op}`. {}",
                        self.label,
                        self.diagnostics()
                    ),
                )
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
                Ok(Some(_)) => return,
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

/// Map a reason string that arrived from a remote onto one this client declares.
///
/// A remote's `reason` is data: it decides which branch is taken, so it is matched
/// against a closed list. An unrecognized code becomes `helper_refused`, and the
/// original text stays in the human `detail`.
fn known_reason(reason: &str) -> &'static str {
    const KNOWN: &[&str] = &[
        "bad_request",
        "unsupported_op",
        "unsupported_version",
        "frame_too_large",
        "invalid_path",
        "invalid_request",
        "operation_in_progress",
        "install_in_progress",
        "identity_mismatch",
        "fleet_exists",
        "no_fleet",
        "no_ca_key",
        "machine_known",
        "machine_already_issued",
        "operation_replayed",
        "csr_identity_mismatch",
        "roster_conflict",
        "roster_refused",
        "roster_too_large",
        // A lock held by a concurrent lifecycle or roster operation is a retry, distinct
        // from a stale revision (`roster_conflict`) and from an invalid change
        // (`roster_refused`).
        "lock_unavailable",
        // An idempotent `install` replay whose materials are not the ones already
        // installed. A reconciliation refusal, never an overwrite.
        "materials_differ",
        "runtime_running",
        "unsupported_action",
        "unsupported_platform",
        "foreign_unit",
        "manager_unavailable",
        "manager_refused",
        "staging_missing",
        "unusable_host",
        "failed",
    ];
    KNOWN
        .iter()
        .find(|known| **known == reason)
        .copied()
        .unwrap_or("helper_refused")
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

    /// A remote decides which branch this client takes, so its reason is matched against
    /// a closed list rather than trusted as a code.
    #[test]
    fn a_remote_reason_is_matched_against_the_codes_this_client_knows() {
        assert_eq!(known_reason("materials_differ"), "materials_differ");
        assert_eq!(known_reason("lock_unavailable"), "lock_unavailable");
        assert_eq!(known_reason("roster_conflict"), "roster_conflict");
        assert_eq!(known_reason("no_ca_key"), "no_ca_key");
        assert_eq!(known_reason("something_new"), "helper_refused");
        assert_eq!(known_reason(""), "helper_refused");
    }
}
