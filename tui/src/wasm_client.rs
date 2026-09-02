//! Speaking to a local `ouro-wasm` from `ouro wasm` (docs/WASM.md W10, D14).
//!
//! The five developer subcommands — `inspect`, `run`, `hook`, `check`, `new` — need a helper
//! and no node. This module is the whole of that: where the helper is allowed to come from,
//! how it is started, the six methods, and the two rules that keep running somebody else's
//! component on a developer's laptop as contained as running it on a node.
//!
//! # Where the helper may come from, and where it may not (D14)
//!
//! Three places, in order:
//!
//!   1. `--helper <path>`, which the developer typed;
//!   2. `$OUROBOROS_WASM_HELPER`, absolute, which the developer exported;
//!   3. `ouro`'s own sibling — `<dir of the *resolved* binary>/ouro-wasm` — the helper
//!      installed alongside this `ouro`.
//!
//! **Nothing cwd-derived unless the developer said so.** `Ouroboros.Wasm.helper_path/0`
//! removed every cwd-derived candidate in W7 for a reason that applies here with more force:
//! the helper *is* the containment boundary, so a cloned repository that could drop a
//! `priv/wasm/ouro-wasm` into a directory somebody runs `ouro wasm inspect` in would be
//! handing this command the binary it spawns to contain untrusted code. A developer may still
//! *point at* a helper inside a checkout — `--helper ./priv/wasm/ouro-wasm`, or the absolute
//! `$OUROBOROS_WASM_HELPER` that CI itself exports — because that is a person choosing, which
//! is the only thing that may choose. What is forbidden is a path this command derives on its
//! own from wherever it happens to have been run.
//!
//! # Every candidate is canonicalised and vetted before it is spawned ([`vet`])
//!
//! Three defects made the rule above a description rather than a mechanism, all three of them
//! found by review and each with a proof:
//!
//!   * **The sibling was the directory `ouro` was *reached through*.** `current_exe` returns
//!     the path used to start the process, symlinks and all, so a repository shipping
//!     `./ouro -> /usr/local/bin/ouro` beside its own `./ouro-wasm` had that `ouro-wasm`
//!     executed. `current_exe` is now canonicalised *first*, so the sibling is the directory
//!     the real binary lives in.
//!   * **The file checked and the file executed could differ.** `--helper ouro-wasm` has no
//!     path separator: `is_file()` resolved it against the working directory, and
//!     `Command::new` then did a `$PATH` search and ran something else entirely. Every
//!     accepted path is now canonicalised and it is the *canonical* path that is spawned —
//!     which is what [`HelperBinary`] exists to make unskippable.
//!   * **Nothing checked who owned it.** A helper that is writable by anyone but its owner is
//!     a containment boundary anybody can replace. [`vet`] applies the same shape
//!     `fleet.rs`'s packaged-EPMD check applies: a regular file, owned, executable, and not
//!     group- or world-writable.
//!
//! Outside the model, stated: a local attacker who can already write into the directory the
//! real `ouro` lives in, or who can hard-link that binary into a directory they control.
//! A hard link needs local write access to a directory on the same filesystem, which is
//! access this rule cannot take away — the link is indistinguishable from the file, because
//! it *is* the file. What the model does cover is a repository, a clone, an archive, or
//! anything else that arrives as data.
//!
//! # The environment the helper is given
//!
//! The same allow-list `Ouroboros.Wasm.Pool`'s `@inherited_env` passes: `PATH`, `HOME`,
//! `TMPDIR`, and each only when its value does not look like a credential. Expressed here as
//! [`std::process::Command::env_clear`] plus three insertions rather than as the pool's
//! removal list, because Rust has the clear the BEAM's `Port.open/2` does not — the outcome is
//! the same and this direction cannot be incomplete.
//!
//! # Everything the helper says is somebody else's text
//!
//! A guest's reply, its log lines and its `describe` are authored by the component. They are
//! printed to a terminal, where a control character is not a character but an instruction —
//! move the cursor, erase the line, set a colour, retitle the window. [`sanitize`] strips
//! them before anything here prints. The helper does its own bounding on the wire; this is the
//! second half, on the way to a tty.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

/// The helper's file name, wherever it is found.
pub const HELPER: &str = "ouro-wasm";

/// The override an operator exports, mirrored from `Ouroboros.Wasm.helper_path/0`.
pub const HELPER_ENV: &str = "OUROBOROS_WASM_HELPER";

/// The variables the helper inherits, and the only ones. `Ouroboros.Wasm.Pool`'s
/// `@inherited_env`, name for name.
const INHERITED_ENV: [&str; 3] = ["PATH", "HOME", "TMPDIR"];

/// How long any one request may take before the helper is declared stuck. Sized by `load`,
/// which compiles: the node's own `request_timeout_ms` is 30 s and a `call` gets its deadline
/// plus a margin, so this is that margin applied to the longest thing a developer waits for.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

/// The three bounds every instance runs under. There is no unlimited default here for the same
/// reason the helper has none: a bound nobody stated is a bound nobody chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub deadline_ms: u64,
}

/// The node's own defaults, from `config/config.exs`'s `capability_limits`. Copied rather than
/// read, because there is no node in this loop to ask — and named here so the copy is one
/// place a reader can check against the config file.
pub const NODE_DEFAULT_LIMITS: Limits = Limits {
    fuel: 100_000_000,
    memory_bytes: 64 * 1024 * 1024,
    deadline_ms: 5_000,
};

impl Limits {
    fn to_json(self) -> Value {
        json!({
            "fuel": self.fuel,
            "memory_bytes": self.memory_bytes,
            "deadline_ms": self.deadline_ms,
        })
    }

    /// Clamps each bound to what the helper reported it will accept, and says what it moved.
    ///
    /// A `--fuel` past the helper's ceiling is a request the helper would refuse
    /// `limits_out_of_range`; clamping it is not a widening — the direction is only ever
    /// downwards — and it turns a refusal an author has to decode into a printed line. The
    /// bounds come out of `doctor`, so this can never invent a ceiling the helper does not
    /// have.
    pub fn clamped(self, limits: &Value) -> (Limits, Vec<String>) {
        let mut moved = Vec::new();
        let mut out = self;

        let mut cap = |asked: &mut u64, key: &str, label: &str| {
            if let Some(bound) = limits.get(key).and_then(Value::as_u64) {
                if *asked > bound {
                    moved.push(format!("{label} {asked} is above the helper's {bound}"));
                    *asked = bound;
                }
            }
        };

        cap(&mut out.fuel, "max_fuel", "fuel");
        cap(&mut out.memory_bytes, "max_memory_bytes", "memory");
        cap(&mut out.deadline_ms, "max_deadline_ms", "deadline");

        (out, moved)
    }
}

/// A helper path that has been canonicalised and vetted, and the only thing [`Helper::start`]
/// will spawn.
///
/// A newtype rather than a `PathBuf`, and that is the whole point of it: review found a path
/// that passed `is_file()` and then had `Command::new` run a *different* file, so "the checked
/// path is the spawned path" cannot be a convention somebody remembers. It is a type nobody can
/// construct except through [`vet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperBinary(PathBuf);

impl HelperBinary {
    /// The canonical absolute path, for a message that names which binary was used.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl std::fmt::Display for HelperBinary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// The helper's path, resolved by the three rules in the module header and no others.
pub fn resolve(explicit: Option<&Path>) -> Result<HelperBinary> {
    resolve_from(explicit, std::env::var_os(HELPER_ENV), sibling())
}

/// The rule itself, as a function of what was typed, what was exported, and where this binary
/// really lives — so a test can state all three instead of mutating a process-wide environment,
/// and so the list of candidates is one expression a reader can check against D14.
///
/// There is no fourth argument, and that absence is the decision: nothing derived from the
/// working directory is passed in, so nothing derived from it can be selected. A developer may
/// still *name* a path inside a checkout through the first two, which is a person choosing.
fn resolve_from(
    explicit: Option<&Path>,
    from_env: Option<OsString>,
    sibling: Option<PathBuf>,
) -> Result<HelperBinary> {
    if let Some(path) = explicit {
        return vet(path, "--helper");
    }

    if let Some(from_env) = from_env {
        let path = PathBuf::from(&from_env);
        // Absolute, exactly as `Ouroboros.Wasm.helper_path/0` requires: a relative value in an
        // environment variable is resolved against the working directory, and a helper chosen
        // by where the command happened to be run is the one thing D14 forbids. Refused before
        // it is canonicalised, because canonicalising it *is* resolving it against the cwd.
        if !path.is_absolute() {
            bail!(
                "{HELPER_ENV} is {:?}, which is not an absolute path. A relative one would be \
                 resolved against the working directory, and the helper is the containment \
                 boundary: where it comes from must not depend on where this command was typed.",
                from_env
            );
        }
        return vet(&path, HELPER_ENV);
    }

    // `exists()` rather than `is_file()`: something is there and it is not usable, so the
    // reader is owed the reason rather than "there is no helper".
    if let Some(sibling) = sibling {
        if sibling.exists() {
            return vet(&sibling, "the `ouro-wasm` installed beside `ouro`");
        }
    }

    bail!(
        "no `{HELPER}` to run this with. `ouro wasm` looks in exactly three places, in order: \
         `--helper <path>`, an absolute ${HELPER_ENV}, and beside the installed `ouro` binary. \
         It deliberately derives nothing from the working directory — the helper is the \
         containment boundary, so a checkout must not be able to supply one this command went \
         looking for. Build one with `make wasm` and point ${HELPER_ENV} at it."
    );
}

/// Canonicalises a candidate and refuses it unless it is a helper this process may trust.
///
/// The same shape `fleet.rs`'s packaged-EPMD check applies, for the same reason: a program this
/// process is about to execute is not somewhere to be relaxed about ownership. Four questions,
/// in the order that makes each one meaningful:
///
///   1. **Canonicalise.** Every symlink resolved and the result absolute, so what is checked
///      below is the file itself and — because this canonical path is what [`HelperBinary`]
///      carries to `Command::new` — so that the file checked is the file run. A path that
///      cannot be canonicalised does not exist, and is refused rather than forwarded to a
///      `$PATH` search.
///   2. **A regular file.** A directory, a device, a socket or a FIFO is not a helper.
///   3. **Owned, and executable.** `uid == geteuid()` is `fleet.rs`'s rule. Root ownership is
///      accepted too: a helper installed by a package manager into `/usr/local/bin` is owned by
///      root and is *more* trustworthy than one owned by this account, not less — the attacker
///      in this model is a repository, and refusing the safest install would push a developer
///      to `--helper`, which is vetted by this same function anyway.
///   4. **Not group- or world-writable.** A binary anybody may rewrite is a containment
///      boundary anybody may replace, whoever nominally owns it.
///
/// What this cannot answer is who may write the *directory* it sits in; see the module header
/// for that residual.
pub fn vet(path: &Path, source: &str) -> Result<HelperBinary> {
    let canonical = std::fs::canonicalize(path).with_context(|| {
        format!(
            "{source}: {} could not be resolved to a real path",
            path.display()
        )
    })?;

    let metadata = std::fs::symlink_metadata(&canonical)
        .with_context(|| format!("{source}: could not inspect {}", canonical.display()))?;

    let uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file() {
        bail!(
            "{source}: {} is not a regular file, so it is not a helper",
            canonical.display()
        );
    }
    if metadata.uid() != uid && metadata.uid() != 0 {
        bail!(
            "{source}: {} is owned by uid {}, not by this account (uid {uid}) or root. The \
             helper is the containment boundary: a binary somebody else owns is a binary \
             somebody else chooses.",
            canonical.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & 0o111 == 0 {
        bail!("{source}: {} is not executable", canonical.display());
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "{source}: {} is group- or world-writable (mode {:o}); a helper anybody can rewrite \
             is a containment boundary anybody can replace",
            canonical.display(),
            metadata.mode() & 0o7777
        );
    }

    Ok(HelperBinary(canonical))
}

/// The helper installed beside `ouro`, with `current_exe` canonicalised **first**.
///
/// Uncanonicalised, this was the directory `ouro` was *reached through*: a repository shipping
/// `./ouro -> /usr/local/bin/ouro` next to its own `./ouro-wasm` had that `ouro-wasm` spawned,
/// which is exactly the thing D14 exists to prevent, arriving by the one road nobody was
/// watching. Canonicalising first makes this the directory the real binary lives in.
fn sibling() -> Option<PathBuf> {
    let executable = std::fs::canonicalize(std::env::current_exe().ok()?).ok()?;
    Some(executable.parent()?.join(HELPER))
}

/// A running `ouro-wasm serve` and the line protocol over its stdio.
pub struct Helper {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<String>,
    stderr: Arc<Mutex<Vec<String>>>,
    next_id: i64,
    path: PathBuf,
}

impl Helper {
    /// Starts `<binary> serve` with the allow-listed environment and nothing else.
    ///
    /// Takes a [`HelperBinary`] and not a path, so the canonical path [`vet`] approved is the
    /// path `Command::new` receives. There is no way to reach this function with anything else,
    /// which is the fix for a `--helper ouro-wasm` that passed `is_file()` against the working
    /// directory and then had `Command::new` do a `$PATH` search for something different.
    pub fn start(binary: &HelperBinary) -> Result<Helper> {
        let path = binary.path();
        let mut command = Command::new(path);
        command.arg("serve");

        // Deny by default: clear, then put back exactly what the pool passes.
        command.env_clear();
        for name in INHERITED_ENV {
            if let Some(value) = std::env::var_os(name) {
                if !looks_like_credential(&value) {
                    command.env(name, value);
                }
            }
        }

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("could not start {}", path.display()))?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin pipe"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("no stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("no stderr pipe"))?;

        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });

        // Drained on a thread of its own, and that is not tidiness: the helper's per-call log
        // budget keeps one call under a pipe buffer, and an owner that never reads the pipe
        // wedges it anyway. This is `ouro wasm` being that owner properly.
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Ok(mut lines) = sink.lock() {
                    lines.push(line);
                }
            }
        });

        Ok(Helper {
            child,
            stdin,
            replies,
            stderr: log,
            next_id: 1,
            path: path.to_path_buf(),
        })
    }

    /// Where this helper was found, for the line every command prints.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One request, one answer. `Err` carries the refusal name and the helper's message.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;

        let line = serde_json::to_string(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )?;
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;

        let reply: Value = match self.replies.recv_timeout(REQUEST_TIMEOUT) {
            Ok(line) => serde_json::from_str(&line)
                .with_context(|| format!("the helper answered {method} with something not JSON"))?,
            Err(RecvTimeoutError::Timeout) => {
                bail!("the helper did not answer {method} within {REQUEST_TIMEOUT:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                bail!("the helper closed its stdout while answering {method}")
            }
        };

        if let Some(error) = reply.get("error") {
            return Err(Refusal::from_error(error).into());
        }

        Ok(reply["result"].clone())
    }

    pub fn doctor(&mut self) -> Result<Value> {
        self.request("doctor", Value::Null)
    }

    pub fn inspect(&mut self, path: &Path) -> Result<Value> {
        self.request("inspect", json!({ "path": path.to_string_lossy() }))
    }

    pub fn load(&mut self, sha256: &str, path: &Path) -> Result<Value> {
        self.request(
            "load",
            json!({ "sha256": sha256, "path": path.to_string_lossy() }),
        )
    }

    pub fn instantiate(
        &mut self,
        instance: &str,
        sha256: &str,
        config: &str,
        limits: Limits,
    ) -> Result<Value> {
        self.request(
            "instantiate",
            json!({
                "instance": instance,
                "sha256": sha256,
                "config": config,
                "limits": limits.to_json(),
            }),
        )
    }

    pub fn call(&mut self, instance: &str, export: &str, payload: &str) -> Result<Value> {
        self.request(
            "call",
            json!({ "instance": instance, "export": export, "payload": payload }),
        )
    }

    pub fn drop_instance(&mut self, instance: &str) -> Result<Value> {
        self.request("drop", json!({ "instance": instance }))
    }

    /// The guest log lines this helper has written since `since`, sanitized. The helper's own
    /// diagnostics are not guest speech and are left out: a line is a guest's when it carries
    /// the `guest <instance>` prefix `Host::new`'s `log` writes.
    pub fn guest_log(&self, since: usize) -> Vec<String> {
        let lines = match self.stderr.lock() {
            Ok(lines) => lines,
            Err(poisoned) => poisoned.into_inner(),
        };
        lines
            .iter()
            .skip(since)
            .filter(|line| line.contains("guest "))
            .map(|line| sanitize(line))
            .collect()
    }

    /// The guest log lines written since `mark` by a call whose reply said it wrote
    /// `expected` of them. stderr is a different pipe from stdout, read on a thread of its
    /// own, so the reply can arrive before the last line the guest wrote has been read; this
    /// waits for the count the helper reported, bounded so a reader thread that has died
    /// cannot hang the command, and then reads. `expected` is 0 for a refused call, whose
    /// count the helper does not know: that read is immediate.
    pub fn guest_log_counted(&self, mark: usize, expected: u64) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while (self.log_mark() as u64) < mark as u64 + expected && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.guest_log(mark)
    }

    /// How many stderr lines have arrived, so a caller can mark a point and read past it.
    pub fn log_mark(&self) -> usize {
        match self.stderr.lock() {
            Ok(lines) => lines.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        // The helper exits on EOF, but a guest inside a deadline is still a child this process
        // started and must not outlive it.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A refusal from the helper, in the two forms it arrives in: the stable name and the prose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub refusal: String,
    pub message: String,
}

impl Refusal {
    fn from_error(error: &Value) -> Refusal {
        Refusal {
            refusal: error["data"]["refusal"]
                .as_str()
                .unwrap_or("helper_error")
                .to_string(),
            message: sanitize(error["message"].as_str().unwrap_or("")),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "{}", self.refusal)
        } else {
            write!(f, "{}: {}", self.refusal, self.message)
        }
    }
}

impl std::error::Error for Refusal {}

/// The refusal name inside an error, if it was one. `ouro wasm` prints the *name* prominently
/// — it is the closed vocabulary an author can look up — and the prose after it.
pub fn refusal_of(error: &anyhow::Error) -> Option<&Refusal> {
    error.downcast_ref::<Refusal>()
}

/// Strips what a terminal would obey out of text a component wrote.
///
/// Control characters become spaces and an ANSI escape sequence — `ESC [ … final` and the
/// one-character `ESC x` forms — is removed whole rather than left as a visible `[0m`. Tabs
/// and newlines survive: they are layout in a reply, and the caller decides whether a reply is
/// printed on one line or many.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();

    while let Some(character) = characters.next() {
        if character == '\u{1b}' {
            // CSI and OSC both run to a terminator; every other escape is two characters.
            match characters.peek() {
                Some('[') => {
                    characters.next();
                    for inner in characters.by_ref() {
                        if ('@'..='~').contains(&inner) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    characters.next();
                    // OSC ends at BEL or ST; a string terminator is ESC \, whose ESC this loop
                    // consumes and whose backslash the next iteration drops as ordinary text.
                    for inner in characters.by_ref() {
                        if inner == '\u{7}' || inner == '\u{1b}' {
                            break;
                        }
                    }
                }
                Some(_) => {
                    characters.next();
                }
                None => {}
            }
            continue;
        }

        if character == '\n' || character == '\t' {
            out.push(character);
        } else if character.is_control() {
            out.push(' ');
        } else {
            out.push(character);
        }
    }

    out
}

/// The pool's own `@credential_value` question, asked of one environment value: does this path
/// carry a `scheme://user:password@` or a PEM private key header?
///
/// Hand-written rather than a regex, because `ouro` has no regex crate and the shape is two
/// literals. Both halves are the same shape the pool matches, narrowed to what a path can
/// plausibly contain, and a value this cannot read as UTF-8 is refused outright: an
/// unreadable value is one nothing here can vouch for.
fn looks_like_credential(value: &std::ffi::OsStr) -> bool {
    let Some(text) = value.to_str() else {
        return true;
    };
    userinfo_url(text) || private_key_header(text)
}

/// `scheme://user:password@` anywhere in the value.
fn userinfo_url(text: &str) -> bool {
    let mut from = 0usize;

    while let Some(offset) = text[from..].find("://") {
        let start = from + offset;
        if has_scheme(text, start) && has_userinfo(&text[start + 3..]) {
            return true;
        }
        from = start + 3;
    }

    false
}

/// Whether the bytes before `at` are a URI scheme: `[a-z][a-z0-9+.-]*`, read backwards.
fn has_scheme(text: &str, at: usize) -> bool {
    let bytes = text.as_bytes();
    let mut start = at;
    while start > 0 && is_scheme_byte(bytes[start - 1]) {
        start -= 1;
    }
    start < at && bytes[start].is_ascii_alphabetic()
}

/// Whether an authority — everything up to the next `/` — carries a non-empty `user:pass@`.
fn has_userinfo(rest: &str) -> bool {
    let authority = match rest.find('/') {
        Some(end) => &rest[..end],
        None => rest,
    };

    match (authority.find(':'), authority.find('@')) {
        (Some(colon), Some(at)) => colon < at && colon > 0 && !authority[colon + 1..at].is_empty(),
        _absent => false,
    }
}

fn is_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'.' || byte == b'-'
}

fn private_key_header(text: &str) -> bool {
    text.to_ascii_uppercase().contains("PRIVATE KEY-----")
}

/// The environment `ouro wasm` would hand a helper, for a test that wants to read it without
/// starting one.
pub fn inherited_environment() -> BTreeMap<String, OsString> {
    INHERITED_ENV
        .iter()
        .filter_map(|name| {
            let value = std::env::var_os(name)?;
            (!looks_like_credential(&value)).then(|| ((*name).to_string(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ansi_escape_from_a_guest_is_removed_rather_than_shown() {
        // A component that could write this into a reply could clear the developer's screen and
        // print its own verdict line.
        let text = sanitize("ok\u{1b}[2J\u{1b}[HREFUSED BY OPERATOR");
        assert_eq!(text, "okREFUSED BY OPERATOR");
        assert!(!text.contains('\u{1b}'));

        // A window-title OSC is removed whole, terminator included.
        assert_eq!(sanitize("a\u{1b}]0;owned\u{7}b"), "ab");
    }

    #[test]
    fn control_characters_become_spaces_and_layout_survives() {
        assert_eq!(sanitize("a\rb"), "a b");
        assert_eq!(sanitize("a\nb\tc"), "a\nb\tc");
        assert_eq!(sanitize("a\u{0}b"), "a b");
    }

    #[test]
    fn the_helper_environment_is_the_pools_allow_list() {
        // Not a list this module may extend quietly: `Ouroboros.Wasm.Pool`'s `@inherited_env`
        // is the same three names, and a helper handed more than the node hands it would be a
        // developer's laptop containing less than a node does.
        assert_eq!(INHERITED_ENV, ["PATH", "HOME", "TMPDIR"]);
    }

    #[test]
    fn a_value_shaped_like_a_credential_is_not_inherited() {
        assert!(looks_like_credential(std::ffi::OsStr::new(
            "https://user:secret@example.test/bin"
        )));
        assert!(looks_like_credential(std::ffi::OsStr::new(
            "-----BEGIN OPENSSH PRIVATE KEY-----"
        )));
        assert!(looks_like_credential(std::ffi::OsStr::new(
            "-----begin private key-----"
        )));

        // And an ordinary path is not a credential, or the allow-list would pass nothing.
        assert!(!looks_like_credential(std::ffi::OsStr::new(
            "/usr/local/bin:/usr/bin"
        )));
        assert!(!looks_like_credential(std::ffi::OsStr::new(
            "https://example.test/bin"
        )));
        assert!(!looks_like_credential(std::ffi::OsStr::new("/Users/a")));
    }

    #[test]
    fn limits_are_clamped_down_to_the_helpers_maxima_and_never_up() {
        let bounds = json!({
            "max_fuel": 1_000u64,
            "max_memory_bytes": 65_536u64,
            "max_deadline_ms": 100u64,
        });

        let (clamped, moved) = Limits {
            fuel: 10_000,
            memory_bytes: 1_000_000,
            deadline_ms: 60_000,
        }
        .clamped(&bounds);

        assert_eq!(clamped.fuel, 1_000);
        assert_eq!(clamped.memory_bytes, 65_536);
        assert_eq!(clamped.deadline_ms, 100);
        assert_eq!(moved.len(), 3, "every clamp is said out loud: {moved:?}");

        // Under the ceiling nothing moves — a clamp that raised a bound would be this command
        // handing a guest more than the developer asked for.
        let (kept, quiet) = Limits {
            fuel: 10,
            memory_bytes: 1_024,
            deadline_ms: 1,
        }
        .clamped(&bounds);
        assert_eq!(kept.fuel, 10);
        assert_eq!(kept.memory_bytes, 1_024);
        assert!(quiet.is_empty());
    }

    /// The resolution rule, in the one direction that matters: a helper sitting in the working
    /// directory is not a candidate, and there is nowhere in `resolve_from`'s signature to
    /// hand it one. Add a cwd candidate to `resolve_from` and this goes red.
    #[test]
    fn the_working_directory_is_not_a_place_a_helper_may_come_from() {
        let planted = plant_a_helper("resolve");

        // Nothing typed, nothing exported, no sibling: with a perfectly good helper sitting in
        // `<cwd>/priv/wasm/`, the answer is still that there is none.
        let error = resolve_from(None, None, None).expect_err("a planted helper is not a helper");
        assert!(
            error.to_string().contains("working directory"),
            "the refusal must say why the cwd was not consulted: {error}"
        );
        assert!(planted.helper.is_file(), "the plant was real");

        // The proof that the cwd cannot creep back in is the signature, not this assertion:
        // `resolve_from` is handed what was typed, what was exported and this binary's own
        // directory, and there is no fourth place for a working directory to arrive from.
        // Running `ouro wasm` *inside* the planted tree is the integration test
        // `a_helper_planted_in_the_working_directory_is_not_executed` in tests/wasm_cli.rs.
    }

    /// A relative `$OUROBOROS_WASM_HELPER` is refused rather than resolved, because resolving
    /// one is a read of the working directory by another name.
    ///
    /// The integration twin plants a *real, working* helper at the relative path, so the
    /// absolute-path rule is demonstrably what refuses it rather than the file being missing:
    /// `a_relative_helper_override_is_refused_even_when_it_would_have_worked`.
    #[test]
    fn a_relative_helper_override_is_refused() {
        let planted = plant_a_helper("relative");
        let relative = OsString::from("priv/wasm/ouro-wasm");

        let error = resolve_from(None, Some(relative), None)
            .expect_err("a relative override must not resolve");
        assert!(
            error.to_string().contains("absolute"),
            "the refusal must name the rule: {error}"
        );
        // And it is refused for being relative rather than for being absent: the same bytes at
        // an absolute path resolve.
        assert!(
            resolve_from(None, Some(planted.helper.clone().into_os_string()), None).is_ok(),
            "the same file, named absolutely, is a helper"
        );
    }

    /// The two candidates that *are* honoured, so the test above is a rule and not a refusal
    /// to work at all — and what comes back is the **canonical** path, which is what makes the
    /// checked file and the executed file the same file.
    #[test]
    fn an_absolute_override_and_a_sibling_are_both_honoured() {
        let planted = plant_a_helper("honoured");
        let canonical = std::fs::canonicalize(&planted.helper).expect("the plant canonicalises");

        let from_env = resolve_from(None, Some(planted.helper.clone().into_os_string()), None)
            .expect("an absolute override resolves");
        assert_eq!(from_env.path(), canonical);

        let from_sibling =
            resolve_from(None, None, Some(planted.helper.clone())).expect("a sibling resolves");
        assert_eq!(from_sibling.path(), canonical);

        let typed = resolve_from(Some(&planted.helper), None, None).expect("--helper resolves");
        assert_eq!(typed.path(), canonical);
    }

    /// H2. `--helper ouro-wasm` has no path separator, so `is_file()` used to resolve it against
    /// the working directory while `Command::new` did a `$PATH` search — the checked file and
    /// the executed file were different files, which review proved by having the `$PATH` one
    /// write a marker.
    ///
    /// Two things stop it now and this test names both: `vet` canonicalises, so a bare name that
    /// does not exist relative to the cwd is refused outright; and what it returns is a
    /// [`HelperBinary`], which is the only thing `Helper::start` will spawn — so even a bare
    /// name that *does* resolve is spawned as its absolute path and never handed to a `$PATH`
    /// search. Delete the `canonicalize` in `vet` and this goes red.
    #[test]
    fn a_bare_helper_name_is_never_left_for_a_path_search() {
        let error = resolve_from(Some(Path::new("ouro-wasm")), None, None)
            .expect_err("a bare name that is not a file here must refuse");
        assert!(
            error.to_string().contains("could not be resolved"),
            "the refusal must be about resolving the path: {error}"
        );

        // And a bare name that *does* resolve comes back absolute, so nothing downstream can
        // search for it.
        let planted = plant_a_helper("bare");
        let restore = std::env::current_dir().ok();
        let vetted = vet(&planted.helper, "--helper").expect("the plant vets");
        assert!(
            vetted.path().is_absolute(),
            "a vetted helper is absolute: {}",
            vetted.path().display()
        );
        if let Some(restore) = restore {
            let _ = std::env::set_current_dir(restore);
        }
    }

    /// H1. `current_exe` returns the path the process was *reached through*, symlinks and all,
    /// so a repository shipping `./ouro -> /usr/local/bin/ouro` beside its own `./ouro-wasm`
    /// had that `ouro-wasm` spawned. `sibling` canonicalises first.
    ///
    /// Asserted on the function rather than on a second `ouro`: what the bug was is that the
    /// *directory* was wrong, and this is the directory. The end-to-end proof — a real symlinked
    /// `ouro` beside a real planted helper — is
    /// `a_symlinked_ouro_does_not_adopt_the_helper_beside_the_symlink` in tests/wasm_cli.rs.
    #[test]
    fn the_sibling_is_the_directory_the_real_binary_lives_in() {
        let sibling = sibling().expect("this test binary has a directory");
        let real = std::fs::canonicalize(std::env::current_exe().expect("a current exe"))
            .expect("the test binary canonicalises");

        assert_eq!(
            sibling.parent().expect("the sibling has a directory"),
            real.parent().expect("the real binary has a directory"),
            "the sibling must be beside the resolved binary, not beside the path it was reached \
             through"
        );
        assert_eq!(sibling.file_name().expect("a file name"), HELPER);
    }

    /// `--helper` is what a developer typed, so it is honoured — and still has to exist.
    #[test]
    fn an_explicit_helper_that_is_not_a_file_is_refused() {
        let error = resolve_from(Some(Path::new("/nonexistent/ouro-wasm")), None, None)
            .expect_err("a missing --helper must refuse");
        assert!(error.to_string().contains("could not be resolved"));
    }

    /// `vet` refuses what is not a helper, whichever of the three roads it arrived by.
    ///
    /// Each clause deleted from `vet` turns one of these red: the file-type check (a directory),
    /// the executable bit, and the group/world-writable bit. Ownership has no negative case here
    /// — a test cannot make a file owned by somebody else without privileges it does not have —
    /// and is stated as a gap rather than asserted falsely.
    #[test]
    fn a_helper_must_be_an_executable_file_nobody_else_can_rewrite() {
        use std::os::unix::fs::PermissionsExt;

        let planted = plant_a_helper("vet");

        // A directory is not a helper.
        let directory = planted.helper.parent().expect("a parent directory");
        let error = vet(directory, "--helper").expect_err("a directory is not a helper");
        assert!(error.to_string().contains("not a regular file"));

        // Neither is a file nobody may execute.
        let inert = directory.join("not-executable");
        std::fs::write(&inert, b"#!/bin/sh\nexit 0\n").expect("a file");
        std::fs::set_permissions(&inert, std::fs::Permissions::from_mode(0o644))
            .expect("permissions");
        let error = vet(&inert, "--helper").expect_err("a non-executable is not a helper");
        assert!(error.to_string().contains("not executable"));

        // Nor one anybody may rewrite — a containment boundary the world can replace is not one.
        std::fs::set_permissions(&planted.helper, std::fs::Permissions::from_mode(0o777))
            .expect("permissions");
        let error = vet(&planted.helper, "--helper").expect_err("world-writable is not a helper");
        assert!(
            error.to_string().contains("group- or world-writable"),
            "the refusal must name the rule: {error}"
        );

        // Group-writable alone is enough, because a group is other people.
        std::fs::set_permissions(&planted.helper, std::fs::Permissions::from_mode(0o775))
            .expect("permissions");
        assert!(vet(&planted.helper, "--helper").is_err());

        // And the honest case still passes, or the rule would be a refusal to work.
        std::fs::set_permissions(&planted.helper, std::fs::Permissions::from_mode(0o755))
            .expect("permissions");
        assert!(vet(&planted.helper, "--helper").is_ok());
    }

    struct Planted {
        root: PathBuf,
        helper: PathBuf,
    }

    impl Drop for Planted {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    /// A `priv/wasm/ouro-wasm` in a directory of its own — the shape a cloned repository has.
    fn plant_a_helper(tag: &str) -> Planted {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "ouro-wasm-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after 1970")
                .as_nanos()
        ));
        let directory = root.join("priv").join("wasm");
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let helper = directory.join(HELPER);
        std::fs::write(&helper, b"#!/bin/sh\nexit 0\n").expect("a planted helper");
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755))
            .expect("an executable plant");
        Planted { root, helper }
    }
}
