//! The askpass bridge: the only path a password or a passphrase ever travels.
//!
//! OpenSSH will ask for a secret on `/dev/tty`, and a deployment worker has no tty. The
//! documented way out is `SSH_ASKPASS` with `SSH_ASKPASS_REQUIRE=force`, which makes
//! `ssh` run a helper and read the answer from its stdout. The helper this ships is
//! `ouro fleet askpass`: it connects to a Unix socket whose path arrives in
//! `OUROBOROS_ASKPASS_SOCKET` (a path, not a secret), sends the prompt `ssh` handed it,
//! and prints back exactly what the other side answered.
//!
//! The other side is [`Bridge`], and it is deliberately narrow:
//!
//! - it accepts a connection only while an `ssh` child of this worker is actually
//!   running, so a stray process cannot make a password prompt appear;
//! - it checks the connecting peer's uid against its own;
//! - it *classifies* the prompt rather than displaying it. OpenSSH composes that
//!   sentence, and the proposal is explicit that an arbitrary remote-influenced prompt
//!   must not be rendered as trusted UI. A prompt that is not recognisably a password
//!   or a passphrase request fails the attempt with a stable reason;
//! - it caps password prompts per connection at [`super::MAX_PASSWORD_ATTEMPTS`];
//! - it never logs the response, and the response never reaches argv, the environment,
//!   the journal or an error string. It exists as a [`Zeroizing<String>`] for the length
//!   of one `write_all`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::challenge::{passphrase_metadata, password_metadata, Answer, ChallengeKind};
use super::{refuse, sanitize_remote_text, ChallengeRequest, Conversation};

/// The environment variable that names the bridge's socket.
pub const SOCKET_ENV: &str = "OUROBOROS_ASKPASS_SOCKET";

/// A prompt longer than this is not a prompt.
const MAX_PROMPT_BYTES: usize = 4 * 1024;

/// How long the accept loop sleeps between polls while nothing is connecting.
const POLL: Duration = Duration::from_millis(20);

/// What the bridge knows about the connection `ssh` is making, so it can describe the
/// question without quoting the remote.
#[derive(Clone, Debug)]
pub struct PromptContext {
    pub target: String,
    pub user: String,
    pub port: u16,
    /// A label for the selected key, when one was selected.
    pub key_label: Option<String>,
    pub key_fingerprint: Option<String>,
}

/// What `ssh` was asking for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prompt {
    Password,
    Passphrase,
    /// Anything else, including a host-key confirmation. The attempt fails.
    Unsupported,
}

/// Classify an OpenSSH prompt without showing it to anyone.
///
/// Passphrase is tested first: "passphrase" and "password" are different words and the
/// substring test for the second must not win on the first.
pub fn classify(prompt: &str) -> Prompt {
    let lowered = prompt.to_ascii_lowercase();
    if lowered.contains("passphrase") {
        return Prompt::Passphrase;
    }
    // A host-key confirmation is a prompt OpenSSH will route here when it is allowed to
    // ask; this client never allows it (StrictHostKeyChecking is always `yes`), and if
    // one ever arrives it is refused rather than turned into a yes/no dialog that looks
    // like the operation's own.
    if lowered.contains("fingerprint")
        || lowered.contains("continue connecting")
        || lowered.contains("authenticity of host")
    {
        return Prompt::Unsupported;
    }
    if lowered.contains("password") {
        return Prompt::Password;
    }
    Prompt::Unsupported
}

/// The worker/CLI half: a private socket that answers one `ssh` process at a time.
pub struct Bridge {
    socket: PathBuf,
    /// The short private directory the socket lives in, removed with the bridge.
    home: PathBuf,
    /// The two-line launcher `SSH_ASKPASS` names.
    launcher: PathBuf,
    armed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    attempts: Arc<AtomicU32>,
    /// The number of prompts this bridge actually served, for tests and for the journal
    /// line that says how many attempts an authentication took.
    served: Arc<AtomicU32>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Bridge {
    /// Bind the socket and start accepting.
    ///
    /// Deliberately *not* inside the operation's scratch directory: a Unix socket path
    /// is limited to about a hundred bytes by `sockaddr_un`, and a data directory an
    /// operator chose plus `fleet/deploy/<id>.d/` plus a file name is already most of
    /// that. The socket therefore lives in its own short private directory, which is
    /// removed with the bridge. Its path is not a secret — it travels in an environment
    /// variable — and what protects it is the 0700 directory, the 0600 socket, the peer
    /// uid check and the arming window.
    pub fn start(
        askpass_program: &Path,
        context: PromptContext,
        conversation: Arc<dyn Conversation>,
    ) -> Result<Self> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let home = std::env::temp_dir().join(format!("ouro-ap-{}", super::random_hex(5)?));
        super::ensure_private_subdir(&home)?;
        let socket = home.join("s");

        // `SSH_ASKPASS` names an executable and OpenSSH passes the prompt as its only
        // argument, so it cannot name `ouro fleet askpass` directly. This two-line
        // launcher is that indirection and nothing else: it carries a path, never a
        // secret, it is private to this account, and it is removed with the bridge.
        let launcher = home.join("askpass");
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&launcher)
                .with_context(|| format!("creating {}", launcher.display()))?;
            writeln!(
                file,
                "#!/bin/sh\nexec {} fleet askpass \"$@\"",
                super::ssh::shell_quote(&askpass_program.display().to_string())
            )
            .with_context(|| format!("writing {}", launcher.display()))?;
        }
        if socket.as_os_str().len() > 100 {
            return refuse(
                "askpass_unavailable",
                format!(
                    "{} is too long for a Unix socket; set TMPDIR to a shorter directory",
                    socket.display()
                ),
            );
        }
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket)
            .with_context(|| format!("binding the askpass socket {}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", socket.display()))?;
        listener
            .set_nonblocking(true)
            .context("configuring the askpass socket")?;

        let armed = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU32::new(0));
        let served = Arc::new(AtomicU32::new(0));

        let thread = {
            let armed = Arc::clone(&armed);
            let stop = Arc::clone(&stop);
            let attempts = Arc::clone(&attempts);
            let served = Arc::clone(&served);
            std::thread::Builder::new()
                .name("ouro-askpass".to_string())
                .spawn(move || {
                    accept_loop(
                        listener,
                        armed,
                        stop,
                        attempts,
                        served,
                        context,
                        conversation,
                    )
                })
                .context("starting the askpass bridge")?
        };

        Ok(Self {
            socket,
            home,
            launcher,
            armed,
            stop,
            attempts,
            served,
            thread: Some(thread),
        })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The environment an `ssh` invocation needs to reach this bridge. `DISPLAY` is
    /// cleared because `SSH_ASKPASS_REQUIRE=force` is what selects the helper, and an
    /// inherited display would otherwise be part of that decision on some builds.
    pub fn ssh_env(&self) -> Vec<(String, String)> {
        vec![
            (
                "SSH_ASKPASS".to_string(),
                self.launcher.display().to_string(),
            ),
            ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
            ("DISPLAY".to_string(), String::new()),
            (SOCKET_ENV.to_string(), self.socket.display().to_string()),
        ]
    }

    /// Allow prompts for the duration of one `ssh` invocation, and reset the per-
    /// connection password attempt counter.
    pub fn arm(&self) {
        self.attempts.store(0, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }

    pub fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    /// How many prompts this bridge has answered, in total.
    pub fn served(&self) -> u32 {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.launcher);
        let _ = std::fs::remove_dir(&self.home);
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_loop(
    listener: UnixListener,
    armed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    attempts: Arc<AtomicU32>,
    served: Arc<AtomicU32>,
    context: PromptContext,
    conversation: Arc<dyn Conversation>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = serve_one(stream, &armed, &attempts, &served, &context, &conversation);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL);
            }
            Err(_) => return,
        }
    }
}

fn serve_one(
    stream: UnixStream,
    armed: &AtomicBool,
    attempts: &AtomicU32,
    served: &AtomicU32,
    context: &PromptContext,
    conversation: &Arc<dyn Conversation>,
) -> Result<()> {
    // The listener polls, so it is non-blocking, and an accepted socket inherits that on
    // macOS. Reading the prompt must block for it, not fail because it has not arrived
    // in the same instant as the connection.
    stream
        .set_nonblocking(false)
        .context("configuring the askpass connection")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .context("bounding the askpass read")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .context("bounding the askpass write")?;

    let mut writer = stream.try_clone().context("cloning the askpass socket")?;
    let peer = peer_uid(&stream)?;
    let own = unsafe { libc::geteuid() };
    if peer != own {
        return deny(
            &mut writer,
            "peer_uid_mismatch",
            "this socket answers only the account that owns the operation",
        );
    }
    if !armed.load(Ordering::SeqCst) {
        return deny(
            &mut writer,
            "not_authenticating",
            "no authentication attempt is in flight for this operation",
        );
    }

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let read = reader
        .by_ref()
        .take(MAX_PROMPT_BYTES as u64 + 1)
        .read_line(&mut line)
        .context("reading an askpass request")?;
    if read == 0 || read > MAX_PROMPT_BYTES {
        return deny(
            &mut writer,
            "bad_request",
            "an askpass request is one bounded JSON line",
        );
    }
    let request: Value = match serde_json::from_str(line.trim()) {
        Ok(value) => value,
        Err(_) => {
            return deny(
                &mut writer,
                "bad_request",
                "an askpass request is one JSON object per line",
            )
        }
    };
    let prompt = request.get("prompt").and_then(Value::as_str).unwrap_or("");

    let (kind, metadata) = match classify(prompt) {
        Prompt::Passphrase => (
            ChallengeKind::Passphrase,
            passphrase_metadata(
                context.key_label.as_deref().unwrap_or("the selected key"),
                context
                    .key_fingerprint
                    .as_deref()
                    .unwrap_or("fingerprint unknown"),
            ),
        ),
        Prompt::Password => {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt > super::MAX_PASSWORD_ATTEMPTS {
                return deny(
                    &mut writer,
                    "too_many_attempts",
                    "this connection has already used its password attempts",
                );
            }
            (
                ChallengeKind::Password,
                password_metadata(
                    &context.target,
                    &context.user,
                    context.port,
                    attempt,
                    super::MAX_PASSWORD_ATTEMPTS,
                ),
            )
        }
        Prompt::Unsupported => {
            // Deliberately not echoed back to the operator: the point of refusing is
            // that this text is not something to put in front of a person about to type
            // a password.
            return deny(
                &mut writer,
                "unsupported_prompt",
                "the SSH client asked something that is not a password or a key passphrase; \
                 keyboard-interactive and multi-factor prompts are not automated",
            );
        }
    };

    let answer = conversation.ask(ChallengeRequest { kind, metadata });
    match answer {
        Ok(Answer::Secret(secret)) => {
            served.fetch_add(1, Ordering::SeqCst);
            answer_with(&mut writer, &secret)
        }
        Ok(_) => deny(
            &mut writer,
            "invalid_response",
            "that challenge was answered with something other than a secret",
        ),
        Err(error) => {
            let reason = super::reason_of(&error).unwrap_or("authentication_cancelled");
            deny(
                &mut writer,
                reason,
                "the authentication request was not answered",
            )
        }
    }
}

fn answer_with(writer: &mut UnixStream, secret: &Zeroizing<String>) -> Result<()> {
    // Built by hand rather than through `serde_json::to_string` on a struct holding the
    // secret, so the only heap copy of it that exists here is this one buffer.
    let mut frame = Zeroizing::new(String::with_capacity(secret.len() + 32));
    frame.push_str("{\"ok\":true,\"response\":");
    frame.push_str(&Value::String(secret.to_string()).to_string());
    frame.push_str("}\n");
    writer
        .write_all(frame.as_bytes())
        .context("answering an askpass request")?;
    writer.flush().context("flushing an askpass answer")
}

fn deny(writer: &mut UnixStream, reason: &'static str, detail: &str) -> Result<()> {
    let frame = json!({"ok": false, "reason": reason, "detail": detail}).to_string();
    writer
        .write_all(frame.as_bytes())
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .context("refusing an askpass request")?;
    refuse(reason, detail.to_string())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd as _;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor is owned by `stream` for the duration of the call, and both
    // out-pointers name initialized local storage.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("reading the askpass peer's uid");
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd as _;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor is owned by `stream`, and the option buffer and its length
    // describe initialized local storage of exactly that size.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast::<libc::c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("reading the askpass peer's uid");
    }
    Ok(credentials.uid)
}

// ---------------------------------------------------------------- the client half

/// `ouro fleet askpass`: what OpenSSH executes.
///
/// Takes the prompt from argv (OpenSSH's own convention) or, failing that, from stdin,
/// and writes the answer on stdout with the trailing newline `ssh` expects. Anything
/// that goes wrong exits non-zero with a message on stderr and nothing on stdout, which
/// `ssh` reads as "no answer".
pub fn client_main(prompt: Option<String>) -> Result<()> {
    let socket = std::env::var(SOCKET_ENV).map_err(|_| {
        anyhow::anyhow!(
            "{SOCKET_ENV} is not set; `ouro fleet askpass` is started by an Ouroboros deployment, never by hand"
        )
    })?;
    let prompt = match prompt {
        Some(prompt) => prompt,
        None => {
            let mut text = String::new();
            std::io::stdin()
                .take(MAX_PROMPT_BYTES as u64)
                .read_to_string(&mut text)
                .context("reading the prompt from stdin")?;
            text
        }
    };
    let secret = request(Path::new(&socket), &prompt)?;
    let mut out = std::io::stdout().lock();
    out.write_all(secret.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .context("writing the answer")
}

/// One request/reply over the bridge socket.
pub fn request(socket: &Path, prompt: &str) -> Result<Zeroizing<String>> {
    let stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .context("bounding the askpass read")?;
    let mut writer = stream.try_clone().context("cloning the askpass socket")?;
    let frame = json!({ "prompt": prompt }).to_string();
    writer
        .write_all(frame.as_bytes())
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .context("sending the prompt")?;

    let mut reader = BufReader::new(stream);
    let mut line = Zeroizing::new(String::new());
    reader
        .by_ref()
        .take(MAX_PROMPT_BYTES as u64 + 1)
        .read_line(&mut line)
        .context("reading the answer")?;
    let reply: Value =
        serde_json::from_str(line.trim()).context("the askpass bridge answered malformed JSON")?;
    if reply.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = reply
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("refused");
        let detail = reply
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("the deployment refused this authentication prompt");
        anyhow::bail!("{}: {}", reason, sanitize_remote_text(detail, 200));
    }
    match reply.get("response").and_then(Value::as_str) {
        Some(response) => Ok(Zeroizing::new(response.to_string())),
        None => anyhow::bail!("the askpass bridge answered without a response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prompts OpenSSH actually composes, and the ones it must never get an answer
    /// to. The passphrase form was captured from OpenSSH 10.3 on this machine, including
    /// the truncated key path it prints.
    #[test]
    fn prompts_are_classified_and_anything_unrecognized_is_refused() {
        assert_eq!(
            classify("Enter passphrase for key '/Users/me/.ssh/id_ed25519': "),
            Prompt::Passphrase
        );
        assert_eq!(classify("Enter passphrase: "), Prompt::Passphrase);
        assert_eq!(classify("me@100.64.0.2's password: "), Prompt::Password);
        assert_eq!(classify("Password: "), Prompt::Password);

        for hostile in [
            "The authenticity of host '100.64.0.2' can't be established.",
            "ED25519 key fingerprint is SHA256:abc. Are you sure you want to continue connecting (yes/no)?",
            "Verification code: ",
            "Duo two-factor login. Enter a passcode:",
            "",
        ] {
            assert_eq!(
                classify(hostile),
                Prompt::Unsupported,
                "an unrecognized prompt is never answered: {hostile}"
            );
        }
    }

    /// A passphrase prompt must not be read as a password prompt, because the two are
    /// different questions with different metadata and different attempt budgets.
    #[test]
    fn passphrase_wins_over_the_password_substring_test() {
        assert_eq!(
            classify("Enter passphrase for key (password-protected): "),
            Prompt::Passphrase
        );
    }
}
