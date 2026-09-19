//! Answering the engine's questions from a terminal.
//!
//! The CLI's [`Conversation`]. A password or passphrase is read with the terminal's echo
//! turned off through `termios`, which is a dozen lines of `libc` and does not need a
//! crate; the buffer is a [`Zeroizing<String>`] from the moment it exists. Host trust is
//! a separate explicit yes/no that `--yes` cannot answer, exactly as the proposal
//! requires. A plan is printed in full before the question.
//!
//! Without a terminal — a cron job, a CI step, a service — every question is a refusal
//! with a stable reason rather than a prompt nobody will ever see. That is what makes
//! "noninteractive use requires pre-established host trust and usable noninteractive
//! authentication" a property of the code rather than a sentence in a document.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use super::challenge::Answer;
use super::challenge::ChallengeKind;
use super::plan::Plan;
use super::{refuse, ChallengeRequest, Conversation, Event};

/// The CLI's conversation: questions to the terminal, progress to stderr.
pub struct TerminalConversation {
    /// `--yes`. Accepts a resolved plan; never a host key, never a secret.
    pub assume_yes: bool,
    /// `--json`: progress is not printed, because stdout is a document.
    pub quiet: bool,
    cancelled: AtomicBool,
    /// First withdrawal reason per armed `ssh` child. Polled from the masked
    /// prompt so a dead connection does not leave the operator typing into a
    /// socket whose peer was killed.
    withdrawn: Mutex<HashMap<u64, &'static str>>,
}

impl TerminalConversation {
    pub fn new(assume_yes: bool, quiet: bool) -> Self {
        Self {
            assume_yes,
            quiet,
            cancelled: AtomicBool::new(false),
            withdrawn: Mutex::new(HashMap::new()),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn withdrawn_reason(&self, issuer: u64) -> Option<&'static str> {
        if issuer == 0 {
            return None;
        }
        self.withdrawn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&issuer)
            .copied()
    }

    fn read_secret(&self, prompt: &str, issuer: u64) -> Result<Zeroizing<String>> {
        read_secret_until(prompt, || self.withdrawn_reason(issuer))
    }
}

impl Conversation for TerminalConversation {
    fn ask(&self, request: ChallengeRequest) -> Result<Answer> {
        self.ask_from(0, request)
    }

    fn ask_from(&self, issuer: u64, request: ChallengeRequest) -> Result<Answer> {
        if let Some(reason) = self.withdrawn_reason(issuer) {
            return refuse(
                reason,
                "the SSH connection closed before this secret was entered",
            );
        }
        match request.kind {
            ChallengeKind::HostTrust => {
                let address = text(&request.metadata, "address");
                let port = request
                    .metadata
                    .get("port")
                    .and_then(Value::as_u64)
                    .unwrap_or(22);
                let algorithm = text(&request.metadata, "algorithm");
                let fingerprint = text(&request.metadata, "sha256_fingerprint");
                let user = text(&request.metadata, "user");
                if !interactive() {
                    return refuse(
                        "host_unknown",
                        format!(
                            "{address} port {port} is not a known host on this machine, and there is no terminal to confirm its key. Its {algorithm} key is {fingerprint}; verify it independently and record it before running this noninteractively"
                        ),
                    );
                }
                let mut out = std::io::stderr();
                writeln!(
                    out,
                    "\nThe host {address} port {port} (account {user}) is not yet trusted on this machine.\n  algorithm    {algorithm}\n  fingerprint  {fingerprint}\n\nVerify this fingerprint independently — on the machine itself, not over this connection."
                )?;
                if let Some(command) = super::challenge::host_key_verification_command(&algorithm) {
                    writeln!(out, "From the device's console or an already trusted SSH connection, run:\n  {command}\nCompare its SHA256 fingerprint with the one above.")?;
                }
                // `--yes` deliberately does not answer this. Host verification is the
                // one decision automation cannot make on the operator's behalf.
                let accepted = confirm("Trust this host and continue?")?;
                Ok(Answer::Trust(accepted))
            }
            ChallengeKind::Password => {
                let prompt = format!(
                    "Password for {}@{} (attempt {} of {}): ",
                    text(&request.metadata, "user"),
                    text(&request.metadata, "target"),
                    number(&request.metadata, "attempt"),
                    number(&request.metadata, "max_attempts"),
                );
                Ok(Answer::Secret(self.read_secret(&prompt, issuer)?))
            }
            ChallengeKind::Passphrase => {
                let prompt = format!(
                    "Passphrase for key {} ({}): ",
                    text(&request.metadata, "key_label"),
                    text(&request.metadata, "public_fingerprint"),
                );
                Ok(Answer::Secret(self.read_secret(&prompt, issuer)?))
            }
            ChallengeKind::Review => {
                if let Some(plan) = request.metadata.get("plan") {
                    if let Ok(plan) = serde_json::from_value::<Plan>(plan.clone()) {
                        let mut out = std::io::stderr();
                        writeln!(out, "\n{}", plan.render())?;
                    }
                }
                if self.assume_yes {
                    return Ok(Answer::Approval(true));
                }
                if !interactive() {
                    return refuse(
                        "review_declined",
                        "there is no terminal to review this plan on. Run it again with --yes to accept the resolved plan, or with --dry-run to print it",
                    );
                }
                if confirm("Apply this plan?")? {
                    Ok(Answer::Approval(true))
                } else {
                    refuse("review_declined", "the plan was not approved")
                }
            }
        }
    }

    fn withdraw(&self, issuer: u64, reason: &'static str) {
        if issuer == 0 {
            return;
        }
        let mut held = self
            .withdrawn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        held.entry(issuer).or_insert(reason);
    }

    fn notify(&self, event: Event) {
        if self.quiet {
            return;
        }
        let mut out = std::io::stderr();
        let _ = match event {
            Event::State(state) => writeln!(out, "· {}", state.as_str().replace('_', " ")),
            Event::Step {
                machine,
                step,
                outcome,
                detail,
            } => match detail {
                Some(detail) if !detail.is_empty() => {
                    writeln!(out, "  {machine}: {step} {outcome} — {detail}")
                }
                _ => writeln!(out, "  {machine}: {step} {outcome}"),
            },
            Event::Log(line) => writeln!(out, "  {line}"),
        };
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

fn text(metadata: &Value, field: &str) -> String {
    metadata
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn number(metadata: &Value, field: &str) -> String {
    metadata
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".into())
}

/// SIGINT and SIGTERM held back for the length of a masked prompt, and restored — and
/// therefore delivered — when this is dropped.
struct BlockedSignals {
    previous: libc::sigset_t,
    blocked: bool,
}

impl BlockedSignals {
    fn around_prompt() -> Self {
        // SAFETY: every pointer names initialized local storage, and `sigprocmask` on a
        // set this thread owns touches nothing else.
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            let mut previous: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut mask) != 0
                || libc::sigaddset(&mut mask, libc::SIGINT) != 0
                || libc::sigaddset(&mut mask, libc::SIGTERM) != 0
                || libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut previous) != 0
            {
                return Self {
                    previous,
                    blocked: false,
                };
            }
            Self {
                previous,
                blocked: true,
            }
        }
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        if self.blocked {
            // SAFETY: `previous` is the mask this thread had before, captured above.
            unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
            }
        }
    }
}

/// Whether there is a person on the other side of stdin.
pub fn interactive() -> bool {
    // SAFETY: `isatty` reads only the descriptor number it is given.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// A yes/no question on stderr, answered on stdin. Anything but an explicit yes is no.
fn confirm(question: &str) -> Result<bool> {
    let mut out = std::io::stderr();
    write!(out, "{question} [y/N] ")?;
    out.flush()?;
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("reading the answer")?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Read one line with the terminal's echo turned off.
///
/// Reads from `/dev/tty` when it can, so a piped stdin does not silently turn a masked
/// prompt into an unmasked read of whatever is on the pipe. Echo is restored on every
/// path, including the error one.
pub fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    read_secret_until(prompt, || None)
}

fn read_secret_until(
    prompt: &str,
    withdrawn: impl Fn() -> Option<&'static str>,
) -> Result<Zeroizing<String>> {
    use std::os::fd::AsRawFd as _;

    if !interactive() {
        return refuse(
            "authentication_required",
            "this operation needs a password or passphrase and there is no terminal to type it into. Use key or agent authentication for noninteractive runs",
        );
    }

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening the terminal to ask for a secret")?;
    let fd = tty.as_raw_fd();

    // SAFETY: `fd` is an open terminal for the whole of this function, and both termios
    // structures are initialized local storage.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(std::io::Error::last_os_error()).context("reading the terminal mode");
    }
    let mut quiet = original;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ECHONL;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(std::io::Error::last_os_error()).context("turning off terminal echo");
    }

    // Ctrl-C at a masked prompt used to leave the terminal with echo off: the default
    // SIGINT disposition kills this process before anything restores `termios`, and the
    // operator's shell inherits an invisible one. Blocking the two signals across the
    // read means they are *delivered* after the terminal is put back — the prompt is a
    // few hundred microseconds of work, and the signal is not lost.
    let _blocked = BlockedSignals::around_prompt();

    let mut out = std::io::stderr();
    let _ = write!(out, "{prompt}");
    let _ = out.flush();

    let mut secret = Zeroizing::new(String::new());
    let mut buffer = [0_u8; 256];
    let read = loop {
        if let Some(reason) = withdrawn() {
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &original) };
            return refuse(
                reason,
                "the SSH connection closed before this secret was entered",
            );
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` names this terminal for the duration of the call.
        let ready = unsafe { libc::poll(&mut pollfd, 1, 100) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &original) };
            return Err(error).context("waiting for the secret");
        }
        if ready == 0 {
            continue;
        }
        match std::io::Read::read(&mut &tty, &mut buffer) {
            Ok(0) => break Ok(0),
            Ok(n) => {
                secret.push_str(&String::from_utf8_lossy(&buffer[..n]));
                if secret.contains('\n') || secret.contains('\r') {
                    break Ok(secret.len());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(error),
        }
    };

    // Restored before the result is examined: an error path that leaves a terminal with
    // echo off is a terminal the operator has to repair by hand.
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &original) };
    read.context("reading the secret")?;

    while secret.ends_with('\n') || secret.ends_with('\r') {
        secret.pop();
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Without a terminal, every question is a refusal with a stable reason. Under
    /// `cargo test` stdin is not a tty, which is exactly the noninteractive case.
    #[test]
    fn without_a_terminal_every_question_is_a_named_refusal() {
        let conversation = TerminalConversation::new(false, true);

        let host = conversation
            .ask(ChallengeRequest {
                kind: ChallengeKind::HostTrust,
                metadata: json!({
                    "address": "100.64.0.2", "port": 22, "algorithm": "ssh-ed25519",
                    "sha256_fingerprint": "SHA256:abc", "user": "me"
                }),
            })
            .expect_err("no terminal to confirm a host key on");
        assert_eq!(super::super::reason_of(&host), Some("host_unknown"));
        assert!(
            format!("{host}").contains("SHA256:abc"),
            "the refusal still names the fingerprint to verify: {host}"
        );

        let password = conversation
            .ask(ChallengeRequest {
                kind: ChallengeKind::Password,
                metadata: json!({"user": "me", "target": "100.64.0.2", "attempt": 1, "max_attempts": 3}),
            })
            .expect_err("no terminal to type a password into");
        assert_eq!(
            super::super::reason_of(&password),
            Some("authentication_required")
        );

        let review = conversation
            .ask(ChallengeRequest {
                kind: ChallengeKind::Review,
                metadata: json!({}),
            })
            .expect_err("no terminal to review a plan on");
        assert_eq!(super::super::reason_of(&review), Some("review_declined"));
    }

    /// `--yes` accepts a resolved plan and still cannot accept an unknown host key.
    #[test]
    fn assume_yes_accepts_a_plan_and_never_a_host_key() {
        let conversation = TerminalConversation::new(true, true);

        match conversation
            .ask(ChallengeRequest {
                kind: ChallengeKind::Review,
                metadata: json!({}),
            })
            .expect("--yes approves the resolved plan")
        {
            Answer::Approval(true) => {}
            other => panic!("expected an approval, got {other:?}"),
        }

        let host = conversation
            .ask(ChallengeRequest {
                kind: ChallengeKind::HostTrust,
                metadata: json!({
                    "address": "100.64.0.2", "port": 22, "algorithm": "ssh-ed25519",
                    "sha256_fingerprint": "SHA256:abc", "user": "me"
                }),
            })
            .expect_err("--yes never accepts an unknown host key");
        assert_eq!(super::super::reason_of(&host), Some("host_unknown"));

        let password = conversation
            .ask(ChallengeRequest {
                kind: ChallengeKind::Password,
                metadata: json!({}),
            })
            .expect_err("--yes never answers a password prompt");
        assert_eq!(
            super::super::reason_of(&password),
            Some("authentication_required")
        );
    }

    /// Cancellation is observable at step boundaries.
    #[test]
    fn cancellation_is_visible_to_the_engine() {
        let conversation = TerminalConversation::new(false, true);
        assert!(!conversation.cancelled());
        conversation.cancel();
        assert!(conversation.cancelled());
    }

    /// A withdrawn issuer unblocks before the prompt is rendered, so a dead
    /// connection is not reported as a missing terminal.
    #[test]
    fn withdraw_unblocks_a_secret_prompt_by_name() {
        let conversation = TerminalConversation::new(false, true);
        conversation.withdraw(4, "connection_lost");
        conversation.withdraw(4, "challenge_expired");
        let error = conversation
            .ask_from(
                4,
                ChallengeRequest {
                    kind: ChallengeKind::Password,
                    metadata: json!({
                        "user": "me", "target": "100.64.0.2",
                        "attempt": 1, "max_attempts": 3
                    }),
                },
            )
            .expect_err("a withdrawn issuer does not wait for a secret");
        assert_eq!(
            super::super::reason_of(&error),
            Some("connection_lost"),
            "the first withdrawal reason wins: {error:#}"
        );
        let host = conversation
            .ask_from(
                4,
                ChallengeRequest {
                    kind: ChallengeKind::HostTrust,
                    metadata: json!({
                        "address": "100.64.0.2", "port": 22, "algorithm": "ssh-ed25519",
                        "sha256_fingerprint": "SHA256:abc", "user": "me"
                    }),
                },
            )
            .expect_err("withdrawn before the host-trust question");
        assert_eq!(super::super::reason_of(&host), Some("connection_lost"));
    }

    /// Progress goes to stderr and is suppressed in `--json` mode, so stdout stays a
    /// document.
    #[test]
    fn json_mode_prints_no_progress() {
        let quiet = TerminalConversation::new(false, true);
        quiet.notify(Event::State(super::super::OperationState::Deploying));
        quiet.notify(Event::Log("nothing should appear on stdout".into()));
        // Nothing to assert beyond "this does not panic and writes no stdout"; the
        // stdout contract is asserted end to end by the CLI tests.
    }
}
