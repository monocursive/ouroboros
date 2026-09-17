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

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use super::challenge::{Answer, ChallengeKind};
use super::plan::Plan;
use super::{refuse, ChallengeRequest, Conversation, Event};

/// The CLI's conversation: questions to the terminal, progress to stderr.
pub struct TerminalConversation {
    /// `--yes`. Accepts a resolved plan; never a host key, never a secret.
    pub assume_yes: bool,
    /// `--json`: progress is not printed, because stdout is a document.
    pub quiet: bool,
    cancelled: AtomicBool,
}

impl TerminalConversation {
    pub fn new(assume_yes: bool, quiet: bool) -> Self {
        Self {
            assume_yes,
            quiet,
            cancelled: AtomicBool::new(false),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl Conversation for TerminalConversation {
    fn ask(&self, request: ChallengeRequest) -> Result<Answer> {
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
                Ok(Answer::Secret(read_secret(&prompt)?))
            }
            ChallengeKind::Passphrase => {
                let prompt = format!(
                    "Passphrase for key {} ({}): ",
                    text(&request.metadata, "key_label"),
                    text(&request.metadata, "public_fingerprint"),
                );
                Ok(Answer::Secret(read_secret(&prompt)?))
            }
            ChallengeKind::Review => {
                let digest = text(&request.metadata, "plan_digest");
                if let Some(plan) = request.metadata.get("plan") {
                    if let Ok(plan) = serde_json::from_value::<Plan>(plan.clone()) {
                        let mut out = std::io::stderr();
                        writeln!(out, "\n{}", plan.render())?;
                    }
                }
                if self.assume_yes {
                    return Ok(Answer::Approval {
                        plan_digest: digest,
                    });
                }
                if !interactive() {
                    return refuse(
                        "review_declined",
                        "there is no terminal to review this plan on. Run it again with --yes to accept the resolved plan, or with --dry-run to print it",
                    );
                }
                if confirm("Apply this plan?")? {
                    Ok(Answer::Approval {
                        plan_digest: digest,
                    })
                } else {
                    refuse("review_declined", "the plan was not approved")
                }
            }
        }
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

    let mut out = std::io::stderr();
    let _ = write!(out, "{prompt}");
    let _ = out.flush();

    let mut secret = Zeroizing::new(String::new());
    let read = std::io::BufReader::new(&tty).read_line(&mut secret);

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
                metadata: json!({"plan_digest": "abc"}),
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
                metadata: json!({"plan_digest": "d1"}),
            })
            .expect("--yes approves the resolved plan")
        {
            Answer::Approval { plan_digest } => assert_eq!(plan_digest, "d1"),
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
