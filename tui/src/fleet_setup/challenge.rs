//! Typed, expiring, single-use questions, and the registry that binds each answer to
//! the session that was asked (seam S4).
//!
//! The engine never renders a remote prompt as trusted UI. OpenSSH hands the askpass
//! bridge a sentence it composed; [`crate::fleet_setup::askpass`] classifies it into
//! exactly one of [`ChallengeKind::Password`] or [`ChallengeKind::Passphrase`] and
//! refuses everything else, and what reaches an operator is *this* module's metadata:
//! the target, the user, the port, the attempt number, the key label, the fingerprint.
//! None of that is a secret, which is what makes it safe to journal and to log.
//!
//! The registry exists because a challenge is an authorization boundary. An answer is
//! accepted once and before its expiry; anything else is one of two stable refusals.
//! §8 and §10 deleted the per-session binding: a challenge is answered by whoever is an
//! administrator on this runtime, and the `--frames` front end has exactly one peer on
//! its own stdin.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{refuse, CHALLENGE_LIFETIME};

fn withdrawn_detail(reason: &'static str) -> String {
    match reason {
        "connection_lost" => {
            "the SSH connection closed before this challenge was answered".to_string()
        }
        "challenge_expired" => format!(
            "nobody answered this challenge within {} seconds",
            CHALLENGE_LIFETIME.as_secs()
        ),
        other => format!("this challenge was withdrawn ({other})"),
    }
}

/// The four question types. Every one of them carries secret-free metadata only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Password,
    Passphrase,
    HostTrust,
    Review,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passphrase => "passphrase",
            Self::HostTrust => "host_trust",
            Self::Review => "review",
        }
    }
}

/// One question, as it appears on the wire and in a terminal.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub challenge: String,
    pub kind: ChallengeKind,
    /// RFC 3339 UTC. Present for a person and for a broker that shows a countdown; the
    /// registry enforces expiry from its own monotonic clock, not from this string.
    pub expires_at: String,
    /// Kind-specific, secret-free facts. See the module docs.
    pub metadata: Value,
}

impl Challenge {
    pub fn describe(&self) -> String {
        match self.kind {
            ChallengeKind::Password => format!(
                "password for {}@{} port {} (attempt {} of {})",
                text(&self.metadata, "user"),
                text(&self.metadata, "target"),
                number(&self.metadata, "port"),
                number(&self.metadata, "attempt"),
                number(&self.metadata, "max_attempts"),
            ),
            ChallengeKind::Passphrase => format!(
                "passphrase for key {} ({})",
                text(&self.metadata, "key_label"),
                text(&self.metadata, "public_fingerprint"),
            ),
            ChallengeKind::HostTrust => format!(
                "host key for {} port {} — {} {}",
                text(&self.metadata, "address"),
                number(&self.metadata, "port"),
                text(&self.metadata, "algorithm"),
                text(&self.metadata, "sha256_fingerprint"),
            ),
            ChallengeKind::Review => "the deployment plan".to_string(),
        }
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
        .unwrap_or_else(|| "unknown".to_string())
}

/// What an operator sent back.
///
/// [`Answer::Secret`] is the one variant that holds one, in a buffer that is zeroized
/// when it is dropped. Neither the worker nor the broker logs the frame it arrived in.
pub enum Answer {
    Secret(Zeroizing<String>),
    Trust(bool),
    /// A review, answered either way. A decline is an *answer*, not a refusal to
    /// answer: the operation stops with `review_declined` instead of sitting there
    /// until the challenge expires.
    Approval(bool),
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret(_) => formatter.write_str("Answer::Secret(<redacted>)"),
            Self::Trust(accept) => write!(formatter, "Answer::Trust({accept})"),
            Self::Approval(accept) => write!(formatter, "Answer::Approval({accept})"),
        }
    }
}

impl Answer {
    /// Decode the `response` object of a `respond` frame for a challenge of this kind.
    /// Refuses a shape that does not answer the question that was asked.
    pub fn decode(kind: ChallengeKind, response: &Value) -> Result<Self> {
        match kind {
            ChallengeKind::Password | ChallengeKind::Passphrase => {
                match response.get("secret").and_then(Value::as_str) {
                    Some(secret) => Ok(Self::Secret(Zeroizing::new(secret.to_string()))),
                    None => refuse(
                        "invalid_response",
                        "a password or passphrase challenge is answered with `secret`",
                    ),
                }
            }
            ChallengeKind::HostTrust => match response.get("accept").and_then(Value::as_bool) {
                Some(accept) => Ok(Self::Trust(accept)),
                None => refuse(
                    "invalid_response",
                    "a host trust challenge is answered with `accept`",
                ),
            },
            // §8: a review, like host trust, is answered with `accept`.
            ChallengeKind::Review => match response
                .get("accept")
                .or_else(|| response.get("approve"))
                .and_then(Value::as_bool)
            {
                Some(accept) => Ok(Self::Approval(accept)),
                None => refuse(
                    "invalid_response",
                    "a review challenge is answered with `accept`",
                ),
            },
        }
    }
}

/// One pending question, plus the answer when it arrives.
struct Pending {
    kind: ChallengeKind,
    deadline: Instant,
    answer: Option<Answer>,
    consumed: bool,
    /// The armed SSH child that asked, or 0 if this question came from the engine
    /// thread (host trust, review) and must not be withdrawn with a connection.
    issuer: u64,
    /// Set when the issuer is aborted. A late `respond` is refused with this reason
    /// rather than `unknown_challenge`, so the operator sees *why* the prompt vanished.
    withdrawn: Option<&'static str>,
}

/// The worker's pending questions.
///
/// Used from two threads: the engine thread blocks in [`Self::wait`], and the socket
/// thread delivers an answer in [`Self::respond`]. A `Condvar` rather than a channel
/// because a challenge can also expire while nobody is listening, and the waiter has to
/// wake up for that too.
#[derive(Default)]
pub struct Registry {
    state: Mutex<State>,
    signal: Condvar,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    /// First withdrawal reason per issuer. A later `invalidate_issuer` (the `Armed`
    /// guard dropping after a prompt expired) must not overwrite `challenge_expired`
    /// with `connection_lost`. Lives on this registry, not in a process-global table:
    /// moving the registry cannot leave a dangling pointer.
    withdrawn_issuers: HashMap<u64, &'static str>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a question as pending and return the wire form of it.
    ///
    /// `issuer` is the armed `ssh` child that asked, or `0` for an engine-thread
    /// question (host trust, review) that [`Self::invalidate_issuer`] must not touch.
    pub fn issue(&self, kind: ChallengeKind, metadata: Value, issuer: u64) -> Result<Challenge> {
        self.issue_for(kind, metadata, CHALLENGE_LIFETIME, issuer)
    }

    pub fn issue_for(
        &self,
        kind: ChallengeKind,
        metadata: Value,
        lifetime: Duration,
        issuer: u64,
    ) -> Result<Challenge> {
        let id = super::random_hex(16)?;
        let expires_at = super::utc_timestamp_at(std::time::SystemTime::now() + lifetime)?;
        let mut state = self.lock();
        if issuer != 0 {
            if let Some(reason) = state.withdrawn_issuers.get(&issuer).copied() {
                return refuse(reason, withdrawn_detail(reason));
            }
        }
        state.pending.insert(
            id.clone(),
            Pending {
                kind,
                deadline: Instant::now() + lifetime,
                answer: None,
                consumed: false,
                issuer,
                withdrawn: None,
            },
        );
        Ok(Challenge {
            challenge: id,
            kind,
            expires_at,
            metadata,
        })
    }

    /// Deliver an answer. The refusals here are the whole replay contract.
    pub fn respond(&self, challenge: &str, response: &Value) -> Result<()> {
        let mut state = self.lock();
        let Some(pending) = state.pending.get_mut(challenge) else {
            return refuse(
                "unknown_challenge",
                "this operation has no such pending challenge",
            );
        };
        if let Some(reason) = pending.withdrawn {
            return refuse(reason, withdrawn_detail(reason));
        }
        if pending.consumed || pending.answer.is_some() {
            return refuse(
                "challenge_consumed",
                "this challenge was already answered; ask for a new one",
            );
        }
        if Instant::now() >= pending.deadline {
            pending.consumed = true;
            self.signal.notify_all();
            return refuse(
                "challenge_expired",
                "this challenge expired; the step will ask again",
            );
        }
        let answer = Answer::decode(pending.kind, response)?;
        pending.answer = Some(answer);
        self.signal.notify_all();
        Ok(())
    }

    /// Block until the challenge is answered or expires. Consumes it either way: a
    /// second response to the same id is [`challenge_consumed`](Self::respond).
    pub fn wait(&self, challenge: &str) -> Result<Answer> {
        let mut state = self.lock();
        loop {
            let Some(pending) = state.pending.get_mut(challenge) else {
                return refuse("unknown_challenge", "the challenge is no longer pending");
            };
            if let Some(reason) = pending.withdrawn {
                pending.consumed = true;
                return refuse(reason, withdrawn_detail(reason));
            }
            if let Some(answer) = pending.answer.take() {
                pending.consumed = true;
                return Ok(answer);
            }
            let now = Instant::now();
            if now >= pending.deadline {
                pending.consumed = true;
                return refuse(
                    "challenge_expired",
                    "nobody answered this challenge before it expired",
                );
            }
            let remaining = pending.deadline - now;
            let (guard, _timeout) = self
                .signal
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
        }
    }

    /// Withdraw every unanswered challenge this issuer asked. The worker's UI sees
    /// them leave `pending`; a late `respond` is refused with `reason`.
    pub fn invalidate_issuer(&self, issuer: u64, reason: &'static str) {
        if issuer == 0 {
            return;
        }
        let mut state = self.lock();
        // First reason wins: recorded even if nothing is pending yet, so a
        // subsequent `issue` for this issuer is refused rather than parked.
        let reason = *state.withdrawn_issuers.entry(issuer).or_insert(reason);
        for pending in state.pending.values_mut() {
            if pending.issuer != issuer {
                continue;
            }
            if pending.withdrawn.is_some() {
                continue;
            }
            pending.answer = None;
            pending.consumed = true;
            pending.withdrawn = Some(reason);
            pending.deadline = Instant::now();
        }
        self.signal.notify_all();
    }

    /// Expire every challenge nobody has answered, and leave answered ones alone.
    ///
    /// What §8's stdin EOF means for a question still on the wire. The peer that closed
    /// the pipe was the only one who could ever answer it — there is exactly one, and
    /// there is no reattach — so the five minutes the deadline would otherwise run are
    /// five minutes of an operation parked on an answer that cannot arrive, holding its
    /// flock, refusing every `--operation ID` resume `operation_in_progress`.
    ///
    /// An answer that *has* arrived is untouched: a `respond` and an EOF in the same
    /// breath is the ordinary way a peer says its last word, and that word is kept.
    pub fn expire_unanswered(&self) {
        let mut state = self.lock();
        for pending in state.pending.values_mut() {
            if pending.consumed || pending.answer.is_some() {
                continue;
            }
            pending.deadline = Instant::now();
        }
        self.signal.notify_all();
    }

    /// Drop every pending challenge, so a disconnected session's unconsumed secret has
    /// nothing left to be delivered to. The proposal: "A lost authentication session
    /// invalidates its pending challenge and drops any unconsumed secret."
    pub fn invalidate_all(&self) {
        let mut state = self.lock();
        for pending in state.pending.values_mut() {
            pending.answer = None;
            pending.consumed = true;
            pending.deadline = Instant::now();
        }
        self.signal.notify_all();
    }

    /// The metadata a status reply shows for whatever is pending, without the answer.
    pub fn pending_kinds(&self) -> Vec<(String, ChallengeKind)> {
        let state = self.lock();
        let mut pending: Vec<(String, ChallengeKind)> = state
            .pending
            .iter()
            .filter(|(_, entry)| {
                !entry.consumed && entry.withdrawn.is_none() && entry.answer.is_none()
            })
            .map(|(id, entry)| (id.clone(), entry.kind))
            .collect();
        pending.sort_by(|left, right| left.0.cmp(&right.0));
        pending
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The metadata the proposal requires for each kind, built in one place so a surface
/// cannot invent a field or leave one out.
pub fn password_metadata(target: &str, user: &str, port: u16, attempt: u32, max: u32) -> Value {
    json!({
        "target": target,
        "user": user,
        "port": port,
        "attempt": attempt,
        "max_attempts": max,
    })
}

pub fn passphrase_metadata(key_label: &str, public_fingerprint: &str) -> Value {
    json!({
        "key_label": key_label,
        "public_fingerprint": public_fingerprint,
    })
}

pub fn host_trust_metadata(
    address: &str,
    port: u16,
    algorithm: &str,
    sha256_fingerprint: &str,
    user: &str,
) -> Value {
    json!({
        "address": address,
        "port": port,
        "algorithm": algorithm,
        "sha256_fingerprint": sha256_fingerprint,
        "user": user,
        "verification_command": host_key_verification_command(algorithm),
    })
}

/// Key filenames come from an allowlist, never interpolated remote metadata.
pub fn host_key_verification_command(algorithm: &str) -> Option<&'static str> {
    match algorithm {
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => {
            Some("ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub -E sha256")
        }
        "ssh-ed25519" => Some("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256"),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            Some("ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub -E sha256")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kind is answered by the shape that answers *that* question, and by no other.
    ///
    /// The one that matters is `accept` against a secret: §8 gives `respond` two shapes
    /// and a peer that sends the wrong one is a peer this process must not interpret.
    /// An `{"accept": true}` treated as an empty password would hand `ssh` a blank
    /// secret and burn one of its three attempts against the target's account; an
    /// `{"secret": "..."}` treated as approval would accept a plan nobody read.
    #[test]
    fn a_challenge_is_answered_by_the_shape_that_answers_it() {
        for kind in [ChallengeKind::Password, ChallengeKind::Passphrase] {
            let refused = Answer::decode(kind, &json!({"accept": true}))
                .expect_err("`accept` never answers a secret");
            assert_eq!(super::super::reason_of(&refused), Some("invalid_response"));
            // Not even `false`, and not an empty secret either.
            assert!(Answer::decode(kind, &json!({"accept": false})).is_err());
            assert!(Answer::decode(kind, &json!({"approve": true})).is_err());
            assert!(Answer::decode(kind, &json!({})).is_err());
            assert!(matches!(
                Answer::decode(kind, &json!({"secret": "s"})).expect("a secret"),
                Answer::Secret(_)
            ));
        }

        for kind in [ChallengeKind::HostTrust, ChallengeKind::Review] {
            let refused = Answer::decode(kind, &json!({"secret": "yes"}))
                .expect_err("a secret never answers a decision");
            assert_eq!(super::super::reason_of(&refused), Some("invalid_response"));
            assert!(Answer::decode(kind, &json!({"accept": "true"})).is_err());
        }
        assert!(matches!(
            Answer::decode(ChallengeKind::HostTrust, &json!({"accept": false}))
                .expect("a decision"),
            Answer::Trust(false)
        ));
        assert!(matches!(
            Answer::decode(ChallengeKind::Review, &json!({"accept": true})).expect("a decision"),
            Answer::Approval(true)
        ));
    }

    /// §8's stdin EOF, at the registry: what nobody answered expires now, and what
    /// somebody did answer is still delivered.
    #[test]
    fn expiring_the_unanswered_leaves_an_answer_that_already_arrived() {
        let registry = Registry::new();
        let answered = registry
            .issue(ChallengeKind::Review, json!({}), 0)
            .expect("a challenge");
        let unanswered = registry
            .issue(ChallengeKind::HostTrust, json!({}), 0)
            .expect("a challenge");
        registry
            .respond(&answered.challenge, &json!({"accept": true}))
            .expect("an answer that arrived before the pipe closed");

        registry.expire_unanswered();

        assert!(matches!(
            registry.wait(&answered.challenge).expect("the kept answer"),
            Answer::Approval(true)
        ));
        let expired = registry
            .wait(&unanswered.challenge)
            .expect_err("nothing can answer this one now");
        assert_eq!(
            super::super::reason_of(&expired),
            Some("challenge_expired"),
            "{expired:#}"
        );
    }

    /// An answer is accepted once, and a second one is refused rather than applied.
    #[test]
    fn a_challenge_is_single_use() {
        let registry = Registry::new();
        let challenge = registry
            .issue(ChallengeKind::HostTrust, json!({}), 0)
            .expect("a challenge");
        registry
            .respond(&challenge.challenge, &json!({"accept": true}))
            .expect("the first answer");
        let error = registry
            .respond(&challenge.challenge, &json!({"accept": true}))
            .expect_err("a replayed answer");
        assert_eq!(super::super::reason_of(&error), Some("challenge_consumed"));
        assert!(matches!(
            registry.wait(&challenge.challenge).expect("the answer"),
            Answer::Trust(true)
        ));
    }

    /// A challenge nobody asked for is not a challenge.
    #[test]
    fn an_unknown_challenge_is_refused() {
        let registry = Registry::new();
        let error = registry
            .respond("deadbeef", &json!({"accept": true}))
            .expect_err("an unknown id");
        assert_eq!(super::super::reason_of(&error), Some("unknown_challenge"));
    }

    /// §8: a review is answered with `accept`, like host trust.
    #[test]
    fn a_review_is_answered_with_accept() {
        assert!(matches!(
            Answer::decode(ChallengeKind::Review, &json!({"accept": true})).expect("approval"),
            Answer::Approval(true)
        ));
        // A decline is delivered, so the operation stops now rather than at the expiry.
        assert!(matches!(
            Answer::decode(ChallengeKind::Review, &json!({"accept": false})).expect("a decline"),
            Answer::Approval(false)
        ));
        let malformed =
            Answer::decode(ChallengeKind::Review, &json!({})).expect_err("no answer at all");
        assert_eq!(
            super::super::reason_of(&malformed),
            Some("invalid_response")
        );
    }

    /// A secret never reaches a `Debug` rendering.
    #[test]
    fn a_secret_answer_prints_as_redacted() {
        let answer = Answer::decode(ChallengeKind::Password, &json!({"secret": "hunter2"}))
            .expect("a password answer");
        assert_eq!(format!("{answer:?}"), "Answer::Secret(<redacted>)");
    }

    /// An expired challenge wakes its waiter rather than blocking it for ever.
    #[test]
    fn an_unanswered_challenge_expires() {
        let registry = Registry::new();
        let challenge = registry
            .issue_for(
                ChallengeKind::Password,
                json!({}),
                Duration::from_millis(10),
                0,
            )
            .expect("a challenge");
        let error = registry.wait(&challenge.challenge).expect_err("an expiry");
        assert_eq!(super::super::reason_of(&error), Some("challenge_expired"));
    }
}
