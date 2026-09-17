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
//! accepted once, before its expiry, and only from the subject and session that were
//! attached when it was issued; anything else is one of three stable refusals that the
//! broker turns into a JSON-RPC error.

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

/// Who a challenge was issued to: the authenticated subject and its client session.
/// Seam S4 binds an answer to both, so a second browser tab cannot answer the first
/// one's password prompt.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Binding {
    pub subject: String,
    pub session: String,
}

/// One question, as it appears on the wire and in a terminal.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Challenge {
    pub challenge: String,
    pub kind: ChallengeKind,
    /// RFC 3339 UTC. Present for a person and for a broker that shows a countdown; the
    /// registry enforces expiry from its own monotonic clock, not from this string.
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_to: Option<Binding>,
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
    Approval { plan_digest: String },
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret(_) => formatter.write_str("Answer::Secret(<redacted>)"),
            Self::Trust(accept) => write!(formatter, "Answer::Trust({accept})"),
            Self::Approval { plan_digest } => {
                write!(formatter, "Answer::Approval({plan_digest})")
            }
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
            ChallengeKind::Review => {
                let approve = response
                    .get("approve")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !approve {
                    return refuse("review_declined", "the plan was not approved");
                }
                match response.get("plan_digest").and_then(Value::as_str) {
                    Some(digest) => Ok(Self::Approval {
                        plan_digest: digest.to_string(),
                    }),
                    None => refuse(
                        "invalid_response",
                        "an approval carries the digest of the plan that was reviewed",
                    ),
                }
            }
        }
    }
}

/// One pending question, plus the answer when it arrives.
struct Pending {
    kind: ChallengeKind,
    bound_to: Option<Binding>,
    deadline: Instant,
    answer: Option<Answer>,
    consumed: bool,
    /// The armed SSH child that asked, or 0 if this question came from the engine
    /// thread (host trust, review) and must not be withdrawn with a connection.
    issuer: u64,
    /// Set when the issuer is aborted. A late `respond` is refused with this reason
    /// rather than `unknown_challenge`, so the operator sees *why* the prompt vanished.
    withdrawn: Option<&'static str>,
    /// Kept so a client that attaches *after* the question was asked can be shown it.
    /// The metadata is secret-free by construction, which is what makes replay safe.
    expires_at: String,
    metadata: Value,
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
    pub fn issue(
        &self,
        kind: ChallengeKind,
        metadata: Value,
        bound_to: Option<Binding>,
        issuer: u64,
    ) -> Result<Challenge> {
        self.issue_for(kind, metadata, bound_to, CHALLENGE_LIFETIME, issuer)
    }

    pub fn issue_for(
        &self,
        kind: ChallengeKind,
        metadata: Value,
        bound_to: Option<Binding>,
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
                bound_to: bound_to.clone(),
                deadline: Instant::now() + lifetime,
                answer: None,
                consumed: false,
                issuer,
                withdrawn: None,
                expires_at: expires_at.clone(),
                metadata: metadata.clone(),
            },
        );
        Ok(Challenge {
            challenge: id,
            kind,
            expires_at,
            bound_to,
            metadata,
        })
    }

    /// Bind every still-unanswered question that has no owner to this client, and hand
    /// them back so they can be put in front of it.
    ///
    /// A worker starts before anything attaches to it — that is the point of a detached
    /// worker — so the first question can be asked while nobody is listening. Without
    /// this, the operation would sit waiting for an answer to a question no surface ever
    /// showed. A challenge that already has an owner is untouched: binding is
    /// first-claim, and it is permanent.
    pub fn claim_unbound(&self, binding: &Binding) -> Vec<Challenge> {
        let mut claimed = Vec::new();
        let mut state = self.lock();
        let now = Instant::now();
        for (id, pending) in state.pending.iter_mut() {
            if pending.consumed
                || pending.withdrawn.is_some()
                || pending.answer.is_some()
                || now >= pending.deadline
                || pending.bound_to.is_some()
            {
                continue;
            }
            pending.bound_to = Some(binding.clone());
            claimed.push(Challenge {
                challenge: id.clone(),
                kind: pending.kind,
                expires_at: pending.expires_at.clone(),
                bound_to: pending.bound_to.clone(),
                metadata: pending.metadata.clone(),
            });
        }
        claimed.sort_by(|left, right| left.challenge.cmp(&right.challenge));
        claimed
    }

    /// Deliver an answer. The three refusals here are the whole of seam S4's
    /// replay/binding contract.
    pub fn respond(&self, challenge: &str, from: Option<&Binding>, response: &Value) -> Result<()> {
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
        if pending.bound_to.as_ref() != from {
            return refuse(
                "challenge_not_bound",
                "this challenge was issued to another session; reconnect and answer the one issued to you",
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
    })
}

#[cfg(test)]
mod tests {
    use super::super::{ChallengeRequest, Conversation, Event};
    use super::*;
    use std::sync::Arc;

    fn binding(session: &str) -> Binding {
        Binding {
            subject: "operator".into(),
            session: session.into(),
        }
    }

    /// The registry's whole job: answered once, by the right session, before expiry.
    #[test]
    fn a_challenge_is_answered_once_by_the_session_it_was_issued_to() {
        let registry = Registry::new();
        let issued = registry
            .issue(
                ChallengeKind::Password,
                password_metadata("100.64.0.2", "me", 22, 1, 3),
                Some(binding("live")),
                0,
            )
            .expect("an issued challenge");

        // Another session's answer is refused, and does not consume the challenge.
        let wrong = registry
            .respond(
                &issued.challenge,
                Some(&binding("other-tab")),
                &json!({"secret": "s3cret"}),
            )
            .expect_err("a foreign session cannot answer");
        assert_eq!(super::super::reason_of(&wrong), Some("challenge_not_bound"));

        // So is an unauthenticated one.
        let anonymous = registry
            .respond(&issued.challenge, None, &json!({"secret": "s3cret"}))
            .expect_err("an unbound responder cannot answer a bound challenge");
        assert_eq!(
            super::super::reason_of(&anonymous),
            Some("challenge_not_bound")
        );

        registry
            .respond(
                &issued.challenge,
                Some(&binding("live")),
                &json!({"secret": "s3cret"}),
            )
            .expect("the bound session answers");

        let replay = registry
            .respond(
                &issued.challenge,
                Some(&binding("live")),
                &json!({"secret": "s3cret"}),
            )
            .expect_err("a second answer is a replay");
        assert_eq!(super::super::reason_of(&replay), Some("challenge_consumed"));

        match registry.wait(&issued.challenge).expect("the answer") {
            Answer::Secret(secret) => assert_eq!(secret.as_str(), "s3cret"),
            other => panic!("a password challenge yields a secret, got {other:?}"),
        }
    }

    /// An abandoned challenge expires rather than holding the engine forever.
    #[test]
    fn an_unanswered_challenge_expires_and_a_late_answer_is_named_as_late() {
        let registry = Registry::new();
        let issued = registry
            .issue_for(
                ChallengeKind::HostTrust,
                host_trust_metadata("100.64.0.2", 22, "ssh-ed25519", "SHA256:abc", "me"),
                None,
                Duration::from_millis(40),
                0,
            )
            .expect("an issued challenge");

        let waited = registry
            .wait(&issued.challenge)
            .expect_err("nobody answered it");
        assert_eq!(super::super::reason_of(&waited), Some("challenge_expired"));

        let late = registry
            .respond(&issued.challenge, None, &json!({"accept": true}))
            .expect_err("an answer after expiry");
        assert!(
            matches!(
                super::super::reason_of(&late),
                Some("challenge_expired" | "challenge_consumed")
            ),
            "a late answer is refused by name: {late:#}"
        );
    }

    /// The waiter really blocks and really wakes: the answer arrives from another
    /// thread while the engine thread is parked on the condvar.
    #[test]
    fn the_waiter_wakes_when_another_thread_answers() {
        let registry = Arc::new(Registry::new());
        let issued = registry
            .issue(ChallengeKind::HostTrust, json!({}), None, 0)
            .expect("an issued challenge");

        let responder = Arc::clone(&registry);
        let id = issued.challenge.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            responder
                .respond(&id, None, &json!({"accept": true}))
                .expect("an answer");
        });

        match registry.wait(&issued.challenge).expect("the answer") {
            Answer::Trust(accept) => assert!(accept),
            other => panic!("a host trust challenge yields a decision, got {other:?}"),
        }
        thread.join().expect("the responder thread");
    }

    /// A response has to answer the question that was asked.
    #[test]
    fn a_response_of_the_wrong_shape_is_refused_by_name() {
        assert_eq!(
            super::super::reason_of(
                &Answer::decode(ChallengeKind::Password, &json!({"accept": true}))
                    .expect_err("a trust decision does not answer a password prompt")
            ),
            Some("invalid_response")
        );
        assert_eq!(
            super::super::reason_of(
                &Answer::decode(ChallengeKind::Review, &json!({"approve": false}))
                    .expect_err("a declined review")
            ),
            Some("review_declined")
        );
        assert_eq!(
            super::super::reason_of(
                &Answer::decode(ChallengeKind::Review, &json!({"approve": true}))
                    .expect_err("an approval without a digest approves nothing specific")
            ),
            Some("invalid_response")
        );
    }

    /// A lost session drops every unconsumed secret rather than holding it for whoever
    /// reconnects next.
    #[test]
    fn invalidating_a_session_drops_its_unconsumed_answer() {
        let registry = Registry::new();
        let issued = registry
            .issue(ChallengeKind::Password, json!({}), Some(binding("live")), 0)
            .expect("an issued challenge");
        registry
            .respond(
                &issued.challenge,
                Some(&binding("live")),
                &json!({"secret": "s3cret"}),
            )
            .expect("an answer");

        registry.invalidate_all();

        let after = registry
            .wait(&issued.challenge)
            .expect_err("the dropped secret is not delivered");
        assert_eq!(super::super::reason_of(&after), Some("challenge_expired"));
        assert!(registry.pending_kinds().is_empty());
    }

    /// A question asked before anyone was listening is claimed by the first client to
    /// attach, and is that client's from then on.
    #[test]
    fn an_unowned_question_is_claimed_once_by_the_first_client_to_attach() {
        let registry = Registry::new();
        let issued = registry
            .issue(ChallengeKind::Review, json!({"plan_digest": "d1"}), None, 0)
            .expect("an issued challenge");

        let claimed = registry.claim_unbound(&binding("first"));
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].challenge, issued.challenge);
        assert_eq!(
            claimed[0].metadata,
            json!({"plan_digest": "d1"}),
            "the question is replayed in full, and it carries no secret"
        );

        assert!(
            registry.claim_unbound(&binding("second")).is_empty(),
            "a claimed question is not claimable again"
        );
        let stolen = registry
            .respond(
                &issued.challenge,
                Some(&binding("second")),
                &json!({"approve": true, "plan_digest": "d1"}),
            )
            .expect_err("a claimed challenge belongs to its claimant");
        assert_eq!(
            super::super::reason_of(&stolen),
            Some("challenge_not_bound")
        );

        registry
            .respond(
                &issued.challenge,
                Some(&binding("first")),
                &json!({"approve": true, "plan_digest": "d1"}),
            )
            .expect("the claimant answers");
    }

    /// A secret never reaches a debug rendering, which is what an error chain prints.
    #[test]
    fn a_secret_answer_does_not_render_itself() {
        let answer = Answer::Secret(Zeroizing::new("hunter2-unique-probe".to_string()));
        assert_eq!(format!("{answer:?}"), "Answer::Secret(<redacted>)");
    }

    /// Aborting an issuer unblocks its waiter immediately and refuses a late answer
    /// with that reason, without touching a question a different issuer asked.
    #[test]
    fn aborting_an_issuer_unblocks_its_waiter_and_refuses_a_late_answer() {
        let registry = Arc::new(Registry::new());
        let issuer = 7;
        let issued = registry
            .issue(ChallengeKind::Password, json!({}), None, issuer)
            .expect("an issued challenge");
        let other = registry
            .issue(ChallengeKind::Review, json!({}), None, 0)
            .expect("an engine-thread question");

        let waiter = Arc::clone(&registry);
        let id = issued.challenge.clone();
        let thread = std::thread::spawn(move || waiter.wait(&id));

        std::thread::sleep(Duration::from_millis(20));
        registry.invalidate_issuer(issuer, "connection_lost");
        registry.invalidate_issuer(issuer, "challenge_expired");

        let waited = thread.join().expect("the waiter thread");
        assert_eq!(
            super::super::reason_of(&waited.expect_err("the prompt was withdrawn")),
            Some("connection_lost"),
            "the first withdrawal reason wins"
        );

        let late = registry
            .respond(&issued.challenge, None, &json!({"secret": "too-late"}))
            .expect_err("a late answer is refused by name");
        assert_eq!(
            super::super::reason_of(&late),
            Some("connection_lost"),
            "a late answer names the withdrawal, not a generic unknown: {late:#}"
        );
        assert!(
            registry
                .respond(
                    &other.challenge,
                    None,
                    &json!({"approve": true, "plan_digest": "d"})
                )
                .is_ok(),
            "an engine-thread question is not withdrawn with the SSH child"
        );
        assert!(registry.pending_kinds().is_empty());
    }

    /// A registry issued on the stack and then moved into an `Arc` is still the
    /// conversation's registry. The old process-global pointer table would have
    /// aborted the stale address.
    #[test]
    fn withdrawing_through_a_conversation_survives_moving_the_registry_into_an_arc() {
        struct ViaConversation {
            registry: Arc<Registry>,
        }
        impl Conversation for ViaConversation {
            fn ask(&self, request: ChallengeRequest) -> anyhow::Result<Answer> {
                self.ask_from(0, request)
            }
            fn ask_from(&self, issuer: u64, request: ChallengeRequest) -> anyhow::Result<Answer> {
                let issued = self
                    .registry
                    .issue(request.kind, request.metadata, None, issuer)?;
                self.registry.wait(&issued.challenge)
            }
            fn withdraw(&self, issuer: u64, reason: &'static str) {
                self.registry.invalidate_issuer(issuer, reason);
            }
            fn notify(&self, _event: Event) {}
        }

        let registry = Registry::new();
        let issued = registry
            .issue(ChallengeKind::Password, json!({}), None, 11)
            .expect("an issued challenge");
        let registry = Arc::new(registry);
        let conversation = ViaConversation {
            registry: Arc::clone(&registry),
        };

        let waiter = Arc::clone(&registry);
        let id = issued.challenge.clone();
        let thread = std::thread::spawn(move || waiter.wait(&id));
        std::thread::sleep(Duration::from_millis(20));
        conversation.withdraw(11, "connection_lost");

        let waited = thread.join().expect("the waiter thread");
        assert_eq!(
            super::super::reason_of(&waited.expect_err("the prompt was withdrawn")),
            Some("connection_lost")
        );
    }
}
