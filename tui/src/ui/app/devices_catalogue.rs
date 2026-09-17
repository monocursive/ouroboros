//! The one table of snake_case codes this view turns into sentences.
//!
//! Broker refusals, deploy blockers and operation states used to live as four `match`
//! arms that named the same facts in different words. A new code then had four places to
//! miss. This module is the catalogue; [`super`] only formats around it. The Elixir
//! surface has its own copy on purpose: the two clients do not share a crate, and a
//! sentence that drifted would be a review finding rather than a silent coupling.

/// Broker / worker reason codes this client has words for. The drift test in
/// `tests/devices_flow.rs` walks the fixtures against this list so a new code on the
/// wire cannot land as an identifier.
pub const REASON_CODES: &[&str] = &[
    "plan_changed",
    "operation_in_progress",
    "start_in_flight",
    "challenge_not_bound",
    "challenge_consumed",
    "challenge_expired",
    "challenge_kind_mismatch",
    "host_key_changed",
    "already_attached",
    "operation_finished",
    "operation_state_unknown",
    "operation_not_yours",
    "deploy_blocked",
    "no_worker",
    "worker_attaching",
    "worker_unavailable",
    "worker_unreachable",
    "worker_timeout",
    "no_review_pending",
    "session_unbound",
    "unknown_operation",
    "devices_busy",
    "no_data_dir",
    "ouro_path_unknown",
    "journal_unreadable",
];

/// `capabilities.reasons` / `deploy_blocked` blockers. Same codes can appear as broker
/// reasons with a different sentence: a host that cannot deploy is not the same statement
/// as a verb that was refused for that reason after the fact.
pub const BLOCKER_CODES: &[&str] = &[
    "no_ca_key",
    "ouro_path_unknown",
    "no_data_dir",
    "cleartext_web_bind",
];

/// `fleet.deployment.status`'s `state` values, including the client-only `attaching`.
pub const OPERATION_STATES: &[&str] = &[
    "spawning",
    "attaching",
    "inspecting",
    "awaiting_host_trust",
    "awaiting_auth",
    "awaiting_review",
    "deploying",
    "restarting_host",
    "checking_readiness",
    "completed",
    "interrupted",
    "failed",
    "cancelled",
];

/// The broker's stable reason codes, as sentences. An unrecognised code is printed as
/// itself: a runtime that grew a refusal this build predates must still be legible.
pub fn reason_sentence(reason: &str) -> String {
    match reason {
        "plan_changed" => "the plan changed after it was reviewed, so it was not applied. \
                           Read the new one and approve that."
            .into(),
        "operation_in_progress" => {
            "this operation is already running under a different approval.".into()
        }
        "start_in_flight" => "an approval for this operation is still in flight.".into(),
        "challenge_not_bound" => "this question was asked of a different session, so this \
                                  one cannot answer it."
            .into(),
        "challenge_consumed" => "this question has already been answered once. A challenge \
                                 is consumed when it is sent, so this is not a second guess."
            .into(),
        "challenge_expired" => "this question expired before it was answered.".into(),
        "challenge_kind_mismatch" => "this answer is the wrong shape for the question.".into(),
        "host_key_changed" => "this host's key has changed. That blocks the deployment and \
                               needs a separate, verified repair; it is never accepted here."
            .into(),
        "already_attached" => "a worker is already attached to this operation.".into(),
        "operation_finished" => "this operation has already finished.".into(),
        "operation_state_unknown" => "this operation's record cannot be read, so resuming \
                                      it would be starting a second worker against a \
                                      machine whose state nobody knows."
            .into(),
        "operation_not_yours" => "this operation belongs to another identity, and taking \
                                  it over is a decision to make out loud."
            .into(),
        // Named here too so the code never reaches the fallback; the sentence a caller
        // actually draws comes from the blocker list, which has the names.
        "deploy_blocked" => "this host cannot deploy right now.".into(),
        "no_worker" => "no worker is attached to this operation; read its status, then \
                        continue it."
            .into(),
        "worker_attaching" => "this operation's worker is still being connected to.".into(),
        "worker_unavailable" | "worker_unreachable" => {
            "the deployment worker is no longer reachable from this runtime.".into()
        }
        "worker_timeout" => "the deployment worker did not answer in time.".into(),
        "no_review_pending" => "this operation has no plan waiting for approval.".into(),
        "session_unbound" => "this connection carries no client session, and a deployment \
                              question is answered by the session it was issued to."
            .into(),
        "unknown_operation" => "this runtime has no operation with that id.".into(),
        "devices_busy" => "this runtime is already running as many device inventories as \
                           it allows. Try again in a moment."
            .into(),
        "no_data_dir" => "this runtime serves no durable data directory, so it holds no \
                          deployments."
            .into(),
        "ouro_path_unknown" => "this runtime does not know where its own ouro executable \
                                is, so it cannot run a deployment."
            .into(),
        "journal_unreadable" => "this operation's record on the deployment host could not \
                                 be read."
            .into(),
        // A code this build predates, made readable rather than printed as an identifier.
        // The words are the code's own — nothing is invented — so an operator can still
        // quote it, and a screen full of `quantum_decoherence_detected` is not what a
        // person is asked to act on.
        other => format!("the runtime named the reason {}.", other.replace('_', " ")),
    }
}

/// One blocker code, in words.
///
/// The single vocabulary for both places the codes arrive: `fleet.devices`'s
/// `capabilities.reasons`, which says in advance what this host cannot do, and a
/// `deploy_blocked` refusal, which says the same thing at the moment something is
/// attempted.
pub fn blocker_sentence(reason: &str) -> String {
    match reason {
        "no_ca_key" => "This machine does not hold the fleet's certificate authority key, \
                        so it can describe the fleet but cannot admit a member. Open \
                        Devices on the machine that does."
            .into(),
        "ouro_path_unknown" => "This runtime cannot say where its own ouro executable is, \
                                so it has nothing to hand a deployment worker."
            .into(),
        "no_data_dir" => "This runtime serves no durable data directory, so a deployment \
                          would have nowhere to keep its journal."
            .into(),
        "cleartext_web_bind" => "This runtime publishes its web endpoint on a non-loopback \
                                 address with no TLS, so credential entry is refused on \
                                 this deployment host."
            .into(),
        other => format!(
            "This runtime reports the blocker {}.",
            other.replace('_', " ")
        ),
    }
}

/// The deployment snapshot's state, as a person reads it. The codes stay in the data.
pub fn operation_state(state: &str) -> String {
    match state {
        "spawning" => "starting the deployment worker".into(),
        "attaching" => "connecting to the deployment worker".into(),
        "inspecting" => "inspecting the target".into(),
        "awaiting_host_trust" => "waiting for you to verify the host key".into(),
        "awaiting_auth" => "waiting for your credential".into(),
        "awaiting_review" => "waiting for you to review the plan".into(),
        "deploying" => "deploying".into(),
        "restarting_host" => "restarting this runtime".into(),
        "checking_readiness" => "checking readiness".into(),
        "completed" => "completed".into(),
        "interrupted" => "interrupted".into(),
        "failed" => "failed".into(),
        "cancelled" => "cancelled".into(),
        "" => "state not reported".into(),
        other => format!("{other} (a state this client does not know)"),
    }
}

/// Whether `code` has a dedicated arm rather than the unknown-code fallback.
pub fn reason_known(code: &str) -> bool {
    REASON_CODES.contains(&code)
}

/// Whether `code` has a dedicated blocker sentence.
pub fn blocker_known(code: &str) -> bool {
    BLOCKER_CODES.contains(&code)
}

/// Whether `code` has a dedicated operation-state sentence.
pub fn operation_state_known(code: &str) -> bool {
    OPERATION_STATES.contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalogued_code_has_a_dedicated_sentence() {
        for code in REASON_CODES {
            let sentence = reason_sentence(code);
            assert!(
                !sentence.contains(code),
                "{code} printed as its identifier: {sentence}"
            );
            assert!(sentence.len() > 12, "{code} has no explanation");
        }

        for code in BLOCKER_CODES {
            let sentence = blocker_sentence(code);
            assert!(
                !sentence.contains(code),
                "{code} printed as its identifier: {sentence}"
            );
        }

        for code in OPERATION_STATES {
            let sentence = operation_state(code);
            assert!(
                !sentence.contains("does not know"),
                "{code} fell through: {sentence}"
            );
        }
    }
}
