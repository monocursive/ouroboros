//! The one table of snake_case codes this view turns into sentences.
//!
//! Broker refusals, deploy blockers and operation states used to live as four `match`
//! arms that named the same facts in different words. A new code then had four places to
//! miss. This module is the catalogue; [`super`] only formats around it. The Elixir
//! surface has its own copy on purpose: the two clients do not share a crate, and a
//! sentence that drifted would be a review finding rather than a silent coupling.

/// Reason codes this client has words for: the ones a `fleet.devices` or `fleet.status`
/// read can be refused with, and the ones a journal's `last_error` can record. The drift
/// test in `tests/devices_flow.rs` walks the fixtures against this list so a new code on
/// the wire cannot land as an identifier.
///
/// The challenge, approval and takeover codes went with the flow that raised them: this
/// client answers no challenge, approves no plan and takes over nothing (§10), so a
/// sentence for `challenge_not_bound` would be a sentence about a screen that no longer
/// exists. What survives is what a read can still be told, plus what a worker can still
/// have written down before it stopped.
pub const REASON_CODES: &[&str] = &[
    "host_key_changed",
    "version_mismatch",
    "fleet_present",
    "already_installed",
    "challenge_expired",
    "worker_unavailable",
    "worker_unreachable",
    "worker_timeout",
    "unknown_operation",
    "devices_busy",
    "no_data_dir",
    "ouro_path_unknown",
    "journal_unreadable",
];

/// `capabilities.reasons`: what this runtime says it cannot do, and why.
///
/// `no_ca_key` is gone with the per-member PKI (§1): one fleet is one shared bundle, every
/// member holds the CA key, and "this machine cannot admit" stopped being a fact about
/// any machine. A document that still sends it is named by the fallback rather than
/// explained by a sentence this build no longer believes.
pub const BLOCKER_CODES: &[&str] = &[
    "ouro_path_unknown",
    "no_data_dir",
    "cleartext_web_bind",
    "dev_runtime",
];

/// The journal's `state` values, as `fleet.devices`'s operation rows carry them.
///
/// `attaching` is gone with the client that attached: there is no worker connection for a
/// terminal to be partway through making.
pub const OPERATION_STATES: &[&str] = &[
    "spawning",
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

/// The runtime's stable reason codes, as sentences. An unrecognised code is printed as
/// itself: a runtime that grew a refusal this build predates must still be legible.
pub fn reason_sentence(reason: &str) -> String {
    match reason {
        "host_key_changed" => "this host's key has changed. That blocks the deployment and \
                               needs a separate, verified repair; it is never accepted here."
            .into(),
        "version_mismatch" => "that machine runs a different Ouroboros from this one, and \
                               nothing was replaced. Upgrade one of them to match."
            .into(),
        "fleet_present" => "that machine already belongs to a different fleet.".into(),
        "already_installed" => "that machine is already in this fleet under this name, so \
                                nothing was rewritten."
            .into(),
        "challenge_expired" => "a question the deployment asked went unanswered for five \
                                minutes, so the operation stopped."
            .into(),
        "worker_unavailable" | "worker_unreachable" => {
            "the deployment worker is no longer reachable from this runtime.".into()
        }
        "worker_timeout" => "the deployment worker did not answer in time.".into(),
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
/// `fleet.devices`'s `capabilities.reasons`: what this runtime says in advance it cannot
/// do. The terminal client no longer gates anything on them — it runs nothing — but they
/// are still facts the runtime reported about itself, and one of them changes what a
/// printed recipe means.
pub fn blocker_sentence(reason: &str) -> String {
    match reason {
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
        // Only ever a reason a machine cannot set *itself* up: a Mix dev runtime drives a
        // deployment onto another machine perfectly well, and what it cannot do is be the
        // thing installed here. A live run let it try, wrote a LaunchAgent that exits 1,
        // and said nothing.
        "dev_runtime" => "This is a development runtime; the packaged ouro is what sets a \
                          machine up."
            .into(),
        other => format!(
            "This runtime reports the blocker {}.",
            other.replace('_', " ")
        ),
    }
}

/// A journal's `state`, as a person reads it. The codes stay in the data.
///
/// The waiting states keep their words even though this client answers none of them: an
/// operation *is* waiting for somebody, and a row that said only "deploying" while a
/// worker sat on an unanswered host-key question would be describing the wrong thing.
/// Where it is answered is the web page, not here.
pub fn operation_state(state: &str) -> String {
    match state {
        "spawning" => "starting the deployment worker".into(),
        "inspecting" => "inspecting the target".into(),
        "awaiting_host_trust" => "waiting for somebody to verify the host key".into(),
        "awaiting_auth" => "waiting for a credential".into(),
        "awaiting_review" => "waiting for somebody to review the plan".into(),
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
