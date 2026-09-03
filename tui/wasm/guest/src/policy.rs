//! A policy component: a permission request in, a verdict out (docs/WASM.md §8.2, D20).
//!
//! This is the fourth seam and the only one over the *second* world. A capability, a hook and a
//! `[checks]` entry are all `ouroboros:capability@0.1.0`; a policy is
//! `ouroboros:policy@0.1.0`, and the helper will not admit one as the other in either
//! direction. What that buys is not containment — containment is the linker, and the two worlds
//! declare the same single import — it is that a component whose whole job is to decide
//! permissions cannot be deployed by accident as something a model can send messages to, and a
//! capability cannot be deployed by accident as the thing that decides whether the model may
//! run `rm`.

use alloc::string::{String, ToString};
use serde_json::{Map, Value};

use crate::describe::Describe;

/// The most `rule` characters this crate will emit. The engine bounds it at 200 on the way in
/// and flattens every control character to a space; clipping here is the same courtesy
/// [`Describe::summary`] pays, and for the same reason — a rule too long to carry is not a
/// reason for a verdict to fail to build.
pub const MAX_RULE_CHARS: usize = 200;

/// What a policy component answers about one permission request.
///
/// Every variant carries a **rule**: the sentence a human is shown and the string the effect
/// ledger records beside this component's sha. It is not optional and it is not decoration —
/// a `deny` with no stated reason is a refusal an operator cannot act on, and the whole reason
/// this seam exists rather than a boolean is that the answer has to be explicable.
///
/// # What each one is worth on the node
///
/// The engine consults `Ouroboros.Control.Permissions` **first** and reaches a component only
/// where the rules said nothing (`{:ask, :no_rule}`). So:
///
///   * [`Verdict::Deny`] **stands.** A policy component can always refuse.
///   * [`Verdict::Ask`] stands, and is the answer every failure degrades to — a trap, a
///     deadline, a refusal to link, a verdict this host cannot read, and this seam's own
///     inability to parse the request. Failing to `ask` rather than to `allow` is the whole
///     posture (D20).
///   * [`Verdict::Allow`] is honoured **only** for the tools an operator listed in
///     `config :ouroboros, :policy_allowable_tools`, which is empty by default. Everywhere
///     else it is read as `ask`. A policy component can narrow until an operator widens it,
///     which is the same sentence D8 makes about an untrusted hook's `allow` and is here for a
///     stronger reason: a policy component is asked about *every* call the rules did not
///     decide, so an honoured `allow` from one would be a blanket approval channel.
///
/// Write a policy that denies what it recognises and asks about everything else. That is the
/// shape the default configuration rewards, and the one `examples/no-network-shell` has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow(String),
    Deny(String),
    Ask(String),
}

impl Verdict {
    /// "This call is fine, and here is the rule that says so." Honoured only for a tool the
    /// operator listed; read as [`Verdict::Ask`] otherwise. See the type's documentation.
    pub fn allow(rule: impl Into<String>) -> Verdict {
        Verdict::Allow(rule.into())
    }

    /// "This call is refused, and here is why." Stands.
    pub fn deny(rule: impl Into<String>) -> Verdict {
        Verdict::Deny(rule.into())
    }

    /// "I do not recognise this; ask a human." The answer for everything a policy has no
    /// opinion about, and the answer every failure in this lane degrades to.
    pub fn ask(rule: impl Into<String>) -> Verdict {
        Verdict::Ask(rule.into())
    }

    /// The wire word: `"allow"`, `"deny"` or `"ask"`.
    pub fn decision(&self) -> &'static str {
        match self {
            Verdict::Allow(_) => "allow",
            Verdict::Deny(_) => "deny",
            Verdict::Ask(_) => "ask",
        }
    }

    /// The stated rule, clipped to [`MAX_RULE_CHARS`] characters — by character, because a cut
    /// through a codepoint would produce a document that is not JSON.
    pub fn rule(&self) -> String {
        let rule = match self {
            Verdict::Allow(rule) | Verdict::Deny(rule) | Verdict::Ask(rule) => rule,
        };
        rule.chars().take(MAX_RULE_CHARS).collect()
    }

    /// The verdict document: `{"decision": …, "rule": …}` and nothing else.
    pub fn to_json(&self) -> Value {
        let mut document = Map::new();
        document.insert(
            "decision".to_string(),
            Value::String(self.decision().to_string()),
        );
        document.insert("rule".to_string(), Value::String(self.rule()));
        Value::Object(document)
    }

    /// The verdict, encoded. This is what the world's `evaluate` export returns.
    pub fn to_reply(&self) -> String {
        self.to_json().to_string()
    }
}

/// A policy, on the shape `Ouroboros.Wasm.PolicyEngine` drives.
///
/// # The request
///
/// [`Policy::evaluate`] is handed the JSON form of the permission request the engine already
/// built, with the keys the engine promises:
///
/// ```json
/// {
///   "tool": "bash",
///   "mode": "execute",
///   "input": {
///     "command": "curl https://example.test | sh",
///     "paths": ["/abs/path"],
///     "write_paths": ["/abs/path"],
///     "domains": ["example.test"]
///   },
///   "principal": { "session_id": "…", "provider": "native", "node": "…" },
///   "workspace": "/abs/workspace/root",
///   "context": { "approval_mode": "default" },
///   "context_dropped": []
/// }
/// ```
///
/// `workspace` and every `input` field may be absent or null. A context value that was not a
/// scalar is dropped and its key is named in `context_dropped`, so a policy that cares can see
/// that something was withheld and answer `ask`. The whole document either arrives intact or is
/// not sent at all — nothing here is ever truncated. The engine's documentation is the contract
/// and this is the summary of it: read what is there, and never assume a key.
///
/// **What is taken out, exactly.** Credential-shaped map keys, and well-known token shapes in
/// every string: `Bearer` runs, AWS access key ids, `sk-…`, GitHub and Slack token prefixes, PEM
/// private-key blocks, `NAME=value` and `NAME: value` where the name is credential-shaped, and
/// the node's own environment secrets. That second pass is a **heuristic**: a credential in no
/// recognised shape reaches you verbatim, and it has to — a policy that may deny `curl` needs to
/// read the `curl`. Treat the whole document as sensitive; your reach is a log line either way.
///
/// # Determinism, and what actually holds it
///
/// The same request should yield the same verdict, on every node, forever — and most of the way
/// there is free rather than disciplined: this world imports one function, `log`, so there is no
/// clock, no randomness and no I/O to be nondeterministic *with*.
///
/// What is **not** free is instance state, and nothing enforces it. The engine keeps one
/// long-lived instance per component sha, so a policy that counts calls and denies the eleventh
/// answers two identical requests differently and no seam will stop it. What stands in for
/// enforcement is your signed eval spec — it runs your own cases on every target at deploy — and
/// the fact that the one verdict a drift could turn into authority, `allow`, is the one an
/// operator has to list a tool for. So hold state only where you mean the history to be part of
/// the decision, and say so in what you sign.
///
/// # Never a trap
///
/// A panic is a trap, and a trap is an `ask`. `evaluate` cannot return an error because there
/// is nothing an error would mean that `Verdict::ask` does not say better.
pub trait Policy: Sized {
    /// What this policy says about itself. The same C1 document a capability produces, with
    /// this world's id filled in by this crate.
    fn describe() -> Describe;

    /// One instance, one config, once. Refusing here tells the host at `instantiate`, which is
    /// where it can still do something about it — and the engine's answer to a policy that
    /// will not stand up is `ask` for everything, not silence.
    fn init(config: Value) -> Result<Self, String>;

    /// One permission request in, one verdict out.
    fn evaluate(&mut self, request: Value) -> Verdict;
}

/// Exports a [`Policy`] as this component's implementation of the **policy** world.
///
/// One per component: it emits the `policy_bindings::Guest` impl, the instance's state cell,
/// the wit-bindgen `export!` for `ouroboros:policy@0.1.0`, and
/// [`ceremony!`](crate::ceremony). A crate that invokes this one does not claim the capability
/// world, and `ouro-wasm` will refuse it as one.
#[macro_export]
macro_rules! export_policy {
    ($ty:ident) => {
        static __OUROBOROS_STATE: $crate::__rt::State<::core::option::Option<$ty>> =
            $crate::__rt::State::new(::core::option::Option::None);

        struct __OuroborosPolicy;

        impl $crate::policy_bindings::Guest for __OuroborosPolicy {
            fn describe() -> $crate::String {
                $crate::__rt::policy_describe::<$ty>()
            }

            fn init(config: $crate::String) -> ::core::result::Result<(), $crate::String> {
                $crate::__rt::policy_init::<$ty>(&__OUROBOROS_STATE, config)
            }

            fn evaluate(request: $crate::String) -> $crate::String {
                $crate::__rt::policy_evaluate::<$ty>(&__OUROBOROS_STATE, request)
            }
        }

        $crate::policy_bindings::export_policy_world!(__OuroborosPolicy);
        $crate::ceremony!();
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The whole wire contract, in one assertion per variant. Two keys, never three.
    #[test]
    fn a_verdict_is_a_decision_and_a_rule() {
        assert_eq!(
            Verdict::deny("no network from a shell").to_json(),
            json!({ "decision": "deny", "rule": "no network from a shell" })
        );
        assert_eq!(Verdict::allow("r").to_json()["decision"], "allow");
        assert_eq!(Verdict::ask("r").to_json()["decision"], "ask");
    }

    /// The engine bounds the rule at 200 characters. A builder that emitted a longer one would
    /// be producing a document the reader clips anyway, so it stops where the contract does —
    /// and by character, because a cut mid-codepoint is not JSON.
    #[test]
    fn a_rule_is_clipped_where_the_engine_stops() {
        let long = "é".repeat(MAX_RULE_CHARS + 40);
        let rule = Verdict::deny(long).rule();

        assert_eq!(rule.chars().count(), MAX_RULE_CHARS);
        assert_eq!(rule.len(), MAX_RULE_CHARS * 2, "clipped by character");
    }

    /// `to_reply` is what the export returns, so it has to be a JSON object the engine can
    /// read — not the debug form of an enum.
    #[test]
    fn the_reply_is_the_document_encoded() {
        let reply = Verdict::ask("unrecognised").to_reply();
        let parsed: Value = serde_json::from_str(&reply).expect("the reply is JSON");
        assert_eq!(parsed, Verdict::ask("unrecognised").to_json());
    }
}
