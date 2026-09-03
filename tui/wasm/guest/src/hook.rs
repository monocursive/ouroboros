//! Lane H: a `[[hooks]]` entry and a `[checks]` entry, on the contract
//! `lib/ouroboros/provider/native/hooks.ex` already speaks.
//!
//! A hook component is a capability-world component (docs/WASM.md §8.1): the hook payload goes
//! in through `handle-message`, and the reply *is* the stdout contract `parse_output/1` reads —
//! the same JSON a shell hook prints, because four vendors converged on that shape and a fifth
//! would make the feature worth less than not having it. This module is that contract, typed.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde_json::{Map, Value};

use crate::describe::Describe;

/// The payload a hook is handed, on the shape `hooks.ex` builds.
///
/// Every field is optional in the wire sense: this struct is built from whatever arrived and
/// never fails, because a hook that could not parse its payload would be a hook that stopped
/// running the day the seam grew a field. [`HookInput::raw`] keeps the whole document, so a
/// field this struct does not name is still readable.
///
/// # What a hook may see, which is not "nothing"
///
/// Containment bounds what a component may *do*; the payload is what it may *see*, and from an
/// untrusted workspace that is a real read (docs/WASM.md D8):
///
///   * `PreToolUse` carries the whole `tool_input` of every matching call — the command a
///     `bash` is about to run, the path *and the content* a `write` is about to write. Kept
///     deliberately: a hook that may deny needs the arguments it is denying.
///   * `PostToolUse` / `PostToolUseFailure` carry `tool_input` and, for an **untrusted** hook,
///     a [`tool_response`](HookInput::tool_response) of `{"is_error": …, "bytes": …}` and
///     nothing else. The output body — a read file's contents, a command's stdout — is not in
///     the payload. A trusted hook is handed the response itself.
///   * `FileChanged` would carry the paths a turn changed and never their contents, and is not
///     dispatched to an untrusted hook at all. Neither are `Notification` and `SessionEnd`: the
///     turn loop discards what all three return, so running one untrusted would buy a read in
///     exchange for a verdict nothing consumes.
///   * The rest carry the session identifiers, the workspace root, and the event's own fields.
#[derive(Clone, Debug)]
pub struct HookInput {
    /// `hook_event_name`: `"PreToolUse"`, `"PostToolUse"`, `"PostToolUseFailure"`,
    /// `"UserPromptSubmit"`, `"Stop"`, `"SessionStart"`, `"SessionEnd"`, `"PreCompact"`,
    /// `"Notification"` or `"FileChanged"`. Empty when the payload named no event.
    pub event: String,
    /// The tool this call is about, for the events that have one.
    pub tool_name: Option<String>,
    /// The tool's arguments. `Value::Null` when the event carries none.
    pub tool_input: Value,
    /// The tool's answer, narrowed to `{"is_error": …, "bytes": …}` for an untrusted hook.
    pub tool_response: Value,
    /// This session's identifier, as the daemon knows it.
    pub session_id: Option<String>,
    /// The provider's identifier for the same session, when there is one.
    pub provider_session_id: Option<String>,
    /// The turn this event happened in. Absent for the three lifecycle events.
    pub turn_id: Option<String>,
    /// The workspace root the session is running in.
    pub cwd: Option<String>,
    /// Whether the operator trusts this workspace. A hook shipped *by* an untrusted workspace
    /// sees `false` here and should read it as "my verdict will be narrowed", not as an
    /// instruction.
    pub workspace_trusted: bool,
    /// `FileChanged`: the paths a turn changed, never their contents.
    pub paths: Vec<String>,
    /// `SessionStart`: `"startup"` or `"resume"`.
    pub source: Option<String>,
    /// `SessionEnd`: why the session ended.
    pub reason: Option<String>,
    /// `PreCompact`: `"manual"` or `"automatic"`.
    pub trigger: Option<String>,
    /// `PreCompact`: the operator's compaction instructions.
    pub custom_instructions: Option<String>,
    /// The payload exactly as it arrived, so a field this struct does not name is not lost.
    pub raw: Value,
}

impl HookInput {
    /// Reads a payload. Never fails: anything missing or mistyped is absent.
    pub fn from_json(payload: Value) -> Self {
        let string = |key: &str| {
            payload
                .get(key)
                .and_then(Value::as_str)
                .map(ToString::to_string)
        };

        Self {
            // `event` is the `[checks]` payload's own key, so one struct reads both shapes and
            // a hook handed a check payload sees `"check"` rather than an empty event.
            event: string("hook_event_name")
                .or_else(|| string("event"))
                .unwrap_or_default(),
            tool_name: string("tool_name"),
            tool_input: payload.get("tool_input").cloned().unwrap_or(Value::Null),
            tool_response: payload.get("tool_response").cloned().unwrap_or(Value::Null),
            session_id: string("session_id"),
            provider_session_id: string("provider_session_id"),
            turn_id: string("turn_id"),
            cwd: string("cwd"),
            workspace_trusted: payload
                .get("workspace_trusted")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            paths: payload
                .get("paths")
                .and_then(Value::as_array)
                .map(|paths| {
                    paths
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            source: string("source"),
            reason: string("reason"),
            trigger: string("trigger"),
            custom_instructions: string("custom_instructions"),
            raw: payload,
        }
    }

    /// A field of the payload this struct does not name.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.raw.get(key)
    }

    /// A string field of `tool_input` — `"path"`, `"command"`, `"content"`, whatever the tool
    /// declares. `None` when it is absent or is not a string.
    pub fn tool_input_str(&self, key: &str) -> Option<&str> {
        self.tool_input.get(key).and_then(Value::as_str)
    }

    /// Whether this is the named event, ignoring case. `hooks.ex` sends `"PreToolUse"`; the
    /// compatible implementations agree, but a comparison that depends on that is one rename
    /// away from a hook that silently stops firing.
    pub fn is(&self, event: &str) -> bool {
        self.event.len() == event.len()
            && self
                .event
                .bytes()
                .zip(event.bytes())
                .all(|(a, b)| a.eq_ignore_ascii_case(&b))
    }
}

/// What a hook may say back.
///
/// The seam reads three independent things out of a reply — a decision, an `updatedInput`, and
/// context lines — and these are the combinations worth stating. `Deny` and `Ask` carry the
/// reason that becomes the decision's first context line, which is the line a human is most
/// likely to read.
///
/// # What an untrusted workspace's verdict keeps, and what the node drops
///
/// A component hook is admitted from a workspace nobody trusts (D8) because its authority is
/// bounded on the way back out. Copied from `hooks.ex`, which is where it is enforced:
///
///   * **`Allow` is dropped.** From an untrusted workspace it is read as **silence** — `allow`
///     resolves an engine `ask`, which is what removes the human from the loop.
///   * **`UpdatedInput` is dropped.** It replaces the arguments of a call the engine then
///     allows, path and content both, so a clone could redirect an allowed `write` to content
///     of its choosing at a path of its choosing inside the allowed roots.
///   * **`Deny`, `Ask` and `Context` stand.** All three can only make the outcome stricter.
///
/// Stated once: **an untrusted hook can make a decision stricter, never looser.** A `deny` also
/// needs a hook to have run at all, and no hook is invoked on a call a rule already denied — so
/// a hook can never allow what a rule denied, whatever it returns here.
///
/// Every context line an untrusted hook produces is **labelled**, per *line* and not per
/// string: each line of what you send arrives at the model prefixed `[untrusted workspace
/// hook] `, including the line that became a denial's reason, and including every line of a
/// multi-line string. Per line and not per string, because a label on the first line of ten
/// leaves nine reading as if the runtime wrote them. So a multi-line [`Verdict::Context`] is
/// safe to send and will not read as this runtime's own words. It is then clipped to 8 KiB
/// *after* labelling.
#[derive(Clone, Debug)]
pub enum Verdict {
    /// Nothing to say. The reply is the empty string and the seam records no decision.
    ///
    /// This is the right answer for an event a hook does not care about, and it is **not**
    /// [`Verdict::Allow`]: silence is not consent, and the two are distinct at the seam
    /// precisely so that an installed hook is never an approval bypass.
    Silent,
    /// Resolve an engine `ask` in favour of the call. Read as [`Verdict::Silent`] from an
    /// untrusted workspace.
    Allow,
    /// Refuse the call. `reason` is what the model is told, and it is final: the first `deny`
    /// stops the chain and no later hook runs.
    Deny { reason: String },
    /// Put the decision to a human, where a mode would have auto-approved. `reason` is what
    /// they are shown.
    Ask { reason: String },
    /// Say something without deciding anything: `additionalContext`, appended to the tool
    /// result or the next prompt. The lines are joined with `\n` into the one string the
    /// contract carries, and each arrives labelled for an untrusted workspace.
    Context { lines: Vec<String> },
    /// Replace the tool's arguments. Dropped from an untrusted workspace; re-evaluated by the
    /// permission engine before it is used even from a trusted one, so a rewrite cannot
    /// launder a denied command.
    UpdatedInput { input: Value },
}

impl Verdict {
    /// The reply string, on the stdout contract `Hooks.parse_output/1` reads.
    pub fn to_reply(&self) -> String {
        let mut specific = Map::new();

        match self {
            Verdict::Silent => return String::new(),
            Verdict::Allow => {
                specific.insert(
                    "permissionDecision".to_string(),
                    Value::String("allow".to_string()),
                );
            }
            Verdict::Deny { reason } => {
                specific.insert(
                    "permissionDecision".to_string(),
                    Value::String("deny".to_string()),
                );
                specific.insert(
                    "permissionDecisionReason".to_string(),
                    Value::String(reason.clone()),
                );
            }
            Verdict::Ask { reason } => {
                specific.insert(
                    "permissionDecision".to_string(),
                    Value::String("ask".to_string()),
                );
                specific.insert(
                    "permissionDecisionReason".to_string(),
                    Value::String(reason.clone()),
                );
            }
            Verdict::Context { lines } => {
                if lines.is_empty() {
                    return String::new();
                }
                specific.insert(
                    "additionalContext".to_string(),
                    Value::String(lines.join("\n")),
                );
            }
            Verdict::UpdatedInput { input } => {
                specific.insert("updatedInput".to_string(), input.clone());
            }
        }

        let mut document = Map::new();
        document.insert("hookSpecificOutput".to_string(), Value::Object(specific));
        Value::Object(document).to_string()
    }

    /// [`Verdict::Deny`] from anything that reads as a reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Verdict::Deny {
            reason: reason.into(),
        }
    }

    /// [`Verdict::Ask`] from anything that reads as a reason.
    pub fn ask(reason: impl Into<String>) -> Self {
        Verdict::Ask {
            reason: reason.into(),
        }
    }

    /// [`Verdict::Context`] with one line.
    pub fn context(line: impl Into<String>) -> Self {
        Verdict::Context {
            lines: alloc::vec![line.into()],
        }
    }
}

/// A `[[hooks]]` entry with `component = "…"`.
///
/// A fresh instance per invocation is the whole state story: `hooks.ex` stands one up, sends one
/// message, and drops it. No guest memory carries from one hook run to the next, so `&mut self`
/// here is the arguments of *this* call and nothing else — a counter in it counts to one.
///
/// A hook that fails to run is not consent and not a denial. An `Err` from either method, a
/// trap, or a refusal at any stage is logged by the node and read as silence.
pub trait Hook: Sized {
    /// The entry's declared `config`, parsed. `{}` when the entry declared none.
    fn init(config: Value) -> Result<Self, String>;

    /// One event, one verdict.
    fn on(&mut self, input: HookInput) -> Result<Verdict, String>;

    /// What this hook says about itself. `describe` is unused on the hook path, so this
    /// defaults to the crate's own name and version, which [`export_hook!`] reads out of the
    /// author's `Cargo.toml`. Override it if the component is also shipped as a capability.
    fn describe(name: &str, version: &str) -> Describe {
        Describe::new(name, version)
    }
}

/// What a `[checks]` component answers.
#[derive(Clone, Debug)]
pub enum CheckOutcome {
    /// Nothing to report. The reply is the empty string, which is what a pass is.
    Pass,
    /// The failure text, injected into the turn as a **user message** — a stronger position
    /// than a hook's `additionalContext` gets, which is why an untrusted workspace's failure is
    /// labelled per line exactly as a hook's context is, the check's own name and path
    /// included. It is tail-clipped to the last forty lines, as a command check's output is.
    Fail(String),
}

/// A `[checks]` entry with `component = "…"`.
///
/// The same seam as [`Hook`] without a verdict: a check has no decision to make, only text. The
/// payload is `{"event": "check", "name": "<the key in ouroboros.toml>"}` and carries nothing
/// about the session at all — which is the whole of what a check is told.
///
/// A component check runs from an untrusted workspace under D8 and for D8's reason. A *command*
/// check does not: there is no difference in kind between a repository-supplied command line
/// and a `[[hooks]]` command.
pub trait Check: Sized {
    /// The entry's declared `config`, parsed.
    fn init(config: Value) -> Result<Self, String>;

    /// Run, and say whether it passed. `name` is the key this check was declared under.
    ///
    /// A check that could not run is not a check that passed: answer [`CheckOutcome::Fail`]
    /// with what went wrong, or `Err` — which the node also reports as a failure, naming the
    /// refusal.
    fn run(&mut self, name: &str) -> Result<CheckOutcome, String>;

    /// As [`Hook::describe`].
    fn describe(name: &str, version: &str) -> Describe {
        Describe::new(name, version)
    }
}

/// Exports a [`Hook`] as this component's implementation of the world.
///
/// One per component: the `bindings::Guest` impl, the instance's state cell, the wit-bindgen
/// `export!`, and [`ceremony!`](crate::ceremony). The default `describe` reads
/// `CARGO_PKG_NAME` and `CARGO_PKG_VERSION` from *your* manifest.
#[macro_export]
macro_rules! export_hook {
    ($ty:ident) => {
        static __OUROBOROS_STATE: $crate::__rt::State<::core::option::Option<$ty>> =
            $crate::__rt::State::new(::core::option::Option::None);

        struct __OuroborosGuest;

        impl $crate::bindings::Guest for __OuroborosGuest {
            fn describe() -> $crate::String {
                $crate::__rt::hook_describe::<$ty>(
                    ::core::env!("CARGO_PKG_NAME"),
                    ::core::env!("CARGO_PKG_VERSION"),
                )
            }

            fn init(config: $crate::String) -> ::core::result::Result<(), $crate::String> {
                $crate::__rt::hook_init::<$ty>(&__OUROBOROS_STATE, config)
            }

            fn handle_message(
                body: $crate::String,
            ) -> ::core::result::Result<$crate::String, $crate::String> {
                $crate::__rt::hook_handle::<$ty>(&__OUROBOROS_STATE, body)
            }
        }

        $crate::bindings::export_world!(__OuroborosGuest);
        $crate::ceremony!();
    };
}

/// Exports a [`Check`] as this component's implementation of the world. As
/// [`export_hook!`](crate::export_hook), for the `[checks]` contract.
#[macro_export]
macro_rules! export_check {
    ($ty:ident) => {
        static __OUROBOROS_STATE: $crate::__rt::State<::core::option::Option<$ty>> =
            $crate::__rt::State::new(::core::option::Option::None);

        struct __OuroborosGuest;

        impl $crate::bindings::Guest for __OuroborosGuest {
            fn describe() -> $crate::String {
                $crate::__rt::check_describe::<$ty>(
                    ::core::env!("CARGO_PKG_NAME"),
                    ::core::env!("CARGO_PKG_VERSION"),
                )
            }

            fn init(config: $crate::String) -> ::core::result::Result<(), $crate::String> {
                $crate::__rt::check_init::<$ty>(&__OUROBOROS_STATE, config)
            }

            fn handle_message(
                body: $crate::String,
            ) -> ::core::result::Result<$crate::String, $crate::String> {
                $crate::__rt::check_handle::<$ty>(&__OUROBOROS_STATE, body)
            }
        }

        $crate::bindings::export_world!(__OuroborosGuest);
        $crate::ceremony!();
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The verdict vocabulary, key by key, as `Hooks.parse_output/1` reads it. Rename any one
    /// of these strings and the node stops reading the verdict — silently, because a reply it
    /// cannot parse is a reply it treats as nothing having happened.
    #[test]
    fn a_decision_is_stated_where_the_seam_reads_it() {
        assert_eq!(
            Verdict::deny("no").to_reply(),
            r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"no"}}"#
        );
        assert_eq!(
            Verdict::ask("are you sure").to_reply(),
            r#"{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"are you sure"}}"#
        );
        assert_eq!(
            Verdict::Allow.to_reply(),
            r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#
        );
        assert_eq!(
            Verdict::UpdatedInput {
                input: json!({ "path": "safe" })
            }
            .to_reply(),
            r#"{"hookSpecificOutput":{"updatedInput":{"path":"safe"}}}"#
        );
    }

    /// Silence is the **empty reply**, and it has to be: `parse_output/1` reads an empty string
    /// as nothing having happened, and reads `{}` the same way only by accident of it carrying
    /// no keys. Answering `Allow` here instead would be an installed hook resolving an engine
    /// `ask` it had no opinion about — which is the one thing the seam's "silence is not
    /// consent" rule exists to stop.
    #[test]
    fn silence_is_the_empty_reply_and_not_an_allow() {
        assert_eq!(Verdict::Silent.to_reply(), "");
        assert_eq!(Verdict::Context { lines: Vec::new() }.to_reply(), "");
        assert_ne!(Verdict::Allow.to_reply(), "");
    }

    /// Context lines are joined into the one string the contract carries, with `\n` between
    /// them — which is what makes the node's per-*line* labelling reach every one of them.
    #[test]
    fn context_lines_become_one_newline_separated_string() {
        let verdict = Verdict::Context {
            lines: alloc::vec!["first".to_string(), "second".to_string()],
        };

        assert_eq!(
            verdict.to_reply(),
            r#"{"hookSpecificOutput":{"additionalContext":"first\nsecond"}}"#
        );
    }

    /// The payload `hooks.ex` builds, read back field by field. Every key here is one the seam
    /// actually sends; a hook reading a name this struct got wrong would see `None` forever.
    #[test]
    fn the_payload_is_read_on_the_keys_the_seam_sends() {
        let input = HookInput::from_json(json!({
            "session_id": "sess-1",
            "provider_session_id": "prov-1",
            "turn_id": "turn-1",
            "cwd": "/w",
            "workspace_trusted": true,
            "hook_event_name": "PreToolUse",
            "tool_name": "write",
            "tool_input": { "path": "src/a.rs", "content": "x" },
            "tool_response": { "is_error": false, "bytes": 12 }
        }));

        assert_eq!(input.event, "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("write"));
        assert_eq!(input.tool_input_str("path"), Some("src/a.rs"));
        assert_eq!(input.tool_response["bytes"], 12);
        assert_eq!(input.session_id.as_deref(), Some("sess-1"));
        assert_eq!(input.provider_session_id.as_deref(), Some("prov-1"));
        assert_eq!(input.turn_id.as_deref(), Some("turn-1"));
        assert_eq!(input.cwd.as_deref(), Some("/w"));
        assert!(input.workspace_trusted);
    }

    /// The event-specific fields, and the conservative defaults. `workspace_trusted` absent
    /// reads as *untrusted*, which is the only safe direction for a field a hook might branch
    /// on.
    #[test]
    fn the_event_fields_are_read_and_the_defaults_are_conservative() {
        let changed = HookInput::from_json(json!({
            "hook_event_name": "FileChanged",
            "paths": ["lib/a.ex", "lib/b.ex", 7]
        }));
        assert_eq!(changed.paths, ["lib/a.ex", "lib/b.ex"]);
        assert!(!changed.workspace_trusted);
        assert!(changed.tool_input.is_null());

        let compact = HookInput::from_json(json!({
            "hook_event_name": "PreCompact",
            "trigger": "manual",
            "custom_instructions": "keep the migration"
        }));
        assert_eq!(compact.trigger.as_deref(), Some("manual"));
        assert_eq!(
            compact.custom_instructions.as_deref(),
            Some("keep the migration")
        );

        let started = HookInput::from_json(json!({
            "hook_event_name": "SessionStart",
            "source": "resume"
        }));
        assert_eq!(started.source.as_deref(), Some("resume"));
    }

    /// A field this struct does not name is still readable, because a payload that grows a key
    /// must not be a hook that stopped seeing the rest of it.
    #[test]
    fn an_unnamed_field_survives_in_raw() {
        let input = HookInput::from_json(json!({
            "hook_event_name": "PreCompact",
            "messages": 41
        }));

        assert_eq!(input.get("messages"), Some(&json!(41)));
        assert_eq!(input.get("nothing"), None);
    }

    /// A `[checks]` payload has no `hook_event_name` at all, so `event` falls through to its
    /// `event` key rather than reading as no event.
    #[test]
    fn a_check_payload_names_its_own_event() {
        let input = HookInput::from_json(json!({ "event": "check", "name": "lint" }));

        assert!(input.is("check"));
        assert_eq!(input.get("name"), Some(&json!("lint")));
    }

    /// `is/1` ignores case and nothing else. A prefix must not match: `"Stop"` and `"Stopped"`
    /// would be one hook firing on two events.
    #[test]
    fn an_event_is_matched_case_insensitively_and_wholly() {
        let input = HookInput::from_json(json!({ "hook_event_name": "PreToolUse" }));

        assert!(input.is("PreToolUse"));
        assert!(input.is("pretooluse"));
        assert!(!input.is("PreToolUseFailure"));
        assert!(!input.is("PreTool"));
    }

    /// Nothing in here fails. A payload that is not an object at all still produces a struct,
    /// because a hook that could not parse its payload would be a hook that stopped running the
    /// day the seam grew a field.
    #[test]
    fn a_payload_that_is_not_an_object_is_still_read() {
        let input = HookInput::from_json(json!("nonsense"));

        assert_eq!(input.event, "");
        assert!(input.tool_name.is_none());
        assert!(input.paths.is_empty());
    }
}
