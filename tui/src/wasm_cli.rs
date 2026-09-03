//! `ouro wasm` — the operator readiness surface and the component author's local loop.
//!
//! # `doctor` asks a node; the other five ask a helper (docs/WASM.md W5, W10)
//!
//! `doctor` asks the gateway for `wasm.status`, which starts nothing — not the helper, not a
//! component, not an instance — and prints a readable summary, or the raw map under `--json`.
//! **Absence is not a failure.** The helper is opt-in by presence on disk, so a node that
//! never built one is a node whose operator chose that, and this exits 0 saying so. The only
//! non-zero exit is a gateway that refused the question.
//!
//! `inspect`, `run`, `hook`, `check` and `new` are the other half and have no node at all.
//! They start a local `ouro-wasm` and speak its line protocol ([`crate::wasm_client`]), which
//! is what makes an author's loop a loop: write a component, see what the node would make of
//! it, without deploying anything to find out. That they *do* start a helper is the deliberate
//! difference from `doctor`, and `doctor` keeps its property — a readiness surface that spawned
//! to answer whether spawning works would be answering a different question.
//!
//! # Everything these commands print about a component is untrusted
//!
//! A reply, a `describe`, a log line, a path out of an `ouroboros.toml`: all of it is authored
//! by somebody whose component this command is about to run. Every one of them goes through
//! [`crate::wasm_client::sanitize`] before it reaches a terminal, and the ones that are
//! repository text are clipped to the same bound the node clips them to.
//!
//! # `run` and `hook` execute attacker-authored code, and that is fine for one reason
//!
//! They execute it *inside `ouro-wasm`*, under the bounds the node uses, with the environment
//! the node's pool passes and nothing more. No path here reaches wasmtime except through the
//! helper, no limit here is sent above what the helper reports it accepts, and the helper
//! itself comes only from the three places D14 names.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::model::{WasmHelper, WasmStatus};
use crate::transport::Client;
use crate::wasm_client::{self, Helper, Limits, NODE_DEFAULT_LIMITS};

const STATUS_METHOD: &str = "wasm.status";

/// Query lane-W readiness. Always `wasm.status`: there is no probe verb, because starting
/// the helper to see whether it starts is exactly what a read-scope surface must not do.
pub async fn doctor<O: Write>(client: &Client, json: bool, out: &mut O) -> Result<()> {
    let answer = client
        .call(STATUS_METHOD, serde_json::json!({}))
        .await
        .map_err(|error| anyhow!("the runtime refused {STATUS_METHOD}: {error}"))?;

    let text = if json {
        serde_json::to_string_pretty(&answer)?
    } else {
        render(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// A readable one-glance summary of the status map. Absent fields read as their safe
/// default (missing / not running / not known) so an older or partial answer never panics.
pub fn render(answer: &Value) -> String {
    let status = WasmStatus::decode(answer);
    let helper = &status.helper;
    let mut lines = Vec::new();

    let path = helper.path.as_deref().unwrap_or("(unknown)");

    if helper.present {
        lines.push(format!("WebAssembly containment: helper present ({path})"));
    } else {
        lines.push(format!(
            "WebAssembly containment: no helper on this node ({path})"
        ));
        lines.push(
            "  this is an opt-in, not a fault: build it with `make wasm`, or leave it off and \
             component hooks and capabilities stay unavailable here"
                .into(),
        );
    }

    lines.push(format!("  helper pool: {}", render_pool(&status)));

    if let Some(reason) = helper.broken_reason.as_deref() {
        lines.push(format!("  broken: {reason}"));
    }

    lines.push(format!(
        "  world: {}{}",
        helper.world.as_deref().unwrap_or("(unknown)"),
        match helper.usable {
            Some(true) => ", helper reports usable",
            Some(false) => ", helper reports NOT usable",
            None => "",
        }
    ));

    if !helper.worlds.is_empty() {
        lines.push(format!("  helper offers: {}", helper.worlds.join(", ")));
    }

    if let Some(limits) = render_limits(helper) {
        lines.push(format!("  limits: {limits}"));
    }

    lines.push(format!(
        "  hook components: {} of {} used{}",
        helper.hook_components,
        helper.hook_component_budget,
        if helper.hook_budget_spent() {
            " — spent; restart the wasm pool before another component hook can load"
        } else {
            ""
        }
    ));

    lines.push(format!("  store: {}", render_store(&status)));
    lines.push(format!("  rollouts: {}", render_rollouts(&status)));
    lines.push(format!(
        "  boot restart: {}",
        if status.boot_enabled {
            "enabled"
        } else {
            "disabled (no data directory, so nothing durable to restart)"
        }
    ));

    lines.join("\n")
}

fn render_pool(status: &WasmStatus) -> String {
    let helper = &status.helper;

    match helper.phase.as_deref() {
        Some("absent") | None => "no pool on this node".into(),
        Some("idle") => "idle (the helper starts on the first component that needs it)".into(),
        Some("ready") => {
            let version = helper
                .wasmtime
                .as_deref()
                .map(|version| format!(", wasmtime {version}"))
                .unwrap_or_default();

            format!(
                "ready{}{version}, {} instance(s), {} owned, {} pending drop(s)",
                helper
                    .os_pid
                    .map(|pid| format!(" (pid {pid})"))
                    .unwrap_or_default(),
                helper.instances,
                helper.owned,
                helper.pending_drops
            )
        }
        Some(other) => other.to_string(),
    }
}

/// The three bounds an operator asks about, out of whatever table the helper reported. A
/// bound this helper does not name is left out rather than guessed at.
fn render_limits(helper: &WasmHelper) -> Option<String> {
    let named = [
        ("max_deadline_ms", "deadline"),
        ("max_memory_bytes", "memory"),
        ("max_component_bytes", "component"),
    ]
    .iter()
    .filter_map(|(key, label)| {
        helper
            .limits
            .get(*key)
            .map(|bound| format!("{label} {bound}"))
    })
    .collect::<Vec<_>>();

    if named.is_empty() {
        None
    } else {
        Some(named.join(", "))
    }
}

fn render_store(status: &WasmStatus) -> String {
    let store = &status.store;

    let Some(root) = store.root.as_deref() else {
        return "none (this node has no data directory)".into();
    };

    let held = match (store.held, store.bytes) {
        (Some(held), Some(bytes)) => format!("{held} component(s), {bytes} byte(s)"),
        _unreadable => "unreadable".into(),
    };

    let budget = store
        .budget_bytes
        .map(|budget| format!(" of {budget} byte(s) budget"))
        .unwrap_or_default();

    let protected = match store.protected {
        Some(protected) => format!(", {protected} protected by a rollout"),
        None => ", protection unknown (the rollout register did not answer)".into(),
    };

    format!("{held}{budget}{protected} in {root}")
}

fn render_rollouts(status: &WasmStatus) -> String {
    let Some(total) = status.rollouts.total else {
        return "unknown (the rollout register did not answer)".into();
    };

    format!(
        "{total} lane-W ({} live, {} deploying, {} quarantined, {} superseded, {} rolled back)",
        status.rollouts.state("live"),
        status.rollouts.state("deploying"),
        status.rollouts.state("quarantined"),
        status.rollouts.state("superseded"),
        status.rollouts.state("rolled_back"),
    )
}

// ===================================================================== the hook narrowing (C6)
//
// The node narrows what a component hook from a workspace nobody trusts may say
// (`lib/ouroboros/provider/native/hooks.ex`, docs/WASM.md D8). `ouro wasm hook` prints that
// narrowing, which means implementing it a second time — so both implementations are pinned to
// one fixture, `test/support/wasm_golden/hook_narrowing.json`, read by a test on each side.
// Nothing below is enforcement: the node's copy is the one that decides anything. This one
// exists so an author can see the decision before they ship the component that provokes it.

/// What an untrusted hook's context lines are labelled with. `hooks.ex`'s
/// `@untrusted_context_prefix`.
pub const UNTRUSTED_CONTEXT_PREFIX: &str = "[untrusted workspace hook] ";

/// `hooks.ex`'s `@max_context_bytes`: how much of one context line survives.
pub const MAX_CONTEXT_BYTES: usize = 8 * 1024;

/// `hooks.ex`'s `@discarded_events`, by their wire names. An untrusted hook is not dispatched
/// on these at all: the turn loop throws the answer away, so running one would buy a clone a
/// read of this session for a verdict nothing consumes.
pub const DISCARDED_EVENTS: [&str; 3] = ["Notification", "FileChanged", "SessionEnd"];

/// Every event this runtime dispatches, by the name a hook declares. `hooks.ex`'s
/// `@event_names`, which is also the vocabulary `--event` accepts.
pub const EVENTS: [&str; 10] = [
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "PreCompact",
    "Notification",
    "FileChanged",
];

/// The runtime's own spelling of an event name, matched the way `event/1` matches it: trimmed
/// and case-insensitive. `None` when this runtime does not dispatch it.
///
/// Case-insensitive because the node is: `@events` is keyed by the downcased name, so a hook
/// declaring `event = "pretooluse"` runs. A `--event` that refused the spelling a workspace may
/// legitimately use would send an author looking for a bug in their component.
pub fn canonical_event(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase();
    EVENTS
        .into_iter()
        .find(|event| event.to_ascii_lowercase() == normalized)
}

/// The three decisions a hook may state, plus the older `block` spelling that means `deny`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Ask,
}

impl Decision {
    fn parse(value: Option<&Value>) -> Option<Decision> {
        match value.and_then(Value::as_str)? {
            "allow" => Some(Decision::Allow),
            "deny" => Some(Decision::Deny),
            "ask" => Some(Decision::Ask),
            // Claude Code's and Factory's older shape.
            "block" => Some(Decision::Deny),
            _other => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Ask => "ask",
        }
    }
}

/// One hook's answer, parsed out of the stdout contract exactly as `Hooks.parse_output/1` reads
/// it: the decision, the input rewrite, and the context lines in the order the seam reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Option<Decision>,
    pub updated_input: Option<Value>,
    pub context: Vec<String>,
}

impl Verdict {
    /// Reads a guest's reply. Anything that is not a JSON object — an empty reply, prose, an
    /// array — is silence, and silence is not consent.
    pub fn parse(reply: &str) -> Verdict {
        let trimmed = reply.trim();
        if trimmed.is_empty() {
            return Verdict::default();
        }

        let Ok(Value::Object(decoded)) = serde_json::from_str::<Value>(trimmed) else {
            return Verdict::default();
        };

        let empty = Map::new();
        let specific = match decoded.get("hookSpecificOutput") {
            Some(Value::Object(map)) => map,
            _absent => &empty,
        };

        // `||` in the Elixir, so a null or false in `hookSpecificOutput` falls through to the
        // top-level key rather than shadowing it. The two keys are not always the same name:
        // a decision is `hookSpecificOutput.permissionDecision` or top-level `decision`.
        let either = |nested: &str, top: &str| -> Option<&Value> {
            match specific.get(nested) {
                Some(value) if !value.is_null() && value != &Value::Bool(false) => Some(value),
                _fall_through => decoded.get(top),
            }
        };

        Verdict {
            decision: Decision::parse(either("permissionDecision", "decision")),
            updated_input: match either("updatedInput", "updatedInput") {
                Some(Value::Object(map)) => Some(Value::Object(map.clone())),
                _not_a_map => None,
            },
            context: [
                specific.get("permissionDecisionReason"),
                specific.get("additionalContext"),
                decoded.get("additionalContext"),
                decoded.get("systemMessage"),
            ]
            .into_iter()
            .flatten()
            .filter_map(context_line)
            .collect(),
        }
    }

    /// The verdict as the node would keep it, and the keys it let go.
    ///
    /// Trusted is identity: narrowing is a property of the lane, never of the verdict, and
    /// nothing here narrows what an operator asked for.
    pub fn narrow(&self, trusted: bool) -> (Verdict, Vec<&'static str>) {
        if trusted {
            return (self.clone(), Vec::new());
        }

        let mut dropped = Vec::new();
        let mut kept = self.clone();

        if kept.decision == Some(Decision::Allow) {
            // `allow` resolves an engine `ask`, which is what takes the human out of the loop.
            kept.decision = None;
            dropped.push("allow");
        }
        if kept.updated_input.is_some() {
            // `updatedInput` replaces the path *and* the content of a call the engine allows.
            kept.updated_input = None;
            dropped.push("updatedInput");
        }

        kept.context = kept.context.iter().map(|line| labelled(line)).collect();
        (kept, dropped)
    }

    fn to_json(&self) -> Value {
        json!({
            "decision": self.decision.map(Decision::as_str),
            "updated_input": self.updated_input.clone(),
            "context": self.context,
        })
    }
}

fn context_line(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    (!text.is_empty()).then(|| clip(text, MAX_CONTEXT_BYTES))
}

/// Labels every **line** of one context string, which is the whole point rather than a detail:
/// one `additionalContext` is one string, a string may carry newlines, and a prefix on line one
/// leaves every line after it reading as text this runtime wrote.
///
/// All three line endings, normalised to `\n` — a lone `\r` is a line break to every reader and
/// a way to redraw over one in a terminal. Clipped after labelling, so the bound holds on what
/// the runtime has already added to.
fn labelled(text: &str) -> String {
    let mut lines = Vec::new();
    let mut rest = text;

    loop {
        let breaks = [rest.find("\r\n"), rest.find('\n'), rest.find('\r')];
        let Some(at) = breaks.into_iter().flatten().min() else {
            lines.push(rest);
            break;
        };
        lines.push(&rest[..at]);
        let width = if rest[at..].starts_with("\r\n") { 2 } else { 1 };
        rest = &rest[at + width..];
    }

    let joined = lines
        .iter()
        .map(|line| format!("{UNTRUSTED_CONTEXT_PREFIX}{line}"))
        .collect::<Vec<_>>()
        .join("\n");

    clip(&joined, MAX_CONTEXT_BYTES)
}

/// `hooks.ex`'s `clip/2`, with one stated divergence: Elixir's `binary_part/3` cuts on a byte
/// and can split a codepoint, where this cuts on the character boundary at or below the limit.
/// Nothing in the fixture reaches the limit; see docs/WASM.md D14.
fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… (truncated)", &text[..end])
}

/// Whether the node would dispatch this hook at all. `hooks.ex`'s `dispatchable?/2`.
pub fn dispatched(event: &str, trusted: bool) -> bool {
    trusted || !DISCARDED_EVENTS.contains(&event)
}

/// The `tool_response` an untrusted `PostToolUse` hook is handed: the shape of the answer
/// without the answer. `hooks.ex`'s `tool_response/2`.
///
/// The output body is what every tool this session ran produced — a file it read, a command's
/// stdout — and a hook that can put text into the next prompt is a way back out for it. What
/// survives is what a "did that fail" hook needs.
pub fn tool_response(response: &Value, trusted: bool) -> Value {
    if trusted {
        return response.clone();
    }

    let Value::Object(map) = response else {
        return json!({ "is_error": false, "bytes": 0 });
    };

    let bytes = map
        .get("output")
        .and_then(Value::as_str)
        .map(str::len)
        .unwrap_or(0);

    json!({
        "is_error": map.get("is_error") == Some(&Value::Bool(true)),
        "bytes": bytes,
    })
}

// ===================================================================== `ouro wasm inspect`

/// What the world admits, and what refused it. Derived from the helper's own answers rather
/// than from a second copy of `world::check`: `inspect` says what the bytes declare, and a
/// `load` of the same bytes is what runs the admission check and names its refusal.
struct Admission {
    /// `Ok(())` when the helper admitted these bytes to its component cache.
    capability: Result<(), wasm_client::Refusal>,
    /// Why a hook would refuse it even so. The hook lane's own bound is tighter than the
    /// helper's: `hooks.ex`'s `@max_component_bytes` is 16 MiB against the helper's 64.
    hook: Option<String>,
}

/// `hooks.ex`'s `@max_component_bytes`, the ceiling a hook or a `[checks]` component is read
/// under. The signing lane's 16 MiB, not the helper's 64: a hook is not the place to discover
/// that a repository shipped sixty megabytes of guest.
pub const HOOK_MAX_COMPONENT_BYTES: u64 = 16 * 1024 * 1024;

/// `hooks.ex`'s `@max_hook_config_bytes`: the string a component's `init` is handed.
pub const MAX_HOOK_CONFIG_BYTES: usize = 16 * 1024;

/// `hooks.ex`'s `@max_matcher_bytes`.
pub const MAX_MATCHER_BYTES: usize = 200;

/// `hooks.ex`'s `@max_check_name_bytes`: how much of a repository-authored name or path may be
/// printed beside a verdict.
pub const MAX_CHECK_NAME_BYTES: usize = 200;

/// `hooks.ex`'s `@max_untrusted_components`: hooks and checks together.
pub const MAX_UNTRUSTED_COMPONENTS: usize = 8;

/// `hooks.ex`'s `@max_hooks` and `@max_checks`.
pub const MAX_HOOKS: usize = 50;
pub const MAX_CHECKS: usize = 20;

/// `hooks.ex`'s `@max_config_bytes`: the `ouroboros.toml` itself.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// `hooks.ex`'s `@component_deadline_ceiling_ms`, which is the helper's `MAX_DEADLINE_MS`.
pub const COMPONENT_DEADLINE_CEILING_MS: u64 = 60_000;

/// `hooks.ex`'s `@default_timeout_ms`.
pub const DEFAULT_HOOK_TIMEOUT_MS: u64 = 60_000;

/// `ouro wasm inspect <file>`: what these bytes are, what shape they have against the bounds
/// that decide whether they compile, and whether the node would admit them.
pub fn inspect<O: Write>(
    helper_path: Option<&Path>,
    file: &Path,
    json: bool,
    out: &mut O,
) -> Result<bool> {
    let binary = wasm_client::resolve(helper_path)?;
    let mut helper = Helper::start(&binary)?;

    let report = helper.doctor()?;
    let inspected = match helper.inspect(file) {
        Ok(inspected) => inspected,
        // A refusal here is about the *bytes* — unreadable, oversize, too complex to compile —
        // and is the answer, not an error in this command.
        Err(error) => {
            let text = render_refused(file, &error, json);
            writeln!(out, "{text}")?;
            out.flush()?;
            return Ok(false);
        }
    };

    let sha = inspected["sha256"].as_str().unwrap_or_default().to_string();
    let admission = Admission {
        capability: match helper.load(&sha, file) {
            Ok(_admitted) => Ok(()),
            Err(error) => Err(refusal_or_bail(error)?),
        },
        hook: hook_refusal(&inspected),
    };

    let text = if json {
        serde_json::to_string_pretty(&inspect_json(&inspected, &report, &admission))?
    } else {
        render_inspect(file, &inspected, &report, &admission)
    };

    writeln!(out, "{text}")?;
    out.flush()?;
    Ok(admission.capability.is_ok())
}

/// Why the hook lane would refuse a component the capability lane admits. Only the byte ceiling
/// differs today; stated as an `Option<String>` so a second reason has somewhere to go.
fn hook_refusal(inspected: &Value) -> Option<String> {
    let size = inspected["size"].as_u64().unwrap_or(0);
    (size > HOOK_MAX_COMPONENT_BYTES).then(|| {
        format!(
            "oversize_component — {size} bytes against the hook lane's {HOOK_MAX_COMPONENT_BYTES}"
        )
    })
}

fn refusal_or_bail(error: anyhow::Error) -> Result<wasm_client::Refusal> {
    match wasm_client::refusal_of(&error) {
        Some(refusal) => Ok(refusal.clone()),
        // Not a refusal: a broken pipe, a helper that died. That is this command failing.
        None => Err(error),
    }
}

fn render_refused(file: &Path, error: &anyhow::Error, json: bool) -> String {
    match wasm_client::refusal_of(error) {
        Some(refusal) if json => serde_json::to_string_pretty(&json!({
            "path": file.to_string_lossy(),
            "admitted": false,
            "refusal": refusal.refusal,
            "message": refusal.message,
        }))
        .unwrap_or_else(|_| refusal.to_string()),
        Some(refusal) => format!(
            "{}\n  refused: {} — {}",
            file.display(),
            refusal.refusal,
            refusal.message
        ),
        None => format!("{}\n  {error}", file.display()),
    }
}

/// The readable report: what it declares, how its shape sits against the bounds that decide
/// whether it compiles at all, and one verdict line.
fn render_inspect(file: &Path, inspected: &Value, report: &Value, admission: &Admission) -> String {
    let mut lines = vec![format!("{}", file.display())];

    lines.push(format!(
        "  world:   {}",
        clean(inspected["world"].as_str().unwrap_or("(unknown)"))
    ));
    lines.push(format!(
        "  sha256:  {}",
        clean(inspected["sha256"].as_str().unwrap_or("(unknown)"))
    ));
    lines.push(format!(
        "  size:    {} byte(s)",
        inspected["size"].as_u64().unwrap_or(0)
    ));
    lines.push(format!("  imports: {}", names(&inspected["imports"])));
    lines.push(format!("  exports: {}", names(&inspected["exports"])));

    if let Some(shape) = inspected["shape"].as_object() {
        lines.push("  shape (the bound in front of the compiler; reading / ceiling):".into());
        for (key, value) in shape {
            let reading = value.as_u64().unwrap_or(0);
            let bound = report["limits"][format!("max_{key}")].as_u64();
            lines.push(match bound {
                Some(bound) => format!(
                    "    {key:<20} {reading:>12} / {bound:<12}{}",
                    headroom(reading, bound)
                ),
                None => format!("    {key:<20} {reading:>12} / (this helper names no bound)"),
            });
        }
    }

    lines.push(verdict_line(admission));
    lines.join("\n")
}

fn headroom(reading: u64, bound: u64) -> String {
    if reading == 0 {
        String::new()
    } else if reading > bound {
        " OVER".to_string()
    } else {
        format!(" {}×", bound / reading.max(1))
    }
}

fn verdict_line(admission: &Admission) -> String {
    match (&admission.capability, &admission.hook) {
        (Ok(()), None) => {
            "  verdict: admitted — as a capability and as a hook component".to_string()
        }
        (Ok(()), Some(reason)) => format!(
            "  verdict: admitted as a capability; refused as a hook component: {}",
            clean(reason)
        ),
        (Err(refusal), _) => format!(
            "  verdict: neither — refused {}: {}",
            clean(&refusal.refusal),
            clean(&refusal.message)
        ),
    }
}

fn inspect_json(inspected: &Value, report: &Value, admission: &Admission) -> Value {
    let mut value = inspected.clone();
    value["limits"] = report["limits"].clone();
    value["admitted_as_capability"] = json!(admission.capability.is_ok());
    value["admitted_as_hook"] = json!(admission.capability.is_ok() && admission.hook.is_none());
    value["refusal"] = match (&admission.capability, &admission.hook) {
        (Err(refusal), _) => json!({
            "refusal": refusal.refusal,
            "message": refusal.message,
            "lane": "both",
        }),
        (Ok(()), Some(reason)) => json!({ "message": reason, "lane": "hook" }),
        (Ok(()), None) => Value::Null,
    };
    value
}

fn names(value: &Value) -> String {
    match value.as_array() {
        Some(names) if !names.is_empty() => names
            .iter()
            .filter_map(Value::as_str)
            .map(clean)
            .collect::<Vec<_>>()
            .join(", "),
        _none => "(none)".to_string(),
    }
}

/// Sanitized and clipped: every string here was chosen by whoever wrote the component.
fn clean(text: &str) -> String {
    clip(&wasm_client::sanitize(text), MAX_CHECK_NAME_BYTES)
}

// ========================================================================= `ouro wasm run`

/// What `ouro wasm run` was asked to do. A struct rather than nine arguments, because the two
/// callers — the dispatch arm and its test — should be reading the same field names.
pub struct RunRequest<'a> {
    pub helper: Option<&'a Path>,
    pub file: &'a Path,
    pub config: String,
    pub messages: Vec<String>,
    pub limits: Limits,
    pub describe: bool,
    pub json: bool,
}

/// One message's outcome, kept so the whole run can be rendered at once.
struct Answered {
    message: String,
    outcome: Result<String, wasm_client::Refusal>,
    fuel_used: u64,
    logs: Vec<String>,
    wall_ms: u128,
}

/// `ouro wasm run`: load, instantiate once, and send every message to the **same** instance.
///
/// The same instance on purpose. State is instance-held in this world, so a capability that
/// counts messages or keeps what its `init` was given can only be exercised by a second message
/// to the guest that answered the first — and a fresh instance per message would quietly test a
/// different component from the one that gets deployed.
pub fn run<O: Write>(request: &RunRequest, out: &mut O) -> Result<bool> {
    let binary = wasm_client::resolve(request.helper)?;
    let mut helper = Helper::start(&binary)?;

    let report = helper.doctor()?;
    let (limits, moved) = request.limits.clamped(&report["limits"]);

    let inspected = helper.inspect(request.file)?;
    let sha = inspected["sha256"].as_str().unwrap_or_default().to_string();

    // `inspect` recomputed the digest from the bytes it read and `load` recomputes it again:
    // a file swapped between the two is a `sha_mismatch` refusal rather than a substituted
    // component. Nothing here signs anything — a developer named this file — so the digest is
    // the cache key and the swap detector, and is not claimed to be more.
    helper.load(&sha, request.file).map_err(name_the_refusal)?;

    let instance = "ouro-wasm-run";
    helper
        .instantiate(instance, &sha, &request.config, limits)
        .map_err(name_the_refusal)?;

    let described = if request.describe {
        let mark = helper.log_mark();
        let (described, expected) = match helper.call(instance, "describe", "") {
            Ok(result) => (
                Ok(wasm_client::sanitize(
                    result["payload"].as_str().unwrap_or_default(),
                )),
                result["log_lines"].as_u64().unwrap_or(0),
            ),
            Err(error) => (Err(refusal_or_bail(error)?), 0),
        };
        Some((described, helper.guest_log_counted(mark, expected)))
    } else {
        None
    };

    let mut answered = Vec::new();
    for message in &request.messages {
        let mark = helper.log_mark();
        let started = Instant::now();
        let reply = helper.call(instance, "handle-message", message);
        let wall_ms = started.elapsed().as_millis();
        let expected_logs = reply
            .as_ref()
            .ok()
            .and_then(|result| result["log_lines"].as_u64())
            .unwrap_or(0);

        let (outcome, fuel_used) = match reply {
            Ok(result) => (
                Ok(wasm_client::sanitize(
                    result["payload"].as_str().unwrap_or_default(),
                )),
                result["fuel_used"].as_u64().unwrap_or(0),
            ),
            Err(error) => (Err(refusal_or_bail(error)?), 0),
        };

        answered.push(Answered {
            message: message.clone(),
            outcome,
            fuel_used,
            // Read after the answer, and only once the lines the reply counted have arrived:
            // the helper's stderr is a different pipe from its stdout, so a line the guest
            // wrote during the call can land just after the reply to it.
            logs: helper.guest_log_counted(mark, expected_logs),
            wall_ms,
        });
    }

    // Always, and before the report: a trapped instance is already gone server-side, and a
    // live one is this process's to let go of.
    let _ = helper.drop_instance(instance);

    let ok = answered.iter().all(|answer| answer.outcome.is_ok());
    let text = if request.json {
        serde_json::to_string_pretty(&run_json(
            &inspected, &limits, &moved, &described, &answered,
        ))?
    } else {
        render_run(&inspected, &limits, &moved, &described, &answered)
    };

    writeln!(out, "{text}")?;
    out.flush()?;
    Ok(ok)
}

type Described = Option<(Result<String, wasm_client::Refusal>, Vec<String>)>;

fn render_run(
    inspected: &Value,
    limits: &Limits,
    moved: &[String],
    described: &Described,
    answered: &[Answered],
) -> String {
    let mut lines = vec![
        format!(
            "world {}, sha256 {}",
            clean(inspected["world"].as_str().unwrap_or("(unknown)")),
            clean(inspected["sha256"].as_str().unwrap_or("(unknown)"))
        ),
        format!(
            "bounds: fuel {}, memory {} byte(s), deadline {} ms",
            limits.fuel, limits.memory_bytes, limits.deadline_ms
        ),
    ];

    for note in moved {
        lines.push(format!("  clamped: {note}"));
    }

    if let Some((described, logs)) = described {
        lines.push(String::new());
        match described {
            Ok(text) => lines.push(format!("describe: {}", clip(text, 4 * 1024))),
            Err(refusal) => lines.push(format!(
                "describe refused {}: {}",
                clean(&refusal.refusal),
                clean(&refusal.message)
            )),
        }
        for line in logs {
            lines.push(format!("  log: {line}"));
        }
    }

    for (index, answer) in answered.iter().enumerate() {
        lines.push(String::new());
        lines.push(format!(
            "message {}: {}",
            index + 1,
            clip(&answer.message, 512)
        ));
        match &answer.outcome {
            Ok(reply) => lines.push(format!("  reply: {}", clip(reply, 8 * 1024))),
            Err(refusal) => lines.push(format!(
                "  refused {}: {}",
                clean(&refusal.refusal),
                clean(&refusal.message)
            )),
        }
        for line in &answer.logs {
            lines.push(format!("  log: {line}"));
        }
        lines.push(format!(
            "  fuel {} used, {} ms wall",
            answer.fuel_used, answer.wall_ms
        ));
    }

    lines.join("\n")
}

fn run_json(
    inspected: &Value,
    limits: &Limits,
    moved: &[String],
    described: &Described,
    answered: &[Answered],
) -> Value {
    json!({
        "world": inspected["world"],
        "sha256": inspected["sha256"],
        "limits": {
            "fuel": limits.fuel,
            "memory_bytes": limits.memory_bytes,
            "deadline_ms": limits.deadline_ms,
            "clamped": moved,
        },
        "describe": described.as_ref().map(|(described, logs)| match described {
            Ok(text) => json!({ "payload": text, "log": logs }),
            Err(refusal) => json!({ "refusal": refusal.refusal, "message": refusal.message }),
        }),
        "messages": answered.iter().map(|answer| match &answer.outcome {
            Ok(reply) => json!({
                "message": answer.message,
                "reply": reply,
                "fuel_used": answer.fuel_used,
                "log": answer.logs,
                "wall_ms": answer.wall_ms,
            }),
            Err(refusal) => json!({
                "message": answer.message,
                "refusal": refusal.refusal,
                "refusal_message": refusal.message,
                "log": answer.logs,
                "wall_ms": answer.wall_ms,
            }),
        }).collect::<Vec<_>>(),
    })
}

/// A refusal that stopped the whole run — a `load` or an `instantiate` — reads better with its
/// name in front of it than as anyhow's chain.
fn name_the_refusal(error: anyhow::Error) -> anyhow::Error {
    match wasm_client::refusal_of(&error) {
        Some(refusal) => anyhow!(
            "the helper refused: {} — {}",
            clean(&refusal.refusal),
            clean(&refusal.message)
        ),
        None => error,
    }
}

// ======================================================================== `ouro wasm hook`

/// What `ouro wasm hook` was asked to do.
pub struct HookRequest<'a> {
    pub helper: Option<&'a Path>,
    pub file: &'a Path,
    pub event: String,
    pub payload: Value,
    pub config: String,
    pub trusted: bool,
    pub timeout_ms: u64,
    pub json: bool,
}

/// `ouro wasm hook`: run the component the way `hooks.ex`'s `invoke/3` would, and print both
/// verdicts — what the component said, and what the node would keep.
///
/// The point of showing both is that the second is the only one that ever reaches a turn. An
/// author who tests a hook by reading its own output is testing a verdict the runtime may have
/// already dropped; this is the same rules, applied where they can be seen.
pub fn hook<O: Write>(request: &HookRequest, out: &mut O) -> Result<bool> {
    // Everything a node would refuse this request for, before a helper is started: a helper
    // started to be told the request was malformed is a process spawned for nothing.
    //
    // Case-insensitively, because `event/1` downcases before it looks the name up — a hook
    // declaring `event = "pretooluse"` runs on the node, so `--event pretooluse` has to print
    // the narrowing for the hook that runs rather than refuse a spelling the runtime accepts.
    let Some(event) = canonical_event(&request.event) else {
        bail!(
            "`{}` is not a hook event. This runtime dispatches: {}",
            clean(&request.event),
            EVENTS.join(", ")
        );
    };
    if request.config.len() > MAX_HOOK_CONFIG_BYTES {
        bail!(
            "`--config` is {} bytes; a hook's declared `config` is bounded at \
             {MAX_HOOK_CONFIG_BYTES} — it is repository text that crosses into a guest's memory, \
             and a config is a switch rather than a corpus",
            request.config.len()
        );
    }

    let binary = wasm_client::resolve(request.helper)?;
    let mut helper = Helper::start(&binary)?;

    // The payload the seam builds: whatever the author supplied, with the event name set by
    // the runtime — in the runtime's own spelling, which is what `@event_names` puts on the
    // wire whatever the author typed — and, for the two post events, the response narrowed on
    // the way *in*.
    let mut payload = match request.payload.clone() {
        Value::Object(map) => map,
        _not_an_object => Map::new(),
    };
    payload.insert("hook_event_name".into(), json!(event));

    let narrowed_response = payload.get("tool_response").map(|response| {
        let kept = tool_response(response, request.trusted);
        (response.clone(), kept)
    });
    if let Some((_raw, kept)) = &narrowed_response {
        payload.insert("tool_response".into(), kept.clone());
    }

    let dispatched = dispatched(event, request.trusted);

    // The node's own bounds: `Wasm.capability_limits()` with the one bound a hook declares for
    // itself substituted in, and never above the component deadline ceiling. There is no second
    // limits block, exactly as there is none in `hooks.ex`.
    let report = helper.doctor()?;
    let (limits, moved) = Limits {
        deadline_ms: request.timeout_ms.min(COMPONENT_DEADLINE_CEILING_MS),
        ..NODE_DEFAULT_LIMITS
    }
    .clamped(&report["limits"]);

    // Statted and bounded before the helper is told anything about it, which is the order
    // `read_component/1` uses: `hooks.ex` stats for a regular file under `@max_component_bytes`
    // and only then hashes and loads. Doing it after `inspect` would mean a sixty-megabyte file
    // was read and walked before anybody said it was too big for this lane.
    let metadata = std::fs::metadata(request.file)
        .with_context(|| format!("could not read {}", request.file.display()))?;
    if !metadata.is_file() {
        bail!(
            "not_a_regular_file: {} is not a regular file",
            request.file.display()
        );
    }
    if metadata.len() > HOOK_MAX_COMPONENT_BYTES {
        bail!(
            "oversize_component: {} bytes against the hook lane's {HOOK_MAX_COMPONENT_BYTES}",
            metadata.len()
        );
    }

    let inspected = helper.inspect(request.file)?;
    let sha = inspected["sha256"].as_str().unwrap_or_default().to_string();
    helper.load(&sha, request.file).map_err(name_the_refusal)?;

    // One instance, one message, always dropped — the whole state story of a hook run.
    let instance = "hook/ouro-wasm-hook";
    helper
        .instantiate(instance, &sha, &request.config, limits)
        .map_err(name_the_refusal)?;

    let mark = helper.log_mark();
    let body = serde_json::to_string(&Value::Object(payload.clone()))?;
    let replied = helper.call(instance, "handle-message", &body);
    let expected_logs = replied
        .as_ref()
        .ok()
        .and_then(|result| result["log_lines"].as_u64())
        .unwrap_or(0);
    let logs = helper.guest_log_counted(mark, expected_logs);
    let _ = helper.drop_instance(instance);

    let reply = match replied {
        Ok(result) => result["payload"].as_str().unwrap_or_default().to_string(),
        Err(error) => {
            let refusal = refusal_or_bail(error)?;
            // A hook that failed to run is not consent and not a denial: the node reports it
            // and carries on with silence, so this says the same thing.
            writeln!(
                out,
                "the hook did not run: {} — {}\nthe node would treat this as silence, which is \
                 not consent",
                clean(&refusal.refusal),
                clean(&refusal.message)
            )?;
            out.flush()?;
            return Ok(false);
        }
    };

    let raw = Verdict::parse(&reply);
    let (kept, dropped) = if dispatched {
        raw.narrow(request.trusted)
    } else {
        (Verdict::default(), vec!["dispatch"])
    };

    let text = if request.json {
        serde_json::to_string_pretty(&json!({
            "event": event,
            "lane": lane(request.trusted),
            "dispatched": dispatched,
            "payload": Value::Object(payload),
            "tool_response": narrowed_response.as_ref().map(|(raw, kept)| json!({
                "raw": raw, "kept": kept,
            })),
            "reply": wasm_client::sanitize(&reply),
            "raw_verdict": raw.to_json(),
            "kept_verdict": kept.to_json(),
            "dropped": dropped,
            "log": logs,
            "limits": { "deadline_ms": limits.deadline_ms, "clamped": moved },
        }))?
    } else {
        render_hook(
            request,
            &HookReport {
                event,
                dispatched,
                narrowed_response: &narrowed_response,
                raw: &raw,
                kept: &kept,
                dropped: &dropped,
                logs: &logs,
            },
        )
    };

    writeln!(out, "{text}")?;
    out.flush()?;
    Ok(true)
}

fn lane(trusted: bool) -> &'static str {
    if trusted {
        "trusted"
    } else {
        "untrusted"
    }
}

/// One hook run's outcome, gathered so the renderer takes a request and an answer rather than
/// eight positional arguments nobody can read at the call site.
struct HookReport<'a> {
    event: &'a str,
    dispatched: bool,
    /// The `tool_response` as it arrived and as it was sent, when there was one.
    narrowed_response: &'a Option<(Value, Value)>,
    raw: &'a Verdict,
    kept: &'a Verdict,
    dropped: &'a [&'a str],
    logs: &'a [String],
}

fn render_hook(request: &HookRequest, report: &HookReport) -> String {
    let HookReport {
        event,
        dispatched,
        narrowed_response,
        raw,
        kept,
        dropped,
        logs,
    } = *report;

    let mut lines = vec![format!("{} on the {} lane", event, lane(request.trusted))];

    if !dispatched {
        lines.push(format!(
            "  NOT DISPATCHED: the turn loop discards what a {} hook returns, so an untrusted \
             one is not run at all. Everything below is what it *would* have said.",
            event
        ));
    }

    if let Some((raw_response, kept_response)) = narrowed_response {
        lines.push("  payload narrowing (on the way in):".into());
        lines.push(format!(
            "    tool_response given: {}",
            compact(raw_response)
        ));
        lines.push(format!(
            "    tool_response sent:  {}",
            compact(kept_response)
        ));
        if raw_response != kept_response {
            lines.push(
                "    the output body is dropped: a hook that can put text into the next prompt \
                 is a way back out for whatever a tool produced"
                    .into(),
            );
        }
    }

    for line in logs {
        lines.push(format!("  log: {line}"));
    }

    lines.push(String::new());
    lines.push("raw verdict (what the component said):".into());
    lines.extend(render_verdict(raw));

    lines.push(String::new());
    lines.push(format!(
        "kept verdict (what the node would act on, {} lane):",
        lane(request.trusted)
    ));
    lines.extend(render_verdict(kept));

    lines.push(String::new());
    if dropped.is_empty() {
        lines.push("dropped: nothing — this verdict reaches the turn whole".into());
    } else {
        lines.push("dropped:".into());
        for key in dropped {
            lines.push(format!("  {key} — {}", why_dropped(key)));
        }
    }

    lines.join("\n")
}

fn render_verdict(verdict: &Verdict) -> Vec<String> {
    let mut lines = vec![format!(
        "  decision:      {}",
        verdict
            .decision
            .map(Decision::as_str)
            .unwrap_or("(none — silence, which is not consent)")
    )];

    lines.push(format!(
        "  updatedInput:  {}",
        match &verdict.updated_input {
            Some(value) => compact(value),
            None => "(none)".to_string(),
        }
    ));

    if verdict.context.is_empty() {
        lines.push("  context:       (none)".into());
    } else {
        lines.push("  context:".into());
        for line in &verdict.context {
            for physical in wasm_client::sanitize(line).split('\n') {
                lines.push(format!("    {physical}"));
            }
        }
    }

    lines
}

fn why_dropped(key: &str) -> &'static str {
    match key {
        "allow" => {
            "an untrusted component may make a decision stricter and never looser; `allow` is \
             what resolves an engine `ask`, so it is read as silence"
        }
        "updatedInput" => {
            "it replaces the path and the content of a call the engine then allows, which is \
             authority rather than annotation"
        }
        "dispatch" => {
            "the runtime discards this event's answer, so dispatching an untrusted hook on it \
             would buy a clone a read of this session for a verdict nothing consumes"
        }
        _other => "narrowed by the untrusted lane",
    }
}

fn compact(value: &Value) -> String {
    clip(
        &wasm_client::sanitize(&serde_json::to_string(value).unwrap_or_default()),
        2 * 1024,
    )
}

// ===================================================== reading files somebody else wrote
//
// Every file below is one a *developer* named and somebody *else* wrote: an `ouroboros.toml`
// out of a clone, a payload, a file of messages. Three properties, and review proved that
// having two of them is having none.
//
//   * **A regular file.** `metadata()` follows symlinks and answers without opening, so a
//     `ouroboros.toml -> /dev/zero` is refused here rather than discovered by the read. That
//     matters more than it sounds: `metadata().len()` on a character device is *zero*, so a
//     size bound taken from it passes, and the `read_to_string` after it never ends. Measured
//     against the version this replaces: still reading after eight seconds, at 13 GB resident.
//     The same check refuses a FIFO before anything opens it — `open` on a FIFO with no writer
//     blocks in the kernel, and a path is somebody else's string.
//   * **A bound taken from the read, not from the stat.** `take(limit + 1)` and a length
//     comparison afterwards, so the bound holds whatever the stat said. This is the shape
//     `host.rs`'s `read_component` already uses, for the same reason.
//   * **A named refusal.** An author who pointed at the wrong file is owed which rule it broke.

/// The largest hook payload `--payload` will read. A hook payload is a JSON object describing
/// one tool call; a mebibyte is three orders of magnitude above any real one and still small
/// enough to be a bound rather than a gesture.
pub const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;

/// The largest `--messages` file. The helper's own frame cap, because a file of JSON lines is
/// at most a sequence of message bodies and a body larger than one frame could never be sent.
pub const MAX_MESSAGES_BYTES: u64 = 8 * 1024 * 1024;

/// Reads a regular file, bounded, refusing anything that is not one.
fn read_bounded(path: &Path, limit: u64, what: &str) -> Result<String> {
    // Before opening it, not after: `metadata` follows symlinks and answers without blocking,
    // so a link to a device or a FIFO is refused here rather than in the kernel.
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("could not read {what} {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "{what} {} is not a regular file; a device, a directory or a FIFO is not a file \
             this reads",
            path.display()
        );
    }

    let file = std::fs::File::open(path)
        .with_context(|| format!("could not open {what} {}", path.display()))?;

    // One byte past the cap, so an over-cap file is detected without being read whole.
    let mut content = String::new();
    file.take(limit + 1)
        .read_to_string(&mut content)
        .with_context(|| format!("could not read {what} {}", path.display()))?;

    if content.len() as u64 > limit {
        bail!(
            "{what} {} is larger than the {limit} byte cap",
            path.display()
        );
    }
    Ok(content)
}

/// Standard input, under the same bound. `-` is a developer saying "from a pipe", and a pipe is
/// as unbounded as a file is.
fn read_bounded_stdin(limit: u64, what: &str) -> Result<String> {
    let mut content = String::new();
    std::io::stdin()
        .lock()
        .take(limit + 1)
        .read_to_string(&mut content)
        .with_context(|| format!("could not read {what} from standard input"))?;

    if content.len() as u64 > limit {
        bail!("{what} on standard input is larger than the {limit} byte cap");
    }
    Ok(content)
}

/// `--message` first, then `--messages`, in file order.
///
/// A line that is not JSON is refused rather than sent: the helper would take it as a body, and
/// a developer who meant a message should be told they wrote something else.
pub fn read_messages(inline: &[String], file: Option<&Path>) -> Result<Vec<String>> {
    let mut messages = inline.to_vec();

    if let Some(path) = file {
        let content = read_bounded(path, MAX_MESSAGES_BYTES, "the messages file")?;
        for (number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            serde_json::from_str::<Value>(line)
                .with_context(|| format!("{}:{}: not a JSON line", path.display(), number + 1))?;
            messages.push(line.to_string());
        }
    }

    if messages.is_empty() {
        bail!("nothing to send: pass --message '<json>' or --messages <file>");
    }
    Ok(messages)
}

/// The hook payload: a file, `-` for standard input, or an empty object.
pub fn read_payload(source: Option<&str>) -> Result<Value> {
    let text = match source {
        None => return Ok(json!({})),
        Some("-") => read_bounded_stdin(MAX_PAYLOAD_BYTES, "the hook payload")?,
        Some(path) => read_bounded(Path::new(path), MAX_PAYLOAD_BYTES, "the hook payload")?,
    };

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(trimmed).context("the hook payload is not JSON")
}

// ====================================================================== `ouro wasm check`

/// One `[[hooks]]` or `[checks]` entry, as `check` read it and judged it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `[[hooks]] #3` or `[checks] lint` — the name the node's own error text uses.
    pub label: String,
    pub target: String,
    pub verdict: EntryVerdict,
    /// Whether this entry declared a `matcher` this command could not decide.
    ///
    /// A field rather than a verdict, because it is orthogonal to one: an entry with an
    /// unverified matcher is otherwise perfectly admissible, and an entry refused for its path
    /// had a matcher nobody got to. See [`MatcherState`].
    pub matcher: MatcherState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryVerdict {
    /// A `command =` entry. Not this command's business — an untrusted workspace's shell hooks
    /// are declined by `Hooks.trusted?/2` and always were — but counted and shown, because an
    /// author looking at a table with a hole in it will wonder what fell in it.
    Command,
    /// Admissible: inside the workspace, under every bound, and in the world.
    Admitted,
    /// Refused, with the name the node would use.
    Refused(String),
}

impl EntryVerdict {
    fn refused(&self) -> bool {
        matches!(self, EntryVerdict::Refused(_))
    }
}

/// What this command could say about an entry's `matcher`.
///
/// The node compiles it as a PCRE, twice — alone, and then inside `\A(?:…)\z`. `ouro` carries no
/// regex engine, and adding one to decide a single TOML field would put a large dependency in
/// the client's graph to answer a question the node answers anyway.
///
/// So this command does not answer it, and — this is the half review had to correct — it no
/// longer *pretends* to. The first version guessed with a parenthesis-balance check, which was
/// wrong in both directions: it passed `matcher = "*"`, which the node refuses (`quantifier does
/// not follow a repeatable item`) while `check` printed "every component entry would be
/// admitted" and exited 0; and it refused `matcher = "\Q(\E"`, which the node compiles happily,
/// because a quoted literal paren opens no group. A heuristic wrong in both directions is worse
/// than no answer, because an author reads it as one.
///
/// What is left is what can be decided here exactly: the 200-byte bound. The rest is reported as
/// unverified, and the summary will not use the word "admitted" while any row carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatcherState {
    /// No `matcher` was declared, so nothing is left undecided.
    Absent,
    /// A `matcher` was declared and is within its byte bound; whether it *compiles* is the
    /// node's answer to give.
    Unverified,
}

/// `ouro wasm check`: read a workspace's `ouroboros.toml` and say which of its component
/// entries the node would admit **from a workspace nobody trusts**, which is the strict case.
///
/// It never instantiates anything. Admission is a question about a file's path, its size, its
/// world and the count of its siblings; running the component answers none of it, and running
/// eight components to find out whether eight components are allowed would be an odd way to
/// enforce a bound on eight components.
pub fn check<O: Write>(
    helper_path: Option<&Path>,
    workspace: &Path,
    json: bool,
    out: &mut O,
) -> Result<bool> {
    let root = std::fs::canonicalize(workspace)
        .with_context(|| format!("no workspace at {}", workspace.display()))?;
    let document = read_workspace_toml(&root)?;

    let binary = wasm_client::resolve(helper_path)?;
    let mut helper = Helper::start(&binary)?;

    let entries = check_entries(&root, &document, &mut helper)?;
    // Exit code says *refused*, never *unverified*: an entry this command could not decide is
    // not an entry it may fail a build over, and an author who wired `ouro wasm check` into a
    // pre-commit hook should not have it break on a matcher the node compiles fine.
    let ok = !entries.iter().any(|entry| entry.verdict.refused());
    let unverified = entries
        .iter()
        .filter(|entry| entry.matcher == MatcherState::Unverified)
        .count();

    let text = if json {
        serde_json::to_string_pretty(&json!({
            "workspace": root.to_string_lossy(),
            "trust": "untrusted",
            "helper": binary.path().to_string_lossy(),
            "refused": entries.iter().filter(|entry| entry.verdict.refused()).count(),
            "unverified_matchers": unverified,
            // Deliberately not a key called `admitted`: nothing here can say a workspace is
            // admissible while a matcher it declared is still the node's to compile.
            "no_refusals": ok,
            "entries": entries.iter().map(|entry| json!({
                "entry": entry.label,
                "target": entry.target,
                "verdict": match &entry.verdict {
                    EntryVerdict::Command => json!("command"),
                    EntryVerdict::Admitted => json!("admitted"),
                    EntryVerdict::Refused(reason) => json!({ "refused": reason }),
                },
                "matcher": match entry.matcher {
                    MatcherState::Absent => json!(null),
                    MatcherState::Unverified => json!("unverified"),
                },
            })).collect::<Vec<_>>(),
        }))?
    } else {
        render_check(&root, &binary, &entries)
    };

    writeln!(out, "{text}")?;
    out.flush()?;
    Ok(ok)
}

fn read_workspace_toml(root: &Path) -> Result<toml::Value> {
    let path = root.join("ouroboros.toml");
    // Regular-file and bounded, exactly as `read_config/1` is — `hooks.ex` stats for
    // `type: :regular` before it reads, and so does this. See `read_bounded` for what a
    // size bound taken from a stat is worth against a device.
    let content = read_bounded(&path, MAX_CONFIG_BYTES, "ouroboros.toml")?;
    toml::from_str(&content).with_context(|| format!("{}: not valid TOML", path.display()))
}

/// One entry after parsing, before the untrusted budget is spent on it.
///
/// The split into two passes is the node's own and review had to point that out: `hooks_from/4`
/// runs `build/4` over every entry and puts the failures in `errors`, and only what *survived*
/// reaches `cap_untrusted/2`. So an entry with a path that does not resolve costs a repository
/// nothing — where the first version of this command charged it a slot, and five broken paths
/// could therefore hide five good components behind a budget that was never really spent.
enum Parsed {
    /// Refused before the budget: bad grammar, or a path outside the workspace.
    Refused(Entry),
    /// A `command =` entry. Declined untrusted, and never a component, so never budgeted.
    Command(Entry),
    /// A component the node would have built. `path` is canonical and inside the root.
    Component {
        label: String,
        target: String,
        matcher: MatcherState,
        path: PathBuf,
    },
}

/// The whole admission pass, as a function of the document so a test can hand it one.
///
/// Order is the node's: `[[hooks]]` in document order, then `[checks]` sorted by name, with one
/// untrusted-component budget spent across both — a repository cannot double it by moving half
/// its components into `[checks]` — and spent only on entries that parsed.
fn check_entries(root: &Path, document: &toml::Value, helper: &mut Helper) -> Result<Vec<Entry>> {
    // `MAX_HOOKS` is the node's cap across *all three* scopes, and this reads only the
    // workspace's — so applying it here is a superset of what a node would take. It never
    // decides anything in practice: the untrusted component budget is eight and bites first.
    // The two take-caps are reported rather than applied silently, because an entry missing
    // from a table an author is reading is indistinguishable from one that passed.
    let hooks = hook_tables(document);
    let checks = check_tables(document);

    let mut parsed: Vec<Parsed> = Vec::new();
    for (index, hook) in hooks.iter().take(MAX_HOOKS).enumerate() {
        parsed.push(parse_hook(root, hook, index + 1));
    }
    if hooks.len() > MAX_HOOKS {
        parsed.push(Parsed::Refused(truncated(
            "[[hooks]]",
            hooks.len(),
            MAX_HOOKS,
        )));
    }
    for (name, check) in checks.iter().take(MAX_CHECKS) {
        parsed.push(parse_check(root, name, check));
    }
    if checks.len() > MAX_CHECKS {
        parsed.push(Parsed::Refused(truncated(
            "[checks]",
            checks.len(),
            MAX_CHECKS,
        )));
    }

    let mut entries = Vec::new();
    let mut spent = 0usize;
    for one in parsed {
        entries.push(match one {
            Parsed::Refused(entry) | Parsed::Command(entry) => entry,
            Parsed::Component {
                label,
                target,
                matcher,
                path,
            } => {
                spent += 1;
                if spent > MAX_UNTRUSTED_COMPONENTS {
                    refused(
                        label,
                        &target,
                        &format!(
                            "an untrusted workspace may run {MAX_UNTRUSTED_COMPONENTS} \
                             components; this is #{spent} and was declined"
                        ),
                    )
                    .with_matcher(matcher)
                } else {
                    admit(label, target, matcher, &path, helper)?
                }
            }
        });
    }

    Ok(entries)
}

fn truncated(table: &str, declared: usize, cap: usize) -> Entry {
    Entry {
        label: table.to_string(),
        target: format!("{declared} declared"),
        verdict: EntryVerdict::Refused(format!(
            "only the first {cap} are read; {} beyond that are never loaded",
            declared - cap
        )),
        matcher: MatcherState::Absent,
    }
}

fn hook_tables(document: &toml::Value) -> Vec<toml::Value> {
    match document.get("hooks") {
        Some(toml::Value::Array(entries)) => entries.clone(),
        Some(one) => vec![one.clone()],
        None => Vec::new(),
    }
}

/// `[checks]` is a table, and the node sorts it before it takes the first twenty: a map has no
/// document order, so without the sort "the first twenty" would be whichever twenty the parser
/// happened to hand over.
fn check_tables(document: &toml::Value) -> Vec<(String, toml::Value)> {
    let Some(toml::Value::Table(table)) = document.get("checks") else {
        return Vec::new();
    };
    let sorted: BTreeMap<String, toml::Value> = table
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    sorted.into_iter().collect()
}

/// Everything `build/4` decides about one `[[hooks]]` entry, and nothing the node decides later.
fn parse_hook(root: &Path, hook: &toml::Value, index: usize) -> Parsed {
    let label = format!("[[hooks]] #{index}");
    let command = hook.get("command");
    let component = hook.get("component");

    // Exactly one of the two. Both is ambiguous and neither is nothing to run.
    let target = match (command, component) {
        (None, None) => {
            return Parsed::Refused(refused(
                label,
                "(none)",
                "has no `command` and no `component`",
            ))
        }
        (Some(_), Some(_)) => {
            return Parsed::Refused(refused(
                label,
                "(both)",
                "declares both `command` and `component`; a hook is one or the other",
            ))
        }
        (Some(command), None) => {
            // A `command =` hook takes no `config`: a command hook has no `init`, so `config` on
            // one is a mistake worth a line rather than a value silently ignored.
            let shown_command = clean(command.as_str().unwrap_or("(not a string)"));
            if hook.get("config").is_some() {
                return Parsed::Refused(refused(
                    label,
                    &shown_command,
                    "`config` is only meaningful for a `component` hook",
                ));
            }
            if let Some(reason) = event_refusal(hook) {
                return Parsed::Refused(refused(label, &shown_command, &reason));
            }
            return Parsed::Command(Entry {
                label,
                target: shown_command,
                verdict: EntryVerdict::Command,
                matcher: MatcherState::Absent,
            });
        }
        (None, Some(component)) => component,
    };

    let shown_target = shown(target);
    if let Some(reason) = event_refusal(hook) {
        return Parsed::Refused(refused(label, &shown_target, &reason));
    }
    let matcher = match matcher_state(hook) {
        Ok(state) => state,
        Err(reason) => return Parsed::Refused(refused(label, &shown_target, &reason)),
    };
    if let Some(reason) = config_refusal(hook) {
        return Parsed::Refused(refused(label, &shown_target, &reason).with_matcher(matcher));
    }

    match resolve_component(root, target) {
        Ok(path) => Parsed::Component {
            label,
            target: shown_target,
            matcher,
            path,
        },
        Err(reason) => {
            Parsed::Refused(refused(label, &shown_target, &reason).with_matcher(matcher))
        }
    }
}

fn event_refusal(hook: &toml::Value) -> Option<String> {
    match hook.get("event").and_then(toml::Value::as_str) {
        None => Some("has no `event`".into()),
        Some(name) if canonical_event(name).is_none() => {
            Some(format!("`{}` is not a hook event", clean(name)))
        }
        Some(_known) => None,
    }
}

/// The `matcher` field, decided as far as it can be decided here. See [`MatcherState`].
fn matcher_state(hook: &toml::Value) -> Result<MatcherState, String> {
    let Some(matcher) = hook.get("matcher") else {
        return Ok(MatcherState::Absent);
    };
    match matcher.as_str() {
        None => Err("`matcher` must be a string".into()),
        // An empty or blank matcher is `nil` to the node — `matcher/1` trims and returns
        // `{:ok, nil}` — so there is nothing left for anybody to compile.
        Some(pattern) if pattern.trim().is_empty() => Ok(MatcherState::Absent),
        Some(pattern) if pattern.len() > MAX_MATCHER_BYTES => Err(format!(
            "`matcher` is {} bytes; the limit is {MAX_MATCHER_BYTES}",
            pattern.len()
        )),
        Some(_bounded) => Ok(MatcherState::Unverified),
    }
}

fn config_refusal(table: &toml::Value) -> Option<String> {
    match table.get("config") {
        None => None,
        Some(value) => match value.as_str() {
            None => Some("`config` must be a string".into()),
            Some(config) if config.len() > MAX_HOOK_CONFIG_BYTES => Some(format!(
                "`config` is {} bytes; the limit is {MAX_HOOK_CONFIG_BYTES}",
                config.len()
            )),
            Some(_bounded) => None,
        },
    }
}

/// Everything `check/5` decides about one `[checks]` entry.
fn parse_check(root: &Path, name: &str, check: &toml::Value) -> Parsed {
    let label = format!("[checks] {}", clean(name));

    match check {
        // A bare **non-empty** string is a command check. An empty one matches neither of the
        // node's two clauses and falls through to its catch-all, so it is refused here too.
        toml::Value::String(command) if !command.is_empty() => Parsed::Command(Entry {
            label,
            target: clean(command),
            verdict: EntryVerdict::Command,
            matcher: MatcherState::Absent,
        }),
        toml::Value::Table(_) => {
            let Some(component) = check.get("component") else {
                return Parsed::Refused(refused(
                    label,
                    "(none)",
                    "must be a command string or a `{ component = \"…\" }` table",
                ));
            };
            let shown_target = shown(component);
            if let Some(reason) = config_refusal(check) {
                return Parsed::Refused(refused(label, &shown_target, &reason));
            }
            match resolve_component(root, component) {
                Ok(path) => Parsed::Component {
                    label,
                    target: shown_target,
                    matcher: MatcherState::Absent,
                    path,
                },
                Err(reason) => Parsed::Refused(refused(label, &shown_target, &reason)),
            }
        }
        _other => Parsed::Refused(refused(
            label,
            &shown(check),
            "must be a command string or a `{ component = \"…\" }` table",
        )),
    }
}

/// The path half of `component_path/3`: a workspace `component` is relative to the root and
/// canonically inside it. Everything here is decided at *load* time on the node, so a failure
/// here is a failure that never reaches the untrusted budget.
fn resolve_component(root: &Path, component: &toml::Value) -> Result<PathBuf, String> {
    let Some(declared) = component.as_str() else {
        return Err("`component` must be a string".into());
    };
    let declared = declared.trim();
    if declared.is_empty() {
        return Err("has an empty `component`".into());
    }

    // A workspace `component` is relative to the workspace root and refused rather than
    // resolved when it is absolute.
    if Path::new(declared).is_absolute() {
        return Err("a workspace `component` must be relative to the workspace root".into());
    }

    // Canonical, so a symlink pointing out of the tree is followed and *then* refused: resolving
    // links before processing `..` is what stops a lexical `../..` and a planted link alike.
    // One message for both ways this fails, exactly as the node has one: two messages differing
    // on whether the target exists is an existence oracle for paths this workspace may not read.
    let outside = "`component` is not a readable regular file inside the workspace";
    let Ok(canonical) = std::fs::canonicalize(root.join(declared)) else {
        return Err(outside.into());
    };
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(outside.into());
    }
    Ok(canonical)
}

/// The two questions the node asks when a hook actually *runs*: is it under the hook lane's byte
/// ceiling, and is it in the world? Both cost a budget slot on the node too, because both happen
/// after `build/4` — so this runs only for an entry that was budgeted.
fn admit(
    label: String,
    target: String,
    matcher: MatcherState,
    path: &Path,
    helper: &mut Helper,
) -> Result<Entry> {
    let size = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    if size > HOOK_MAX_COMPONENT_BYTES {
        return Ok(refused(
            label,
            &target,
            &format!("is {size} bytes; the limit is {HOOK_MAX_COMPONENT_BYTES}"),
        )
        .with_matcher(matcher));
    }

    // The world, asked of the helper rather than guessed at. `inspect` reports what the bytes
    // declare and `load` is what runs the admission check and names its refusal; neither
    // instantiates, so nothing in this workspace runs to be checked.
    match helper.inspect(path) {
        Err(error) => {
            let refusal = refusal_or_bail(error)?;
            Ok(refused(label, &target, &refusal.refusal).with_matcher(matcher))
        }
        Ok(inspected) => {
            let sha = inspected["sha256"].as_str().unwrap_or_default().to_string();
            match helper.load(&sha, path) {
                Ok(_admitted) => Ok(Entry {
                    label,
                    target,
                    verdict: EntryVerdict::Admitted,
                    matcher,
                }),
                Err(error) => {
                    let refusal = refusal_or_bail(error)?;
                    Ok(refused(label, &target, &refusal.refusal).with_matcher(matcher))
                }
            }
        }
    }
}

fn refused(label: String, target: &str, reason: &str) -> Entry {
    Entry {
        label,
        target: target.to_string(),
        verdict: EntryVerdict::Refused(clean(reason)),
        matcher: MatcherState::Absent,
    }
}

impl Entry {
    fn with_matcher(mut self, matcher: MatcherState) -> Entry {
        self.matcher = matcher;
        self
    }
}

/// A repository-authored value, shown the way it may be shown: sanitized and clipped.
fn shown(value: &toml::Value) -> String {
    match value.as_str() {
        Some(text) => clean(text),
        None => "(not a string)".to_string(),
    }
}

fn render_check(root: &Path, binary: &wasm_client::HelperBinary, entries: &[Entry]) -> String {
    let mut lines = vec![
        format!("{}/ouroboros.toml", root.display()),
        "  judged as an UNTRUSTED workspace, which is the strict case: a component hook runs \
         from a clone, a command hook does not"
            .into(),
        format!("  helper: {binary}"),
    ];

    if entries.is_empty() {
        lines.push("  no [[hooks]] and no [checks]".into());
        return lines.join("\n");
    }

    let width = entries
        .iter()
        .map(|entry| entry.label.len())
        .max()
        .unwrap_or(0);
    for entry in entries {
        lines.push(match &entry.verdict {
            EntryVerdict::Command => format!(
                "  {:<width$}  command  {}  (declined untrusted: a command hook is `sh -c` on \
                 this machine)",
                entry.label, entry.target
            ),
            EntryVerdict::Admitted => {
                format!("  {:<width$}  ok       {}", entry.label, entry.target)
            }
            EntryVerdict::Refused(reason) => format!(
                "  {:<width$}  REFUSED  {}\n  {:<width$}           {reason}",
                entry.label, entry.target, ""
            ),
        });

        if entry.matcher == MatcherState::Unverified {
            lines.push(format!(
                "  {:<width$}           matcher: unverified (the node compiles it as PCRE; this \
                 client has no regex engine and checked only its {MAX_MATCHER_BYTES}-byte bound)",
                ""
            ));
        }
    }

    lines.push(summary(entries));
    lines.join("\n")
}

/// The last line, which is the one an author reads and the one review caught lying.
///
/// It used to say "every component entry would be admitted" whenever nothing was refused —
/// including for `matcher = "*"`, which the node refuses outright. A summary may only report
/// what was actually decided: how many rows were verified, and how many carry a matcher that is
/// still the node's to compile. The word "admitted" does not appear while any of the second kind
/// exists, because that sentence is the whole of what an author takes away.
fn summary(entries: &[Entry]) -> String {
    let refused = entries
        .iter()
        .filter(|entry| entry.verdict.refused())
        .count();
    let admitted = entries
        .iter()
        .filter(|entry| entry.verdict == EntryVerdict::Admitted)
        .count();
    let unverified = entries
        .iter()
        .filter(|entry| entry.matcher == MatcherState::Unverified)
        .count();

    let mut parts = Vec::new();
    if refused > 0 {
        parts.push(format!(
            "{refused} entr{} refused",
            if refused == 1 { "y" } else { "ies" }
        ));
    }
    parts.push(format!(
        "{admitted} component entr{} verified",
        if admitted == 1 { "y" } else { "ies" }
    ));
    if unverified > 0 {
        parts.push(format!(
            "{unverified} matcher{} NOT verified here — the node compiles those, and refuses a \
             pattern that does not",
            if unverified == 1 { "" } else { "s" }
        ));
    }

    let line = parts.join("; ");
    if refused == 0 && unverified == 0 {
        // The only case in which the strong sentence is true.
        format!("  {line}; every component entry would be admitted")
    } else {
        format!("  {line}")
    }
}

// ======================================================================== `ouro wasm new`

/// The scaffold, embedded rather than fetched: a command that downloads its template is a
/// command that runs somebody else's code the first time it is used.
///
/// These are the SDK's own template files at `tui/wasm/guest/template/`, which is the one
/// place a scaffold is written and reviewed (W10b). `include_str!` makes them part of this
/// binary at compile time; `the_embedded_template_is_the_template_on_disk` reads the same
/// paths at run time and compares, so this cannot quietly become a copy that drifted — which
/// is what the raw-`wit-bindgen` template under `src/wasm_template/` had become.
const TEMPLATE_CARGO: &str = include_str!("../wasm/guest/template/Cargo.toml");
const TEMPLATE_README: &str = include_str!("../wasm/guest/template/README.md");
const TEMPLATE_CAPABILITY: &str = include_str!("../wasm/guest/template/src/lib.rs");
const TEMPLATE_HOOK: &str = include_str!("../wasm/guest/template/src/lib.hook.rs");

/// Written as `.gitignore`. Dotless in the template directory so it does not become an ignore
/// rule for the template itself.
const TEMPLATE_GITIGNORE: &str = include_str!("../wasm/guest/template/gitignore");

/// The SDK's path inside a checkout, relative to the checkout root.
const SDK_RELATIVE: [&str; 3] = ["tui", "wasm", "guest"];

/// The package name the manifest at that path must declare. A directory laid out like the SDK
/// is not the SDK.
const SDK_CRATE: &str = "ouroboros-guest";

/// How much of a candidate `Cargo.toml` is read before it is parsed. The SDK's own is under two
/// kilobytes; this is a file that may have been planted, and every input is bounded before it
/// is parsed.
const MAX_SDK_MANIFEST_BYTES: u64 = 64 * 1024;

/// Contract C1's bound on a `describe` summary, which is where `--summary` ends up.
const MAX_SUMMARY_CHARS: usize = 200;

/// `Wasm.Artifact`'s `@max_name_bytes`.
const MAX_NAME_BYTES: usize = 64;

/// The refusal when there is no SDK to point at. Named here because two paths reach it.
const NO_SDK: &str = "no `ouroboros-guest` to depend on. It is not published to crates.io, so a \
                      scaffolded project reaches the SDK by path — and this command will not go \
                      looking for one near the directory it was typed in, because a path \
                      dependency's `build.rs` and proc-macros run at build time and a checkout \
                      that supplied one would be choosing what your `cargo build` executes \
                      (docs/WASM.md D14). It comes from `--sdk-path <PATH>`, or from the \
                      checkout the running `ouro` binary lives in. Neither is available here: \
                      pass `--sdk-path` naming a checkout's `tui/wasm/guest`.";

/// `ouro wasm new <name>`: a component project that builds, in the shape this world wants.
///
/// Two shapes over one world: a `Capability` by default, a `Hook` under `--hook`. Both are the
/// SDK's template with the table in `tui/wasm/guest/template/PLACEHOLDERS.md` substituted.
///
/// `sdk_path` is where the generated `Cargo.toml` reaches `ouroboros-guest`, and everything
/// interesting about this command is in [`sdk_path`]: a path dependency is **executed** at
/// build time, so where it comes from is D14's question and gets D14's answer.
pub fn new<O: Write>(
    into: &Path,
    name: &str,
    hook: bool,
    summary: Option<&str>,
    named_sdk: Option<&Path>,
    out: &mut O,
) -> Result<()> {
    let name = name.trim();
    project_name(name)?;

    let root = into.join(name);
    if root.exists() {
        bail!("{} already exists", root.display());
    }

    let summary = summary
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .unwrap_or(if hook {
            "A hook component."
        } else {
            "A capability component."
        });
    project_summary(summary)?;

    let sdk = sdk_path(named_sdk, installed_exe().as_deref())?;

    let files = [
        ("Cargo.toml", TEMPLATE_CARGO),
        (
            "src/lib.rs",
            if hook {
                TEMPLATE_HOOK
            } else {
                TEMPLATE_CAPABILITY
            },
        ),
        ("README.md", TEMPLATE_README),
        (".gitignore", TEMPLATE_GITIGNORE),
    ];

    for (relative, template) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        std::fs::write(&path, substitute(template, name, summary, &sdk)?)
            .with_context(|| format!("could not write {}", path.display()))?;
    }

    writeln!(
        out,
        "{}\n  a {} component in {}, on ouroboros-guest at {}\n\n  cargo build --release \
         --target wasm32-wasip2\n  ouro wasm inspect target/wasm32-wasip2/release/{}.wasm",
        root.display(),
        if hook { "hook" } else { "capability" },
        crate_world(),
        sdk,
        crate_name(name),
    )?;
    out.flush()?;
    Ok(())
}

/// The project's name, held to two rules at once.
///
/// The first is `Wasm.Artifact.name?/1`'s, verbatim — `[a-z0-9][a-z0-9._-]{0,63}` — because
/// this name *is* what a manifest will carry and what a rollout will be registered under, and
/// a scaffold that let somebody start on a name the signer will refuse has taught them the
/// wrong charset. The second is cargo's, which is narrower in two places the first allows: a
/// package name may not begin with a digit and may not contain `.`. Both are stated, because a
/// name refused by one is refused for a different reason than a name refused by the other.
fn project_name(name: &str) -> Result<()> {
    let first = name.chars().next();

    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !first.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        bail!(
            "`{}` is not a capability name. The rule is `Wasm.Artifact.name?/1`'s: lower-case \
             letters and digits, `.`, `_` and `-`, starting with a letter or a digit, at most \
             {MAX_NAME_BYTES} bytes.",
            clean(name)
        );
    }

    // Cargo's own, applied second so its message is about cargo and not about the manifest.
    if !first.is_some_and(|c| c.is_ascii_lowercase()) || name.contains('.') {
        bail!(
            "`{}` is a capability name but not a cargo package name: cargo refuses a package \
             name that starts with a digit or contains `.`, and this name is the crate's. Pick \
             one that is both.",
            clean(name)
        );
    }

    Ok(())
}

/// The `describe` summary, which is spliced into a Rust string literal in `src/lib.rs`.
///
/// A `"` or a `\` in it would close or escape that literal — `--summary '"; compile_error!("' `
/// is a scaffold that writes a crate refusing to build, and a longer version is a scaffold that
/// writes whatever the caller wanted. Refused rather than escaped: this is a one-line
/// description, and there is nothing a quote in it buys anybody.
fn project_summary(summary: &str) -> Result<()> {
    if summary.chars().count() > MAX_SUMMARY_CHARS {
        bail!(
            "--summary is {} characters; contract C1 bounds a summary at {MAX_SUMMARY_CHARS}",
            summary.chars().count()
        );
    }

    if let Some(character) = summary
        .chars()
        .find(|c| matches!(c, '"' | '\\') || c.is_control())
    {
        bail!(
            "--summary holds {character:?}, which cannot go into a Rust string literal without \
             changing what the literal is. Quotes, backslashes and control characters are \
             refused rather than escaped."
        );
    }

    Ok(())
}

fn crate_world() -> &'static str {
    "ouroboros:capability@0.1.0"
}

/// cargo's own rule: a crate's library artifact is its package name with `-` become `_`.
fn crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// `{{Name}}`: the project name as a Rust type, UpperCamelCase.
///
/// The leading-non-letter branch is unreachable through [`new`], which refuses such a name for
/// cargo's sake before this is called. It is here because this is a total function over a
/// `&str` and a partial one would be a trap for the next caller.
fn type_name(name: &str) -> String {
    let mut camel = String::with_capacity(name.len());
    let mut capitalise = true;

    for character in name.chars() {
        if character == '-' || character == '_' || character == '.' {
            capitalise = true;
            continue;
        }
        if capitalise {
            camel.extend(character.to_uppercase());
            // A digit has no upper case, so it does not consume the pending capital: `9lives`
            // is `9Lives` and not `9lives`.
            capitalise = !character.is_alphabetic();
        } else {
            camel.push(character);
        }
    }

    match camel.chars().next() {
        Some(first) if first.is_ascii_alphabetic() => camel,
        _ => format!("Component{camel}"),
    }
}

/// The `ouro` binary this process actually is, canonicalised **first**.
///
/// The same line `wasm_client::sibling` takes and for the same reason: `current_exe` returns
/// the path the process was started through, symlinks and all, so a repository shipping
/// `./ouro -> /usr/local/bin/ouro` beside its own `tui/wasm/guest` would otherwise be "where
/// `ouro` was installed". Canonicalising makes this the directory the real binary lives in.
fn installed_exe() -> Option<PathBuf> {
    std::fs::canonicalize(std::env::current_exe().ok()?).ok()
}

/// Where the generated `Cargo.toml` reaches `ouroboros-guest`, as a **canonical absolute** path.
///
/// # Why this is D14's question and not a matter of taste
///
/// The first cut of this command walked up from the *output directory* to the nearest
/// `tui/wasm/guest`, on the reasoning that a `path =` line in a manifest is a source path and
/// not something that gets executed. That reasoning is wrong, and review proved it wrong: a
/// cargo path dependency's `build.rs` and its proc-macros run during `cargo build`, so an SDK
/// planted on any shared ancestor of the directory a developer scaffolds in — `/tmp`, a home
/// directory, a mounted share — got its build script executed by the first build of the
/// scaffolded project. That is a checkout choosing what runs on a developer's machine, which is
/// exactly what D14 exists to stop, arriving through the seam nobody was watching.
///
/// So the rule is D14's, verbatim: **nothing cwd-derived**. Two sources and no third:
///
///   1. `--sdk-path <PATH>` — a person naming one, honoured wherever it points.
///   2. The checkout the running `ouro` lives in, found by walking the ancestors of the
///      **canonicalised `current_exe`** and never of the working directory. In a checkout that
///      is `tui/target/{debug,release}/ouro`, whose ancestors include the checkout root.
///
/// Whichever it is, it is vetted by [`vet_sdk`] and written **absolute**. Absolute because the
/// relative form was byte-identical in the benign case and the planted one, so a manifest an
/// author read told them nothing about which SDK they had.
fn sdk_path(named: Option<&Path>, installed: Option<&Path>) -> Result<String> {
    let vetted = match named {
        Some(path) => vet_sdk(path, "--sdk-path")?,
        None => {
            let installed = installed.ok_or_else(|| anyhow!("{NO_SDK}"))?;

            let candidate = installed
                .ancestors()
                .map(|ancestor| {
                    SDK_RELATIVE
                        .iter()
                        .fold(ancestor.to_path_buf(), |path, part| path.join(part))
                })
                .find(|candidate| candidate.join("Cargo.toml").exists())
                .ok_or_else(|| anyhow!("{NO_SDK}"))?;

            // Vetted rather than skipped past: a directory laid out like the SDK above the
            // binary and failing a check is a fact worth printing, not one to walk around.
            vet_sdk(&candidate, "the checkout this `ouro` binary lives in")?
        }
    };

    let text = vetted.to_string_lossy().into_owned();

    // The value is spliced into a TOML string. A `"` closes it, a `\` starts an escape, and a
    // newline ends the line and starts a key — `--sdk-path '/x"\nevil = "…'` is a `Cargo.toml`
    // this command wrote and the operator did not. Refused rather than escaped: these are
    // characters no SDK checkout has in its path.
    if let Some(character) = text
        .chars()
        .find(|c| matches!(c, '"' | '\\') || c.is_control())
    {
        bail!(
            "the SDK path {} holds {character:?}, which cannot go into a Cargo.toml string \
             without changing what the manifest says. Quotes, backslashes and control \
             characters are refused rather than escaped.",
            clean(&text)
        );
    }

    Ok(text)
}

/// Whether a directory is an `ouroboros-guest` checkout this command may point a build at.
///
/// It is about to become a cargo path dependency, which means its `build.rs` and its
/// proc-macros will run on this machine. Four questions, in the order that makes each one
/// meaningful — the shape [`crate::wasm_client::vet`] applies to the helper, for the same
/// reason:
///
///   1. **No symlink on the way in.** The directory itself and the two levels above it —
///      `guest`, `wasm`, `tui` in the SDK's own layout — must each be a real directory.
///      A `guest -> /somewhere/else` under a checkout is a redirection nobody reading the path
///      would see.
///   2. **A regular `Cargo.toml`.** Not a symlink, not a directory, not a device, and bounded
///      before it is read.
///   3. **It is the SDK.** `[package] name` must be exactly `ouroboros-guest`. A directory that
///      is merely *shaped* like `tui/wasm/guest` is not the SDK, and this is the check that
///      says so.
///   4. **Canonicalised**, and the canonical path is what is written — so the path in the
///      manifest is the directory that was checked.
fn vet_sdk(candidate: &Path, source: &str) -> Result<PathBuf> {
    let mut level = Some(candidate);
    for _ in 0..SDK_RELATIVE.len() {
        let Some(path) = level else { break };

        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("{source}: {} could not be inspected", path.display()))?;

        if metadata.file_type().is_symlink() {
            bail!(
                "{source}: {} is a symlink. The SDK becomes a cargo path dependency, whose \
                 build script runs on this machine, so a link that sends the build somewhere \
                 the path does not name is refused.",
                path.display()
            );
        }
        if !metadata.is_dir() {
            bail!("{source}: {} is not a directory", path.display());
        }

        level = path.parent();
    }

    let manifest = candidate.join("Cargo.toml");
    let metadata = std::fs::symlink_metadata(&manifest).with_context(|| {
        format!(
            "{source}: {} has no Cargo.toml, so it is not a crate",
            candidate.display()
        )
    })?;

    if !metadata.file_type().is_file() {
        bail!(
            "{source}: {} is not a regular file, so it is not a manifest",
            manifest.display()
        );
    }
    if metadata.len() > MAX_SDK_MANIFEST_BYTES {
        bail!(
            "{source}: {} is {} bytes; a crate manifest is not that big",
            manifest.display(),
            metadata.len()
        );
    }

    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("{source}: reading {}", manifest.display()))?;
    let document: toml::Value = toml::from_str(&text)
        .with_context(|| format!("{source}: {} is not TOML", manifest.display()))?;

    let package = document
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str);

    if package != Some(SDK_CRATE) {
        bail!(
            "{source}: {} declares the package `{}`, not `{SDK_CRATE}`. A directory laid out \
             like the SDK is not the SDK, and this build would have run its build script.",
            manifest.display(),
            clean(package.unwrap_or("(none)"))
        );
    }

    std::fs::canonicalize(candidate)
        .with_context(|| format!("{source}: could not resolve {}", candidate.display()))
}

/// The template's substitution table (`tui/wasm/guest/template/PLACEHOLDERS.md`), applied in
/// **one pass** over the template rather than as a sequence of `replace` calls.
///
/// Two things follow from the single pass, and both of them matter:
///
///   * A substituted value is never itself substituted. `--sdk-path` is arbitrary operator
///     text that lands in a `Cargo.toml`, and a path holding `{{name}}` has to arrive as those
///     characters; a chain of `replace` calls would rewrite it depending on which call ran
///     first, which is a rule about ordering that nobody would remember.
///   * A placeholder this command does not know is an **error**, not a literal `{{…}}` carried
///     into somebody's project. Add one to a template file and forget the table here and
///     `ouro wasm new` refuses loudly instead of writing a manifest cargo cannot parse.
fn substitute(template: &str, name: &str, summary: &str, sdk_path: &str) -> Result<String> {
    let snake = crate_name(name);
    let camel = type_name(name);
    let table: [(&str, &str); 5] = [
        ("name_snake", &snake),
        ("name", name),
        ("Name", &camel),
        ("summary", summary),
        ("sdk_path", sdk_path),
    ];

    let mut written = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find("{{") {
        written.push_str(&rest[..open]);

        let after = &rest[open + 2..];
        let close = after
            .find("}}")
            .ok_or_else(|| anyhow!("a template file opens a placeholder it never closes"))?;
        let key = &after[..close];

        let value = table
            .iter()
            .find(|(named, _)| *named == key)
            .map(|(_, value)| *value)
            .ok_or_else(|| {
                anyhow!(
                    "a template file uses {{{{{key}}}}}, which this command does not substitute \
                     — see tui/wasm/guest/template/PLACEHOLDERS.md"
                )
            })?;

        written.push_str(value);
        rest = &after[close + 2..];
    }

    written.push_str(rest);
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_absent_helper_reads_as_an_opt_out_and_not_a_fault() {
        let text = render(&json!({
            "node": "ouroboros@here",
            "helper": {
                "present": false,
                "path": "/nonexistent/ouro-wasm",
                "world": "ouroboros:capability@0.1.0",
                "phase": "absent",
                "instances": 0,
                "owned": 0,
                "pending_drops": 0,
                "hook_components": 0,
                "hook_component_budget": 16,
                "usable": null,
                "worlds": [],
                "wasmtime": null,
                "limits": null,
                "broken_reason": null
            },
            "store": {
                "root": null,
                "budget_bytes": 536870912,
                "held": null,
                "bytes": null,
                "protected": null
            },
            "rollouts": {"total": 0, "by_state": {"live": 0}},
            "boot": {"enabled": false}
        }));

        assert!(text.contains("no helper on this node"));
        assert!(text.contains("this is an opt-in, not a fault"));
        assert!(text.contains("helper pool: no pool on this node"));
        assert!(text.contains("store: none (this node has no data directory)"));
        assert!(text.contains("boot restart: disabled"));
        // Nothing here claims a spent budget on a node that has admitted nothing.
        assert!(!text.contains("spent"));
    }

    #[test]
    fn a_ready_helper_shows_what_it_is_running_under() {
        let text = render(&json!({
            "node": "ouroboros@here",
            "helper": {
                "present": true,
                "path": "/opt/ouro-wasm",
                "world": "ouroboros:capability@0.1.0",
                "phase": "ready",
                "os_pid": 4242,
                "instances": 2,
                "owned": 1,
                "pending_drops": 0,
                "hook_components": 16,
                "hook_component_budget": 16,
                "usable": true,
                "worlds": ["ouroboros:capability@0.1.0"],
                "wasmtime": "43.0.1",
                "limits": {"max_deadline_ms": 60000, "max_memory_bytes": 268435456},
                "broken_reason": null
            },
            "store": {
                "root": "/var/lib/ouroboros/wasm/components",
                "budget_bytes": 536870912,
                "held": 2,
                "bytes": 3145728,
                "protected": 1
            },
            "rollouts": {
                "total": 3,
                "by_state": {"live": 1, "quarantined": 1, "superseded": 1, "deploying": 0, "rolled_back": 0}
            },
            "boot": {"enabled": true}
        }));

        assert!(text.contains("helper present"));
        assert!(text.contains("ready (pid 4242), wasmtime 43.0.1, 2 instance(s)"));
        assert!(text.contains("helper reports usable"));
        assert!(text.contains("deadline 60000"));
        assert!(text.contains("hook components: 16 of 16 used"));
        assert!(text.contains("restart the wasm pool"));
        assert!(text.contains("2 component(s), 3145728 byte(s)"));
        assert!(text.contains("1 protected by a rollout"));
        assert!(text.contains("3 lane-W (1 live"));
        assert!(text.contains("boot restart: enabled"));
    }

    /// A broken pool says why, and an unreadable store says so rather than reading as empty.
    #[test]
    fn a_broken_pool_and_an_unreadable_store_both_say_so() {
        let text = render(&json!({
            "helper": {
                "present": true,
                "path": "/opt/ouro-wasm",
                "phase": "broken",
                "hook_components": 0,
                "hook_component_budget": 16,
                "usable": false,
                "broken_reason": "{:handshake_refused, %{usable: false, worlds: []}}"
            },
            "store": {"root": "/var/lib/ouroboros/wasm/components", "held": null, "bytes": null, "protected": null},
            "rollouts": {"total": null, "by_state": {}},
            "boot": {"enabled": true}
        }));

        assert!(text.contains("helper pool: broken"));
        assert!(text.contains("broken: {:handshake_refused"));
        assert!(text.contains("helper reports NOT usable"));
        assert!(text.contains("store: unreadable"));
        assert!(text.contains("protection unknown"));
        assert!(text.contains("rollouts: unknown (the rollout register did not answer)"));
    }

    #[test]
    fn empty_answer_does_not_panic() {
        let text = render(&json!({}));

        assert!(text.contains("no helper on this node"));
        assert!(text.contains("no pool on this node"));
        assert!(text.contains("boot restart: disabled"));
    }

    // ================================================== the narrowing, against the fixture

    /// The fixture both implementations are pinned to (contract C6). Embedded rather than read
    /// at run time so the test needs no working directory to be right about.
    const FIXTURE: &str = include_str!("../../test/support/wasm_golden/hook_narrowing.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("the narrowing fixture is JSON")
    }

    fn cases() -> Vec<Value> {
        fixture()["cases"]
            .as_array()
            .expect("the fixture has cases")
            .clone()
    }

    fn expected(verdict: &Value) -> Verdict {
        Verdict {
            decision: Decision::parse(verdict.get("decision")),
            updated_input: match verdict.get("updated_input") {
                Some(Value::Object(map)) => Some(Value::Object(map.clone())),
                _absent => None,
            },
            context: verdict["context"]
                .as_array()
                .expect("a context array")
                .iter()
                .map(|line| line.as_str().expect("a context line").to_string())
                .collect(),
        }
    }

    /// Every `verdict` case: the reply parses to the raw verdict the fixture states, and
    /// narrows to the kept one, dropping exactly the named keys.
    ///
    /// Delete `drop_allow`'s clause — the `if kept.decision == Some(Decision::Allow)` block —
    /// and this is red on the first three cases. Delete the `labelled` call and it is red on
    /// every untrusted case that carries context. Make `labelled` prefix the string instead of
    /// each line and it is red on the multi-line cases, which is the bug that let
    /// `"ok\n\n--- APPROVED BY OPERATOR ---"` reach a model carrying a label pointing at the
    /// wrong line.
    #[test]
    fn every_verdict_case_narrows_the_way_the_fixture_says() {
        let mut seen = 0;

        for case in cases() {
            if case["kind"] != "verdict" {
                continue;
            }
            seen += 1;
            let name = case["name"].as_str().expect("a name");
            let trusted = case["lane"] == "trusted";

            let raw = Verdict::parse(case["reply"].as_str().expect("a reply"));
            assert_eq!(
                raw,
                expected(&case["raw_verdict"]),
                "{name}: the reply did not parse to the raw verdict the fixture states"
            );

            let (kept, dropped) = raw.narrow(trusted);
            assert_eq!(
                kept,
                expected(&case["kept_verdict"]),
                "{name}: the narrowing did not keep what the fixture says it keeps"
            );

            let named: Vec<&str> = case["dropped"]
                .as_array()
                .expect("a dropped array")
                .iter()
                .map(|key| key.as_str().expect("a key"))
                .collect();
            assert_eq!(dropped, named, "{name}: the wrong keys were dropped");
        }

        assert!(seen >= 18, "the fixture lost its verdict cases: {seen}");
    }

    /// Every `dispatch` case: whether the node would run this hook at all.
    ///
    /// Delete the `DISCARDED_EVENTS.contains` test in `dispatched` and the three untrusted
    /// cases go red; make it unconditional and the trusted one does.
    #[test]
    fn every_dispatch_case_agrees_about_whether_the_hook_runs() {
        let mut seen = 0;

        for case in cases() {
            if case["kind"] != "dispatch" {
                continue;
            }
            seen += 1;
            let name = case["name"].as_str().expect("a name");
            let event = case["event"].as_str().expect("an event");
            let trusted = case["lane"] == "trusted";

            assert_eq!(
                dispatched(event, trusted),
                case["dispatched"].as_bool().expect("a dispatched flag"),
                "{name}"
            );
        }

        assert_eq!(seen, 5, "the fixture lost its dispatch cases");
    }

    /// Every `payload` case: what an untrusted `PostToolUse` hook is handed on the way *in*.
    ///
    /// Delete the untrusted branch of `tool_response` — return the response itself — and the
    /// three untrusted cases go red on the leaked `output`.
    #[test]
    fn every_payload_case_narrows_the_response_the_way_the_fixture_says() {
        let mut seen = 0;

        for case in cases() {
            let Some(response) = case.get("tool_response") else {
                continue;
            };
            seen += 1;
            let name = case["name"].as_str().expect("a name");
            let trusted = case["lane"] == "trusted";

            assert_eq!(
                tool_response(&response["raw"], trusted),
                response["kept"],
                "{name}"
            );
        }

        assert_eq!(seen, 5, "the fixture lost its payload cases");
    }

    /// `NODE_DEFAULT_LIMITS` is a copy of `config/config.exs`'s `capability_limits`, because
    /// there is no node in this loop to ask — and a copy that drifted would have `ouro wasm run`
    /// quietly testing a component under bounds no node uses.
    ///
    /// Read as text rather than parsed: this is a Rust test asserting about an Elixir config
    /// file, and a grep for three numbers under one key is the smallest thing that can notice
    /// the change without pulling a TOML-shaped parser at an Elixir keyword list.
    #[test]
    fn the_node_default_limits_are_the_ones_config_exs_states() {
        let config = include_str!("../../config/config.exs");
        let block = config
            .split("capability_limits: [")
            .nth(1)
            .expect("config.exs declares capability_limits")
            .split(']')
            .next()
            .expect("the list closes");

        for (key, value) in [
            ("fuel", NODE_DEFAULT_LIMITS.fuel),
            ("memory_bytes", NODE_DEFAULT_LIMITS.memory_bytes),
            ("deadline_ms", NODE_DEFAULT_LIMITS.deadline_ms),
        ] {
            let declared = block
                .lines()
                .find_map(|line| line.trim().strip_prefix(&format!("{key}: ")))
                .unwrap_or_else(|| panic!("capability_limits has no {key}: {block}"))
                .trim_end_matches(',')
                .trim();

            // `64 * 1024 * 1024` in the Elixir, `100_000_000` in either — evaluate the products
            // and drop the underscores, which is the whole of the arithmetic this file needs.
            let evaluated: u64 = declared
                .split('*')
                .map(|factor| {
                    factor
                        .trim()
                        .replace('_', "")
                        .parse::<u64>()
                        .unwrap_or_else(|_| panic!("{key} is {declared}, which this cannot read"))
                })
                .product();

            assert_eq!(
                evaluated, value,
                "config.exs says {key} is {declared}; NODE_DEFAULT_LIMITS says {value}"
            );
        }
    }

    /// The constants the fixture states are the constants this side uses. A fixture that
    /// agreed about every case and disagreed about the prefix would be pinning nothing.
    #[test]
    fn the_fixtures_constants_are_this_sides_constants() {
        let fixture = fixture();
        assert_eq!(
            fixture["untrusted_context_prefix"],
            UNTRUSTED_CONTEXT_PREFIX
        );
        assert_eq!(fixture["max_context_bytes"], MAX_CONTEXT_BYTES);
        assert_eq!(fixture["discarded_events"], json!(DISCARDED_EVENTS));
    }

    // ================================================================== the rendering

    fn echo_inspected() -> Value {
        json!({
            "sha256": "b8bc6fd12f88567dddf1735a4b858d122bca6eaf80013c4fa866494b39c0fa6b",
            "world": "ouroboros:capability@0.1.0",
            "imports": ["log"],
            "exports": ["describe", "init", "handle-message"],
            "size": 48333,
            "shape": { "functions": 101, "code_bytes": 40721 },
        })
    }

    fn echo_limits() -> Value {
        json!({ "limits": { "max_functions": 20000, "max_code_bytes": 4194304 } })
    }

    #[test]
    fn inspect_shows_the_shape_against_the_bound_and_one_verdict_line() {
        let text = render_inspect(
            Path::new("echo.wasm"),
            &echo_inspected(),
            &echo_limits(),
            &Admission {
                capability: Ok(()),
                hook: None,
            },
        );

        assert!(text.contains("world:   ouroboros:capability@0.1.0"));
        assert!(text.contains("imports: log"));
        // The reading, its ceiling, and the headroom between them — the three numbers an
        // author needs to know whether they are near a refusal or nowhere near one.
        let row = text
            .lines()
            .find(|line| line.trim_start().starts_with("functions "))
            .expect("a functions row");
        assert!(row.contains("101"), "the reading is shown: {row}");
        assert!(row.contains("20000"), "the ceiling is shown: {row}");
        assert!(row.contains("198×"), "the headroom is shown: {row}");
        assert!(text.contains("verdict: admitted — as a capability and as a hook component"));
    }

    #[test]
    fn a_refused_component_names_the_refusal_rather_than_only_failing() {
        let text = render_inspect(
            Path::new("clock.wasm"),
            &json!({
                "sha256": "aa", "world": "unknown",
                "imports": ["log", "wasi:cli/environment"], "exports": [], "size": 10,
            }),
            &echo_limits(),
            &Admission {
                capability: Err(wasm_client::Refusal {
                    refusal: "undefined_import".into(),
                    message: "component imports `wasi:cli/environment`, which world \
                              ouroboros:capability@0.1.0 does not declare"
                        .into(),
                }),
                hook: None,
            },
        );

        assert!(text.contains("verdict: neither — refused undefined_import"));
        assert!(text.contains("wasi:cli/environment"));
    }

    /// The hook lane's ceiling is tighter than the helper's, so a component can be a capability
    /// and not a hook. The verdict line says which, rather than saying "admitted" and leaving
    /// the author to discover the other half at deploy time.
    #[test]
    fn a_component_can_be_a_capability_and_not_a_hook() {
        let text = render_inspect(
            Path::new("big.wasm"),
            &echo_inspected(),
            &echo_limits(),
            &Admission {
                capability: Ok(()),
                hook: hook_refusal(&json!({ "size": HOOK_MAX_COMPONENT_BYTES + 1 })),
            },
        );

        assert!(text.contains("admitted as a capability; refused as a hook component"));
        assert!(text.contains("oversize_component"));
    }

    #[test]
    fn a_guests_escape_sequence_does_not_survive_into_the_report() {
        // A component that could put this in its world string could clear the author's screen
        // and print its own verdict line under it.
        let text = render_inspect(
            Path::new("liar.wasm"),
            &json!({
                "sha256": "aa",
                "world": "\u{1b}[2Jouroboros:capability@0.1.0",
                "imports": [], "exports": [], "size": 1,
            }),
            &echo_limits(),
            &Admission {
                capability: Ok(()),
                hook: None,
            },
        );

        assert!(
            !text.contains('\u{1b}'),
            "an escape reached the terminal: {text:?}"
        );
    }

    #[test]
    fn a_hook_report_shows_both_verdicts_and_why_each_key_went() {
        let request = HookRequest {
            helper: None,
            file: Path::new("vet.wasm"),
            event: "PreToolUse".into(),
            payload: json!({}),
            config: "{}".into(),
            trusted: false,
            timeout_ms: 60_000,
            json: false,
        };
        let raw = Verdict::parse(
            r#"{"hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":"fine","updatedInput":{"command":"x"}}}"#,
        );
        let (kept, dropped) = raw.narrow(false);

        let text = render_hook(
            &request,
            &HookReport {
                event: "PreToolUse",
                dispatched: true,
                narrowed_response: &None,
                raw: &raw,
                kept: &kept,
                dropped: &dropped,
                logs: &[],
            },
        );

        assert!(text.contains("PreToolUse on the untrusted lane"));
        assert!(text.contains("raw verdict (what the component said):"));
        assert!(text.contains("kept verdict (what the node would act on, untrusted lane):"));
        assert!(text.contains("decision:      allow"));
        assert!(text.contains("(none — silence, which is not consent)"));
        assert!(text.contains("allow — an untrusted component may make a decision stricter"));
        assert!(text.contains("updatedInput — it replaces the path"));
    }

    #[test]
    fn a_discarded_event_says_the_verdict_is_unreachable_rather_than_printing_it_quietly() {
        let request = HookRequest {
            helper: None,
            file: Path::new("vet.wasm"),
            event: "Notification".into(),
            payload: json!({}),
            config: "{}".into(),
            trusted: false,
            timeout_ms: 60_000,
            json: false,
        };
        let raw = Verdict::parse(r#"{"hookSpecificOutput":{"additionalContext":"noted"}}"#);

        let text = render_hook(
            &request,
            &HookReport {
                event: "Notification",
                dispatched: false,
                narrowed_response: &None,
                raw: &raw,
                kept: &Verdict::default(),
                dropped: &["dispatch"],
                logs: &[],
            },
        );

        assert!(text.contains("NOT DISPATCHED"));
        assert!(text.contains("Everything below is what it *would* have said"));
        assert!(text.contains("dispatch — the runtime discards this event's answer"));
    }

    #[test]
    fn a_post_tool_use_report_shows_the_payload_narrowing_too() {
        let request = HookRequest {
            helper: None,
            file: Path::new("vet.wasm"),
            event: "PostToolUse".into(),
            payload: json!({}),
            config: "{}".into(),
            trusted: false,
            timeout_ms: 60_000,
            json: false,
        };
        let raw_response = json!({ "is_error": false, "output": "the file contents" });
        let kept_response = tool_response(&raw_response, false);

        let text = render_hook(
            &request,
            &HookReport {
                event: "PostToolUse",
                dispatched: true,
                narrowed_response: &Some((raw_response, kept_response)),
                raw: &Verdict::default(),
                kept: &Verdict::default(),
                dropped: &[],
                logs: &[],
            },
        );

        assert!(text.contains("tool_response given:"));
        assert!(text.contains("\"bytes\":17"));
        assert!(
            !text.contains("tool_response sent:  {\"is_error\":false,\"output\""),
            "the output body reached the hook: {text}"
        );
        assert!(text.contains("the output body is dropped"));
    }

    // ================================================================== `check`

    fn check_table(toml: &str) -> toml::Value {
        toml::from_str(toml).expect("the fixture parses")
    }

    fn first_hook(document: &toml::Value) -> Parsed {
        parse_hook(Path::new("/nowhere"), &hook_tables(document)[0], 1)
    }

    fn refusal_of_first(document: &toml::Value) -> String {
        match first_hook(document) {
            Parsed::Refused(Entry {
                verdict: EntryVerdict::Refused(reason),
                ..
            }) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    impl std::fmt::Debug for Parsed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Parsed::Refused(entry) => write!(f, "Refused({entry:?})"),
                Parsed::Command(entry) => write!(f, "Command({entry:?})"),
                Parsed::Component { label, .. } => write!(f, "Component({label})"),
            }
        }
    }

    /// The grammar half of `check`, which needs no helper: the exactly-one-of rule, the event
    /// vocabulary, and the byte bounds.
    #[test]
    fn the_grammar_refusals_are_the_nodes_own() {
        let document = check_table("[[hooks]]\nevent = \"NotAnEvent\"\ncomponent = \"./a.wasm\"\n");
        assert_eq!(
            refusal_of_first(&document),
            "`NotAnEvent` is not a hook event"
        );

        let document = check_table("[[hooks]]\nevent = \"PreToolUse\"\n");
        assert_eq!(
            refusal_of_first(&document),
            "has no `command` and no `component`"
        );

        let document = check_table(
            "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"x\"\ncomponent = \"./a.wasm\"\n",
        );
        assert!(refusal_of_first(&document).contains("one or the other"));

        let long = "a".repeat(MAX_MATCHER_BYTES + 1);
        let document = check_table(&format!(
            "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./a.wasm\"\nmatcher = \"{long}\"\n"
        ));
        assert!(refusal_of_first(&document).contains("201 bytes"));
    }

    /// L4/M24. The node downcases before it looks an event up, so a hook declaring
    /// `event = "pretooluse"` runs — and `check` must not refuse a spelling the runtime accepts.
    /// Delete the `to_ascii_lowercase` in `canonical_event` and the second half goes red.
    #[test]
    fn an_event_is_matched_the_way_the_node_matches_it() {
        assert_eq!(canonical_event("PreToolUse"), Some("PreToolUse"));
        assert_eq!(canonical_event("pretooluse"), Some("PreToolUse"));
        assert_eq!(canonical_event("  POSTTOOLUSE  "), Some("PostToolUse"));
        assert_eq!(canonical_event("NotAnEvent"), None);
        assert_eq!(canonical_event(""), None);

        // And `check` agrees, because both ask the same function.
        let document = check_table("[[hooks]]\nevent = \"pretooluse\"\ncomponent = \"./a.wasm\"\n");
        assert_eq!(
            event_refusal(&hook_tables(&document)[0]),
            None,
            "a lowercase event is a real event on the node"
        );
    }

    /// H4 and M3, the two halves of the same lie.
    ///
    /// `matcher = "*"` is refused by the node (`quantifier does not follow a repeatable item`)
    /// and the old parenthesis-balance heuristic passed it, so `check` printed "every component
    /// entry would be admitted" and exited 0. `matcher = "\Q(\E"` is a quoted literal paren that
    /// the node compiles happily, and the same heuristic refused it. Neither is decided here any
    /// more: both are `Unverified`, which the summary refuses to call admitted.
    ///
    /// Reintroduce any pattern-shape guess and one of these two goes red.
    #[test]
    fn a_matcher_is_reported_as_unverified_rather_than_guessed_at() {
        // `*` is refused by the node; `\Q(\E` and `a)|(x` are compiled by it; `(a+)+$` is
        // catastrophic but valid. Not one of them is this client's to judge.
        for pattern in [
            "*",
            "\\\\Q(\\\\E",
            "a)|(x",
            "bash|write",
            "(a+)+$",
            "[a-",
            "\\\\",
        ] {
            let document = check_table(&format!(
                "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./a.wasm\"\nmatcher = \"{pattern}\"\n"
            ));
            assert_eq!(
                matcher_state(&hook_tables(&document)[0]),
                Ok(MatcherState::Unverified),
                "`{pattern}` must be reported as the node's to compile, not decided here"
            );
        }

        // A blank matcher is `nil` to the node, so there is nothing left undecided.
        for blank in ["", "  "] {
            let document = check_table(&format!(
                "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./a.wasm\"\nmatcher = \"{blank}\"\n"
            ));
            assert_eq!(
                matcher_state(&hook_tables(&document)[0]),
                Ok(MatcherState::Absent)
            );
        }

        // The one thing that *is* decided here, exactly: the byte bound.
        let long = "a".repeat(MAX_MATCHER_BYTES + 1);
        let document = check_table(&format!(
            "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./a.wasm\"\nmatcher = \"{long}\"\n"
        ));
        assert!(matcher_state(&hook_tables(&document)[0])
            .expect_err("an oversize matcher is refused")
            .contains("201 bytes"));
    }

    /// The summary is the line an author takes away, so it may not say "admitted" while a
    /// matcher is still the node's to compile. Delete the `unverified == 0` half of `summary`'s
    /// condition and this goes red.
    #[test]
    fn the_summary_never_claims_admission_it_did_not_verify() {
        let clean_row = Entry {
            label: "[[hooks]] #1".into(),
            target: "./a.wasm".into(),
            verdict: EntryVerdict::Admitted,
            matcher: MatcherState::Absent,
        };
        let with_matcher = Entry {
            matcher: MatcherState::Unverified,
            ..clean_row.clone()
        };

        let verified = summary(std::slice::from_ref(&clean_row));
        assert!(verified.contains("1 component entry verified"));
        assert!(verified.contains("every component entry would be admitted"));

        let unverified = summary(std::slice::from_ref(&with_matcher));
        assert!(
            !unverified.contains("would be admitted"),
            "a matcher this client cannot compile is not an admission: {unverified}"
        );
        assert!(unverified.contains("1 matcher NOT verified here"));

        let refused = summary(&[Entry {
            verdict: EntryVerdict::Refused("no".into()),
            ..clean_row.clone()
        }]);
        assert!(refused.contains("1 entry refused"));
        assert!(!refused.contains("would be admitted"));
    }

    #[test]
    fn a_config_past_the_bound_is_refused_for_a_hook_and_a_check_alike() {
        let long = "x".repeat(MAX_HOOK_CONFIG_BYTES + 1);
        let document = check_table(&format!(
            "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./a.wasm\"\nconfig = \"{long}\"\n"
        ));
        assert!(refusal_of_first(&document).contains("16385 bytes"));
    }

    /// L5. Two rows the node refuses that the first version passed over in silence: a `config`
    /// on a `command =` hook (a command hook has no `init`), and a `[checks]` entry whose value
    /// is the empty string (it matches neither of the node's two clauses).
    #[test]
    fn a_config_on_a_command_hook_and_an_empty_check_are_both_refused() {
        let document = check_table(
            "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"./lint\"\nconfig = \"{}\"\n",
        );
        assert!(refusal_of_first(&document).contains("only meaningful for a `component` hook"));

        let document = check_table("[checks]\nlint = \"\"\n");
        let (name, value) = check_tables(&document).remove(0);
        match parse_check(Path::new("/nowhere"), &name, &value) {
            Parsed::Refused(Entry {
                verdict: EntryVerdict::Refused(reason),
                ..
            }) => assert!(reason.contains("must be a command string")),
            other => panic!("an empty check must be refused, got {other:?}"),
        }
    }

    /// `[checks]` is a table and has no document order, so the node sorts before it takes the
    /// first twenty: without the sort, "the first twenty" would be whichever twenty the parser
    /// handed over.
    #[test]
    fn checks_are_read_in_sorted_order() {
        let document = check_table("[checks]\nzed = \"z\"\nalpha = \"a\"\nmid = \"m\"\n");
        let names: Vec<String> = check_tables(&document)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, vec!["alpha", "mid", "zed"]);
    }

    #[test]
    fn the_check_table_says_which_entries_a_clone_would_have_refused() {
        let entries = vec![
            Entry {
                label: "[[hooks]] #1".into(),
                target: "./hooks/vet.wasm".into(),
                verdict: EntryVerdict::Admitted,
                matcher: MatcherState::Absent,
            },
            Entry {
                label: "[[hooks]] #2".into(),
                target: "./bin/lint".into(),
                verdict: EntryVerdict::Command,
                matcher: MatcherState::Absent,
            },
            Entry {
                label: "[[hooks]] #3".into(),
                target: "../../outside.wasm".into(),
                verdict: EntryVerdict::Refused(
                    "`component` is not a readable regular file inside the workspace".into(),
                ),
                matcher: MatcherState::Absent,
            },
            Entry {
                label: "[[hooks]] #4".into(),
                target: "./hooks/vet.wasm".into(),
                verdict: EntryVerdict::Admitted,
                matcher: MatcherState::Unverified,
            },
        ];

        let text = render_check(Path::new("/w"), &fake_binary(), &entries);

        assert!(text.contains("judged as an UNTRUSTED workspace"));
        assert!(text.contains("[[hooks]] #1  ok"));
        assert!(text.contains("[[hooks]] #2  command"));
        assert!(text.contains("[[hooks]] #3  REFUSED"));
        assert!(text.contains("not a readable regular file inside the workspace"));
        assert!(text.contains("matcher: unverified (the node compiles it as PCRE"));
        assert!(text.contains("1 entry refused"));
        assert!(!text.contains("would be admitted"));
        // Which binary judged this workspace is part of the answer, not decoration: two helpers
        // of different vintages can disagree about a world.
        assert!(text.contains("helper: "));
    }

    /// A `HelperBinary` for a rendering test. `vet` is the only constructor, so this points it
    /// at a file that certainly exists, is owned by this account or root, and is executable.
    fn fake_binary() -> wasm_client::HelperBinary {
        wasm_client::vet(Path::new("/bin/sh"), "a rendering test")
            .expect("/bin/sh is an executable regular file")
    }

    // ================================================================== `new`

    /// The template `ouro wasm new` writes is the SDK's template on disk, not a copy of it.
    ///
    /// `include_str!` reads at compile time; this reads the same paths at run time and
    /// compares. Editing a template file cannot make it red — cargo tracks an `include_str!`
    /// and rebuilds — and that is the point: what it catches is a constant that stopped
    /// pointing at the SDK's template. Point one of them at a copy and it goes red naming the
    /// file, which is the drift that actually happened before W10b, when `src/wasm_template/`
    /// was a second scaffold nothing held to the SDK's.
    #[test]
    fn the_embedded_template_is_the_template_on_disk() {
        let template = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("wasm")
            .join("guest")
            .join("template");

        for (relative, embedded) in [
            ("Cargo.toml", TEMPLATE_CARGO),
            ("README.md", TEMPLATE_README),
            ("src/lib.rs", TEMPLATE_CAPABILITY),
            ("src/lib.hook.rs", TEMPLATE_HOOK),
            ("gitignore", TEMPLATE_GITIGNORE),
        ] {
            let on_disk = std::fs::read_to_string(template.join(relative))
                .unwrap_or_else(|error| panic!("the SDK template is missing {relative}: {error}"));

            assert_eq!(
                embedded, on_disk,
                "the {relative} `ouro` embeds is not the one at tui/wasm/guest/template/"
            );
        }
    }

    /// Every placeholder the embedded templates use is one this command substitutes.
    ///
    /// `tui/wasm/tests/sdk.rs` holds the template to `PLACEHOLDERS.md`; this holds *this
    /// binary* to the same table. Add a `{{…}}` to a template file and forget the table in
    /// `substitute` and `ouro wasm new` now refuses — where before it would have carried the
    /// literal into somebody's `Cargo.toml`, which is a broken project handed over silently.
    #[test]
    fn both_scaffolds_substitute_everything_and_leave_no_placeholder() {
        for template in [
            TEMPLATE_CARGO,
            TEMPLATE_README,
            TEMPLATE_CAPABILITY,
            TEMPLATE_HOOK,
            TEMPLATE_GITIGNORE,
        ] {
            let written = substitute(template, "my-guard", "Guards.", "../../tui/wasm/guest")
                .expect("every placeholder a template file uses is in the table");
            assert!(
                !written.contains("{{"),
                "a placeholder survived substitution:\n{written}"
            );
        }

        // The two shapes differ where they must: only the hook one speaks the verdict contract.
        let hook = substitute(TEMPLATE_HOOK, "my-guard", "Guards.", "/sdk").expect("the hook");
        let capability =
            substitute(TEMPLATE_CAPABILITY, "my-guard", "Guards.", "/sdk").expect("the capability");
        assert!(hook.contains("export_hook!(MyGuard)"));
        assert!(hook.contains("Verdict"));
        assert!(capability.contains("export_capability!(MyGuard)"));
        assert!(!capability.contains("Verdict"));

        // Both are `no_std`, which is the import list and therefore the security claim.
        assert!(hook.contains("#![no_std]"));
        assert!(capability.contains("#![no_std]"));

        // Both name forms come out of the same pass, each as itself.
        assert!(hook.contains("my_guard.wasm") && hook.contains("my-guard asks about"));
    }

    /// A placeholder this command does not know is refused, and a substituted value is never
    /// substituted again.
    ///
    /// The second half is not hypothetical: `--sdk-path` is arbitrary operator text that lands
    /// in a `Cargo.toml`. Replace `substitute`'s single pass with a chain of `.replace()` calls
    /// and this goes red — the path would be rewritten by whichever call ran after it, which is
    /// a `path =` line that silently stopped being the one the operator typed.
    #[test]
    fn an_unknown_placeholder_is_refused_and_a_value_is_never_re_substituted() {
        let refusal = substitute("{{whatever}}", "my-guard", "s", "/sdk")
            .expect_err("a placeholder outside the table is an error")
            .to_string();
        assert!(refusal.contains("{{whatever}}"), "{refusal}");
        assert!(refusal.contains("PLACEHOLDERS.md"), "{refusal}");

        assert!(substitute("{{name", "my-guard", "s", "/sdk")
            .expect_err("an unclosed placeholder is an error")
            .to_string()
            .contains("never closes"));

        let written = substitute(
            "{{sdk_path}} :: {{name}} :: {{name_snake}}",
            "my-guard",
            "s",
            "/x/{{name}}/guest",
        )
        .expect("a path is text, not a template");
        assert_eq!(written, "/x/{{name}}/guest :: my-guard :: my_guard");
    }

    /// The Rust type name. The `Component` prefix branch is belt-and-braces — `new` refuses a
    /// name starting with a digit before it is reached, because cargo refuses such a package
    /// name — and this is where that stays true of the function itself.
    #[test]
    fn the_type_name_is_always_an_identifier() {
        assert_eq!(type_name("my-guard"), "MyGuard");
        assert_eq!(type_name("my_guard"), "MyGuard");
        assert_eq!(type_name("my.guard"), "MyGuard");
        assert_eq!(type_name("guard"), "Guard");
        assert_eq!(type_name("9lives"), "Component9Lives");
    }

    /// The name charset is `Wasm.Artifact.name?/1`'s, and then cargo's on top of it.
    ///
    /// L8: relax `project_name` to the old "letters, digits, `-` and `_`" and this goes red on
    /// `MyThing` and on the hundred-character name — a scaffold that taught an author a name
    /// the signer will refuse, after they had written the component.
    #[test]
    fn a_project_name_is_the_artifact_charset_and_a_cargo_package_name() {
        for good in ["guard", "my-guard", "my_guard", "g9"] {
            project_name(good).unwrap_or_else(|error| panic!("`{good}` is a name: {error}"));
        }

        for bad in ["MyThing", "_leading", "-leading", "", "a b", "a/b"] {
            let refusal = project_name(bad).unwrap_err().to_string();
            assert!(refusal.contains("lower-case"), "{bad}: {refusal}");
        }

        let long = "a".repeat(MAX_NAME_BYTES + 1);
        assert!(project_name(&long)
            .expect_err("65 bytes is past the artifact bound")
            .to_string()
            .contains("64 bytes"));
        project_name(&"a".repeat(MAX_NAME_BYTES)).expect("64 bytes is the bound, not past it");

        // Allowed by the artifact charset, refused by cargo's — and the refusal says which.
        for bad in ["9lives", "my.guard"] {
            let refusal = project_name(bad).unwrap_err().to_string();
            assert!(refusal.contains("cargo"), "{bad}: {refusal}");
        }
    }

    /// M7. `--summary` is spliced into a Rust string literal in `src/lib.rs`, so a `"` in it
    /// writes a crate that is not the crate this command meant to write.
    ///
    /// Delete `project_summary`'s call in `new` and this goes red: the scaffold would carry
    /// `"; compile_error!("` into the source, and the author's first `cargo build` would fail
    /// with a message about their own file.
    #[test]
    fn a_summary_that_would_escape_its_string_literal_is_refused() {
        project_summary("Does one thing.").expect("plain text is a summary");

        for bad in [r#"a" ; compile_error!("pwn"#, "a\\", "a\nb", "a\u{1b}[31m"] {
            let refusal = project_summary(bad).unwrap_err().to_string();
            assert!(refusal.contains("refused rather than escaped"), "{refusal}");
        }

        // C1's bound, enforced here rather than only claimed in the flag's help.
        let long = "x".repeat(MAX_SUMMARY_CHARS + 1);
        assert!(project_summary(&long)
            .expect_err("201 characters is past C1's bound")
            .to_string()
            .contains("200"));
        project_summary(&"x".repeat(MAX_SUMMARY_CHARS)).expect("200 is the bound, not past it");
    }

    /// H1. The SDK never comes from an ancestor of the working or output directory — it comes
    /// from `--sdk-path` or from the checkout the running binary lives in, and nowhere else.
    ///
    /// The planted layout is the reviewer's: an `ouroboros-guest` on a shared ancestor
    /// (`/tmp`, a home directory, a mounted share) of the place a developer scaffolds in. It
    /// used to be found and written into the manifest, and the first `cargo build` of the
    /// scaffolded project ran its `build.rs`. Restore a walk over the output directory's
    /// ancestors and this goes red.
    #[test]
    fn the_sdk_is_never_taken_from_a_directory_near_the_output() {
        let scratch = scratch_dir("sdk-plant");
        let plant = scratch.join("shared/tui/wasm/guest");
        std::fs::create_dir_all(&plant).expect("a planted SDK");
        std::fs::write(
            plant.join("Cargo.toml"),
            "[package]\nname = \"ouroboros-guest\"\nversion = \"0.1.0\"\n",
        )
        .expect("a planted manifest");
        std::fs::create_dir_all(scratch.join("shared/dev/work")).expect("somewhere to work");

        // A binary installed where no checkout is above it: there is no SDK, and the plant on
        // the output directory's ancestor is not consulted at all.
        let elsewhere = scratch.join("usr/local/bin/ouro");
        std::fs::create_dir_all(elsewhere.parent().expect("a bin directory")).expect("a bin");
        std::fs::write(&elsewhere, "").expect("an installed binary");

        let refusal = sdk_path(None, Some(&elsewhere))
            .expect_err("nothing above the binary, so nothing to point at")
            .to_string();
        assert!(refusal.contains("--sdk-path"), "{refusal}");
        assert!(
            !refusal.contains("shared"),
            "the plant was not even looked at: {refusal}"
        );

        // The same plant, named by a person: honoured, because that is a person choosing.
        let named = sdk_path(Some(&plant), None).expect("--sdk-path is a person choosing");
        assert!(named.ends_with("shared/tui/wasm/guest"), "{named}");
        assert!(Path::new(&named).is_absolute(), "written absolute: {named}");

        // And a binary inside a checkout finds that checkout's SDK.
        let checkout = scratch.join("co");
        std::fs::create_dir_all(checkout.join("tui/wasm/guest")).expect("a checkout");
        std::fs::write(
            checkout.join("tui/wasm/guest/Cargo.toml"),
            "[package]\nname = \"ouroboros-guest\"\n",
        )
        .expect("the SDK's manifest");
        let binary = checkout.join("tui/target/debug/ouro");
        std::fs::create_dir_all(binary.parent().expect("a target directory")).expect("a target");
        std::fs::write(&binary, "").expect("a built binary");

        let found = sdk_path(None, Some(&binary)).expect("the checkout above the binary");
        assert!(found.ends_with("co/tui/wasm/guest"), "{found}");

        std::fs::remove_dir_all(&scratch).ok();
    }

    /// H1. What `vet_sdk` refuses, and each refusal is a way the path would not have been the
    /// directory it named.
    ///
    /// Delete the symlink check and the first case goes red; delete the package-name check and
    /// the second does. Both are a `build.rs` this command would have pointed a build at.
    #[test]
    fn an_sdk_that_is_not_the_sdk_is_refused_by_name() {
        let scratch = scratch_dir("sdk-vet");
        let real = scratch.join("real/tui/wasm/guest");
        std::fs::create_dir_all(&real).expect("a real SDK");
        std::fs::write(
            real.join("Cargo.toml"),
            "[package]\nname = \"ouroboros-guest\"\n",
        )
        .expect("a real manifest");

        // A `guest` that is a link to somewhere else: a redirection nobody reading the path
        // would see.
        #[cfg(unix)]
        {
            let linked = scratch.join("link/tui/wasm");
            std::fs::create_dir_all(&linked).expect("a checkout shape");
            std::os::unix::fs::symlink(&real, linked.join("guest")).expect("a symlinked guest");

            let refusal = sdk_path(Some(&linked.join("guest")), None)
                .expect_err("a symlinked guest is refused")
                .to_string();
            assert!(refusal.contains("symlink"), "{refusal}");
        }

        // A directory laid out like the SDK, holding some other crate.
        let impostor = scratch.join("fake/tui/wasm/guest");
        std::fs::create_dir_all(&impostor).expect("an impostor");
        std::fs::write(
            impostor.join("Cargo.toml"),
            "[package]\nname = \"not-the-sdk\"\n",
        )
        .expect("an impostor manifest");

        let refusal = sdk_path(Some(&impostor), None)
            .expect_err("a directory shaped like the SDK is not the SDK")
            .to_string();
        assert!(refusal.contains("ouroboros-guest"), "{refusal}");
        assert!(refusal.contains("not-the-sdk"), "{refusal}");

        // A `Cargo.toml` that is a directory is not a manifest.
        let hollow = scratch.join("hollow/tui/wasm/guest/Cargo.toml");
        std::fs::create_dir_all(&hollow).expect("a Cargo.toml that is a directory");
        assert!(
            sdk_path(Some(hollow.parent().expect("the guest dir")), None)
                .expect_err("a directory is not a manifest")
                .to_string()
                .contains("not a regular file")
        );

        std::fs::remove_dir_all(&scratch).ok();
    }

    /// M5. The SDK path is spliced into a TOML string, so a `"` or a newline in it writes a
    /// manifest the operator did not. Refused rather than escaped.
    ///
    /// Delete the character check in `sdk_path` and this goes red with a `Cargo.toml` carrying
    /// an extra key.
    #[cfg(unix)]
    #[test]
    fn an_sdk_path_that_would_escape_its_toml_string_is_refused() {
        let scratch = scratch_dir("sdk-toml");
        let guest = scratch.join("a\"b/tui/wasm/guest");
        std::fs::create_dir_all(&guest).expect("a directory with a quote in its path");
        std::fs::write(
            guest.join("Cargo.toml"),
            "[package]\nname = \"ouroboros-guest\"\n",
        )
        .expect("a manifest");

        let refusal = sdk_path(Some(&guest), None)
            .expect_err("a quote cannot go into a TOML string")
            .to_string();
        assert!(refusal.contains("refused rather than escaped"), "{refusal}");

        std::fs::remove_dir_all(&scratch).ok();
    }

    /// `new` writes four files and no fifth, in the shape asked for, with the SDK the caller
    /// named — canonical and absolute.
    #[test]
    fn new_writes_the_four_files_of_the_shape_it_was_asked_for() {
        let scratch = scratch_dir("new-files");
        let sdk = scratch.join("co/tui/wasm/guest");
        std::fs::create_dir_all(&sdk).expect("an SDK to point at");
        std::fs::write(
            sdk.join("Cargo.toml"),
            "[package]\nname = \"ouroboros-guest\"\n",
        )
        .expect("the SDK's manifest");
        let into = scratch.join("work");
        std::fs::create_dir_all(&into).expect("a scratch directory");

        let mut out = Vec::new();
        new(
            &into,
            "my-guard",
            true,
            Some("Guards the writes."),
            Some(&sdk),
            &mut out,
        )
        .expect("the scaffold is written");

        let root = into.join("my-guard");
        for expected in ["Cargo.toml", "src/lib.rs", "README.md", ".gitignore"] {
            assert!(root.join(expected).is_file(), "missing {expected}");
        }
        // The world file the old template copied is gone: the SDK carries the bindings now, so
        // a `wit/` directory in a scaffolded project would be a second copy of the world that
        // nothing compiles.
        assert!(
            !root.join("wit").exists(),
            "a scaffold has no wit/ of its own"
        );

        let cargo = std::fs::read_to_string(root.join("Cargo.toml")).expect("the manifest");
        let canonical = std::fs::canonicalize(&sdk).expect("the SDK resolves");
        assert!(
            cargo.contains(&format!(r#"path = "{}""#, canonical.display())),
            "the manifest carries the canonical absolute SDK path:\n{cargo}"
        );
        assert!(cargo.contains(r#"name = "my-guard""#));

        let source = std::fs::read_to_string(root.join("src/lib.rs")).expect("the crate root");
        assert!(source.contains("export_hook!(MyGuard)"));
        assert!(source.contains("Guards the writes."));

        // What it printed names the SDK it wrote, absolutely — the relative form read the same
        // whether the SDK was the real one or one planted on a shared ancestor.
        let printed = String::from_utf8(out).expect("the summary is text");
        assert!(
            printed.contains(&canonical.display().to_string()),
            "{printed}"
        );

        // A second `new` into the same place refuses rather than overwriting somebody's work.
        let mut again = Vec::new();
        assert!(new(&into, "my-guard", true, None, Some(&sdk), &mut again).is_err());

        std::fs::remove_dir_all(&scratch).ok();
    }

    /// A scratch directory under the system temp, named for this process and this moment.
    fn scratch_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ouro-wasm-cli-unit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after 1970")
                .as_nanos()
        ))
    }
}
