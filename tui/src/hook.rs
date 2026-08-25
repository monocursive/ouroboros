//! `ouro hook post-tool-use`: the vendor half of E2.
//!
//! ## Why this exists
//!
//! Ouroboros runs no tool loop inside a Claude session, so it cannot append diagnostics to
//! an edit result the way the native agent will. What Claude Code *does* offer is a
//! `PostToolUse` hook: a command it runs after a tool has already succeeded, whose stdout
//! can carry text back into the model's context. `Ouroboros.Provider.ClaudeAdapter`
//! composes that hook into the `--settings` JSON it already builds for a bridged session,
//! matched on `Edit|Write|MultiEdit|NotebookEdit`, and this subcommand is what it runs.
//!
//! ## The contract, pinned
//!
//! Claude Code writes one JSON object on stdin carrying at least `tool_name`,
//! `tool_input`, `session_id` and `cwd`, and reads one JSON object on stdout
//! (<https://code.claude.com/docs/en/hooks>):
//!
//! ```json
//! {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "…"}}
//! ```
//!
//! `session_id` in that payload is *Claude's* session, not Ouroboros's. The session this
//! hook reports to is the one in `OUROBOROS_SESSION_ID`, which the adapter put in the
//! command's environment — the same four variables the MCP bridge gets, for the same
//! reason.
//!
//! ## It never blocks, and that is the whole design
//!
//! A `PostToolUse` hook can refuse an edit by exiting 2 with a reason on stderr. This one
//! never does, under any circumstance: no runtime, no language server, a timeout, a
//! malformed payload, and a file with nothing to say about it all exit 0. The tool has
//! *already run* by the time this hook is called, so a refusal here cannot undo anything —
//! it can only send the model back to redo work that succeeded. OpenCode #9102 is that
//! loop with receipts: diagnostics appended without an explicit success line made agents
//! retry and abandon edits that had worked. Hence "Edit applied." first, every time.
//!
//! ## The wording
//!
//! Three shapes, and no fourth:
//!
//! ```text
//! Edit applied.
//! Found 2 new diagnostic issues in lib/a.ex:
//!   error lib/a.ex:12:5 [E001] undefined variable
//!   warning lib/a.ex:21:1 [W002] unused
//! ```
//!
//! ```text
//! Edit applied.
//! No new diagnostics.
//! ```
//!
//! ```text
//! Edit applied.
//! (no LSP data for this file)
//! ```
//!
//! New-only against the pre-edit baseline, errors always, at most three warnings, at most
//! twenty lines then `+N more` — R4 §2's noise bounds, applied by
//! [`crate::mcp_serve::diagnostic_lines`] so that this hook and the `diagnostics` MCP tool
//! cannot drift into two policies.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::mcp_serve::{render_found, Bridge, PostEdit, Server};

/// The event name echoed back in `hookSpecificOutput`. Claude Code matches on it.
pub const HOOK_EVENT: &str = "PostToolUse";

/// The tools this hook is installed for. One string, so the adapter and this module cannot
/// disagree about which tool calls produce an edit.
pub const EDIT_TOOLS: &str = "Edit|Write|MultiEdit|NotebookEdit";

/// R4 §2's budget, end to end. The runtime bounds its own half at five seconds too; this
/// is the outer one, so a runtime that stops answering costs the turn a fixed five seconds
/// rather than however long a socket takes to notice.
pub const BUDGET: Duration = Duration::from_secs(5);

/// A hook payload carries a tool's arguments. `Write` carries file *content*, so the cap is
/// generous — and it is still a cap, because a peer that never stops writing is a peer
/// growing this process's memory on its say-so.
const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;

/// The first line, always. The tool already succeeded; anything after this is advice.
pub const APPLIED: &str = "Edit applied.";

/// What no answer inside the budget reads as. Deliberately not an empty diagnostics list:
/// "nobody looked" and "nothing is wrong" are different facts.
pub const NO_DATA: &str = "(no LSP data for this file)";

/// What a fresh answer with nothing new reads as.
pub const NO_NEW: &str = "No new diagnostics.";

/// The fields of one `PostToolUse` payload this hook acts on. Everything else in it is
/// read past: the shape is the vendor's and it grows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PostToolUse {
    pub tool_name: Option<String>,
    pub path: Option<String>,
    /// Claude Code's session id. Carried for the log line and nothing else — the session
    /// this hook reports to comes from the environment.
    pub session_id: Option<String>,
    pub cwd: Option<String>,
}

impl PostToolUse {
    /// Reads what can be read. A payload that is not JSON, or is JSON of another shape, is
    /// an empty event rather than an error: this hook has no failure it is allowed to
    /// express.
    pub fn parse(input: &str) -> Self {
        let Ok(event) = serde_json::from_str::<Value>(input.trim()) else {
            return Self::default();
        };

        let tool_input = event.get("tool_input");

        // `Edit`, `Write` and `MultiEdit` name it `file_path`; `NotebookEdit` names it
        // `notebook_path`; `path` is accepted because other harnesses that speak this
        // contract use it and the cost of accepting it is nothing.
        let path = ["file_path", "notebook_path", "path"]
            .iter()
            .find_map(|key| tool_input.and_then(|input| string(input, key)));

        Self {
            tool_name: string(&event, "tool_name"),
            path,
            session_id: string(&event, "session_id"),
            cwd: string(&event, "cwd"),
        }
    }

    /// The file to ask about, absolute. A relative path in the payload is relative to the
    /// directory the tool ran in, which the payload also carries.
    pub fn absolute_path(&self) -> Option<String> {
        let path = self.path.as_ref()?;

        if Path::new(path).is_absolute() {
            return Some(path.clone());
        }

        match &self.cwd {
            Some(cwd) => Some(Path::new(cwd).join(path).display().to_string()),
            None => Some(path.clone()),
        }
    }
}

fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|found| !found.is_empty())
        .map(str::to_string)
}

/// The whole answer, as the bytes Claude Code reads.
///
/// Serialised canonically — keys sorted via [`crate::model::sorted_json`] — so the bytes
/// are the same from the plain and desktop binaries, whose `serde_json` holds keys in
/// different orders.
pub fn frame(additional_context: &str) -> String {
    let value = crate::model::sorted_json(&json!({
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "additionalContext": additional_context
        }
    }));

    serde_json::to_string(&value).unwrap_or_else(|_unencodable| {
        // Unreachable for a string, and still not a reason to fail an edit.
        format!(
            r#"{{"hookSpecificOutput":{{"hookEventName":"{HOOK_EVENT}","additionalContext":"{APPLIED}"}}}}"#
        )
    })
}

/// The three shapes, chosen from one outcome.
pub fn additional_context(path: &str, outcome: &PostEdit) -> String {
    match outcome {
        PostEdit::NoData => format!("{APPLIED}\n{NO_DATA}"),
        PostEdit::Fresh(found) if found.is_empty() => format!("{APPLIED}\n{NO_NEW}"),
        PostEdit::Fresh(found) => format!("{APPLIED}\n{}", render_found(path, found, "new ")),
    }
}

/// Reads one `PostToolUse` payload and writes one answer. Never fails, never blocks.
pub async fn post_tool_use() -> Result<()> {
    let input = read_input(tokio::io::stdin()).await;
    let event = PostToolUse::parse(&input);

    let Some(path) = event.absolute_path() else {
        // No file, nothing to say. An empty stdout is a hook that ran and had no context
        // to add, which is exactly the truth here — and it costs the turn no tokens.
        return Ok(());
    };

    println!(
        "{}",
        frame(&additional_context(&path, &outcome(&path).await))
    );
    Ok(())
}

/// Everything that can go wrong collapses into "no LSP data", because none of it is
/// something the model can act on and all of it happened after a successful edit.
async fn outcome(path: &str) -> PostEdit {
    outcome_within(path, BUDGET).await
}

/// The same, with the budget named. Public so a test can watch the deadline fire without
/// spending five seconds waiting for the one this hook actually runs under.
pub async fn outcome_within(path: &str, budget: Duration) -> PostEdit {
    let Ok(bridge) = Bridge::from_env() else {
        return PostEdit::NoData;
    };

    let mut server = Server::new(Ok(bridge));

    match tokio::time::timeout(budget, server.post_edit_diagnostics(path)).await {
        Ok(Ok(outcome)) => outcome,
        // A refusal from the runtime and a five-second silence are the same fact from
        // here: nobody looked at the file, and the edit stands either way.
        Ok(Err(_refused)) => PostEdit::NoData,
        Err(_elapsed) => PostEdit::NoData,
    }
}

/// Bounded, and an unreadable stdin is an empty payload rather than an error.
pub async fn read_input<R: AsyncRead + Unpin>(reader: R) -> String {
    let mut input = String::new();

    if reader
        .take(MAX_INPUT_BYTES)
        .read_to_string(&mut input)
        .await
        .is_err()
    {
        return String::new();
    }

    input
}
