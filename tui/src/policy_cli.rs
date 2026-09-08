//! `ouro policy`: earned widening, from a terminal (docs/SELF.md §S2).
//!
//! A signed policy component may only ever *narrow*. An `allow` it returns is honoured for
//! a tool named in `config :ouroboros, :policy_allowable_tools`, empty by default, and read
//! as `ask` otherwise. Widening that list used to be one thing only: an operator typing a
//! tool name into a config file. S2 added the other way in — replay the component against
//! decisions humans already made on that node, and promote a tool only where it
//! contradicted none of them — and this is the surface for it.
//!
//! The loop a person runs is three commands:
//!
//! ```text
//! ouro policy status
//! ouro policy replay no-network-shell --out report.json
//! ouro policy promote no-network-shell --tool bash --evidence report.json
//! ```
//!
//! and `ouro policy demote` is the fourth, for when the number in front of them was not the
//! whole story.
//!
//! ## The report file is the point of `--out`
//!
//! `replay` is what produces the evidence and `promote` is what consumes it, so the report
//! travels through a file an operator can read, file and hand to somebody else. The runtime
//! re-runs the replay itself before it writes anything — the report is evidence that a
//! replay happened, not that it is still true — so this file is a record of what was decided
//! on, never the decision.
//!
//! ## Two outputs, one rule about which stream they use
//!
//! [`crate::ledger_cli`]'s posture, verbatim: a table for a person and JSON for a pipe, and
//! in both cases **stdout carries only the answer**. Where the report was written, and every
//! other remark about the call, goes to stderr, so `ouro policy replay … --json | jq` reads a
//! clean report and the operator still learns that a file was created.
//!
//! ## This client states no threshold of its own
//!
//! Whether a tool has earned promotion is the node's judgement, made against the node's own
//! numbers, in the re-run the node performs. So the report table prints the seven counts and
//! derives nothing from them: `ouro policy status` is where the thresholds this node holds
//! are printed, because that is where they come from.
//!
//! ## Nothing here can print a request
//!
//! The corpus these counts are over holds the exact document a component would have been
//! shown — command lines, paths, domains — and no verb serves a row of it. What arrives is
//! counts, and for a contradiction a fingerprint, a session id and an instant. There is
//! deliberately no renderer below for anything else, because a renderer for a field the
//! protocol does not send is a request for one.

use std::fmt::Write as _;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::transport::Client;

/// The five gateway verbs. Constants so the client and its tests cannot disagree.
pub const STATUS_METHOD: &str = "policy.status";
pub const REPLAY_METHOD: &str = "policy.replay";
pub const PROMOTE_METHOD: &str = "policy.promote";
pub const DEMOTE_METHOD: &str = "policy.demote";
pub const CLEAR_METHOD: &str = "policy.clear";

/// The ceiling on a report file this client will read. A report carries seven counts per
/// tool and at most twenty contradiction rows per tool; a mebibyte is room for hundreds of
/// tools and is a bound rather than a guess about how many there are.
///
/// `take(limit + 1)` rather than a `metadata()` check, for [`crate::wasm_deploy_cli`]'s
/// reason: a length reported by a stat is not a bound, because `/dev/zero` and a growing
/// file both report one that has nothing to do with what a read returns.
pub const MAX_REPORT_BYTES: u64 = 1024 * 1024;

/// How many contradiction rows the table prints per tool. The runtime already bounds the
/// report at twenty; this is the same number stated where a terminal is written to, so a
/// report from a runtime that ever raised its own bound still fits a screen.
const MAX_ROWS_SHOWN: usize = 20;

/// `ouro policy replay`'s flags, as the client holds them.
#[derive(Debug, Clone, Default)]
pub struct ReplayOptions {
    /// The live lane-W policy to replay, by name.
    pub name: String,
    /// Only human answers recorded at or after this ISO 8601 instant.
    pub since: Option<String>,
    /// Where to write the report `promote --evidence` reads back.
    pub out: Option<PathBuf>,
    /// The whole report on stdout instead of a table.
    pub json: bool,
}

/// `ouro policy promote`'s flags.
#[derive(Debug, Clone, Default)]
pub struct PromoteOptions {
    pub name: String,
    pub tool: String,
    /// The report file a previous `replay --out` wrote.
    pub evidence: PathBuf,
    pub json: bool,
}

/// `ouro policy demote`'s flags.
#[derive(Debug, Clone, Default)]
pub struct DemoteOptions {
    pub name: String,
    pub tool: String,
    /// Why. Echoed by the runtime and stored nowhere: the record keeps an enumerated term.
    pub reason: String,
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// `policy.status` and `policy.clear` take nothing at all, and their envelopes are closed,
/// so an empty object is the only thing either accepts.
pub fn no_params() -> Value {
    Value::Object(Map::new())
}

/// The `policy.replay` parameter object. An absent flag is an absent param, so the
/// runtime's own default — the whole corpus — applies rather than a second one here.
pub fn replay_params(options: &ReplayOptions) -> Value {
    let mut params = Map::new();
    params.insert("name".into(), json!(options.name));

    if let Some(since) = &options.since {
        params.insert("since".into(), json!(since));
    }

    Value::Object(params)
}

/// The `policy.promote` parameter object.
///
/// Note what is not here: an **actor**. Who promoted is the identity the connection
/// authenticated as, read by the runtime from its own side of the socket; a client that
/// could type one would be a client that could promote under anybody's name.
pub fn promote_params(name: &str, tool: &str, report: Value) -> Value {
    json!({"name": name, "tool": tool, "report": report})
}

/// The `policy.demote` parameter object.
pub fn demote_params(options: &DemoteOptions) -> Value {
    json!({
        "name": options.name,
        "tool": options.tool,
        "reason": options.reason,
    })
}

// ---------------------------------------------------------------------------
// The five commands
// ---------------------------------------------------------------------------

/// `ouro policy status` — the record, the corpus's counts, and this node's thresholds.
pub async fn status<O: Write, N: Write>(
    client: &Client,
    json_output: bool,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let answer = call(client, STATUS_METHOD, no_params()).await?;
    write_record(&answer, json_output, out, notes)
}

/// `ouro policy replay` — ask the component every answer a human gave, and count.
///
/// Writes the report file `promote` reads back when `--out` names one. The file is written
/// before anything is printed, so a report that could not be saved is an error rather than a
/// table somebody acts on and cannot hand over.
pub async fn replay<O: Write, N: Write>(
    client: &Client,
    options: &ReplayOptions,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let answer = call(client, REPLAY_METHOD, replay_params(options)).await?;

    if let Some(path) = &options.out {
        write_report(path, &answer)?;
        writeln!(notes, "ouro policy: wrote the report to {}", path.display())?;
        notes.flush()?;
    }

    let text = if options.json {
        let mut text = serde_json::to_string_pretty(&answer)?;
        text.push('\n');
        text
    } else {
        render_report(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.flush()?;
    Ok(())
}

/// `ouro policy promote` — hand the node a report and let it check for itself.
pub async fn promote<O: Write, N: Write>(
    client: &Client,
    options: &PromoteOptions,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let report = read_report(&options.evidence)?;
    let params = promote_params(&options.name, &options.tool, report);
    let answer = call(client, PROMOTE_METHOD, params).await?;

    write_record(&answer, options.json, out, notes)
}

/// `ouro policy demote` — withdraw one tool's promotion. Narrowing, and idempotent.
pub async fn demote<O: Write, N: Write>(
    client: &Client,
    options: &DemoteOptions,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let answer = call(client, DEMOTE_METHOD, demote_params(options)).await?;
    write_record(&answer, options.json, out, notes)
}

/// `ouro policy clear` — forget the record, so a different policy can earn its own.
pub async fn clear<O: Write, N: Write>(
    client: &Client,
    json_output: bool,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let answer = call(client, CLEAR_METHOD, no_params()).await?;
    write_record(&answer, json_output, out, notes)
}

async fn call(client: &Client, method: &str, params: Value) -> Result<Value> {
    client
        .call(method, params)
        .await
        .map_err(|error| anyhow!("the runtime refused {method}: {error}"))
}

fn write_record<O: Write, N: Write>(
    answer: &Value,
    json_output: bool,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let text = if json_output {
        let mut text = serde_json::to_string_pretty(answer)?;
        text.push('\n');
        text
    } else {
        render_status(answer)
    };

    out.write_all(text.as_bytes())?;
    out.flush()?;

    // The one remark a record can carry, and it belongs on the other stream: the reply to
    // `policy.demote` echoes the sentence the operator typed, which the record itself never
    // stored.
    if let Some(reason) = field(answer, "reason") {
        writeln!(notes, "ouro policy: recorded against \"{reason}\"")?;
        notes.flush()?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The promotion record as a person reads it.
///
/// Four header lines and, where the record holds anything, a row per promoted tool and a row
/// per demotion. `allowed` is the column that matters: a tool can be promoted and *not*
/// allowed, because a demotion newer than its promotion withdrew it, and the two facts sit
/// beside each other rather than one hiding the other.
pub fn render_status(answer: &Value) -> String {
    let mut text = String::new();

    let durability = field(answer, "durability").unwrap_or_else(|| "unknown".to_string());

    let policy = match (
        answer.pointer("/policy/name").and_then(Value::as_str),
        answer
            .pointer("/policy/component_sha256")
            .and_then(Value::as_str),
    ) {
        (Some(name), Some(sha)) => format!("{name} @ {}", short(sha)),
        // `unavailable` is the record saying it could not answer, and an empty record and a
        // record nobody could read are different facts. The runtime's own direction of failure
        // is the safe one — nothing is allowable while the authority is down — but a person
        // reading this page has to be able to tell "nothing promoted" from "nothing known".
        _ if durability == "unavailable" => {
            "the promotion record is not answering on this node".to_string()
        }
        _ => "nothing promoted on this node".to_string(),
    };

    let _ = writeln!(text, "policy   {policy}");
    let _ = writeln!(text, "record   {durability}");
    let _ = writeln!(text, "corpus   {}", corpus_sentence(answer));
    let _ = writeln!(text, "gate     {}", gate_sentence(answer));

    let allowed: Vec<String> = list(answer, "allowable_tools");
    let tools = array(answer, "tools");

    if !tools.is_empty() {
        let rows: Vec<ToolRow> = tools
            .iter()
            .map(|tool| ToolRow::from(tool, &allowed))
            .collect();

        let tool = width(rows.iter().map(|row| &row.tool), "tool");
        let promoted = width(rows.iter().map(|row| &row.promoted_at), "promoted");
        let actor = width(rows.iter().map(|row| &row.actor), "actor");
        let decisions = width(rows.iter().map(|row| &row.decisions), "decisions");

        let _ = writeln!(text);
        let _ = writeln!(
            text,
            "{:<tool$}  {:<7}  {:<promoted$}  {:<actor$}  {:>decisions$}  contradictions",
            "tool", "allowed", "promoted", "actor", "decisions"
        );

        for row in &rows {
            let _ = writeln!(
                text,
                "{:<tool$}  {:<7}  {:<promoted$}  {:<actor$}  {:>decisions$}  {}",
                row.tool,
                row.allowed,
                row.promoted_at,
                row.actor,
                row.decisions,
                row.contradictions
            );
        }
    }

    let demotions = array(answer, "demotions");

    if !demotions.is_empty() {
        let rows: Vec<DemotionRow> = demotions.iter().map(DemotionRow::from).collect();

        let tool = width(rows.iter().map(|row| &row.tool), "tool");
        let at = width(rows.iter().map(|row| &row.at), "at");
        let reason = width(rows.iter().map(|row| &row.reason), "reason");

        let _ = writeln!(text);
        let _ = writeln!(
            text,
            "{:<tool$}  {:<at$}  {:<reason$}  session",
            "tool", "at", "reason"
        );

        for row in rows.iter().take(MAX_ROWS_SHOWN) {
            let _ = writeln!(
                text,
                "{:<tool$}  {:<at$}  {:<reason$}  {}",
                row.tool, row.at, row.reason, row.session_id
            );
        }
    }

    text
}

/// A replay report as a person reads it.
///
/// The seven counts per tool, and nothing derived from them: whether a tool has earned a
/// promotion is decided by the node, in the re-run it performs when `promote` is called, and
/// a verdict computed here would be this client's opinion wearing the node's clothes.
///
/// `decisions` is `agreements + contradictions + stricter + asks`, and `agreements` contains
/// `would_resolve` — which is the number that says whether a promotion is worth making,
/// because it counts the prompts it would remove.
pub fn render_report(answer: &Value) -> String {
    let mut text = String::new();

    let policy = match (
        answer.get("policy_name").and_then(Value::as_str),
        answer.get("component_sha256").and_then(Value::as_str),
    ) {
        (Some(name), Some(sha)) => format!("{name} @ {}", short(sha)),
        (None, Some(sha)) => short(sha).to_string(),
        _ => "an unnamed component".to_string(),
    };

    let _ = writeln!(text, "policy    {policy}");
    let _ = writeln!(
        text,
        "corpus    {} rows, {} unreadable",
        number(answer, "/corpus_size"),
        number(answer, "/unreadable")
    );
    let _ = writeln!(
        text,
        "since     {}",
        field(answer, "since").unwrap_or_else(|| "the whole corpus".to_string())
    );
    let _ = writeln!(
        text,
        "replayed  {}",
        field(answer, "replayed_at").unwrap_or_else(|| "?".to_string())
    );
    let _ = writeln!(
        text,
        "report    {}",
        field(answer, "report_sha256")
            .map(|digest| short(&digest).to_string())
            .unwrap_or_else(|| "unsealed".to_string())
    );

    let mut tools: Vec<(String, &Value)> = answer
        .get("per_tool")
        .and_then(Value::as_object)
        .map(|table| {
            table
                .iter()
                .map(|(tool, counts)| (tool.clone(), counts))
                .collect()
        })
        .unwrap_or_default();

    tools.sort_by(|left, right| left.0.cmp(&right.0));

    if tools.is_empty() {
        let _ = writeln!(text, "\nno decisions in the corpus to replay");
        return text;
    }

    let rows: Vec<CountRow> = tools
        .iter()
        .map(|(tool, counts)| CountRow::from(tool, counts))
        .collect();

    let tool = width(rows.iter().map(|row| &row.tool), "tool");

    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "{:<tool$}  decisions  agreements  contradictions  would_resolve  stricter  asks  unreadable",
        "tool"
    );

    for row in &rows {
        let _ = writeln!(
            text,
            "{:<tool$}  {:>9}  {:>10}  {:>14}  {:>13}  {:>8}  {:>4}  {:>10}",
            row.tool,
            row.decisions,
            row.agreements,
            row.contradictions,
            row.would_resolve,
            row.stricter,
            row.asks,
            row.unreadable
        );
    }

    let contradictions = contradiction_rows(&tools);

    if !contradictions.is_empty() {
        let tool = width(contradictions.iter().map(|row| &row.tool), "tool");
        let at = width(contradictions.iter().map(|row| &row.at), "at");
        let session = width(contradictions.iter().map(|row| &row.session_id), "session");

        let _ = writeln!(text);
        let _ = writeln!(
            text,
            "{:<tool$}  {:<at$}  {:<session$}  request",
            "tool", "at", "session"
        );

        // The fingerprint of the human answer, and never the request itself: the digest is
        // what joins this row to the `:permission` ledger entry beside it, which is where an
        // operator goes to see what was actually asked.
        for row in contradictions.iter().take(MAX_ROWS_SHOWN) {
            let _ = writeln!(
                text,
                "{:<tool$}  {:<at$}  {:<session$}  {}",
                row.tool,
                row.at,
                row.session_id,
                short(&row.fingerprint)
            );
        }
    }

    text
}

// ---------------------------------------------------------------------------
// The report file
// ---------------------------------------------------------------------------

/// Reads a report file, bounded, and refuses anything that is not a JSON object.
///
/// Refusing here rather than letting the runtime do it is the difference between "that is
/// not a report" naming the file and an `invalid_params` naming a parameter the operator
/// never typed.
pub fn read_report(path: &Path) -> Result<Value> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading the replay report at {}", path.display()))?;

    if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
        bail!(
            "{} is not a regular file, so it is not a replay report",
            path.display()
        );
    }

    let mut buffer = Vec::new();

    std::fs::File::open(path)
        .with_context(|| format!("reading the replay report at {}", path.display()))?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut buffer)
        .with_context(|| format!("reading the replay report at {}", path.display()))?;

    if buffer.len() as u64 > MAX_REPORT_BYTES {
        bail!(
            "{} is larger than {MAX_REPORT_BYTES} bytes; a replay report is a few kilobytes",
            path.display()
        );
    }

    let report: Value = serde_json::from_slice(&buffer)
        .with_context(|| format!("{} is not JSON", path.display()))?;

    if !report.is_object() {
        bail!(
            "{} is not a replay report: `ouro policy replay <name> --out {}` writes one",
            path.display(),
            path.display()
        );
    }

    Ok(report)
}

/// Writes the report `promote --evidence` reads back, pretty and newline-terminated so it
/// diffs and so `cat` leaves a prompt where it belongs.
fn write_report(path: &Path, report: &Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(report)?;
    text.push('\n');

    std::fs::write(path, text)
        .with_context(|| format!("writing the replay report to {}", path.display()))
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

struct ToolRow {
    tool: String,
    allowed: String,
    promoted_at: String,
    actor: String,
    decisions: String,
    contradictions: String,
}

impl ToolRow {
    fn from(entry: &Value, allowed: &[String]) -> Self {
        let tool = field(entry, "tool").unwrap_or_else(|| "?".to_string());

        Self {
            allowed: if allowed.contains(&tool) { "yes" } else { "no" }.to_string(),
            tool,
            promoted_at: field(entry, "promoted_at").unwrap_or_else(|| "?".to_string()),
            actor: field(entry, "actor").unwrap_or_else(|| "?".to_string()),
            decisions: count_at(entry, "/evidence/decisions"),
            contradictions: count_at(entry, "/evidence/contradictions"),
        }
    }
}

struct DemotionRow {
    tool: String,
    at: String,
    reason: String,
    session_id: String,
}

impl From<&Value> for DemotionRow {
    fn from(entry: &Value) -> Self {
        Self {
            tool: field(entry, "tool").unwrap_or_else(|| "?".to_string()),
            at: field(entry, "at").unwrap_or_else(|| "?".to_string()),
            reason: field(entry, "reason").unwrap_or_else(|| "unstated".to_string()),
            session_id: field(entry, "session_id").unwrap_or_else(|| "-".to_string()),
        }
    }
}

struct CountRow {
    tool: String,
    decisions: u64,
    agreements: u64,
    contradictions: u64,
    would_resolve: u64,
    stricter: u64,
    asks: u64,
    unreadable: u64,
}

impl CountRow {
    fn from(tool: &str, counts: &Value) -> Self {
        let at = |key: &str| counts.get(key).and_then(Value::as_u64).unwrap_or(0);

        Self {
            tool: tool.to_string(),
            decisions: at("decisions"),
            agreements: at("agreements"),
            contradictions: at("contradictions"),
            would_resolve: at("would_resolve"),
            stricter: at("stricter"),
            asks: at("asks"),
            unreadable: at("unreadable"),
        }
    }
}

struct ContradictionRow {
    tool: String,
    at: String,
    session_id: String,
    fingerprint: String,
}

fn contradiction_rows(tools: &[(String, &Value)]) -> Vec<ContradictionRow> {
    let mut rows = Vec::new();

    for (tool, counts) in tools {
        for row in counts
            .get("contradiction_rows")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            rows.push(ContradictionRow {
                tool: tool.clone(),
                at: field(row, "at").unwrap_or_else(|| "?".to_string()),
                session_id: field(row, "session_id").unwrap_or_else(|| "-".to_string()),
                fingerprint: field(row, "fingerprint").unwrap_or_else(|| "?".to_string()),
            });
        }
    }

    rows
}

// ---------------------------------------------------------------------------
// Sentences and fields
// ---------------------------------------------------------------------------

/// What the node says about its corpus, which is counts and nothing else.
fn corpus_sentence(answer: &Value) -> String {
    let records = number(answer, "/evidence/records");

    let mut per_tool: Vec<(String, u64)> = answer
        .pointer("/evidence/by_tool")
        .and_then(Value::as_object)
        .map(|table| {
            table
                .iter()
                .map(|(tool, count)| (tool.clone(), count.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();

    // Largest first, and by name where two are equal, so the sentence is a function of the
    // answer rather than of the order a map was walked in.
    per_tool.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let mut sentence = format!("{records} answers");

    if !per_tool.is_empty() {
        let named: Vec<String> = per_tool
            .iter()
            .map(|(tool, count)| format!("{count} {tool}"))
            .collect();

        let _ = write!(sentence, " ({})", named.join(", "));
    }

    let degraded = [
        (number(answer, "/evidence/without_document"), "no document"),
        (number(answer, "/evidence/unreadable"), "unreadable"),
    ];

    for (count, what) in degraded {
        if count > 0 {
            let _ = write!(sentence, ", {count} {what}");
        }
    }

    sentence
}

/// The thresholds **this node** holds, read out of its own answer rather than restated here.
fn gate_sentence(answer: &Value) -> String {
    match (
        answer
            .pointer("/thresholds/decisions")
            .and_then(Value::as_u64),
        answer
            .pointer("/thresholds/contradictions")
            .and_then(Value::as_u64),
    ) {
        (Some(decisions), Some(contradictions)) => {
            format!("{decisions} decisions and at most {contradictions} contradictions, per tool")
        }
        _ => "this runtime did not state its thresholds".to_string(),
    }
}

fn field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|found| !found.is_empty())
        .map(str::to_string)
}

/// A count at a JSON pointer, or zero. Zero rather than `None` because every number these
/// verbs answer with is a count, and a count nobody sent is a count of nothing.
fn number(value: &Value, pointer: &str) -> u64 {
    value.pointer(pointer).and_then(Value::as_u64).unwrap_or(0)
}

fn count_at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .map(|count| count.to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn list(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

/// The first sixteen characters of a digest. Enough to find a row and short enough that a
/// table fits, which is the same prefix the runtime's own log lines use.
fn short(digest: &str) -> &str {
    if digest.len() > 16 {
        &digest[..16]
    } else {
        digest
    }
}

fn width<'a>(values: impl Iterator<Item = &'a String>, header: &str) -> usize {
    values
        .map(|value| value.chars().count())
        .max()
        .unwrap_or(0)
        .max(header.chars().count())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> Value {
        json!({
            "node": "ouroboros@studio",
            "policy": {
                "name": "no-network-shell",
                "component_sha256": "b".repeat(64),
            },
            "tools": [
                {
                    "tool": "bash",
                    "seq": 1,
                    "promoted_at": "2026-01-01T00:00:00.000000Z",
                    "actor": "operator:ana",
                    "evidence": {
                        "report_sha256": "d".repeat(64),
                        "decisions": 214,
                        "contradictions": 0,
                        "replayed_at": "2026-01-01T00:00:00.000000Z"
                    }
                },
                {
                    "tool": "read",
                    "seq": 3,
                    "promoted_at": "2026-01-01T00:01:30.000000Z",
                    "actor": "operator:ana",
                    "evidence": {
                        "report_sha256": "e".repeat(64),
                        "decisions": 63,
                        "contradictions": 0,
                        "replayed_at": "2026-01-01T00:01:30.000000Z"
                    }
                }
            ],
            "demotions": [
                {
                    "tool": "bash",
                    "seq": 4,
                    "at": "2026-01-01T00:01:30.000000Z",
                    "reason": "human_contradiction",
                    "fingerprint": "a".repeat(64),
                    "session_id": "session-1"
                }
            ],
            "allowable_tools": ["read"],
            "durability": "synced_checkpoint",
            "thresholds": {"decisions": 50, "contradictions": 0},
            "evidence": {
                "records": 277,
                "by_tool": {"bash": 214, "read": 63},
                "without_document": 0,
                "unreadable": 0
            }
        })
    }

    fn report() -> Value {
        json!({
            "policy_name": "no-network-shell",
            "component_sha256": "b".repeat(64),
            "corpus_size": 277,
            "unreadable": 0,
            "since": null,
            "replayed_at": "2026-01-01T00:00:00.000000Z",
            "report_sha256": "1234567890abcdef1111111111111111111111111111111111111111111111ff",
            "per_tool": {
                "read": {
                    "decisions": 63, "agreements": 57, "contradictions": 0,
                    "would_resolve": 41, "stricter": 4, "asks": 2, "unreadable": 0,
                    "contradiction_rows": []
                },
                "bash": {
                    "decisions": 214, "agreements": 180, "contradictions": 2,
                    "would_resolve": 24, "stricter": 9, "asks": 23, "unreadable": 0,
                    "contradiction_rows": [
                        {"fingerprint": "a".repeat(64), "session_id": "session-1",
                         "at": "2026-01-01T00:00:00.000000Z"}
                    ]
                }
            }
        })
    }

    #[test]
    fn the_two_verbs_that_take_nothing_send_an_empty_object() {
        // Both envelopes are closed, so anything this client invented would be `-32602`.
        assert_eq!(no_params(), json!({}));
    }

    #[test]
    fn an_absent_since_is_an_absent_param() {
        let params = replay_params(&ReplayOptions {
            name: "no-network-shell".into(),
            ..ReplayOptions::default()
        });

        assert_eq!(params, json!({"name": "no-network-shell"}));

        let narrowed = replay_params(&ReplayOptions {
            name: "no-network-shell".into(),
            since: Some("2026-08-01T00:00:00Z".into()),
            ..ReplayOptions::default()
        });

        assert_eq!(
            narrowed,
            json!({"name": "no-network-shell", "since": "2026-08-01T00:00:00Z"})
        );
    }

    #[test]
    fn promote_sends_the_report_whole_and_never_an_actor() {
        // The actor is the identity the connection authenticated as, read by the runtime
        // from its own side of the socket. A client that could name one could promote under
        // anybody's.
        let params = promote_params("no-network-shell", "bash", report());
        let object = params.as_object().expect("an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(keys, vec!["name", "report", "tool"]);
        assert_eq!(object["report"], report());
    }

    #[test]
    fn demote_carries_the_sentence_the_operator_typed() {
        let params = demote_params(&DemoteOptions {
            name: "no-network-shell".into(),
            tool: "bash".into(),
            reason: "it allowed a curl a human denied".into(),
            json: false,
        });

        assert_eq!(
            params,
            json!({
                "name": "no-network-shell",
                "tool": "bash",
                "reason": "it allowed a curl a human denied"
            })
        );
    }

    #[test]
    fn the_record_table_separates_promoted_from_allowed() {
        let text = render_status(&status());

        assert!(
            text.contains("no-network-shell @ bbbbbbbbbbbbbbbb"),
            "{text}"
        );
        assert!(text.contains("synced_checkpoint"), "{text}");

        // Both tools are promoted; only one is allowed, because a demotion newer than a
        // promotion withdrew the other. A table that showed only `allowable_tools` would
        // hide the fact that `bash` was ever promoted at all.
        let bash = text
            .lines()
            .find(|line| line.starts_with("bash "))
            .expect("a bash row");
        let read = text
            .lines()
            .find(|line| line.starts_with("read "))
            .expect("a read row");

        assert!(bash.contains("no"), "{bash}");
        assert!(bash.contains("214"), "{bash}");
        assert!(read.contains("yes"), "{read}");
        assert!(read.contains("operator:ana"), "{read}");

        // The demotion is its own section, and it names the term the record stored rather
        // than any sentence anybody typed.
        assert!(text.contains("human_contradiction"), "{text}");
        assert!(text.contains("session-1"), "{text}");
    }

    #[test]
    fn the_gate_is_the_node_s_own_numbers() {
        let text = render_status(&status());
        assert!(
            text.contains("50 decisions and at most 0 contradictions"),
            "{text}"
        );

        // A runtime that did not state them is said so rather than filled in from a
        // constant compiled into this client.
        let mut silent = status();
        silent
            .as_object_mut()
            .expect("an object")
            .remove("thresholds");

        let text = render_status(&silent);
        assert!(text.contains("did not state its thresholds"), "{text}");
        assert!(!text.contains("50 decisions"), "{text}");
    }

    #[test]
    fn an_empty_record_is_an_answer_rather_than_an_empty_table() {
        let empty = json!({
            "node": "ouroboros@studio",
            "policy": null,
            "tools": [],
            "demotions": [],
            "allowable_tools": [],
            "durability": "ephemeral_checkpoint",
            "thresholds": {"decisions": 50, "contradictions": 0},
            "evidence": {
                "records": 148,
                "by_tool": {"bash": 96, "read": 40, "web_fetch": 12},
                "without_document": 1,
                "unreadable": 0
            }
        });

        let text = render_status(&empty);

        assert!(text.contains("nothing promoted on this node"), "{text}");
        // Largest first, so the sentence does not depend on how a map was walked.
        assert!(
            text.contains("148 answers (96 bash, 40 read, 12 web_fetch)"),
            "{text}"
        );
        assert!(text.contains("1 no document"), "{text}");
        // No table at all rather than a header over nothing.
        assert!(!text.contains("contradictions\n"), "{text}");
    }

    #[test]
    fn a_record_that_could_not_be_read_is_not_a_record_that_is_empty() {
        // `Control.PolicyPromotion.status/0` answers `durability: unavailable` with empty
        // lists when its authority is down. Nothing is allowable while that is true, which is
        // the safe direction; printing it as "nothing promoted" would be reading a failure as
        // a fact.
        let unavailable = json!({
            "node": "ouroboros@studio",
            "policy": null,
            "tools": [],
            "demotions": [],
            "allowable_tools": [],
            "durability": "unavailable",
            "thresholds": {"decisions": 50, "contradictions": 0},
            "evidence": {"records": 0, "by_tool": {}, "without_document": 0, "unreadable": 0}
        });

        let text = render_status(&unavailable);

        assert!(text.contains("not answering on this node"), "{text}");
        assert!(!text.contains("nothing promoted"), "{text}");
    }

    #[test]
    fn the_report_table_prints_the_counts_and_derives_nothing() {
        let text = render_report(&report());

        assert!(
            text.contains("no-network-shell @ bbbbbbbbbbbbbbbb"),
            "{text}"
        );
        assert!(text.contains("277 rows, 0 unreadable"), "{text}");
        // An absent `since` is the whole corpus, said rather than left blank.
        assert!(text.contains("the whole corpus"), "{text}");
        assert!(text.contains("1234567890abcdef"), "{text}");

        // Tools in name order, so two runs over one report are two identical pages.
        let bash = text.find("\nbash ").expect("a bash row");
        let read = text.find("\nread ").expect("a read row");
        assert!(bash < read, "{text}");

        // No verdict column: whether a tool has earned a promotion is decided by the node,
        // in the re-run it performs, against thresholds this client never holds.
        assert!(!text.contains("promotable"), "{text}");
        assert!(!text.contains("earned"), "{text}");
    }

    #[test]
    fn a_contradiction_row_names_a_digest_and_never_a_request() {
        let text = render_report(&report());

        assert!(text.contains("session-1"), "{text}");
        assert!(text.contains("aaaaaaaaaaaaaaaa"), "{text}");
        // The whole point of the corpus never crossing the wire: there is no field here
        // that could hold one, and no renderer that would print it.
        assert!(!text.contains("curl"), "{text}");
        assert!(!text.contains("document"), "{text}");
    }

    #[test]
    fn a_report_over_a_corpus_with_nothing_in_it_says_so() {
        let text = render_report(&json!({
            "policy_name": "guard",
            "component_sha256": "c".repeat(64),
            "corpus_size": 0,
            "unreadable": 0,
            "per_tool": {}
        }));

        assert!(
            text.contains("no decisions in the corpus to replay"),
            "{text}"
        );
    }

    #[test]
    fn a_report_file_round_trips_and_a_directory_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "ouro-policy-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock")
                .as_nanos()
        ));

        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("report.json");

        write_report(&path, &report()).expect("a written report");
        assert_eq!(read_report(&path).expect("a read report"), report());

        // A directory is not a report, and neither is a file that is not an object.
        assert!(read_report(&dir).is_err());

        std::fs::write(&path, "[1, 2, 3]").expect("a written array");
        let refusal = read_report(&path).expect_err("an array is not a report");
        assert!(format!("{refusal:#}").contains("is not a replay report"));

        std::fs::write(&path, "not json at all").expect("a written non-report");
        let refusal = read_report(&path).expect_err("bytes that are not JSON");
        assert!(format!("{refusal:#}").contains("is not JSON"));

        // The bound is on what is read rather than on what a stat claims.
        std::fs::write(&path, vec![b'x'; (MAX_REPORT_BYTES + 2) as usize]).expect("a big file");
        let refusal = read_report(&path).expect_err("a report past the bound");
        assert!(format!("{refusal:#}").contains("larger than"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
