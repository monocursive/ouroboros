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
//!
//! ## One decode contract, and every string from the node goes through it
//!
//! The gateway on the other end is authenticated and **not trusted**: a session's own bash
//! can reach it, and the module doc above is a claim about what a well-behaved runtime sends
//! rather than about what this client would print if it sent something else. So every string
//! that arrives passes [`text`] before it is measured or written:
//!
//!   * control characters are blanked ([`crate::model::plain`] — the repo's rule, stated at
//!     `agents.rs:59-63`), because these pages are `write!`d straight to a terminal and an
//!     escape sequence in a tool name is a node repainting somebody else's screen;
//!   * a value over [`MAX_FIELD_BYTES`] is cut on a character boundary with a marker, so a
//!     60 kB tool name is 4 kB of page rather than 60 kB times every row;
//!   * and every column width is capped at [`MAX_COLUMN`], so one long value cannot pad the
//!     whole table out to its own length. Rust packs a `{:width$}` into a `u16`, so an
//!     uncapped width is also a formatter panic at 65 536.
//!
//! [`short`] is the same rule for digests: it prints a prefix only when the value really is
//! `[0-9a-f]{64}` and `?` otherwise, and it slices ASCII it has already checked rather than
//! bytes it has not — the byte slice it replaced panicked on any non-ASCII digest.

use std::fmt::Write as _;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::model::plain;
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
/// report from a runtime that ever raised its own bound still fits a screen. What is over
/// the bound is *said* rather than dropped silently — see `omitted`.
const MAX_ROWS_SHOWN: usize = 20;

/// How many promoted rows the record table prints. A record holds one row per promoted
/// `(tool, shape)` and nothing in the protocol bounds how many an operator may make.
const MAX_SHAPES_SHOWN: usize = 64;

/// The bytes of any one string from the node that reach a page. Four kibibytes is far more
/// than a tool name, a shape or an actor id ever is, and far less than the 8 MiB frame the
/// transport admits (`transport.rs:63`).
pub const MAX_FIELD_BYTES: usize = 4096;

/// The characters any one column may be padded to. A column is as wide as its widest value
/// until it is this wide, and then it stops: one long value must not multiply every row.
pub const MAX_COLUMN: usize = 64;

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
    /// The command prefix this promotion is about. A promotion is per `(tool, shape)`, so a
    /// shape is as required as the tool is.
    pub shape: String,
    /// The report file a previous `replay --out` wrote.
    pub evidence: PathBuf,
    pub json: bool,
}

/// `ouro policy demote`'s flags.
#[derive(Debug, Clone, Default)]
pub struct DemoteOptions {
    pub name: String,
    pub tool: String,
    /// The command prefix whose promotion is withdrawn. Narrowing is per shape too:
    /// demoting `mix test` leaves `mix` standing.
    pub shape: String,
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
pub fn promote_params(name: &str, tool: &str, shape: &str, report: Value) -> Value {
    json!({"name": name, "tool": tool, "shape": shape, "report": report})
}

/// The `policy.demote` parameter object.
pub fn demote_params(options: &DemoteOptions) -> Value {
    json!({
        "name": options.name,
        "tool": options.tool,
        "shape": options.shape,
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
    let params = promote_params(&options.name, &options.tool, &options.shape, report);
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
/// Five header lines and, where the record holds anything, a row per promoted `(tool, shape)`
/// and a row per demotion. Promotion is per shape (S-D27), so `bash` can appear twice with
/// different command prefixes and different answers in the `allowed` column.
///
/// `allowed` is the column that matters: a shape can be promoted and *not* allowed, because a
/// demotion newer than its promotion withdrew it, and the two facts sit beside each other
/// rather than one hiding the other.
///
/// `submitted` is the digest of the report the operator handed in, under the name the runtime
/// gives it — `report_sha256_as_submitted`. It is a keyless sha256 over that file's own
/// contents: it says the file was not edited between the replay and the promotion, and nothing
/// about who produced the numbers. The numbers beside it are the node's own re-run.
pub fn render_status(answer: &Value) -> String {
    let mut page = String::new();

    let durability = field(answer, "durability").unwrap_or_else(|| "unknown".to_string());

    let policy = match (
        answer.pointer("/policy/name").and_then(Value::as_str),
        answer
            .pointer("/policy/component_sha256")
            .and_then(Value::as_str),
    ) {
        (Some(name), Some(sha)) => format!("{} @ {}", text(name), short(sha)),
        // `unavailable` is the record saying it could not answer, and an empty record and a
        // record nobody could read are different facts. The runtime's own direction of failure
        // is the safe one — nothing is allowable while the authority is down — but a person
        // reading this page has to be able to tell "nothing promoted" from "nothing known".
        _ if durability == "unavailable" => {
            "the promotion record is not answering on this node".to_string()
        }
        _ => "nothing promoted on this node".to_string(),
    };

    let _ = writeln!(page, "policy   {policy}");
    let _ = writeln!(page, "record   {durability}");
    let _ = writeln!(page, "corpus   {}", corpus_sentence(answer));
    let _ = writeln!(page, "gate     {}", gate_sentence(answer));
    let _ = writeln!(page, "shadow   {}", shadow_sentence(answer));

    let promoted = array(answer, "tools");

    if !promoted.is_empty() {
        let rows: Vec<ToolRow> = promoted
            .iter()
            .take(MAX_SHAPES_SHOWN)
            .map(ToolRow::from)
            .collect();

        let tool = width(rows.iter().map(|row| &row.tool), "tool");
        let shape = width(rows.iter().map(|row| &row.shape), "shape");
        let promoted_at = width(rows.iter().map(|row| &row.promoted_at), "promoted");
        let actor = width(rows.iter().map(|row| &row.actor), "actor");

        let _ = writeln!(page);
        let _ = writeln!(
            page,
            "{:<tool$}  {:<shape$}  {:<7}  {:<promoted_at$}  {:<actor$}  {:>9}  {:>8}  submitted",
            "tool", "shape", "allowed", "promoted", "actor", "decisions", "resolves"
        );

        for row in &rows {
            let _ = writeln!(
                page,
                "{:<tool$}  {:<shape$}  {:<7}  {:<promoted_at$}  {:<actor$}  {:>9}  {:>8}  {}",
                row.tool,
                row.shape,
                row.allowed,
                row.promoted_at,
                row.actor,
                row.decisions,
                row.resolves,
                row.submitted
            );
        }

        omitted(
            &mut page,
            promoted.len(),
            MAX_SHAPES_SHOWN,
            "promoted shapes",
        );
    }

    let demotions = array(answer, "demotions");

    if !demotions.is_empty() {
        let rows: Vec<DemotionRow> = demotions
            .iter()
            .take(MAX_ROWS_SHOWN)
            .map(DemotionRow::from)
            .collect();

        let tool = width(rows.iter().map(|row| &row.tool), "tool");
        let shape = width(rows.iter().map(|row| &row.shape), "shape");
        let at = width(rows.iter().map(|row| &row.at), "at");
        let reason = width(rows.iter().map(|row| &row.reason), "reason");
        let by = width(rows.iter().map(|row| &row.actor), "by");

        let _ = writeln!(page);
        let _ = writeln!(
            page,
            "{:<tool$}  {:<shape$}  {:<at$}  {:<reason$}  {:<by$}  session",
            "tool", "shape", "at", "reason", "by"
        );

        for row in &rows {
            let _ = writeln!(
                page,
                "{:<tool$}  {:<shape$}  {:<at$}  {:<reason$}  {:<by$}  {}",
                row.tool, row.shape, row.at, row.reason, row.actor, row.session_id
            );
        }

        omitted(&mut page, demotions.len(), MAX_ROWS_SHOWN, "demotions");
    }

    page
}

/// A replay report as a person reads it.
///
/// Two tables. The per-tool one is the seven counts, and nothing derived from them. The
/// per-shape one is where a promotion is actually decided (S-D27), and it carries a `needs`
/// row taken from the report's **own** `thresholds` block, so an operator can read down a
/// column and see which shapes clear this node's bar and by how much.
///
/// The numbers in the `needs` row are the node's, not this client's. That is the same posture
/// as everywhere else here: a threshold compiled into a client is a client's opinion wearing
/// the node's clothes, and a report from a runtime that did not state its thresholds says so.
///
/// `decisions` is `agreements + contradictions + stricter + asks`, and `agreements` contains
/// `would_resolve` — which is the number that says whether a promotion is worth making,
/// because it counts the prompts it would remove. `requests` and `sessions` count only the
/// rows answered **definitely**, so both are at most `decisions - asks`.
pub fn render_report(answer: &Value) -> String {
    let mut page = String::new();

    let policy = match (
        answer.get("policy_name").and_then(Value::as_str),
        answer.get("component_sha256").and_then(Value::as_str),
    ) {
        (Some(name), Some(sha)) => format!("{} @ {}", text(name), short(sha)),
        (None, Some(sha)) => short(sha),
        _ => "an unnamed component".to_string(),
    };

    let _ = writeln!(page, "policy    {policy}");
    let _ = writeln!(
        page,
        "corpus    {} rows, {} unreadable",
        number(answer, "/corpus_size"),
        number(answer, "/unreadable")
    );
    let _ = writeln!(
        page,
        "since     {}",
        field(answer, "since").unwrap_or_else(|| "the whole corpus".to_string())
    );
    let _ = writeln!(
        page,
        "replayed  {}",
        field(answer, "replayed_at").unwrap_or_else(|| "?".to_string())
    );
    let _ = writeln!(
        page,
        "report    {}",
        answer
            .get("report_sha256")
            .and_then(Value::as_str)
            .map(short)
            .unwrap_or_else(|| "unsealed".to_string())
    );

    let tools = table(answer, "per_tool");

    if tools.is_empty() {
        let _ = writeln!(page, "\nno decisions in the corpus to replay");
        return page;
    }

    let rows: Vec<CountRow> = tools
        .iter()
        .map(|(tool, counts)| CountRow::from(tool, counts))
        .collect();

    let tool = width(rows.iter().map(|row| &row.tool), "tool");

    let _ = writeln!(page);
    let _ = writeln!(
        page,
        "{:<tool$}  decisions  agreements  contradictions  would_resolve  stricter  asks  unreadable",
        "tool"
    );

    for row in &rows {
        let _ = writeln!(
            page,
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

    shape_table(&mut page, answer, &tools);
    contradiction_table(&mut page, &tools);

    page
}

/// The per-shape half, with this node's own thresholds in a `needs` row above the numbers.
fn shape_table(page: &mut String, answer: &Value, tools: &[(String, &Value)]) {
    let mut rows: Vec<ShapeRow> = Vec::new();

    for (tool, _counts) in tools {
        for (shape, counts) in table(answer, "per_shape")
            .into_iter()
            .find(|(named, _)| named == tool)
            .map(|(_, shapes)| table(shapes, ""))
            .unwrap_or_default()
        {
            rows.push(ShapeRow::from(tool, &shape, counts));
        }
    }

    if rows.is_empty() {
        return;
    }

    let needs = Needs::from(answer);
    let tool = width(
        rows.iter().map(|row| &row.tool).chain([&needs.label]),
        "tool",
    );
    let shape = width(rows.iter().map(|row| &row.shape), "shape");

    let _ = writeln!(page);
    let _ = writeln!(
        page,
        "{:<tool$}  {:<shape$}  {:>9}  {:>14}  {:>10}  {:>8}  {:>8}  {:>8}",
        "tool",
        "shape",
        "decisions",
        "contradictions",
        "unreadable",
        "requests",
        "sessions",
        "resolves"
    );

    let _ = writeln!(
        page,
        "{:<tool$}  {:<shape$}  {:>9}  {:>14}  {:>10}  {:>8}  {:>8}  {:>8}",
        needs.label,
        "",
        "",
        needs.contradictions,
        needs.unreadable,
        needs.distinct_fingerprints,
        needs.distinct_sessions,
        needs.would_resolve
    );

    for row in rows.iter().take(MAX_SHAPES_SHOWN) {
        let _ = writeln!(
            page,
            "{:<tool$}  {:<shape$}  {:>9}  {:>14}  {:>10}  {:>8}  {:>8}  {:>8}",
            row.tool,
            row.shape,
            row.decisions,
            row.contradictions,
            row.unreadable,
            row.distinct_fingerprints,
            row.distinct_sessions,
            row.would_resolve
        );
    }

    omitted(page, rows.len(), MAX_SHAPES_SHOWN, "shapes");
}

fn contradiction_table(page: &mut String, tools: &[(String, &Value)]) {
    let contradictions = contradiction_rows(tools);

    if contradictions.is_empty() {
        return;
    }

    let tool = width(contradictions.iter().map(|row| &row.tool), "tool");
    let at = width(contradictions.iter().map(|row| &row.at), "at");
    let session = width(contradictions.iter().map(|row| &row.session_id), "session");

    let _ = writeln!(page);
    let _ = writeln!(
        page,
        "{:<tool$}  {:<at$}  {:<session$}  request",
        "tool", "at", "session"
    );

    // The fingerprint of the human answer, and never the request itself: the digest is what
    // joins this row to the `:permission` ledger entry beside it, which is where an operator
    // goes to see what was actually asked.
    for row in contradictions.iter().take(MAX_ROWS_SHOWN) {
        let _ = writeln!(
            page,
            "{:<tool$}  {:<at$}  {:<session$}  {}",
            row.tool,
            row.at,
            row.session_id,
            short(&row.fingerprint)
        );
    }

    omitted(page, contradictions.len(), MAX_ROWS_SHOWN, "contradictions");
}

/// What a bound left out, said rather than dropped. A table that silently stops at twenty is a
/// table somebody reads as "there were twenty".
fn omitted(page: &mut String, total: usize, shown: usize, what: &str) {
    if total > shown {
        let _ = writeln!(page, "… {} more {what} not shown", total - shown);
    }
}

// ---------------------------------------------------------------------------
// The report file
// ---------------------------------------------------------------------------

/// Reads a report file, bounded, and refuses anything that is not a JSON object.
///
/// Refusing here rather than letting the runtime do it is the difference between "that is
/// not a report" naming the file and an `invalid_params` naming a parameter the operator
/// never typed.
///
/// The type check is on the **open handle**, not on the path. `symlink_metadata` answers about
/// whatever the name pointed at when it was asked, and the thing opened a moment later need
/// not be the same object; `File::metadata` is an `fstat` on the descriptor already held, so
/// what is checked and what is read are the same file. The bound is on what a read returns
/// rather than on what a stat claims, for `wasm_deploy_cli`'s reason: `/dev/zero` and a
/// growing file both report a length that has nothing to do with what comes back.
pub fn read_report(path: &Path) -> Result<Value> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("reading the replay report at {}", path.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("reading the replay report at {}", path.display()))?;

    if !metadata.file_type().is_file() {
        bail!(
            "{} is not a regular file, so it is not a replay report",
            path.display()
        );
    }

    let mut buffer = Vec::new();

    file.take(MAX_REPORT_BYTES + 1)
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
    shape: String,
    allowed: String,
    promoted_at: String,
    actor: String,
    decisions: String,
    resolves: String,
    submitted: String,
}

impl From<&Value> for ToolRow {
    fn from(entry: &Value) -> Self {
        Self {
            tool: field(entry, "tool").unwrap_or_else(|| "?".to_string()),
            shape: field(entry, "shape").unwrap_or_else(|| "?".to_string()),
            // The runtime decides this: `allowed` is `shape in allowable[tool]`, computed
            // where the record is. A client that recomputed it from `allowable` would be a
            // second implementation of the gate, and the two would eventually disagree.
            allowed: match entry.get("allowed").and_then(Value::as_bool) {
                Some(true) => "yes".to_string(),
                Some(false) => "no".to_string(),
                None => "?".to_string(),
            },
            promoted_at: field(entry, "promoted_at").unwrap_or_else(|| "?".to_string()),
            actor: field(entry, "actor").unwrap_or_else(|| "?".to_string()),
            decisions: count_at(entry, "/evidence/decisions"),
            resolves: count_at(entry, "/evidence/would_resolve"),
            submitted: entry
                .pointer("/evidence/report_sha256_as_submitted")
                .and_then(Value::as_str)
                .map(short)
                .unwrap_or_else(|| "?".to_string()),
        }
    }
}

struct DemotionRow {
    tool: String,
    shape: String,
    at: String,
    reason: String,
    actor: String,
    session_id: String,
}

impl From<&Value> for DemotionRow {
    fn from(entry: &Value) -> Self {
        Self {
            tool: field(entry, "tool").unwrap_or_else(|| "?".to_string()),
            shape: field(entry, "shape").unwrap_or_else(|| "?".to_string()),
            at: field(entry, "at").unwrap_or_else(|| "?".to_string()),
            reason: field(entry, "reason").unwrap_or_else(|| "unstated".to_string()),
            // The canary names no actor — it is the runtime narrowing on a human's
            // contradiction — and an operator's demotion does.
            actor: field(entry, "actor").unwrap_or_else(|| "the runtime".to_string()),
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
            tool: text(tool),
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

struct ShapeRow {
    tool: String,
    shape: String,
    decisions: u64,
    contradictions: u64,
    unreadable: u64,
    distinct_fingerprints: u64,
    distinct_sessions: u64,
    would_resolve: u64,
}

impl ShapeRow {
    fn from(tool: &str, shape: &str, counts: &Value) -> Self {
        let at = |key: &str| counts.get(key).and_then(Value::as_u64).unwrap_or(0);

        Self {
            tool: text(tool),
            shape: text(shape),
            decisions: at("decisions"),
            contradictions: at("contradictions"),
            unreadable: at("unreadable"),
            distinct_fingerprints: at("distinct_fingerprints"),
            distinct_sessions: at("distinct_sessions"),
            would_resolve: at("would_resolve"),
        }
    }
}

/// The five numbers **this report says** a promotion had to clear, rendered as a row above the
/// measurements. Every one of them is read out of the report; a report that states none is
/// said to state none.
struct Needs {
    label: String,
    contradictions: String,
    unreadable: String,
    distinct_fingerprints: String,
    distinct_sessions: String,
    would_resolve: String,
}

impl Needs {
    fn from(answer: &Value) -> Self {
        let at = |key: &str| {
            answer
                .pointer(&format!("/thresholds/{key}"))
                .and_then(Value::as_u64)
        };

        let most = |key: &str| at(key).map(|n| format!("max {n}")).unwrap_or_default();
        let least = |key: &str| at(key).map(|n| format!("min {n}")).unwrap_or_default();

        let stated = ["contradictions", "unreadable", "distinct_fingerprints"]
            .iter()
            .any(|key| at(key).is_some());

        Self {
            label: if stated {
                "needs".to_string()
            } else {
                "(no thresholds stated)".to_string()
            },
            contradictions: most("contradictions"),
            unreadable: most("unreadable"),
            distinct_fingerprints: least("distinct_fingerprints"),
            distinct_sessions: least("distinct_sessions"),
            would_resolve: least("would_resolve"),
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
                tool: text(tool),
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
///
/// `by_tool` is the busiest tools the runtime chose to name and `other_tools`/`other_records`
/// are what it left out, because the corpus is bounded by rows rather than by how many
/// distinct tool names those rows carry.
fn corpus_sentence(answer: &Value) -> String {
    let records = number(answer, "/evidence/records");

    let mut per_tool: Vec<(String, u64)> = answer
        .pointer("/evidence/by_tool")
        .and_then(Value::as_object)
        .map(|table| {
            table
                .iter()
                .map(|(tool, count)| (text(tool), count.as_u64().unwrap_or(0)))
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
            .take(MAX_ROWS_SHOWN)
            .map(|(tool, count)| format!("{count} {tool}"))
            .collect();

        let _ = write!(sentence, " ({})", named.join(", "));
    }

    let others = number(answer, "/evidence/other_tools");

    if others > 0 {
        let _ = write!(
            sentence,
            ", {others} other tools with {} answers",
            number(answer, "/evidence/other_records")
        );
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

    // A corpus nobody could read is a different fact from an empty one, and the runtime says
    // which by putting a term in `error` rather than by answering zero quietly.
    if let Some(error) = answer
        .pointer("/evidence/error")
        .and_then(Value::as_str)
        .map(text)
        .filter(|error| !error.is_empty())
    {
        let _ = write!(sentence, " — the corpus could not be read: {error}");
    }

    sentence
}

/// The thresholds **this node** holds, read out of its own answer rather than restated here.
fn gate_sentence(answer: &Value) -> String {
    let at = |key: &str| {
        answer
            .pointer(&format!("/thresholds/{key}"))
            .and_then(Value::as_u64)
    };

    match (
        at("distinct_fingerprints"),
        at("distinct_sessions"),
        at("would_resolve"),
        at("contradictions"),
        at("unreadable"),
    ) {
        (
            Some(requests),
            Some(sessions),
            Some(resolves),
            Some(contradictions),
            Some(unreadable),
        ) => {
            format!(
                "{requests} distinct requests in {sessions} sessions, {resolves} it would \
                 resolve, at most {contradictions} contradictions for the tool and \
                 {unreadable} unreadable in the shape"
            )
        }
        _ => "this runtime did not state its thresholds".to_string(),
    }
}

/// How often a promoted shape is put to a person anyway (S-D29), in the node's own number.
fn shadow_sentence(answer: &Value) -> String {
    match answer.get("shadow_every").and_then(Value::as_u64) {
        Some(0) => {
            "sampling is off: nothing inside a promoted shape is ever put to a person".to_string()
        }
        Some(every) => format!("every {every}th honoured allow is put to a person anyway"),
        None => "this runtime did not say how often it samples a promoted shape".to_string(),
    }
}

/// A string the node chose, ready for a terminal this client does not own.
///
/// [`crate::model::plain`] first — the repo's rule, `agents.rs:59-63` — then a cut on a
/// character boundary with a marker. Blanked before the width is counted, so the column
/// arithmetic measures what will actually be shown.
fn text(raw: &str) -> String {
    let blanked = plain(raw.trim());

    if blanked.len() <= MAX_FIELD_BYTES {
        return blanked;
    }

    let mut end = MAX_FIELD_BYTES;

    while end > 0 && !blanked.is_char_boundary(end) {
        end -= 1;
    }

    format!("{}…", &blanked[..end])
}

fn field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(text)
        .filter(|found| !found.is_empty())
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

/// An object at `key` — or the value itself when `key` is empty — as pairs in key order, so
/// two runs over one report are two identical pages whatever order a map iterates in.
fn table<'a>(value: &'a Value, key: &str) -> Vec<(String, &'a Value)> {
    let object = if key.is_empty() {
        value.as_object()
    } else {
        value.get(key).and_then(Value::as_object)
    };

    let mut entries: Vec<(String, &Value)> = object
        .map(|table| {
            table
                .iter()
                .map(|(name, member)| (name.clone(), member))
                .collect()
        })
        .unwrap_or_default();

    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

/// The first sixteen characters of a **digest**, and `?` for anything that is not one.
///
/// The check is the point. This used to be `&digest[..16]` on whatever string arrived, and
/// `[..16]` is a *byte* range: any digest-shaped field whose seventeenth byte fell inside a
/// multi-byte character panicked the client outright, and four node-controlled fields reach
/// here. A sha256 is sixty-four lowercase hex characters; anything else is not a digest and
/// is not printed as though it were.
fn short(digest: &str) -> String {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        digest[..16].to_string()
    } else {
        "?".to_string()
    }
}

/// The width of a column: its widest value, never below its header and never above
/// [`MAX_COLUMN`].
///
/// The ceiling is not cosmetic. Rust packs a `{:width$}` into a `u16`, so a column wider than
/// 65 535 panics the formatter; and below that, a single 60 kB value pads *every* row of the
/// table out to 60 kB, which turns one hostile string into a page hundreds of times its size.
fn width<'a>(values: impl Iterator<Item = &'a String>, header: &str) -> usize {
    values
        .map(|value| value.chars().count())
        .max()
        .unwrap_or(0)
        .max(header.chars().count())
        .min(MAX_COLUMN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record fixture, in the shape the runtime answers after the S2a redesign: one row
    /// per promoted `(tool, shape)`, with `allowed` beside it.
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
                    "shape": "curl",
                    "allowed": false,
                    "seq": 1,
                    "promoted_at": "2026-01-01T00:00:00.000000Z",
                    "actor": "operator:ana",
                    "evidence": {
                        "report_sha256_as_submitted": "d".repeat(64),
                        "decisions": 214,
                        "contradictions": 0,
                        "distinct_fingerprints": 31,
                        "distinct_sessions": 4,
                        "would_resolve": 24,
                        "replayed_at": "2026-01-01T00:00:00.000000Z"
                    }
                },
                {
                    "tool": "bash",
                    "shape": "mix test",
                    "allowed": true,
                    "seq": 3,
                    "promoted_at": "2026-01-01T00:01:30.000000Z",
                    "actor": "operator:ana",
                    "evidence": {
                        "report_sha256_as_submitted": "e".repeat(64),
                        "decisions": 63,
                        "contradictions": 0,
                        "distinct_fingerprints": 22,
                        "distinct_sessions": 2,
                        "would_resolve": 41,
                        "replayed_at": "2026-01-01T00:01:30.000000Z"
                    }
                }
            ],
            "demotions": [
                {
                    "tool": "bash",
                    "shape": "curl",
                    "seq": 4,
                    "at": "2026-01-01T00:01:30.000000Z",
                    "reason": "human_contradiction",
                    "fingerprint": "a".repeat(64),
                    "session_id": "session-1",
                    "actor": null
                }
            ],
            "allowable": {"bash": ["mix test"]},
            "allowable_tools": ["bash"],
            "durability": "synced_checkpoint",
            "shadow_every": 10,
            "thresholds": {
                "contradictions": 0, "unreadable": 0, "distinct_fingerprints": 20,
                "distinct_sessions": 2, "would_resolve": 1
            },
            "evidence": {
                "records": 277,
                "by_tool": {"bash": 214, "read": 63},
                "without_document": 0,
                "unreadable": 0,
                "other_tools": 0,
                "other_records": 0,
                "error": null
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
            "thresholds": {
                "contradictions": 0, "unreadable": 0, "distinct_fingerprints": 20,
                "distinct_sessions": 2, "would_resolve": 1
            },
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
            },
            "per_shape": {
                "bash": {
                    "mix test": {
                        "decisions": 96, "agreements": 90, "contradictions": 0,
                        "would_resolve": 74, "stricter": 2, "asks": 4, "unreadable": 0,
                        "distinct_fingerprints": 41, "distinct_sessions": 6,
                        "human_denies": 2, "contradiction_rows": []
                    },
                    "curl": {
                        "decisions": 34, "agreements": 26, "contradictions": 2,
                        "would_resolve": 3, "stricter": 5, "asks": 1, "unreadable": 0,
                        "distinct_fingerprints": 12, "distinct_sessions": 1,
                        "human_denies": 7, "contradiction_rows": [
                            {"fingerprint": "a".repeat(64), "session_id": "session-1",
                             "at": "2026-01-01T00:00:00.000000Z"}
                        ]
                    }
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
    fn promote_sends_the_shape_and_never_an_actor() {
        // The actor is the identity the connection authenticated as, read by the runtime
        // from its own side of the socket. A client that could name one could promote under
        // anybody's. The shape is the other half of what a promotion is about (S-D27).
        let params = promote_params("no-network-shell", "bash", "mix test", report());
        let object = params.as_object().expect("an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(keys, vec!["name", "report", "shape", "tool"]);
        assert_eq!(object["shape"], "mix test");
        assert_eq!(object["report"], report());
    }

    #[test]
    fn demote_carries_the_shape_and_the_sentence_the_operator_typed() {
        let params = demote_params(&DemoteOptions {
            name: "no-network-shell".into(),
            tool: "bash".into(),
            shape: "curl".into(),
            reason: "it allowed a curl a human denied".into(),
            json: false,
        });

        assert_eq!(
            params,
            json!({
                "name": "no-network-shell",
                "tool": "bash",
                "shape": "curl",
                "reason": "it allowed a curl a human denied"
            })
        );
    }

    #[test]
    fn the_record_table_separates_promoted_from_allowed_per_shape() {
        let page = render_status(&status());

        assert!(
            page.contains("no-network-shell @ bbbbbbbbbbbbbbbb"),
            "{page}"
        );
        assert!(page.contains("synced_checkpoint"), "{page}");

        // Both shapes of one tool are promoted; only one is allowed, because a demotion newer
        // than a promotion withdrew the other. A table that showed only `allowable_tools`
        // would say `bash` and hide which half of it is standing.
        let curl = page
            .lines()
            .find(|line| line.starts_with("bash  curl "))
            .expect("a curl row");
        let mix = page
            .lines()
            .find(|line| line.starts_with("bash  mix test "))
            .expect("a mix test row");

        assert!(curl.contains(" no  "), "{curl}");
        assert!(curl.contains("214"), "{curl}");
        assert!(mix.contains(" yes  "), "{mix}");
        assert!(mix.contains("operator:ana"), "{mix}");

        // The digest is printed under the name the runtime gives it: a keyless sha256 over
        // the submitted report's own contents, which is not a signature.
        assert!(page.contains("submitted"), "{page}");
        assert!(mix.contains("eeeeeeeeeeeeeeee"), "{mix}");

        // The demotion is its own section, and it names the term the record stored rather
        // than any sentence anybody typed — plus the shape, which is what was narrowed.
        assert!(page.contains("human_contradiction"), "{page}");
        assert!(page.contains("session-1"), "{page}");
        // The canary names no actor, and the page says so rather than leaving it blank.
        assert!(page.contains("the runtime"), "{page}");
    }

    #[test]
    fn the_gate_and_the_sample_are_the_node_s_own_numbers() {
        let page = render_status(&status());
        assert!(
            page.contains("20 distinct requests in 2 sessions"),
            "{page}"
        );
        assert!(page.contains("at most 0 contradictions"), "{page}");
        assert!(page.contains("every 10th honoured allow"), "{page}");

        // A runtime that did not state them is said so rather than filled in from a constant
        // compiled into this client.
        let mut silent = status();
        let fields = silent.as_object_mut().expect("an object");
        fields.remove("thresholds");
        fields.remove("shadow_every");

        let page = render_status(&silent);
        assert!(page.contains("did not state its thresholds"), "{page}");
        assert!(page.contains("did not say how often it samples"), "{page}");
        assert!(!page.contains("20 distinct requests"), "{page}");

        // And sampling that is off is a fact worth reading, not a missing number.
        let mut off = status();
        off["shadow_every"] = json!(0);
        assert!(render_status(&off).contains("sampling is off"), "{page}");
    }

    #[test]
    fn an_empty_record_is_an_answer_rather_than_an_empty_table() {
        let empty = json!({
            "node": "ouroboros@studio",
            "policy": null,
            "tools": [],
            "demotions": [],
            "allowable": {},
            "allowable_tools": [],
            "durability": "ephemeral_checkpoint",
            "shadow_every": 10,
            "thresholds": {
                "contradictions": 0, "unreadable": 0, "distinct_fingerprints": 20,
                "distinct_sessions": 2, "would_resolve": 1
            },
            "evidence": {
                "records": 148,
                "by_tool": {"bash": 96, "read": 40, "web_fetch": 12},
                "without_document": 1,
                "unreadable": 0,
                "other_tools": 0,
                "other_records": 0,
                "error": null
            }
        });

        let page = render_status(&empty);

        assert!(page.contains("nothing promoted on this node"), "{page}");
        // Largest first, so the sentence does not depend on how a map was walked.
        assert!(
            page.contains("148 answers (96 bash, 40 read, 12 web_fetch)"),
            "{page}"
        );
        assert!(page.contains("1 no document"), "{page}");
        // No table at all rather than a header over nothing.
        assert!(!page.contains("allowed"), "{page}");
    }

    #[test]
    fn the_corpus_sentence_says_what_the_runtime_left_out() {
        // The reply names the busiest 32 tools and counts the rest; a sentence that printed
        // only the named ones would under-report the corpus by however many it did not name.
        let mut bounded = status();
        bounded["evidence"]["other_tools"] = json!(468);
        bounded["evidence"]["other_records"] = json!(1_204);

        let page = render_status(&bounded);
        assert!(page.contains("468 other tools with 1204 answers"), "{page}");

        // And a corpus nobody could read is a different fact from an empty one.
        let mut broken = status();
        broken["evidence"]["error"] = json!("policy_evidence_unreadable");
        let page = render_status(&broken);
        assert!(page.contains("the corpus could not be read"), "{page}");
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
            "allowable": {},
            "allowable_tools": [],
            "durability": "unavailable",
            "shadow_every": 10,
            "thresholds": {"contradictions": 0, "unreadable": 0, "distinct_fingerprints": 20,
                           "distinct_sessions": 2, "would_resolve": 1},
            "evidence": {"records": 0, "by_tool": {}, "without_document": 0, "unreadable": 0,
                         "other_tools": 0, "other_records": 0, "error": null}
        });

        let page = render_status(&unavailable);

        assert!(page.contains("not answering on this node"), "{page}");
        assert!(!page.contains("nothing promoted"), "{page}");
    }

    #[test]
    fn the_report_table_prints_the_counts_and_derives_nothing() {
        let page = render_report(&report());

        assert!(
            page.contains("no-network-shell @ bbbbbbbbbbbbbbbb"),
            "{page}"
        );
        assert!(page.contains("277 rows, 0 unreadable"), "{page}");
        // An absent `since` is the whole corpus, said rather than left blank.
        assert!(page.contains("the whole corpus"), "{page}");
        assert!(page.contains("1234567890abcdef"), "{page}");

        // Tools in name order, so two runs over one report are two identical pages.
        let bash = page.find("\nbash ").expect("a bash row");
        let read = page.find("\nread ").expect("a read row");
        assert!(bash < read, "{page}");

        // No verdict column: whether a shape has earned a promotion is decided by the node,
        // in the re-run it performs, against thresholds this client never holds.
        assert!(!page.contains("promotable"), "{page}");
        assert!(!page.contains("earned"), "{page}");
    }

    #[test]
    fn the_shape_table_puts_this_node_s_requirement_beside_its_measurement() {
        let page = render_report(&report());

        // The `needs` row is read out of the report's own `thresholds` block. An operator
        // reads down a column: `curl` has 12 distinct requests against a minimum of 20 and
        // one session against a minimum of 2, so it is not promotable and the page says why.
        let needs = page
            .lines()
            .find(|line| line.starts_with("needs"))
            .expect("a needs row");

        assert!(needs.contains("min 20"), "{needs}");
        assert!(needs.contains("min 2"), "{needs}");
        assert!(needs.contains("max 0"), "{needs}");

        // The shape rows are the block under the `needs` row.
        let rows: Vec<&str> = page
            .lines()
            .skip_while(|line| !line.starts_with("needs"))
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .collect();

        let curl = rows
            .iter()
            .find(|line| line.contains("curl"))
            .expect("a curl shape row");
        let mix = rows
            .iter()
            .find(|line| line.contains("mix test"))
            .expect("a mix test shape row");

        assert!(curl.contains("12"), "{curl}");
        assert!(mix.contains("41"), "{mix}");

        // A report from a runtime that stated none says so rather than being filled in.
        let mut silent = report();
        silent
            .as_object_mut()
            .expect("an object")
            .remove("thresholds");

        let page = render_report(&silent);
        assert!(page.contains("(no thresholds stated)"), "{page}");
        assert!(!page.contains("min 20"), "{page}");
    }

    #[test]
    fn a_contradiction_row_names_a_digest_and_never_a_request() {
        let page = render_report(&report());

        assert!(page.contains("session-1"), "{page}");
        assert!(page.contains("aaaaaaaaaaaaaaaa"), "{page}");
        // The whole point of the corpus never crossing the wire: there is no field here
        // that could hold one, and no renderer that would print it.
        assert!(!page.contains("curl http"), "{page}");
        assert!(!page.contains("document"), "{page}");
    }

    /// R6. The bounds on printed rows are bounds, and what they left out is said.
    #[test]
    fn the_printed_rows_are_bounded_and_the_remainder_is_counted() {
        let mut many = report();
        let rows: Vec<Value> = (0..25)
            .map(|index| {
                json!({
                    "fingerprint": format!("{index:064x}"),
                    "session_id": format!("session-{index}"),
                    "at": "2026-01-01T00:00:00.000000Z"
                })
            })
            .collect();

        many["per_tool"]["bash"]["contradiction_rows"] = json!(rows);

        let page = render_report(&many);
        let printed = page
            .lines()
            .filter(|line| line.contains("session-"))
            .count();

        assert_eq!(printed, MAX_ROWS_SHOWN, "{page}");
        assert!(page.contains("… 5 more contradictions not shown"), "{page}");
    }

    #[test]
    fn a_report_over_a_corpus_with_nothing_in_it_says_so() {
        let page = render_report(&json!({
            "policy_name": "guard",
            "component_sha256": "c".repeat(64),
            "corpus_size": 0,
            "unreadable": 0,
            "per_tool": {}
        }));

        assert!(
            page.contains("no decisions in the corpus to replay"),
            "{page}"
        );
    }

    // -----------------------------------------------------------------------
    // The decode contract, against the S2b review's four exploits.
    // -----------------------------------------------------------------------

    /// HIGH-2. `short` used to be `&digest[..16]` — a *byte* range on whatever string arrived.
    /// Four node-controlled fields reach it, and any one of them with a multi-byte character
    /// across byte 16 panicked the client outright.
    #[test]
    fn a_digest_shaped_field_that_is_not_a_digest_renders_a_question_mark() {
        let evil = "\u{20ac}".repeat(8);

        for (what, mut answer) in [
            ("policy.component_sha256", status()),
            ("report.component_sha256", report()),
            ("report.report_sha256", report()),
            ("contradiction fingerprint", report()),
        ] {
            match what {
                "policy.component_sha256" => answer["policy"]["component_sha256"] = json!(evil),
                "report.component_sha256" => answer["component_sha256"] = json!(evil),
                "report.report_sha256" => answer["report_sha256"] = json!(evil),
                _ => {
                    answer["per_tool"]["bash"]["contradiction_rows"][0]["fingerprint"] = json!(evil)
                }
            }

            let page = if what.starts_with("policy.") {
                render_status(&answer)
            } else {
                render_report(&answer)
            };

            // Rendered, and rendered as what it is: not a digest.
            assert!(page.contains('?'), "{what}: {page}");
            assert!(!page.contains(&evil), "{what} printed a non-digest as one");
        }

        // And a real one still prints its first sixteen characters.
        assert_eq!(short(&"a".repeat(64)), "a".repeat(16));
        assert_eq!(short(&"A".repeat(64)), "?");
        assert_eq!(short("deadbeef"), "?");
        assert_eq!(short(&"z".repeat(64)), "?");
    }

    /// HIGH-3. These pages are written straight to a terminal this client does not own, and
    /// the gateway on the other end is authenticated and not trusted.
    #[test]
    fn no_control_character_from_the_node_reaches_the_page() {
        let mut answer = status();

        answer["tools"][0]["tool"] = json!("bash\u{1b}[2J\u{1b}[1;1H");
        answer["tools"][0]["shape"] = json!("curl\u{1b}[31m");
        answer["tools"][0]["actor"] = json!("operator:ana\u{1b}]0;pwned\u{7}");
        answer["tools"][0]["promoted_at"] = json!("2026\u{8}\u{8}\u{8}\u{8}1999");
        answer["demotions"][0]["session_id"] = json!("s\u{1b}[31mession");
        answer["demotions"][0]["reason"] = json!("human_contradiction\u{1b}[0m");
        answer["demotions"][0]["actor"] = json!("ana\u{7}");
        answer["durability"] = json!("synced\u{1b}[5m");
        answer["policy"]["name"] = json!("no-network-shell\n\rpolicy   totally-different");
        answer["evidence"]["by_tool"] = json!({"ba\u{1b}[2Jsh": 1});

        let page = render_status(&answer);

        for hostile in ['\u{1b}', '\u{7}', '\u{8}', '\n', '\r'] {
            if hostile == '\n' {
                continue;
            }

            assert!(!page.contains(hostile), "{hostile:?} survived: {page:?}");
        }

        // A bare newline in a name used to forge a whole line on the page: a reader looking
        // for the `policy` header found two, and the second was the node's sentence.
        assert_eq!(
            page.lines()
                .filter(|line| line.starts_with("policy   "))
                .count(),
            1,
            "{page:?}"
        );

        let mut answer = report();
        answer["policy_name"] = json!("guard\u{1b}[2J");
        answer["per_tool"]["bash\u{1b}[31m"] = answer["per_tool"]["bash"].clone();
        answer["per_tool"]["bash\u{1b}[31m"]["contradiction_rows"][0]["session_id"] =
            json!("sess\u{1b}]0;x\u{7}");
        answer["per_shape"]["bash"]["mi\u{1b}x"] = answer["per_shape"]["bash"]["mix test"].clone();

        let page = render_report(&answer);
        assert!(!page.contains('\u{1b}'), "{page:?}");
        assert!(!page.contains('\u{7}'), "{page:?}");
    }

    /// HIGH-2, the other half: one long value used to pad every row of the table out to its
    /// own length, and a value past 65 535 panicked the formatter — Rust packs a `{:width$}`
    /// into a `u16`.
    #[test]
    fn one_long_string_from_the_node_neither_panics_nor_multiplies_the_page() {
        let mut answer = status();
        answer["tools"][0]["tool"] = json!("a".repeat(65_536));
        let page = render_status(&answer);
        assert!(page.contains('…'), "the value is cut and says so");

        let mut answer = report();
        answer["per_tool"] = json!({"a".repeat(65_536): answer["per_tool"]["bash"].clone()});
        answer["per_shape"] = json!({});
        let _page = render_report(&answer);

        // Fifty-one rows, one of them 60 kB: the page is the value plus the table, not the
        // value times the rows.
        let mut answer = status();
        let tools = answer["tools"].as_array_mut().expect("a list");

        for index in 0..50 {
            let mut tool = tools[0].clone();
            tool["shape"] = json!(format!("shape-{index}"));
            tools.push(tool);
        }

        tools[0]["tool"] = json!("a".repeat(60_000));

        let page = render_status(&answer);

        assert!(
            page.len() < 3 * MAX_FIELD_BYTES + 8_192,
            "the page is {} bytes",
            page.len()
        );
    }

    /// EXPLOIT 4, stated rather than fixed: `--json` is the node's answer, verbatim, and that
    /// is its contract. The *table* is the client's defence, and it has no renderer for a
    /// field the protocol does not send.
    #[test]
    fn the_table_has_no_renderer_for_a_document_even_when_one_arrives() {
        let mut answer = report();
        answer["per_tool"]["bash"]["contradiction_rows"][0]["document"] =
            json!("{\"command\":\"curl http://10.0.0.1/secrets\"}");

        let page = render_report(&answer);
        assert!(!page.contains("10.0.0.1"), "{page}");
        assert!(!page.contains("secrets"), "{page}");
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

        // LOW-4. A directory is refused by the *open handle's* metadata rather than by a stat
        // on the path, so what was checked and what would be read are the same object.
        let refusal = read_report(&dir).expect_err("a directory is not a report");
        assert!(
            format!("{refusal:#}").contains("is not a regular file"),
            "{refusal:#}"
        );

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
