//! `ouro ledger`: the effect ledger, read from a terminal.
//!
//! The ledger is the row of the 2026 scorecard nobody else fills — a durable, per-effect
//! record of what an agent was allowed to do and what came of it — and until now the only
//! way to read one was `Ouroboros.effects/1` in an IEx session on the machine that owned
//! it. This is the same query over the gateway, with `--fleet` asking every connected core
//! node instead of one.
//!
//! ## Two outputs, one rule about which stream they use
//!
//! A table for a person and NDJSON for a pipe, and in both cases **stdout carries only the
//! answer**. A node that did not respond is written to stderr, so `ouro ledger --json |
//! jq` reads a clean stream of entries and the operator still learns that the picture is
//! incomplete. This is the posture `ouro run` already takes toward its own stream.
//!
//! ## Sequences are per node
//!
//! There is no cross-node ordering to present, because each node mints its own sequence.
//! Rows are grouped by node and newest-first within a node, and every row names the node it
//! came from. A fleet-wide "12" means nothing; `studio-mini` plus 12 does.

use std::fmt::Write as _;
use std::io::Write;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use crate::transport::Client;

/// The gateway verb. One constant so the client and its tests cannot disagree.
pub const LIST_METHOD: &str = "ledger.list";

/// What the flags said.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Ask every connected core node rather than this one.
    pub fleet: bool,
    /// Only effects after this sequence. Per node, like the sequences themselves.
    pub since: u64,
    /// One JSON object per entry instead of a table.
    pub json: bool,
    /// How many entries at most. The runtime bounds this too, and its bound wins.
    pub limit: Option<u64>,
}

impl Options {
    /// The params `ledger.list` is called with. Absent flags are absent params, so the
    /// runtime's own defaults apply rather than a second set of defaults living here.
    pub fn params(&self) -> Value {
        let mut params = Map::new();

        if self.fleet {
            params.insert("fleet".into(), json!(true));
        }

        if self.since > 0 {
            params.insert("since_sequence".into(), json!(self.since));
        }

        if let Some(limit) = self.limit {
            params.insert("limit".into(), json!(limit));
        }

        Value::Object(params)
    }
}

/// Asks, then writes. `out` gets the answer and `notes` gets everything about how complete
/// it is.
pub async fn run<O: Write, N: Write>(
    client: &Client,
    options: &Options,
    out: &mut O,
    notes: &mut N,
) -> Result<()> {
    let answer = client
        .call(LIST_METHOD, options.params())
        .await
        .map_err(|error| anyhow!("the runtime refused {LIST_METHOD}: {error}"))?;

    let text = if options.json {
        render_ndjson(&answer)
    } else {
        render_table(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.flush()?;

    for line in incomplete(&answer) {
        writeln!(notes, "ouro ledger: {line}")?;
    }

    notes.flush()?;
    Ok(())
}

/// One JSON object per line, exactly as the runtime sent it. Nothing is reshaped here: a
/// pipe wants the ledger's own record, not this client's reading of it.
pub fn render_ndjson(answer: &Value) -> String {
    let mut text = String::new();

    for entry in entries(answer) {
        if let Ok(line) = serde_json::to_string(entry) {
            text.push_str(&line);
            text.push('\n');
        }
    }

    text
}

/// The human page.
pub fn render_table(answer: &Value) -> String {
    let rows: Vec<Row> = entries(answer).iter().map(Row::from).collect();

    if rows.is_empty() {
        return "no effects retained\n".to_string();
    }

    let node = width(&rows, |row| &row.node, "node");
    let sequence = width(&rows, |row| &row.sequence, "seq");
    let status = width(&rows, |row| &row.status, "status");
    let effect = width(&rows, |row| &row.effect, "effect");
    let principal = width(&rows, |row| &row.principal, "principal");

    let mut text = String::new();

    let _ = writeln!(
        text,
        "{:<node$}  {:>sequence$}  {:<status$}  {:<effect$}  {:<principal$}  id",
        "node", "seq", "status", "effect", "principal"
    );

    for row in &rows {
        let _ = writeln!(
            text,
            "{:<node$}  {:>sequence$}  {:<status$}  {:<effect$}  {:<principal$}  {}",
            row.node, row.sequence, row.status, row.effect, row.principal, row.id
        );
    }

    text
}

/// What could not be read, as sentences. Empty when every node answered — which is the
/// only case in which the list above is the whole picture.
pub fn incomplete(answer: &Value) -> Vec<String> {
    answer
        .get("nodes")
        .and_then(Value::as_array)
        .map(|nodes| {
            nodes
                .iter()
                .filter(|node| node.get("status").and_then(Value::as_str) != Some("ok"))
                .map(|node| {
                    let name = node
                        .get("node")
                        .and_then(Value::as_str)
                        .unwrap_or("an unnamed node");

                    format!("{name} did not answer, so this list is incomplete")
                })
                .collect()
        })
        .unwrap_or_default()
}

fn entries(answer: &Value) -> &[Value] {
    answer
        .get("entries")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

struct Row {
    node: String,
    sequence: String,
    status: String,
    effect: String,
    principal: String,
    id: String,
}

impl From<&Value> for Row {
    fn from(entry: &Value) -> Self {
        Self {
            node: field(entry, "origin_node"),
            sequence: entry
                .get("sequence")
                .and_then(Value::as_u64)
                .map(|sequence| sequence.to_string())
                .unwrap_or_else(|| "?".to_string()),
            status: field(entry, "status"),
            effect: field(entry, "effect"),
            principal: field(entry, "principal"),
            id: field(entry, "id"),
        }
    }
}

fn field(entry: &Value, key: &str) -> String {
    entry
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}

fn width(rows: &[Row], of: impl Fn(&Row) -> &String, header: &str) -> usize {
    rows.iter()
        .map(|row| of(row).chars().count())
        .max()
        .unwrap_or(0)
        .max(header.chars().count())
}
