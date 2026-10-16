//! The end-of-run summary (J13): a few lines computed only from an attempt's
//! final receipt and its journal.
//!
//! `docs/specs/jail-launch-and-summary.md` §4. [`summary`] is a pure function
//! of the parsed `jail.json` and the bytes of `trace.ndjson` (or the reason
//! there are none): it reads nothing else, keeps no state and counts nothing
//! on the side, so anyone holding the two files can recompute it. The lines
//! `run` prints on a terminal, the lines `tail --summary` prints and the
//! `ukai.jail.summary/1` object `tail --summary --json` prints are renderings
//! of the one [`Summary`] it returns, never separate computations.
//!
//! Every line keeps the honesty invariant: a number is printed only where
//! the evidence supports it. A class's numbers are exact only when the class
//! is active and its complete journal agrees with the receipt's count
//! (`/coverage/<class>/observed_count`); a degraded class or an incomplete
//! journal makes every number a lower bound (`at least`); a class that was
//! not observed prints `not observed`, never `0`; a journal that disagrees
//! with its receipt prints the disagreement and no number. Nothing about
//! reads or file contents is printed, because neither is observed.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::records::escape_control;

/// The identifier of the `tail --summary --json` record, whose schema is
/// `docs/specs/jail-v1/jail-summary.schema.json`.
pub const SCHEMA_SUMMARY: &str = "ukai.jail.summary/1";

/// The largest journal the summary scans (initial, §4.1). A larger one is
/// not read: the lines that need it say so, and the receipt-only lines
/// still print.
pub const SCAN_CAP: u64 = 16 * 1024 * 1024;

/// Entries a terminal list shows before `+N more` (§4.1).
pub const TERMINAL_LIST: usize = 5;

/// Entries a JSON list keeps before counting the rest as `omitted` (§4.5).
pub const JSON_LIST: usize = 64;

/// Every terminal line starts with this, as the receipt line does.
pub const PREFIX: &str = "ukai-jail: ";

/// The most lines the terminal form prints, the receipt line included (§4.1).
pub const MAX_TERMINAL_LINES: usize = 8;

/// The six coverage classes, in the receipt's order (jail-v1 §11.4).
const CLASSES: [&str; 6] = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"];

/// The classes the audit source counts: what `observe on` adds.
const AUDIT_CLASSES: [&str; 4] = ["exec", "fs.write", "fs.deny", "net"];

/// The journal the summary was given, or why there is none.
#[derive(Clone, Copy, Debug)]
pub enum Journal<'a> {
    /// The local `trace.ndjson`, whole (at most [`SCAN_CAP`] bytes).
    Bytes(&'a [u8]),
    /// `--trace-fd N`: the events went to that descriptor and no local
    /// journal was kept (jail-v1 §13.3). Only the live run knows this.
    Streamed(i32),
    /// The local journal is larger than [`SCAN_CAP`]: its size in bytes.
    NotScanned(u64),
    /// No local journal exists.
    Absent,
    /// A local journal exists and could not be read.
    Unreadable,
}

/// What the journal established, as the summary reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JournalState {
    /// Every line is a frame, and the last is the `jail.receipt` note of this
    /// very receipt (jail-v1 §13.3).
    Complete,
    /// Read, but not complete: a partial or corrupt line, or no final note
    /// naming this receipt. Every count from it is a lower bound.
    Incomplete,
    /// Streamed to a descriptor (`--trace-fd`).
    Streamed(i32),
    /// Over the scan cap, by its size in bytes.
    NotScanned(u64),
    /// No local journal.
    Absent,
    /// A local journal that could not be read.
    Unreadable,
}

impl JournalState {
    /// The `journal` value of `ukai.jail.summary/1`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            JournalState::Complete => "complete",
            JournalState::Incomplete => "incomplete",
            JournalState::Streamed(_) => "streamed",
            JournalState::NotScanned(_) => "not_scanned",
            JournalState::Absent => "absent",
            JournalState::Unreadable => "unreadable",
        }
    }

    /// Why there are no journal counts, when there are none.
    fn missing(self) -> Option<String> {
        match self {
            JournalState::Complete | JournalState::Incomplete => None,
            JournalState::Streamed(fd) => Some(format!("journal streamed to fd {fd}")),
            JournalState::NotScanned(bytes) => Some(format!(
                "journal not scanned ({} MiB)",
                bytes.div_ceil(1024 * 1024)
            )),
            JournalState::Absent => Some("journal absent".to_owned()),
            JournalState::Unreadable => Some("journal unreadable".to_owned()),
        }
    }
}

/// One summary line: its name, its text without [`PREFIX`], and the facts
/// behind the text.
#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    /// `status`, `workspace`, `network`, `credentials`, `evidence`,
    /// `limits` or `cleanup`.
    pub line: &'static str,
    /// The terminal text, every evidence string in it escaped.
    pub text: String,
    /// The numbers and states the text was written from.
    pub facts: Value,
}

/// The summary of one attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    /// The receipt's `attempt_id`, as recorded.
    pub attempt_id: String,
    /// `sha256:` over the receipt's RFC 8785 canonical bytes, the name the
    /// journal's receipt notes carry; `None` for a receipt that cannot be
    /// canonicalized.
    pub receipt_digest: Option<String>,
    /// What the journal established.
    pub journal: JournalState,
    /// The lines, in print order.
    pub lines: Vec<Line>,
}

impl Summary {
    /// The terminal form: one `ukai-jail: ` line per summary line, then the
    /// receipt line, which stays last.
    #[must_use]
    pub fn terminal(&self, receipt_path: &Path) -> Vec<String> {
        let mut lines: Vec<String> = self
            .lines
            .iter()
            .map(|line| format!("{PREFIX}{}", line.text))
            .collect();
        lines.push(format!(
            "{PREFIX}receipt {}",
            escape_control(&receipt_path.display().to_string())
        ));
        lines
    }

    /// The `ukai.jail.summary/1` form.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA_SUMMARY,
            "attempt_id": self.attempt_id,
            "receipt_digest": self.receipt_digest,
            "journal": self.journal.as_str(),
            "lines": self.lines.iter().map(|line| json!({
                "line": line.line,
                "text": line.text,
                "facts": line.facts,
            })).collect::<Vec<_>>(),
        })
    }
}

/// [`Summary::to_json`] as text a terminal can show safely. JSON already
/// escapes C0 inside strings (a raw C0 character in the output is the
/// pretty-printer's own line break); this also writes DEL, C1 and the bidi
/// controls that [`escape_control`] escapes as `\uXXXX`. Those characters can
/// only occur inside JSON strings, where the escape denotes the same
/// character, so the value is unchanged and only its spelling is.
#[must_use]
pub fn json_text(value: &Value) -> String {
    let raw = serde_json::to_string_pretty(value).unwrap_or_default();
    let mut out = String::with_capacity(raw.len());
    for character in raw.chars() {
        let escaped = u32::from(character) >= 0x7f
            && escape_control(character.encode_utf8(&mut [0; 4])).len() != character.len_utf8();
        if escaped {
            let _ = write!(out, "\\u{:04x}", u32::from(character));
        } else {
            out.push(character);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The journal scan
// ---------------------------------------------------------------------------

/// The parts of one journal frame the summary reads. Every other field is
/// skipped unparsed, which keeps an A01-sized journal within the cost budget.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Frame<'a> {
    #[serde(borrow)]
    source: Option<Cow<'a, str>>,
    source_seq: Option<u64>,
    #[serde(borrow)]
    operation: Option<Cow<'a, str>>,
    #[serde(borrow)]
    decision: Option<Cow<'a, str>>,
    #[serde(borrow)]
    monotonic_ns: Option<Cow<'a, str>>,
    outcome: Option<FrameOutcome>,
    #[serde(borrow)]
    fields: Option<FrameFields<'a>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct FrameOutcome {
    ok: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct FrameFields<'a> {
    #[serde(borrow)]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow)]
    transition: Option<Cow<'a, str>>,
    #[serde(borrow)]
    phase: Option<Cow<'a, str>>,
    #[serde(borrow)]
    receipt_digest: Option<Cow<'a, str>>,
    #[serde(borrow)]
    action: Option<Cow<'a, str>>,
    #[serde(borrow)]
    attempted_operation: Option<Cow<'a, str>>,
    #[serde(borrow)]
    destination: Option<Cow<'a, str>>,
    #[serde(borrow)]
    reason: Option<Cow<'a, str>>,
    #[serde(borrow)]
    credential_id: Option<Cow<'a, str>>,
    uses_recorded: Option<bool>,
    #[serde(borrow)]
    credentials: Option<Vec<Cow<'a, str>>>,
    path: Option<FramePath>,
    path2: Option<FramePath>,
}

/// An event path (`$defs/path`): its kind, and its value when it is named.
#[derive(Deserialize)]
struct FramePath {
    kind: String,
    value: Option<Value>,
}

impl FramePath {
    /// The `{kind, value}` of a named workspace path, and its distinctness
    /// key (the value's JSON spelling: a string, or the base64 object of a
    /// non-UTF-8 name).
    fn workspace(&self) -> Option<(String, Value)> {
        if self.kind != "workspace_relative" {
            return None;
        }
        let value = self.value.as_ref()?;
        Some((
            value.to_string(),
            json!({"kind": "workspace_relative", "value": value}),
        ))
    }

    /// Whether the event recorded no name for this path (§4.2's unnamed:
    /// `unavailable`, or a `digest` outside every known root).
    fn unnamed(&self) -> bool {
        matches!(self.kind.as_str(), "unavailable" | "digest")
    }
}

/// The class a frame is counted under, as the producer counts it
/// (`ClosedOperation::coverage_class`, and the proxy's own class): `None`
/// for a frame no coverage count includes. `limits` hits are counted from
/// cgroup counters, not journal frames, so no frame is a `limits` frame.
fn class_of(source: &str, operation: &str) -> Option<&'static str> {
    match (source, operation) {
        ("audit", "proc.exec" | "proc.exit") => Some("exec"),
        ("audit", "fs.create" | "fs.write" | "fs.rename" | "fs.unlink") => Some("fs.write"),
        ("audit", "fs.deny") => Some("fs.deny"),
        ("audit", "net.connect") => Some("net"),
        ("proxy", "net.connect") => Some("proxy.net"),
        _ => None,
    }
}

/// Network results for one destination.
#[derive(Default)]
struct Allowed {
    results: u64,
    connect_failed: u64,
}

/// Everything one pass over the journal's frames counted.
#[derive(Default)]
struct Scan {
    /// Frames per class (the K47 totals).
    class_counts: BTreeMap<&'static str, u64>,
    /// Distinct workspace paths opened for writing, renamed (either side),
    /// removed, by distinctness key.
    opened: BTreeSet<String>,
    renamed: BTreeSet<String>,
    removed: BTreeSet<String>,
    /// Every named workspace path above, for the JSON list.
    named: BTreeMap<String, Value>,
    /// Successful write-class results with a path that has no name.
    unnamed: u64,
    /// `fs.deny` results whose attempted operation is a file write.
    refused: u64,
    /// Proxy results allowed by policy, by destination (`None`: the request
    /// named none).
    allowed: BTreeMap<Option<String>, Allowed>,
    /// Proxy results denied, by destination and reason.
    denied: BTreeMap<(Option<String>, String), u64>,
    /// Proxy results whose `fields.credentials` names each id.
    uses: BTreeMap<String, u64>,
    /// Credential ids whose lifecycle notes say this build records uses.
    uses_recorded: BTreeSet<String>,
    /// Each credential's distinct lifecycle transitions, in journal order.
    transitions: BTreeMap<String, Vec<String>>,
    /// Proxy results refused for a `credential_*` reason.
    credential_refusals: u64,
    /// The first `exec_confirmed` lifecycle note's clock.
    exec_confirmed_ns: Option<u128>,
    /// The last `settled` receipt note's clock.
    settled_ns: Option<u128>,
    /// The last frame's `(phase, receipt_digest)` when it is a receipt note.
    last_receipt_note: Option<(String, String)>,
    /// Each source's last `source_seq`.
    last_seq: BTreeMap<String, u64>,
    /// Whether a `trace_transport_loss` note has been read: from it on, a
    /// missing sequence number is a recorded loss (jail-v1 §13.1).
    loss_recorded: bool,
    /// A sequence number was skipped before any recorded loss: a frame is
    /// missing that nothing says was lost, so the journal is not complete.
    unrecorded_hole: bool,
    /// Whether a line that is not a frame was met (a partial final line, a
    /// line that is not a JSON object, or one over [`crate::journal::FRAME_MAX`]).
    /// Nothing from that line on is counted.
    broken: bool,
}

fn scan(bytes: &[u8]) -> Scan {
    let mut scan = Scan::default();
    let mut frames = crate::journal::frames(bytes);
    for line in frames.by_ref() {
        // A frame is one JSON object (jail-v1 §13.3). The derived parser
        // would also take an array for the struct, so the shape is checked
        // first.
        let object = line.trim_ascii_start().first() == Some(&b'{');
        let parsed = (object && line.len() < crate::journal::FRAME_MAX)
            .then(|| serde_json::from_slice::<Frame<'_>>(line).ok())
            .flatten();
        let Some(frame) = parsed else {
            scan.broken = true;
            return scan;
        };
        // jail-v1 §13.1: one writer numbers each source from 1, strictly
        // increasing. A number that does not increase is a repeated or
        // reordered frame, which no conforming writer produces: nothing from
        // it on is counted, so a repeat can never inflate a lower bound.
        if !scan.sequenced(&frame) {
            scan.broken = true;
            return scan;
        }
        scan.add(&frame);
    }
    scan.broken = frames.torn();
    scan
}

impl Scan {
    /// Checks `frame`'s sequence number against its source's last one and
    /// records it: false when it does not increase (or is missing). A skipped
    /// number before any recorded transport loss marks the journal
    /// incomplete without stopping the count.
    fn sequenced(&mut self, frame: &Frame<'_>) -> bool {
        let Some(seq) = frame.source_seq else {
            return false;
        };
        let source = frame.source.as_deref().unwrap_or("");
        if source == "wrapper"
            && frame.operation.as_deref() == Some("note")
            && frame.fields.as_ref().is_some_and(|fields| {
                fields.kind.as_deref() == Some("coverage_gap")
                    && fields.reason.as_deref() == Some("trace_transport_loss")
            })
        {
            self.loss_recorded = true;
        }
        let last = self.last_seq.get(source).copied().unwrap_or(0);
        if seq <= last {
            return false;
        }
        if seq != last + 1 && !self.loss_recorded {
            self.unrecorded_hole = true;
        }
        self.last_seq.insert(source.to_owned(), seq);
        true
    }

    fn add(&mut self, frame: &Frame<'_>) {
        let source = frame.source.as_deref().unwrap_or("");
        let operation = frame.operation.as_deref().unwrap_or("");
        let empty = FrameFields::default();
        let fields = frame.fields.as_ref().unwrap_or(&empty);
        self.last_receipt_note = None;
        if let Some(class) = class_of(source, operation) {
            *self.class_counts.entry(class).or_insert(0) += 1;
        }
        let ok = frame.outcome.as_ref().and_then(|outcome| outcome.ok);
        match (source, operation) {
            ("audit", "fs.create" | "fs.write" | "fs.rename" | "fs.unlink") if ok == Some(true) => {
                self.add_write(operation, fields);
            }
            ("audit", "fs.deny") => {
                if matches!(
                    fields.attempted_operation.as_deref(),
                    Some("fs.create" | "fs.write" | "fs.rename" | "fs.unlink")
                ) {
                    self.refused += 1;
                }
            }
            ("proxy", "net.connect") => self.add_proxy(frame, fields),
            ("wrapper", "note") => self.add_note(frame, fields),
            ("wrapper", "jail.receipt") => {
                if fields.phase.as_deref() == Some("settled") {
                    self.settled_ns = clock(frame).or(self.settled_ns);
                }
                if let (Some(phase), Some(digest)) = (&fields.phase, &fields.receipt_digest) {
                    self.last_receipt_note = Some((phase.to_string(), digest.to_string()));
                }
            }
            _ => {}
        }
    }

    fn add_write(&mut self, operation: &str, fields: &FrameFields<'_>) {
        if operation == "fs.write"
            && !matches!(
                fields.action.as_deref(),
                Some("opened_for_mutation" | "truncated")
            )
        {
            return;
        }
        let paths: Vec<&FramePath> = fields.path.iter().chain(&fields.path2).collect();
        if paths.iter().any(|path| path.unnamed()) {
            self.unnamed += 1;
        }
        for path in paths {
            let Some((key, value)) = path.workspace() else {
                continue;
            };
            let set = match operation {
                "fs.rename" => &mut self.renamed,
                "fs.unlink" => &mut self.removed,
                _ => &mut self.opened,
            };
            set.insert(key.clone());
            self.named.entry(key).or_insert(value);
        }
    }

    fn add_proxy(&mut self, frame: &Frame<'_>, fields: &FrameFields<'_>) {
        let destination = fields.destination.as_deref().map(str::to_owned);
        let reason = fields.reason.as_deref().unwrap_or("");
        match frame.decision.as_deref() {
            Some("allow") => {
                let entry = self.allowed.entry(destination).or_default();
                entry.results += 1;
                if frame.outcome.as_ref().and_then(|outcome| outcome.ok) != Some(true) {
                    entry.connect_failed += 1;
                }
            }
            _ => {
                *self
                    .denied
                    .entry((destination, reason.to_owned()))
                    .or_insert(0) += 1;
            }
        }
        if reason.starts_with("credential_") {
            self.credential_refusals += 1;
        }
        if let Some(ids) = &fields.credentials {
            let distinct: BTreeSet<&str> = ids.iter().map(|id| id.as_ref()).collect();
            for id in distinct {
                *self.uses.entry(id.to_owned()).or_insert(0) += 1;
            }
        }
    }

    fn add_note(&mut self, frame: &Frame<'_>, fields: &FrameFields<'_>) {
        match fields.kind.as_deref() {
            Some("lifecycle") if fields.transition.as_deref() == Some("exec_confirmed") => {
                if self.exec_confirmed_ns.is_none() {
                    self.exec_confirmed_ns = clock(frame);
                }
            }
            Some("credential") => {
                let Some(id) = fields.credential_id.as_deref() else {
                    return;
                };
                if fields.uses_recorded == Some(true) {
                    self.uses_recorded.insert(id.to_owned());
                }
                if let Some(transition) = fields.transition.as_deref() {
                    let seen = self.transitions.entry(id.to_owned()).or_default();
                    if !seen.iter().any(|known| known == transition) {
                        seen.push(transition.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
}

/// A frame's `monotonic_ns`, one supervisor clock for every source.
fn clock(frame: &Frame<'_>) -> Option<u128> {
    frame.monotonic_ns.as_deref()?.parse().ok()
}

// ---------------------------------------------------------------------------
// What each class's numbers may claim
// ---------------------------------------------------------------------------

/// What the evidence lets a class's numbers say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Claim {
    /// Active, complete journal, journal and receipt agree: exact numbers.
    Exact,
    /// Degraded, or an incomplete journal: every number a lower bound.
    AtLeast,
    /// Unsupported or never started: no number at all.
    NotObserved,
    /// Observed, but there is no journal to count from here.
    NoJournal,
    /// The complete journal and the receipt disagree on the count: no number.
    Disagree,
}

impl Claim {
    /// The `bound` value of a count in `ukai.jail.summary/1`.
    fn bound(self) -> &'static str {
        match self {
            Claim::Exact => "exact",
            Claim::AtLeast => "at_least",
            Claim::NotObserved => "not_observed",
            Claim::NoJournal => "unavailable",
            Claim::Disagree => "disagree",
        }
    }

    /// Whether numbers may be printed at all.
    fn counts(self) -> bool {
        matches!(self, Claim::Exact | Claim::AtLeast)
    }

    /// `n` as this claim prints it.
    fn number(self, n: u64) -> String {
        match self {
            Claim::AtLeast => format!("at least {n}"),
            _ => n.to_string(),
        }
    }

    /// `n` as a JSON count: null unless numbers may be printed.
    fn json(self, n: u64) -> Value {
        if self.counts() { json!(n) } else { Value::Null }
    }
}

/// The receipt's view of one class, and what the summary may claim from it.
struct Class {
    name: &'static str,
    status: String,
    claim: Claim,
}

fn classify(receipt: &Value, scan: Option<&Scan>, state: JournalState) -> Vec<Class> {
    CLASSES
        .iter()
        .map(|&name| {
            let coverage = receipt.pointer(&format!("/coverage/{name}"));
            let status = coverage
                .and_then(|c| c.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unsupported")
                .to_owned();
            let observed = coverage
                .and_then(|c| c.get("observed_count"))
                .and_then(Value::as_u64);
            let claim = match (status.as_str(), scan) {
                ("active" | "degraded", None) => Claim::NoJournal,
                ("active" | "degraded", Some(scan)) => {
                    let counted = scan.class_counts.get(name).copied().unwrap_or(0);
                    if name == "limits" {
                        // Hits are cgroup facts, never journal frames: the
                        // summary takes no number from the journal for them.
                        Claim::NoJournal
                    } else if status == "active"
                        && state == JournalState::Complete
                        && observed == Some(counted)
                    {
                        Claim::Exact
                    } else if state == JournalState::Complete && status == "active" {
                        // K47: a complete journal must hold exactly the
                        // results the receipt counted.
                        Claim::Disagree
                    } else if observed.is_some_and(|observed| counted > observed) {
                        // A lower bound above the receipt's own count is no
                        // bound at all.
                        Claim::Disagree
                    } else {
                        Claim::AtLeast
                    }
                }
                // `unsupported`, `supported` (never started) and anything
                // this build does not know: nothing was observed.
                _ => Claim::NotObserved,
            };
            Class {
                name,
                status,
                claim,
            }
        })
        .collect()
}

fn claim_of(classes: &[Class], name: &str) -> Claim {
    classes
        .iter()
        .find(|class| class.name == name)
        .map_or(Claim::NotObserved, |class| class.claim)
}

// ---------------------------------------------------------------------------
// The pure function
// ---------------------------------------------------------------------------

/// The summary of the attempt whose final receipt is `receipt` (parsed
/// `jail.json`) and whose journal is `journal`. Reads nothing else.
#[must_use]
pub fn summary(receipt: &Value, journal: Journal<'_>) -> Summary {
    let receipt_digest = crate::canonical::to_jcs(receipt)
        .ok()
        .map(|bytes| crate::canonical::sha256_prefixed(&bytes));
    let (scan, state) = match journal {
        Journal::Bytes(bytes) => {
            let scan = scan(bytes);
            let complete = !scan.broken
                && !scan.unrecorded_hole
                && match (&scan.last_receipt_note, &receipt_digest) {
                    (Some((_, noted)), Some(digest)) => noted == digest,
                    _ => false,
                };
            let state = if complete {
                JournalState::Complete
            } else {
                JournalState::Incomplete
            };
            (Some(scan), state)
        }
        Journal::Streamed(fd) => (None, JournalState::Streamed(fd)),
        Journal::NotScanned(size) => (None, JournalState::NotScanned(size)),
        Journal::Absent => (None, JournalState::Absent),
        Journal::Unreadable => (None, JournalState::Unreadable),
    };
    let classes = classify(receipt, scan.as_ref(), state);
    let view = View {
        receipt,
        scan: scan.as_ref(),
        state,
        classes: &classes,
    };
    let mut lines = vec![view.status(), view.workspace(), view.network()];
    lines.extend(view.credentials());
    lines.push(view.evidence());
    lines.extend(view.limits());
    lines.extend(view.cleanup());
    Summary {
        attempt_id: text(receipt, "/attempt_id").unwrap_or_default().to_owned(),
        receipt_digest,
        journal: state,
        lines,
    }
}

/// A string at a JSON pointer.
fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// An escaped evidence string, for a terminal line.
fn shown(value: &str) -> String {
    escape_control(value)
}

/// `items`, at most [`TERMINAL_LIST`] of them, then `+N more`.
fn capped(items: Vec<String>, separator: &str) -> String {
    let more = items.len().saturating_sub(TERMINAL_LIST);
    let mut out = items
        .into_iter()
        .take(TERMINAL_LIST)
        .collect::<Vec<_>>()
        .join(separator);
    if more > 0 {
        let _ = write!(out, " +{more} more");
    }
    out
}

/// `one` for a count of 1, `many` otherwise.
fn noun<'a>(n: u64, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// A duration in milliseconds, truncated: `420ms`, `4.2s`, `3m41s`,
/// `1h02m09s`.
fn duration(ms: u128) -> String {
    let seconds = ms / 1000;
    if seconds == 0 {
        format!("{ms}ms")
    } else if seconds < 60 {
        format!("{seconds}.{}s", (ms % 1000) / 100)
    } else if seconds < 3600 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!(
            "{}h{:02}m{:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    }
}

/// Milliseconds since the epoch of an RFC 3339 UTC timestamp as the receipt
/// writes them (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`).
fn epoch_ms(timestamp: &str) -> Option<i128> {
    let b = timestamp.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last()? != b'Z'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i128> {
        let digits = timestamp.get(range)?;
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let millis = match &timestamp[19..timestamp.len() - 1] {
        "" => 0,
        fraction => {
            let digits = fraction.strip_prefix('.')?;
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let mut padded = digits.chars().take(3).collect::<String>();
            while padded.len() < 3 {
                padded.push('0');
            }
            padded.parse().ok()?
        }
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millis)
}

/// The receipt and the journal scan, with what each class may claim.
struct View<'a> {
    receipt: &'a Value,
    scan: Option<&'a Scan>,
    state: JournalState,
    classes: &'a [Class],
}

impl View<'_> {
    fn text(&self, pointer: &str) -> Option<&str> {
        text(self.receipt, pointer)
    }

    // -- status -------------------------------------------------------------

    fn status(&self) -> Line {
        let phase = self.text("/phase").unwrap_or("unknown");
        let mut parts = vec![if phase == "settled" {
            "settled".to_owned()
        } else {
            format!("NOT settled ({})", shown(phase))
        }];
        let kind = self.text("/outcome/kind").unwrap_or("unknown");
        let code = self
            .receipt
            .pointer("/outcome/code")
            .and_then(Value::as_u64);
        let signal = self
            .receipt
            .pointer("/outcome/signal")
            .and_then(Value::as_u64);
        let cause = self.text("/outcome/cause");
        let mut outcome = match (kind, code, signal) {
            ("exited", Some(code), _) => format!("exited {code}"),
            ("signaled", _, Some(signal)) => format!("signaled {signal}"),
            ("exec_error", ..) => "exec failed".to_owned(),
            // A refused phase already says so.
            ("refused", ..) if phase == "refused" => String::new(),
            ("refused", ..) => "refused".to_owned(),
            ("pending", ..) => "outcome pending".to_owned(),
            _ => "outcome unknown".to_owned(),
        };
        if let Some(cause) = cause {
            if !outcome.is_empty() {
                outcome.push(' ');
            }
            let _ = write!(outcome, "({})", shown(cause));
        }
        if !outcome.is_empty() {
            parts.push(outcome);
        }

        // Duration: one supervisor clock from the exec confirmation to the
        // settled receipt; without a journal, the receipt's wall clock.
        let journal_ms = self.scan.and_then(|scan| {
            let (start, end) = (scan.exec_confirmed_ns?, scan.settled_ns?);
            end.checked_sub(start).map(|ns| ns / 1_000_000)
        });
        let wall_ms = if self.scan.is_none() {
            match (
                self.text("/created_at").and_then(epoch_ms),
                self.text("/updated_at").and_then(epoch_ms),
            ) {
                (Some(start), Some(end)) if end >= start => u128::try_from(end - start).ok(),
                _ => None,
            }
        } else {
            None
        };
        if let Some(ms) = journal_ms {
            parts.push(format!("{} exec→settled", duration(ms)));
        } else if let Some(ms) = wall_ms {
            parts.push(format!("{} attempt (wall clock)", duration(ms)));
        }

        let tree_empty = self
            .receipt
            .pointer("/lifetime/tree_empty")
            .and_then(Value::as_bool);
        let scope = self.text("/lifetime/verification_scope");
        let survivors = match (tree_empty, scope) {
            (Some(true), Some("registered_boundary")) => {
                parts.push("survivors: none (verified, registered cgroup only)".to_owned());
                "none_verified_registered_boundary"
            }
            (Some(true), _) => {
                parts.push("survivors: none (verified)".to_owned());
                "none_verified"
            }
            _ => {
                parts.push("survivors: NOT verified".to_owned());
                "not_verified"
            }
        };

        let mut codes: Vec<&str> = Vec::new();
        for error in self
            .receipt
            .pointer("/errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(code) = error.get("code").and_then(Value::as_str)
                && !codes.contains(&code)
            {
                codes.push(code);
            }
        }
        if !codes.is_empty() {
            let rendered = codes
                .iter()
                .map(|code| {
                    if *code == "tree_unknown" {
                        "tree_unknown: run ukai-jail gc".to_owned()
                    } else {
                        shown(code)
                    }
                })
                .collect();
            parts.push(format!("errors: {}", capped(rendered, ", ")));
        }
        let integrity = self.text("/lifetime/integrity");
        if integrity == Some("lost") {
            parts.push("integrity lost: state retained".to_owned());
        }
        Line {
            line: "status",
            text: parts.join(" · "),
            facts: json!({
                "phase": phase,
                "outcome": kind,
                "code": code,
                "signal": signal,
                "cause": cause,
                "exec_to_settled_ms": journal_ms.map(|ms| u64::try_from(ms).unwrap_or(u64::MAX)),
                "attempt_wall_ms": wall_ms.map(|ms| u64::try_from(ms).unwrap_or(u64::MAX)),
                "survivors": survivors,
                "errors": codes,
                "integrity": integrity,
            }),
        }
    }

    // -- workspace ----------------------------------------------------------

    fn workspace(&self) -> Line {
        let write = claim_of(self.classes, "fs.write");
        let deny = claim_of(self.classes, "fs.deny");
        let observe_off = self.text("/policy/observe") == Some("off");
        let empty = Scan::default();
        let scan = self.scan.unwrap_or(&empty);
        let (opened, renamed, removed) = (
            scan.opened.len() as u64,
            scan.renamed.len() as u64,
            scan.removed.len() as u64,
        );
        let text = match write {
            Claim::NotObserved if observe_off => "not observed (--observe off)".to_owned(),
            Claim::NotObserved => "not observed".to_owned(),
            Claim::NoJournal => self.state.missing().unwrap_or_default(),
            Claim::Disagree => "journal and receipt disagree on fs.write".to_owned(),
            Claim::Exact | Claim::AtLeast => {
                let mut text = format!(
                    "{} {} opened for writing",
                    write.number(opened),
                    noun(opened, "path", "paths")
                );
                for (n, what) in [(renamed, "in renames"), (removed, "removed")] {
                    if n > 0 {
                        let _ = write!(text, ", {} {what}", write.number(n));
                    }
                }
                if scan.unnamed > 0 {
                    let _ = write!(
                        text,
                        " · {} {}",
                        write.number(scan.unnamed),
                        noun(
                            scan.unnamed,
                            "result with an unnamed path",
                            "results with unnamed paths"
                        )
                    );
                }
                text
            }
        };
        let mut text = format!("workspace: {text}");
        match deny {
            Claim::Exact | Claim::AtLeast if scan.refused > 0 => {
                let _ = write!(
                    text,
                    " · {} {}",
                    deny.number(scan.refused),
                    noun(scan.refused, "refused write", "refused writes")
                );
            }
            Claim::Disagree => {
                text.push_str(" · refused writes: journal and receipt disagree on fs.deny");
            }
            _ => {}
        }
        let paths: Vec<&Value> = if write.counts() {
            scan.named.values().take(JSON_LIST).collect()
        } else {
            Vec::new()
        };
        let omitted = if write.counts() {
            scan.named.len().saturating_sub(JSON_LIST)
        } else {
            0
        };
        Line {
            line: "workspace",
            text,
            facts: json!({
                "bound": write.bound(),
                "opened_for_writing": write.json(opened),
                "renamed": write.json(renamed),
                "removed": write.json(removed),
                "unnamed": write.json(scan.unnamed),
                "refused": deny.json(scan.refused),
                "refused_bound": deny.bound(),
                "paths": paths,
                "omitted": omitted,
            }),
        }
    }

    // -- network ------------------------------------------------------------

    fn network(&self) -> Line {
        let mode = self.text("/applied/network/mode").unwrap_or("pending");
        let claim = claim_of(self.classes, "proxy.net");
        let resolver_refused = self
            .receipt
            .pointer("/coverage/proxy.net/resolver_refused")
            .and_then(Value::as_u64);
        let label = |destination: &Option<String>| {
            destination
                .as_deref()
                .map_or_else(|| "(no destination)".to_owned(), shown)
        };
        let empty = Scan::default();
        let scan = self.scan.unwrap_or(&empty);
        let mut allowed: Vec<(&Option<String>, &Allowed)> = scan.allowed.iter().collect();
        allowed.sort_by(|a, b| b.1.results.cmp(&a.1.results).then_with(|| a.0.cmp(b.0)));
        let mut denied_by_destination: BTreeMap<&Option<String>, u64> = BTreeMap::new();
        for ((destination, _), n) in &scan.denied {
            *denied_by_destination.entry(destination).or_insert(0) += n;
        }
        let mut denied: Vec<(&Option<String>, u64)> = denied_by_destination.into_iter().collect();
        denied.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let text = match (mode, claim) {
            ("none", _) => "none".to_owned(),
            ("host", _) => "host, not observed".to_owned(),
            ("proxy", Claim::NotObserved) => "proxy, not observed".to_owned(),
            ("proxy", Claim::NoJournal) => {
                format!("proxy, {}", self.state.missing().unwrap_or_default())
            }
            ("proxy", Claim::Disagree) => {
                "proxy, journal and receipt disagree on proxy.net".to_owned()
            }
            ("proxy", Claim::Exact | Claim::AtLeast) => {
                let mut parts = Vec::new();
                if !allowed.is_empty() {
                    let items = allowed
                        .iter()
                        .map(|(destination, entry)| {
                            let mut item =
                                format!("{} ({}", label(destination), claim.number(entry.results));
                            if entry.connect_failed > 0 {
                                let _ = write!(
                                    item,
                                    ", {} connect failed",
                                    claim.number(entry.connect_failed)
                                );
                            }
                            item.push(')');
                            item
                        })
                        .collect();
                    parts.push(format!("allowed {}", capped(items, ", ")));
                }
                if !denied.is_empty() {
                    let items = denied
                        .iter()
                        .map(|(destination, n)| {
                            format!("{} ({})", label(destination), claim.number(*n))
                        })
                        .collect();
                    parts.push(format!("denied {}", capped(items, ", ")));
                }
                if parts.is_empty() {
                    parts.push(match claim {
                        Claim::Exact => "proxy, no connections".to_owned(),
                        _ => "proxy, none recorded (a lower bound)".to_owned(),
                    });
                }
                if let Some(n) = resolver_refused {
                    parts.push(format!("{n} refused for resolver capacity, not policy"));
                }
                parts.join(" · ")
            }
            _ => "not applied".to_owned(),
        };
        let counted = mode == "proxy" && claim.counts();
        let allowed_json: Vec<Value> = if counted {
            allowed
                .iter()
                .take(JSON_LIST)
                .map(|(destination, entry)| {
                    json!({
                        "destination": destination,
                        "results": entry.results,
                        "connect_failed": entry.connect_failed,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut denied_json: Vec<(&(Option<String>, String), &u64)> = if counted {
            scan.denied.iter().collect()
        } else {
            Vec::new()
        };
        denied_json.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let omitted = if counted {
            allowed.len().saturating_sub(JSON_LIST) + denied_json.len().saturating_sub(JSON_LIST)
        } else {
            0
        };
        let denied_json: Vec<Value> = denied_json
            .into_iter()
            .take(JSON_LIST)
            .map(|((destination, reason), n)| {
                json!({"destination": destination, "reason": reason, "results": n})
            })
            .collect();
        Line {
            line: "network",
            text: format!("network: {text}"),
            facts: json!({
                "mode": mode,
                "bound": if mode == "proxy" { claim.bound() } else { "not_observed" },
                "allowed": allowed_json,
                "denied": denied_json,
                "omitted": omitted,
                "resolver_refused": resolver_refused,
            }),
        }
    }

    // -- credentials --------------------------------------------------------

    fn credentials(&self) -> Option<Line> {
        let credentials = self.receipt.pointer("/credentials")?.as_array()?;
        if credentials.is_empty() {
            return None;
        }
        let claim = claim_of(self.classes, "proxy.net");
        let empty = Scan::default();
        let scan = self.scan.unwrap_or(&empty);
        let mut parts = Vec::new();
        let mut facts = Vec::new();
        let mut vault = false;
        for credential in credentials {
            let id = credential.get("id").and_then(Value::as_str).unwrap_or("");
            let mode = credential
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let never_staged = credential.get("never_staged").and_then(Value::as_bool);
            let transitions: Vec<String> = scan.transitions.get(id).cloned().unwrap_or_default();
            let mut part = format!("{}: {}", shown(id), shown(mode));
            let (uses, uses_bound) = if mode == "vault" {
                vault = true;
                if never_staged == Some(true) {
                    part.push_str(", never staged");
                }
                let recorded = scan.uses_recorded.contains(id);
                let uses = scan.uses.get(id).copied().unwrap_or(0);
                match claim {
                    Claim::NoJournal => {
                        let _ = write!(
                            part,
                            " · uses: {}",
                            self.state.missing().unwrap_or_default()
                        );
                        (Value::Null, "unavailable")
                    }
                    Claim::NotObserved => {
                        part.push_str(" · uses not observed");
                        (Value::Null, "not_observed")
                    }
                    Claim::Disagree => {
                        part.push_str(" · uses: journal and receipt disagree on proxy.net");
                        (Value::Null, "disagree")
                    }
                    Claim::Exact | Claim::AtLeast if !recorded => {
                        // A journal whose credential notes do not say this
                        // build records uses: its silence is not a zero.
                        part.push_str(" · uses not recorded");
                        (Value::Null, "not_recorded")
                    }
                    Claim::Exact | Claim::AtLeast => {
                        let _ = write!(
                            part,
                            " · used on {} {}",
                            claim.number(uses),
                            noun(uses, "proxy result", "proxy results")
                        );
                        (json!(uses), claim.bound())
                    }
                }
            } else {
                // The agent holds the value itself: there is no use to count.
                part.push_str(", staged (readable by the agent)");
                (Value::Null, "not_observed")
            };
            let notable: Vec<String> = transitions
                .iter()
                .filter(|transition| !matches!(transition.as_str(), "loaded" | "refresh_started"))
                .map(|transition| shown(transition))
                .collect();
            if !notable.is_empty() {
                let _ = write!(part, " · {}", notable.join(", "));
            }
            parts.push(part);
            facts.push(json!({
                "id": id,
                "mode": mode,
                "never_staged": never_staged,
                "uses": uses,
                "uses_bound": uses_bound,
                "transitions": transitions,
            }));
        }
        let count = parts.len();
        let mut text = format!(
            "{} {}",
            if count == 1 {
                "credential"
            } else {
                "credentials"
            },
            capped(parts, "; ")
        );
        // A lower bound of zero says nothing, so it is not printed.
        let silent = claim == Claim::AtLeast && scan.credential_refusals == 0;
        let refusals = if vault && claim.counts() {
            if !silent {
                let _ = write!(
                    text,
                    " · {} {}",
                    claim.number(scan.credential_refusals),
                    noun(
                        scan.credential_refusals,
                        "credential refusal",
                        "credential refusals"
                    )
                );
            }
            json!(scan.credential_refusals)
        } else {
            Value::Null
        };
        let omitted = facts.len().saturating_sub(JSON_LIST);
        facts.truncate(JSON_LIST);
        Some(Line {
            line: "credentials",
            text,
            facts: json!({
                "credentials": facts,
                "omitted": omitted,
                "refusals": refusals,
                "refusals_bound": if vault { claim.bound() } else { "not_observed" },
            }),
        })
    }

    // -- evidence -----------------------------------------------------------

    fn evidence(&self) -> Line {
        let observe = self.text("/policy/observe").unwrap_or("on");
        let mut parts = Vec::new();
        let observe_off = observe == "off";
        if observe_off {
            parts.push("observation off: exec, file and connect classes not observed".to_owned());
        } else {
            if self
                .receipt
                .pointer("/observer/attached")
                .and_then(Value::as_bool)
                == Some(false)
            {
                parts.push("observer not attached".to_owned());
            }
            let active = self
                .classes
                .iter()
                .filter(|class| class.status == "active" && class.claim != Claim::Disagree)
                .count();
            let observer_gaps = self
                .receipt
                .pointer("/observer/gaps")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if active == CLASSES.len() && self.state == JournalState::Complete && observer_gaps == 0
            {
                parts.push(format!(
                    "{active}/{} classes active, no gaps",
                    CLASSES.len()
                ));
            } else {
                parts.push(format!("{active}/{} classes active", CLASSES.len()));
            }
        }
        let mut gaps = Vec::new();
        let (mut not_started, mut not_observed) = (Vec::new(), Vec::new());
        for class in self.classes {
            if observe_off && AUDIT_CLASSES.contains(&class.name) {
                continue;
            }
            match class.status.as_str() {
                "active" => {}
                "degraded" => {
                    let class_gaps: Vec<&Value> = self
                        .receipt
                        .pointer(&format!("/coverage/{}/gaps", class.name))
                        .and_then(Value::as_array)
                        .map(|gaps| gaps.iter().collect())
                        .unwrap_or_default();
                    let mut item = format!("{} degraded", class.name);
                    if let Some(first) = class_gaps.first() {
                        let reason = first.get("reason").and_then(Value::as_str).unwrap_or("?");
                        let lost = first
                            .get("lost_count")
                            .and_then(Value::as_u64)
                            .map_or_else(|| "unknown".to_owned(), |n| n.to_string());
                        let _ = write!(item, " ({}, lost {lost}", shown(reason));
                        if class_gaps.len() > 1 {
                            let _ = write!(item, ", +{} more gaps", class_gaps.len() - 1);
                        }
                        item.push(')');
                    }
                    parts.push(item);
                    for gap in class_gaps {
                        gaps.push(json!({
                            "class": class.name,
                            "reason": gap.get("reason"),
                            "lost_count": gap.get("lost_count"),
                        }));
                    }
                }
                "supported" => not_started.push(class.name),
                _ => not_observed.push(class.name),
            }
        }
        // Classes in the same state share one item, so a refusal before any
        // observer existed stays one short line.
        for (names, state) in [(not_started, "not started"), (not_observed, "not observed")] {
            if !names.is_empty() {
                parts.push(format!("{} {state}", names.join(", ")));
            }
        }
        let disagree: Vec<&str> = self
            .classes
            .iter()
            .filter(|class| class.claim == Claim::Disagree)
            .map(|class| class.name)
            .collect();
        for class in &disagree {
            parts.push(format!("journal and receipt disagree on {class}"));
        }
        match self.state {
            JournalState::Complete => {}
            JournalState::Incomplete => {
                parts.push("journal incomplete: counts above are lower bounds".to_owned());
            }
            other => parts.extend(other.missing()),
        }
        let audit_shown = !observe_off
            && self.classes.iter().any(|class| {
                AUDIT_CLASSES.contains(&class.name)
                    && matches!(class.status.as_str(), "active" | "degraded")
            });
        if audit_shown {
            parts.push("reads and file contents are not observed".to_owned());
        }
        let statuses: serde_json::Map<String, Value> = self
            .classes
            .iter()
            .map(|class| (class.name.to_owned(), json!(class.status)))
            .collect();
        Line {
            line: "evidence",
            text: format!("evidence: {}", parts.join(" · ")),
            facts: json!({
                "observe": observe,
                "evidence": self.text("/policy/evidence"),
                "attached": self.receipt.pointer("/observer/attached").and_then(Value::as_bool),
                "classes": statuses,
                "gaps": gaps,
                "disagree": disagree,
            }),
        }
    }

    // -- limits -------------------------------------------------------------

    fn limits(&self) -> Option<Line> {
        let limits = self.receipt.pointer("/applied/limits")?.as_array()?;
        let mut hit = Vec::new();
        let mut not_applied = Vec::new();
        for limit in limits {
            let key = limit.get("key").and_then(Value::as_str).unwrap_or("?");
            let requested = limit
                .get("requested")
                .and_then(Value::as_str)
                .unwrap_or("?");
            if limit.get("hit").and_then(Value::as_bool) == Some(true) {
                hit.push((key, requested));
            }
            if limit.get("applied").and_then(Value::as_bool) == Some(false) {
                not_applied.push((key, requested));
            }
        }
        if hit.is_empty() && not_applied.is_empty() {
            return None;
        }
        let render = |items: &[(&str, &str)]| {
            capped(
                items
                    .iter()
                    .map(|(key, requested)| format!("{} ({})", shown(key), shown(requested)))
                    .collect(),
                ", ",
            )
        };
        let mut parts = Vec::new();
        if !hit.is_empty() {
            parts.push(format!("hit {}", render(&hit)));
        }
        if !not_applied.is_empty() {
            parts.push(format!("not applied: {}", render(&not_applied)));
        }
        let pairs = |items: &[(&str, &str)]| -> Vec<Value> {
            items
                .iter()
                .map(|(key, requested)| json!({"key": key, "requested": requested}))
                .collect()
        };
        Some(Line {
            line: "limits",
            text: format!("limits: {}", parts.join(" · ")),
            facts: json!({"hit": pairs(&hit), "not_applied": pairs(&not_applied)}),
        })
    }

    // -- cleanup and protection ---------------------------------------------

    fn cleanup(&self) -> Option<Line> {
        let cleanup = self.text("/state_cleanup");
        let protection = self.text("/child_protection");
        let mut parts = Vec::new();
        if cleanup == Some("pending") {
            parts.push("vendor state cleanup pending: run ukai-jail gc");
        }
        if protection == Some("unprotected") {
            parts.push("uncontained (none): nothing above was enforced");
        }
        if parts.is_empty() {
            return None;
        }
        Some(Line {
            line: "cleanup",
            text: parts.join(" · "),
            facts: json!({"state_cleanup": cleanup, "child_protection": protection}),
        })
    }
}

// ---------------------------------------------------------------------------
// Reading an attempt
// ---------------------------------------------------------------------------

/// The canonical receipt of the attempt directory `attempt`: the path the
/// receipt line names.
#[must_use]
pub fn receipt_path(attempt: &Path) -> std::path::PathBuf {
    attempt.join(crate::state::RECEIPT_NAME)
}

/// Reads an attempt's canonical receipt and journal and summarizes them.
/// `streamed` is the `--trace-fd` the live run used, when it used one: only
/// the run knows it, and no local journal exists then.
///
/// # Errors
/// The receipt cannot be read, is too large, or is not JSON.
pub fn summarize_attempt(attempt: &Path, streamed: Option<i32>) -> Result<Summary, String> {
    use crate::journal::{Bounded, read_bounded};
    let receipt_bytes = match read_bounded(
        attempt,
        crate::state::RECEIPT_NAME,
        crate::cleanup::RECEIPT_MAX,
    ) {
        Bounded::Bytes(bytes) => bytes,
        Bounded::TooLarge(_) => return Err("the receipt exceeds its size bound".to_owned()),
        Bounded::Absent => {
            return Err(format!("{}: no receipt", receipt_path(attempt).display()));
        }
        Bounded::Unreadable(error) => return Err(error),
    };
    let receipt: Value = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| format!("{}: {error}", receipt_path(attempt).display()))?;
    if let Some(fd) = streamed {
        return Ok(summary(&receipt, Journal::Streamed(fd)));
    }
    Ok(match read_bounded(attempt, "trace.ndjson", SCAN_CAP) {
        Bounded::Bytes(bytes) => summary(&receipt, Journal::Bytes(&bytes)),
        Bounded::TooLarge(size) => summary(&receipt, Journal::NotScanned(size)),
        Bounded::Absent => summary(&receipt, Journal::Absent),
        Bounded::Unreadable(_) => summary(&receipt, Journal::Unreadable),
    })
}
