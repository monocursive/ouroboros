//! The record rules JSON Schema cannot state (R01, jail-v1 §17 "Before J5").
//!
//! The frozen schemas (`docs/specs/jail-v1/*.schema.json`) carry every rule a
//! schema can express: shapes, phase tuples, per-source and per-operation
//! event semantics. What is left needs a comparison a schema has no keyword
//! for, or a view across more than one record:
//!
//! - [`receipt`]: native byte strings are canonical, credential ids and limit
//!   keys are unique, a counted class's source is not unsupported, and a
//!   gap's interval does not end before it starts;
//! - [`event`]: an event's native byte strings and its coverage-gap interval;
//! - [`trace`]: one attempt per stream, `source_seq` per source (§13.1), and
//!   receipt notes in lifecycle order; [`trace_ends_with`]: the stream ends on
//!   the final receipt's note, and its loss note agrees with that receipt's
//!   loss gaps (§13.3);
//! - [`control`]: one attempt, increasing message numbers and kinds in
//!   lifecycle order (§8.2).
//!
//! `docs/specs/jail-v1/validate_contract.py` holds a port of every rule here,
//! and both run the shared corpus `docs/specs/jail-v1/fixtures/semantic-cases.json`,
//! which names the rule each negative case must break; [`RULES`] is the list
//! the corpus cites. Every live test that reads a receipt, trace or control
//! transcript runs these checks (`tests/common/mod.rs`).
//!
//! A checker never panics and never stops at the first finding: it returns
//! every violation, each with the rule it breaks. Input that the schema would
//! reject (a missing field, a wrong type) is skipped here, not reported twice.

use std::fmt;

use serde_json::Value;

/// One broken rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The rule's stable identifier, one of [`RULES`].
    pub rule: &'static str,
    /// Where: a JSON path in a record, or `[index]` into a stream.
    pub at: String,
    /// What was found.
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.rule, self.at, self.detail)
    }
}

/// Every rule these checkers enforce, with the specification text it comes
/// from. The shared corpus cites exactly these.
pub const RULES: &[(&str, &str)] = &[
    (
        "native_string",
        "canonicalization.md \"Native strings\": a byte object is canonical padded base64 of bytes that are not UTF-8, and no native value holds NUL",
    ),
    (
        "credential_id_unique",
        "jail-v1.md:1833 (§13.2) and canonicalization.md: staged credentials have unique logical ids",
    ),
    (
        "limit_key_unique",
        "jail-v1.md:703 and :1895-1897 (§6.4, §13.2): one limit per key, each stating its own scope and hit",
    ),
    (
        "coverage_source_unsupported",
        "jail-v1.md:1561-1563 (§11.4): an active, supported or degraded class names its assigned source, which cannot then be unsupported",
    ),
    (
        "gap_interval_reversed",
        "jail-v1.md:1627-1629 (§11.4) and :1791 (§13.1): a gap is the interval from the last healthy point to recovery, so it does not end before it starts",
    ),
    (
        "trace_attempt_mixed",
        "jail-v1.md:1774 (§13.1) and :1909-1911 (§13.3): a trace is the one stream of one attempt",
    ),
    (
        "source_seq_order",
        "jail-v1.md:1775-1776 (§13.1): source_seq never restarts within an attempt, so it increases per source",
    ),
    (
        "source_seq_gap",
        "jail-v1.md:1775-1776 (§13.1) and :1938-1940 (§13.3): each source counts from 1; a missing number is lost evidence, which the stream's first loss records as a trace_transport_loss note",
    ),
    (
        "receipt_note_order",
        "jail-v1.md:837-851 (§8.1) and :1817-1821, :1846-1849 (§13.2): receipt notes follow the lifecycle; nothing after exec is a refusal, nothing leaves settled or refused",
    ),
    (
        "trace_final_receipt",
        "jail-v1.md:1792-1795 (§13.1) and :1948-1949 (§13.3): a complete trace ends on the jail.receipt note naming the final receipt's phase and canonical digest",
    ),
    (
        "trace_loss_recorded",
        "jail-v1.md:1928-1931 and :1938-1940 (§13.3): the first loss writes one trace_transport_loss note from the last healthy point, and every later receipt records that loss on each covered evidence class",
    ),
    (
        "control_attempt_mixed",
        "jail-v1.md:923-924 (§8.2): control output carries one attempt's messages",
    ),
    (
        "control_seq_order",
        "jail-v1.md:923-924 (§8.2): the message number increases monotonically",
    ),
    (
        "control_kind_order",
        "jail-v1.md:923-931 (§8.2) and :847-851 (§8.1): prepared, then exec_confirmed, then one terminal message; refused never after exec; nothing after a terminal message",
    ),
];

fn violation(rule: &'static str, at: impl Into<String>, detail: impl Into<String>) -> Violation {
    debug_assert!(RULES.iter().any(|(known, _)| *known == rule), "{rule}");
    Violation {
        rule,
        at: at.into(),
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------
// Native strings (canonicalization.md)
// ---------------------------------------------------------------------------

/// Why `value` is not a canonical native string, if it is not.
///
/// A JSON string is the UTF-8 form; an object is exactly
/// `{"encoding":"base64","data":...}` with canonical padded base64 of bytes
/// that are not valid UTF-8. Neither form may hold NUL.
///
/// # Errors
/// Why the value is not a canonical native string.
pub fn native_bytes(value: &Value) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let raw = match value {
        Value::String(text) => text.as_bytes().to_vec(),
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            if keys != ["data", "encoding"] {
                return Err(format!("a byte object has the keys {keys:?}"));
            }
            if map["encoding"] != "base64" {
                return Err("a byte object's encoding is not base64".to_owned());
            }
            let data = map["data"]
                .as_str()
                .ok_or("a byte object's data is not a string")?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|error| format!("the base64 does not decode: {error}"))?;
            if base64::engine::general_purpose::STANDARD.encode(&raw) != data {
                return Err("the base64 is not canonical".to_owned());
            }
            if std::str::from_utf8(&raw).is_ok() {
                return Err("UTF-8 bytes must use the JSON string form".to_owned());
            }
            raw
        }
        other => return Err(format!("{other} is not a native string")),
    };
    if raw.contains(&0) {
        return Err("a native value contains NUL".to_owned());
    }
    Ok(raw)
}

/// Every object that declares `"encoding": "base64"` under `node` is a
/// canonical native string.
fn byte_objects(node: &Value, at: &str, out: &mut Vec<Violation>) {
    match node {
        Value::Object(map) => {
            if map.get("encoding").and_then(Value::as_str) == Some("base64") {
                if let Err(error) = native_bytes(node) {
                    out.push(violation("native_string", at, error));
                }
                return;
            }
            for (key, value) in map {
                byte_objects(value, &format!("{at}.{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                byte_objects(value, &format!("{at}[{index}]"), out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Receipts (§11.4, §13.2)
// ---------------------------------------------------------------------------

/// A decimal nanosecond string (`0` or digits without a leading zero, the
/// schema's pattern); `None` when it is not one (the schema rejects that
/// separately).
fn decimal(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0'))
    })
}

/// Numeric order of two canonical decimal strings, at any length: a longer
/// one is larger, equal lengths compare as text. No integer type bounds it,
/// so `validate_contract.py`'s arbitrary-precision integers agree.
fn decimal_less(left: &str, right: &str) -> bool {
    (left.len(), left) < (right.len(), right)
}

/// A gap whose non-null end is before its start.
fn gap_interval(gap: &Value, at: &str, out: &mut Vec<Violation>) {
    if let (Some(start), Some(end)) = (decimal(&gap["start_ns"]), decimal(&gap["end_ns"]))
        && decimal_less(end, start)
    {
        out.push(violation(
            "gap_interval_reversed",
            at,
            format!("the interval ends at {end} before it starts at {start}"),
        ));
    }
}

/// Every rule a receipt breaks that its schema cannot state.
#[must_use]
pub fn receipt(record: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    byte_objects(record, "$", &mut out);
    for (path, list, key, rule) in [
        (
            "$.credentials",
            &record["credentials"],
            "id",
            "credential_id_unique",
        ),
        (
            "$.applied.limits",
            &record["applied"]["limits"],
            "key",
            "limit_key_unique",
        ),
    ] {
        let mut seen = std::collections::BTreeSet::new();
        for (index, item) in list.as_array().into_iter().flatten().enumerate() {
            if !seen.insert(item[key].to_string()) {
                out.push(violation(
                    rule,
                    format!("{path}[{index}]"),
                    format!("duplicate {key} {}", item[key]),
                ));
            }
        }
    }
    if let Some(coverage) = record["coverage"].as_object() {
        for (name, class) in coverage {
            if class["status"] != "unsupported"
                && let Some(source) = class["sources"][0].as_str()
                && record["observer"]["sources"][source] == "unsupported"
            {
                out.push(violation(
                    "coverage_source_unsupported",
                    format!("$.coverage.{name}"),
                    format!(
                        "the class is {} but counts from source {source}, which the observer reports unsupported",
                        class["status"]
                    ),
                ));
            }
            for (index, gap) in class["gaps"].as_array().into_iter().flatten().enumerate() {
                gap_interval(gap, &format!("$.coverage.{name}.gaps[{index}]"), &mut out);
            }
        }
    }
    for (index, gap) in record["observer"]["gaps"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        gap_interval(gap, &format!("$.observer.gaps[{index}]"), &mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// Events and traces (§13.1, §13.3)
// ---------------------------------------------------------------------------

fn is_note(event: &Value, kind: &str) -> bool {
    event["source"] == "wrapper" && event["operation"] == "note" && event["fields"]["kind"] == kind
}

/// The stream's record of a transport loss (§13.3).
fn is_loss_note(event: &Value) -> bool {
    is_note(event, "coverage_gap") && event["fields"]["reason"] == "trace_transport_loss"
}

/// A sequence number: a JSON integer, or a number with no fractional part,
/// which JSON Schema's `integer` also admits (`2.0`).
fn sequence_number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|number| number.fract() == 0.0 && *number >= 0.0 && *number < 2f64.powi(53))
            .and_then(|number| format!("{number:.0}").parse().ok())
    })
}

/// Every rule one event breaks that its schema cannot state.
#[must_use]
pub fn event(event: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    byte_objects(&event["fields"], "$.fields", &mut out);
    if is_note(event, "coverage_gap") {
        gap_interval(&event["fields"], "$.fields", &mut out);
    }
    out
}

/// A receipt phase's place in the §8.1 lifecycle, and whether `next` may
/// follow `previous` in a stream of receipts.
fn phase_may_follow(previous: &str, next: &str) -> bool {
    previous == next
        || matches!(
            (previous, next),
            ("prepared", "enforced" | "settled" | "refused") | ("enforced", "settled")
        )
}

/// Every rule a trace (the events of one stream, in order) breaks beyond
/// its events' own schemas: each event's [`event`] rules, one attempt,
/// `source_seq` per source, and receipt notes in lifecycle order.
///
/// `source_seq` starts at 1 for each source and increases (§13.1). A number
/// may be missing only once the stream recorded a loss: the first loss
/// writes a `trace_transport_loss` coverage-gap note (§13.3), and after it a
/// sink refuses ordinary frames whose numbers were already spent. Without
/// that note a missing number is a silent loss.
#[must_use]
pub fn trace(events: &[Value]) -> Vec<Violation> {
    let mut out = Vec::new();
    for (index, item) in events.iter().enumerate() {
        for mut found in event(item) {
            found.at = format!("[{index}]{}", found.at.trim_start_matches('$'));
            out.push(found);
        }
    }
    if let Some(first) = events.first() {
        for (index, item) in events.iter().enumerate() {
            if item["attempt_id"] != first["attempt_id"] {
                out.push(violation(
                    "trace_attempt_mixed",
                    format!("[{index}]"),
                    format!(
                        "attempt {} in a trace of attempt {}",
                        item["attempt_id"], first["attempt_id"]
                    ),
                ));
            }
        }
    }
    // Holes are recorded loss only from the stream's first loss note on: the
    // frames before it are a prefix of what the writer accepted (§13.3), so a
    // number missing there is a silent loss.
    let first_loss = events.iter().position(is_loss_note).unwrap_or(events.len());
    for source in ["wrapper", "audit", "proxy"] {
        let numbered: Vec<(usize, u64)> = events
            .iter()
            .enumerate()
            .filter(|(_, item)| item["source"] == source)
            .filter_map(|(index, item)| {
                sequence_number(&item["source_seq"]).map(|seq| (index, seq))
            })
            .collect();
        if let Some(pair) = numbered.windows(2).find(|pair| pair[1].1 <= pair[0].1) {
            out.push(violation(
                "source_seq_order",
                format!("[{}]", pair[1].0),
                format!("{source} source_seq {} after {}", pair[1].1, pair[0].1),
            ));
            continue;
        }
        if let Some((position, (index, seq))) = numbered
            .iter()
            .enumerate()
            .take_while(|(_, (index, _))| *index < first_loss)
            .find(|(position, (_, seq))| u64::try_from(*position + 1) != Ok(*seq))
        {
            out.push(violation(
                "source_seq_gap",
                format!("[{index}]"),
                format!(
                    "{source} source_seq {seq} where {} was due, and the stream records no transport loss",
                    position + 1
                ),
            ));
        }
    }
    let mut previous: Option<(usize, &str)> = None;
    for (index, item) in events.iter().enumerate() {
        if item["operation"] != "jail.receipt" {
            continue;
        }
        let Some(phase) = item["fields"]["phase"].as_str() else {
            continue;
        };
        if let Some((_, before)) = previous
            && !phase_may_follow(before, phase)
        {
            out.push(violation(
                "receipt_note_order",
                format!("[{index}]"),
                format!("a {phase} receipt note after a {before} one"),
            ));
        }
        previous = Some((index, phase));
    }
    out
}

/// `sha256:` over a receipt's RFC 8785 canonical bytes: the one name a
/// receipt has in `jail.receipt` notes and control messages
/// (canonicalization.md, "A receipt digest").
///
/// # Errors
/// Why the receipt has no canonical bytes (a floating-point number).
pub fn receipt_digest(receipt: &Value) -> Result<String, crate::canonical::CanonicalError> {
    let canonical = crate::canonical::to_jcs(receipt)?;
    Ok(crate::canonical::sha256_prefixed(&canonical))
}

/// Whether a complete trace ends on the note of `receipt`, the attempt's
/// final receipt (§13.3): its last frame is a wrapper `jail.receipt` event
/// of the same attempt naming that receipt's phase and canonical digest.
#[must_use]
pub fn trace_ends_with(events: &[Value], receipt: &Value) -> Vec<Violation> {
    let at = format!("[{}]", events.len().saturating_sub(1));
    let Some(last) = events.last() else {
        return vec![violation(
            "trace_final_receipt",
            at,
            "the trace is empty but the attempt has a receipt",
        )];
    };
    let digest = match receipt_digest(receipt) {
        Ok(digest) => digest,
        Err(error) => {
            return vec![violation(
                "trace_final_receipt",
                at,
                format!("the final receipt has no canonical digest: {error}"),
            )];
        }
    };
    let expected = (
        Some("wrapper"),
        Some("jail.receipt"),
        receipt["attempt_id"].as_str(),
        receipt["phase"].as_str(),
        Some(digest.as_str()),
    );
    let found = (
        last["source"].as_str(),
        last["operation"].as_str(),
        last["attempt_id"].as_str(),
        last["fields"]["phase"].as_str(),
        last["fields"]["receipt_digest"].as_str(),
    );
    let mut out = if found == expected {
        Vec::new()
    } else {
        vec![violation(
            "trace_final_receipt",
            at,
            format!("the last frame is {found:?}; the final receipt's note would be {expected:?}"),
        )]
    };
    loss_recorded(events, receipt, &mut out);
    out
}

/// The stream's loss note and the final receipt tell one story (§13.3): every
/// `trace_transport_loss` gap of the receipt has the note's source and start
/// and names only classes the note names, and every class the note names that
/// the receipt covers (not `unsupported`) has such a gap. A receipt loss gap
/// with no note in a complete stream is a loss the stream never recorded.
fn loss_recorded(events: &[Value], receipt: &Value, out: &mut Vec<Violation>) {
    let mut recorded: Vec<(&str, &Value)> = Vec::new();
    for (class, entry) in receipt["coverage"].as_object().into_iter().flatten() {
        for gap in entry["gaps"].as_array().into_iter().flatten() {
            if gap["reason"] == "trace_transport_loss" {
                recorded.push((class.as_str(), gap));
            }
        }
    }
    let Some(note) = events.iter().find(|event| is_loss_note(event)) else {
        if let Some((class, _)) = recorded.first() {
            out.push(violation(
                "trace_loss_recorded",
                format!("$.coverage.{class}"),
                "the receipt records a trace transport loss the stream has no note for",
            ));
        }
        return;
    };
    let fields = &note["fields"];
    let named: Vec<&str> = fields["classes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    for (class, gap) in &recorded {
        let within = gap["classes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .all(|name| named.contains(&name));
        if gap["source"] != fields["source"] || gap["start_ns"] != fields["start_ns"] || !within {
            out.push(violation(
                "trace_loss_recorded",
                format!("$.coverage.{class}"),
                format!(
                    "the receipt's loss gap ({} from {}, classes {}) is not the note's ({} from {}, classes {})",
                    gap["source"],
                    gap["start_ns"],
                    gap["classes"],
                    fields["source"],
                    fields["start_ns"],
                    fields["classes"]
                ),
            ));
        }
    }
    for class in named {
        let covered = receipt["coverage"][class]["status"]
            .as_str()
            .is_some_and(|status| status != "unsupported");
        if covered && !recorded.iter().any(|(name, _)| *name == class) {
            out.push(violation(
                "trace_loss_recorded",
                format!("$.coverage.{class}"),
                "the note names this covered class but the receipt records no transport loss on it",
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Control transcripts (§8.2)
// ---------------------------------------------------------------------------

/// Whether control message kind `next` may follow `previous` (§8.1, §8.2).
///
/// Messages can be dropped (a reader that stalls, §13.3), so a kind may be
/// missing; the ones present keep their order. `prepared` comes first,
/// `exec_confirmed` once after it, then exactly one terminal message.
fn kind_may_follow(previous: &str, next: &str) -> bool {
    matches!(
        (previous, next),
        (
            "prepared",
            "exec_confirmed" | "refused" | "settled" | "unsettled"
        ) | ("exec_confirmed", "settled" | "unsettled")
    )
}

/// Every rule a control transcript (one attempt's messages, in order)
/// breaks beyond its messages' own schema.
#[must_use]
pub fn control(messages: &[Value]) -> Vec<Violation> {
    let mut out = Vec::new();
    let Some(first) = messages.first() else {
        return out;
    };
    for (index, message) in messages.iter().enumerate() {
        if message["attempt_id"] != first["attempt_id"] {
            out.push(violation(
                "control_attempt_mixed",
                format!("[{index}]"),
                format!(
                    "attempt {} in a transcript of attempt {}",
                    message["attempt_id"], first["attempt_id"]
                ),
            ));
        }
    }
    for (index, pair) in messages.windows(2).enumerate() {
        if let (Some(before), Some(after)) = (pair[0]["seq"].as_u64(), pair[1]["seq"].as_u64())
            && after <= before
        {
            out.push(violation(
                "control_seq_order",
                format!("[{}]", index + 1),
                format!("message number {after} after {before}"),
            ));
        }
        if let (Some(before), Some(after)) = (pair[0]["kind"].as_str(), pair[1]["kind"].as_str())
            && !kind_may_follow(before, after)
        {
            out.push(violation(
                "control_kind_order",
                format!("[{}]", index + 1),
                format!("{after} after {before}"),
            ));
        }
    }
    out
}
