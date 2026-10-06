//! Bounded count comparisons over freshly verified, independent run snapshots.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use ouro_records::canonical::to_jcs;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    daemon::Client,
    protocol::{
        Chain, LedgerError, MAX_FRAME_BYTES, READ_OUTPUT_BYTES, ReadFilter, ReadPage, ReadRequest,
        ReadSelector, Result,
    },
};

const CLASSES: [&str; 6] = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"];
const MAX_BYTES: usize = 64 * 1_048_576;
const MAX_PAGES: usize = 4096;
const MAX_BUCKETS: usize = 4096;
const MAX_KEYS: usize = 8 * 1_048_576;

#[derive(Default)]
struct Counts {
    entries: BTreeMap<String, Value>,
    key_bytes: usize,
}

impl Counts {
    fn add(&mut self, record: &Value) -> Result<()> {
        let Some(class) = event_class(record) else {
            return Ok(());
        };
        // Deliberately counts, not entity equivalence: paths, hosts, PIDs and
        // timestamps are not compared. Audit and proxy stay separate.
        let key = String::from_utf8(
            to_jcs(&json!({"class":class,
            "source":record["source"],"operation":record["operation"],
            "stage":record["stage"],"decision":record["decision"],"outcome":record["outcome"]}))
            .map_err(|e| LedgerError(e.to_string()))?,
        )
        .map_err(|e| LedgerError(e.to_string()))?;
        if let Some(entry) = self.entries.get_mut(&key) {
            entry["count"] = json!(entry["count"].as_u64().unwrap() + 1);
            return Ok(());
        }
        if key.len() > 8192
            || self.entries.len() >= MAX_BUCKETS
            || self.key_bytes + key.len() > MAX_KEYS
        {
            return Err(LedgerError(
                "diff count bucket budget exceeded; narrow the evidence outside diff".into(),
            ));
        }
        self.key_bytes += key.len();
        self.entries.insert(
            key,
            json!({"count":1,"first_record":{
            "seq":record["seq"],"provenance":record["provenance"]}}),
        );
        Ok(())
    }
}

fn event_class(record: &Value) -> Option<&'static str> {
    if record["kind"] != "source" {
        return None;
    }
    match (record["source"].as_str()?, record["operation"].as_str()?) {
        ("proxy", "net.connect" | "net.dns") => Some("proxy.net"),
        (_, "proc.exec" | "proc.exit") => Some("exec"),
        (_, "fs.create" | "fs.write" | "fs.rename" | "fs.unlink") => Some("fs.write"),
        (_, "fs.deny") => Some("fs.deny"),
        (_, "net.connect" | "net.dns") => Some("net"),
        (_, "limit.hit") => Some("limits"),
        _ => None,
    }
}

struct Evidence {
    summary: Value,
    counts: Counts,
}

fn collect(
    run: &str,
    read: &mut impl FnMut(&ReadRequest) -> Result<ReadPage>,
    deadline: Instant,
) -> Evidence {
    let mut evidence = Evidence {
        summary: json!({"run_id":run,"snapshot":null,
        "state":"unknown","child_protection":"unknown","coverage":null,
        "local_consistency":false,"complete":false,"problem":null}),
        counts: Counts::default(),
    };
    let result = (|| -> Result<()> {
        let mut request = ReadRequest {
            run_id: run.into(),
            filter: ReadFilter {
                selector: ReadSelector::All,
                stage: None,
                since: None,
                until: None,
            },
            cursor: None,
            limit: 1000,
        };
        let mut pending = String::new();
        let mut bytes = 0;
        for _ in 0..MAX_PAGES {
            if Instant::now() >= deadline {
                return Err(LedgerError("diff time budget exceeded".into()));
            }
            let page = read(&request)?;
            if evidence.summary["snapshot"].is_null() {
                evidence.summary = json!({"run_id":run,"snapshot":page.snapshot,"state":page.state,
                    "child_protection":page.child_protection,"coverage":page.coverage,
                    "local_consistency":false,"complete":false,"problem":null});
            }
            if !page.local_consistency
                || matches!(page.stream_status.as_str(), "corrupt" | "incomplete")
            {
                return Err(LedgerError(format!(
                    "snapshot cannot be compared: {} {:?}",
                    page.stream_status, page.problems
                )));
            }
            bytes += page.ndjson.len();
            if bytes > MAX_BYTES {
                return Err(LedgerError(
                    "diff snapshot exceeds 64 MiB byte budget".into(),
                ));
            }
            pending.push_str(&page.ndjson);
            while let Some(end) = pending.find('\n') {
                if end > MAX_FRAME_BYTES {
                    return Err(LedgerError("diff record exceeds frame bound".into()));
                }
                evidence
                    .counts
                    .add(&serde_json::from_str::<Value>(&pending[..end])?)?;
                pending.drain(..=end);
            }
            if pending.len() > MAX_FRAME_BYTES {
                return Err(LedgerError("diff record exceeds frame bound".into()));
            }
            if page.done {
                if !pending.is_empty() {
                    return Err(LedgerError("diff received a partial final record".into()));
                }
                evidence.summary["complete"] = json!(true);
                evidence.summary["local_consistency"] = json!(true);
                return Ok(());
            }
            request.cursor = Some(
                page.next_cursor
                    .ok_or_else(|| LedgerError("diff reader omitted continuation".into()))?,
            );
        }
        Err(LedgerError("diff page budget exceeded".into()))
    })();
    if let Err(error) = result {
        evidence.summary["problem"] = json!(error.to_string());
    }
    evidence
}

fn class_reason(summary: &Value, class: &str) -> Option<&'static str> {
    if summary["complete"] != true || summary["local_consistency"] != true {
        return Some("incomplete_evidence");
    }
    if !matches!(summary["state"].as_str(), Some("settled" | "denied")) {
        return Some("run_not_terminal");
    }
    let coverage = &summary["coverage"];
    let entry = &coverage["classes"][class];
    let gaps = |v: &Value| v["gap_count"].as_u64().is_some_and(|n| n > 0);
    if coverage["status"] == "degraded"
        || gaps(coverage)
        || gaps(&coverage["classes"]["ledger"])
        || coverage["classes"]["ledger"]["status"] == "degraded"
        || gaps(entry)
        || entry["status"] == "degraded"
    {
        return Some("coverage_degraded");
    }
    if !matches!(coverage["status"].as_str(), Some("by_class" | "active"))
        || entry["status"] != "active"
    {
        return Some("unobserved");
    }
    if entry["sources"].as_array().is_none_or(Vec::is_empty) {
        return Some("source_unspecified");
    }
    None
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    left_run: String,
    right_run: String,
    left_head: Chain,
    right_head: Chain,
    offset: usize,
}

/// Every invocation verifies both streams afresh. Output pagination binds the
/// two heads and run order; a changed head refuses rather than mixing snapshots.
pub fn compare(
    client: &mut Client,
    left: &str,
    right: &str,
    after: Option<&str>,
    limit: u32,
) -> Result<Value> {
    compare_with(left, right, after, limit, &mut |request| {
        client.read(request)
    })
}

fn compare_with(
    left: &str,
    right: &str,
    after: Option<&str>,
    limit: u32,
    read: &mut impl FnMut(&ReadRequest) -> Result<ReadPage>,
) -> Result<Value> {
    if !(1..=1000).contains(&limit) {
        return Err(LedgerError("diff limit must be between 1 and 1000".into()));
    }
    for run in [left, right] {
        if run.len() != 36
            || !run.starts_with("run_")
            || !run.as_bytes()[4..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(LedgerError("diff requires canonical run ids".into()));
        }
    }
    let position: Option<Position> = after
        .map(|v| {
            if v.len() > 1024 {
                return Err(LedgerError("diff position exceeds bound".into()));
            }
            Ok(serde_json::from_str(v)?)
        })
        .transpose()?;
    if position
        .as_ref()
        .is_some_and(|p| p.left_run != left || p.right_run != right)
    {
        return Err(LedgerError(
            "diff position belongs to different runs".into(),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let a = collect(left, read, deadline);
    let b = collect(right, read, deadline);
    if let Some(p) = &position
        && (a.summary["snapshot"] != serde_json::to_value(&p.left_head)?
            || b.summary["snapshot"] != serde_json::to_value(&p.right_head)?)
    {
        return Err(LedgerError(
            "diff snapshot changed; start a new comparison".into(),
        ));
    }
    let mut classes = BTreeMap::new();
    for class in CLASSES {
        let ar = class_reason(&a.summary, class);
        let br = class_reason(&b.summary, class);
        let sources = |s: &Value| {
            let mut sources = s["coverage"]["classes"][class]["sources"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            sources.sort_by_key(Value::to_string);
            sources
        };
        let same_sources = sources(&a.summary) == sources(&b.summary);
        let comparable = ar.is_none() && br.is_none() && same_sources;
        classes.insert(class, json!({"status":if comparable {"comparable"} else {"incomparable"},
            "left_reason":ar,"right_reason":br,"shared_reason":if ar.is_none() && br.is_none() && !same_sources {Some("source_set_mismatch")} else {None}}));
    }
    let mut keys: Vec<_> = a
        .counts
        .entries
        .keys()
        .chain(b.counts.entries.keys())
        .collect();
    keys.sort();
    keys.dedup();
    let mut changes = Vec::new();
    for key in keys {
        let observation: Value = serde_json::from_str(key)?;
        let class = observation["class"].as_str().unwrap();
        if classes[class]["status"] != "comparable" {
            continue;
        }
        let count = |e: &Evidence| {
            e.counts
                .entries
                .get(key)
                .map_or(0, |v| v["count"].as_u64().unwrap())
        };
        if count(&a) == count(&b) {
            continue;
        }
        changes.push(
            json!({"observation":observation,"left_count":count(&a),"right_count":count(&b),
            "left_first_record":a.counts.entries.get(key).map(|v| &v["first_record"]),
            "right_first_record":b.counts.entries.get(key).map(|v| &v["first_record"])}),
        );
    }
    let total = changes.len();
    let offset = position.as_ref().map_or(0, |p| p.offset);
    if offset > total {
        return Err(LedgerError("diff position exceeds result length".into()));
    }
    let mut items = Vec::new();
    let mut bytes = 0;
    for item in changes.into_iter().skip(offset).take(limit as usize) {
        let size = serde_json::to_vec(&item)?.len();
        if size > READ_OUTPUT_BYTES {
            return Err(LedgerError("diff item exceeds output bound".into()));
        }
        if bytes + size > READ_OUTPUT_BYTES {
            break;
        }
        bytes += size;
        items.push(item);
    }
    let complete = a.summary["complete"] == true && b.summary["complete"] == true;
    let next_after = if complete && offset + items.len() < total {
        Some(serde_json::to_string(&Position {
            left_run: left.into(),
            right_run: right.into(),
            left_head: serde_json::from_value(a.summary["snapshot"].clone())?,
            right_head: serde_json::from_value(b.summary["snapshot"].clone())?,
            offset: offset + items.len(),
        })?)
    } else {
        None
    };
    let compared = classes
        .values()
        .filter(|v| v["status"] == "comparable")
        .count();
    Ok(
        json!({"schema":"ouro.ledger.diff/1","mode":"event_counts","complete":complete,
        "comparison_status":if compared == 0 {"incomparable"} else if compared == CLASSES.len() {"comparable"} else {"partial"},
        "left":a.summary,"right":b.summary,"classes":classes,"changes":items,
        "total_changes":total,"next_after":next_after}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_gapped_and_live_classes_cannot_be_compared() {
        let summary = json!({"complete":true,"local_consistency":true,"state":"settled",
            "coverage":{"status":"by_class","gap_count":0,"classes":{
                "exec":{"status":"active","sources":["audit"],"gap_count":0}}}});
        assert_eq!(class_reason(&summary, "exec"), None);
        for (path, value, expected) in [
            ("/state", json!("admitted"), "run_not_terminal"),
            ("/complete", json!(false), "incomplete_evidence"),
            ("/coverage/status", json!("degraded"), "coverage_degraded"),
            ("/coverage/status", json!("unobserved"), "unobserved"),
            ("/coverage/gap_count", json!(1), "coverage_degraded"),
            (
                "/coverage/classes/exec/gap_count",
                json!(1),
                "coverage_degraded",
            ),
            (
                "/coverage/classes/exec/status",
                json!("unsupported"),
                "unobserved",
            ),
            (
                "/coverage/classes/exec/sources",
                json!([]),
                "source_unspecified",
            ),
        ] {
            let mut altered = summary.clone();
            *altered.pointer_mut(path).unwrap() = value;
            assert_eq!(class_reason(&altered, "exec"), Some(expected));
        }
        assert_eq!(class_reason(&summary, "proxy.net"), Some("unobserved"));
    }

    #[test]
    fn count_keys_separate_sources_stages_and_outcomes_and_enforce_budget() {
        let mut counts = Counts::default();
        let mut record = json!({"kind":"source","source":"audit","operation":"net.connect",
            "stage":"attempt","decision":null,"outcome":null,"seq":1,"provenance":{"role":"producer"}});
        counts.add(&record).unwrap();
        record["fields"] = json!({"pid":123,"host":"different.example"});
        counts.add(&record).unwrap();
        assert_eq!(counts.entries.len(), 1);
        assert_eq!(counts.entries.values().next().unwrap()["count"], 2);
        record["source"] = json!("proxy");
        counts.add(&record).unwrap();
        assert_eq!(event_class(&record), Some("proxy.net"));
        assert_eq!(counts.entries.len(), 2);
        record["outcome"] = json!({"message":"x".repeat(8192)});
        assert!(counts.add(&record).is_err());
        record["outcome"] = Value::Null;
        record["stage"] = json!("result");
        counts.key_bytes = MAX_KEYS;
        assert!(counts.add(&record).is_err());
    }
    fn test_page() -> ReadPage {
        let mut page: ReadPage = serde_json::from_str(include_str!(
            "../../../docs/specs/ledger-v1/fixtures/read-page.json"
        ))
        .unwrap();
        page.ndjson =
            include_str!("../../../docs/specs/ledger-v1/fixtures/exec-failure-records.ndjson")
                .into();
        page.done = true;
        page.next_cursor = None;
        page
    }

    #[test]
    fn different_sources_are_incomparable_without_changing_protection_labels() {
        let left = "run_11111111111111111111111111111111";
        let right = "run_22222222222222222222222222222222";
        let report = compare_with(left, right, None, 100, &mut |request| {
            let mut page = test_page();
            if request.run_id == right {
                page.child_protection = "unprotected".into();
                page.coverage["classes"]["exec"]["sources"] = json!(["wrapper"]);
            }
            Ok(page)
        })
        .unwrap();
        assert_eq!(
            report["classes"]["exec"]["shared_reason"],
            "source_set_mismatch"
        );
        assert_eq!(report["classes"]["exec"]["status"], "incomparable");
        assert_eq!(report["left"]["child_protection"], "enforced");
        assert_eq!(report["right"]["child_protection"], "unprotected");
    }

    #[test]
    fn page_budget_exhaustion_and_partial_records_fail_closed() {
        let mut calls = 0;
        let result = collect(
            "run_11111111111111111111111111111111",
            &mut |_| {
                calls += 1;
                let mut page = test_page();
                page.ndjson.clear();
                page.done = false;
                page.next_cursor = Some("a".repeat(64));
                Ok(page)
            },
            Instant::now() + Duration::from_secs(30),
        );
        assert_eq!(calls, MAX_PAGES);
        assert_eq!(result.summary["complete"], false);
        assert!(
            result.summary["problem"]
                .as_str()
                .unwrap()
                .contains("page budget")
        );
        let result = collect(
            "run_11111111111111111111111111111111",
            &mut |_| {
                let mut page = test_page();
                page.ndjson.pop();
                Ok(page)
            },
            Instant::now() + Duration::from_secs(30),
        );
        assert_eq!(result.summary["complete"], false);
        assert!(
            result.summary["problem"]
                .as_str()
                .unwrap()
                .contains("partial final record")
        );
    }
}
