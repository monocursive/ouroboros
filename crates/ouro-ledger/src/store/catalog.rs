//! Stateless discovery over accepted canonical projections. Positions bind a
//! matching catalog fingerprint and scope, never caller-supplied display labels.
use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    discovery::{MAX_CATALOG_LIMIT, MAX_CATALOG_RUNS, MAX_POSITION_BYTES, validate_filter},
    protocol::{
        CatalogPage, CatalogRequest, DiscoveryPage, DiscoveryRequest, READ_OUTPUT_BYTES,
        ReadFilter, ReadSelector, RunFilter, RunSummary,
    },
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    schema: String,
    snapshot: String,
    scope: String,
    last_run: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryPosition {
    schema: String,
    snapshot: String,
    scope: String,
    catalog_after: Option<String>,
    read_position: Option<String>,
}

fn position<T: serde::de::DeserializeOwned>(value: Option<&str>) -> Result<Option<T>> {
    value
        .map(|v| {
            if v.len() > MAX_POSITION_BYTES {
                return Err(LedgerError("discovery position exceeds bound".into()));
            }
            Ok(serde_json::from_str(v)?)
        })
        .transpose()
}

impl Stream {
    fn catalog_outcome(&self) -> &str {
        if !self.poisoned.is_empty() {
            return "unknown";
        }
        self.run
            .outcome
            .as_ref()
            .and_then(|v| v["kind"].as_str())
            .filter(|v| {
                [
                    "pending",
                    "refused",
                    "exited",
                    "signaled",
                    "exec_error",
                    "unknown",
                ]
                .contains(v)
            })
            .unwrap_or(
                if self.run.state == "prepared" || self.run.state == "admitted" {
                    "pending"
                } else {
                    "unknown"
                },
            )
    }

    fn catalog_matches(&self, filter: &RunFilter) -> bool {
        if filter
            .since
            .as_ref()
            .is_some_and(|since| self.last_activity_at.as_ref().is_none_or(|t| t < since))
            || filter
                .until
                .as_ref()
                .is_some_and(|until| self.last_activity_at.as_ref().is_none_or(|t| t >= until))
            || filter
                .launch
                .as_ref()
                .is_some_and(|name| self.run.payload["launch"].as_str() != Some(name.as_str()))
            || filter
                .outcome
                .as_ref()
                .is_some_and(|kind| kind != self.catalog_outcome())
        {
            return false;
        }
        filter.tags.iter().all(|tag| {
            self.run.payload["tags"]
                .as_array()
                .is_some_and(|tags| tags.iter().any(|v| v.as_str() == Some(tag)))
        })
    }

    fn catalog_summary(&self) -> RunSummary {
        let ambiguous = !self.poisoned.is_empty();
        let mut coverage = if ambiguous {
            json!({"scope":"snapshot_run","status":"degraded","classes":{},"gap_count":self.poisoned.len()})
        } else {
            crate::reader::coverage_summary(&self.run.coverage)
        };
        coverage["selection_status"] = json!(crate::reader::selection_status(
            &ReadFilter {
                selector: ReadSelector::All,
                stage: None,
                since: None,
                until: None
            },
            &coverage
        ));
        RunSummary {
            run_id: self.run.run_id.clone(),
            attempt_id: self.run.attempt_id.clone(),
            request_id: self.run.request_id.clone(),
            last_activity_at: self.last_activity_at.clone(),
            profile: self.run.payload["profile"]
                .as_str()
                .unwrap_or("unknown")
                .into(),
            launch: self.run.payload["launch"].as_str().map(str::to_owned),
            tags: self.run.payload["tags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            state: if ambiguous {
                "outcome_unknown".into()
            } else {
                self.run.state.clone()
            },
            outcome: self.catalog_outcome().into(),
            child_protection: self.run.child_protection.clone(),
            coverage,
            chain: self.run.chain.clone(),
            evidence_status: if ambiguous {
                "ambiguous"
            } else if self.pruned.is_some() {
                "pruned"
            } else {
                "available"
            }
            .into(),
            history: self.run.history.clone(),
            capture_history: self.run.capture_history.clone(),
        }
    }
}

impl Store {
    /// Compatibility endpoint: a single bounded full-record response, never an
    /// unbounded substitute for the catalog API.
    pub fn legacy_runs(&self) -> Result<Vec<RunRecord>> {
        struct Budget(usize);
        impl std::io::Write for Budget {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > self.0 {
                    return Err(std::io::Error::other(
                        "legacy runs exceeds response bound; use catalog pagination",
                    ));
                }
                self.0 -= bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        if self.streams.len() > MAX_CATALOG_LIMIT as usize {
            return Err(LedgerError(
                "legacy runs exceeds run count bound; use catalog pagination".into(),
            ));
        }
        let mut budget = Budget(READ_OUTPUT_BYTES);
        for stream in self.streams.values() {
            serde_json::to_writer(&mut budget, &stream.run)?;
            serde_json::to_writer(&mut budget, &stream.poisoned)?;
        }
        Ok(self.runs())
    }

    pub fn catalog(&self, request: &CatalogRequest) -> Result<CatalogPage> {
        validate_filter(&request.filter)?;
        if !(1..=MAX_CATALOG_LIMIT).contains(&request.limit) {
            return Err(LedgerError(
                "catalog limit must be between 1 and 100".into(),
            ));
        }
        if self.streams.len() > MAX_CATALOG_RUNS {
            return Err(LedgerError(
                "catalog exceeds 16384-run scan bound; explicit run readers remain available"
                    .into(),
            ));
        }
        let mut filter = request.filter.clone();
        filter.tags.sort();
        let scope = digest(&json!({"filter":filter,"limit":request.limit}))?;
        let prior: Option<Position> = position(request.after.as_deref())?;
        if let Some(prior) = &prior {
            check_run_id(&prior.last_run)?;
            if prior.schema != "ouro.ledger.catalog-position/1" || prior.scope != scope {
                return Err(LedgerError(
                    "catalog position belongs to a different scope or limit".into(),
                ));
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"ouro.ledger.catalog/1\0");
        let mut runs = Vec::new();
        let mut bytes = 0;
        let mut full = false;
        let mut more = false;
        let mut matched_runs = 0;
        let mut prior_exists = prior.is_none();
        // One bounded pass, no SQLite dependency or copies of full RunRecords.
        for (id, stream) in &self.streams {
            if !stream.catalog_matches(&filter) {
                continue;
            }
            matched_runs += 1;
            let summary = stream.catalog_summary();
            let encoded = canonical(&serde_json::to_value(&summary)?)?;
            hash.update((encoded.len() as u64).to_le_bytes());
            hash.update(&encoded);
            if prior.as_ref().is_some_and(|p| id == &p.last_run) {
                prior_exists = true;
            }
            if prior.as_ref().is_some_and(|p| id <= &p.last_run) {
                continue;
            }
            if encoded.len() > READ_OUTPUT_BYTES {
                return Err(LedgerError("catalog summary exceeds page bound".into()));
            }
            full |=
                runs.len() >= request.limit as usize || bytes + encoded.len() > READ_OUTPUT_BYTES;
            if full {
                more = true;
                continue;
            }
            bytes += encoded.len();
            runs.push(summary);
        }
        let snapshot = format!("sha256:{:x}", hash.finalize());
        if prior.as_ref().is_some_and(|p| p.snapshot != snapshot) || !prior_exists {
            return Err(LedgerError(
                "matching catalog changed; restart discovery".into(),
            ));
        }
        let next_after = if more {
            Some(serde_json::to_string(&Position {
                schema: "ouro.ledger.catalog-position/1".into(),
                snapshot: snapshot.clone(),
                scope,
                last_run: runs
                    .last()
                    .expect("one bounded summary fits")
                    .run_id
                    .clone(),
            })?)
        } else {
            None
        };
        Ok(CatalogPage {
            schema: "ouro.ledger.catalog/1".into(),
            snapshot,
            runs,
            matched_runs,
            scanned_runs: self.streams.len() as u32,
            next_after,
            done: !more,
        })
    }

    pub fn discover(&mut self, request: &DiscoveryRequest) -> Result<DiscoveryPage> {
        validate_filter(&request.runs)?;
        if request.filter.selector == ReadSelector::All {
            return Err(LedgerError(
                "discovered query requires an evidence class".into(),
            ));
        }
        crate::reader::validate_request(&ReadRequest {
            run_id: String::new(),
            filter: request.filter.clone(),
            cursor: None,
            limit: request.limit,
        })?;
        let mut filters = request.runs.clone();
        filters.tags.sort();
        let scope = digest(&json!({"runs":filters,"filter":request.filter,"limit":request.limit}))?;
        let prior: Option<DiscoveryPosition> = position(request.after.as_deref())?;
        if prior
            .as_ref()
            .is_some_and(|p| p.schema != "ouro.ledger.discovery-position/1" || p.scope != scope)
        {
            return Err(LedgerError(
                "query discovery position belongs to a different scope or limit".into(),
            ));
        }
        let catalog_after = prior.as_ref().and_then(|p| p.catalog_after.clone());
        let catalog = self.catalog(&CatalogRequest {
            filter: filters,
            after: catalog_after.clone(),
            limit: 1,
        })?;
        if prior
            .as_ref()
            .is_some_and(|p| p.snapshot != catalog.snapshot)
        {
            return Err(LedgerError(
                "matching catalog changed; restart discovery".into(),
            ));
        }
        let run = catalog.runs.into_iter().next();
        let mut result = DiscoveryPage {
            schema: "ouro.ledger.discovery/1".into(),
            catalog_snapshot: catalog.snapshot.clone(),
            matched_runs: catalog.matched_runs,
            run: run.clone(),
            page: None,
            problem: None,
            next_after: None,
            done: true,
        };
        let Some(run) = run else {
            return Ok(result);
        };
        let read = self.read(&ReadRequest {
            run_id: run.run_id.clone(),
            filter: request.filter.clone(),
            cursor: prior.and_then(|p| p.read_position),
            limit: request.limit,
        });
        let continuation = match read {
            Ok(page) => {
                if page.snapshot != run.chain || page.run_id != run.run_id {
                    return Err(LedgerError(
                        "reader snapshot differs from the selected catalog head".into(),
                    ));
                }
                let progress = if page.done {
                    catalog.next_after.map(|v| (Some(v), None))
                } else {
                    Some((catalog_after, page.next_cursor.clone()))
                };
                result.page = Some(page);
                progress
            }
            Err(error) => {
                result.problem = Some(error.to_string());
                catalog.next_after.map(|v| (Some(v), None))
            }
        };
        if let Some((catalog_after, read_position)) = continuation {
            result.next_after = Some(serde_json::to_string(&DiscoveryPosition {
                schema: "ouro.ledger.discovery-position/1".into(),
                snapshot: catalog.snapshot,
                scope,
                catalog_after,
                read_position,
            })?);
            result.done = false;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Peer {
        Peer {
            uid: unsafe { libc::geteuid() },
            pid: std::process::id(),
            birth: "catalog-fixture".into(),
            boot_id: "fixture".into(),
        }
    }
    fn payload() -> Value {
        serde_json::from_str(include_str!(
            "../../../../docs/specs/ledger-v1/fixtures/request.json"
        ))
        .unwrap()
    }
    fn request() -> CatalogRequest {
        CatalogRequest {
            filter: RunFilter::default(),
            after: None,
            limit: 1,
        }
    }

    #[test]
    fn catalog_metadata_is_bounded_immutable_and_preserves_legacy_absence() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["launch"] = json!("fixture-launch");
        plan["tags"] = json!(["blue", "qa"]);
        let run = store.prepare("named", &plan, &peer()).unwrap();
        assert_eq!(
            store.prepare("named", &plan, &peer()).unwrap().run_id,
            run.run_id
        );
        let mut changed = plan.clone();
        changed["tags"] = json!(["changed"]);
        assert!(store.prepare("named", &changed, &peer()).is_err());
        for bad in [
            json!(["a", "a"]),
            json!(["a".repeat(65)]),
            json!(["raw text\n"]),
            json!(["/path"]),
            json!(null),
            json!(vec!["a"; 17]),
        ] {
            changed["tags"] = bad;
            assert!(store.prepare("invalid", &changed, &peer()).is_err());
        }
        let legacy = store.prepare("legacy", &payload(), &peer()).unwrap();
        let mut query = request();
        query.limit = 100;
        let page = store.catalog(&query).unwrap();
        let old = page
            .runs
            .iter()
            .find(|r| r.run_id == legacy.run_id)
            .unwrap();
        assert_eq!(old.launch, None);
        assert!(old.tags.is_empty());
        query.filter.launch = Some("fixture-launch".into());
        query.filter.tags = vec!["qa".into(), "blue".into()];
        query.filter.outcome = Some("pending".into());
        let page = store.catalog(&query).unwrap();
        assert_eq!(page.matched_runs, 1);
        assert_eq!(page.runs[0].run_id, run.run_id);
        assert_eq!(page.runs[0].child_protection, "unprotected");
        query.filter.since = Some("9999-01-01T00:00:00Z".into());
        assert!(store.catalog(&query).unwrap().runs.is_empty());
        query.filter.until = Some("2020-01-01T00:00:00Z".into());
        assert!(store.catalog(&query).is_err());
    }

    #[test]
    fn catalog_pages_survive_restart_but_refuse_scope_and_matching_membership_changes() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["tags"] = json!(["selected"]);
        for id in ["first", "second"] {
            store.prepare(id, &plan, &peer()).unwrap();
        }
        let mut query = request();
        query.filter.tags = vec!["selected".into()];
        let first = store.catalog(&query).unwrap();
        query.after = first.next_after.clone();
        let second = store.catalog(&query).unwrap();
        assert!(second.done);
        assert_ne!(first.runs[0].run_id, second.runs[0].run_id);
        drop(store);
        let mut store = Store::open(&data).unwrap();
        assert_eq!(store.catalog(&query).unwrap(), second);
        store.prepare("not-selected", &payload(), &peer()).unwrap();
        let unchanged = store.catalog(&query).unwrap();
        assert_eq!(unchanged.snapshot, second.snapshot);
        assert_eq!(unchanged.runs, second.runs);
        let mut rebound = query.clone();
        rebound.limit = 2;
        assert!(store.catalog(&rebound).is_err());
        rebound = query.clone();
        rebound.filter.outcome = Some("pending".into());
        assert!(store.catalog(&rebound).is_err());
        let mut forged: Value = serde_json::from_str(query.after.as_ref().unwrap()).unwrap();
        forged["last_run"] = json!("run_00000000000000000000000000000000");
        rebound = query.clone();
        rebound.after = Some(forged.to_string());
        assert!(store.catalog(&rebound).is_err());
        store.prepare("new-match", &plan, &peer()).unwrap();
        assert!(
            store
                .catalog(&query)
                .unwrap_err()
                .to_string()
                .contains("catalog changed")
        );
    }

    #[test]
    fn pruned_runs_remain_discoverable_with_labels_but_query_reports_unavailable_history() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        plan["launch"] = json!("label-only");
        plan["tags"] = json!(["retained"]);
        let run = store.prepare("pruned", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        store
            .append_owner(
                &run.run_id,
                "denied",
                "denied",
                None,
                &json!({"outcome":{"kind":"refused"}}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let result = store
            .gc_at(1, None, 100, &peer(), super::super::tests::gc_future())
            .unwrap();
        assert_eq!(result.pruned.len(), 1);
        drop(store);
        let mut store = Store::open(&data).unwrap();
        let query = DiscoveryRequest {
            runs: RunFilter {
                tags: vec!["retained".into()],
                outcome: Some("refused".into()),
                ..Default::default()
            },
            filter: ReadFilter {
                selector: ReadSelector::Execs,
                stage: None,
                since: None,
                until: None,
            },
            after: None,
            limit: 100,
        };
        let page = store.discover(&query).unwrap();
        let summary = page.run.unwrap();
        assert_eq!(summary.run_id, run.run_id);
        assert_eq!(summary.evidence_status, "pruned");
        assert_eq!(summary.child_protection, "unprotected");
        assert_eq!(summary.launch.as_deref(), Some("label-only"));
        assert!(summary.history.is_some());
        assert!(page.page.is_none());
        assert!(page.problem.unwrap().contains("history was pruned"));
        assert!(page.done);
    }

    #[test]
    fn catalog_omits_large_receipts_while_legacy_response_and_catalog_scan_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare("bounded", &payload(), &peer()).unwrap();
        let template = store.streams[&run.run_id].clone();
        store.streams.get_mut(&run.run_id).unwrap().run.receipts =
            vec![json!({"large":"x".repeat(131072)})];
        assert!(store.legacy_runs().is_err());
        assert_eq!(store.catalog(&request()).unwrap().runs.len(), 1);
        store.streams.clear();
        for i in 0..=MAX_CATALOG_RUNS {
            let id = format!("run_{i:032x}");
            let mut stream = template.clone();
            stream.run.run_id = id.clone();
            store.streams.insert(id, stream);
        }
        assert!(
            store
                .catalog(&request())
                .unwrap_err()
                .to_string()
                .contains("scan bound")
        );
        store.streams.pop_last();
        let page = store.catalog(&request()).unwrap();
        assert_eq!(page.scanned_runs, MAX_CATALOG_RUNS as u32);
        assert_eq!(page.runs.len(), 1);
        assert!(page.next_after.is_some());
    }
}
