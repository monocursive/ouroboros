//! Fresh verification in two halves. The writer plans a page from its
//! accepted state: for each stream that costs a directory listing, a stat
//! per segment and two small bounded reads, and for each pruned run a copy
//! of its terminal projection (its retained authority is shared, not
//! copied). A verifier then re-reads and re-hashes the canonical bytes off
//! the writer thread, never past the layout the plan saw, so one large run
//! never stalls the owners and producers waiting on the writer.
use std::{fs::OpenOptions, path::PathBuf};

use serde_json::Value;

use super::{
    Store, check_run_id,
    frozen::validate_frozen,
    pruning,
    stream::{
        load::{Layout, load_stream},
        poison_details,
    },
    writer::private_file,
};
use crate::protocol::{
    Chain, LedgerError, MAX_VERIFY_LIMIT, Result, RunRecord, VerifyPage, VerifyReport,
};

/// One page of fresh verification, as the writer planned it.
pub(crate) struct VerifyPlan {
    targets: Vec<Target>,
    next_after: Option<String>,
    done: bool,
    gc_generation: u64,
}

/// One run to re-read: what the writer saw on disk, and what it accepted, at
/// the moment it planned the run.
pub(crate) struct Target {
    run_id: String,
    directory: PathBuf,
    /// The writer's own findings about this run.
    poisoned: Vec<String>,
    /// The head the writer had accepted when the layout was taken.
    accepted: Chain,
    /// The labels the writer had accepted, reported when the re-read fails.
    child_protection: String,
    coverage: Value,
    /// The canonical bytes the writer had accepted, when nothing poisoned
    /// the stream. A writer that has not poisoned a stream left no bytes
    /// beyond them: any there are someone else's.
    accepted_bytes: Option<u64>,
    kind: TargetKind,
}

enum TargetKind {
    Pruned {
        retained: std::sync::Arc<pruning::Retained>,
        run: Box<RunRecord>,
    },
    Stream {
        layout: Layout,
        /// The published run.json bytes, read with the layout so a later
        /// append's projection is never compared with this prefix.
        projection: std::result::Result<Vec<u8>, String>,
    },
}

impl Store {
    /// Select a page and take each run's layout. A page stops at `limit`
    /// runs or before it would re-read more than VERIFY_PAGE_BYTES of
    /// canonical history (it always holds at least one run), so a single
    /// request never re-reads a whole store.
    pub(crate) fn plan_verify(
        &self,
        run_id: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<VerifyPlan> {
        if let Some(id) = run_id {
            return Ok(VerifyPlan {
                targets: vec![self.target(id)?],
                next_after: None,
                done: true,
                gc_generation: self.gc_generation(),
            });
        }
        if !(1..=MAX_VERIFY_LIMIT).contains(&limit) {
            return Err(LedgerError::refused(format!(
                "verify limit must be between 1 and {MAX_VERIFY_LIMIT}"
            )));
        }
        if let Some(id) = after {
            check_run_id(id)?;
        }
        let lower = after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut targets: Vec<Target> = Vec::new();
        let mut bytes = 0u64;
        let mut next_after = None;
        for (id, stream) in self
            .streams()
            .range::<str, _>((lower, std::ops::Bound::Unbounded))
        {
            let read = bytes.saturating_add(stream.accepted_bytes());
            if let Some(last) = targets.last()
                && (targets.len() >= limit as usize || read > self.verify_page_bytes())
            {
                next_after = Some(last.run_id.clone());
                break;
            }
            bytes = read;
            targets.push(self.target(id)?);
        }
        Ok(VerifyPlan {
            targets,
            done: next_after.is_none(),
            next_after,
            gc_generation: self.gc_generation(),
        })
    }

    fn target(&self, id: &str) -> Result<Target> {
        let stream = self.stream(id)?;
        let directory = self.run_dir(id);
        let kind = match stream.pruned() {
            Some(retained) => TargetKind::Pruned {
                retained: retained.clone(),
                run: Box::new(stream.run().clone()),
            },
            None => TargetKind::Stream {
                layout: Layout::read(&directory, id),
                projection: private_file(&directory.join("run.json"), &mut OpenOptions::new())
                    .and_then(|file| {
                        crate::protocol::read_bounded(
                            file,
                            crate::projection::MAX_RUN_BYTES as u64,
                            "run projection exceeds its bounded read limit",
                        )
                    })
                    .map_err(|error| error.to_string()),
            },
        };
        Ok(Target {
            run_id: id.into(),
            directory,
            poisoned: poison_details(stream.poisoned()),
            accepted: stream.run().chain.clone(),
            child_protection: stream.run().child_protection.clone(),
            coverage: crate::reader::coverage_summary(&stream.run().coverage),
            accepted_bytes: (!stream.is_poisoned()).then(|| stream.accepted_bytes()),
            kind,
        })
    }

    /// One page planned and re-read on the calling thread, for direct store
    /// users. The daemon never calls this: it re-reads on the connection.
    pub fn verify_page(
        &self,
        run_id: Option<&str>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<VerifyPage> {
        verify_page(
            &mut |run_id, after, limit| self.plan_verify(run_id, after, limit),
            &mut || Ok(self.gc_generation()),
            &mut || true,
            run_id,
            after,
            limit,
        )
    }

    /// Every run, page by page, as the CLI assembles it.
    #[cfg(test)]
    pub(crate) fn verify(&self, run_id: Option<&str>) -> Result<Vec<VerifyReport>> {
        let mut reports = Vec::new();
        let mut after = None;
        loop {
            let page = self.verify_page(run_id, after.as_deref(), MAX_VERIFY_LIMIT)?;
            reports.extend(page.reports);
            if page.done {
                return Ok(reports);
            }
            after = page.next_after;
        }
    }
}

impl Target {
    /// Re-read and re-hash this run. `proceed` is asked before every
    /// canonical frame; once it refuses, the report says what was not checked.
    /// A re-read that fails outright is this run's problem, never the page's:
    /// a GC may have caused it, and every other run is still reported.
    pub(crate) fn verify(self, proceed: &mut impl FnMut() -> bool) -> VerifyReport {
        let (run_id, child_protection, coverage) = (
            self.run_id.clone(),
            self.child_protection.clone(),
            self.coverage.clone(),
        );
        self.reread(proceed).unwrap_or_else(|error| VerifyReport {
            run_id,
            local_consistency: false,
            child_protection,
            coverage,
            events: 0,
            problems: vec![format!(
                "fresh verification could not re-read this run: {error}"
            )],
            history: None,
        })
    }

    fn reread(self, proceed: &mut impl FnMut() -> bool) -> Result<VerifyReport> {
        let (layout, projection) = match self.kind {
            TargetKind::Pruned { retained, run } => {
                return Ok(pruning::verify_pruned(
                    &self.directory,
                    &self.run_id,
                    &retained,
                    &run,
                ));
            }
            TargetKind::Stream { layout, projection } => (layout, projection),
        };
        let on_disk = layout.total_bytes;
        let proceed = &mut || {
            crate::faults::verify_frame();
            proceed()
        };
        let loaded = load_stream(&self.directory, &self.run_id, layout, &|_| Ok(()), proceed)?;
        let stream = loaded.stream;
        let mut problems = poison_details(stream.poisoned());
        // The re-read failed only in bytes the writer never wrote: what it
        // found there is not this writer's interrupted or damaged write.
        if let (Some(accepted), Some(on_disk)) = (self.accepted_bytes, on_disk)
            && on_disk > accepted
            && stream.is_poisoned()
            && stream.accepted_bytes() >= accepted
        {
            problems = vec![format!(
                "{} canonical bytes follow what this writer accepted; it never wrote or \
                 acknowledged them",
                on_disk - accepted
            )];
        }
        if let Some(read) = loaded.stopped {
            problems.push(format!(
                "fresh verification stopped at its time limit after re-reading {read} canonical \
                 bytes; the rest of this run was not checked"
            ));
        }
        if stream
            .run()
            .capture_history
            .as_ref()
            .is_some_and(|h| h.state == "pruning")
        {
            problems.push("capture deletion is incomplete; retry GC or restart the writer".into());
        }
        if !stream.is_poisoned() && loaded.stopped.is_none() {
            let published = projection.ok().and_then(|bytes| {
                let value: Value = serde_json::from_slice(&bytes).ok()?;
                validate_frozen("run", &value).ok()?;
                Some(value)
            });
            if published.is_none_or(|value| {
                serde_json::to_value(stream.run()).is_ok_and(|expected| expected != value)
            }) {
                problems.push("run projection does not match verified canonical records".into());
            }
            // A clean re-read must end exactly where the writer's acceptance
            // did; anything else on disk was never acknowledged by it.
            if self.poisoned.is_empty() && stream.run().chain != self.accepted {
                problems.push(
                    "canonical history on disk differs from what this writer accepted".into(),
                );
            }
        }
        problems.extend(self.poisoned);
        problems.sort();
        problems.dedup();
        Ok(VerifyReport {
            run_id: self.run_id,
            local_consistency: problems.is_empty(),
            child_protection: stream.run().child_protection.clone(),
            coverage: crate::reader::coverage_summary(&stream.run().coverage),
            events: loaded.events,
            problems,
            history: None,
        })
    }
}

/// Fresh verification of one run or one page: `plan` asks the writer, and
/// every re-read happens here. A GC may remove or rewrite what a report then
/// finds missing or changed, so when one ran meanwhile, each run with
/// problems is planned and re-read once more.
pub(crate) fn verify_page(
    plan: &mut impl FnMut(Option<&str>, Option<&str>, u32) -> Result<VerifyPlan>,
    gc_generation: &mut impl FnMut() -> Result<u64>,
    proceed: &mut impl FnMut() -> bool,
    run_id: Option<&str>,
    after: Option<&str>,
    limit: u32,
) -> Result<VerifyPage> {
    let page = plan(run_id, after, limit)?;
    let mut reports: Vec<_> = page
        .targets
        .into_iter()
        .map(|target| target.verify(proceed))
        .collect();
    if reports.iter().any(|report| !report.problems.is_empty())
        && gc_generation()? != page.gc_generation
    {
        for report in reports
            .iter_mut()
            .filter(|report| !report.problems.is_empty())
        {
            let again = plan(Some(&report.run_id), None, 1)?;
            let Some(target) = again.targets.into_iter().next() else {
                continue;
            };
            *report = target.verify(proceed);
            if !report.problems.is_empty() && gc_generation()? != again.gc_generation {
                report
                    .problems
                    .push("a GC ran while this run was verified; verify it again".into());
                report.local_consistency = false;
            }
        }
    }
    Ok(VerifyPage {
        reports,
        next_after: page.next_after,
        done: page.done,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::tests::{gc_fixture, gc_future, payload, peer};
    use super::*;
    use crate::manifest::{self, STREAM};

    #[test]
    fn bytes_after_a_live_streams_accepted_prefix_are_foreign_not_an_interrupted_write() {
        use std::io::Write as _;
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare("foreign", &payload(), &peer()).unwrap();
        let segment = store.run_dir(&run.run_id).join(STREAM);
        let mut foreign = 0;
        // An unterminated frame, then garbage completing it to a whole line.
        for tail in [&b"{\"foreign\":"[..], b"1}\n"] {
            fs::OpenOptions::new()
                .append(true)
                .open(&segment)
                .unwrap()
                .write_all(tail)
                .unwrap();
            foreign += tail.len();
            let report = store.verify(None).unwrap().remove(0);
            assert!(!report.local_consistency);
            assert_eq!(
                report.problems,
                [format!(
                    "{foreign} canonical bytes follow what this writer accepted; it never wrote \
                     or acknowledged them"
                )]
            );
            let page = store
                .read(&crate::protocol::ReadRequest {
                    run_id: run.run_id.clone(),
                    filter: crate::protocol::ReadFilter {
                        selector: crate::protocol::ReadSelector::All,
                        stage: None,
                        since: None,
                        until: None,
                    },
                    cursor: None,
                    limit: 10,
                })
                .unwrap();
            assert!(!page.local_consistency);
            assert_eq!(page.stream_status, "corrupt");
            assert_eq!(
                page.problems,
                [
                    "canonical bytes follow the accepted prefix; this writer never wrote or \
                  acknowledged them"
                ]
            );
        }
    }

    #[test]
    fn a_run_whose_re_read_fails_is_reported_and_the_rest_of_its_page_too() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let first = store.prepare("first", &payload(), &peer()).unwrap();
        let second = store.prepare("second", &payload(), &peer()).unwrap();
        // A capture GC authority the re-read cannot even read.
        fs::write(
            store.run_dir(&first.run_id).join("captures-gc.json"),
            b"not an authority",
        )
        .unwrap();
        let reports = store.verify(None).unwrap();
        assert_eq!(reports.len(), 2, "{reports:?}");
        for report in reports {
            if report.run_id == first.run_id {
                assert!(!report.local_consistency);
                assert_eq!(report.problems.len(), 1, "{report:?}");
                assert!(
                    report.problems[0]
                        .starts_with("fresh verification could not re-read this run: "),
                    "{report:?}"
                );
            } else {
                assert_eq!(report.run_id, second.run_id);
                assert!(report.local_consistency, "{report:?}");
            }
        }
    }

    fn planned(store: &Store, run_id: &str) -> Target {
        let mut plan = store.plan_verify(Some(run_id), None, 1).unwrap();
        assert_eq!(plan.targets.len(), 1);
        plan.targets.remove(0)
    }

    #[test]
    fn a_planned_run_is_re_read_as_planned_while_the_writer_appends() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare("planned", &payload(), &peer()).unwrap();
        store.hold(&run.run_id, "before-plan", &peer()).unwrap();
        let target = planned(&store, &run.run_id);
        // Appends after the plan grow the segment, run.json and the manifest.
        for n in 0..3 {
            store
                .hold(&run.run_id, &format!("after-plan-{n}"), &peer())
                .unwrap();
        }
        let report = target.verify(&mut || true);
        assert!(report.local_consistency, "{report:?}");
        assert_eq!(report.events, 2);
        assert!(store.verify(None).unwrap()[0].local_consistency);
        assert_eq!(store.verify(None).unwrap()[0].events, 5);
    }

    #[test]
    fn valid_history_this_writer_never_accepted_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let run = store.prepare("forged", &payload(), &peer()).unwrap();
        let directory = store.root().join(&run.run_id);
        let files = [STREAM, "run.json", manifest::NAME];
        let snapshot = || files.map(|name| fs::read(directory.join(name)).unwrap());
        let accepted = snapshot();
        store.hold(&run.run_id, "later", &peer()).unwrap();
        let extended = snapshot();
        drop(store);
        for (name, bytes) in files.iter().zip(&accepted) {
            fs::write(directory.join(name), bytes).unwrap();
        }
        let store = Store::open(&data).unwrap();
        assert!(store.verify(None).unwrap()[0].local_consistency);
        // A writer-shaped extension, with its projection and manifest, that
        // this writer never acknowledged.
        for (name, bytes) in files.iter().zip(&extended) {
            fs::write(directory.join(name), bytes).unwrap();
        }
        let report = planned(&store, &run.run_id).verify(&mut || true);
        assert!(!report.local_consistency, "{report:?}");
        assert_eq!(
            report.problems,
            ["canonical history on disk differs from what this writer accepted"]
        );
    }

    #[test]
    fn a_stopped_re_read_says_what_it_did_not_check() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare("stopped", &payload(), &peer()).unwrap();
        store.hold(&run.run_id, "second", &peer()).unwrap();
        let mut frames = 0;
        let report = planned(&store, &run.run_id).verify(&mut || {
            frames += 1;
            frames <= 1
        });
        assert!(!report.local_consistency, "{report:?}");
        assert_eq!(report.events, 1);
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.contains("stopped at its time limit")),
            "{report:?}"
        );
    }

    #[test]
    fn a_gc_between_plan_and_re_read_is_planned_again_not_reported_as_damage() {
        let (_temp, store, run) = gc_fixture();
        let store = std::cell::RefCell::new(store);
        let mut collect = true;
        let page = verify_page(
            &mut |run_id, after, limit| {
                let plan = store.borrow().plan_verify(run_id, after, limit);
                // The planned segments are removed before they are re-read.
                if std::mem::take(&mut collect) {
                    let result = store
                        .borrow_mut()
                        .gc_at(1, None, 100, &peer(), gc_future())
                        .unwrap();
                    assert_eq!(result.pruned.len(), 1, "{:?}", result.failed);
                }
                plan
            },
            &mut || Ok(store.borrow().gc_generation()),
            &mut || true,
            Some(&run.run_id),
            None,
            1,
        )
        .unwrap();
        let report = &page.reports[0];
        assert!(report.local_consistency, "{report:?}");
        assert_eq!(report.history.as_ref().unwrap().state, "pruned");
    }
}
