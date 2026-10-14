//! The walk: `gc` over `<data>/attempts` (and nothing else) under one entry
//! bound per invocation (S7). Each attempt root is identified without
//! following a link out of it, the lease of a claimed root is taken, jail
//! state and the last receipt are read, [`super::decide`] says what may be
//! done, the [`Host`] does it, jail state records it (S6), the temporary
//! files a crash left are removed when the owner is dead, and the J3
//! resumption of the proxy directory and vendor state runs within what is
//! left of the bound.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::SystemTime;

use super::decide::{CgroupStep, Decision, Facts, Next, OwnerVerdict, ScratchStep, decide};
use super::host::{Host, LeafRecord, NativeHost};
use super::view::{leaf_entry, parse_receipt, parse_state};
use super::{Budget, Entry, Options, RECORD_MAX, Report, SEAM_MAX_ENTRIES, seam_max_entries};
use crate::cleanup;
use crate::cli::GcArgs;
use crate::records::{ErrorCode, ErrorStage, JailError, Remediation, rfc3339_utc};
use crate::state::{self, AttemptDir, AttemptId, anchored};
use crate::supervisor::Context;

/// The per-invocation entry bound (S7).
struct Meter {
    max: usize,
    charged: usize,
}

impl Meter {
    fn remaining(&self) -> usize {
        self.max - self.charged
    }

    fn charge(&mut self, entries: usize) {
        self.charged = self.charged.saturating_add(entries).min(self.max);
    }

    /// Charges a removal that was given `given` entries: what it visited
    /// (J4 wave 2: `Removal::visited`), and all it was given when it
    /// stopped.
    fn charge_removal(&mut self, removal: &cleanup::Removal, given: usize) {
        self.charge(if removal.complete {
            removal.visited.min(given)
        } else {
            given
        });
    }
}

/// What `gc` did with one attempt, rendered as the entry's `action`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    Skipped,
    Retained,
    Pending,
    TerminatedOrphan,
    RemovedCgroup,
    RemovedScratch,
    RemovedVendorState,
    CompletedCleanup,
    WouldTerminateOrphan,
    WouldRemoveCgroup,
    WouldRemoveScratch,
    WouldRemoveVendorState,
    WouldCompleteCleanup,
}

impl Action {
    /// The report's spelling.
    fn as_str(self) -> &'static str {
        match self {
            Action::Skipped => "skipped",
            Action::Retained => "retained",
            Action::Pending => "pending",
            Action::TerminatedOrphan => "terminated_orphan",
            Action::RemovedCgroup => "removed_cgroup",
            Action::RemovedScratch => "removed_scratch",
            Action::RemovedVendorState => "removed_vendor_state",
            Action::CompletedCleanup => "completed_cleanup",
            Action::WouldTerminateOrphan => "would_terminate_orphan",
            Action::WouldRemoveCgroup => "would_remove_cgroup",
            Action::WouldRemoveScratch => "would_remove_scratch",
            Action::WouldRemoveVendorState => "would_remove_vendor_state",
            Action::WouldCompleteCleanup => "would_complete_cleanup",
        }
    }
}

/// What one invocation works with: where it looks, whom it asks, and what
/// it may do.
struct Pass<'a> {
    data_dir: &'a Path,
    attempts: &'a Path,
    host: &'a dyn Host,
    options: Options,
    dry_run: bool,
}

fn state_access(path: &Path, detail: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Reconciling,
        Remediation::InspectState,
        format!("{}: {detail}", path.display()),
    )
}

/// `gc` on this host: the native host, [`Options::DEFAULT`] and the S9 seam.
/// Every `OURO_JAIL_TEST_*` variable in force is recorded in the report
/// (S9), its own and the persistence seam's included.
///
/// # Errors
/// As [`gc_with`].
pub fn gc(ctx: &Context, args: &GcArgs) -> Result<Report, JailError> {
    let mut options = Options::DEFAULT;
    if let Some(value) = std::env::var_os(SEAM_MAX_ENTRIES) {
        options.max_entries = seam_max_entries(&value.to_string_lossy(), options.max_entries);
    }
    let mut report = gc_with(ctx, args, &NativeHost::new(ctx), options)?;
    report.test_seams = state::test_seams()
        .and_then(|seams| seams.as_object().cloned())
        .into_iter()
        .flatten()
        .map(|(name, value)| (name, value.as_str().unwrap_or_default().to_owned()))
        .collect();
    Ok(report)
}

/// Enumerates the registered state root and reconciles what it may (§14.2).
///
/// # Errors
/// [`ErrorCode::UnsafeStatePath`] when the state root or `attempts/` fails
/// its checks (a symlinked `attempts/` included), and
/// [`ErrorCode::StateWriteFailed`] when `attempts/` cannot be read.
pub fn gc_with(
    ctx: &Context,
    args: &GcArgs,
    host: &dyn Host,
    options: Options,
) -> Result<Report, JailError> {
    let mut report = Report {
        entries: Vec::new(),
        dry_run: args.dry_run,
        incomplete: Vec::new(),
        budget: Budget {
            max_entries: options.max_entries,
            charged: 0,
            exhausted: false,
            listing_complete: true,
        },
        test_seams: BTreeMap::new(),
    };
    let data_dir = state::data_dir(&ctx.env_settings, ctx.home.as_deref())?;
    // §14.2 enumerates "the registered state root". A root that fails the
    // §6.2 checks is not this operator's registered state, so `gc` says so
    // instead of printing a clean scan of a directory anyone can write.
    match std::fs::symlink_metadata(&data_dir) {
        Ok(_) => state::check_state_dir(&data_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => {
            return Err(JailError::new(
                ErrorCode::UnsafeStatePath,
                ErrorStage::Resolving,
                Remediation::InspectState,
                format!("{}: {error}", data_dir.display()),
            ));
        }
    }
    let attempts = data_dir.join("attempts");
    // The same check one level down: a symlinked or foreign `attempts/` is
    // not the registered state root's, and is never followed.
    match std::fs::symlink_metadata(&attempts) {
        Ok(_) => state::check_state_dir(&attempts)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(state_access(&attempts, error)),
    }
    let listing = std::fs::read_dir(&attempts).map_err(|error| state_access(&attempts, error))?;
    let mut meter = Meter {
        max: options.max_entries,
        charged: 0,
    };
    // S7: the listing counts against the bound, and stops at it.
    let mut names: Vec<OsString> = Vec::new();
    for entry in listing {
        if meter.remaining() == 0 {
            report.budget.listing_complete = false;
            break;
        }
        meter.charge(1);
        match entry {
            Ok(entry) => names.push(entry.file_name()),
            Err(error) => report.incomplete.push(format!("attempts/ (read: {error})")),
        }
    }
    names.sort();
    let pass = Pass {
        data_dir: &data_dir,
        attempts: &attempts,
        host,
        options,
        dry_run: args.dry_run,
    };
    for name in names {
        let entry = visit(&pass, &name, &mut meter, &mut report.incomplete);
        report.entries.push(entry);
    }
    if !report.budget.listing_complete {
        report.incomplete.push(format!(
            "attempts/ (the per-invocation bound of {} entries ended the listing; run gc again)",
            options.max_entries
        ));
    }
    report.incomplete.sort();
    report.budget.charged = meter.charged;
    report.budget.exhausted = meter.remaining() == 0;
    Ok(report)
}

/// One name read from `attempts/`.
fn visit(
    pass: &Pass<'_>,
    name: &std::ffi::OsStr,
    meter: &mut Meter,
    incomplete: &mut Vec<String>,
) -> Entry {
    let dry_run = pass.dry_run;
    let display = name.to_string_lossy().into_owned();
    let mut entry = Entry {
        attempt_id: display.clone(),
        ..Entry::default()
    };
    let mut finish = |action: Action, reason: String| {
        entry.action = action.as_str().to_owned();
        entry.reason = reason;
    };
    let Some(id) = name.to_str().and_then(|text| AttemptId::parse(text).ok()) else {
        finish(
            Action::Skipped,
            "the directory name is not an attempt id".to_owned(),
        );
        return entry;
    };
    // Never follow a link out of the state root: the entry itself must be a
    // private directory this operator owns.
    let path = pass.attempts.join(name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            finish(
                Action::Skipped,
                format!("the entry cannot be inspected: {error}"),
            );
            return entry;
        }
    };
    if metadata.file_type().is_symlink() {
        finish(
            Action::Skipped,
            "a symlink, which gc never follows out of the state root".to_owned(),
        );
        return entry;
    }
    if !metadata.is_dir() {
        finish(Action::Skipped, "not a directory".to_owned());
        return entry;
    }
    {
        use std::os::unix::fs::MetadataExt as _;
        if let Err(error) = state::check_ownership(
            &path,
            metadata.uid(),
            metadata.mode() & 0o7777,
            state::DIRECTORY_MODE,
        ) {
            finish(
                Action::Retained,
                format!("not a private attempt root: {}", error.message),
            );
            return entry;
        }
    }
    let dir = AttemptDir::new(pass.data_dir, &id);
    // J4-G: the claim race (§7). The supervisor creates `jail.lock`, locks
    // it, and only then claims `jail-state.json`. A root without the claim is
    // never locked here: between the supervisor's create and its lock, a
    // lock taken by gc would make it refuse `attempt_exists`. A claimed root
    // was locked before it was claimed, so its lease is held by a live
    // supervisor or by nobody.
    match std::fs::symlink_metadata(dir.state_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (action, reason) = unclaimed(&dir);
            finish(action, reason);
            return entry;
        }
        _ => {}
    }
    // J4-D3: probe the lease without creating `jail.lock`.
    let lease = match state::Lease::probe_existing(&dir.lock_path()) {
        Ok(state::LeaseProbe::Acquired(lease)) => lease,
        Ok(state::LeaseProbe::Absent) => {
            let reason = match state::check_fresh_attempt(&dir) {
                Ok(()) => "no jail.lock: no lease protects this attempt".to_owned(),
                Err(error) => error.message,
            };
            finish(
                Action::Retained,
                format!(
                    "no jail.lock, so no lease protects this attempt and gc leaves it untouched: \
                     {reason}"
                ),
            );
            return entry;
        }
        Ok(state::LeaseProbe::Held) => {
            finish(
                Action::Retained,
                "a live supervisor holds the lease".to_owned(),
            );
            return entry;
        }
        Err(error) => {
            finish(Action::Skipped, error.message);
            return entry;
        }
    };

    let state = read_view(&dir.state_path(), state::STATE_FILE_MAX, |bytes| {
        parse_state(bytes, &display)
    })
    .and_then(|state| state.ok_or_else(|| "the file vanished".to_owned()));
    // J4 wave 3 (G4): an attempt an earlier pass left with nothing to do
    // costs this pass its name and one read: its root is not listed again,
    // nothing is probed and nothing is written.
    if let Ok(view) = &state
        && let Some(at) = &view.gc_finished
    {
        entry.action = Action::Retained.as_str().to_owned();
        entry.reason = format!(
            "{FINISHED}: gc found nothing left to do at {at}; receipts, policy and trace are \
             retained, and the attempt root is not listed again"
        );
        drop(lease);
        return entry;
    }
    let facts = Facts {
        host: pass.host.identity(),
        state,
        receipt: read_view(&dir.receipt_path(), RECORD_MAX, |bytes| {
            parse_receipt(bytes, &display)
        }),
        owner: None,
        leaf: None,
    };
    let decision = settle(facts, pass.host);
    entry.owner = decision.owner.as_ref().map(OwnerVerdict::describe);
    if let Some(retention) = &decision.retain {
        if retention.failed_access {
            incomplete.push(format!("{display} (corrupt_state)"));
        }
        entry.action = Action::Retained.as_str().to_owned();
        entry.reason.clone_from(&retention.reason);
        drop(lease);
        return entry;
    }

    let done = reconcile(pass, &dir, &decision, meter, &mut entry);
    if let Some(failure) = &done.failure {
        incomplete.push(format!("{display} ({failure})"));
    }
    // J4 W2-S: what crashed durable replacements left, removed only because
    // the owner is dead and this pass holds the lease.
    let leftover = leftovers(&dir, decision.owner_dead(), dry_run, meter, &mut entry);
    entry.temp_files = leftover.outcome.as_ref().map(TempFiles::describe);
    if let Some(failure) = &leftover.failure {
        incomplete.push(format!("{display} ({failure})"));
    }
    // J4 W2-S: gc's own verification of the registered leaf (this pass's or
    // an earlier one's) proves the tree dead for the vendor-state cleanup;
    // so does a tree that never existed (audit 2026-09-25-2, S4): no leaf
    // means no cgroup was ever created, so nothing was ever charged to a
    // tree and nothing outside the state dir can be using the vendor state,
    // which unblocks the cleanup a supervisor SIGKILL between staging and
    // preparation would otherwise retain forever.
    let gc_verified = match done.action {
        Some(Action::WouldTerminateOrphan | Action::WouldRemoveCgroup) if dry_run => true,
        _ => verified_by_gc(&dir) || decision.tree_never_existed,
    };
    // J3: the dead supervisor's proxy directory, then vendor state.
    let (action, reason, visited, resumed_settled) = proxy_then_resume(
        &dir,
        &display,
        dry_run,
        incomplete,
        &mut entry,
        Resumption {
            limits: cleanup::Limits {
                max_entries: meter.remaining(),
                max_depth: pass.options.max_depth,
            },
            gc_verified,
        },
    );
    // S7: what the resumption visited is charged to this invocation.
    meter.charge(visited);
    let (action, reason) = combine(action, reason, &done);
    entry.action = action.as_str().to_owned();
    entry.reason = reason;
    // What is left after the resumption, which may remove managed scratch
    // too. Scratch whose kind cannot be read may be managed scratch nothing
    // removes: never finished, and reported as §6.4's failed state access.
    let scratch = done.scratch.recheck(&dir);
    if let cleanup::Scratch::Unknown(why) = &scratch {
        entry.scratch = Some(format!("unknown: {why}"));
        incomplete.push(format!("{display} (scratch: {why})"));
    }
    // J4 wave 3 (G4): nothing is left for any later pass: the owner is
    // dead, the cgroup settled, no scratch, temporary file, proxy directory
    // or vendor state remains, and nothing failed. Recorded last, so a crash
    // before it only costs the next pass this one's (idempotent) work.
    let finished = !dry_run
        && decision.owner_dead()
        && done.failure.is_none()
        && done.cgroup_final
        && leftover.failure.is_none()
        && matches!(leftover.outcome, None | Some(TempFiles::Removed(_)))
        && resumed_settled
        && scratch.is_gone();
    if finished {
        match record(&dir, act("gc_finished"), &mut entry.recorded) {
            Ok(()) => {}
            Err(failure) => incomplete.push(format!("{display} ({failure})")),
        }
    }
    drop(lease);
    entry
}

/// The first word of the reason of an attempt an earlier pass finished.
pub const FINISHED: &str = "finished";

/// Asks [`decide`] until it decides, answering its probes from the host.
fn settle(mut facts: Facts, host: &dyn Host) -> Decision {
    loop {
        match decide(&facts) {
            Next::ProbeOwner(owner) => facts.owner = Some(host.owner(&owner)),
            Next::ProbeLeaf(leaf) => facts.leaf = Some(host.probe_leaf(&leaf)),
            // J4 W2-S: N7
            Next::ProbeNamedLeaf(path) => facts.leaf = Some(host.probe_named_leaf(&path)),
            Next::Decided(decision) => return decision,
        }
    }
}

/// Reads a bounded record and parses it; `Ok(None)` when it does not exist.
fn read_view<T>(
    path: &Path,
    cap: u64,
    parse: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<Option<T>, String> {
    match state::read_capped(path, cap) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => parse(&bytes).map(Some),
        Err(error) => Err(error.to_string()),
    }
}

/// The report for a root nobody has claimed (§7, §14.2; N5).
fn unclaimed(dir: &AttemptDir) -> (Action, String) {
    match std::fs::symlink_metadata(dir.lock_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            Action::Retained,
            match state::check_fresh_attempt(dir) {
                Ok(()) => "no jail.lock and no jail-owned artifact: an unclaimed attempt root, \
                           which gc leaves untouched and claimable"
                    .to_owned(),
                Err(error) => format!(
                    "no jail.lock, so no lease protects this attempt and gc leaves it untouched: {}",
                    error.message
                ),
            },
        ),
        _ => (
            Action::Retained,
            "jail.lock but no jail-state.json: an unclaimed root, which a live supervisor may \
             be claiming now or whose supervisor died before claiming it; gc takes no lease on \
             an unclaimed root and leaves it untouched"
                .to_owned(),
        ),
    }
}

/// What [`reconcile`] did, for the entry's summary.
struct Done {
    /// The most significant step: a terminated orphan, a removed cgroup or
    /// removed scratch, or what a dry run would do.
    action: Option<Action>,
    /// What failed, when something did: the cleanup is incomplete (§6.4).
    failure: Option<String>,
    /// J4 wave 3 (G4): nothing is left for gc to do with the cgroup.
    cgroup_final: bool,
    /// The attempt's scratch as this pass left it.
    scratch: cleanup::Scratch,
}

/// Performs the cgroup and scratch steps of a decision and records them.
fn reconcile(
    pass: &Pass<'_>,
    dir: &AttemptDir,
    decision: &Decision,
    meter: &mut Meter,
    entry: &mut Entry,
) -> Done {
    let (host, dry_run) = (pass.host, pass.dry_run);
    let mut done = Done {
        action: None,
        failure: None,
        cgroup_final: false,
        scratch: cleanup::managed_scratch(dir),
    };
    // How the tree's end was verified by this pass, when it was.
    let mut verified: Option<&'static str> = None;
    match &decision.cgroup {
        CgroupStep::Nothing => done.cgroup_final = true,
        CgroupStep::Report(text) => entry.cgroup = Some(text.clone()),
        CgroupStep::Settled(text) => {
            entry.cgroup = Some(text.clone());
            done.cgroup_final = true;
        }
        CgroupStep::Terminate(_) if dry_run => {
            entry.cgroup = Some("would_terminate_orphan".to_owned());
            done.action = Some(Action::WouldTerminateOrphan);
        }
        CgroupStep::Remove(_) | CgroupStep::RemoveNamed(_) if dry_run => {
            entry.cgroup = Some("would_remove".to_owned());
            done.action = Some(Action::WouldRemoveCgroup);
        }
        CgroupStep::Terminate(leaf) => {
            match terminate(pass, dir, leaf, meter, &mut entry.recorded) {
                Ok(()) => {
                    entry.cgroup = Some("terminated_orphan_and_removed".to_owned());
                    done.action = Some(Action::TerminatedOrphan);
                    done.cgroup_final = true;
                    verified = Some("gc ended the orphan and verified its leaf empty");
                }
                Err(failure) => {
                    entry.cgroup = Some(format!("failed: {failure}"));
                    done.failure = Some(format!("cgroup: {failure}"));
                }
            }
        }
        CgroupStep::Remove(leaf) => match remove(dir, leaf, host, meter, &mut entry.recorded) {
            Ok(()) => {
                entry.cgroup = Some("removed".to_owned());
                done.action = Some(Action::RemovedCgroup);
                done.cgroup_final = true;
                verified = Some("gc verified the leaf empty and removed it");
            }
            Err(failure) => {
                entry.cgroup = Some(format!("failed: {failure}"));
                done.failure = Some(format!("cgroup: {failure}"));
            }
        },
        // J4 W2-S: N7
        CgroupStep::RemoveNamed(path) => {
            match remove_named(dir, path, host, meter, &mut entry.recorded) {
                Ok(()) => {
                    entry.cgroup = Some("removed".to_owned());
                    done.action = Some(Action::RemovedCgroup);
                    done.cgroup_final = true;
                    verified = Some(
                        "gc removed the empty leaf registered by name only; this attempt \
                         places nothing in a leaf before its identity is recorded",
                    );
                }
                Err(failure) => {
                    entry.cgroup = Some(format!("failed: {failure}"));
                    done.failure = Some(format!("cgroup: {failure}"));
                }
            }
        }
    }
    let basis: Option<String> = match &decision.scratch {
        ScratchStep::NotApplicable => None,
        ScratchStep::Keep(reason) => {
            if !present(&done.scratch).is_empty() {
                entry.scratch = Some(format!("retained: {reason}"));
            }
            None
        }
        ScratchStep::Now(basis) => Some(basis.clone()),
        ScratchStep::AfterCgroup => {
            if dry_run && done.action.is_some() {
                Some("the cgroup step would verify the tree's end".to_owned())
            } else if let Some(basis) = verified {
                Some(basis.to_owned())
            } else {
                if !present(&done.scratch).is_empty() {
                    entry.scratch = Some("retained: the tree's end was not verified".to_owned());
                }
                None
            }
        }
    };
    if let Some(basis) = basis {
        remove_scratch(pass, dir, &basis, meter, entry, &mut done);
    }
    done
}

/// A gc record of `action`, made now.
fn act(action: &str) -> state::GcAction {
    state::GcAction {
        action: action.to_owned(),
        at: state::Field::Set(rfc3339_utc(SystemTime::now())),
        ..state::GcAction::default()
    }
}

fn record(
    dir: &AttemptDir,
    item: state::GcAction,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    let action = item.action.clone();
    // J4 W2-S: P14, gc's reconciliation records' own persistence site.
    state::update_attempt_state(state::Site::GcRecord, dir, |state| {
        coalesce(state.gc_actions.get_or_insert_default(), item);
    })
    .map_err(|error| format!("jail state could not record {action}: {}", error.message))?;
    recorded.push(action);
    Ok(())
}

/// J4 wave 3 (G5): appends `item`, unless a record saying the same thing is
/// already there; that one then keeps its first time (`at`) and gains a
/// `count` and the `last_at` time. A pass that repeats what an earlier one
/// did (a kill that cannot be verified, an intent whose removal fails) adds
/// no record, so jail state stays far below its read cap however many
/// passes run.
fn coalesce(actions: &mut Vec<state::GcAction>, item: state::GcAction) {
    match actions.iter_mut().find(|existing| existing.same_act(&item)) {
        Some(existing) => {
            let count = existing.count.get().copied().unwrap_or(1).saturating_add(1);
            existing.count = state::Field::Set(count);
            existing.last_at = state::Field::or_null(item.at.get().cloned());
        }
        None => actions.push(item),
    }
}

/// §14.2: "Record `gc_terminated_orphan` and verify emptiness before deleting
/// state." The intent is durable before the kill, so a crash after the kill
/// never loses the fact that gc killed; the result is recorded after the leaf
/// was seen empty, and only then is the leaf removed.
fn terminate(
    pass: &Pass<'_>,
    dir: &AttemptDir,
    leaf: &LeafRecord,
    meter: &mut Meter,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    let host = pass.host;
    let killing = state::GcAction {
        execution_cgroup: state::Field::Set(leaf_entry(leaf)),
        ..act("gc_terminating_orphan")
    };
    record(dir, killing, recorded).map_err(|error| format!("{error}; nothing was killed"))?;
    host.terminate_leaf(leaf, pass.options.kill_budget)
        .map_err(|failure| failure.to_string())?;
    let killed = state::GcAction {
        execution_cgroup: state::Field::Set(leaf_entry(leaf)),
        verified_empty: state::Field::Set(true),
        ..act("gc_terminated_orphan")
    };
    record(dir, killed, recorded)?;
    remove(dir, leaf, host, meter, recorded)
}

/// Removes a leaf gc saw empty. J4 wave 3 (G3): the intent
/// (`gc_removing_cgroup`) is durable before the `rmdir`, so a crash or a
/// failed record after it leaves jail state saying gc verified the leaf
/// empty, and the next pass finishes from that.
fn remove(
    dir: &AttemptDir,
    leaf: &LeafRecord,
    host: &dyn Host,
    meter: &mut Meter,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    let removing = state::GcAction {
        execution_cgroup: state::Field::Set(leaf_entry(leaf)),
        verified_empty: state::Field::Set(true),
        ..act("gc_removing_cgroup")
    };
    record(dir, removing, recorded).map_err(|error| format!("{error}; nothing was removed"))?;
    let mut left = meter.remaining();
    let given = left;
    let removed = host.remove_leaf(leaf, &mut left);
    meter.charge(given - left.min(given));
    removed.map_err(|failure| failure.to_string())?;
    let gone = state::GcAction {
        execution_cgroup: state::Field::Set(leaf_entry(leaf)),
        ..act("gc_removed_cgroup")
    };
    record(dir, gone, recorded)
}

// N7
fn remove_named(
    dir: &AttemptDir,
    path: &Path,
    host: &dyn Host,
    meter: &mut Meter,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    // J4 wave 3 (G3): the intent first, by name (no identity is recorded).
    let removing = state::GcAction {
        execution_cgroup: state::Field::Set(state::LeafEntry::new(path.to_path_buf(), None)),
        registered: state::Field::Set(NAME_ONLY.to_owned()),
        verified_empty: state::Field::Set(true),
        ..act("gc_removing_cgroup")
    };
    record(dir, removing, recorded).map_err(|error| format!("{error}; nothing was removed"))?;
    let mut left = meter.remaining();
    let given = left;
    let removed = host.remove_named_leaf(path, &mut left);
    meter.charge(given - left.min(given));
    let identity = removed.map_err(|failure| failure.to_string())?;
    let gone = state::GcAction {
        execution_cgroup: state::Field::Set(state::LeafEntry::new(
            path.to_path_buf(),
            Some(identity),
        )),
        registered: state::Field::Set(NAME_ONLY.to_owned()),
        ..act("gc_removed_cgroup")
    };
    record(dir, gone, recorded)
}

/// How a gc record marks a leaf jail state registered by name only.
const NAME_ONLY: &str = "name_only";

/// The managed directories present, or none when scratch is not managed (an
/// operator `--scratch` is never deleted) or cannot be read ([`visit`]
/// reports that).
fn present(scratch: &cleanup::Scratch) -> &[&'static str] {
    match scratch {
        cleanup::Scratch::Managed(present) => present,
        cleanup::Scratch::NotManaged | cleanup::Scratch::Unknown(_) => &[],
    }
}

/// §14.2: "when tree death is unverified the scratch is retained and GC may
/// remove it later." Only managed scratch and placeholders, through the
/// anchored traversal, within what is left of the entry bound.
fn remove_scratch(
    pass: &Pass<'_>,
    dir: &AttemptDir,
    basis: &str,
    meter: &mut Meter,
    entry: &mut Entry,
    done: &mut Done,
) {
    let present = present(&done.scratch).to_vec();
    if present.is_empty() {
        return;
    }
    if pass.dry_run {
        entry.scratch = Some("would_remove".to_owned());
        done.action.get_or_insert(Action::WouldRemoveScratch);
        return;
    }
    for name in present {
        let given = meter.remaining();
        if given == 0 {
            let reason = "pending: the per-invocation entry bound is reached".to_owned();
            done.failure
                .get_or_insert_with(|| format!("scratch: {reason}"));
            entry.scratch = Some(reason);
            done.scratch = done.scratch.recheck(dir);
            return;
        }
        let removal = cleanup::remove_managed_dir(
            dir,
            name,
            cleanup::Limits {
                max_entries: given,
                max_depth: pass.options.max_depth,
            },
        );
        meter.charge_removal(&removal, given);
        if !removal.complete {
            let reason = format!(
                "pending: {}",
                removal.reason.as_deref().unwrap_or("the removal stopped")
            );
            done.failure
                .get_or_insert_with(|| format!("scratch: {reason}"));
            entry.scratch = Some(reason);
            done.scratch = done.scratch.recheck(dir);
            return;
        }
    }
    done.scratch = done.scratch.recheck(dir);
    let removed = state::GcAction {
        basis: state::Field::Set(basis.to_owned()),
        ..act("gc_removed_scratch")
    };
    match record(dir, removed, &mut entry.recorded) {
        Ok(()) => {
            entry.scratch = Some("removed".to_owned());
            done.action.get_or_insert(Action::RemovedScratch);
        }
        Err(failure) => {
            entry.scratch = Some(format!("removed; {failure}"));
            done.failure.get_or_insert(failure);
        }
    }
}

// `gc` of a dead supervisor's proxy directory (§14.2), moved
// here from `supervisor.rs` with the rest of gc (J4 exception G1)
/// Runs [`state::gc_proxy_dir`], says in `proxy_dir` what became of the
/// directory (one whose read or removal failed is a cleanup that did not
/// complete, §6.4: `gc` exits 1; one whose identity cannot be proven is
/// retained and said so, §14.2), then resumes the vendor-state cleanup
/// exactly as before, and maps its result to the entry's action. The last
/// value says whether neither left anything for a later pass (J4 wave 3,
/// G4).
fn proxy_then_resume(
    dir: &AttemptDir,
    name: &str,
    dry_run: bool,
    incomplete: &mut Vec<String>,
    entry: &mut Entry,
    resumption: Resumption,
) -> (Action, String, usize, bool) {
    let mut settled = true;
    entry.proxy_dir = match state::gc_proxy_dir(dir, dry_run) {
        Ok(outcome) => {
            if let state::ProxyDirRemoval::Failed(reason) = &outcome {
                incomplete.push(format!("{name} (proxy directory: {reason})"));
            }
            settled &= matches!(
                outcome,
                state::ProxyDirRemoval::Nothing | state::ProxyDirRemoval::Removed
            );
            outcome.describe()
        }
        Err(error) => {
            incomplete.push(format!("{name} ({})", error.code.as_str()));
            settled = false;
            Some(format!("failed: {}", error.code.as_str()))
        }
    };
    // §12, §14.2 — resume a pending vendor-state cleanup the
    // terminal receipt permits.
    // J4 W2-S: or gc's own verification of the registered leaf permits (see
    // `cleanup::permitted`); within what is left of this invocation's bound
    // (S7), which the caller charges with what it visited.
    let (outcome, visited) =
        match cleanup::resume_with(dir, dry_run, resumption.limits, resumption.gc_verified) {
            Ok(resumed) => (Ok(resumed.outcome), resumed.visited),
            Err(error) => (Err(error), 0),
        };
    settled &= matches!(
        outcome,
        Ok(cleanup::Resume::NothingPending
            | cleanup::Resume::Completed { .. }
            | cleanup::Resume::ReceiptCompleted)
    );
    let (action, reason) = match outcome {
        Ok(cleanup::Resume::NothingPending) => (
            Action::Retained,
            "no vendor-state cleanup is pending; receipts, policy and trace are retained"
                .to_owned(),
        ),
        Ok(cleanup::Resume::Completed {
            receipt_updated: true,
        }) => (
            Action::RemovedVendorState,
            "the pending vendor-state cleanup completed and the receipt records it".to_owned(),
        ),
        // J4 wave 3 (G1, S6): permitted by gc's own verification of the
        // leaf; the dead supervisor's last receipt is not refused or settled
        // and is never rewritten.
        Ok(cleanup::Resume::Completed {
            receipt_updated: false,
        }) => (
            Action::RemovedVendorState,
            "the pending vendor-state cleanup completed; jail state and this report record it \
             (gc's own verification of the leaf permitted it, and gc never rewrites a receipt \
             that is not refused or settled)"
                .to_owned(),
        ),
        Ok(cleanup::Resume::WouldRemove) => (
            Action::WouldRemoveVendorState,
            "the records permit the pending vendor-state cleanup".to_owned(),
        ),
        Ok(cleanup::Resume::ReceiptCompleted) => (
            Action::CompletedCleanup,
            "no vendor state was registered and no managed scratch is left, so the receipt's \
             pending cleanup is complete and the receipt records it"
                .to_owned(),
        ),
        Ok(cleanup::Resume::WouldCompleteReceipt) => (
            Action::WouldCompleteCleanup,
            "no vendor state was registered and no managed scratch is left, so the receipt's \
             pending cleanup would be recorded complete"
                .to_owned(),
        ),
        Ok(cleanup::Resume::Retained(reason)) => (
            Action::Retained,
            format!("vendor-state cleanup is not permitted: {reason}"),
        ),
        Ok(cleanup::Resume::StillPending(reason)) => {
            incomplete.push(format!("{name} ({reason})"));
            (
                Action::Pending,
                format!("vendor-state cleanup stopped again: {reason}"),
            )
        }
        Err(error) => {
            incomplete.push(format!("{name} ({})", error.code.as_str()));
            (Action::Skipped, error.message)
        }
    };
    (action, reason, visited, settled)
}

/// What [`proxy_then_resume`] may spend, and what permits the resumption.
struct Resumption {
    /// What is left of this invocation's bound (S7).
    limits: cleanup::Limits,
    /// gc verified the registered leaf empty ([`verified_by_gc`]).
    gc_verified: bool,
}

/// Whether jail state records that gc verified the registered execution
/// leaf empty (`gc_terminated_orphan` or `gc_removed_cgroup` of that leaf).
fn verified_by_gc(dir: &AttemptDir) -> bool {
    let name = dir
        .root()
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Ok(Some(state)) = read_view(&dir.state_path(), state::STATE_FILE_MAX, |bytes| {
        parse_state(bytes, &name)
    }) else {
        return false;
    };
    state.leaf.as_ref().is_some_and(|registered| {
        state
            .gc_verified
            .iter()
            .any(|verified| registered.verified_by(verified))
    })
}

/// What became of the temporary files a crash left in an attempt root,
/// rendered as the entry's `temp_files`.
#[derive(Clone, PartialEq, Eq, Debug)]
enum TempFiles {
    /// Removed and recorded: `removed <count>`.
    Removed(usize),
    /// Removed, but the record failed: `removed; <failure>`.
    RemovedUnrecorded(String),
    /// A dry run: `would_remove`.
    WouldRemove,
    /// Kept: `retained: <why>`.
    Retained(&'static str),
    /// Not all of them listed: `pending: <why>`.
    Pending(&'static str),
    /// The listing or a removal failed: `failed: <why>`.
    Failed(String),
}

impl TempFiles {
    fn describe(&self) -> String {
        match self {
            TempFiles::Removed(count) => format!("removed {count}"),
            TempFiles::RemovedUnrecorded(failure) => format!("removed; {failure}"),
            TempFiles::WouldRemove => "would_remove".to_owned(),
            TempFiles::Retained(why) => format!("retained: {why}"),
            TempFiles::Pending(why) => format!("pending: {why}"),
            TempFiles::Failed(why) => format!("failed: {why}"),
        }
    }
}

/// What [`leftovers`] found and did.
struct Leftovers {
    /// `None` when there were no temporary files.
    outcome: Option<TempFiles>,
    /// A failure that leaves the cleanup incomplete.
    failure: Option<String>,
}

/// Lists the temporary files crashed durable replacements left in the
/// attempt root (charged to the bound, S7), and removes those of this
/// tool's records when the owner is dead: the caller holds the lease, so no
/// supervisor can be writing one. Records what it removed (S6, P14).
fn leftovers(
    dir: &AttemptDir,
    owner_dead: bool,
    dry_run: bool,
    meter: &mut Meter,
    entry: &mut Entry,
) -> Leftovers {
    let settled = |outcome| Leftovers {
        outcome: Some(outcome),
        failure: None,
    };
    let listing = match state::leftover_temp_files_within(dir, meter.remaining()) {
        Ok(listing) => listing,
        Err(error) => {
            return Leftovers {
                outcome: Some(TempFiles::Failed(error.to_string())),
                failure: Some(format!(
                    "temporary files: the attempt root cannot be listed: {error}"
                )),
            };
        }
    };
    meter.charge(listing.read);
    entry.leftover_temp_files.clone_from(&listing.names);
    if !listing.complete {
        return Leftovers {
            outcome: Some(TempFiles::Pending(
                "the per-invocation entry bound ended the listing",
            )),
            failure: Some("temporary files: the listing is incomplete".to_owned()),
        };
    }
    if listing.names.is_empty() {
        return Leftovers {
            outcome: None,
            failure: None,
        };
    }
    let ours: Vec<&String> = listing
        .names
        .iter()
        .filter(|name| state::is_record_temp_name(name))
        .collect();
    if !owner_dead {
        return settled(TempFiles::Retained(
            "the attempt's owner is not established dead",
        ));
    }
    if ours.is_empty() {
        return settled(TempFiles::Retained(
            "none is a temporary file of this tool's records",
        ));
    }
    if dry_run {
        return settled(TempFiles::WouldRemove);
    }
    let attempt = match state::open_attempt_dir(dir) {
        Ok(attempt) => attempt,
        Err(error) => {
            return Leftovers {
                failure: Some(format!(
                    "temporary files: the attempt root cannot be opened: {}",
                    error.message
                )),
                outcome: Some(TempFiles::Failed(error.message)),
            };
        }
    };
    let mut removed = Vec::new();
    for name in ours {
        let Ok(component) = anchored::Name::new(name.as_bytes()) else {
            continue;
        };
        // Only a regular file: a link of that name is not what a crash left.
        let regular = attempt
            .stat_at(&component)
            .is_ok_and(|stat| stat.kind == anchored::Kind::Regular);
        if !regular {
            continue;
        }
        if let Err(error) = attempt.unlink_at(&component) {
            return Leftovers {
                outcome: Some(TempFiles::Failed(format!("{name}: {error}"))),
                failure: Some(format!("temporary files: {name}: {error}")),
            };
        }
        removed.push(name.clone());
    }
    if removed.is_empty() {
        return settled(TempFiles::Retained(
            "none is a regular file of this tool's records",
        ));
    }
    let count = removed.len();
    let record_of = state::GcAction {
        names: state::Field::Set(removed),
        ..act("gc_removed_temp_files")
    };
    match record(dir, record_of, &mut entry.recorded) {
        Ok(()) => settled(TempFiles::Removed(count)),
        Err(failure) => Leftovers {
            outcome: Some(TempFiles::RemovedUnrecorded(failure.clone())),
            failure: Some(failure),
        },
    }
}

/// The entry's action and reason: a failed gc step makes it `pending`; a gc
/// step that did something names the action when the J3 resumption had
/// nothing to do (`retained`), and the resumption's own reason is kept.
fn combine(action: Action, reason: String, done: &Done) -> (Action, String) {
    if let Some(failure) = &done.failure {
        return (Action::Pending, format!("{failure}; {reason}"));
    }
    match done.action {
        Some(step) if action == Action::Retained => (step, reason),
        _ => (action, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_record_is_kept_once_with_a_count() {
        let mut actions = Vec::new();
        let record = |at: &str, inode: u64| {
            serde_json::from_value::<state::GcAction>(serde_json::json!({
                "action": "gc_terminating_orphan", "at": at,
                "execution_cgroup": {"path": "/p", "device": 1, "inode": inode}}))
            .unwrap()
        };
        coalesce(&mut actions, record("t1", 2));
        coalesce(&mut actions, record("t2", 2));
        coalesce(&mut actions, record("t3", 3));
        coalesce(&mut actions, record("t4", 2));
        assert_eq!(actions.len(), 2, "{actions:#?}");
        let first = serde_json::to_value(&actions[0]).unwrap();
        assert_eq!(first["at"], "t1");
        assert_eq!(first["count"], 3);
        assert_eq!(first["last_at"], "t4");
        assert!(
            serde_json::to_value(&actions[1])
                .unwrap()
                .get("count")
                .is_none()
        );
    }

    /// G5: `leftovers` removes only regular files. A symlink or FIFO left
    /// under a temporary record name is not what a crash left, and unlinking
    /// it would destroy something else's object.
    #[test]
    fn a_symlink_or_fifo_named_like_a_temp_file_is_never_unlinked() {
        use std::os::unix::fs::symlink;
        // A private attempt root, as gc only ever reaches one.
        let dir = state::testing::private_tempdir();
        let attempt = AttemptDir::from_root(dir.path().to_path_buf());
        let target = dir.path().join("operator-file");
        std::fs::write(&target, b"mine").unwrap();
        let id = "00000000-0000-4000-8000-000000000009";
        let linked = dir.path().join(format!(".jail.json.{id}.tmp"));
        symlink(&target, &linked).unwrap();
        let fifo = dir.path().join(format!(".policy.json.{id}.tmp"));
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let mut meter = Meter {
            max: 1000,
            charged: 0,
        };
        let mut entry = Entry::default();
        let leftover = leftovers(&attempt, true, false, &mut meter, &mut entry);
        assert!(leftover.failure.is_none(), "{:?}", leftover.outcome);
        assert!(
            std::fs::symlink_metadata(&linked).is_ok(),
            "the symlink survives gc"
        );
        assert!(
            std::fs::symlink_metadata(&fifo).is_ok(),
            "the FIFO survives gc"
        );
        assert!(std::fs::read(&target).is_ok(), "the target is untouched");
    }
}
