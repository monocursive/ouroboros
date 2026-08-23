//! `--continue`: the last session for *this* workspace, on any machine (F2).
//!
//! The question a person asks by typing it is "put me back where I was", and the honest
//! answer has three parts: which directory they mean, which of the fleet's sessions were
//! opened on it, and which of those can still take a turn. Every one of them is decided
//! here, as a pure function over rows the gateway already answered, so the rule is
//! readable and testable without a runtime.
//!
//! ## Where the rows come from
//!
//! `interactive.list` — a `read`-scope method the gateway fans out over `:erpc` to every
//! connected, compatible fleet machine before it answers
//! ([`lib/ouroboros/gateway/methods.ex`], `fleet_sessions/1`). So a session started on the
//! laptop is a candidate from the studio, which is the whole point of the row's `node`
//! field. Nothing here contacts another machine itself.
//!
//! ## Which row wins
//!
//! `updated_at`, descending — the session's own last-touched timestamp, which
//! `Interactive.State.touch/1` writes as a fixed-width UTC ISO-8601 string, so ordering it
//! lexicographically orders it chronologically. Deliberately **not** `cursor`: that is a
//! per-session event count, and a chatty session from last week would outrank the one
//! abandoned ten minutes ago. Ties fall to `created_at` and then to `id`, so two rows
//! written in the same microsecond still resolve the same way twice.
//!
//! ## Which rows are eligible
//!
//! A terminal session takes no further turns — [`crate::run::Driver::resume`] refuses one
//! outright — so terminal rows are skipped rather than opened and then rejected. The rows
//! carry no separate "resumable" capability to consult: `options.capabilities` describes
//! what the *transport* can do, not whether a closed conversation may be reopened, and
//! inventing a key the runtime never sent would be this client guessing.
//!
//! ## Which directory
//!
//! Comparison is lexical, on tidied absolute paths, and that is a limit rather than a
//! shortcut: a row's `workspace` is a path on *its own* machine, and a client that
//! canonicalised it would be resolving another host's symlinks against this filesystem.
//! Locally the two spellings that actually occur — the path as typed and the path with
//! its symlinks resolved — are both offered, because `/tmp` and `/private/tmp` are the
//! same directory to everyone except a string comparison.

use std::path::Path;

use serde_json::{json, Value};

use crate::model::{Plane, SessionInfo};
use crate::proto::Hello;
use crate::transport::Client;

/// The directory `--continue` was asked about, in the spellings a row might carry.
///
/// Two, at most: the path made absolute the way [`crate::runtime::resolve_workspace`]
/// makes one — the same function `ouro new` and `ouro run` send a workspace through, so
/// the target is spelled the way the row that started here was spelled — and its
/// canonical form where this filesystem has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    absolute: String,
    /// `None` where the directory does not exist here, which is the ordinary case for a
    /// workspace named with `--workspace` for another machine.
    canonical: Option<String>,
}

impl Workspace {
    /// Resolves what was typed against where it was typed.
    ///
    /// `named` is `--workspace` if there was one; without it the working directory is the
    /// question, which is what makes `ouro --continue` mean "this project".
    pub fn resolve(named: Option<&Path>, here: &Path) -> Self {
        let absolute = match named {
            Some(path) => crate::runtime::resolve_workspace(path, here),
            // Not `resolve_workspace(".", here)`: that spells the directory `/w/.`, and
            // while `tidy` folds the two together anyway, the string this type *displays*
            // in a refusal should be the one a person recognises.
            None => here.display().to_string(),
        };

        let canonical = std::fs::canonicalize(&absolute)
            .ok()
            .map(|path| tidy(&path.display().to_string()));

        Self {
            absolute: tidy(&absolute),
            canonical: canonical.filter(|path| !path.is_empty()),
        }
    }

    /// The two spellings, without touching the filesystem. For tests, and for a caller
    /// that already knows both.
    pub fn from_parts(absolute: &str, canonical: Option<&str>) -> Self {
        Self {
            absolute: tidy(absolute),
            canonical: canonical.map(tidy).filter(|path| !path.is_empty()),
        }
    }

    /// What a message calls this directory: the path as it was resolved, not as the
    /// filesystem spells it after following links.
    pub fn display(&self) -> &str {
        &self.absolute
    }

    /// Whether a row's `workspace` names this directory.
    pub fn matches(&self, workspace: &str) -> bool {
        let workspace = tidy(workspace);

        if workspace.is_empty() {
            return false;
        }

        workspace == self.absolute || self.canonical.as_deref() == Some(workspace.as_str())
    }
}

/// Folds the spellings of one directory that differ only in punctuation.
///
/// `ouro run` with no `--workspace` sends `<cwd>/.` — `Path::join(".")` appends rather
/// than normalises — so a client that compared raw strings would fail to find the session
/// it had itself started ten seconds earlier. Trailing separators go for the same reason.
/// Nothing else is normalised: `..` is not folded, because folding it lexically is wrong
/// across a symlink and this function is not allowed to touch the disk.
fn tidy(path: &str) -> String {
    let mut path = path.trim();

    loop {
        let trimmed = path
            .strip_suffix("/.")
            .or_else(|| path.strip_suffix('/').filter(|rest| !rest.is_empty()))
            .unwrap_or(path);

        if trimmed == path {
            return path.to_string();
        }

        path = trimmed;
    }
}

/// What `--continue` found, and enough about what it passed over to say so.
#[derive(Debug, Clone)]
pub struct Resolution<'a> {
    /// The row to open, where one is eligible.
    pub chosen: Option<&'a SessionInfo>,
    /// Interactive rows on this workspace that were skipped because they have ended.
    pub ended_here: usize,
    /// Interactive rows the list carried at all, on any workspace. Distinguishes "this
    /// runtime knows of no sessions" from "none of them are yours".
    pub seen: usize,
}

impl Resolution<'_> {
    /// The sentence printed when there is nothing to continue.
    ///
    /// Specific about *why*, because the three reasons want three different next moves:
    /// start one, look somewhere else, or accept that the conversation is over.
    pub fn refusal(&self, workspace: &Workspace) -> String {
        let here = workspace.display();

        if self.ended_here > 0 {
            return format!(
                "no session to continue in {here}: the {} session{} there {} ended, and an \
                 ended session takes no further turns. Start a new one with --or-new",
                self.ended_here,
                if self.ended_here == 1 { "" } else { "s" },
                if self.ended_here == 1 { "has" } else { "have" }
            );
        }

        if self.seen == 0 {
            return format!(
                "no session to continue in {here}: this runtime and the fleet machines it \
                 can reach have no interactive sessions at all. Start one with --or-new"
            );
        }

        format!(
            "no session to continue in {here}: none of the {} interactive session{} this \
             runtime can see was opened on that directory. Start one with --or-new",
            self.seen,
            if self.seen == 1 { "" } else { "s" }
        )
    }
}

/// Picks the session `--continue` means, out of rows the gateway already fanned out.
///
/// Pure: no clock, no filesystem, no second call. Everything it decides is decidable from
/// the rows, which is why the fixture in the tests is a two-node `interactive.list`
/// answer and not a running fleet.
pub fn resolve<'a>(rows: &'a [SessionInfo], workspace: &Workspace) -> Resolution<'a> {
    let interactive = rows.iter().filter(|row| row.plane == Plane::Interactive);

    let mut seen = 0usize;
    let mut ended_here = 0usize;
    let mut chosen: Option<&SessionInfo> = None;

    for row in interactive {
        seen += 1;

        let Some(row_workspace) = row.workspace.as_deref() else {
            continue;
        };

        if !workspace.matches(row_workspace) {
            continue;
        }

        // Terminal is the whole eligibility rule. A row whose owner is offline is *not*
        // excluded here: `last_known` says this client could not see the machine on the
        // last refresh, and resuming it is exactly how a person finds out whether it came
        // back — the gateway refuses with its own sentence if it did not.
        if row.status.terminal() {
            ended_here += 1;
            continue;
        }

        match chosen {
            Some(current) if !newer(row, current) => {}
            _otherwise => chosen = Some(row),
        }
    }

    Resolution {
        chosen,
        ended_here,
        seen,
    }
}

/// Whether `candidate` is the later of two rows.
///
/// A row with no `updated_at` never displaces one that has it: "the runtime did not say
/// when" is not evidence of being recent. Between two rows that both lack it the
/// `created_at` and then the `id` decide, so the answer is stable rather than
/// list-order-dependent.
fn newer(candidate: &SessionInfo, current: &SessionInfo) -> bool {
    (
        candidate.updated_at.as_deref(),
        candidate.created_at.as_deref(),
        candidate.id.as_str(),
    ) > (
        current.updated_at.as_deref(),
        current.created_at.as_deref(),
        current.id.as_str(),
    )
}

/// What `--continue` resolved to, once there was a gateway to ask.
pub enum Continued {
    Session(ContinuedSession),
    /// The list was answered and held nothing to continue. The sentence says why.
    Nothing(String),
}

/// The row `--continue` picked, reduced to what a person needs to recognise it.
pub struct ContinuedSession {
    pub id: String,
    pub node: Option<String>,
    pub title: Option<String>,
    pub updated_at: Option<String>,
}

impl ContinuedSession {
    /// The line printed before the turn starts. Says the id, the machine, and when the
    /// session was last touched, because "continuing" is a claim about *which* of several
    /// sessions and a caller who cannot check it is being asked to trust a guess.
    pub fn describe(&self) -> String {
        let mut line = format!("continuing {}", self.id);

        if let Some(title) = &self.title {
            line.push_str(&format!(" ({title})"));
        }
        if let Some(node) = &self.node {
            line.push_str(&format!(" on {node}"));
        }
        if let Some(updated) = &self.updated_at {
            line.push_str(&format!(", last active {updated}"));
        }

        line
    }
}

/// Resolves `--continue` against `interactive.list`.
///
/// One `read`-scope call, and the gateway has already fanned it out over every connected,
/// compatible fleet machine, so a session started on another node is a candidate here
/// without this client contacting it. `Err` is reserved for "could not look" — a gateway
/// that does not serve the method, or one that refused the call — which is never allowed
/// to become `--or-new`'s "there was nothing there".
pub async fn target(
    client: &Client,
    hello: &Hello,
    workspace: &Workspace,
) -> Result<Continued, String> {
    if !hello.serves("interactive.list") {
        return Err(format!(
            "this gateway does not serve interactive.list, so --continue cannot find the \
             last session in {}; name one with --resume <id>",
            workspace.display()
        ));
    }

    let rows = client
        .call("interactive.list", json!({}))
        .await
        .map_err(|error| {
            format!(
                "interactive.list was refused, so --continue could not look for a session \
                 in {}: {error:#}",
                workspace.display()
            )
        })?;

    let rows = SessionInfo::decode_list(Plane::Interactive, &rows);
    let resolution = resolve(&rows, workspace);

    Ok(match resolution.chosen {
        Some(row) => Continued::Session(ContinuedSession {
            id: row.id.clone(),
            node: row.node.clone(),
            title: row
                .raw
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|title| !title.is_empty())
                .map(str::to_string),
            updated_at: row.updated_at.clone(),
        }),
        None => Continued::Nothing(resolution.refusal(workspace)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{json, Value};

    /// One `interactive.list` row, in the shape `Interactive.State.public/1` answers.
    fn row(id: &str, node: &str, workspace: &str, status: &str, updated: &str) -> Value {
        json!({
            "_struct": "Ouroboros.Interactive.State",
            "id": id,
            "node": node,
            "provider": "native",
            "status": status,
            "workspace": workspace,
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": updated,
        })
    }

    fn rows(values: Value) -> Vec<SessionInfo> {
        SessionInfo::decode_list(Plane::Interactive, &values)
    }

    fn here() -> Workspace {
        Workspace::from_parts("/w/project", None)
    }

    #[test]
    fn the_newest_session_for_this_workspace_wins_across_two_machines() {
        let rows = rows(json!([
            row(
                "on-alpha",
                "ouroboros@alpha",
                "/w/project",
                "idle",
                "2026-02-01T10:00:00.000000Z"
            ),
            row(
                "on-beta",
                "ouroboros@beta",
                "/w/project",
                "idle",
                "2026-02-01T12:00:00.000000Z"
            ),
        ]));

        let resolution = resolve(&rows, &here());

        assert_eq!(
            resolution.chosen.map(|row| row.id.as_str()),
            Some("on-beta")
        );
        assert_eq!(
            resolution.chosen.and_then(|row| row.node.as_deref()),
            Some("ouroboros@beta"),
            "the row keeps saying which machine it is on; --continue does not move it"
        );
        assert_eq!(resolution.ended_here, 0);
        assert_eq!(resolution.seen, 2);
    }

    #[test]
    fn list_order_does_not_decide_which_session_is_newest() {
        let newest_first = rows(json!([
            row(
                "on-beta",
                "ouroboros@beta",
                "/w/project",
                "idle",
                "2026-02-01T12:00:00.000000Z"
            ),
            row(
                "on-alpha",
                "ouroboros@alpha",
                "/w/project",
                "idle",
                "2026-02-01T10:00:00.000000Z"
            ),
        ]));

        assert_eq!(
            resolve(&newest_first, &here())
                .chosen
                .map(|row| row.id.as_str()),
            Some("on-beta")
        );
    }

    #[test]
    fn a_session_on_another_workspace_is_never_continued() {
        let rows = rows(json!([
            row(
                "elsewhere",
                "ouroboros@alpha",
                "/w/other",
                "idle",
                "2026-02-01T23:00:00.000000Z"
            ),
            row(
                "mine",
                "ouroboros@alpha",
                "/w/project",
                "idle",
                "2026-02-01T10:00:00.000000Z"
            ),
        ]));

        let resolution = resolve(&rows, &here());

        assert_eq!(resolution.chosen.map(|row| row.id.as_str()), Some("mine"));
        assert_eq!(resolution.seen, 2);
    }

    #[test]
    fn a_workspace_that_only_has_ended_sessions_says_so_rather_than_opening_one() {
        let rows = rows(json!([
            row(
                "closed",
                "ouroboros@alpha",
                "/w/project",
                "closed",
                "2026-02-01T23:00:00.000000Z"
            ),
            row(
                "failed",
                "ouroboros@beta",
                "/w/project",
                "failed",
                "2026-02-01T22:00:00.000000Z"
            ),
        ]));

        let resolution = resolve(&rows, &here());

        assert!(resolution.chosen.is_none());
        assert_eq!(resolution.ended_here, 2);

        let refusal = resolution.refusal(&here());
        assert!(refusal.contains("/w/project"), "{refusal}");
        assert!(refusal.contains("have ended"), "{refusal}");
        assert!(refusal.contains("--or-new"), "{refusal}");
    }

    #[test]
    fn a_newer_ended_session_does_not_hide_the_live_one_under_it() {
        let rows = rows(json!([
            row(
                "closed",
                "ouroboros@alpha",
                "/w/project",
                "closed",
                "2026-02-01T23:00:00.000000Z"
            ),
            row(
                "live",
                "ouroboros@beta",
                "/w/project",
                "idle",
                "2026-02-01T09:00:00.000000Z"
            ),
        ]));

        let resolution = resolve(&rows, &here());

        assert_eq!(resolution.chosen.map(|row| row.id.as_str()), Some("live"));
        assert_eq!(resolution.ended_here, 1);
    }

    #[test]
    fn a_status_this_build_does_not_recognise_is_still_eligible() {
        let rows = rows(json!([row(
            "hibernating",
            "ouroboros@alpha",
            "/w/project",
            "hibernating",
            "2026-02-01T09:00:00.000000Z"
        )]));

        assert_eq!(
            resolve(&rows, &here()).chosen.map(|row| row.id.as_str()),
            Some("hibernating"),
            "an unrecognised status is not terminal; guessing otherwise would hide a live \
             session"
        );
    }

    #[test]
    fn the_two_refusals_for_an_empty_answer_are_different_sentences() {
        let none = resolve(&[], &here());
        assert!(none.chosen.is_none());
        assert!(
            none.refusal(&here())
                .contains("no interactive sessions at all"),
            "{}",
            none.refusal(&here())
        );

        let elsewhere = rows(json!([row(
            "elsewhere",
            "ouroboros@alpha",
            "/w/other",
            "idle",
            "2026-02-01T09:00:00.000000Z"
        )]));
        let resolution = resolve(&elsewhere, &here());
        assert!(
            resolution
                .refusal(&here())
                .contains("was opened on that directory"),
            "{}",
            resolution.refusal(&here())
        );
    }

    #[test]
    fn a_coding_task_is_not_something_continue_can_open() {
        let coding = SessionInfo::decode_list(
            Plane::Coding,
            &json!([row(
                "task",
                "ouroboros@alpha",
                "/w/project",
                "running",
                "2026-02-01T09:00:00.000000Z"
            )]),
        );

        let resolution = resolve(&coding, &here());

        assert!(resolution.chosen.is_none());
        assert_eq!(
            resolution.seen, 0,
            "a coding task has nobody to prompt it; it is not counted as a near miss either"
        );
    }

    #[test]
    fn the_dot_ouro_run_appends_to_a_workspace_is_the_same_directory() {
        assert!(here().matches("/w/project/."));
        assert!(here().matches("/w/project/"));
        assert!(here().matches("/w/project"));
        assert!(!here().matches("/w/project2"));
        assert!(!here().matches("/w"));
        assert!(!here().matches(""));
    }

    #[test]
    fn both_spellings_of_a_symlinked_directory_match_and_the_typed_one_is_displayed() {
        let workspace = Workspace::from_parts("/tmp/project", Some("/private/tmp/project"));

        assert!(workspace.matches("/tmp/project"));
        assert!(workspace.matches("/private/tmp/project/"));
        assert!(!workspace.matches("/private/tmp/other"));
        assert_eq!(
            workspace.display(),
            "/tmp/project",
            "a refusal names the directory the person typed, not the one behind the link"
        );
    }

    #[test]
    fn a_row_that_names_no_workspace_is_passed_over_rather_than_assumed_to_be_here() {
        let rows = rows(json!([{
            "id": "nameless",
            "node": "ouroboros@alpha",
            "status": "idle",
            "updated_at": "2026-02-01T23:00:00.000000Z",
        }]));

        assert!(resolve(&rows, &here()).chosen.is_none());
    }

    #[test]
    fn a_row_without_a_timestamp_never_displaces_one_that_has_it() {
        let rows = rows(json!([
            {
                "id": "undated",
                "node": "ouroboros@alpha",
                "status": "idle",
                "workspace": "/w/project",
            },
            row(
                "dated",
                "ouroboros@beta",
                "/w/project",
                "idle",
                "2020-01-01T00:00:00.000000Z"
            ),
        ]));

        assert_eq!(
            resolve(&rows, &here()).chosen.map(|row| row.id.as_str()),
            Some("dated"),
            "silence about when is not evidence of being recent"
        );
    }

    #[test]
    fn resolving_a_named_workspace_absolutises_it_where_it_was_typed() {
        let workspace = Workspace::resolve(Some(Path::new("project")), Path::new("/w"));
        assert_eq!(workspace.display(), "/w/project");

        let absolute = Workspace::resolve(Some(Path::new("/srv/work/")), Path::new("/w"));
        assert_eq!(absolute.display(), "/srv/work");

        let cwd = Workspace::resolve(None, Path::new("/w/project"));
        assert_eq!(cwd.display(), "/w/project");
    }
}
