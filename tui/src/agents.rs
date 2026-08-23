//! `ouro agents` (G2): the fleet, once, grouped by what each session needs.
//!
//! The same grouping the Sessions rail draws, printed rather than rendered — for a
//! terminal without a tty, for a pipe, and for the thirty seconds where opening a UI to
//! answer "is anything waiting on me" is thirty seconds too many.
//!
//! It answers from `interactive.list` and `coding.list`, which are already fanned out over
//! every fleet node, and it does **not** subscribe: the grouping is computed from the
//! declared status of each row and nothing else, so a row's group is a fact the runtime
//! stated rather than something this command watched for. That is also why the counts here
//! can differ from the rail's by one: the rail additionally counts approvals it is
//! *holding* on an open stream, and this command holds none.

use std::fmt::Write;

use serde_json::{json, Value};

use crate::model::{Plane, SessionInfo, Triage};

/// How wide the id column is before it is cut. Wide enough for a generated id, narrow
/// enough that the columns after it survive an eighty-column terminal.
const ID_WIDTH: usize = 34;

/// What one row of the plain listing says.
fn row(session: &SessionInfo) -> String {
    let mut line = format!(
        "  {:<6} {:<width$}",
        session.plane.tag(),
        cut(&session.id, ID_WIDTH),
        width = ID_WIDTH
    );

    let _ = write!(line, " {:<18}", cut(session.status.as_str(), 18));

    if let Some(node) = session.node.as_deref() {
        let _ = write!(line, " {:<24}", cut(node, 24));
    } else {
        let _ = write!(line, " {:<24}", "");
    }

    // The one fact that is about the *observation* rather than the session: a row retained
    // from the last complete list because its owner went offline. It stays in whichever
    // group it was last seen in — promoting every unreachable session to "needs input"
    // would make the top of the list meaningless — and it says why it might be stale.
    if session.last_known {
        let _ = write!(line, " last-known · owner offline");
    } else if let Some(objective) = session
        .objective
        .as_deref()
        .map(str::trim)
        .filter(|objective| !objective.is_empty())
    {
        let _ = write!(line, " {}", cut(objective, 48));
    }

    line.trim_end().to_string()
}

fn cut(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }

    let head: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{head}…")
}

/// The plain-text page, in the order a person reads it: what needs them, then what is
/// running, then what is finished.
pub fn render(rows: &[(Triage, &SessionInfo)]) -> String {
    let mut page = String::new();

    if rows.is_empty() {
        let _ = writeln!(page, "no sessions on any node this runtime can see");
        return page;
    }

    for group in Triage::ALL {
        let members: Vec<_> = rows
            .iter()
            .filter(|(row_group, _session)| *row_group == group)
            .map(|(_group, session)| *session)
            .collect();

        // An empty group is still named. "Nothing needs you" is the answer this command
        // exists to give, and a page that omitted the heading would leave a reader
        // wondering whether it had looked.
        let _ = writeln!(page, "{} ({})", group.label(), members.len());

        if members.is_empty() {
            let _ = writeln!(page, "  none");
        }

        for session in members {
            let _ = writeln!(page, "{}", row(session));
        }

        let _ = writeln!(page);
    }

    page
}

/// The `--json` form: one object, with the groups as arrays of whole rows.
///
/// Whole rows — the runtime's own objects, untouched — rather than a projection of them,
/// because a script reading this should not be limited to the four fields the plain page
/// happens to print, and because a projection here would be a second schema to keep in
/// step with the gateway's.
pub fn render_json(rows: &[(Triage, &SessionInfo)]) -> Value {
    let mut groups = serde_json::Map::new();

    for group in Triage::ALL {
        let members: Vec<Value> = rows
            .iter()
            .filter(|(row_group, _session)| *row_group == group)
            .map(|(_group, session)| {
                json!({
                    "plane": session.plane.as_str(),
                    "id": session.id,
                    "status": session.status.as_str(),
                    "node": session.node,
                    "provider": session.provider,
                    "workspace": session.workspace,
                    "objective": session.objective,
                    "last_known": session.last_known,
                    "session": session.raw,
                })
            })
            .collect();

        groups.insert(group.as_str().to_string(), Value::Array(members));
    }

    let counts: serde_json::Map<String, Value> = Triage::ALL
        .iter()
        .map(|group| {
            (
                group.as_str().to_string(),
                json!(groups[group.as_str()].as_array().map_or(0, Vec::len)),
            )
        })
        .collect();

    json!({ "counts": counts, "groups": groups })
}

/// Groups the two lists the gateway answered with, using the same classification the rail
/// uses. No approvals are held here, so the pending count is zero for every row.
pub fn group<'a>(
    interactive: &'a [SessionInfo],
    coding: &'a [SessionInfo],
) -> Vec<(Triage, &'a SessionInfo)> {
    let mut rows: Vec<(Triage, &SessionInfo)> = interactive
        .iter()
        .chain(coding.iter())
        .map(|session| (session.triage(0), session))
        .collect();

    rows.sort_by(|(left_group, left), (right_group, right)| {
        left_group
            .cmp(right_group)
            .then_with(|| right.updated_at.cmp(&left.updated_at))
            .then_with(|| left.plane.cmp(&right.plane))
            .then_with(|| left.id.cmp(&right.id))
    });

    rows
}

/// Decodes both list answers, dropping only the rows this build cannot read.
pub fn decode(interactive: &Value, coding: &Value) -> (Vec<SessionInfo>, Vec<SessionInfo>) {
    (
        SessionInfo::decode_list(Plane::Interactive, interactive),
        SessionInfo::decode_list(Plane::Coding, coding),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(plane: Plane, id: &str, status: &str, node: &str) -> Value {
        json!({
            "id": id,
            "status": status,
            "node": node,
            "provider": if plane == Plane::Interactive { "native" } else { "codex" },
            "workspace": "/w",
            "updated_at": "2026-01-01T00:00:00.000000Z",
        })
    }

    #[test]
    fn the_groups_are_named_even_when_they_are_empty() {
        let (interactive, coding) = decode(&json!([]), &json!([]));
        let rows = group(&interactive, &coding);

        assert_eq!(
            render(&rows),
            "no sessions on any node this runtime can see\n"
        );

        let (interactive, coding) = decode(
            &json!([session(
                Plane::Interactive,
                "s1",
                "running",
                "ouroboros@alpha"
            )]),
            &json!([]),
        );
        let rows = group(&interactive, &coding);
        let page = render(&rows);

        assert!(page.contains("NEEDS INPUT (0)\n  none\n"), "{page}");
        assert!(page.contains("WORKING (1)"), "{page}");
        assert!(page.contains("DONE (0)"), "{page}");
    }

    #[test]
    fn a_session_awaiting_approval_is_first_whatever_its_timestamp() {
        let (interactive, coding) = decode(
            &json!([
                session(Plane::Interactive, "newest", "running", "ouroboros@alpha"),
                {
                    "id": "waiting",
                    "status": "awaiting_approval",
                    "node": "ouroboros@beta",
                    "updated_at": "2020-01-01T00:00:00.000000Z"
                }
            ]),
            &json!([]),
        );
        let rows = group(&interactive, &coding);

        assert_eq!(rows[0].0, Triage::NeedsInput);
        assert_eq!(rows[0].1.id, "waiting");
    }

    #[test]
    fn the_json_form_carries_the_counts_and_the_whole_rows() {
        let (interactive, coding) = decode(
            &json!([session(Plane::Interactive, "s1", "idle", "ouroboros@alpha")]),
            &json!([session(Plane::Coding, "t1", "completed", "ouroboros@beta")]),
        );
        let rows = group(&interactive, &coding);
        let value = render_json(&rows);

        assert_eq!(value["counts"]["needs_input"], 1);
        assert_eq!(value["counts"]["working"], 0);
        assert_eq!(value["counts"]["done"], 1);
        assert_eq!(value["groups"]["needs_input"][0]["id"], "s1");
        assert_eq!(value["groups"]["done"][0]["plane"], "coding");
        assert_eq!(
            value["groups"]["done"][0]["session"]["node"], "ouroboros@beta",
            "the runtime's own row travels whole"
        );
    }
}
