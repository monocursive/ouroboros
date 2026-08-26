//! The one page Slice 3a prints in place of a UI.
//!
//! It reads `runtime.status` the way the Dashboard tab will: nothing here knows the name
//! of a plane. The availability matrix is whatever keys the runtime sent, rendered in
//! sorted order, so a plane added upstream tomorrow appears without a change here. Slice
//! 3b replaces this module with the ratatui Dashboard and keeps the same posture.

use std::fmt::Write;

use serde_json::Value;

use crate::model::plain;
use crate::proto::Hello;

/// The header: who answered, at what scope, speaking what.
pub fn render_hello(address: &str, hello: &Hello) -> String {
    let mut page = String::new();

    let _ = writeln!(page, "connected to {address}");
    let _ = writeln!(
        page,
        "  server     {}",
        plain(blank_as_unknown(&hello.server))
    );
    let _ = writeln!(
        page,
        "  node       {}",
        plain(blank_as_unknown(&hello.node))
    );
    let _ = writeln!(
        page,
        "  role       {}",
        plain(blank_as_unknown(&hello.role))
    );
    let _ = writeln!(
        page,
        "  scope      {}",
        plain(blank_as_unknown(&hello.scope))
    );
    let _ = writeln!(page, "  protocol   {}", hello.protocol);
    let _ = writeln!(page, "  methods    {}", hello.methods.len());

    page
}

/// The body: availability first, because a plane that is down explains everything under
/// it, then the counts a Dashboard would show as tables.
pub fn render_status(status: &Value) -> String {
    let mut page = String::new();

    let _ = writeln!(page, "runtime.status");
    let _ = writeln!(page, "  node         {}", scalar(status, "node"));
    let _ = writeln!(page, "  role         {}", scalar(status, "role"));
    let _ = writeln!(page, "  cluster      {}", cluster(status));
    let _ = writeln!(page, "  connected    {}", connected_nodes(status));

    let _ = writeln!(page, "  availability");

    match status.get("availability").and_then(Value::as_object) {
        Some(availability) if !availability.is_empty() => {
            let mut planes: Vec<(&String, &Value)> = availability.iter().collect();
            planes.sort_by(|left, right| left.0.cmp(right.0));

            let width = planes
                .iter()
                .map(|(name, _)| name.len())
                .max()
                .unwrap_or(0)
                .max(1);

            for (plane, state) in planes {
                let _ = writeln!(page, "    {plane:<width$}  {}", render_value(state));
            }
        }
        // The gateway answered, so this is the runtime reporting no availability map at
        // all rather than a plane being down, and it is said that way.
        _ => {
            let _ = writeln!(page, "    (the runtime reported no availability map)");
        }
    }

    for (label, key) in [
        ("agents", "agents"),
        ("interactive", "interactive_sessions"),
        ("coding", "coding_tasks"),
        ("teams", "teams"),
        ("plans", "orchestration_plans"),
    ] {
        let _ = writeln!(page, "  {label:<12} {}", count(status, key));
    }

    let control = status.get("control");
    let posture = status
        .get("availability")
        .and_then(Value::as_object)
        .and_then(|availability| availability.get("control"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let runs = control
        .and_then(|control| control.get("runs"))
        .and_then(Value::as_array)
        .map(|runs| runs.len())
        .unwrap_or(0);

    let _ = writeln!(page, "  control      {posture} ({runs} runs)");

    let _ = writeln!(page, "  upgrade      {}", mode(status, "upgrade"));
    let _ = writeln!(page, "  release      {}", mode(status, "release"));
    let _ = writeln!(page, "  forge        {}", forge(status));

    page
}

fn blank_as_unknown(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}

fn scalar(status: &Value, key: &str) -> String {
    status
        .get(key)
        .map(render_value)
        .unwrap_or_else(|| "-".into())
}

fn count(status: &Value, key: &str) -> String {
    match status.get(key).and_then(Value::as_array) {
        Some(items) => items.len().to_string(),
        None => "-".into(),
    }
}

fn mode(status: &Value, key: &str) -> String {
    status
        .get(key)
        .and_then(|value| value.get("mode"))
        .map(render_value)
        .unwrap_or_else(|| "-".into())
}

fn forge(status: &Value) -> String {
    let Some(forge) = status.get("forge") else {
        return "-".into();
    };

    if forge.is_null() {
        return "-".into();
    }

    let signer = forge
        .get("signer")
        .map(render_value)
        .unwrap_or_else(|| "-".into());
    let live = forge
        .get("live_count")
        .map(render_value)
        .unwrap_or_else(|| "-".into());
    let admit = match forge.get("admit_possible?").and_then(Value::as_bool) {
        Some(true) => "admit=yes",
        Some(false) => "admit=no",
        None => "admit=?",
    };

    format!("signer={signer} live={live} {admit}")
}

/// `Ouroboros.Cluster.status/0` reports formation and distribution separately, and a
/// single word for both would have to invent one. Whatever of them is present is shown.
fn cluster(status: &Value) -> String {
    let Some(cluster) = status.get("cluster") else {
        return "-".into();
    };

    let mut parts = Vec::new();

    if let Some(strategy) = cluster.get("formation").and_then(|f| f.get("strategy")) {
        parts.push(format!("strategy={}", render_value(strategy)));
    }

    if let Some(distributed) = cluster.get("distributed") {
        parts.push(format!("distributed={}", render_value(distributed)));
    }

    // A cluster status this build does not recognize is still the runtime's answer.
    if parts.is_empty() {
        return render_value(cluster);
    }

    parts.join(" ")
}

fn connected_nodes(status: &Value) -> String {
    match status.get("connected_nodes").and_then(Value::as_array) {
        Some(nodes) if nodes.is_empty() => "none".into(),
        Some(nodes) => nodes
            .iter()
            .map(render_value)
            .collect::<Vec<_>>()
            .join(", "),
        None => "-".into(),
    }
}

/// One value, rendered the way the generic tree widget will: a string is itself, and
/// anything else keeps its JSON shape rather than being flattened into a guess.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => plain(text),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_a_tri_state_availability_matrix_in_sorted_order() {
        let status = json!({
            "node": "nonode@nohost",
            "role": "core",
            "availability": {
                "workspace": "disabled",
                "cluster": "available",
                "mesh": "unavailable"
            }
        });

        let page = render_status(&status);
        let planes: Vec<&str> = page
            .lines()
            .filter(|line| line.starts_with("    "))
            .collect();

        assert_eq!(planes.len(), 3);
        assert!(planes[0].contains("cluster") && planes[0].contains("available"));
        assert!(planes[1].contains("mesh") && planes[1].contains("unavailable"));
        assert!(planes[2].contains("workspace") && planes[2].contains("disabled"));
    }

    #[test]
    fn a_plane_this_build_never_heard_of_still_renders() {
        let status = json!({ "availability": { "forged_capability_lane": "available" } });

        assert!(render_status(&status).contains("forged_capability_lane"));
    }

    #[test]
    fn a_missing_availability_map_is_said_out_loud() {
        assert!(render_status(&json!({})).contains("no availability map"));
    }

    #[test]
    fn counts_come_from_list_lengths() {
        let status = json!({
            "agents": [{ "id": "a" }, { "id": "b" }],
            "interactive_sessions": [],
            "availability": { "control": "available" },
            "control": { "runs": [{ "id": "r" }] }
        });

        let page = render_status(&status);

        assert!(page.contains("agents       2"), "{page}");
        assert!(page.contains("interactive  0"), "{page}");
        assert!(
            page.contains("coding       -"),
            "an absent list is not a zero"
        );
        assert!(page.contains("available (1 runs)"));
    }

    #[test]
    fn forge_posture_is_rendered_from_whatever_the_runtime_sent() {
        let status = json!({
            "forge": {
                "signer": "deny",
                "admit_possible?": false,
                "live_count": 0,
                "live": []
            }
        });

        assert!(
            render_status(&status).contains("signer=deny live=0 admit=no"),
            "{}",
            render_status(&status)
        );
    }

    #[test]
    fn cluster_reports_formation_and_distribution_rather_than_one_invented_word() {
        let status = json!({
            "cluster": {
                "distributed": false,
                "formation": { "strategy": "none", "supervised": false }
            }
        });

        assert!(render_status(&status).contains("strategy=none distributed=false"));
    }

    #[test]
    fn an_unrecognized_cluster_status_is_still_shown() {
        let status = json!({ "cluster": { "something_new": 1 } });

        assert!(render_status(&status).contains("something_new"));
    }

    #[test]
    fn a_hello_with_empty_fields_says_unknown_rather_than_nothing() {
        let page = render_hello("127.0.0.1:1", &Hello::default());

        assert!(page.contains("server     unknown"));
        assert!(page.contains("protocol   0"));
    }

    #[test]
    fn gateway_strings_reach_the_page_without_control_characters() {
        let status = json!({
            "node": "core@\u{1b}evil",
            "availability": { "mesh": "\u{9b}4m red" }
        });

        let page = render_status(&status);

        assert!(!page.contains('\u{1b}'), "{page}");
        assert!(!page.contains('\u{9b}'), "{page}");
        assert!(page.contains("core@ evil"), "{page}");
    }
}
