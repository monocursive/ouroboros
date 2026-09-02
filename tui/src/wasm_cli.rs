//! `ouro wasm doctor` — the WebAssembly containment operator readiness surface
//! (docs/WASM.md W5). It asks the gateway for `wasm.status`, which starts nothing — not the
//! helper, not a component, not an instance — and prints a readable summary, or the raw map
//! under `--json`. Reporting is all this does; building the helper (`make wasm`), signing a
//! component and deploying one live elsewhere.
//!
//! **Absence is not a failure.** The helper is opt-in by presence on disk, so a node that
//! never built one is a node whose operator chose that, and this exits 0 saying so. The only
//! non-zero exit is a gateway that refused the question.

use crate::model::{WasmHelper, WasmStatus};
use crate::transport::Client;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::io::Write;

const STATUS_METHOD: &str = "wasm.status";

/// Query lane-W readiness. Always `wasm.status`: there is no probe verb, because starting
/// the helper to see whether it starts is exactly what a read-scope surface must not do.
pub async fn doctor<O: Write>(client: &Client, json: bool, out: &mut O) -> Result<()> {
    let answer = client
        .call(STATUS_METHOD, serde_json::json!({}))
        .await
        .map_err(|error| anyhow!("the runtime refused {STATUS_METHOD}: {error}"))?;

    let text = if json {
        serde_json::to_string_pretty(&answer)?
    } else {
        render(&answer)
    };

    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// A readable one-glance summary of the status map. Absent fields read as their safe
/// default (missing / not running / not known) so an older or partial answer never panics.
pub fn render(answer: &Value) -> String {
    let status = WasmStatus::decode(answer);
    let helper = &status.helper;
    let mut lines = Vec::new();

    let path = helper.path.as_deref().unwrap_or("(unknown)");

    if helper.present {
        lines.push(format!("WebAssembly containment: helper present ({path})"));
    } else {
        lines.push(format!(
            "WebAssembly containment: no helper on this node ({path})"
        ));
        lines.push(
            "  this is an opt-in, not a fault: build it with `make wasm`, or leave it off and \
             component hooks and capabilities stay unavailable here"
                .into(),
        );
    }

    lines.push(format!("  helper pool: {}", render_pool(&status)));

    if let Some(reason) = helper.broken_reason.as_deref() {
        lines.push(format!("  broken: {reason}"));
    }

    lines.push(format!(
        "  world: {}{}",
        helper.world.as_deref().unwrap_or("(unknown)"),
        match helper.usable {
            Some(true) => ", helper reports usable",
            Some(false) => ", helper reports NOT usable",
            None => "",
        }
    ));

    if !helper.worlds.is_empty() {
        lines.push(format!("  helper offers: {}", helper.worlds.join(", ")));
    }

    if let Some(limits) = render_limits(helper) {
        lines.push(format!("  limits: {limits}"));
    }

    lines.push(format!(
        "  hook components: {} of {} used{}",
        helper.hook_components,
        helper.hook_component_budget,
        if helper.hook_budget_spent() {
            " — spent; restart the wasm pool before another component hook can load"
        } else {
            ""
        }
    ));

    lines.push(format!("  store: {}", render_store(&status)));
    lines.push(format!("  rollouts: {}", render_rollouts(&status)));
    lines.push(format!(
        "  boot restart: {}",
        if status.boot_enabled {
            "enabled"
        } else {
            "disabled (no data directory, so nothing durable to restart)"
        }
    ));

    lines.join("\n")
}

fn render_pool(status: &WasmStatus) -> String {
    let helper = &status.helper;

    match helper.phase.as_deref() {
        Some("absent") | None => "no pool on this node".into(),
        Some("idle") => "idle (the helper starts on the first component that needs it)".into(),
        Some("ready") => {
            let version = helper
                .wasmtime
                .as_deref()
                .map(|version| format!(", wasmtime {version}"))
                .unwrap_or_default();

            format!(
                "ready{}{version}, {} instance(s), {} owned, {} pending drop(s)",
                helper
                    .os_pid
                    .map(|pid| format!(" (pid {pid})"))
                    .unwrap_or_default(),
                helper.instances,
                helper.owned,
                helper.pending_drops
            )
        }
        Some(other) => other.to_string(),
    }
}

/// The three bounds an operator asks about, out of whatever table the helper reported. A
/// bound this helper does not name is left out rather than guessed at.
fn render_limits(helper: &WasmHelper) -> Option<String> {
    let named = [
        ("max_deadline_ms", "deadline"),
        ("max_memory_bytes", "memory"),
        ("max_component_bytes", "component"),
    ]
    .iter()
    .filter_map(|(key, label)| {
        helper
            .limits
            .get(*key)
            .map(|bound| format!("{label} {bound}"))
    })
    .collect::<Vec<_>>();

    if named.is_empty() {
        None
    } else {
        Some(named.join(", "))
    }
}

fn render_store(status: &WasmStatus) -> String {
    let store = &status.store;

    let Some(root) = store.root.as_deref() else {
        return "none (this node has no data directory)".into();
    };

    let held = match (store.held, store.bytes) {
        (Some(held), Some(bytes)) => format!("{held} component(s), {bytes} byte(s)"),
        _unreadable => "unreadable".into(),
    };

    let budget = store
        .budget_bytes
        .map(|budget| format!(" of {budget} byte(s) budget"))
        .unwrap_or_default();

    let protected = match store.protected {
        Some(protected) => format!(", {protected} protected by a rollout"),
        None => ", protection unknown (the rollout register did not answer)".into(),
    };

    format!("{held}{budget}{protected} in {root}")
}

fn render_rollouts(status: &WasmStatus) -> String {
    let Some(total) = status.rollouts.total else {
        return "unknown (the rollout register did not answer)".into();
    };

    format!(
        "{total} lane-W ({} live, {} deploying, {} quarantined, {} superseded, {} rolled back)",
        status.rollouts.state("live"),
        status.rollouts.state("deploying"),
        status.rollouts.state("quarantined"),
        status.rollouts.state("superseded"),
        status.rollouts.state("rolled_back"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_absent_helper_reads_as_an_opt_out_and_not_a_fault() {
        let text = render(&json!({
            "node": "ouroboros@here",
            "helper": {
                "present": false,
                "path": "/nonexistent/ouro-wasm",
                "world": "ouroboros:capability@0.1.0",
                "phase": "absent",
                "instances": 0,
                "owned": 0,
                "pending_drops": 0,
                "hook_components": 0,
                "hook_component_budget": 16,
                "usable": null,
                "worlds": [],
                "wasmtime": null,
                "limits": null,
                "broken_reason": null
            },
            "store": {
                "root": null,
                "budget_bytes": 536870912,
                "held": null,
                "bytes": null,
                "protected": null
            },
            "rollouts": {"total": 0, "by_state": {"live": 0}},
            "boot": {"enabled": false}
        }));

        assert!(text.contains("no helper on this node"));
        assert!(text.contains("this is an opt-in, not a fault"));
        assert!(text.contains("helper pool: no pool on this node"));
        assert!(text.contains("store: none (this node has no data directory)"));
        assert!(text.contains("boot restart: disabled"));
        // Nothing here claims a spent budget on a node that has admitted nothing.
        assert!(!text.contains("spent"));
    }

    #[test]
    fn a_ready_helper_shows_what_it_is_running_under() {
        let text = render(&json!({
            "node": "ouroboros@here",
            "helper": {
                "present": true,
                "path": "/opt/ouro-wasm",
                "world": "ouroboros:capability@0.1.0",
                "phase": "ready",
                "os_pid": 4242,
                "instances": 2,
                "owned": 1,
                "pending_drops": 0,
                "hook_components": 16,
                "hook_component_budget": 16,
                "usable": true,
                "worlds": ["ouroboros:capability@0.1.0"],
                "wasmtime": "43.0.1",
                "limits": {"max_deadline_ms": 60000, "max_memory_bytes": 268435456},
                "broken_reason": null
            },
            "store": {
                "root": "/var/lib/ouroboros/wasm/components",
                "budget_bytes": 536870912,
                "held": 2,
                "bytes": 3145728,
                "protected": 1
            },
            "rollouts": {
                "total": 3,
                "by_state": {"live": 1, "quarantined": 1, "superseded": 1, "deploying": 0, "rolled_back": 0}
            },
            "boot": {"enabled": true}
        }));

        assert!(text.contains("helper present"));
        assert!(text.contains("ready (pid 4242), wasmtime 43.0.1, 2 instance(s)"));
        assert!(text.contains("helper reports usable"));
        assert!(text.contains("deadline 60000"));
        assert!(text.contains("hook components: 16 of 16 used"));
        assert!(text.contains("restart the wasm pool"));
        assert!(text.contains("2 component(s), 3145728 byte(s)"));
        assert!(text.contains("1 protected by a rollout"));
        assert!(text.contains("3 lane-W (1 live"));
        assert!(text.contains("boot restart: enabled"));
    }

    /// A broken pool says why, and an unreadable store says so rather than reading as empty.
    #[test]
    fn a_broken_pool_and_an_unreadable_store_both_say_so() {
        let text = render(&json!({
            "helper": {
                "present": true,
                "path": "/opt/ouro-wasm",
                "phase": "broken",
                "hook_components": 0,
                "hook_component_budget": 16,
                "usable": false,
                "broken_reason": "{:handshake_refused, %{usable: false, worlds: []}}"
            },
            "store": {"root": "/var/lib/ouroboros/wasm/components", "held": null, "bytes": null, "protected": null},
            "rollouts": {"total": null, "by_state": {}},
            "boot": {"enabled": true}
        }));

        assert!(text.contains("helper pool: broken"));
        assert!(text.contains("broken: {:handshake_refused"));
        assert!(text.contains("helper reports NOT usable"));
        assert!(text.contains("store: unreadable"));
        assert!(text.contains("protection unknown"));
        assert!(text.contains("rollouts: unknown (the rollout register did not answer)"));
    }

    #[test]
    fn empty_answer_does_not_panic() {
        let text = render(&json!({}));

        assert!(text.contains("no helper on this node"));
        assert!(text.contains("no pool on this node"));
        assert!(text.contains("boot restart: disabled"));
    }
}
