//! `ouro desktop doctor` — the Computer Use operator readiness surface (docs/COMPUTER_USE.md
//! D2, §8.5). It asks the gateway for `computer_use.status`, which starts nothing, and prints
//! a readable summary — or the raw map under `--json`. Reporting is all this does; the model
//! tools (`desktop_state`/`desktop_act`) and enabling the feature live elsewhere.

use crate::transport::Client;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::io::Write;

const STATUS_METHOD: &str = "computer_use.status";

/// Query `computer_use.status` and write a summary (or the raw JSON) to `out`.
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

/// A readable one-glance summary of the status map. Absent fields read as their safe default
/// (off / missing / not running) so an older or partial answer never panics.
pub fn render(status: &Value) -> String {
    let mut lines = Vec::new();

    let enabled = field_bool(status, "enabled");
    let flag = field_bool(status, "flag");
    let present = field_bool(status, "helper_present");
    let path = status
        .get("helper_path")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)");

    lines.push(format!(
        "Computer Use: {} — flag {}, helper {} ({})",
        if enabled { "enabled" } else { "disabled" },
        if flag { "on" } else { "off" },
        if present { "present" } else { "missing" },
        path
    ));

    if field_bool(status, "running") {
        let sessions = status.get("sessions").and_then(Value::as_u64).unwrap_or(0);
        lines.push(format!("  helper pool: running, {sessions} session(s)"));

        if let Some(readiness) = status.get("doctor").and_then(|d| d.get("readiness")) {
            lines.push(format!("  readiness: {}", render_readiness(readiness)));

            if let Some(next) = readiness
                .get("recommended_next_step")
                .and_then(Value::as_str)
                .filter(|step| !step.is_empty())
            {
                lines.push(format!("  next: {next}"));
            }
        }
    } else {
        lines.push("  helper pool: not running (starts on the first desktop_state)".into());
    }

    let denied = status
        .get("denied_app_ids")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    lines.push(format!("  denied apps: {denied}"));

    lines.join("\n")
}

fn render_readiness(readiness: &Value) -> String {
    [
        "can_screenshot",
        "can_ax_tree",
        "can_list_windows",
        "can_input",
    ]
    .iter()
    .map(|key| {
        let short = key.strip_prefix("can_").unwrap_or(key);
        let ok = readiness.get(key).and_then(Value::as_bool).unwrap_or(false);
        format!("{short}={}", if ok { "ok" } else { "no" })
    })
    .collect::<Vec<_>>()
    .join(" ")
}

fn field_bool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn disabled_with_no_pool_reads_clean() {
        let text = render(&json!({
            "enabled": false,
            "flag": false,
            "helper_present": false,
            "helper_path": "/nonexistent/ouro-computer-use",
            "denied_app_ids": ["com.apple.Terminal", "com.ouroboros.desktop"],
            "running": false
        }));
        assert!(text.contains("Computer Use: disabled"));
        assert!(text.contains("helper missing"));
        assert!(text.contains("helper pool: not running"));
        assert!(text.contains("denied apps: 2"));
    }

    #[test]
    fn running_pool_shows_readiness() {
        let text = render(&json!({
            "enabled": true,
            "flag": true,
            "helper_present": true,
            "helper_path": "/opt/ouro-computer-use",
            "denied_app_ids": [],
            "running": true,
            "sessions": 2,
            "doctor": {
                "readiness": {
                    "can_screenshot": true,
                    "can_ax_tree": true,
                    "can_list_windows": true,
                    "can_input": false,
                    "recommended_next_step": "Grant Accessibility."
                }
            }
        }));
        assert!(text.contains("Computer Use: enabled"));
        assert!(text.contains("running, 2 session(s)"));
        assert!(text.contains("screenshot=ok"));
        assert!(text.contains("input=no"));
        assert!(text.contains("next: Grant Accessibility."));
    }

    #[test]
    fn empty_answer_does_not_panic() {
        let text = render(&json!({}));
        assert!(text.contains("Computer Use: disabled"));
        assert!(text.contains("not running"));
    }
}
