//! Command filters preserve argv positions through a real Linux exec.
#![cfg(target_os = "linux")]

use ouro_fixture::harness::{Jail, Run};
use std::os::unix::fs::PermissionsExt as _;

mod common;

fn run(argv: &[&str]) -> Run {
    run_with_rule(argv, "forbid")
}

fn run_with_rule(argv: &[&str], rule: &str) -> Run {
    run_with_rules(argv, &format!("{rule} = [\"true blocked\"]"))
}

fn run_with_rules(argv: &[&str], rules: &str) -> Run {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let config = jail.config_dir().join("config.toml");
    std::fs::write(&config, format!("[jail.commands]\n{rules}\n")).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    jail.args(["run", "--profile", "tool", "--observe", "on", "--workspace"])
        .arg(&workspace)
        .args(["--limit", "wall=5s"])
        .trace()
        .target(argv)
        .run()
        .unwrap()
}

/// The `command_rule` notes of a run's trace, entry denials and exec kills
/// alike.
fn command_rule_notes(run: &Run) -> Vec<&serde_json::Value> {
    run.trace_events()
        .iter()
        .filter(|event| {
            let kind = &event["fields"]["kind"];
            kind == "command_forbidden" || kind == "command_denied"
        })
        .collect()
}

/// A killed exec leaves flight with its event, so its death invents no
/// `entry_abandoned` gap (jail-v2 §7.2, mutation-B09's neighbour).
fn assert_no_entry_abandoned_gap(run: &Run) {
    let abandoned: Vec<&serde_json::Value> = run
        .trace_events()
        .iter()
        .filter(|event| {
            event["fields"]["kind"] == "coverage_gap"
                && event["fields"]["reason"] == "entry_abandoned"
        })
        .collect();
    assert!(
        abandoned.is_empty(),
        "the killed exec was accounted an abandoned entry: {abandoned:#?}"
    );
}

#[test]
fn empty_arguments_do_not_turn_an_allowed_command_into_a_forbidden_one() {
    if !common::live() {
        return;
    }
    for argv in [
        vec!["/usr/bin/true", "", "blocked"],
        vec!["/usr/bin/true", "blocked", ""],
        vec!["/usr/bin/true", "", "blocked", ""],
    ] {
        let result = run(&argv);
        assert_eq!(result.code(), Some(0), "{argv:?}: {}", result.stderr_text());
        assert!(result.receipt_errors().is_empty());
        let receipt = result.receipt_phase("settled").expect("settled receipt");
        assert_eq!(receipt["lifetime"]["tree_empty"], true);
    }
}

#[test]
fn a_matching_child_command_is_still_forbidden() {
    if !common::live() {
        return;
    }
    let result = run(&[
        "/usr/bin/python3",
        "-c",
        "import os; os.execl('/usr/bin/true', 'true', 'blocked')",
    ]);
    assert_eq!(result.code(), Some(1), "{}", result.stderr_text());
    assert!(result.stderr_text().contains("command_forbidden"));
}

#[test]
fn denied_execve_and_execveat_return_eperm_without_running_the_image() {
    if !common::live() {
        return;
    }
    // `deny` returns EPERM while `forbid` also stops the run. Use `deny`
    // here so the child's assertion cannot race the supervisor's stop.
    for image in ["'/usr/bin/true'", "os.open('/usr/bin/true', os.O_RDONLY)"] {
        let script = format!(
            "import os, errno; image={image};\ntry: os.execve(image, ['true', 'blocked'], {{}})\nexcept OSError as e: assert e.errno == errno.EPERM; print('exec-denied', flush=True)"
        );
        let result = run_with_rule(&["/usr/bin/python3", "-c", &script], "deny");
        assert_eq!(result.code(), Some(0), "{}", result.stderr_text());
        // A successful replacement by true would also exit zero, but could
        // never produce this marker from the original Python image.
        assert!(result.stdout_text().contains("exec-denied"));
        assert!(result.receipt_errors().is_empty());
        common::assert_run_records(&result);
        // K21 (mutation-M12 guard): the denial is not only the errno the
        // child observed; the trace carries the `command_denied`
        // `command_rule` note with the pattern and the injected `EPERM`.
        let note = command_rule_notes(&result)
            .into_iter()
            .find(|note| note["fields"]["kind"] == "command_denied")
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "no command_denied note: {}",
                    serde_json::to_string(result.trace_events()).unwrap()
                )
            });
        assert_eq!(note["fields"]["pattern"], "true blocked", "{note}");
        assert_eq!(note["fields"]["errno"], "EPERM", "{note}");
        assert!(
            note["fields"].get("enforcement").is_none(),
            "an entry denial is not an exec kill: {note}"
        );
    }
}

/// One run whose child execs a workspace copy of the fixture: the entry
/// check judges the bare name and passes, the kernel's own image record at
/// the exec stop names the file's full workspace path, which the rule
/// names — a hit only the exec re-check can see. A real file, not a
/// symlink: `/proc/<tid>/exe` resolves symlinks, and a host's `/usr/bin`
/// binaries may be multicall symlinks whose resolved path no rule can name
/// portably.
fn killed_at_exec_run(rule: &str) -> Run {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let image = workspace.join("t");
    std::fs::copy(ouro_fixture::harness::fixture_path(), &image).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = jail.config_dir().join("config.toml");
    std::fs::write(
        &config,
        format!("[jail.commands]\n{rule} = [\"{} **\"]\n", image.display()),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    jail.args(["run", "--profile", "tool", "--observe", "on", "--workspace"])
        .arg(&workspace)
        .args(["--limit", "wall=5s"])
        .trace()
        .target([
            "/usr/bin/python3",
            "-c",
            "import os\nprint('before-exec', flush=True)\nos.execv('t', ['t', 'SHOULD_NOT_PRINT'])",
        ])
        .run()
        .unwrap()
}

/// K31 (audit 6 F5), mutation-B08 guard: an exec whose entry argv passed
/// the rules but whose kernel-installed image hits one is killed at the
/// exec — `SIGKILL` before the image runs an instruction — with a
/// `killed_at_exec` `command_rule` note, the run stopped for a `forbid`,
/// and no `entry_abandoned` gap invented for the killed exec.
#[test]
fn an_exec_the_entry_passed_whose_image_hits_a_forbid_rule_is_killed_at_exec() {
    if !common::live() {
        return;
    }
    let result = killed_at_exec_run("forbid");
    assert_eq!(result.code(), Some(1), "{}", result.stderr_text());
    assert!(
        result.stderr_text().contains("command_forbidden"),
        "{}",
        result.stderr_text()
    );
    assert!(
        !result.stdout_text().contains("SHOULD_NOT_PRINT"),
        "the new image ran: {}",
        result.stdout_text()
    );
    common::assert_run_records(&result);
    let note = command_rule_notes(&result)
        .into_iter()
        .find(|note| note["fields"]["enforcement"] == "killed_at_exec")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no killed_at_exec note: {}",
                serde_json::to_string(result.trace_events()).unwrap()
            )
        });
    assert_eq!(note["fields"]["kind"], "command_forbidden", "{note}");
    assert_eq!(note["fields"]["signal"], "SIGKILL", "{note}");
    assert!(
        note["fields"]["pattern"]
            .as_str()
            .is_some_and(|pattern| pattern.ends_with("workspace/t **")),
        "the pattern must name the exec'd image's workspace path: {note}"
    );
    assert!(
        note["fields"].get("errno").is_none(),
        "a kill carries no errno: {note}"
    );
    assert_no_entry_abandoned_gap(&result);
}

/// The `deny` leg of the same kill: the exec dies by `SIGKILL` — a deny
/// cannot un-run an installed image — and the run continues to completion,
/// the note its only account.
#[test]
fn a_deny_rule_that_only_the_kernel_copy_hits_kills_the_exec_and_the_run_completes() {
    if !common::live() {
        return;
    }
    let result = killed_at_exec_run("deny");
    assert!(
        result.signal() == Some(libc::SIGKILL) || result.code().is_some(),
        "the run ended without a verdict: {}",
        result.stderr_text()
    );
    assert!(
        !result.stderr_text().contains("command_forbidden"),
        "a deny does not stop the run: {}",
        result.stderr_text()
    );
    assert!(
        !result.stdout_text().contains("SHOULD_NOT_PRINT"),
        "the new image ran: {}",
        result.stdout_text()
    );
    common::assert_run_records(&result);
    let note = command_rule_notes(&result)
        .into_iter()
        .find(|note| note["fields"]["enforcement"] == "killed_at_exec")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "no killed_at_exec note: {}",
                serde_json::to_string(result.trace_events()).unwrap()
            )
        });
    assert_eq!(note["fields"]["kind"], "command_denied", "{note}");
    assert_eq!(note["fields"]["signal"], "SIGKILL", "{note}");
    assert_no_entry_abandoned_gap(&result);
    let receipt = common::checked_receipt(
        result
            .receipt_phase("settled")
            .expect("the run settles after the kill"),
    );
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
}
