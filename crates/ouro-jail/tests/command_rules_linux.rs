//! Command filters preserve argv positions through a real Linux exec.
#![cfg(target_os = "linux")]

use ouro_fixture::harness::{Jail, Run};
use std::os::unix::fs::PermissionsExt as _;

mod common;

fn run(argv: &[&str]) -> Run {
    run_with_rule(argv, "forbid")
}

fn run_with_rule(argv: &[&str], rule: &str) -> Run {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let config = jail.config_dir().join("config.toml");
    std::fs::write(
        &config,
        format!("[jail.commands]\n{rule} = [\"true blocked\"]\n"),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    jail.args(["run", "--profile", "tool", "--observe", "on", "--workspace"])
        .arg(&workspace)
        .args(["--limit", "wall=5s"])
        .target(argv)
        .run()
        .unwrap()
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
    }
}
