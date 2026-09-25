//! J5-D: no Linux mechanism leaks into portable requirements (jail-v1 §16,
//! J5 exit criterion; §3.1 "It does not ask for `cgroup_v2=true`"; I10).
//!
//! Two claims, both through the real binary:
//!
//! - On every platform, the requirement names a policy derives (what
//!   `explain --json` lists, and what every receipt's `policy.requirements`
//!   carries) name semantics, never a Linux mechanism.
//! - On macOS, where nothing Linux exists, the inspection outputs (`version`,
//!   `explain`, `doctor`, `gc` and `run --label-only`, in both renderings)
//!   carry no Linux vocabulary at all: not the closed set's Linux name, not a
//!   `cgroup` key, not a requirement named after a cgroup.
//!
//! Receipts are M02's (`portable_records.rs`); this file covers the rest.

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

/// Words that name a Linux mechanism rather than a portable semantic.
const LINUX_WORDS: [&str; 10] = [
    "cgroup",
    "pidfd",
    "namespace",
    "seccomp",
    "bwrap",
    "bubblewrap",
    "/proc",
    "linux",
    "ptrace",
    "landlock",
];

fn linux_words_in(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    LINUX_WORDS
        .iter()
        .copied()
        .filter(|word| lower.contains(word))
        .collect()
}

struct Harness {
    temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Harness {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = common::private_tempdir();
        let make = |name: &str, mode: u32| {
            let path = temp.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
            path
        };
        Harness {
            data: make("data", 0o700),
            config: make("config", 0o700),
            work: make("work", 0o755),
            temp,
        }
    }

    /// The built binary with a cleared environment, so the developer's own
    /// `OURO_*` settings cannot reach it.
    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ouro-jail"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.path())
            .env("OURO_DATA_DIR", &self.data)
            .env("OURO_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .args(arguments)
            .output()
            .expect("the binary runs")
    }
}

/// Policies that derive every requirement kind a built-in profile can:
/// containment, observation, the proxy, `none`'s tree boundary, explicit
/// tree ceilings and observation off.
const POLICIES: [&[&str]; 8] = [
    &["--profile", "tool"],
    &["--profile", "tool", "--observe", "off"],
    &[
        "--profile",
        "tool",
        "--limit",
        "pids=64",
        "--limit",
        "mem=1GiB",
    ],
    &["--profile", "tool", "--limit", "cpu=50"],
    &["--profile", "build", "--limit", "mem=1GiB"],
    &["--profile", "agent"],
    &["--profile", "none"],
    &["--profile", "none", "--observe", "off"],
];

#[test]
fn derived_requirement_names_name_no_linux_mechanism() {
    let harness = Harness::new();
    let mut seen = std::collections::BTreeSet::new();
    for policy in POLICIES {
        let mut arguments = vec!["explain", "--json"];
        arguments.extend_from_slice(policy);
        let output = harness.run(&arguments);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{policy:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("explain --json prints JSON");
        for requirement in report["requirements"].as_array().expect("requirements") {
            let name = requirement["name"].as_str().expect("a name").to_owned();
            assert_eq!(
                linux_words_in(&name),
                Vec::<&str>::new(),
                "{policy:?}: the requirement `{name}` names a Linux mechanism"
            );
            seen.insert(name);
        }
    }
    // The tree boundary `none` and every explicit tree ceiling need is the
    // one this rename is about; make sure the matrix actually derived it.
    assert!(
        seen.contains("execution_boundary"),
        "the matrix derives the execution boundary requirement: {seen:?}"
    );
}

/// macOS execution is unsupported in this milestone (§3.2). Its inspection
/// output must say so in portable terms: a macOS operator reading `doctor`
/// or `gc` sees no Linux mechanism named as something this host lacks.
#[cfg(target_os = "macos")]
#[test]
fn macos_inspection_output_carries_no_linux_vocabulary() {
    let harness = Harness::new();
    // A refused run leaves an attempt, so `gc` has an entry to render.
    let refused = harness.run(&["run", "--profile", "none", "--", "/usr/bin/true"]);
    assert_eq!(refused.status.code(), Some(125));
    let mut commands: Vec<Vec<&str>> = vec![
        vec!["version"],
        vec!["version", "--json"],
        vec!["gc", "--dry-run"],
        vec!["gc", "--json", "--dry-run"],
    ];
    for policy in POLICIES {
        for head in [
            &["explain"][..],
            &["explain", "--json"][..],
            &["doctor"][..],
            &["doctor", "--json"][..],
        ] {
            let mut arguments = head.to_vec();
            // `doctor` takes only profile selection (§6.1).
            if head[0] == "doctor" {
                arguments.extend_from_slice(&policy[..2]);
            } else {
                arguments.extend_from_slice(policy);
            }
            commands.push(arguments);
        }
        let mut label = vec!["run", "--label-only"];
        label.extend_from_slice(policy);
        label.extend_from_slice(&["--", "/usr/bin/true"]);
        commands.push(label);
    }
    let gc = harness.run(&["gc", "--json", "--dry-run"]);
    let gc: serde_json::Value = serde_json::from_slice(&gc.stdout).expect("gc --json");
    assert!(
        !gc["entries"].as_array().expect("entries").is_empty(),
        "gc has the refused attempt to render: {gc:#}"
    );
    for arguments in commands {
        let output = harness.run(&arguments);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            linux_words_in(&text),
            Vec::<&str>::new(),
            "{arguments:?} names a Linux mechanism on macOS:\n{text}"
        );
    }
}
