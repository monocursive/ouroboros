//! The command grammar, the configuration layers and the policy `explain`
//! resolves, on every platform (§6.1–§6.4).
//!
//! Nothing here executes a program. Each test reads what `explain` resolved,
//! or stops at a usage error or at a refusal raised while resolving and
//! validating, before any platform work, so every claim holds identically on
//! Linux and macOS and runs on both.
//!
//! The X02 usage-error clauses of the acceptance map cite tests here in the
//! Linux lane, where the conformance verdict reads them; M01's macOS lane
//! cites one too, as proof the shared suites ran there. The refusals that
//! exist only because macOS cannot execute stay in `macos_refusal.rs`.

use std::path::PathBuf;
use std::process::{Command, Output};

mod common;

/// A private state root, a private config directory and an empty workspace.
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

    /// Runs the built binary with a cleared environment, so the developer's own
    /// `OURO_*` settings and `HOME` cannot reach it.
    fn run(&self, arguments: &[&str]) -> Output {
        self.run_with_env(arguments, &[])
    }

    fn run_with_env(&self, arguments: &[&str], extra: &[(&str, &str)]) -> Output {
        clear_group_and_other_write(&self.config);
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-jail"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.path())
            .env("OURO_DATA_DIR", &self.data)
            .env("OURO_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .args(arguments);
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("the binary runs")
    }
}

/// Takes the group and other write bits off everything the test wrote under
/// the configuration directory, as an operator's umask of 022 would have.
/// The tests write with `std::fs::write`, whose mode follows this process's
/// umask; on a host whose umask is 002 (Ubuntu's default for a user with a
/// private group) the binary would rightly refuse those files as writable by
/// group, and each test here is about something else.
fn clear_group_and_other_write(root: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    for entry in std::fs::read_dir(root).expect("the config directory lists") {
        let path = entry.expect("an entry").path();
        let metadata = std::fs::symlink_metadata(&path).expect("an entry's metadata");
        if metadata.file_type().is_symlink() {
            continue;
        }
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & 0o022 != 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & !0o022))
                .expect("permissions");
        }
        if metadata.is_dir() {
            clear_group_and_other_write(&path);
        }
    }
}

// ---------------------------------------------------------------------------
// Usage errors (§6.1, §6.4)
// ---------------------------------------------------------------------------

#[test]
fn usage_errors_exit_two() {
    let harness = Harness::new();
    let attempt = "att_00000000-0000-4000-8000-000000000001";
    for arguments in [
        // PROGRAM is mandatory without --label-only.
        vec!["run"],
        // --label-only rejects the gate and the attempt id.
        vec!["run", "--label-only", "--gate-fd", "9"],
        vec!["run", "--label-only", "--attempt-id", attempt],
        // --attempt-id is only valid with --gate-fd.
        vec!["run", "--attempt-id", attempt, "--", "/usr/bin/true"],
        // Limit grammar.
        vec!["run", "--limit", "wall=0s", "--", "/usr/bin/true"],
        vec!["run", "--limit", "wall=300", "--", "/usr/bin/true"],
        vec!["run", "--limit", "disk=1", "--", "/usr/bin/true"],
        vec![
            "run",
            "--limit",
            "mem=18446744073709551615GiB",
            "--",
            "/usr/bin/true",
        ],
        vec![
            "run",
            "--limit",
            "wall=1m",
            "--limit",
            "wall=2m",
            "--",
            "/usr/bin/true",
        ],
        // Unknown flag values.
        vec!["run", "--observe", "maybe", "--", "/usr/bin/true"],
        vec!["run", "--evidence", "loose", "--", "/usr/bin/true"],
        // An unknown subcommand.
        vec!["frobnicate"],
    ] {
        let output = harness.run(&arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?} must be a usage error, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(
        !harness.data.join("attempts").exists(),
        "a usage error never allocates attempt state"
    );
}

/// §6.1 spells `doctor [--profile NAME|FILE] [--launch NAME] [--workspace
/// PATH] [--scratch PATH] [--json]`; the other policy override flags belong
/// to `run` and `explain`, so doctor rejects them as usage errors instead of
/// silently probing a different plan than the one the operator meant to name.
/// The flags it does spell still parse.
#[test]
fn doctor_takes_no_policy_override_flags() {
    let harness = Harness::new();
    for override_flag in [
        vec!["doctor", "--rw", "/tmp"],
        vec!["doctor", "--ro", "/tmp"],
        vec!["doctor", "--deny-read", "/tmp"],
        vec!["doctor", "--allow-host", "example.com"],
        vec!["doctor", "--limit", "wall=1m"],
        vec!["doctor", "--observe", "off"],
        vec!["doctor", "--evidence", "best-effort"],
    ] {
        let output = harness.run(&override_flag);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{override_flag:?} must be a usage error, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // The spelled grammar including the workspace roots still parses.
    for spelled in [
        vec!["doctor", "--json", "--profile", "tool"],
        vec!["doctor", "--workspace", "/tmp"],
        vec!["doctor", "--scratch", "/tmp", "--profile", "tool"],
    ] {
        let output = harness.run(&spelled);
        assert_ne!(
            output.status.code(),
            Some(2),
            "{spelled:?} is spelled grammar, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // §6.4: doctor runs its probes and exits 0 for a plan this host can run
    // and 125 for one it cannot, never a usage error.
    let output = harness.run(&["doctor", "--json", "--profile", "tool"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["component"], serde_json::json!("ouro-jail"));
    let ready = report["ready"].as_bool().expect("`ready` is a boolean");
    assert_eq!(
        output.status.code(),
        Some(if ready { 0 } else { 125 }),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if cfg!(target_os = "macos") {
        assert!(
            !ready,
            "macOS has no execution backend, so nothing is ready"
        );
    }
}

#[test]
fn a_malformed_attempt_id_is_a_usage_error_not_a_path() {
    let harness = Harness::new();
    for id in [
        "att_00000000-0000-0000-8000-000000000001",
        "att_../../escape",
        "not-an-attempt",
    ] {
        // Supplied together with a gate fd so that the grammar, not the flag
        // combination, is what refuses.
        let output = harness.run(&[
            "run",
            "--gate-fd",
            "0",
            "--attempt-id",
            id,
            "--",
            "/usr/bin/true",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "`{id}` must refuse as a usage error"
        );
    }
    assert!(!harness.data.join("attempts").exists());
}

#[test]
fn an_accepted_limit_reaches_the_snapshot() {
    let harness = Harness::new();
    let output = harness.run(&[
        "explain", "--json", "--limit", "wall=90s", "--limit", "pids=8",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let limits = &report["policy"]["snapshot"]["limits"];
    assert_eq!(limits["wall"]["value"], serde_json::json!("90000"));
    assert_eq!(limits["wall"]["required"], serde_json::json!(true));
    assert_eq!(limits["pids"]["value"], serde_json::json!("8"));
    assert_eq!(
        limits["pids"]["required"],
        serde_json::json!(true),
        "an explicit ceiling is required even when it is lower than the preferred one"
    );
}

// ---------------------------------------------------------------------------
// Configuration (§6.2, §6.3)
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_or_duplicate_configuration_key_refuses() {
    let harness = Harness::new();
    std::fs::write(
        harness.config.join("config.toml"),
        "[jail]\nfuture_key = true\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown key is never silently ignored"
    );

    std::fs::write(
        harness.config.join("config.toml"),
        "[jail.limits]\nwall = \"1m\"\nwall = \"2m\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain"]);
    assert_eq!(output.status.code(), Some(2), "a duplicate key refuses");
}

#[test]
fn a_project_file_may_narrow_but_may_not_select_a_profile() {
    let harness = Harness::new();

    std::fs::write(
        harness.work.join("ouro.toml"),
        "[jail.limits]\nwall = \"1m\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "narrowing is allowed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["limits"]["wall"]["value"],
        serde_json::json!("60000")
    );

    std::fs::write(
        harness.work.join("ouro.toml"),
        "[jail]\nprofile = \"none\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain"]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "a project file may not select a profile"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("jail.profile"),
        "the refusal names the exact key path"
    );

    std::fs::write(
        harness.work.join("ouro.toml"),
        "[jail]\nextends = \"tool\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("jail.extends"));

    std::fs::write(
        harness.work.join("ouro.toml"),
        "[jail.limits]\nwall = \"10h\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain"]);
    assert_eq!(output.status.code(), Some(125), "widening refuses");
    assert!(String::from_utf8_lossy(&output.stderr).contains("jail.limits.wall"));
}

#[test]
fn only_the_documented_environment_variables_are_read() {
    let harness = Harness::new();

    // An allowed variable is applied.
    let output = harness.run_with_env(&["explain", "--json"], &[("OURO_JAIL_OBSERVE", "off")]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["observation"]["mode"],
        serde_json::json!("off")
    );
    assert!(
        !report["requirements"]
            .as_array()
            .expect("requirements")
            .iter()
            .any(|requirement| requirement["name"] == "closed_set_observation"),
        "observation off drops the observer requirement"
    );

    // An invalid value for an allowed variable is a usage error rather than a
    // silent fallback.
    let output = harness.run_with_env(&["explain"], &[("OURO_JAIL_OBSERVE", "maybe")]);
    assert_eq!(output.status.code(), Some(2));

    // Variables outside the allow-list are ignored.
    let baseline = harness.run(&["explain", "--json"]);
    let baseline: serde_json::Value = serde_json::from_slice(&baseline.stdout).expect("JSON");
    let output = harness.run_with_env(
        &["explain", "--json"],
        &[
            ("OURO_JAIL_PROFILE", "none"),
            ("OURO_RW", "/"),
            ("OURO_ALLOW_HOST", "example.com"),
            ("OURO_JAIL_EVIDENCE_MODE", "best-effort"),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["digest"], baseline["policy"]["digest"],
        "no environment variable outside the allow-list changes the policy"
    );
}

#[test]
fn a_profile_file_narrows_its_base_and_may_not_extend_none() {
    let harness = Harness::new();
    let profile = harness.config.join("tight.toml");
    std::fs::write(
        &profile,
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n[limits]\nwall = \"90s\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain", "--json", "--profile", profile.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["limits"]["wall"]["value"],
        serde_json::json!("90000")
    );
    assert_eq!(
        report["policy"]["snapshot"]["profile"],
        serde_json::json!("tool")
    );

    std::fs::write(
        &profile,
        "schema = \"ouro.jail.policy/1\"\nextends = \"none\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain", "--profile", profile.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "only --profile none selects none"
    );

    std::fs::write(
        &profile,
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n[limits]\nwall = \"10h\"\n",
    )
    .expect("the file is written");
    // §6.3 refuses a raised ceiling only in the untrusted project `ouro.toml`;
    // an operator profile file may raise one, as the operator's own `--limit`
    // may, so this resolves.
    let output = harness.run(&["explain", "--json", "--profile", profile.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["limits"]["wall"]["value"],
        serde_json::json!("36000000")
    );
}

/// §6.1: `--profile none` is the only way to select `none`; files cannot
/// select it. `config.toml` is a defaults file, so `jail.profile = "none"`
/// refuses instead of silently dropping the operator onto the uncontained
/// profile, while the explicit flag and a contained configured profile work.
#[test]
fn config_toml_may_not_select_the_none_profile() {
    let harness = Harness::new();
    std::fs::write(
        harness.config.join("config.toml"),
        "[jail]\nprofile = \"none\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain"]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "a defaults file cannot select the uncontained profile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("jail.profile"),
        "the refusal names the exact key path"
    );

    // The explicit act still selects it.
    let output = harness.run(&["explain", "--json", "--profile", "none"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["profile"],
        serde_json::json!("none")
    );

    // A contained profile from the defaults file still applies.
    std::fs::write(
        harness.config.join("config.toml"),
        "[jail]\nprofile = \"tool\"\n",
    )
    .expect("the file is written");
    let output = harness.run(&["explain", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["profile"],
        serde_json::json!("tool")
    );
}

/// §6.2: paths apply relative to the file containing them, and `config.toml`
/// lives in the config directory itself. `./reference` must resolve beside
/// the file, not one directory above it.
#[test]
fn config_toml_paths_anchor_to_the_config_directory() {
    let harness = Harness::new();
    let read_only = || {
        let output = harness.run(&["explain", "--json"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        report["policy"]["snapshot"]["filesystem"]["read_only"]
            .as_array()
            .expect("read_only is a list")
            .clone()
    };
    // The profile's own read-only roots (the runtime roots on Linux, none on
    // macOS) are there either way; what config.toml adds is the claim.
    let baseline = read_only();
    std::fs::write(
        harness.config.join("config.toml"),
        "[jail.filesystem]\nread_only = [\"./reference\"]\n",
    )
    .expect("the file is written");
    let added: Vec<serde_json::Value> = read_only()
        .into_iter()
        .filter(|entry| !baseline.contains(entry))
        .collect();
    let expected = harness.config.join("reference");
    assert_eq!(
        added,
        [serde_json::json!({
            "root": "host",
            "path": expected.to_string_lossy().into_owned(),
        })],
        "the anchor is the directory containing config.toml"
    );
}

#[test]
fn a_profile_selected_in_config_is_resolved_beside_config() {
    let harness = Harness::new();
    std::fs::write(
        harness.config.join("config.toml"),
        "[jail]\nprofile = \"selected.toml\"\n",
    )
    .unwrap();
    std::fs::write(
        harness.config.join("selected.toml"),
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n",
    )
    .unwrap();
    let output = harness.run(&["explain", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["policy"]["snapshot"]["profile"], "tool");
}

/// §6.2/§6.3: `[jail_host.network] translation_prefixes` is merged into proxy
/// policy before digest creation, so equivalent spellings must render as one
/// canonical RFC 5952 form — and text that is not an IPv6 CIDR refuses with
/// the exact key path instead of entering the snapshot as opaque input.
#[test]
fn translation_prefixes_are_canonicalized_before_the_digest() {
    let harness = Harness::new();
    let write_config = |prefixes: &str| {
        // Prefixes merge into proxy policy only, so the trusted defaults file
        // also selects `agent`, the one profile with a proxy.
        std::fs::write(
            harness.config.join("config.toml"),
            format!(
                "[jail]\nprofile = \"agent\"\n\n[jail_host.network]\ntranslation_prefixes = [{prefixes}]\n"
            ),
        )
        .expect("the file is written");
    };

    write_config("\"2001:0db8::/96\"");
    let output = harness.run(&["explain", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["snapshot"]["network"]["translation_prefixes"],
        serde_json::json!(["2001:db8::/96"]),
        "the leading zero group is compressed and lowercased"
    );
    let canonical_digest = report["policy"]["digest"].clone();

    // An equivalent spelling of the same prefix produces the same digest.
    write_config("\"2001:db8:0:0:0:0:0:0/96\"");
    let output = harness.run(&["explain", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        report["policy"]["digest"], canonical_digest,
        "equivalent spellings have one digest"
    );

    // Anything that is not an IPv6 CIDR refuses, naming the key.
    write_config("\"banana\"");
    let output = harness.run(&["explain"]);
    assert_eq!(output.status.code(), Some(2), "a non-CIDR entry refuses");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("jail_host.network.translation_prefixes"),
        "the refusal names the exact key path"
    );
}

#[test]
fn the_build_profile_requires_an_explicit_memory_ceiling() {
    let harness = Harness::new();
    let output = harness.run(&["explain", "--profile", "build"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the defaults table makes mem required for build"
    );
    let output = harness.run(&["explain", "--profile", "build", "--limit", "mem=512MiB"]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn a_contained_profile_rejects_a_host_grant() {
    let harness = Harness::new();
    let output = harness.run(&["explain", "--allow-host", "example.com"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "`tool` has no proxy and accepts no host grants"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("network.allow"));
}

// ---------------------------------------------------------------------------
// Channels (§8.2, §13.3)
// ---------------------------------------------------------------------------

#[test]
fn an_invalid_channel_descriptor_refuses_before_preparation() {
    let harness = Harness::new();
    for arguments in [
        // stdio is never a private channel.
        vec!["run", "--control-fd", "1", "--", "/usr/bin/true"],
        // A descriptor that is not open at all.
        vec!["run", "--control-fd", "9", "--", "/usr/bin/true"],
    ] {
        let output = harness.run(&arguments);
        assert_eq!(
            output.status.code(),
            Some(125),
            "{arguments:?} must refuse: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("invalid_fd"),
            "{arguments:?} names the fd problem"
        );
    }
    assert!(
        !harness.data.join("attempts").exists(),
        "fd validation happens before any attempt state exists"
    );
}

// ---------------------------------------------------------------------------
// The review's HIGH findings, each as the exploit that found it
// ---------------------------------------------------------------------------

/// H2: only absence means "no project file".
///
/// §2 makes that file untrusted input, and silently ignoring a tightening the
/// operator or the project asked for is the one outcome that must not
/// happen. So an unreadable file, a directory, a dangling symlink or an I/O
/// error refuses, rather than discarding the whole narrowing layer and
/// exiting 0 with the wider policy.
#[test]
fn h2_an_unusable_project_file_refuses_instead_of_being_ignored() {
    use std::os::unix::fs::PermissionsExt as _;

    let narrowing = "[jail.limits]\nwall = \"1m\"\n";
    let harness = Harness::new();
    std::fs::write(harness.work.join("ouro.toml"), narrowing).expect("written");
    let baseline = harness.run(&["explain", "--json"]);
    assert_eq!(baseline.status.code(), Some(0));
    let baseline: serde_json::Value = serde_json::from_slice(&baseline.stdout).expect("JSON");
    assert_eq!(
        baseline["policy"]["snapshot"]["limits"]["wall"]["value"],
        serde_json::json!("60000"),
        "the readable file narrows, so the unreadable cases below are the change"
    );

    // Unreadable.
    let harness = Harness::new();
    let path = harness.work.join("ouro.toml");
    std::fs::write(&path, narrowing).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("mode");
    let output = harness.run(&["explain"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unreadable project file must refuse: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid_config"));

    // A directory.
    let harness = Harness::new();
    std::fs::create_dir(harness.work.join("ouro.toml")).expect("a directory");
    assert_eq!(harness.run(&["explain"]).status.code(), Some(2));

    // A dangling symlink.
    let harness = Harness::new();
    std::os::unix::fs::symlink("nowhere", harness.work.join("ouro.toml")).expect("a symlink");
    assert_eq!(harness.run(&["explain"]).status.code(), Some(2));

    // A symlink to a real file is also refused: the open is `O_NOFOLLOW`, so
    // the contained party cannot point the policy file anywhere it likes.
    let harness = Harness::new();
    let real = harness.work.join("real.toml");
    std::fs::write(&real, narrowing).expect("written");
    std::os::unix::fs::symlink(&real, harness.work.join("ouro.toml")).expect("a symlink");
    assert_eq!(harness.run(&["explain"]).status.code(), Some(2));
}

/// H3: the project file read is bounded, and a fifo cannot hang the supervisor.
#[test]
fn h3_the_project_file_read_is_bounded_and_never_blocks() {
    let harness = Harness::new();
    let path = harness.work.join("ouro.toml");
    // A fifo: a plain read waits for a writer, and none ever comes.
    let status = Command::new("/usr/bin/mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo runs");
    assert!(status.success());
    let start = std::time::Instant::now();
    let output = harness.run(&["explain"]);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "the read must not block on a fifo"
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("regular file"),
        "the refusal names the reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // A file past the cap is refused rather than read into memory.
    let harness = Harness::new();
    let big = vec![b'#'; 512 * 1024];
    std::fs::write(harness.work.join("ouro.toml"), &big).expect("written");
    let output = harness.run(&["explain"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("maximum"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// H7: the state root may not live inside anything the child can see.
#[test]
fn h7_a_state_root_inside_a_grant_refuses() {
    use std::os::unix::fs::PermissionsExt as _;

    let harness = Harness::new();
    let inside = harness.work.join("state");
    std::fs::create_dir(&inside).expect("a directory");
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o700)).expect("mode");

    let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-jail"));
    let output = command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", harness.temp.path())
        .env("OURO_DATA_DIR", &inside)
        .env("OURO_CONFIG_DIR", &harness.config)
        .current_dir(&harness.work)
        .args(["run", "--", "/usr/bin/true"])
        .output()
        .expect("the binary runs");
    assert_eq!(
        output.status.code(),
        Some(125),
        "state inside the workspace must refuse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsafe_state_path"), "{stderr}");
    assert!(stderr.contains("overlaps"), "{stderr}");
    assert!(
        !inside.join("attempts").exists(),
        "nothing is allocated under an unsafe state root"
    );
}

/// H8: `--receipt PATH` is validated before anything is written.
///
/// That a safe path is then written, and replaced by the next run, needs a
/// run that ends with a receipt: `macos_refusal.rs` proves it on the refusal.
#[test]
fn h8_the_receipt_copy_path_is_validated() {
    let harness = Harness::new();

    // Inside the workspace, which the child can see.
    let output = harness.run(&[
        "run",
        "--receipt",
        harness
            .work
            .join("copy.json")
            .to_str()
            .expect("a UTF-8 path"),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("child-visible"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Inside the state root, where the canonical receipt already lives.
    let output = harness.run(&[
        "run",
        "--receipt",
        harness
            .data
            .join("copy.json")
            .to_str()
            .expect("a UTF-8 path"),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("state root"));

    // An existing file is never replaced.
    let existing = harness.temp.path().join("important.json");
    std::fs::write(&existing, b"someone else's file").expect("written");
    let output = harness.run(&[
        "run",
        "--receipt",
        existing.to_str().expect("a UTF-8 path"),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already exists"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&existing).expect("readable"),
        b"someone else's file",
        "the file is untouched"
    );

    // A symlink is never followed.
    let link = harness.temp.path().join("link.json");
    std::os::unix::fs::symlink(&existing, &link).expect("a symlink");
    let output = harness.run(&[
        "run",
        "--receipt",
        link.to_str().expect("a UTF-8 path"),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already exists"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&existing).expect("readable"),
        b"someone else's file"
    );
    assert!(
        !harness.data.join("attempts").exists(),
        "a refused copy path is refused before any attempt state exists"
    );
}

// ---------------------------------------------------------------------------
// The review's MEDIUM findings
// ---------------------------------------------------------------------------

/// M2: one directory has one digest, however it is spelled.
#[test]
fn m2_equivalent_workspace_spellings_have_one_digest() {
    let harness = Harness::new();
    let canonical = std::fs::canonicalize(&harness.work).expect("canonical");
    let digest_of = |workspace: &str| {
        let output = harness.run(&["explain", "--json", "--workspace", workspace]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{workspace}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        report["policy"]["digest"]
            .as_str()
            .expect("a digest")
            .to_owned()
    };
    let expected = digest_of(canonical.to_str().expect("a UTF-8 path"));
    for spelling in [
        format!("{}/", harness.work.display()),
        format!("{}/.", harness.work.display()),
        format!("{}//", harness.work.display()),
        format!("{}/../{}", harness.work.display(), "work"),
        // The spelling the harness made, uncanonicalized: on macOS the
        // temporary directory lies behind the `/var` symlink.
        harness.work.display().to_string(),
    ] {
        assert_eq!(digest_of(&spelling), expected, "`{spelling}`");
    }
}

/// L2: `--workspace` must name a directory.
#[test]
fn l2_a_workspace_that_is_not_a_directory_refuses() {
    let harness = Harness::new();
    let file = harness.temp.path().join("a-file");
    std::fs::write(&file, b"x").expect("written");
    let output = harness.run(&[
        "explain",
        "--workspace",
        file.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not a directory"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = harness.run(&["explain", "--workspace", "/nonexistent/anywhere"]);
    assert_eq!(output.status.code(), Some(2));
}

/// M6: a `schema` this build does not implement is never interpreted.
#[test]
fn m6_an_unknown_policy_schema_refuses() {
    for (file, body) in [
        ("config", "[jail]\nschema = \"ouro.jail.policy/999\"\n"),
        ("project", "[jail]\nschema = \"ouro.jail.policy/999\"\n"),
    ] {
        let harness = Harness::new();
        if file == "config" {
            std::fs::write(harness.config.join("config.toml"), body).expect("written");
        } else {
            std::fs::write(harness.work.join("ouro.toml"), body).expect("written");
        }
        let output = harness.run(&["explain"]);
        assert_eq!(output.status.code(), Some(2), "{file}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("jail.schema"), "{file}: {stderr}");
    }
    // The right schema is accepted, so the check is about the value.
    let harness = Harness::new();
    std::fs::write(
        harness.work.join("ouro.toml"),
        "[jail]\nschema = \"ouro.jail.policy/1\"\n[jail.limits]\nwall = \"1m\"\n",
    )
    .expect("written");
    assert_eq!(harness.run(&["explain"]).status.code(), Some(0));
}

/// M7: `gc` validates the state root it is about to enumerate.
#[test]
fn m7_gc_refuses_a_state_root_that_is_not_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let harness = Harness::new();
    std::fs::set_permissions(&harness.data, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let output = harness.run(&["gc", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "§6.4: gc uses 1 for failed state access"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsafe_state_path"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "no clean scan is printed for a root that failed its checks"
    );
}

/// M13: inspection output carries environment names, never values.
#[test]
fn m13_explain_prints_environment_names_only() {
    let harness = Harness::new();
    let output = harness.run_with_env(&["explain", "--json"], &[("PATH", "/usr/bin:/secret-dir")]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !text.contains("/secret-dir"),
        "an environment value reached inspection output"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let bindings = report["policy"]["snapshot"]["environment"]["bindings"]
        .as_array()
        .expect("bindings");
    assert!(!bindings.is_empty(), "the names are still there");
    for binding in bindings {
        assert!(binding["name"].is_string());
        assert!(
            binding.get("value").is_none(),
            "no binding carries a value: {binding}"
        );
    }
    assert_eq!(
        report["policy"]["environment_values"],
        serde_json::json!("omitted"),
        "and the omission is stated rather than left to be inferred"
    );
}
