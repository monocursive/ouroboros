//! M01–M03: the macOS build runs the shared tests, refuses execution, and gets
//! its inspection exit codes right.
//!
//! §3.2 and §3.3: this milestone ships no macOS backend, so `run` refuses with
//! exit 125 before exec — including `--profile none`, because the tree-lifetime
//! guarantees `none` needs are not proved on this platform either. `explain`
//! and `version` still succeed; `doctor` and `run --label-only` report every
//! capability and exit 125.
//!
//! The whole file is gated to macOS: on Linux the execution slice makes these
//! expectations wrong, and a test that asserts a refusal where execution works
//! would be a lie about the platform rather than a check of it.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::{Registry, Resource, Validator};

/// A private state root, a private config directory and an empty workspace.
struct Harness {
    _temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Harness {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().expect("a temporary directory");
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
            _temp: temp,
        }
    }

    /// Runs the built binary with a cleared environment, so the developer's own
    /// `OURO_*` settings and `HOME` cannot reach it.
    fn run(&self, arguments: &[&str]) -> Output {
        self.run_with_env(arguments, &[])
    }

    fn run_with_env(&self, arguments: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ouro-jail"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self._temp.path())
            .env("OURO_DATA_DIR", &self.data)
            .env("OURO_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .args(arguments);
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("the binary runs")
    }

    /// Runs the binary with extra descriptors opened by a shell, which is the
    /// only portable way to hand a child an fd above stdio without unsafe code.
    fn run_with_fds(
        &self,
        control: Option<&Path>,
        trace: Option<&Path>,
        arguments: &[&str],
    ) -> Output {
        let mut script = String::new();
        let mut files: Vec<String> = Vec::new();
        let mut shift = 0;
        if let Some(path) = control {
            shift += 1;
            script.push_str(&format!("exec 3>\"${shift}\"; "));
            files.push(path.to_string_lossy().into_owned());
        }
        if let Some(path) = trace {
            shift += 1;
            script.push_str(&format!("exec 4>\"${shift}\"; "));
            files.push(path.to_string_lossy().into_owned());
        }
        script.push_str(&format!("shift {shift}; exec \"$@\""));

        let mut command = Command::new("/bin/sh");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self._temp.path())
            .env("OURO_DATA_DIR", &self.data)
            .env("OURO_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .arg("-c")
            .arg(script)
            .arg("sh");
        for file in &files {
            command.arg(file);
        }
        command.arg(env!("CARGO_BIN_EXE_ouro-jail"));
        command.args(arguments);
        command.output().expect("the shell wrapper runs")
    }

    fn attempt_dir(&self) -> PathBuf {
        std::fs::read_dir(self.data.join("attempts"))
            .expect("the attempts directory exists")
            .next()
            .expect("one attempt")
            .expect("a directory entry")
            .path()
    }

    fn receipts(&self) -> Vec<serde_json::Value> {
        let attempts = self.data.join("attempts");
        let Ok(listing) = std::fs::read_dir(&attempts) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in listing.flatten() {
            let path = entry.path().join("jail.json");
            if let Ok(text) = std::fs::read_to_string(&path) {
                out.push(serde_json::from_str(&text).expect("a receipt is valid JSON"));
            }
        }
        out
    }
}

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the specification directory exists")
}

fn receipt_validator() -> Validator {
    let mut schemas: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for entry in std::fs::read_dir(specs_dir()).expect("readable") {
        let path = entry.expect("an entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(".schema.json") {
            let text = std::fs::read_to_string(&path).expect("readable");
            schemas.insert(
                name.to_owned(),
                serde_json::from_str(&text).expect("valid JSON"),
            );
        }
    }
    let pairs: Vec<(String, Resource)> = schemas
        .values()
        .map(|schema| {
            (
                schema["$id"].as_str().expect("an $id").to_owned(),
                Resource::from_contents(schema.clone()),
            )
        })
        .collect();
    let registry: &'static Registry = Box::leak(Box::new(
        Registry::new()
            .extend(pairs)
            .expect("valid URIs")
            .prepare()
            .expect("the registry resolves"),
    ));
    jsonschema::options()
        .with_registry(registry)
        .should_validate_formats(true)
        .build(&schemas["jail-receipt.schema.json"])
        .expect("the receipt schema compiles")
}

fn assert_refusal_tuple(receipt: &serde_json::Value, containment: &str, protection: &str) {
    assert_eq!(receipt["phase"], serde_json::json!("refused"));
    assert_eq!(receipt["containment"], serde_json::json!(containment));
    assert_eq!(receipt["child_protection"], serde_json::json!(protection));
    assert_eq!(receipt["exec_observed"], serde_json::json!(false));
    assert_eq!(
        receipt["lifetime"]["boundary"],
        serde_json::json!("pending")
    );
    assert_eq!(
        receipt["lifetime"]["verification_scope"],
        serde_json::Value::Null
    );
    assert_eq!(receipt["lifetime"]["tree_empty"], serde_json::Value::Null);
    assert_eq!(receipt["lifetime"]["verified_at"], serde_json::Value::Null);
    assert_eq!(
        receipt["lifetime"]["integrity"],
        serde_json::json!("pending")
    );
    assert_eq!(receipt["process"], serde_json::Value::Null);
    assert_eq!(receipt["outcome"]["kind"], serde_json::json!("refused"));
    assert_eq!(receipt["revision"], serde_json::json!(1));
    assert_eq!(
        receipt["outcome"]["error"]["code"],
        serde_json::json!("unsupported_platform")
    );
    assert_eq!(
        receipt["outcome"]["error"]["remediation_category"],
        serde_json::json!("unsupported")
    );
    assert_eq!(receipt["platform"]["os"], serde_json::json!("macos"));
    assert_eq!(receipt["observer"]["attached"], serde_json::json!(false));
    for class in ["exec", "fs.write", "fs.deny", "net", "limits", "proxy.net"] {
        assert_eq!(
            receipt["coverage"][class]["status"],
            serde_json::json!("unsupported"),
            "{class} cannot be anything else when nothing attached"
        );
        assert_eq!(
            receipt["coverage"][class]["observed_count"],
            serde_json::Value::Null
        );
    }
}

// ---------------------------------------------------------------------------
// M01
// ---------------------------------------------------------------------------

#[test]
fn m01_run_refuses_before_exec_and_the_marker_never_appears() {
    let harness = Harness::new();
    let marker = harness.work.join("marker");
    let output = harness.run(&[
        "run",
        "--",
        "/usr/bin/touch",
        marker.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !marker.exists(),
        "no user command may execute before the boundary exists (I01)"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported_platform"),
        "the diagnostic names the refusal code"
    );

    let receipts = harness.receipts();
    assert_eq!(receipts.len(), 1, "exactly one attempt was recorded");
    let receipt = &receipts[0];
    receipt_validator()
        .validate(receipt)
        .expect("the refusal receipt satisfies the checked-in schema");
    assert_refusal_tuple(receipt, "pending", "pending");
    assert!(
        receipt["argv_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")),
        "the literal argv is recorded as a digest, never as text"
    );
    let text = serde_json::to_string(receipt).expect("serializes");
    assert!(
        !text.contains("/usr/bin/touch") && !text.contains("marker"),
        "raw argv never enters a receipt (I09)"
    );
}

#[test]
fn m01_none_also_refuses_and_stays_unprotected() {
    let harness = Harness::new();
    let marker = harness.work.join("marker-none");
    let output = harness.run(&[
        "run",
        "--profile",
        "none",
        "--",
        "/usr/bin/touch",
        marker.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(125));
    assert!(!marker.exists());

    let receipts = harness.receipts();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    receipt_validator()
        .validate(receipt)
        .expect("the refusal receipt satisfies the checked-in schema");
    // I08: `none` is unprotected in every receipt, including this refusal.
    assert_refusal_tuple(receipt, "none", "unprotected");
    assert_eq!(
        receipt["applied"]["network"]["mode"],
        serde_json::json!("host")
    );
    assert_eq!(receipt["applied"]["filesystem"], serde_json::Value::Null);
    assert_eq!(receipt["applied"]["syscalls"], serde_json::Value::Null);
}

#[test]
fn m01_the_attempt_directory_holds_the_policy_and_the_claim() {
    let harness = Harness::new();
    let output = harness.run(&["run", "--", "/usr/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    let attempts = harness.data.join("attempts");
    let entry = std::fs::read_dir(&attempts)
        .expect("the attempts directory exists")
        .next()
        .expect("one attempt")
        .expect("a directory entry");
    for name in ["jail.json", "jail-state.json", "policy.json", "jail.lock"] {
        assert!(
            entry.path().join(name).exists(),
            "{name} is part of the attempt layout"
        );
    }
    let policy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(entry.path().join("policy.json")).unwrap())
            .expect("valid JSON");
    assert_eq!(
        policy["schema"],
        serde_json::json!("ouro.jail.policy-file/1")
    );
    assert_eq!(
        policy["snapshot"]["schema"],
        serde_json::json!("ouro.jail.policy-snapshot/1")
    );
    let receipt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(entry.path().join("jail.json")).unwrap())
            .expect("valid JSON");
    assert_eq!(
        receipt["policy"]["digest"], policy["policy_digest"],
        "the receipt carries the digest of the stored snapshot"
    );
}

// ---------------------------------------------------------------------------
// M03
// ---------------------------------------------------------------------------

#[test]
fn m03_inspection_commands_use_the_exit_codes_of_section_six_four() {
    let harness = Harness::new();

    for arguments in [
        vec!["version"],
        vec!["version", "--json"],
        vec!["explain"],
        vec!["explain", "--json"],
        vec!["gc"],
        vec!["gc", "--json", "--dry-run"],
    ] {
        let output = harness.run(&arguments);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{arguments:?} must succeed on macOS: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    for (arguments, json) in [
        (vec!["doctor"], false),
        (vec!["doctor", "--json"], true),
        (vec!["run", "--label-only"], false),
    ] {
        let output = harness.run(&arguments);
        assert_eq!(
            output.status.code(),
            Some(125),
            "{arguments:?} must report an unsupported plan"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        if json {
            let report: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("JSON on stdout");
            let rows = report["capabilities"].as_array().expect("capability rows");
            assert!(
                rows.iter()
                    .any(|row| row["name"] == "tree_termination" && row["status"] == "unsupported"),
                "{arguments:?} still describes each capability: {stdout}"
            );
        } else {
            assert!(
                stdout.contains("capability tree_termination unsupported"),
                "{arguments:?} still describes each capability: {stdout}"
            );
        }
    }
}

#[test]
fn m03_explain_distinguishes_requested_policy_from_unmeasured_capability() {
    let harness = Harness::new();
    let output = harness.run(&["explain", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("explain prints JSON on stdout");
    assert_eq!(report["probed"], serde_json::json!(false));
    assert_eq!(report["capabilities"]["measured"], serde_json::json!(false));
    assert_eq!(
        report["policy"]["snapshot"]["platform"],
        serde_json::json!("macos")
    );
    let requirements = report["requirements"].as_array().expect("requirements");
    assert!(!requirements.is_empty());
    for requirement in requirements {
        assert_eq!(
            requirement["measurement"],
            serde_json::json!("unmeasured"),
            "explain never claims a measurement it did not make"
        );
    }
    // And it really did not probe: no attempt state was created.
    assert!(!harness.data.join("attempts").exists());
}

#[test]
fn m03_doctor_reports_every_requirement_as_unsupported_and_unmeasured() {
    let harness = Harness::new();
    let output = harness.run(&["doctor", "--json"]);
    assert_eq!(output.status.code(), Some(125));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor prints JSON on stdout");
    assert_eq!(report["ready"], serde_json::json!(false));
    let capabilities = report["capabilities"].as_array().expect("capabilities");
    assert!(!capabilities.is_empty());
    for capability in capabilities {
        assert_eq!(capability["status"], serde_json::json!("unsupported"));
        assert_eq!(
            capability["measured_at"],
            serde_json::Value::Null,
            "no probe ran, so there is no measurement time"
        );
        assert_eq!(
            capability["reason_code"],
            serde_json::json!("unsupported_platform")
        );
    }
    let names: Vec<&str> = capabilities
        .iter()
        .map(|capability| capability["name"].as_str().expect("a name"))
        .collect();
    for requirement in report["requirements"].as_array().expect("requirements") {
        assert!(
            names.contains(&requirement.as_str().expect("a name")),
            "every requirement gets a capability row"
        );
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
    let output = harness.run(&["explain", "--profile", profile.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "a profile file may only narrow"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("limits.wall"));
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

fn event_validator() -> Validator {
    let mut schemas: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for entry in std::fs::read_dir(specs_dir()).expect("readable") {
        let path = entry.expect("an entry").path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(".schema.json") {
            let text = std::fs::read_to_string(&path).expect("readable");
            schemas.insert(
                name.to_owned(),
                serde_json::from_str(&text).expect("valid JSON"),
            );
        }
    }
    let pairs: Vec<(String, Resource)> = schemas
        .values()
        .map(|schema| {
            (
                schema["$id"].as_str().expect("an $id").to_owned(),
                Resource::from_contents(schema.clone()),
            )
        })
        .collect();
    let registry: &'static Registry = Box::leak(Box::new(
        Registry::new()
            .extend(pairs)
            .expect("valid URIs")
            .prepare()
            .expect("the registry resolves"),
    ));
    jsonschema::options()
        .with_registry(registry)
        .should_validate_formats(true)
        .build(&schemas["jail-event.schema.json"])
        .expect("the jail event schema compiles")
}

fn ndjson(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("the stream is readable")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("each frame is one JSON object"))
        .collect()
}

#[test]
fn the_local_trace_records_the_wrapper_events_of_a_refusal() {
    let harness = Harness::new();
    let output = harness.run(&["run", "--", "/usr/bin/true"]);
    assert_eq!(output.status.code(), Some(125));

    let events = ndjson(&harness.attempt_dir().join("trace.ndjson"));
    assert_eq!(events.len(), 2, "a lifecycle note and the receipt event");
    let validator = event_validator();
    for event in &events {
        validator
            .validate(event)
            .expect("every wrapper event satisfies the jail producer schema");
        assert_eq!(event["source"], serde_json::json!("wrapper"));
    }
    assert_eq!(events[0]["source_seq"], serde_json::json!(1));
    assert_eq!(events[0]["fields"]["kind"], serde_json::json!("lifecycle"));
    assert_eq!(
        events[0]["fields"]["transition"],
        serde_json::json!("refused")
    );
    assert_eq!(events[1]["source_seq"], serde_json::json!(2));
    assert_eq!(events[1]["operation"], serde_json::json!("jail.receipt"));
    assert_eq!(events[1]["fields"]["phase"], serde_json::json!("refused"));
    assert!(
        events[1]["fields"]["receipt_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
}

#[test]
fn a_control_descriptor_receives_the_refused_message() {
    let harness = Harness::new();
    let control = harness._temp.path().join("control.ndjson");
    let output = harness.run_with_fds(
        Some(&control),
        None,
        &["run", "--control-fd", "3", "--", "/usr/bin/true"],
    );
    assert_eq!(
        output.status.code(),
        Some(125),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let messages = ndjson(&control);
    assert_eq!(messages.len(), 1, "one control message for one refusal");
    let message = &messages[0];
    assert_eq!(message["schema"], serde_json::json!("ouro.jail.control/1"));
    assert_eq!(message["kind"], serde_json::json!("refused"));
    assert_eq!(message["receipt_phase"], serde_json::json!("refused"));
    assert_eq!(message["seq"], serde_json::json!(1));
    assert_eq!(
        message["error"]["code"],
        serde_json::json!("unsupported_platform")
    );
    assert_eq!(
        message["attempt_id"],
        harness.receipts()[0]["attempt_id"],
        "the control message names the attempt it reports on"
    );
    let text = serde_json::to_string(message).expect("serializes");
    assert!(
        !text.contains("/usr/bin/true"),
        "a control message never carries raw argv (§8.2)"
    );
}

#[test]
fn a_trace_descriptor_replaces_the_local_stream_rather_than_duplicating_it() {
    let harness = Harness::new();
    let trace = harness._temp.path().join("trace.ndjson");
    let output = harness.run_with_fds(
        None,
        Some(&trace),
        &["run", "--trace-fd", "4", "--", "/usr/bin/true"],
    );
    assert_eq!(
        output.status.code(),
        Some(125),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = ndjson(&trace);
    assert_eq!(
        events.len(),
        2,
        "the stream went to the supplied descriptor"
    );
    let validator = event_validator();
    for event in &events {
        validator
            .validate(event)
            .expect("valid jail producer events");
    }
    assert!(
        !harness.attempt_dir().join("trace.ndjson").exists(),
        "§13.3: with --trace-fd the full trace is not also written locally"
    );
}

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

#[test]
fn the_receipt_flag_writes_an_additional_copy() {
    let harness = Harness::new();
    let copy = harness._temp.path().join("copy.json");
    let output = harness.run(&[
        "run",
        "--receipt",
        copy.to_str().expect("a UTF-8 path"),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(125));
    let copied: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&copy).expect("the copy exists"))
            .expect("valid JSON");
    assert_eq!(
        copied,
        harness.receipts()[0],
        "the copy is the canonical receipt, not a different rendering"
    );
}
