//! M01–M03: the macOS build runs the shared tests, refuses execution, and gets
//! its inspection exit codes right.
//!
//! §3.2 and §3.3: jail-v1 ships no macOS backend, so `run` refuses with exit
//! 125 before exec — including `--profile none`, because the tree-lifetime
//! guarantees `none` needs are not proved on this platform either. `explain`
//! and `version` still succeed; `doctor` and `run --label-only` report every
//! capability and exit 125.
//!
//! The whole file is gated to macOS: on Linux `run` executes, which makes these
//! expectations wrong, and a test that asserts a refusal where execution works
//! would be a lie about the platform rather than a check of it. The grammar,
//! configuration and `explain` tests, whose claims hold on every platform, are
//! in `portable_cli_config.rs`.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
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
            .env("HOME", self.temp.path())
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
    common::validators()["jail-receipt"]
        .validate(receipt)
        .expect("the refusal receipt satisfies the checked-in schema");
    common::assert_semantic_receipt(receipt);
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
    common::validators()["jail-receipt"]
        .validate(receipt)
        .expect("the refusal receipt satisfies the checked-in schema");
    common::assert_semantic_receipt(receipt);
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
// Channels (§8.2, §13.3)
// ---------------------------------------------------------------------------

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
    let validator = &common::validators()["jail-event"];
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
    let control = harness.temp.path().join("control.ndjson");
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
    let trace = harness.temp.path().join("trace.ndjson");
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
    let validator = &common::validators()["jail-event"];
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
fn the_receipt_flag_writes_an_additional_copy() {
    let harness = Harness::new();
    let copy = harness.temp.path().join("copy.json");
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

// ---------------------------------------------------------------------------
// The review's HIGH findings, each as the exploit that found it
// ---------------------------------------------------------------------------

/// H5: a control consumer that stops reading must not stall the supervisor.
#[test]
fn h5_a_control_consumer_that_stops_reading_cannot_stall_the_supervisor() {
    let harness = Harness::new();
    let control = harness.temp.path().join("control.fifo");
    let status = Command::new("/usr/bin/mkfifo")
        .arg(&control)
        .status()
        .expect("mkfifo runs");
    assert!(status.success());

    // A reader that opens the fifo and then never reads: the supervisor's
    // writes fill the pipe buffer and stay unread.
    let mut idle = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "exec 9<'{}'; exec sleep 30",
            control.to_str().expect("a UTF-8 path")
        ))
        .spawn()
        .expect("the idle reader starts");

    let start = std::time::Instant::now();
    let output = harness.run_with_fds(
        Some(&control),
        None,
        &["run", "--control-fd", "3", "--", "/usr/bin/true"],
    );
    let elapsed = start.elapsed();
    let _ = idle.kill();
    let _ = idle.wait();

    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the supervisor blocked for {elapsed:?} inside the control write"
    );
    assert_eq!(
        output.status.code(),
        Some(125),
        "the refusal still lands: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        harness.receipts().len(),
        1,
        "and the receipt is still written"
    );
}

/// H8: a `--receipt` path outside the state root and every child-visible
/// root is written, and the next run with the same path replaces that copy
/// instead of refusing it as an existing file: the help promises atomic
/// replacement. A copy needs a receipt, which on this platform only the
/// refusal writes; the path validation itself is
/// `portable_cli_config.rs::h8_the_receipt_copy_path_is_validated`.
#[test]
fn h8_a_safe_receipt_copy_path_is_written_and_then_replaced() {
    let harness = Harness::new();
    let fresh = harness.temp.path().join("fresh.json");
    let copy_of_run = || {
        let output = harness.run(&[
            "run",
            "--receipt",
            fresh.to_str().expect("a UTF-8 path"),
            "--",
            "/usr/bin/true",
        ]);
        assert_eq!(
            output.status.code(),
            Some(125),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let copy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fresh).expect("the copy exists"))
                .expect("a receipt");
        assert_eq!(copy["schema"], "ouro.jail.receipt/1");
        copy["attempt_id"].clone()
    };
    let first = copy_of_run();
    let second = copy_of_run();
    assert_ne!(first, second, "the prior receipt copy was replaced");
    assert!(
        harness
            .receipts()
            .iter()
            .any(|receipt| receipt["attempt_id"] == second),
        "the copy is the second attempt's receipt"
    );
}

/// H9 on macOS: a gated run whose gate is held open but never written
/// refuses at probing, before it ever reaches the gate wait, with one refused
/// receipt and exit 125. No signal is sent: on this platform the gate wait is
/// unreachable, so what holds is that nothing past probing ran.
#[test]
fn h9_a_gated_run_refuses_at_probing_before_the_gate_wait() {
    let harness = Harness::new();
    let gate = harness.temp.path().join("gate.fifo");
    let status = Command::new("/usr/bin/mkfifo")
        .arg(&gate)
        .status()
        .expect("mkfifo runs");
    assert!(status.success());

    // A writer that holds the fifo open without sending a frame, so the
    // supervisor sits in the 60-second gate wait.
    let mut holder = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "exec 9>'{}'; exec sleep 30",
            gate.to_str().expect("a UTF-8 path")
        ))
        .spawn()
        .expect("the holder starts");

    let mut child = Command::new("/bin/sh")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", harness.temp.path())
        .env("OURO_DATA_DIR", &harness.data)
        .env("OURO_CONFIG_DIR", &harness.config)
        .current_dir(&harness.work)
        .arg("-c")
        .arg(format!(
            "exec 3<'{}'; shift 0; exec \"$@\"",
            gate.to_str().expect("a UTF-8 path")
        ))
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_ouro-jail"))
        .args([
            "run",
            "--gate-fd",
            "3",
            "--attempt-id",
            "att_00000000-0000-4000-8000-0000000000aa",
            "--",
            "/usr/bin/true",
        ])
        .spawn()
        .expect("the supervisor starts");

    let status = child.wait().expect("the supervisor exits");
    let _ = holder.kill();
    let _ = holder.wait();
    assert_eq!(
        status.code(),
        Some(125),
        "the attempt refuses rather than being killed"
    );
    let receipts = harness.receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["phase"], serde_json::json!("refused"));
}

// ---------------------------------------------------------------------------
// The review's MEDIUM findings
// ---------------------------------------------------------------------------

/// M4: the local trace file is state, so it is private.
#[test]
fn m4_the_local_trace_file_is_created_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let harness = Harness::new();
    let output = harness.run(&["run", "--", "/usr/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    let trace = harness.attempt_dir().join("trace.ndjson");
    let mode = std::fs::metadata(&trace)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "§6.2: files under the state root are 0600");
}

/// A2: the receipt records the operator's explicit grants, not the baseline.
#[test]
fn a2_explicit_operator_grants_reach_the_receipt() {
    let harness = Harness::new();
    let granted = harness.temp.path().join("granted");
    std::fs::create_dir(&granted).expect("a directory");
    let output = harness.run(&[
        "run",
        "--ro",
        granted.to_str().expect("a UTF-8 path"),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(125));
    let receipt = &harness.receipts()[0];
    let grants = receipt["policy"]["grants"].as_array().expect("grants");
    assert_eq!(grants.len(), 1, "one flag, one grant: {grants:?}");
    assert_eq!(grants[0]["kind"], serde_json::json!("read_only"));
    assert_eq!(grants[0]["by"], serde_json::json!("operator"));
    common::validators()["jail-receipt"]
        .validate(receipt)
        .expect("the receipt with grants still satisfies the schema");
    common::assert_semantic_receipt(receipt);

    // A run with no operator flags records none.
    let harness = Harness::new();
    assert_eq!(
        harness.run(&["run", "--", "/usr/bin/true"]).status.code(),
        Some(125)
    );
    assert_eq!(
        harness.receipts()[0]["policy"]["grants"]
            .as_array()
            .expect("grants")
            .len(),
        0,
        "the profile baseline is not a grant"
    );
}

/// L5: the seccomp table subcommand is a Linux artefact.
#[test]
fn l5_the_seccomp_table_subcommand_does_not_exist_on_macos() {
    let harness = Harness::new();
    let output = harness.run(&["__seccomp-table"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown subcommand is a usage error on this platform"
    );
}
