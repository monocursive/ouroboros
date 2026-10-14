//! The bound every reader holds a receipt and `policy.json` to
//! (`cleanup::RECEIPT_MAX`), over whole runs: the enforced receipt the worker
//! persists, a policy too large to record, a refusal that would pass the
//! bound, and a boundary whose report no receipt could hold. Simulated
//! platform, portable.

use std::path::{Path, PathBuf};

use clap::Parser as _;
use ouro_jail::cleanup::{RECEIPT_MAX, RECEIPT_WRITE_MAX};
use ouro_jail::config::EnvSettings;
use ouro_jail::platform::{RunEvent, StopReason};
use ouro_jail::records::{ErrorCode, ErrorStage, Phase};
use ouro_jail::{cli, supervisor};
use serde_json::Value;

mod common;
use common::sim;

/// A private state root with a workspace in it.
fn roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = common::private_tempdir();
    let root_path = root.path().canonicalize().unwrap();
    let workspace = root_path.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    (root, root_path, workspace)
}

/// A context over `platform` with its state under `root`.
fn context(platform: sim::ScriptedPlatform, root: &Path, workspace: &Path) -> supervisor::Context {
    supervisor::Context {
        platform: Box::new(platform),
        env_settings: EnvSettings {
            config_dir: Some(root.join("config")),
            data_dir: Some(root.join("data")),
            ..Default::default()
        },
        cwd: workspace.to_path_buf(),
        home: None,
        env_lookup: Box::new(|_| None),
    }
}

fn command(arguments: &[String]) -> cli::Command {
    let mut all = vec!["ouro-jail".to_owned()];
    all.extend_from_slice(arguments);
    cli::Cli::parse_from(all).command
}

/// §7: a receipt past the bound would be one no reader accepts, so the
/// enforced receipt is refused before the worker writes it, and that failed
/// persistence after exec stops the tree (`state_write_failed`). The
/// receipt on disk stays the last one within the bound: the prepared one.
#[test]
fn an_enforced_receipt_past_the_bound_stops_the_run() {
    let (_root, root_path, workspace) = roots();
    // A best-effort loss is recorded without a stop; its reason alone takes
    // every later receipt past the bound.
    let platform = sim::ScriptedPlatform::new("bound simulation", sim::namespace_boundary())
        .events([
            RunEvent::EvidenceLost {
                reason: "x".repeat(usize::try_from(RECEIPT_MAX).unwrap()),
                after_target_end: false,
            },
            RunEvent::ExecConfirmed,
        ])
        .then(RunEvent::TargetExited { code: 0 });
    let calls = platform.calls.clone();
    let cli::Command::Run(args) = command(&[
        "run".to_owned(),
        "--evidence".to_owned(),
        "best-effort".to_owned(),
        "--workspace".to_owned(),
        workspace.display().to_string(),
        "--".to_owned(),
        "simulated-target".to_owned(),
    ]) else {
        unreachable!()
    };
    let report = supervisor::run(&context(platform, &root_path, &workspace), &args);
    assert_eq!(
        *calls.stops.lock().unwrap(),
        [StopReason::StateWriteFailed],
        "{:?}",
        report.error
    );
    assert_ne!(report.exit_code, 0);
    let bytes = std::fs::read(report.receipt_path.expect("a claimed attempt")).unwrap();
    assert!(u64::try_from(bytes.len()).unwrap() <= RECEIPT_MAX);
    let receipt: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(receipt["phase"], "prepared", "{receipt:#}");
}

/// §7 and I01: a policy whose records would pass the bound is refused while
/// it is resolved, with the configuration's code, so `explain`,
/// `--label-only` and `run` agree, and `run` claims no attempt it could not
/// record a refusal for. (`doctor` resolves through the same check, but its
/// command line takes no grants, and the files a policy is read from are
/// each capped far below the bound.)
#[test]
fn a_policy_too_large_to_record_is_refused_before_any_claim() {
    let (_root, root_path, workspace) = roots();
    // 130 read-only grants of about 24 KiB each: the receipt carries each
    // grant, beside the room its mount table and the run may take.
    let deep = vec!["d".repeat(200); 120].join("/");
    let mut selection = vec!["--workspace".to_owned(), workspace.display().to_string()];
    for index in 0..130 {
        selection.push("--ro".to_owned());
        selection.push(format!("{}/elsewhere/{deep}/{index}", root_path.display()));
    }
    let too_large = |error: &ouro_jail::records::JailError, verb: &str| {
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{verb}: {error:?}");
        assert_eq!(error.stage, ErrorStage::Resolving, "{verb}");
        assert!(
            error.message.contains("too large to record"),
            "{verb}: {}",
            error.message
        );
    };
    let platform = || sim::ScriptedPlatform::new("bound simulation", sim::namespace_boundary());

    let cli::Command::Explain(explain) =
        command(&[&["explain".to_owned()][..], &selection].concat())
    else {
        unreachable!()
    };
    let ctx = context(platform(), &root_path, &workspace);
    let refused = supervisor::explain(&ctx, &explain).err().expect("refused");
    too_large(&refused, "explain");

    for extra in [
        vec!["--label-only".to_owned()],
        vec!["--".to_owned(), "simulated-target".to_owned()],
    ] {
        let cli::Command::Run(args) =
            command(&[&["run".to_owned()][..], &selection, &extra].concat())
        else {
            unreachable!()
        };
        let report = supervisor::run(&ctx, &args);
        too_large(report.error.as_ref().expect("refused"), "run");
        assert!(report.receipt.is_none() && report.receipt_path.is_none());
    }
    let attempts = root_path.join("data/attempts");
    assert!(
        std::fs::read_dir(&attempts).map_or(true, |mut entries| entries.next().is_none()),
        "an attempt was claimed"
    );
}

/// I01: a refusal whose receipt an error raised before it would take past
/// the bound is still recorded. That error's message is cut, saying so, no
/// error is omitted, and the whole message reaches stderr instead
/// (`unrecorded`).
#[test]
fn a_refusal_past_the_bound_cuts_the_oversized_message_and_is_recorded() {
    let (_root, root_path, workspace) = roots();
    let mut platform = sim::ScriptedPlatform::new("bound simulation", sim::namespace_boundary())
        .events([
            RunEvent::EvidenceLost {
                reason: "x".repeat(usize::try_from(RECEIPT_MAX).unwrap()),
                after_target_end: false,
            },
            RunEvent::ExecError {
                errno: "ENOENT".to_owned(),
                detail: None,
            },
        ]);
    platform.applied = Some(sim::contained_applied("none"));
    let cli::Command::Run(args) = command(&[
        "run".to_owned(),
        "--evidence".to_owned(),
        "best-effort".to_owned(),
        "--workspace".to_owned(),
        workspace.display().to_string(),
        "--".to_owned(),
        "simulated-target".to_owned(),
    ]) else {
        unreachable!()
    };
    let report = supervisor::run(&context(platform, &root_path, &workspace), &args);
    let receipt = report
        .receipt
        .as_ref()
        .unwrap_or_else(|| panic!("{:?}", report.error));
    assert_eq!(receipt.phase, Phase::Refused);
    let codes: Vec<&str> = receipt
        .errors
        .iter()
        .map(|error| error.code.as_str())
        .collect();
    assert_eq!(codes, ["evidence_lost", "exec_failed"], "{codes:?}");
    let cut = &receipt.errors[0].message;
    assert!(
        cut.ends_with("the run that wrote this receipt prints the whole message on stderr]"),
        "{}",
        &cut[cut.len().saturating_sub(160)..]
    );
    assert_eq!(report.unrecorded.len(), 1);
    assert_eq!(report.unrecorded[0].code, "evidence_lost");
    assert_eq!(
        report.unrecorded[0].message.len(),
        usize::try_from(RECEIPT_MAX).unwrap(),
        "stderr gets the whole message"
    );
    let bytes = std::fs::read(report.receipt_path.unwrap()).unwrap();
    assert!(u64::try_from(bytes.len()).unwrap() <= RECEIPT_MAX);
    let on_disk: Value = serde_json::from_slice(&bytes).unwrap();
    common::validators()["jail-receipt"]
        .validate(&on_disk)
        .unwrap_or_else(|error| {
            panic!(
                "the receipt fails its schema at {}: {error}",
                error.instance_path()
            )
        });
}

/// Every receipt lists at most 128 errors, whatever its phase: a settled
/// run that raised more omits the oldest from its receipt, marks the first
/// it keeps, and names on stderr every error the receipt does not hold as
/// it was raised (the report's own error aside).
#[test]
fn a_settled_receipt_past_128_errors_leaves_what_it_omits_to_stderr() {
    let (_root, root_path, workspace) = roots();
    let losses = (0..130).map(|index| RunEvent::EvidenceLost {
        reason: format!("loss {index}"),
        after_target_end: false,
    });
    let mut platform = sim::ScriptedPlatform::new("bound simulation", sim::namespace_boundary())
        .events(losses.chain([RunEvent::ExecConfirmed]));
    platform.applied = Some(sim::contained_applied("none"));
    let cli::Command::Run(args) = command(&[
        "run".to_owned(),
        "--evidence".to_owned(),
        "best-effort".to_owned(),
        "--workspace".to_owned(),
        workspace.display().to_string(),
        "--".to_owned(),
        "simulated-target".to_owned(),
    ]) else {
        unreachable!()
    };
    let report = supervisor::run(&context(platform, &root_path, &workspace), &args);
    let receipt = report.receipt.as_ref().expect("a settled receipt");
    assert_eq!(receipt.phase, Phase::Settled, "{:?}", report.error);
    assert_eq!(receipt.errors.len(), 128);
    assert!(
        receipt.errors[0]
            .message
            .starts_with("[2 other error(s) omitted"),
        "{}",
        receipt.errors[0].message
    );
    assert_eq!(
        report.error.as_ref().map(|error| error.message.as_str()),
        Some("loss 0"),
        "the first cause is the report's error"
    );
    let stderr: Vec<&str> = report
        .unrecorded
        .iter()
        .map(|error| error.message.as_str())
        .collect();
    assert_eq!(stderr, ["loss 1", "loss 2"], "omitted, then marked");
    let bytes = std::fs::read(report.receipt_path.unwrap()).unwrap();
    let on_disk: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(on_disk["errors"].as_array().map(Vec::len), Some(128));
}

/// I01: what the platform reports once the boundary exists is held to the
/// receipt's bounds before any of it is recorded. A boundary that reports
/// more environment names than a receipt lists, or names too large for one
/// (control characters, escaped to six bytes each), is torn down without
/// running the target and refused as a configuration (exit 2), in a
/// schema-valid refused receipt within the write bound that records the
/// boundary as never established. A teardown that verified the tree adds
/// nothing; one that did not is an error of its own.
#[test]
fn a_boundary_whose_report_cannot_be_recorded_is_refused_with_a_receipt() {
    use ouro_jail::lifecycle::VerificationScope;
    let many: Vec<String> = (0..1025).map(|index| format!("V{index}")).collect();
    let long: Vec<String> = (0..10)
        .map(|index| format!("{}{index}", "\u{1}".repeat(100_000)))
        .collect();
    for (names, says, verified) in [
        (many.clone(), "1025 environment names", true),
        (long, "bytes", true),
        (many, "1025 environment names", false),
    ] {
        let (_root, root_path, workspace) = roots();
        let mut platform =
            sim::ScriptedPlatform::new("bound simulation", sim::namespace_boundary());
        if verified {
            platform = platform.abort_tree(sim::verified_tree(VerificationScope::AttemptTree));
        }
        let mut applied = sim::contained_applied("none");
        applied.environment_names = names;
        platform.applied = Some(applied);
        let calls = platform.calls.clone();
        let cli::Command::Run(args) = command(&[
            "run".to_owned(),
            "--workspace".to_owned(),
            workspace.display().to_string(),
            "--".to_owned(),
            "simulated-target".to_owned(),
        ]) else {
            unreachable!()
        };
        let report = supervisor::run(&context(platform, &root_path, &workspace), &args);
        let error = report.error.as_ref().expect("refused");
        assert_eq!(report.exit_code, 2, "{error:?}");
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{error:?}");
        assert_eq!(error.stage, ErrorStage::Preparing);
        assert!(error.message.contains(says), "{}", error.message);
        assert_eq!(
            *calls.aborts.lock().unwrap(),
            1,
            "the boundary is torn down"
        );
        assert!(report.unrecorded.is_empty(), "{:?}", report.unrecorded);
        let bytes = std::fs::read(report.receipt_path.expect("a claimed attempt")).unwrap();
        assert!(u64::try_from(bytes.len()).unwrap() <= RECEIPT_WRITE_MAX);
        let receipt: Value = serde_json::from_slice(&bytes).unwrap();
        common::check_receipt(&receipt).unwrap_or_else(|error| panic!("{error}\n{receipt:#}"));
        assert_eq!(receipt["phase"], "refused");
        assert_eq!(receipt["lifetime"]["boundary"], "pending");
        assert_eq!(
            receipt["applied"]["environment_names"],
            serde_json::json!([])
        );
        let codes: Vec<&str> = receipt["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|error| error["code"].as_str().unwrap())
            .collect();
        if verified {
            assert_eq!(codes, ["invalid_config"]);
        } else {
            assert_eq!(codes, ["tree_unknown", "invalid_config"]);
        }
    }
}
