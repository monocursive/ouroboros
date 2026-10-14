//! The bound every reader holds a receipt and `policy.json` to
//! (`cleanup::RECEIPT_MAX`), over whole runs: the enforced receipt the worker
//! persists, a policy too large to record, and a refusal that would pass the
//! bound. Simulated platform, portable.

use std::path::{Path, PathBuf};

use clap::Parser as _;
use ouro_jail::cleanup::RECEIPT_MAX;
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

/// I01: a refusal whose receipt the errors raised before it would take past
/// the bound is still recorded. Those errors are omitted, newest first, an
/// error says how many, and they reach stderr instead (`unrecorded`).
#[test]
fn a_refusal_past_the_bound_omits_earlier_errors_and_is_recorded() {
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
    assert_eq!(codes, ["state_write_failed", "exec_failed"], "{codes:?}");
    assert!(
        receipt.errors[0]
            .message
            .starts_with("1 earlier error(s) are omitted"),
        "{}",
        receipt.errors[0].message
    );
    assert_eq!(report.unrecorded.len(), 1);
    assert_eq!(report.unrecorded[0].code, "evidence_lost");
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
