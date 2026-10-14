//! The bound every reader holds a receipt to (`cleanup::RECEIPT_MAX`), at
//! the writer a whole run reaches while the target runs: the enforced
//! receipt, persisted on the worker. Simulated platform, portable.

use clap::Parser as _;
use ouro_jail::cleanup::RECEIPT_MAX;
use ouro_jail::config::EnvSettings;
use ouro_jail::platform::{RunEvent, StopReason};
use ouro_jail::{cli, supervisor};
use serde_json::Value;

mod common;
use common::sim;

/// §7: a receipt past the bound would be one no reader accepts, so the
/// enforced receipt is refused before the worker writes it, and that failed
/// persistence after exec stops the tree (`state_write_failed`). The
/// receipt on disk stays the last one within the bound: the prepared one.
#[test]
fn an_enforced_receipt_past_the_bound_stops_the_run() {
    let root = common::private_tempdir();
    let root_path = root.path().canonicalize().unwrap();
    let workspace = root_path.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
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
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail",
        "run",
        "--evidence",
        "best-effort",
        "--workspace",
        workspace.to_str().unwrap(),
        "--",
        "simulated-target",
    ])
    .command
    else {
        unreachable!()
    };
    let context = supervisor::Context {
        platform: Box::new(platform),
        env_settings: EnvSettings {
            config_dir: Some(root_path.join("config")),
            data_dir: Some(root_path.join("data")),
            ..Default::default()
        },
        cwd: workspace,
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&context, &args);
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
