//! L05: an unobservable tree end must retain state, even after target exit.
use clap::Parser;
use common::sim;
use ouro_jail::{cli, config::EnvSettings, records::*, supervisor};
use std::path::PathBuf;
use std::time::Duration;

mod common;

#[test]
fn l05_unknown_tree_retains_scratch_and_never_settles() {
    // Canonicalize to avoid macOS's /var -> /private/var alias in state paths.
    let root = common::private_tempdir();
    let root_path = root.path().canonicalize().unwrap();
    let workspace = root_path.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail",
        "run",
        "--workspace",
        workspace.to_str().unwrap(),
        "--",
        "simulated-target",
    ])
    .command
    else {
        unreachable!()
    };
    // The tree's end cannot be observed: verification establishes nothing,
    // and the scratch the attempt made must stay.
    let platform = sim::ScriptedPlatform::new("L05 simulation", sim::namespace_boundary())
        .tree(sim::unverified_tree("attempt_tree", "pending"))
        .on_prepare(|plan| {
            std::fs::create_dir(plan.attempt_dir.join("scratch")).unwrap();
            std::fs::write(
                plan.attempt_dir.join("scratch/retained"),
                "a possibly live tree owns this",
            )
            .unwrap();
        });
    let calls = platform.calls.clone();
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
    assert_ne!(report.exit_code, 0);
    assert_eq!(
        report.error.as_ref().unwrap().code,
        ErrorCode::TreeUnknown,
        "{:?}",
        report.error
    );
    let receipt = serde_json::to_value(report.receipt.unwrap()).unwrap();
    assert_ne!(receipt["phase"], "settled");
    assert_eq!(receipt["outcome"]["kind"], "exited");
    assert_eq!(receipt["outcome"]["code"], 0);
    assert_eq!(receipt["lifetime"]["tree_empty"], serde_json::Value::Null);
    assert_eq!(receipt["lifetime"]["verified_at"], serde_json::Value::Null);
    let attempt: PathBuf = report.receipt_path.unwrap().parent().unwrap().to_owned();
    assert!(attempt.join("scratch/retained").exists());
    // Verification was asked for, within §9.3's forced-stop budget.
    let budgets = calls.tree_budgets.lock().unwrap();
    assert!(
        !budgets.is_empty()
            && budgets
                .iter()
                .all(|budget| *budget == Duration::from_secs(5)),
        "{budgets:?}"
    );
}
