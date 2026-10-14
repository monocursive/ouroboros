//! §8.1 / §13.2: an attempt that ends unsettled keeps its last nonsettled
//! phase, and `enforced` is the phase after a confirmed target exec. A run
//! whose target ended before any exec confirmation stays `prepared`, whatever
//! the profile: the end-of-run code is shared. Simulated platform, portable.
use clap::Parser;
use ouro_jail::lifecycle::{Integrity, VerificationScope};
use ouro_jail::platform::RunEvent;
use ouro_jail::records::ErrorCode;
use ouro_jail::{cli, config::EnvSettings, supervisor};
use serde_json::Value;

mod common;
use common::sim;

/// What the simulated run does.
#[derive(Clone, Copy)]
struct Script {
    /// Report the exec confirmation before the end.
    confirm_exec: bool,
    /// The integrity tree verification ends with.
    integrity: Integrity,
}

impl Script {
    /// `none`'s boundary, the run as scripted, and a tree whose death was not
    /// established.
    fn platform(self) -> sim::ScriptedPlatform {
        let platform = sim::ScriptedPlatform::new("phase simulation", sim::cgroup_boundary()).tree(
            sim::unverified_tree(VerificationScope::RegisteredBoundary, self.integrity),
        );
        if self.confirm_exec {
            platform
                .events([RunEvent::ExecConfirmed])
                .then(RunEvent::TargetSignaled { signal: 9 })
        } else {
            // A signal death with no independent evidence of exec.
            platform.events([]).then(RunEvent::Unknown {
                reason: "the target ended by a signal before its exec was confirmed".into(),
            })
        }
    }
}

fn run(script: Script) -> Value {
    run_keeping(script).1
}

/// As [`run`], keeping the state directory for inspection.
fn run_keeping(script: Script) -> (tempfile::TempDir, Value) {
    let root = common::private_tempdir();
    let root_path = root.path().canonicalize().unwrap();
    let workspace = root_path.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail",
        "run",
        "--profile",
        "none",
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
        platform: Box::new(script.platform()),
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
        report.error.as_ref().map(|error| error.code),
        Some(ErrorCode::TreeUnknown),
        "{:?}",
        report.error
    );
    let receipt = serde_json::to_value(report.receipt.unwrap()).unwrap();
    common::validators()["jail-receipt"]
        .validate(&receipt)
        .unwrap_or_else(|error| panic!("the receipt fails its schema: {error}\n{receipt:#}"));
    (root, receipt)
}

#[test]
fn an_unsettled_end_without_a_confirmed_exec_stays_prepared() {
    for (integrity, expected) in [(Integrity::Pending, "verified"), (Integrity::Lost, "lost")] {
        let receipt = run(Script {
            confirm_exec: false,
            integrity,
        });
        assert_eq!(receipt["phase"], "prepared", "{integrity:?}: {receipt:#}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(receipt["outcome"]["kind"], "unknown");
        assert_eq!(receipt["lifetime"]["tree_empty"], Value::Null);
        // An unknown end keeps the prepared verification; a loss stays lost.
        assert_eq!(receipt["lifetime"]["integrity"], expected, "{integrity:?}");
    }
}

#[test]
fn an_unsettled_end_after_a_confirmed_exec_stays_enforced() {
    let receipt = run(Script {
        confirm_exec: true,
        integrity: Integrity::Lost,
    });
    assert_eq!(receipt["phase"], "enforced", "{receipt:#}");
    assert_eq!(receipt["exec_observed"], true);
    assert_eq!(receipt["outcome"]["kind"], "signaled");
    assert_eq!(receipt["lifetime"]["integrity"], "lost");
}

/// §13.3: a `jail.receipt` trace note names its receipt by `sha256:` over
/// the receipt's RFC 8785 canonical bytes (canonicalization.md), so a
/// consumer holding only `jail.json` can check it whatever the file's layout
/// or the writer's field order. Found in J4 wave 2: the digest was over the
/// product's own compact serialization, which no consumer could reproduce
/// without its field order.
#[test]
fn the_receipt_note_names_the_receipt_by_its_canonical_digest() {
    let (root, receipt) = run_keeping(Script {
        confirm_exec: true,
        integrity: Integrity::Lost,
    });
    let attempts = root.path().canonicalize().unwrap().join("data/attempts");
    let attempt = std::fs::read_dir(&attempts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("one attempt directory");
    let on_disk: Value =
        serde_json::from_slice(&std::fs::read(attempt.join("jail.json")).unwrap()).unwrap();
    assert_eq!(on_disk, receipt, "jail.json is the reported receipt");
    let trace = std::fs::read(attempt.join("trace.ndjson")).unwrap();
    let note = trace
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .rfind(|frame| frame["operation"] == "jail.receipt")
        .expect("a receipt note in the trace");
    let canonical = ouro_jail::canonical::to_jcs(&on_disk).expect("a receipt has no floats");
    assert_eq!(note["fields"]["phase"], on_disk["phase"]);
    assert_eq!(
        note["fields"]["receipt_digest"],
        ouro_jail::canonical::sha256_prefixed(&canonical),
        "the note's digest is over the receipt's canonical bytes"
    );
}
