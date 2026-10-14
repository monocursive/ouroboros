//! Portable: what the jail library must not do to the process that hosts
//! it.
//!
//! `ouro-jail run` gives the caller EOF on stdout once the target closes it
//! by pointing the supervisor's own stdout at `/dev/null` after preparation
//! (§8.3, X05.3). That is a decision for the `ouro-jail` binary, whose stdout
//! is the target's: a program that calls the library in-process (§16: "The
//! future `ouro` executable can call the jail library in-process") keeps its
//! own stdout. These tests run a whole attempt in-process over a scripted
//! platform, on Linux and macOS alike.

use std::path::{Path, PathBuf};

use clap::Parser as _;
use ouro_jail::cli;
use ouro_jail::config::EnvSettings;
use ouro_jail::lifecycle::VerificationScope;
use ouro_jail::supervisor;

mod common;
use common::sim;

/// The `(dev, ino)` of what this process's descriptor 1 refers to.
fn stdout_identity() -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let path = if Path::new("/dev/fd/1").exists() {
        PathBuf::from("/dev/fd/1")
    } else {
        PathBuf::from("/proc/self/fd/1")
    };
    let metadata = std::fs::metadata(path).expect("descriptor 1 can be inspected");
    (metadata.dev(), metadata.ino())
}

/// One whole attempt, in this process, through `supervisor::run`.
fn run_in_process() -> supervisor::RunReport {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = common::private_tempdir();
    let root = std::fs::canonicalize(temp.path()).expect("canonical");
    for name in ["config", "data", "workspace"] {
        std::fs::create_dir(root.join(name)).expect("a directory");
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))
            .expect("private");
    }
    let workspace = root.join("workspace");
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ouro-jail".to_owned(),
        "run".to_owned(),
        "--workspace".to_owned(),
        workspace.display().to_string(),
        "--".to_owned(),
        "simulated-target".to_owned(),
    ])
    .command
    else {
        unreachable!("`run` parses as the run command")
    };
    let ctx = supervisor::Context {
        // Every requirement available, the target execs and exits 0, and the
        // tree is verified empty.
        platform: Box::new(
            sim::ScriptedPlatform::new("in-process simulation", sim::namespace_boundary())
                .abort_tree(sim::verified_tree(VerificationScope::AttemptTree)),
        ),
        env_settings: EnvSettings {
            config_dir: Some(root.join("config")),
            data_dir: Some(root.join("data")),
            ..EnvSettings::default()
        },
        cwd: workspace,
        home: Some(root.join("home")),
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&ctx, &args);
    drop(temp);
    report
}

/// X05.3's stdout release is the binary's, not the library's: a whole
/// attempt run in-process leaves the host's descriptor 1 on the object it
/// was on. (It used to be pointed at `/dev/null` by the library itself, which
/// silently swallowed the output of every in-process caller after its first
/// run, this test binary included.)
#[test]
fn an_in_process_run_leaves_the_hosts_stdout_where_it_was() {
    let before = stdout_identity();
    let report = run_in_process();
    assert_eq!(
        report.exit_code, 0,
        "the scripted attempt did not run to its end: {:?}",
        report.error
    );
    assert!(
        report.receipt.is_some(),
        "the attempt reached no receipt, so preparation was never passed"
    );
    assert_eq!(
        stdout_identity(),
        before,
        "running an attempt in-process moved this process's stdout"
    );
}
