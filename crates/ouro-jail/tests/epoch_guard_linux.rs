//! The uncontained-epoch guard, end to end (audit 6 F1, jail-v2 §3.2 /
//! K03): a `--profile none` run arms its live markers and settles
//! `uncontained.epoch` when its tree is gone, and a later contained run
//! refuses a trusted file the settled marker predates until it is re-saved.
#![cfg(target_os = "linux")]

use ouro_fixture::harness::Jail;
use std::os::unix::fs::PermissionsExt as _;

mod common;

/// Two runs share one state root the way two commands of one operator do:
/// both read and write the same data and configuration directories.
fn jail_on(data: &std::path::Path, config: &std::path::Path) -> Jail {
    Jail::new()
        .unwrap()
        .env("OURO_DATA_DIR", data)
        .env("OURO_CONFIG_DIR", config)
}

#[test]
fn a_none_run_settles_the_epoch_and_a_trusted_file_it_predates_refuses() {
    if !common::live() {
        return;
    }
    let first = Jail::new().unwrap();
    let data = first.data_dir();
    let config = first.config_dir();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let workspace = first.root().join("workspace");
    std::fs::create_dir(&workspace).unwrap();

    // A trusted file the settled marker will postdate. `config.toml` and
    // the launch directory would refuse run 1 itself, so the predating
    // file is a `--profile` policy written beside the markers before
    // run 1 ever ran.
    let policy = data.join("predates.toml");
    std::fs::write(
        &policy,
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Run 1: `none`, with no trusted file in the directories it refuses
    // (config.toml, launch/). Its live markers go up in both directories
    // before the target is released and are replaced by the settled marker
    // when the tree is gone.
    let run = first
        .args(["run", "--profile", "none"])
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target(["/usr/bin/true"])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    common::assert_run_records(&run);
    // Mutation-B06 guard: the settled marker is written at all, and the
    // live markers ended with the run.
    for dir in [&data, &config] {
        let settled = ouro_jail::state::uncontained_settled_path(dir);
        assert!(settled.is_file(), "{} was never written", settled.display());
        let live: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("uncontained.") && name.ends_with(".live")
                    })
            })
            .collect();
        assert!(live.is_empty(), "a live marker outlived the run: {live:?}");
    }

    // Run 2: the predating file refuses before exec.
    let run = jail_on(&data, &config)
        .arg("run")
        .arg("--profile")
        .arg(&policy)
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target(["/usr/bin/touch", "SHOULD_NOT_EXIST"])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(
        !workspace.join("SHOULD_NOT_EXIST").exists(),
        "the target ran before the refusal"
    );
    let stderr = run.stderr_text();
    assert!(
        stderr.contains("unsafe_config_path") && stderr.contains("predates the last uncontained"),
        "{stderr}"
    );

    // The operator's remedy is the re-save: a ctime after the settle is
    // trusted, and the same command runs.
    std::fs::write(
        &policy,
        "schema = \"ouro.jail.policy/1\"\nextends = \"tool\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    let run = jail_on(&data, &config)
        .arg("run")
        .arg("--profile")
        .arg(&policy)
        .arg("--workspace")
        .arg(&workspace)
        .receipt()
        .target(["/usr/bin/true"])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert!(run.receipt_errors().is_empty());
}
