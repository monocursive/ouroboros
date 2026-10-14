#![cfg(target_os = "linux")]
//! What `agent` protects of the workspace's git metadata, live, and what it
//! does not.
//!
//! `agent` keeps `.git` writable so commits work and binds `.git/hooks` and
//! `.git/config` read-only wherever they exist at launch, at any depth and
//! under a read-write grant of a git directory itself, plus the hooks of
//! submodules' git directories (jail-v1 §9.1). Ordinary git use inside the
//! run (commits, fetches, checkouts, `git submodule update`, moving and
//! removing linked worktrees, `git rm` of a submodule) keeps working.
//! What the protection does not stop is shown too: a run set on
//! redirecting git can plant a `commondir`, and a submodule's config stays
//! writable. The protection raises the cost of accidental damage and naive
//! planting, not of a deliberate run.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use ouro_fixture::harness::{self, Jail, Run};

mod common;

/// The identity every commit here is made with, inside the run and out.
const IDENTITY: [&str; 4] = [
    "-c",
    "user.name=ouro-test",
    "-c",
    "user.email=ouro-test@example.invalid",
];

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Whether `git` runs here; the live checks below need it on both sides of
/// the boundary, and the runtime roots `agent` binds are this host's.
fn git_available() -> bool {
    let found = Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !found {
        harness::skip_or_fail("git is not installed on this host");
    }
    found
}

/// Runs `git` in `dir` on the host, failing the test on an error, and
/// returns its trimmed stdout.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(IDENTITY)
        .args([
            "-c",
            "protocol.file.allow=always",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A repository at `dir` with one commit.
fn repository(dir: &Path) {
    private_dir(dir);
    git(dir, &["init", "-q"]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", "init"]);
}

/// An `agent` run over `workspace` of `script` under `/bin/sh`, from the
/// workspace.
fn agent_run(jail: Jail, workspace: &Path, script: &str) -> Run {
    agent_run_with(jail, workspace, &[], script)
}

/// [`agent_run`] with `grants` (`--rw <path>`) besides the workspace.
fn agent_run_with(jail: Jail, workspace: &Path, grants: &[&Path], script: &str) -> Run {
    let mut jail = jail
        .arg("run")
        .arg("--profile")
        .arg("agent")
        .arg("--workspace")
        .arg(workspace);
    for grant in grants {
        jail = jail.arg("--rw").arg(grant);
    }
    jail.receipt()
        .target([
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!("cd {} && {script}", workspace.display())),
        ])
        .run()
        .unwrap()
}

/// The `git` invocation the scripts inside the run use: the same identity,
/// and local paths allowed as remotes.
fn inside_git() -> String {
    format!("git {} -c protocol.file.allow=always", IDENTITY.join(" "))
}

/// A settled run that exited 0, its records held to their contract.
fn assert_settled_cleanly(run: &Run) {
    assert_eq!(
        run.code(),
        Some(0),
        "stdout {} stderr {}",
        run.stdout_text(),
        run.stderr_text()
    );
    let receipt = common::settled(run);
    assert_eq!(
        receipt["applied"]["filesystem"]["protected_coverage"], "existing_and_root",
        "{receipt:#}"
    );
}

/// Attempted, live: a workspace holding a nested repository `sub`; the run
/// writes a hook into `sub/.git/hooks` and appends to `sub/.git/config`,
/// then commits in `sub`. Verdict: both writes fail and leave the host
/// unchanged, and the commit lands.
#[test]
fn a_nested_repositorys_hooks_and_config_are_read_only_and_commits_still_work() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    repository(&workspace);
    let sub = workspace.join("sub");
    repository(&sub);
    let config = std::fs::read(sub.join(".git/config")).unwrap();
    let script = format!(
        "if echo planted > sub/.git/hooks/post-checkout; then exit 10; fi; \
         if echo '[core] hooksPath = /tmp' >> sub/.git/config; then exit 11; fi; \
         {git} -C sub commit -q --allow-empty -m inside || exit 12",
        git = inside_git()
    );
    let run = agent_run(jail, &workspace, &script);
    assert_settled_cleanly(&run);
    assert!(
        !sub.join(".git/hooks/post-checkout").exists(),
        "a hook was planted in the nested repository"
    );
    assert_eq!(
        std::fs::read(sub.join(".git/config")).unwrap(),
        config,
        "the nested repository's config changed"
    );
    assert_eq!(git(&sub, &["log", "-1", "--format=%s"]), "inside");
}

/// A superproject at `workspace` with a submodule `mod` from `upstream`
/// inside it, whose recorded commit the submodule has not fetched yet, and
/// a linked worktree `wt`. Returns the recorded commit.
fn superproject(workspace: &Path) -> String {
    repository(workspace);
    let upstream = workspace.join("upstream");
    repository(&upstream);
    git(workspace, &["submodule", "-q", "add", "./upstream", "mod"]);
    git(workspace, &["commit", "-q", "-m", "add mod"]);
    // Upstream moves on and the superproject records it; the submodule has
    // not fetched it, so an update inside the run must.
    git(&upstream, &["commit", "-q", "--allow-empty", "-m", "two"]);
    let recorded = git(&upstream, &["rev-parse", "HEAD"]);
    git(
        workspace,
        &[
            "update-index",
            "--cacheinfo",
            &format!("160000,{recorded},mod"),
        ],
    );
    git(workspace, &["commit", "-q", "-m", "bump mod"]);
    git(workspace, &["worktree", "add", "-q", "wt"]);
    recorded
}

/// Attempted, live: a superproject with a submodule and a linked worktree.
/// The run plants a hook in the submodule's git directory, then runs `git
/// submodule update` (which must fetch), moves and removes the worktree,
/// removes the submodule with `git rm`, and fetches, checks out and
/// commits. Verdict: the hook write fails; everything else works and
/// leaves the host repository consistent: no worktree left half-removed.
#[test]
fn submodule_and_worktree_maintenance_work_inside_a_run() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    let recorded = superproject(&workspace);
    let script = format!(
        "if echo planted > .git/modules/mod/hooks/post-checkout; then exit 10; fi; \
         {git} submodule -q update || exit 11; \
         test \"$({git} -C mod rev-parse HEAD)\" = {recorded} || exit 12; \
         {git} worktree move wt wt2 || exit 13; \
         {git} worktree remove --force wt2 || exit 14; \
         {git} rm -q -f mod || exit 15; \
         {git} fetch -q ./upstream || exit 16; \
         {git} checkout -q -b topic || exit 17; \
         {git} commit -q -m inside || exit 18",
        git = inside_git()
    );
    let run = agent_run(jail, &workspace, &script);
    assert_settled_cleanly(&run);
    assert!(
        !workspace
            .join(".git/modules/mod/hooks/post-checkout")
            .exists(),
        "a hook was planted in the submodule's git directory"
    );
    assert_eq!(
        git(&workspace, &["worktree", "list", "--porcelain"])
            .lines()
            .filter(|line| line.starts_with("worktree "))
            .count(),
        1
    );
    assert!(!workspace.join("wt").exists() && !workspace.join("wt2").exists());
    assert!(!workspace.join(".git/worktrees/wt").exists());
    assert_eq!(git(&workspace, &["log", "-1", "--format=%s"]), "inside");
    assert_eq!(git(&workspace, &["ls-files", "mod"]), "");
}

/// Attempted, live: `git submodule deinit` inside a run. Verdict, a limit
/// of the protected config: the submodule's checkout is emptied, but the
/// superproject's `.git/config` cannot be written, so the submodule stays
/// registered there (git reports the error and still exits 0).
#[test]
fn the_limit_submodule_deinit_cannot_unregister_inside_a_run() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    superproject(&workspace);
    git(&workspace, &["submodule", "-q", "update"]);
    let script = format!("{git} submodule -q deinit -f mod", git = inside_git());
    let run = agent_run(jail, &workspace, &script);
    assert_settled_cleanly(&run);
    assert!(
        run.stderr_text().contains(".git/config"),
        "{}",
        run.stderr_text()
    );
    assert_eq!(
        std::fs::read_dir(workspace.join("mod")).unwrap().count(),
        0,
        "the checkout was not emptied"
    );
    assert!(!git(&workspace, &["config", "--get", "submodule.mod.url"]).is_empty());
}

/// Attempted, live: the run appends to a submodule's config. Verdict, a
/// limit: the write succeeds, and git outside the jail reads it; one
/// `core.fsmonitor` line there runs on the operator's plain `git status`
/// in the superproject. The config stays writable because `git submodule
/// update` rewrites it on every run.
#[test]
fn the_limit_a_submodules_config_stays_writable() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    superproject(&workspace);
    git(&workspace, &["submodule", "-q", "update"]);
    let script = "printf '[ouro]\\n\\tmarker = run\\n' >> .git/modules/mod/config";
    let run = agent_run(jail, &workspace, script);
    assert_settled_cleanly(&run);
    assert_eq!(
        git(&workspace.join("mod"), &["config", "--get", "ouro.marker"]),
        "run"
    );
}

/// Attempted, live: the common agent-worktree layout. The workspace is a
/// linked worktree of a repository outside it, and the run is granted
/// `--rw <main>/.git` so it can commit; it writes a hook and the config of
/// that git directory, then commits. Verdict: both writes fail, since the
/// names match the host path of the granted root, and the commit lands.
#[test]
fn a_read_write_grant_of_a_git_directory_keeps_its_hooks_and_config_read_only() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let main = jail.root().join("main");
    repository(&main);
    let workspace = jail.root().join("workspace");
    git(
        &main,
        &["worktree", "add", "-q", workspace.to_str().unwrap()],
    );
    let git_dir = main.join(".git");
    let config = std::fs::read(git_dir.join("config")).unwrap();
    let script = format!(
        "if echo planted > {hook}; then exit 10; fi; \
         if echo '[core] hooksPath = /tmp' >> {config}; then exit 11; fi; \
         {git} commit -q --allow-empty -m inside || exit 12",
        hook = git_dir.join("hooks/pre-commit").display(),
        config = git_dir.join("config").display(),
        git = inside_git()
    );
    let run = agent_run_with(jail, &workspace, &[&git_dir], &script);
    assert_settled_cleanly(&run);
    assert!(
        !git_dir.join("hooks/pre-commit").exists(),
        "a hook was planted"
    );
    assert_eq!(std::fs::read(git_dir.join("config")).unwrap(), config);
    assert_eq!(git(&workspace, &["log", "-1", "--format=%s"]), "inside");
}

/// Attempted, live: the run copies the repository's objects and refs aside
/// with a config of its own, and plants `.git/commondir` naming the copy.
/// Verdict: the plant succeeds, and the operator's git outside the jail
/// then reads the run's config, not the protected one. This is the limit
/// jail-v1 §9.1 and the guide state: the protection stops edits of the
/// existing hooks and config, not a run that redirects git past them.
#[test]
fn the_limit_a_planted_commondir_redirects_git_past_the_protection() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    repository(&workspace);
    let script = "mkdir copy && cp -r .git/objects .git/refs .git/HEAD copy/ && \
                  printf '[core]\\n\\trepositoryformatversion = 0\\n[ouro]\\n\\tmarker = run\\n' \
                  > copy/config && echo ../copy > .git/commondir";
    let run = agent_run(jail, &workspace, script);
    assert_settled_cleanly(&run);
    assert_eq!(git(&workspace, &["config", "--get", "ouro.marker"]), "run");
}

/// `count` nested repositories, each with a hooks directory and a config.
fn nested_repositories(workspace: &Path, count: usize) -> PathBuf {
    for index in 0..count {
        let git = workspace.join(format!("r{index}/.git"));
        private_dir(&git.join("hooks"));
        std::fs::write(git.join("config"), b"[core]\n").unwrap();
    }
    workspace.to_owned()
}

/// Attempted, live: an `agent` run over 600 nested repositories, whose
/// hooks and configs are 1200 protected segments. Verdict: the receipt's
/// mount bound refuses before anything is pinned, as a configuration
/// naming the count.
#[test]
fn many_nested_repositories_refuse_before_any_pin() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = nested_repositories(&jail.root().join("workspace"), 600);
    let run = agent_run(jail, &workspace, "true");
    assert_eq!(run.code(), Some(2), "{}", run.stderr_text());
    let receipt = common::checked_receipt(
        run.receipt_phase("refused")
            .expect("a refusal writes a final receipt"),
    );
    let error = &receipt["errors"][0];
    assert_eq!(error["code"], "invalid_config", "{receipt:#}");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("hold 1200 protected segments"),
        "{message}"
    );
    assert!(
        message.contains("before any protected segment was pinned"),
        "not the refusal before pinning: {message}"
    );
}

/// Attempted, live: an `agent` run over 450 nested repositories (900
/// protected segments) from a session whose soft descriptor limit is 1024.
/// Verdict: the pins fit once the supervisor raises its soft limit, the run
/// settles, and its mount table binds every one of them read-only.
#[test]
fn nested_repositories_within_the_bound_fit_a_1024_soft_descriptor_limit() {
    if !common::live() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = nested_repositories(&jail.root().join("workspace"), 450);
    let _limit = common::SoftNofile::set(1024);
    let run = agent_run(jail, &workspace, "true");
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let receipt = common::settled(&run);
    assert_eq!(receipt["errors"], serde_json::json!([]), "{receipt:#}");
    let protected = receipt["applied"]["filesystem"]["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["mode"] == "ro"
                && row["path"].as_str().is_some_and(|path| {
                    path.ends_with("/.git/hooks") || path.ends_with("/.git/config")
                })
        })
        .count();
    assert_eq!(protected, 900, "{receipt:#}");
}
