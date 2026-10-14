#![cfg(target_os = "linux")]
//! What `agent` protects of the workspace's git metadata, live.
//!
//! `agent` keeps `.git` writable so commits work and binds `.git/hooks` and
//! `.git/config` read-only, at any depth, and every file-form `.git` (a
//! gitlink) whole (jail-v1 §9.1): a contained run cannot edit the hooks or
//! the config git reads with the operator's authority on their next `git`
//! command outside the jail. Ordinary git use inside the run (commits,
//! fetches, checkouts, `git submodule update`) keeps working. What the
//! protection does not cover is shown here too: a run determined to
//! redirect git past it can still plant a `commondir`.

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
    jail.arg("run")
        .arg("--profile")
        .arg("agent")
        .arg("--workspace")
        .arg(workspace)
        .receipt()
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

/// Attempted, live: a superproject with a submodule `mod` whose recorded
/// commit the submodule has not fetched yet, from an upstream inside the
/// workspace. The run rewrites the gitlink `mod/.git`, then runs `git
/// submodule update`, a fetch, a branch checkout and a commit. Verdict: the
/// gitlink write fails and leaves it unchanged; the update fetches and
/// checks out the recorded commit, and the rest works.
#[test]
fn a_gitlink_is_read_only_and_submodule_update_still_works() {
    if !common::live() || !git_available() {
        return;
    }
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    repository(&workspace);
    let upstream = workspace.join("upstream");
    repository(&upstream);
    git(&workspace, &["submodule", "-q", "add", "./upstream", "mod"]);
    git(&workspace, &["commit", "-q", "-m", "add mod"]);
    // Upstream moves on and the superproject records it; the submodule has
    // not fetched it, so the update inside the run must.
    git(&upstream, &["commit", "-q", "--allow-empty", "-m", "two"]);
    let recorded = git(&upstream, &["rev-parse", "HEAD"]);
    git(
        &workspace,
        &[
            "update-index",
            "--cacheinfo",
            &format!("160000,{recorded},mod"),
        ],
    );
    git(&workspace, &["commit", "-q", "-m", "bump mod"]);
    let gitlink = workspace.join("mod/.git");
    let before = std::fs::read(&gitlink).unwrap();
    assert!(before.starts_with(b"gitdir: "), "not a gitlink: {before:?}");

    let script = format!(
        "if echo 'gitdir: /tmp' > mod/.git; then exit 10; fi; \
         {git} submodule -q update || exit 11; \
         {git} fetch -q ./upstream || exit 12; \
         {git} checkout -q -b topic || exit 13; \
         {git} commit -q --allow-empty -m inside || exit 14",
        git = inside_git()
    );
    let run = agent_run(jail, &workspace, &script);
    assert_settled_cleanly(&run);
    assert_eq!(
        std::fs::read(&gitlink).unwrap(),
        before,
        "the gitlink changed"
    );
    assert_eq!(
        git(&workspace.join("mod"), &["rev-parse", "HEAD"]),
        recorded
    );
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

/// Sets this process's soft `RLIMIT_NOFILE` (the jail it spawns inherits
/// it) and puts the old one back on drop.
struct SoftNofile(libc::rlimit);

impl SoftNofile {
    fn set(soft: libc::rlim_t) -> SoftNofile {
        // SAFETY: an all-zero rlimit is a valid value the call overwrites.
        let mut old: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `old` is writable storage of the type getrlimit fills.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut old) },
            0
        );
        let lowered = libc::rlimit {
            rlim_cur: soft.min(old.rlim_max),
            rlim_max: old.rlim_max,
        };
        // SAFETY: a valid rlimit that outlives the call; lowering the soft
        // limit within the hard one needs no privilege.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) },
            0
        );
        SoftNofile(old)
    }
}

impl Drop for SoftNofile {
    fn drop(&mut self) {
        // SAFETY: restores the limit read at construction, within the
        // unchanged hard limit.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const self.0) };
    }
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
    let _limit = SoftNofile::set(1024);
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
