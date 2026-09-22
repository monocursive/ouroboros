//! The conformance driver of jail-v1 §16 and contract §3.8.
//!
//! A GitHub-hosted runner, or a developer machine, drives the provisioned
//! Linux reference host over SSH as the `ouro-ci` account. Nothing is
//! installed on the host and nothing there polls anything: the driver copies
//! the tree into a per-run directory, builds, runs `doctor --json`, compares
//! it with the pinned manifest, runs the suite with `OURO_CONFORMANCE=1` so a
//! skip is a failure, copies the evidence back and removes the run directory —
//! on success only. A failed run keeps its directory and prints the path.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::manifest::{self, Manifest};
use crate::stamp;

/// The remote parent of every run directory, relative to the account's home.
pub const REMOTE_RUNS: &str = "ouro-ci/runs";
/// Cargo is not on the non-login PATH of the reference host.
pub const REMOTE_CARGO: &str = "$HOME/.cargo/bin/cargo";

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub user: String,
    pub key: PathBuf,
    pub known_hosts: Option<PathBuf>,
}

/// The SSH options every call shares. `StrictHostKeyChecking=yes` means an
/// unknown host key fails rather than being learned.
#[must_use]
pub fn ssh_opts(target: &Target) -> Vec<String> {
    let mut v = vec![
        "-i".to_string(),
        target.key.display().to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
    ];
    if let Some(kh) = &target.known_hosts {
        v.push("-o".to_string());
        v.push(format!("UserKnownHostsFile={}", kh.display()));
    }
    v
}

/// A full `ssh` argv for one remote command.
#[must_use]
pub fn ssh_argv(target: &Target, remote_command: &str) -> Vec<String> {
    let mut v = ssh_opts(target);
    v.push(format!("{}@{}", target.user, target.host));
    v.push(remote_command.to_string());
    v
}

/// The `-e` transport string rsync uses, so the same options apply.
#[must_use]
pub fn rsh_string(target: &Target) -> String {
    let mut s = String::from("ssh");
    for opt in ssh_opts(target) {
        s.push(' ');
        s.push_str(&opt);
    }
    s
}

/// A full `rsync` argv copying `local` into the run directory.
#[must_use]
pub fn rsync_argv(target: &Target, local: &Path, run_dir: &str) -> Vec<String> {
    let mut local = local.display().to_string();
    if !local.ends_with('/') {
        local.push('/');
    }
    vec![
        "-az".to_string(),
        "--delete".to_string(),
        "--exclude".to_string(),
        "target".to_string(),
        "--exclude".to_string(),
        ".git".to_string(),
        "-e".to_string(),
        rsh_string(target),
        local,
        format!("{}@{}:{REMOTE_RUNS}/{run_dir}/", target.user, target.host),
    ]
}

/// `<utc-stamp>-<short sha>`, restricted to characters that need no quoting.
#[must_use]
pub fn run_dir_name(stamp: &str, short_sha: &str) -> String {
    let clean: String = short_sha
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(12)
        .collect();
    let sha = if clean.is_empty() {
        "nosha".to_string()
    } else {
        clean
    };
    format!("{stamp}-{sha}")
}

/// True when a name is safe to paste into a remote shell command unquoted.
#[must_use]
pub fn is_shell_safe(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The run directory as a remote *shell* expression, for commands.
fn run_path(run_dir: &str) -> String {
    format!("$HOME/{REMOTE_RUNS}/{run_dir}")
}

/// The run directory as a path a person can paste, for messages. `$HOME` would
/// be expanded by the wrong shell if it appeared in a printed path.
#[must_use]
pub fn run_path_for_humans(run_dir: &str) -> String {
    format!("~/{REMOTE_RUNS}/{run_dir}")
}

/// The remote build command.
#[must_use]
pub fn build_command(run_dir: &str, jobs: u32) -> String {
    format!(
        "cd {} && {REMOTE_CARGO} build --release --workspace -j{jobs}",
        run_path(run_dir)
    )
}

/// The remote doctor command. Its output lands in the run directory so the
/// evidence copy is a plain read afterwards.
#[must_use]
pub fn doctor_command(run_dir: &str) -> String {
    let p = run_path(run_dir);
    format!(
        "cd {p} && ./target/release/ouro-jail doctor --json > doctor.json 2> doctor.stderr; \
         rc=$?; cat doctor.stderr 1>&2; exit $rc"
    )
}

/// The remote test command.
///
/// `OURO_CONFORMANCE=1` turns every live skip into a failure (jail-v1 §16).
/// The output is redirected to `test.log` and then echoed, rather than piped
/// through `tee`, so the exit status is the suite's without depending on the
/// remote login shell providing `pipefail` or `PIPESTATUS`.
/// The remote test command.
///
/// One test thread, not two. The ptrace observer's thread owns every
/// `waitpid` in its process (CONTRACT §3.5), so two tests attaching a tracer
/// in the same test binary reap each other's children and both block for
/// ever. Measured on the reference host: `observer_linux` passes in under
/// four seconds at `--test-threads=1` and never finishes at 2. This is a
/// property of the mechanism, not a preference about speed.
#[must_use]
pub fn test_command(run_dir: &str, jobs: u32) -> String {
    let p = run_path(run_dir);
    format!(
        "cd {p} && OURO_CONFORMANCE=1 \
         OURO_JAIL_BIN=$PWD/target/release/ouro-jail \
         OURO_FIXTURE_BIN=$PWD/target/release/ouro-fixture \
         {REMOTE_CARGO} test --workspace --release -j{jobs} -- --test-threads=1 \
         > test.log 2>&1; rc=$?; cat test.log; exit $rc"
    )
}

/// Options for one conformance run.
pub struct Options {
    pub target: Target,
    pub manifest: PathBuf,
    pub evidence: PathBuf,
    pub worktree: PathBuf,
    pub host_manifest_script: PathBuf,
    pub jobs: u32,
    pub keep_remote: bool,
}

struct Outcome {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn run(program: &str, args: &[String], stdin_file: Option<&Path>) -> std::io::Result<Outcome> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(path) = stdin_file {
        cmd.stdin(std::fs::File::open(path)?);
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    let out = cmd.output()?;
    Ok(Outcome {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn step(name: &str) {
    println!("== {name}");
}

/// Everything that went wrong, in order. Empty means the run passed.
pub struct Report {
    pub failures: Vec<String>,
    pub remote_dir: String,
    pub evidence: PathBuf,
}

/// Drive one conformance run. Returns the report; the caller sets the exit code.
pub fn drive(opts: &Options) -> std::io::Result<Report> {
    let mut failures: Vec<String> = Vec::new();

    let short_sha = git_short_sha(&opts.worktree);
    let run_dir = run_dir_name(&stamp::utc_stamp_now(), &short_sha);
    assert!(
        is_shell_safe(&run_dir),
        "run directory name `{run_dir}` is not shell safe"
    );
    std::fs::create_dir_all(&opts.evidence)?;

    println!(
        "conformance: {}@{} run {run_dir} at {}",
        opts.target.user,
        opts.target.host,
        stamp::rfc3339_from_unix(stamp::unix_now())
    );
    println!("worktree: {}", opts.worktree.display());

    // 1. The run directory.
    step("create the remote run directory");
    let out = run(
        "ssh",
        &ssh_argv(&opts.target, &format!("mkdir -p {}", run_path(&run_dir))),
        None,
    )?;
    if !out.status.success() {
        failures.push(format!("mkdir failed: {}", out.stderr.trim()));
        return finish(opts, &run_dir, failures, None, None);
    }

    // 2. The tree.
    step("rsync the worktree");
    let out = run(
        "rsync",
        &rsync_argv(&opts.target, &opts.worktree, &run_dir),
        None,
    )?;
    if !out.status.success() {
        failures.push(format!("rsync failed: {}", out.stderr.trim()));
        return finish(opts, &run_dir, failures, None, None);
    }

    // 3. The build.
    step("build the workspace, release");
    let out = run(
        "ssh",
        &ssh_argv(&opts.target, &build_command(&run_dir, opts.jobs)),
        None,
    )?;
    print!("{}", out.stdout);
    if !out.status.success() {
        eprint!("{}", out.stderr);
        failures.push("remote `cargo build --release --workspace` failed".to_string());
        return finish(opts, &run_dir, failures, None, None);
    }

    // 4. doctor --json and the manifest comparison.
    step("doctor --json");
    let doctor_run = run(
        "ssh",
        &ssh_argv(&opts.target, &doctor_command(&run_dir)),
        None,
    )?;
    if !doctor_run.stderr.trim().is_empty() {
        eprint!("{}", doctor_run.stderr);
    }
    let doctor_text = match run(
        "ssh",
        &ssh_argv(
            &opts.target,
            &format!("cat {}/doctor.json", run_path(&run_dir)),
        ),
        None,
    ) {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            failures.push(format!(
                "doctor produced no readable doctor.json: {}",
                o.stderr.trim()
            ));
            String::new()
        }
        Err(e) => {
            failures.push(format!("could not read doctor.json: {e}"));
            String::new()
        }
    };
    if !doctor_text.is_empty() {
        std::fs::write(opts.evidence.join("doctor.json"), &doctor_text)?;
    }
    if !doctor_run.status.success() {
        failures.push(format!(
            "`ouro-jail doctor --json` exited {}",
            doctor_run
                .status
                .code()
                .map_or_else(|| "on a signal".to_string(), |c| c.to_string())
        ));
    }

    step("compare doctor with the expected-capability manifest");
    match Manifest::load(&opts.manifest) {
        Err(e) => failures.push(e),
        Ok(m) => match serde_json::from_str::<Value>(&doctor_text) {
            Err(e) => failures.push(format!(
                "doctor.json is not JSON ({e}), so not one of the {} manifest \
                 capabilities could be compared",
                m.expected.len()
            )),
            Ok(doctor) => {
                let rows = manifest::compare(&m, &doctor);
                for row in &rows {
                    let actual = row.actual.as_deref().unwrap_or("<absent>");
                    println!(
                        "   {:<32} expected {:<12} got {:<12} {}",
                        row.name,
                        row.expected,
                        actual,
                        if row.ok() { "ok" } else { "MISMATCH" }
                    );
                    if let Some(p) = &row.problem {
                        failures.push(format!("capability `{}`: {p}", row.name));
                    }
                }
                for name in manifest::unlisted(&m, &doctor) {
                    println!("   note: doctor reports `{name}`, which the manifest does not list");
                }
            }
        },
    }

    // 5. The suite.
    step("run the conformance suite (OURO_CONFORMANCE=1)");
    let suite = run(
        "ssh",
        &ssh_argv(&opts.target, &test_command(&run_dir, opts.jobs)),
        None,
    )?;
    print!("{}", suite.stdout);
    if !suite.stderr.trim().is_empty() {
        eprint!("{}", suite.stderr);
    }
    std::fs::write(opts.evidence.join("test.log"), &suite.stdout)?;
    if !suite.status.success() {
        failures.push("the remote conformance suite failed".to_string());
    }

    // 6. The host manifest, collected with the checked-in script.
    step("collect the host manifest");
    match run(
        "ssh",
        &ssh_argv(&opts.target, "bash -s"),
        Some(&opts.host_manifest_script),
    ) {
        Ok(o) if o.status.success() => {
            std::fs::write(opts.evidence.join("host-manifest.txt"), &o.stdout)?;
        }
        Ok(o) => failures.push(format!("host-manifest.sh failed: {}", o.stderr.trim())),
        Err(e) => failures.push(format!("host-manifest.sh could not run: {e}")),
    }

    finish(
        opts,
        &run_dir,
        failures,
        Some(doctor_text),
        Some(suite.stdout),
    )
}

fn finish(
    opts: &Options,
    run_dir: &str,
    failures: Vec<String>,
    _doctor: Option<String>,
    _suite: Option<String>,
) -> std::io::Result<Report> {
    let remote = run_path_for_humans(run_dir);
    if failures.is_empty() && !opts.keep_remote {
        step("remove the remote run directory");
        let _ = run(
            "ssh",
            &ssh_argv(&opts.target, &format!("rm -rf {}", run_path(run_dir))),
            None,
        );
    }

    println!();
    if failures.is_empty() {
        println!("conformance: PASS");
        println!("evidence: {}", opts.evidence.display());
    } else {
        println!("conformance: FAIL ({} problem(s))", failures.len());
        for f in &failures {
            println!("  - {f}");
        }
        println!(
            "remote run directory kept: {}@{}:{remote}",
            opts.target.user, opts.target.host
        );
        println!("evidence: {}", opts.evidence.display());
    }

    let summary = if failures.is_empty() {
        format!("conformance PASS {run_dir}\n")
    } else {
        format!(
            "conformance FAIL {run_dir}\n{}\n",
            failures
                .iter()
                .map(|f| format!("- {f}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let _ = std::fs::write(opts.evidence.join("summary.txt"), summary);

    Ok(Report {
        failures,
        remote_dir: remote,
        evidence: opts.evidence.clone(),
    })
}

fn git_short_sha(worktree: &Path) -> String {
    Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// The repository root of the current worktree.
#[must_use]
pub fn worktree_root() -> PathBuf {
    Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            host: "198.51.100.7".into(),
            user: "ouro-ci".into(),
            key: PathBuf::from("/home/runner/.ssh/ouro_ci"),
            known_hosts: None,
        }
    }

    #[test]
    fn ssh_options_are_batch_and_strict_and_never_learn_a_host_key() {
        let opts = ssh_opts(&target());
        assert_eq!(
            opts,
            vec![
                "-i",
                "/home/runner/.ssh/ouro_ci",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes"
            ]
        );
        assert!(!opts.iter().any(|o| o.contains("accept-new")));
    }

    #[test]
    fn known_hosts_is_added_only_when_given() {
        let mut t = target();
        assert!(
            !ssh_opts(&t)
                .iter()
                .any(|o| o.contains("UserKnownHostsFile"))
        );
        t.known_hosts = Some(PathBuf::from("/home/runner/.ssh/known_hosts"));
        assert!(
            ssh_opts(&t)
                .iter()
                .any(|o| o == "UserKnownHostsFile=/home/runner/.ssh/known_hosts")
        );
    }

    #[test]
    fn the_ssh_argv_ends_with_the_destination_then_the_command() {
        let argv = ssh_argv(&target(), "echo hi");
        assert_eq!(argv[argv.len() - 2], "ouro-ci@198.51.100.7");
        assert_eq!(argv[argv.len() - 1], "echo hi");
    }

    #[test]
    fn rsync_excludes_target_and_git_and_ends_the_source_with_a_slash() {
        let argv = rsync_argv(&target(), Path::new("/w/tree"), "20260922T000000Z-abc123");
        assert!(argv.contains(&"--delete".to_string()));
        let excludes: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, a)| *a == "--exclude" && *i + 1 < argv.len())
            .map(|(i, _)| &argv[i + 1])
            .collect();
        assert_eq!(excludes, vec!["target", ".git"]);
        assert_eq!(argv[argv.len() - 2], "/w/tree/");
        assert_eq!(
            argv[argv.len() - 1],
            "ouro-ci@198.51.100.7:ouro-ci/runs/20260922T000000Z-abc123/"
        );
        let rsh = argv.iter().position(|a| a == "-e").unwrap();
        assert!(argv[rsh + 1].starts_with("ssh -i "));
        assert!(argv[rsh + 1].contains("BatchMode=yes"));
    }

    #[test]
    fn a_source_path_that_already_ends_in_a_slash_is_not_doubled() {
        let argv = rsync_argv(&target(), Path::new("/w/tree/"), "d");
        assert_eq!(argv[argv.len() - 2], "/w/tree/");
    }

    #[test]
    fn run_directory_names_sort_and_stay_shell_safe() {
        let a = run_dir_name("20260922T044450Z", "6121a2e0520c");
        assert_eq!(a, "20260922T044450Z-6121a2e0520c");
        assert!(is_shell_safe(&a));

        let dirty = run_dir_name("20260922T044450Z", "abc; rm -rf /");
        assert_eq!(dirty, "20260922T044450Z-abcrmrf");
        assert!(is_shell_safe(&dirty));

        let none = run_dir_name("20260922T044450Z", "");
        assert_eq!(none, "20260922T044450Z-nosha");
        assert!(is_shell_safe(&none));
    }

    #[test]
    fn shell_safety_rejects_what_would_need_quoting() {
        assert!(is_shell_safe("20260922T044450Z-abc"));
        assert!(!is_shell_safe(""));
        assert!(!is_shell_safe("a b"));
        assert!(!is_shell_safe("a;b"));
        assert!(!is_shell_safe("a$b"));
        assert!(!is_shell_safe("a/b"));
    }

    #[test]
    fn the_remote_commands_use_the_account_cargo_and_two_jobs() {
        let b = build_command("d", 2);
        assert!(
            b.contains("$HOME/.cargo/bin/cargo build --release --workspace -j2"),
            "{b}"
        );
        assert!(b.starts_with("cd $HOME/ouro-ci/runs/d &&"), "{b}");
    }

    #[test]
    fn the_test_command_forbids_skips_and_names_both_binaries() {
        let t = test_command("d", 2);
        assert!(t.contains("OURO_CONFORMANCE=1"), "{t}");
        assert!(
            t.contains("OURO_JAIL_BIN=$PWD/target/release/ouro-jail"),
            "{t}"
        );
        assert!(
            t.contains("OURO_FIXTURE_BIN=$PWD/target/release/ouro-fixture"),
            "{t}"
        );
        assert!(
            t.contains("--test-threads=1"),
            "the suite runs serially because a tracer owns every waitpid in its process: {t}"
        );
        assert!(t.contains("> test.log 2>&1"), "{t}");
        assert!(
            t.contains("exit $rc"),
            "the suite's own status must survive"
        );
        assert!(
            !t.contains("| tee"),
            "tee would mask the suite's exit status"
        );
    }

    #[test]
    fn the_printed_run_path_is_pasteable_and_the_shell_one_expands() {
        assert_eq!(run_path("d"), "$HOME/ouro-ci/runs/d");
        assert_eq!(run_path_for_humans("d"), "~/ouro-ci/runs/d");
        assert!(
            !run_path_for_humans("d").contains('$'),
            "a printed path must not carry an unexpanded shell variable"
        );
    }

    #[test]
    fn the_doctor_command_keeps_its_own_exit_status() {
        let d = doctor_command("d");
        assert!(d.contains("doctor --json > doctor.json"), "{d}");
        assert!(d.contains("exit $rc"), "{d}");
    }
}
