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
        // ssh parses this option again as configuration, including its list
        // of paths. Preserve one filename through that second parser too.
        let path = kh
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        v.push(format!("UserKnownHostsFile=\"{path}\""));
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
        // rsync parses -e itself: quote an argument and double embedded quotes.
        s.push('\'');
        s.push_str(&opt.replace('\'', "''"));
        s.push('\'');
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
        // Anchored: an unanchored `target` would drop any directory of that
        // name anywhere in the tree, and would also shield a stale remote
        // `target/` from `--delete`.
        "--exclude".to_string(),
        "/target".to_string(),
        "--exclude".to_string(),
        "/.git".to_string(),
        // The runner writes its own evidence beside the checkout; there is no
        // reason to push it to the shared host.
        "--exclude".to_string(),
        "/evidence".to_string(),
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

/// The remote I02 vendor-name scan (jail-v1 §15 row I02).
///
/// Nothing ran it before, so a vendor name in the execution core landed green.
#[must_use]
pub fn i02_command(run_dir: &str) -> String {
    format!(
        "cd {} && {REMOTE_CARGO} run --release -p xtask -- i02-scan",
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
         {REMOTE_CARGO} test --workspace --release -j{jobs} --no-fail-fast \
         -- --test-threads=1 \
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

fn run(
    program: &str,
    args: &[String],
    stdin_file: Option<&Path>,
) -> std::io::Result<CommandResult> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(path) = stdin_file {
        cmd.stdin(std::fs::File::open(path)?);
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    let out = cmd.output()?;
    Ok(CommandResult {
        code: out.status.code(),
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

// ------------------------------------------------------- the decision, as data
//
// Everything the live steps produce is recorded as plain values, and one pure
// function turns those values into the failure list and the keep-or-remove
// decision. Nothing tested the driver's enforcement before: deleting the
// suite's exit-code check left `cargo test -p xtask` fully green while a live
// run printed PASS with a panic in the uploaded evidence.

/// What one shelled-out step produced.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    #[must_use]
    pub fn status_text(&self) -> String {
        match self.code {
            Some(c) => c.to_string(),
            None => "a signal".to_string(),
        }
    }
}

/// Every live step's outcome. `None` means the step did not run, because an
/// earlier one failed; that is not itself a failure.
#[derive(Debug, Default)]
pub struct RunOutcomes {
    pub remote_created: bool,
    pub mkdir: Option<CommandResult>,
    pub rsync: Option<CommandResult>,
    pub build: Option<CommandResult>,
    pub i02: Option<CommandResult>,
    pub doctor: Option<CommandResult>,
    /// The bytes of `doctor.json`, when they could be read back.
    pub doctor_json: Option<String>,
    pub suite: Option<CommandResult>,
    /// The full `test.log`, which is the only test evidence.
    pub test_log: Option<String>,
    pub host_manifest: Option<CommandResult>,
    /// Anything that went wrong writing the local evidence.
    pub evidence_errors: Vec<String>,
}

/// What the driver decided.
#[derive(Debug)]
pub struct Decision {
    pub failures: Vec<String>,
    pub keep_remote: bool,
}

/// Cargo prints one of these for every test binary; the process exit code
/// alone is not enough when a run is allowed to continue past a failure.
const FAILED_BINARY_MARKER: &str = "test result: FAILED";
/// The harness prints this for every live test it did not run.
const SKIP_MARKER: &str = "skipped:";

/// Turn the step results into failures. Pure: every branch is unit-tested.
#[must_use]
pub fn decide(
    outcomes: &RunOutcomes,
    manifest: Option<&Manifest>,
    keep_remote_flag: bool,
) -> Decision {
    let mut failures: Vec<String> = Vec::new();

    fn step(failures: &mut Vec<String>, name: &str, result: &Option<CommandResult>) -> bool {
        match result {
            None => false,
            Some(r) if r.ok() => true,
            Some(r) => {
                failures.push(format!(
                    "{name} exited {}{}",
                    r.status_text(),
                    first_line(&r.stderr)
                ));
                false
            }
        }
    }

    if !step(&mut failures, "the remote run directory", &outcomes.mkdir) && outcomes.mkdir.is_some()
    {
        return finish_decision(failures, outcomes, keep_remote_flag);
    }
    if outcomes.mkdir.is_none() {
        failures.push("the run did not start".to_string());
        return finish_decision(failures, outcomes, keep_remote_flag);
    }
    if !step(&mut failures, "rsync", &outcomes.rsync) {
        return finish_decision(failures, outcomes, keep_remote_flag);
    }
    if !step(&mut failures, "the remote release build", &outcomes.build) {
        return finish_decision(failures, outcomes, keep_remote_flag);
    }
    step(&mut failures, "the I02 vendor-name scan", &outcomes.i02);

    // doctor and the manifest comparison.
    match &outcomes.doctor {
        None => failures.push("`ouro-jail doctor --json` did not run".to_string()),
        Some(r) if !r.ok() => failures.push(format!(
            "`ouro-jail doctor --json` exited {}{}",
            r.status_text(),
            first_line(&r.stderr)
        )),
        Some(_) => {}
    }
    let expected = manifest.map_or(0, |m| m.expected.len());
    match (&outcomes.doctor_json, manifest) {
        (None, _) => failures.push(format!(
            "doctor.json could not be read, so none of the {expected} manifest \
             capabilities could be compared"
        )),
        (Some(_), None) => {
            failures.push("the expected-capability manifest could not be loaded".to_string());
        }
        (Some(text), Some(m)) => match serde_json::from_str::<Value>(text) {
            Err(e) => failures.push(format!(
                "doctor.json is not JSON ({e}), so none of the {expected} manifest \
                 capabilities could be compared"
            )),
            Ok(doctor) => {
                for row in manifest::compare(m, &doctor) {
                    if let Some(p) = &row.problem {
                        failures.push(format!("capability `{}`: {p}", row.name));
                    }
                }
            }
        },
    }

    // The suite. Its exit code, every test binary's own verdict, and skips.
    match &outcomes.suite {
        None => failures.push("the remote conformance suite did not run".to_string()),
        Some(r) if !r.ok() => failures.push(format!(
            "the remote conformance suite exited {}",
            r.status_text()
        )),
        Some(_) => {}
    }
    match &outcomes.test_log {
        None => failures.push("test.log could not be read, so no test evidence exists".to_string()),
        Some(log) => {
            // `--no-fail-fast` lets later binaries run, so a failure in any of
            // them must count, not only in the last one cargo reported.
            let failed_binaries = log.matches(FAILED_BINARY_MARKER).count();
            if failed_binaries > 0 {
                failures.push(format!(
                    "{failed_binaries} test binar{} reported FAILED",
                    if failed_binaries == 1 { "y" } else { "ies" }
                ));
            }
            // The suite runs under OURO_CONFORMANCE=1, where a skip is
            // already a failure; a `skipped:` line therefore means the rule
            // was bypassed, and the job must not be green.
            let skips: Vec<&str> = log
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with(SKIP_MARKER))
                .collect();
            if !skips.is_empty() {
                failures.push(format!(
                    "{} live test(s) were skipped under OURO_CONFORMANCE=1: {}",
                    skips.len(),
                    skips.join(" | ")
                ));
            }
            if !log.contains("test result:") {
                failures.push("test.log contains no test result at all".to_string());
            }
        }
    }

    step(&mut failures, "the host manifest", &outcomes.host_manifest);
    if outcomes.host_manifest.is_none() {
        failures.push("the host manifest was not collected".to_string());
    }
    for e in &outcomes.evidence_errors {
        failures.push(format!("evidence: {e}"));
    }

    finish_decision(failures, outcomes, keep_remote_flag)
}

fn finish_decision(failures: Vec<String>, outcomes: &RunOutcomes, keep_flag: bool) -> Decision {
    let keep_remote = outcomes.remote_created && (!failures.is_empty() || keep_flag);
    Decision {
        failures,
        keep_remote,
    }
}

/// The first line of a diagnostic, scrubbed, for a failure message.
fn first_line(stderr: &str) -> String {
    let line = stderr.lines().map(str::trim).find(|l| !l.is_empty());
    match line {
        Some(l) => format!(": {}", scrub(l)),
        None => String::new(),
    }
}

/// Remove anything that names a local secret from text that becomes evidence.
///
/// `evidence/summary.txt` is uploaded as a build artifact, and ssh's own
/// diagnostics quote the identity file by path. Key material never reached it,
/// but the path to the operator's private key did.
#[must_use]
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for word in text.split_inclusive(char::is_whitespace) {
        let trimmed = word.trim_end();
        let looks_like_a_path = trimmed.starts_with('/') || trimmed.starts_with('~');
        if looks_like_a_path {
            out.push_str("<path>");
            out.push_str(&word[trimmed.len()..]);
        } else {
            out.push_str(word);
        }
    }
    for marker in [
        "Identity file",
        "Host key",
        "UserKnownHostsFile",
        "ssh-rsa",
        "ssh-ed25519",
    ] {
        if out.contains(marker) {
            return format!(
                "<{} diagnostic withheld from the evidence>",
                marker.to_lowercase()
            );
        }
    }
    out
}

// ------------------------------------------------------------------- the run

/// Drive one conformance run. Returns the report; the caller sets the exit code.
pub fn drive(opts: &Options) -> std::io::Result<Report> {
    let short_sha = git_short_sha(&opts.worktree);
    let run_dir = run_dir_name(&stamp::utc_stamp_now(), &short_sha);
    assert!(
        is_shell_safe(&run_dir),
        "run directory name `{run_dir}` is not shell safe"
    );

    let mut outcomes = RunOutcomes::default();
    let manifest = match Manifest::load(&opts.manifest) {
        Ok(m) => Some(m),
        Err(e) => {
            outcomes.evidence_errors.push(e);
            None
        }
    };

    if let Err(e) = std::fs::create_dir_all(&opts.evidence) {
        outcomes
            .evidence_errors
            .push(format!("{}: {e}", opts.evidence.display()));
    }

    // The key must be the key that was named. Without this check ssh falls
    // back to the agent or the default identity and the run proceeds under a
    // different credential.
    if !opts.target.key.is_file() {
        outcomes
            .evidence_errors
            .push("the private key named by --key does not exist".to_string());
        let decision = decide(&outcomes, manifest.as_ref(), opts.keep_remote);
        return report(opts, &run_dir, decision);
    }

    println!(
        "conformance: {}@{} run {run_dir} at {}",
        opts.target.user,
        opts.target.host,
        stamp::rfc3339_from_unix(stamp::unix_now())
    );
    println!("worktree: {}", opts.worktree.display());

    step("create the remote run directory");
    outcomes.mkdir = Some(ssh(opts, &format!("mkdir -p {}", run_path(&run_dir)))?);
    outcomes.remote_created = outcomes.mkdir.as_ref().is_some_and(CommandResult::ok);

    if outcomes.remote_created {
        step("rsync the worktree");
        outcomes.rsync = Some(run(
            "rsync",
            &rsync_argv(&opts.target, &opts.worktree, &run_dir),
            None,
        )?);
    }

    if outcomes.rsync.as_ref().is_some_and(CommandResult::ok) {
        step("build the workspace, release");
        let r = ssh(opts, &build_command(&run_dir, opts.jobs))?;
        print!("{}", r.stdout);
        if !r.ok() {
            eprint!("{}", r.stderr);
        }
        outcomes.build = Some(r);
    }

    if outcomes.build.as_ref().is_some_and(CommandResult::ok) {
        step("I02 vendor-name scan");
        let r = ssh(opts, &i02_command(&run_dir))?;
        print!("{}", r.stdout);
        outcomes.i02 = Some(r);

        step("doctor --json");
        let d = ssh(opts, &doctor_command(&run_dir))?;
        if !d.stderr.trim().is_empty() {
            eprint!("{}", d.stderr);
        }
        outcomes.doctor = Some(d);

        let cat = ssh(opts, &format!("cat {}/doctor.json", run_path(&run_dir)))?;
        if cat.ok() && !cat.stdout.trim().is_empty() {
            outcomes.doctor_json = Some(cat.stdout.clone());
            write_evidence(opts, "doctor.json", &cat.stdout, &mut outcomes);
        }

        step("compare doctor with the expected-capability manifest");
        if let (Some(m), Some(text)) = (manifest.as_ref(), outcomes.doctor_json.as_ref())
            && let Ok(doctor) = serde_json::from_str::<Value>(text)
        {
            for row in manifest::compare(m, &doctor) {
                println!(
                    "   {:<34} expected {:<12} got {:<12} {}",
                    row.name,
                    row.expected,
                    row.actual.as_deref().unwrap_or("<absent>"),
                    if row.ok() { "ok" } else { "MISMATCH" }
                );
            }
            for name in manifest::unlisted(m, &doctor) {
                println!("   note: doctor reports `{name}`, which the manifest does not list");
            }
        }

        step("run the conformance suite (OURO_CONFORMANCE=1)");
        let suite = ssh(opts, &test_command(&run_dir, opts.jobs))?;
        print!("{}", suite.stdout);
        if !suite.stderr.trim().is_empty() {
            eprint!("{}", suite.stderr);
        }
        outcomes.test_log = Some(suite.stdout.clone());
        write_evidence(opts, "test.log", &suite.stdout, &mut outcomes);
        outcomes.suite = Some(suite);
    }

    step("collect the host manifest");
    let hm = run(
        "ssh",
        &ssh_argv(&opts.target, "bash -s"),
        Some(&opts.host_manifest_script),
    )?;
    if hm.ok() {
        write_evidence(opts, "host-manifest.txt", &hm.stdout, &mut outcomes);
    }
    outcomes.host_manifest = Some(hm);

    let decision = decide(&outcomes, manifest.as_ref(), opts.keep_remote);

    if outcomes.remote_created && !decision.keep_remote {
        step("remove the remote run directory");
        let rm = ssh(opts, &format!("rm -rf {}", run_path(&run_dir)))?;
        if !rm.ok() {
            eprintln!(
                "conformance: the remote run directory could not be removed ({})",
                rm.status_text()
            );
        }
        prune_old_runs(opts);
    }

    report(opts, &run_dir, decision)
}

fn ssh(opts: &Options, remote_command: &str) -> std::io::Result<CommandResult> {
    run("ssh", &ssh_argv(&opts.target, remote_command), None)
}

fn write_evidence(opts: &Options, name: &str, body: &str, outcomes: &mut RunOutcomes) {
    if let Err(e) = std::fs::write(opts.evidence.join(name), body) {
        outcomes.evidence_errors.push(format!("{name}: {e}"));
    }
}

/// Remove run directories older than a week, by exact name.
///
/// `~/ouro-ci/runs` is the driver's own directory and nothing prunes it; a
/// kept failure is a few hundred megabytes. Names are listed and matched
/// against their own timestamp prefix: no wildcard reaches the host.
fn prune_old_runs(opts: &Options) {
    let Ok(listing) = ssh(opts, &format!("ls -1 $HOME/{REMOTE_RUNS} 2>/dev/null")) else {
        return;
    };
    if !listing.ok() {
        return;
    }
    let cutoff = stamp::utc_stamp_from_unix(stamp::unix_now() - 7 * 86_400);
    for name in listing.stdout.lines().map(str::trim) {
        if !is_shell_safe(name) || !older_than(name, &cutoff) {
            continue;
        }
        let _ = ssh(opts, &format!("rm -rf $HOME/{REMOTE_RUNS}/{name}"));
        println!("   pruned {name}");
    }
}

/// Is this run directory's stamp before the cutoff?
#[must_use]
pub fn older_than(name: &str, cutoff_stamp: &str) -> bool {
    let Some((stamp, _)) = name.split_once('-') else {
        return false;
    };
    // Only a well-formed stamp is ever considered for removal.
    stamp.len() == cutoff_stamp.len()
        && stamp.ends_with('Z')
        && stamp.contains('T')
        && stamp < cutoff_stamp
}

fn report(opts: &Options, run_dir: &str, decision: Decision) -> std::io::Result<Report> {
    let remote = run_path_for_humans(run_dir);

    println!();
    if decision.failures.is_empty() {
        println!("conformance: PASS");
    } else {
        println!("conformance: FAIL ({} problem(s))", decision.failures.len());
        for f in &decision.failures {
            println!("  - {f}");
        }
        if decision.keep_remote {
            println!(
                "remote run directory kept: {}@{}:{remote}",
                opts.target.user, opts.target.host
            );
        } else {
            println!("no remote run directory was created");
        }
    }
    println!("evidence: {}", opts.evidence.display());

    let summary = if decision.failures.is_empty() {
        format!("conformance PASS {run_dir}\n")
    } else {
        format!(
            "conformance FAIL {run_dir}\n{}\n",
            decision
                .failures
                .iter()
                .map(|f| format!("- {f}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    if let Err(e) = std::fs::write(opts.evidence.join("summary.txt"), summary) {
        eprintln!("conformance: the summary could not be written: {e}");
    }

    Ok(Report {
        failures: decision.failures,
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
                .any(|o| o == "UserKnownHostsFile=\"/home/runner/.ssh/known_hosts\"")
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
        assert_eq!(argv[argv.len() - 2], "/w/tree/");
        assert_eq!(
            argv[argv.len() - 1],
            "ouro-ci@198.51.100.7:ouro-ci/runs/20260922T000000Z-abc123/"
        );
        let rsh = argv.iter().position(|a| a == "-e").unwrap();
        assert!(argv[rsh + 1].starts_with("ssh '-i' "));
        assert!(argv[rsh + 1].contains("BatchMode=yes"));
    }

    #[test]
    fn a_source_path_that_already_ends_in_a_slash_is_not_doubled() {
        let argv = rsync_argv(&target(), Path::new("/w/tree/"), "d");
        assert_eq!(argv[argv.len() - 2], "/w/tree/");
    }

    #[test]
    fn rsync_transport_quotes_whitespace_and_both_quote_kinds() {
        let mut t = target();
        t.key = PathBuf::from("/keys/a b'c\"d");
        t.known_hosts = Some(PathBuf::from("/hosts/a b'c\"d"));
        let command = rsh_string(&t);
        assert!(command.contains("'-i' '/keys/a b''c\"d'"));
        assert!(command.contains("'UserKnownHostsFile=\"/hosts/a b''c\\\"d\"'"));
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

    // ------------------------------------------------- the decision function
    //
    // Every one of these used to be untested: the driver's only enforcement
    // was a line in `drive()` that no test reached, so deleting the suite's
    // exit-code check left `cargo test -p xtask` green while a live run
    // printed PASS with a panic in the uploaded evidence.

    fn okc() -> CommandResult {
        CommandResult {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn failed(code: i32, stderr: &str) -> CommandResult {
        CommandResult {
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    fn a_manifest() -> Manifest {
        Manifest {
            expected: std::collections::BTreeMap::from([(
                "bwrap_present".to_string(),
                "available".to_string(),
            )]),
        }
    }

    const GOOD_DOCTOR: &str = r#"{"capabilities":[{"name":"bwrap_present","status":"available"}]}"#;
    const GOOD_LOG: &str = "running 3 tests\ntest result: ok. 3 passed; 0 failed\n";

    fn a_clean_run() -> RunOutcomes {
        RunOutcomes {
            remote_created: true,
            mkdir: Some(okc()),
            rsync: Some(okc()),
            build: Some(okc()),
            i02: Some(okc()),
            doctor: Some(okc()),
            doctor_json: Some(GOOD_DOCTOR.to_string()),
            suite: Some(okc()),
            test_log: Some(GOOD_LOG.to_string()),
            host_manifest: Some(okc()),
            evidence_errors: Vec::new(),
        }
    }

    fn verdict(o: &RunOutcomes) -> Decision {
        decide(o, Some(&a_manifest()), false)
    }

    #[test]
    fn a_clean_run_passes_and_the_remote_directory_is_removed() {
        let d = verdict(&a_clean_run());
        assert!(d.failures.is_empty(), "{:?}", d.failures);
        assert!(!d.keep_remote);
    }

    #[test]
    fn a_failing_suite_exit_code_fails_the_run() {
        let mut o = a_clean_run();
        o.suite = Some(failed(101, ""));
        let d = verdict(&o);
        assert!(
            d.failures.iter().any(|f| f.contains("suite exited 101")),
            "{:?}",
            d.failures
        );
        assert!(d.keep_remote, "a failed run keeps its directory");
    }

    #[test]
    fn a_failure_in_any_test_binary_counts_not_only_the_last() {
        // `--no-fail-fast` lets later binaries run and report `ok` after an
        // earlier one failed; the process code is the safety net, and this is
        // the second one.
        let mut o = a_clean_run();
        o.test_log = Some(
            "test result: ok. 4 passed; 0 failed\n\
             test result: FAILED. 1 passed; 2 failed\n\
             test result: ok. 9 passed; 0 failed\n"
                .to_string(),
        );
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.contains("1 test binary reported FAILED")),
            "{:?}",
            d.failures
        );

        o.test_log = Some(
            "test result: FAILED. 0 passed; 1 failed\n\
             test result: FAILED. 0 passed; 3 failed\n"
                .to_string(),
        );
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("2 test binaries reported FAILED")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn a_skipped_live_test_fails_the_run() {
        let mut o = a_clean_run();
        o.test_log = Some(
            "running 2 tests\n\
             skipped: strace is not installed on this host\n\
             skipped: bubblewrap is not installed on this host\n\
             test result: ok. 2 passed; 0 failed\n"
                .to_string(),
        );
        let d = verdict(&o);
        let named = d
            .failures
            .iter()
            .find(|f| f.contains("were skipped"))
            .expect("a skip under conformance mode is a failure");
        assert!(named.contains("2 live test(s)"), "{named}");
        assert!(named.contains("strace"), "{named}");
        assert!(named.contains("bubblewrap"), "{named}");
    }

    #[test]
    fn an_empty_or_unreadable_test_log_fails_the_run() {
        let mut o = a_clean_run();
        o.test_log = None;
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("no test evidence")),
            "{:?}",
            verdict(&o).failures
        );

        o.test_log = Some("warning: something\n".to_string());
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("no test result at all")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn each_earlier_step_fails_the_run_and_stops_the_later_ones() {
        // mkdir
        let mut o = RunOutcomes {
            mkdir: Some(failed(255, "Host key verification failed")),
            ..RunOutcomes::default()
        };
        let d = verdict(&o);
        assert_eq!(d.failures.len(), 1, "{:?}", d.failures);
        assert!(d.failures[0].contains("remote run directory exited 255"));
        assert!(!d.keep_remote, "nothing was created, nothing to keep");

        // rsync
        o = a_clean_run();
        o.rsync = Some(failed(23, "rsync error"));
        o.build = None;
        let d = verdict(&o);
        assert_eq!(d.failures.len(), 1, "{:?}", d.failures);
        assert!(d.failures[0].contains("rsync exited 23"));
        assert!(d.keep_remote);

        // build
        o = a_clean_run();
        o.build = Some(failed(101, "error[E0433]"));
        o.i02 = None;
        o.doctor = None;
        o.doctor_json = None;
        o.suite = None;
        o.test_log = None;
        let d = verdict(&o);
        assert_eq!(d.failures.len(), 1, "{:?}", d.failures);
        assert!(d.failures[0].contains("release build exited 101"));
    }

    #[test]
    fn the_i02_scan_gates_the_run() {
        let mut o = a_clean_run();
        o.i02 = Some(failed(1, "src/launch.rs:2: vendor name"));
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("I02 vendor-name scan exited 1")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn a_doctor_that_failed_or_produced_no_json_fails_the_run() {
        let mut o = a_clean_run();
        o.doctor = Some(failed(127, "ouro-jail: not found"));
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("doctor --json` exited 127")),
            "{:?}",
            verdict(&o).failures
        );

        o = a_clean_run();
        o.doctor_json = None;
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.contains("none of the 1 manifest capabilities")),
            "{:?}",
            d.failures
        );

        o = a_clean_run();
        o.doctor_json = Some("not json at all".to_string());
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("doctor.json is not JSON")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn a_manifest_mismatch_fails_the_run_in_both_directions() {
        let mut o = a_clean_run();
        o.doctor_json = Some(
            r#"{"capabilities":[{"name":"bwrap_present","status":"unavailable"}]}"#.to_string(),
        );
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("capability `bwrap_present`")),
            "{:?}",
            verdict(&o).failures
        );

        o.doctor_json = Some(r#"{"capabilities":[]}"#.to_string());
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("not reported by doctor")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn a_manifest_that_did_not_load_fails_the_run() {
        let o = a_clean_run();
        let d = decide(&o, None, false);
        assert!(
            d.failures
                .iter()
                .any(|f| f.contains("manifest could not be loaded")),
            "{:?}",
            d.failures
        );
    }

    #[test]
    fn a_missing_host_manifest_or_evidence_write_fails_the_run() {
        let mut o = a_clean_run();
        o.host_manifest = Some(failed(1, "bash: line 1"));
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("host manifest exited 1")),
            "{:?}",
            verdict(&o).failures
        );

        o = a_clean_run();
        o.host_manifest = None;
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("host manifest was not collected")),
            "{:?}",
            verdict(&o).failures
        );

        o = a_clean_run();
        o.evidence_errors = vec!["doctor.json: Read-only file system".to_string()];
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.starts_with("evidence:")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn keep_remote_is_honoured_on_a_clean_run_and_never_invents_a_directory() {
        let clean = a_clean_run();
        assert!(decide(&clean, Some(&a_manifest()), true).keep_remote);

        let never_created = RunOutcomes {
            remote_created: false,
            mkdir: Some(failed(255, "")),
            ..RunOutcomes::default()
        };
        assert!(!decide(&never_created, Some(&a_manifest()), true).keep_remote);
    }

    #[test]
    fn a_signal_killed_step_is_a_failure_and_says_so() {
        let mut o = a_clean_run();
        o.suite = Some(CommandResult {
            code: None,
            stdout: String::new(),
            stderr: String::new(),
        });
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("suite exited a signal")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn no_local_path_reaches_a_failure_message() {
        // `evidence/summary.txt` is uploaded as a build artifact; ssh quotes
        // the identity file by path in its own diagnostics.
        let raw = "Warning: Identity file /Users/someone/.ssh/ouro_key not accessible";
        let scrubbed = scrub(raw);
        assert!(!scrubbed.contains("/Users/someone"), "{scrubbed}");
        assert!(!scrubbed.contains("ouro_key"), "{scrubbed}");

        let plain = "Permission denied (publickey).";
        assert_eq!(scrub(plain), plain);

        assert_eq!(scrub("rsync: /a/b/c failed"), "rsync: <path> failed");
        assert!(scrub("Host key for 1.2.3.4 has changed").starts_with('<'));

        let mut o = a_clean_run();
        o.mkdir = Some(failed(255, raw));
        o.remote_created = false;
        let d = verdict(&o);
        for f in &d.failures {
            assert!(!f.contains("/Users/someone"), "{f}");
        }
    }

    #[test]
    fn only_a_well_formed_stamp_older_than_the_cutoff_is_pruned() {
        let cutoff = "20260922T000000Z";
        assert!(older_than("20260901T120000Z-abc123", cutoff));
        assert!(!older_than("20260923T120000Z-abc123", cutoff));
        assert!(
            !older_than("20260922T000000Z-abc123", cutoff),
            "not strictly older"
        );
        assert!(!older_than("nostamp", cutoff));
        assert!(!older_than("short-abc", cutoff));
        assert!(!older_than("2026090112000ZZ-abc", cutoff), "wrong shape");
    }

    #[test]
    fn the_remote_scan_runs_before_the_suite_and_uses_the_account_cargo() {
        let c = i02_command("d");
        assert!(
            c.contains("$HOME/.cargo/bin/cargo run --release -p xtask -- i02-scan"),
            "{c}"
        );
        assert!(c.starts_with("cd $HOME/ouro-ci/runs/d &&"), "{c}");
    }

    #[test]
    fn the_suite_does_not_stop_at_the_first_failing_binary() {
        let t = test_command("d", 2);
        assert!(t.contains("--no-fail-fast"), "{t}");
        assert!(
            t.contains("--test-threads=1"),
            "one tracer per process: {t}"
        );
    }

    #[test]
    fn the_rsync_excludes_are_anchored_and_cover_the_local_evidence() {
        let argv = rsync_argv(&target(), Path::new("/w/tree"), "d");
        let excludes: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, a)| *a == "--exclude" && *i + 1 < argv.len())
            .map(|(i, _)| &argv[i + 1])
            .collect();
        assert_eq!(excludes, vec!["/target", "/.git", "/evidence"]);
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
