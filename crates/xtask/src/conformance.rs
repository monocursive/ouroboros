//! The conformance driver of jail-v1 §16 and contract §3.8.
//!
//! A GitHub-hosted runner, or a developer machine, drives the provisioned
//! Linux reference host over SSH as the `ouro-ci` account. Nothing is
//! installed on the host and nothing there polls anything: the driver copies
//! the tree into a per-run directory, builds, runs `doctor --json`, compares
//! it with the pinned manifest, runs the suite with `OURO_CONFORMANCE=1` so a
//! skip is a failure, copies the evidence back and removes the run directory —
//! on success only. A failed run keeps its directory and prints the path.
//! The build and the suite run detached on the host and are watched with
//! short status checks, so a dropped connection loses no result.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::gates;
use crate::manifest::{self, Manifest};
use crate::stamp;

/// The remote parent of every run directory, relative to the account's home.
pub const REMOTE_RUNS: &str = "ouro-ci/runs";
/// Cargo is not on the non-login PATH of the reference host.
pub const REMOTE_CARGO: &str = "$HOME/.cargo/bin/cargo";
/// rustup, which names the pinned toolchain's own binaries for the suite:
/// its proxies put `~/.cargo/bin` at the front of the PATH they are given.
pub const REMOTE_RUSTUP: &str = "$HOME/.cargo/bin/rustup";

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub user: String,
    pub key: PathBuf,
    pub known_hosts: Option<PathBuf>,
}

/// The SSH options every call shares. `StrictHostKeyChecking=yes` means an
/// unknown host key fails rather than being learned.
///
/// Keepalives: from the hosted runner, a connection to the reference host
/// that carried no traffic for minutes was reset mid-run (three runs on
/// 2026-09-23 and 2026-09-24, after 4.5, 10 and 20 minutes). A probe every
/// 15 s keeps any idle-state middlebox fresh and ends a dead connection in
/// two minutes instead of never. Long steps no longer depend on one
/// connection at all (see [`detached_start`]); this covers the short ones.
#[must_use]
pub fn ssh_opts(target: &Target) -> Vec<String> {
    let mut v = vec![
        "-i".to_string(),
        target.key.display().to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=15".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=8".to_string(),
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

/// The remote build, run by [`detached_start`] in the run directory, with
/// the build-provenance environment of [`build_env`].
#[must_use]
pub fn build_command(jobs: u32, revision: &str) -> String {
    format!(
        "env {} {REMOTE_CARGO} build --release --workspace -j{jobs}",
        build_env(revision)
    )
}

/// The build-provenance claims every cargo step that builds or tests the
/// jail receives (`crates/ouro-jail/src/build_provenance.rs` states the
/// rule; its build.rs enforces it): the tested commit and whether the tree
/// was dirty, from the suite's own revision marker. Cargo tracks both, so
/// the build and test steps get identical values or the suite rebuilds the
/// tested binary with other claims. An unknown revision passes nothing, and
/// the binary then records the claims as unknown.
#[must_use]
pub fn build_env(revision: &str) -> String {
    let (sha, dirty) = match revision.strip_suffix("+dirty") {
        Some(sha) => (sha, true),
        None => (revision, false),
    };
    let known = sha.len() == 40
        && sha.bytes().all(|b| b.is_ascii_hexdigit())
        && !sha.bytes().all(|b| b == b'0');
    if known {
        format!("OURO_BUILD_REVISION={sha} OURO_BUILD_DIRTY={dirty}")
    } else {
        String::new()
    }
}

/// What `doctor --json`'s `build` object must say for a conformance run to
/// count: the tested revision, a clean tree, and an optimised release build.
#[must_use]
pub fn provenance_problems(doctor: &Value, revision: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let (sha, dirty) = match revision.strip_suffix("+dirty") {
        Some(sha) => (sha, true),
        None => (revision, false),
    };
    let build = &doctor["build"];
    if !build.is_object() {
        problems.push("doctor.json has no build object".to_string());
        return problems;
    }
    match build["revision"].as_str() {
        Some(r) if r.eq_ignore_ascii_case(sha) => {}
        other => problems.push(format!(
            "doctor.json names revision {other:?}, not the tested {sha}"
        )),
    }
    if dirty {
        problems.push(format!("the tested tree {sha} had uncommitted changes"));
    }
    if build["dirty"] != Value::Bool(false) {
        problems.push(format!(
            "doctor.json says dirty {}, not false",
            build["dirty"]
        ));
    }
    if build["opt_level"].as_str() != Some("3") {
        problems.push(format!(
            "doctor.json says opt_level {}, not \"3\"",
            build["opt_level"]
        ));
    }
    if build["debug_assertions"] != Value::Bool(false) {
        problems.push(format!(
            "doctor.json says debug_assertions {}, not false",
            build["debug_assertions"]
        ));
    }
    problems
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
        "cd {p} && XDG_RUNTIME_DIR=/run/user/$(id -u) systemd-run --user --scope --quiet \
         ./target/release/ouro-jail doctor --json > doctor.json 2> doctor.stderr; \
         rc=$?; cat doctor.stderr 1>&2; exit $rc"
    )
}

/// The user scope the suite runs in, named so a driver that gives up can
/// stop exactly this run's processes and nothing else.
#[must_use]
pub fn suite_unit(run_dir: &str) -> String {
    format!("ouro-conformance-{run_dir}.scope")
}

/// The remote test command, run by [`detached_start`] in the run directory
/// with its output in `test.log`.
///
/// `OURO_CONFORMANCE=1` turns every live skip into a failure (jail-v1 §16).
///
/// One test thread, not two. The ptrace observer's thread owns every
/// `waitpid` in its process (CONTRACT §3.5), so two tests attaching a tracer
/// in the same test binary reap each other's children and both block for
/// ever. Measured on the reference host: `observer_linux` passes in under
/// four seconds at `--test-threads=1` and never finishes at 2. This is a
/// property of the mechanism, not a preference about speed.
#[must_use]
pub fn test_command(run_dir: &str, jobs: u32, revision: &str) -> String {
    format!(
        "C=$({REMOTE_RUSTUP} which cargo) && R=$({REMOTE_RUSTUP} which rustc) \
         && D=$({REMOTE_RUSTUP} which rustdoc) && \
         XDG_RUNTIME_DIR=/run/user/$(id -u) systemd-run --user --scope --quiet --unit={} \
         env OURO_CONFORMANCE=1 \
         OURO_JAIL_BIN=$PWD/target/release/ouro-jail \
         OURO_FIXTURE_BIN=$PWD/target/release/ouro-fixture \
         RUSTC=$R RUSTDOC=$D {} \
         {}",
        suite_unit(run_dir),
        build_env(revision),
        with_suite_path(
            &format!("$C test --workspace --release -j{jobs} --no-fail-fast -- --test-threads=1"),
            revision
        )
    )
}

// ------------------------------------------------------------------ I01
//
// jail-v1 §15 I01: "Full jail conformance passes with ledger and fleet absent
// from PATH and no BEAM installed." Nothing asserted it: the host manifest
// recorded `beam_present` and looked for three names on the login PATH, and
// the driver failed on neither. The suite now runs with the system directories
// only on its PATH and prints that PATH as the first line of `test.log`, and a
// probe run with the same PATH looks for every ledger, fleet and BEAM name.

/// The suite's PATH: the system directories, nothing from the account.
pub const SUITE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The first line of `test.log`, printed by the shell the suite runs in.
pub const SUITE_PATH_MARKER: &str = "ouro-suite-path=";

/// `PATH=<SUITE_PATH> /bin/sh -c "echo <marker>$PATH; exec <command>"`, to
/// follow `env` and its other variables.
///
/// # Panics
/// If `command` contains a double quote, which would end the quoting.
#[must_use]
pub fn with_suite_path(command: &str, revision: &str) -> String {
    assert!(
        !command.contains('"'),
        "a suite command cannot contain a double quote: {command}"
    );
    let sha = revision.strip_suffix("+dirty").unwrap_or(revision);
    assert!(
        sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "the suite's revision must be a 40-hex commit, optionally +dirty: {revision}"
    );
    // `\$PATH` survives the detached shell as `$PATH`, so the innermost shell,
    // started with the scrubbed PATH, prints the PATH it really has, and the
    // conformance flag as the suite really has it.
    format!(
        "PATH={SUITE_PATH} /bin/sh -c \"echo {SUITE_PATH_MARKER}\\$PATH; \
         echo {}{revision}; echo {}\\$OURO_CONFORMANCE; exec {command}\"",
        gates::MARKER_REVISION,
        gates::MARKER_CONFORMANCE
    )
}

/// Did the suite's log print exactly the scrubbed PATH (and no other)?
#[must_use]
pub fn suite_ran_with_the_scrubbed_path(log: &str) -> bool {
    let mut markers = log
        .lines()
        .filter_map(|l| l.trim().strip_prefix(SUITE_PATH_MARKER))
        .peekable();
    markers.peek().is_some() && markers.all(|path| path == SUITE_PATH)
}

/// Names that must not be found on the suite's PATH: the rest of the
/// ecosystem and every BEAM entry point.
pub const I01_BINARIES: &[&str] = &[
    "ouro",
    "ouro-ledger",
    "ouro-fleet",
    "erl",
    "erlc",
    "beam.smp",
    "escript",
    "elixir",
    "iex",
    "mix",
    "rebar3",
];
/// Where `cargo install` and user installs put binaries that the suite's
/// PATH does not list but a later shell might.
pub const I01_EXTRA_BIN_DIRS: &[&str] = &["$HOME/.cargo/bin", "$HOME/.local/bin"];

/// Where a BEAM installation lives when it is installed but not on PATH.
/// A `~/` entry is the account's home directory.
pub const I01_DIRECTORIES: &[&str] = &[
    "/usr/lib/erlang",
    "/usr/lib64/erlang",
    "/usr/local/lib/erlang",
    "/opt/erlang",
    "/usr/lib/elixir",
    "/usr/local/lib/elixir",
    "~/.asdf/installs/erlang",
    "~/.kerl",
    "~/.local/share/mise/installs/erlang",
];
/// The distribution packages that install a BEAM.
pub const I01_PACKAGES: &[&str] = &["erlang-base", "erlang-base-hipe", "esl-erlang", "elixir"];

/// The remote I01 probe, run over SSH with the suite's PATH.
///
/// Every name is reported, found or not, so a probe that printed nothing
/// (or stopped half way) is a problem rather than a clean result.
#[must_use]
pub fn i01_command() -> String {
    let mut s = format!("PATH={SUITE_PATH}; export PATH; echo \"i01 path $PATH\"; ");
    for b in I01_BINARIES {
        // On the suite's PATH, or where `cargo install` and user installs
        // put binaries (the PATH of a shell the tests might start).
        s.push_str(&format!("p=$(command -v {b} 2>/dev/null); "));
        for dir in I01_EXTRA_BIN_DIRS {
            s.push_str(&format!(
                "[ -z \"$p\" ] && [ -e {dir}/{b} ] && p={dir}/{b}; "
            ));
        }
        s.push_str(&format!("echo \"i01 binary {b} ${{p:-absent}}\"; "));
    }
    for d in I01_DIRECTORIES {
        let path = d
            .strip_prefix("~/")
            .map_or_else(|| (*d).to_string(), |rest| format!("$HOME/{rest}"));
        s.push_str(&format!(
            "if [ -e {path} ]; then echo \"i01 directory {d} present\"; \
             else echo \"i01 directory {d} absent\"; fi; "
        ));
    }
    for p in I01_PACKAGES {
        // Without dpkg the answer is unknown, which is a problem, not absent.
        s.push_str(&format!(
            "if ! command -v dpkg-query >/dev/null 2>&1; then echo \"i01 package {p} unknown\"; \
             elif dpkg-query -W -f='${{Status}}' {p} 2>/dev/null | grep -q 'install ok installed'; \
             then echo \"i01 package {p} installed\"; else echo \"i01 package {p} absent\"; fi; "
        ));
    }
    s.push_str("true");
    s
}

/// Everything the I01 probe found, or could not show. Empty means I01's
/// environment holds.
#[must_use]
pub fn i01_problems(stdout: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut path_lines = 0;
    for line in stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(rest) = line.strip_prefix("i01 ") else {
            problems.push(format!(
                "the I01 probe printed an unexpected line: `{}`",
                scrub(line)
            ));
            continue;
        };
        if let Some(path) = rest.strip_prefix("path ") {
            path_lines += 1;
            if path != SUITE_PATH {
                problems.push(format!(
                    "the I01 probe ran with PATH `{}`, not the suite's",
                    scrub(path)
                ));
            }
            continue;
        }
        let mut words = rest.splitn(3, ' ');
        let (Some(kind), Some(name), Some(state)) = (words.next(), words.next(), words.next())
        else {
            problems.push(format!(
                "the I01 probe printed an unreadable line: `{}`",
                scrub(line)
            ));
            continue;
        };
        *seen
            .entry((kind.to_string(), name.to_string()))
            .or_insert(0) += 1;
        match (kind, state) {
            ("binary" | "directory" | "package", "absent") => {}
            ("binary", found) => {
                problems.push(format!("`{name}` is on the suite's PATH at {found}"))
            }
            ("directory", _) => {
                problems.push(format!("a BEAM installation directory exists: {name}"))
            }
            ("package", "installed") => {
                problems.push(format!("the BEAM package `{name}` is installed"))
            }
            ("package", other) => problems.push(format!(
                "whether the BEAM package `{name}` is installed is {other}"
            )),
            _ => problems.push(format!(
                "the I01 probe printed an unreadable line: `{}`",
                scrub(line)
            )),
        }
    }
    if path_lines != 1 {
        problems.push(format!(
            "the I01 probe reported its PATH {path_lines} times, not once"
        ));
    }
    for (kind, names) in [
        ("binary", I01_BINARIES),
        ("directory", I01_DIRECTORIES),
        ("package", I01_PACKAGES),
    ] {
        for name in names {
            match seen.get(&(kind.to_string(), (*name).to_string())) {
                None => problems.push(format!("the I01 probe did not report the {kind} {name}")),
                Some(1) => {}
                Some(n) => problems.push(format!(
                    "the I01 probe reported the {kind} {name} {n} times"
                )),
            }
        }
    }
    problems
}

// ------------------------------------------------------ contract validation

/// The contract validator (jail-v1 §13, R01), run at the same revision.
pub const CONTRACT_VALIDATOR: &str = "docs/specs/jail-v1/validate_contract.py";

/// `uv run <validator>`, run locally in the worktree.
#[must_use]
pub fn contract_validation_argv() -> (String, Vec<String>) {
    (
        "uv".to_string(),
        vec!["run".to_string(), CONTRACT_VALIDATOR.to_string()],
    )
}

// ------------------------------------------------------ plain-session smoke

/// The plain-session smoke leg (revision 18, §9.3): a `tool` run, a `none`
/// run and `doctor`, started from the SSH session itself, never inside a
/// scope the driver entered, so `run` and `doctor` take the step a plain
/// login takes and move themselves into a delegated scope.
///
/// It prints the session's own cgroup first, which is the evidence that the
/// session was outside the user manager's delegated subtree, and `smoke
/// <step> <status>` after each step. The receipts and doctor's report are read
/// back afterwards. A private data and config directory keeps the leg's state
/// out of the account's own.
#[must_use]
pub fn smoke_command(run_dir: &str) -> String {
    let p = run_path(run_dir);
    let env = "OURO_DATA_DIR=$PWD/smoke/data OURO_CONFIG_DIR=$PWD/smoke/config";
    format!(
        "cd {p} && rm -rf smoke && mkdir -p smoke/ws smoke/data smoke/config && \
         chmod 700 smoke/data smoke/config && \
         echo \"smoke cgroup $(cat /proc/self/cgroup)\" && \
         for profile in tool none; do \
         {env} ./target/release/ouro-jail run --profile $profile --workspace $PWD/smoke/ws \
         --receipt $PWD/smoke/$profile.json -- /usr/bin/true > smoke/$profile.out 2>&1; \
         echo \"smoke $profile $?\"; done; \
         {env} ./target/release/ouro-jail doctor --json > smoke/doctor.json 2> smoke/doctor.err; \
         echo \"smoke doctor $?\""
    )
}

/// What the smoke leg produced.
#[derive(Debug, Clone)]
pub struct Smoke {
    pub transcript: CommandResult,
    pub tool: Option<String>,
    pub none: Option<String>,
    pub doctor: Option<String>,
}

/// Everything wrong with the smoke leg. Empty means it passed.
#[must_use]
pub fn smoke_problems(smoke: &Smoke) -> Vec<String> {
    let mut p = Vec::new();
    let t = &smoke.transcript;
    if !t.ok() {
        p.push(format!(
            "the smoke command exited {}{}",
            t.status_text(),
            first_line(&t.stderr)
        ));
    }
    let lines: Vec<&str> = t.stdout.lines().map(str::trim).collect();
    match lines.iter().find_map(|l| l.strip_prefix("smoke cgroup ")) {
        None => p.push("the smoke session did not report its cgroup".to_string()),
        Some(cgroup) if cgroup.contains("/user@") => p.push(format!(
            "the smoke session was already inside the user manager's subtree ({cgroup}), \
             so it proves nothing about the scope step"
        )),
        Some(_) => {}
    }
    for step in ["tool", "none", "doctor"] {
        let prefix = format!("smoke {step} ");
        match lines.iter().find_map(|l| l.strip_prefix(prefix.as_str())) {
            None => p.push(format!(
                "the smoke step {step} did not report its exit status"
            )),
            Some("0") => {}
            Some(code) => p.push(format!("the smoke step {step} exited {code}")),
        }
    }
    for (profile, receipt) in [("tool", &smoke.tool), ("none", &smoke.none)] {
        let Some(text) = receipt else {
            p.push(format!("the smoke {profile} run left no receipt"));
            continue;
        };
        let Ok(r) = serde_json::from_str::<Value>(text) else {
            p.push(format!("the smoke {profile} receipt is not JSON"));
            continue;
        };
        if r["phase"] != "settled" {
            p.push(format!(
                "the smoke {profile} receipt is {}, not settled",
                r["phase"]
            ));
        }
        if r["outcome"]["kind"] != "exited" || r["outcome"]["code"] != 0 {
            p.push(format!(
                "the smoke {profile} target did not exit 0: {}",
                r["outcome"]
            ));
        }
        let details = &r["lifetime"]["native"]["details"];
        let scope = &details["supervisor_scope"];
        if scope["state"] != "entered" {
            p.push(format!(
                "the smoke {profile} supervisor's scope step is {} (reason {}), not entered",
                scope["state"], scope["reason_code"]
            ));
        }
        if scope.get("test_seam").is_some() {
            p.push(format!("the smoke {profile} run recorded a test seam"));
        }
        if !details["execution_cgroup"]["path"].is_string() {
            p.push(format!("the smoke {profile} attempt has no execution leaf"));
        }
    }
    match smoke.doctor.as_deref().map(serde_json::from_str::<Value>) {
        None => p.push("the smoke doctor left no report".to_string()),
        Some(Err(_)) => p.push("the smoke doctor report is not JSON".to_string()),
        Some(Ok(d)) => {
            if d["supervisor_scope"]["state"] != "entered" {
                p.push(format!(
                    "the smoke doctor's scope step is {}, not entered",
                    d["supervisor_scope"]["state"]
                ));
            }
            let row = d["capabilities"]
                .as_array()
                .and_then(|rows| rows.iter().find(|r| r["name"] == "supervisor_scope"));
            match row {
                Some(r) if r["status"] == "available" && r["reason_code"] == "entered" => {}
                Some(r) => p.push(format!(
                    "the smoke doctor's supervisor_scope row is {} ({})",
                    r["status"], r["reason_code"]
                )),
                None => p.push("the smoke doctor has no supervisor_scope row".to_string()),
            }
        }
    }
    p
}

// ------------------------------------------------------------ detached steps
//
// The build and the suite run for minutes and print nothing until they end.
// Run inside one SSH session, their result reached the driver only if that
// connection survived the whole time, and from the hosted runner it did not:
// the suite finished on the host, and the job failed with no test result. So
// a long step is started detached from the session that starts it, writes
// its output and exit status to files in the run directory, and is watched
// with short, separate status checks. A check that fails is retried; no
// connection has to last longer than one check.

/// Start `command` in the run directory, detached, as step `name`.
///
/// The step writes its output to `<name>.log`, its shell's pid to
/// `<name>.pid`, and its exit status to `<name>.rc`, the last by rename, so
/// a status that exists is complete. The command runs in a subshell, so an
/// `exit` in it cannot skip the status. `setsid -f` forks it into a session
/// of its own and returns at once, so the end of the starting SSH session
/// signals nothing to it, and its descriptors are redirected so that session
/// can close at once. No `&` list and no `nohup`: the first leaves INT and
/// QUIT ignored in a non-interactive shell, the second HUP, both survive
/// exec, and the suite's operator-signal tests need them at their defaults.
/// `mkdir <name>.started` makes starting idempotent: a start whose reply was
/// lost cannot start the step twice.
///
/// # Panics
/// If `command` contains a single quote, which would end the quoting.
#[must_use]
pub fn detached_start(run_dir: &str, name: &str, command: &str) -> String {
    assert!(
        !command.contains('\''),
        "a detached command cannot contain a single quote: {command}"
    );
    let p = run_path(run_dir);
    format!(
        "cd {p} && mkdir {name}.started && \
         setsid -f sh -c 'echo $$ > {name}.pid; ( {command} ) > {name}.log 2>&1; \
         echo $? > {name}.rc.new; mv {name}.rc.new {name}.rc' \
         < /dev/null > /dev/null 2>&1 && echo started"
    )
}

/// One status check of step `name`: `done <status>`, `running <log lines>`,
/// `vanished` (its shell is gone and left no status) or `absent` (it was
/// never started). A step that ends between the two tests is read again, so
/// a normal end is never reported as `vanished`.
#[must_use]
pub fn detached_poll(run_dir: &str, name: &str) -> String {
    let p = run_path(run_dir);
    format!(
        "cd {p} && if [ -f {name}.rc ]; then echo \"done $(cat {name}.rc)\"; \
         elif [ ! -d {name}.started ]; then echo absent; \
         elif [ -f {name}.pid ] && ! kill -0 \"$(cat {name}.pid)\" 2>/dev/null; then \
         if [ -f {name}.rc ]; then echo \"done $(cat {name}.rc)\"; else echo vanished; fi; \
         else echo \"running $(cat {name}.log 2>/dev/null | wc -l)\"; fi"
    )
}

/// Stop step `name`: its process group (the shell is the leader of its own
/// session), and `unit` when the step runs in a named user scope. Only this
/// run's processes are named; nothing is matched by pattern.
#[must_use]
pub fn detached_stop(run_dir: &str, name: &str, unit: Option<&str>) -> String {
    let p = run_path(run_dir);
    let mut s = format!(
        "cd {p}; if [ -f {name}.pid ]; then kill -s TERM -- -\"$(cat {name}.pid)\" 2>/dev/null; fi; "
    );
    if let Some(unit) = unit {
        s.push_str(&format!(
            "XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user stop {unit} 2>/dev/null; "
        ));
    }
    s.push_str("true");
    s
}

/// What one status check said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    Absent,
    Running(u64),
    Vanished,
    Done(i32),
}

/// Parse a status check's output; `None` for anything else.
#[must_use]
pub fn parse_poll(stdout: &str) -> Option<Poll> {
    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest = rest.trim();
    match word {
        "absent" if rest.is_empty() => Some(Poll::Absent),
        "vanished" if rest.is_empty() => Some(Poll::Vanished),
        "running" => rest.parse().ok().map(Poll::Running),
        "done" => rest.parse().ok().map(Poll::Done),
        _ => None,
    }
}

/// How long to wait for a detached step, and how often to look.
#[derive(Debug, Clone, Copy)]
pub struct Patience {
    pub interval: std::time::Duration,
    pub limit: std::time::Duration,
    /// Consecutive failed checks after which contact counts as lost.
    pub failed_checks: u32,
}

/// The release build: about a minute on the reference host from scratch.
pub const BUILD_PATIENCE: Patience = Patience {
    interval: std::time::Duration::from_secs(15),
    limit: std::time::Duration::from_secs(20 * 60),
    failed_checks: 12,
};

/// The suite: about fifteen minutes on the reference host. The limit leaves
/// room inside the workflow's 45-minute job budget for everything else.
pub const SUITE_PATIENCE: Patience = Patience {
    interval: std::time::Duration::from_secs(20),
    limit: std::time::Duration::from_secs(35 * 60),
    failed_checks: 9,
};

/// How waiting for a detached step ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Waited {
    Done(i32),
    Absent,
    Vanished,
    TimedOut,
    LostContact(String),
    Unreadable(String),
}

/// Wait for a detached step. Pure apart from its arguments: `check` runs one
/// status check, `pause` waits, `elapsed` reads the clock, and `progress`
/// hears each new log length, so every ending is unit-tested.
pub fn wait_for(
    patience: Patience,
    mut check: impl FnMut() -> std::io::Result<CommandResult>,
    mut pause: impl FnMut(std::time::Duration),
    mut elapsed: impl FnMut() -> std::time::Duration,
    mut progress: impl FnMut(u64),
) -> Waited {
    let mut failed = 0u32;
    let mut last_lines = None;
    loop {
        if elapsed() >= patience.limit {
            return Waited::TimedOut;
        }
        let why = match check() {
            Ok(r) if r.ok() => match parse_poll(&r.stdout) {
                Some(Poll::Done(code)) => return Waited::Done(code),
                Some(Poll::Absent) => return Waited::Absent,
                Some(Poll::Vanished) => return Waited::Vanished,
                Some(Poll::Running(lines)) => {
                    failed = 0;
                    if last_lines != Some(lines) {
                        progress(lines);
                        last_lines = Some(lines);
                    }
                    None
                }
                None => {
                    let line = r.stdout.lines().next().unwrap_or("").trim();
                    return Waited::Unreadable(scrub(line));
                }
            },
            Ok(r) => Some(format!(
                "exited {}{}",
                r.status_text(),
                first_line(&r.stderr)
            )),
            Err(e) => Some(format!("could not run ssh: {e}")),
        };
        if let Some(why) = why {
            failed += 1;
            if failed >= patience.failed_checks {
                return Waited::LostContact(format!(
                    "{failed} consecutive status checks failed; the last {why}"
                ));
            }
        }
        pause(patience.interval);
    }
}

/// What a detached step produced: its exit status when it ended, its log
/// when it could be read back, and what went wrong otherwise.
#[derive(Debug, Clone, Default)]
pub struct Detached {
    pub code: Option<i32>,
    pub log: Option<String>,
    pub problem: Option<String>,
}

/// The problem a way of waiting stands for; `None` when the step ended.
#[must_use]
pub fn wait_problem(waited: &Waited, patience: Patience) -> Option<String> {
    match waited {
        Waited::Done(_) => None,
        Waited::Absent => Some("was never started".to_string()),
        Waited::Vanished => Some("ended without recording its exit status".to_string()),
        Waited::TimedOut => Some(format!(
            "did not finish within {} minutes and was stopped",
            patience.limit.as_secs() / 60
        )),
        Waited::LostContact(why) => Some(format!("lost contact with the host: {why}")),
        Waited::Unreadable(line) => Some(format!("gave an unreadable status: `{line}`")),
    }
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
    /// Why the detached build has no exit status, when it has none.
    pub build_wait: Option<String>,
    pub i02: Option<CommandResult>,
    pub doctor: Option<CommandResult>,
    /// The bytes of `doctor.json`, when they could be read back.
    pub doctor_json: Option<String>,
    pub suite: Option<CommandResult>,
    /// Why the detached suite has no exit status, when it has none.
    pub suite_wait: Option<String>,
    /// The full `test.log`, which is the only test evidence.
    pub test_log: Option<String>,
    pub host_manifest: Option<CommandResult>,
    /// Anything that went wrong writing the local evidence.
    pub evidence_errors: Vec<String>,
    /// `validate_contract.py` at the same revision, run locally.
    pub contract_validation: Option<CommandResult>,
    /// The I01 probe on the host.
    pub i01: Option<CommandResult>,
    /// The plain-session smoke leg.
    pub smoke: Option<Smoke>,
    /// The acceptance map and §15, loaded before the run.
    pub acceptance: Option<Result<gates::Acceptance, String>>,
    /// The revision the driver ran (`<sha>` or `<sha>+dirty`), which the
    /// suite prints and the verdict checks the log against.
    pub revision: Option<String>,
}

/// The driver checks this run produced, for the gate verdict.
#[must_use]
pub fn driver_checks(
    outcomes: &RunOutcomes,
    manifest: Option<&Manifest>,
) -> BTreeMap<String, bool> {
    let ok = |r: &Option<CommandResult>| r.as_ref().is_some_and(CommandResult::ok);
    let doctor_manifest = ok(&outcomes.doctor)
        && match (manifest, outcomes.doctor_json.as_deref()) {
            (Some(m), Some(text)) => serde_json::from_str::<Value>(text)
                .is_ok_and(|doctor| manifest::compare(m, &doctor).iter().all(manifest::Row::ok)),
            _ => false,
        };
    BTreeMap::from([
        ("i02_scan".to_string(), ok(&outcomes.i02)),
        (
            "contract_validation".to_string(),
            ok(&outcomes.contract_validation),
        ),
        ("doctor_manifest".to_string(), doctor_manifest),
        (
            "i01_absent".to_string(),
            ok(&outcomes.i01)
                && outcomes
                    .i01
                    .as_ref()
                    .is_some_and(|r| i01_problems(&r.stdout).is_empty()),
        ),
        (
            "i01_scrubbed_path".to_string(),
            outcomes
                .test_log
                .as_deref()
                .is_some_and(suite_ran_with_the_scrubbed_path),
        ),
        (
            "plain_session_smoke".to_string(),
            outcomes
                .smoke
                .as_ref()
                .is_some_and(|s| smoke_problems(s).is_empty()),
        ),
    ])
}

/// The gate verdict over this run's `test.log`: `None` without a log (that
/// is its own failure), an error when the map could not be loaded.
#[must_use]
pub fn gate_verdict(
    outcomes: &RunOutcomes,
    manifest: Option<&Manifest>,
) -> Option<Result<gates::Verdict, String>> {
    let log = outcomes.test_log.as_deref()?;
    Some(match &outcomes.acceptance {
        None => Err("the acceptance map was not loaded".to_string()),
        Some(Err(e)) => Err(e.clone()),
        Some(Ok(a)) => {
            let logs = BTreeMap::from([(gates::Lane::Linux, gates::parse_log(log))]);
            let mut v = gates::evaluate(&a.map, &a.rows, &logs, &driver_checks(outcomes, manifest));
            // The log must be this run's: the revision the driver ran, in
            // conformance mode.
            let expected = outcomes.revision.as_deref().unwrap_or("unknown");
            v.problems
                .extend(gates::binding_problems(&logs, Some(expected)));
            v.map_label = gates::MAP_PATH.to_string();
            v.lanes_label = gates::describe_lanes(&logs);
            Ok(v)
        }
    })
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
    // A build with no exit status is a failure in its own right: without
    // this, a lost build would read as "did not run" and fail nothing.
    if let Some(why) = &outcomes.build_wait {
        failures.push(format!("the remote release build {why}"));
        return finish_decision(failures, outcomes, keep_remote_flag);
    }
    if !step(&mut failures, "the remote release build", &outcomes.build) {
        return finish_decision(failures, outcomes, keep_remote_flag);
    }
    step(&mut failures, "the I02 vendor-name scan", &outcomes.i02);
    match &outcomes.contract_validation {
        None => failures.push(format!(
            "the contract validator did not run ({CONTRACT_VALIDATOR})"
        )),
        Some(r) if !r.ok() => failures.push(format!(
            "the contract validator ({CONTRACT_VALIDATOR}) exited {}{}",
            r.status_text(),
            first_line(&r.stderr)
        )),
        Some(_) => {}
    }

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
                let revision = outcomes.revision.as_deref().unwrap_or("");
                for p in provenance_problems(&doctor, revision) {
                    failures.push(format!("build provenance: {p}"));
                }
            }
        },
    }

    // The suite. Its exit code, every test binary's own verdict, and skips.
    match (&outcomes.suite, &outcomes.suite_wait) {
        (_, Some(why)) => failures.push(format!("the remote conformance suite {why}")),
        (None, None) => failures.push("the remote conformance suite did not run".to_string()),
        (Some(r), None) => {
            if !r.ok() {
                failures.push(format!(
                    "the remote conformance suite exited {}",
                    r.status_text()
                ));
            }
        }
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

    // I01 and the plain-session smoke leg.
    match &outcomes.i01 {
        None => failures.push("the I01 probe did not run".to_string()),
        Some(r) if !r.ok() => failures.push(format!(
            "the I01 probe exited {}{}",
            r.status_text(),
            first_line(&r.stderr)
        )),
        Some(r) => failures.extend(
            i01_problems(&r.stdout)
                .into_iter()
                .map(|p| format!("I01: {p}")),
        ),
    }
    match &outcomes.smoke {
        None => failures.push("the plain-session smoke leg did not run".to_string()),
        Some(s) => failures.extend(
            smoke_problems(s)
                .into_iter()
                .map(|p| format!("plain-session smoke: {p}")),
        ),
    }

    // The per-gate verdict over the suite's own log (§15, §16 J5).
    match gate_verdict(outcomes, manifest) {
        // No test.log: already a failure above, and there is nothing to judge.
        None => {}
        Some(Err(e)) => failures.push(format!(
            "the acceptance map could not be used, so no gate verdict exists: {e}"
        )),
        Some(Ok(v)) => failures.extend(v.failures()),
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
    // The revision the suite prints and the verdict binds its log to.
    // Without one (no git), the run cannot be tied to anything and fails.
    let revision = gates::repository_revision(&opts.worktree).unwrap_or_else(|| {
        outcomes
            .evidence_errors
            .push("the worktree's revision could not be read with git".to_string());
        "0000000000000000000000000000000000000000+dirty".to_string()
    });
    outcomes.revision = Some(revision.clone());
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

    // The acceptance map and §15 at this revision, before anything runs: a
    // map that does not load fails the run whatever the suite does.
    outcomes.acceptance = Some(gates::load(&opts.worktree));

    // The contract validator, locally, at the same revision (R01): its
    // output is evidence beside the suite's.
    step("validate the contract (validate_contract.py)");
    let (program, args) = contract_validation_argv();
    let validation = run_in(&opts.worktree, &program, &args);
    print!("{}", validation.stdout);
    if !validation.stderr.trim().is_empty() {
        eprint!("{}", validation.stderr);
    }
    write_evidence(
        opts,
        "contract-validation.txt",
        &format!(
            "$ {program} {}\nexit {}\n--- stdout ---\n{}--- stderr ---\n{}",
            args.join(" "),
            validation.status_text(),
            validation.stdout,
            validation.stderr
        ),
        &mut outcomes,
    );
    outcomes.contract_validation = Some(validation);

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
        let build = run_detached(
            opts,
            &run_dir,
            "build",
            &build_command(opts.jobs, &revision),
            BUILD_PATIENCE,
            None,
        );
        if let Some(log) = &build.log {
            print!("{log}");
        }
        match build.code {
            Some(code) => {
                outcomes.build = Some(CommandResult {
                    code: Some(code),
                    stdout: build.log.unwrap_or_default(),
                    stderr: String::new(),
                });
            }
            None => outcomes.build_wait = build.problem,
        }
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

        step("plain-session smoke (no systemd-run: run and doctor enter a scope themselves)");
        let smoke = run_smoke(opts, &run_dir)?;
        print!("{}", smoke.transcript.stdout);
        for p in smoke_problems(&smoke) {
            println!("   problem: {p}");
        }
        write_evidence(
            opts,
            "smoke-transcript.txt",
            &smoke.transcript.stdout,
            &mut outcomes,
        );
        for (name, body) in [
            ("smoke-tool-receipt.json", &smoke.tool),
            ("smoke-none-receipt.json", &smoke.none),
            ("smoke-doctor.json", &smoke.doctor),
        ] {
            if let Some(body) = body {
                write_evidence(opts, name, body, &mut outcomes);
            }
        }
        outcomes.smoke = Some(smoke);

        step("I01: no ledger, fleet or BEAM on the suite's PATH or installed");
        let i01 = ssh(opts, &i01_command())?;
        print!("{}", i01.stdout);
        write_evidence(opts, "i01.txt", &i01.stdout, &mut outcomes);
        outcomes.i01 = Some(i01);

        step("run the conformance suite (OURO_CONFORMANCE=1)");
        let unit = suite_unit(&run_dir);
        let suite = run_detached(
            opts,
            &run_dir,
            "test",
            &test_command(&run_dir, opts.jobs, &revision),
            SUITE_PATIENCE,
            Some(&unit),
        );
        if let Some(log) = &suite.log {
            print!("{log}");
            write_evidence(opts, "test.log", log, &mut outcomes);
        }
        outcomes.test_log = suite.log.clone();
        match suite.code {
            Some(code) => {
                outcomes.suite = Some(CommandResult {
                    code: Some(code),
                    stdout: suite.log.unwrap_or_default(),
                    stderr: String::new(),
                });
            }
            None => outcomes.suite_wait = suite.problem,
        }
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

    step("the per-gate verdict (acceptance-map.toml)");
    match gate_verdict(&outcomes, manifest.as_ref()) {
        None => println!("   no test.log, so no gate verdict"),
        Some(Err(e)) => {
            println!("   {e}");
            write_evidence(
                opts,
                "gates.txt",
                &format!("no gate verdict: {e}\n"),
                &mut outcomes,
            );
        }
        Some(Ok(v)) => {
            let text = v.render();
            print!("{text}");
            write_evidence(opts, "gates.txt", &text, &mut outcomes);
            if let Some(Ok(a)) = &outcomes.acceptance {
                let json = serde_json::to_string_pretty(&v.to_json(&a.map)).unwrap_or_default();
                write_evidence(opts, "gates.json", &format!("{json}\n"), &mut outcomes);
            }
        }
    }

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

/// Run a local program in `dir`. A program that cannot be started is a
/// result with no status, never an early exit of the whole run.
fn run_in(dir: &Path, program: &str, args: &[String]) -> CommandResult {
    match Command::new(program)
        .args(args)
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(out) => CommandResult {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => CommandResult {
            code: None,
            stdout: String::new(),
            stderr: format!("could not run {program}: {e}"),
        },
    }
}

/// The plain-session smoke leg and its three records. The leg is seconds
/// long, so it runs in one SSH session; a record that cannot be read back is
/// absent, which `smoke_problems` reports.
fn run_smoke(opts: &Options, run_dir: &str) -> std::io::Result<Smoke> {
    let transcript = ssh(opts, &smoke_command(run_dir))?;
    let read = |name: &str| -> std::io::Result<Option<String>> {
        let r = ssh(opts, &format!("cat {}/smoke/{name}", run_path(run_dir)))?;
        Ok((r.ok() && !r.stdout.trim().is_empty()).then_some(r.stdout))
    };
    Ok(Smoke {
        transcript,
        tool: read("tool.json")?,
        none: read("none.json")?,
        doctor: read("doctor.json")?,
    })
}

/// Run one long step detached and wait for it (see [`detached_start`]).
/// Never an error: every way it can end is recorded in the result.
fn run_detached(
    opts: &Options,
    run_dir: &str,
    name: &str,
    command: &str,
    patience: Patience,
    unit: Option<&str>,
) -> Detached {
    let started = ssh(opts, &detached_start(run_dir, name, command));
    // A failed start is not final: its reply may be what was lost. The first
    // status check says whether the step exists.
    let start_note = match &started {
        Ok(r) if r.ok() => String::new(),
        Ok(r) => format!(
            " (starting it exited {}{})",
            r.status_text(),
            first_line(&r.stderr)
        ),
        Err(e) => format!(" (starting it could not run ssh: {e})"),
    };
    let began = std::time::Instant::now();
    let waited = wait_for(
        patience,
        || ssh(opts, &detached_poll(run_dir, name)),
        std::thread::sleep,
        || began.elapsed(),
        |lines| println!("   ... {name}.log: {lines} lines"),
    );
    if matches!(waited, Waited::TimedOut | Waited::LostContact(_)) {
        // Best effort: when contact is lost this may not reach the host.
        let _ = ssh(opts, &detached_stop(run_dir, name, unit));
    }
    // The log, complete or partial, is evidence either way. A lost reply is
    // retried; a log that cannot be read at all is recorded as absent.
    let mut log = None;
    for _ in 0..3 {
        if let Ok(r) = ssh(opts, &format!("cat {}/{name}.log", run_path(run_dir)))
            && r.ok()
        {
            log = Some(r.stdout);
            break;
        }
        std::thread::sleep(patience.interval);
    }
    let problem = wait_problem(&waited, patience).map(|p| {
        if matches!(waited, Waited::Absent) {
            format!("{p}{start_note}")
        } else {
            p
        }
    });
    Detached {
        code: match waited {
            Waited::Done(code) => Some(code),
            _ => None,
        },
        log,
        problem,
    }
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
                "StrictHostKeyChecking=yes",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=8"
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
        let b = build_command(2, REV);
        assert_eq!(
            b,
            format!(
                "env OURO_BUILD_REVISION={REV} OURO_BUILD_DIRTY=false \
                 $HOME/.cargo/bin/cargo build --release --workspace -j2"
            )
        );
        let started = detached_start("d", "build", &b);
        assert!(
            started.starts_with("cd $HOME/ouro-ci/runs/d && mkdir build.started &&"),
            "{started}"
        );
    }

    #[test]
    fn the_build_and_test_steps_carry_identical_provenance_claims() {
        // Cargo tracks both variables: a test step with other values (or
        // none) rebuilds the tested binary under the suite (review of J5-D, F8).
        for revision in [REV.to_string(), format!("{REV}+dirty")] {
            let env = build_env(&revision);
            assert!(!env.is_empty(), "{revision}");
            assert!(build_command(2, &revision).contains(&env), "{revision}");
            assert!(test_command("d", 2, &revision).contains(&env), "{revision}");
        }
        assert_eq!(
            build_env(&format!("{REV}+dirty")),
            format!("OURO_BUILD_REVISION={REV} OURO_BUILD_DIRTY=true")
        );
        // An unknown revision claims nothing.
        for unknown in [
            "0000000000000000000000000000000000000000+dirty",
            "abc",
            "",
            "g123456789abcdef0123456789abcdef01234567",
        ] {
            assert_eq!(build_env(unknown), "", "{unknown}");
        }
    }

    #[test]
    fn doctors_build_provenance_must_name_the_tested_clean_optimised_build() {
        let good: Value = serde_json::from_str(GOOD_DOCTOR).unwrap();
        assert!(provenance_problems(&good, REV).is_empty());
        let mutate = |f: &dyn Fn(&mut Value)| {
            let mut d = good.clone();
            f(&mut d);
            provenance_problems(&d, REV)
        };
        assert!(!mutate(&|d| d["build"]["revision"] = "f".repeat(40).into()).is_empty());
        assert!(!mutate(&|d| d["build"]["revision"] = Value::Null).is_empty());
        assert!(!mutate(&|d| d["build"]["dirty"] = Value::Bool(true)).is_empty());
        assert!(!mutate(&|d| d["build"]["dirty"] = Value::Null).is_empty());
        assert!(!mutate(&|d| d["build"]["opt_level"] = "0".into()).is_empty());
        assert!(!mutate(&|d| d["build"]["debug_assertions"] = Value::Bool(true)).is_empty());
        assert!(!mutate(&|d| d["build"] = Value::Null).is_empty());
        assert!(!provenance_problems(&good, &format!("{REV}+dirty")).is_empty());
        // And the decision fails the run on it.
        let mut o = a_clean_run();
        o.doctor_json = Some(GOOD_DOCTOR.replace("\"dirty\":false", "\"dirty\":true"));
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.starts_with("build provenance:")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn the_test_command_forbids_skips_and_names_both_binaries() {
        let t = test_command("d", 2, REV);
        assert!(t.contains("OURO_CONFORMANCE=1"), "{t}");
        assert!(
            t.contains("--unit=ouro-conformance-d.scope"),
            "a driver that gives up stops exactly this scope: {t}"
        );
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
        assert!(
            !t.contains("| tee"),
            "tee would mask the suite's exit status"
        );
        assert!(
            !t.contains('\''),
            "a detached command cannot contain a single quote"
        );
        let started = detached_start("d", "test", &t);
        assert!(
            started.contains("> test.log 2>&1"),
            "the log is test.log: {started}"
        );
        assert!(
            started.contains("echo $? > test.rc.new; mv test.rc.new test.rc"),
            "the suite's own status must survive, written whole: {started}"
        );
    }

    // ------------------------------------------------------- detached steps

    #[test]
    fn a_detached_start_is_idempotent_and_holds_no_session_descriptor() {
        let s = detached_start("d", "test", "true");
        let mkdir = s.find("mkdir test.started").unwrap();
        let setsid = s.find("setsid -f sh -c").unwrap();
        assert!(mkdir < setsid, "the guard comes before the start: {s}");
        assert!(
            s.contains("< /dev/null > /dev/null 2>&1 && echo started"),
            "the detached shell must not keep the SSH session's descriptors: {s}"
        );
        assert!(
            !s.contains("nohup") && !s.contains(" & "),
            "no nohup and no & list: they leave HUP, INT and QUIT ignored: {s}"
        );
        assert!(s.contains("( true ) > test.log 2>&1"), "{s}");
    }

    #[test]
    #[should_panic(expected = "single quote")]
    fn a_detached_command_with_a_single_quote_is_refused() {
        let _ = detached_start("d", "x", "echo 'hi'");
    }

    #[test]
    fn a_stop_names_this_run_only() {
        let s = detached_stop("d", "test", Some("ouro-conformance-d.scope"));
        assert!(s.contains("kill -s TERM -- -\"$(cat test.pid)\""), "{s}");
        assert!(
            s.contains("systemctl --user stop ouro-conformance-d.scope"),
            "{s}"
        );
        assert!(!s.contains("pkill") && !s.contains("killall"), "{s}");
        assert!(!detached_stop("d", "build", None).contains("systemctl"));
    }

    #[test]
    fn status_checks_parse_strictly() {
        assert_eq!(parse_poll("done 0\n"), Some(Poll::Done(0)));
        assert_eq!(parse_poll("done 101"), Some(Poll::Done(101)));
        assert_eq!(parse_poll("running       42\n"), Some(Poll::Running(42)));
        assert_eq!(parse_poll("\nabsent\n"), Some(Poll::Absent));
        assert_eq!(parse_poll("vanished"), Some(Poll::Vanished));
        assert_eq!(parse_poll("done"), None, "a status without its code");
        assert_eq!(parse_poll("done x"), None);
        assert_eq!(parse_poll("running"), None);
        assert_eq!(parse_poll("absent now"), None);
        assert_eq!(parse_poll(""), None);
        assert_eq!(parse_poll("Welcome to Ubuntu"), None);
    }

    fn reply(stdout: &str) -> std::io::Result<CommandResult> {
        Ok(CommandResult {
            code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
        })
    }

    fn dropped() -> std::io::Result<CommandResult> {
        Ok(CommandResult {
            code: Some(255),
            stdout: String::new(),
            stderr: "client_loop: send disconnect: Broken pipe".to_string(),
        })
    }

    const QUICK: Patience = Patience {
        interval: std::time::Duration::from_secs(10),
        limit: std::time::Duration::from_secs(100),
        failed_checks: 3,
    };

    /// Drive `wait_for` over scripted replies with a fake clock that advances
    /// by each pause. Returns the ending, the progress heard and the pauses.
    fn scripted(
        replies: Vec<std::io::Result<CommandResult>>,
        patience: Patience,
    ) -> (Waited, Vec<u64>, usize) {
        let mut replies = replies.into_iter();
        let clock = std::cell::Cell::new(std::time::Duration::ZERO);
        let pauses = std::cell::Cell::new(0usize);
        let mut heard = Vec::new();
        let waited = wait_for(
            patience,
            || {
                replies
                    .next()
                    .expect("the wait asked more than was scripted")
            },
            |d| {
                clock.set(clock.get() + d);
                pauses.set(pauses.get() + 1);
            },
            || clock.get(),
            |n| heard.push(n),
        );
        (waited, heard, pauses.get())
    }

    #[test]
    fn a_step_that_ends_is_done_with_its_own_status() {
        let (w, heard, _) = scripted(
            vec![
                reply("running 1"),
                reply("running 1"),
                reply("running 7"),
                reply("done 101"),
            ],
            QUICK,
        );
        assert_eq!(w, Waited::Done(101));
        assert_eq!(heard, vec![1, 7], "progress is reported once per change");
    }

    #[test]
    fn dropped_checks_are_retried_and_contact_survives_them() {
        // The failure this replaces: one dropped connection lost the result.
        let (w, _, _) = scripted(
            vec![
                reply("running 3"),
                dropped(),
                dropped(),
                reply("running 9"),
                dropped(),
                reply("done 0"),
            ],
            QUICK,
        );
        assert_eq!(w, Waited::Done(0));
    }

    #[test]
    fn consecutive_failed_checks_lose_contact_and_say_why() {
        let (w, _, _) = scripted(
            vec![reply("running 3"), dropped(), dropped(), dropped()],
            QUICK,
        );
        match w {
            Waited::LostContact(why) => {
                assert!(why.contains("3 consecutive"), "{why}");
                assert!(why.contains("exited 255"), "{why}");
                assert!(why.contains("Broken pipe"), "{why}");
            }
            other => panic!("expected lost contact, got {other:?}"),
        }
        let (w, _, _) = scripted(
            vec![
                Err(std::io::Error::other("no ssh")),
                Err(std::io::Error::other("no ssh")),
                Err(std::io::Error::other("no ssh")),
            ],
            QUICK,
        );
        assert!(
            matches!(w, Waited::LostContact(ref why) if why.contains("no ssh")),
            "{w:?}"
        );
    }

    #[test]
    fn a_step_that_never_ends_times_out() {
        let replies = (0..20).map(|_| reply("running 5")).collect();
        let (w, _, pauses) = scripted(replies, QUICK);
        assert_eq!(w, Waited::TimedOut);
        assert_eq!(pauses, 10, "100 s at 10 s per check");
    }

    #[test]
    fn absent_vanished_and_unreadable_end_the_wait_at_once() {
        assert_eq!(scripted(vec![reply("absent")], QUICK).0, Waited::Absent);
        assert_eq!(
            scripted(vec![reply("running 2"), reply("vanished")], QUICK).0,
            Waited::Vanished
        );
        assert!(matches!(
            scripted(vec![reply("Last login: /home/x")], QUICK).0,
            Waited::Unreadable(ref l) if l == "Last login: <path>"
        ));
    }

    #[test]
    fn every_ending_but_done_is_a_problem() {
        assert_eq!(wait_problem(&Waited::Done(3), QUICK), None);
        for w in [
            Waited::Absent,
            Waited::Vanished,
            Waited::TimedOut,
            Waited::LostContact("x".into()),
            Waited::Unreadable("x".into()),
        ] {
            assert!(wait_problem(&w, QUICK).is_some(), "{w:?}");
        }
        assert!(
            wait_problem(&Waited::TimedOut, SUITE_PATIENCE)
                .unwrap()
                .contains("35 minutes")
        );
    }

    /// The scripts themselves, run by a real shell against a private HOME.
    /// Linux only: that is where they run, and macOS has no `setsid`.
    #[cfg(target_os = "linux")]
    mod scripts {
        use super::super::*;

        struct Home(PathBuf);

        impl Home {
            fn new(tag: &str) -> Home {
                let dir = std::env::temp_dir()
                    .join(format!("xtask-detached-{tag}-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(dir.join(REMOTE_RUNS).join("d")).unwrap();
                Home(dir)
            }

            fn sh(&self, script: &str) -> String {
                let out = Command::new("sh")
                    .arg("-c")
                    .arg(script)
                    .env("HOME", &self.0)
                    .output()
                    .unwrap();
                String::from_utf8_lossy(&out.stdout).into_owned()
            }

            fn poll(&self, name: &str) -> Option<Poll> {
                parse_poll(&self.sh(&detached_poll("d", name)))
            }

            /// Poll until the step is no longer running, up to ten seconds.
            fn settle(&self, name: &str) -> Option<Poll> {
                for _ in 0..200 {
                    match self.poll(name) {
                        Some(Poll::Running(_)) => {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        other => return other,
                    }
                }
                self.poll(name)
            }

            fn file(&self, name: &str) -> String {
                std::fs::read_to_string(self.0.join(REMOTE_RUNS).join("d").join(name))
                    .unwrap_or_default()
            }
        }

        impl Drop for Home {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn a_step_records_its_output_and_status_even_one_that_exits() {
            let home = Home::new("done");
            assert_eq!(home.poll("s"), Some(Poll::Absent));
            let started = home.sh(&detached_start("d", "s", "echo out; echo err 1>&2; exit 3"));
            assert_eq!(started.trim(), "started");
            assert_eq!(home.settle("s"), Some(Poll::Done(3)));
            let log = home.file("s.log");
            assert!(log.contains("out") && log.contains("err"), "{log}");
        }

        /// The suite's operator-signal tests need INT, QUIT and HUP at their
        /// defaults; an `&` list ignores INT and QUIT in a non-interactive
        /// shell and `nohup` ignores HUP, and both survive exec.
        #[test]
        fn a_step_starts_with_default_int_quit_and_hup() {
            let home = Home::new("signals");
            home.sh(&detached_start("d", "s", "grep ^SigIgn: /proc/self/status"));
            assert_eq!(home.settle("s"), Some(Poll::Done(0)));
            let line = home.file("s.log");
            let mask = u64::from_str_radix(line.trim().trim_start_matches("SigIgn:").trim(), 16)
                .unwrap_or_else(|e| panic!("no SigIgn mask in {line:?}: {e}"));
            for (name, signal) in [("INT", 2), ("QUIT", 3), ("HUP", 1)] {
                assert_eq!(
                    mask & (1u64 << (signal - 1)),
                    0,
                    "{name} is ignored in the step: {line}"
                );
            }
        }

        #[test]
        fn a_second_start_does_not_run_the_step_twice() {
            let home = Home::new("twice");
            home.sh(&detached_start("d", "s", "echo once >> count; sleep 1"));
            let again = home.sh(&detached_start("d", "s", "echo once >> count; sleep 1"));
            assert_eq!(again.trim(), "", "the second start must not report started");
            assert_eq!(home.settle("s"), Some(Poll::Done(0)));
            assert_eq!(home.file("count").lines().count(), 1);
        }

        #[test]
        fn a_step_that_dies_without_a_status_is_vanished_and_a_stop_ends_it() {
            let home = Home::new("stop");
            home.sh(&detached_start("d", "s", "sleep 30"));
            assert!(matches!(home.poll("s"), Some(Poll::Running(_))));
            // Wait for the pid file, then stop the step's process group.
            for _ in 0..100 {
                if !home.file("s.pid").is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            home.sh(&detached_stop("d", "s", None));
            assert_eq!(home.settle("s"), Some(Poll::Vanished));
        }

        /// The suite's PATH survives the detached wrapper's two shells: the
        /// log's first line is the marker, and the command sees that PATH.
        #[test]
        fn the_scrubbed_path_reaches_the_command_through_the_detached_quoting() {
            let home = Home::new("path");
            let command = format!(
                "env {}",
                with_suite_path(
                    "/usr/bin/printenv PATH",
                    "0123456789abcdef0123456789abcdef01234567"
                )
            );
            home.sh(&detached_start("d", "s", &command));
            assert_eq!(home.settle("s"), Some(Poll::Done(0)));
            let log = home.file("s.log");
            assert!(suite_ran_with_the_scrubbed_path(&log), "{log}");
            assert!(log.lines().any(|l| l == SUITE_PATH), "{log}");
        }

        /// The I01 probe runs in a real shell and reports every name, so the
        /// only problems it can leave are things it found.
        #[test]
        fn the_i01_probe_reports_every_name_in_a_real_shell() {
            let home = Home::new("i01");
            let out = home.sh(&i01_command());
            for p in i01_problems(&out) {
                assert!(
                    !p.contains("did not report") && !p.contains("PATH"),
                    "{p}\n{out}"
                );
            }
        }
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

    const GOOD_DOCTOR: &str = r#"{"capabilities":[{"name":"bwrap_present","status":"available"}],"build":{"revision":"0123456789abcdef0123456789abcdef01234567","dirty":false,"opt_level":"3","debug_assertions":false}}"#;
    /// A suite log that satisfies [`MINI_MAP`]: the PATH line, then one
    /// library binary and the one mapped test.
    const GOOD_LOG: &str = "\
ouro-suite-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ouro-suite-revision=0123456789abcdef0123456789abcdef01234567
ouro-suite-conformance=1
     Running unittests src/lib.rs (target/release/deps/ouro_jail-1d54b8c75e2e48d1)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/conformance_j1.rs (target/release/deps/conformance_j1-004409195d769e4e)

running 1 test
test x01_literal_argv ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
";

    /// The revision the clean run's driver and log agree on.
    const REV: &str = "0123456789abcdef0123456789abcdef01234567";

    /// X01 by a test; each driver check on the one clause it may prove, so
    /// each check's wiring into the verdict is exercised by the decision
    /// tests.
    const MINI_SPEC: &str = "\
## 15. Acceptance matrix

| ID | Test and required result |
|---|---|
| X01 | Spaces reach the fixture literally. |
| R01 | The contract validates. |
| I01 | Nothing else is installed and the suite is clean. |
| I02 | No vendor names. |

## 16. Next
";
    const MINI_MAP: &str = r#"
schema = "ouro.jail.acceptance-map/1"

[[gate]]
id = "X01"
row = "Spaces reach the fixture literally."

[[gate]]
id = "R01"
row = "The contract validates."

[[gate]]
id = "I01"
row = "Nothing else is installed and the suite is clean."

[[gate]]
id = "I02"
row = "No vendor names."

[[clause]]
id = "X01.1"
gate = "X01"
clause = "spaces"
tag = "live-cli"
tests = ["ouro-jail/tests/conformance_j1.rs::x01_literal_argv"]

[[clause]]
id = "R01.1"
gate = "R01"
clause = "the validator passes"
tag = "portable"
checks = ["contract_validation"]

[[clause]]
id = "I01.1"
gate = "I01"
clause = "nothing else installed"
tag = "live-cli"
checks = ["i01_absent"]

[[clause]]
id = "I01.2"
gate = "I01"
clause = "the suite's PATH"
tag = "live-cli"
checks = ["i01_scrubbed_path"]

[[clause]]
id = "I01.3"
gate = "I01"
clause = "the suite is clean"
tag = "live-cli"
checks = ["suite_clean"]

[[clause]]
id = "I02.1"
gate = "I02"
clause = "the scan passes"
tag = "portable"
checks = ["i02_scan"]
"#;

    fn mini_acceptance() -> gates::Acceptance {
        gates::Acceptance {
            map: gates::Map::parse(MINI_MAP).unwrap(),
            rows: gates::spec_rows(MINI_SPEC).unwrap(),
        }
    }

    /// What the I01 probe prints on a host with nothing to find.
    fn clean_i01() -> String {
        let mut s = format!("i01 path {SUITE_PATH}\n");
        for b in I01_BINARIES {
            s.push_str(&format!("i01 binary {b} absent\n"));
        }
        for d in I01_DIRECTORIES {
            s.push_str(&format!("i01 directory {d} absent\n"));
        }
        for p in I01_PACKAGES {
            s.push_str(&format!("i01 package {p} absent\n"));
        }
        s
    }

    const SMOKE_TRANSCRIPT: &str = "\
smoke cgroup 0::/user.slice/user-1001.slice/session-6195.scope
smoke tool 0
smoke none 0
smoke doctor 0
";

    /// A settled receipt from the plain session, trimmed to what the smoke
    /// leg reads (the shape measured on the reference host, 2026-09-24).
    fn smoke_receipt() -> Value {
        serde_json::json!({
            "phase": "settled",
            "outcome": {"kind": "exited", "code": 0, "signal": null},
            "lifetime": {"native": {"details": {
                "supervisor_scope": {
                    "state": "entered",
                    "unit": "ouro-jail-3546133-b8e991b5ed034daf.scope",
                    "reason_code": null,
                    "cgroup": "/user.slice/user-1001.slice/user@1001.service/app.slice/ouro-jail-3546133-b8e991b5ed034daf.scope"
                },
                "execution_cgroup": {
                    "path": "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/ouro-att_c38d4ec4-7acf-4eb9-be7a-9538b066f6e7.leaf"
                }
            }}}
        })
    }

    fn smoke_doctor() -> Value {
        serde_json::json!({
            "ready": true,
            "supervisor_scope": {"state": "entered", "unit": "ouro-jail-3546172-781d4f78be14463e.scope"},
            "capabilities": [
                {"name": "supervisor_scope", "status": "available", "reason_code": "entered"}
            ]
        })
    }

    fn clean_smoke() -> Smoke {
        Smoke {
            transcript: CommandResult {
                code: Some(0),
                stdout: SMOKE_TRANSCRIPT.to_string(),
                stderr: String::new(),
            },
            tool: Some(smoke_receipt().to_string()),
            none: Some(smoke_receipt().to_string()),
            doctor: Some(smoke_doctor().to_string()),
        }
    }

    fn a_clean_run() -> RunOutcomes {
        RunOutcomes {
            remote_created: true,
            mkdir: Some(okc()),
            rsync: Some(okc()),
            build: Some(okc()),
            build_wait: None,
            i02: Some(okc()),
            doctor: Some(okc()),
            doctor_json: Some(GOOD_DOCTOR.to_string()),
            suite: Some(okc()),
            suite_wait: None,
            test_log: Some(GOOD_LOG.to_string()),
            host_manifest: Some(okc()),
            evidence_errors: Vec::new(),
            contract_validation: Some(okc()),
            i01: Some(CommandResult {
                code: Some(0),
                stdout: clean_i01(),
                stderr: String::new(),
            }),
            smoke: Some(clean_smoke()),
            acceptance: Some(Ok(mini_acceptance())),
            revision: Some(REV.to_string()),
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
    fn a_lost_suite_fails_the_run_and_says_why_even_with_a_clean_partial_log() {
        // The hosted failure: the suite kept running on the host, and the
        // driver had no status for it. A partial log with no FAILED line
        // must not make that a pass.
        let mut o = a_clean_run();
        o.suite = None;
        o.suite_wait =
            Some("lost contact with the host: 9 consecutive status checks failed".into());
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("the remote conformance suite lost contact")),
            "{:?}",
            d.failures
        );
        assert!(
            !d.failures.iter().any(|f| f.contains("did not run")),
            "one cause, reported once: {:?}",
            d.failures
        );
        assert!(d.keep_remote);
    }

    #[test]
    fn a_lost_build_fails_the_run_and_stops_there() {
        let mut o = a_clean_run();
        o.build = None;
        o.build_wait = Some("did not finish within 20 minutes and was stopped".into());
        o.i02 = None;
        o.doctor = None;
        o.doctor_json = None;
        o.suite = None;
        o.test_log = None;
        let d = verdict(&o);
        assert_eq!(
            d.failures,
            vec!["the remote release build did not finish within 20 minutes and was stopped"]
        );
        assert!(d.keep_remote);
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
        let t = test_command("d", 2, REV);
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

    // ------------------------------------------------------------- J5: I01

    #[test]
    fn i01_the_suite_runs_with_only_the_system_directories_on_its_path_and_says_so() {
        let t = test_command("d", 2, REV);
        assert!(
            t.contains(&format!(
                "PATH={SUITE_PATH} /bin/sh -c \"echo {SUITE_PATH_MARKER}\\$PATH; \
                 echo ouro-suite-revision={REV}; \
                 echo ouro-suite-conformance=\\$OURO_CONFORMANCE; exec $C test"
            )),
            "{t}"
        );
        // Review H6: the rustup proxy puts ~/.cargo/bin in front of the
        // PATH it is given, so the suite runs the toolchain's own cargo,
        // rustc and rustdoc, found by rustup in the run directory.
        assert!(
            t.starts_with(
                "C=$($HOME/.cargo/bin/rustup which cargo) && R=$($HOME/.cargo/bin/rustup which rustc) \
                 && D=$($HOME/.cargo/bin/rustup which rustdoc) && "
            ),
            "{t}"
        );
        assert!(t.contains(" RUSTC=$R RUSTDOC=$D "), "{t}");
        assert!(
            !t.contains("exec $HOME/.cargo/bin/cargo"),
            "never the proxy: {t}"
        );
        for dir in SUITE_PATH.split(':') {
            assert!(
                dir.starts_with("/usr/") || dir == "/bin" || dir == "/sbin",
                "only system directories: {dir}"
            );
        }
        let marker = format!("{SUITE_PATH_MARKER}{SUITE_PATH}");
        assert!(suite_ran_with_the_scrubbed_path(&format!(
            "{marker}\nrunning 1 test\n"
        )));
        assert!(
            !suite_ran_with_the_scrubbed_path("running 1 test\n"),
            "no marker"
        );
        assert!(
            !suite_ran_with_the_scrubbed_path(
                "ouro-suite-path=/home/ouro-ci/.cargo/bin:/usr/bin\n"
            ),
            "a PATH with the account's directories"
        );
        assert!(
            !suite_ran_with_the_scrubbed_path(&format!(
                "{marker}\nouro-suite-path=/opt/erlang/bin:{SUITE_PATH}\n"
            )),
            "two markers that disagree"
        );
    }

    #[test]
    #[should_panic(expected = "double quote")]
    fn a_suite_command_with_a_double_quote_is_refused() {
        let _ = with_suite_path("echo \"hi\"", REV);
    }

    #[test]
    #[should_panic(expected = "revision")]
    fn a_revision_that_is_not_a_commit_is_refused() {
        let _ = with_suite_path("true", "main; rm -rf /");
    }

    /// Review H6, the proof on the host: under `OURO_CONFORMANCE=1` this
    /// test process (like every test process cargo starts) has exactly the
    /// suite's PATH. Elsewhere the driver's PATH is not in force and there is
    /// nothing to check; a log without the conformance marker is refused by
    /// the verdict, so this cannot pass for a conformance run by skipping.
    ///
    /// Linux only: the scrubbed PATH is the Linux conformance driver's; the
    /// macOS leg sets OURO_CONFORMANCE=1 for the verdict's sake with its own
    /// PATH.
    #[cfg(target_os = "linux")]
    #[test]
    fn i01_under_conformance_the_test_process_has_exactly_the_suite_path() {
        if std::env::var_os("OURO_CONFORMANCE").as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        assert_eq!(
            std::env::var("PATH").ok().as_deref(),
            Some(SUITE_PATH),
            "the suite's tests run with a PATH other than the one the driver set"
        );
    }

    #[test]
    fn i01_the_probe_also_looks_where_cargo_install_puts_binaries() {
        let c = i01_command();
        for b in I01_BINARIES {
            for dir in I01_EXTRA_BIN_DIRS {
                assert!(c.contains(&format!("[ -e {dir}/{b} ]")), "{dir}/{b}: {c}");
            }
        }
        assert!(I01_EXTRA_BIN_DIRS.contains(&"$HOME/.cargo/bin"));
    }

    #[test]
    fn a_log_from_another_revision_or_without_conformance_mode_fails_the_run() {
        let mut o = a_clean_run();
        o.test_log = Some(GOOD_LOG.replace(REV, "fedcba9876543210fedcba9876543210fedcba98"));
        let d = verdict(&o);
        assert!(
            d.failures.iter().any(|f| f.contains("revision")),
            "{:?}",
            d.failures
        );
        o.test_log = Some(GOOD_LOG.replace("ouro-suite-conformance=1", "ouro-suite-conformance="));
        let d = verdict(&o);
        assert!(
            d.failures.iter().any(|f| f.contains("OURO_CONFORMANCE")),
            "{:?}",
            d.failures
        );
        let v = gate_verdict(&a_clean_run(), Some(&a_manifest()))
            .unwrap()
            .unwrap();
        assert!(v.lanes_label.contains(&REV[..12]), "{}", v.lanes_label);
    }

    #[test]
    fn i01_the_probe_uses_the_suite_path_and_names_every_candidate() {
        let c = i01_command();
        assert!(
            c.starts_with(&format!("PATH={SUITE_PATH}; export PATH;")),
            "{c}"
        );
        for b in I01_BINARIES {
            assert!(c.contains(&format!("command -v {b} ")), "{b}: {c}");
        }
        for d in I01_DIRECTORIES {
            let path = d.replace("~/", "$HOME/");
            assert!(c.contains(&format!("[ -e {path} ]")), "{d}: {c}");
            assert!(c.contains(&format!("i01 directory {d} absent")), "{d}: {c}");
        }
        for p in I01_PACKAGES {
            assert!(
                c.contains(&format!("dpkg-query -W -f='${{Status}}' {p} ")),
                "{p}: {c}"
            );
        }
    }

    #[test]
    fn i01_a_clean_probe_has_no_problems() {
        assert_eq!(i01_problems(&clean_i01()), Vec::<String>::new());
    }

    #[test]
    fn i01_anything_found_is_a_problem_that_names_it() {
        for (from, to, needle) in [
            (
                "i01 binary erl absent",
                "i01 binary erl /usr/bin/erl",
                "erl",
            ),
            (
                "i01 binary ouro-ledger absent",
                "i01 binary ouro-ledger /usr/local/bin/ouro-ledger",
                "ouro-ledger",
            ),
            (
                "i01 directory /usr/lib/erlang absent",
                "i01 directory /usr/lib/erlang present",
                "/usr/lib/erlang",
            ),
            (
                "i01 package erlang-base absent",
                "i01 package erlang-base installed",
                "erlang-base",
            ),
            (
                "i01 package elixir absent",
                "i01 package elixir unknown",
                "elixir",
            ),
        ] {
            let out = clean_i01().replace(from, to);
            let p = i01_problems(&out);
            assert_eq!(p.len(), 1, "{to}: {p:?}");
            assert!(p[0].contains(needle), "{p:?}");
        }
    }

    #[test]
    fn i01_a_silent_partial_or_foreign_probe_is_a_problem_not_a_pass() {
        assert!(!i01_problems("").is_empty(), "silence proves nothing");
        let partial: String = clean_i01()
            .lines()
            .take(3)
            .map(|l| format!("{l}\n"))
            .collect();
        let p = i01_problems(&partial);
        assert!(
            p.iter()
                .any(|p| p.contains("did not report") && p.contains("beam.smp")),
            "{p:?}"
        );
        let other_path = clean_i01().replace(
            &format!("i01 path {SUITE_PATH}"),
            "i01 path /home/ouro-ci/.cargo/bin:/usr/bin",
        );
        assert!(
            i01_problems(&other_path).iter().any(|p| p.contains("PATH")),
            "{other_path}"
        );
        let twice = format!("{}i01 binary erl absent\n", clean_i01());
        assert!(
            !i01_problems(&twice).is_empty(),
            "a name reported twice is not trusted"
        );
    }

    #[test]
    fn an_i01_finding_or_a_missing_probe_fails_the_run() {
        let mut o = a_clean_run();
        o.i01 = Some(CommandResult {
            code: Some(0),
            stdout: clean_i01().replace("i01 binary erl absent", "i01 binary erl /usr/bin/erl"),
            stderr: String::new(),
        });
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("I01: ") && f.contains("erl")),
            "{:?}",
            d.failures
        );
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("gate I01 fails") && f.contains("i01_absent")),
            "{:?}",
            d.failures
        );

        o.i01 = None;
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.contains("I01 probe did not run")),
            "{:?}",
            d.failures
        );

        o = a_clean_run();
        o.i01 = Some(failed(255, "Connection reset"));
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("I01 probe exited 255")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn a_suite_log_without_the_scrubbed_path_fails_i01() {
        let mut o = a_clean_run();
        o.test_log = Some(GOOD_LOG.replace(
            "ouro-suite-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
            "",
        ));
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("gate I01 fails") && f.contains("i01_scrubbed_path")),
            "{:?}",
            d.failures
        );
    }

    // ------------------------------------------- J5: contract validation

    #[test]
    fn the_contract_validator_is_run_with_uv_from_the_worktree() {
        let (program, args) = contract_validation_argv();
        assert_eq!(program, "uv");
        assert_eq!(
            args,
            vec!["run".to_string(), CONTRACT_VALIDATOR.to_string()]
        );
    }

    #[test]
    fn a_failed_or_absent_contract_validation_fails_the_run() {
        let mut o = a_clean_run();
        o.contract_validation = Some(failed(1, "AssertionError: receipt-tool.json"));
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.contains("contract validator") && f.contains("exited 1")),
            "{:?}",
            d.failures
        );
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("gate R01 fails") && f.contains("contract_validation"))
        );

        o.contract_validation = None;
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("contract validator did not run")),
            "{:?}",
            verdict(&o).failures
        );
    }

    // ------------------------------------------ J5: plain-session smoke

    #[test]
    fn the_smoke_leg_runs_in_the_plain_session_and_never_in_a_driver_scope() {
        let c = smoke_command("d");
        assert!(c.starts_with("cd $HOME/ouro-ci/runs/d && "), "{c}");
        assert!(
            !c.contains("systemd-run"),
            "the point is that nothing wraps it: {c}"
        );
        assert!(
            !c.contains("XDG_RUNTIME_DIR"),
            "the session's own environment: {c}"
        );
        assert!(!c.contains("OURO_JAIL_TEST_"), "no test seam: {c}");
        assert!(
            c.contains("/proc/self/cgroup"),
            "it records where the session is: {c}"
        );
        for needle in [
            "for profile in tool none",
            "run --profile $profile",
            "--receipt $PWD/smoke/$profile.json",
            "doctor --json > smoke/doctor.json",
            "OURO_DATA_DIR=$PWD/smoke/data",
            "chmod 700 smoke/data smoke/config",
        ] {
            assert!(c.contains(needle), "{needle}: {c}");
        }
    }

    #[test]
    fn a_clean_smoke_leg_has_no_problems() {
        assert_eq!(smoke_problems(&clean_smoke()), Vec::<String>::new());
    }

    #[test]
    fn a_smoke_session_already_inside_the_user_manager_proves_nothing() {
        let mut s = clean_smoke();
        s.transcript.stdout = SMOKE_TRANSCRIPT.replace(
            "session-6195.scope",
            "user@1001.service/app.slice/ouro-conformance-x.scope",
        );
        let p = smoke_problems(&s);
        assert!(p.iter().any(|p| p.contains("already inside")), "{p:?}");
        s.transcript.stdout = SMOKE_TRANSCRIPT.replace(
            "smoke cgroup 0::/user.slice/user-1001.slice/session-6195.scope\n",
            "",
        );
        assert!(
            smoke_problems(&s).iter().any(|p| p.contains("cgroup")),
            "{:?}",
            smoke_problems(&s)
        );
    }

    #[test]
    fn every_way_a_smoke_step_can_fail_is_named() {
        let receipt = smoke_receipt();
        type Edit = Box<dyn Fn(&mut Value)>;
        let edits: Vec<(&str, Edit, &str)> = vec![
            (
                "tool",
                Box::new(|r: &mut Value| r["phase"] = "enforced".into()),
                "settled",
            ),
            (
                "tool",
                Box::new(|r: &mut Value| r["outcome"]["code"] = 1.into()),
                "exit",
            ),
            (
                "none",
                Box::new(|r: &mut Value| {
                    r["lifetime"]["native"]["details"]["supervisor_scope"]["state"] =
                        "already_delegated".into();
                }),
                "entered",
            ),
            (
                "none",
                Box::new(|r: &mut Value| {
                    r["lifetime"]["native"]["details"]["supervisor_scope"]["state"] =
                        "unavailable".into();
                }),
                "entered",
            ),
            (
                "tool",
                Box::new(|r: &mut Value| {
                    r["lifetime"]["native"]["details"]["supervisor_scope"]["test_seam"] =
                        "assume-outside".into();
                }),
                "seam",
            ),
            (
                "tool",
                Box::new(|r: &mut Value| {
                    r["lifetime"]["native"]["details"]["execution_cgroup"] = Value::Null;
                }),
                "leaf",
            ),
        ];
        for (profile, edit, needle) in edits {
            let mut r = receipt.clone();
            edit(&mut r);
            let mut s = clean_smoke();
            if profile == "tool" {
                s.tool = Some(r.to_string());
            } else {
                s.none = Some(r.to_string());
            }
            let p = smoke_problems(&s);
            assert!(
                p.iter().any(|p| p.contains(profile) && p.contains(needle)),
                "{profile} {needle}: {p:?}"
            );
        }

        let mut s = clean_smoke();
        s.tool = None;
        assert!(
            smoke_problems(&s)
                .iter()
                .any(|p| p.contains("tool") && p.contains("no receipt"))
        );
        let mut s = clean_smoke();
        s.none = Some("not json".into());
        assert!(
            smoke_problems(&s)
                .iter()
                .any(|p| p.contains("none") && p.contains("JSON"))
        );
        let mut s = clean_smoke();
        s.transcript.stdout = SMOKE_TRANSCRIPT.replace("smoke none 0", "smoke none 125");
        assert!(
            smoke_problems(&s)
                .iter()
                .any(|p| p.contains("none") && p.contains("125"))
        );
        let mut s = clean_smoke();
        s.transcript.stdout = SMOKE_TRANSCRIPT.replace("smoke doctor 0\n", "");
        assert!(
            smoke_problems(&s)
                .iter()
                .any(|p| p.contains("doctor") && p.contains("did not report"))
        );
        let mut s = clean_smoke();
        s.transcript.code = Some(255);
        assert!(smoke_problems(&s).iter().any(|p| p.contains("exited 255")));

        let mut doctor = smoke_doctor();
        doctor["supervisor_scope"]["state"] = "already_delegated".into();
        let mut s = clean_smoke();
        s.doctor = Some(doctor.to_string());
        assert!(
            smoke_problems(&s)
                .iter()
                .any(|p| p.contains("doctor") && p.contains("entered"))
        );
        let mut doctor = smoke_doctor();
        doctor["capabilities"][0]["status"] = "unavailable".into();
        let mut s = clean_smoke();
        s.doctor = Some(doctor.to_string());
        assert!(
            smoke_problems(&s)
                .iter()
                .any(|p| p.contains("doctor") && p.contains("row"))
        );
    }

    #[test]
    fn a_failed_or_absent_smoke_leg_fails_the_run() {
        let mut o = a_clean_run();
        let mut s = clean_smoke();
        s.transcript.stdout = SMOKE_TRANSCRIPT.replace("smoke tool 0", "smoke tool 1");
        o.smoke = Some(s);
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("plain-session smoke: ")),
            "{:?}",
            d.failures
        );
        assert!(
            !d.failures.iter().any(|f| f.starts_with("gate ")),
            "the smoke leg proves no §15 clause; it fails the run on its own: {:?}",
            d.failures
        );

        o.smoke = None;
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("plain-session smoke leg did not run")),
            "{:?}",
            verdict(&o).failures
        );
    }

    // ------------------------------------------------- J5: gate verdict

    #[test]
    fn a_mapped_test_missing_from_the_log_fails_the_run_by_gate_and_clause() {
        let mut o = a_clean_run();
        o.test_log = Some(
            GOOD_LOG
                .replace("test x01_literal_argv ... ok\n", "")
                .replace("1 passed", "0 passed"),
        );
        let d = verdict(&o);
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("gate X01 fails: X01.1: ") && f.contains("absent")),
            "{:?}",
            d.failures
        );
        o.test_log =
            Some(GOOD_LOG.replace("x01_literal_argv ... ok", "x01_literal_argv ... ignored"));
        let d = verdict(&o);
        assert!(
            d.failures.iter().any(|f| f.starts_with("gate X01 fails")),
            "{:?}",
            d.failures
        );
        assert!(
            d.failures
                .iter()
                .any(|f| f.starts_with("acceptance: ") && f.contains("not pinned")),
            "an unpinned ignore is its own failure: {:?}",
            d.failures
        );
    }

    #[test]
    fn an_acceptance_map_that_did_not_load_fails_the_run() {
        let mut o = a_clean_run();
        o.acceptance = Some(Err("the acceptance map: expected `=`".to_string()));
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("acceptance map") && f.contains("expected")),
            "{:?}",
            verdict(&o).failures
        );
        o.acceptance = None;
        assert!(
            verdict(&o)
                .failures
                .iter()
                .any(|f| f.contains("no gate verdict") && f.contains("not loaded")),
            "{:?}",
            verdict(&o).failures
        );
    }

    #[test]
    fn every_driver_check_is_derived_from_its_own_step() {
        let clean = driver_checks(&a_clean_run(), Some(&a_manifest()));
        for k in gates::CHECKS.iter().filter(|k| **k != "suite_clean") {
            assert_eq!(clean.get(*k), Some(&true), "{k}: {clean:?}");
        }
        let flip = |edit: &dyn Fn(&mut RunOutcomes), check: &str| {
            let mut o = a_clean_run();
            edit(&mut o);
            let c = driver_checks(&o, Some(&a_manifest()));
            assert_ne!(c.get(check), Some(&true), "{check}: {c:?}");
        };
        flip(&|o| o.i02 = Some(failed(1, "")), "i02_scan");
        flip(&|o| o.i02 = None, "i02_scan");
        flip(
            &|o| o.contract_validation = Some(failed(1, "")),
            "contract_validation",
        );
        flip(
            &|o| o.doctor_json = Some(r#"{"capabilities":[]}"#.to_string()),
            "doctor_manifest",
        );
        flip(&|o| o.doctor = Some(failed(1, "")), "doctor_manifest");
        flip(
            &|o| o.i01.as_mut().unwrap().stdout = String::new(),
            "i01_absent",
        );
        flip(
            &|o| o.test_log = Some("running 0 tests\n".to_string()),
            "i01_scrubbed_path",
        );
        flip(
            &|o| o.smoke.as_mut().unwrap().tool = None,
            "plain_session_smoke",
        );
        assert_eq!(
            driver_checks(&a_clean_run(), None).get("doctor_manifest"),
            Some(&false)
        );
    }

    #[test]
    fn the_verdict_the_driver_writes_is_the_one_it_decides_on() {
        let v = gate_verdict(&a_clean_run(), Some(&a_manifest()))
            .expect("a log exists")
            .expect("the map loaded");
        assert!(v.failures().is_empty(), "{:?}", v.failures());
        let mut o = a_clean_run();
        o.test_log = None;
        assert!(gate_verdict(&o, Some(&a_manifest())).is_none());
    }
}
