//! What the helper actually enforces, observed on a running Linux kernel.
//!
//! Everything here drives the real binary against a real workspace and asserts on what the
//! kernel did, not on what the plan said it would do — the plan is already covered by the
//! portable unit tests, and a plan that compiles correctly and enforces nothing is exactly
//! the failure this file exists to catch.
//!
//! # When these do not run
//!
//! The whole file is `cfg(target_os = "linux")`, so `cargo test` on macOS compiles and
//! skips it. On Linux each test additionally asks the binary's own `doctor` whether this
//! kernel and container can enforce anything, and **prints why it is skipping** rather
//! than passing quietly — a green run that silently checked nothing is worse than a red
//! one. Unprivileged Docker blocks `unshare(CLONE_NEWUSER)`, so proving these needs
//! `--privileged` (or a host).

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HELPER: &str = env!("CARGO_BIN_EXE_ouro-sandbox");

// ------------------------------------------------------------------------- scaffolding

fn doctor() -> serde_json::Value {
    let output = Command::new(HELPER)
        .arg("doctor")
        .output()
        .expect("doctor runs");
    serde_json::from_slice(&output.stdout).expect("doctor emits JSON")
}

/// `Some(reason)` when this environment cannot enforce, so a test can say so out loud.
fn unsupported() -> Option<String> {
    let report = doctor();
    if report["usable"] == serde_json::Value::Bool(true) {
        None
    } else {
        Some(format!(
            "kernel {} cannot enforce: {}",
            report["kernel"], report["notes"]
        ))
    }
}

macro_rules! require_enforcement {
    () => {
        if let Some(reason) = unsupported() {
            eprintln!("SKIPPED: {reason}");
            return;
        }
    };
}

struct Workspace {
    root: PathBuf,
    scratch: PathBuf,
}

impl Workspace {
    fn new(tag: &str) -> Workspace {
        let base = std::env::temp_dir().join(format!(
            "ouro-sandbox-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("workspace");
        let scratch = base.join("scratch");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("deps/foo/.git")).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(root.join("existing.txt"), "before\n").unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        Workspace { root, scratch }
    }

    fn outside(&self) -> PathBuf {
        self.root.parent().unwrap().join("outside.txt")
    }

    fn request(&self, mode: &str, network: bool) -> String {
        let writable = if mode == "read_only" {
            String::new()
        } else {
            format!(r#","writable":["{}"]"#, self.root.display())
        };

        format!(
            r#"{{"mode":"{mode}","scratch":"{}","cwd":"{}","denied_names":[".git",".ouroboros"],"network":{network}{writable}}}"#,
            self.scratch.display(),
            self.root.display(),
        )
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.root.parent().unwrap());
    }
}

fn run_shell(request: &str, script: &str) -> Output {
    Command::new(HELPER)
        .args(["exec", "--request", request, "--", "/bin/sh", "-c", script])
        .output()
        .expect("helper runs")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The assertion that ties this crate to the Elixir escalation loop: a denial has to
/// *look* like the thing `Ouroboros.Provider.Native.Sandbox.violation/3` matches.
fn assert_reads_as_read_only_denial(output: &Output, what: &str) {
    let text = combined(output);
    assert!(
        !output.status.success(),
        "{what}: expected a denial, got success. output: {text}"
    );
    assert!(
        text.contains("Read-only file system"),
        "{what}: a denial must surface as EROFS so the escalation loop recognises it, \
         got: {text}"
    );
}

// ------------------------------------------------------------------------ the doctor

#[test]
fn doctor_states_what_this_kernel_can_do() {
    let report = doctor();
    // Printed unconditionally: the run's own record of what it was standing on.
    eprintln!("doctor: {report}");

    assert_eq!(report["helper"], "ouro-sandbox");
    assert_eq!(report["os"], "linux");
    assert!(report["usable"].is_boolean());
    assert!(report["landlock"]["available"].is_boolean());
}

// ------------------------------------------------------------------------ the basics

#[test]
fn a_command_runs_and_its_exit_status_is_this_processs_exit_status() {
    require_enforcement!();
    let workspace = Workspace::new("status");

    let ok = run_shell(&workspace.request("read_only", false), "echo hello");
    assert!(ok.status.success(), "{}", combined(&ok));
    assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "hello");

    // The command's own failure must arrive unchanged — not folded into a helper status.
    let failed = run_shell(&workspace.request("read_only", false), "exit 42");
    assert_eq!(failed.status.code(), Some(42), "{}", combined(&failed));
}

#[test]
fn reads_still_reach_the_whole_filesystem() {
    require_enforcement!();
    let workspace = Workspace::new("reads");

    let output = run_shell(
        &workspace.request("read_only", false),
        "cat /etc/hostname > /dev/null && cat existing.txt",
    );
    assert!(output.status.success(), "{}", combined(&output));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "before");
}

#[test]
fn the_scratch_directory_is_writable_in_every_mode() {
    require_enforcement!();
    let workspace = Workspace::new("scratch");

    for mode in ["read_only", "workspace_write"] {
        let output = run_shell(
            &workspace.request(mode, false),
            &format!(
                "echo x > {}/probe && cat {}/probe",
                workspace.scratch.display(),
                workspace.scratch.display()
            ),
        );
        assert!(output.status.success(), "{mode}: {}", combined(&output));
    }
}

// -------------------------------------------------------------- the filesystem policy

#[test]
fn read_only_denies_a_write_into_the_workspace() {
    require_enforcement!();
    let workspace = Workspace::new("ro-deny");

    let output = run_shell(
        &workspace.request("read_only", false),
        "echo mutated > existing.txt",
    );
    assert_reads_as_read_only_denial(&output, "read_only workspace write");
    assert_eq!(
        std::fs::read_to_string(workspace.root.join("existing.txt")).unwrap(),
        "before\n",
        "the file changed on the host, which means nothing was enforced"
    );
}

#[test]
fn workspace_write_permits_the_workspace_and_denies_everything_outside_it() {
    require_enforcement!();
    let workspace = Workspace::new("ww");

    let inside = run_shell(
        &workspace.request("workspace_write", false),
        "echo mutated > existing.txt",
    );
    assert!(inside.status.success(), "{}", combined(&inside));
    assert_eq!(
        std::fs::read_to_string(workspace.root.join("existing.txt")).unwrap(),
        "mutated\n"
    );

    let outside = run_shell(
        &workspace.request("workspace_write", false),
        &format!("echo x > {}", workspace.outside().display()),
    );
    assert_reads_as_read_only_denial(&outside, "write outside the workspace");
    assert!(!workspace.outside().exists());
}

#[test]
fn a_writable_worktree_under_a_read_only_data_directory_stays_writable() {
    require_enforcement!();
    // The D7 case the bubblewrap backend calls out: the node's data directory is
    // protected, but a session's worktree *inside* it must still be writable. It works
    // because the writable bind is taken before the read-only sweep, while its source is
    // still pristine — get that order wrong and this is the test that notices.
    let workspace = Workspace::new("nested-worktree");
    let data = workspace.root.parent().unwrap().join("data");
    let worktree = data.join("worktrees/s1");
    std::fs::create_dir_all(&worktree).unwrap();
    std::fs::write(data.join("node.db"), "state\n").unwrap();
    std::fs::write(worktree.join("f.txt"), "before\n").unwrap();

    let request = format!(
        r#"{{"mode":"workspace_write","scratch":"{}","cwd":"{}","writable":["{}"],"protected":["{}"],"denied_names":[".git"],"network":false}}"#,
        workspace.scratch.display(),
        worktree.display(),
        worktree.display(),
        data.display(),
    );

    let inside = run_shell(&request, "echo mutated > f.txt");
    assert!(
        inside.status.success(),
        "the worktree must stay writable: {}",
        combined(&inside)
    );
    assert_eq!(
        std::fs::read_to_string(worktree.join("f.txt")).unwrap(),
        "mutated\n"
    );

    // And the data directory around it must not be.
    let around = run_shell(&request, &format!("echo x > {}/node.db", data.display()));
    assert_reads_as_read_only_denial(&around, "write into the data directory itself");
    assert_eq!(
        std::fs::read_to_string(data.join("node.db")).unwrap(),
        "state\n"
    );
}

#[test]
fn an_existing_git_directory_is_read_only_inside_a_writable_workspace() {
    require_enforcement!();
    let workspace = Workspace::new("git");

    let head = run_shell(
        &workspace.request("workspace_write", false),
        "echo broken > .git/HEAD",
    );
    assert_reads_as_read_only_denial(&head, "write into .git");
    assert_eq!(
        std::fs::read_to_string(workspace.root.join(".git/HEAD")).unwrap(),
        "ref: refs/heads/main\n"
    );

    // A vendored dependency's repository is as protected as the workspace's own.
    let nested = run_shell(
        &workspace.request("workspace_write", false),
        "echo x > deps/foo/.git/config",
    );
    assert_reads_as_read_only_denial(&nested, "write into a nested .git");
}

#[test]
fn an_escalated_policy_lifts_the_git_fence_and_keeps_the_ouroboros_one() {
    require_enforcement!();
    let workspace = Workspace::new("escalated");
    std::fs::create_dir_all(workspace.root.join(".ouroboros")).unwrap();

    let request = format!(
        r#"{{"mode":"workspace_write_escalated","scratch":"{}","cwd":"{}","denied_names":[".ouroboros"],"network":false,"writable":["{}"]}}"#,
        workspace.scratch.display(),
        workspace.root.display(),
        workspace.root.display(),
    );

    let git = run_shell(&request, "echo escalated > .git/HEAD");
    assert!(
        git.status.success(),
        "an approved escalation must be able to write .git: {}",
        combined(&git)
    );

    let ouro = run_shell(&request, "echo x > .ouroboros/state");
    assert_reads_as_read_only_denial(&ouro, "the .ouroboros fence survives an escalation");
}

// -------------------------------------------------------------------- name-based creates

#[test]
fn creating_a_new_git_directory_is_denied_only_where_the_preload_filter_is_present() {
    require_enforcement!();
    let workspace = Workspace::new("create-git");

    let library = std::env::var("OUROBOROS_FS_FILTER_LIBRARY").unwrap_or_default();
    if library.is_empty() || !Path::new(&library).exists() {
        // The honest gap, stated rather than skipped past: Landlock cannot deny the
        // creation of a path that does not exist yet, so this case is carried entirely by
        // the LD_PRELOAD shim, exactly as it is under the bubblewrap backend.
        eprintln!(
            "SKIPPED: OUROBOROS_FS_FILTER_LIBRARY is unset, so the name-based create \
             denial has no enforcement layer in this run and is NOT proven here"
        );
        return;
    }

    // Carried in the request, which is the path the daemon actually uses — the
    // environment variable is only a hand-run fallback and proving that instead would
    // prove the wrong thing.
    let request = workspace.request("workspace_write", false).replace(
        r#""network":false"#,
        &format!(r#""network":false,"fs_filter_library":"{library}""#),
    );
    assert!(request.contains("fs_filter_library"), "request: {request}");

    let output = run_shell(
        &request,
        "mkdir -p deps/bar/.git && echo x > deps/bar/.git/HEAD",
    );

    assert_reads_as_read_only_denial(&output, "mkdir of a new .git");
    assert!(!workspace.root.join("deps/bar/.git").exists());
}

// ------------------------------------------------------------------------- the network

/// Runs a script under `bash`, which unlike `sh` can open a TCP socket (`/dev/tcp`) and is
/// therefore the only way to observe the network posture without adding a dependency.
fn run_bash(request: &str, script: &str) -> Option<Output> {
    if !Path::new("/bin/bash").exists() {
        return None;
    }
    Some(
        Command::new(HELPER)
            .args([
                "exec",
                "--request",
                request,
                "--",
                "/bin/bash",
                "-c",
                script,
            ])
            .output()
            .expect("helper runs"),
    )
}

#[test]
fn a_network_denied_policy_cannot_reach_off_the_machine() {
    require_enforcement!();
    if doctor()["namespaces"]["net"] != serde_json::Value::Bool(true) {
        eprintln!("SKIPPED: no network namespace available in this environment");
        return;
    }
    let workspace = Workspace::new("net-out");

    let Some(output) = run_bash(
        &workspace.request("read_only", false),
        "exec 3<>/dev/tcp/1.1.1.1/80",
    ) else {
        eprintln!("SKIPPED: no /bin/bash, so the network posture cannot be observed here");
        return;
    };

    let text = combined(&output);
    assert!(!output.status.success(), "the connect succeeded: {text}");
    // The exact string the Elixir side matches to attribute a denial to the network half
    // of the sandbox rather than the filesystem half.
    assert!(
        text.contains("Network is unreachable"),
        "expected ENETUNREACH from an empty network namespace, got: {text}"
    );
}

#[test]
fn a_network_denied_policy_still_leaves_loopback_usable() {
    require_enforcement!();
    if doctor()["namespaces"]["net"] != serde_json::Value::Bool(true) {
        eprintln!("SKIPPED: no network namespace available in this environment");
        return;
    }
    let workspace = Workspace::new("net-lo");

    // Nothing is listening, so this cannot connect — but *how* it fails is the point.
    // "Connection refused" means the loopback interface is up and the packet was
    // delivered and rejected; "Network is unreachable" would mean this helper had left a
    // build tool that talks to itself over TCP with no way to do so.
    let Some(output) = run_bash(
        &workspace.request("read_only", false),
        "exec 3<>/dev/tcp/127.0.0.1/1",
    ) else {
        eprintln!("SKIPPED: no /bin/bash, so the network posture cannot be observed here");
        return;
    };

    let text = combined(&output);
    assert!(
        text.contains("Connection refused"),
        "loopback must stay reachable inside the namespace, got: {text}"
    );
}

// -------------------------------------------------------------------------- the belts

#[test]
fn the_command_cannot_remount_its_way_out_of_the_policy() {
    require_enforcement!();
    let workspace = Workspace::new("remount");

    // Three layers say no to this: the capability was dropped, seccomp refuses the
    // syscall, and Landlock would deny the write even if a remount succeeded.
    let output = run_shell(
        &workspace.request("read_only", false),
        "mount -o remount,rw / 2>&1; echo mutated > existing.txt",
    );
    assert_reads_as_read_only_denial(&output, "remount then write");
    assert_eq!(
        std::fs::read_to_string(workspace.root.join("existing.txt")).unwrap(),
        "before\n"
    );
}

#[test]
fn a_seccomp_denied_syscall_fails_with_a_recognisable_errno() {
    require_enforcement!();
    let workspace = Workspace::new("seccomp");

    // `unshare` is on the belt's denylist: a fresh user namespace would hand the command
    // a full capability set to start over with.
    let output = run_shell(
        &workspace.request("read_only", false),
        "unshare --user --map-root-user /bin/true 2>&1 || echo DENIED",
    );
    let text = combined(&output);
    assert!(
        text.contains("DENIED") || text.contains("Operation not permitted"),
        "expected unshare to be refused by the seccomp belt, got: {text}"
    );
}

#[test]
fn the_command_runs_without_capabilities() {
    require_enforcement!();
    let workspace = Workspace::new("caps");

    let output = run_shell(
        &workspace.request("read_only", false),
        "grep -E '^CapEff|^CapBnd' /proc/self/status",
    );
    let text = combined(&output);
    assert!(output.status.success(), "{text}");
    for line in text.lines() {
        if let Some((_, value)) = line.split_once(':') {
            assert_eq!(
                value.trim(),
                "0000000000000000",
                "a capability survived into the command: {line}"
            );
        }
    }
}

#[test]
fn no_new_privs_is_set_so_a_setuid_binary_cannot_escalate() {
    require_enforcement!();
    let workspace = Workspace::new("nnp");

    let output = run_shell(
        &workspace.request("read_only", false),
        "grep NoNewPrivs /proc/self/status",
    );
    assert!(
        combined(&output).contains("NoNewPrivs:\t1"),
        "{}",
        combined(&output)
    );
}

// --------------------------------------------------------------- backend-failure shape

#[test]
fn a_policy_that_cannot_be_parsed_is_a_backend_failure_not_a_command_failure() {
    // Deliberately not gated on enforcement: this is the path the Elixir side reads to
    // tell "this node could not sandbox it" from "your command failed", and it must hold
    // everywhere.
    let output = Command::new(HELPER)
        .args([
            "exec",
            "--request",
            "{not json",
            "--",
            "/bin/sh",
            "-c",
            "echo ran",
        ])
        .output()
        .expect("helper runs");

    assert_eq!(
        output.status.code(),
        Some(125),
        "a backend failure must not look like a command exit status"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("ouro-sandbox: "),
        "Sandbox.backend_failure/3 matches on this exact prefix, got: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("ran"),
        "the command must not run when its policy could not be applied"
    );
}

#[test]
fn a_request_naming_an_unimplemented_field_is_refused_rather_than_under_enforced() {
    let output = Command::new(HELPER)
        .args([
            "exec",
            "--request",
            r#"{"mode":"read_only","scratch":"/tmp","future_knob":true}"#,
            "--",
            "/bin/sh",
            "-c",
            "echo ran",
        ])
        .output()
        .expect("helper runs");

    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("ouro-sandbox: "));
}

#[test]
fn the_request_can_arrive_on_stdin_without_eating_the_commands_own_input() {
    require_enforcement!();
    use std::io::Write;
    use std::process::Stdio;

    let workspace = Workspace::new("stdin");
    let request = workspace.request("read_only", false);

    let mut child = Command::new(HELPER)
        .args(["exec", "--request-file", "-", "--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("helper spawns");

    {
        let stdin = child.stdin.as_mut().unwrap();
        // The request, its newline, and then the payload that belongs to `cat`. A
        // buffered read of the request would swallow the payload.
        stdin.write_all(request.as_bytes()).unwrap();
        stdin.write_all(b"\nthe command's own input\n").unwrap();
    }

    let output = child.wait_with_output().expect("helper finishes");
    assert!(output.status.success(), "{}", combined(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "the command's own input"
    );
}
