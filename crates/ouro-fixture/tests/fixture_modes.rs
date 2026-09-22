//! Every `ouro-fixture` mode, run as a real process.
//!
//! These tests assert two things for each operation: the JSON line the fixture
//! printed, and the real effect on the filesystem or the process. A line that
//! claims a file was created is checked against the file.
//!
//! Portable modes run on both platforms. Linux-only syscalls have a pair of
//! tests: on Linux they must work, on macOS they must report `unsupported` and
//! exit 3. Nothing here is skipped.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const EXIT_EXPECTATION_FAILED: i32 = 3;
const EXIT_USAGE: i32 = 2;

fn fixture() -> std::path::PathBuf {
    ouro_fixture::harness::fixture_path()
}

fn run(args: &[&str]) -> Output {
    Command::new(fixture())
        .args(args)
        .output()
        .expect("the fixture binary must run")
}

fn lines(out: &Output) -> Vec<Value> {
    out.stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_slice(l)
                .unwrap_or_else(|e| panic!("not a JSON line: {e}: {}", String::from_utf8_lossy(l)))
        })
        .collect()
}

fn only(out: &Output) -> Value {
    let l = lines(out);
    assert_eq!(l.len(), 1, "expected one line, got {l:?}");
    l.into_iter().next().unwrap()
}

fn code(out: &Output) -> i32 {
    out.status
        .code()
        .expect("the fixture must not die on a signal")
}

struct Dir(ouro_fixture::harness::TempDir);

impl Dir {
    fn new() -> Dir {
        Dir(ouro_fixture::harness::TempDir::new("ouro-fixture-modes").unwrap())
    }
    fn path(&self) -> &Path {
        self.0.path()
    }
    fn at(&self, name: &str) -> String {
        self.path().join(name).display().to_string()
    }
}

// ------------------------------------------------------------------- open

#[test]
fn open_creates_a_file_through_every_variant_this_platform_has() {
    let dir = Dir::new();
    let portable = ["openat"];
    let legacy = ["open", "creat"];

    for via in portable {
        let path = dir.at(&format!("via-{via}"));
        let out = run(&["open", &path, "--via", via, "--create", "--write"]);
        let line = only(&out);
        assert_eq!(line["op"], via);
        assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
        assert!(line["ret"].as_i64().unwrap() >= 0, "{line}");
        assert_eq!(line["errno"], Value::Null);
        assert!(Path::new(&path).is_file(), "{via} did not create the file");
    }

    for via in legacy {
        let path = dir.at(&format!("via-{via}"));
        let out = run(&["open", &path, "--via", via, "--create", "--write"]);
        let line = only(&out);
        assert_eq!(line["op"], via);
        if ouro_fixture::raw::has_legacy_syscalls() {
            assert_eq!(code(&out), 0, "{line}");
            assert!(Path::new(&path).is_file());
        } else {
            assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
            assert!(line["args"]["unsupported"].is_string(), "{line}");
            assert!(!Path::new(&path).exists());
        }
    }
}

#[test]
fn openat2_works_on_linux_and_reports_unsupported_elsewhere() {
    let dir = Dir::new();
    let path = dir.at("openat2-target");
    let out = run(&["open", &path, "--via", "openat2", "--create", "--write"]);
    let line = only(&out);
    assert_eq!(line["op"], "openat2");
    if cfg!(target_os = "linux") {
        assert_eq!(code(&out), 0, "{line}");
        assert!(Path::new(&path).is_file());
    } else {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        let reason = line["args"]["unsupported"].as_str().unwrap();
        assert!(reason.contains("unsupported on this platform"), "{reason}");
        assert!(!Path::new(&path).exists());
    }
}

#[test]
fn an_expected_errno_succeeds_and_an_unexpected_one_fails() {
    let dir = Dir::new();
    let missing = dir.at("absent/deeper");

    let out = run(&["open", &missing, "--expect", "ENOENT"]);
    assert_eq!(code(&out), 0);
    assert_eq!(only(&out)["errno"], "ENOENT");

    let out = run(&["open", &missing]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "default expect is ok");

    let out = run(&["open", &missing, "--expect", "EACCES"]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
    assert_eq!(only(&out)["errno"], "ENOENT", "the real errno is reported");

    let out = run(&["open", &missing, "--expect", "any"]);
    assert_eq!(code(&out), 0, "`any` accepts a performed failure");
}

#[test]
fn an_unknown_errno_name_is_a_usage_error_before_anything_runs() {
    let dir = Dir::new();
    let out = run(&["open", &dir.at("x"), "--expect", "ENOTAREALERRNO"]);
    assert_eq!(code(&out), EXIT_USAGE);
    assert!(lines(&out).is_empty(), "nothing was performed");
    assert!(!dir.path().join("x").exists());
}

#[test]
fn a_path_with_an_interior_nul_is_refused_before_the_syscall() {
    // The boundary test for the unsafe layer: the kernel would see a truncated
    // path and touch a different file, so the fixture must never call it.
    //
    // Such a path cannot arrive through argv, because `execve` argument
    // strings are themselves NUL terminated and the standard library refuses
    // one outright. It arrives through a `script` step, where the JSON string
    // carries the NUL, which is exactly the route a generated workload uses.
    let dir = Dir::new();
    let path = format!("{}\u{0}ignored", dir.at("boundary"));
    let script = dir.at("nul.json");
    std::fs::write(
        &script,
        serde_json::json!([["open", path, "--create", "--write"]]).to_string(),
    )
    .unwrap();

    let out = run(&["script", &script]);
    let line = only(&out);
    assert_eq!(line["op"], "openat");
    assert_eq!(line["args"]["refused"], "interior_nul");
    assert_eq!(line["ret"], -1);
    assert_eq!(line["errno"], Value::Null);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
    assert!(
        !dir.path().join("boundary").exists(),
        "the truncated path must not have been created"
    );
    let siblings: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(siblings, ["nul.json"], "no other file was created either");
}

// --------------------------------------------------- directories and links

#[test]
fn mkdir_and_rmdir_work_through_their_variants() {
    let dir = Dir::new();
    for (mk, rm) in [("mkdirat", "unlinkat"), ("mkdir", "rmdir")] {
        let path = dir.at(&format!("d-{mk}"));
        let out = run(&["mkdir", &path, "--via", mk]);
        let line = only(&out);
        assert_eq!(line["op"], mk);
        if mk == "mkdir" && !ouro_fixture::raw::has_legacy_syscalls() {
            assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
            continue;
        }
        assert_eq!(code(&out), 0, "{line}");
        assert!(Path::new(&path).is_dir());

        let out = run(&["rmdir", &path, "--via", rm]);
        let line = only(&out);
        assert_eq!(line["op"], rm);
        assert_eq!(code(&out), 0, "{line}");
        assert!(!Path::new(&path).exists());
    }
}

#[test]
fn rename_unlink_link_and_symlink_change_the_filesystem_as_reported() {
    let dir = Dir::new();
    let a = dir.at("a");
    let b = dir.at("b");
    let hard = dir.at("hard");
    let sym = dir.at("sym");

    assert_eq!(code(&run(&["open", &a, "--create", "--write"])), 0);

    let out = run(&["rename", &a, &b, "--via", "renameat"]);
    assert_eq!(only(&out)["op"], "renameat");
    assert_eq!(code(&out), 0);
    assert!(!Path::new(&a).exists() && Path::new(&b).is_file());

    let out = run(&["link", &b, &hard, "--via", "linkat"]);
    assert_eq!(only(&out)["op"], "linkat");
    assert_eq!(code(&out), 0);
    assert!(Path::new(&hard).is_file());

    let out = run(&["symlink", &b, &sym, "--via", "symlinkat"]);
    assert_eq!(only(&out)["op"], "symlinkat");
    assert_eq!(code(&out), 0);
    assert!(std::fs::symlink_metadata(&sym).unwrap().is_symlink());

    let out = run(&["unlink", &hard, "--via", "unlinkat"]);
    assert_eq!(only(&out)["op"], "unlinkat");
    assert_eq!(code(&out), 0);
    assert!(!Path::new(&hard).exists());
    assert!(Path::new(&b).is_file(), "the other link survives");
}

#[test]
fn renameat2_works_on_linux_and_reports_unsupported_elsewhere() {
    let dir = Dir::new();
    let a = dir.at("r2-a");
    let b = dir.at("r2-b");
    assert_eq!(code(&run(&["open", &a, "--create", "--write"])), 0);

    let out = run(&["rename", &a, &b, "--via", "renameat2"]);
    let line = only(&out);
    assert_eq!(line["op"], "renameat2");
    if cfg!(target_os = "linux") {
        assert_eq!(code(&out), 0, "{line}");
        assert!(Path::new(&b).is_file());
        // RENAME_NOREPLACE must refuse an existing destination.
        let c = dir.at("r2-c");
        assert_eq!(code(&run(&["open", &c, "--create", "--write"])), 0);
        let out = run(&[
            "rename",
            &b,
            &c,
            "--via",
            "renameat2",
            "--noreplace",
            "--expect",
            "EEXIST",
        ]);
        assert_eq!(code(&out), 0, "{}", only(&out));
    } else {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        assert!(line["args"]["unsupported"].is_string(), "{line}");
        assert!(Path::new(&a).is_file(), "nothing moved");
    }
}

#[test]
fn mknod_creates_the_node_kind_it_names() {
    let dir = Dir::new();

    // mknodat: present on every Linux architecture, absent on Darwin.
    let fifo = dir.at("node-fifo");
    let out = run(&["mknod", &fifo, "--via", "mknodat"]);
    let line = only(&out);
    assert_eq!(line["op"], "mknodat");
    if cfg!(target_os = "linux") {
        assert_eq!(code(&out), 0, "{line}");
        assert_eq!(line["args"]["dev"], 0);
        assert_eq!(line["args"]["kind"], "S_IFIFO");
        assert_eq!(line["args"]["dirfd"], "AT_FDCWD");
        assert_eq!(line["args"]["mode"], "10600", "S_IFIFO | 0600, octal");
        use std::os::unix::fs::FileTypeExt;
        let meta = std::fs::symlink_metadata(&fifo).unwrap();
        assert!(meta.file_type().is_fifo(), "not a fifo: {meta:?}");
    } else {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        let reason = line["args"]["unsupported"].as_str().unwrap();
        assert!(reason.contains("unsupported on this platform"), "{reason}");
        assert!(!Path::new(&fifo).exists());
    }

    // mknod: the legacy number, and a regular file this time.
    let reg = dir.at("node-regular");
    let out = run(&[
        "mknod",
        &reg,
        "--via",
        "mknod",
        "--regular",
        "--mode",
        "640",
    ]);
    let line = only(&out);
    assert_eq!(line["op"], "mknod");
    if !ouro_fixture::raw::has_legacy_syscalls() {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        assert!(line["args"]["unsupported"].is_string(), "{line}");
        return;
    }
    assert_eq!(line["args"]["kind"], "S_IFREG");
    assert_eq!(line["args"]["dev"], 0);
    assert!(line["args"].get("dirfd").is_none(), "mknod takes no dirfd");
    if cfg!(target_os = "linux") {
        assert_eq!(code(&out), 0, "{line}");
        let meta = std::fs::metadata(&reg).unwrap();
        assert!(meta.is_file());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o7777, 0o640);
    } else {
        // Darwin restricts every `mknod` to the super-user, so the honest
        // result here is EPERM and no node.
        assert_eq!(line["errno"], "EPERM", "{line}");
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        assert!(!Path::new(&reg).exists());
    }
}

#[test]
fn mknod_reports_the_kernels_refusal_rather_than_pre_judging_it() {
    let dir = Dir::new();
    let path = dir.at("exists");
    assert_eq!(code(&run(&["open", &path, "--create", "--write"])), 0);

    let out = run(&["mknod", &path, "--via", "mknodat", "--expect", "EEXIST"]);
    let line = only(&out);
    if cfg!(target_os = "linux") {
        assert_eq!(line["errno"], "EEXIST", "{line}");
        assert_eq!(code(&out), 0);
    } else {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "mknodat is Linux only");
    }
}

#[test]
fn truncate_sets_the_length_by_path() {
    let dir = Dir::new();
    let path = dir.at("t-by-path");
    std::fs::write(&path, vec![b'x'; 100]).unwrap();

    let out = run(&["truncate", &path, "4096"]);
    let line = only(&out);
    assert_eq!(line["op"], "truncate");
    assert_eq!(line["args"]["length"], 4096);
    assert_eq!(line["errno"], Value::Null);
    assert_eq!(code(&out), 0, "{line}");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 4096);

    let out = run(&["truncate", &path, "0"]);
    assert_eq!(code(&out), 0);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);

    // A missing path and a negative length are the kernel's answers, not ours.
    let out = run(&["truncate", &dir.at("absent"), "10", "--expect", "ENOENT"]);
    assert_eq!(code(&out), 0, "{}", only(&out));
    let out = run(&["truncate", &path, "--", "-1"]);
    assert_eq!(only(&out)["errno"], "EINVAL", "{}", only(&out));
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
}

#[test]
fn ftruncate_reports_the_open_that_named_the_path_and_then_a_descriptor_only_call() {
    let dir = Dir::new();
    let path = dir.at("t-by-fd");
    std::fs::write(&path, vec![b'x'; 100]).unwrap();

    let out = run(&["ftruncate", &path, "2048"]);
    let l = lines(&out);
    assert_eq!(l.len(), 2, "the open and the truncation: {l:?}");

    assert_eq!(l[0]["op"], "openat", "the path is named here");
    assert!(l[0]["ret"].as_i64().unwrap() >= 0);

    assert_eq!(l[1]["op"], "ftruncate");
    assert_eq!(l[1]["args"]["length"], 2048);
    assert_eq!(
        l[1]["args"]["fd"], l[0]["ret"],
        "the truncation uses the descriptor the open returned"
    );
    assert_eq!(
        l[1]["args"]["path_named_to_the_kernel"], false,
        "ftruncate passes no path; the report says so"
    );
    assert_eq!(l[1]["errno"], Value::Null);
    assert_eq!(code(&out), 0);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 2048);

    // A missing file fails at the open, so no truncation is reported at all.
    let out = run(&["ftruncate", &dir.at("absent"), "10"]);
    let l = lines(&out);
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!(l[0]["op"], "openat");
    assert_eq!(l[0]["errno"], "ENOENT");
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
}

// --------------------------------------------------------------- processes

#[test]
fn exec_forks_execs_and_reports_both_the_exec_and_the_child_status() {
    let fixture = fixture().display().to_string();
    let out = run(&["exec", "--", &fixture, "exit", "7"]);
    let l = lines(&out);
    assert_eq!(l.len(), 3, "exec, the child's own line, and wait: {l:?}");

    let exec = l.iter().find(|v| v["op"] == "execve").unwrap();
    assert_eq!(exec["ret"], 0);
    assert_eq!(exec["errno"], Value::Null);

    let wait = l.iter().find(|v| v["op"] == "wait").unwrap();
    assert_eq!(wait["args"]["exited"], true);
    assert_eq!(wait["args"]["code"], 7);
    assert_eq!(wait["args"]["signal"], Value::Null);
    assert_eq!(code(&out), 0, "the exec itself succeeded");
}

#[test]
fn a_missing_executable_is_reported_as_enoent_not_as_a_crash() {
    let out = run(&["exec", "--expect", "ENOENT", "--", "/nonexistent/program"]);
    let l = lines(&out);
    let exec = l.iter().find(|v| v["op"] == "execve").unwrap();
    assert_eq!(exec["ret"], -1);
    assert_eq!(exec["errno"], "ENOENT");
    assert_eq!(code(&out), 0);

    let out = run(&["exec", "--", "/nonexistent/program"]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
}

#[test]
fn exec_replace_leaves_no_line_on_success_and_one_on_failure() {
    let fixture = fixture().display().to_string();
    let out = run(&["exec-replace", "--", &fixture, "exit", "5"]);
    let l = lines(&out);
    assert_eq!(l.len(), 1, "only the replacing image reports: {l:?}");
    assert_eq!(l[0]["op"], "exit");
    assert_eq!(
        code(&out),
        5,
        "the new image's exit status is the process's"
    );

    let out = run(&["exec-replace", "--expect", "ENOENT", "--", "/nope"]);
    assert_eq!(only(&out)["errno"], "ENOENT");
    assert_eq!(code(&out), 0);
}

#[test]
fn execveat_works_on_linux_and_reports_unsupported_elsewhere() {
    let fixture = fixture().display().to_string();
    let out = run(&["exec", "--via", "execveat", "--", &fixture, "exit", "0"]);
    let l = lines(&out);
    let exec = l.iter().find(|v| v["op"] == "execveat").unwrap();
    if cfg!(target_os = "linux") {
        assert_eq!(exec["ret"], 0, "{exec}");
        assert_eq!(code(&out), 0);
    } else {
        assert!(exec["args"]["unsupported"].is_string(), "{exec}");
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        assert_eq!(l.len(), 1, "nothing was forked: {l:?}");
    }
}

#[test]
fn fork_storm_forks_and_reaps_exactly_what_it_reports() {
    let out = run(&["fork-storm", "24"]);
    let line = only(&out);
    assert_eq!(line["args"]["requested"], 24);
    assert_eq!(line["args"]["forked"], 24);
    assert_eq!(line["args"]["reaped"], 24);
    assert_eq!(code(&out), 0);
}

#[test]
fn a_background_descendant_outlives_the_parent_and_the_parent_exits_zero() {
    // The descendant inherits stdout, so reading that pipe to EOF would wait
    // for the descendant, not the parent. That is the point of X07, and it is
    // why this test reads exactly one line and then waits for the parent only.
    let mut child = Command::new(fixture())
        .args(["background", "300000"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let line = read_one_line(&mut stdout);
    let pid = line["args"]["pid"].as_i64().unwrap();
    assert!(pid > 0);
    assert_eq!(line["args"]["detached"], true);

    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0), "the parent exits without waiting");

    // The parent is reaped; the descendant is still alive. `kill(pid, 0)` only
    // probes, and the process is one this test's own tree created.
    // SAFETY: signal 0 performs no delivery, only an existence and permission check.
    let alive = unsafe { libc::kill(pid as libc::pid_t, 0) };
    assert_eq!(alive, 0, "the detached descendant should still exist");

    // Clean up only what this test spawned.
    // SAFETY: as above, with SIGKILL, on a pid this test created.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
}

/// Read stdout until the first complete JSON line. A harness synchronises on
/// this line rather than on a timer.
fn read_one_line(stdout: &mut impl std::io::Read) -> Value {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 256];
        let n = stdout.read(&mut chunk).expect("stdout must be readable");
        assert!(n > 0, "the fixture closed stdout without reporting");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            return serde_json::from_slice(&buf[..i]).expect("the report line must be JSON");
        }
    }
}

#[test]
fn a_thread_starts_and_joins() {
    let out = run(&["thread"]);
    let line = only(&out);
    assert_eq!(line["args"]["joined"], true);
    assert_eq!(code(&out), 0);
    if cfg!(target_os = "linux") {
        assert!(
            line["args"]["tid"].as_i64().unwrap() > 0,
            "a real kernel thread id: {line}"
        );
    }
}

#[test]
fn exit_and_raise_produce_the_status_they_report() {
    let out = run(&["exit", "42"]);
    assert_eq!(only(&out)["args"]["code"], 42);
    assert_eq!(code(&out), 42);

    let out = run(&["raise", "TERM"]);
    let line = only(&out);
    assert_eq!(line["args"]["signal"], "TERM");
    assert_eq!(line["args"]["signum"], libc::SIGTERM);
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        out.status.signal(),
        Some(libc::SIGTERM),
        "the process must die of the signal it raised"
    );

    let out = run(&["raise", "NOTASIGNAL"]);
    assert_eq!(code(&out), EXIT_USAGE);
}

// ----------------------------------------------------------- introspection

#[test]
fn echo_args_reproduces_hostile_arguments_byte_for_byte() {
    let hostile = [
        "plain",
        "with space",
        "quote'and\"double",
        "new\nline",
        "$(id) `id` ${HOME} | ; & > <",
        "\u{00e9}\u{1F600}",
        "-looks-like-a-flag",
    ];
    let mut args: Vec<&str> = vec!["echo-args", "--"];
    args.extend_from_slice(&hostile);
    let out = run(&args);
    let line = only(&out);
    let got = line["args"]["argv"].as_array().unwrap();
    assert_eq!(got.len(), hostile.len());
    for (want, item) in hostile.iter().zip(got) {
        let bytes: Vec<u8> = item["bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| u8::try_from(b.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(bytes, want.as_bytes(), "argument {want:?} was altered");
        assert_eq!(item["len"].as_u64().unwrap() as usize, want.len());
    }
    assert_eq!(code(&out), 0);
}

#[test]
fn the_byte_streams_are_exact_and_carry_no_report_line() {
    for (mode, take_stdout) in [("stdout-bytes", true), ("stderr-bytes", false)] {
        let n = 300_000usize;
        let out = run(&[mode, &n.to_string(), "--no-report"]);
        let stream = if take_stdout {
            &out.stdout
        } else {
            &out.stderr
        };
        let other = if take_stdout {
            &out.stderr
        } else {
            &out.stdout
        };
        assert_eq!(stream.len(), n, "{mode} wrote the wrong number of bytes");
        assert!(other.is_empty(), "{mode} leaked into the other stream");
        for (i, b) in stream.iter().enumerate() {
            assert_eq!(*b, (i % 256) as u8, "byte {i} of {mode}");
        }
        assert_eq!(code(&out), 0);
    }
}

#[test]
fn the_report_can_be_moved_off_stdout_by_descriptor() {
    // `--report-fd 2` keeps stdout byte-exact while the report still exists.
    let out = run(&["stdout-bytes", "1024", "--report-fd", "2"]);
    assert_eq!(out.stdout.len(), 1024);
    let line: Value = serde_json::from_slice(
        out.stderr
            .split(|b| *b == b'\n')
            .find(|l| !l.is_empty())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(line["op"], "stdout-bytes");
    assert_eq!(line["args"]["written"], 1024);
}

#[test]
fn env_reports_names_only_and_never_a_value() {
    let secret = "ouro-fixture-must-not-print-this-value";
    let out = Command::new(fixture())
        .arg("env")
        .env("OURO_FIXTURE_TEST_SECRET", secret)
        .output()
        .unwrap();
    let line = only(&out);
    let names: Vec<&str> = line["args"]["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(names.contains(&"OURO_FIXTURE_TEST_SECRET"));
    assert_eq!(line["args"]["values_reported"], false);
    let whole = String::from_utf8_lossy(&out.stdout);
    assert!(!whole.contains(secret), "a value leaked into the report");
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "names are sorted");
    assert_eq!(code(&out), 0);
}

#[test]
fn fds_reports_kinds_without_paths() {
    let out = run(&["fds"]);
    let line = only(&out);
    assert_eq!(line["args"]["paths_reported"], false);
    let fds = line["args"]["fds"].as_array().unwrap();
    let numbers: Vec<i64> = fds.iter().map(|f| f["fd"].as_i64().unwrap()).collect();
    for n in [0, 1, 2] {
        assert!(numbers.contains(&n), "stdio must be open: {numbers:?}");
    }
    for f in fds {
        let kind = f["kind"].as_str().unwrap();
        assert!(
            [
                "fifo",
                "character",
                "directory",
                "block",
                "regular",
                "symlink",
                "socket",
                "unknown",
                "unreadable"
            ]
            .contains(&kind),
            "unexpected kind {kind}"
        );
    }
    assert_eq!(code(&out), 0);
}

#[test]
fn status_reads_proc_on_linux_and_reports_unsupported_elsewhere() {
    let out = run(&["status"]);
    let line = only(&out);
    assert_eq!(line["op"], "status");
    if cfg!(target_os = "linux") {
        assert_eq!(code(&out), 0, "{line}");
        let fields = &line["args"]["fields"];
        for key in ["CapEff", "NoNewPrivs", "Seccomp", "NSpid"] {
            assert!(fields[key].is_string(), "{key} missing from {line}");
        }
    } else {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
        let reason = line["args"]["unsupported"].as_str().unwrap();
        assert!(reason.contains("Linux interface"), "{reason}");
    }
}

#[test]
fn write_mmap_writes_through_the_descriptor_and_the_mapping() {
    let dir = Dir::new();
    let path = dir.at("mapped");
    let out = run(&["write-mmap", &path]);
    let l = lines(&out);
    let ops: Vec<&str> = l.iter().map(|v| v["op"].as_str().unwrap()).collect();
    assert_eq!(
        ops,
        ["openat", "ftruncate", "write", "mmap", "msync", "munmap"],
        "the sequence must be visible so O04 can assert which of these the tracer ignores"
    );
    for op in ["write", "mmap", "msync", "munmap"] {
        let v = l.iter().find(|v| v["op"] == op).unwrap();
        assert_eq!(
            v["args"]["closed_set"], false,
            "{op} is not in the closed set"
        );
    }
    assert_eq!(code(&out), 0);
    let content = std::fs::read(&path).unwrap();
    assert_eq!(content.len(), 4096);
    assert!(content.starts_with(b"ouro-fixture:mmap\n"));
}

// ------------------------------------------------------------------ network

#[test]
fn connect_reports_a_real_result_and_refuses_a_name() {
    // Port 9 on the loopback interface is discard; nothing listens in a test
    // environment, so the connect must fail with a real errno.
    let out = run(&["connect", "127.0.0.1:9", "--expect", "ECONNREFUSED"]);
    let l = lines(&out);
    assert_eq!(l[0]["op"], "socket");
    assert!(l[0]["ret"].as_i64().unwrap() >= 0);
    assert_eq!(l[1]["op"], "connect");
    let errno = l[1]["errno"].as_str();
    assert!(
        errno == Some("ECONNREFUSED")
            || errno == Some("ETIMEDOUT")
            || errno == Some("EHOSTUNREACH"),
        "unexpected connect result: {}",
        l[1]
    );

    let out = run(&["connect", "example.invalid:80"]);
    assert_eq!(code(&out), EXIT_USAGE);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refuses names on purpose"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ------------------------------------------------------------------- script

#[test]
fn a_script_runs_every_step_in_one_process_and_reports_each() {
    let dir = Dir::new();
    let a = dir.at("s-a");
    let b = dir.at("s-b");
    let script = dir.at("script.json");
    let steps = serde_json::json!([
        ["open", a, "--create", "--write"],
        ["rename", a, b, "--via", "renameat"],
        ["unlink", b, "--via", "unlinkat"],
        ["open", b, "--expect", "ENOENT"],
    ]);
    std::fs::write(&script, steps.to_string()).unwrap();

    let out = run(&["script", &script]);
    let l = lines(&out);
    let ops: Vec<&str> = l.iter().map(|v| v["op"].as_str().unwrap()).collect();
    assert_eq!(ops, ["openat", "renameat", "unlinkat", "openat"]);
    assert_eq!(code(&out), 0);
    assert!(!Path::new(&b).exists());
}

#[test]
fn a_script_accepts_the_node_and_truncation_modes_too() {
    let dir = Dir::new();
    let file = dir.at("s-file");
    let node = dir.at("s-node");
    let script = dir.at("nodes.json");
    let steps = serde_json::json!([
        ["open", file.clone(), "--create", "--write"],
        ["truncate", file.clone(), "1024"],
        ["ftruncate", file.clone(), "512"],
        ["mknod", node.clone(), "--via", "mknodat"],
    ]);
    std::fs::write(&script, steps.to_string()).unwrap();

    let out = run(&["script", &script]);
    let ops: Vec<&str> = lines(&out)
        .iter()
        .map(|v| v["op"].as_str().unwrap().to_string())
        .collect::<Vec<String>>()
        .leak()
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        ops,
        ["openat", "truncate", "openat", "ftruncate", "mknodat"],
        "every step runs in the one process, in order"
    );
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 512);
    if cfg!(target_os = "linux") {
        assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
        use std::os::unix::fs::FileTypeExt;
        assert!(
            std::fs::symlink_metadata(&node)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    } else {
        assert_eq!(code(&out), EXIT_EXPECTATION_FAILED, "mknodat is Linux only");
    }
}

#[test]
fn one_failed_step_fails_the_whole_script_without_stopping_it() {
    let dir = Dir::new();
    let script = dir.at("script.json");
    let steps = serde_json::json!([
        ["open", dir.at("missing"), "--expect", "EACCES"],
        ["mkdir", dir.at("made")],
    ]);
    std::fs::write(&script, steps.to_string()).unwrap();

    let out = run(&["script", &script]);
    assert_eq!(lines(&out).len(), 2, "later steps still run");
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
    assert!(dir.path().join("made").is_dir());
}

#[test]
fn a_malformed_script_is_a_usage_error() {
    let dir = Dir::new();
    let script = dir.at("bad.json");
    std::fs::write(&script, r#"{"not":"an array"}"#).unwrap();
    let out = run(&["script", &script]);
    assert_eq!(code(&out), EXIT_USAGE);

    std::fs::write(&script, r#"[["nosuchmode"]]"#).unwrap();
    assert_eq!(code(&run(&["script", &script])), EXIT_USAGE);

    assert_eq!(code(&run(&["script", &dir.at("absent.json")])), EXIT_USAGE);
}

// --------------------------------------------------------------- lifetimes

#[test]
fn sleep_spin_and_ignore_term_report_before_they_block() {
    // The report line is what a harness waits on; it must precede the wait.
    let started = std::time::Instant::now();
    let mut child = Command::new(fixture())
        .args(["ignore-term", "30000"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let line = read_one_line(&mut stdout);
    assert_eq!(line["op"], "ignore-term");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "the report arrived only after the sleep"
    );

    // SIGTERM is ignored; only SIGKILL ends it. This test kills only its own child.
    let pid = child.id() as libc::pid_t;
    // SAFETY: a signal to a process this test spawned.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    std::thread::yield_now();
    assert!(
        child.try_wait().unwrap().is_none(),
        "SIGTERM must not end an ignore-term fixture"
    );
    child.kill().unwrap();
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));

    let out = run(&["sleep", "10"]);
    assert_eq!(only(&out)["op"], "sleep");
    assert_eq!(code(&out), 0);

    let out = run(&["spin", "10"]);
    assert_eq!(only(&out)["op"], "spin");
    assert_eq!(code(&out), 0);
}
