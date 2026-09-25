//! J5-E: the performance workloads and the per-launch launcher of
//! `cargo xtask perf` (jail-v1 §5), run as real processes.
//!
//! `fileops` and `spawn-tree` are the fixed file-operation and the
//! descendant-heavy workloads; `spawn-tree 0` is the no-op. Each prints a
//! `perf-start` line carrying its own `CLOCK_MONOTONIC` reading first and one
//! summary line last. `perf-launch` runs outside the jail: it reads the same
//! clock just before `fork`, waits for the launched command with `wait4`,
//! samples what it can while the command runs and harvests the attempt
//! directory a jailed launch leaves. Every assertion here is on a fact the
//! harness consumes; a line that claims work was done is checked against the
//! filesystem or the process table.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const EXIT_EXPECTATION_FAILED: i32 = 3;
const EXIT_USAGE: i32 = 2;

fn fixture() -> PathBuf {
    ouro_fixture::harness::fixture_path()
}

fn run<S: AsRef<OsStr>>(args: &[S]) -> Output {
    Command::new(fixture())
        .args(args.iter().map(AsRef::as_ref))
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

fn code(out: &Output) -> i32 {
    out.status
        .code()
        .expect("the fixture must not die on a signal")
}

fn tmp() -> ouro_fixture::harness::TempDir {
    ouro_fixture::harness::TempDir::new("ouro-fixture-perf").unwrap()
}

fn os(p: &Path) -> OsString {
    p.as_os_str().to_os_string()
}

/// The two lines every workload prints: `perf-start` first, the summary last.
fn start_and_summary(out: &Output, mode: &str) -> (Value, Value) {
    let l = lines(out);
    assert_eq!(l.len(), 2, "a workload prints exactly two lines: {l:?}");
    assert_eq!(l[0]["op"], "perf-start", "{l:?}");
    assert_eq!(l[0]["args"]["mode"], mode, "{l:?}");
    assert_eq!(l[1]["op"], mode, "{l:?}");
    (l[0].clone(), l[1].clone())
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v["args"][key]
        .as_u64()
        .unwrap_or_else(|| panic!("`{key}` is not an unsigned integer in {v}"))
}

// ------------------------------------------------------------------ fileops

#[test]
fn fileops_performs_every_round_and_leaves_nothing_behind() {
    let dir = tmp();
    let out = run(&[OsString::from("fileops"), "50".into(), os(dir.path())]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let (start, summary) = start_and_summary(&out, "fileops");
    assert_eq!(u64_at(&start, "pid"), u64::from(out_pid(&start)));
    for key in ["rounds", "created", "renamed", "unlinked"] {
        assert_eq!(u64_at(&summary, key), 50, "{key}: {summary}");
    }
    assert_eq!(summary["args"]["ok"], true, "{summary}");
    assert_eq!(summary["args"]["first_error"], Value::Null, "{summary}");
    assert_eq!(summary["ret"], 50);
    // The summary repeats the start stamp, so a reader needs one line only,
    // and the work happened between the two stamps.
    assert_eq!(
        u64_at(&summary, "start_ns"),
        u64_at(&start, "monotonic_ns"),
        "{summary}"
    );
    assert!(u64_at(&summary, "end_ns") > u64_at(&summary, "start_ns"));
    assert!(u64_at(&summary, "maxrss_kib") > 0, "{summary}");
    // Every round unlinks what it created: the directory is empty again.
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(left.is_empty(), "fileops left {left:?} behind");
    // The syscalls are the ones J0 measured, named in the line.
    let expect_rename = if ouro_fixture::raw::has_legacy_syscalls() {
        "rename"
    } else {
        "renameat"
    };
    assert_eq!(summary["args"]["rename_via"], expect_rename, "{summary}");
}

fn out_pid(start: &Value) -> u32 {
    u32::try_from(start["args"]["pid"].as_u64().unwrap()).unwrap()
}

#[test]
fn fileops_counts_a_failure_and_exits_3() {
    let dir = tmp();
    let missing = dir.path().join("absent");
    let out = run(&[OsString::from("fileops"), "4".into(), os(&missing)]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
    let (_, summary) = start_and_summary(&out, "fileops");
    assert_eq!(u64_at(&summary, "created"), 0, "{summary}");
    assert_eq!(summary["args"]["ok"], false);
    assert_eq!(summary["args"]["first_error"]["op"], "openat", "{summary}");
    assert_eq!(
        summary["args"]["first_error"]["errno"], "ENOENT",
        "{summary}"
    );
}

// --------------------------------------------------------------- spawn-tree

#[test]
fn spawn_tree_runs_every_child_to_completion() {
    let out = run(&["spawn-tree", "6", "--", "/usr/bin/true"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let (start, summary) = start_and_summary(&out, "spawn-tree");
    assert_eq!(u64_at(&summary, "count"), 6);
    assert_eq!(u64_at(&summary, "forked"), 6, "{summary}");
    assert_eq!(u64_at(&summary, "exited_zero"), 6, "{summary}");
    assert_eq!(u64_at(&summary, "failed"), 0, "{summary}");
    assert_eq!(summary["args"]["ok"], true);
    assert_eq!(summary["args"]["argv0"], "/usr/bin/true");
    assert_eq!(u64_at(&summary, "start_ns"), u64_at(&start, "monotonic_ns"));
    assert!(u64_at(&summary, "end_ns") > u64_at(&summary, "start_ns"));
    // The children were reaped, so their peak is on record.
    assert!(u64_at(&summary, "children_maxrss_kib") > 0, "{summary}");
}

#[test]
fn spawn_tree_counts_children_that_fail_or_cannot_exec() {
    let out = run(&["spawn-tree", "3", "--", "/usr/bin/false"]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
    let (_, summary) = start_and_summary(&out, "spawn-tree");
    assert_eq!(u64_at(&summary, "forked"), 3, "{summary}");
    assert_eq!(u64_at(&summary, "exited_zero"), 0, "{summary}");
    assert_eq!(u64_at(&summary, "failed"), 3, "{summary}");
    assert_eq!(summary["args"]["ok"], false);

    let out = run(&["spawn-tree", "2", "--", "/nonexistent/program"]);
    assert_eq!(code(&out), EXIT_EXPECTATION_FAILED);
    let (_, summary) = start_and_summary(&out, "spawn-tree");
    assert_eq!(u64_at(&summary, "failed"), 2, "{summary}");
}

#[test]
fn the_start_line_precedes_the_work() {
    // The children write to the same stdout: the start reading must come
    // before their output, and the summary after it.
    let out = run(&["spawn-tree", "2", "--", "/bin/echo", "child"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let order: Vec<&str> = text
        .lines()
        .map(|l| {
            if l.contains("\"perf-start\"") {
                "start"
            } else if l.contains("\"spawn-tree\"") {
                "summary"
            } else {
                l
            }
        })
        .collect();
    assert_eq!(order, ["start", "child", "child", "summary"], "{text}");
}

#[test]
fn spawn_tree_zero_is_the_no_op_workload() {
    let out = run(&["spawn-tree", "0"]);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stderr));
    let (_, summary) = start_and_summary(&out, "spawn-tree");
    assert_eq!(u64_at(&summary, "forked"), 0);
    assert_eq!(summary["args"]["ok"], true);
    // The default child is named even when none runs.
    assert_eq!(summary["args"]["argv0"], "/usr/bin/true");
}

#[test]
fn the_workloads_refuse_an_interior_nul_before_any_work() {
    // A process argv cannot carry a NUL; a script step can.
    let dir = tmp();
    let script = dir.path().join("steps.json");
    std::fs::write(&script, r#"[["fileops", "1", "/tmp/a\u0000b"]]"#).unwrap();
    let out = run(&[OsString::from("script"), os(&script)]);
    assert_eq!(
        code(&out),
        EXIT_USAGE,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(lines(&out).is_empty(), "no start line before a usage error");
    assert!(String::from_utf8_lossy(&out.stderr).contains("interior_nul"));
}

// -------------------------------------------------------------- perf-launch

struct Launch {
    out: Output,
    result: Value,
}

fn perf_launch(extra: &[OsString], argv: &[OsString]) -> Launch {
    let dir = tmp();
    let result_path = dir.path().join("result.json");
    let mut args: Vec<OsString> = vec![
        "--no-report".into(),
        "perf-launch".into(),
        "--out".into(),
        os(&result_path),
    ];
    args.extend(extra.iter().cloned());
    args.push("--".into());
    args.extend(argv.iter().cloned());
    let out = run(&args);
    assert_eq!(
        code(&out),
        0,
        "perf-launch measures and exits 0 whatever the command did: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&result_path).expect("perf-launch writes its result");
    let result: Value = serde_json::from_slice(&bytes).expect("the result is one JSON object");
    Launch { out, result }
}

fn n(v: &Value, path: &[&str]) -> u64 {
    let mut cur = v;
    for key in path {
        cur = &cur[*key];
    }
    cur.as_u64()
        .unwrap_or_else(|| panic!("{path:?} is not an unsigned integer in {v:#}"))
}

#[test]
fn perf_launch_brackets_the_command_on_the_clock_the_workload_reads() {
    let launch = perf_launch(
        &[],
        &[
            os(&fixture()),
            "spawn-tree".into(),
            "3".into(),
            "--".into(),
            "/usr/bin/true".into(),
        ],
    );
    let r = &launch.result;
    assert_eq!(r["schema"], "ouro.fixture.perf-launch/1", "{r:#}");
    assert_eq!(r["exec_errno"], Value::Null, "{r:#}");
    assert_eq!(r["timed_out"], false);
    assert_eq!(r["status"]["exited"], true, "{r:#}");
    assert_eq!(r["status"]["code"], 0, "{r:#}");
    assert!(n(r, &["rusage", "maxrss_kib"]) > 0, "{r:#}");
    let (start, summary) = start_and_summary(&launch.out, "spawn-tree");
    // One clock: the launcher's reading before fork, the target's at entry
    // and at the end, the launcher's after the reap, in that order.
    let t0 = n(r, &["t0_ns"]);
    let t1 = n(r, &["t1_ns"]);
    let entry = u64_at(&start, "monotonic_ns");
    let end = u64_at(&summary, "end_ns");
    assert!(
        t0 < entry && entry < end && end < t1,
        "{t0} {entry} {end} {t1}"
    );
    assert_eq!(n(r, &["pid"]), u64::from(out_pid(&start)));
    // The launcher and the target report the same time namespace, which is
    // what makes the two readings comparable (null where there is no /proc).
    assert_eq!(r["timens"], start["args"]["timens"], "{r:#} {start}");
    if cfg!(target_os = "linux") {
        assert!(r["timens"].as_str().unwrap().starts_with("time:["), "{r:#}");
    } else {
        assert_eq!(r["timens"], Value::Null);
    }
    assert_eq!(r["attempts"], Value::Null, "no data directory was named");
    // How the exit was seen, and the cgroup a direct target inherits.
    if cfg!(target_os = "linux") {
        assert_eq!(r["waited_via"], "pidfd", "{r:#}");
        assert!(r["cgroup"].as_str().unwrap().starts_with('/'), "{r:#}");
    } else {
        assert_eq!(r["waited_via"], "wnohang", "{r:#}");
        assert_eq!(r["cgroup"], Value::Null, "{r:#}");
    }
}

#[test]
fn perf_launch_reads_the_clock_before_fork_and_again_after_exec() {
    let launch = perf_launch(&[], &[os(&fixture()), "spawn-tree".into(), "0".into()]);
    let r = &launch.result;
    let (start, _) = start_and_summary(&launch.out, "spawn-tree");
    let (t0, exec) = (n(r, &["t0_ns"]), n(r, &["exec_ns"]));
    // fork and exec take time, so the pre-fork reading is strictly earlier
    // than the one taken once the exec is confirmed, which precedes the
    // target's own entry reading.
    assert!(t0 < exec, "{t0} {exec}");
    assert!(exec <= u64_at(&start, "monotonic_ns"), "{r:#} {start}");
}

/// Linux only: sampling reads /proc. On macOS the test does not exist rather
/// than skipping, because a skip is a failure under OURO_CONFORMANCE=1 and
/// the macOS lane runs in conformance mode.
#[cfg(target_os = "linux")]
#[test]
fn perf_launch_samples_the_launched_process_not_itself() {
    // A launched process far larger than the launcher: its own high-water
    // mark is what is sampled.
    let python = Path::new("/usr/bin/python3");
    if !python.exists() {
        ouro_fixture::harness::skip_or_fail("needs /usr/bin/python3");
        return;
    }
    let launch = perf_launch(
        &["--sample-ms".into(), "2".into()],
        &[
            os(python),
            "-c".into(),
            "import time; x = bytearray(96 << 20); time.sleep(0.3)".into(),
        ],
    );
    let s = &launch.result["sampling"];
    assert!(n(s, &["hwm_kib"]) > 90 * 1024, "{:#}", launch.result);
    assert!(n(&launch.result, &["rusage", "maxrss_kib"]) > 90 * 1024);
}

#[test]
fn perf_launch_reports_an_exec_failure_as_data() {
    let launch = perf_launch(&[], &["/nonexistent/program".into()]);
    let r = &launch.result;
    assert_eq!(r["exec_errno"], "ENOENT", "{r:#}");
    assert_eq!(r["status"]["code"], 127, "{r:#}");
}

#[test]
fn perf_launch_samples_the_launched_process_while_it_runs() {
    let launch = perf_launch(
        &["--sample-ms".into(), "2".into()],
        &[os(&fixture()), "sleep".into(), "150".into()],
    );
    let r = &launch.result;
    let s = &r["sampling"];
    assert_eq!(s["interval_ms"], 2);
    assert!(n(s, &["samples"]) >= 5, "{r:#}");
    if cfg!(target_os = "linux") {
        // VmHWM of the launched process, sampled after its exec.
        assert!(n(s, &["hwm_kib"]) > 0, "{r:#}");
    } else {
        assert_eq!(s["hwm_kib"], Value::Null, "{r:#}");
    }
    assert_eq!(s["leaf_path"], Value::Null);
}

#[test]
fn perf_launch_with_sampling_off_takes_no_sample() {
    let launch = perf_launch(
        &["--sample-ms".into(), "0".into()],
        &[os(&fixture()), "sleep".into(), "20".into()],
    );
    assert_eq!(
        launch.result["sampling"]["samples"], 0,
        "{:#}",
        launch.result
    );
}

/// A receipt (the checked-in tool example) whose leaf path is `leaf`.
fn receipt_with_leaf(leaf: &Path) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1/examples");
    let mut receipt: Value =
        serde_json::from_slice(&std::fs::read(root.join("receipt-tool.json")).unwrap()).unwrap();
    receipt["lifetime"]["native"]["details"]["execution_cgroup"] =
        json!({ "path": leaf.to_str().unwrap() });
    receipt
}

/// A trace whose last frame is the note of `receipt`, as the product ends one.
fn trace_ending_on(receipt: &[u8]) -> Vec<u8> {
    let (phase, digest) = ouro_fixture::harness::receipt_note_of(receipt).unwrap();
    let event = json!({
        "schema": "ouro.event/1", "attempt_id": "att_x", "source": "audit",
        "source_seq": 1, "operation": "fs.write", "stage": "result",
    });
    let note = json!({
        "schema": "ouro.event/1", "attempt_id": "att_x", "source": "wrapper",
        "source_seq": 1, "operation": "jail.receipt", "stage": "result",
        "fields": { "phase": phase, "receipt_digest": digest },
    });
    let exit = json!({
        "schema": "ouro.event/1", "attempt_id": "att_x", "source": "wrapper",
        "source_seq": 0, "operation": "note", "stage": "result",
        "fields": { "kind": "coverage_gap" },
    });
    let mut bytes = Vec::new();
    for frame in [&event, &event, &exit, &note] {
        bytes.extend_from_slice(serde_json::to_string(frame).unwrap().as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

#[test]
fn perf_launch_finds_the_leaf_from_the_receipt_and_harvests_the_attempt() {
    let state = tmp();
    let leaf = state.path().join("leaf");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::write(leaf.join("memory.peak"), "123456\n").unwrap();
    let attempt = state.path().join("data/attempts/att_x");
    std::fs::create_dir_all(&attempt).unwrap();
    let receipt = serde_json::to_vec_pretty(&receipt_with_leaf(&leaf)).unwrap();
    std::fs::write(attempt.join("jail.json"), &receipt).unwrap();
    std::fs::write(attempt.join("trace.ndjson"), trace_ending_on(&receipt)).unwrap();

    let launch = perf_launch(
        &[
            "--sample-ms".into(),
            "2".into(),
            "--data-dir".into(),
            os(&state.path().join("data")),
        ],
        &[os(&fixture()), "sleep".into(), "100".into()],
    );
    let r = &launch.result;
    let s = &r["sampling"];
    assert_eq!(s["leaf_path"], leaf.to_str().unwrap(), "{r:#}");
    assert_eq!(s["leaf_peak_bytes"], 123_456, "{r:#}");
    assert!(n(s, &["leaf_samples"]) > 0, "{r:#}");

    let attempts = r["attempts"]
        .as_array()
        .expect("the attempts are harvested");
    assert_eq!(attempts.len(), 1, "{r:#}");
    let a = &attempts[0];
    assert_eq!(a["id"], "att_x");
    assert_eq!(a["receipt"], true);
    let t = &a["trace"];
    assert_eq!(t["state"], "complete", "{r:#}");
    assert_eq!(t["frames"], 4);
    assert_eq!(
        t["guard"],
        Value::Null,
        "the trace ends on its receipt's note: {r:#}"
    );
    assert_eq!(t["by_source"]["audit"], 2);
    assert_eq!(t["by_source"]["wrapper"], 2);
    assert_eq!(t["by_operation"]["fs.write"], 2);
    assert_eq!(t["notes"]["coverage_gap"], 1);
}

#[test]
fn perf_launch_says_when_a_trace_does_not_end_on_its_receipt() {
    let state = tmp();
    let attempt = state.path().join("data/attempts/att_x");
    std::fs::create_dir_all(&attempt).unwrap();
    let receipt =
        serde_json::to_vec_pretty(&receipt_with_leaf(&state.path().join("gone"))).unwrap();
    let mut trace = trace_ending_on(&receipt);
    // Drop the final note: a prefix that still ends on a frame boundary.
    trace.truncate(
        trace[..trace.len() - 1]
            .iter()
            .rposition(|b| *b == b'\n')
            .unwrap()
            + 1,
    );
    std::fs::write(attempt.join("jail.json"), &receipt).unwrap();
    std::fs::write(attempt.join("trace.ndjson"), &trace).unwrap();

    let launch = perf_launch(
        &["--data-dir".into(), os(&state.path().join("data"))],
        &["/usr/bin/true".into()],
    );
    let t = &launch.result["attempts"][0]["trace"];
    assert_eq!(t["state"], "complete", "{t:#}");
    assert!(
        t["guard"]
            .as_str()
            .is_some_and(|g| g.contains("jail.receipt")),
        "a missing final note must be named: {t:#}"
    );
    // The leaf that no longer exists is not a peak of zero.
    assert_eq!(launch.result["sampling"]["leaf_peak_bytes"], Value::Null);
}
