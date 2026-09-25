//! J5-C, R01 and O01 live: every record the real jail writes, under every
//! profile, passes the frozen contract, and the live output carries each kind
//! of event the examples freeze.
//!
//! jail-v1 §17 "Before J5" asks to "finish the executable schema constraints,
//! verify all source-specific event semantics and freeze the wire versions".
//! The frozen schemas and `ouro_jail::records::semantic` state those rules and
//! the examples show one instance of each kind of record. This file runs the
//! real `ouro-jail` on the reference host, releases each attempt through the
//! managed gate (§8.2) like an owner would, and holds every receipt, the trace
//! and the control transcript to the whole contract
//! (`common::assert_run_records`: schemas, receipt rules, `source_seq` per
//! source, receipt notes in lifecycle order, the trace ending on the final
//! receipt's note, control messages in order). Each run is built to produce a
//! known set of event kinds, and the test asserts the trace carries them, so a
//! kind the product writes in a shape the schema rejects cannot hide behind a
//! run that never produced it.
//!
//! The note kinds a normal run does not write are held to the same contract
//! where they are produced: `coverage_gap` in `j4_loss_linux.rs` (whose
//! helper runs these checks since J5-C), `lifetime` in the R06 tests, `limit`
//! only on a host without a delegated pids controller, `helper` only when an
//! `agent` helper dies.
//!
//! Every process these tests start is their own jail's; nothing on the host
//! is inspected or changed.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use ouro_fixture::harness::{self, HttpServer, Jail, Release, Run, TraceConsumer};
use serde_json::Value;

mod common;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Profile {
    Tool,
    Build,
    Agent,
    None,
}

impl Profile {
    fn name(self) -> &'static str {
        match self {
            Profile::Tool => "tool",
            Profile::Build => "build",
            Profile::Agent => "agent",
            Profile::None => "none",
        }
    }

    /// Whether this host can run the profile; a skip is a failure under
    /// `OURO_CONFORMANCE=1`.
    fn available(self) -> bool {
        if !common::live() {
            return false;
        }
        if self != Profile::None {
            return true;
        }
        let leaf = ouro_jail::platform::linux::probe::run_one(
            "cgroup_delegated_leaf",
            &harness::jail_path(),
            Path::new("bwrap"),
        );
        if leaf.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
            harness::skip_or_fail(&format!(
                "the none profile needs a delegated user scope: {}",
                leaf.evidence
            ));
            return false;
        }
        true
    }
}

/// One gated `ouro-jail run --profile <profile>` over a private workspace
/// holding the fixture, with trace, control, gate and `--receipt` plumbed.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
    profile: Profile,
}

fn case(profile: Profile, extra: &[&str]) -> Case {
    case_with(profile, "strict", extra)
}

fn case_with(profile: Profile, evidence: &str, extra: &[&str]) -> Case {
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut jail = jail
        .arg("run")
        .arg("--profile")
        .arg(profile.name())
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace);
    if profile == Profile::Build {
        // `build` requires an explicit memory ceiling (§6.4) and exposes no
        // workspace, so the fixture is a declared read-only input.
        jail = jail
            .args(["--limit", "mem=512MiB"])
            .arg("--ro")
            .arg(&fixture);
    }
    for arg in extra {
        jail = jail.arg(arg);
    }
    Case {
        jail: jail.trace().control().gate().receipt(),
        workspace,
        fixture,
        profile,
    }
}

impl Case {
    /// Where the script's operations run: the workspace, or scratch under
    /// `build` (§3.1: a build reads declared inputs and writes scratch).
    fn base(&self) -> String {
        if self.profile == Profile::Build {
            "/tmp/j5c".to_owned()
        } else {
            self.workspace.to_str().unwrap().to_owned()
        }
    }

    fn fixture_s(&self) -> String {
        self.fixture.to_str().unwrap().to_owned()
    }

    /// Runs a fixture script of `steps` and releases the gate once the
    /// prepared receipt names the attempt and policy the owner reads, as a
    /// managed owner does (§8.2). `release` is the frame the owner sends.
    fn run(self, steps: &Value, release: &Release) -> Run {
        let script = self.workspace.join("j5c.json");
        std::fs::write(&script, serde_json::to_vec(steps).unwrap()).unwrap();
        let mut jail = self.jail;
        if self.profile == Profile::Build {
            jail = jail.arg("--ro").arg(&script);
        }
        let mut spawned = jail
            .target([
                self.fixture.clone().into_os_string(),
                OsString::from("script"),
                script.into_os_string(),
            ])
            .spawn()
            .expect("the jail starts");
        let control = spawned
            .owner()
            .await_prepared()
            .expect("a prepared message");
        // The prepared receipt is durable before `prepared` is sent (§8.2).
        let prepared = common::checked_receipt(
            spawned
                .receipt_value()
                .expect("the prepared receipt is on disk when `prepared` arrives"),
        );
        let attempt = control["attempt_id"]
            .as_str()
            .expect("an attempt")
            .to_owned();
        let digest = prepared["policy"]["digest"]
            .as_str()
            .expect("a policy digest")
            .to_owned();
        spawned
            .owner()
            .release(release, &attempt, &digest)
            .expect("the owner releases");
        spawned.wait().expect("the jail finishes")
    }
}

/// The kind of each trace event: source, operation, completion, and the
/// decision (proxy), `fields.kind` (wrapper note) or `attempted_operation`
/// (`fs.deny`), in the key form `portable_records.rs` gives the examples.
fn kinds(run: &Run) -> BTreeSet<String> {
    let text = |value: &Value| value.as_str().unwrap_or("-").to_owned();
    run.trace_events()
        .iter()
        .map(|event| {
            let detail = match event["source"].as_str() {
                Some("proxy") => text(&event["decision"]),
                Some("wrapper") if event["operation"] == "note" => text(&event["fields"]["kind"]),
                Some("audit") if event["operation"] == "fs.deny" => {
                    text(&event["fields"]["attempted_operation"])
                }
                _ => "-".to_owned(),
            };
            format!(
                "{} {} {} {}",
                text(&event["source"]),
                text(&event["operation"]),
                text(&event["outcome"]["completion"]),
                detail
            )
        })
        .collect()
}

fn assert_kinds(run: &Run, profile: Profile, expected: &[&str]) {
    let found = kinds(run);
    for kind in expected {
        assert!(
            found.contains(*kind),
            "{profile:?}: the live trace has no `{kind}`; it has {found:#?}"
        );
    }
}

/// What a failed exit-code assertion needs: stderr, the last receipt's
/// outcome and errors, and the fixture's last lines.
fn explain(run: &Run) -> String {
    let last = run.receipts().last().cloned().unwrap_or(Value::Null);
    let stdout = run.stdout_text();
    let tail: Vec<&str> = stdout.lines().rev().take(4).collect();
    format!(
        "stderr {:?}; receipt phase {} outcome {} errors {}; fixture tail {tail:?}",
        run.stderr_text(),
        last["phase"],
        last["outcome"],
        last["errors"]
    )
}

fn control_kinds(run: &Run) -> Vec<String> {
    run.control_messages()
        .iter()
        .map(|message| message["kind"].as_str().unwrap_or("-").to_owned())
        .collect()
}

/// The closed-set operations every contained or `none` run makes: a create,
/// a write, a truncation, a rename, a removal, a directory, a DAC denial of a
/// write, a connect, a failed exec, and an exec whose process then exits.
fn steps(case: &Case) -> Vec<Value> {
    let base = case.base();
    let at = |name: &str| format!("{base}/{name}");
    let mut steps = Vec::new();
    if case.profile == Profile::Build {
        steps.push(serde_json::json!(["mkdir", base]));
    }
    steps.extend([
        serde_json::json!(["open", at("created.txt"), "--create", "--write"]),
        serde_json::json!(["open", at("created.txt"), "--write"]),
        serde_json::json!(["truncate", at("created.txt"), "0"]),
        serde_json::json!(["rename", at("created.txt"), at("renamed.txt")]),
        serde_json::json!(["mkdir", at("dir")]),
        serde_json::json!(["symlink", "renamed.txt", at("link")]),
        serde_json::json!(["unlink", at("link")]),
        serde_json::json!([
            "open",
            at("readonly.txt"),
            "--create",
            "--write",
            "--mode",
            "400"
        ]),
        serde_json::json!(["open", at("readonly.txt"), "--write", "--expect", "EACCES"]),
        serde_json::json!(["connect", "127.0.0.1:1", "--expect", "any"]),
        serde_json::json!([
            "exec",
            "--via",
            "execve",
            "--expect",
            "ENOENT",
            "--",
            "/nonexistent-ouro-j5c"
        ]),
        serde_json::json!([
            "exec",
            "--via",
            "execve",
            "--",
            case.fixture_s(),
            "exit",
            "0"
        ]),
    ]);
    steps
}

/// What every observed run above writes, whatever the profile.
const OBSERVED_KINDS: &[&str] = &[
    "audit fs.create syscall_return -",
    "audit fs.write syscall_return -",
    "audit fs.rename syscall_return -",
    "audit fs.unlink syscall_return -",
    "audit fs.deny syscall_return fs.write",
    "audit net.connect syscall_return -",
    "audit proc.exec syscall_return -",
    "audit proc.exec exec_transition -",
    "audit proc.exit process_exit -",
    "wrapper note wrapper lifecycle",
    "wrapper jail.receipt wrapper -",
];

fn observed_profile(profile: Profile) {
    if !profile.available() {
        return;
    }
    let c = case(profile, &[]);
    let steps = Value::from(steps(&c));
    let run = c.run(&steps, &Release::Valid);
    assert_eq!(
        run.code(),
        Some(0),
        "{profile:?}: the fixture's expectations held: {}",
        explain(&run)
    );
    common::assert_run_records(&run);
    assert_kinds(&run, profile, OBSERVED_KINDS);
    assert_eq!(
        control_kinds(&run),
        ["prepared", "exec_confirmed", "settled"],
        "{profile:?}"
    );
}

#[test]
fn j5_tool_records_pass_the_frozen_contract() {
    observed_profile(Profile::Tool);
}

#[test]
fn j5_build_records_pass_the_frozen_contract() {
    observed_profile(Profile::Build);
}

#[test]
fn j5_none_records_pass_the_frozen_contract() {
    observed_profile(Profile::None);
}

/// `agent` adds the proxy source (an allowed and a denied request, §10) and
/// the mediator's audit results: a connect to a host Unix socket in the
/// workspace, refused as an `fs.deny` of `net.connect` (§11.2, §11.4).
#[test]
fn j5_agent_records_pass_the_frozen_contract() {
    if !Profile::Agent.available() {
        return;
    }
    let allowed = HttpServer::start(b"allowed".to_vec()).expect("an allowed origin");
    let refused = HttpServer::start(b"never".to_vec()).expect("a refused origin");
    let (a, r) = (allowed.addr().port(), refused.addr().port());
    let allow = format!("127.0.0.1:{a}");
    let c = case(Profile::Agent, &["--allow-host", &allow]);
    let host_socket = c.workspace.join("host.sock");
    let listener = std::os::unix::net::UnixListener::bind(&host_socket).expect("a host socket");
    let mut steps = steps(&c);
    steps.extend([
        serde_json::json!(["http-get", format!("http://127.0.0.1:{a}/allowed")]),
        serde_json::json!([
            "http-get",
            format!("http://127.0.0.1:{r}/refused"),
            "--expect",
            "any"
        ]),
        serde_json::json!([
            "unix-connect",
            host_socket.to_str().unwrap(),
            "--expect",
            "EACCES"
        ]),
    ]);
    let run = c.run(&Value::from(steps), &Release::Valid);
    drop(listener);
    assert_eq!(
        run.code(),
        Some(0),
        "the fixture's expectations held: {}",
        explain(&run)
    );
    assert_eq!(refused.stop().len(), 0, "the refused origin saw nothing");
    let _ = allowed.stop();
    common::assert_run_records(&run);
    assert_kinds(&run, Profile::Agent, OBSERVED_KINDS);
    assert_kinds(
        &run,
        Profile::Agent,
        &[
            "proxy net.connect proxy_close allow",
            "proxy net.connect proxy_close deny",
            "audit fs.deny syscall_return net.connect",
        ],
    );
    assert_eq!(
        control_kinds(&run),
        ["prepared", "exec_confirmed", "settled"]
    );
}

/// A gate the owner answers with the wrong policy digest refuses (§8.2): the
/// refused receipt, the trace ending on its note and the transcript
/// `prepared, refused` pass the same contract, and the target never ran.
#[test]
fn j5_a_refused_release_writes_records_that_pass_the_frozen_contract() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, &[]);
    let marker = format!("{}/ran.txt", c.base());
    let steps = serde_json::json!([["open", marker, "--create", "--write"]]);
    let run = c.run(
        &steps,
        &Release::WrongDigest(format!("sha256:{}", "0".repeat(64))),
    );
    assert_eq!(
        run.code(),
        Some(125),
        "a gate refusal: {}",
        run.stderr_text()
    );
    assert!(!Path::new(&marker).exists(), "the target never ran");
    common::assert_run_records(&run);
    assert_eq!(control_kinds(&run), ["prepared", "refused"]);
    let refused = run.receipt_phase("refused").expect("a refused receipt");
    assert_eq!(refused["outcome"]["error"]["code"], "gate_invalid");
    assert!(
        kinds(&run).iter().all(|kind| !kind.starts_with("audit ")),
        "nothing ran, so nothing was observed: {:#?}",
        kinds(&run)
    );
}

/// `--observe off` (O05): no audit source at all, and what the wrapper and
/// the receipt say still passes the contract. The fixture ends within
/// milliseconds, so without an observer its exec is sometimes confirmed and
/// sometimes not (measured on the reference host: unconfirmed in each of 8
/// runs after the other tests of this file, confirmed in the one run alone);
/// both are valid records.
#[test]
fn j5_observation_off_records_pass_the_frozen_contract() {
    if !Profile::Tool.available() {
        return;
    }
    let c = case(Profile::Tool, &["--observe", "off"]);
    let steps = Value::from(steps(&c));
    let run = c.run(&steps, &Release::Valid);
    common::assert_run_records(&run);
    // Without an observer a target that ends quickly can end before its exec
    // is confirmed: the outcome is then `unknown` and the run exits 1 (§6.4, a
    // post-launch tool failure), which the records must say consistently.
    let settled = run.receipt_phase("settled").expect("a settled receipt");
    match settled["outcome"]["kind"].as_str() {
        Some("exited") => assert_eq!(run.code(), Some(0), "{}", explain(&run)),
        Some("unknown") => assert_eq!(run.code(), Some(1), "{}", explain(&run)),
        other => panic!("an unexpected outcome {other:?}: {}", explain(&run)),
    }
    let found = kinds(&run);
    assert!(
        found.iter().all(|kind| !kind.starts_with("audit ")),
        "observation off emits no audit source: {found:#?}"
    );
    assert_kinds(
        &run,
        Profile::Tool,
        &[
            "wrapper note wrapper lifecycle",
            "wrapper jail.receipt wrapper -",
        ],
    );
}

/// J5-C review item 15, live: a real trace transport loss. The consumer reads
/// at most a pipeful at a time and pauses past the one-second no-progress
/// deadline (§13.3), so the stream loses frames; best-effort lets the target
/// finish, and the consumer comes back for the reserve notes. The loss note names the classes
/// this `tool` attempt covers (no `proxy.net`), and the settled receipt
/// records the same loss from the same start as a wrapper loss: the whole
/// contract, `trace_loss_recorded` included, holds on the live records.
#[test]
fn j5_a_trace_loss_note_and_its_receipt_agree() {
    if !Profile::Tool.available() {
        return;
    }
    let mut c = case_with(Profile::Tool, "best-effort", &[]);
    let base = c.base();
    // About 80 KB of results: more than the 64 KiB pipe, so frames wait in
    // the queue while the consumer pauses past the deadline; few enough that
    // its next read takes the rest, loss note included, long before the
    // target's end, so the terminal drain finds nothing queued and the final
    // receipt note completes the stream.
    let mut steps: Vec<Value> = (0..150)
        .map(|index| serde_json::json!(["open", format!("{base}/f{index}"), "--create", "--write"]))
        .collect();
    steps.push(serde_json::json!(["sleep", "3000"]));
    c.jail = c.jail.trace_consumer(TraceConsumer::Slow {
        chunk: 64 * 1024,
        pause: std::time::Duration::from_millis(1500),
    });
    let run = c.run(&Value::from(steps), &Release::Valid);
    assert_eq!(
        run.code(),
        Some(1),
        "evidence loss is a tool error: {}",
        explain(&run)
    );
    common::assert_run_records(&run);
    let note = run
        .trace_events()
        .iter()
        .find(|event| event["fields"]["reason"] == "trace_transport_loss")
        .unwrap_or_else(|| panic!("no loss note: {}", explain(&run)))
        .clone();
    assert_eq!(
        note["fields"]["classes"],
        serde_json::json!(["exec", "fs.write", "fs.deny", "net"]),
        "the note names what this attempt covers"
    );
    let settled = run.receipt_phase("settled").expect("a settled receipt");
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let gap = settled["coverage"][class]["gaps"]
            .as_array()
            .and_then(|gaps| {
                gaps.iter()
                    .find(|gap| gap["reason"] == "trace_transport_loss")
            })
            .unwrap_or_else(|| panic!("{class}: no loss gap: {:#}", settled["coverage"]));
        assert_eq!(gap["source"], "wrapper", "{class}: {gap}");
        assert_eq!(
            gap["start_ns"], note["fields"]["start_ns"],
            "{class}: {gap}"
        );
    }
}

/// J5-C wave 3, R03.5 "Trace partial writes ... cannot block deadline
/// enforcement", one run with a consumer that reads 4 KiB and then pauses
/// `pause_ms`: every trace frame reaches the consumer in several partial
/// writes (the test seam `OURO_JAIL_TEST_TRACE_FD_WRITE_MAX=64` caps each
/// `write(2)` of the `--trace-fd` sink at 64 bytes, and every frame is longer),
/// the target produces results for longer than its 2 s wall and then sleeps
/// 30 s, and the consumer is slow but live (its pause stays inside the sink's
/// one-second no-progress deadline). The wall still fires on time:
/// the run ends within seconds, the receipt's cause is `wall_expiry` with the
/// wall's `hit` recorded, and, when the stream is complete, the target's own
/// `proc.exit` lies within 3.5 s of its exec on the product's clock. The trace
/// is every frame reassembled from its pieces (the whole contract holds), or,
/// when the terminal drain could not deliver the backlog within its budget,
/// visibly incomplete with the loss in the receipt; never corrupt.
/// Seconds since the epoch of an RFC 3339 UTC time as the product writes it
/// (`YYYY-MM-DDThh:mm:ssZ`, `records::rfc3339_utc`).
fn rfc3339_seconds(text: &str) -> i64 {
    let number = |range: std::ops::Range<usize>| -> i64 {
        text.get(range)
            .and_then(|part| part.parse().ok())
            .unwrap_or_else(|| panic!("not an RFC 3339 UTC time: {text}"))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    // Howard Hinnant's days_from_civil.
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days * 86_400 + number(11..13) * 3600 + number(14..16) * 60 + number(17..19)
}

#[test]
fn rfc3339_seconds_matches_known_times() {
    assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), 0);
    assert_eq!(rfc3339_seconds("2000-02-29T23:59:59Z"), 951_868_799);
    assert_eq!(rfc3339_seconds("2026-09-25T00:15:36Z"), 1_790_295_336);
}

// J5-C wave 4 (review rev-late F2): the trace fd is a SOCK_SEQPACKET socket,
// which keeps every write(2) the jail makes as one message, so the write size
// the release binary uses is visible to the consumer. A pipe reassembles the
// pieces, which is how the wave-3 version of these tests passed with the seam
// dropped by the supervisor (the review's M2).

/// The seam's cap in these runs.
const WRITE_MAX: usize = 64;

/// The descriptor number the wrapper gives the jail's end of the socket.
const TRACE_FD: i32 = 63;

/// Connects a SOCK_SEQPACKET socket to `argv[1]`, puts it on fd 63 and execs
/// `argv[2..]` (the jail): `--trace-fd 63` is then the test's socket.
const SEQPACKET_WRAPPER: &str = "import os, socket, sys\n\
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)\n\
    s.connect(sys.argv[1])\n\
    os.dup2(s.fileno(), 63)\n\
    os.execv(sys.argv[2], sys.argv[2:])\n";

fn seqpacket_listener(path: &Path) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    // SAFETY: plain socket calls on a zeroed address this function owns.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
        let owned = std::os::fd::OwnedFd::from_raw_fd(fd);
        let mut address: libc::sockaddr_un = std::mem::zeroed();
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() < address.sun_path.len(), "{}", path.display());
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        let length =
            libc::socklen_t::try_from(std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1)
                .unwrap();
        assert_eq!(
            libc::bind(fd, (&raw const address).cast(), length),
            0,
            "bind: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(libc::listen(fd, 1), 0, "listen");
        owned
    }
}

/// Waits up to `millis` for `fd` to be readable.
fn readable_within(fd: i32, millis: i32) -> bool {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd.
    unsafe { libc::poll(&raw mut pollfd, 1, millis) == 1 }
}

/// Bytes queued on the socket's receive side (SIOCINQ sums every queued
/// message of a SOCK_SEQPACKET socket).
fn queued_bytes(fd: i32) -> usize {
    let mut queued: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int.
    let status = unsafe { libc::ioctl(fd, libc::FIONREAD, &raw mut queued) };
    assert_eq!(status, 0, "FIONREAD: {}", std::io::Error::last_os_error());
    usize::try_from(queued).unwrap()
}

/// One message, consumed (`peek` false) or peeked at the socket's peek
/// offset; `None` when nothing is queued (`MSG_DONTWAIT`) or at end of file.
fn receive(fd: i32, buffer: &mut [u8], peek: bool, wait: bool) -> Option<Vec<u8>> {
    let mut flags = libc::MSG_TRUNC;
    if peek {
        flags |= libc::MSG_PEEK;
    }
    if !wait {
        flags |= libc::MSG_DONTWAIT;
    }
    loop {
        // SAFETY: `buffer` is live and writable for its length.
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), flags) };
        if received < 0 {
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => return None,
                _ => panic!("recv: {error}"),
            }
        }
        let length = usize::try_from(received).unwrap();
        assert!(
            length <= buffer.len(),
            "a {length}-byte message was truncated"
        );
        return (length > 0).then(|| buffer[..length].to_vec());
    }
}

fn set_peek_offset(fd: i32, offset: libc::c_int) {
    // SAFETY: one int option.
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEEK_OFF,
            (&raw const offset).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap(),
        )
    };
    assert_eq!(
        status,
        0,
        "SO_PEEK_OFF: {}",
        std::io::Error::last_os_error()
    );
}

/// How the consumer reads.
#[derive(Clone, Copy, Debug)]
enum Pace {
    /// Slow but live: a 20 ms pause after every 64 messages.
    Live,
    /// Live, until it has `after` messages; then it stops reading until the
    /// jail is blocked with a frame partly written (see [`Held`]), keeps that
    /// stall for `hold`, and reads live again.
    HoldMidFrame {
        after: usize,
        hold: std::time::Duration,
    },
}

/// A frame the jail held partly written while the consumer stalled.
#[derive(Clone, Debug)]
struct Held {
    /// Where the jail's writes stopped: every byte before this offset was
    /// written (read or queued), and none after it, for the whole stall.
    offset: usize,
    /// How much of the unfinished frame was written by then.
    written: usize,
    /// How long the stall was held once the jail was seen blocked there.
    held_for: std::time::Duration,
}

/// Everything the consumer received: one entry per `write(2)` of the jail.
struct Received {
    messages: Vec<Vec<u8>>,
    held: Option<Held>,
}

impl Received {
    fn stream(&self) -> Vec<u8> {
        self.messages.concat()
    }
}

/// The bytes after the last LF of `stream`: an unfinished frame.
fn unfinished(stream: &[u8]) -> usize {
    stream.len()
        - stream
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |at| at + 1)
}

/// Accepts the jail's connection and reads until end of file at `pace`.
fn consume(listener: &std::os::fd::OwnedFd, pace: Pace) -> Received {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    assert!(
        readable_within(listener.as_raw_fd(), 30_000),
        "the jail never connected its trace fd"
    );
    // SAFETY: accept on a listening socket this test owns.
    let connection = unsafe {
        let fd = libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        );
        assert!(fd >= 0, "accept: {}", std::io::Error::last_os_error());
        std::os::fd::OwnedFd::from_raw_fd(fd)
    };
    let fd = connection.as_raw_fd();
    let mut buffer = vec![0u8; 128 * 1024];
    let mut received = Received {
        messages: Vec::new(),
        held: None,
    };
    let mut hold = match pace {
        Pace::Live => None,
        Pace::HoldMidFrame { after, hold } => Some((after, hold)),
    };
    loop {
        if let Some((after, duration)) = hold
            && received.messages.len() >= after
        {
            received.held = Some(hold_mid_frame(fd, &mut buffer, &mut received, duration));
            hold = None;
        }
        assert!(
            readable_within(fd, 60_000),
            "the trace fd was silent for a minute"
        );
        let Some(message) = receive(fd, &mut buffer, false, true) else {
            break;
        };
        received.messages.push(message);
        if received.messages.len().is_multiple_of(64) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    received
}

/// Stops reading until the jail is blocked with a frame partly written, then
/// holds the stall for `duration`.
///
/// The writer flushes whole queued frames in capped pieces until a write
/// would block, so it stops mid-frame only when the socket is full. The
/// consumer waits until the queued byte count stops changing, then peeks
/// (without consuming) at every queued message: if they end mid-frame, the
/// jail is holding that frame's rest. If they end on a frame boundary (the
/// block fell between frames, or the target was between batches), one
/// message is consumed, which frees room for about one more piece, and the
/// check repeats. Once held, the stall lasts `duration`, and the queued
/// count must not have moved: the jail wrote nothing more of that frame.
fn hold_mid_frame(
    fd: i32,
    buffer: &mut [u8],
    received: &mut Received,
    duration: std::time::Duration,
) -> Held {
    let started = std::time::Instant::now();
    loop {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the jail was never seen blocked with a frame partly written"
        );
        // Stable: unchanged over 100 ms.
        let mut queued = queued_bytes(fd);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let now = queued_bytes(fd);
            if now == queued {
                break;
            }
            queued = now;
        }
        let mut stream = received.stream();
        if queued > 0 {
            set_peek_offset(fd, 0);
            let mut peeked = 0;
            while peeked < queued {
                let message = receive(fd, buffer, true, false).expect("a queued message");
                peeked += message.len();
                stream.extend_from_slice(&message);
            }
            set_peek_offset(fd, -1);
            assert_eq!(peeked, queued, "the peeked messages are the queued bytes");
        }
        let written = unfinished(&stream);
        if written > 0 && queued > 0 {
            std::thread::sleep(duration);
            assert_eq!(
                queued_bytes(fd),
                queued,
                "the jail wrote more while it was supposed to be blocked"
            );
            return Held {
                offset: stream.len(),
                written,
                held_for: duration,
            };
        }
        match receive(fd, buffer, false, false) {
            Some(message) => received.messages.push(message),
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
}

/// One `tool` attempt with a 2 s wall whose fixture opens files in batches
/// for longer than the wall, traced into a SOCK_SEQPACKET socket under the
/// write-size seam; the consumer reads at `pace`. Returns the run, what the
/// consumer received and the final receipt, once the wall is shown to have
/// fired on time and every message to be one capped piece of one frame.
fn wall_under_partial_writes(pace: Pace) -> (Run, Received, Value) {
    let jail = Jail::with_program(PYTHON)
        .expect("a private harness")
        .args(["-c", SEQPACKET_WRAPPER]);
    let socket = jail.root().join("trace.sock");
    let listener = seqpacket_listener(&socket);
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = workspace.join("ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let base = workspace.to_str().unwrap().to_owned();
    let mut steps: Vec<Value> = Vec::new();
    for batch in 0..40 {
        for index in 0..30 {
            steps.push(serde_json::json!([
                "open",
                format!("{base}/b{batch}-{index}"),
                "--create",
                "--write"
            ]));
        }
        steps.push(serde_json::json!(["sleep", "100"]));
    }
    steps.push(serde_json::json!(["sleep", "30000"]));
    let script = workspace.join("j5c.json");
    std::fs::write(&script, serde_json::to_vec(&Value::from(steps)).unwrap()).unwrap();
    let consumer = std::thread::spawn(move || consume(&listener, pace));
    let run = jail
        .arg(&socket)
        .arg(harness::jail_path())
        .arg("run")
        .args([
            "--profile",
            "tool",
            "--evidence",
            "best-effort",
            "--limit",
            "wall=2s",
            "--workspace",
        ])
        .arg(&workspace)
        .args(["--trace-fd", &TRACE_FD.to_string()])
        .env(ouro_jail::trace::TRACE_FD_WRITE_SEAM, WRITE_MAX.to_string())
        .control()
        .receipt()
        .target([
            fixture.into_os_string(),
            OsString::from("script"),
            script.into_os_string(),
        ])
        .run()
        .expect("the jail runs");
    let received = consumer.join().expect("the consumer");
    // Receipts and the control transcript: the whole contract.
    common::assert_run_records(&run);
    let last = run
        .receipts()
        .into_iter()
        .max_by_key(|receipt| receipt["revision"].as_u64().unwrap_or(0))
        .expect("a receipt");
    assert_eq!(last["outcome"]["cause"], "wall_expiry", "{}", explain(&run));
    let wall = last["applied"]["limits"]
        .as_array()
        .and_then(|limits| limits.iter().find(|limit| limit["key"] == "wall"))
        .expect("the wall limit");
    assert_eq!(
        wall["hit"], true,
        "the receipt records the wall's hit: {wall}"
    );
    // On the product's own clock: the tree was verified dead soon after the
    // 2 s wall, and the final receipt, written after the terminal drain's
    // one-second budget, soon after that. Whole seconds, so the bounds carry
    // a second of rounding.
    assert_eq!(
        last["phase"], "settled",
        "the wall's stop ended the tree and it was verified dead: {:#}",
        last["lifetime"]
    );
    let seconds = |pointer: &str| {
        rfc3339_seconds(
            last.pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{pointer}: {last:#}")),
        )
    };
    let created = seconds("/created_at");
    assert!(
        seconds("/lifetime/verified_at") - created <= 4,
        "the tree died {} s after the attempt began: the wall was late",
        seconds("/lifetime/verified_at") - created
    );
    assert!(
        seconds("/updated_at") - created <= 6,
        "the final receipt came {} s after the attempt began",
        seconds("/updated_at") - created
    );
    assert_eq!(
        last["lifetime"]["native"]["details"]["test_seams"][ouro_jail::trace::TRACE_FD_WRITE_SEAM],
        WRITE_MAX.to_string(),
        "the seam is recorded in the receipt"
    );
    // The seam as the release binary applied it: every write(2) was at most
    // the cap, and lay inside one frame (the writer moves one frame at a
    // time, resuming it at its offset).
    assert!(!received.messages.is_empty(), "nothing was traced");
    for (index, message) in received.messages.iter().enumerate() {
        assert!(
            message.len() <= WRITE_MAX,
            "write {index} was {} bytes: the seam's cap of {WRITE_MAX} was not applied",
            message.len()
        );
        assert!(
            !message[..message.len() - 1].contains(&b'\n'),
            "write {index} spans two frames"
        );
    }
    // Every complete line is a valid event; only the last, unterminated one
    // may be partial: a torn frame anywhere else would join the next one on
    // its line and fail to parse.
    let stream = received.stream();
    let complete = stream.len() - unfinished(&stream);
    let lines: Vec<&[u8]> = stream[..complete]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    let mut pieces = 0;
    for (index, line) in lines.iter().enumerate() {
        assert!(
            line.len() + 1 > WRITE_MAX,
            "frame {index} fits one write, so it proves nothing about pieces"
        );
        pieces += (line.len() + 1).div_ceil(WRITE_MAX);
        let event: Value = serde_json::from_slice(line).unwrap_or_else(|error| {
            panic!(
                "frame {index} is torn or corrupt ({error}): {}",
                String::from_utf8_lossy(line)
            )
        });
        let errors: Vec<String> = common::validators()["jail-event"]
            .iter_errors(&event)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "frame {index}: {errors:?}");
    }
    assert!(
        received.messages.len() >= pieces,
        "{} writes for frames that need at least {pieces} capped pieces",
        received.messages.len()
    );
    eprintln!(
        "{} frames in {} writes of at most {WRITE_MAX} bytes, {} unfinished bytes at the end",
        lines.len(),
        received.messages.len(),
        stream.len() - complete
    );
    (run, received, last)
}

/// The events of every complete line of `stream`.
fn events_of(stream: &[u8]) -> Vec<Value> {
    let complete = stream.len() - unfinished(stream);
    stream[..complete]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("a parsed frame"))
        .collect()
}

fn has_error(receipt: &Value, code: &str) -> bool {
    receipt["errors"]
        .as_array()
        .is_some_and(|errors| errors.iter().any(|error| error["code"] == code))
}

/// The consumer keeps up (a 20 ms pause every 64 messages): every frame
/// reaches it, written in pieces of at most the seam's cap, the stream is
/// complete and passes the frozen contract, and the target's own end comes
/// 2 s after its exec.
#[test]
fn j5_r03_a_wall_fires_on_time_while_every_trace_frame_is_written_in_pieces() {
    if !Profile::Tool.available() || !Path::new(PYTHON).is_file() {
        return;
    }
    let (_run, received, last) = wall_under_partial_writes(Pace::Live);
    let stream = received.stream();
    assert_eq!(
        unfinished(&stream),
        0,
        "a consumer that keeps up gets every frame"
    );
    let events = events_of(&stream);
    common::check_trace(&events, Some(&last))
        .unwrap_or_else(|error| panic!("the trace fails its contract: {error}"));
    assert!(
        !events
            .iter()
            .any(|event| event["fields"]["reason"] == "trace_transport_loss"),
        "a consumer that keeps up loses nothing"
    );
    assert!(!has_error(&last, "evidence_lost"), "{:#}", last["errors"]);
    let at = |pick: &dyn Fn(&Value) -> bool| -> u128 {
        events
            .iter()
            .find(|event| pick(event))
            .and_then(|event| event["monotonic_ns"].as_str())
            .and_then(|ns| ns.parse().ok())
            .unwrap_or_else(|| panic!("the event is missing from the trace"))
    };
    let target = last["process"]["pid"].as_i64().expect("the target's pid");
    let exec = at(&|event| event["fields"]["transition"] == "exec_confirmed");
    let exit = at(&|event| {
        event["operation"] == "proc.exit" && event["fields"]["pid"].as_i64() == Some(target)
    });
    assert!(
        exit.saturating_sub(exec) < 3_500_000_000,
        "the target ended {} ms after its exec: the wall was late",
        exit.saturating_sub(exec) / 1_000_000
    );
}

/// The consumer stops reading while the jail is writing, waits until the
/// jail is blocked with a frame partly written (proved from the socket
/// itself, see `hold_mid_frame`), and holds that stall for 1.5 s, past the
/// one-second no-progress deadline, before reading live again. The wall
/// fires on time all the same, the receipt records the loss, and the frame
/// the jail held is either finished intact from its offset (the stream then
/// records its own loss, or ends visibly incomplete later) or is the visibly
/// incomplete last line; never a torn frame followed by more bytes. A writer
/// that blocked on its consumer would hold the supervisor for as long as the
/// consumer stalls (wave 3's M4: the wall came 40 s late).
#[test]
fn j5_r03_a_wall_fires_on_time_while_a_stalled_consumer_holds_a_partial_frame() {
    if !Profile::Tool.available() || !Path::new(PYTHON).is_file() {
        return;
    }
    let (_run, received, last) = wall_under_partial_writes(Pace::HoldMidFrame {
        after: 64,
        hold: std::time::Duration::from_millis(1500),
    });
    let held = received
        .held
        .clone()
        .expect("the consumer held its stall on a partly written frame");
    assert!(held.written > 0 && held.written < held.offset, "{held:?}");
    assert!(
        held.held_for > std::time::Duration::from_secs(1),
        "the stall outlasts the one-second no-progress deadline"
    );
    eprintln!("held: {held:?}");
    // Blocked for longer than the deadline with frames queued: a loss.
    assert!(
        has_error(&last, "evidence_lost"),
        "a writer held past its deadline is an evidence loss: {:#}",
        last["errors"]
    );
    let stream = received.stream();
    let frame_start = held.offset - held.written;
    let frame_end = stream[frame_start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|at| frame_start + at);
    let events = events_of(&stream);
    match frame_end {
        Some(end) => {
            // The held frame was finished from its offset: it is one whole,
            // valid event (every complete line was validated above).
            assert!(
                serde_json::from_slice::<Value>(&stream[frame_start..end]).is_ok(),
                "the held frame, finished, is one event"
            );
            eprintln!(
                "the held frame ({} bytes, {} written before the stall) was finished",
                end - frame_start,
                held.written
            );
            if unfinished(&stream) == 0 {
                // A complete stream records its own loss.
                assert!(
                    events
                        .iter()
                        .any(|event| event["fields"]["reason"] == "trace_transport_loss"),
                    "a complete stream after a loss carries the loss note"
                );
                common::check_trace(&events, Some(&last))
                    .unwrap_or_else(|error| panic!("the trace fails its contract: {error}"));
            } else {
                assert_eq!(last["observer"]["sources"]["wrapper"], "degraded");
            }
        }
        None => {
            // Never finished: the held frame is the visibly incomplete end.
            assert_eq!(unfinished(&stream), stream.len() - frame_start);
            assert_eq!(last["observer"]["sources"]["wrapper"], "degraded");
            eprintln!("the held frame is the incomplete end of the stream");
        }
    }
}

// ===========================================================================
// J5-C, R01.5: the integrity (pending, lost) and unknown-exec settlement
// tuples, as the real jail writes them
// ===========================================================================
//
// jail-v1 §13.2: "`lifetime.integrity` is `pending` before a boundary is
// validated, `verified` when its identity and the claimed scope have been
// checked, or `lost` after detected tampering/escape"; "Lost integrity
// requires null tree result/time and forbids settlement/cleanup"; "Verified
// settlement with unknown exec evidence is valid". The corpus (R01.1) shows
// the schema accepts those tuples; these runs show the real jail writes them,
// each held to the whole frozen contract.

const PYTHON: &str = "/usr/bin/python3";

fn error_codes(receipt: &Value) -> Vec<String> {
    receipt["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .filter_map(|error| error["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A private workspace in `jail`'s root.
fn private_workspace(jail: &Jail) -> PathBuf {
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    workspace
}

/// R01.5, integrity pending: §13.2's "Refusal before boundary creation" row.
/// stdin is a directory, which a contained run refuses in preparation
/// (§8.3), before any boundary exists: phase `refused`, containment and
/// protection `pending`, no exec, boundary `pending` with no native identity,
/// no scope, no tree result or time, and integrity `pending`.
#[test]
fn j5_r01_a_refusal_before_the_boundary_carries_integrity_pending() {
    if !Profile::Tool.available() {
        return;
    }
    let jail = Jail::with_program("/bin/sh")
        .expect("a private harness")
        .args(["-c", "exec \"$0\" \"$@\" </"])
        .arg(harness::jail_path());
    let workspace = private_workspace(&jail);
    let marker = jail.root().join("target-ran");
    let run = jail
        .arg("run")
        .args(["--profile", "tool", "--workspace"])
        .arg(&workspace)
        .trace()
        .control()
        .receipt()
        .target(["/bin/sh", "-c", &format!("touch {}", marker.display())])
        .run()
        .expect("the jail runs");
    assert_eq!(run.code(), Some(125), "{}", explain(&run));
    assert!(!marker.exists(), "the target ran");
    common::assert_run_records(&run);
    let receipts = run.receipts();
    assert!(
        receipts.len() >= 2,
        "the canonical receipt and the --receipt copy: {receipts:#?}"
    );
    for receipt in &receipts {
        assert_eq!(receipt["phase"], "refused", "{receipt:#}");
        assert_eq!(receipt["containment"], "pending", "{receipt:#}");
        assert_eq!(receipt["child_protection"], "pending", "{receipt:#}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(
            receipt["lifetime"],
            serde_json::json!({
                "boundary": "pending",
                "native": null,
                "tree_empty": null,
                "verified_at": null,
                "verification_scope": null,
                "integrity": "pending",
            }),
            "{receipt:#}"
        );
        assert_eq!(receipt["applied"]["network"]["mode"], "pending");
        assert_eq!(receipt["outcome"]["kind"], "refused");
        assert_eq!(receipt["outcome"]["error"]["code"], "invalid_fd");
        assert_eq!(receipt["outcome"]["error"]["stage"], "preparing");
    }
    let refused = run.control_kind("refused");
    assert_eq!(refused.len(), 1, "{:?}", control_kinds(&run));
    assert_eq!(refused[0]["receipt_phase"], "refused");
}

/// A cgroup this test creates beside the attempt leaves under the operator's
/// delegated subtree: the kind of cgroup an uncontained child can create for
/// itself and move into. Removed with the test; only the attempt's own target
/// is ever in it.
struct Destination {
    path: PathBuf,
}

impl Destination {
    fn new(tag: &str) -> Destination {
        // SAFETY: getuid takes no arguments and cannot fail.
        let root = ouro_jail::platform::linux::cgroup::delegated_root(unsafe { libc::getuid() })
            .expect("the delegated subtree exists");
        let path = root.join(format!("ouro-j5c-{tag}-{}", std::process::id()));
        std::fs::create_dir(&path).expect("a destination cgroup");
        Destination { path }
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        // Only the attempt's own target can be here: the test made this cgroup.
        if populated(&self.path) {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while populated(&self.path) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn populated(cgroup: &Path) -> bool {
    std::fs::read_to_string(cgroup.join("cgroup.events"))
        .is_ok_and(|events| events.lines().any(|line| line == "populated 1"))
}

/// The attempt leaf a receipt registered, removed once it is checked to be
/// that leaf (its pinned inode) and empty: the jail retains it after a loss
/// (§14.2), so the test that caused the loss removes it.
fn remove_retained_leaf(receipt: &Value) {
    use std::os::unix::fs::MetadataExt as _;
    let leaf = &receipt["lifetime"]["native"]["details"]["execution_cgroup"];
    let path = PathBuf::from(leaf["path"].as_str().expect("a leaf path"));
    let inode = leaf["inode"].as_u64().expect("a leaf inode");
    if std::fs::metadata(&path).is_ok_and(|meta| meta.ino() == inode) && !populated(&path) {
        std::fs::remove_dir(&path).expect("the empty retained leaf is removed");
    }
}

/// The §13.2 lost tuple: no tree result or time, never settled, cleanup never
/// complete, and the unknown tree reported.
fn assert_lost_tuple(receipt: &Value) {
    assert_ne!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(receipt["containment"], "none");
    assert_eq!(receipt["child_protection"], "unprotected");
    let lifetime = &receipt["lifetime"];
    assert_eq!(lifetime["integrity"], "lost", "{receipt:#}");
    assert_eq!(lifetime["boundary"], "supervisor_cgroup");
    assert_eq!(lifetime["verification_scope"], "registered_boundary");
    assert_eq!(lifetime["tree_empty"], Value::Null);
    assert_eq!(lifetime["verified_at"], Value::Null);
    assert_ne!(receipt["state_cleanup"], "complete");
}

/// R01.5, integrity lost: a `none` target moves itself out of its leaf into a
/// cgroup of its own and stays alive until the test lets it exit 7. The
/// escape reaches the receipt while it runs (§9.3, P7), and the final receipt
/// keeps the lost tuple with the target's own exit.
#[test]
fn j5_r01_a_detected_escape_carries_integrity_lost() {
    if !Profile::None.available() {
        return;
    }
    let destination = Destination::new("escape");
    let jail = Jail::new().expect("a private harness");
    let workspace = private_workspace(&jail);
    let moved = jail.root().join("moved");
    let go = jail.root().join("go");
    let code = format!(
        "import os, time\n\
         open({dest:?}, 'w').write('0')\n\
         open({moved:?}, 'w').write(str(os.getpid()))\n\
         for _ in range(3000):\n\
         \x20   if os.path.exists({go:?}): break\n\
         \x20   time.sleep(0.01)\n\
         os._exit(7)\n",
        dest = destination.path.join("cgroup.procs").to_str().unwrap(),
        moved = moved.to_str().unwrap(),
        go = go.to_str().unwrap(),
    );
    let spawned = jail
        .arg("run")
        .args(["--profile", "none", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .trace()
        .control()
        .receipt()
        .target([PYTHON, "-c", &code])
        .spawn()
        .expect("the jail starts");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let running = loop {
        let latest = spawned.receipt_value().unwrap_or(Value::Null);
        if latest["lifetime"]["integrity"] == "lost" {
            break latest;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no receipt recorded the escape; the latest: {latest:#}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    // While the target runs, from the receipt written when the loss was seen.
    let running = common::checked_receipt(running);
    assert!(moved.exists() && !go.exists());
    assert_lost_tuple(&running);
    assert_eq!(running["phase"], "enforced", "{running:#}");
    assert_eq!(running["outcome"]["kind"], "pending", "{running:#}");
    std::fs::write(&go, b"").unwrap();
    let run = spawned.wait().expect("the jail ends");
    common::assert_run_records(&run);
    assert_eq!(run.code(), Some(1), "{}", explain(&run));
    let last = run
        .receipts()
        .into_iter()
        .max_by_key(|receipt| receipt["revision"].as_u64().unwrap_or(0))
        .expect("a receipt");
    assert_lost_tuple(&last);
    assert_eq!(last["phase"], "enforced");
    assert_eq!(last["exec_observed"], true);
    assert_eq!(last["outcome"]["kind"], "exited", "{last:#}");
    assert_eq!(last["outcome"]["code"], 7);
    assert!(
        error_codes(&last).iter().any(|code| code == "tree_unknown"),
        "{last:#}"
    );
    assert!(run.control_kind("settled").is_empty());
    assert_eq!(run.control_kind("unsettled").len(), 1);
    remove_retained_leaf(&last);
}

/// R01.5, verified settlement with unknown exec evidence. With observation
/// off, exec is confirmed only by the target's executable image differing
/// from the launcher's (§11.2; `check_exec_without_tracer`). The target here
/// is the jail's own binary as bound into the sandbox for the launcher, so
/// the image never differs and nothing independent saw the exec: the tree's
/// end is verified, the attempt settles, `exec_observed` stays false, and the
/// outcome is the coded unknown (§6.4 `exec_unconfirmed`).
#[test]
fn j5_r01_an_exec_the_jail_cannot_confirm_settles_with_exec_unknown() {
    if !Profile::Tool.available() {
        return;
    }
    let jail = Jail::new().expect("a private harness");
    let workspace = private_workspace(&jail);
    let run = jail
        .arg("run")
        .args(["--profile", "tool", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .trace()
        .control()
        .receipt()
        .target([
            ouro_jail::platform::linux::bwrap::JAIL_INSIDE_PATH,
            "version",
        ])
        .run()
        .expect("the jail runs");
    common::assert_run_records(&run);
    assert_eq!(run.code(), Some(1), "{}", explain(&run));
    let receipts = run.receipts();
    assert!(receipts.len() >= 2, "{receipts:#?}");
    for settled in &receipts {
        assert_eq!(settled["phase"], "settled", "{settled:#}");
        assert_eq!(settled["exec_observed"], false, "{settled:#}");
        assert_eq!(settled["containment"], "enforced");
        assert_eq!(settled["child_protection"], "enforced");
        assert_eq!(settled["outcome"]["kind"], "unknown", "{settled:#}");
        assert_eq!(settled["outcome"]["code"], Value::Null);
        assert_eq!(settled["outcome"]["signal"], Value::Null);
        assert!(
            error_codes(settled)
                .iter()
                .any(|code| code == "exec_unconfirmed"),
            "{settled:#}"
        );
        let lifetime = &settled["lifetime"];
        assert_eq!(lifetime["boundary"], "pid_namespace");
        assert_eq!(lifetime["verification_scope"], "attempt_tree");
        assert_eq!(lifetime["integrity"], "verified");
        assert_eq!(lifetime["tree_empty"], true);
        assert!(lifetime["verified_at"].is_string(), "{settled:#}");
    }
    let kinds = control_kinds(&run);
    assert!(
        kinds.iter().any(|kind| kind == "settled"),
        "the attempt settled: {kinds:?}"
    );
    assert!(
        !kinds.iter().any(|kind| kind == "exec_confirmed"),
        "nothing confirmed the exec: {kinds:?}"
    );
    assert!(
        !run.trace_events()
            .iter()
            .any(|event| event["fields"]["transition"] == "exec_confirmed"),
        "the trace confirms no exec"
    );
}
