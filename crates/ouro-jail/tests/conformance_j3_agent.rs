#![cfg(target_os = "linux")]
//! The `agent` profile end to end on the stock reference host (J3 wave 2).
//!
//! Rows: S03, N01, N02, N03 (end to end), N04, N05, C01 (the live `run`
//! half), X06 for `agent`, and the J2 gap the `none` slice found (the filter
//! count is read back). Every test drives the real `ouro-jail run --profile
//! agent` binary through the shared harness: the real launcher, the real
//! mediator, the real bridge and the real proxy. Servers, sockets and
//! credentials are fixtures this file creates; the only processes signalled
//! are ones the run itself started. Nested user namespaces are unavailable on
//! this host by design: that is asserted as a measurement, never skipped.
//!
//! Each test states what was attempted, the raw result the fixture or the
//! target script reported, and the verdict it asserts.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonschema::{Registry, Resource, Validator};
use ouro_fixture::harness::{self, HttpServer, Jail, ProbeKind, Run, Spawned, UnixProbe};
use serde_json::Value;

mod common;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

/// One validator per checked-in schema, by stem.
fn validators() -> &'static BTreeMap<String, Validator> {
    static ONCE: std::sync::OnceLock<BTreeMap<String, Validator>> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let mut schemas: BTreeMap<String, Value> = BTreeMap::new();
        for entry in std::fs::read_dir(specs_dir()).unwrap() {
            let path = entry.unwrap().path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Some(stem) = name.strip_suffix(".schema.json") {
                let text = std::fs::read_to_string(&path).unwrap();
                schemas.insert(stem.to_owned(), serde_json::from_str(&text).unwrap());
            }
        }
        let pairs: Vec<(String, Resource)> = schemas
            .values()
            .map(|schema| {
                (
                    schema["$id"].as_str().unwrap().to_owned(),
                    Resource::from_contents(schema.clone()),
                )
            })
            .collect();
        let registry: Registry = Registry::new().extend(pairs).unwrap().prepare().unwrap();
        let registry: &'static Registry = Box::leak(Box::new(registry));
        schemas
            .into_iter()
            .map(|(name, schema)| {
                let validator = jsonschema::options()
                    .with_registry(registry)
                    .should_validate_formats(true)
                    .build(&schema)
                    .unwrap();
                (name, validator)
            })
            .collect()
    })
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A run of `ouro-jail run --profile <profile>` over a private workspace
/// holding the conformance fixture at `<workspace>/bin/ouro-fixture`, with the
/// trace and control channels plumbed.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
}

fn case(profile: &str) -> Case {
    let jail = Jail::new().unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace.join("bin"));
    let fixture = workspace.join("bin/ouro-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let jail = jail
        .arg("run")
        .arg("--profile")
        .arg(profile)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    Case {
        jail,
        workspace,
        fixture,
    }
}

impl Case {
    /// A fixture `script` of `steps` written into the workspace; returns the
    /// target argv that runs it.
    fn script(&self, name: &str, steps: &Value) -> Vec<OsString> {
        let path = self.workspace.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_vec(steps).unwrap()).unwrap();
        vec![
            self.fixture.clone().into_os_string(),
            OsString::from("script"),
            path.into_os_string(),
        ]
    }
}

fn py(script: &str, args: &[&str]) -> Vec<OsString> {
    let mut out = vec![
        OsString::from("/usr/bin/python3"),
        OsString::from("-c"),
        OsString::from(script),
    ];
    out.extend(args.iter().map(OsString::from));
    out
}

/// The JSON document a Python target printed last.
fn py_out(run: &Run) -> Value {
    let text = run.stdout_text();
    let line = text
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "the target printed no JSON: stdout {text:?}, stderr {}",
                run.stderr_text()
            )
        });
    serde_json::from_str(line).unwrap()
}

/// Every receipt and trace event validated against the checked-in schemas;
/// returns the settled receipt.
fn settled(run: &Run) -> Value {
    run.assert_channels_complete();
    assert!(
        run.receipt_errors().is_empty(),
        "{:?}",
        run.receipt_errors()
    );
    for receipt in run.receipts() {
        validators()["jail-receipt"]
            .validate(&receipt)
            .unwrap_or_else(|error| panic!("a receipt fails its schema: {error}\n{receipt:#}"));
    }
    for event in run.trace_events() {
        validators()["jail-event"]
            .validate(event)
            .unwrap_or_else(|error| panic!("an event fails its schema: {error}\n{event:#}"));
    }
    run.receipt_phase("settled").unwrap_or_else(|| {
        panic!(
            "no settled receipt: exit {:?}, stderr {}",
            run.code(),
            run.stderr_text()
        )
    })
}

fn details(receipt: &Value) -> &Value {
    &receipt["lifetime"]["native"]["details"]
}

/// The fixture's own report lines for one operation name, in order.
fn ops<'a>(lines: &'a [Value], op: &str) -> Vec<&'a Value> {
    lines.iter().filter(|line| line["op"] == op).collect()
}

fn events<'a>(run: &'a Run, source: &str) -> Vec<&'a Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == source)
        .collect()
}

/// Audit results a mediated connect produced (`observation:
/// seccomp_user_notification`), `net.connect` or `fs.deny`.
fn mediated(run: &Run) -> Vec<&Value> {
    events(run, "audit")
        .into_iter()
        .filter(|event| event["fields"]["observation"] == "seccomp_user_notification")
        .collect()
}

fn helper_notes<'a>(run: &'a Run, transition: &str) -> Vec<&'a Value> {
    events(run, "wrapper")
        .into_iter()
        .filter(|event| {
            event["fields"]["kind"] == "helper" && event["fields"]["transition"] == transition
        })
        .collect()
}

/// The attempt directory of a run's only attempt.
fn attempt_of(data: &Path) -> PathBuf {
    let mut found: Vec<PathBuf> = std::fs::read_dir(data.join("attempts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    found.pop().unwrap()
}

/// Waits for `prepared` and returns (control message, prepared receipt).
fn prepared(spawned: &mut Spawned) -> (Value, Value) {
    let message = spawned
        .owner()
        .await_prepared()
        .expect("a prepared message");
    let receipt = spawned.receipt_value().expect("a prepared receipt");
    assert_eq!(receipt["phase"], "prepared");
    (message, receipt)
}

fn release(spawned: &mut Spawned, message: &Value, receipt: &Value) {
    spawned
        .owner()
        .release(
            &harness::gate::Release::Valid,
            message["attempt_id"].as_str().unwrap(),
            receipt["policy"]["digest"].as_str().unwrap(),
        )
        .unwrap();
}

fn readlinks(pid: i64) -> BTreeMap<i64, String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let fd: i64 = entry.file_name().to_str()?.parse().ok()?;
            let link = std::fs::read_link(entry.path()).ok()?;
            Some((fd, link.to_string_lossy().into_owned()))
        })
        .collect()
}

// ===========================================================================
// S03: the inner sandbox (jail-v1 §9.2, north-star §4.6)
// ===========================================================================

/// S03, Landlock + seccomp form. Attempted: the fixture's `sandbox-exec`
/// sets no_new_privs, installs Landlock (read-write beneath one fresh
/// directory, read-only beneath the fixture's directory, /usr, /etc and
/// /proc) and a
/// seccomp filter returning EPERM for mkdir/mkdirat, then execs a script that
/// reads and writes a protected workspace file, writes inside its grant,
/// creates a directory inside its grant, and connects out directly.
/// Verdict: the inner sandbox starts inside `agent` and restricts its child
/// (EACCES from Landlock, EPERM from the inner filter, ENETUNREACH from the
/// outer network namespace), its filter stacks on the outer three, and the
/// observer records the Landlock denials as `fs.deny`.
#[test]
fn s03_a_landlock_and_seccomp_inner_sandbox_starts_and_restricts_its_child() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    let grant = c.workspace.join("inner-rw");
    let secret = c.workspace.join("secret");
    private_dir(&grant);
    private_dir(&secret);
    fixture_file(
        &secret.join("protected.txt"),
        b"never read by the inner child",
    );
    let steps = serde_json::json!([
        ["open", secret.join("protected.txt"), "--expect", "EACCES"],
        [
            "open",
            secret.join("protected.txt"),
            "--write",
            "--expect",
            "EACCES"
        ],
        ["open", grant.join("made.txt"), "--create", "--write"],
        ["mkdir", grant.join("dir"), "--expect", "EPERM"],
        ["connect", "10.255.255.1:80", "--expect", "ENETUNREACH"],
        ["status"]
    ]);
    let ops_path = grant.join("ops.json");
    std::fs::write(&ops_path, serde_json::to_vec(&steps).unwrap()).unwrap();
    let bin = c.workspace.join("bin");
    let mut argv = vec![
        c.fixture.clone().into_os_string(),
        OsString::from("sandbox-exec"),
        OsString::from("--landlock-rw"),
        grant.clone().into_os_string(),
    ];
    for ro in [
        bin.as_path(),
        Path::new("/usr"),
        Path::new("/etc"),
        Path::new("/proc"),
    ] {
        argv.push(OsString::from("--landlock-ro"));
        argv.push(ro.as_os_str().to_owned());
    }
    for name in ["mkdir", "mkdirat"] {
        argv.push(OsString::from("--seccomp-errno"));
        argv.push(OsString::from(name));
    }
    argv.push(OsString::from("--"));
    argv.push(c.fixture.clone().into_os_string());
    argv.push(OsString::from("script"));
    argv.push(ops_path.into_os_string());
    let run = c.jail.target(argv).run().unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout_text(),
        run.stderr_text()
    );
    let lines = run.fixture_lines();
    // The inner sandbox's own setup, step by step.
    for op in [
        "prctl",
        "landlock_create_ruleset",
        "landlock_restrict_self",
        "seccomp",
    ] {
        let steps = ops(&lines, op);
        assert!(!steps.is_empty(), "{op} was not reported: {lines:#?}");
        for step in steps {
            assert!(step["errno"].is_null(), "{op} failed: {step}");
        }
    }
    let status = ops(&lines, "status")[0];
    assert_eq!(status["args"]["fields"]["NoNewPrivs"], "1");
    assert_eq!(
        status["args"]["fields"]["Seccomp_filters"], "4",
        "the inner filter stacks on the agent baseline, the mediation filter and the \
         observer's narrowing filter"
    );
    assert_eq!(
        std::fs::read(secret.join("protected.txt")).unwrap(),
        b"never read by the inner child"
    );
    assert!(grant.join("made.txt").exists(), "the grant is writable");
    assert!(
        !grant.join("dir").exists(),
        "the inner filter refused mkdir"
    );

    let receipt = settled(&run);
    assert_eq!(receipt["outcome"]["kind"], "exited");
    // The observer saw the Landlock denial of the mutating open (EACCES is
    // an `fs.deny` of the attempted `fs.write`). The read-only open's denial
    // is outside the closed set (§11.2), and the inner filter's EPERM for
    // mkdir outranks the observer's trace stop, so neither is an event.
    let denials: Vec<&Value> = events(&run, "audit")
        .into_iter()
        .filter(|event| event["operation"] == "fs.deny")
        .collect();
    assert_eq!(denials.len(), 1, "{denials:#?}");
    assert_eq!(denials[0]["outcome"]["errno"], "EACCES");
    assert_eq!(denials[0]["fields"]["attempted_operation"], "fs.write");
    assert!(
        !events(&run, "audit")
            .iter()
            .any(|event| event["outcome"]["errno"] == "EPERM"),
        "the inner filter's denial is not observed"
    );
    assert_eq!(
        details(&receipt)["agent"]["filter_variant"],
        "unprivileged_inner"
    );
}

/// S03, outer-boundary reversal. Attempted, as the target, with the
/// util-linux tools visible read-only inside the sandbox: remount `/`
/// read-write, unmount the proxy directory, lazily unmount `/`, bind a
/// directory over the proxy directory, join the namespace of pid 1 with
/// `nsenter`, create a user, network or mount namespace with `unshare`, and
/// `chroot`. Verdict: each exits non-zero with its failure visible, and
/// afterwards nothing changed: every namespace is the same, `/`, `/usr` and
/// the proxy directory are still read-only mounts, and the proxy directory
/// still holds exactly its socket.
#[test]
fn s03_each_outer_boundary_reversal_fails_and_changes_nothing() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import errno, json, os, subprocess
def ns():
    return {k: os.readlink("/proc/self/ns/" + k) for k in ["mnt", "net", "user", "pid", "uts", "ipc", "cgroup"]}
def mounts():
    out = {}
    for line in open("/proc/self/mountinfo"):
        f = line.split()
        if f[4] in ("/", "/usr", "/run/ouro/proxy"):
            out[f[4]] = "ro" if "ro" in f[5].split(",") else "rw"
    return out
def write(path):
    try:
        open(path, "w").close()
        return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]
out = {"ns_before": ns(), "mounts_before": mounts(), "tools": {}}
for label, argv in [
    ("remount_root_rw", ["/usr/bin/mount", "-o", "remount,rw", "/"]),
    ("umount_proxy", ["/usr/bin/umount", "/run/ouro/proxy"]),
    ("umount_lazy_root", ["/usr/bin/umount", "-l", "/"]),
    ("bind_over_proxy", ["/usr/bin/mount", "--bind", "/tmp", "/run/ouro/proxy"]),
    ("nsenter_pid1", ["/usr/bin/nsenter", "-t", "1", "-n", "-m", "--", "/usr/bin/true"]),
    ("unshare_user", ["/usr/bin/unshare", "-Ur", "/usr/bin/true"]),
    ("unshare_net", ["/usr/bin/unshare", "-n", "/usr/bin/true"]),
    ("unshare_mount", ["/usr/bin/unshare", "-m", "/usr/bin/true"]),
]:
    p = subprocess.run(argv, capture_output=True, text=True)
    out["tools"][label] = {"rc": p.returncode, "stderr": p.stderr.strip()[:160]}
try:
    os.chroot("/")
    out["chroot"] = "ok"
except OSError as e:
    out["chroot"] = errno.errorcode[e.errno]
out["ns_after"] = ns()
out["mounts_after"] = mounts()
out["write_root"] = write("/escaped")
out["write_usr"] = write("/usr/escaped")
out["write_proxy_dir"] = write("/run/ouro/proxy/escaped")
out["proxy_listing"] = sorted(os.listdir("/run/ouro/proxy"))
print(json.dumps(out))
"#;
    let c = case("agent");
    let run = c.jail.target(py(SCRIPT, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    for (label, result) in out["tools"].as_object().unwrap() {
        assert_ne!(result["rc"], 0, "{label} succeeded: {result}");
        assert!(
            !result["stderr"].as_str().unwrap().is_empty(),
            "{label} failed silently: {result}"
        );
    }
    assert_eq!(out["chroot"], "EPERM");
    assert_eq!(out["ns_before"], out["ns_after"], "a namespace changed");
    assert_eq!(out["mounts_before"], out["mounts_after"], "a mount changed");
    for mount in ["/", "/usr", "/run/ouro/proxy"] {
        assert_eq!(out["mounts_after"][mount], "ro", "{mount}: {out}");
    }
    assert_eq!(out["write_root"], "EROFS");
    assert_eq!(out["write_usr"], "EROFS");
    assert_eq!(out["write_proxy_dir"], "EROFS");
    assert_eq!(out["proxy_listing"], serde_json::json!(["proxy.sock"]));
    let receipt = settled(&run);
    assert_eq!(receipt["outcome"]["code"], 0);
}

/// S03, namespace form, on a host that denies nested user namespaces.
/// Attempted: a bubblewrap inner sandbox and `unshare -U`, as the target.
/// Verdict: both fail visibly to the child (non-zero, with a diagnostic);
/// the receipt records the measured capability as unavailable, the variant
/// that follows from it, and setup operations without mount or unshare;
/// nothing claims the inner sandbox ran.
#[test]
fn s03_a_namespace_inner_sandbox_fails_visibly_and_the_receipt_says_unavailable() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import json, subprocess
out = {}
for label, argv in [
    ("bwrap", ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--ro-bind", "/usr", "/usr",
               "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
               "--symlink", "usr/lib64", "/lib64", "--", "/usr/bin/true"]),
    ("unshare_user", ["/usr/bin/unshare", "-U", "/usr/bin/true"]),
]:
    p = subprocess.run(argv, capture_output=True, text=True)
    out[label] = {"rc": p.returncode, "stderr": p.stderr.strip()[:200]}
print(json.dumps(out))
"#;
    let c = case("agent");
    let run = c.jail.receipt().target(py(SCRIPT, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    for label in ["bwrap", "unshare_user"] {
        assert_ne!(out[label]["rc"], 0, "{label}: {out}");
        assert!(!out[label]["stderr"].as_str().unwrap().is_empty(), "{out}");
    }
    let receipt = settled(&run);
    let agent = &details(&receipt)["agent"];
    assert_eq!(agent["nested_user_namespace"], "unavailable", "{agent:#}");
    assert_eq!(agent["filter_variant"], "unprivileged_inner");
    let setup: Vec<&str> = agent["allowed_setup_operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| op.as_str().unwrap())
        .collect();
    assert!(setup.contains(&"landlock_restrict_self") && setup.contains(&"seccomp"));
    for absent in ["mount", "umount2", "unshare", "pivot_root"] {
        assert!(!setup.contains(&absent), "{absent} in {setup:?}");
    }
    let digest = ouro_jail::platform::linux::seccomp::agent_baseline(
        ouro_jail::platform::linux::seccomp::AgentVariant::UnprivilegedInner,
    )
    .unwrap()
    .digest();
    assert_eq!(agent["baseline_filter_digest"], digest.as_str());
    assert_eq!(receipt["applied"]["syscalls"]["digest"], digest.as_str());
    assert_eq!(
        agent["mediation_filter_digest"],
        ouro_jail::platform::linux::unixpeer::filter_digest().as_str()
    );
}

/// S03, the named limits of jail-v1 §10, measured. Attempted: (1) an inner
/// filter asking for its own seccomp notification listener, and a plain
/// inner filter; (2) inside a Landlock domain that denies every TCP connect,
/// a connect to the bridge and one to a remote address. Verdict: (1) EBUSY
/// for the listener while the outer mediation holds one, and the plain
/// filter stacks; (2) the mediated connect to the bridge succeeds — a
/// mediated connect runs in the supervisor's context, so an inner Landlock
/// network rule does not compose through it, as §10 names — while direct
/// egress still fails in the network namespace.
#[test]
fn s03_the_named_limits_are_what_the_specification_says() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import ctypes, errno, json
libc = ctypes.CDLL(None, use_errno=True)
class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]
prog = (SockFilter * 1)(SockFilter(0x06, 0, 0, 0x7fff0000))
fprog = SockFprog(1, prog)
libc.syscall.restype = ctypes.c_long
out = {"no_new_privs": libc.prctl(38, 1, 0, 0, 0)}
def seccomp(flags):
    rc = libc.syscall(317, 1, ctypes.c_ulong(flags), ctypes.byref(fprog))
    return "ok" if rc >= 0 else errno.errorcode[ctypes.get_errno()]
out["inner_new_listener"] = seccomp(1 << 3)
out["inner_plain_filter"] = seccomp(0)
out["seccomp_filters"] = [l.split()[1] for l in open("/proc/self/status") if l.startswith("Seccomp_filters:")][0]
print(json.dumps(out))
"#;
    let c = case("agent");
    let grant = c.workspace.join("inner-rw");
    private_dir(&grant);
    let steps = serde_json::json!([
        ["connect", "127.0.0.1:3128"],
        ["connect", "10.255.255.1:80", "--expect", "ENETUNREACH"]
    ]);
    let ops_path = grant.join("net.json");
    std::fs::write(&ops_path, serde_json::to_vec(&steps).unwrap()).unwrap();
    let script_path = c.workspace.join("limits.py");
    std::fs::write(&script_path, SCRIPT).unwrap();
    let fixture = c.fixture.to_string_lossy().into_owned();
    let bin = c.workspace.join("bin").to_string_lossy().into_owned();
    let grant_text = grant.to_string_lossy().into_owned();
    let ops_text = ops_path.to_string_lossy().into_owned();
    let shell = format!(
        "/usr/bin/python3 {script} && {fixture} sandbox-exec --landlock-rw {grant_text} \
         --landlock-ro {bin} --landlock-ro /usr --landlock-ro /etc --landlock-deny-tcp \
         -- {fixture} script {ops_text}",
        script = script_path.display()
    );
    let run = c
        .jail
        .target(["/bin/sh", "-c", shell.as_str()])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let text = run.stdout_text();
    let limits: Value = serde_json::from_str(
        text.lines()
            .find(|line| line.contains("inner_new_listener"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(limits["no_new_privs"], 0);
    assert_eq!(limits["inner_new_listener"], "EBUSY", "{limits}");
    assert_eq!(limits["inner_plain_filter"], "ok");
    assert_eq!(limits["seccomp_filters"], "4");
    let lines = run.fixture_lines();
    let landlock = ops(&lines, "landlock_restrict_self");
    assert!(
        !landlock.is_empty() && landlock[0]["errno"].is_null(),
        "{lines:#?}"
    );
    let connects = ops(&lines, "connect");
    assert_eq!(connects.len(), 2, "{lines:#?}");
    assert!(
        connects[0]["errno"].is_null(),
        "named limit: the mediated connect to the bridge is not subject to the inner \
         Landlock TCP rule: {}",
        connects[0]
    );
    assert_eq!(connects[1]["errno"], "ENETUNREACH");
    settled(&run);
}

// ===========================================================================
// N01: direct egress fails for contained profiles
// ===========================================================================

/// N01, for `agent` and for `tool`. Attempted, ignoring every proxy
/// variable: TCP to a remote IPv4 address and to the host's loopback port of
/// a live origin, TCP to an IPv6 documentation address, UDP connect and
/// send, a DNS query, and a plain HTTP GET straight to the origin. Verdict:
/// each fails (ENETUNREACH, or ECONNREFUSED on the attempt's own loopback),
/// and the origin on the host saw no connection at all.
#[test]
fn n01_direct_tcp_udp_ipv6_and_a_proxy_ignoring_client_fail() {
    if !common::live() {
        return;
    }
    for profile in ["agent", "tool"] {
        let origin = HttpServer::start(b"never".to_vec()).unwrap();
        let port = origin.addr().port();
        let c = case(profile);
        let steps = serde_json::json!([
            ["connect", "10.255.255.1:80", "--expect", "ENETUNREACH"],
            [
                "connect",
                format!("127.0.0.1:{port}"),
                "--expect",
                "ECONNREFUSED"
            ],
            ["connect", "[2001:db8::1]:80", "--expect", "ENETUNREACH"],
            [
                "connect",
                "10.255.255.1:53",
                "--udp",
                "--expect",
                "ENETUNREACH"
            ],
            ["udp-sendto", "10.255.255.1:53", "--expect", "ENETUNREACH"],
            ["udp-sendto", "[2001:db8::1]:53", "--expect", "ENETUNREACH"],
            [
                "dns-query",
                "10.255.255.1",
                "example.com",
                "--timeout-ms",
                "500",
                "--expect",
                "ENETUNREACH"
            ],
            [
                "http-get",
                origin.url("/direct"),
                "--no-proxy",
                "--timeout-ms",
                "2000",
                "--expect",
                "any"
            ]
        ]);
        let argv = c.script(&format!("n01-{profile}"), &steps);
        let run = c.jail.target(argv).run().unwrap();
        assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
        let lines = run.fixture_lines();
        let get = ops(&lines, "http-get")[0];
        assert_eq!(get["args"]["via_proxy"], false, "{profile}: {get}");
        assert_eq!(get["args"]["failed_step"], "connect", "{profile}: {get}");
        assert_eq!(
            origin.stop().len(),
            0,
            "{profile}: the host origin was reached"
        );
        let receipt = settled(&run);
        let mode = if profile == "agent" { "proxy" } else { "none" };
        assert_eq!(receipt["applied"]["network"]["mode"], mode);
    }
}

// ===========================================================================
// N02 / N03: the real proxy, through the real bridge
// ===========================================================================

/// N02. Attempted, through the proxy variables (so through the bridge):
/// an allowed plain-HTTP GET, a denied one (a port with no grant), and an
/// allowed CONNECT tunnel carrying a GET. Verdict: 200, 403 and 200+200;
/// the origin saw exactly the two allowed requests and the denied port saw
/// nothing; the trace holds exactly one proxy-source result per request,
/// each with its own id and the matching decision and reason; the audit
/// source separately records the target's own connects to the bridge (and
/// never the bridge's connects to the proxy, which are helper plumbing);
/// `proxy.net` counts the three proxy results and `net` the audit ones.
#[test]
fn n02_allowed_and_denied_requests_through_the_bridge_yield_one_proxy_result_each() {
    if !common::live() {
        return;
    }
    let origin = HttpServer::start(b"allowed body".to_vec()).unwrap();
    let denied = HttpServer::start(b"never".to_vec()).unwrap();
    let (o, d) = (origin.addr().port(), denied.addr().port());
    let c = case("agent");
    let steps = serde_json::json!([
        ["http-get", format!("http://127.0.0.1:{o}/allowed")],
        [
            "http-get",
            format!("http://127.0.0.1:{d}/denied"),
            "--expect",
            "any"
        ],
        [
            "http-connect",
            format!("127.0.0.1:{o}"),
            "--then-get",
            "/tunnel"
        ]
    ]);
    let argv = c.script("n02", &steps);
    let run = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .target(argv)
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let lines = run.fixture_lines();
    let gets = ops(&lines, "http-get");
    assert_eq!(gets[0]["args"]["status_code"], 200, "{lines:#?}");
    assert_eq!(gets[0]["args"]["via_proxy"], true);
    assert_eq!(gets[1]["args"]["status_code"], 403, "{lines:#?}");
    let connect = ops(&lines, "http-connect")[0];
    assert_eq!(connect["args"]["status_code"], 200, "{connect}");
    assert_eq!(
        gets[2]["args"]["status_code"], 200,
        "the GET inside the tunnel"
    );
    let seen: Vec<String> = origin.stop().iter().map(|r| r.target.clone()).collect();
    assert_eq!(seen, ["/allowed", "/tunnel"]);
    assert_eq!(denied.stop().len(), 0);

    let receipt = settled(&run);
    let proxy = events(&run, "proxy");
    assert_eq!(proxy.len(), 3, "{proxy:#?}");
    let mut ids: Vec<i64> = proxy
        .iter()
        .map(|event| event["fields"]["request_id"].as_i64().unwrap())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3, "one result per request id");
    let facts: Vec<(String, String, String)> = proxy
        .iter()
        .map(|event| {
            (
                event["decision"].as_str().unwrap().to_owned(),
                event["fields"]["kind"].as_str().unwrap().to_owned(),
                event["fields"]["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        facts.contains(&("allow".into(), "http".into(), "relayed".into())),
        "{facts:?}"
    );
    assert!(
        facts.contains(&("deny".into(), "http".into(), "host_not_allowed".into())),
        "{facts:?}"
    );
    assert!(
        facts.contains(&("allow".into(), "connect".into(), "relayed".into())),
        "{facts:?}"
    );
    let seqs: Vec<i64> = proxy
        .iter()
        .map(|e| e["source_seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, [1, 2, 3], "the proxy's own sequence");
    for event in &proxy {
        assert_eq!(event["operation"], "net.connect");
        assert_eq!(event["stage"], "result");
    }
    // The audit source: the target's three connects to the bridge, and no
    // AF_UNIX connect at all (the bridge's own connects to the proxy socket
    // are the jail's plumbing, not the target's).
    let audit = mediated(&run);
    assert_eq!(audit.len(), 3, "{audit:#?}");
    for event in &audit {
        assert_eq!(event["operation"], "net.connect", "{event}");
        assert_eq!(event["fields"]["address_family"], 2, "{event}");
        assert!(
            event["decision"].is_null(),
            "an audit result carries no decision"
        );
        assert_eq!(event["outcome"]["ok"], true);
    }
    assert_eq!(receipt["coverage"]["proxy.net"]["status"], "active");
    assert_eq!(receipt["coverage"]["proxy.net"]["observed_count"], 3);
    assert_eq!(
        receipt["coverage"]["proxy.net"]["sources"],
        serde_json::json!(["proxy"])
    );
    assert_eq!(receipt["coverage"]["net"]["observed_count"], 3);
    assert_eq!(receipt["observer"]["sources"]["proxy"], "active");
    assert_eq!(
        receipt["applied"]["network"]["allowed_hosts"],
        serde_json::json!([format!("127.0.0.1:{o}")])
    );
}

/// N03, end to end. Attempted through the bridge: (A) a name rule whose
/// name resolves only to loopback, the apex of a wildcard rule, and a
/// numeric destination with no grant; (B) the same name with a numeric grant
/// for one of its two loopback answers, a Host header that disagrees with
/// the absolute URI, and the granted destination. Verdict: forbidden_address,
/// host_not_allowed and host_not_allowed (the origin untouched); then
/// mixed_answers, host_mismatch, and one successful request.
#[test]
fn n03_address_and_host_rules_hold_end_to_end() {
    if !common::live() {
        return;
    }
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let steps = serde_json::json!([
        [
            "http-get",
            format!("http://localhost:{o}/by-name"),
            "--expect",
            "any"
        ],
        ["http-get", "http://example.test/apex", "--expect", "any"],
        [
            "http-get",
            format!("http://127.0.0.1:{o}/ungranted"),
            "--expect",
            "any"
        ]
    ]);
    let argv = c.script("n03a", &steps);
    let run = c
        .jail
        .args(["--allow-host", &format!("localhost:{o}")])
        .args(["--allow-host", "*.example.test"])
        .target(argv)
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    settled(&run);
    let reasons: Vec<&str> = events(&run, "proxy")
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        ["forbidden_address", "host_not_allowed", "host_not_allowed"]
    );
    for get in ops(&run.fixture_lines(), "http-get") {
        assert_eq!(get["args"]["status_code"], 403, "{get}");
    }

    let c = case("agent");
    let steps = serde_json::json!([
        [
            "http-get",
            format!("http://localhost:{o}/mixed"),
            "--expect",
            "any"
        ],
        [
            "http-get",
            format!("http://127.0.0.1:{o}/mismatch"),
            "--host-header",
            "other.test",
            "--expect",
            "any"
        ],
        ["http-get", format!("http://127.0.0.1:{o}/granted")]
    ]);
    let argv = c.script("n03b", &steps);
    let run = c
        .jail
        .args(["--allow-host", &format!("localhost:{o}")])
        .args(["--allow-host", &format!("127.0.0.1:{o}")])
        .target(argv)
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    settled(&run);
    let reasons: Vec<&str> = events(&run, "proxy")
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, ["mixed_answers", "host_mismatch", "relayed"]);
    let statuses: Vec<i64> = ops(&run.fixture_lines(), "http-get")
        .iter()
        .map(|get| get["args"]["status_code"].as_i64().unwrap())
        .collect();
    assert_eq!(statuses, [403, 400, 200]);
    let seen: Vec<String> = origin.stop().iter().map(|r| r.target.clone()).collect();
    assert_eq!(
        seen,
        ["/granted"],
        "only the granted request reached the origin"
    );
}

// ===========================================================================
// N04: bounded, fail-closed
// ===========================================================================

/// The supervisor's proxy listener, found by its bound name in the
/// supervisor's `/proc/<pid>/net/unix` and its descriptor table, then taken
/// with `pidfd_getfd` (the supervisor is this test's child, so Yama permits
/// it) and shut down: what a dead proxy looks like to every client.
fn kill_proxy_listener(supervisor: u32) {
    let pid = i32::try_from(supervisor).unwrap();
    let table = std::fs::read_to_string(format!("/proc/{pid}/net/unix")).unwrap();
    let inode = table
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() >= 8 && fields[7].ends_with("/proxy.sock") && fields[5] == "01")
                .then(|| fields[6].to_owned())
        })
        .expect("the proxy listener is bound in the supervisor");
    let wanted = format!("socket:[{inode}]");
    let fd = readlinks(i64::from(pid))
        .into_iter()
        .find(|(_, link)| *link == wanted)
        .map(|(fd, _)| fd)
        .expect("the supervisor holds the proxy listener");
    // SAFETY: pidfd_open and pidfd_getfd take scalars; both return new
    // descriptors owned here or -1. shutdown takes a descriptor and a flag.
    unsafe {
        let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0);
        assert!(
            pidfd >= 0,
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        );
        let copy = libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0);
        assert!(
            copy >= 0,
            "pidfd_getfd: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(libc::shutdown(copy as i32, libc::SHUT_RDWR), 0);
        libc::close(copy as i32);
        libc::close(pidfd as i32);
    }
}

/// N04, proxy death. Attempted: after `prepared`, the proxy's listener is
/// shut down from outside; then the target makes an allowed request through
/// the bridge, connects to the proxy socket directly, and tries direct
/// egress. Verdict: every path fails, the origin sees nothing, nothing fell
/// back to direct egress, and the trace records the proxy as stopped.
#[test]
fn n04_proxy_death_fails_closed_and_is_recorded() {
    if !common::live() {
        return;
    }
    let origin = HttpServer::start(b"never".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let steps = serde_json::json!([
        [
            "http-get",
            format!("http://127.0.0.1:{o}/after-death"),
            "--timeout-ms",
            "3000",
            "--expect",
            "any"
        ],
        [
            "unix-connect",
            "/run/ouro/proxy/proxy.sock",
            "--expect",
            "ECONNREFUSED"
        ],
        ["connect", "10.255.255.1:80", "--expect", "ENETUNREACH"]
    ]);
    let argv = c.script("n04-proxy", &steps);
    let mut spawned = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .gate()
        .receipt()
        .target(argv)
        .spawn()
        .unwrap();
    let (message, receipt) = prepared(&mut spawned);
    kill_proxy_listener(spawned.pid());
    release(&mut spawned, &message, &receipt);
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let get = ops(&run.fixture_lines(), "http-get")[0].clone();
    assert!(get["args"]["status_code"].is_null(), "no response: {get}");
    assert_eq!(origin.stop().len(), 0);
    settled(&run);
    assert_eq!(
        helper_notes(&run, "proxy_stopped").len(),
        1,
        "the death is recorded"
    );
}

/// N04, bridge death. Attempted: the target makes one request through the
/// bridge, kills the bridge (a process in its own namespace), then makes a
/// second. Verdict: the first succeeds; the second is refused at
/// 127.0.0.1:3128 and reaches no one; the trace records the bridge's exit.
#[test]
fn n04_bridge_death_fails_closed_and_is_recorded() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import json, os, signal, sys, time, urllib.request
url = sys.argv[1]
out = {}
def get():
    try:
        return urllib.request.urlopen(url, timeout=5).status
    except Exception as e:
        return type(e).__name__ + ":" + str(getattr(e, "reason", e))
out["before"] = get()
bridge = None
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            if open("/proc/%s/cmdline" % pid, "rb").read() == b"/run/ouro/jail\0__bridge\0":
                bridge = int(pid)
        except OSError:
            pass
out["bridge_found"] = bridge is not None
os.kill(bridge, signal.SIGKILL)
for _ in range(500):
    if not os.path.exists("/proc/%d" % bridge):
        break
    time.sleep(0.01)
out["bridge_gone"] = not os.path.exists("/proc/%d" % bridge)
out["after"] = get()
print(json.dumps(out))
"#;
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let url = format!("http://127.0.0.1:{o}/x");
    let c = case("agent");
    let run = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .target(py(SCRIPT, &[&url]))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    assert_eq!(out["before"], 200, "{out}");
    assert_eq!(out["bridge_found"], true);
    assert_eq!(out["bridge_gone"], true);
    assert!(
        out["after"]
            .as_str()
            .unwrap()
            .contains("Connection refused"),
        "{out}"
    );
    assert_eq!(origin.stop().len(), 1, "only the request before the death");
    settled(&run);
    assert_eq!(helper_notes(&run, "bridge_exited").len(), 1);
}

/// N04, budgets through the real proxy. Attempted: a request head past
/// 32 KiB through the bridge; 128 connections to the proxy socket each
/// holding an incomplete head, then a 129th with a complete request; then,
/// with those closed, a normal request. Verdict: 431; 503 overload for the
/// 129th while the others are held; 200 afterwards (bounded, and it
/// recovers).
#[test]
fn n04_header_overflow_and_saturation_are_bounded() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import json, socket, sys
port = int(sys.argv[1])
head = "GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % (port, port)
def status(sock):
    data = b""
    sock.settimeout(8)
    while b"\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    parts = data.split(b" ")
    return int(parts[1]) if len(parts) > 1 else None
out = {}
s = socket.create_connection(("127.0.0.1", 3128))
try:
    s.sendall((head + "X-Fill: " + "a" * 40000 + "\r\n\r\n").encode())
except OSError:
    pass
out["overflow"] = status(s)
s.close()
held = []
for _ in range(128):
    h = socket.socket(socket.AF_UNIX)
    h.connect("/run/ouro/proxy/proxy.sock")
    h.sendall(head.encode())
    held.append(h)
extra = socket.socket(socket.AF_UNIX)
extra.connect("/run/ouro/proxy/proxy.sock")
extra.sendall((head + "\r\n").encode())
out["saturated"] = status(extra)
extra.close()
for h in held:
    h.close()
ok = None
for _ in range(50):
    s = socket.create_connection(("127.0.0.1", 3128))
    s.sendall((head + "\r\n").encode())
    ok = status(s)
    s.close()
    if ok == 200:
        break
out["recovered"] = ok
print(json.dumps(out))
"#;
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let run = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .target(py(SCRIPT, &[&o.to_string()]))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    assert_eq!(out["overflow"], 431, "{out}");
    assert_eq!(out["saturated"], 503, "{out}");
    assert_eq!(out["recovered"], 200, "{out}");
    settled(&run);
    let reasons: Vec<&str> = events(&run, "proxy")
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert!(reasons.contains(&"header_too_large"), "{reasons:?}");
    assert!(reasons.contains(&"overload"), "{reasons:?}");
}

/// N04, slow headers through the bridge. Attempted: a request head sent one
/// byte a second, never finished. Verdict: 408 at the proxy's absolute
/// 10-second header deadline (between 9 and 13 seconds), not later.
#[test]
fn n04_slow_headers_end_at_the_absolute_header_deadline() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import json, socket, time
s = socket.create_connection(("127.0.0.1", 3128))
s.setblocking(False)
start = time.monotonic()
data = b""
payload = b"GET http://127.0.0.1:1/ HTTP/1.1\r\nX-Slow: " + b"a" * 64
i = 0
while time.monotonic() - start < 20:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\r\n" in data:
            break
    except BlockingIOError:
        pass
    if i < len(payload):
        try:
            s.send(payload[i:i + 1])
            i += 1
        except OSError:
            break
    time.sleep(1.0)
parts = data.split(b" ")
print(json.dumps({"status": int(parts[1]) if len(parts) > 1 else None,
                  "elapsed": time.monotonic() - start, "sent": i}))
"#;
    let c = case("agent");
    let run = c
        .jail
        .timeout(Duration::from_secs(60))
        .target(py(SCRIPT, &[]))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    assert_eq!(out["status"], 408, "{out}");
    let elapsed = out["elapsed"].as_f64().unwrap();
    assert!((9.0..13.0).contains(&elapsed), "{out}");
    settled(&run);
    let reasons: Vec<&str> = events(&run, "proxy")
        .iter()
        .map(|event| event["fields"]["reason"].as_str().unwrap())
        .collect();
    assert_eq!(reasons, ["header_timeout"]);
}

// ===========================================================================
// N05: host peers are unreachable, same-attempt IPC works
// ===========================================================================

/// A launch profile that gives the attempt vendor state, so a host socket
/// can be planted in it after the boundary exists.
const STATE_PROFILE: &str = "name = \"n05state\"\njail = \"agent\"\nstate_var = \"N05_HOME\"\n";

fn write_launch_profile(jail: &Jail, name: &str, text: &str) {
    let dir = jail.config_dir().join("launch");
    private_dir(&dir);
    fixture_file(&dir.join(format!("{name}.toml")), text.as_bytes());
}

/// A host listener that, to every client it accepts, sends one descriptor
/// with SCM_RIGHTS: the authority a reachable host peer would hand out.
struct ScmHost {
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScmHost {
    fn start(path: &Path, gift: &Path) -> ScmHost {
        use std::os::fd::AsRawFd as _;
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let file = std::fs::File::open(gift).unwrap();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (a, s) = (accepted.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok((stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let fd = file.as_raw_fd();
                let mut byte = [0u8; 1];
                let mut iov = libc::iovec {
                    iov_base: byte.as_mut_ptr().cast(),
                    iov_len: 1,
                };
                // SAFETY: a control buffer sized by CMSG_SPACE for one fd,
                // filled through the CMSG macros, and a live iovec.
                unsafe {
                    let space = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
                    let mut control = vec![0u8; space];
                    let mut msg: libc::msghdr = std::mem::zeroed();
                    msg.msg_iov = &raw mut iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = control.as_mut_ptr().cast();
                    msg.msg_controllen = space;
                    let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
                    std::ptr::copy_nonoverlapping(
                        std::ptr::from_ref(&fd).cast::<u8>(),
                        libc::CMSG_DATA(cmsg),
                        std::mem::size_of::<i32>(),
                    );
                    libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0);
                }
            }
        });
        ScmHost {
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn stop(mut self) -> usize {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// N05, host peers. Attempted, from inside `agent`: connects to host-bound
/// pathname sockets that existed before launch (stream and seqpacket, three
/// address-length spellings, relative and absolute), to a hard-link alias
/// and a symlink alias of one, to host sockets created after the boundary
/// existed in the workspace, in scratch and in vendor state, to host sockets
/// in an extra read-write and an extra read-only grant, to a host abstract
/// name, and to a host peer that hands out a descriptor with SCM_RIGHTS;
/// and one connect to the authorized proxy. Verdict: every host peer is
/// refused (EACCES for pathnames, ECONNREFUSED for the abstract name, which
/// is not in the attempt's namespace) and none of them ever saw a
/// connection, so no descriptor could be passed; the proxy connect alone
/// succeeds; each refusal is an audit `fs.deny` for `net.connect`.
#[test]
fn n05_host_peers_existing_late_aliased_and_in_every_grant_are_unreachable() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    write_launch_profile(&c.jail, "n05state", STATE_PROFILE);
    let ws = c.workspace.clone();
    let extra_rw = c.jail.root().join("extra-rw");
    let extra_ro = c.jail.root().join("extra-ro");
    private_dir(&extra_rw);
    private_dir(&extra_ro);
    let host = UnixProbe::bind(&ws.join("host.sock")).unwrap();
    let host_seq = UnixProbe::bind_kind(&ws.join("host-seq.sock"), ProbeKind::Seqpacket).unwrap();
    std::fs::hard_link(ws.join("host.sock"), ws.join("alias.sock")).unwrap();
    std::os::unix::fs::symlink(ws.join("host.sock"), ws.join("sym.sock")).unwrap();
    let rw = UnixProbe::bind(&extra_rw.join("extra.sock")).unwrap();
    let ro = UnixProbe::bind(&extra_ro.join("ro.sock")).unwrap();
    let abstract_name = format!("ouro-j3-agent-host-{}", std::process::id());
    let host_abstract =
        UnixProbe::bind_abstract(abstract_name.as_bytes(), ProbeKind::Stream).unwrap();
    fixture_file(&c.jail.root().join("gift.txt"), b"a host descriptor");
    let scm = ScmHost::start(&ws.join("scm-host.sock"), &c.jail.root().join("gift.txt"));

    let pathnames = [
        ws.join("host.sock"),
        ws.join("alias.sock"),
        ws.join("sym.sock"),
        ws.join("late.sock"),
        PathBuf::from("/tmp/late.sock"),
        PathBuf::from("/run/ouro/state/late.sock"),
        extra_rw.join("extra.sock"),
        extra_ro.join("ro.sock"),
        ws.join("scm-host.sock"),
    ];
    let mut steps: Vec<Value> = pathnames
        .iter()
        .map(|path| serde_json::json!(["unix-connect", path, "--expect", "EACCES"]))
        .collect();
    steps.push(serde_json::json!([
        "unix-connect",
        ws.join("host.sock"),
        "--len",
        "exact",
        "--expect",
        "EACCES"
    ]));
    steps.push(serde_json::json!([
        "unix-connect",
        ws.join("host.sock"),
        "--len",
        "full",
        "--expect",
        "EACCES"
    ]));
    steps.push(serde_json::json!([
        "unix-connect",
        "host.sock",
        "--expect",
        "EACCES"
    ]));
    steps.push(serde_json::json!([
        "unix-connect",
        ws.join("host-seq.sock"),
        "--seqpacket",
        "--expect",
        "EACCES"
    ]));
    steps.push(serde_json::json!([
        "unix-abstract-connect",
        abstract_name,
        "--expect",
        "ECONNREFUSED"
    ]));
    steps.push(serde_json::json!([
        "unix-connect",
        "/run/ouro/proxy/proxy.sock"
    ]));
    let argv = c.script("n05-host", &Value::Array(steps.clone()));
    let mut spawned = c
        .jail
        .args(["--launch", "n05state"])
        .args(["--rw", extra_rw.to_str().unwrap()])
        .args(["--ro", extra_ro.to_str().unwrap()])
        .gate()
        .receipt()
        .target(argv)
        .spawn()
        .unwrap();
    let (message, receipt) = prepared(&mut spawned);
    // Created now, after the boundary and its mounts exist: no enumeration
    // at launch could have covered them.
    let attempt = attempt_of(&spawned.root().join("data"));
    let late = [
        UnixProbe::bind(&ws.join("late.sock")).unwrap(),
        UnixProbe::bind(&attempt.join("scratch/late.sock")).unwrap(),
        UnixProbe::bind(&attempt.join("vendor-state/late.sock")).unwrap(),
    ];
    release(&mut spawned, &message, &receipt);
    let run = spawned.wait().unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout_text(),
        run.stderr_text()
    );
    for (label, count) in [
        ("host", host.stop()),
        ("host-seq", host_seq.stop()),
        ("extra-rw", rw.stop()),
        ("extra-ro", ro.stop()),
        ("host-abstract", host_abstract.stop()),
        ("scm-host", scm.stop()),
    ] {
        assert_eq!(count, 0, "the host peer {label} was reached");
    }
    for probe in late {
        assert_eq!(probe.stop(), 0, "a late host socket was reached");
    }
    let lines = run.fixture_lines();
    let connects = ops(&lines, "connect");
    assert_eq!(
        connects.last().unwrap()["errno"],
        Value::Null,
        "the authorized proxy"
    );
    let receipt = settled(&run);
    let denials: Vec<&Value> = mediated(&run)
        .into_iter()
        .filter(|event| event["operation"] == "fs.deny")
        .collect();
    assert_eq!(
        denials.len(),
        13,
        "one audit fs.deny per refused pathname: {denials:#?}"
    );
    for denial in denials {
        assert_eq!(denial["fields"]["attempted_operation"], "net.connect");
        assert_eq!(denial["fields"]["address_family"], 1);
        assert_eq!(denial["outcome"]["errno"], "EACCES");
    }
    assert_eq!(receipt["phase"], "settled");
}

/// N05, same-attempt IPC. Attempted: a listener the child binds in scratch
/// and one in the workspace (a shared root), each reached by a second child
/// (stream and seqpacket); an abstract name bound and reached inside; a
/// descriptor passed with SCM_RIGHTS between two attempt processes; and
/// datagram AF_UNIX sockets in every spelling. Verdict: every same-attempt
/// exchange succeeds and the descriptor arrives; datagram creation is EPERM.
#[test]
fn n05_same_attempt_ipc_and_scm_rights_work_and_datagram_sockets_are_refused() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    let fixture = c.fixture.to_string_lossy().into_owned();
    let ws = c.workspace.clone();
    fixture_file(&ws.join("payload.txt"), b"passed between attempt processes");
    let steps = serde_json::json!([
        [
            "unix-listen",
            "/tmp/ipc.sock",
            "--accept",
            "1",
            "--",
            fixture,
            "unix-connect",
            "/tmp/ipc.sock",
            "--exchange"
        ],
        [
            "unix-listen",
            "/tmp/ipc-seq.sock",
            "--seqpacket",
            "--accept",
            "1",
            "--",
            fixture,
            "unix-connect",
            "/tmp/ipc-seq.sock",
            "--seqpacket",
            "--exchange"
        ],
        [
            "unix-listen",
            ws.join("ws-ipc.sock"),
            "--accept",
            "1",
            "--",
            fixture,
            "unix-connect",
            ws.join("ws-ipc.sock"),
            "--exchange"
        ],
        [
            "scm-recv",
            "/tmp/scm.sock",
            "--",
            fixture,
            "scm-send",
            "/tmp/scm.sock",
            ws.join("payload.txt")
        ],
        ["unix-socket-dgram", "--expect", "EPERM"],
        ["unix-socket-dgram", "--raw", "--expect", "EPERM"],
        [
            "unix-socket-dgram",
            "--cloexec",
            "--nonblock",
            "--expect",
            "EPERM"
        ],
        ["unix-socketpair-dgram", "--expect", "EPERM"],
        [
            "unix-socketpair-dgram",
            "--raw",
            "--cloexec",
            "--expect",
            "EPERM"
        ]
    ]);
    const ABSTRACT: &str = r#"
import json, socket
l = socket.socket(socket.AF_UNIX)
l.bind("\0ouro-attempt-abstract")
l.listen(1)
c = socket.socket(socket.AF_UNIX)
c.connect("\0ouro-attempt-abstract")
a, _ = l.accept()
c.sendall(b"x")
print(json.dumps({"abstract": a.recv(1).decode()}))
"#;
    let argv = c.script("n05-ipc", &steps);
    let shell = format!(
        "{} && /usr/bin/python3 -c '{}'",
        argv.iter()
            .map(|part| part.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        ABSTRACT
    );
    let run = c
        .jail
        .target(["/bin/sh", "-c", shell.as_str()])
        .run()
        .unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout_text(),
        run.stderr_text()
    );
    let lines = run.fixture_lines();
    let exchanges = ops(&lines, "exchange");
    assert_eq!(exchanges.len(), 3, "{lines:#?}");
    for exchange in exchanges {
        assert!(exchange["errno"].is_null(), "{exchange}");
    }
    let received = ops(&lines, "recvmsg");
    assert_eq!(received.len(), 1, "{lines:#?}");
    assert_eq!(received[0]["args"]["fds_received"], 1, "{}", received[0]);
    let kinds: Vec<&Value> = ops(&lines, "fstat")
        .iter()
        .map(|op| &op["args"]["kind"])
        .collect();
    assert!(kinds.iter().any(|kind| *kind == "regular"), "{kinds:?}");
    assert_eq!(py_out(&run)["abstract"], "x");
    let datagrams: Vec<&Value> = ops(&lines, "socket")
        .into_iter()
        .chain(ops(&lines, "socketpair"))
        .filter(|op| {
            op["args"]["family"] == "AF_UNIX"
                && matches!(op["args"]["type"].as_str(), Some("SOCK_DGRAM" | "SOCK_RAW"))
        })
        .collect();
    assert_eq!(datagrams.len(), 5, "{lines:#?}");
    for socket in datagrams {
        assert_eq!(socket["errno"], "EPERM", "{socket}");
    }
    settled(&run);
}

/// N05, proxy replacement before the first connect. Attempted: after
/// `prepared`, the operator-side proxy socket is renamed away and a rogue
/// listener bound at its path; then the target makes a request through the
/// bridge and connects to the proxy socket directly. Verdict: both are
/// refused by identity (the node at the path is not the pinned one), the
/// rogue listener never sees a connection, and the replaced directory is
/// retained and reported rather than emptied by name.
#[test]
fn n05_a_proxy_replaced_before_the_first_connect_is_never_reached() {
    if !common::live() {
        return;
    }
    let origin = HttpServer::start(b"never".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let steps = serde_json::json!([
        [
            "http-get",
            format!("http://127.0.0.1:{o}/x"),
            "--timeout-ms",
            "3000",
            "--expect",
            "any"
        ],
        [
            "unix-connect",
            "/run/ouro/proxy/proxy.sock",
            "--expect",
            "EACCES"
        ]
    ]);
    let argv = c.script("n05-replace-before", &steps);
    let mut spawned = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .gate()
        .receipt()
        .target(argv)
        .spawn()
        .unwrap();
    let (message, receipt) = prepared(&mut spawned);
    let proxy_dir = attempt_of(&spawned.root().join("data")).join("proxy");
    std::fs::rename(
        proxy_dir.join("proxy.sock"),
        proxy_dir.join("proxy.sock.orig"),
    )
    .unwrap();
    let rogue = UnixProbe::bind(&proxy_dir.join("proxy.sock")).unwrap();
    release(&mut spawned, &message, &receipt);
    let run = spawned.wait().unwrap();
    assert_eq!(
        run.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout_text(),
        run.stderr_text()
    );
    assert!(
        proxy_dir.join("proxy.sock").exists(),
        "the jail removes only the socket node it bound, never a replacement"
    );
    assert_eq!(rogue.stop(), 0, "the replacement was reached");
    assert_eq!(origin.stop().len(), 0);
    let get = ops(&run.fixture_lines(), "http-get")[0].clone();
    assert!(get["args"]["status_code"].is_null(), "{get}");
    let receipt = settled(&run);
    let errors = receipt["errors"].to_string();
    assert!(errors.contains("proxy directory was retained"), "{errors}");
    assert!(
        proxy_dir.join("proxy.sock.orig").exists(),
        "never deleted by name"
    );
    let denial = mediated(&run)
        .into_iter()
        .find(|event| event["fields"]["address_family"] == 1)
        .expect("the direct connect is an audit result");
    assert_eq!(denial["operation"], "fs.deny");
}

/// Reads one line from a FIFO the target writes, bounded.
fn await_fifo(path: &Path) -> String {
    let path = path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::fs::File::open(path).and_then(|mut file| file.read_to_string(&mut text));
        let _ = tx.send(text);
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("the target reached its synchronization point")
}

fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a NUL-terminated path; mkfifo creates a node or fails.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

/// N05, proxy replacement after the first connect. Attempted: the target
/// makes one request through the bridge, signals through a FIFO, and waits;
/// the operator-side socket is then replaced by a rogue listener; the target
/// makes a second request and a direct connect. Verdict: the first request
/// succeeds; after the replacement both paths are refused and the rogue
/// never sees a connection: the bridge does not reconnect through an
/// unvalidated replacement.
#[test]
fn n05_a_proxy_replaced_after_the_first_connect_is_never_reached() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import json, socket, sys, urllib.request
url, ready, go = sys.argv[1], sys.argv[2], sys.argv[3]
def get():
    try:
        return urllib.request.urlopen(url, timeout=5).status
    except Exception as e:
        return type(e).__name__
out = {"first": get()}
open(ready, "w").write("first done\n")
open(go).read()
out["second"] = get()
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("/run/ouro/proxy/proxy.sock")
    out["direct"] = "ok"
except OSError as e:
    out["direct"] = e.errno
print(json.dumps(out))
"#;
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let (ready, go) = (c.workspace.join("ready.fifo"), c.workspace.join("go.fifo"));
    mkfifo(&ready);
    mkfifo(&go);
    let url = format!("http://127.0.0.1:{o}/x");
    let spawned = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .target(py(
            SCRIPT,
            &[&url, ready.to_str().unwrap(), go.to_str().unwrap()],
        ))
        .spawn()
        .unwrap();
    assert_eq!(await_fifo(&ready), "first done\n");
    let proxy_dir = attempt_of(&spawned.root().join("data")).join("proxy");
    std::fs::rename(
        proxy_dir.join("proxy.sock"),
        proxy_dir.join("proxy.sock.orig"),
    )
    .unwrap();
    let rogue = UnixProbe::bind(&proxy_dir.join("proxy.sock")).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&go)
        .unwrap()
        .write_all(b"go\n")
        .unwrap();
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    assert_eq!(out["first"], 200, "{out}");
    assert_ne!(out["second"], 200, "{out}");
    assert_eq!(out["direct"], libc::EACCES, "{out}");
    assert_eq!(rogue.stop(), 0, "the replacement was reached");
    assert_eq!(origin.stop().len(), 1, "only the first request");
    settled(&run);
}

/// N05, the bridge's view under child path and mount changes. Attempted by
/// the target: rename, unlink and replace the proxy socket, plant a symlink
/// and a directory in the proxy directory, bind a directory over it and
/// unmount it; then a request through the bridge. Verdict: every change
/// fails (EROFS for the read-only directory, and the mount calls fail) and
/// the request succeeds: nothing the child can do redirects the bridge.
#[test]
fn n05_child_path_and_mount_changes_cannot_redirect_the_bridge() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import errno, json, os, socket, subprocess, sys, urllib.request
out = {}
def attempt(label, fn):
    try:
        fn()
        out[label] = "ok"
    except OSError as e:
        out[label] = errno.errorcode[e.errno]
d = "/run/ouro/proxy"
attempt("rename", lambda: os.rename(d + "/proxy.sock", d + "/moved.sock"))
attempt("unlink", lambda: os.unlink(d + "/proxy.sock"))
attempt("symlink", lambda: os.symlink("/tmp/evil.sock", d + "/evil.sock"))
attempt("mkdir", lambda: os.mkdir(d + "/sub"))
def rebind():
    s = socket.socket(socket.AF_UNIX)
    s.bind(d + "/proxy.sock")
attempt("bind_replacement", rebind)
for label, argv in [("mount_over", ["/usr/bin/mount", "--bind", "/tmp", d]),
                    ("umount", ["/usr/bin/umount", d])]:
    out[label] = subprocess.run(argv, capture_output=True).returncode
out["listing"] = sorted(os.listdir(d))
out["get"] = urllib.request.urlopen(sys.argv[1], timeout=5).status
print(json.dumps(out))
"#;
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let url = format!("http://127.0.0.1:{o}/after");
    let run = c
        .jail
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .target(py(SCRIPT, &[&url]))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    for label in ["rename", "unlink", "symlink", "mkdir"] {
        assert_eq!(out[label], "EROFS", "{label}: {out}");
    }
    assert_eq!(out["bind_replacement"], "EADDRINUSE", "{out}");
    assert_ne!(out["mount_over"], 0, "{out}");
    assert_ne!(out["umount"], 0, "{out}");
    assert_eq!(out["listing"], serde_json::json!(["proxy.sock"]));
    assert_eq!(out["get"], 200, "{out}");
    assert_eq!(origin.stop().len(), 1);
    settled(&run);
}

// ===========================================================================
// C01: both credential modes through `run`, with an `agent` launch profile
// ===========================================================================

/// C01, the live `run` half. Attempted: an `agent` launch profile staging a
/// `copy_rw` token and a `bind_ro` config (fixture credentials only), with a
/// network grant of its own; the target reads both, writes both, and makes a
/// request allowed only by the profile's grant. Verdict: the copy is a
/// private writable copy (the source is unchanged), the view is the exact
/// source read-only; the receipt carries logical ids, modes, the copy's
/// digest of the source bytes and a null digest with a reason for the view,
/// and no path or byte of either; the profile's grant reaches the proxy;
/// vendor state is removed at settlement.
#[test]
fn c01_an_agent_launch_profile_stages_both_credential_modes_through_run() {
    if !common::live() {
        return;
    }
    const SCRIPT: &str = r#"
import errno, json, os, sys, urllib.request
home = os.environ["C01_HOME"]
out = {"home": home}
out["auth"] = open(home + "/auth.json").read()
out["config"] = open(home + "/conf/config.toml").read()
open(home + "/auth.json", "w").write("refreshed inside the attempt")
out["auth_after"] = open(home + "/auth.json").read()
try:
    open(home + "/conf/config.toml", "w").write("x")
    out["config_write"] = "ok"
except OSError as e:
    out["config_write"] = errno.errorcode[e.errno]
out["get"] = urllib.request.urlopen(sys.argv[1], timeout=5).status
out["run_ouro"] = sorted(os.listdir("/run/ouro"))
print(json.dumps(out))
"#;
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let creds = c.jail.root().join("creds");
    private_dir(&creds);
    fixture_file(&creds.join("auth.json"), b"fixture-token-copy");
    fixture_file(&creds.join("config.toml"), b"fixture = \"config\"\n");
    let profile = format!(
        "name = \"c01agent\"\njail = \"agent\"\nstate_var = \"C01_HOME\"\n\
         state_subdirs = [\"conf\"]\n\n\
         [credentials.auth]\nsource = \"{}\"\ndest = \"auth.json\"\nmode = \"copy_rw\"\n\n\
         [credentials.config]\nsource = \"{}\"\ndest = \"conf/config.toml\"\nmode = \"bind_ro\"\n\n\
         [network]\nallow = [\"127.0.0.1:{o}\"]\n",
        creds.join("auth.json").display(),
        creds.join("config.toml").display()
    );
    write_launch_profile(&c.jail, "c01agent", &profile);
    let url = format!("http://127.0.0.1:{o}/via-launch-grant");
    let run = c
        .jail
        .args(["--launch", "c01agent"])
        .target(py(SCRIPT, &[&url]))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let out = py_out(&run);
    assert_eq!(out["home"], "/run/ouro/state");
    assert_eq!(out["auth"], "fixture-token-copy");
    assert_eq!(out["config"], "fixture = \"config\"\n");
    assert_eq!(out["auth_after"], "refreshed inside the attempt");
    assert_eq!(out["config_write"], "EROFS");
    assert_eq!(out["get"], 200);
    assert_eq!(
        out["run_ouro"],
        serde_json::json!(["jail", "proxy", "state"])
    );
    assert_eq!(
        std::fs::read(creds.join("auth.json")).unwrap(),
        b"fixture-token-copy"
    );
    assert_eq!(
        std::fs::read(creds.join("config.toml")).unwrap(),
        b"fixture = \"config\"\n"
    );
    assert_eq!(origin.stop().len(), 1);

    let receipt = settled(&run);
    let credentials = receipt["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 2, "{credentials:#?}");
    let auth = credentials.iter().find(|row| row["id"] == "auth").unwrap();
    let config = credentials
        .iter()
        .find(|row| row["id"] == "config")
        .unwrap();
    assert_eq!(auth["mode"], "copy_rw");
    let expected = {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(b"fixture-token-copy");
        format!(
            "sha256:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    assert_eq!(auth["digest"], expected.as_str());
    assert!(auth["digest_unavailable_reason"].is_null());
    assert_eq!(config["mode"], "bind_ro");
    assert!(
        config["digest"].is_null(),
        "a writable source is never stable"
    );
    assert!(config["digest_unavailable_reason"].is_string());
    let text = receipt.to_string();
    for secret in ["fixture-token-copy", "creds/auth.json", "creds/config.toml"] {
        assert!(!text.contains(secret), "{secret} reached the receipt");
    }
    assert_eq!(
        receipt["applied"]["network"]["allowed_hosts"],
        serde_json::json!([format!("127.0.0.1:{o}")])
    );
    assert_eq!(receipt["state_cleanup"], "complete");
}

// ===========================================================================
// X06 for `agent`, and the J2 filter-count gap
// ===========================================================================

/// X06 for `agent`. Attempted: while the target is still blocked, the
/// launcher's and the bridge's descriptor tables are read from outside; the
/// released target then lists its own descriptors, status and environment.
/// Verdict: before release the launcher holds the mediation listener and the
/// sock_diag socket (the supervisor took copies of both) and the bridge holds
/// only /dev/null stdio and its one listening socket; after release the
/// target holds exactly 0/1/2, no notification listener, no sock_diag, proxy
/// or bridge socket; it has no capability, runs under the three filters, is
/// not traced visibly, and its environment has the proxy variables, no
/// `OURO_*`, and matches the receipt's names.
#[test]
fn x06_no_notification_sockdiag_proxy_or_bridge_descriptor_reaches_the_target() {
    if !common::live() {
        return;
    }
    let c = case("agent");
    let steps = serde_json::json!([["fds"], ["status"], ["env"]]);
    let argv = c.script("x06", &steps);
    let mut spawned = c.jail.gate().receipt().target(argv).spawn().unwrap();
    let (message, receipt) = prepared(&mut spawned);
    let native = details(&receipt);
    let launcher = native["launcher_pid"].as_i64().unwrap();
    let launcher_fds = readlinks(launcher);
    assert_eq!(
        launcher_fds.get(&18).map(String::as_str),
        Some("anon_inode:seccomp notify"),
        "{launcher_fds:?}"
    );
    assert!(
        launcher_fds
            .get(&19)
            .is_some_and(|link| link.starts_with("socket:"))
    );
    let bridge = native["helpers"][0]["pid"].as_i64().unwrap();
    assert_eq!(native["helpers"][0]["kind"], "bridge");
    assert_eq!(native["helpers"][0]["seccomp_filters"], 2);
    let bridge_fds = readlinks(bridge);
    for fd in 0..3 {
        assert_eq!(
            bridge_fds.get(&fd).map(String::as_str),
            Some("/dev/null"),
            "{bridge_fds:?}"
        );
    }
    let others: Vec<&String> = bridge_fds
        .iter()
        .filter(|(fd, _)| **fd > 2)
        .map(|(_, link)| link)
        .collect();
    assert_eq!(others.len(), 1, "only the listening socket: {bridge_fds:?}");
    assert!(others[0].starts_with("socket:"));
    let helpers = &native["execution_cgroup"]["charged_helpers"];
    assert!(
        helpers
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["role"] == "bridge" && h["pid"] == bridge),
        "{helpers}"
    );
    release(&mut spawned, &message, &receipt);
    let run = spawned.wait().unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let lines = run.fixture_lines();
    let fds: Vec<i64> = ops(&lines, "fds")[0]["args"]["fds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["fd"].as_i64().unwrap())
        .collect();
    assert_eq!(fds, [0, 1, 2], "{lines:#?}");
    // The proxy raises the supervisor's descriptor limit only after the
    // backend is spawned: the target keeps the limit it was started with.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a live rlimit.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) },
        0
    );
    assert_eq!(
        ops(&lines, "fds")[0]["args"]["soft_limit"],
        limit.rlim_cur,
        "the target inherited a raised descriptor limit"
    );
    let status = &ops(&lines, "status")[0]["args"]["fields"];
    assert_eq!(status["NoNewPrivs"], "1");
    assert_eq!(status["Seccomp"], "2");
    assert_eq!(status["Seccomp_filters"], "3");
    assert_eq!(status["TracerPid"], "0");
    assert!(
        status["CapEff"]
            .as_str()
            .unwrap()
            .chars()
            .all(|ch| ch == '0')
    );
    let names: Vec<String> = ops(&lines, "env")[0]["args"]["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect();
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        assert!(
            names.iter().any(|n| n == name),
            "{name} missing from {names:?}"
        );
    }
    assert!(
        names.iter().all(|name| !name.starts_with("OURO_")),
        "{names:?}"
    );
    let settled_receipt = settled(&run);
    let mut recorded: Vec<String> = settled_receipt["applied"]["environment_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect();
    let mut seen = names.clone();
    recorded.sort();
    seen.sort();
    assert_eq!(seen, recorded);
    assert!(
        !std::path::Path::new(&format!("/proc/{bridge}")).exists(),
        "the bridge died with the attempt"
    );
}

/// The J2 gap the `none` slice found, closed for every contained profile:
/// the launcher's `Seccomp_filters` is read back and checked against what the
/// boundary installs, and the receipt says what was expected and observed.
/// Attempted: `tool` with observation on and off, and `agent` with
/// observation off (on is covered above). Verdict: 2, 1 and 2.
#[test]
fn every_contained_profile_reads_back_its_filter_count() {
    if !common::live() {
        return;
    }
    for (profile, observe, expected) in [("tool", "on", 2), ("tool", "off", 1), ("agent", "off", 2)]
    {
        let c = case(profile);
        // Alive long enough for the observation-off backend to read back
        // the exec transition (a fast exit honestly stays unknown there).
        let target = [
            c.fixture.clone().into_os_string(),
            "sleep".into(),
            "300".into(),
        ];
        let run = c
            .jail
            .args(["--observe", observe])
            .receipt()
            .target(target)
            .run()
            .unwrap();
        assert_eq!(
            run.code(),
            Some(0),
            "{profile}/{observe}: {}",
            run.stderr_text()
        );
        let receipt = settled(&run);
        let filters = &details(&receipt)["seccomp_filters"];
        assert_eq!(
            filters["expected"], expected,
            "{profile}/{observe}: {filters}"
        );
        assert_eq!(
            filters["observed"], expected,
            "{profile}/{observe}: {filters}"
        );
    }
}

/// O05 for `agent`: observation off leaves the proxy's own facts. Attempted:
/// one allowed request with `--observe off`. Verdict: no audit event at all,
/// every audit class unsupported with a null count, and `proxy.net` active
/// with the one proxy result.
#[test]
fn agent_observation_off_keeps_only_the_proxy_facts() {
    if !common::live() {
        return;
    }
    let origin = HttpServer::start(b"ok".to_vec()).unwrap();
    let o = origin.addr().port();
    let c = case("agent");
    let steps = serde_json::json!([
        ["http-get", format!("http://127.0.0.1:{o}/off")],
        ["sleep", "300"]
    ]);
    let argv = c.script("o05", &steps);
    let run = c
        .jail
        .args(["--observe", "off"])
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{o}"))
        .target(argv)
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "stderr: {}", run.stderr_text());
    let receipt = settled(&run);
    assert!(events(&run, "audit").is_empty());
    assert_eq!(events(&run, "proxy").len(), 1);
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        assert_eq!(
            receipt["coverage"][class]["status"], "unsupported",
            "{class}"
        );
        assert!(receipt["coverage"][class]["observed_count"].is_null());
    }
    assert_eq!(receipt["coverage"]["proxy.net"]["status"], "active");
    assert_eq!(receipt["coverage"]["proxy.net"]["observed_count"], 1);
    assert_eq!(origin.stop().len(), 1);
}

/// `agent` refuses (125) when it cannot establish its proxy, naming it.
/// Attempted: a run whose descriptor limit cannot hold the proxy's §10
/// budget (the hard limit lowered for this one process). Verdict: exit 125,
/// a refused receipt whose error names the proxy, the target never ran, and
/// the proxy directory is gone.
#[test]
fn agent_refuses_naming_the_proxy_it_cannot_establish() {
    if !common::live() {
        return;
    }
    let jail = Jail::with_program("/bin/sh").unwrap();
    let workspace = jail.root().join("workspace");
    private_dir(&workspace);
    let marker = workspace.join("ran");
    let run = jail
        .arg("-c")
        // 300 descriptors: enough for the backend's descriptor map (its
        // sources live at 256 and above), not for the proxy's 128 x 2 + 64.
        .arg("ulimit -n 300 && exec \"$0\" \"$@\"")
        .arg(harness::jail_path())
        .arg("run")
        // Without the observer, whose own probe needs descriptors too: this
        // test is about the proxy's budget, which preparation checks.
        .args(["--profile", "agent", "--observe", "off", "--workspace"])
        .arg(&workspace)
        .receipt()
        .target(["/usr/bin/touch", marker.to_str().unwrap()])
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(125), "stderr: {}", run.stderr_text());
    assert!(!marker.exists(), "the target ran");
    let receipt = run.receipt_phase("refused").expect("a refused receipt");
    let error = receipt["outcome"]["error"].to_string();
    assert!(
        error.contains("`agent` proxy could not be established"),
        "{error}"
    );
    assert!(!attempt_of(&run.data_dir).join("proxy").exists());
}
