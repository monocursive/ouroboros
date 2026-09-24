//! The `agent` doctor probes (jail-v1 §14.1): proxy and bridge connectivity
//! with an allowed and a denied destination and direct-egress rejection; the
//! unix-peer mediation (a host socket denied, an attempt socket allowed); and
//! the scripted inner sandbox (Landlock and seccomp) with attempted
//! outer-boundary reversal.
//!
//! "Measured, never assumed": the probe is one real `ouro-jail run --profile
//! agent` of this binary, with private state, a loopback origin this process
//! serves, a host socket this process binds, and `__probe-inside` as the
//! target, whose checks below report each raw result. The three rows are
//! read from that one run, which is performed once per doctor invocation.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::{OwnedTempDir, ProbeResult, ProbeStatus};
use crate::platform::linux::clock::Deadline;
use crate::platform::linux::sys::errno_name;

/// The agent probe's own deadline: one full `agent` run, which itself
/// measures `nested_user_namespace` (§9.2). §14.1's per-probe 5 seconds
/// applies to each of the three rows it answers.
const AGENT_PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// A path inside the sandbox whose read and write the inner sandbox denies.
const PROTECTED_NAME: &str = "protected.txt";

/// What the one agent run established.
#[derive(Clone, Debug)]
pub struct AgentProbe {
    /// Why the run itself failed, when it did.
    pub failure: Option<String>,
    /// Each `label=value` line the inside checks reported.
    pub lines: BTreeMap<String, String>,
    /// Connections the loopback origin accepted.
    pub origin_hits: usize,
    /// Connections that reached the denied destination's listener.
    pub denied_hits: usize,
    /// Connections that reached the host socket.
    pub host_hits: usize,
    /// The proxy-source results in the run's trace: (decision, reason).
    pub proxy_results: Vec<(String, String)>,
    /// The receipt's `agent` native details.
    pub agent_details: Option<serde_json::Value>,
}

impl AgentProbe {
    fn line(&self, label: &str) -> &str {
        self.lines.get(label).map_or("unreported", String::as_str)
    }
}

/// The run, once per process.
pub fn agent_probe(jail_exe: &Path) -> &'static AgentProbe {
    static ONCE: OnceLock<AgentProbe> = OnceLock::new();
    ONCE.get_or_init(|| run(jail_exe))
}

/// A loopback listener serving `HTTP/1.1 200` to each connection until
/// stopped, counting them.
struct Origin {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Origin {
    fn start(respond: bool) -> io::Result<Origin> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (h, s) = (Arc::clone(&hits), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        h.fetch_add(1, Ordering::SeqCst);
                        if respond {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let mut head = [0u8; 2048];
                            let _ = stream.read(&mut head);
                            let _ = stream.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            );
                        }
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Ok(Origin {
            port,
            hits,
            stop,
            thread: Some(thread),
        })
    }

    fn finish(mut self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.hits.load(Ordering::SeqCst)
    }
}

fn failed(reason: impl Into<String>) -> AgentProbe {
    AgentProbe {
        failure: Some(reason.into()),
        lines: BTreeMap::new(),
        origin_hits: 0,
        denied_hits: 0,
        host_hits: 0,
        proxy_results: Vec::new(),
        agent_details: None,
    }
}

fn private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

fn run(jail_exe: &Path) -> AgentProbe {
    let root = match OwnedTempDir::new("probe-agent") {
        Ok(root) => root,
        Err(error) => return failed(format!("temporary directory: {error}")),
    };
    let data = root.path.join("data");
    let config = root.path.join("config");
    let workspace = root.path.join("ws");
    for dir in [&data, &config, &workspace] {
        if let Err(error) = private_dir(dir) {
            return failed(format!("{}: {error}", dir.display()));
        }
    }
    if let Err(error) = std::fs::write(workspace.join(PROTECTED_NAME), b"outside the inner grant") {
        return failed(format!("protected fixture: {error}"));
    }
    let (origin, denied) = match (Origin::start(true), Origin::start(false)) {
        (Ok(origin), Ok(denied)) => (origin, denied),
        (Err(error), _) | (_, Err(error)) => return failed(format!("loopback origin: {error}")),
    };
    let host_socket = workspace.join("host.sock");
    let host = match UnixListener::bind(&host_socket) {
        Ok(host) => host,
        Err(error) => return failed(format!("host socket: {error}")),
    };
    let _ = host.set_nonblocking(true);

    let receipt = root.path.join("receipt.json");
    let inside = |check: &str| check.to_owned();
    let checks = [
        inside(&format!("allowed=http:{}", origin.port)),
        inside(&format!("denied=http:{}", denied.port)),
        inside("egress=tcp:10.255.255.1:80"),
        inside(&format!("host_unix=unix:{}", host_socket.display())),
        inside("attempt_unix=unix-self:/tmp/attempt.sock"),
        inside(&format!(
            "inner=inner:{}",
            workspace.join(PROTECTED_NAME).display()
        )),
    ];
    // Observation stays on, as in a default run: the observer is what
    // confirms the target's exec here, because the target is this same
    // binary and an unchanged executable image proves nothing.
    let mut command = Command::new(jail_exe);
    command
        .arg("run")
        .arg("--profile")
        .arg("agent")
        .arg("--workspace")
        .arg(&workspace)
        .arg("--allow-host")
        .arg(format!("127.0.0.1:{}", origin.port))
        .arg("--limit")
        .arg("wall=10s")
        .arg("--receipt")
        .arg(&receipt)
        .arg("--")
        .arg(super::bwrap::JAIL_INSIDE_PATH)
        .arg(super::INSIDE_SUBCOMMAND)
        .args(&checks)
        .env("OURO_DATA_DIR", &data)
        .env("OURO_CONFIG_DIR", &config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The probe's run is doctor's fixture (§14.1): if doctor dies, the run's
    // supervisor dies with it and takes its jail down as any killed
    // supervisor does, instead of running on to its wall limit on pid 1.
    super::exec::die_with_parent(&mut command);
    let captured = super::exec::run_captured(&mut command, Deadline::after(AGENT_PROBE_DEADLINE));
    let origin_hits = origin.finish();
    let denied_hits = denied.finish();
    let mut host_hits = 0;
    while host.accept().is_ok() {
        host_hits += 1;
    }
    let captured = match captured {
        Ok(captured) => captured,
        Err(error) => return failed(format!("the agent run could not start: {error}")),
    };
    if captured.timed_out {
        return failed("the agent run exceeded its deadline");
    }
    if captured.code() != Some(0) {
        return failed(format!(
            "the agent run exited {:?}: {}",
            captured.code(),
            captured.stderr.lines().last().unwrap_or("")
        ));
    }
    let lines = captured
        .stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let receipt: Option<serde_json::Value> = std::fs::read(&receipt)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let agent_details = receipt
        .as_ref()
        .and_then(|receipt| receipt.pointer("/lifetime/native/details/agent"))
        .cloned();
    AgentProbe {
        failure: None,
        lines,
        origin_hits,
        denied_hits,
        host_hits,
        proxy_results: proxy_results(&data),
        agent_details,
    }
}

/// The proxy-source results in the one attempt's trace.
fn proxy_results(data: &Path) -> Vec<(String, String)> {
    let Ok(attempts) = std::fs::read_dir(data.join("attempts")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for attempt in attempts.flatten() {
        let Ok(trace) = std::fs::read_to_string(attempt.path().join("trace.ndjson")) else {
            continue;
        };
        for line in trace.lines() {
            let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if event["source"] == "proxy" {
                out.push((
                    event["decision"].as_str().unwrap_or("").to_owned(),
                    event["fields"]["reason"].as_str().unwrap_or("").to_owned(),
                ));
            }
        }
    }
    out
}

/// `agent_proxy_bridge`.
#[must_use]
pub fn proxy_bridge(jail_exe: &Path) -> ProbeResult {
    const NAME: &str = "agent_proxy_bridge";
    const MECHANISM: &str = "outside-http-proxy+loopback-bridge";
    let probe = agent_probe(jail_exe);
    if let Some(failure) = &probe.failure {
        return ProbeResult::error(NAME, MECHANISM, failure.clone());
    }
    let allowed = probe.line("allowed");
    let denied = probe.line("denied");
    let egress = probe.line("egress");
    let proxy_allow = probe
        .proxy_results
        .iter()
        .any(|(decision, reason)| decision == "allow" && reason == "relayed");
    let proxy_deny = probe
        .proxy_results
        .iter()
        .any(|(decision, reason)| decision == "deny" && reason == "host_not_allowed");
    let evidence = format!(
        "through 127.0.0.1:3128: allowed destination {allowed} ({} origin connection(s)), \
         denied destination {denied} ({} connection(s) reached it); direct TCP egress {egress}; \
         proxy results allow/relayed {proxy_allow}, deny/host_not_allowed {proxy_deny}",
        probe.origin_hits, probe.denied_hits
    );
    let ok = allowed == "200"
        && denied == "403"
        && egress == "ENETUNREACH"
        && probe.origin_hits >= 1
        && probe.denied_hits == 0
        && proxy_allow
        && proxy_deny;
    if ok {
        ProbeResult::new(NAME, ProbeStatus::Available, MECHANISM, "ok", evidence)
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "proxy_path_unproven",
            evidence,
        )
    }
}

/// `agent_unix_peer_mediation`.
#[must_use]
pub fn unix_peer(jail_exe: &Path) -> ProbeResult {
    const NAME: &str = "agent_unix_peer_mediation";
    const MECHANISM: &str = "seccomp-user-notification";
    let probe = agent_probe(jail_exe);
    if let Some(failure) = &probe.failure {
        return ProbeResult::error(NAME, MECHANISM, failure.clone());
    }
    let host = probe.line("host_unix");
    let attempt = probe.line("attempt_unix");
    let evidence = format!(
        "a host socket in the workspace: connect {host} ({} connection(s) reached it); \
         an attempt-bound socket: connect {attempt}",
        probe.host_hits
    );
    if host == "EACCES" && probe.host_hits == 0 && attempt == "ok" {
        ProbeResult::new(NAME, ProbeStatus::Available, MECHANISM, "ok", evidence)
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "host_peer_reachable",
            evidence,
        )
    }
}

/// What each inner-sandbox step must report on every supported host.
pub const INNER_EXPECTED: [(&str, &str); 10] = [
    ("landlock", "ok"),
    ("seccomp", "ok"),
    ("write", "EACCES"),
    ("read", "EACCES"),
    ("mkdir", "EPERM"),
    ("remount", "EPERM"),
    ("umount", "EPERM"),
    ("setns", "EPERM"),
    ("unshare", "EPERM"),
    ("egress", "ENETUNREACH"),
];

/// `agent_inner_sandbox`.
#[must_use]
pub fn inner_sandbox(jail_exe: &Path) -> ProbeResult {
    const NAME: &str = "agent_inner_sandbox";
    const MECHANISM: &str = "landlock+seccomp";
    let probe = agent_probe(jail_exe);
    if let Some(failure) = &probe.failure {
        return ProbeResult::error(NAME, MECHANISM, failure.clone());
    }
    let inner = probe.line("inner");
    let steps: BTreeMap<&str, &str> = inner
        .split(',')
        .filter_map(|step| step.split_once(':'))
        .collect();
    let nested = probe
        .agent_details
        .as_ref()
        .and_then(|details| details["nested_user_namespace"].as_str())
        .unwrap_or("unrecorded")
        .to_owned();
    let evidence = format!("{inner}; nested user namespace {nested}");
    let ok = INNER_EXPECTED
        .iter()
        .all(|(step, want)| steps.get(step) == Some(want));
    if ok {
        ProbeResult::new(NAME, ProbeStatus::Available, MECHANISM, "ok", evidence)
    } else {
        ProbeResult::new(
            NAME,
            ProbeStatus::Unavailable,
            MECHANISM,
            "inner_sandbox_unproven",
            evidence,
        )
    }
}

// ---------------------------------------------------------------------------
// The checks `__probe-inside` runs for the agent probe
// ---------------------------------------------------------------------------

/// `http:PORT`: a plain-HTTP GET of `http://127.0.0.1:PORT/` through the
/// bridge at `127.0.0.1:3128` (the proxy variables' address); the status
/// code, or the errno of the failed step.
#[must_use]
pub fn check_http(port: &str) -> String {
    let Ok(port) = port.parse::<u16>() else {
        return "invalid_port".to_owned();
    };
    let mut stream = match TcpStream::connect(crate::platform::linux::bridge::LISTEN) {
        Ok(stream) => stream,
        Err(error) => return io_errno(&error),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let request = format!(
        "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if let Err(error) = stream.write_all(request.as_bytes()) {
        return io_errno(&error);
    }
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let head = String::from_utf8_lossy(&response);
    head.split_whitespace()
        .nth(1)
        .map_or_else(|| "no_response".to_owned(), ToOwned::to_owned)
}

/// `tcp:HOST:PORT`: a direct connect that ignores the proxy.
#[must_use]
pub fn check_tcp(address: &str) -> String {
    let Ok(address) = address.parse::<std::net::SocketAddr>() else {
        return "invalid_address".to_owned();
    };
    match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
        Ok(_) => "ok".to_owned(),
        Err(error) => io_errno(&error),
    }
}

/// `unix:PATH`: an AF_UNIX stream connect to a pathname.
#[must_use]
pub fn check_unix(path: &str) -> String {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => "ok".to_owned(),
        Err(error) => io_errno(&error),
    }
}

/// `unix-self:PATH`: bind and listen at PATH, then connect to it.
#[must_use]
pub fn check_unix_self(path: &str) -> String {
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(error) => return format!("bind_{}", io_errno(&error)),
    };
    let result = check_unix(path);
    drop(listener);
    let _ = std::fs::remove_file(path);
    result
}

fn io_errno(error: &io::Error) -> String {
    error.raw_os_error().map_or_else(
        || format!("{:?}", error.kind()),
        |code| errno_name(code).to_owned(),
    )
}

// Landlock (linux/landlock.h), ABI 1 file-system rights.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const ACCESS_EXECUTE: u64 = 1 << 0;
const ACCESS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;
const ACCESS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_MAKE_REG: u64 = 1 << 8;
const NR_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const NR_LANDLOCK_ADD_RULE: libc::c_long = 445;
const NR_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// `inner:PROTECTED`: the scripted inner sandbox of north-star §4.6, in this
/// process. It sets `no_new_privs`, installs a Landlock ruleset granting
/// read and write beneath a fresh directory in scratch and read and execute
/// beneath `/usr`, and a
/// seccomp filter returning `EPERM` for `mkdir`/`mkdirat`; then it tries a
/// write and a read of `PROTECTED` (outside both grants), a `mkdir`, and
/// each outer-boundary reversal: remount `/` read-write, unmount the proxy
/// directory, join a namespace, create a user namespace, and direct egress.
/// Each step reports its raw result; nothing is inferred.
#[must_use]
pub fn check_inner(protected: &str) -> String {
    let mut steps: Vec<(&str, String)> = Vec::new();
    // The writable grant is a fresh directory, not all of `/tmp`: the
    // workspace (and so the protected file) may itself be mounted beneath
    // `/tmp` when the operator's workspace path is there.
    let _ = std::fs::create_dir(INNER_GRANT);
    steps.push((
        "landlock",
        landlock(&[(INNER_GRANT, true), ("/usr", false)]),
    ));
    steps.push(("seccomp", inner_seccomp()));
    let path = std::ffi::CString::new(protected).unwrap_or_default();
    // SAFETY: `path` is NUL-terminated and outlives each call; the variadic
    // mode is passed because O_CREAT is not set (it is ignored).
    let write = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    steps.push(("write", result(i64::from(write))));
    // SAFETY: as above.
    let read = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    steps.push(("read", result(i64::from(read))));
    // Inside the Landlock grant, so only the inner seccomp filter can
    // refuse it. SAFETY: a static NUL-terminated path.
    steps.push((
        "mkdir",
        result(i64::from(unsafe {
            libc::mkdir(c"/tmp/.ouro-inner-grant/made".as_ptr(), 0o700)
        })),
    ));
    // SAFETY: mount with static NUL-terminated strings and null data.
    steps.push((
        "remount",
        result(i64::from(unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_BIND,
                std::ptr::null(),
            )
        })),
    ));
    // SAFETY: umount2 with a static NUL-terminated path.
    steps.push((
        "umount",
        result(i64::from(unsafe {
            libc::umount2(c"/run/ouro/proxy".as_ptr(), libc::MNT_DETACH)
        })),
    ));
    // SAFETY: setns takes two scalars; the filter answers before the fd is
    // examined.
    steps.push(("setns", result(i64::from(unsafe { libc::setns(0, 0) }))));
    // SAFETY: unshare takes a flags word.
    steps.push((
        "unshare",
        result(i64::from(unsafe { libc::unshare(libc::CLONE_NEWUSER) })),
    ));
    steps.push(("egress", check_tcp("10.255.255.1:80")));
    steps
        .iter()
        .map(|(step, value)| format!("{step}:{value}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn result(rc: i64) -> String {
    if rc >= 0 {
        if rc > 2 {
            // SAFETY: a descriptor this process just opened.
            unsafe { libc::close(i32::try_from(rc).unwrap_or(-1)) };
        }
        "ok".to_owned()
    } else {
        errno_name(crate::platform::linux::sys::last_errno()).to_owned()
    }
}

fn landlock(grants: &[(&str, bool)]) -> String {
    // SAFETY: querying the ABI takes a null attribute and a zero size.
    let abi = unsafe {
        libc::syscall(
            NR_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return format!(
            "abi_{}",
            errno_name(crate::platform::linux::sys::last_errno())
        );
    }
    let read = ACCESS_READ_FILE | ACCESS_READ_DIR | ACCESS_EXECUTE;
    let all = read | ACCESS_WRITE_FILE | ACCESS_MAKE_DIR | ACCESS_MAKE_REG;
    let attr = RulesetAttr {
        handled_access_fs: all,
    };
    // SAFETY: `attr` is live and its size is passed; the call returns a new
    // descriptor or -1.
    let ruleset = unsafe {
        libc::syscall(
            NR_LANDLOCK_CREATE_RULESET,
            std::ptr::from_ref(&attr),
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset < 0 {
        return format!(
            "ruleset_{}",
            errno_name(crate::platform::linux::sys::last_errno())
        );
    }
    let ruleset = i32::try_from(ruleset).unwrap_or(-1);
    for (root, writable) in grants {
        let Ok(c) = std::ffi::CString::new(*root) else {
            continue;
        };
        // SAFETY: `c` is NUL-terminated; O_PATH opens without I/O rights.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            continue;
        }
        let rule = PathBeneathAttr {
            allowed_access: if *writable { all } else { read },
            parent_fd: fd,
        };
        // SAFETY: `rule` is live for the call; the kernel copies it.
        let rc = unsafe {
            libc::syscall(
                NR_LANDLOCK_ADD_RULE,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                std::ptr::from_ref(&rule),
                0u32,
            )
        };
        // SAFETY: closing the descriptor opened above.
        unsafe { libc::close(fd) };
        if rc != 0 {
            return format!(
                "rule_{}",
                errno_name(crate::platform::linux::sys::last_errno())
            );
        }
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS takes scalars.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return format!(
            "nnp_{}",
            errno_name(crate::platform::linux::sys::last_errno())
        );
    }
    // SAFETY: restricts this thread with the ruleset built above.
    let rc = unsafe { libc::syscall(NR_LANDLOCK_RESTRICT_SELF, ruleset, 0u32) };
    // SAFETY: the ruleset descriptor is no longer needed.
    unsafe { libc::close(ruleset) };
    if rc != 0 {
        return format!(
            "restrict_{}",
            errno_name(crate::platform::linux::sys::last_errno())
        );
    }
    "ok".to_owned()
}

/// A seccomp filter returning `EPERM` for `mkdir` (83) and `mkdirat` (258),
/// architecture checked first, built with the jail's own assembler.
fn inner_seccomp() -> String {
    use crate::platform::linux::bpf::Asm;
    use crate::platform::linux::seccomp::{
        AUDIT_ARCH_X86_64, LINUX_EPERM, SD_ARCH, SD_NR, SECCOMP_RET_ALLOW, ret_errno,
    };
    let mut asm = Asm::new();
    asm.ld_w_abs(SD_ARCH)
        .jeq(AUDIT_ARCH_X86_64, None, Some("deny"))
        .ld_w_abs(SD_NR)
        .jeq(83, Some("deny"), None)
        .jeq(258, Some("deny"), None)
        .ret(SECCOMP_RET_ALLOW)
        .label("deny")
        .ret(ret_errno(LINUX_EPERM));
    let Ok(program) = asm.assemble() else {
        return "assemble_failed".to_owned();
    };
    match crate::platform::linux::seccomp::install(&program) {
        Ok(()) => "ok".to_owned(),
        Err(error) => io_errno(&error),
    }
}

/// The inner sandbox's only writable grant, inside the attempt's scratch.
const INNER_GRANT: &str = "/tmp/.ouro-inner-grant";

/// Where the protected fixture of a probe workspace is, for tests.
#[must_use]
pub fn protected_path(workspace: &Path) -> PathBuf {
    workspace.join(PROTECTED_NAME)
}
