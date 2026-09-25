#![cfg(target_os = "linux")]
//! J4 wave 0, the observer's own defects: places where the ptrace observer
//! could report coverage as complete when it is not (J4 contract D1, D2, D6).
//!
//! Each `j4_dN_…` test was written before its fix and failed on the base it
//! was written against (f147a149); the failure it produced there is quoted
//! in the J4 report. The shape is the observer suite's: a C fixture built at
//! test time is the inside launcher (it installs the narrowing filter this
//! crate produces, blocks on its release pipe, then execs), the test seizes
//! it with [`Tracer::attach`], and what the observer said is compared with
//! what the fixture says the kernel returned. The two `none` receipt checks
//! run the real `ouro-jail` over the same fixture.
//!
//! Every process these tests trace is one they start; nothing on the host is
//! inspected or changed.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::seccomp;
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, Tracer, TracerConfig, TracerEvent, TracerSummary,
    narrowing_filter_bytes,
};
use serde_json::Value;

// J5-C: the shared contract checks for the two `none` receipts below.
mod common;

const HELPER_C: &str = r##"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LD_ARCH BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch))
#define LD_NR BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
#define RET(k) BPF_STMT(BPF_RET | BPF_K, (k))

static void report(const char *label, long r, const char *p1) {
    printf("%s\t%ld\t%d\t%s\n", label, r, r < 0 ? errno : 0, p1 ? p1 : "");
    fflush(stdout);
}

static int install_file(const char *path) {
    static struct sock_filter prog[1024];
    struct sock_fprog fprog;
    int fd = open(path, O_RDONLY);
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, prog, sizeof prog);
    close(fd);
    if (n <= 0 || (size_t) n % sizeof(struct sock_filter)) return -2;
    fprog.len = (unsigned short) ((size_t) n / sizeof(struct sock_filter));
    fprog.filter = prog;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -3;
    if (syscall(SYS_seccomp, 1, 0, &fprog)) return -4;
    return 0;
}

static int await_release(void) {
    char b;
    for (;;) {
        ssize_t n = read(0, &b, 1);
        if (n == 1) return 0;
        if (n == 0) return -1;
        if (errno != EINTR) return -1;
    }
}

/* launch NARROWING PROG ARGS...: the observer's filter only, as in `none`. */
static int mode_launch(int argc, char **argv) {
    if (argc < 4) return 2;
    if (install_file(argv[2])) { fprintf(stderr, "narrowing failed\n"); return 3; }
    report("ready", (long) getpid(), "");
    if (await_release()) return 4;
    execv(argv[3], &argv[3]);
    fprintf(stderr, "execv %s: %s\n", argv[3], strerror(errno));
    return 127;
}

/* launch2 BASELINE NARROWING PROG ARGS...: the product's contained shape. */
static int mode_launch2(int argc, char **argv) {
    if (argc < 5) return 2;
    if (install_file(argv[2])) { fprintf(stderr, "baseline failed\n"); return 3; }
    if (install_file(argv[3])) { fprintf(stderr, "narrowing failed\n"); return 3; }
    report("ready", (long) getpid(), "");
    if (await_release()) return 4;
    execv(argv[4], &argv[4]);
    fprintf(stderr, "execv %s: %s\n", argv[4], strerror(errno));
    return 127;
}

/* The child's own filter, through seccomp(2) or prctl(2). */
static long install(struct sock_filter *prog, unsigned short len, unsigned long flags, int via_prctl) {
    struct sock_fprog fprog;
    fprog.len = len;
    fprog.filter = prog;
    if (via_prctl) return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0);
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog);
}

static int g_listener = -1;
static void *continue_every_call(void *arg) {
    (void) arg;
    for (;;) {
        struct seccomp_notif req;
        struct seccomp_notif_resp resp;
        memset(&req, 0, sizeof req);
        if (ioctl(g_listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR) continue;
            return NULL;
        }
        memset(&resp, 0, sizeof resp);
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(g_listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0 && errno != ENOENT) return NULL;
    }
}

/* listener HIDDEN SEEN: install a filter with its own notification listener
   that notifies every openat, answer each notification with CONTINUE, then
   create HIDDEN with openat (the kernel runs it with no trace stop) and SEEN
   with mkdir (not notified, so the observer's trace stop applies). */
static int mode_listener(int argc, char **argv) {
    struct sock_filter prog[] = {
        LD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        RET(SECCOMP_RET_USER_NOTIF),
        RET(SECCOMP_RET_ALLOW),
    };
    pthread_t t;
    long r;
    if (argc < 4) return 2;
    r = install(prog, 6, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0);
    report("listener", r, "");
    if (r < 0) return 3;
    g_listener = (int) r;
    pthread_create(&t, NULL, continue_every_call, NULL);
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY | O_CREAT, 0600);
    report("hidden_open", r, argv[2]);
    if (r >= 0) close((int) r);
    r = syscall(SYS_mkdir, argv[3], 0700);
    report("seen_mkdir", r, argv[3]);
    return 0;
}

/* errno-filter seccomp|prctl DENIED SEEN: a listener-less filter that fails
   mkdir and mkdirat with EPERM (and kills any other architecture), then
   mkdir DENIED (preempted before the trace stop) and create SEEN (not). */
static int mode_errno_filter(int argc, char **argv) {
    struct sock_filter prog[] = {
        LD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdir, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdirat, 1, 0),
        RET(SECCOMP_RET_ALLOW),
        RET(SECCOMP_RET_ERRNO | EPERM),
    };
    long r;
    if (argc < 5) return 2;
    r = install(prog, 8, 0, strcmp(argv[2], "prctl") == 0);
    report("install", r, argv[2]);
    if (r < 0) return 3;
    r = syscall(SYS_mkdir, argv[3], 0700);
    report("preempted_mkdir", r, argv[3]);
    r = syscall(SYS_openat, AT_FDCWD, argv[4], O_WRONLY | O_CREAT, 0600);
    report("seen_open", r, argv[4]);
    if (r >= 0) close((int) r);
    return 0;
}

/* tool-listener: what the tool baseline answers to the child's own filters. */
static int mode_tool_listener(void) {
    struct sock_filter allow[] = { RET(SECCOMP_RET_ALLOW) };
    long r;
    r = install(allow, 1, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0);
    report("new_listener", r, "");
    if (r >= 0) close((int) r);
    /* seccomp(2) takes an unsigned int: the high word is not the flags. */
    r = install(allow, 1, (1UL << 32) | SECCOMP_FILTER_FLAG_NEW_LISTENER, 0);
    report("new_listener_high_word", r, "");
    if (r >= 0) close((int) r);
    r = install(allow, 1, 0, 0);
    report("plain_filter", r, "");
    return 0;
}

static long int80(long nr, long a, long b, long c) {
    long res;
    __asm__ volatile("int $0x80" : "=a"(res) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    errno = res < 0 ? (int) -res : 0;
    return res < 0 ? -1 : res;
}

/* foreign I386 X32 NATIVE: an i386 open that creates I386, an x32 openat of
   X32, an i386 call with a number no table has, and a native create. */
static int mode_foreign(int argc, char **argv) {
    char *low;
    long r;
    if (argc < 5) return 2;
    low = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low == MAP_FAILED) { report("i386_open", -1, argv[2]); return 3; }
    strncpy(low, argv[2], 4000);
    r = int80(5 /* i386 open */, (long) (uint32_t) (uintptr_t) low, O_WRONLY | O_CREAT, 0600);
    report("i386_open", r, argv[2]);
    if (r >= 0) close((int) r);
    r = syscall(0x40000000L | __NR_openat, AT_FDCWD, argv[3], O_WRONLY | O_CREAT, 0600);
    report("x32_openat", r, argv[3]);
    if (r >= 0) close((int) r);
    r = int80(0x7ffe, 0, 0, 0);
    report("i386_no_such_call", r, "");
    r = syscall(SYS_openat, AT_FDCWD, argv[4], O_WRONLY | O_CREAT, 0600);
    report("native_open", r, argv[4]);
    if (r >= 0) close((int) r);
    return 0;
}

/* forks-then-trace N: N fork children that exit at once (one lifecycle fact
   each for the observer), then a filter that asks for a trace stop on getpid,
   a number outside the closed set, carrying the narrowing filter's own trace
   data (0x4f4a), and a getpid: a stop the observer's own program never makes,
   which it can only answer with a gap. */
static int mode_forks_then_trace(int argc, char **argv) {
    struct sock_filter prog[] = {
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 1, 0),
        RET(SECCOMP_RET_ALLOW),
        RET(SECCOMP_RET_TRACE | 0x4f4a),
    };
    long n, i, made = 0, r;
    if (argc < 3) return 2;
    n = atol(argv[2]);
    for (i = 0; i < n; i++) {
        pid_t kid = fork();
        if (kid == 0) _exit(0);
        if (kid > 0) { made++; waitpid(kid, NULL, 0); }
    }
    report("forked", made, "");
    r = install(prog, 4, 0, 0);
    report("install", r, "");
    r = syscall(SYS_getpid);
    report("getpid", r, "");
    return 0;
}

/* trace-request MADE: the child's own filter asks for trace stops, with data
   of its own (0x1234), on getpid (outside the closed set) and on mkdir
   (inside it). One stop each; the observer must neither decode the first
   nor count it as loss, and must report the second exactly once. */
static int mode_trace_request(int argc, char **argv) {
    struct sock_filter prog[] = {
        LD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdir, 1, 0),
        RET(SECCOMP_RET_ALLOW),
        RET(SECCOMP_RET_TRACE | 0x1234),
    };
    long r;
    if (argc < 3) return 2;
    r = install(prog, 8, 0, 0);
    report("install", r, "");
    if (r < 0) return 3;
    r = syscall(SYS_getpid);
    report("getpid", r, "");
    r = syscall(SYS_mkdir, argv[2], 0700);
    report("mkdir", r, argv[2]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "launch")) return mode_launch(argc, argv);
    if (!strcmp(argv[1], "launch2")) return mode_launch2(argc, argv);
    if (!strcmp(argv[1], "listener")) return mode_listener(argc, argv);
    if (!strcmp(argv[1], "errno-filter")) return mode_errno_filter(argc, argv);
    if (!strcmp(argv[1], "tool-listener")) return mode_tool_listener();
    if (!strcmp(argv[1], "foreign")) return mode_foreign(argc, argv);
    if (!strcmp(argv[1], "forks-then-trace")) return mode_forks_then_trace(argc, argv);
    if (!strcmp(argv[1], "trace-request")) return mode_trace_request(argc, argv);
    return 2;
}
"##;

// ---------------------------------------------------------------------------
// Harness: one tracer at a time, a fixture built once
// ---------------------------------------------------------------------------

/// A tracer's thread owns `waitpid(-1, __WALL)` for the whole process, so two
/// checks in this binary would reap each other's children. Serialised here,
/// whatever parallelism the runner chooses.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn build() -> Result<&'static (PathBuf, PathBuf), String> {
    static BUILD: OnceLock<Result<(PathBuf, PathBuf), String>> = OnceLock::new();
    BUILD
        .get_or_init(|| {
            if !Path::new("/usr/bin/gcc").exists() {
                return Err("/usr/bin/gcc is not installed".to_string());
            }
            let dir = std::env::temp_dir().join(format!("ouro-j4-observer-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            let source = dir.join("j4.c");
            std::fs::write(&source, HELPER_C).map_err(|e| format!("write j4.c: {e}"))?;
            let helper = dir.join("j4");
            let out = Command::new("/usr/bin/gcc")
                .args(["-O1", "-Wall", "-pthread", "-B/usr/bin", "-o"])
                .arg(&helper)
                .arg(&source)
                .output()
                .map_err(|e| format!("run gcc: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "gcc failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            let filter = dir.join("filter.bin");
            std::fs::write(&filter, narrowing_filter_bytes())
                .map_err(|e| format!("write filter.bin: {e}"))?;
            Ok((helper, filter))
        })
        .as_ref()
        .map_err(Clone::clone)
}

struct Work {
    dir: PathBuf,
    helper: PathBuf,
    filter: PathBuf,
}

impl Work {
    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }
    fn helper_s(&self) -> String {
        self.helper.to_string_lossy().into_owned()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn setup(name: &str) -> Option<Work> {
    let (helper, filter) = match build() {
        Ok(pair) => pair,
        Err(err) => {
            harness::skip_or_fail(&format!("{name}: {err}"));
            return None;
        }
    };
    let dir = std::env::temp_dir().join(format!("ouro-j4-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the work directory");
    Some(Work {
        dir,
        helper: helper.clone(),
        filter: filter.clone(),
    })
}

struct Launched {
    pid: libc::pid_t,
    release: std::process::ChildStdin,
    output: BufReader<std::process::ChildStdout>,
}

impl Launched {
    fn await_ready(&mut self) {
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .expect("the launcher announces itself");
        let report = Report::parse(line.trim_end_matches('\n'))
            .unwrap_or_else(|| panic!("unparseable readiness line {line:?}"));
        assert_eq!(report.label, "ready", "unexpected first line {line:?}");
    }
    fn release(&mut self) {
        self.release.write_all(b"g").expect("release byte");
        self.release.flush().expect("flush");
    }
    fn lines(&mut self) -> Vec<Report> {
        let mut out = Vec::new();
        let mut line = String::new();
        while self.output.read_line(&mut line).unwrap_or(0) > 0 {
            if let Some(report) = Report::parse(line.trim_end_matches('\n')) {
                out.push(report);
            }
            line.clear();
        }
        out
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        // SAFETY: `kill` with a pid this test created and a valid signal.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Report {
    label: String,
    raw: i64,
    errno: i32,
    path: String,
}

impl Report {
    fn parse(line: &str) -> Option<Report> {
        let mut fields = line.split('\t');
        let label = fields.next()?.to_string();
        let raw = fields.next()?.parse().ok()?;
        let errno = fields.next()?.parse().ok()?;
        Some(Report {
            label,
            raw,
            errno,
            path: fields.next().unwrap_or_default().to_string(),
        })
    }
    fn find<'a>(reports: &'a [Report], label: &str) -> &'a Report {
        reports
            .iter()
            .find(|r| r.label == label)
            .unwrap_or_else(|| panic!("no fixture line {label:?} in {reports:?}"))
    }
}

fn spawn(mut command: Command) -> Launched {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn");
    let pid = child.id() as libc::pid_t;
    let release = child.stdin.take().expect("stdin");
    let output = BufReader::new(child.stdout.take().expect("stdout"));
    // The tracer thread owns every wait in this process, so the handle is
    // not kept.
    drop(child);
    let mut launched = Launched {
        pid,
        release,
        output,
    };
    launched.await_ready();
    launched
}

/// The observer's filter only: the `none` shape.
fn launch(work: &Work, argv: &[&str]) -> Launched {
    let mut command = Command::new(&work.helper);
    command.arg("launch").arg(&work.filter).args(argv);
    spawn(command)
}

/// The `tool` baseline, then the observer's filter: the contained shape.
fn launch_tool(work: &Work, argv: &[&str]) -> Launched {
    let baseline = seccomp::tool_baseline().expect("the tool baseline");
    let path = work.path("baseline.bin");
    std::fs::write(&path, baseline.to_bytes()).expect("write the baseline");
    let mut command = Command::new(&work.helper);
    command
        .arg("launch2")
        .arg(&path)
        .arg(&work.filter)
        .args(argv);
    spawn(command)
}

struct Observed {
    events: Vec<TracerEvent>,
    summary: TracerSummary,
}

impl Observed {
    fn primaries(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::Syscall { args, .. } => args
                    .path
                    .as_ref()
                    .map(|p| String::from_utf8_lossy(&p.bytes).into_owned()),
                _ => None,
            })
            .collect()
    }
    fn of_op(&self, op: ClosedOp) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TracerEvent::Syscall { op: o, .. } if *o == op))
            .count()
    }
    /// Gaps whose reason has this name. Matched by the name the receipt
    /// carries, which is what a consumer sees.
    fn gaps_named(&self, name: &str) -> Vec<(OpSet, Option<u64>)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::Gap {
                    reason, ops, count, ..
                } if reason.as_str() == name => Some((*ops, *count)),
                _ => None,
            })
            .collect()
    }
    fn describe(&self) -> String {
        self.events
            .iter()
            .filter(|e| !matches!(e, TracerEvent::Fork { .. }))
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

fn collect(tracer: Tracer, budget: Duration) -> Observed {
    let deadline = Instant::now() + budget;
    let mut events = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tracer.events().recv_timeout(left) {
            Ok(TracerEvent::Finished) => {
                events.push(TracerEvent::Finished);
                break;
            }
            Ok(e) => events.push(e),
            Err(_) => break,
        }
    }
    let summary = tracer.finish();
    Observed { events, summary }
}

fn attach(pid: libc::pid_t, config: TracerConfig) -> Tracer {
    Tracer::attach(pid, config).unwrap_or_else(|e| panic!("attach {pid}: {e}"))
}

/// Run `argv` under the observer's filter only, the `none` shape.
fn observe(work: &Work, argv: &[&str]) -> (Vec<Report>, Observed) {
    let mut run = launch(work, argv);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    (reports, collect(tracer, Duration::from_secs(60)))
}

// ===========================================================================
// D1: a child's own seccomp filter can take calls away from the observer
// ===========================================================================

/// D1, the listener. A child that installs its own filter with a
/// notification listener and answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` runs
/// a closed-set call with no ptrace stop: `USER_NOTIF` outranks the
/// narrowing filter's `TRACE`. The observer cannot see that call, so it must
/// say so, for every class, from the moment the listener exists.
#[test]
fn j4_d1_a_child_notification_listener_is_a_gap_in_every_class() {
    let _serial = serial();
    let Some(work) = setup("d1-listener") else {
        return;
    };
    let helper = work.helper_s();
    let hidden = work.path("hidden");
    let seen = work.path("seen");
    let (reports, observed) = observe(&work, &[&helper, "listener", &hidden, &seen]);

    let listener = Report::find(&reports, "listener");
    assert!(
        listener.raw >= 0,
        "the listener was installed: {listener:?}"
    );
    let open = Report::find(&reports, "hidden_open");
    assert_eq!(open.errno, 0, "the continued openat ran: {open:?}");
    assert!(
        Path::new(&hidden).exists(),
        "and it created its file, with no trace stop for the observer"
    );
    assert!(
        !observed.primaries().iter().any(|p| p == &hidden),
        "the continued call is invisible to ptrace:\n  {}",
        observed.describe()
    );
    assert!(
        observed.primaries().iter().any(|p| p == &seen),
        "a call the listener does not take is still observed:\n  {}",
        observed.describe()
    );
    let gaps = observed.gaps_named("child_notification_listener");
    assert_eq!(
        gaps.len(),
        1,
        "a child's notification listener must be a named gap, not active coverage:\n  {}",
        observed.describe()
    );
    assert_eq!(
        gaps[0].0,
        OpSet::ALL,
        "any closed-set call may be continued"
    );
    assert_eq!(gaps[0].1, None, "how many calls it hid is not known");
}

/// D1, the named exclusion (integrator decision S3). A listener-less filter
/// of the child's own that fails a closed-set call (`SECCOMP_RET_ERRNO`
/// outranks `TRACE`) takes that call away before the observer's stop, but
/// the refused call had no effect. So its result is not observed and is not
/// a gap either: "a result the child's own filter refuses before the
/// observer's stop is not observed; it had no effect". (Passes on the base as
/// well: it pins the exclusion, so an inner Landlock/seccomp sandbox under
/// strict evidence is not stopped for it.)
#[test]
fn j4_d1_exclusion_a_filter_that_refuses_a_call_is_not_a_gap() {
    let _serial = serial();
    let Some(work) = setup("d1-errno") else {
        return;
    };
    refusing_filter_case(&work, "seccomp");
}

/// D1, the same exclusion through `prctl(PR_SET_SECCOMP)`, which cannot ask
/// for a listener at all.
#[test]
fn j4_d1_exclusion_holds_for_a_filter_installed_through_prctl() {
    let _serial = serial();
    let Some(work) = setup("d1-prctl") else {
        return;
    };
    refusing_filter_case(&work, "prctl");
}

fn refusing_filter_case(work: &Work, method: &str) {
    let helper = work.helper_s();
    let denied = work.path("denied");
    let seen = work.path("seen");
    let (reports, observed) = observe(work, &[&helper, "errno-filter", method, &denied, &seen]);

    assert_eq!(Report::find(&reports, "install").errno, 0, "{reports:?}");
    let mkdir = Report::find(&reports, "preempted_mkdir");
    assert_eq!(mkdir.errno, libc::EPERM, "the child's filter failed mkdir");
    assert!(!Path::new(&denied).exists(), "and it had no effect");
    assert_eq!(
        observed.of_op(ClosedOp::Mkdir),
        0,
        "the refused call is not observed:\n  {}",
        observed.describe()
    );
    assert!(observed.primaries().iter().any(|p| p == &seen));
    let gaps: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| matches!(e, TracerEvent::Gap { .. }))
        .collect();
    assert!(
        gaps.is_empty(),
        "a refusal with no effect is the named exclusion, not a gap: {gaps:?}"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// D1, the extra stop. A child's own filter returning `SECCOMP_RET_TRACE`
/// reaches this tracer as a stop the narrowing filter did not ask for. On a
/// number outside the closed set it is continued untouched — never decoded,
/// never counted as loss, never labelled as a filter that is not the
/// observer's — and on a closed-set number it is the one stop the call has,
/// reported once.
#[test]
fn j4_d1_a_child_trace_request_is_continued_not_mislabelled() {
    let _serial = serial();
    let Some(work) = setup("d1-trace") else {
        return;
    };
    let helper = work.helper_s();
    let made = work.path("made");
    let (reports, observed) = observe(&work, &[&helper, "trace-request", &made]);

    assert_eq!(Report::find(&reports, "install").errno, 0, "{reports:?}");
    let getpid = Report::find(&reports, "getpid");
    assert!(getpid.raw > 0, "getpid ran after its stop: {getpid:?}");
    assert_eq!(Report::find(&reports, "mkdir").errno, 0);
    let gaps: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| matches!(e, TracerEvent::Gap { .. }))
        .collect();
    assert!(
        gaps.is_empty(),
        "a stop the child's own filter asked for is not a loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.of_op(ClosedOp::Mkdir),
        1,
        "the closed-set call it also traced is reported once:\n  {}",
        observed.describe()
    );
    assert!(observed.primaries().iter().any(|p| p == &made));
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// D1, the contained profiles: `tool` and `build` refuse a notification
/// listener outright (`EPERM`), whatever the high word of the argument, and
/// still let the child stack a plain filter.
#[test]
fn j4_d1_the_tool_baseline_refuses_a_notification_listener() {
    let _serial = serial();
    let Some(work) = setup("d1-tool") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch_tool(&work, &[&helper, "tool-listener"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let listener = Report::find(&reports, "new_listener");
    assert_eq!(
        listener.errno,
        libc::EPERM,
        "the tool baseline must refuse a notification listener: {listener:?}"
    );
    assert_eq!(
        Report::find(&reports, "new_listener_high_word").errno,
        libc::EPERM
    );
    assert_eq!(Report::find(&reports, "plain_filter").errno, 0);
    assert!(
        observed
            .gaps_named("child_notification_listener")
            .is_empty(),
        "a refused listener hides nothing"
    );
}

// ===========================================================================
// D2: a call under another ABI in `none`
// ===========================================================================

/// D2. Without a containment baseline nothing refuses the i386 or x32 ABI,
/// so the narrowing filter must stop on them, and the observer — which
/// decodes only the native table — must record each one it cannot attribute
/// as a gap in every class, labelled foreign, never as a native result. A
/// call the kernel refused as nonexistent (`ENOSYS`, which is what x32 gets
/// on a kernel built without it) had no effect and is not a loss.
#[test]
fn j4_d2_a_foreign_abi_call_without_a_baseline_is_a_gap() {
    let _serial = serial();
    let Some(work) = setup("d2-foreign") else {
        return;
    };
    let helper = work.helper_s();
    let i386 = work.path("by-i386");
    let x32 = work.path("by-x32");
    let native = work.path("native");
    let (reports, observed) = observe(&work, &[&helper, "foreign", &i386, &x32, &native]);

    let i386_open = Report::find(&reports, "i386_open");
    assert_eq!(i386_open.errno, 0, "the i386 open ran: {i386_open:?}");
    assert!(Path::new(&i386).exists(), "and created its file");
    let x32_open = Report::find(&reports, "x32_openat");
    let nonexistent = Report::find(&reports, "i386_no_such_call");
    assert_eq!(nonexistent.errno, libc::ENOSYS);
    assert_eq!(Report::find(&reports, "native_open").errno, 0);

    let named = observed.primaries();
    assert!(
        named.iter().any(|p| p == &native),
        "the native call is seen"
    );
    assert!(
        !named.iter().any(|p| p == &i386 || p == &x32),
        "a foreign call is never decoded from the x86_64 table: {named:?}"
    );
    // Every foreign call the kernel did not refuse as nonexistent.
    let expected: u64 = [i386_open, x32_open]
        .iter()
        .filter(|r| r.errno != libc::ENOSYS)
        .count() as u64;
    let gaps = observed.gaps_named("foreign_abi");
    assert!(
        !gaps.is_empty(),
        "a foreign-ABI call in `none` must be a gap, not silence:\n  {}",
        observed.describe()
    );
    for (ops, _) in &gaps {
        assert_eq!(*ops, OpSet::ALL, "a call nothing decoded may be any class");
    }
    let counted: u64 = gaps.iter().filter_map(|(_, count)| *count).sum();
    assert_eq!(
        counted,
        expected,
        "one per foreign call that ran; x32={x32_open:?}\n  {}",
        observed.describe()
    );
}

// ===========================================================================
// D6: critical facts behind a full lifecycle backlog
// ===========================================================================

/// D6. The outbox bounds lifecycle facts at a count, and used to check that
/// bound before the exemption for critical facts: with the backlog full, a
/// target's `Exit` and a `Gap` were dropped. The budget is filled first here
/// — twenty thousand fork facts nobody reads, with the byte budget raised so
/// the count bound is the one reached — then the fixture causes a gap and
/// exits. Both must reach the consumer, the gap ahead of the exit.
#[test]
fn j4_d6_critical_facts_survive_a_full_lifecycle_backlog() {
    let _serial = serial();
    let Some(work) = setup("d6-backlog") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "forks-then-trace", "20000"]);
    let target = run.pid;
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_bytes_max: 64 * 1024 * 1024,
            ..TracerConfig::default()
        },
    );
    run.release();
    // Nothing is read until the observer has reaped the fixture, so every
    // fact, the exit included, waits in the observer's own buffer. Its
    // stdout closes before its death is reported, hence the reap and not EOF.
    let reports = run.lines();
    let deadline = Instant::now() + Duration::from_secs(120);
    while Path::new(&format!("/proc/{target}")).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    let observed = collect(tracer, Duration::from_secs(300));
    println!(
        "d6: forked={} lifecycle_dropped={} emitted={} gaps={}",
        Report::find(&reports, "forked").raw,
        observed.summary.loss.lifecycle_dropped,
        observed.summary.emitted,
        observed.summary.gaps
    );

    assert!(Report::find(&reports, "forked").raw >= 20_000 - 10);
    assert_eq!(Report::find(&reports, "install").errno, 0);
    assert!(
        observed.summary.loss.lifecycle_dropped > 0,
        "the lifecycle budget must be full before the critical facts: {:?}",
        observed.summary.loss
    );
    let exit = observed.events.iter().position(|e| {
        matches!(e, TracerEvent::Exit { pid, status, .. }
            if *pid == target && libc::WIFEXITED(*status) && libc::WEXITSTATUS(*status) == 0)
    });
    let gap = observed.events.iter().position(|e| {
        matches!(e, TracerEvent::Gap { reason, .. } if *reason == GapReason::UnexpectedTraceStop)
    });
    let dropped_facts: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| {
            matches!(e, TracerEvent::Gap { reason, ops, .. }
                if *reason == GapReason::LifecycleDropped && !ops.is_empty())
        })
        .collect();
    assert!(
        exit.is_some(),
        "the target's exit must survive a full lifecycle backlog; dropped: {dropped_facts:?}"
    );
    assert!(
        gap.is_some(),
        "and so must a gap; dropped: {dropped_facts:?}"
    );
    assert!(gap < exit, "the gap is delivered ahead of what followed it");
    assert!(
        dropped_facts.is_empty(),
        "only bookkeeping facts may be dropped: {dropped_facts:?}"
    );
    assert!(matches!(
        observed.events.last(),
        Some(TracerEvent::Finished)
    ));
}

// ===========================================================================
// The same two defects, end to end, in a `none` receipt
// ===========================================================================

/// `none` needs a delegated leaf (§9.3); the conformance run provides it.
fn none_live() -> bool {
    let leaf = ouro_jail::platform::linux::probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "the none receipt checks need a delegated user scope: {}",
            leaf.evidence
        ));
        return false;
    }
    true
}

fn none_run(work: &Work, evidence: &str, argv: &[&str]) -> Run {
    let workspace = work.dir.join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    Jail::new()
        .expect("a private harness")
        .arg("run")
        .arg("--profile")
        .arg("none")
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control()
        .target(argv.iter().map(OsString::from))
        .run()
        .expect("the jail runs")
}

/// The run's settled receipt, after every record of the run was held to its
/// contract.
///
/// J5-C: the two `none` checks below used to read the settled receipt with no
/// validation at all (gap analysis §1.3.2). Every receipt now passes its
/// schema and `ouro_jail::records::semantic::receipt`, the trace passes
/// `jail-event` per event and `semantic::trace` plus `trace_ends_with`, and
/// the control transcript passes `jail-control` and `semantic::control`.
fn settled_receipt(run: &Run) -> Value {
    run.assert_channels_complete();
    common::assert_run_records(run);
    run.receipt_phase("settled")
        .unwrap_or_else(|| panic!("no settled receipt: {}", run.stderr_text()))
}

fn gap_reasons(receipt: &Value) -> Vec<String> {
    receipt["observer"]["gaps"]
        .as_array()
        .map(|gaps| {
            gaps.iter()
                .filter_map(|gap| gap["reason"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// D1 in a receipt: a `none` child with its own notification listener. The
/// receipt must not read `active`, and strict evidence stops the attempt.
#[test]
fn j4_d1_none_a_child_listener_degrades_the_receipt_and_strict_stops() {
    let _serial = serial();
    if !none_live() {
        return;
    }
    let Some(work) = setup("d1-none") else {
        return;
    };
    let helper = work.helper_s();
    let hidden = work.path("hidden");
    let seen = work.path("seen");
    let run = none_run(&work, "strict", &[&helper, "listener", &hidden, &seen]);
    let receipt = settled_receipt(&run);
    let reasons = gap_reasons(&receipt);
    assert!(
        reasons.iter().any(|r| r == "child_notification_listener"),
        "the receipt must name the listener gap: {:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
        assert_eq!(entry["observed_count"], Value::Null, "{class}");
    }
    assert_eq!(
        receipt["outcome"]["cause"], "evidence_loss",
        "strict evidence stops the attempt: {:#}",
        receipt["outcome"]
    );
}

/// D2 in a receipt: a `none` child making one i386 call, best-effort so the
/// run completes. Every audit class is degraded and says why.
#[test]
fn j4_d2_none_a_foreign_abi_call_degrades_the_receipt() {
    let _serial = serial();
    if !none_live() {
        return;
    }
    let Some(work) = setup("d2-none") else {
        return;
    };
    let helper = work.helper_s();
    let i386 = work.path("by-i386");
    let x32 = work.path("by-x32");
    let native = work.path("native");
    let run = none_run(
        &work,
        "best-effort",
        &[&helper, "foreign", &i386, &x32, &native],
    );
    let receipt = settled_receipt(&run);
    assert!(Path::new(&i386).exists(), "the i386 call ran");
    // Best-effort: the loss is an error of the run, not a stop of the child.
    assert_eq!(
        receipt["outcome"]["kind"], "exited",
        "{:#}",
        receipt["outcome"]
    );
    assert_eq!(receipt["outcome"]["code"], 0, "{:#}", receipt["outcome"]);
    assert!(
        gap_reasons(&receipt).iter().any(|r| r == "foreign_abi"),
        "the receipt must name the foreign-ABI gap: {:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    }
}
