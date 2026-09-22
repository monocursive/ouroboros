#![cfg(target_os = "linux")]
//! The live harness for the Linux ptrace observer.
//!
//! Every test here runs a real process tree on a real kernel, seizes it with
//! [`Tracer::attach`] and compares what the observer reported with what the
//! traced program said about itself. The fixture prints the raw return and
//! errno of every call it makes, so the comparison is result by result and
//! errno by errno, not "an event turned up".
//!
//! The fixture is a small C program built at test time (`helper.c` below).
//! It doubles as the inside launcher of jail-v1 §3.6: it installs the
//! narrowing filter this crate produces — read from a file, never a second
//! copy of the program — blocks reading one byte from stdin, and then execs
//! the target. That is exactly the sequence the product's launcher performs,
//! so the tests exercise the attach window as it will really exist.
//!
//! Tests skip with a reason when a tool they need is missing. Under
//! `OURO_CONFORMANCE=1` a skip is a failure.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ouro_fixture::harness;
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, Tracer, TracerConfig, TracerError, TracerEvent, TracerSummary, cmdline,
    descendants, narrowing_filter, narrowing_filter_bytes, narrowing_filter_digest, nspid,
};

// --------------------------------------------------------------- fixtures

/// The launcher and every fixture, in one binary.
///
/// `launch` is the inside launcher: it reads the cBPF program produced by
/// `narrowing_filter()` from a file, installs it with `no_new_privs`, blocks
/// on the release pipe and then execs. Every other mode is a fixture that
/// prints one tab-separated line per operation:
/// `label <TAB> raw return <TAB> errno <TAB> path <TAB> path2`.
const HELPER_C: &str = r##"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

struct ouro_open_how { unsigned long long flags, mode, resolve; };

static void report(const char *label, long r, const char *p1, const char *p2) {
    printf("%s\t%ld\t%d\t%s\t%s\n", label, r, r < 0 ? errno : 0, p1 ? p1 : "", p2 ? p2 : "");
    fflush(stdout);
}

static int install_filter(const char *path) {
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

/* helper launch FILTER PROGRAM [ARGS...]
   helper launch FILTER --probe-openat PATH   */
static int mode_launch(int argc, char **argv) {
    if (argc < 4) return 2;
    if (install_filter(argv[2])) { fprintf(stderr, "install_filter failed\n"); return 3; }
    /* The exec that brought us here is complete and the filter is on. The
       supervisor seizes only after reading this, so the seize can never land
       in the middle of an exec it did not ask about. */
    report("ready", (long) getpid(), "", "");
    if (await_release()) return 4;
    if (strcmp(argv[3], "--probe-openat") == 0) {
        long r;
        if (argc < 5) return 2;
        r = syscall(SYS_openat, AT_FDCWD, argv[4], O_WRONLY | O_CREAT, 0600);
        report("openat_create", r, argv[4], "");
        r = syscall(SYS_openat, AT_FDCWD, argv[4], O_RDONLY, 0);
        report("openat_rdonly", r, argv[4], "");
        r = syscall(SYS_write, 1, "", 0);
        report("write", r, "", "");
        return 0;
    }
    execv(argv[3], &argv[3]);
    fprintf(stderr, "execv %s: %s\n", argv[3], strerror(errno));
    return 127;
}

/* helper closed-set BASE EACCES_FILE */
static int mode_closed_set(int argc, char **argv) {
    char a[512], b[512], c[512], s[512], d[512], miss[512], sock[512];
    char a2[512], b2[512], d2[512], a3[512], c3[512], s3[512], a4[512];
    char n1[512], n2[512];
    struct ouro_open_how how;
    struct sockaddr_un sa;
    const char *base;
    long r;
    int fd;
    if (argc < 4) return 2;
    base = argv[2];
    snprintf(a, sizeof a, "%s/a", base);
    snprintf(b, sizeof b, "%s/b", base);
    snprintf(c, sizeof c, "%s/c", base);
    snprintf(s, sizeof s, "%s/s", base);
    snprintf(d, sizeof d, "%s/d", base);
    snprintf(miss, sizeof miss, "%s/absent/x", base);
    snprintf(sock, sizeof sock, "%s/no-socket", base);
    snprintf(a2, sizeof a2, "%s/a2", base);
    snprintf(b2, sizeof b2, "%s/b2", base);
    snprintf(d2, sizeof d2, "%s/d2", base);
    snprintf(a3, sizeof a3, "%s/a3", base);
    snprintf(c3, sizeof c3, "%s/c3", base);
    snprintf(s3, sizeof s3, "%s/s3", base);
    snprintf(a4, sizeof a4, "%s/a4", base);
    snprintf(n1, sizeof n1, "%s/n1", base);
    snprintf(n2, sizeof n2, "%s/n2", base);

    r = syscall(SYS_openat, AT_FDCWD, a, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    report("open_create", r, a, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_openat, AT_FDCWD, a, O_RDONLY, 0);
    report("open_rdonly", r, a, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_openat, AT_FDCWD, a, O_WRONLY, 0);
    report("open_write", r, a, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_openat, AT_FDCWD, miss, O_WRONLY | O_CREAT, 0600);
    report("open_enoent", r, miss, "");
    r = syscall(SYS_mkdir, d, 0700);
    report("mkdir", r, d, "");
    r = syscall(SYS_mkdir, d, 0700);
    report("mkdir_eexist", r, d, "");
    r = syscall(SYS_rename, a, b);
    report("rename", r, a, b);
    r = syscall(SYS_link, b, c);
    report("link", r, b, c);
    r = syscall(SYS_symlink, "a-target", s);
    report("symlink", r, s, "a-target");
    r = syscall(SYS_unlink, c);
    report("unlink", r, c, "");
    r = syscall(SYS_unlink, c);
    report("unlink_enoent", r, c, "");
    r = syscall(SYS_rmdir, d);
    report("rmdir", r, d, "");
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, sock, sizeof sa.sun_path - 1);
    r = syscall(SYS_connect, fd, &sa, (long) sizeof sa);
    report("connect", r, sock, "");
    if (fd >= 0) close(fd);
    r = syscall(SYS_openat, AT_FDCWD, argv[3], O_WRONLY, 0);
    report("open_eacces", r, argv[3], "");

    r = syscall(SYS_creat, a2, 0600);
    report("creat", r, a2, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_renameat2, AT_FDCWD, a2, AT_FDCWD, b2, 0);
    report("renameat2", r, a2, b2);
    r = syscall(SYS_unlinkat, AT_FDCWD, b2, 0);
    report("unlinkat", r, b2, "");
    r = syscall(SYS_mkdirat, AT_FDCWD, d2, 0700);
    report("mkdirat", r, d2, "");
    r = syscall(SYS_unlinkat, AT_FDCWD, d2, AT_REMOVEDIR);
    report("unlinkat_removedir", r, d2, "");
    r = syscall(SYS_open, a3, O_WRONLY | O_CREAT, 0600);
    report("open", r, a3, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_linkat, AT_FDCWD, a3, AT_FDCWD, c3, 0);
    report("linkat", r, a3, c3);
    r = syscall(SYS_symlinkat, "t2", AT_FDCWD, s3);
    report("symlinkat", r, s3, "t2");
    how.flags = O_WRONLY | O_CREAT;
    how.mode = 0600;
    how.resolve = 0;
    r = syscall(437, AT_FDCWD, a4, &how, (long) sizeof how);
    report("openat2", r, a4, ""); if (r >= 0) close((int) r);

    /* the three rows jail-v1 §11.2 gained: a pathname truncate and the two
       mknod spellings. A FIFO needs no privilege. */
    r = syscall(SYS_truncate, a3, 0L);
    report("truncate", r, a3, "");
    r = syscall(SYS_mknod, n1, S_IFIFO | 0600, 0);
    report("mknod", r, n1, "");
    r = syscall(SYS_mknodat, AT_FDCWD, n2, S_IFIFO | 0600, 0);
    report("mknodat", r, n2, "");
    r = syscall(SYS_ftruncate, 0, 0L);
    report("ftruncate", r, "", "");
    return 0;
}

/* helper exec-cases MISSING NOEXEC */
static int mode_exec_cases(int argc, char **argv) {
    char *av[2];
    if (argc < 4) return 2;
    av[1] = NULL;
    av[0] = argv[2];
    execv(argv[2], av);
    report("execve_enoent", -1, argv[2], "");
    av[0] = argv[3];
    execv(argv[3], av);
    report("execve_eacces", -1, argv[3], "");
    av[0] = "/bin/true";
    execv("/bin/true", av);
    report("execve_true", -1, "/bin/true", "");
    return 9;
}

/* helper fork-once */
static int mode_fork_once(void) {
    pid_t pid = fork();
    int status = 0;
    if (pid < 0) return 3;
    if (pid == 0) {
        char buf[64];
        int n = snprintf(buf, sizeof buf, "child\t%d\t0\t\t\n", (int) getpid());
        ssize_t w = write(1, buf, (size_t) n);
        (void) w;
        _exit(7);
    }
    waitpid(pid, &status, 0);
    report("parent", (long) pid, "", "");
    return 0;
}

static void *sleeper(void *arg) {
    (void) arg;
    usleep(300000);
    report("worker", 0, "", "");
    return NULL;
}

static char *g_exec_argv[2];

static void *execer(void *arg) {
    (void) arg;
    usleep(150000);
    execv(g_exec_argv[0], g_exec_argv);
    _exit(3);
}

/* helper threads leader-exit | helper threads worker-exec PROGRAM */
static int mode_threads(int argc, char **argv) {
    pthread_t t[4];
    int i;
    if (argc < 3) return 2;
    if (strcmp(argv[2], "worker-exec") == 0) {
        if (argc < 4) return 2;
        g_exec_argv[0] = argv[3];
        g_exec_argv[1] = NULL;
        for (i = 0; i < 3; i++) pthread_create(&t[i], NULL, sleeper, NULL);
        pthread_create(&t[3], NULL, execer, NULL);
        report("leader", 0, "", "");
        for (;;) pause();
    }
    for (i = 0; i < 4; i++) pthread_create(&t[i], NULL, sleeper, NULL);
    report("leader", 0, "", "");
    pthread_exit(NULL);
    return 0;
}

/* helper rwm PATH N */
static int mode_rwm(int argc, char **argv) {
    long n, i;
    int fd;
    char buf[64];
    if (argc < 4) return 2;
    n = atol(argv[3]);
    fd = (int) syscall(SYS_openat, AT_FDCWD, argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600);
    report("open_create", (long) fd, argv[2], "");
    if (fd < 0) return 3;
    for (i = 0; i < n; i++) {
        void *m;
        ssize_t w = write(fd, "hello", 5);
        (void) w;
        lseek(fd, 0, SEEK_SET);
        w = read(fd, buf, sizeof buf);
        (void) w;
        m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m != MAP_FAILED) { ((char *) m)[0] = 'x'; munmap(m, 4096); }
    }
    close(fd);
    report("done", n, argv[2], "");
    return 0;
}

/* helper storm N PATH: N covered openat, then wait for a second release
   byte, then one mkdir so the consumer can observe the queue recovering. */
static int mode_storm(int argc, char **argv) {
    long n, i;
    char dir[512];
    if (argc < 4) return 2;
    n = atol(argv[2]);
    for (i = 0; i < n; i++) {
        long r = syscall(SYS_openat, AT_FDCWD, argv[3], O_WRONLY | O_CREAT, 0600);
        if (r >= 0) close((int) r);
    }
    report("storm", n, argv[3], "");
    if (await_release()) return 4;
    snprintf(dir, sizeof dir, "%s.d", argv[3]);
    report("after", syscall(SYS_mkdir, dir, 0700), dir, "");
    return 0;
}

/* helper fileops N DIR: the J0 file workload. */
static int mode_fileops(int argc, char **argv) {
    long n, i;
    char a[512], b[512];
    if (argc < 4) return 2;
    n = atol(argv[2]);
    snprintf(a, sizeof a, "%s/w", argv[3]);
    snprintf(b, sizeof b, "%s/x", argv[3]);
    for (i = 0; i < n; i++) {
        long fd = syscall(SYS_openat, AT_FDCWD, a, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) close((int) fd);
        syscall(SYS_rename, a, b);
        syscall(SYS_unlink, b);
    }
    report("fileops", n, argv[3], "");
    return 0;
}

/* helper denied ROPATH */
static int mode_denied(int argc, char **argv) {
    long r;
    if (argc < 3) return 2;
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY | O_CREAT, 0600);
    report("open_erofs", r, argv[2], "");
    r = syscall(SYS_mkdir, argv[2], 0700);
    report("mkdir_erofs", r, argv[2], "");
    return 0;
}

/* helper raise: die from a signal, so the wait status is not an exit code */
static int mode_raise(void) {
    report("raising", 0, "", "");
    kill(getpid(), SIGKILL);
    return 0;
}

/* helper open-path PATH: one covered openat on an arbitrary byte string.
   The path is not echoed: it need not be printable. */
static int mode_open_path(int argc, char **argv) {
    long r;
    if (argc < 3) return 2;
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY | O_CREAT, 0600);
    if (r >= 0) close((int) r);
    printf("open_path\t%ld\t%d\t\t\n", r, r < 0 ? errno : 0);
    fflush(stdout);
    return 0;
}

/* helper openat2-short PATH: an open_how too small for the kernel to use,
   so its flags cannot be decoded by anyone, tracer included. */
static int mode_openat2_short(int argc, char **argv) {
    struct ouro_open_how how;
    long r;
    if (argc < 3) return 2;
    how.flags = O_WRONLY | O_CREAT;
    how.mode = 0600;
    how.resolve = 0;
    r = syscall(437, AT_FDCWD, argv[2], &how, (long) 8);
    report("openat2_short", r, argv[2], "");
    return 0;
}

/* helper shell-ops BASE: the same shape through coreutils, for bubblewrap. */
static int mode_shell_ops(int argc, char **argv) {
    char a[512], b[512], d[512];
    long r;
    if (argc < 3) return 2;
    snprintf(a, sizeof a, "%s/a", argv[2]);
    snprintf(b, sizeof b, "%s/b", argv[2]);
    snprintf(d, sizeof d, "%s/d", argv[2]);
    r = syscall(SYS_openat, AT_FDCWD, a, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    report("open_create", r, a, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_rename, a, b);
    report("rename", r, a, b);
    r = syscall(SYS_unlink, b);
    report("unlink", r, b, "");
    r = syscall(SYS_mkdir, d, 0700);
    report("mkdir", r, d, "");
    r = syscall(SYS_rmdir, d);
    report("rmdir", r, d, "");
    report("nspid", (long) getpid(), "", "");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "launch")) return mode_launch(argc, argv);
    if (!strcmp(argv[1], "closed-set")) return mode_closed_set(argc, argv);
    if (!strcmp(argv[1], "exec-cases")) return mode_exec_cases(argc, argv);
    if (!strcmp(argv[1], "fork-once")) return mode_fork_once();
    if (!strcmp(argv[1], "threads")) return mode_threads(argc, argv);
    if (!strcmp(argv[1], "rwm")) return mode_rwm(argc, argv);
    if (!strcmp(argv[1], "storm")) return mode_storm(argc, argv);
    if (!strcmp(argv[1], "fileops")) return mode_fileops(argc, argv);
    if (!strcmp(argv[1], "denied")) return mode_denied(argc, argv);
    if (!strcmp(argv[1], "raise")) return mode_raise();
    if (!strcmp(argv[1], "open-path")) return mode_open_path(argc, argv);
    if (!strcmp(argv[1], "openat2-short")) return mode_openat2_short(argc, argv);
    if (!strcmp(argv[1], "shell-ops")) return mode_shell_ops(argc, argv);
    return 2;
}
"##;

mod common;

// ---------------------------------------------------------------------------
// One tracer at a time
// ---------------------------------------------------------------------------

/// Serialise the checks in this binary.
///
/// Every check here drives real processes. A tracer's thread owns
/// `waitpid(-1, __WALL)` for the whole process, so while one is attached it
/// reaps *every* child this process has, including the `gcc` a second check is
/// waiting on and the launcher a second tracer just seized. Two of them at
/// once do not race on any data structure; they steal each other's children,
/// and the loser waits for a status that has already been collected.
///
/// That is a property of the binary, not of how it is invoked, so it is
/// enforced here rather than by passing `--test-threads=1`: the checks are
/// correct under any parallelism the runner chooses.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A check that panicked while holding this poisoned it. There is no shared
    // state behind the lock — only the process's children, which that check no
    // longer has — so the next one takes the guard and carries on.
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ------------------------------------------------------------- scaffolding

/// Report a missing precondition, in the words the rest of the suite uses.
/// Under `OURO_CONFORMANCE=1` a skip is a failure, so a conformance run
/// cannot pass by not running.
fn skip(reason: &str) -> bool {
    harness::skip_or_fail(reason);
    false
}

fn tool(path: &str) -> bool {
    Path::new(path).exists()
}

/// The shared build directory: the compiled helper and the filter file the
/// launcher installs. Built once per test binary.
fn build() -> Result<&'static (PathBuf, PathBuf), String> {
    static BUILD: OnceLock<Result<(PathBuf, PathBuf), String>> = OnceLock::new();
    BUILD
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("ouro-j1-observer-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            let source = dir.join("helper.c");
            std::fs::write(&source, HELPER_C).map_err(|e| format!("write helper.c: {e}"))?;
            let helper = dir.join("helper");
            // `-B` beside the compiler, so building the fixture does not
            // depend on `PATH`: `gcc` looks up `as` and `ld` there, and every
            // other program these checks run is named absolutely for the same
            // reason. A host that has the compiler but not its assembler
            // still skips, with that as the reason.
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
            // The launcher installs the bytes this crate produces. There is
            // no second copy of the program anywhere in the tests.
            let filter = dir.join("filter.bin");
            std::fs::write(&filter, narrowing_filter_bytes())
                .map_err(|e| format!("write filter.bin: {e}"))?;
            Ok((helper, filter))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// A per-test working directory, removed when the test ends.
struct Work {
    dir: PathBuf,
    helper: PathBuf,
    filter: PathBuf,
}

impl Work {
    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().into_owned()
    }

    fn base(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Prepare a test. `None` means the test skipped and must return.
fn setup(name: &str, tools: &[&str]) -> Option<Work> {
    for path in tools {
        if !tool(path) {
            skip(&format!("{name}: {path} is not installed"));
            return None;
        }
    }
    let (helper, filter) = match build() {
        Ok(pair) => pair,
        Err(err) => {
            skip(&format!("{name}: the fixture could not be built: {err}"));
            return None;
        }
    };
    let dir = std::env::temp_dir().join(format!("ouro-j1-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the work directory");
    Some(Work {
        dir,
        helper: helper.clone(),
        filter: filter.clone(),
    })
}

/// A launcher that is running and blocked on its release pipe.
struct Launched {
    pid: libc::pid_t,
    release: std::process::ChildStdin,
    output: BufReader<std::process::ChildStdout>,
}

impl Launched {
    /// Wait until the launcher has finished its own exec and installed the
    /// filter. Seizing before that would attach in the middle of an exec
    /// this test never asked about, and the kernel would rightly report that
    /// transition too.
    fn await_ready(&mut self) {
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .expect("the launcher announces itself");
        let report = Report::parse(line.trim_end_matches('\n'))
            .unwrap_or_else(|| panic!("unparseable readiness line {line:?}"));
        assert_eq!(report.label, "ready", "unexpected first line {line:?}");
    }

    /// Let the launcher exec.
    fn release(&mut self) {
        self.release
            .write_all(b"g")
            .expect("write the release byte");
        self.release.flush().expect("flush the release byte");
    }

    /// The rest of the fixture's stdout, as bytes. Used where the output
    /// carries a pathname that is not required to be text.
    fn raw_output(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut self.output, &mut buf);
        buf
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
        // The tracer thread owns every wait in this process, so the child is
        // never waited on here. Killing is only a safety net for a test that
        // failed before releasing.
        // SAFETY: `kill` with a pid this test created and a valid signal.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }
}

/// One line of fixture output.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Report {
    label: String,
    raw: i64,
    errno: i32,
    path: String,
    path2: String,
}

impl Report {
    fn parse(line: &str) -> Option<Report> {
        let mut fields = line.split('\t');
        let label = fields.next()?.to_string();
        let raw = fields.next()?.parse().ok()?;
        let errno = fields.next()?.parse().ok()?;
        let path = fields.next().unwrap_or_default().to_string();
        let path2 = fields.next().unwrap_or_default().to_string();
        Some(Report {
            label,
            raw,
            errno,
            path,
            path2,
        })
    }

    /// The signed raw syscall return the kernel produced, which is what the
    /// observer reports: the value on success, `-errno` on failure.
    fn ret(&self) -> i64 {
        if self.errno == 0 {
            self.raw
        } else {
            -i64::from(self.errno)
        }
    }
}

/// Spawn the launcher with the fixture arguments it should exec into.
fn launch(work: &Work, argv: &[&str]) -> Launched {
    let mut command = Command::new(&work.helper);
    command.arg("launch").arg(&work.filter).args(argv);
    spawn_launcher(command)
}

fn spawn_launcher(mut command: Command) -> Launched {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the launcher");
    let pid = child.id() as libc::pid_t;
    let release = child.stdin.take().expect("stdin pipe");
    let output = BufReader::new(child.stdout.take().expect("stdout pipe"));
    // `std::process::Child` never reaps on drop, and the tracer thread owns
    // every wait in this process, so the handle itself is not kept.
    drop(child);
    let mut launched = Launched {
        pid,
        release,
        output,
    };
    launched.await_ready();
    launched
}

/// Everything the observer said, and its counters.
struct Observed {
    events: Vec<TracerEvent>,
    summary: TracerSummary,
}

impl Observed {
    fn syscalls(&self) -> Vec<&TracerEvent> {
        self.events
            .iter()
            .filter(|event| matches!(event, TracerEvent::Syscall { .. }))
            .collect()
    }

    fn exits(&self) -> Vec<(libc::pid_t, i32)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Exit { pid, status, .. } => Some((*pid, *status)),
                _ => None,
            })
            .collect()
    }

    fn execs(&self) -> Vec<libc::pid_t> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Exec { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect()
    }

    fn forks(&self) -> Vec<(libc::pid_t, libc::pid_t)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Fork { parent, child, .. } => Some((*parent, *child)),
                _ => None,
            })
            .collect()
    }

    fn gaps(&self) -> Vec<(GapReason, Option<u64>)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Gap { reason, count, .. } => Some((*reason, *count)),
                _ => None,
            })
            .collect()
    }

    fn untraced_exits(&self) -> Vec<libc::pid_t> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::UntracedChildExit { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect()
    }

    fn finished(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, TracerEvent::Finished))
    }
}

/// Read every event until `Finished`, then take the summary.
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
            Ok(event) => events.push(event),
            Err(_) => break,
        }
    }
    let summary = tracer.finish();
    Observed { events, summary }
}

/// The primary and secondary path of a syscall event, as text.
fn paths(event: &TracerEvent) -> (String, String) {
    match event {
        TracerEvent::Syscall { args, .. } => (
            args.path
                .as_ref()
                .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
                .unwrap_or_default(),
            args.path2
                .as_ref()
                .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
                .unwrap_or_default(),
        ),
        _ => (String::new(), String::new()),
    }
}

fn describe(event: &TracerEvent) -> String {
    match event {
        TracerEvent::Syscall {
            tid,
            op,
            syscall,
            ret,
            ..
        } => {
            let (a, b) = paths(event);
            format!("{tid} {syscall} ({}) {a} {b} = {ret}", op.as_str())
        }
        other => format!("{other:?}"),
    }
}

/// Attach, with a message that names what was refused.
fn attach(pid: libc::pid_t, config: TracerConfig) -> Tracer {
    match Tracer::attach(pid, config) {
        Ok(tracer) => tracer,
        Err(err) => panic!("attach to {pid} failed: {err}"),
    }
}

/// Wait for the inside launcher to appear under `root` and return its host
/// pid, validated by its argv.
fn find_launcher(root: libc::pid_t, argv0: &[u8], budget: Duration) -> Option<libc::pid_t> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        for pid in descendants(root) {
            if let Some(argv) = cmdline(pid)
                && argv.first().is_some_and(|first| first == argv0)
            {
                return Some(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    None
}

// ------------------------------------------------------------------ tests

/// O01: every closed-set result the observer reports is the result the
/// traced program says it got, with the same errno, the same paths and the
/// same syscall; and a read-only open produces no event at all.
#[test]
fn o01_every_closed_set_result_matches_the_fixture() {
    let _serial = serial();
    let Some(work) = setup("o01", &["/usr/bin/gcc"]) else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let locked = work.path("locked");
    std::fs::write(&locked, b"x").expect("create the locked file");
    std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o000)).expect("chmod 000");

    let helper = work.helper.to_string_lossy().into_owned();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "closed-set", &base, &locked]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    // label -> the syscall and operation it must produce, or None when the
    // closed set does not cover it.
    let expected: &[(&str, Option<(&str, ClosedOp)>)] = &[
        ("open_create", Some(("openat", ClosedOp::Open))),
        ("open_rdonly", None),
        ("open_write", Some(("openat", ClosedOp::Open))),
        ("open_enoent", Some(("openat", ClosedOp::Open))),
        ("mkdir", Some(("mkdir", ClosedOp::Mkdir))),
        ("mkdir_eexist", Some(("mkdir", ClosedOp::Mkdir))),
        ("rename", Some(("rename", ClosedOp::Rename))),
        ("link", Some(("link", ClosedOp::Link))),
        ("symlink", Some(("symlink", ClosedOp::Symlink))),
        ("unlink", Some(("unlink", ClosedOp::Unlink))),
        ("unlink_enoent", Some(("unlink", ClosedOp::Unlink))),
        ("rmdir", Some(("rmdir", ClosedOp::Rmdir))),
        ("connect", Some(("connect", ClosedOp::Connect))),
        ("open_eacces", Some(("openat", ClosedOp::Open))),
        ("creat", Some(("creat", ClosedOp::Open))),
        ("renameat2", Some(("renameat2", ClosedOp::Rename))),
        ("unlinkat", Some(("unlinkat", ClosedOp::Unlink))),
        ("mkdirat", Some(("mkdirat", ClosedOp::Mkdir))),
        ("unlinkat_removedir", Some(("unlinkat", ClosedOp::Unlink))),
        ("open", Some(("open", ClosedOp::Open))),
        ("linkat", Some(("linkat", ClosedOp::Link))),
        ("symlinkat", Some(("symlinkat", ClosedOp::Symlink))),
        ("openat2", Some(("openat2", ClosedOp::Open))),
        ("truncate", Some(("truncate", ClosedOp::Truncate))),
        ("mknod", Some(("mknod", ClosedOp::Mknod))),
        ("mknodat", Some(("mknodat", ClosedOp::Mknod))),
        // `ftruncate` mutates through a descriptor, like `write`, and is
        // named in §11.2 as excluded.
        ("ftruncate", None),
    ];
    let labels: Vec<&str> = reports.iter().map(|r| r.label.as_str()).collect();
    assert_eq!(
        labels,
        expected.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        "the fixture must report every operation, in order"
    );
    // A few results the test asserts itself, so the comparison below cannot
    // pass by both sides being wrong in the same way.
    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["open_enoent"].errno,
        libc::ENOENT,
        "a missing directory"
    );
    assert_eq!(
        by_label["mkdir_eexist"].errno,
        libc::EEXIST,
        "the second mkdir"
    );
    assert_eq!(
        by_label["unlink_enoent"].errno,
        libc::ENOENT,
        "the second unlink"
    );
    assert_eq!(
        by_label["connect"].errno,
        libc::ENOENT,
        "a socket that is not there"
    );
    assert_eq!(
        by_label["open_eacces"].errno,
        libc::EACCES,
        "a mode 0000 file"
    );
    assert_eq!(
        by_label["open_rdonly"].errno, 0,
        "the read-only open must succeed"
    );

    // Only the events about this test's files. Nothing else reaches the
    // fixture's own paths, so this drops the loader's read-only opens
    // without dropping anything the fixture did.
    let ours: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|event| {
            let (a, b) = paths(event);
            a.starts_with(&base)
                || b.starts_with(&base)
                || matches!(
                    event,
                    TracerEvent::Syscall {
                        op: ClosedOp::Connect,
                        ..
                    }
                )
        })
        .collect();
    let wanted: Vec<&(&str, Option<(&str, ClosedOp)>)> =
        expected.iter().filter(|(_, e)| e.is_some()).collect();
    assert_eq!(
        ours.len(),
        wanted.len(),
        "observed:\n  {}\nexpected {} results",
        ours.iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join("\n  "),
        wanted.len()
    );
    for (event, (label, expectation)) in ours.iter().zip(wanted.iter()) {
        let (want_syscall, want_op) = expectation.expect("filtered to Some");
        let report = by_label[label];
        let TracerEvent::Syscall {
            op,
            syscall,
            ret,
            args,
            ..
        } = event
        else {
            unreachable!("filtered to syscalls")
        };
        assert_eq!(*syscall, want_syscall, "{label}: syscall");
        assert_eq!(*op, want_op, "{label}: operation");
        assert_eq!(*ret, report.ret(), "{label}: return value");
        if want_op == ClosedOp::Connect {
            let sockaddr = args.sockaddr.as_ref().expect("connect carries a sockaddr");
            assert_eq!(
                sockaddr.family,
                Some(libc::AF_UNIX as u16),
                "{label}: family"
            );
            let text = String::from_utf8_lossy(&sockaddr.bytes).into_owned();
            assert!(
                text.contains(&report.path),
                "{label}: the sockaddr must carry the path the fixture used: {text:?}"
            );
        } else {
            let (a, b) = paths(event);
            assert_eq!(a, report.path, "{label}: path");
            assert_eq!(b, report.path2, "{label}: second path");
            let snapshot = args.path.as_ref().expect("a path snapshot");
            assert!(
                snapshot.complete,
                "{label}: the path snapshot must be complete"
            );
        }
    }

    // The read-only open is outside the set: not an event, not a loss.
    assert!(
        observed.summary.filtered_readonly_opens >= 1,
        "the read-only open must be counted as filtered, not lost"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert_eq!(observed.gaps(), vec![], "no gaps in a clean run");
    assert_eq!(
        observed.execs(),
        vec![run.pid],
        "one confirmed exec: the launcher's"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)], "one exit, status 0");
    assert!(observed.finished(), "the tracer must report Finished");
}

/// O01/O06 through bubblewrap: the same evidence for a process in a pid and
/// user namespace, found by walking `/proc` rather than by having forked it,
/// with the host pid in the events and the namespace pid in the process.
#[test]
fn o01_through_bubblewrap_carries_host_pids_for_namespace_processes() {
    let _serial = serial();
    if !common::live() {
        return;
    }
    let Some(work) = setup("bwrap", &["/usr/bin/gcc"]) else {
        return;
    };
    let build_dir = work
        .helper
        .parent()
        .expect("the helper lives in a directory")
        .to_path_buf();
    let mut command = Command::new(common::bwrap_path());
    command
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(&build_dir)
        .args([
            "/ouro",
            "--",
            "/ouro/helper",
            "launch",
            "/ouro/filter.bin",
            "/ouro/helper",
            "shell-ops",
            "/tmp",
        ]);
    let mut run = spawn_launcher(command);
    let bwrap = run.pid;
    let Some(inner) = find_launcher(bwrap, b"/ouro/helper", Duration::from_secs(15)) else {
        panic!("the inside launcher never appeared under bwrap {bwrap}");
    };
    let ns = nspid(inner).expect("NSpid of the inside launcher");
    let tracer = attach(inner, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert!(
        ns.len() >= 2,
        "the launcher must be inside a pid namespace: {ns:?}"
    );
    assert_eq!(
        ns[0], inner,
        "the first NSpid entry is the host pid we seized"
    );
    let inside = *ns.last().expect("a namespace pid");
    assert_ne!(
        inside, inner,
        "host pid {inner} must differ from namespace pid {inside}"
    );
    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["nspid"].raw,
        i64::from(inside),
        "the process sees its namespace pid; the observer reports the host pid"
    );

    let expected: &[(&str, &str, ClosedOp)] = &[
        ("open_create", "openat", ClosedOp::Open),
        ("rename", "rename", ClosedOp::Rename),
        ("unlink", "unlink", ClosedOp::Unlink),
        ("mkdir", "mkdir", ClosedOp::Mkdir),
        ("rmdir", "rmdir", ClosedOp::Rmdir),
    ];
    let ours: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|event| {
            let (a, b) = paths(event);
            a.starts_with("/tmp/") || b.starts_with("/tmp/")
        })
        .collect();
    assert_eq!(
        ours.len(),
        expected.len(),
        "observed:\n  {}",
        ours.iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    for (event, (label, want_syscall, want_op)) in ours.iter().zip(expected.iter()) {
        let report = by_label[label];
        let TracerEvent::Syscall {
            pid,
            op,
            syscall,
            ret,
            ..
        } = event
        else {
            unreachable!()
        };
        assert_eq!(*syscall, *want_syscall, "{label}");
        assert_eq!(*op, *want_op, "{label}");
        assert_eq!(*ret, report.ret(), "{label}");
        assert_eq!(*pid, inner, "{label}: events carry the host pid");
        let (a, b) = paths(event);
        assert_eq!(a, report.path, "{label}: path");
        assert_eq!(b, report.path2, "{label}: second path");
    }
    assert_eq!(
        observed.exits(),
        vec![(inner, 0)],
        "the inside process exited 0"
    );
    assert!(
        observed.untraced_exits().contains(&bwrap),
        "bubblewrap is a child of this process and never a tracee: {:?}",
        observed.untraced_exits()
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a failed exec is a result with an errno, a successful one is the
/// confirmed transition, and the two are never confused.
#[test]
fn o02_exec_success_and_failure_are_distinct_events() {
    let _serial = serial();
    let Some(work) = setup("exec", &["/usr/bin/gcc", "/bin/true"]) else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let missing = work.path("absent-program");
    let noexec = work.path("not-executable");
    std::fs::write(&noexec, b"#!/nope\n").expect("create the non-executable file");
    std::fs::set_permissions(&noexec, PermissionsExt::from_mode(0o644)).expect("chmod 644");

    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "exec-cases", &missing, &noexec]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(by_label["execve_enoent"].errno, libc::ENOENT);
    assert_eq!(by_label["execve_eacces"].errno, libc::EACCES);
    assert!(
        !by_label.contains_key("execve_true"),
        "the last exec must succeed, so the fixture never reports it"
    );

    let failures: Vec<(String, i64)> = observed
        .syscalls()
        .into_iter()
        .filter_map(|event| match event {
            TracerEvent::Syscall {
                op: ClosedOp::Exec,
                ret,
                ..
            } => Some((paths(event).0, *ret)),
            _ => None,
        })
        .collect();
    assert_eq!(
        failures,
        vec![
            (missing.clone(), -i64::from(libc::ENOENT)),
            (noexec.clone(), -i64::from(libc::EACCES)),
        ],
        "a failed exec is a result with the errno the caller saw"
    );
    assert_eq!(
        observed.execs(),
        vec![run.pid, run.pid],
        "two confirmed transitions: into the fixture and into /bin/true"
    );
    assert_eq!(observed.summary.exec_transitions, 2);
    // A confirmed transition names the image by the pathname snapshot of the
    // entry it was paired with. Descendant argv digests stay null in J1, so
    // this is the only name the consumer gets, and it is an argument
    // snapshot rather than a resolved path (§11.3).
    let images: Vec<String> = observed
        .events
        .iter()
        .filter_map(|event| match event {
            TracerEvent::Exec { path, .. } => Some(
                path.as_ref()
                    .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
                    .unwrap_or_default(),
            ),
            _ => None,
        })
        .collect();
    assert_eq!(
        images,
        vec![helper.clone(), "/bin/true".to_string()],
        "each transition carries the pathname its entry asked for"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)], "/bin/true exited 0");
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a fork child that never execs is tracked and reaped, and emits no
/// `proc.exit` — the spec ties that event to a witnessed exec.
#[test]
fn o02_a_fork_child_that_never_execs_emits_no_exit() {
    let _serial = serial();
    let Some(work) = setup("fork", &["/usr/bin/gcc"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "fork-once"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    let child = by_label["child"].raw as libc::pid_t;
    assert_eq!(
        by_label["parent"].raw as libc::pid_t, child,
        "the fixture waited for it"
    );

    assert!(
        observed.forks().contains(&(run.pid, child)),
        "the fork must be tracked: {:?}",
        observed.forks()
    );
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "only the process that was seen to exec produces an Exit"
    );
    assert_eq!(observed.summary.reaped_tasks, 2, "both tasks were reaped");
    assert_eq!(observed.summary.exits, 1);
    assert_eq!(observed.summary.tracees, 2);
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a leader that calls `pthread_exit` while four workers are alive is
/// not a process death. Exactly one `Exit` arrives, at the end, with the
/// group's status and not a worker's.
#[test]
fn o02_a_leader_leaving_live_workers_emits_exactly_one_exit() {
    let _serial = serial();
    let Some(work) = setup("threads", &["/usr/bin/gcc"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "threads", "leader-exit"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        reports.iter().filter(|r| r.label == "worker").count(),
        4,
        "all four workers must outlive the leader and finish"
    );
    assert_eq!(reports.iter().filter(|r| r.label == "leader").count(), 1);
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "one Exit, for the thread group, after the last thread"
    );
    assert_eq!(observed.summary.exits, 1);
    assert_eq!(
        observed.summary.tracees, 5,
        "the leader and its four workers were all tracked"
    );
    assert_eq!(
        observed.summary.reaped_tasks, 5,
        "every thread death was reaped"
    );
    assert_eq!(
        observed.summary.loss.final_status_unknown, 0,
        "the leader was the last thread reaped, so the status is the group's"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O02: a worker thread that execs becomes the leader. The process keeps the
/// identity it was born with, and one confirmed transition is reported.
#[test]
fn o02_a_non_leader_exec_keeps_the_birth_identity() {
    let _serial = serial();
    let Some(work) = setup("nonleader", &["/usr/bin/gcc", "/bin/true"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "threads", "worker-exec", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        observed.execs(),
        vec![run.pid, run.pid],
        "the exec from a worker is reported under the identity the process was born with"
    );
    assert_eq!(observed.summary.exec_transitions, 2);
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "one Exit, under the same identity, when /bin/true finishes"
    );
    assert_eq!(observed.summary.exits, 1);
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// The fail-closed property the supervisor relies on: with the narrowing
/// filter installed and no tracer attached, a closed-set call does not run.
/// It fails with ENOSYS. If the observer dies, the target stops working
/// rather than proceeding unobserved.
#[test]
fn the_narrowing_filter_without_a_tracer_fails_closed_with_enosys() {
    let _serial = serial();
    let Some(work) = setup("enosys", &["/usr/bin/gcc"]) else {
        return;
    };
    let target = work.path("never-created");
    let mut run = launch(&work, &["--probe-openat", &target]);
    // No tracer at all.
    run.release();
    let reports = run.lines();
    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();

    assert_eq!(
        by_label["openat_create"].errno,
        libc::ENOSYS,
        "a covered open must not run without a tracer"
    );
    assert_eq!(by_label["openat_create"].raw, -1);
    assert_eq!(
        by_label["openat_rdonly"].errno,
        libc::ENOSYS,
        "the filter traces by syscall number, so a read-only open fails too"
    );
    assert_eq!(
        by_label["write"].errno, 0,
        "a syscall outside the closed set is allowed straight through"
    );
    assert!(
        !Path::new(&target).exists(),
        "the syscall must not have run: ENOSYS is refusal, not a silent success"
    );
}

/// O03: a consumer that does not read cannot stop the tree. Loss is bounded,
/// counted exactly, coalesced into one gap, and no result is duplicated or
/// invented.
#[test]
fn o03_queue_loss_is_bounded_counted_and_coalesced() {
    let _serial = serial();
    let Some(work) = setup("loss", &["/usr/bin/gcc"]) else {
        return;
    };
    const STORM: u64 = 20_000;
    const QUEUE: usize = 64;
    let target = work.path("storm-target");
    let helper = work.helper.to_string_lossy().into_owned();
    let storm = STORM.to_string();
    let mut run = launch(&work, &[&helper, "storm", &storm, &target]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_max: QUEUE,
            ..TracerConfig::default()
        },
    );
    let started = Instant::now();
    run.release();

    // The fixture prints this after all 20,000 calls. Nothing has been read
    // from the queue yet, so backpressure has already engaged.
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the storm report");
    let report = Report::parse(line.trim_end()).expect("a storm report");
    assert_eq!(report.label, "storm");
    assert_eq!(report.raw, STORM as i64);
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "a stalled consumer must never hold the tree indefinitely"
    );

    // Start reading, which frees the queue.
    let mut events = Vec::new();
    while let Ok(event) = tracer.events().recv_timeout(Duration::from_millis(500)) {
        events.push(event);
    }
    // One more call, so the gap the tracer has been carrying is delivered
    // ahead of the result that follows it.
    run.release();
    let rest = collect(tracer, Duration::from_secs(30));
    events.extend(rest.events);
    let observed = Observed {
        events,
        summary: rest.summary,
    };

    assert_eq!(
        observed.summary.ops.open, STORM,
        "every call was observed exactly once, whether or not it could be delivered"
    );
    assert!(
        observed.summary.loss.queue_dropped > 0,
        "the queue was 64 events deep and 20,000 arrived"
    );
    let queue_gaps: Vec<(GapReason, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _)| *reason == GapReason::QueueFull)
        .collect();
    assert!(!queue_gaps.is_empty(), "the loss must be reported as a gap");
    for (_, count) in &queue_gaps {
        assert!(
            count.is_some(),
            "the count of dropped events is known exactly"
        );
    }
    let counted: u64 = queue_gaps.iter().filter_map(|(_, c)| *c).sum();
    assert_eq!(
        counted, observed.summary.loss.queue_dropped,
        "the gap accounts for every dropped event"
    );
    let delivered: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                TracerEvent::Syscall {
                    op: ClosedOp::Open,
                    ..
                }
            )
        })
        .collect();
    assert!(
        (delivered.len() as u64) < STORM,
        "some results were dropped, so not all of them can have been delivered"
    );
    for event in &delivered {
        assert_eq!(
            paths(event).0,
            target,
            "no delivered result names a path nobody asked for"
        );
    }
    assert!(
        observed.syscalls().iter().any(|e| matches!(
            e,
            TracerEvent::Syscall {
                op: ClosedOp::Mkdir,
                ..
            }
        )),
        "the call made after the queue recovered is reported"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// O04: `write`, `read` and `mmap` are outside the closed set. They produce
/// no events, and the filter does not even stop for them.
#[test]
fn o04_write_read_and_mmap_produce_no_events_and_no_stops() {
    let _serial = serial();
    let Some(work) = setup("o04", &["/usr/bin/gcc"]) else {
        return;
    };
    const ITERATIONS: i64 = 1000;
    let target = work.path("rwm-target");
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "rwm", &target, &ITERATIONS.to_string()]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["done"].raw, ITERATIONS,
        "the fixture ran the whole loop"
    );

    let ours: Vec<&TracerEvent> = observed
        .syscalls()
        .into_iter()
        .filter(|event| paths(event).0 == target)
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "only the open is covered: {}",
        ours.iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert_eq!(observed.summary.ops.open, 1);
    assert_eq!(observed.summary.ops.total(), 1, "nothing else is claimed");
    assert!(
        observed.summary.stops < 100,
        "{} stops for {ITERATIONS} write/read/mmap rounds: they must not stop at all",
        observed.summary.stops
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// A denied operation is the original operation with the errno the kernel
/// gave it. Classifying it is the consumer's job; the observer delivers the
/// result. EROFS comes from a read-only bind inside bubblewrap, EACCES from
/// a mode 0000 file (asserted by `o01_every_closed_set_result_matches_the_fixture`).
#[test]
fn o01_a_denied_write_keeps_its_own_operation_and_errno() {
    let _serial = serial();
    if !common::live() {
        return;
    }
    let Some(work) = setup("denied", &["/usr/bin/gcc"]) else {
        return;
    };
    let build_dir = work.helper.parent().expect("a directory").to_path_buf();
    let mut command = Command::new(common::bwrap_path());
    command
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(&build_dir)
        .args([
            "/ouro",
            "--",
            "/ouro/helper",
            "launch",
            "/ouro/filter.bin",
            "/ouro/helper",
            "denied",
            "/ouro/forbidden",
        ]);
    let mut run = spawn_launcher(command);
    let Some(inner) = find_launcher(run.pid, b"/ouro/helper", Duration::from_secs(15)) else {
        panic!("the inside launcher never appeared");
    };
    let tracer = attach(inner, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let by_label: BTreeMap<&str, &Report> = reports.iter().map(|r| (r.label.as_str(), r)).collect();
    assert_eq!(
        by_label["open_erofs"].errno,
        libc::EROFS,
        "a read-only bind denies a create with EROFS"
    );
    assert_eq!(by_label["mkdir_erofs"].errno, libc::EROFS);

    let ours: Vec<(String, ClosedOp, i64)> = observed
        .syscalls()
        .into_iter()
        .filter(|e| paths(e).0 == "/ouro/forbidden")
        .map(|e| match e {
            TracerEvent::Syscall { op, ret, .. } => (paths(e).0, *op, *ret),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        ours,
        vec![
            (
                "/ouro/forbidden".to_string(),
                ClosedOp::Open,
                -i64::from(libc::EROFS)
            ),
            (
                "/ouro/forbidden".to_string(),
                ClosedOp::Mkdir,
                -i64::from(libc::EROFS)
            ),
        ],
        "the denial is reported as the operation that was attempted"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// The J0 file workload again, under the productized tracer, so the cost
/// measured in J0 can be compared with the cost of the module that shipped.
#[test]
fn perf_the_j0_file_workload_costs_what_the_spike_cost() {
    let _serial = serial();
    let Some(work) = setup("perf", &["/usr/bin/gcc"]) else {
        return;
    };
    const ROUNDS: &str = "5000";
    let base = work.base();
    let helper = work.helper.to_string_lossy().into_owned();

    let untraced_start = Instant::now();
    let status = Command::new(&work.helper)
        .args(["fileops", ROUNDS, &base])
        .stdout(Stdio::null())
        .status()
        .expect("run the workload untraced");
    let untraced = untraced_start.elapsed();
    assert!(status.success(), "the untraced run must succeed");

    let mut run = launch(&work, &[&helper, "fileops", ROUNDS, &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    let traced_start = Instant::now();
    run.release();
    let observed = collect(tracer, Duration::from_secs(300));
    let traced = traced_start.elapsed();

    println!(
        "perf fileops rounds={ROUNDS}: untraced={:.3}s traced={:.3}s ratio={:.1}x \
         (J0 spike narrow median 0.81s, untraced 0.15s)",
        untraced.as_secs_f64(),
        traced.as_secs_f64(),
        traced.as_secs_f64() / untraced.as_secs_f64().max(0.001),
    );
    println!(
        "perf accounting: stops={} events={} open={} rename={} unlink={} loss={}",
        observed.summary.stops,
        observed.summary.emitted,
        observed.summary.ops.open,
        observed.summary.ops.rename,
        observed.summary.ops.unlink,
        observed.summary.loss.total(),
    );
    assert_eq!(observed.summary.ops.open, 5000);
    assert_eq!(observed.summary.ops.rename, 5000);
    assert_eq!(observed.summary.ops.unlink, 5000);
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// The preconditions of `attach`, tried from the outside: a pid that is not
/// ours, and one that is already traced.
#[test]
fn attach_refuses_what_it_may_not_trace() {
    let _serial = serial();
    let Some(work) = setup("preconditions", &["/usr/bin/gcc"]) else {
        return;
    };
    match Tracer::attach(1, TracerConfig::default()) {
        Err(TracerError::Seize { pid: 1, errno }) => {
            assert!(
                errno == libc::EPERM || errno == libc::ESRCH,
                "errno {errno}"
            );
        }
        other => panic!("seizing pid 1 must be refused, got {other:?}"),
    }
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "fork-once"]);
    let tracer = attach(run.pid, TracerConfig::default());
    match Tracer::attach(run.pid, TracerConfig::default()) {
        Err(TracerError::Seize { errno, .. }) => {
            assert_eq!(errno, libc::EPERM, "a second seize of the same task");
        }
        other => panic!("a task can only have one tracer, got {other:?}"),
    }
    run.release();
    let observed = collect(tracer, Duration::from_secs(30));
    assert!(observed.finished());
}

/// The filter the launcher installs is the one this crate publishes, and its
/// digest names those bytes.
#[test]
fn the_launcher_installs_the_published_filter() {
    let _serial = serial();
    let Some(work) = setup("filter", &["/usr/bin/gcc"]) else {
        return;
    };
    let on_disk = std::fs::read(&work.filter).expect("read the filter file");
    assert_eq!(
        on_disk,
        narrowing_filter_bytes(),
        "the fixture installs our bytes"
    );
    assert_eq!(on_disk.len(), narrowing_filter().len() * 8);
    let digest = narrowing_filter_digest();
    assert!(
        digest.starts_with("sha256:") && digest.len() == 71,
        "{digest}"
    );
    println!(
        "narrowing filter: {} instructions, {digest}",
        narrowing_filter().len()
    );
}

/// O06: a pathname is bytes. What the caller passed is what the snapshot
/// holds, whether or not it is text; and a snapshot that did not reach the
/// end of the name says so instead of presenting a prefix as the name.
#[test]
fn o06_a_path_is_bytes_and_a_short_snapshot_declares_itself_incomplete() {
    let _serial = serial();
    let Some(work) = setup("o06", &["/usr/bin/gcc"]) else {
        return;
    };
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let mut raw = work.base().into_bytes();
    raw.extend_from_slice(b"/na");
    raw.push(0xff);
    raw.extend_from_slice(b"me-longer-than-the-small-snapshot-bound");
    assert!(
        String::from_utf8(raw.clone()).is_err(),
        "the name really is not UTF-8"
    );
    let arg = OsString::from_vec(raw.clone());

    let open_path = |config: TracerConfig| {
        let mut command = Command::new(&work.helper);
        command
            .arg("launch")
            .arg(&work.filter)
            .arg(&work.helper)
            .arg("open-path")
            .arg(&arg);
        let mut run = spawn_launcher(command);
        let pid = run.pid;
        let tracer = attach(pid, config);
        run.release();
        let _ = run.raw_output();
        let observed = collect(tracer, Duration::from_secs(30));
        let snapshot = observed
            .syscalls()
            .into_iter()
            .find_map(|event| match event {
                TracerEvent::Syscall {
                    op: ClosedOp::Open,
                    args,
                    ..
                } => args.path.clone(),
                _ => None,
            })
            .expect("the covered open must be observed");
        (snapshot, observed)
    };

    let (whole, observed) = open_path(TracerConfig::default());
    assert_eq!(
        whole.bytes, raw,
        "the snapshot is the caller's bytes, not a lossy rendering"
    );
    assert!(
        whole.complete,
        "4096 bytes is more than enough for this name"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );

    let (short, observed) = open_path(TracerConfig {
        path_snapshot_max: 16,
        ..TracerConfig::default()
    });
    assert_eq!(
        short.bytes,
        raw[..16].to_vec(),
        "what was read is a prefix of the name"
    );
    assert!(
        !short.complete,
        "and it must not be presented as the whole name"
    );
    // The launcher's own `execve` path is longer than sixteen bytes too, so
    // it is counted here as well; what matters is that each one says so.
    assert!(
        observed.summary.loss.path_truncated >= 1,
        "a snapshot that stopped at the bound must be counted"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "a truncated path is a weaker claim, not a lost result: {:?}",
        observed.summary.loss
    );
    assert_eq!(
        observed.summary.ops.open, 1,
        "the result itself is still reported"
    );
}

/// O03/L4: an `open_how` the kernel would reject is metadata nobody can
/// decode, so membership of the covered mutation set was never established.
/// No covered `Open` is delivered, nothing is guessed, and because the kernel
/// rejected the same structure there is no covered operation to have missed:
/// the call is counted as an invalid argument, not as lost coverage.
#[test]
fn o03_an_undecodable_open_how_is_never_a_covered_open() {
    let _serial = serial();
    let Some(work) = setup("openhow", &["/usr/bin/gcc"]) else {
        return;
    };
    let target = work.path("openat2-short");
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "openat2-short", &target]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    let report = reports
        .iter()
        .find(|r| r.label == "openat2_short")
        .expect("the fixture reports its openat2");
    assert_eq!(
        report.errno,
        libc::EINVAL,
        "the kernel refuses a short open_how too"
    );

    assert!(
        observed.syscalls().iter().all(|event| !matches!(
            event,
            TracerEvent::Syscall {
                syscall: "openat2",
                ..
            }
        )),
        "an open whose flags could not be decoded must not be delivered as a \
         covered Open: {}",
        observed
            .syscalls()
            .iter()
            .map(|e| describe(e))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(!Path::new(&target).exists(), "and the call really did fail");
    assert_eq!(
        observed.summary.argument_invalid, 1,
        "the kernel rejected the same structure, so this is the tracee's \
         argument and not the observer's coverage"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "a tracee must not be able to manufacture loss: {:?}",
        observed.summary.loss
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// `Exit` carries the raw wait status, so a consumer can tell a process that
/// exited from one that was killed. A signal death is not an exit code.
#[test]
fn o02_an_exit_carries_the_raw_wait_status_of_a_signal_death() {
    let _serial = serial();
    let Some(work) = setup("raise", &["/usr/bin/gcc"]) else {
        return;
    };
    let helper = work.helper.to_string_lossy().into_owned();
    let mut run = launch(&work, &[&helper, "raise"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        reports.len(),
        1,
        "the fixture announces itself and then dies"
    );
    let exits = observed.exits();
    assert_eq!(exits.len(), 1, "one thread group died: {exits:?}");
    let (pid, status) = exits[0];
    assert_eq!(pid, run.pid);
    assert!(
        libc::WIFSIGNALED(status),
        "status {status:#x} must say the process was killed, not that it returned"
    );
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert!(
        !libc::WIFEXITED(status),
        "a signal death has no exit code to report"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// O03: the in-flight bound of §11.4 is real. When it is reached, entries
/// are refused and counted, and the results that would have followed become
/// gaps rather than events the observer cannot stand behind.
#[test]
fn o03_the_in_flight_bound_refuses_entries_and_reports_no_results() {
    let _serial = serial();
    let Some(work) = setup("inflight", &["/usr/bin/gcc"]) else {
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let locked = work.path("locked");
    std::fs::write(&locked, b"x").expect("create the locked file");
    std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o000)).expect("chmod 000");
    let helper = work.helper.to_string_lossy().into_owned();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "closed-set", &base, &locked]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            inflight_max: 0,
            ..TracerConfig::default()
        },
    );
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));

    assert_eq!(
        reports.len(),
        27,
        "the fixture still runs: the bound is ours, not the tracee's"
    );
    assert!(
        observed.syscalls().is_empty(),
        "no entry could be recorded, so no result is claimed"
    );
    assert_eq!(observed.summary.ops.total(), 0);
    assert!(
        observed.summary.loss.inflight_rejected >= 26,
        "every closed-set entry was refused: {}",
        observed.summary.loss.inflight_rejected
    );
    assert_eq!(
        observed.summary.loss.unmatched_exits, 0,
        "a refused entry is not stepped to an exit"
    );
    assert!(
        observed
            .gaps()
            .iter()
            .any(|(reason, _)| *reason == GapReason::InflightExhausted),
        "the refusals are reported as gaps: {:?}",
        observed.gaps()
    );
    // Exec and exit tracking do not depend on the in-flight table.
    assert_eq!(observed.execs(), vec![run.pid]);
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}
