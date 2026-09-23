#![cfg(target_os = "linux")]
//! J4 slice L: loss handling end to end (jail-v1 §11.4, §15 O03, O05, R04,
//! §16 "loss handling").
//!
//! What is checked, live on the reference host:
//!
//! - R04: a real ptrace-observer loss — a thread parked in
//!   `openat(FIFO, O_WRONLY)` destroyed by a sibling's `execve`, which the
//!   observer can only report as `entry_abandoned` — stops a strict attempt
//!   (cause `evidence_loss`, exit 1) and lets a best-effort one run to its
//!   own end (exit 1 for the loss), in `tool` and `none`. The classes the
//!   lost open belongs to are degraded with null counts; the classes it does
//!   not belong to keep counts equal to what the fixture did; the protection
//!   label is the profile's; the trace carries the gap note.
//! - O03: a class never returns to active after an early gap, however much
//!   clean activity follows; an exit is never unmatched, because the observer
//!   steps a tracee to a syscall exit only with its entry in hand (checked at
//!   the tracer seam, where a mutation of that rule is visible); map
//!   exhaustion (the in-flight bound) and ring loss (the tracer queue) reached
//!   through the product with the shrink-only test seams.
//! - O05: an observer that cannot attach refuses before exec in best-effort
//!   too, whichever step notices; every directory-entry operation lost to the
//!   in-flight bound degrades `fs.write`; a denied connect counts only under
//!   `fs.deny`, for the ptrace observer and for the `agent` mediator.
//! - §11.4 "Record actual values in the observer plan": the bounds in force,
//!   and any test seam that shrank them, are in the receipt.
//!
//! The fixture is a C program built at test time (gcc, as the observer
//! suites do). Every process signalled is one these tests started; every
//! file is under a private temporary directory.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use jsonschema::{Registry, Resource, Validator};
use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::tracer::{
    GapReason, Tracer, TracerConfig, TracerEvent, TracerSummary, narrowing_filter_bytes,
};
use serde_json::Value;

mod common;

const HELPER_C: &str = r##"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void report(const char *label, long r, int err, const char *p) {
    printf("%s\t%ld\t%d\t%s\n", label, r, err, p ? p : "");
    fflush(stdout);
}

static void on_signal(int sig) { (void) sig; }

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

/* A TCP connect to 127.0.0.1:1: refused (or unreachable without a
   loopback), never a denial. Returns the raw result; -2 when the socket
   itself was refused, which makes no connect at all. */
static long connect_loopback(int *err) {
    struct sockaddr_in a;
    long r;
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) { *err = errno; return -2; }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(1);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    r = connect(s, (struct sockaddr *) &a, sizeof a);
    *err = r < 0 ? errno : 0;
    close(s);
    return r;
}

/* ------------------------------------------------------------------ */
/* A thread parked inside openat(FIFO, O_WRONLY)                        */
/* ------------------------------------------------------------------ */

struct parked {
    const char *fifo;
    int go[2];
    pid_t tid;
    long result;
    int err;
    int stat_fd, syscall_fd;
};

static void *park_thread(void *arg) {
    struct parked *p = arg;
    char b;
    __atomic_store_n(&p->tid, (pid_t) syscall(SYS_gettid), __ATOMIC_RELEASE);
    while (read(p->go[0], &b, 1) < 0 && errno == EINTR) {}
    p->result = syscall(SYS_openat, AT_FDCWD, p->fifo, O_WRONLY | O_CLOEXEC);
    p->err = p->result < 0 ? errno : 0;
    return NULL;
}

/* Whether the kernel says the thread is asleep inside openat: state S, so
   past the observer's stop at its entry (a tracing stop reads t), and
   /proc/.../syscall naming openat. Only pread(2) of descriptors opened
   before the thread's call, which is outside the closed set. */
static int is_parked(struct parked *p) {
    char buf[512];
    char *rp;
    char state;
    ssize_t n = pread(p->stat_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    rp = strrchr(buf, ')');
    state = rp && rp[1] == ' ' ? rp[2] : 0;
    n = pread(p->syscall_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    return state == 'S' && buf[0] >= '0' && buf[0] <= '9' && atol(buf) == SYS_openat;
}

static int await_parked(struct parked *p) {
    int i;
    for (i = 0; i < 200000; i++) {
        if (is_parked(p)) return 0;
        usleep(100);
    }
    return -5;
}

/* Start the thread, open its /proc files while no call of it is in flight,
   let it make its call, and return once it is parked. */
static int park(struct parked *p, pthread_t *t) {
    char path[96];
    p->tid = 0;
    if (pipe2(p->go, O_CLOEXEC)) return -1;
    if (pthread_create(t, NULL, park_thread, p)) return -2;
    while (!__atomic_load_n(&p->tid, __ATOMIC_ACQUIRE)) sched_yield();
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", (int) p->tid);
    p->stat_fd = open(path, O_RDONLY | O_CLOEXEC);
    snprintf(path, sizeof path, "/proc/self/task/%d/syscall", (int) p->tid);
    p->syscall_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (p->stat_fd < 0 || p->syscall_fd < 0) return -3;
    if (write(p->go[1], "g", 1) != 1) return -4;
    return await_parked(p);
}

/* In a fresh child: park a thread, then execve SELF exit0 from the main
   thread. The exec destroys the parked thread with its call in flight. */
static void lose_by_exec(const char *fifo, const char *self) {
    struct parked p;
    pthread_t t;
    int r;
    char *args[3];
    memset(&p, 0, sizeof p);
    p.fifo = fifo;
    r = park(&p, &t);
    report("parked", r, 0, fifo);
    if (r) _exit(125);
    args[0] = (char *) self;
    args[1] = "exit0";
    args[2] = NULL;
    execv(self, args);
    report("execv", -1, errno, self);
    _exit(126);
}

static int lose_one_open(const char *fifo, const char *self) {
    int status = -1;
    pid_t kid = fork();
    if (kid == 0) lose_by_exec(fifo, self);
    if (kid < 0) { report("fork", -1, errno, ""); return -1; }
    waitpid(kid, &status, 0);
    report("child", status, 0, "");
    return status;
}

/* ------------------------------------------------------------------ */
/* Target modes                                                         */
/* ------------------------------------------------------------------ */

/* r04 FIFO SELF NCONNECT SLEEP_MS: NCONNECT loopback connects, then the
   target itself loses one open: a thread parks in it and the main thread
   re-execs SELF sleep SLEEP_MS, which destroys the parked thread with its
   call in flight. The new image sleeps, then exits 0. (The target, not a
   child: a strict stop's SIGTERM is delivered only after the exec's own
   syscall exit, so it cannot abandon a second entry; a namespace teardown's
   SIGKILL of a child mid-exec could.) */
static int mode_r04(int argc, char **argv) {
    struct parked p;
    pthread_t t;
    char *args[4];
    int i, n, err, rr;
    long r;
    if (argc < 6) return 2;
    n = atoi(argv[4]);
    for (i = 0; i < n; i++) {
        r = connect_loopback(&err);
        report("connect", r, err, "");
    }
    memset(&p, 0, sizeof p);
    p.fifo = argv[2];
    rr = park(&p, &t);
    report("parked", rr, 0, p.fifo);
    if (rr) return 3;
    args[0] = argv[3];
    args[1] = "sleep";
    args[2] = argv[5];
    args[3] = NULL;
    execv(argv[3], args);
    report("execv", -1, errno, argv[3]);
    return 4;
}

/* bg-park FIFO: a child parks a thread in openat(FIFO) and says so; the
   target then exits 0, leaving the child — its call still in flight — to
   the tree's teardown. */
static int mode_bg_park(int argc, char **argv) {
    int ready[2];
    char b;
    pid_t kid;
    if (argc < 3) return 2;
    if (pipe2(ready, O_CLOEXEC)) return 3;
    kid = fork();
    if (kid == 0) {
        struct parked p;
        pthread_t t;
        memset(&p, 0, sizeof p);
        p.fifo = argv[2];
        if (park(&p, &t) == 0 && write(ready[1], "p", 1) == 1) {
            for (;;) pause();
        }
        _exit(125);
    }
    if (kid < 0 || read(ready[0], &b, 1) != 1) {
        report("parked", -1, errno, argv[2]);
        return 4;
    }
    report("parked", 0, 0, argv[2]);
    return 0;
}

/* sleep MS: report, sleep, report, exit 0. */
static int mode_sleep(int argc, char **argv) {
    if (argc < 3) return 2;
    report("sleeping", 0, 0, "");
    sleep_ms(atol(argv[2]));
    report("done", 0, 0, "");
    return 0;
}

/* early-loss FIFO SELF DIR ROUNDS: one open lost first, then ROUNDS rounds
   of four successful fs.write results each. */
static int mode_early_loss(int argc, char **argv) {
    char d[4096], f[4096];
    int i, rounds, made = 0;
    long r;
    if (argc < 6) return 2;
    rounds = atoi(argv[5]);
    lose_one_open(argv[2], argv[3]);
    snprintf(d, sizeof d, "%s/d", argv[4]);
    snprintf(f, sizeof f, "%s/f", argv[4]);
    for (i = 0; i < rounds; i++) {
        if (syscall(SYS_mkdir, d, 0700) == 0) made++;
        if (syscall(SYS_rmdir, d) == 0) made++;
        r = syscall(SYS_openat, AT_FDCWD, f, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (r >= 0) { made++; close((int) r); }
        if (syscall(SYS_unlink, f) == 0) made++;
    }
    report("results", made, 0, "");
    return 0;
}

/* inflight FIFO DIR: park a thread in openat(FIFO), which holds the only
   in-flight slot the seam leaves; make every directory-entry call of the
   closed set (each runs; the observer cannot follow it); release the
   parked thread with a signal (EINTR, no restart); then one mkdir and one
   connect with the slot free again. */
static int mode_inflight(int argc, char **argv) {
    struct sigaction sa;
    struct parked p;
    struct open_how how;
    pthread_t t;
    char a[4096], a2[4096], a3[4096], b[4096], b2[4096], f[4096], g[4096], h[4096], o2[4096];
    char l1[4096], l2[4096], s1[4096], s2[4096], p1[4096], p2[4096], after[4096];
    const char *d;
    long r;
    int err, rr;
    if (argc < 4) return 2;
    d = argv[3];
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGUSR1, &sa, NULL);
#define P(buf, name) snprintf(buf, sizeof buf, "%s/%s", d, name)
    P(a, "a"); P(a2, "a2"); P(a3, "a3"); P(b, "b"); P(b2, "b2"); P(f, "f"); P(g, "g");
    P(h, "h"); P(o2, "o2"); P(l1, "l1"); P(l2, "l2"); P(s1, "s1"); P(s2, "s2");
    P(p1, "p1"); P(p2, "p2"); P(after, "after");
    memset(&p, 0, sizeof p);
    p.fifo = argv[2];
    rr = park(&p, &t);
    report("parked", rr, 0, p.fifo);
    if (rr) return 3;
#define OP(label, call, path) do { r = (call); report(label, r, r < 0 ? errno : 0, path); } while (0)
    OP("mkdir", syscall(SYS_mkdir, a, 0700), a);
    OP("mkdirat", syscall(SYS_mkdirat, AT_FDCWD, b, 0700), b);
    OP("rename", syscall(SYS_rename, a, a2), a2);
    OP("renameat", syscall(SYS_renameat, AT_FDCWD, b, AT_FDCWD, b2), b2);
    OP("renameat2", syscall(SYS_renameat2, AT_FDCWD, a2, AT_FDCWD, a3, 0), a3);
    OP("rmdir", syscall(SYS_rmdir, a3), a3);
    OP("unlinkat_dir", syscall(SYS_unlinkat, AT_FDCWD, b2, AT_REMOVEDIR), b2);
    OP("creat", syscall(SYS_creat, f, 0600), f);
    if (r >= 0) close((int) r);
    OP("open", syscall(SYS_open, g, O_WRONLY | O_CREAT | O_CLOEXEC, 0600), g);
    if (r >= 0) close((int) r);
    OP("openat", syscall(SYS_openat, AT_FDCWD, h, O_WRONLY | O_CREAT | O_CLOEXEC, 0600), h);
    if (r >= 0) close((int) r);
    memset(&how, 0, sizeof how);
    how.flags = O_WRONLY | O_CREAT | O_CLOEXEC;
    how.mode = 0600;
    OP("openat2", syscall(SYS_openat2, AT_FDCWD, o2, &how, sizeof how), o2);
    if (r >= 0) close((int) r);
    OP("truncate", syscall(SYS_truncate, f, 0), f);
    OP("link", syscall(SYS_link, f, l1), l1);
    OP("linkat", syscall(SYS_linkat, AT_FDCWD, f, AT_FDCWD, l2, 0), l2);
    OP("symlink", syscall(SYS_symlink, "f", s1), s1);
    OP("symlinkat", syscall(SYS_symlinkat, "f", AT_FDCWD, s2), s2);
    OP("mknod", syscall(SYS_mknod, p1, S_IFIFO | 0600, 0), p1);
    OP("mknodat", syscall(SYS_mknodat, AT_FDCWD, p2, S_IFIFO | 0600, 0), p2);
    OP("unlink", syscall(SYS_unlink, l1), l1);
    OP("unlinkat", syscall(SYS_unlinkat, AT_FDCWD, l2, 0), l2);
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report("released", p.result, p.err, p.fifo);
    OP("after_mkdir", syscall(SYS_mkdir, after, 0700), after);
    r = connect_loopback(&err);
    report("connect", r, err, "");
    return 0;
}

/* queue DIR: one result that carries a path (mkdir), one that carries none
   (connect), then exit. */
static int mode_queue(int argc, char **argv) {
    char q[4096];
    long r;
    int err;
    if (argc < 3) return 2;
    snprintf(q, sizeof q, "%s/q", argv[2]);
    r = syscall(SYS_mkdir, q, 0700);
    report("mkdir", r, r < 0 ? errno : 0, q);
    r = connect_loopback(&err);
    report("connect", r, err, "");
    return 0;
}

/* deny-connect DIR: a pathname AF_UNIX listener made mode 000 and a connect
   to it; a UDP connect to a broadcast address without SO_BROADCAST, twice;
   and a loopback TCP connect. A socket(2) the profile refuses makes no
   connect and is reported as such. */
static int udp_broadcast(const char *label, const char *addr) {
    struct sockaddr_in a;
    long r;
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) { report("udp_socket", -1, errno, label); return -1; }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(9);
    inet_pton(AF_INET, addr, &a.sin_addr);
    r = connect(s, (struct sockaddr *) &a, sizeof a);
    report(label, r, r < 0 ? errno : 0, addr);
    close(s);
    return 0;
}

static int mode_deny_connect(int argc, char **argv) {
    struct sockaddr_un u;
    long r;
    int l, c, err;
    if (argc < 3) return 2;
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    snprintf(u.sun_path, sizeof u.sun_path, "%s/s.sock", argv[2]);
    l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (l < 0) {
        report("unix_socket", -1, errno, u.sun_path);
    } else if (bind(l, (struct sockaddr *) &u, sizeof u) || listen(l, 4)) {
        report("unix_bind", -1, errno, u.sun_path);
    } else {
        chmod(u.sun_path, 0);
        c = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c < 0) {
            report("unix_socket", -1, errno, u.sun_path);
        } else {
            r = connect(c, (struct sockaddr *) &u, sizeof u);
            report("unix_connect", r, r < 0 ? errno : 0, u.sun_path);
            close(c);
        }
    }
    udp_broadcast("udp_connect", "127.255.255.255");
    udp_broadcast("udp_connect", "255.255.255.255");
    r = connect_loopback(&err);
    report("connect", r, err, "");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tracer-seam modes                                                    */
/* ------------------------------------------------------------------ */

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

/* launch FILTER PROG ARGS...: the observer's filter only, as in `none`;
   announce, wait for one byte on stdin, exec. */
static int mode_launch(int argc, char **argv) {
    char b;
    if (argc < 4) return 2;
    if (install_file(argv[2])) { fprintf(stderr, "narrowing failed\n"); return 3; }
    report("ready", (long) getpid(), 0, "");
    for (;;) {
        ssize_t n = read(0, &b, 1);
        if (n == 1) break;
        if (n == 0 || errno != EINTR) return 4;
    }
    execv(argv[3], &argv[3]);
    return 127;
}

static volatile int restarted;
static void on_restart(int sig) { (void) sig; __atomic_add_fetch(&restarted, 1, __ATOMIC_RELEASE); }

struct exec_arg { const char *self; };
static void *exec_thread(void *arg) {
    struct exec_arg *e = arg;
    char *args[3];
    args[0] = (char *) e->self;
    args[1] = "exit0";
    args[2] = NULL;
    execv(e->self, args);
    report("thread_execv", -1, errno, e->self);
    _exit(126);
}

/* pairing FIFO SELF DIR: every way a tracee can reach a syscall exit
   stop — or must not — that the observer has to pair: calls outside the
   set, read-only opens it filters at their entry, covered calls, a covered
   call interrupted and restarted (SA_RESTART), one interrupted for good
   (EINTR), a non-leader execve while a sibling has a covered call in
   flight, and vfork + execve. */
static int mode_pairing(int argc, char **argv) {
    struct sigaction sa;
    struct parked p;
    pthread_t t;
    char m[4096];
    int i, status;
    long r;
    pid_t kid;
    if (argc < 5) return 2;
    snprintf(m, sizeof m, "%s/m", argv[4]);
    for (i = 0; i < 2000; i++) syscall(SYS_getpid);
    for (i = 0; i < 100; i++) {
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) close((int) r);
    }
    for (i = 0; i < 50; i++) {
        syscall(SYS_mkdir, m, 0700);
        syscall(SYS_rmdir, m);
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_restart;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = on_signal;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);
    memset(&p, 0, sizeof p);
    p.fifo = argv[2];
    report("parked", park(&p, &t), 0, "");
    pthread_kill(t, SIGUSR1);
    while (!__atomic_load_n(&restarted, __ATOMIC_ACQUIRE)) usleep(100);
    report("reparked", await_parked(&p), 0, "");
    pthread_kill(t, SIGUSR2);
    pthread_join(t, NULL);
    report("interrupted", p.result, p.err, "");

    kid = fork();
    if (kid == 0) {
        struct parked q;
        struct exec_arg e;
        pthread_t tq, te;
        memset(&q, 0, sizeof q);
        q.fifo = argv[2];
        if (park(&q, &tq)) _exit(125);
        e.self = argv[3];
        pthread_create(&te, NULL, exec_thread, &e);
        pthread_join(te, NULL);
        _exit(124);
    }
    waitpid(kid, &status, 0);
    report("non_leader_exec", status, 0, "");

    kid = vfork();
    if (kid == 0) {
        char *args[3];
        args[0] = argv[3];
        args[1] = "exit0";
        args[2] = NULL;
        execv(argv[3], args);
        _exit(126);
    }
    waitpid(kid, &status, 0);
    report("vfork_exec", status, 0, "");
    return 0;
}

/* pairing-inflight FIFO DIR: under an in-flight bound of one, park a thread
   (it holds the slot), make twenty covered calls and twenty read-only
   opens the observer refuses to follow, release the thread (EINTR), then one
   covered call with the slot free. */
static int mode_pairing_inflight(int argc, char **argv) {
    struct sigaction sa;
    struct parked p;
    pthread_t t;
    char m[4096];
    int i;
    long r;
    if (argc < 4) return 2;
    snprintf(m, sizeof m, "%s/m", argv[3]);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGUSR2, &sa, NULL);
    memset(&p, 0, sizeof p);
    p.fifo = argv[2];
    report("parked", park(&p, &t), 0, "");
    for (i = 0; i < 10; i++) {
        syscall(SYS_mkdir, m, 0700);
        syscall(SYS_rmdir, m);
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) close((int) r);
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) close((int) r);
        syscall(SYS_getpid);
    }
    pthread_kill(t, SIGUSR2);
    pthread_join(t, NULL);
    report("interrupted", p.result, p.err, "");
    r = syscall(SYS_mkdir, m, 0700);
    report("after", r, r < 0 ? errno : 0, m);
    return 0;
}

/* ------------------------------------------------------------------ */
/* A ptrace wrapper around ouro-jail                                    */
/* ------------------------------------------------------------------ */

enum { R_FREE = 0, R_JAIL, R_KEPT, R_UNDECIDED, R_DETACHING };
struct task { pid_t tid; int role; pid_t held; int started; int classified; int quiet; };
#define MAXT 8192
static struct task tasks[MAXT];

static struct task *task_find(pid_t tid) {
    int i;
    for (i = 0; i < MAXT; i++) if (tasks[i].role != R_FREE && tasks[i].tid == tid) return &tasks[i];
    return NULL;
}

static struct task *task_add(pid_t tid, int role) {
    int i;
    for (i = 0; i < MAXT; i++) {
        if (tasks[i].role == R_FREE) {
            memset(&tasks[i], 0, sizeof tasks[i]);
            tasks[i].tid = tid;
            tasks[i].role = role;
            return &tasks[i];
        }
    }
    fprintf(stderr, "wrap: task table full\n");
    exit(119);
}

static pid_t tgid_of(pid_t tid) {
    char path[64], buf[4096], *at;
    int fd;
    ssize_t n;
    snprintf(path, sizeof path, "/proc/%d/status", (int) tid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    at = strstr(buf, "\nTgid:");
    return at ? (pid_t) atol(at + 6) : -1;
}

/* bubblewrap, or the jail's own launcher (not the observer probe's, whose
   program is the jail's `__probe-inside`). */
static int keep_image(pid_t pid) {
    char path[64], buf[65536], *arg, *base;
    int fd, launch = 0, inside = 0;
    ssize_t n;
    snprintf(path, sizeof path, "/proc/%d/cmdline", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    base = strrchr(buf, '/');
    base = base ? base + 1 : buf;
    if (!strcmp(base, "bwrap")) return 1;
    for (arg = buf; arg < buf + n; arg += strlen(arg) + 1) {
        if (!strcmp(arg, "__launch")) launch = 1;
        if (!strncmp(arg, "__probe", 7)) inside = 1;
    }
    return launch && !inside;
}

/* Asleep in something that is not an exec: a child of the jail that does
   not exec (the ptrace probe's, in pause(2)). */
static int asleep_without_exec(pid_t pid) {
    char path[64], buf[512], *rp;
    int fd;
    ssize_t n;
    char state;
    long nr;
    snprintf(path, sizeof path, "/proc/%d/stat", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    rp = strrchr(buf, ')');
    state = rp && rp[1] == ' ' ? rp[2] : 0;
    if (state != 'S') return 0;
    snprintf(path, sizeof path, "/proc/%d/syscall", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0 || buf[0] < '0' || buf[0] > '9') return 0;
    buf[n] = 0;
    nr = atol(buf);
    return nr != SYS_execve && nr != SYS_execveat;
}

static void resume(pid_t held) {
    if (held > 0) ptrace(PTRACE_CONT, held, 0, 0);
}

/* wrap-all JAIL ARGS... / wrap-launcher JAIL ARGS...: run JAIL as a traced
   child, the way a debugger started before it would. wrap-all traces
   every descendant. wrap-launcher holds every new process of the jail's own
   (its thread that made it stays at the fork-event stop) until the process
   shows what it is: one that execs bubblewrap or the jail's own launcher
   (`__launch` without the observer probe's `__probe-inside`) stays traced with
   everything below it; any other one, and one asleep without an exec (the
   ptrace probe's child), is detached first. So the jail's probes seize
   their own children as usual, and only its seize of the real launcher finds
   it traced already. Every stop is continued; signals are delivered. Exits
   with the jail's status. */
static int mode_wrap(int argc, char **argv, int selective) {
    long opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    struct task *self;
    pid_t jail;
    int st, code = 1, done = 0;
    time_t jail_gone = 0;
    if (argc < 3) return 2;
    jail = fork();
    if (jail == 0) {
        raise(SIGSTOP);
        execv(argv[2], &argv[2]);
        _exit(127);
    }
    if (waitpid(jail, &st, WUNTRACED) != jail || !WIFSTOPPED(st)) return 120;
    if (ptrace(PTRACE_SEIZE, jail, 0, opts)) { perror("wrap: seize"); return 121; }
    self = task_add(jail, R_JAIL);
    self->started = 1;
    self->classified = 1;
    kill(jail, SIGCONT);
    for (;;) {
        struct task *e;
        pid_t pid = waitpid(-1, &st, __WALL | WNOHANG);
        if (pid == 0) {
            int i;
            if (done && time(NULL) - jail_gone > 20) break;
            for (i = 0; i < MAXT; i++) {
                struct task *u = &tasks[i];
                if (u->role != R_UNDECIDED || !u->started) continue;
                if (asleep_without_exec(u->tid)) {
                    if (++u->quiet >= 20) {
                        u->role = R_DETACHING;
                        ptrace(PTRACE_INTERRUPT, u->tid, 0, 0);
                    }
                } else {
                    u->quiet = 0;
                }
            }
            usleep(200);
            continue;
        }
        if (pid < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (pid == jail) {
                code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                done = 1;
                jail_gone = time(NULL);
            }
            e = task_find(pid);
            if (e) {
                if (e->role == R_UNDECIDED || e->role == R_DETACHING) resume(e->held);
                e->role = R_FREE;
            }
            continue;
        }
        if (!WIFSTOPPED(st)) continue;
        {
            int sig = WSTOPSIG(st), event = st >> 16;
            e = task_find(pid);
            if (!e) {
                /* A new task whose first stop came before its parent's
                   event: it waits here until that event says what it is. */
                e = task_add(pid, R_KEPT);
                e->started = 1;
                continue;
            }
            if (e->role == R_DETACHING) {
                pid_t held = e->held;
                siginfo_t si;
                int inject = 0;
                if (event == 0 && sig != (SIGTRAP | 0x80)) inject = sig;
                (void) si;
                ptrace(PTRACE_DETACH, pid, 0, inject);
                e->role = R_FREE;
                resume(held);
                continue;
            }
            if (!e->started) {
                e->started = 1;
                if (e->classified) ptrace(PTRACE_CONT, pid, 0, 0);
                continue;
            }
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                unsigned long msg = 0;
                struct task *k;
                pid_t kid;
                ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg);
                kid = (pid_t) msg;
                k = task_find(kid);
                if (!k) k = task_add(kid, R_KEPT);
                k->classified = 1;
                if (e->role == R_JAIL && tgid_of(kid) == jail) {
                    k->role = R_JAIL;
                } else if (e->role == R_JAIL && selective) {
                    k->role = R_UNDECIDED;
                    k->held = pid;
                    if (k->started) ptrace(PTRACE_CONT, kid, 0, 0);
                    continue; /* the jail thread stays stopped */
                } else {
                    k->role = R_KEPT;
                }
                if (k->started) ptrace(PTRACE_CONT, kid, 0, 0);
                ptrace(PTRACE_CONT, pid, 0, 0);
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
                if (e->role == R_UNDECIDED) {
                    pid_t held = e->held;
                    if (keep_image(pid)) {
                        e->role = R_KEPT;
                        e->held = 0;
                        ptrace(PTRACE_CONT, pid, 0, 0);
                    } else {
                        ptrace(PTRACE_DETACH, pid, 0, 0);
                        e->role = R_FREE;
                    }
                    resume(held);
                    continue;
                }
                ptrace(PTRACE_CONT, pid, 0, 0);
                continue;
            }
            if (event == PTRACE_EVENT_STOP) {
                siginfo_t si;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) < 0 && errno == EINVAL) {
                    ptrace(PTRACE_LISTEN, pid, 0, 0); /* a group-stop */
                } else {
                    ptrace(PTRACE_CONT, pid, 0, 0);
                }
                continue;
            }
            if (event == 0) {
                ptrace(PTRACE_CONT, pid, 0, sig == (SIGTRAP | 0x80) ? 0 : sig);
                continue;
            }
            ptrace(PTRACE_CONT, pid, 0, 0);
        }
    }
    return code;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "exit0")) return 0;
    if (!strcmp(argv[1], "r04")) return mode_r04(argc, argv);
    if (!strcmp(argv[1], "sleep")) return mode_sleep(argc, argv);
    if (!strcmp(argv[1], "bg-park")) return mode_bg_park(argc, argv);
    if (!strcmp(argv[1], "early-loss")) return mode_early_loss(argc, argv);
    if (!strcmp(argv[1], "inflight")) return mode_inflight(argc, argv);
    if (!strcmp(argv[1], "queue")) return mode_queue(argc, argv);
    if (!strcmp(argv[1], "deny-connect")) return mode_deny_connect(argc, argv);
    if (!strcmp(argv[1], "launch")) return mode_launch(argc, argv);
    if (!strcmp(argv[1], "pairing")) return mode_pairing(argc, argv);
    if (!strcmp(argv[1], "pairing-inflight")) return mode_pairing_inflight(argc, argv);
    if (!strcmp(argv[1], "wrap-all")) return mode_wrap(argc, argv, 0);
    if (!strcmp(argv[1], "wrap-launcher")) return mode_wrap(argc, argv, 1);
    return 2;
}
"##;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The observer's thread owns `waitpid(-1, __WALL)` for the whole process in
/// the tracer-seam check, so everything here is serialised.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The fixture and the observer's filter, built once.
fn build() -> Option<&'static (PathBuf, PathBuf)> {
    static BUILD: OnceLock<Result<(PathBuf, PathBuf), String>> = OnceLock::new();
    let built = BUILD.get_or_init(|| {
        if !Path::new("/usr/bin/gcc").exists() {
            return Err("/usr/bin/gcc is not installed".to_owned());
        }
        // Cargo's scratch area for integration tests, not the shared /tmp.
        let dir =
            Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("j4-loss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let source = dir.join("loss.c");
        std::fs::write(&source, HELPER_C).map_err(|e| format!("write loss.c: {e}"))?;
        let helper = dir.join("j4-loss");
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
    });
    match built {
        Ok(pair) => Some(pair),
        Err(error) => {
            harness::skip_or_fail(&format!("the loss fixture: {error}"));
            None
        }
    }
}

/// `none` needs a delegated leaf (§9.3); the conformance run provides it.
fn none_live() -> bool {
    let leaf = ouro_jail::platform::linux::probe::run_one(
        "cgroup_delegated_leaf",
        &harness::jail_path(),
        Path::new("bwrap"),
    );
    if leaf.status != ouro_jail::platform::linux::probe::ProbeStatus::Available {
        harness::skip_or_fail(&format!(
            "the none checks need a delegated user scope: {}",
            leaf.evidence
        ));
        return false;
    }
    true
}

/// Whether this host can run a live check of `profile`.
fn live(profile: &str) -> bool {
    common::live() && (profile != "none" || none_live())
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path and a mode.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// One `ouro-jail run` over a private workspace holding the fixture at
/// `<workspace>/bin/j4-loss`, a FIFO nobody opens for reading at
/// `<workspace>/fifo`, and an empty `<workspace>/ops`.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    helper: PathBuf,
    fifo: PathBuf,
    ops: PathBuf,
}

fn case(profile: &str, evidence: &str) -> Option<Case> {
    case_on(Jail::new().unwrap(), profile, evidence)
}

fn case_on(jail: Jail, profile: &str, evidence: &str) -> Option<Case> {
    let (built, _) = build()?;
    let workspace = jail.root().join("workspace");
    private_dir(&workspace.join("bin"));
    private_dir(&workspace.join("ops"));
    let helper = workspace.join("bin/j4-loss");
    std::fs::copy(built, &helper).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let fifo = workspace.join("fifo");
    mkfifo(&fifo);
    let jail = jail
        .arg("run")
        .arg("--profile")
        .arg(profile)
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control();
    Some(Case {
        jail,
        ops: workspace.join("ops"),
        workspace,
        helper,
        fifo,
    })
}

impl Case {
    fn argv(&self, mode: &str, rest: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<OsString> {
        let mut argv = vec![self.helper.clone().into_os_string(), OsString::from(mode)];
        argv.extend(rest.iter().map(|arg| arg.as_ref().to_os_string()));
        argv
    }
}

/// One line the fixture reported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    label: String,
    raw: i64,
    errno: i32,
    path: String,
}

fn lines(stdout: &str) -> Vec<Line> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            Some(Line {
                label: fields.next()?.to_owned(),
                raw: fields.next()?.parse().ok()?,
                errno: fields.next()?.parse().ok()?,
                path: fields.next().unwrap_or_default().to_owned(),
            })
        })
        .collect()
}

fn line<'a>(lines: &'a [Line], label: &str) -> &'a Line {
    lines
        .iter()
        .find(|line| line.label == label)
        .unwrap_or_else(|| panic!("no fixture line {label:?} in {lines:#?}"))
}

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

/// One validator per checked-in schema, by stem.
fn validators() -> &'static BTreeMap<String, Validator> {
    static ONCE: OnceLock<BTreeMap<String, Validator>> = OnceLock::new();
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

/// Every receipt and trace event validated against the checked-in schemas;
/// returns the receipt of `phase`.
fn receipt(run: &Run, phase: &str) -> Value {
    run.assert_channels_complete();
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
    run.receipt_phase(phase).unwrap_or_else(|| {
        panic!(
            "no {phase} receipt: exit {:?}, stderr {}",
            run.code(),
            run.stderr_text()
        )
    })
}

fn details(receipt: &Value) -> &Value {
    &receipt["lifetime"]["native"]["details"]
}

fn audit_events(run: &Run) -> Vec<&Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == "audit")
        .collect()
}

/// Audit results whose (first) path is this workspace-relative one.
fn results_on<'a>(run: &'a Run, relative: &str) -> Vec<&'a Value> {
    audit_events(run)
        .into_iter()
        .filter(|event| {
            event["fields"]["path"]["kind"] == "workspace_relative"
                && event["fields"]["path"]["value"] == relative
        })
        .collect()
}

fn gap_notes<'a>(run: &'a Run, reason: &str) -> Vec<&'a Value> {
    run.trace_events()
        .iter()
        .filter(|event| {
            event["source"] == "wrapper"
                && event["fields"]["kind"] == "coverage_gap"
                && event["fields"]["reason"] == reason
        })
        .collect()
}

fn error_codes(receipt: &Value) -> Vec<String> {
    receipt["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|error| error["code"].as_str().map(str::to_owned))
        .collect()
}

/// The class entry, asserted degraded with a null count and a gap of
/// `reason` naming it; returns that gap.
fn assert_degraded<'a>(receipt: &'a Value, class: &str, reason: &str) -> &'a Value {
    let entry = &receipt["coverage"][class];
    assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    assert_eq!(
        entry["observed_count"],
        Value::Null,
        "{class}: a degraded class has no count: {entry:#}"
    );
    assert_eq!(entry["sources"], serde_json::json!(["audit"]), "{class}");
    entry["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gap| {
            gap["reason"] == reason
                && gap["classes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|name| name == class)
        })
        .unwrap_or_else(|| panic!("{class}: no {reason} gap naming it: {entry:#}"))
}

/// The class entry, asserted active with exactly `count` results.
fn assert_active(receipt: &Value, class: &str, count: u64) {
    let entry = &receipt["coverage"][class];
    assert_eq!(entry["status"], "active", "{class}: {entry:#}");
    assert_eq!(
        entry["observed_count"], count,
        "{class}: the count must be what the fixture did: {entry:#}"
    );
    assert!(entry["gaps"].as_array().unwrap().is_empty(), "{class}");
}

/// Connect results the fixture reported, split into denials (EACCES,
/// EPERM: `fs.deny`) and the rest (`net`). `-2` is a socket the profile
/// refused, which made no connect at all.
fn connects(lines: &[Line]) -> (u64, u64) {
    let mut denied = 0;
    let mut other = 0;
    for line in lines.iter().filter(|line| line.label.ends_with("connect")) {
        if line.raw == -2 {
            continue;
        }
        if line.raw < 0 && (line.errno == libc::EACCES || line.errno == libc::EPERM) {
            denied += 1;
        } else {
            other += 1;
        }
    }
    (denied, other)
}

// ===========================================================================
// R04: a real ptrace-observer loss, strict and best-effort, tool and none
// ===========================================================================

/// Loopback connects the R04 fixture makes before its loss.
const R04_CONNECTS: usize = 3;

/// The exec-class results of every R04 run: the target's exec, its re-exec,
/// its exit.
const R04_EXEC_RESULTS: u64 = 3;

fn r04(profile: &str, evidence: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case(profile, evidence) else {
        return;
    };
    let strict = evidence == "strict";
    // Strict must stop a target that would sleep far longer than the check
    // takes; best-effort lets a short sleep run out.
    let sleep_ms = if strict { "30000" } else { "300" };
    let connect_count = R04_CONNECTS.to_string();
    let argv = c.argv("r04", &[&c.fifo, &c.helper, &connect_count, &sleep_ms]);
    let started = Instant::now();
    let run = c
        .jail
        .timeout(Duration::from_secs(90))
        .target(argv)
        .run()
        .unwrap();
    let elapsed = started.elapsed();
    let label = format!("{profile}/{evidence}");
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");

    // The fixture did lose one open, and nothing else. (That the re-exec
    // ran is the exec count below: under strict, the stop can end the new
    // image before it says anything.)
    assert_eq!(line(&out, "parked").raw, 0, "{label}: {out:#?}");
    let (denied, other) = connects(&out);
    assert_eq!(denied, 0, "{label}: {out:#?}");
    assert_eq!(other, R04_CONNECTS as u64, "{label}: {out:#?}");

    // The jail exits 1 for the loss in both modes, with the error recorded.
    assert_eq!(run.code(), Some(1), "{label}: stderr {}", run.stderr_text());
    assert!(
        error_codes(&settled).contains(&"evidence_lost".to_owned()),
        "{label}: {:#}",
        settled["errors"]
    );
    let outcome = &settled["outcome"];
    if strict {
        assert_eq!(outcome["cause"], "evidence_loss", "{label}: {outcome:#}");
        assert_eq!(outcome["kind"], "signaled", "{label}: {outcome:#}");
        assert!(
            out.iter().all(|line| line.label != "done"),
            "{label}: the target was stopped before its end: {out:#?}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "{label}: stopped for the loss, not at the end of its sleep ({elapsed:?})"
        );
    } else {
        assert_eq!(outcome["kind"], "exited", "{label}: {outcome:#}");
        assert_eq!(outcome["code"], 0, "{label}: {outcome:#}");
        assert_eq!(outcome["cause"], Value::Null, "{label}: {outcome:#}");
        line(&out, "sleeping");
        line(&out, "done");
    }

    // Exactly the lost call's classes are degraded; the others are exact.
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "entry_abandoned");
        assert_eq!(gap["lost_count"], 1, "{label}: {gap:#}");
    }
    assert_active(&settled, "exec", R04_EXEC_RESULTS);
    assert_active(&settled, "net", R04_CONNECTS as u64);
    assert_eq!(settled["observer"]["sources"]["audit"], "degraded");
    assert_eq!(settled["observer"]["attached"], true);
    // The label is the profile's, loss or not.
    let (containment, protection) = if profile == "none" {
        ("none", "unprotected")
    } else {
        ("enforced", "enforced")
    };
    assert_eq!(settled["containment"], containment, "{label}");
    assert_eq!(settled["child_protection"], protection, "{label}");
    // The trace says what was lost, in a gap note.
    let notes = gap_notes(&run, "entry_abandoned");
    assert_eq!(notes.len(), 1, "{label}: one gap note: {notes:#?}");
    // And never invents the lost call's result: no result names the FIFO.
    assert!(
        results_on(&run, "fifo").is_empty(),
        "{label}: no result for the abandoned open: {:#?}",
        results_on(&run, "fifo")
    );
}

#[test]
fn j4_r04_ptrace_loss_strict_tool() {
    r04("tool", "strict");
}

#[test]
fn j4_r04_ptrace_loss_strict_none() {
    r04("none", "strict");
}

#[test]
fn j4_r04_ptrace_loss_best_effort_tool() {
    r04("tool", "best-effort");
}

#[test]
fn j4_r04_ptrace_loss_best_effort_none() {
    r04("none", "best-effort");
}

/// R04, the settlement case: a call still in flight when the tree is torn
/// down after the target's exit (X07) is a loss too. The kill interrupts it
/// after the observer let it run, so whether it had its effect is unknown
/// (for an `O_CREAT` open it may well have); the result is not invented and
/// its classes are degraded. Here a background child's thread is parked in
/// `openat(FIFO)` when the target exits. (Whether the jail also reports this
/// as an `evidence_lost` error depends today on when the supervisor reads it
/// — see the J4 slice L report — so only the coverage is asserted.)
fn teardown_loss(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case(profile, "strict") else {
        return;
    };
    let argv = c.argv("bg-park", &[&c.fifo]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "parked").raw, 0, "{profile}: {out:#?}");
    assert_eq!(settled["outcome"]["kind"], "exited", "{profile}");
    assert_eq!(settled["outcome"]["code"], 0, "{profile}");
    assert_eq!(settled["lifetime"]["tree_empty"], true, "{profile}: X07");
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "entry_abandoned");
        assert_eq!(gap["lost_count"], 1, "{profile}: {gap:#}");
    }
    // The target's exec and exit; the child never execs.
    assert_active(&settled, "exec", 2);
    assert_active(&settled, "net", 0);
    assert_eq!(gap_notes(&run, "entry_abandoned").len(), 1, "{profile}");
    assert!(
        results_on(&run, "fifo").is_empty(),
        "{profile}: no result for the interrupted open"
    );
    println!(
        "{profile}: exit {:?}, errors {:?}",
        run.code(),
        error_codes(&settled)
    );
}

#[test]
fn j4_r04_a_call_in_flight_at_teardown_is_loss_tool() {
    teardown_loss("tool");
}

#[test]
fn j4_r04_a_call_in_flight_at_teardown_is_loss_none() {
    teardown_loss("none");
}

// ===========================================================================
// O03: no return to active; no unmatched exit; exhaustion via the seams
// ===========================================================================

/// §11.4: "Coverage cannot return to fully active for the entire run after
/// a historical gap." One open lost first, then two hundred rounds of clean
/// `fs.write` results that the observer does see: the class stays degraded
/// with no count, and the gap's interval ends before them.
#[test]
fn j4_o03_a_class_never_returns_to_active_after_an_early_gap() {
    let _serial = serial();
    if !live("tool") {
        return;
    }
    let Some(c) = case("tool", "best-effort") else {
        return;
    };
    let argv = c.argv("early-loss", &[&c.fifo, &c.helper, &c.ops, &"200"]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "results").raw, 800, "{out:#?}");
    let gap = assert_degraded(&settled, "fs.write", "entry_abandoned").clone();
    // The observer saw every later result...
    let ops = c.ops.to_string_lossy().into_owned();
    let later: Vec<&Value> = audit_events(&run)
        .into_iter()
        .filter(|event| {
            matches!(
                event["operation"].as_str(),
                Some("fs.create" | "fs.unlink" | "fs.write")
            )
        })
        .collect();
    assert!(
        later.len() >= 800,
        "the clean results after the gap were observed: {} events (ops dir {ops})",
        later.len()
    );
    // ...after the gap closed, and still the class is not active again.
    let end: u64 = gap["end_ns"].as_str().unwrap().parse().unwrap();
    let after = later
        .iter()
        .filter(|event| {
            event["monotonic_ns"]
                .as_str()
                .and_then(|ns| ns.parse::<u64>().ok())
                .is_some_and(|ns| ns > end)
        })
        .count();
    assert!(after >= 800, "{after} results after the gap's end {end}");
    assert_eq!(settled["observer"]["sources"]["audit"], "degraded");
    assert_active(&settled, "net", 0);
}

/// Launch `argv` under the observer's filter and trace it with `config`,
/// the way the product does: attach while the launcher is blocked, release,
/// read until the observer finishes.
fn observe(
    argv: &[&dyn AsRef<std::ffi::OsStr>],
    config: TracerConfig,
) -> (Vec<Line>, Vec<TracerEvent>, TracerSummary) {
    let (helper, filter) = build().expect("built");
    let mut child = Command::new(helper)
        .arg("launch")
        .arg(filter)
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn");
    let pid = child.id() as libc::pid_t;
    let mut release = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    // The tracer thread owns every wait in this process from here on.
    drop(child);
    let mut ready = String::new();
    output.read_line(&mut ready).unwrap();
    assert!(ready.starts_with("ready\t"), "{ready:?}");
    let tracer = Tracer::attach(pid, config).unwrap_or_else(|e| panic!("attach {pid}: {e}"));
    release.write_all(b"g").unwrap();
    let mut text = String::new();
    let mut buf = String::new();
    while output.read_line(&mut buf).unwrap_or(0) > 0 {
        text.push_str(&buf);
        buf.clear();
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut events = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match tracer.events().recv_timeout(left) {
            Ok(TracerEvent::Finished) | Err(_) => break,
            Ok(event) => events.push(event),
        }
    }
    let summary = tracer.finish();
    (lines(&text), events, summary)
}

fn unmatched(events: &[TracerEvent], summary: &TracerSummary) -> Vec<String> {
    let mut found: Vec<String> = events
        .iter()
        .filter(|event| {
            matches!(event, TracerEvent::Gap { reason, .. } if *reason == GapReason::UnmatchedExit)
        })
        .map(|event| format!("{event:?}"))
        .collect();
    if summary.loss.unmatched_exits > 0 {
        found.push(format!(
            "unmatched_exits = {}",
            summary.loss.unmatched_exits
        ));
    }
    found
}

/// S2: "unmatched exit" is unreachable by construction, because the observer
/// steps a tracee to its syscall exit (`PTRACE_SYSCALL`) only when it holds
/// that tracee's entry, and continues it (`PTRACE_CONT`) otherwise. Checked
/// at the tracer seam over every way a tracee can reach — or must not reach
/// — an exit stop: calls outside the set, read-only opens filtered at their
/// entry, covered calls, an interrupted call restarted under `SA_RESTART`,
/// one interrupted for good, a non-leader `execve` with a sibling's call in
/// flight, `vfork`; and, under an in-flight bound of one, entries the
/// observer refused to follow. A rule that stepped any of those to an exit
/// without its entry shows here as `unmatched_exit`.
#[test]
fn j4_o03_unmatched_exit_is_unreachable() {
    let _serial = serial();
    if !common::live() {
        return;
    }
    let Some((helper, _)) = build() else {
        return;
    };
    let dir = common::private_tempdir();
    let fifo = dir.path().join("fifo");
    mkfifo(&fifo);
    let (out, events, summary) = observe(
        &[&helper, &"pairing", &fifo, &helper, &dir.path()],
        TracerConfig::default(),
    );
    assert_eq!(line(&out, "parked").raw, 0, "{out:#?}");
    assert_eq!(line(&out, "reparked").raw, 0, "{out:#?}");
    assert_eq!(line(&out, "interrupted").errno, libc::EINTR, "{out:#?}");
    assert_eq!(line(&out, "non_leader_exec").raw, 0, "{out:#?}");
    assert_eq!(line(&out, "vfork_exec").raw, 0, "{out:#?}");
    // Every path was taken.
    assert!(summary.filtered_readonly_opens >= 100, "{summary:?}");
    assert!(
        summary.ops.mkdir >= 50 && summary.ops.rmdir >= 50,
        "{summary:?}"
    );
    assert!(summary.restarts >= 2, "restart and EINTR: {summary:?}");
    assert!(summary.loss.abandoned_entries >= 1, "{summary:?}");
    assert!(summary.tasks_destroyed_by_exec >= 1, "{summary:?}");
    assert_eq!(
        unmatched(&events, &summary),
        Vec::<String>::new(),
        "an exit stop without its entry: {summary:?}"
    );

    let (out, events, summary) = observe(
        &[&helper, &"pairing-inflight", &fifo, &dir.path()],
        TracerConfig {
            inflight_max: 1,
            ..TracerConfig::default()
        },
    );
    assert_eq!(line(&out, "parked").raw, 0, "{out:#?}");
    assert_eq!(line(&out, "after").raw, 0, "{out:#?}");
    assert!(
        summary.loss.inflight_rejected >= 20,
        "the bound refused entries: {summary:?}"
    );
    assert_eq!(
        unmatched(&events, &summary),
        Vec::<String>::new(),
        "an exit stop for an entry the observer refused: {summary:?}"
    );
}

/// O03 through the product: map exhaustion (the in-flight bound) and ring
/// loss (the tracer queue), reached with the shrink-only seams. Each one
/// degrades exactly the classes of the calls it swallowed, with null
/// counts, and never reports a result for them.
#[test]
fn j4_o03_exhaustion_through_the_product() {
    let _serial = serial();
    if !live("tool") {
        return;
    }
    // Map exhaustion: one in-flight slot, held by a parked open; the mkdir
    // made meanwhile cannot be followed.
    let Some(c) = case_on(
        Jail::new()
            .unwrap()
            .env("OURO_JAIL_TEST_TRACER_INFLIGHT", "1"),
        "tool",
        "best-effort",
    ) else {
        return;
    };
    let argv = c.argv("inflight", &[&c.fifo, &c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "parked").raw, 0, "{out:#?}");
    assert_eq!(
        details(&settled)["observer_plan"]["in_flight_max"],
        1,
        "the seam took effect: {:#}",
        details(&settled)
    );
    let gap = assert_degraded(&settled, "fs.write", "inflight_exhausted");
    assert!(gap["lost_count"].as_u64().unwrap_or(0) >= 1, "{gap:#}");
    assert_active(&settled, "net", 1);
    assert_active(&settled, "exec", 2);
    assert_eq!(line(&out, "mkdir").raw, 0, "{out:#?}");
    assert!(
        results_on(&run, "ops/a").is_empty(),
        "no result for a call the observer could not follow: {:#?}",
        results_on(&run, "ops/a")
    );

    // Ring loss: a queue budget too small for any result that carries a
    // path, big enough for the lifecycle facts. The mkdir is dropped after
    // the bounded wait; the connect, which carries no path, is not.
    let Some(c) = case_on(
        Jail::new()
            .unwrap()
            .env("OURO_JAIL_TEST_TRACER_QUEUE_BYTES", "16384"),
        "tool",
        "best-effort",
    ) else {
        return;
    };
    let argv = c.argv("queue", &[&c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "mkdir").raw, 0, "the mkdir ran: {out:#?}");
    assert_eq!(
        details(&settled)["observer_plan"]["queue_bytes_max"],
        16384,
        "the seam took effect: {:#}",
        details(&settled)
    );
    let gap = assert_degraded(&settled, "fs.write", "queue_full");
    assert_eq!(gap["lost_count"], 1, "{gap:#}");
    assert_degraded(&settled, "fs.deny", "queue_full");
    assert_active(&settled, "net", 1);
    assert_active(&settled, "exec", 2);
    assert!(
        !audit_events(&run)
            .iter()
            .any(|event| event["operation"] == "fs.create"),
        "the dropped mkdir has no result: {:#?}",
        audit_events(&run)
    );
    assert_eq!(run.code(), Some(1), "best-effort exits 1 for the loss");
}

// ===========================================================================
// O05
// ===========================================================================

/// O05: "unavailable attachment refuses even in best-effort". A ptrace
/// wrapper of the test's own runs the jail. Traced whole (`wrap-all`), every
/// child the jail makes is already traced, so the jail's own probe of the
/// observer notices first; traced selectively (`wrap-launcher`: the
/// probes' children are let go, the real launcher is kept), the probes pass
/// and the seize at the attach site fails `EPERM`. Either way: best-effort,
/// and still a refusal before exec — exit 125, a refused receipt, and the
/// target never ran.
fn attach_failure(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some((built, _)) = build() else {
        return;
    };
    for (mode, stage, code, says) in [
        (
            "wrap-all",
            "probing",
            "missing_capability",
            "closed_set_observation",
        ),
        (
            "wrap-launcher",
            "preparing",
            "observer_unavailable",
            "could not attach",
        ),
    ] {
        let jail = Jail::with_program(built)
            .unwrap()
            .arg(mode)
            .arg(harness::jail_path());
        let Some(c) = case_on(jail, profile, "best-effort") else {
            return;
        };
        let marker = c.workspace.join("marker");
        let run = c
            .jail
            .target([
                OsString::from("/usr/bin/touch"),
                marker.clone().into_os_string(),
            ])
            .run()
            .unwrap();
        let label = format!("{profile}/{mode}");
        assert_eq!(
            run.code(),
            Some(125),
            "{label}: stderr {}",
            run.stderr_text()
        );
        let refused = receipt(&run, "refused");
        let error = &refused["outcome"]["error"];
        assert_eq!(error["code"], code, "{label}: {error:#}");
        assert_eq!(error["stage"], stage, "{label}: {error:#}");
        assert!(
            error["message"].as_str().unwrap_or("").contains(says),
            "{label}: {error:#}"
        );
        assert_eq!(refused["policy"]["evidence"], "best-effort", "{label}");
        assert_eq!(refused["exec_observed"], false, "{label}");
        assert!(!marker.exists(), "{label}: the target never ran");
        assert!(
            audit_events(&run).is_empty(),
            "{label}: nothing was observed"
        );
    }
}

#[test]
fn j4_o05_attach_failure_refuses_in_best_effort_tool() {
    attach_failure("tool");
}

#[test]
fn j4_o05_attach_failure_refuses_in_best_effort_none() {
    attach_failure("none");
}

/// O05: "Directory-operation losses degrade fs.write." Every directory-entry
/// variant of the closed set, made while a parked open holds the only
/// in-flight slot the seam leaves: each one ran, none could be followed,
/// and each is a loss of `fs.write` (and of `fs.deny`, which a lost result
/// could also have been) — not of `exec` or `net`, whose counts stay exact.
#[test]
fn j4_o05_directory_operation_losses_degrade_fs_write() {
    let _serial = serial();
    for profile in ["tool", "none"] {
        if !live(profile) {
            return;
        }
        let Some(c) = case_on(
            Jail::new()
                .unwrap()
                .env("OURO_JAIL_TEST_TRACER_INFLIGHT", "1"),
            profile,
            "best-effort",
        ) else {
            return;
        };
        let argv = c.argv("inflight", &[&c.fifo, &c.ops]);
        let run = c.jail.target(argv).run().unwrap();
        let out = lines(&run.stdout_text());
        let settled = receipt(&run, "settled");
        assert_eq!(line(&out, "parked").raw, 0, "{profile}: {out:#?}");
        let lost: Vec<&Line> = out
            .iter()
            .take_while(|line| line.label != "released")
            .filter(|line| line.label != "parked")
            .collect();
        assert_eq!(lost.len(), 20, "{profile}: {lost:#?}");
        for line in &lost {
            assert!(line.raw >= 0, "{profile}: every call ran: {line:?}");
        }
        assert_eq!(line(&out, "released").errno, libc::EINTR, "{profile}");
        for class in ["fs.write", "fs.deny"] {
            let gap = assert_degraded(&settled, class, "inflight_exhausted");
            assert_eq!(
                gap["lost_count"], 20,
                "{profile}/{class}: one per call made while the slot was held: {gap:#}"
            );
        }
        assert_active(&settled, "exec", 2);
        assert_active(&settled, "net", 1);
        // Only the call made after the release is a result; none of the
        // twenty is.
        let results: Vec<&Value> = audit_events(&run)
            .into_iter()
            .filter(|event| event["operation"] != "proc.exec" && event["operation"] != "proc.exit")
            .collect();
        assert_eq!(
            results.len(),
            2,
            "{profile}: the later mkdir and connect only: {results:#?}"
        );
    }
}

/// O05: "denied connect counts only in fs.deny." Connects the kernel denies
/// (a mode-000 AF_UNIX socket, a UDP broadcast address without
/// `SO_BROADCAST`) are `fs.deny` results with `attempted_operation =
/// net.connect` and never `net` ones; the other connects are `net`. The
/// receipt's counts equal what the fixture did, class by class. `agent`
/// takes its connects through the unix-peer mediator, and the same holds.
fn denied_connect(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case(profile, "strict") else {
        return;
    };
    let argv = c.argv("deny-connect", &[&c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(run.code(), Some(0), "{profile}: {}", run.stderr_text());
    let (denied, other) = connects(&out);
    assert!(
        denied >= 1,
        "{profile}: the fixture must have made a denied connect: {out:#?}"
    );
    assert_active(&settled, "fs.deny", denied);
    assert_active(&settled, "net", other);
    let audit = audit_events(&run);
    let denials: Vec<&&Value> = audit
        .iter()
        .filter(|event| event["operation"] == "fs.deny")
        .collect();
    assert_eq!(denials.len() as u64, denied, "{profile}: {denials:#?}");
    for event in &denials {
        assert_eq!(
            event["fields"]["attempted_operation"], "net.connect",
            "{profile}: {event:#}"
        );
        if profile == "agent" {
            assert_eq!(
                event["fields"]["observation"], "seccomp_user_notification",
                "{profile}: {event:#}"
            );
        }
    }
    let nets: Vec<&&Value> = audit
        .iter()
        .filter(|event| event["operation"] == "net.connect")
        .collect();
    assert_eq!(nets.len() as u64, other, "{profile}: {nets:#?}");
    for event in &nets {
        let errno = event["outcome"]["errno"].as_str().unwrap_or("");
        assert!(
            errno != "EACCES" && errno != "EPERM",
            "{profile}: a denial counted under net: {event:#}"
        );
    }
}

#[test]
fn j4_o05_denied_connect_counts_only_in_fs_deny_tool() {
    denied_connect("tool");
}

#[test]
fn j4_o05_denied_connect_counts_only_in_fs_deny_none() {
    denied_connect("none");
}

#[test]
fn j4_o05_denied_connect_counts_only_in_fs_deny_agent() {
    denied_connect("agent");
}

// ===========================================================================
// The observer plan (§11.4 "Record actual values in the observer plan")
// ===========================================================================

/// The bounds in force are in the receipt's native details, before the
/// target runs (prepared) and at the end (settled): the §11.4 defaults with
/// no seam; exactly the shrunk value, named, with one; and a seam that
/// would widen a bound is ignored and says so.
#[test]
fn j4_observer_plan_is_recorded() {
    let _serial = serial();
    for profile in ["tool", "none"] {
        if !live(profile) {
            return;
        }
        for (seams, inflight, queue) in [
            (&[][..], 16_384, 4_194_304),
            (
                &[
                    ("OURO_JAIL_TEST_TRACER_INFLIGHT", "7"),
                    ("OURO_JAIL_TEST_TRACER_QUEUE_BYTES", "65536"),
                ][..],
                7,
                65_536,
            ),
            (
                &[
                    ("OURO_JAIL_TEST_TRACER_INFLIGHT", "16385"),
                    ("OURO_JAIL_TEST_TRACER_QUEUE_BYTES", "0"),
                ][..],
                16_384,
                4_194_304,
            ),
        ] {
            let mut jail = Jail::new().unwrap();
            for (name, value) in seams {
                jail = jail.env(name, value);
            }
            let Some(c) = case_on(jail, profile, "strict") else {
                return;
            };
            let argv = c.argv("exit0", &[]);
            let run = c.jail.target(argv).run().unwrap();
            let settled = receipt(&run, "settled");
            let label = format!("{profile} {seams:?}");
            assert_eq!(run.code(), Some(0), "{label}: {}", run.stderr_text());
            let plan = &details(&settled)["observer_plan"];
            assert_eq!(plan["backend"], "ptrace", "{label}: {plan:#}");
            assert_eq!(plan["in_flight_max"], inflight, "{label}: {plan:#}");
            assert_eq!(plan["queue_bytes_max"], queue, "{label}: {plan:#}");
            assert_eq!(plan["queue_events_max"], 16_384, "{label}: {plan:#}");
            assert_eq!(plan["path_snapshot_max"], 4096, "{label}: {plan:#}");
            assert_eq!(plan["event_bytes_max"], 65_536, "{label}: {plan:#}");
            assert_eq!(
                plan["kernel_ring_bytes"],
                Value::Null,
                "{label}: the ptrace observer has no kernel ring: {plan:#}"
            );
            let recorded = plan["test_seams"].as_object().unwrap();
            assert_eq!(
                recorded.len(),
                seams.len(),
                "{label}: every seam set is named: {plan:#}"
            );
            for (name, value) in seams {
                let applied: u64 = value.parse().unwrap();
                let widening = !(1..=if name.ends_with("INFLIGHT") {
                    16_384
                } else {
                    4_194_304
                })
                    .contains(&applied);
                assert_eq!(
                    recorded[*name],
                    if widening {
                        Value::Null
                    } else {
                        Value::from(applied)
                    },
                    "{label}: {plan:#}"
                );
            }
            // Unchanged from the prepared receipt, which the gate owner sees.
            assert_eq!(
                settled["coverage"]["exec"]["status"], "active",
                "{label}: nothing was lost"
            );
        }
    }
}
