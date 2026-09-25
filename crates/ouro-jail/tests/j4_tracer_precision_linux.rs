#![cfg(target_os = "linux")]
//! J4 wave 2, slice W2-T: the ptrace observer's precision (jail-v1 §11.2,
//! §11.4, §15 O01, O03, O05).
//!
//! The promise under test is the one §11.4 makes of every covered call: its
//! result is reported, or its classes carry a gap — never silence, and never
//! a gap for a call that had no effect. Each finding here was reproduced by
//! a failing test on b8617f82 before its fix:
//!
//! - O-2: a covered call interrupted by a signal whose handler lacks
//!   `SA_RESTART` shows the tracer `-ERESTARTSYS` at its syscall-exit stop.
//!   The kernel turns that into `EINTR` only later, when it sets up the
//!   handler; no re-entry follows. The observer took every restart code for
//!   a restart, so the `EINTR` result was never emitted and the class read
//!   active. The observer now follows the call to the kernel's decision: a
//!   re-entry at the same instruction (restarted), the handler's entry
//!   (`EINTR` or restarted, from the restart code and the frame the kernel
//!   wrote), or a death (no result, no effect); anything else is a
//!   `restart_unresolved` gap.
//! - O-1: with the in-flight table full, a read-only open — outside the
//!   closed set — was refused as `inflight_exhausted` before the read-only
//!   filter ran, so reads became loss.
//! - O-3 is reproduced at the session seam (`session.rs`), where the kill can
//!   be placed inside the tracer's own window; the stress check here shows
//!   the same window through the real tracer loop.
//!
//! The fixture is a C program built at test time (gcc, as the other observer
//! suites do). Every process signalled is one these tests started; every
//! file is under a private temporary directory.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ouro_fixture::harness::{self, Jail, Run};
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, Tracer, TracerConfig, TracerEvent, TracerSummary,
    narrowing_filter_bytes,
};
use serde_json::Value;

mod common;

const HELPER_C: &str = r##"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static void report(const char *label, long r, int err, const char *p) {
    printf("%s\t%ld\t%d\t%s\n", label, r, err, p ? p : "");
    fflush(stdout);
}

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

/* ------------------------------------------------------------------ */
/* The launcher of the tracer-seam checks                               */
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

/* ------------------------------------------------------------------ */
/* A thread parked inside a covered call                                */
/* ------------------------------------------------------------------ */

enum { K_OPEN = 1, K_CONNECT = 2 };

struct parked {
    int kind;
    const char *path;
    int sock;
    struct sockaddr_un addr;
    int go[2];
    pid_t tid;
    long result;
    int err;
    int stat_fd, syscall_fd, status_fd;
    /* A directory the thread makes once its call has returned, if set. */
    const char *after;
    long after_result;
    int after_err;
};

static void *park_thread(void *arg) {
    struct parked *p = arg;
    char b;
    __atomic_store_n(&p->tid, (pid_t) syscall(SYS_gettid), __ATOMIC_RELEASE);
    while (read(p->go[0], &b, 1) < 0 && errno == EINTR) {}
    if (p->kind == K_OPEN)
        p->result = syscall(SYS_openat, AT_FDCWD, p->path, O_WRONLY | O_CLOEXEC);
    else
        p->result = syscall(SYS_connect, p->sock, (struct sockaddr *) &p->addr,
                            (socklen_t) sizeof p->addr);
    p->err = p->result < 0 ? errno : 0;
    if (p->after) {
        p->after_result = syscall(SYS_mkdir, p->after, 0700);
        p->after_err = p->after_result < 0 ? errno : 0;
    }
    return NULL;
}

static long parked_nr(struct parked *p) {
    return p->kind == K_OPEN ? SYS_openat : SYS_connect;
}

/* Whether the kernel says the thread is asleep inside its call: state S
   (a tracing stop reads t) and /proc/.../syscall naming it. Only pread(2)
   of descriptors opened before the call, which is outside the closed set. */
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
    return state == 'S' && buf[0] >= '0' && buf[0] <= '9' && atol(buf) == parked_nr(p);
}

static int await_parked(struct parked *p) {
    int i;
    for (i = 0; i < 200000; i++) {
        if (is_parked(p)) return 0;
        usleep(100);
    }
    return -5;
}

/* The thread's voluntary context switches: a woken sleeper adds one. */
static long switches(struct parked *p) {
    char buf[2048];
    char *at;
    ssize_t n = pread(p->status_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return -1;
    buf[n] = 0;
    at = strstr(buf, "\nvoluntary_ctxt_switches:");
    return at ? atol(at + strlen("\nvoluntary_ctxt_switches:")) : -1;
}

/* Wait until the parked thread has been woken (by a signal) and is parked
   again (restarted): proof the interruption happened before the call is
   let complete. */
static int await_reparked(struct parked *p, long before) {
    int i;
    for (i = 0; i < 200000; i++) {
        if (switches(p) > before && is_parked(p)) return 0;
        usleep(100);
    }
    return -6;
}

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
    snprintf(path, sizeof path, "/proc/self/task/%d/status", (int) p->tid);
    p->status_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (p->stat_fd < 0 || p->syscall_fd < 0 || p->status_fd < 0) return -3;
    if (write(p->go[1], "g", 1) != 1) return -4;
    return await_parked(p);
}

/* A pathname AF_UNIX listener with a backlog of 0 and one connection
   already queued, so the next connect blocks until an accept. */
static int full_listener(struct parked *p, const char *dir, int *listener) {
    int l, first;
    memset(&p->addr, 0, sizeof p->addr);
    p->addr.sun_family = AF_UNIX;
    snprintf(p->addr.sun_path, sizeof p->addr.sun_path, "%s/s.sock", dir);
    l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (l < 0) return -1;
    if (bind(l, (struct sockaddr *) &p->addr, sizeof p->addr) || listen(l, 0)) return -2;
    first = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (first < 0) return -3;
    if (connect(first, (struct sockaddr *) &p->addr, sizeof p->addr)) return -4;
    p->sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (p->sock < 0) return -5;
    *listener = l;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Interrupting a parked call                                           */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_hits;
static const char *g_hpath;
static void on_sig(int sig) { (void) sig; g_hits++; }
static void on_info(int sig, siginfo_t *info, void *uc) { (void) sig; (void) info; (void) uc; g_hits++; }
static void on_mkdir(int sig) {
    (void) sig;
    syscall(SYS_mkdir, g_hpath, 0700);
    g_hits++;
}

/* A handler that rewrites its own frame: where the kernel prepared a
   restart (rax = the call's number, rip on the syscall instruction), it
   makes the thread see EINTR instead, so no re-entry ever follows. */
static volatile sig_atomic_t g_rewrote;
static long g_rewrite_nr;
static void on_rewrite(int sig, siginfo_t *info, void *ucv) {
    ucontext_t *uc = ucv;
    (void) sig; (void) info;
    g_hits++;
    if (uc->uc_mcontext.gregs[REG_RAX] == g_rewrite_nr) {
        uc->uc_mcontext.gregs[REG_RAX] = -EINTR;
        uc->uc_mcontext.gregs[REG_RIP] += 2;
        g_rewrote++;
    }
}

static void set_action(int sig, void (*handler)(int), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

/* interrupt HOW KIND FIFO DIR: park a thread in openat(FIFO, O_WRONLY)
   (KIND open) or in a connect to a full AF_UNIX listener (KIND connect),
   then signal it. HOW:
     eintr        a handler without SA_RESTART: the call returns EINTR;
     siginfo-alt  the same through SA_SIGINFO on an alternate signal stack;
     mkdir        the same, the handler making a covered call of its own;
     restart      a handler with SA_RESTART: restarted, then let complete;
     ignored      SIGUSR1 ignored (a tracee still sees it): restarted;
     default      SIGWINCH, ignored by default: restarted;
     twice        SIGHUP ignored (restarted), then SIGUSR1 without
                  SA_RESTART (EINTR), both inside the same call;
     fatal        SIGTERM, fatal by default: the process dies inside it;
     rewrite      SA_SIGINFO with SA_RESTART, the handler rewriting the
                  restart the kernel prepared in its frame into EINTR: no
                  re-entry follows, and the thread then ends;
     rewrite-mkdir  the same, the thread then making mkdir DIR/after;
     restart-mkdir  SA_RESTART, the handler making a covered call of its
                  own (mkdir DIR/h): restarted, then let complete. */
static int mode_interrupt(int argc, char **argv) {
    struct parked p;
    pthread_t t;
    const char *how, *kind;
    char hpath[4096], apath[4096];
    int listener = -1, rr, restarts = 0;
    long before;
    stack_t ss;
    if (argc < 6) return 2;
    how = argv[2];
    kind = argv[3];
    memset(&p, 0, sizeof p);
    p.kind = strcmp(kind, "connect") ? K_OPEN : K_CONNECT;
    p.path = argv[4];
    snprintf(hpath, sizeof hpath, "%s/h", argv[5]);
    snprintf(apath, sizeof apath, "%s/after", argv[5]);
    g_hpath = hpath;
    if (p.kind == K_CONNECT && (rr = full_listener(&p, argv[5], &listener))) {
        report("listener", rr, errno, "");
        return 3;
    }
    if (!strcmp(how, "eintr") || !strcmp(how, "twice")) {
        set_action(SIGUSR1, on_sig, 0);
    } else if (!strcmp(how, "siginfo-alt")) {
        struct sigaction sa;
        ss.ss_sp = malloc(1 << 16);
        ss.ss_size = 1 << 16;
        ss.ss_flags = 0;
        if (!ss.ss_sp || sigaltstack(&ss, NULL)) { report("altstack", -1, errno, ""); return 3; }
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_info;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);
    } else if (!strcmp(how, "mkdir")) {
        set_action(SIGUSR1, on_mkdir, 0);
    } else if (!strcmp(how, "rewrite") || !strcmp(how, "rewrite-mkdir")) {
        struct sigaction sa;
        g_rewrite_nr = parked_nr(&p);
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_rewrite;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);
        if (!strcmp(how, "rewrite-mkdir")) p.after = apath;
    } else if (!strcmp(how, "restart-mkdir")) {
        set_action(SIGUSR1, on_mkdir, SA_RESTART);
        restarts = 1;
    } else if (!strcmp(how, "restart")) {
        set_action(SIGUSR1, on_sig, SA_RESTART);
        restarts = 1;
    } else if (!strcmp(how, "ignored")) {
        set_action(SIGUSR1, SIG_IGN, 0);
        restarts = 1;
    } else if (!strcmp(how, "default")) {
        restarts = 1;
    } else if (strcmp(how, "fatal")) {
        return 2;
    }
    if (!strcmp(how, "twice")) set_action(SIGHUP, SIG_IGN, 0);
    rr = park(&p, &t);
    report("parked", rr, 0, p.path);
    if (rr) return 3;
    before = switches(&p);
    if (!strcmp(how, "twice")) {
        pthread_kill(t, SIGHUP);
        rr = await_reparked(&p, before);
        report("reparked", rr, 0, p.path);
        if (rr) return 3;
        pthread_kill(t, SIGUSR1);
    } else if (!strcmp(how, "default")) {
        pthread_kill(t, SIGWINCH);
    } else if (!strcmp(how, "fatal")) {
        pthread_kill(t, SIGTERM);
        sleep_ms(10000);
        report("survived", 0, 0, "");
        return 5;
    } else {
        pthread_kill(t, SIGUSR1);
    }
    if (restarts) {
        rr = await_reparked(&p, before);
        report("reparked", rr, 0, p.path);
        if (rr) return 3;
        /* Let the restarted call complete: a reader for the FIFO (a
           read-only open, outside the closed set), or an accept. */
        if (p.kind == K_OPEN) {
            int fd = (int) syscall(SYS_openat, AT_FDCWD, p.path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            pthread_join(t, NULL);
            if (fd >= 0) close(fd);
        } else {
            int a = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
            pthread_join(t, NULL);
            if (a >= 0) close(a);
        }
    } else {
        pthread_join(t, NULL);
    }
    if (p.result >= 0 && p.kind == K_OPEN) close((int) p.result);
    report("call", p.result, p.err, p.path);
    report("handled", (long) g_hits, 0, "");
    report("handler_mkdir", access(hpath, F_OK) == 0, 0, hpath);
    report("rewrote", (long) g_rewrote, 0, "");
    if (p.after) report("after", p.after_result, p.after_err, apath);
    return 0;
}

/* ------------------------------------------------------------------ */
/* O-1: the in-flight bound and calls outside the closed set            */
/* ------------------------------------------------------------------ */

/* inflight FIFO DIR N: park a thread in openat(FIFO) — under an in-flight
   bound of one it holds the only slot — then N rounds of one mkdir, one
   rmdir (covered, refused a slot) and two read-only opens (outside the set,
   never a slot); release the thread with a handler without SA_RESTART
   (EINTR); then one mkdir with the slot free. */
static int mode_inflight(int argc, char **argv) {
    struct parked p;
    pthread_t t;
    char m[4096], after[4096];
    long i, n, r, covered = 0, reads = 0;
    if (argc < 5) return 2;
    n = atol(argv[4]);
    snprintf(m, sizeof m, "%s/m", argv[3]);
    snprintf(after, sizeof after, "%s/after", argv[3]);
    set_action(SIGUSR1, on_sig, 0);
    memset(&p, 0, sizeof p);
    p.kind = K_OPEN;
    p.path = argv[2];
    r = park(&p, &t);
    report("parked", r, 0, p.path);
    if (r) return 3;
    for (i = 0; i < n; i++) {
        if (syscall(SYS_mkdir, m, 0700) == 0) covered++;
        if (syscall(SYS_rmdir, m) == 0) covered++;
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) { reads++; close((int) r); }
        r = syscall(SYS_open, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) { reads++; close((int) r); }
    }
    report("covered", covered, 0, m);
    report("reads", reads, 0, "");
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report("released", p.result, p.err, p.path);
    r = syscall(SYS_mkdir, after, 0700);
    report("after", r, r < 0 ? errno : 0, after);
    return 0;
}

/* ------------------------------------------------------------------ */
/* O-3: a group exit racing entry stops                                 */
/* ------------------------------------------------------------------ */

static const char *g_race_dir;
static void *hammer(void *arg) {
    char d[4096];
    snprintf(d, sizeof d, "%s/t%ld", g_race_dir, (long) (intptr_t) arg);
    for (;;) {
        syscall(SYS_mkdir, d, 0700);
        syscall(SYS_rmdir, d);
    }
    return NULL;
}

/* killrace DIR THREADS MS: THREADS threads make covered calls without
   pause; after MS milliseconds the main thread ends the group, which kills
   every one of them wherever it is — some at a trace stop. */
static int mode_killrace(int argc, char **argv) {
    long i, n;
    pthread_t t;
    if (argc < 5) return 2;
    g_race_dir = argv[2];
    n = atol(argv[3]);
    for (i = 0; i < n; i++) pthread_create(&t, NULL, hammer, (void *) (intptr_t) i);
    sleep_ms(atol(argv[4]));
    syscall(SYS_exit_group, 7);
    return 0;
}

/* ------------------------------------------------------------------ */
/* J4 wave 3                                                            */
/* ------------------------------------------------------------------ */

/* Whether the process's main (leader) thread is asleep inside openat. */
struct leader { const char *self; int stat_fd, syscall_fd; };

static int leader_parked(struct leader *a) {
    char buf[512];
    char *rp;
    char state;
    ssize_t n = pread(a->stat_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    rp = strrchr(buf, ')');
    state = rp && rp[1] == ' ' ? rp[2] : 0;
    n = pread(a->syscall_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    return state == 'S' && buf[0] >= '0' && buf[0] <= '9' && atol(buf) == SYS_openat;
}

static void *exec_when_leader_parked(void *arg) {
    struct leader *a = arg;
    char *args[3];
    int i;
    for (i = 0; i < 200000 && !leader_parked(a); i++) usleep(100);
    report("leader_parked", leader_parked(a), 0, "");
    args[0] = (char *) a->self;
    args[1] = "exit0";
    args[2] = NULL;
    execv(a->self, args);
    report("thread_execv", -1, errno, a->self);
    _exit(126);
}

/* leader-exec FIFO SELF: the main (leader) thread parks in
   openat(FIFO, O_WRONLY); a second thread waits until it is parked and then
   execs SELF exit0, which destroys the leader with its call in flight: the
   open never returns. */
static int mode_leader_exec(int argc, char **argv) {
    static struct leader a;
    char path[96];
    pthread_t t;
    long r;
    if (argc < 4) return 2;
    a.self = argv[3];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", (int) getpid());
    a.stat_fd = open(path, O_RDONLY | O_CLOEXEC);
    snprintf(path, sizeof path, "/proc/self/task/%d/syscall", (int) getpid());
    a.syscall_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (a.stat_fd < 0 || a.syscall_fd < 0) return 3;
    if (pthread_create(&t, NULL, exec_when_leader_parked, &a)) return 4;
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY | O_CLOEXEC);
    report("leader_open_returned", r, r < 0 ? errno : 0, argv[2]);
    return 5;
}

/* A thread that serves a notification listener with CONTINUE. */
static int g_listener = -1;
static void *serve_continue(void *arg) {
    (void) arg;
    for (;;) {
        struct seccomp_notif req;
        struct seccomp_notif_resp resp;
        memset(&req, 0, sizeof req);
        if (ioctl(g_listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;
            return NULL;
        }
        memset(&resp, 0, sizeof resp);
        resp.id = req.id;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        ioctl(g_listener, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
    return NULL;
}

/* hide FIFO DIR HOW: a thread parks in openat(FIFO), holding the one
   in-flight slot a bound of one allows; meanwhile the main thread (HOW
   listener) installs a filter with its own notification listener for mkdir,
   served with CONTINUE, and makes mkdir DIR/hidden1, or (HOW untraced)
   makes clone(CLONE_UNTRACED), whose child makes mkdir DIR/untraced. Then
   the parked thread is released (EINTR) and the main thread makes mkdir
   DIR/hidden2. */
static int mode_hide(int argc, char **argv) {
    struct parked p;
    pthread_t t, s;
    char path[4096];
    long r;
    struct sock_filter prog[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mkdir, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fprog = { 4, prog };
    if (argc < 5) return 2;
    set_action(SIGUSR1, on_sig, 0);
    memset(&p, 0, sizeof p);
    p.kind = K_OPEN;
    p.path = argv[2];
    r = park(&p, &t);
    report("parked", r, 0, p.path);
    if (r) return 3;
    if (!strcmp(argv[4], "listener")) {
        g_listener = (int) syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                   SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
        report("listener", g_listener, g_listener < 0 ? errno : 0, "");
        if (g_listener < 0) return 3;
        pthread_create(&s, NULL, serve_continue, NULL);
        snprintf(path, sizeof path, "%s/hidden1", argv[3]);
        r = syscall(SYS_mkdir, path, 0700);
        report("hidden1", r, r < 0 ? errno : 0, path);
    } else if (!strcmp(argv[4], "untraced")) {
        int status = 0;
        long child = syscall(SYS_clone, CLONE_UNTRACED | SIGCHLD, 0, 0, 0, 0);
        if (child == 0) {
            snprintf(path, sizeof path, "%s/untraced", argv[3]);
            r = syscall(SYS_mkdir, path, 0700);
            report("untraced_mkdir", r, r < 0 ? errno : 0, path);
            _exit(0);
        }
        report("clone", child, child < 0 ? errno : 0, "");
        if (child > 0) waitpid((pid_t) child, &status, 0);
    } else {
        return 2;
    }
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report("released", p.result, p.err, p.path);
    snprintf(path, sizeof path, "%s/hidden2", argv[3]);
    r = syscall(SYS_mkdir, path, 0700);
    report("hidden2", r, r < 0 ? errno : 0, path);
    return 0;
}

/* reexec N PATH: exec PATH reexec N-1 PATH until N is 0. */
static int mode_reexec(int argc, char **argv) {
    char n[32];
    char *args[5];
    int left;
    if (argc < 4) return 2;
    left = atoi(argv[2]);
    if (left <= 0) { report("done", 0, 0, ""); return 0; }
    snprintf(n, sizeof n, "%d", left - 1);
    args[0] = argv[3]; args[1] = "reexec"; args[2] = n; args[3] = argv[3]; args[4] = NULL;
    execv(argv[3], args);
    report("execv", -1, errno, argv[3]);
    return 3;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "exit0")) return 0;
    if (!strcmp(argv[1], "leader-exec")) return mode_leader_exec(argc, argv);
    if (!strcmp(argv[1], "hide")) return mode_hide(argc, argv);
    if (!strcmp(argv[1], "reexec")) return mode_reexec(argc, argv);
    if (!strcmp(argv[1], "launch")) return mode_launch(argc, argv);
    if (!strcmp(argv[1], "interrupt")) return mode_interrupt(argc, argv);
    if (!strcmp(argv[1], "inflight")) return mode_inflight(argc, argv);
    if (!strcmp(argv[1], "killrace")) return mode_killrace(argc, argv);
    return 2;
}
"##;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The observer's thread owns `waitpid(-1, __WALL)` for the whole process in
/// the tracer-seam checks, so everything here is serialised.
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
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("j4-precision-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let source = dir.join("precision.c");
        std::fs::write(&source, HELPER_C).map_err(|e| format!("write precision.c: {e}"))?;
        let helper = dir.join("j4-precision");
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
            harness::skip_or_fail(&format!("the precision fixture: {error}"));
            None
        }
    }
}

fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path and a mode.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
}

/// One line the fixture reported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    label: String,
    raw: i64,
    errno: i32,
    path: String,
}

impl Line {
    /// The call's signed raw return, `-errno` for a failure: what the
    /// observer reports as `ret`.
    fn ret(&self) -> i64 {
        if self.raw < 0 {
            -i64::from(self.errno)
        } else {
            self.raw
        }
    }
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

/// What one run under the bare tracer produced.
struct Observed {
    out: Vec<Line>,
    events: Vec<TracerEvent>,
    summary: TracerSummary,
    launcher: libc::pid_t,
}

impl Observed {
    /// Results whose first path argument is `path`.
    fn results_on(&self, path: &str) -> Vec<(ClosedOp, &'static str, i64)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Syscall {
                    op,
                    syscall,
                    args,
                    ret,
                    ..
                } if args
                    .path
                    .as_ref()
                    .is_some_and(|p| p.bytes == path.as_bytes()) =>
                {
                    Some((*op, *syscall, *ret))
                }
                _ => None,
            })
            .collect()
    }

    /// `connect` results.
    fn connects(&self) -> Vec<i64> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Syscall {
                    op: ClosedOp::Connect,
                    ret,
                    ..
                } => Some(*ret),
                _ => None,
            })
            .collect()
    }

    fn gaps(&self) -> Vec<(GapReason, OpSet, Option<u64>)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                TracerEvent::Gap {
                    reason, ops, count, ..
                } => Some((*reason, *ops, *count)),
                _ => None,
            })
            .collect()
    }

    /// The launcher's process exit status, from its `Exit`.
    fn exit_status(&self) -> Option<i32> {
        self.events.iter().find_map(|event| match event {
            TracerEvent::Exit { pid, status, .. } if *pid == self.launcher => Some(*status),
            _ => None,
        })
    }

    fn describe(&self) -> String {
        self.events
            .iter()
            .map(|event| format!("{event:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

/// Run the fixture under the bare tracer: the filter installed by the
/// launcher, `Tracer::attach`, release, every event until `Finished`.
fn observe(argv: &[&dyn AsRef<std::ffi::OsStr>], config: TracerConfig) -> Observed {
    let (helper, _) = build().expect("built");
    observe_image(helper, argv, config, Duration::ZERO)
}

/// [`observe`], launching `image` (a copy of the fixture), and reading no
/// event until the tree has ended and `idle` has passed: a consumer that is
/// not reading.
fn observe_image(
    image: &Path,
    argv: &[&dyn AsRef<std::ffi::OsStr>],
    config: TracerConfig,
    idle: Duration,
) -> Observed {
    let (helper, filter) = build().expect("built");
    let mut child = Command::new(helper)
        .arg("launch")
        .arg(filter)
        .arg(image)
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
    std::thread::sleep(idle);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut events = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match tracer.events().recv_timeout(left) {
            Ok(TracerEvent::Finished) | Err(_) => break,
            Ok(event) => events.push(event),
        }
    }
    let summary = tracer.finish();
    Observed {
        out: lines(&text),
        events,
        summary,
        launcher: pid,
    }
}

/// A private work directory holding a FIFO nobody reads.
struct Work {
    _dir: tempfile::TempDir,
    root: PathBuf,
    fifo: PathBuf,
}

fn work() -> Work {
    let dir = common::private_tempdir();
    let root = dir.path().to_path_buf();
    let fifo = root.join("fifo");
    mkfifo(&fifo);
    Work {
        _dir: dir,
        root,
        fifo,
    }
}

fn s(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Interrupt a parked call under the bare tracer.
fn interrupt(how: &str, kind: &str) -> (Work, Observed) {
    let w = work();
    let observed = observe(
        &[&"interrupt", &how, &kind, &w.fifo, &w.root],
        TracerConfig::default(),
    );
    (w, observed)
}

/// The one result the parked call produced: the FIFO open, or the one
/// `connect` of the parked thread (the fixture's own first connect, which
/// fills the backlog, is the other).
fn parked_results(kind: &str, w: &Work, observed: &Observed) -> Vec<i64> {
    if kind == "open" {
        observed
            .results_on(&s(&w.fifo))
            .into_iter()
            .map(|(op, syscall, ret)| {
                assert_eq!((op, syscall), (ClosedOp::Open, "openat"));
                ret
            })
            .collect()
    } else {
        // The first connect filled the backlog and succeeded.
        let mut connects = observed.connects();
        assert!(
            !connects.is_empty() && connects[0] == 0,
            "the backlog-filling connect: {connects:?}\n  {}",
            observed.describe()
        );
        connects.remove(0);
        connects
    }
}

// ===========================================================================
// O-2 at the tracer seam
// ===========================================================================

/// O-2: a handler without `SA_RESTART`. The kernel returns `-ERESTARTSYS`
/// at the syscall exit and `EINTR` to the program; the one result the call
/// has is `EINTR`, and it is reported — no gap, no silence.
fn eintr_is_the_result(how: &str, kind: &str) {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = interrupt(how, kind);
    let label = format!("{how}/{kind}");
    let out = &observed.out;
    assert_eq!(line(out, "parked").raw, 0, "{label}: {out:#?}");
    let call = line(out, "call");
    assert_eq!(
        call.errno,
        libc::EINTR,
        "{label}: the fixture's own view: {out:#?}"
    );
    assert_eq!(line(out, "handled").raw, 1, "{label}: {out:#?}");
    assert_eq!(
        parked_results(kind, &w, &observed),
        vec![-i64::from(libc::EINTR)],
        "{label}: one call, one result, and it is EINTR:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.gaps(),
        vec![],
        "{label}: an interrupted call is not loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{label}: {:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.restarts, 0,
        "{label}: nothing was restarted: {:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.interrupted, 1,
        "{label}: decided at the handler's entry: {:?}",
        observed.summary
    );
    assert_eq!(observed.exit_status(), Some(0), "{label}");
}

#[test]
fn j4_o2_a_handler_without_sa_restart_makes_eintr_the_result_open() {
    eintr_is_the_result("eintr", "open");
}

#[test]
fn j4_o2_a_handler_without_sa_restart_makes_eintr_the_result_connect() {
    eintr_is_the_result("eintr", "connect");
}

/// The same through `SA_SIGINFO` on an alternate signal stack: the frame
/// the kernel wrote is found from the handler's own arguments, wherever
/// the stack is.
#[test]
fn j4_o2_eintr_through_sa_siginfo_on_an_alternate_stack() {
    eintr_is_the_result("siginfo-alt", "open");
}

/// Two interruptions of one call: an ignored signal (restarted), then
/// a handler without `SA_RESTART` (`EINTR`). One call, one result.
#[test]
fn j4_o2_a_restart_then_an_eintr_in_one_call_is_one_result() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = interrupt("twice", "open");
    let out = &observed.out;
    assert_eq!(line(out, "reparked").raw, 0, "{out:#?}");
    assert_eq!(line(out, "call").errno, libc::EINTR, "{out:#?}");
    assert_eq!(
        parked_results("open", &w, &observed),
        vec![-i64::from(libc::EINTR)],
        "\n  {}",
        observed.describe()
    );
    assert_eq!(observed.gaps(), vec![], "\n  {}", observed.describe());
    assert_eq!(observed.summary.restarts, 1, "{:?}", observed.summary);
    assert_eq!(observed.summary.interrupted, 1, "{:?}", observed.summary);
    assert_eq!(observed.summary.loss.total(), 0, "{:?}", observed.summary);
}

/// A handler without `SA_RESTART` that makes a covered call of its own:
/// both are results, the interrupted call's `EINTR` first — it was decided
/// before the handler ran — and the handler's `mkdir` after it.
#[test]
fn j4_o2_a_handler_s_own_call_follows_the_eintr_it_interrupted() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = interrupt("mkdir", "open");
    let out = &observed.out;
    assert_eq!(line(out, "call").errno, libc::EINTR, "{out:#?}");
    assert_eq!(line(out, "handler_mkdir").raw, 1, "{out:#?}");
    let fifo = s(&w.fifo);
    let h = s(&w.root.join("h"));
    let order: Vec<(String, i64)> = observed
        .events
        .iter()
        .filter_map(|event| match event {
            TracerEvent::Syscall { args, ret, .. } => {
                let path = String::from_utf8_lossy(&args.path.as_ref()?.bytes).into_owned();
                (path == fifo || path == h).then_some((path, *ret))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        order,
        vec![(fifo, -i64::from(libc::EINTR)), (h, 0)],
        "\n  {}",
        observed.describe()
    );
    assert_eq!(observed.gaps(), vec![], "\n  {}", observed.describe());
}

/// A handler with `SA_RESTART`: the kernel re-enters the call, which then
/// completes. One result, the restarted call's, and no gap.
fn restarted_is_one_result(how: &str, kind: &str) {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = interrupt(how, kind);
    let label = format!("{how}/{kind}");
    let out = &observed.out;
    assert_eq!(line(out, "reparked").raw, 0, "{label}: {out:#?}");
    let call = line(out, "call");
    assert!(call.raw >= 0, "{label}: the call completed: {out:#?}");
    let results = parked_results(kind, &w, &observed);
    assert_eq!(
        results.len(),
        1,
        "{label}: one call, one result:\n  {}",
        observed.describe()
    );
    assert!(
        results[0] >= 0,
        "{label}: the restarted call's success: {results:?}"
    );
    if kind == "connect" {
        assert_eq!(results[0], call.ret(), "{label}");
    }
    assert_eq!(
        observed.gaps(),
        vec![],
        "{label}: a restart is not loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.summary.restarts, 1,
        "{label}: the restart was recognised: {:?}",
        observed.summary
    );
    assert_eq!(observed.summary.loss.total(), 0, "{label}");
}

#[test]
fn j4_o2_a_handler_with_sa_restart_gives_the_restarted_result_open() {
    restarted_is_one_result("restart", "open");
}

#[test]
fn j4_o2_a_handler_with_sa_restart_gives_the_restarted_result_connect() {
    restarted_is_one_result("restart", "connect");
}

/// No handler: a signal the tracee ignores still interrupts a traced call
/// (the kernel reports it to the tracer), and the kernel re-enters it.
#[test]
fn j4_o2_an_ignored_signal_restarts_the_call() {
    restarted_is_one_result("ignored", "open");
}

#[test]
fn j4_o2_a_default_ignored_signal_restarts_the_call() {
    restarted_is_one_result("default", "open");
}

/// A fatal signal in the window between the restart-coded exit and the
/// kernel's decision: the process dies inside the call. A restart code
/// means the call did nothing, and no result was ever returned: no result,
/// no gap, and the process's own death is reported.
#[test]
fn j4_o2_a_fatal_signal_inside_the_call_is_no_result_and_no_loss() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = interrupt("fatal", "open");
    let out = &observed.out;
    assert_eq!(line(out, "parked").raw, 0, "{out:#?}");
    assert!(out.iter().all(|line| line.label != "survived"), "{out:#?}");
    let status = observed.exit_status().expect("the process's exit");
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM,
        "status {status:#x}"
    );
    assert_eq!(
        parked_results("open", &w, &observed),
        Vec::<i64>::new(),
        "\n  {}",
        observed.describe()
    );
    assert_eq!(observed.gaps(), vec![], "\n  {}", observed.describe());
    assert_eq!(observed.summary.loss.total(), 0, "{:?}", observed.summary);
    assert_eq!(
        observed.summary.restarts_unfinished, 1,
        "the call died waiting for the kernel's decision: {:?}",
        observed.summary
    );
}

// ===========================================================================
// O-1 at the tracer seam
// ===========================================================================

/// O-1: under an in-flight bound of one, held by a parked open, every
/// covered call is refused a slot (`inflight_exhausted`, naming its own
/// operation) — and no read-only open is: those are outside the closed set,
/// are filtered at their entry, and never consume or are refused a slot.
#[test]
fn j4_o1_read_only_opens_are_never_inflight_loss() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    const ROUNDS: u64 = 10;
    let w = work();
    let observed = observe(
        &[&"inflight", &w.fifo, &w.root, &ROUNDS.to_string()],
        TracerConfig {
            inflight_max: 1,
            ..TracerConfig::default()
        },
    );
    let out = &observed.out;
    assert_eq!(line(out, "parked").raw, 0, "{out:#?}");
    assert_eq!(line(out, "covered").raw, 2 * ROUNDS as i64, "{out:#?}");
    assert_eq!(line(out, "reads").raw, 2 * ROUNDS as i64, "{out:#?}");
    assert_eq!(line(out, "after").raw, 0, "{out:#?}");
    let summary = &observed.summary;
    assert_eq!(
        summary.loss.inflight_rejected,
        2 * ROUNDS,
        "only the covered calls were refused: {summary:?}"
    );
    assert!(
        summary.filtered_readonly_opens >= 2 * ROUNDS,
        "the reads were filtered, not refused: {summary:?}"
    );
    let exhausted: Vec<(OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::InflightExhausted)
        .map(|(_, ops, count)| (ops, count))
        .collect();
    let lost: u64 = exhausted.iter().filter_map(|(_, count)| *count).sum();
    assert_eq!(lost, 2 * ROUNDS, "{exhausted:?}");
    for (ops, _) in &exhausted {
        assert!(
            !ops.contains(ClosedOp::Open),
            "a gap naming an open: only reads were opened while the slot was held: {ops:?}"
        );
    }
    // The slot came back: the mkdir after the release is a result.
    assert_eq!(
        observed.results_on(&s(&w.root.join("after"))),
        vec![(ClosedOp::Mkdir, "mkdir", 0)]
    );
}

// ===========================================================================
// O-3 through the tracer loop
// ===========================================================================

/// O-3, measured through the real tracer loop: threads that make covered
/// calls without pause, ended by `exit_group`. Every thread is killed
/// wherever it is; some are at their seccomp entry stop, and the kernel
/// skips a call whose thread has a fatal signal pending after that stop.
/// A thread found killed at a stop the observer never resumed made no call,
/// which is not loss: no `syscall_info_unavailable`, ever. A call the
/// observer had let run when the kill came may have had its effect, so
/// `entry_abandoned` stays a gap there — the only reason allowed.
///
/// The check means something only if the kill did land at such a stop
/// (J4 W3, tracer review R3): at least `RUNS` races are run, and more, up to
/// `MAX_RUNS`, until one has; if none ever does, the test fails rather than
/// pass having checked nothing.
#[test]
fn j4_o3_a_group_exit_racing_entry_stops_is_never_syscall_info_loss() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    const RUNS: usize = 40;
    const MAX_RUNS: usize = 400;
    let mut seen_abandoned = 0u64;
    let mut killed = 0u64;
    let mut unavailable = Vec::new();
    let mut runs = 0;
    for run in 0..MAX_RUNS {
        if run >= RUNS && killed > 0 {
            break;
        }
        runs += 1;
        let w = work();
        let observed = observe(
            &[&"killrace", &w.root, &"4", &"30"],
            TracerConfig::default(),
        );
        let status = observed.exit_status().expect("the group's exit");
        assert_eq!(libc::WEXITSTATUS(status), 7, "run {run}");
        for (reason, ops, count) in observed.gaps() {
            match reason {
                GapReason::EntryAbandoned => seen_abandoned += count.unwrap_or(0),
                other => unavailable.push(format!("run {run}: {other:?} {ops:?} {count:?}")),
            }
        }
        killed += observed.summary.killed_at_entry;
        if observed.summary.loss.syscall_info_unavailable > 0 {
            unavailable.push(format!("run {run}: {:?}", observed.summary.loss));
        }
    }
    println!("entry_abandoned across {runs} runs: {seen_abandoned}; killed at entry: {killed}");
    assert_eq!(
        unavailable,
        Vec::<String>::new(),
        "a thread killed at a stop it was never resumed from made no call"
    );
    assert!(
        killed > 0,
        "no kill landed at an unresumed entry stop in {runs} races: the window was never tested"
    );
}

// ===========================================================================
// Through the product
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
            "the none checks need a delegated user scope: {}",
            leaf.evidence
        ));
        return false;
    }
    true
}

fn live(profile: &str) -> bool {
    common::live() && (profile != "none" || none_live())
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// One `ouro-jail run` over a private workspace holding the fixture at
/// `<workspace>/bin/j4-precision`, a FIFO nobody reads at
/// `<workspace>/fifo`, and an empty `<workspace>/ops`.
struct Case {
    jail: Jail,
    helper: PathBuf,
    fifo: PathBuf,
    ops: PathBuf,
}

fn case_on(jail: Jail, profile: &str, evidence: &str) -> Option<Case> {
    let (built, _) = build()?;
    let workspace = jail.root().join("workspace");
    private_dir(&workspace.join("bin"));
    private_dir(&workspace.join("ops"));
    let helper = workspace.join("bin/j4-precision");
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

/// Every receipt checked against its schema and the semantic rules, every
/// trace event against its schema; returns the receipt of `phase`.
fn receipt(run: &Run, phase: &str) -> Value {
    run.assert_channels_complete();
    // J5-C: every receipt, the trace as a stream and the control transcript,
    // held to the frozen contract.
    common::assert_run_records(run);
    run.receipt_phase(phase).unwrap_or_else(|| {
        panic!(
            "no {phase} receipt: exit {:?}, stderr {}",
            run.code(),
            run.stderr_text()
        )
    })
}

fn audit_events(run: &Run) -> Vec<&Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == "audit")
        .collect()
}

/// Audit results naming this workspace-relative path.
fn results_on<'a>(run: &'a Run, relative: &str) -> Vec<&'a Value> {
    audit_events(run)
        .into_iter()
        .filter(|event| {
            event["fields"]["path"]["kind"] == "workspace_relative"
                && event["fields"]["path"]["value"] == relative
        })
        .collect()
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

/// The class entry, asserted degraded with a null count and one gap of
/// `reason` naming it; returns that gap.
fn assert_degraded<'a>(receipt: &'a Value, class: &str, reason: &str) -> &'a Value {
    let entry = &receipt["coverage"][class];
    assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    assert_eq!(entry["observed_count"], Value::Null, "{class}: {entry:#}");
    let gaps: Vec<&Value> = entry["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|gap| gap["reason"] == reason)
        .collect();
    assert_eq!(gaps.len(), 1, "{class}: one {reason} gap: {entry:#}");
    gaps[0]
}

/// O-2 through the product, strict: the interrupted open is an `fs.write`
/// result with `EINTR`, the class is active and counts it, and nothing is
/// lost — so a strict attempt runs to its end and exits 0. On the base the
/// class read `active` with a count that left the call out, and no result
/// named the FIFO.
fn eintr_through_the_product(profile: &str) {
    let _serial = serial();
    if !live(profile) {
        return;
    }
    let Some(c) = case_on(Jail::new().unwrap(), profile, "strict") else {
        return;
    };
    let argv = c.argv("interrupt", &[&"eintr", &"open", &c.fifo, &c.ops]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "call").errno, libc::EINTR, "{profile}: {out:#?}");
    assert_eq!(
        run.code(),
        Some(0),
        "{profile}: stderr {}",
        run.stderr_text()
    );
    let fifo = results_on(&run, "fifo");
    assert_eq!(
        fifo.len(),
        1,
        "{profile}: one result for the call: {fifo:#?}"
    );
    assert_eq!(fifo[0]["operation"], "fs.write", "{profile}: {:#}", fifo[0]);
    assert_eq!(
        fifo[0]["outcome"]["errno"], "EINTR",
        "{profile}: {:#}",
        fifo[0]
    );
    assert_eq!(fifo[0]["outcome"]["ok"], false, "{profile}");
    // The interrupted open is the only covered filesystem call the fixture
    // makes; the target's exec and exit are the exec class.
    assert_active(&settled, "fs.write", 1);
    assert_active(&settled, "fs.deny", 0);
    assert_active(&settled, "exec", 2);
    assert_active(&settled, "net", 0);
}

#[test]
fn j4_o2_eintr_is_counted_through_the_product_tool() {
    eintr_through_the_product("tool");
}

#[test]
fn j4_o2_eintr_is_counted_through_the_product_none() {
    eintr_through_the_product("none");
}

/// O-1 through the product, with the shrink-only in-flight seam: the lost
/// count is exactly the covered calls made while the parked open held the
/// slot — the reads made meanwhile are outside the closed set and are not
/// loss. On the base every read counted too.
fn inflight_through_the_product(profile: &str) {
    const ROUNDS: u64 = 10;
    let _serial = serial();
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
    let argv = c.argv("inflight", &[&c.fifo, &c.ops, &ROUNDS.to_string()]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "parked").raw, 0, "{profile}: {out:#?}");
    assert_eq!(line(&out, "covered").raw, 2 * ROUNDS as i64, "{profile}");
    assert_eq!(line(&out, "reads").raw, 2 * ROUNDS as i64, "{profile}");
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "inflight_exhausted");
        assert_eq!(
            gap["lost_count"],
            2 * ROUNDS,
            "{profile}/{class}: the covered calls, not the reads: {gap:#}"
        );
    }
    assert_active(&settled, "exec", 2);
    assert_active(&settled, "net", 0);
    assert_eq!(
        results_on(&run, "ops/after").len(),
        1,
        "{profile}: the slot came back"
    );
    assert_eq!(
        run.code(),
        Some(1),
        "{profile}: best-effort exits 1 for the loss"
    );
}

#[test]
fn j4_o1_inflight_loss_counts_only_covered_calls_through_the_product_tool() {
    inflight_through_the_product("tool");
}

#[test]
fn j4_o1_inflight_loss_counts_only_covered_calls_through_the_product_none() {
    inflight_through_the_product("none");
}

// ===========================================================================
// J4 wave 3: the loss review's findings 1, 3 and 4, the tracer review's R1
// ===========================================================================

/// The gaps of `reason`, as `(ops, count)`.
fn gaps_of(observed: &Observed, reason: GapReason) -> Vec<(OpSet, Option<u64>)> {
    observed
        .gaps()
        .into_iter()
        .filter(|(r, _, _)| *r == reason)
        .map(|(_, ops, count)| (ops, count))
        .collect()
}

/// Where in the event stream the first event matching `pick` is.
fn position(observed: &Observed, pick: impl Fn(&TracerEvent) -> bool) -> Option<usize> {
    observed.events.iter().position(pick)
}

/// Loss review finding 1 (honesty), at the tracer seam. The leader parks in
/// `openat(FIFO, O_WRONLY)`; a worker `execve`s, which destroys the leader
/// with its open in flight and gives the worker the leader's id. The open
/// never returns — the fixture never prints `leader_open_returned`.
///
/// With an in-flight bound of one the worker's own `execve` entry cannot be
/// followed (the leader's open holds the slot). On the base the leader's
/// stale open was then left on the thread that now bears its id and paired
/// with the `execve`'s own syscall exit: an invented `openat = 0`. The rule:
/// at a non-leader exec the leader's entry can no longer return, whatever
/// the worker carried, so it is one `entry_abandoned` gap of its own classes,
/// never a result. The unbounded run is the control.
#[test]
fn j4_w3_a_leaders_entry_is_never_paired_with_a_non_leader_execs_exit() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (helper, _) = build().expect("built");
    for inflight in [1usize, 16_384] {
        let w = work();
        let observed = observe(
            &[&"leader-exec", &w.fifo, helper],
            TracerConfig {
                inflight_max: inflight,
                ..TracerConfig::default()
            },
        );
        let label = format!("in-flight bound {inflight}");
        let out = &observed.out;
        assert_eq!(line(out, "leader_parked").raw, 1, "{label}: {out:#?}");
        assert!(
            out.iter().all(|l| l.label != "leader_open_returned"),
            "{label}: the leader's open never returned: {out:#?}"
        );
        assert_eq!(
            observed.results_on(&s(&w.fifo)),
            vec![],
            "{label}: an open that never returned has no result:\n  {}",
            observed.describe()
        );
        assert_eq!(
            gaps_of(&observed, GapReason::EntryAbandoned),
            vec![(OpSet::of(ClosedOp::Open), Some(1))],
            "{label}: the leader's open is one entry_abandoned gap of its classes:\n  {}",
            observed.describe()
        );
        let refused = gaps_of(&observed, GapReason::InflightExhausted);
        if inflight == 1 {
            assert_eq!(
                refused,
                vec![(OpSet::of(ClosedOp::Exec), Some(1))],
                "{label}: the worker's execve could not be followed:\n  {}",
                observed.describe()
            );
        } else {
            assert_eq!(refused, vec![], "{label}");
        }
        assert_eq!(observed.exit_status(), Some(0), "{label}: exit0 ran");
        assert_eq!(
            observed.summary.ops.open, 0,
            "{label}: {:?}",
            observed.summary
        );
    }
}

/// Finding 1 through the product: `tool` and `none` with the shrink-only
/// in-flight seam at one. On the base the settled receipt carried an
/// `fs.write` result `ok: true` on the FIFO for an open that never returned.
fn leader_exec_through_the_product(profile: &str) {
    let _serial = serial();
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
    let argv = c.argv("leader-exec", &[&c.fifo, &c.helper]);
    let run = c.jail.target(argv).run().unwrap();
    let out = lines(&run.stdout_text());
    let settled = receipt(&run, "settled");
    assert_eq!(line(&out, "leader_parked").raw, 1, "{profile}: {out:#?}");
    assert!(
        out.iter().all(|l| l.label != "leader_open_returned"),
        "{profile}: {out:#?}"
    );
    assert_eq!(
        results_on(&run, "fifo"),
        Vec::<&Value>::new(),
        "{profile}: no result for an open that never returned"
    );
    for class in ["fs.write", "fs.deny"] {
        let gap = assert_degraded(&settled, class, "entry_abandoned");
        assert_eq!(gap["lost_count"], 1, "{profile}/{class}: {gap:#}");
    }
    let gap = assert_degraded(&settled, "exec", "inflight_exhausted");
    assert_eq!(
        gap["lost_count"], 1,
        "{profile}: the worker's execve: {gap:#}"
    );
    assert_active(&settled, "net", 0);
    assert_eq!(
        run.code(),
        Some(1),
        "{profile}: best-effort exits 1 for the loss: {}",
        run.stderr_text()
    );
}

#[test]
fn j4_w3_a_non_leader_exec_invents_no_result_through_the_product_tool() {
    leader_exec_through_the_product("tool");
}

#[test]
fn j4_w3_a_non_leader_exec_invents_no_result_through_the_product_none() {
    leader_exec_through_the_product("none");
}

/// Loss review finding 3, the listener. A thread's open holds the only
/// in-flight slot while the main thread asks for its own notification
/// listener: the request cannot be followed to its return, so the observer
/// cannot know whether a listener now exists, and must assume one does —
/// the open-ended `child_notification_listener` gap in every class, with no
/// count. On the base it was a one-count `inflight_exhausted` gap with an
/// end, although the listener then hid both `mkdir`s (continued with no
/// stop). The unbounded run is the control.
#[test]
fn j4_w3_a_listener_refused_a_slot_is_the_open_ended_gap_of_its_kind() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    for inflight in [1usize, 16_384] {
        let w = work();
        let observed = observe(
            &[&"hide", &w.fifo, &w.root, &"listener"],
            TracerConfig {
                inflight_max: inflight,
                ..TracerConfig::default()
            },
        );
        let label = format!("in-flight bound {inflight}");
        let out = &observed.out;
        assert_eq!(line(out, "parked").raw, 0, "{label}: {out:#?}");
        assert!(line(out, "listener").raw >= 0, "{label}: {out:#?}");
        assert_eq!(line(out, "hidden1").raw, 0, "{label}: {out:#?}");
        assert_eq!(line(out, "hidden2").raw, 0, "{label}: {out:#?}");
        assert_eq!(line(out, "released").errno, libc::EINTR, "{label}");
        for hidden in ["hidden1", "hidden2"] {
            assert_eq!(
                observed.results_on(&s(&w.root.join(hidden))),
                vec![],
                "{label}: the listener continued {hidden} with no stop"
            );
        }
        assert_eq!(
            observed.gaps(),
            vec![(GapReason::ChildNotificationListener, OpSet::ALL, None)],
            "{label}: one open-ended listener gap, and no bounded gap in its place:\n  {}",
            observed.describe()
        );
        assert_eq!(
            observed.results_on(&s(&w.fifo)),
            vec![(ClosedOp::Open, "openat", -i64::from(libc::EINTR))],
            "{label}"
        );
    }
}

/// Finding 3, `clone(CLONE_UNTRACED)`: refused a slot, the clone runs
/// unfollowed and makes a task nothing traces. It is the open-ended
/// `untraced_descendant` gap, as when it is followed; on the base it was a
/// one-count `inflight_exhausted` gap with an end.
#[test]
fn j4_w3_an_untraced_clone_refused_a_slot_is_the_open_ended_gap_of_its_kind() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    for inflight in [1usize, 16_384] {
        let w = work();
        let observed = observe(
            &[&"hide", &w.fifo, &w.root, &"untraced"],
            TracerConfig {
                inflight_max: inflight,
                ..TracerConfig::default()
            },
        );
        let label = format!("in-flight bound {inflight}");
        let out = &observed.out;
        assert_eq!(line(out, "parked").raw, 0, "{label}: {out:#?}");
        assert!(line(out, "clone").raw > 0, "{label}: {out:#?}");
        assert_eq!(
            line(out, "untraced_mkdir").errno,
            libc::ENOSYS,
            "{label}: the untraced child fails closed: {out:#?}"
        );
        assert_eq!(
            observed.gaps(),
            vec![(GapReason::UntracedDescendant, OpSet::ALL, None)],
            "{label}: one open-ended untraced-descendant gap:\n  {}",
            observed.describe()
        );
        assert_eq!(
            observed.results_on(&s(&w.root.join("hidden2"))),
            vec![(ClosedOp::Mkdir, "mkdir", 0)],
            "{label}: the slot came back"
        );
    }
}

/// Loss review finding 4, at the tracer seam: the §11.4 queue budget
/// (`queue_bytes_max`, which the observer plan records) must bound what the
/// observer holds on behalf of a consumer that is not reading — the
/// critical facts (`Exit`, `Gap`, `Finished`) aside, which §11.4 exempts.
/// Two hundred execs, each carrying a ~2.8 KiB pathname, while nothing
/// reads; then everything is read. On the base the 66-slot handoff channel
/// sat outside the budget: with a 16 KiB budget the observer held
/// ~200 KiB of `Exec` events.
#[test]
fn j4_w3_the_queue_budget_bounds_what_is_held_for_a_consumer_not_reading() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    const BUDGET: usize = 16_384;
    let (helper, _) = build().expect("built");
    let dir = common::private_tempdir();
    let image = dir.path().join("j4-precision");
    std::fs::copy(helper, &image).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A long pathname to the same image: many "./" components.
    let mut long = dir.path().to_path_buf().into_os_string();
    for _ in 0..1400 {
        long.push("/.");
    }
    long.push("/j4-precision");
    let long = PathBuf::from(long);
    let config = TracerConfig {
        queue_bytes_max: BUDGET,
        ..TracerConfig::default()
    };
    let observed = observe_image(
        &long,
        &[&"reexec", &"200", &long],
        config,
        Duration::from_millis(500),
    );
    assert_eq!(line(&observed.out, "done").raw, 0, "{:#?}", observed.out);
    let mut held = 0usize;
    let mut execs = 0usize;
    for event in &observed.events {
        let snapshots = match event {
            TracerEvent::Exec { path, .. } => {
                execs += 1;
                path.as_ref().map_or(0, |p| p.bytes.len())
            }
            TracerEvent::Syscall { args, .. } => {
                args.path.as_ref().map_or(0, |p| p.bytes.len())
                    + args.path2.as_ref().map_or(0, |p| p.bytes.len())
            }
            // Exempt from every queue bound (§11.4, J4 D6).
            TracerEvent::Exit { .. }
            | TracerEvent::Gap { .. }
            | TracerEvent::UntracedChildExit { .. }
            | TracerEvent::Finished => continue,
            TracerEvent::Attached { .. } | TracerEvent::Fork { .. } => 0,
        };
        held += ouro_jail::platform::linux::tracer::EVENT_FIXED_BYTES + snapshots;
    }
    println!(
        "{execs} Exec events delivered, {held} bytes held, {} dropped",
        observed.summary.loss.lifecycle_dropped
    );
    assert!(
        held <= BUDGET,
        "the observer held {held} bytes for a consumer that was not reading, \
         over the {BUDGET}-byte budget it records"
    );
    assert!(
        observed.summary.loss.lifecycle_dropped > 0
            && !gaps_of(&observed, GapReason::LifecycleDropped).is_empty(),
        "the budget was reached, and what it could not hold is a gap: {:?}",
        observed.summary
    );
}

/// Tracer review R1, at the tracer seam. A handler installed with
/// `SA_SIGINFO | SA_RESTART` interrupts a parked call; the kernel prepares
/// the restart in the handler's frame (`rax` = the call's number, `rip` back
/// on the `syscall` instruction), and the observer reads exactly that at the
/// handler's entry. The handler then rewrites its own frame so the thread
/// sees `EINTR` and the call is never re-entered — as a sibling rewriting the
/// frame the other way before the observer reads it can make a real `EINTR`
/// look like a restart. On the base the observer took the frame at its word:
/// no result and no gap for a call the program saw fail. The rule: a restart
/// read from a handler's frame is settled only by the re-entry itself; the
/// thread's next covered call, when it is another, or the thread's end,
/// settles it as a `restart_unresolved` gap of the call's classes.
fn rewritten_restart_is_a_gap(how: &str, kind: &str) -> (Work, Observed) {
    let (w, observed) = interrupt(how, kind);
    let label = format!("{how}/{kind}");
    let out = &observed.out;
    assert_eq!(line(out, "parked").raw, 0, "{label}: {out:#?}");
    assert_eq!(line(out, "rewrote").raw, 1, "{label}: {out:#?}");
    assert_eq!(
        line(out, "call").errno,
        libc::EINTR,
        "{label}: the program saw EINTR: {out:#?}"
    );
    let ops = OpSet::of(if kind == "open" {
        ClosedOp::Open
    } else {
        ClosedOp::Connect
    });
    assert_eq!(
        parked_results(kind, &w, &observed),
        Vec::<i64>::new(),
        "{label}: no re-entry, so no result was observed:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.gaps(),
        vec![(GapReason::RestartUnresolved, ops, Some(1))],
        "{label}: one gap of the call's classes, never silence:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.summary.restarts, 0,
        "{label}: {:?}",
        observed.summary
    );
    (w, observed)
}

#[test]
fn j4_w3_r1_a_restart_the_handler_rewrote_then_the_threads_end_is_a_gap_open() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    rewritten_restart_is_a_gap("rewrite", "open");
}

#[test]
fn j4_w3_r1_a_restart_the_handler_rewrote_then_the_threads_end_is_a_gap_connect() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    rewritten_restart_is_a_gap("rewrite", "connect");
}

/// R1, the next covered call: the thread's `mkdir` after the rewritten
/// `EINTR` settles the call as a gap at its own entry, so the gap comes
/// before the `mkdir`'s result.
#[test]
fn j4_w3_r1_a_restart_the_handler_rewrote_then_another_call_is_a_gap_first() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = rewritten_restart_is_a_gap("rewrite-mkdir", "open");
    assert_eq!(line(&observed.out, "after").raw, 0, "{:#?}", observed.out);
    let after = s(&w.root.join("after"));
    assert_eq!(
        observed.results_on(&after),
        vec![(ClosedOp::Mkdir, "mkdir", 0)]
    );
    let gap = position(&observed, |event| {
        matches!(
            event,
            TracerEvent::Gap {
                reason: GapReason::RestartUnresolved,
                ..
            }
        )
    });
    let mkdir = position(&observed, |event| {
        matches!(
            event,
            TracerEvent::Syscall {
                op: ClosedOp::Mkdir,
                ..
            }
        )
    });
    assert!(
        gap.is_some() && gap < mkdir,
        "the gap is settled at the mkdir's entry:\n  {}",
        observed.describe()
    );
}

/// What R1's rule costs, pinned so it stays visible: a handler installed
/// with `SA_RESTART` that makes a covered call of its own. That call is the
/// thread's next covered call, and it is not the re-entry, so the
/// interrupted call is a `restart_unresolved` gap — conservative: the
/// observer cannot tell a call inside the handler from one after a frame the
/// handler rewrote. The re-entry that follows is then an ordinary entry with
/// its own result, and the handler's `mkdir` is a result.
#[test]
fn j4_w3_r1_a_covered_call_inside_an_sa_restart_handler_costs_one_gap() {
    let _serial = serial();
    if !common::live() || build().is_none() {
        return;
    }
    let (w, observed) = interrupt("restart-mkdir", "open");
    let out = &observed.out;
    assert_eq!(line(out, "reparked").raw, 0, "{out:#?}");
    assert!(line(out, "call").raw >= 0, "the call completed: {out:#?}");
    assert_eq!(line(out, "handler_mkdir").raw, 1, "{out:#?}");
    let results = parked_results("open", &w, &observed);
    assert_eq!(results.len(), 1, "\n  {}", observed.describe());
    assert!(results[0] >= 0, "{results:?}");
    assert_eq!(
        observed.results_on(&s(&w.root.join("h"))),
        vec![(ClosedOp::Mkdir, "mkdir", 0)]
    );
    assert_eq!(
        observed.gaps(),
        vec![(
            GapReason::RestartUnresolved,
            OpSet::of(ClosedOp::Open),
            Some(1)
        )],
        "\n  {}",
        observed.describe()
    );
}
