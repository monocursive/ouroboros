#![cfg(target_os = "linux")]
//! Regression tests for the Linux ptrace observer, adopted from the
//! independent review of J1.
//!
//! Each one was written by a reviewer against the first version of the
//! module, and each either found a defect or survived a mutation the
//! module's own suite did not catch. They are kept in the reviewer's own
//! shape — build a C fixture, run it under `Tracer::attach`, compare what the
//! observer said with what the fixture said about itself — and the name of
//! each test carries the reviewer's number so the finding it stands for can
//! be traced back.
//!
//! Where a fix changed what the right answer is, the assertion is inverted
//! rather than deleted, and the doc comment says which defect it now pins.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ouro_fixture::harness;
use ouro_jail::platform::linux::seccomp;
use ouro_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, Tracer, TracerConfig, TracerEvent, TracerSummary, clock,
    narrowing_filter_bytes,
};

const HELPER_C: &str = r##"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
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

extern char **environ;

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

static int mode_launch(int argc, char **argv) {
    if (argc < 4) return 2;
    if (install_filter(argv[2])) { fprintf(stderr, "install_filter failed\n"); return 3; }
    /* The exec that brought us here is complete and the filter is on. The
       supervisor seizes only after reading this, so the seize can never land
       in the middle of an exec it did not ask about. */
    report("ready", (long) getpid(), "", "");
    if (await_release()) return 4;
    execv(argv[3], &argv[3]);
    fprintf(stderr, "execv %s: %s\n", argv[3], strerror(errno));
    return 127;
}

/* launch2 BASELINE NARROWING PROG ... : the product's shape, enforcement
   baseline first and the observer's narrowing filter second. */
static int mode_launch2(int argc, char **argv) {
    if (argc < 5) return 2;
    if (install_filter(argv[2])) { fprintf(stderr, "baseline failed\n"); return 3; }
    if (install_filter(argv[3])) { fprintf(stderr, "narrowing failed\n"); return 3; }
    report("ready", (long) getpid(), "", "");
    if (await_release()) return 4;
    execv(argv[4], &argv[4]);
    fprintf(stderr, "execv %s: %s\n", argv[4], strerror(errno));
    return 127;
}

static char *page_pair(size_t *ps_out) {
    size_t ps = (size_t) sysconf(_SC_PAGESIZE);
    char *m = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return NULL;
    if (mprotect(m + ps, ps, PROT_NONE)) return NULL;
    *ps_out = ps;
    return m;
}

static volatile sig_atomic_t g_hits = 0;
static void on_usr1(int s) { (void) s; g_hits++; }

static int mode_restart_fifo(int argc, char **argv) {
    struct sigaction sa;
    pid_t kid;
    long r;
    if (argc < 3) return 2;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    kid = fork();
    if (kid == 0) {
        int i, fd;
        pid_t parent = getppid();
        for (i = 0; i < 6; i++) { usleep(60000); kill(parent, SIGUSR1); }
        usleep(60000);
        fd = (int) syscall(SYS_openat, AT_FDCWD, argv[2], O_RDONLY, 0);
        usleep(200000);
        if (fd >= 0) close(fd);
        _exit(0);
    }
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY, 0);
    report("fifo_open", r, argv[2], "");
    if (r >= 0) close((int) r);
    waitpid(kid, NULL, 0);
    report("signals", (long) g_hits, "", "");
    return 0;
}

static int mode_stopcont(int argc, char **argv) {
    pid_t kid;
    long r;
    if (argc < 3) return 2;
    kid = fork();
    if (kid == 0) {
        int fd;
        pid_t parent = getppid();
        usleep(200000); kill(parent, SIGSTOP);
        usleep(400000); kill(parent, SIGCONT);
        usleep(200000);
        fd = (int) syscall(SYS_openat, AT_FDCWD, argv[2], O_RDONLY, 0);
        usleep(200000);
        if (fd >= 0) close(fd);
        _exit(0);
    }
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY, 0);
    report("fifo_open", r, argv[2], "");
    if (r >= 0) close((int) r);
    waitpid(kid, NULL, 0);
    return 0;
}

static char *g_fifo;
static void *blocker(void *arg) {
    (void) arg;
    syscall(SYS_openat, AT_FDCWD, g_fifo, O_WRONLY, 0);
    return NULL;
}

static int mode_die_inflight(int argc, char **argv) {
    pthread_t t;
    if (argc < 4) return 2;
    g_fifo = argv[2];
    pthread_create(&t, NULL, blocker, NULL);
    usleep(300000);
    report("exiting", (long) atol(argv[3]), "", "");
    syscall(SYS_exit_group, atol(argv[3]));
    return 0;
}

static int mode_forkburst(int argc, char **argv) {
    long n, i, ok = 0;
    if (argc < 4) return 2;
    n = atol(argv[2]);
    for (i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) {
            char *av[2];
            av[0] = argv[3];
            av[1] = NULL;
            execv(argv[3], av);
            _exit(126);
        }
        if (p > 0) ok++; else break;
    }
    for (i = 0; i < ok; i++) { int st = 0; wait(&st); }
    report("forkburst", ok, "", "");
    return 0;
}

static int mode_badpath(int argc, char **argv) {
    size_t ps;
    char *m;
    long r;
    const char *kind;
    char name[256];
    if (argc < 4) return 2;
    kind = argv[2];
    m = page_pair(&ps);
    if (!m) return 3;
    snprintf(name, sizeof name, "%s/edge", argv[3]);
    if (!strcmp(kind, "edge")) {
        size_t len = strlen(name);
        char *p = m + ps - (len + 1);
        memcpy(p, name, len + 1);
        r = syscall(SYS_openat, AT_FDCWD, p, O_WRONLY | O_CREAT, 0600);
        report("edge", r, name, "");
        if (r >= 0) close((int) r);
    } else if (!strcmp(kind, "nonul")) {
        memset(m, 'a', ps);
        r = syscall(SYS_openat, AT_FDCWD, m, O_WRONLY | O_CREAT, 0600);
        report("nonul", r, "", "");
    } else if (!strcmp(kind, "unmapped")) {
        r = syscall(SYS_openat, AT_FDCWD, m + ps, O_WRONLY | O_CREAT, 0600);
        report("unmapped", r, "", "");
    } else if (!strcmp(kind, "minus1")) {
        r = syscall(SYS_openat, AT_FDCWD, (void *) -1L, O_WRONLY | O_CREAT, 0600);
        report("minus1", r, "", "");
    } else if (!strcmp(kind, "null")) {
        r = syscall(SYS_openat, AT_FDCWD, (void *) 0L, O_WRONLY | O_CREAT, 0600);
        report("null", r, "", "");
    } else if (!strcmp(kind, "long")) {
        char *big = malloc(9000);
        memset(big, 'b', 8999);
        big[8999] = 0;
        r = syscall(SYS_openat, AT_FDCWD, big, O_WRONLY | O_CREAT, 0600);
        report("long", r, "", "");
    } else return 2;
    return 0;
}

static int mode_badsock(int argc, char **argv) {
    size_t ps;
    char *m;
    long r;
    int fd;
    const char *kind;
    struct sockaddr_in sin;
    if (argc < 3) return 2;
    kind = argv[2];
    m = page_pair(&ps);
    if (!m) return 3;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9);
    sin.sin_addr.s_addr = htonl(0x7f000001);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    if (!strcmp(kind, "lie-long")) {
        memcpy(m, &sin, sizeof sin);
        memset(m + sizeof sin, 0x5a, 128 - sizeof sin);
        r = syscall(SYS_connect, fd, m, 128L);
        report("lie_long", r, "", "");
    } else if (!strcmp(kind, "edge")) {
        char *p = m + ps - sizeof sin;
        memcpy(p, &sin, sizeof sin);
        r = syscall(SYS_connect, fd, p, (long) sizeof sin);
        report("edge", r, "", "");
    } else if (!strcmp(kind, "over-edge")) {
        char *p = m + ps - 8;
        memcpy(p, &sin, 8);
        r = syscall(SYS_connect, fd, p, 64L);
        report("over_edge", r, "", "");
    } else if (!strcmp(kind, "unmapped")) {
        r = syscall(SYS_connect, fd, m + ps, (long) sizeof sin);
        report("unmapped", r, "", "");
    } else if (!strcmp(kind, "zero-len")) {
        memcpy(m, &sin, sizeof sin);
        r = syscall(SYS_connect, fd, m, 0L);
        report("zero_len", r, "", "");
    } else if (!strcmp(kind, "huge-len")) {
        memcpy(m, &sin, sizeof sin);
        r = syscall(SYS_connect, fd, m, 0x7fffffffL);
        report("huge_len", r, "", "");
    } else if (!strcmp(kind, "null-ptr")) {
        r = syscall(SYS_connect, fd, (void *) 0L, (long) sizeof sin);
        report("null_ptr", r, "", "");
    } else return 2;
    close(fd);
    return 0;
}

static int mode_outside(int argc, char **argv) {
    char mk[512], tr[512], i386[512], x32[512];
    long r;
    int fd;
    char *low;
    if (argc < 3) return 2;
    snprintf(mk, sizeof mk, "%s/by-mknod", argv[2]);
    snprintf(tr, sizeof tr, "%s/by-truncate", argv[2]);
    snprintf(i386, sizeof i386, "%s/by-int80", argv[2]);
    snprintf(x32, sizeof x32, "%s/by-x32", argv[2]);

    r = syscall(SYS_mknodat, AT_FDCWD, mk, S_IFREG | 0600, 0);
    report("mknodat", r, mk, "");

    fd = (int) syscall(SYS_openat, AT_FDCWD, tr, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) { if (write(fd, "hello", 5) < 0) {} close(fd); }
    r = syscall(SYS_truncate, tr, 0L);
    report("truncate", r, tr, "");

    low = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low == MAP_FAILED) {
        report("int80_open", -1, i386, "");
    } else {
        unsigned int p32;
        long res;
        strncpy(low, i386, 4000);
        p32 = (unsigned int) (uintptr_t) low;
        __asm__ volatile("int $0x80" : "=a"(res) : "a"(5L), "b"((long) p32), "c"(0x41L), "d"(0600L) : "memory");
        errno = res < 0 ? (int) -res : 0;
        report("int80_open", res < 0 ? -1 : res, i386, "");
    }

    r = syscall(0x40000000L | 257L, AT_FDCWD, x32, O_WRONLY | O_CREAT, 0600);
    report("x32_openat", r, x32, "");
    return 0;
}

static int mode_openhow(int argc, char **argv) {
    struct ouro_open_how how;
    size_t ps;
    char *m;
    char p[512];
    long r;
    int i;
    static const long sizes[] = {0, 8, 16, 24, 32, 4096, -1};
    if (argc < 3) return 2;
    how.flags = O_WRONLY | O_CREAT;
    how.mode = 0600;
    how.resolve = 0;
    for (i = 0; i < 7; i++) {
        char lbl[64];
        snprintf(p, sizeof p, "%s/how%d", argv[2], i);
        snprintf(lbl, sizeof lbl, "size_%ld", sizes[i]);
        r = syscall(437, AT_FDCWD, p, &how, sizes[i]);
        report(lbl, r, p, "");
        if (r >= 0) close((int) r);
    }
    m = page_pair(&ps);
    if (m) {
        snprintf(p, sizeof p, "%s/how-unmapped", argv[2]);
        r = syscall(437, AT_FDCWD, p, m + ps, 24L);
        report("how_unmapped", r, p, "");
    }
    return 0;
}

static int mode_bigpaths(int argc, char **argv) {
    long n, i;
    char *a, *b;
    size_t len = 4000;
    if (argc < 4) return 2;
    n = atol(argv[2]);
    a = malloc(len + 1);
    b = malloc(len + 1);
    memset(a, 'a', len); a[len] = 0;
    memset(b, 'b', len); b[len] = 0;
    memcpy(a, argv[3], strlen(argv[3]));
    memcpy(b, argv[3], strlen(argv[3]));
    for (i = 0; i < n; i++) syscall(SYS_rename, a, b);
    report("bigpaths", n, "", "");
    return 0;
}

static int mode_sleep_forever(void) {
    report("sleeping", (long) getpid(), "", "");
    for (;;) pause();
}

static int mode_quick(int argc, char **argv) {
    long r;
    char p[512];
    if (argc < 3) return 2;
    snprintf(p, sizeof p, "%s/quick", argv[2]);
    r = syscall(SYS_openat, AT_FDCWD, p, O_WRONLY | O_CREAT, 0600);
    report("quick", r, p, "");
    if (r >= 0) close((int) r);
    return 0;
}

static int mode_vfork(int argc, char **argv) {
    pid_t p;
    int st = 0;
    if (argc < 3) return 2;
    p = vfork();
    if (p == 0) {
        char *av[2];
        av[0] = argv[2];
        av[1] = NULL;
        execv(argv[2], av);
        _exit(126);
    }
    if (p < 0) return 3;
    waitpid(p, &st, 0);
    report("vfork_child", (long) p, "", "");
    {
        pid_t sp = 0;
        char *av[2];
        av[0] = argv[2];
        av[1] = NULL;
        if (posix_spawn(&sp, argv[2], NULL, NULL, av, environ) == 0) {
            waitpid(sp, &st, 0);
            report("spawn_child", (long) sp, "", "");
        } else {
            report("spawn_child", -1, "", "");
        }
    }
    return 0;
}

static int mode_execveat(int argc, char **argv) {
    char *av[2];
    long r;
    int fd;
    if (argc < 4) return 2;
    av[1] = NULL;
    av[0] = argv[3];
    r = syscall(SYS_execveat, AT_FDCWD, argv[3], av, environ, 0);
    report("execveat_fail", r, argv[3], "");
    fd = open(argv[2], O_RDONLY);
    if (fd < 0) { report("open_good", -1, argv[2], ""); return 3; }
    av[0] = argv[2];
    r = syscall(SYS_execveat, fd, "", av, environ, AT_EMPTY_PATH);
    report("execveat_ok", r, argv[2], "");
    return 4;
}

static int mode_closes(int argc, char **argv) {
    long n, i;
    if (argc < 3) return 2;
    n = atol(argv[2]);
    for (i = 0; i < n; i++) syscall(SYS_close, -1);
    report("closes", n, "", "");
    return 0;
}

static int mode_inprogress(void) {
    struct sockaddr_in sin;
    long r;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return 3;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = htonl(0xC0000202);
    r = syscall(SYS_connect, fd, &sin, (long) sizeof sin);
    report("inprogress", r, "", "");
    close(fd);
    return 0;
}

static int mode_twopath(int argc, char **argv) {
    size_t ps = (size_t) sysconf(_SC_PAGESIZE);
    char *m;
    char good[512];
    long r;
    int fd;
    if (argc < 3) return 2;
    snprintf(good, sizeof good, "%s/good", argv[2]);
    fd = (int) syscall(SYS_openat, AT_FDCWD, good, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) close(fd);
    m = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 3;
    mprotect(m + ps, ps, PROT_NONE);
    r = syscall(SYS_rename, good, m + ps);
    report("rename_second_faults", r, good, "");
    r = syscall(SYS_rename, m + ps, good);
    report("rename_first_faults", r, "", good);
    return 0;
}

static void *sleeper(void *arg) { (void) arg; usleep(400000); return NULL; }
static char *g_exec_argv[2];
static void *execer(void *arg) {
    (void) arg;
    usleep(150000);
    execv(g_exec_argv[0], g_exec_argv);
    _exit(3);
}
static int mode_threads_exec(int argc, char **argv) {
    pthread_t t[4];
    int i;
    if (argc < 3) return 2;
    g_exec_argv[0] = argv[2];
    g_exec_argv[1] = NULL;
    for (i = 0; i < 3; i++) pthread_create(&t[i], NULL, sleeper, NULL);
    pthread_create(&t[3], NULL, execer, NULL);
    report("leader", (long) getpid(), "", "");
    for (;;) pause();
}

/* helper exec-over-inflight FIFO PROGRAM: a worker blocks in openat on the
   FIFO while another thread execs. The kernel destroys the blocked thread
   without ever reporting it, and its entry can no longer return. */
static int mode_exec_over_inflight(int argc, char **argv) {
    pthread_t t[2];
    if (argc < 4) return 2;
    g_fifo = argv[2];
    g_exec_argv[0] = argv[3];
    g_exec_argv[1] = NULL;
    pthread_create(&t[0], NULL, blocker, NULL);
    usleep(300000);
    pthread_create(&t[1], NULL, execer, NULL);
    report("leader", (long) getpid(), "", "");
    for (;;) pause();
}

static int mode_abi(int argc, char **argv) {
    char i386[512], native[512], mk[512];
    char *low;
    long r;
    if (argc < 3) return 2;
    snprintf(i386, sizeof i386, "%s/abi-int80", argv[2]);
    snprintf(native, sizeof native, "%s/abi-native", argv[2]);
    snprintf(mk, sizeof mk, "%s/abi-mknod", argv[2]);
    low = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low == MAP_FAILED) { report("int80", -1, i386, ""); }
    else {
        unsigned int p32;
        long res;
        strncpy(low, i386, 4000);
        p32 = (unsigned int) (uintptr_t) low;
        __asm__ volatile("int $0x80" : "=a"(res) : "a"(5L), "b"((long) p32), "c"(0x41L), "d"(0600L) : "memory");
        errno = res < 0 ? (int) -res : 0;
        report("int80", res < 0 ? -1 : res, i386, "");
    }
    r = syscall(SYS_openat, AT_FDCWD, native, O_WRONLY | O_CREAT, 0600);
    report("native", r, native, "");
    if (r >= 0) close((int) r);
    r = syscall(SYS_mknodat, AT_FDCWD, mk, S_IFIFO | 0600, 0);
    report("mknodat", r, mk, "");
    return 0;
}

static int mode_rdonly(int argc, char **argv) {
    long n, i, ok = 0;
    if (argc < 4) return 2;
    n = atol(argv[2]);
    for (i = 0; i < n; i++) {
        long fd = syscall(SYS_openat, AT_FDCWD, argv[3], O_RDONLY, 0);
        if (fd >= 0) { ok++; close((int) fd); }
    }
    report("rdonly", ok, argv[3], "");
    return 0;
}

static char *g_prog;
static pid_t g_worker_tid, g_child;
static void *forker(void *arg) {
    (void) arg;
    g_worker_tid = (pid_t) syscall(SYS_gettid);
    g_child = fork();
    if (g_child == 0) {
        char *av[2];
        av[0] = g_prog;
        av[1] = NULL;
        execv(g_prog, av);
        _exit(126);
    }
    return NULL;
}
static int mode_worker_fork(int argc, char **argv) {
    pthread_t t;
    int st = 0;
    if (argc < 3) return 2;
    g_prog = argv[2];
    pthread_create(&t, NULL, forker, NULL);
    pthread_join(t, NULL);
    waitpid(g_child, &st, 0);
    report("leader_pid", (long) getpid(), "", "");
    report("worker_tid", (long) g_worker_tid, "", "");
    report("child_pid", (long) g_child, "", "");
    return 0;
}

static int mode_symlink(int argc, char **argv) {
    char link[512];
    long r;
    if (argc < 3) return 2;
    snprintf(link, sizeof link, "%s/the-link", argv[2]);
    r = syscall(SYS_symlink, "THE-TARGET", link);
    report("symlink", r, "THE-TARGET", link);
    return 0;
}

static int mode_unreadable(int argc, char **argv) {
    size_t ps = (size_t) sysconf(_SC_PAGESIZE);
    char *m;
    long n, i;
    if (argc < 3) return 2;
    n = atol(argv[2]);
    m = mmap(NULL, ps, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 3;
    for (i = 0; i < n; i++) syscall(SYS_openat, AT_FDCWD, m, O_WRONLY | O_CREAT, 0600);
    report("unreadable", n, "", "");
    return 0;
}

static int mode_i386_pipe(void) {
    int fds[2] = {-1, -1};
    long res;
    __asm__ volatile("int $0x80" : "=a"(res) : "a"(42L), "b"((long) (uintptr_t) fds) : "memory");
    report("i386_pipe", res, "", "");
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    return 0;
}

static long g_n;
static char *g_worker_path;
static void *hammer(void *arg) {
    long i;
    (void) arg;
    for (i = 0; i < g_n; i++) {
        long fd = syscall(SYS_openat, AT_FDCWD, g_worker_path, O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) close((int) fd);
    }
    return NULL;
}
static int mode_two_threads(int argc, char **argv) {
    pthread_t t;
    long i;
    if (argc < 5) return 2;
    g_n = atol(argv[2]);
    g_worker_path = argv[4];
    pthread_create(&t, NULL, hammer, NULL);
    for (i = 0; i < g_n; i++) {
        long fd = syscall(SYS_openat, AT_FDCWD, argv[3], O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) close((int) fd);
    }
    pthread_join(t, NULL);
    report("leader_path", g_n, argv[3], "");
    report("worker_path", g_n, argv[4], "");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "launch")) return mode_launch(argc, argv);
    if (!strcmp(argv[1], "launch2")) return mode_launch2(argc, argv);
    if (!strcmp(argv[1], "restart-fifo")) return mode_restart_fifo(argc, argv);
    if (!strcmp(argv[1], "stopcont")) return mode_stopcont(argc, argv);
    if (!strcmp(argv[1], "die-inflight")) return mode_die_inflight(argc, argv);
    if (!strcmp(argv[1], "forkburst")) return mode_forkburst(argc, argv);
    if (!strcmp(argv[1], "badpath")) return mode_badpath(argc, argv);
    if (!strcmp(argv[1], "badsock")) return mode_badsock(argc, argv);
    if (!strcmp(argv[1], "outside")) return mode_outside(argc, argv);
    if (!strcmp(argv[1], "openhow")) return mode_openhow(argc, argv);
    if (!strcmp(argv[1], "bigpaths")) return mode_bigpaths(argc, argv);
    if (!strcmp(argv[1], "sleep-forever")) return mode_sleep_forever();
    if (!strcmp(argv[1], "quick")) return mode_quick(argc, argv);
    if (!strcmp(argv[1], "vfork")) return mode_vfork(argc, argv);
    if (!strcmp(argv[1], "execveat")) return mode_execveat(argc, argv);
    if (!strcmp(argv[1], "closes")) return mode_closes(argc, argv);
    if (!strcmp(argv[1], "inprogress")) return mode_inprogress();
    if (!strcmp(argv[1], "twopath")) return mode_twopath(argc, argv);
    if (!strcmp(argv[1], "threads-exec")) return mode_threads_exec(argc, argv);
    if (!strcmp(argv[1], "exec-over-inflight")) return mode_exec_over_inflight(argc, argv);
    if (!strcmp(argv[1], "abi")) return mode_abi(argc, argv);
    if (!strcmp(argv[1], "rdonly")) return mode_rdonly(argc, argv);
    if (!strcmp(argv[1], "worker-fork")) return mode_worker_fork(argc, argv);
    if (!strcmp(argv[1], "symlink")) return mode_symlink(argc, argv);
    if (!strcmp(argv[1], "unreadable")) return mode_unreadable(argc, argv);
    if (!strcmp(argv[1], "i386-pipe")) return mode_i386_pipe();
    if (!strcmp(argv[1], "two-threads")) return mode_two_threads(argc, argv);
    return 2;
}
"##;

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
fn skip(reason: &str) {
    harness::skip_or_fail(reason);
}

fn build() -> Result<&'static (PathBuf, PathBuf), String> {
    static BUILD: OnceLock<Result<(PathBuf, PathBuf), String>> = OnceLock::new();
    BUILD
        .get_or_init(|| {
            if !std::path::Path::new("/usr/bin/gcc").exists() {
                return Err("/usr/bin/gcc is not installed".to_string());
            }
            let dir = std::env::temp_dir().join(format!("ouro-j1-regress-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            let source = dir.join("regress.c");
            std::fs::write(&source, HELPER_C).map_err(|e| format!("write regress.c: {e}"))?;
            let helper = dir.join("regress");
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
    fn base(&self) -> String {
        self.dir.to_string_lossy().into_owned()
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
            skip(&format!("{name}: {err}"));
            return None;
        }
    };
    let dir = std::env::temp_dir().join(format!("ouro-j1-r-{name}-{}", std::process::id()));
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
    /// Wait until the launcher has finished its own exec and installed the
    /// filter, so the seize cannot land inside an exec this test never asked
    /// about.
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
    path2: String,
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
            path2: fields.next().unwrap_or_default().to_string(),
        })
    }
    fn ret(&self) -> i64 {
        if self.errno == 0 {
            self.raw
        } else {
            -i64::from(self.errno)
        }
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
    drop(child);
    let mut launched = Launched {
        pid,
        release,
        output,
    };
    launched.await_ready();
    launched
}

fn launch(work: &Work, argv: &[&str]) -> Launched {
    let mut command = Command::new(&work.helper);
    command.arg("launch").arg(&work.filter).args(argv);
    spawn(command)
}

struct Observed {
    events: Vec<TracerEvent>,
    summary: TracerSummary,
}

impl Observed {
    fn syscalls(&self) -> Vec<&TracerEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, TracerEvent::Syscall { .. }))
            .collect()
    }
    fn of_op(&self, op: ClosedOp) -> Vec<&TracerEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, TracerEvent::Syscall { op: o, .. } if *o == op))
            .collect()
    }
    fn exits(&self) -> Vec<(libc::pid_t, i32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::Exit { pid, status, .. } => Some((*pid, *status)),
                _ => None,
            })
            .collect()
    }
    fn execs(&self) -> Vec<libc::pid_t> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::Exec { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect()
    }
    fn forks(&self) -> Vec<(libc::pid_t, libc::pid_t)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::Fork { parent, child, .. } => Some((*parent, *child)),
                _ => None,
            })
            .collect()
    }
    fn gaps(&self) -> Vec<(GapReason, OpSet, Option<u64>)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::Gap {
                    reason, ops, count, ..
                } => Some((*reason, *ops, *count)),
                _ => None,
            })
            .collect()
    }
    fn has_gap(&self, reason: GapReason) -> bool {
        self.gaps().iter().any(|(r, _, _)| *r == reason)
    }
    fn untraced(&self) -> Vec<(libc::pid_t, i32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TracerEvent::UntracedChildExit { pid, status } => Some((*pid, *status)),
                _ => None,
            })
            .collect()
    }
    fn describe(&self) -> String {
        self.events
            .iter()
            .map(|e| match e {
                TracerEvent::Syscall {
                    tid,
                    syscall,
                    args,
                    ret,
                    ..
                } => format!(
                    "Syscall{{{tid} {syscall} ret={ret} p1={:?} p2={:?} sock={:?}}}",
                    args.path.as_ref().map(|p| (
                        String::from_utf8_lossy(&p.bytes[..p.bytes.len().min(48)]).into_owned(),
                        p.complete
                    )),
                    args.path2.as_ref().map(|p| (
                        String::from_utf8_lossy(&p.bytes[..p.bytes.len().min(48)]).into_owned(),
                        p.complete
                    )),
                    args.sockaddr
                ),
                other => format!("{other:?}"),
            })
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

fn primary(event: &TracerEvent) -> String {
    match event {
        TracerEvent::Syscall { args, .. } => args
            .path
            .as_ref()
            .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn mkfifo(path: &str) {
    let c = std::ffi::CString::new(path).expect("a path without NULs");
    // SAFETY: `mkfifo` takes a NUL-terminated path and a mode.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo {path}: {}", std::io::Error::last_os_error());
}

fn rss_kib() -> i64 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }
    0
}

fn proc_state(pid: libc::pid_t) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// A cBPF program written straight out, for the tests that install a filter
/// the module did not produce.
fn filter_bytes(program: &[libc::sock_filter]) -> Vec<u8> {
    let mut out = Vec::new();
    for insn in program {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

// =============================================================== the checks

/// R1: an interrupted-and-restarted covered call produces exactly one
/// result. The regression test for the `ERESTARTSYS` check, which a mutation
/// survived because nothing exercised it.
#[test]
fn r1_a_restarted_syscall_produces_exactly_one_result() {
    let _serial = serial();
    let Some(work) = setup("r1") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "restart-fifo", &fifo]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let open = Report::find(&reports, "fifo_open");
    let signals = Report::find(&reports, "signals");
    assert!(
        signals.raw >= 1,
        "the fixture must actually have been interrupted"
    );
    let opens: Vec<&TracerEvent> = observed
        .of_op(ClosedOp::Open)
        .into_iter()
        .filter(|e| primary(e) == fifo)
        .collect();
    assert_eq!(
        opens.len(),
        1,
        "one call, one result:\n  {}",
        observed.describe()
    );
    let TracerEvent::Syscall { ret, .. } = opens[0] else {
        unreachable!()
    };
    assert_eq!(*ret, open.ret());
    assert!(observed.summary.restarts >= 1, "the restart was recognised");
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "a restart is not loss: {:?}",
        observed.summary.loss
    );
}

/// R2: SIGSTOP and SIGCONT during a covered call neither wedge the tracer nor
/// duplicate the result. The group-stop is told apart from an attach stop by
/// `PTRACE_GETSIGINFO` and preserved with `PTRACE_LISTEN`.
#[test]
fn r2_a_group_stop_during_a_covered_call_is_survived() {
    let _serial = serial();
    let Some(work) = setup("r2") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "stopcont", &fifo]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let open = Report::find(&reports, "fifo_open");
    let opens: Vec<&TracerEvent> = observed
        .of_op(ClosedOp::Open)
        .into_iter()
        .filter(|e| primary(e) == fifo)
        .collect();
    assert_eq!(opens.len(), 1, "\n  {}", observed.describe());
    let TracerEvent::Syscall { ret, .. } = opens[0] else {
        unreachable!()
    };
    assert_eq!(*ret, open.ret());
    assert_eq!(observed.exits().len(), 1, "{:?}", observed.exits());
    assert_eq!(observed.summary.loss.restart_failed, 0);
}

/// R3: a tracee that is already stopped when the supervisor seizes it can
/// still be attached, and the observer keeps working after SIGCONT.
#[test]
fn r3_attaching_to_an_already_stopped_tracee_works() {
    let _serial = serial();
    let Some(work) = setup("r3") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "quick", &base]);
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: a pid this test created, and a valid signal.
    assert_eq!(unsafe { libc::kill(run.pid, libc::SIGSTOP) }, 0);
    std::thread::sleep(Duration::from_millis(200));
    let tracer = attach(run.pid, TracerConfig::default());
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(run.pid, libc::SIGCONT) }, 0);
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "quick");
    assert_eq!(observed.execs(), vec![run.pid]);
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 1);
    assert_eq!(observed.exits(), vec![(run.pid, 0)]);
}

/// R4: a process that exits while a covered call is in flight yields a gap,
/// never a manufactured result, and still yields one exit with the real code.
#[test]
fn r4_an_exit_while_a_call_is_in_flight_is_a_gap_not_a_result() {
    let _serial = serial();
    let Some(work) = setup("r4") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "die-inflight", &fifo, "5"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let opens: Vec<&TracerEvent> = observed
        .of_op(ClosedOp::Open)
        .into_iter()
        .filter(|e| primary(e) == fifo)
        .collect();
    assert!(
        opens.is_empty(),
        "the blocked open never returned, so no result may exist:\n  {}",
        observed.describe()
    );
    assert!(
        observed.summary.loss.abandoned_entries >= 1,
        "the entry that can no longer return must be counted: {:?}",
        observed.summary.loss
    );
    assert!(
        observed.has_gap(GapReason::EntryAbandoned),
        "{:?}",
        observed.gaps()
    );
    let exits = observed.exits();
    assert_eq!(exits.len(), 1, "{exits:?}");
    assert_eq!(exits[0].0, run.pid);
    assert_eq!(libc::WEXITSTATUS(exits[0].1), 5);
}

/// R5: a fork burst keeps attribution — one `Fork`, one `Exec` and one `Exit`
/// per child, each with the child's own exit code.
#[test]
fn r5_a_fork_burst_keeps_attribution() {
    let _serial = serial();
    let Some(work) = setup("r5") else { return };
    const N: usize = 300;
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(&work, &[&helper, "forkburst", &n, "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(180));

    assert_eq!(Report::find(&reports, "forkburst").raw, N as i64);
    let forks = observed.forks();
    assert_eq!(forks.len(), N, "one Fork per child");
    let children: std::collections::BTreeSet<libc::pid_t> = forks.iter().map(|(_, c)| *c).collect();
    assert_eq!(children.len(), N, "no child pid reported twice");
    assert_eq!(
        observed.execs().len(),
        N + 1,
        "the launcher plus every child"
    );
    let exits = observed.exits();
    assert_eq!(exits.len(), N + 1);
    for (pid, status) in &exits {
        assert!(libc::WIFEXITED(*status), "pid {pid} status {status}");
        assert_eq!(libc::WEXITSTATUS(*status), 0, "pid {pid}");
    }
    let exited: std::collections::BTreeSet<libc::pid_t> = exits.iter().map(|(p, _)| *p).collect();
    for child in &children {
        assert!(exited.contains(child), "child {child} never got an Exit");
    }
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R6: pathname arguments that lie. Each case is a snapshot that says what it
/// is, never a path the kernel did not see. A pointer the kernel itself could
/// not read is the tracee's invalid argument, not a hole in coverage.
#[test]
fn r6_hostile_path_pointers_never_produce_a_confident_path() {
    let _serial = serial();
    for kind in ["edge", "nonul", "unmapped", "minus1", "null", "long"] {
        let Some(work) = setup(&format!("r6-{kind}")) else {
            return;
        };
        let helper = work.helper_s();
        let base = work.base();
        let mut run = launch(&work, &[&helper, "badpath", kind, &base]);
        let tracer = attach(run.pid, TracerConfig::default());
        run.release();
        let reports = run.lines();
        let observed = collect(tracer, Duration::from_secs(60));
        let fixture = Report::find(&reports, kind);
        let opens = observed.of_op(ClosedOp::Open);
        assert_eq!(opens.len(), 1, "{kind}: exactly one result");
        let TracerEvent::Syscall { ret, args, .. } = opens[0] else {
            unreachable!()
        };
        assert_eq!(
            *ret,
            fixture.ret(),
            "{kind}: the return must be the kernel's"
        );
        let snapshot = args.path.clone();
        match kind {
            "edge" => {
                let snapshot = snapshot.expect("a readable path");
                assert!(snapshot.complete, "{kind}: the whole path was readable");
                assert_eq!(String::from_utf8_lossy(&snapshot.bytes), fixture.path);
            }
            "nonul" | "long" => {
                let snapshot = snapshot.expect("a snapshot");
                assert!(
                    !snapshot.complete,
                    "{kind}: a truncated path declares itself"
                );
                assert!(snapshot.bytes.len() <= 4096);
            }
            "unmapped" | "minus1" => {
                let snapshot = snapshot.expect("a snapshot");
                assert!(!snapshot.complete);
                assert!(snapshot.bytes.is_empty(), "{kind}: {:?}", snapshot.bytes);
                assert_eq!(
                    fixture.errno,
                    libc::EFAULT,
                    "{kind}: the kernel refused it too"
                );
                assert_eq!(
                    observed.summary.argument_invalid, 1,
                    "{kind}: an argument the kernel itself rejected is not lost coverage"
                );
                assert_eq!(
                    observed.summary.loss.total(),
                    0,
                    "{kind}: {:?}",
                    observed.summary.loss
                );
                assert!(
                    !observed.has_gap(GapReason::PathUnreadable),
                    "{kind}: there was no covered operation to miss"
                );
            }
            "null" => assert!(snapshot.is_none(), "{kind}: a null pointer has no snapshot"),
            _ => unreachable!(),
        }
    }
}

/// R7: a `sockaddr` whose declared length lies. Only the family and whether
/// the whole address of that family was readable are kept: the address bytes
/// are read to decide exactly that and dropped, so a `sockaddr_in`
/// announced as 128 bytes cannot pull 112 bytes of unrelated tracee memory
/// into the observer.
#[test]
fn r7_a_lying_sockaddr_length_retains_only_the_family_it_names() {
    let _serial = serial();
    for kind in [
        "lie-long",
        "edge",
        "over-edge",
        "unmapped",
        "zero-len",
        "huge-len",
        "null-ptr",
    ] {
        let Some(work) = setup(&format!("r7-{kind}")) else {
            return;
        };
        let helper = work.helper_s();
        let mut run = launch(&work, &[&helper, "badsock", kind]);
        let tracer = attach(run.pid, TracerConfig::default());
        run.release();
        let reports = run.lines();
        let observed = collect(tracer, Duration::from_secs(60));
        let connects = observed.of_op(ClosedOp::Connect);
        assert_eq!(connects.len(), 1, "{kind}: one connect, one result");
        let TracerEvent::Syscall { ret, args, .. } = connects[0] else {
            unreachable!()
        };
        let fixture = Report::find(&reports, &kind.replace('-', "_"));
        assert_eq!(*ret, fixture.ret(), "{kind}: the kernel's return");
        let sockaddr = args.sockaddr.clone();
        if kind == "null-ptr" {
            assert!(sockaddr.is_none(), "{kind}: a null address has no snapshot");
            continue;
        }
        let sockaddr = sockaddr.expect("a snapshot");
        if kind == "zero-len" {
            // The kernel rejects a length under two; there is no family.
            assert_eq!(sockaddr.family, None, "{kind}");
            assert!(!sockaddr.complete, "{kind}");
            continue;
        }
        if kind == "unmapped" {
            // The family itself is in unreadable memory: named as loss, and
            // the kernel's EFAULT on the same pointer is not.
            assert_eq!(sockaddr.family, None, "{kind}");
            assert!(!sockaddr.complete, "{kind}");
            continue;
        }
        assert_eq!(
            sockaddr.family,
            Some(libc::AF_INET as u16),
            "{kind}: the family is read from the address the caller passed"
        );
        if kind == "lie-long" || kind == "huge-len" {
            assert!(
                sockaddr.complete,
                "{kind}: the whole sockaddr_in was readable despite the lying claim"
            );
        }
    }
}

/// R8: `mknodat` and `truncate` are inside the closed set as of jail-v1 §11.2,
/// and are now named. A call from an ABI the set does not name still is not.
#[test]
fn r8_the_grown_closed_set_names_mknod_and_truncate_but_never_another_abi() {
    let _serial = serial();
    let Some(work) = setup("r8") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "outside", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let paths: Vec<String> = observed.syscalls().iter().map(|e| primary(e)).collect();
    let mknod = Report::find(&reports, "mknodat");
    let truncate = Report::find(&reports, "truncate");
    assert_eq!(mknod.errno, 0, "the fixture's mknodat must succeed");
    assert_eq!(truncate.errno, 0);
    assert!(
        paths.iter().any(|p| p.ends_with("by-mknod")),
        "mknodat is a directory-entry creation and is inside the set: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("by-truncate")),
        "truncate names a pathname and is inside the set: {paths:?}"
    );
    assert_eq!(observed.of_op(ClosedOp::Mknod).len(), 1);
    assert_eq!(observed.of_op(ClosedOp::Truncate).len(), 1);
    assert!(
        !paths.iter().any(|p| p.ends_with("by-int80")),
        "an i386 open is outside the native ABI and must not be named: {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.ends_with("by-x32")),
        "an x32 openat carries a number from another table: {paths:?}"
    );
}

/// R9: `open_how` structures of every awkward size. Every result the observer
/// does deliver carries the kernel's own return, and a size it cannot decode
/// is never delivered as a covered open.
#[test]
fn r9_open_how_sizes_are_decoded_or_declared_unavailable() {
    let _serial = serial();
    let Some(work) = setup("r9") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "openhow", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    for event in observed.of_op(ClosedOp::Open) {
        let TracerEvent::Syscall { args, ret, .. } = event else {
            unreachable!()
        };
        let path = primary(event);
        assert!(
            args.flags.is_some(),
            "a delivered open must have had its flags decoded: {path}"
        );
        if let Some(fixture) = reports.iter().find(|r| r.path == path) {
            assert_eq!(*ret, fixture.ret(), "path {path}");
        }
    }
    // Sizes 0, 8 and 16 are below the structure the kernel defines, so it
    // rejects them and there was no covered operation to classify.
    for label in ["size_0", "size_8", "size_16"] {
        assert_eq!(Report::find(&reports, label).errno, libc::EINVAL, "{label}");
    }
    assert!(
        observed.summary.argument_invalid >= 3,
        "{:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R10: §11.4 budgets bytes, not events. Sixteen thousand two-path renames
/// must not make the observer hold more than the budget.
#[test]
fn r10_the_queue_bound_is_the_four_mib_of_the_spec() {
    let _serial = serial();
    let Some(work) = setup("r10") else { return };
    const N: u64 = 16_000;
    let helper = work.helper_s();
    let base = work.base();
    let n = N.to_string();
    let rss_before = rss_kib();
    let mut run = launch(&work, &[&helper, "bigpaths", &n, &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    // Deliberately do not read the queue while the fixture runs.
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the fixture report");
    let peak = rss_kib();
    let observed = collect(tracer, Duration::from_secs(120));
    let delta_mib = (peak - rss_before) as f64 / 1024.0;
    println!(
        "r10: {N} two-path events queued, supervisor RSS delta {delta_mib:.2} MiB, \
         observer peak {:.2} MiB, dropped {}",
        observed.summary.queue_bytes_peak as f64 / (1024.0 * 1024.0),
        observed.summary.loss.queue_dropped
    );
    assert_eq!(
        observed.summary.ops.rename, N,
        "every call was still observed"
    );
    assert!(
        observed.summary.queue_bytes_peak <= TracerConfig::default().queue_bytes_max,
        "the observer's own accounting must stay inside the budget: {} bytes",
        observed.summary.queue_bytes_peak
    );
    assert!(
        delta_mib < 4.0,
        "jail-v1 §11.4 budgets a 4 MiB user-space event queue; the observer held \
         {delta_mib:.2} MiB"
    );
    assert!(
        observed.summary.loss.queue_dropped > 0,
        "with a byte budget this workload must lose results rather than memory"
    );
}

/// R11: an untraced child that outlives the traced tree — bubblewrap, in the
/// real tree — still has its exit reported. It has exactly one route.
///
/// J5-T: bubblewrap is the launcher's ancestor, and the test now builds it
/// that way: an untraced `sh` is this process's child, the launcher is its
/// child, and the `sh` outlives the traced tree by two seconds before
/// exiting 5. Written first with the untraced child as the launcher's
/// *sibling*, it asserted that the tracer waits for every child the process
/// had when it attached — which is how a process substitution the
/// supervisor inherited from the shell that exec'd it held the observer open
/// and was then counted as lost. A sibling is not the tracer's to wait for
/// (`j5_tracer_foreign_child_linux`); the child it reached the launcher
/// through is, and this pins that exit's route.
#[test]
fn r11_a_late_untraced_child_exit_is_still_reported() {
    let _serial = serial();
    let Some(work) = setup("r11") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let filter = work.filter.to_string_lossy().into_owned();
    // A background job's stdin is `/dev/null` before its own redirections
    // apply, so the release pipe is passed on fd 3.
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        r#"exec 3<&0; "$@" <&3 3<&- & wait $!; sleep 2; exit 5"#,
        "sh",
        &helper,
        "launch",
        &filter,
        &helper,
        "quick",
        &base,
    ]);
    // Never dropped: `Launched` kills its pid by number on drop, and this
    // one is reaped by the tracer, after which the number is anyone's.
    let mut run = std::mem::ManuallyDrop::new(spawn(command));
    let backend = run.pid;
    let launcher = ouro_jail::platform::linux::tracer::children(backend)
        .into_iter()
        .find(|pid| {
            ouro_jail::platform::linux::tracer::cmdline(*pid)
                .is_some_and(|argv| argv.get(1).map(Vec::as_slice) == Some(b"launch".as_slice()))
        })
        .unwrap_or_else(|| panic!("no launcher under the untraced sh {backend}"));
    let tracer = attach(launcher, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));
    println!(
        "r11: untraced exits {:?}, backend state after finish {:?}",
        observed.untraced(),
        proc_state(backend)
    );
    let exit = observed
        .untraced()
        .into_iter()
        .find(|(p, _)| *p == backend)
        .unwrap_or_else(|| {
            panic!(
                "the exit of the untraced child {backend}, which the launcher descends \
                 through, must reach the supervisor, which was told not to wait for its own \
                 children while a tracer is attached: {:?}",
                observed.untraced()
            )
        });
    assert!(
        libc::WIFEXITED(exit.1) && libc::WEXITSTATUS(exit.1) == 5,
        "its own status: {:#x}",
        exit.1
    );
    assert!(
        observed.summary.unreaped_children.is_empty(),
        "{:?}",
        observed.summary.unreaped_children
    );
}

/// R12: `finish` returns even when a tracee is alive and will not die, and
/// says what it had to do about it. `Drop` is the same path, so a panicking
/// consumer cannot be wedged either.
#[test]
fn r12_finish_returns_even_when_a_tracee_will_not_die() {
    let _serial = serial();
    let Some(work) = setup("r12") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "sleep-forever"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let mut line = String::new();
    run.output
        .read_line(&mut line)
        .expect("the sleeping report");
    let pid = run.pid;

    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let started = Instant::now();
    let joiner = std::thread::spawn(move || {
        let summary = tracer.finish_within(Duration::from_millis(300));
        let _ = tx.send(());
        summary
    });
    let returned = rx.recv_timeout(Duration::from_secs(20)).is_ok();
    if !returned {
        // SAFETY: a pid this test created.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let summary = joiner.join().expect("the joining thread");
    println!(
        "r12: finish_within returned after {:?}, abandoned={} unreaped={:?}",
        started.elapsed(),
        summary.loss.abandoned_tracees,
        summary.unreaped_children
    );
    assert!(returned, "finish must always return");
    assert!(
        summary.loss.abandoned_tracees >= 1,
        "a tree that had to be killed is loss, and is counted: {:?}",
        summary.loss
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && std::path::Path::new(&format!("/proc/{pid}")).exists() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "the tracee that would not die must have been killed, not left stopped"
    );
}

/// R13: a consumer that never reads costs one bounded stall, not one per
/// event, and every call is still observed.
#[test]
fn r13_a_stalled_consumer_stalls_the_tree_by_a_bounded_amount() {
    let _serial = serial();
    let Some(work) = setup("r13") else { return };
    const N: u64 = 20_000;
    let helper = work.helper_s();
    let base = work.base();
    let n = N.to_string();
    let untraced_start = Instant::now();
    let status = Command::new(&work.helper)
        .args(["bigpaths", &n, &base])
        .stdout(Stdio::null())
        .status()
        .expect("untraced run");
    let untraced = untraced_start.elapsed();
    assert!(status.success());

    let mut run = launch(&work, &[&helper, "bigpaths", &n, &base]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_max: 8,
            ..TracerConfig::default()
        },
    );
    let started = Instant::now();
    run.release();
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the fixture report");
    let stalled = started.elapsed();
    let observed = collect(tracer, Duration::from_secs(120));
    println!(
        "r13: untraced {untraced:?}; traced with a consumer that never reads {stalled:?}; \
         dropped={} emitted={}",
        observed.summary.loss.queue_dropped, observed.summary.emitted
    );
    assert_eq!(observed.summary.ops.rename, N, "every call still observed");
    assert!(
        stalled < Duration::from_secs(10),
        "a consumer that never reads must cost one bounded stall, not one per event"
    );
}

/// R17: a filter that traces a number outside the closed set. The tracer says
/// the filter is not its own instead of guessing, and does not wedge the
/// tracee.
///
/// Since J4 D1 the tracer tells whose a stop is by its trace data: a stop
/// carrying the narrowing filter's own data on a number it never traces
/// means the installed program is not the observer's, while one with other
/// data was asked for by another filter (a child's own `SECCOMP_RET_TRACE`)
/// and is continued untouched. This filter therefore carries the observer's
/// data, which is the case this test pins; the other is
/// `observer_j4_linux::j4_d1_a_child_trace_request_is_continued_not_mislabelled`.
#[test]
fn r17_a_foreign_filter_is_named_not_guessed() {
    let _serial = serial();
    let Some(work) = setup("r17") else { return };
    let program = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 2,
            k: 0xc000_003e,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 3,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7ff0_0000 | u32::from(ouro_jail::platform::linux::tracer::NARROWING_TRACE_DATA),
        },
    ];
    let foreign = work.path("foreign.bin");
    std::fs::write(&foreign, filter_bytes(&program)).expect("write the foreign filter");
    let helper = work.helper_s();
    let mut command = Command::new(&work.helper);
    command
        .arg("launch")
        .arg(&foreign)
        .args([&helper, "closes", "50"]);
    let mut run = spawn(command);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "closes");
    assert!(
        observed.summary.loss.unexpected_trace_stops >= 50,
        "every stop for a number outside the set is named: {:?}",
        observed.summary.loss
    );
    assert!(observed.has_gap(GapReason::UnexpectedTraceStop));
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 0, "nothing invented");
}

/// R18: `EINPROGRESS` is the raw return the caller saw, not a completed
/// connection.
#[test]
fn r18_einprogress_is_the_raw_return() {
    let _serial = serial();
    let Some(work) = setup("r18") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "inprogress"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));
    let fixture = Report::find(&reports, "inprogress");
    let connects = observed.of_op(ClosedOp::Connect);
    assert_eq!(connects.len(), 1);
    let TracerEvent::Syscall { ret, .. } = connects[0] else {
        unreachable!()
    };
    assert_eq!(*ret, fixture.ret());
    assert_eq!(fixture.errno, libc::EINPROGRESS, "the fixture's own view");
}

/// R19: the two paths of a two-path call are independent evidence, and a
/// pointer the kernel also rejected is the tracee's argument, not lost
/// coverage.
#[test]
fn r19_two_paths_are_independent_evidence() {
    let _serial = serial();
    let Some(work) = setup("r19") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "twopath", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let renames = observed.of_op(ClosedOp::Rename);
    assert_eq!(renames.len(), 2, "\n  {}", observed.describe());
    for (i, event) in renames.iter().enumerate() {
        let TracerEvent::Syscall { args, ret, .. } = event else {
            unreachable!()
        };
        assert_eq!(*ret, reports[i].ret(), "case {i}");
        let (good, bad) = if i == 0 {
            (args.path.clone().unwrap(), args.path2.clone().unwrap())
        } else {
            (args.path2.clone().unwrap(), args.path.clone().unwrap())
        };
        assert!(good.complete, "case {i}: the readable path is complete");
        assert!(!bad.complete, "case {i}: the faulting path is not");
        assert!(bad.bytes.is_empty(), "case {i}: {:?}", bad.bytes);
    }
    assert!(
        observed.summary.argument_invalid >= 2,
        "the kernel rejected both pointers too: {:?}",
        observed.summary
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R20: every task the tracer tracked is accounted for at the end. A thread
/// the kernel destroys as part of another thread's `execve` is never reported
/// by the kernel, so it is counted rather than left unexplained.
#[test]
fn r20_a_non_leader_exec_accounts_for_every_thread() {
    let _serial = serial();
    let Some(work) = setup("r20") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "threads-exec", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    assert_eq!(observed.exits(), vec![(run.pid, 0)], "one process death");
    println!(
        "r20: tracees={} reaped={} destroyed_by_exec={}",
        observed.summary.tracees,
        observed.summary.reaped_tasks,
        observed.summary.tasks_destroyed_by_exec
    );
    assert_eq!(
        observed.summary.tracees,
        observed.summary.reaped_tasks + observed.summary.tasks_destroyed_by_exec,
        "every task the tracer tracked must be accounted for at the end"
    );
    assert!(observed.summary.tasks_destroyed_by_exec >= 1);
}

/// R21: the product's shape — the `tool` enforcement baseline installed
/// first, the observer's narrowing filter second. The baseline denies the ABI
/// the observer cannot name, and the calls the observer does name still work
/// and are still reported.
#[test]
fn r21_the_tool_baseline_denies_the_abi_the_observer_cannot_name() {
    let _serial = serial();
    let Some(work) = setup("r21") else { return };
    let baseline = seccomp::tool_baseline().expect("the tool baseline");
    let path = work.path("baseline.bin");
    std::fs::write(&path, baseline.to_bytes()).expect("write the baseline");
    let helper = work.helper_s();
    let base = work.base();
    let mut command = Command::new(&work.helper);
    command
        .arg("launch2")
        .arg(&path)
        .arg(&work.filter)
        .args([&helper, "abi", &base]);
    let mut run = spawn(command);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let int80 = Report::find(&reports, "int80");
    let native = Report::find(&reports, "native");
    let mknod = Report::find(&reports, "mknodat");
    println!(
        "r21: int80 errno={} native errno={} mknodat errno={}",
        int80.errno, native.errno, mknod.errno
    );
    assert_eq!(
        int80.errno,
        libc::EPERM,
        "the tool baseline must deny the i386 ABI the observer cannot name"
    );
    assert!(
        !std::path::Path::new(&work.path("abi-int80")).exists(),
        "and it must not have created anything"
    );
    assert_eq!(native.errno, 0, "the native call still works");
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 1, "and is observed");
    assert_eq!(mknod.errno, 0, "mknodat is not denied by the tool baseline");
    assert_eq!(
        observed.of_op(ClosedOp::Mknod).len(),
        1,
        "so the closed set is what must name it: {}",
        observed.describe()
    );
}

/// R22: a read-only open costs one stop and produces no event.
#[test]
fn r22_a_read_only_open_costs_one_stop_and_no_event() {
    let _serial = serial();
    let Some(work) = setup("r22") else { return };
    const N: u64 = 5000;
    let target = work.path("readable");
    std::fs::write(&target, b"x").expect("create the file");
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(&work, &[&helper, "rdonly", &n, &target]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(180));

    assert_eq!(Report::find(&reports, "rdonly").raw, N as i64);
    assert_eq!(observed.of_op(ClosedOp::Open).len(), 0, "no event");
    assert_eq!(observed.summary.ops.total(), 0);
    assert!(observed.summary.filtered_readonly_opens >= N);
    assert!(
        observed.summary.stops < 2 * N,
        "a read-only open must cost the seccomp stop only: {} stops for {N} opens",
        observed.summary.stops
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R23: `Fork.parent` is the thread group, so a consumer can join it with
/// every other event's `pid`, and the forking thread is named separately.
#[test]
fn r23_fork_names_the_thread_group_and_the_thread_that_forked() {
    let _serial = serial();
    let Some(work) = setup("r23") else { return };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "worker-fork", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let leader = Report::find(&reports, "leader_pid").raw as libc::pid_t;
    let worker = Report::find(&reports, "worker_tid").raw as libc::pid_t;
    let child = Report::find(&reports, "child_pid").raw as libc::pid_t;
    assert_ne!(
        worker, leader,
        "the fork really was made by a worker thread"
    );
    let event = observed
        .events
        .iter()
        .find_map(|e| match e {
            TracerEvent::Fork {
                parent,
                parent_tid,
                child: c,
                is_thread,
                child_start_ticks,
                ..
            } if *c == child => Some((*parent, *parent_tid, *is_thread, *child_start_ticks)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no Fork for {child}: {:?}", observed.forks()));
    let (parent, parent_tid, is_thread, start_ticks) = event;
    assert_eq!(
        parent, leader,
        "Fork.parent is the thread group, like every other pid"
    );
    assert_eq!(
        parent_tid, worker,
        "and the forking thread is named on its own"
    );
    assert!(!is_thread, "a fork child is a process, not a thread");
    assert!(
        start_ticks.is_some(),
        "a birth identity tells recycled pids apart"
    );
    // The thread the worker-fork fixture created is reported as a thread.
    let threads: Vec<bool> = observed
        .events
        .iter()
        .filter_map(|e| match e {
            TracerEvent::Fork { is_thread, .. } => Some(*is_thread),
            _ => None,
        })
        .collect();
    assert!(
        threads.contains(&true),
        "the pthread_create is a thread clone: {threads:?}"
    );
}

/// R24: when the queue drops results, the consumer still receives the
/// lifecycle facts, and the gap names the classes it cost.
#[test]
fn r24_a_queue_gap_names_what_it_lost_and_never_swallows_the_exit() {
    let _serial = serial();
    let Some(work) = setup("r24") else { return };
    let helper = work.helper_s();
    let a = work.path("a");
    let b = work.path("b");
    let mut run = launch(&work, &[&helper, "two-threads", "500", &a, &b]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_max: 1,
            ..TracerConfig::default()
        },
    );
    run.release();
    let _ = run.lines();
    std::thread::sleep(Duration::from_millis(1500));
    let observed = collect(tracer, Duration::from_secs(60));

    println!(
        "r24: dropped={} observed={} delivered={} exits={:?} gaps={:?}",
        observed.summary.loss.queue_dropped,
        observed.summary.ops.total(),
        observed.of_op(ClosedOp::Open).len(),
        observed.exits(),
        observed.gaps()
    );
    assert!(
        observed.summary.loss.queue_dropped > 0,
        "the queue must overflow"
    );
    assert_eq!(
        observed.exits().len(),
        1,
        "a supervisor must never lose the exit status it exists to report"
    );
    let queue_gaps: Vec<(GapReason, OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::QueueFull)
        .collect();
    assert!(!queue_gaps.is_empty(), "the loss must be reported as a gap");
    for (_, ops, count) in &queue_gaps {
        assert!(
            count.is_some(),
            "the count of dropped events is known exactly"
        );
        assert!(
            ops.contains(ClosedOp::Open),
            "jail-v1 §11.4: a gap names the affected classes, and these were opens"
        );
    }
    let counted: u64 = queue_gaps.iter().filter_map(|(_, _, c)| *c).sum();
    assert_eq!(counted, observed.summary.loss.queue_dropped);
    assert!(
        observed
            .events
            .iter()
            .any(|e| matches!(e, TracerEvent::Finished))
    );
}

/// R25: `args.path` is the directory entry the call creates on every row,
/// including `symlink`, whose target is an opaque string the kernel stores
/// without resolving it.
#[test]
fn r25_symlink_reports_the_link_it_creates_as_its_primary_path() {
    let _serial = serial();
    let Some(work) = setup("r25") else { return };
    let helper = work.helper_s();
    let base = work.base();
    let mut run = launch(&work, &[&helper, "symlink", &base]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let fixture = Report::find(&reports, "symlink");
    assert_eq!(fixture.errno, 0);
    let events = observed.of_op(ClosedOp::Symlink);
    assert_eq!(events.len(), 1);
    let TracerEvent::Syscall { args, .. } = events[0] else {
        unreachable!()
    };
    let path = String::from_utf8_lossy(&args.path.as_ref().expect("a link").bytes).into_owned();
    let target =
        String::from_utf8_lossy(&args.path2.as_ref().expect("a target").bytes).into_owned();
    assert!(
        path.ends_with("/the-link"),
        "args.path is the entry the call creates, as on every other row: {path}"
    );
    assert_eq!(
        target, "THE-TARGET",
        "and the string the kernel stores without resolving is args.path2"
    );
    assert_eq!(
        args.dirfd2, None,
        "a stored string is resolved against nothing"
    );
}

/// R26: a tracee cannot decide how much loss the observer records. Five
/// thousand calls with a pointer the kernel itself rejects are five thousand
/// invalid arguments, not five thousand holes in coverage — which under
/// strict evidence would let an untrusted child stop its own attempt.
#[test]
fn r26_a_tracee_cannot_manufacture_the_observers_loss() {
    let _serial = serial();
    let Some(work) = setup("r26") else { return };
    const N: u64 = 5000;
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(&work, &[&helper, "unreadable", &n]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(180));

    assert_eq!(Report::find(&reports, "unreadable").raw, N as i64);
    assert_eq!(
        observed.summary.argument_invalid, N,
        "each call had an argument the kernel rejected too"
    );
    assert_eq!(
        observed.summary.loss.path_unreadable, 0,
        "none of it is the observer's coverage"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "and none of it may stop a strict-evidence attempt: {:?}",
        observed.summary.loss
    );
    assert_eq!(
        observed.summary.ops.open, N,
        "every result is still reported"
    );
}

/// R27: a seccomp stop whose `nr` belongs to another architecture's table is
/// never labelled from this one. i386 42 is `pipe`; x86_64 42 is `connect`.
///
/// Since J4 D2 such a stop is labelled foreign (`foreign_abi`), not
/// `unexpected_trace_stop`: the narrowing filter itself now stops on every
/// foreign call, so the stop is expected and the gap says what it is.
#[test]
fn r27_a_foreign_architecture_stop_is_never_labelled_from_the_x86_64_table() {
    let _serial = serial();
    let Some(work) = setup("r27") else { return };
    let program = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 42,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7ff0_0000,
        },
    ];
    let blind = work.path("archblind.bin");
    std::fs::write(&blind, filter_bytes(&program)).expect("write the filter");
    let helper = work.helper_s();
    let mut command = Command::new(&work.helper);
    command
        .arg("launch")
        .arg(&blind)
        .args([&helper, "i386-pipe"]);
    let mut run = spawn(command);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "i386_pipe");
    assert_eq!(
        observed.of_op(ClosedOp::Connect).len(),
        0,
        "an i386 `pipe` must never be reported as an x86_64 `connect`:\n  {}",
        observed.describe()
    );
    assert!(
        observed.summary.loss.foreign_abi >= 1,
        "the stop from another architecture must be a named gap: {:?}",
        observed.summary.loss
    );
    assert!(observed.has_gap(GapReason::ForeignAbi));
    assert_eq!(
        observed.summary.loss.unexpected_trace_stops, 0,
        "and it is labelled foreign, not as a filter that is not the observer's"
    );
}

/// R28: two threads of one process making concurrent covered calls. Each
/// result carries the path its own thread asked for, which is what the
/// per-thread pairing key is for.
#[test]
fn r28_concurrent_threads_pair_their_own_entries_and_exits() {
    let _serial = serial();
    let Some(work) = setup("r28") else { return };
    const N: u64 = 2000;
    let leader_path = work.path("by-leader");
    let worker_path = work.path("by-worker");
    let helper = work.helper_s();
    let n = N.to_string();
    let mut run = launch(
        &work,
        &[&helper, "two-threads", &n, &leader_path, &worker_path],
    );
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let _ = run.lines();
    let observed = collect(tracer, Duration::from_secs(300));

    let mut by_tid: std::collections::BTreeMap<
        libc::pid_t,
        std::collections::BTreeMap<String, u64>,
    > = std::collections::BTreeMap::new();
    for event in observed.of_op(ClosedOp::Open) {
        if let TracerEvent::Syscall { tid, .. } = event {
            *by_tid
                .entry(*tid)
                .or_default()
                .entry(primary(event))
                .or_default() += 1;
        }
    }
    assert_eq!(
        observed.summary.ops.open,
        2 * N,
        "both threads' calls are results"
    );
    assert_eq!(
        by_tid.len(),
        2,
        "exactly two threads made covered calls: {by_tid:?}"
    );
    for (tid, paths) in &by_tid {
        assert_eq!(
            paths.len(),
            1,
            "thread {tid} made calls on one pathname only, so its results must all \
             carry that pathname: {paths:?}"
        );
        assert_eq!(*paths.values().next().expect("one path"), N, "thread {tid}");
    }
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// R29: `PTRACE_O_EXITKILL`. A supervisor that dies must take its traced tree
/// with it; a mutation that dropped the option survived until this test.
#[test]
fn r29_a_dead_supervisor_kills_its_traced_tree() {
    let _serial = serial();
    if build().is_err() {
        skip("r29: the fixture could not be built");
        return;
    }
    let dir = std::env::temp_dir().join(format!("ouro-j1-r29-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the work directory");
    let pid_file = dir.join("pid");
    let exe = std::env::current_exe().expect("the test binary");
    let status = Command::new(&exe)
        .args([
            "--exact",
            "--ignored",
            "--nocapture",
            "exitkill_child_supervisor",
        ])
        .env("OURO_REGRESS_EXITKILL", &pid_file)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("run the child supervisor");
    assert!(status.success(), "the child supervisor: {status:?}");
    let raw = std::fs::read_to_string(&pid_file).expect("the child wrote the tracee pid");
    let tracee: libc::pid_t = raw.trim().parse().expect("a pid");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut alive = true;
    while Instant::now() < deadline {
        if !std::path::Path::new(&format!("/proc/{tracee}")).exists() {
            alive = false;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if alive {
        // SAFETY: a pid this test's child created.
        unsafe { libc::kill(tracee, libc::SIGKILL) };
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !alive,
        "the supervisor died and its tracee {tracee} is still running: \
         PTRACE_O_EXITKILL is what makes a dead supervisor take the tree with it"
    );
}

/// The child half of `r29`: a supervisor that dies without cleaning up.
#[test]
#[ignore]
fn exitkill_child_supervisor() {
    let _serial = serial();
    let Some(pid_file) = std::env::var_os("OURO_REGRESS_EXITKILL") else {
        return;
    };
    let Some(work) = setup("r29-child") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "sleep-forever"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let mut line = String::new();
    run.output.read_line(&mut line).expect("the sleeping line");
    std::fs::write(&pid_file, format!("{}", run.pid)).expect("write the pid");
    std::mem::forget(tracer);
    std::mem::forget(run);
    std::mem::forget(work);
    // SAFETY: `_exit` ends the process without running any destructor, which
    // is the point: this half is a supervisor that dies.
    unsafe { libc::_exit(0) };
}

/// R30: repeated attach and finish cycles leave no thread, no descriptor and
/// no zombie behind.
#[test]
fn r30_repeated_attach_and_finish_leaks_nothing() {
    let _serial = serial();
    let Ok((helper, filter)) = build() else {
        skip("r30: the fixture could not be built");
        return;
    };
    let dir = std::env::temp_dir().join(format!("ouro-j1-r30-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the work directory");

    let count = |path: &str| std::fs::read_dir(path).map(Iterator::count).unwrap_or(0);
    let mut baseline = (0usize, 0usize);
    for round in 0..21u32 {
        if round == 1 {
            std::thread::sleep(Duration::from_millis(100));
            baseline = (count("/proc/self/task"), count("/proc/self/fd"));
            println!(
                "r30: baseline after warm-up threads={} fds={}",
                baseline.0, baseline.1
            );
        }
        let target = dir.join(format!("t{round}"));
        let mut child = Command::new(helper)
            .arg("launch")
            .arg(filter)
            .arg(helper)
            .arg("quick")
            .arg(&target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn");
        let pid = child.id() as libc::pid_t;
        let mut release = child.stdin.take().expect("stdin");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        drop(child);
        let mut ready = String::new();
        out.read_line(&mut ready)
            .expect("the launcher announces itself");
        assert!(
            ready.starts_with("ready"),
            "unexpected first line {ready:?}"
        );
        let tracer = attach(pid, TracerConfig::default());
        release.write_all(b"g").expect("release");
        release.flush().expect("flush");
        let mut line = String::new();
        let _ = out.read_line(&mut line);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut saw_exit = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tracer.events().recv_timeout(left) {
                Ok(TracerEvent::Finished) => break,
                Ok(TracerEvent::Exit { .. }) => saw_exit = true,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let summary = tracer.finish();
        assert!(saw_exit, "round {round}: no Exit");
        assert_eq!(summary.loss.total(), 0, "round {round}: {:?}", summary.loss);
        drop(release);
        drop(out);
    }
    std::thread::sleep(Duration::from_millis(200));
    let threads = count("/proc/self/task");
    let fds = count("/proc/self/fd");
    let zombies = zombies();
    println!("r30: after 20 more cycles threads={threads} fds={fds} zombies={zombies:?}");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        threads <= baseline.0,
        "the tracer thread of each cycle must be joined: {threads} threads, baseline {}",
        baseline.0
    );
    assert!(
        fds <= baseline.1,
        "{fds} descriptors, baseline {}",
        baseline.1
    );
    assert!(zombies.is_empty(), "zombies left behind: {zombies:?}");
}

fn zombies() -> Vec<libc::pid_t> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return out;
    };
    for task in tasks.flatten() {
        let Ok(raw) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for field in raw.split_whitespace() {
            let Ok(pid) = field.parse::<libc::pid_t>() else {
                continue;
            };
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            if status
                .lines()
                .any(|l| l.starts_with("State:") && l.contains('Z'))
            {
                out.push(pid);
            }
        }
    }
    out
}

/// R31: an entry destroyed by another thread's `execve` is reported as loss
/// that names the operation it would have reported, never as bookkeeping. A
/// consumer gates §11.4 strict mode and class degradation on the gap's op
/// set, so an entry the tracer holds in hand must name the classes it would
/// have changed.
///
/// The same run pins the §11.4 gap time base: the tracer was given the
/// supervisor's start reading as its epoch, so every gap endpoint must be an
/// age since that start — bounded by how long ago the test itself began —
/// and not an instant on the boot clock.
#[test]
fn r31_an_entry_destroyed_by_an_exec_names_its_operation() {
    let _serial = serial();
    let Some(work) = setup("r31") else { return };
    let fifo = work.path("f");
    mkfifo(&fifo);
    let helper = work.helper_s();
    // The supervisor-start reading. Gap endpoints must be elapsed since it.
    let epoch = clock::boottime_ns();
    let mut run = launch(&work, &[&helper, "exec-over-inflight", &fifo, "/bin/true"]);
    let tracer = attach(
        run.pid,
        TracerConfig {
            epoch_boottime_ns: epoch,
            ..TracerConfig::default()
        },
    );
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    Report::find(&reports, "leader");
    let abandoned: Vec<(OpSet, Option<u64>)> = observed
        .gaps()
        .into_iter()
        .filter(|(reason, _, _)| *reason == GapReason::EntryAbandoned)
        .map(|(_, ops, count)| (ops, count))
        .collect();
    assert!(
        !abandoned.is_empty(),
        "the entry that was mid-syscall when the exec destroyed its thread is \
         loss and must be reported:\n  {}",
        observed.describe()
    );
    for (ops, _) in &abandoned {
        assert!(
            !ops.is_empty(),
            "jail-v1 §11.4: a gap over an entry that is in hand must name the \
             classes it affected, not report bookkeeping: {abandoned:?}"
        );
        assert!(
            ops.contains(ClosedOp::Open),
            "the destroyed entry was an openat on a FIFO, so the gap must name \
             the fs class: {abandoned:?}"
        );
    }
    assert!(
        observed.summary.loss.abandoned_entries >= 1,
        "{:?}",
        observed.summary.loss
    );
    // The tree still ends properly: the exec survives as /bin/true and the
    // supervisor receives its exit.
    assert_eq!(
        observed.exits(),
        vec![(run.pid, 0)],
        "{:?}",
        observed.exits()
    );
    // Every gap endpoint is an age since the epoch: at most the time this
    // test has itself been running, and never a boot-clock instant.
    let elapsed = clock::boottime_ns().saturating_sub(epoch);
    for event in &observed.events {
        if let TracerEvent::Gap { from_ns, to_ns, .. } = event {
            assert!(from_ns <= to_ns, "a gap bounds itself: {from_ns} > {to_ns}");
            assert!(
                *to_ns <= elapsed,
                "gap endpoints are elapsed since the supervisor start, but {to_ns} \
                 exceeds the {elapsed} ns this test has been running"
            );
        }
    }
}

// ====================================================== J4 N8: dead modes

/// J4 N8, `execveat`: the fixture mode that exercises both results of the
/// row was defined and never run. A failed `execveat` is a result with its
/// errno and its pathname; a successful one through `AT_EMPTY_PATH` is the
/// confirmed transition, carrying the descriptor it resolved against and the
/// empty pathname it was given — never a path the observer did not see.
#[test]
fn j4_n8_execveat_failure_and_success_are_distinct_events() {
    let _serial = serial();
    let Some(work) = setup("n8-execveat") else {
        return;
    };
    let helper = work.helper_s();
    let missing = work.path("absent-program");
    let mut run = launch(&work, &[&helper, "execveat", "/bin/true", &missing]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));
    let failed = Report::find(&reports, "execveat_fail");
    assert_eq!(failed.errno, libc::ENOENT, "{reports:?}");
    assert!(
        reports.iter().all(|r| r.label != "execveat_ok"),
        "the second execveat must replace the image: {reports:?}"
    );
    let results: Vec<(String, i64, &'static str)> = observed
        .of_op(ClosedOp::Exec)
        .into_iter()
        .filter_map(|e| match e {
            TracerEvent::Syscall { syscall, ret, .. } => Some((primary(e), *ret, *syscall)),
            _ => None,
        })
        .collect();
    assert_eq!(
        results,
        vec![(missing.clone(), failed.ret(), "execveat")],
        "one failed-exec result, and nothing for the one that succeeded:\n  {}",
        observed.describe()
    );
    type Transition = (libc::pid_t, Option<(Vec<u8>, bool)>, Option<i32>);
    let transitions: Vec<Transition> = observed
        .events
        .iter()
        .filter_map(|e| match e {
            TracerEvent::Exec {
                pid, path, dirfd, ..
            } => Some((
                *pid,
                path.as_ref().map(|p| (p.bytes.clone(), p.complete)),
                *dirfd,
            )),
            _ => None,
        })
        .collect();
    assert_eq!(transitions.len(), 2, "{}", observed.describe());
    let (pid, path, dirfd) = &transitions[1];
    assert_eq!(*pid, run.pid);
    assert_eq!(
        path.as_ref(),
        Some(&(Vec::new(), true)),
        "the snapshot is the empty pathname AT_EMPTY_PATH passed, complete"
    );
    assert!(
        dirfd.is_some_and(|fd| fd >= 0),
        "the transition names the descriptor it resolved against: {dirfd:?}"
    );
    assert_eq!(observed.exits(), vec![(run.pid, 0)], "/bin/true exited 0");
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// J4 N8, `vfork` and `posix_spawn`: the mode was defined and never run.
/// Both children are born through the vfork path (glibc's `posix_spawn`
/// uses `clone(CLONE_VM|CLONE_VFORK)`, after `clone3` where the kernel and
/// the filters allow it), exec, and exit. Each is attributed to its own
/// pid, as the fixture reported it, with its own confirmed exec and exit;
/// the parent keeps its own.
#[test]
fn j4_n8_vfork_and_posix_spawn_children_keep_their_attribution() {
    let _serial = serial();
    let Some(work) = setup("n8-vfork") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "vfork", "/bin/true"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(30));
    let vforked = Report::find(&reports, "vfork_child").raw as libc::pid_t;
    let spawned = Report::find(&reports, "spawn_child").raw as libc::pid_t;
    assert!(vforked > 0 && spawned > 0, "{reports:?}");
    assert_ne!(vforked, spawned);
    let forks = observed.forks();
    for child in [vforked, spawned] {
        assert!(
            forks.contains(&(run.pid, child)),
            "child {child} must be tracked from its birth: {forks:?}"
        );
    }
    let mut execs = observed.execs();
    execs.sort_unstable();
    let mut want = vec![run.pid, vforked, spawned];
    want.sort_unstable();
    assert_eq!(execs, want, "{}", observed.describe());
    let mut exits = observed.exits();
    exits.sort_unstable();
    let mut want: Vec<(libc::pid_t, i32)> = vec![(run.pid, 0), (vforked, 0), (spawned, 0)];
    want.sort_unstable();
    assert_eq!(exits, want, "{}", observed.describe());
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}
