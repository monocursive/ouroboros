/* The loss suite's fixture (j4_loss_linux.rs): target modes that lose a
   covered call the way R04, O03 and O05 need, the tracer-seam modes, and a
   ptrace wrapper that runs the jail traced already. Every mode but `launch`
   and the wrappers prints the lines of common.h. */
#include "common.h"

#include <arpa/inet.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

static void on_signal(int sig) { (void) sig; }

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

/* Wait until the kernel says the thread is asleep inside openat: past the
   observer's stop at its entry (common.h, asleep_in). */
static int await_parked(struct parked *p) {
    return await_asleep_in(p->stat_fd, p->syscall_fd, SYS_openat);
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
    report_line("parked", r, 0, fifo, "");
    if (r) _exit(125);
    args[0] = (char *) self;
    args[1] = "exit0";
    args[2] = NULL;
    execv(self, args);
    report_line("execv", -1, errno, self, "");
    _exit(126);
}

static int lose_one_open(const char *fifo, const char *self) {
    int status = -1;
    pid_t kid = fork();
    if (kid == 0) lose_by_exec(fifo, self);
    if (kid < 0) { report_line("fork", -1, errno, "", ""); return -1; }
    waitpid(kid, &status, 0);
    report_line("child", status, 0, "", "");
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
        report_line("connect", r, err, "", "");
    }
    memset(&p, 0, sizeof p);
    p.fifo = argv[2];
    rr = park(&p, &t);
    report_line("parked", rr, 0, p.fifo, "");
    if (rr) return 3;
    args[0] = argv[3];
    args[1] = "sleep";
    args[2] = argv[5];
    args[3] = NULL;
    execv(argv[3], args);
    report_line("execv", -1, errno, argv[3], "");
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
        report_line("parked", -1, errno, argv[2], "");
        return 4;
    }
    report_line("parked", 0, 0, argv[2], "");
    return 0;
}

/* sleep MS: report, sleep, report, exit 0. */
static int mode_sleep(int argc, char **argv) {
    if (argc < 3) return 2;
    report_line("sleeping", 0, 0, "", "");
    sleep_ms(atol(argv[2]));
    report_line("done", 0, 0, "", "");
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
        if (native_mkdir(d, 0700) == 0) made++;
        if (native_rmdir(d) == 0) made++;
        r = syscall(SYS_openat, AT_FDCWD, f, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (r >= 0) { made++; close((int) r); }
        if (native_unlink(f) == 0) made++;
    }
    report_line("results", made, 0, "", "");
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
    report_line("parked", rr, 0, p.fifo, "");
    if (rr) return 3;
#define OP(label, call, path) do { r = (call); report(label, r, path, ""); } while (0)
    OP("mkdir", native_mkdir(a, 0700), a);
    OP("mkdirat", syscall(SYS_mkdirat, AT_FDCWD, b, 0700), b);
    OP("rename", native_rename(a, a2), a2);
    OP("renameat", syscall(SYS_renameat, AT_FDCWD, b, AT_FDCWD, b2), b2);
    OP("renameat2", syscall(SYS_renameat2, AT_FDCWD, a2, AT_FDCWD, a3, 0), a3);
    OP("rmdir", native_rmdir(a3), a3);
    OP("unlinkat_dir", syscall(SYS_unlinkat, AT_FDCWD, b2, AT_REMOVEDIR), b2);
    OP("creat", native_creat(f, 0600), f);
    if (r >= 0) close((int) r);
    OP("open", native_open(g, O_WRONLY | O_CREAT | O_CLOEXEC, 0600), g);
    if (r >= 0) close((int) r);
    OP("openat", syscall(SYS_openat, AT_FDCWD, h, O_WRONLY | O_CREAT | O_CLOEXEC, 0600), h);
    if (r >= 0) close((int) r);
    memset(&how, 0, sizeof how);
    how.flags = O_WRONLY | O_CREAT | O_CLOEXEC;
    how.mode = 0600;
    OP("openat2", syscall(SYS_openat2, AT_FDCWD, o2, &how, sizeof how), o2);
    if (r >= 0) close((int) r);
    OP("truncate", syscall(SYS_truncate, f, 0), f);
    OP("link", native_link(f, l1), l1);
    OP("linkat", syscall(SYS_linkat, AT_FDCWD, f, AT_FDCWD, l2, 0), l2);
    OP("symlink", native_symlink("f", s1), s1);
    OP("symlinkat", syscall(SYS_symlinkat, "f", AT_FDCWD, s2), s2);
    OP("mknod", native_mknod(p1, S_IFIFO | 0600, 0), p1);
    OP("mknodat", syscall(SYS_mknodat, AT_FDCWD, p2, S_IFIFO | 0600, 0), p2);
    OP("unlink", native_unlink(l1), l1);
    OP("unlinkat", syscall(SYS_unlinkat, AT_FDCWD, l2, 0), l2);
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report_line("released", p.result, p.err, p.fifo, "");
    OP("after_mkdir", native_mkdir(after, 0700), after);
    r = connect_loopback(&err);
    report_line("connect", r, err, "", "");
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
    r = native_mkdir(q, 0700);
    report("mkdir", r, q, "");
    r = connect_loopback(&err);
    report_line("connect", r, err, "", "");
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
    if (s < 0) { report_line("udp_socket", -1, errno, label, ""); return -1; }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(9);
    inet_pton(AF_INET, addr, &a.sin_addr);
    r = connect(s, (struct sockaddr *) &a, sizeof a);
    report(label, r, addr, "");
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
        report_line("unix_socket", -1, errno, u.sun_path, "");
    } else if (bind(l, (struct sockaddr *) &u, sizeof u) || listen(l, 4)) {
        report_line("unix_bind", -1, errno, u.sun_path, "");
    } else {
        chmod(u.sun_path, 0);
        c = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c < 0) {
            report_line("unix_socket", -1, errno, u.sun_path, "");
        } else {
            r = connect(c, (struct sockaddr *) &u, sizeof u);
            report("unix_connect", r, u.sun_path, "");
            close(c);
        }
    }
    udp_broadcast("udp_connect", "127.255.255.255");
    udp_broadcast("udp_connect", "255.255.255.255");
    r = connect_loopback(&err);
    report_line("connect", r, err, "", "");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tracer-seam modes (`launch` is common.h's)                           */
/* ------------------------------------------------------------------ */

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
    report_line("thread_execv", -1, errno, e->self, "");
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
        native_mkdir(m, 0700);
        native_rmdir(m);
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
    report_line("parked", park(&p, &t), 0, "", "");
    pthread_kill(t, SIGUSR1);
    while (!__atomic_load_n(&restarted, __ATOMIC_ACQUIRE)) usleep(100);
    report_line("reparked", await_parked(&p), 0, "", "");
    pthread_kill(t, SIGUSR2);
    pthread_join(t, NULL);
    report_line("interrupted", p.result, p.err, "", "");

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
    report_line("non_leader_exec", status, 0, "", "");

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
    report_line("vfork_exec", status, 0, "", "");
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
    report_line("parked", park(&p, &t), 0, "", "");
    for (i = 0; i < 10; i++) {
        native_mkdir(m, 0700);
        native_rmdir(m);
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) close((int) r);
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) close((int) r);
        syscall(SYS_getpid);
    }
    pthread_kill(t, SIGUSR2);
    pthread_join(t, NULL);
    report_line("interrupted", p.result, p.err, "", "");
    r = native_mkdir(m, 0700);
    report("after", r, m, "");
    return 0;
}

/* ------------------------------------------------------------------ */
/* A ptrace wrapper around ukai-jail                                    */
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

/* dupenv PROG ARGS...: exec PROG with this environment plus two entries of
   the in-flight seam, "1" first and "16384" second: which one the jail
   applies and which one it records. */
extern char **environ;
static int mode_dupenv(int argc, char **argv) {
    static char *envp[4096];
    int n = 0, i;
    if (argc < 3) return 2;
    for (i = 0; environ[i] && n < 4090; i++) envp[n++] = environ[i];
    envp[n++] = "UKAI_JAIL_TEST_TRACER_INFLIGHT=1";
    envp[n++] = "UKAI_JAIL_TEST_TRACER_INFLIGHT=16384";
    envp[n] = NULL;
    execve(argv[2], &argv[2], envp);
    report_line("dupenv_execve", -1, errno, argv[2], "");
    return 127;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "dupenv")) return mode_dupenv(argc, argv);
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
