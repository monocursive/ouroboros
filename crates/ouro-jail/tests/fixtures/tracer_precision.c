/* The tracer-precision suite's fixture (j4_tracer_precision_linux.rs): a
   thread parked inside a covered call and interrupted every way the kernel
   allows, the in-flight bound against calls outside the closed set, a group
   exit racing entry stops, and the non-leader exec, listener and queue-budget
   cases. `launch` is common.h's; every other mode prints its lines. */
#include "common.h"

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <ucontext.h>

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
        p->after_result = native_mkdir(p->after, 0700);
        p->after_err = p->after_result < 0 ? errno : 0;
    }
    return NULL;
}

static long parked_nr(struct parked *p) {
    return p->kind == K_OPEN ? SYS_openat : SYS_connect;
}

/* Whether the kernel says the thread is asleep inside its call (common.h,
   asleep_in). */
static int is_parked(struct parked *p) {
    return asleep_in(p->stat_fd, p->syscall_fd, parked_nr(p));
}

static int await_parked(struct parked *p) {
    return await_asleep_in(p->stat_fd, p->syscall_fd, parked_nr(p));
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
    native_mkdir(g_hpath, 0700);
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
#ifdef __aarch64__
    if (uc->uc_mcontext.regs[8] == (unsigned long)g_rewrite_nr) {
        uc->uc_mcontext.regs[0] = -EINTR;
        uc->uc_mcontext.pc += 4;
        g_rewrote++;
    }
#else
    if (uc->uc_mcontext.gregs[REG_RAX] == g_rewrite_nr) {
        uc->uc_mcontext.gregs[REG_RAX] = -EINTR;
        uc->uc_mcontext.gregs[REG_RIP] += 2;
        g_rewrote++;
    }
#endif
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
    /* Static: the handler reads hpath through g_hpath. */
    static char hpath[4096], apath[4096];
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
        report_line("listener", rr, errno, "", "");
        return 3;
    }
    if (!strcmp(how, "eintr") || !strcmp(how, "twice")) {
        set_action(SIGUSR1, on_sig, 0);
    } else if (!strcmp(how, "siginfo-alt")) {
        struct sigaction sa;
        ss.ss_sp = malloc(1 << 16);
        ss.ss_size = 1 << 16;
        ss.ss_flags = 0;
        if (!ss.ss_sp || sigaltstack(&ss, NULL)) { report_line("altstack", -1, errno, "", ""); return 3; }
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
    report_line("parked", rr, 0, p.path, "");
    if (rr) return 3;
    before = switches(&p);
    if (!strcmp(how, "twice")) {
        pthread_kill(t, SIGHUP);
        rr = await_reparked(&p, before);
        report_line("reparked", rr, 0, p.path, "");
        if (rr) return 3;
        pthread_kill(t, SIGUSR1);
    } else if (!strcmp(how, "default")) {
        pthread_kill(t, SIGWINCH);
    } else if (!strcmp(how, "fatal")) {
        pthread_kill(t, SIGTERM);
        sleep_ms(10000);
        report_line("survived", 0, 0, "", "");
        return 5;
    } else {
        pthread_kill(t, SIGUSR1);
    }
    if (restarts) {
        rr = await_reparked(&p, before);
        report_line("reparked", rr, 0, p.path, "");
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
    report_line("call", p.result, p.err, p.path, "");
    report_line("handled", (long) g_hits, 0, "", "");
    report_line("handler_mkdir", access(hpath, F_OK) == 0, 0, hpath, "");
    report_line("rewrote", (long) g_rewrote, 0, "", "");
    if (p.after) report_line("after", p.after_result, p.after_err, apath, "");
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
    report_line("parked", r, 0, p.path, "");
    if (r) return 3;
    for (i = 0; i < n; i++) {
        if (native_mkdir(m, 0700) == 0) covered++;
        if (native_rmdir(m) == 0) covered++;
        r = syscall(SYS_openat, AT_FDCWD, "/proc/self/stat", O_RDONLY | O_CLOEXEC);
        if (r >= 0) { reads++; close((int) r); }
        r = native_open("/proc/self/stat", O_RDONLY | O_CLOEXEC, 0);
        if (r >= 0) { reads++; close((int) r); }
    }
    report_line("covered", covered, 0, m, "");
    report_line("reads", reads, 0, "", "");
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report_line("released", p.result, p.err, p.path, "");
    r = native_mkdir(after, 0700);
    report("after", r, after, "");
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
        native_mkdir(d, 0700);
        native_rmdir(d);
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
/* A non-leader exec, a listener of the child's own, the queue budget    */
/* ------------------------------------------------------------------ */

/* The main (leader) thread, whose /proc files are open on these. */
struct leader { const char *self; int stat_fd, syscall_fd; };

static int leader_parked(struct leader *a) {
    return asleep_in(a->stat_fd, a->syscall_fd, SYS_openat);
}

static void *exec_when_leader_parked(void *arg) {
    struct leader *a = arg;
    char *args[3];
    await_asleep_in(a->stat_fd, a->syscall_fd, SYS_openat);
    report_line("leader_parked", leader_parked(a), 0, "", "");
    args[0] = (char *) a->self;
    args[1] = "exit0";
    args[2] = NULL;
    execv(a->self, args);
    report_line("thread_execv", -1, errno, a->self, "");
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
    report("leader_open_returned", r, argv[2], "");
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
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_MKDIR_NR, 0, 1),
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
    report_line("parked", r, 0, p.path, "");
    if (r) return 3;
    if (!strcmp(argv[4], "listener")) {
        g_listener = (int) syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                   SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
        report("listener", g_listener, "", "");
        if (g_listener < 0) return 3;
        pthread_create(&s, NULL, serve_continue, NULL);
        snprintf(path, sizeof path, "%s/hidden1", argv[3]);
        r = native_mkdir(path, 0700);
        report("hidden1", r, path, "");
    } else if (!strcmp(argv[4], "untraced")) {
        int status = 0;
        long child = syscall(SYS_clone, CLONE_UNTRACED | SIGCHLD, 0, 0, 0, 0);
        if (child == 0) {
            snprintf(path, sizeof path, "%s/untraced", argv[3]);
            r = native_mkdir(path, 0700);
            report("untraced_mkdir", r, path, "");
            _exit(0);
        }
        report("clone", child, "", "");
        if (child > 0) waitpid((pid_t) child, &status, 0);
    } else {
        return 2;
    }
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report_line("released", p.result, p.err, p.path, "");
    snprintf(path, sizeof path, "%s/hidden2", argv[3]);
    r = native_mkdir(path, 0700);
    report("hidden2", r, path, "");
    return 0;
}

/* reexec N PATH: exec PATH reexec N-1 PATH until N is 0. */
static int mode_reexec(int argc, char **argv) {
    char n[32];
    char *args[5];
    int left;
    if (argc < 4) return 2;
    left = atoi(argv[2]);
    if (left <= 0) { report_line("done", 0, 0, "", ""); return 0; }
    snprintf(n, sizeof n, "%d", left - 1);
    args[0] = argv[3]; args[1] = "reexec"; args[2] = n; args[3] = argv[3]; args[4] = NULL;
    execv(argv[3], args);
    report_line("execv", -1, errno, argv[3], "");
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
