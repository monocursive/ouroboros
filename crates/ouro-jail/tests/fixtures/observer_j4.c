/* The observer's own-defect suite's fixture (observer_j4_linux.rs): a
   child's own seccomp filter (a notification listener, a filter that refuses
   a call, a filter that asks for trace stops), a foreign-ABI call where
   x86_64 has one, and a full lifecycle backlog. `launch` and `launch2` are
   the inside launcher (common.h); every other mode prints its lines. */
#include "common.h"

#include <pthread.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LD_ARCH BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch))
#define LD_NR BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
#define RET(k) BPF_STMT(BPF_RET | BPF_K, (k))

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
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 0, 3),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        RET(SECCOMP_RET_USER_NOTIF),
        RET(SECCOMP_RET_ALLOW),
    };
    pthread_t t;
    long r;
    if (argc < 4) return 2;
    r = install(prog, 6, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0);
    report("listener", r, "", "");
    if (r < 0) return 3;
    g_listener = (int) r;
    pthread_create(&t, NULL, continue_every_call, NULL);
    r = syscall(SYS_openat, AT_FDCWD, argv[2], O_WRONLY | O_CREAT, 0600);
    report("hidden_open", r, argv[2], "");
    if (r >= 0) close((int) r);
    r = native_mkdir(argv[3], 0700);
    report("seen_mkdir", r, argv[3], "");
    return 0;
}

/* errno-filter seccomp|prctl DENIED SEEN: a listener-less filter that fails
   mkdir and mkdirat with EPERM (and kills any other architecture), then
   mkdir DENIED (preempted before the trace stop) and create SEEN (not). A
   table without a legacy mkdir names mkdirat in both tests. */
static int mode_errno_filter(int argc, char **argv) {
    struct sock_filter prog[] = {
        LD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
        RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_MKDIR_NR, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdirat, 1, 0),
        RET(SECCOMP_RET_ALLOW),
        RET(SECCOMP_RET_ERRNO | EPERM),
    };
    long r;
    if (argc < 5) return 2;
    r = install(prog, 8, 0, strcmp(argv[2], "prctl") == 0);
    report("install", r, argv[2], "");
    if (r < 0) return 3;
    r = native_mkdir(argv[3], 0700);
    report("preempted_mkdir", r, argv[3], "");
    r = syscall(SYS_openat, AT_FDCWD, argv[4], O_WRONLY | O_CREAT, 0600);
    report("seen_open", r, argv[4], "");
    if (r >= 0) close((int) r);
    return 0;
}

/* tool-listener: what the tool baseline answers to the child's own filters. */
static int mode_tool_listener(void) {
    struct sock_filter allow[] = { RET(SECCOMP_RET_ALLOW) };
    long r;
    r = install(allow, 1, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0);
    report("new_listener", r, "", "");
    if (r >= 0) close((int) r);
    /* seccomp(2) takes an unsigned int: the high word is not the flags. */
    r = install(allow, 1, (1UL << 32) | SECCOMP_FILTER_FLAG_NEW_LISTENER, 0);
    report("new_listener_high_word", r, "", "");
    if (r >= 0) close((int) r);
    r = install(allow, 1, 0, 0);
    report("plain_filter", r, "", "");
    return 0;
}

#ifdef __x86_64__
/* foreign I386 X32 NATIVE: an i386 open that creates I386, an x32 openat of
   X32, an i386 call with a number no table has, and a native create. Only
   x86_64 has these ABIs. */
static int mode_foreign(int argc, char **argv) {
    long r;
    if (argc < 5) return 2;
    r = int80_open(argv[2], O_WRONLY | O_CREAT, 0600);
    report("i386_open", r, argv[2], "");
    if (r >= 0) close((int) r);
    r = syscall(0x40000000L | __NR_openat, AT_FDCWD, argv[3], O_WRONLY | O_CREAT, 0600);
    report("x32_openat", r, argv[3], "");
    if (r >= 0) close((int) r);
    r = int80(0x7ffe, 0, 0, 0);
    report("i386_no_such_call", r, "", "");
    r = syscall(SYS_openat, AT_FDCWD, argv[4], O_WRONLY | O_CREAT, 0600);
    report("native_open", r, argv[4], "");
    if (r >= 0) close((int) r);
    return 0;
}
#endif

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
    report("forked", made, "", "");
    r = install(prog, 4, 0, 0);
    report("install", r, "", "");
    r = syscall(SYS_getpid);
    report("getpid", r, "", "");
    return 0;
}

/* trace-request MADE: the child's own filter asks for trace stops, with data
   of its own (0x1234), on getpid (outside the closed set) and on mkdir
   (inside it). One stop each; the observer must neither decode the first
   nor count it as loss, and must report the second exactly once. */
static int mode_trace_request(int argc, char **argv) {
    struct sock_filter prog[] = {
        LD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
        RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_MKDIR_NR, 1, 0),
        RET(SECCOMP_RET_ALLOW),
        RET(SECCOMP_RET_TRACE | 0x1234),
    };
    long r;
    if (argc < 3) return 2;
    r = install(prog, 8, 0, 0);
    report("install", r, "", "");
    if (r < 0) return 3;
    r = syscall(SYS_getpid);
    report("getpid", r, "", "");
    r = native_mkdir(argv[2], 0700);
    report("mkdir", r, argv[2], "");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "launch")) return mode_launch(argc, argv);
    if (!strcmp(argv[1], "launch2")) return mode_launch2(argc, argv);
    if (!strcmp(argv[1], "listener")) return mode_listener(argc, argv);
    if (!strcmp(argv[1], "errno-filter")) return mode_errno_filter(argc, argv);
    if (!strcmp(argv[1], "tool-listener")) return mode_tool_listener();
#ifdef __x86_64__
    if (!strcmp(argv[1], "foreign")) return mode_foreign(argc, argv);
#endif
    if (!strcmp(argv[1], "forks-then-trace")) return mode_forks_then_trace(argc, argv);
    if (!strcmp(argv[1], "trace-request")) return mode_trace_request(argc, argv);
    return 2;
}
