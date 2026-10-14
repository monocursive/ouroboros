/* The observer regression suite's fixture (observer_regression_linux.rs).
   `launch` and `launch2` are the inside launcher (common.h); every other
   mode prints the lines of common.h, one per operation. */
#include "common.h"

#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

extern char **environ;

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
    char mk[512], tr[512];
    long r;
    int fd;
    if (argc < 3) return 2;
    snprintf(mk, sizeof mk, "%s/by-mknod", argv[2]);
    snprintf(tr, sizeof tr, "%s/by-truncate", argv[2]);

    r = syscall(SYS_mknodat, AT_FDCWD, mk, S_IFREG | 0600, 0);
    report("mknodat", r, mk, "");

    fd = (int) syscall(SYS_openat, AT_FDCWD, tr, O_WRONLY | O_CREAT, 0600);
    if (fd >= 0) { if (write(fd, "hello", 5) < 0) {} close(fd); }
    r = syscall(SYS_truncate, tr, 0L);
    report("truncate", r, tr, "");

#ifdef __x86_64__
    {
        char i386[512], x32[512];
        snprintf(i386, sizeof i386, "%s/by-int80", argv[2]);
        snprintf(x32, sizeof x32, "%s/by-x32", argv[2]);
        r = int80_open(i386, 0x41L, 0600L);
        report("int80_open", r, i386, "");
        r = syscall(0x40000000L | 257L, AT_FDCWD, x32, O_WRONLY | O_CREAT, 0600);
        report("x32_openat", r, x32, "");
    }
#endif
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
    char *a, *b, *mapping;
    size_t len = 4000;
    if (argc < 4) return 2;
    n = atol(argv[2]);
    /* Force snapshots across a page boundary after a large second read.
       A growing Vec can retain nearly twice the pathname length here. */
    mapping = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 3;
    a = mapping + 512;
    b = mapping + 2 * 4096 + 512;
    memset(a, 'a', len); a[len] = 0;
    memset(b, 'b', len); b[len] = 0;
    memcpy(a, argv[3], strlen(argv[3]));
    memcpy(b, argv[3], strlen(argv[3]));
    for (i = 0; i < n; i++) native_rename(a, b);
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
    r = native_rename(good, m + ps);
    report("rename_second_faults", r, good, "");
    r = native_rename(m + ps, good);
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

#ifdef __x86_64__
static int mode_abi(int argc, char **argv) {
    char i386[512], native[512], mk[512];
    long r;
    if (argc < 3) return 2;
    snprintf(i386, sizeof i386, "%s/abi-int80", argv[2]);
    snprintf(native, sizeof native, "%s/abi-native", argv[2]);
    snprintf(mk, sizeof mk, "%s/abi-mknod", argv[2]);
    r = int80_open(i386, 0x41L, 0600L);
    report("int80", r, i386, "");
    r = syscall(SYS_openat, AT_FDCWD, native, O_WRONLY | O_CREAT, 0600);
    report("native", r, native, "");
    if (r >= 0) close((int) r);
    r = syscall(SYS_mknodat, AT_FDCWD, mk, S_IFIFO | 0600, 0);
    report("mknodat", r, mk, "");
    return 0;
}
#endif

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
    r = native_symlink("THE-TARGET", link);
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

#ifdef __x86_64__
static int mode_i386_pipe(void) {
    int fds[2] = {-1, -1};
    long res;
    __asm__ volatile("int $0x80" : "=a"(res) : "a"(42L), "b"((long) (uintptr_t) fds) : "memory");
    report("i386_pipe", res, "", "");
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    return 0;
}
#endif

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
#ifdef __x86_64__
    if (!strcmp(argv[1], "abi")) return mode_abi(argc, argv);
#endif
    if (!strcmp(argv[1], "rdonly")) return mode_rdonly(argc, argv);
    if (!strcmp(argv[1], "worker-fork")) return mode_worker_fork(argc, argv);
    if (!strcmp(argv[1], "symlink")) return mode_symlink(argc, argv);
    if (!strcmp(argv[1], "unreadable")) return mode_unreadable(argc, argv);
#ifdef __x86_64__
    if (!strcmp(argv[1], "i386-pipe")) return mode_i386_pipe();
#endif
    if (!strcmp(argv[1], "two-threads")) return mode_two_threads(argc, argv);
    return 2;
}
