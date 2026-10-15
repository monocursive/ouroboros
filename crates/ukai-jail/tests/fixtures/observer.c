/* The observer suite's fixture (observer_linux.rs). `launch` is the inside
   launcher (common.h), with one probe of its own; every other mode is a
   fixture that prints the lines of common.h, one per operation. */
#include "common.h"

#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

extern char **environ;

/* helper launch FILTER PROGRAM [ARGS...]
   helper launch FILTER --probe-openat PATH: no exec; once released, a
   covered open, a read-only open and a write, to show what the filter does
   with no tracer attached. */
static int mode_launch_or_probe(int argc, char **argv) {
    long r;
    int rc;
    if (argc < 4 || strcmp(argv[3], "--probe-openat")) return mode_launch(argc, argv);
    if (argc < 5) return 2;
    rc = launch_until_released(&argv[2], 1);
    if (rc) return rc;
    r = syscall(SYS_openat, AT_FDCWD, argv[4], O_WRONLY | O_CREAT, 0600);
    report("openat_create", r, argv[4], "");
    r = syscall(SYS_openat, AT_FDCWD, argv[4], O_RDONLY, 0);
    report("openat_rdonly", r, argv[4], "");
    r = syscall(SYS_write, 1, "", 0);
    report("write", r, "", "");
    return 0;
}

/* helper closed-set BASE EACCES_FILE */
static int mode_closed_set(int argc, char **argv) {
    char a[512], b[512], c[512], s[512], d[512], miss[512], sock[512];
    char a2[512], b2[512], d2[512], a3[512], c3[512], s3[512], a4[512];
    char n1[512], n2[512];
    struct ukai_open_how how;
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
    r = native_mkdir(d, 0700);
    report("mkdir", r, d, "");
    r = native_mkdir(d, 0700);
    report("mkdir_eexist", r, d, "");
    r = native_rename(a, b);
    report("rename", r, a, b);
    r = native_link(b, c);
    report("link", r, b, c);
    r = native_symlink("a-target", s);
    report("symlink", r, s, "a-target");
    r = native_unlink(c);
    report("unlink", r, c, "");
    r = native_unlink(c);
    report("unlink_enoent", r, c, "");
    r = native_rmdir(d);
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

    r = native_creat(a2, 0600);
    report("creat", r, a2, ""); if (r >= 0) close((int) r);
    r = syscall(SYS_renameat2, AT_FDCWD, a2, AT_FDCWD, b2, 0);
    report("renameat2", r, a2, b2);
    r = syscall(SYS_unlinkat, AT_FDCWD, b2, 0);
    report("unlinkat", r, b2, "");
    r = syscall(SYS_mkdirat, AT_FDCWD, d2, 0700);
    report("mkdirat", r, d2, "");
    r = syscall(SYS_unlinkat, AT_FDCWD, d2, AT_REMOVEDIR);
    report("unlinkat_removedir", r, d2, "");
    r = native_open(a3, O_WRONLY | O_CREAT, 0600);
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

    /* jail-v1 §11.2's pathname truncate and its two mknod spellings. A FIFO
       needs no privilege. */
    r = syscall(SYS_truncate, a3, 0L);
    report("truncate", r, a3, "");
    r = native_mknod(n1, S_IFIFO | 0600, 0);
    report("mknod", r, n1, "");
    r = syscall(SYS_mknodat, AT_FDCWD, n2, S_IFIFO | 0600, 0);
    report("mknodat", r, n2, "");
    r = syscall(SYS_ftruncate, 0, 0L);
    report("ftruncate", r, "", "");

    /* The rest of the rows, so every one is compared: a failed execve and
       execveat, a renameat, and a connect that succeeds (to a listener this
       process holds). */
    {
        char *av[2];
        char prog[512], r4[512], sp[512];
        struct sockaddr_un la;
        int ls, cs;
        snprintf(prog, sizeof prog, "%s/absent-program", base);
        snprintf(r4, sizeof r4, "%s/r4", base);
        snprintf(sp, sizeof sp, "%s/listen.sock", base);
        av[0] = prog;
        av[1] = NULL;
        r = syscall(SYS_execve, prog, av, environ);
        report("execve_enoent", r, prog, "");
        r = syscall(SYS_execveat, AT_FDCWD, prog, av, environ, 0);
        report("execveat_enoent", r, prog, "");
        r = syscall(SYS_renameat, AT_FDCWD, a4, AT_FDCWD, r4);
        report("renameat", r, a4, r4);
        ls = socket(AF_UNIX, SOCK_STREAM, 0);
        memset(&la, 0, sizeof la);
        la.sun_family = AF_UNIX;
        strncpy(la.sun_path, sp, sizeof la.sun_path - 1);
        if (ls < 0 || bind(ls, (struct sockaddr *) &la, sizeof la) || listen(ls, 1)) return 5;
        cs = socket(AF_UNIX, SOCK_STREAM, 0);
        r = syscall(SYS_connect, cs, &la, (long) sizeof la);
        report("connect_ok", r, sp, "");
        close(cs);
        close(ls);
    }
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
    report("after", native_mkdir(dir, 0700), dir, "");
    return 0;
}

/* helper fileops N DIR: N rounds of a create, a rename and an unlink, the
   workload the observer's cost is measured on. */
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
        native_rename(a, b);
        native_unlink(b);
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
    r = native_mkdir(argv[2], 0700);
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
    struct ukai_open_how how;
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
    r = native_rename(a, b);
    report("rename", r, a, b);
    r = native_unlink(b);
    report("unlink", r, b, "");
    r = native_mkdir(d, 0700);
    report("mkdir", r, d, "");
    r = native_rmdir(d);
    report("rmdir", r, d, "");
    report("nspid", (long) getpid(), "", "");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "launch")) return mode_launch_or_probe(argc, argv);
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
