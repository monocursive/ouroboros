/* VM-only lifetime experiment. Kernel debugger-death cleanup is per tracee;
 * fork inheritance and detach are tested separately. No production backend. */
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Version-fenced identity, using the same pinned inspection ABI as the fixture. */
struct unique_info {
    uint8_t uuid[16]; uint64_t uniqueid, parent_uniqueid;
    int32_t pidversion, original_parent_pidversion; uint64_t reserved[2];
};
_Static_assert(sizeof(struct unique_info) == 56, "inspection ABI size");
extern char **environ;
static void timeout_exit(int sig) { (void)sig; _exit(90); }
static double now(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}
static void info(const char *role) {
    struct proc_bsdinfo b = {0}; struct unique_info u = {0};
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &b, sizeof(b)) != sizeof(b) ||
        proc_pidinfo(getpid(), 17, 0, &u, sizeof(u)) != sizeof(u)) _exit(2);
    audit_token_t token; mach_msg_type_number_t n = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &n) != KERN_SUCCESS) _exit(2);
    printf("{\"role\":\"%s\",\"pid\":%d,\"pidversion\":%d,\"uniqueid\":%llu,\"pgid\":%u,\"sid\":%d,\"bsd_flags\":%u,\"audit_token\":[",
           role, getpid(), u.pidversion, (unsigned long long)u.uniqueid, b.pbi_pgid, getsid(0), b.pbi_flags);
    for (int i = 0; i < 8; ++i) printf("%s%u", i ? "," : "", token.val[i]);
    puts("]}");
}
static void heartbeat(const char *directory, const char *role) {
    signal(SIGALRM, timeout_exit); alarm(20);
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/%s.heartbeat", directory, role) >= (int)sizeof(path)) _exit(3);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(3);
    for (;;) { if (write(fd, ".", 1) != 1) _exit(3); usleep(10000); }
}
static int trace(int argc, char **argv) {
    for (int i = 2; i < argc; ++i) {
        char *end; long pid = strtol(argv[i], &end, 10);
        if (*end != ':' || pid <= 1 || pid > INT32_MAX) return 64;
        char *last; long version = strtol(end + 1, &last, 10);
        if (*last || version <= 0 || version > INT32_MAX) return 64;
        struct unique_info u = {0};
        if (proc_pidinfo((pid_t)pid, 17, 0, &u, sizeof(u)) != sizeof(u) || u.pidversion != version) return 125;
        errno = 0;
        int rc = ptrace(PT_ATTACHEXC, (pid_t)pid, NULL, 0);
        int error = errno;
        printf("{\"kind\":\"attach\",\"pid\":%ld,\"pidversion\":%ld,\"rc\":%d,\"errno\":%d}\n", pid, version, rc, error);
        if (rc) return 125;
        int status = 0; double deadline = now() + 2;
        for (;;) {
            pid_t found = waitpid((pid_t)pid, &status, WUNTRACED | WNOHANG);
            if (found == pid) break;
            if (found < 0 || now() > deadline) return 125;
            usleep(10000);
        }
        if (!WIFSTOPPED(status) || ptrace(PT_CONTINUE, (pid_t)pid, (caddr_t)1, 0)) return 125;
    }
    info("tracer");
    printf("{\"kind\":\"tracer_ready\",\"attached_count\":%d}\n", argc - 2);
    /* No userspace cleanup, no exit/SIGTERM handlers and no detach. Faults use
       SIGKILL/SIGSTOP. The independent runner audits before emergency cleanup. */
    for (;;) {
        int status; pid_t pid = waitpid(-1, &status, WNOHANG | WUNTRACED);
        if (pid > 0 && WIFSTOPPED(status) && ptrace(PT_CONTINUE, pid, (caddr_t)1, 0)) return 125;
        usleep(10000);
    }
}
static int late(const char *directory, const char *mode, const char *exe) {
    char trigger[4096];
    if (snprintf(trigger, sizeof(trigger), "%s/trigger", directory) >= (int)sizeof(trigger)) return 64;
    info("root"); puts("{\"kind\":\"before_fork\"}");
    while (access(trigger, F_OK)) usleep(10000);
    pid_t child;
    if (!strcmp(mode, "spawn-group") || !strcmp(mode, "spawn-session")) {
        posix_spawnattr_t attr;
        if (posix_spawnattr_init(&attr) ||
            posix_spawnattr_setflags(&attr, !strcmp(mode, "spawn-group") ? POSIX_SPAWN_SETPGROUP : POSIX_SPAWN_SETSID) ||
            posix_spawnattr_setpgroup(&attr, 0)) return 4;
        char *args[] = {(char *)exe, "--child", (char *)directory, (char *)mode, NULL};
        int error = posix_spawn(&child, exe, NULL, &attr, args, environ);
        posix_spawnattr_destroy(&attr);
        if (error) return error;
    } else {
        child = fork();
        if (child < 0) return 4;
        if (!child) {
            if (strcmp(mode, "fork") && setsid() < 0) _exit(4);
            if (!strcmp(mode, "double-fork")) {
                pid_t second = fork(); if (second < 0) _exit(4); if (second) _exit(0);
            }
            if (!strcmp(mode, "deny-attach")) {
                errno = 0; int rc = ptrace(PT_DENY_ATTACH, 0, NULL, 0);
                printf("{\"kind\":\"deny_attach\",\"rc\":%d,\"errno\":%d}\n", rc, errno);
                if (rc) _exit(4);
            }
            info("late-child"); heartbeat(directory, "late-child");
        }
    }
    heartbeat(directory, "root");
    return 0;
}
int main(int argc, char **argv) {
    int virtualized = 0; size_t n = sizeof(virtualized);
    if (sysctlbyname("kern.hv_vmm_present", &virtualized, &n, NULL, 0) || virtualized != 1) {
        fputs("Research helper requires an isolated VM.\n", stderr); return 125;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGTERM, SIG_IGN); signal(SIGALRM, timeout_exit); alarm(20);
    if (argc >= 3 && !strcmp(argv[1], "--trace")) return trace(argc, argv);
    if (argc == 4 && !strcmp(argv[1], "--late")) return late(argv[2], argv[3], argv[0]);
    if (argc == 4 && !strcmp(argv[1], "--child")) { info("late-child"); heartbeat(argv[2], "late-child"); }
    return 64;
}
