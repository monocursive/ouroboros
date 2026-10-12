/* Linux attack-surface diagnostics, each call in a fresh child. Invalid-argument
 * results only establish reachability, not an exploitable escape. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
struct probe { const char *name; long number; long a; long b; };
int main(void) {
    struct probe probes[] = {
        {"unshare_userns", SYS_unshare, CLONE_NEWUSER, 0},
        {"ptrace_traceme", SYS_ptrace, PTRACE_TRACEME, 0},
        {"mount", SYS_mount, 0, 0},
        {"clone3", SYS_clone3, 0, 0},
        {"process_vm_readv", SYS_process_vm_readv, -1, 0},
        {"pidfd_getfd", SYS_pidfd_getfd, -1, -1},
        {"io_uring_setup", SYS_io_uring_setup, 1, 0},
        {"bpf", SYS_bpf, -1, 0},
        {"keyctl", SYS_keyctl, -1, 0},
        {"setns", SYS_setns, -1, 0},
    };
    for (unsigned i = 0; i < sizeof(probes)/sizeof(probes[0]); ++i) {
        pid_t p = fork(); if (p < 0) return 3;
        if (!p) {
            errno = 0;
            long result = syscall(probes[i].number, probes[i].a, probes[i].b, 0L, 0L, 0L, 0L);
            printf("{\"syscall\":\"%s\",\"return\":%ld,\"errno\":%d}\n", probes[i].name, result, errno);
            fflush(stdout); _exit(0);
        }
        int status; if (waitpid(p, &status, 0) != p || !WIFEXITED(status) || WEXITSTATUS(status)) return 3;
    }
    return 0;
}
