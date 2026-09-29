/* Compat clone3 probe. Any unexpected child exits immediately and is reaped. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    struct clone_args args = { .flags = CLONE_UNTRACED, .exit_signal = SIGCHLD };
    long ret = syscall(0x40000000L | 435, &args, sizeof args);
    if (ret == 0) _exit(42);
    if (ret > 0) {
        int status;
        waitpid((pid_t)ret, &status, 0);
        fputs("unexpected child created\n", stderr);
        return 1;
    }
    printf("x32 clone3 errno=%d\n", errno);
    return errno == ENOSYS ? 0 : 1;
}
