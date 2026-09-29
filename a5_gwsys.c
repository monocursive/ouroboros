/* Syscall posture probe: what does the sandbox's seccomp layer deny?
 * Plain errno report per call; usable under any sandbox. */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/stat.h>

static void p(const char *n, long r, int e) {
    printf("%-22s -> ret=%ld errno=%d (%s)\n", n, r, e, e ? strerror(e) : "ok");
    fflush(stdout);
}
#define TRY(name, nr, ...) { errno=0; long r = syscall(nr, __VA_ARGS__); p(name, r, errno); }

int main(void) {
    TRY("mount", 165, "none", "/mnt", "none", 0L, 0L);
    TRY("unshare(CLONE_NEWUSER)", 272, 0x10000000L, 0L, 0L, 0L, 0L);
    TRY("clone3", 435, 0L, 88L, 0L, 0L, 0L); /* null args: EINVAL = reached kernel */
    TRY("bpf", 321, 0U, 0UL, 0UL, 0UL, 0UL);
    TRY("ptrace", 101, 0L, 0L, 0L, 0L, 0L);
    TRY("process_vm_readv", 310, -1L, 0L, 0L, 0L, 0L, 0L);
    TRY("pidfd_getfd", 438, -1L, 0L, 0U, 0L, 0L, 0L);
    TRY("io_uring_setup", 425, 4U, 0L, 0L, 0L, 0L, 0L);
    TRY("perf_event_open", 298, 0L, -1L, -1L, -1L, 0L);
    TRY("setns", 308, -1L, 0L, 0L, 0L, 0L, 0L);
    TRY("open_tree_attr", 467, AT_FDCWD, "/", 0L, 0L, 0L, 0L);
    TRY("listns", 470, 0L, 0L, 0L, 0L, 0L, 0L);
    TRY("keyctl", 250, 0L, 0L, 0L, 0L, 0L, 0L);
    TRY("kexec_load", 246, 0L, 0L, 0UL, 0L, 0L, 0L);
    /* fs checks */
    errno = 0; int fd = open("/etc/shadow", O_RDONLY); p("open(/etc/shadow)", fd, errno);
    if (fd >= 0) close(fd);
    errno = 0; fd = open("/proc/1/environ", O_RDONLY); p("open(/proc/1/environ)", fd, errno);
    if (fd >= 0) close(fd);
    errno = 0; struct stat st; long r = stat("/home/ubuntu/.ssh", &st); p("stat(~/.ssh)", r, errno);
    return 0;
}
