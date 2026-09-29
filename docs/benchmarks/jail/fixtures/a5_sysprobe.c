/* Pass-5 syscall drift probe: kernel 7.0 x86_64 surface vs jail deny list.
 * Reports errno per syscall under the jail; EPERM-from-seccomp vs kernel
 * results distinguishes "denied" from "shipped allowed". */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

static int probe(const char *name, long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    errno = 0;
    long r = syscall(nr, a0, a1, a2, a3, a4, a5);
    printf("%-24s nr=%-4ld -> ret=%ld errno=%d (%s)\n", name, nr, r, errno,
           errno ? strerror(errno) : "ok");
    fflush(stdout);
    return (int)r;
}

int main(int argc, char **argv) {
    /* settimeofday(164): the one clock-adjustment interface B8's fix missed */
    struct timeval tv = {0, 0};
    probe("settimeofday", 164, (long)&tv, 0, 0, 0, 0, 0);
    /* fanotify_init(300): was reaching kernel per pass 2/3 */
    probe("fanotify_init", 300, 0, 0, 0, 0, 0, 0);
    /* memfd_secret(447), map_shadow_stack(453) */
    probe("memfd_secret", 447, 0, 0, 0, 0, 0, 0);
    probe("map_shadow_stack", 453, 4096, 0, 0, 0, 0, 0);
    /* xattrat family (pass-4 B8 said EINVAL/EFAULT = reaching kernel) */
    probe("setxattrat", 463, AT_FDCWD, (long)"x", (long)"user.a", (long)"v", 1, 0);
    probe("getxattrat", 464, AT_FDCWD, (long)"x", (long)"user.a", (long)0, 0, 0);
    /* kernel 7.0 new surface, absent from jail tables */
    probe("open_tree_attr", 467, AT_FDCWD, (long)"/", 0, 0, 0, 0);
    probe("file_getattr", 468, 1, 0, 0, 0, 0, 0);
    probe("listns", 470, 0, 0, 0, 0, 0, 0);
    probe("rseq_slice_yield", 471, 0, 0, 0, 0, 0, 0);

    /* file_setattr(469): the interesting one — setattr by fd. If the new
     * API skips the read-only-mount check, an fd to a file under a --ro
     * grant could be chmodded/touched. Target file comes from argv[1]. */
    const char *target = argc > 1 ? argv[1] : "/etc/hostname";
    int fd = open(target, O_RDONLY | O_CLOEXEC);
    printf("target %s fd=%d\n", target, fd);
    if (fd >= 0) {
        errno = 0;
        /* struct file_attr guess: reserve 256 bytes zeroed; if the ABI
         * wants a size/version header, zeros may EINVAL — the errno
         * itself distinguishes seccomp-EPERM (denied) from kernel
         * validation (reached). */
        unsigned char buf[256];
        memset(buf, 0, sizeof buf);
        long r = syscall(469, fd, (long)buf, 0, 0, 0, 0);
        printf("file_setattr(ro fd) -> ret=%ld errno=%d (%s)\n", r, errno,
               errno ? strerror(errno) : "ok");
        struct stat st;
        if (fstat(fd, &st) == 0)
            printf("  mode after: %o mtime=%ld\n", st.st_mode, st.st_mtime);
        close(fd);
    }
    /* Also plain chmod(90) on the ro target for the EROFS baseline */
    if (argc > 1) {
        errno = 0;
        long r = syscall(90, target, 0777);
        printf("chmod(ro target) -> ret=%ld errno=%d (%s)\n", r, errno,
               errno ? strerror(errno) : "ok");
    }
    return 0;
}
