/* file_setattr(469) on a read-only-granted file: can the child set
 * FS_XFLAG_IMMUTABLE / projid / extsize through the new fd-based API
 * where chmod-by-path gets EROFS? */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string.h>

struct file_attr {
    unsigned long long fa_xflags;
    unsigned int fa_extsize;
    unsigned int fa_nextents;
    unsigned int fa_projid;
    unsigned int fa_cowextsize;
};

static long file_setattr(int fd, struct file_attr *fa) {
    return syscall(469, fd, fa, 24, 0);
}
static long file_getattr(int fd, struct file_attr *fa) {
    return syscall(468, fd, fa, 24, 0);
}

int main(int argc, char **argv) {
    const char *target = argc > 1 ? argv[1] : "/etc/hostname";
    int fd = open(target, O_RDONLY | O_CLOEXEC);
    printf("open(%s) = %d\n", target, fd);
    if (fd < 0) { perror("open"); return 1; }

    struct file_attr fa;
    memset(&fa, 0, sizeof fa);
    long r = file_getattr(fd, &fa);
    printf("file_getattr -> %ld errno=%d xflags=%llx projid=%u\n",
           r, errno, fa.fa_xflags, fa.fa_projid);

    /* ioctl baseline first: FS_IOC_FSSETXATTR = 0x401c5818? use _IOW via
     * /usr/include; spell it: FS_IOC_FSGETXATTR 0x5818? compute manually:
     * _IOR('X', 31, struct fsxattr) etc. Skip ioctl; syscall is the test. */

    fa.fa_xflags |= 0x00000008ULL; /* FS_XFLAG_IMMUTABLE */
    fa.fa_projid = 4242;
    errno = 0;
    r = file_setattr(fd, &fa);
    printf("file_setattr(IMMUTABLE|projid=4242) -> %ld errno=%d (%s)\n",
           r, errno, errno ? strerror(errno) : "ok");

    memset(&fa, 0, sizeof fa);
    r = file_getattr(fd, &fa);
    printf("after: file_getattr -> %ld xflags=%llx projid=%u\n",
           r, fa.fa_xflags, fa.fa_projid);
    return 0;
}
