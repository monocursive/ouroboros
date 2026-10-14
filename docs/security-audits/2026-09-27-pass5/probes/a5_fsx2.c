/* file_setattr(469) correct ABI: (dfd, filename, file_attr*, usize=24, at_flags) */
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

int main(int argc, char **argv) {
    const char *target = argc > 1 ? argv[1] : "/etc/hostname";
    struct file_attr fa;
    memset(&fa, 0, sizeof fa);

    errno = 0;
    long r = syscall(468, AT_FDCWD, target, &fa, 24, 0);
    printf("getattr(%s) -> %ld errno=%d xflags=%llx projid=%u\n",
           target, r, errno, fa.fa_xflags, fa.fa_projid);

    fa.fa_xflags |= 0x80ULL;  /* FS_XFLAG_NODUMP */
    fa.fa_projid = 4242;
    errno = 0;
    r = syscall(469, AT_FDCWD, target, &fa, 24, 0);
    printf("setattr(NODUMP|projid=4242) -> %ld errno=%d (%s)\n",
           r, errno, errno ? strerror(errno) : "ok");

    memset(&fa, 0, sizeof fa);
    r = syscall(468, AT_FDCWD, target, &fa, 24, 0);
    printf("after: xflags=%llx projid=%u\n", fa.fa_xflags, fa.fa_projid);
    return 0;
}
