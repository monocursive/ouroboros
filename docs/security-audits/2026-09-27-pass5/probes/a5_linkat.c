/* linkat(AT_EMPTY_PATH) from an ro-granted fd into the writable workspace:
 * the EXDEV shield pass-4 verified for by-path link() — does the by-fd
 * spelling cross the bind mount? */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "/etc/hostname";
    const char *dst = argc > 2 ? argv[2] : "/home/ubuntu/a5ws/hardlink";
    int fd = open(src, O_RDONLY | O_CLOEXEC);
    printf("open(%s)=%d\n", src, fd);
    if (fd < 0) return 1;

    errno = 0;
    long r = syscall(SYS_linkat, fd, "", AT_FDCWD, dst, AT_EMPTY_PATH);
    printf("linkat(AT_EMPTY_PATH) -> %ld errno=%d (%s)\n", r, errno,
           errno ? strerror(errno) : "ok");

    /* plain link for the EXDEV baseline */
    errno = 0;
    r = syscall(SYS_link, src, dst);
    printf("link() -> %ld errno=%d (%s)\n", r, errno,
           errno ? strerror(errno) : "ok");
    return 0;
}
