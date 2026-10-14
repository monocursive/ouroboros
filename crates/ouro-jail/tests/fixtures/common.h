/* What the live observer fixtures share: the line every suite parses, the
   inside launcher, a task asleep inside a call, and the native spelling of
   each pathname call. (The unix-peer launcher stand-in, unix_peer.c, needs
   none of it.)

   Each fixture includes this first. Everything here is `static inline`, so
   a fixture that uses only part of it still builds without unused-function
   warnings under -Wall. */
#ifndef OURO_FIXTURE_COMMON_H
#define OURO_FIXTURE_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Native syscall spellings                                             */
/* ------------------------------------------------------------------ */

/* x86_64 keeps the legacy pathname calls, and the fixtures make them there,
   because they are rows of its closed set. AArch64 has only the *at calls, so
   the same operation is made through those; the Rust side names what each
   table calls it (`native_expectation` in tests/common/observer.rs). */
#if defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define NATIVE_MKDIR_NR SYS_mkdirat
#define native_mkdir(p, m) syscall(SYS_mkdirat, AT_FDCWD, (p), (m))
#define native_rename(a, b) syscall(SYS_renameat, AT_FDCWD, (a), AT_FDCWD, (b))
#define native_link(a, b) syscall(SYS_linkat, AT_FDCWD, (a), AT_FDCWD, (b), 0)
#define native_symlink(a, b) syscall(SYS_symlinkat, (a), AT_FDCWD, (b))
#define native_unlink(p) syscall(SYS_unlinkat, AT_FDCWD, (p), 0)
#define native_rmdir(p) syscall(SYS_unlinkat, AT_FDCWD, (p), AT_REMOVEDIR)
#define native_creat(p, m) syscall(SYS_openat, AT_FDCWD, (p), O_WRONLY | O_CREAT | O_TRUNC, (m))
#define native_open(p, f, m) syscall(SYS_openat, AT_FDCWD, (p), (f), (m))
#define native_mknod(p, m, d) syscall(SYS_mknodat, AT_FDCWD, (p), (m), (d))
#elif defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#define NATIVE_MKDIR_NR SYS_mkdir
#define native_mkdir(p, m) syscall(SYS_mkdir, (p), (m))
#define native_rename(a, b) syscall(SYS_rename, (a), (b))
#define native_link(a, b) syscall(SYS_link, (a), (b))
#define native_symlink(a, b) syscall(SYS_symlink, (a), (b))
#define native_unlink(p) syscall(SYS_unlink, (p))
#define native_rmdir(p) syscall(SYS_rmdir, (p))
#define native_creat(p, m) syscall(SYS_creat, (p), (m))
#define native_open(p, f, m) syscall(SYS_open, (p), (f), (m))
#define native_mknod(p, m, d) syscall(SYS_mknod, (p), (m), (d))
#else
#error "the live observer fixtures know the x86_64 and aarch64 syscall tables only"
#endif

/* openat2(2)'s argument, spelled out so a fixture can pass a size the
   kernel's own definition would not. */
struct ouro_open_how { unsigned long long flags, mode, resolve; };

#ifdef __x86_64__
#include <stdint.h>
#include <sys/mman.h>

/* An i386 system call through int 0x80, which a 64-bit process can make on a
   kernel built with IA32 emulation. Returns and sets errno as syscall(2)
   does. */
static inline long int80(long nr, long a, long b, long c) {
    long res;
    __asm__ volatile("int $0x80" : "=a"(res) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
    errno = res < 0 ? (int) -res : 0;
    return res < 0 ? -1 : res;
}

/* An i386 open(path, flags, mode). The i386 ABI passes 32-bit pointers, so
   the name is copied into a page mapped below 4 GiB first; -1 with mmap's
   errno when there is no such page. */
static inline long int80_open(const char *path, long flags, long mode) {
    char *low = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low == MAP_FAILED) return -1;
    strncpy(low, path, 4000);
    return int80(5 /* i386 open */, (long) (uint32_t) (uintptr_t) low, flags, mode);
}
#endif

/* ------------------------------------------------------------------ */
/* The line every suite parses                                          */
/* ------------------------------------------------------------------ */

/* One line per operation, tab-separated: label, raw return, errno, path,
   second path. */
static inline void report_line(const char *label, long r, int err, const char *p1, const char *p2) {
    printf("%s\t%ld\t%d\t%s\t%s\n", label, r, err, p1 ? p1 : "", p2 ? p2 : "");
    fflush(stdout);
}

/* report_line for the call that just returned r: its errno, when r says it
   failed. */
static inline void report(const char *label, long r, const char *p1, const char *p2) {
    report_line(label, r, r < 0 ? errno : 0, p1, p2);
}

static inline void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

/* ------------------------------------------------------------------ */
/* The inside launcher                                                  */
/* ------------------------------------------------------------------ */

/* Install the cBPF program in the file at `path` with no_new_privs: the bytes
   the crate wrote there, never a second copy of the program. 0, or which step
   failed. */
static inline int install_filter_file(const char *path) {
    static struct sock_filter prog[1024];
    struct sock_fprog fprog;
    int fd = open(path, O_RDONLY);
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, prog, sizeof prog);
    close(fd);
    if (n <= 0 || (size_t) n % sizeof(struct sock_filter)) return -2;
    fprog.len = (unsigned short) ((size_t) n / sizeof(struct sock_filter));
    fprog.filter = prog;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -3;
    if (syscall(SYS_seccomp, 1, 0, &fprog)) return -4;
    return 0;
}

/* Block until the supervisor writes the release byte on stdin. 0 once it
   came; -1 at end of file, or on an error other than EINTR. */
static inline int await_release(void) {
    char b;
    for (;;) {
        ssize_t n = read(0, &b, 1);
        if (n == 1) return 0;
        if (n == 0) return -1;
        if (errno != EINTR) return -1;
    }
}

/* What the product's inside launcher does before its exec (jail-v1 §3.6):
   install the filters in the files `filters` names, in order, announce
   "ready", and block on the release byte. 0 to go on, or the exit code.

   "ready" goes out only once the exec that started this process is complete
   and the filters are on. The supervisor seizes only after reading it, so
   the seize can never land in the middle of an exec it did not ask about. */
static inline int launch_until_released(char *const *filters, int count) {
    int i;
    for (i = 0; i < count; i++) {
        if (install_filter_file(filters[i])) {
            fprintf(stderr, "installing the filter in %s failed\n", filters[i]);
            return 3;
        }
    }
    report("ready", (long) getpid(), "", "");
    if (await_release()) return 4;
    return 0;
}

static inline int launch_exec(char **argv) {
    execv(argv[0], argv);
    fprintf(stderr, "execv %s: %s\n", argv[0], strerror(errno));
    return 127;
}

/* launch FILTER PROGRAM [ARGS...]: the observer's filter only, as in `none`. */
static inline int mode_launch(int argc, char **argv) {
    int r;
    if (argc < 4) return 2;
    r = launch_until_released(&argv[2], 1);
    return r ? r : launch_exec(&argv[3]);
}

/* launch2 BASELINE NARROWING PROGRAM [ARGS...]: the contained shape, the
   enforcement baseline first and the observer's narrowing filter second. */
static inline int mode_launch2(int argc, char **argv) {
    int r;
    if (argc < 5) return 2;
    r = launch_until_released(&argv[2], 2);
    return r ? r : launch_exec(&argv[4]);
}

/* ------------------------------------------------------------------ */
/* A task asleep inside a call                                          */
/* ------------------------------------------------------------------ */

/* Whether the task whose /proc stat and syscall files are open on `stat_fd`
   and `syscall_fd` is asleep inside syscall `nr`: state S (a tracing stop
   reads t) and /proc/.../syscall naming it. Only pread(2) of descriptors
   opened before the call, which is outside the closed set. */
static inline int asleep_in(int stat_fd, int syscall_fd, long nr) {
    char buf[512];
    char *rp;
    char state;
    ssize_t n = pread(stat_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    rp = strrchr(buf, ')');
    state = rp && rp[1] == ' ' ? rp[2] : 0;
    n = pread(syscall_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    return state == 'S' && buf[0] >= '0' && buf[0] <= '9' && atol(buf) == nr;
}

/* asleep_in, polled every 100 µs for up to 20 s: 0 once it holds, -5 if it
   never did. */
static inline int await_asleep_in(int stat_fd, int syscall_fd, long nr) {
    int i;
    for (i = 0; i < 200000; i++) {
        if (asleep_in(stat_fd, syscall_fd, nr)) return 0;
        usleep(100);
    }
    return -5;
}

#endif
