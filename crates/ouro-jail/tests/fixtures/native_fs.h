/* Native syscall spellings for the live observer fixtures. Keep the legacy
 * x86_64 calls covered there; AArch64 only exposes the corresponding *at calls. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef __aarch64__
#define native_mkdir(p,m) syscall(SYS_mkdirat, AT_FDCWD, p, m)
#define native_rename(a,b) syscall(SYS_renameat, AT_FDCWD, a, AT_FDCWD, b)
#define native_link(a,b) syscall(SYS_linkat, AT_FDCWD, a, AT_FDCWD, b, 0)
#define native_symlink(a,b) syscall(SYS_symlinkat, a, AT_FDCWD, b)
#define native_unlink(p) syscall(SYS_unlinkat, AT_FDCWD, p, 0)
#define native_rmdir(p) syscall(SYS_unlinkat, AT_FDCWD, p, AT_REMOVEDIR)
#define native_creat(p,m) syscall(SYS_openat, AT_FDCWD, p, O_WRONLY | O_CREAT | O_TRUNC, m)
#define native_open(p,f,m) syscall(SYS_openat, AT_FDCWD, p, f, m)
#define native_mknod(p,m,d) syscall(SYS_mknodat, AT_FDCWD, p, m, d)
#else
#define native_mkdir(p,m) syscall(SYS_mkdir, p, m)
#define native_rename(a,b) syscall(SYS_rename, a, b)
#define native_link(a,b) syscall(SYS_link, a, b)
#define native_symlink(a,b) syscall(SYS_symlink, a, b)
#define native_unlink(p) syscall(SYS_unlink, p)
#define native_rmdir(p) syscall(SYS_rmdir, p)
#define native_creat(p,m) syscall(SYS_creat, p, m)
#define native_open(p,f,m) syscall(SYS_open, p, f, m)
#define native_mknod(p,m,d) syscall(SYS_mknod, p, m, d)
#endif
