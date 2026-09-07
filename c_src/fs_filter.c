/*
 * Name-based create denials for bubblewrap.
 *
 * Seatbelt can write `(deny file-write* (regex #"/\.git($|/)"))` and cover a `.git`
 * directory that does not exist yet. Bubblewrap can only bind destinations that exist
 * when the namespace is set up, so `mkdir deps/foo/.git` after the command starts is
 * otherwise a write the permission engine never sees. This library is loaded inside
 * the sandbox and refuses create/rename/link of any path component named in
 * OUROBOROS_FS_DENY (colon-separated, compared case-insensitively). Denied
 * creates return EROFS so they look like bubblewrap's read-only binds, not
 * an ordinary EACCES the engine would treat as a file-mode problem.
 *
 * Static binaries that never call libc are outside this net; ordinary git, python,
 * and /bin/mkdir are not.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* glibc may #define open to open64 after fcntl.h; intercept the names libc actually has. */
#undef open
#undef openat
#undef open64
#undef openat64
#undef creat64
#undef creat
#undef mkdir
#undef mkdirat
#undef rename
#undef renameat
#undef link
#undef symlink
#undef symlinkat

#define MAX_NAMES 8
#define MAX_NAME 64

static char names[MAX_NAMES][MAX_NAME];
static int name_count = -1;
static char preload_path[4096];
static char exceptions[3][PATH_MAX];
static int exception_count;
static char deny_env[MAX_NAMES * MAX_NAME];
static char exception_env[3 * PATH_MAX * 2 + 3];

static int unhex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static int lower_eq(const char *a, const char *b) {
  for (;;) {
    unsigned char ca = (unsigned char)*a;
    unsigned char cb = (unsigned char)*b;
    if (ca >= 'A' && ca <= 'Z') {
      ca = (unsigned char)(ca - 'A' + 'a');
    }
    if (cb >= 'A' && cb <= 'Z') {
      cb = (unsigned char)(cb - 'A' + 'a');
    }
    if (ca != cb) {
      return 0;
    }
    if (ca == 0) {
      return 1;
    }
    a++;
    b++;
  }
}

static void load_names(void) {
  const char *env;
  const char *cursor;
  int i = 0;

  if (name_count >= 0) {
    return;
  }
  name_count = 0;

  env = getenv("OUROBOROS_FS_DENY");
  if (env == NULL || env[0] == '\0') {
    return;
  }

  snprintf(deny_env, sizeof(deny_env), "%s", env);
  cursor = env;
  while (*cursor && i < MAX_NAMES) {
    const char *end = cursor;
    size_t len;
    while (*end && *end != ':') {
      end++;
    }
    len = (size_t)(end - cursor);
    if (len > 0 && len < MAX_NAME) {
      memcpy(names[i], cursor, len);
      names[i][len] = '\0';
      i++;
    }
    cursor = *end ? end + 1 : end;
  }
  name_count = i;

  env = getenv("OUROBOROS_FS_WRITE_EXCEPTIONS");
  if (env && strlen(env) < sizeof(exception_env)) {
    snprintf(exception_env, sizeof(exception_env), "%s", env);
    cursor = env;
    while (*cursor && exception_count < 3) {
      char decoded[PATH_MAX];
      size_t n = 0;
      int valid = 1;
      while (*cursor && *cursor != ':') {
        int hi = unhex(*cursor++);
        int lo = *cursor && *cursor != ':' ? unhex(*cursor++) : -1;
        if (hi < 0 || lo < 0 || n + 1 >= sizeof(decoded) || (hi == 0 && lo == 0)) { valid = 0; break; }
        decoded[n++] = (char)((hi << 4) | lo);
      }
      decoded[n] = '\0';
      char canonical[PATH_MAX];
      if (!valid || !realpath(decoded, canonical) || strcmp(decoded, canonical)) break;
      memcpy(exceptions[exception_count++], decoded, n + 1);
      if (*cursor == ':') cursor++;
    }
  }

  env = getenv("LD_PRELOAD");
  if (env != NULL) {
    size_t len = strlen(env);
    if (len >= sizeof(preload_path)) {
      len = sizeof(preload_path) - 1;
    }
    memcpy(preload_path, env, len);
    preload_path[len] = '\0';
  }
}

static int component_denied(const char *component) {
  int i;
  if (component == NULL || component[0] == '\0') {
    return 0;
  }
  load_names();
  for (i = 0; i < name_count; i++) {
    if (lower_eq(component, names[i])) {
      return 1;
    }
  }
  return 0;
}

static int components_denied(const char *path) {
  const char *start;
  const char *cursor;
  char component[MAX_NAME];

  if (path == NULL || path[0] == '\0') {
    return 0;
  }

  start = path;
  for (cursor = path;; cursor++) {
    if (*cursor == '/' || *cursor == '\0') {
      size_t len = (size_t)(cursor - start);
      if (len > 0 && len < MAX_NAME) {
        memcpy(component, start, len);
        component[len] = '\0';
        if (component_denied(component)) {
          return 1;
        }
      }
      if (*cursor == '\0') {
        return 0;
      }
      start = cursor + 1;
    }
  }
}

/* Resolve an existing target or its parent before granting an exception. Missing
 * parents fail closed; mkdir -p creates them one at a time. dirfd is respected. */
static int path_denied_at(int dirfd, const char *path) {
  char absolute[PATH_MAX], canonical[PATH_MAX], parent[PATH_MAX];
  load_names();
  if (!path || !*path) return 0;
  if (!exception_count) return components_denied(path);
  if (*path == '/') {
    if (snprintf(absolute, sizeof(absolute), "%s", path) >= (int)sizeof(absolute)) return 1;
  } else {
    char base[PATH_MAX];
    if (dirfd == AT_FDCWD) {
      if (!getcwd(base, sizeof(base))) return 1;
    } else {
      char fdpath[64];
      snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", dirfd);
      ssize_t n = readlink(fdpath, base, sizeof(base) - 1);
      if (n < 0) return 1;
      base[n] = '\0';
    }
    if (snprintf(absolute, sizeof(absolute), "%s/%s", base, path) >= (int)sizeof(absolute)) return 1;
  }
  if (!realpath(absolute, canonical)) {
    snprintf(parent, sizeof(parent), "%s", absolute);
    char *slash = strrchr(parent, '/');
    if (!slash || !slash[1]) return components_denied(path);
    *slash = '\0';
    char resolved[PATH_MAX];
    if (!realpath(*parent ? parent : "/", resolved)) return components_denied(path);
    if (snprintf(canonical, sizeof(canonical), "%s/%s", resolved, slash + 1) >= (int)sizeof(canonical)) return 1;
  }
  for (int i = 0; i < exception_count; i++) {
    size_t n = strlen(exceptions[i]);
    if (!strncmp(canonical, exceptions[i], n) && (canonical[n] == '/' || !canonical[n])) {
      return components_denied(canonical + n);
    }
  }
  return components_denied(path);
}

static int path_denied(const char *path) { return path_denied_at(AT_FDCWD, path); }

static int creating(int flags) { return (flags & O_CREAT) != 0; }
static int needs_mode(int flags) { return creating(flags) || (flags & O_TMPFILE) == O_TMPFILE; }

int mkdir(const char *path, mode_t mode) {
  static int (*real_mkdir)(const char *, mode_t) = NULL;
  if (path_denied(path)) {
    errno = EROFS;
    return -1;
  }
  if (real_mkdir == NULL) {
    real_mkdir = dlsym(RTLD_NEXT, "mkdir");
  }
  return real_mkdir(path, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode) {
  static int (*real_mkdirat)(int, const char *, mode_t) = NULL;
  if (path_denied_at(dirfd, path)) {
    errno = EROFS;
    return -1;
  }
  if (real_mkdirat == NULL) {
    real_mkdirat = dlsym(RTLD_NEXT, "mkdirat");
  }
  return real_mkdirat(dirfd, path, mode);
}

int open(const char *path, int flags, ...) {
  static int (*real_open)(const char *, int, ...) = NULL;
  mode_t mode = 0;
  if (creating(flags) && path_denied(path)) {
    errno = EROFS;
    return -1;
  }
  if (real_open == NULL) {
    real_open = dlsym(RTLD_NEXT, "open");
  }
  if (needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
    return real_open(path, flags, mode);
  }
  return real_open(path, flags);
}

int openat(int dirfd, const char *path, int flags, ...) {
  static int (*real_openat)(int, const char *, int, ...) = NULL;
  mode_t mode = 0;
  if (creating(flags) && path_denied_at(dirfd, path)) {
    errno = EROFS;
    return -1;
  }
  if (real_openat == NULL) {
    real_openat = dlsym(RTLD_NEXT, "openat");
  }
  if (needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
    return real_openat(dirfd, path, flags, mode);
  }
  return real_openat(dirfd, path, flags);
}

int creat(const char *path, mode_t mode) {
  static int (*real_creat)(const char *, mode_t) = NULL;
  if (path_denied(path)) {
    errno = EROFS;
    return -1;
  }
  if (real_creat == NULL) {
    real_creat = dlsym(RTLD_NEXT, "creat");
  }
  return real_creat(path, mode);
}

/* Python and other large-file builds call these public libc entry points directly.
 * Forward through the same path checks; O_LARGEFILE preserves their open semantics. */
int open64(const char *path, int flags, ...) {
  mode_t mode = 0;
  if (needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  return open(path, flags | O_LARGEFILE, mode);
}

int openat64(int dirfd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if (needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  return openat(dirfd, path, flags | O_LARGEFILE, mode);
}

int creat64(const char *path, mode_t mode) {
  return open64(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int rename(const char *oldpath, const char *newpath) {
  static int (*real_rename)(const char *, const char *) = NULL;
  if (path_denied(newpath)) {
    errno = EROFS;
    return -1;
  }
  if (real_rename == NULL) {
    real_rename = dlsym(RTLD_NEXT, "rename");
  }
  return real_rename(oldpath, newpath);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
  static int (*real_renameat)(int, const char *, int, const char *) = NULL;
  if (path_denied_at(newdirfd, newpath)) {
    errno = EROFS;
    return -1;
  }
  if (real_renameat == NULL) {
    real_renameat = dlsym(RTLD_NEXT, "renameat");
  }
  return real_renameat(olddirfd, oldpath, newdirfd, newpath);
}

int link(const char *oldpath, const char *newpath) {
  static int (*real_link)(const char *, const char *) = NULL;
  if (path_denied(newpath)) {
    errno = EROFS;
    return -1;
  }
  if (real_link == NULL) {
    real_link = dlsym(RTLD_NEXT, "link");
  }
  return real_link(oldpath, newpath);
}

int symlink(const char *target, const char *linkpath) {
  static int (*real_symlink)(const char *, const char *) = NULL;
  if (path_denied(linkpath) || path_denied(target)) {
    errno = EROFS;
    return -1;
  }
  if (real_symlink == NULL) {
    real_symlink = dlsym(RTLD_NEXT, "symlink");
  }
  return real_symlink(target, linkpath);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath) {
  static int (*real_symlinkat)(const char *, int, const char *) = NULL;
  if (path_denied_at(newdirfd, linkpath) || path_denied(target)) {
    errno = EROFS;
    return -1;
  }
  if (real_symlinkat == NULL) {
    real_symlinkat = dlsym(RTLD_NEXT, "symlinkat");
  }
  return real_symlinkat(target, newdirfd, linkpath);
}

/* Keep LD_PRELOAD on exec so `env -u LD_PRELOAD git init` does not drop the net. */
static char **with_preload(char *const envp[]) {
  static char preload_entry[4096 + 16];
  static char deny_entry[sizeof(deny_env) + 32];
  static char exception_entry[sizeof(exception_env) + 48];
  int count = 0, kept = 0;
  load_names();
  if (!preload_path[0]) return NULL;
  snprintf(preload_entry, sizeof(preload_entry), "LD_PRELOAD=%s", preload_path);
  snprintf(deny_entry, sizeof(deny_entry), "OUROBOROS_FS_DENY=%s", deny_env);
  snprintf(exception_entry, sizeof(exception_entry), "OUROBOROS_FS_WRITE_EXCEPTIONS=%s", exception_env);
  if (envp) while (envp[count]) count++;
  char **copy = malloc((size_t)(count + 4) * sizeof(char *));
  if (!copy) return NULL;
  for (int i = 0; i < count; i++) {
    if (strncmp(envp[i], "LD_PRELOAD=", 11) && strncmp(envp[i], "OUROBOROS_FS_DENY=", 17) && strncmp(envp[i], "OUROBOROS_FS_WRITE_EXCEPTIONS=", 28)) copy[kept++] = envp[i];
  }
  copy[kept++] = preload_entry;
  copy[kept++] = deny_entry;
  copy[kept++] = exception_entry;
  copy[kept] = NULL;
  return copy;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
  static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
  char **patched;
  int rc;
  if (real_execve == NULL) {
    real_execve = dlsym(RTLD_NEXT, "execve");
  }
  patched = with_preload(envp);
  rc = real_execve(pathname, argv, patched ? patched : envp);
  free(patched);
  return rc;
}

/* execvp is used by env(1); libc's internal execve does not use interposition. */
extern char **environ;
__attribute__((constructor)) static void capture_policy(void) { load_names(); }

int execvpe(const char *file, char *const argv[], char *const envp[]) {
  static int (*real_execvpe)(const char *, char *const[], char *const[]) = NULL;
  if (!real_execvpe) real_execvpe = dlsym(RTLD_NEXT, "execvpe");
  char **patched = with_preload(envp);
  int rc = real_execvpe(file, argv, patched ? patched : envp);
  free(patched);
  return rc;
}

int execvp(const char *file, char *const argv[]) { return execvpe(file, argv, environ); }
int execv(const char *file, char *const argv[]) { return execve(file, argv, environ); }
