/* Diagnostic only: two libc spawn paths, one owned /usr/bin/sleep child. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) abort();
    return (long long)value.tv_sec * 1000000000 + value.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 3 || strncmp(argv[1], "/sys/fs/cgroup/", 15) != 0) return 2;
    int direct = strcmp(argv[2], "direct") == 0;
    if (!direct && strcmp(argv[2], "move") != 0) return 2;
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return 3;
    posix_spawnattr_t attr;
    int error = posix_spawnattr_init(&attr);
    if (error != 0) { close(directory); return 4; }
    if (direct) {
        error = posix_spawnattr_setcgroup_np(&attr, directory);
        if (error == 0) error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETCGROUP);
    }
    char *arguments[] = { "/usr/bin/sleep", "30", NULL };
    char *environment[] = { "PATH=/usr/bin:/bin", NULL };
    pid_t child = -1;
    long long began = ns();
    if (error == 0) error = posix_spawn(&child, arguments[0], NULL, &attr, arguments, environment);
    if (error == 0 && !direct) {
        int file = openat(directory, "cgroup.procs", O_WRONLY | O_CLOEXEC);
        char number[32];
        int length = snprintf(number, sizeof(number), "%d", child);
        if (file < 0) error = errno;
        else {
            if (write(file, number, length) != length) error = errno ? errno : EIO;
            close(file);
        }
    }
    long long elapsed = ns() - began;
    posix_spawnattr_destroy(&attr);
    close(directory);
    int verified = 0;
    int reaped = 0;
    if (child > 0) {
        char path[64];
        char membership[4096];
        snprintf(path, sizeof(path), "/proc/%d/cgroup", child);
        int file = open(path, O_RDONLY | O_CLOEXEC);
        if (file >= 0) {
            ssize_t length = read(file, membership, sizeof(membership) - 1);
            if (length > 0) {
                membership[length] = '\0';
                char *newline = strchr(membership, '\n');
                if (newline) *newline = '\0';
                verified = strncmp(membership, "0::", 3) == 0
                    && strcmp(membership + 3, argv[1] + strlen("/sys/fs/cgroup")) == 0;
            }
            close(file);
        }
        kill(child, SIGTERM);
        pid_t waited;
        do { waited = waitpid(child, NULL, 0); } while (waited < 0 && errno == EINTR);
        reaped = waited == child;
    }
    printf("{\"mode\":\"%s\",\"elapsed_ms\":%.6f,\"spawn_errno\":%d,\"membership_verified\":%s,\"owned_child_reaped\":%s}\n",
           argv[2], elapsed / 1000000.0, error, verified ? "true" : "false",
           reaped ? "true" : "false");
    return error == 0 && verified && reaped ? 0 : 1;
}
