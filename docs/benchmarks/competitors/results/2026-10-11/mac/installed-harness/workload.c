/* Fixed work, a completion record, and in-child timing; no network or secrets. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(4);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    uint64_t start = now(), checksum = 0, count = 0;
    if (!strcmp(argv[1], "noop")) { count = 1; }
    else if (!strcmp(argv[1], "cpu")) {
        uint64_t x = 1;
        for (unsigned i = 0; i < 20000000; ++i) x = x * 6364136223846793005ULL + 1;
        checksum = x; count = 20000000;
    } else if (!strcmp(argv[1], "reads")) {
        char path[80], bytes[4096];
        for (unsigned i = 0; i < 1000; ++i) {
            snprintf(path, sizeof(path), "inputs/f%04u", i);
            int fd = open(path, O_RDONLY); if (fd < 0) return 3;
            ssize_t n = read(fd, bytes, sizeof(bytes)); close(fd);
            if (n != sizeof(bytes)) return 3;
            for (size_t j = 0; j < sizeof(bytes); ++j) checksum += (unsigned char)bytes[j];
            ++count;
        }
    } else if (!strcmp(argv[1], "writes")) {
        char path[80], bytes[1024]; memset(bytes, 'x', sizeof(bytes));
        for (unsigned i = 0; i < 1000; ++i) {
            snprintf(path, sizeof(path), "outputs/f%04u", i);
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0 || write(fd, bytes, sizeof(bytes)) != sizeof(bytes) || close(fd)) return 3;
            checksum += sizeof(bytes); ++count;
        }
    } else if (!strcmp(argv[1], "spawn")) {
        for (unsigned i = 0; i < 100; ++i) {
            pid_t p = fork(); if (p < 0) return 3;
            if (!p) { execl("/usr/bin/true", "true", (char *)NULL); _exit(3); }
            int status; if (waitpid(p, &status, 0) != p || !WIFEXITED(status) || WEXITSTATUS(status)) return 3;
            ++count;
        }
    } else return 2;
    printf("{\"benchmark\":1,\"workload\":\"%s\",\"count\":%llu,\"checksum\":%llu,\"payload_ns\":%llu}\n", argv[1], (unsigned long long)count, (unsigned long long)checksum, (unsigned long long)(now() - start));
    return 0;
}
