/* Minimal known-needs fixture: no interpreter startup or user lookup. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int flags = argv[1][0] == 'w' ? O_WRONLY | O_TRUNC : O_RDONLY;
    if (argv[1][0] == 'd') flags |= O_DIRECTORY;
    int fd = open(argv[2], flags);
    if (fd < 0) return 1;
    close(fd);
    return 0;
}
