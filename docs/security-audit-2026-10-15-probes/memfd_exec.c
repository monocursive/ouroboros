// memfd anonymous-exec probe: execveat on a memfd gives the exec-confirm
// logic an image with no path. Exit 99 = memfd script executed.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  int fd = syscall(__NR_memfd_create, "payload", 0 /*MFD_EXEC as 0x0010 is newer; try both*/);
  if (fd < 0) { printf("memfd_create: %s\n", strerror(errno)); return 1; }
  const char *script = "#!/bin/sh\necho MEMFD_EXEC_OK > /tmp/memfd_marker\n";
  if (write(fd, script, strlen(script)) < 0) { printf("write: %s\n", strerror(errno)); return 2; }
  char path[64];
  snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
  char *const av[] = {(char *)"payload", NULL};
  char *const ev[] = {NULL};
  execveat(fd, "", av, ev, AT_EMPTY_PATH);
  printf("execveat(memfd): %s\n", strerror(errno));
  // second try via /proc path
  execve(path, av, ev);
  printf("execve(/proc/self/fd): %s\n", strerror(errno));
  return 3;
}
