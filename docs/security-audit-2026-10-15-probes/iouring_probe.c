// Probe: can the jailed process do filesystem/network work through io_uring
// opcodes, which run in kernel worker context — invisible to a ptrace observer
// and NOT filtered by seccomp (which only sees io_uring_setup/enter)?
// CC0 test probe.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct io_uring_sqe_ {
  __u8 opcode, flags; __u16 ioprio; __s32 fd; union { __u64 off, addr; };
  __u32 len; union { __u64 off2, addr2; }; __u32 flags2; __u64 user_data;
  union { __u16 buf_index; __u64 pad[3]; }; __u32 personality; __u32 splice_fd_in;
  __u64 __pad2[2];
};
struct io_uring_cqe_ { __u64 user_data; __s32 res; __u32 flags; };
struct io_uring_params_ { __u32 sq_entries, cq_entries, flags, sq_thread_cpu,
  sq_thread_idle, features, wq_fd, resv[3]; __u64 sq_off, cq_off; ...; };

struct params_compat {
  __u32 sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle, features, wq_fd, resv[3];
  struct { __u32 head, tail, ring_mask, ring_entries, flags, dropped, array, resv1, resv2; } sq_off;
  struct { __u32 head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1, resv2; } cq_off;
};

int main(int argc, char **argv) {
  const char *target = argc > 1 ? argv[1] : "/tmp/iouring_probe_out";
  struct params_compat p;
  memset(&p, 0, sizeof p);
  int ring = syscall(__NR_io_uring_setup, 4, &p);
  if (ring < 0) { printf("SETUP: %s\n", strerror(errno)); return 1; }
  printf("SETUP: ok ring=%d features=0x%x\n", ring, p.features);

  // Submit IORING_OP_OPENAT (opcode 18) + IORING_OP_WRITE (7) without any syscall
  // the observer can attribute: single io_uring_enter.
  void *sq_ring = mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring, p.sq_off.head ? 0 : 0);
  (void)sq_ring;
  // Simpler deterministic path: use liburing-style registered ops via enter with SQEs
  // is unavoidable complexity here — instead probe which opcodes the kernel accepts
  // by submitting one OP at a time via io_uring_enter and reading the CQE.
  // We do OP_OPENAT directly into the target path.
  struct io_uring_sqe_ sqe; memset(&sqe, 0, sizeof sqe);
  sqe.opcode = 18 /*IORING_OP_OPENAT*/; sqe.fd = AT_FDCWD;
  sqe.addr = (unsigned long)target; sqe.len = O_WRONLY|O_CREAT|O_APPEND; sqe.off2 = 0600;
  // A real submission needs mmap'ed rings; fall back to probing opcode support:
  // io_uring_register with IORING_REGISTER_OP=? not available. Report setup-only.
  printf("NOTE: full SQE submit requires mmap rings; see iouring2.py\n");
  return 0;
}
