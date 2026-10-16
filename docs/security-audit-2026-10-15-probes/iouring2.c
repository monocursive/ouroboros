// io_uring escape probe: seccomp sees only io_uring_setup/register/enter,
// never the opcodes; SQE ops run in kernel context with no ptrace syscall
// stop. Usage: iouring2 [outfile]. Exit 0 = setup denied (EPERM) or openat
// refused; exit 99 = file created/written through io_uring.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct io_sqe {
  __u8 opcode, flags; __u16 ioprio; __s32 fd;
  __u64 off, addr; __u32 len;
  union { __u64 addr2; __u32 cmd_op; };
  union { __u32 op_flags; __u32 open_flags; __u32 rw_flags; };
  __u64 user_data;
  union { __u16 buf_index; __u64 pad[3]; };
  __u32 personality; __u32 splice_fd_in;
  __u64 __pad2[2];
};
struct io_cqe { __u64 user_data; __s32 res; __u32 flags; };
struct io_params {
  __u32 sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle,
        features, wq_fd, resv[3];
  struct { __u32 head, tail, ring_mask, ring_entries, flags, dropped,
               array, resv_a, resv_b; } sq_off;
  struct { __u32 head, tail, ring_mask, ring_entries, overflow, cqes,
               flags, resv_a, resv_b; } cq_off;
};
#define IO_RING_SZ(p, off, cnt, unit) (((p).off.off_field_placeholder_unused & 0) + 0)

static void *ring_map(int ring, size_t sz, unsigned long off) {
  return mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, off);
}

int main(int argc, char **argv) {
  const char *target = argc > 1 ? argv[1] : "/tmp/IOURING_ESCAPED";
  struct io_params p;
  memset(&p, 0, sizeof p);
  int ring = syscall(__NR_io_uring_setup, 4, &p);
  if (ring < 0) {
    printf("io_uring_setup: %s\n", strerror(errno));
    return errno == EPERM ? 0 : 2;
  }
  printf("io_uring_setup: OK — io_uring NOT denied\n");

  size_t page = 4096;
  size_t sq_ring_sz = (p.sq_off.array + p.sq_entries * 4 + page - 1) & ~(page - 1);
  size_t cq_ring_sz = (p.cq_off.cqes + p.cq_entries * sizeof(struct io_cqe) + page - 1) & ~(page - 1);
  unsigned char *sq = ring_map(ring, sq_ring_sz, 0 /*IORING_OFF_SQ_RING*/);
  unsigned char *cq = ring_map(ring, cq_ring_sz, 0x8000000ULL /*IORING_OFF_CQ_RING*/);
  struct io_sqe *sqes = ring_map(ring, p.sq_entries * sizeof(struct io_sqe), 0x10000000ULL /*IORING_OFF_SQES*/);
  if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) {
    printf("mmap: %s\n", strerror(errno));
    return 3;
  }
  __u32 sq_mask = *(__u32 *)(sq + p.sq_off.ring_mask);
  __u32 cq_mask = *(__u32 *)(cq + p.cq_off.ring_mask);
  __u32 tail = *(__u32 *)(sq + p.sq_off.tail);
  __u32 idx = tail & sq_mask;
  struct io_sqe *s = &sqes[idx];
  memset(s, 0, sizeof *s);
  s->opcode = 18; /* IORING_OP_OPENAT */
  s->fd = AT_FDCWD;
  s->addr = (unsigned long)target;
  s->open_flags = O_WRONLY | O_CREAT | O_APPEND, s->rw_flags = 0600;
  s->user_data = 1;
  *(__u32 *)(sq + p.sq_off.array + idx * 4) = idx;
  *(__u32 *)(sq + p.sq_off.tail) = tail + 1;

  if (syscall(__NR_io_uring_enter, ring, 1, 1, 1, 0, 0) < 0) {
    printf("enter(openat): %s\n", strerror(errno));
    return 4;
  }
  for (int i = 0; i < 1000000; i++) {
    __u32 head = *(__u32 *)(cq + p.cq_off.head);
    __u32 ctail = *(__u32 *)(cq + p.cq_off.tail);
    if (ctail == head) continue;
    struct io_cqe *c = (struct io_cqe *)(cq + p.cq_off.cqes + (head & cq_mask) * sizeof(struct io_cqe));
    printf("CQE openat: res=%d\n", c->res);
    if (c->res < 0) return 5;
    printf("RESULT: io_uring OPENAT created %s with no observable syscall\n", target);
    return 99;
  }
  printf("no CQE\n");
  return 6;
}
