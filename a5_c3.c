/* F1 PoC: i386-ABI clone3(CLONE_UNTRACED) under --profile none. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

struct clone_args_c3 {
    unsigned long long flags;
    unsigned long long pidfd;
    unsigned long long child_tid;
    unsigned long long parent_tid;
    unsigned long long exit_signal;
    unsigned long long stack;
    unsigned long long stack_size;
    unsigned long long tls;
};

int main(void) {
    void *page = mmap((void *)0x10000, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return 1; }
    struct clone_args_c3 *args = page;
    memset(args, 0, sizeof *args);
    args->flags = 0x00800000ULL; /* CLONE_UNTRACED */
    args->exit_signal = 17;      /* SIGCHLD */

    unsigned int arg0 = (unsigned int)(unsigned long)page;
    unsigned int arg1 = (unsigned int)sizeof *args;
    unsigned int ret;
    __asm__ volatile(
        "movl %1, %%ebx\n\t"
        "movl %2, %%ecx\n\t"
        "movl $435, %%eax\n\t"
        "int  $0x80\n\t"
        : "=a"(ret)
        : "rm"(arg0), "rm"(arg1)
        : "ecx", "ebx", "memory");
    if (ret == 0) {
        /* we are the clone3 child: untraced by construction */
        printf("UNTRACED CHILD alive, pid=%d\n", getpid());
        fflush(stdout);
        sleep(2);
        _exit(42);
    }
    printf("parent: clone3 returned %u; waiting for untraced child\n", ret);
    fflush(stdout);
    if (ret > 0 && ret < 0xfffff000u) {
        int st = 0;
        waitpid((pid_t)ret, &st, 0);
        printf("untraced child reaped: status %d\n", st);
    }
    return 0;
}
