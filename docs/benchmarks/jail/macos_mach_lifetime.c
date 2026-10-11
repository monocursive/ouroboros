/* VM-only Mach exception-port lifetime research. Reuse fixture identities,
 * bounded heartbeats and detached-child modes from the debugger experiment. */
#define main ptrace_research_main
#include "macos_ptrace_lifetime.c"
#undef main

static const exception_mask_t masks = EXC_MASK_SYSCALL | EXC_MASK_MACH_SYSCALL | EXC_MASK_BREAKPOINT;
static const exception_behavior_t behavior = EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES;
enum { PORT_CAPACITY = 32 }; /* exception masks occupy at most one 32-bit word */

static void exception_state(const char *role, const char *phase) {
    exception_mask_t observed[PORT_CAPACITY];
    mach_port_t ports[PORT_CAPACITY];
    exception_behavior_t behaviors[PORT_CAPACITY];
    thread_state_flavor_t flavors[PORT_CAPACITY];
    mach_msg_type_number_t count = PORT_CAPACITY;
    kern_return_t rc = task_get_exception_ports(mach_task_self(), masks, observed, &count,
                                               ports, behaviors, flavors);
    exception_mask_t live = 0, dead = 0;
    if (rc == KERN_SUCCESS) {
        for (unsigned i = 0; i < count; ++i) {
            if (ports[i] == MACH_PORT_DEAD) dead |= observed[i];
            else if (MACH_PORT_VALID(ports[i])) {
                mach_port_type_t type = 0;
                if (mach_port_type(mach_task_self(), ports[i], &type) == KERN_SUCCESS &&
                    (type & MACH_PORT_TYPE_SEND)) live |= observed[i];
                else dead |= observed[i];
                mach_port_deallocate(mach_task_self(), ports[i]);
            }
        }
    }
    printf("{\"kind\":\"exception_state\",\"role\":\"%s\",\"phase\":\"%s\",\"rc\":%d,\"live_mask\":%u,\"dead_mask\":%u}\n",
           role, phase, rc, live, dead);
}

static void work(const char *directory, const char *role) {
    signal(SIGALRM, timeout_exit); alarm(20);
    char path[4096], after[4096];
    if (snprintf(path, sizeof(path), "%s/%s.heartbeat", directory, role) >= (int)sizeof(path) ||
        snprintf(after, sizeof(after), "%s/after-owner-loss", directory) >= (int)sizeof(after)) _exit(3);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(3);
    bool reported = false;
    for (;;) {
        if (!reported && access(after, F_OK) == 0) {
            exception_state(role, "after_owner_loss"); reported = true;
        }
        if (write(fd, ".", 1) != 1) _exit(3);
        /* Exercise normal BSD syscalls and a Mach trap, not just CPU looping. */
        (void)getpid();
        mach_port_t thread = mach_thread_self();
        mach_port_deallocate(mach_task_self(), thread);
        usleep(10000);
    }
}

static void child_work(const char *directory, const char *mode) {
    if (!strcmp(mode, "clear-exception")) {
        exception_state("late-child", "before_clear");
        kern_return_t rc = task_set_exception_ports(mach_task_self(), masks, MACH_PORT_NULL,
                                                    behavior, THREAD_STATE_NONE);
        printf("{\"kind\":\"clear_exception\",\"rc\":%d}\n", rc);
        if (rc != KERN_SUCCESS) _exit(4);
    }
    info("late-child"); exception_state("late-child", "before_owner_loss");
    work(directory, "late-child");
}

static int payload(const char *directory, const char *mode, const char *exe) {
    info("root");
    /* The custodian installed the handler on itself before this fork.
     * Inspect inherited state; never attach to the running workload. */
    exception_state("root", "before_owner_loss");
    puts("{\"kind\":\"before_fork\"}");
    char trigger[4096];
    if (snprintf(trigger, sizeof(trigger), "%s/trigger", directory) >= (int)sizeof(trigger)) return 64;
    while (access(trigger, F_OK)) usleep(10000);
    if (!strcmp(mode, "breakpoint-control")) {
        puts("{\"kind\":\"breakpoint_requested\"}");
        __builtin_debugtrap();
        return 4;
    }
    if (strcmp(mode, "root")) {
        pid_t child;
        if (!strcmp(mode, "spawn-group") || !strcmp(mode, "spawn-session")) {
            posix_spawnattr_t attr;
            if (posix_spawnattr_init(&attr) ||
                posix_spawnattr_setflags(&attr, !strcmp(mode, "spawn-group") ? POSIX_SPAWN_SETPGROUP : POSIX_SPAWN_SETSID) ||
                posix_spawnattr_setpgroup(&attr, 0)) return 4;
            char *args[] = {(char *)exe, "--child", (char *)directory, (char *)mode, NULL};
            int error = posix_spawn(&child, exe, NULL, &attr, args, environ);
            posix_spawnattr_destroy(&attr);
            if (error) return error;
        } else {
            child = fork();
            if (child < 0) return 4;
            if (!child) {
                if (strcmp(mode, "fork") && setsid() < 0) _exit(4);
                if (!strcmp(mode, "double-fork")) {
                    pid_t second = fork(); if (second < 0) _exit(4); if (second) _exit(0);
                }
                child_work(directory, mode);
            }
        }
    }
    work(directory, "root");
    return 0;
}

static int custodian(const char *directory, const char *mode, const char *exe) {
    info("custodian");
    mach_port_t channel = MACH_PORT_NULL;
    mach_port_options_t options = {.flags = MPO_EXCEPTION_PORT | MPO_INSERT_SEND_RIGHT};
    kern_return_t rc = mach_port_construct(mach_task_self(), &options, 0, &channel);
    printf("{\"kind\":\"handler_construct\",\"rc\":%d,\"port\":%u,\"flags\":%u}\n", rc, channel, options.flags);
    if (rc != KERN_SUCCESS) return 4;
    rc = task_set_exception_ports(mach_task_self(), masks, channel, behavior, THREAD_STATE_NONE);
    printf("{\"kind\":\"exception_installed\",\"rc\":%d,\"mask\":%u,\"behavior\":%u}\n", rc, masks, (unsigned)behavior);
    if (rc != KERN_SUCCESS) return 4;
    pid_t child = fork();
    if (child < 0) return 4;
    if (!child) {
        signal(SIGALRM, timeout_exit); alarm(20);
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/workload.jsonl", directory) >= (int)sizeof(path)) _exit(4);
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(4);
        close(fd);
        /* Ordinary receive rights are not inherited. Only the kernel's task
         * exception-handler state provides supervision of this child. */
        _exit(payload(directory, mode, exe));
    }
    puts("{\"kind\":\"custodian_ready\"}");
    for (;;) {
        struct { mach_msg_header_t header; char data[8192]; } message;
        kern_return_t rc = mach_msg(&message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                     0, sizeof(message), channel, 100, MACH_PORT_NULL);
        if (rc == MACH_RCV_TIMED_OUT) continue;
        printf("{\"kind\":\"exception_message\",\"rc\":%d,\"id\":%d}\n", rc, rc == KERN_SUCCESS ? message.header.msgh_id : 0);
        /* Do not silently emulate a trapped operation. Such delivery makes
         * the unmodified-workload readiness gate fail and preserves evidence. */
        if (rc == KERN_SUCCESS) mach_msg_destroy(&message.header);
        else return 4;
    }
}

int main(int argc, char **argv) {
    int virtualized = 0; size_t n = sizeof(virtualized);
    if (sysctlbyname("kern.hv_vmm_present", &virtualized, &n, NULL, 0) || virtualized != 1) {
        fputs("Research helper requires an isolated VM.\n", stderr); return 125;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGTERM, SIG_IGN); signal(SIGALRM, timeout_exit); alarm(20);
    if (argc == 4 && !strcmp(argv[1], "--custodian")) return custodian(argv[2], argv[3], argv[0]);
    if (argc == 4 && !strcmp(argv[1], "--child")) child_work(argv[2], argv[3]);
    return 64;
}
