/* Reciprocal ES custody experiment, NOT a production execution backend.
 * Two independently subscribed, descendant-scoped clients protect a known
 * fixture if either custodian dies. Simultaneous loss and dropped fork events
 * are deliberately NOT claimed safe. No jail receipts are produced. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_MEMBERS 4096
#define PEER_READ 198
#define PEER_WRITE 199
struct member { audit_token_t token; bool live; };
static struct member members[MAX_MEMBERS];
static size_t count;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static dispatch_semaphore_t synchronized;
static uint64_t sequence;
static bool sequence_seen, gap, stopping, root_exited;
static pid_t root_pid;
static volatile sig_atomic_t cancelled, injected_gap;
extern char **environ;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void cancel(int sig) { (void)sig; cancelled = 1; }
static void inject_gap(int sig) { (void)sig; injected_gap = 1; }

static void token_json(audit_token_t token) {
    putchar('[');
    for (int i = 0; i < 8; ++i) printf("%s%u", i ? "," : "", token.val[i]);
    putchar(']');
}

/* lock held: PID-version-fenced signalling, never kill(pid) for an ES member. */
static int signal_member(audit_token_t token, int sig) {
    int error = proc_signal_with_audittoken(&token, sig);
    if (error && error != ESRCH) {
        gap = true;
        printf("{\"kind\":\"signal_error\",\"errno\":%d,\"token\":", error);
        token_json(token);
        puts("}");
    }
    return error;
}

static void event(const es_message_t *m) {
    pthread_mutex_lock(&lock);
    if (m->version < 4) gap = true;
    else {
        if (sequence_seen && m->global_seq_num != sequence + 1) gap = true;
        sequence = m->global_seq_num;
        sequence_seen = true;
    }
    const es_process_t *p;
    const char *kind;
    bool exited = false;
    switch (m->event_type) {
    case ES_EVENT_TYPE_NOTIFY_FORK: p = m->event.fork.child; kind = "fork"; break;
    case ES_EVENT_TYPE_NOTIFY_EXEC: p = m->event.exec.target; kind = "exec"; break;
    case ES_EVENT_TYPE_NOTIFY_EXIT: p = m->process; kind = "exit"; exited = true; break;
    default: gap = true; pthread_mutex_unlock(&lock); return;
    }
    audit_token_t token = p->audit_token;
    pid_t pid = audit_token_to_pid(token);
    if (pid != getpid()) {
        size_t i;
        for (i = 0; i < count; ++i) {
            if (audit_token_to_pid(members[i].token) == pid &&
                audit_token_to_pidversion(members[i].token) == audit_token_to_pidversion(token)) break;
        }
        if (i == count) {
            if (count == MAX_MEMBERS) gap = true;
            else members[count++] = (struct member){.token = token};
        }
        if (i < count) {
            members[i].live = !exited;
            if (stopping && !exited) signal_member(token, SIGKILL);
        }
        if (pid == root_pid && exited) root_exited = true;
        printf("{\"kind\":\"%s\",\"sequence\":%llu,\"token\":", kind, (unsigned long long)sequence);
        token_json(token);
        printf(",\"actor_token\":"); token_json(m->process->audit_token);
        puts("}");
    }
    pthread_mutex_unlock(&lock);
}

static bool drain(es_client_t *client) {
    return es_sync_client(client, ^{ dispatch_semaphore_signal(synchronized); }) == ES_RETURN_SUCCESS &&
        dispatch_semaphore_wait(synchronized, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0;
}

static size_t signal_members(void) {
    size_t live = 0;
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < count; ++i) {
        if (!members[i].live) continue;
        int error = signal_member(members[i].token, SIGKILL);
        if (error == ESRCH) members[i].live = false;
        else ++live;
    }
    pthread_mutex_unlock(&lock);
    return live;
}

static size_t live_members(void) {
    size_t live = 0;
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < count; ++i) live += members[i].live;
    pthread_mutex_unlock(&lock);
    return live;
}

static bool nonblocking_private(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 &&
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

/* Only the two custodians own these descriptors. Workload launch closes them.
 * EOF and heartbeat expiry cover death and SIGSTOP independently of PID lists. */
static const char *peer_status(int input, int output, double *heard, double *sent) {
    char bytes[128];
    ssize_t n;
    do {
        n = read(input, bytes, sizeof(bytes));
        if (n > 0) *heard = now();
    } while (n > 0);
    if (n == 0) return "peer_eof";
    if (errno != EAGAIN && errno != EINTR) return "peer_read_error";
    if (now() - *sent >= .05) {
        n = write(output, "H", 1);
        if (n != 1) return "peer_write_error";
        *sent = now();
    }
    if (now() - *heard >= .75) return "peer_timeout";
    return NULL;
}

int main(int argc, char **argv) {
    bool probe = argc == 2 && !strcmp(argv[1], "--probe");
    bool guardian = !probe && argc >= 7 && !strcmp(argv[1], "--guardian");
    bool ward = !probe && argc >= 6 && !strcmp(argv[1], "--ward");
    if (!probe && !guardian && !ward) return 64;
    int separator = guardian ? 5 : 4;
    char *end = NULL;
    long seconds = probe ? 0 : strtol(argv[2], &end, 10);
    if (!probe && (!end || *end || seconds < 1 || seconds > 10 || strcmp(argv[separator], "--"))) return 64;
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, cancel);
    signal(SIGINT, cancel);
    signal(SIGUSR1, inject_gap);
    synchronized = dispatch_semaphore_create(0);
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client,
        ^(es_client_t *c, const es_message_t *m) { (void)c; event(m); });
    printf("{\"kind\":\"capability\",\"result\":%d,\"workload_released\":false}\n", result);
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) return 125;
    if (probe) return es_delete_client(client) == ES_RETURN_SUCCESS ? 0 : 125;
    es_event_type_t types[] = {ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT};
    if (es_subscribe(client, types, 3) != ES_RETURN_SUCCESS || !drain(client)) return 125;
    audit_token_t self_token;
    mach_msg_type_number_t token_count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&self_token, &token_count) != KERN_SUCCESS) return 125;

    int input = PEER_READ, output = PEER_WRITE;
    int to_ward[2] = {-1, -1}, to_guardian[2] = {-1, -1};
    if (guardian) {
        if (pipe(to_ward) || pipe(to_guardian)) return 125;
        input = to_guardian[0]; output = to_ward[1];
    }
    if (!nonblocking_private(input) || !nonblocking_private(output)) return 125;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t actions;
    if (posix_spawnattr_init(&attr) || posix_spawn_file_actions_init(&actions) ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT) ||
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) ||
        posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO)) return 125;
    char **child_argv = argv + separator + 1;
    char **ward_argv = NULL;
    if (guardian) {
        if (posix_spawn_file_actions_adddup2(&actions, to_ward[0], PEER_READ) ||
            posix_spawn_file_actions_adddup2(&actions, to_guardian[1], PEER_WRITE) ||
            posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, argv[4], O_WRONLY | O_CREAT | O_EXCL, 0600)) return 125;
        /* guardian seconds workload-log ward-events -- command args... */
        ward_argv = calloc((size_t)argc + 1, sizeof(char *));
        if (!ward_argv) return 125;
        ward_argv[0] = argv[0]; ward_argv[1] = "--ward";
        ward_argv[2] = argv[2]; ward_argv[3] = argv[3]; ward_argv[4] = "--";
        for (int i = 6; i < argc; ++i) ward_argv[i - 1] = argv[i];
        child_argv = ward_argv;
    } else if (posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, argv[3], O_WRONLY | O_CREAT | O_EXCL, 0600) ||
               posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO)) return 125;
    pid_t child;
    int error = posix_spawn(&child, child_argv[0], &actions, &attr, child_argv, environ);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    free(ward_argv);
    if (guardian) { close(to_ward[0]); close(to_guardian[1]); }
    if (error) { printf("{\"kind\":\"spawn_error\",\"errno\":%d}\n", error); return 125; }
    pthread_mutex_lock(&lock);
    root_pid = child;
    pthread_mutex_unlock(&lock);
    bool admitted = false;
    if (drain(client)) {
        pthread_mutex_lock(&lock);
        for (size_t i = 0; i < count; ++i) {
            if (!gap && members[i].live && audit_token_to_pid(members[i].token) == child) {
                if (!signal_member(members[i].token, SIGCONT)) admitted = true;
            }
        }
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_lock(&lock);
    printf("{\"kind\":\"release\",\"custodian\":\"%s\",\"custodian_pid\":%d,\"child_pid\":%d,\"released\":%s,\"custodian_token\":",
        guardian ? "guardian" : "ward", getpid(), child, admitted ? "true" : "false");
    token_json(self_token);
    puts("}");
    pthread_mutex_unlock(&lock);
    /* The unreaped direct child cannot have its PID reused. */
    if (!admitted) kill(child, SIGKILL);
    double deadline = now() + seconds, heard = now(), sent = 0;
    const char *reason = admitted ? NULL : "admission_failed";
    while (!reason) {
        pthread_mutex_lock(&lock);
        if (injected_gap) gap = true;
        bool lost = gap, ended = root_exited;
        pthread_mutex_unlock(&lock);
        if (lost) reason = "event_integrity";
        else if (ended) reason = "child_exit";
        else if (cancelled) reason = "cancelled";
        else if (now() >= deadline) reason = "wall_expiry";
        else reason = peer_status(input, output, &heard, &sent);
        if (!reason) usleep(10000);
    }
    pthread_mutex_lock(&lock);
    stopping = true;
    printf("{\"kind\":\"stopping\",\"reason\":\"%s\"}\n", reason);
    pthread_mutex_unlock(&lock);
    double stop = now();
    bool synced = true;
    size_t live;
    do {
        signal_members();
        synced = drain(client);
        live = live_members();
        if (!synced) break;
        if (live) usleep(10000);
    } while (live && now() - stop < 5);
    int status = 0;
    bool reaped = waitpid(child, &status, WNOHANG) == child;
    pthread_mutex_lock(&lock);
    printf("{\"kind\":\"settled\",\"observed_live_members\":%zu,\"gap\":%s,\"synced\":%s,\"root_reaped\":%s,"
        "\"termination_ms\":%.3f,\"lifetime_contract_verified\":false}\n", live, gap ? "true" : "false",
        synced ? "true" : "false", reaped ? "true" : "false", (now() - stop) * 1000);
    bool complete = admitted && !live && !gap && synced && reaped;
    pthread_mutex_unlock(&lock);
    close(input); close(output);
    bool expected_stop = !strcmp(reason, "wall_expiry") || !strcmp(reason, "cancelled") || (!guardian && !strcmp(reason, "child_exit"));
    return complete && expected_stop ? 0 : 125;
}
