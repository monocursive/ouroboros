/* Entitled ES lifecycle experiment. This does not produce jail receipts. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
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

#define MAX_MEMBERS 2048
struct member { audit_token_t token; bool live; };
static struct member members[MAX_MEMBERS];
static size_t count;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t last_sequence;
static bool sequence_seen, gap, stopping;
static volatile sig_atomic_t cancelled;
static dispatch_semaphore_t synchronized;
extern char **environ;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void cancel(int sig) { (void)sig; cancelled = 1; }

static void print_token(audit_token_t token) {
    printf("[");
    for (int i = 0; i < 8; ++i) printf("%s%u", i ? "," : "", token.val[i]);
    printf("]");
}

/* Caller holds lock so diagnostics cannot interleave with event records. */
static int signal_member(audit_token_t token, int sig) {
    int error = proc_signal_with_audittoken(&token, sig);
    if (error && error != ESRCH) {
        gap = true;
        printf("{\"kind\":\"signal_error\",\"signal\":%d,\"errno\":%d,\"token\":", sig, error);
        print_token(token);
        printf("}\n");
    }
    return error;
}

/* All observed processes are in the kernel-scoped descendant client. */
static void event(const es_message_t *message) {
    pthread_mutex_lock(&lock);
    if (message->version < 4) gap = true;
    else {
        if (sequence_seen && message->global_seq_num != last_sequence + 1) gap = true;
        last_sequence = message->global_seq_num;
        sequence_seen = true;
    }
    const es_process_t *process;
    const char *kind;
    bool exited = false;
    switch (message->event_type) {
    case ES_EVENT_TYPE_NOTIFY_FORK:
        process = message->event.fork.child; kind = "fork"; break;
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        process = message->event.exec.target; kind = "exec"; break;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        process = message->process; kind = "exit"; exited = true; break;
    default:
        gap = true; pthread_mutex_unlock(&lock); return;
    }
    audit_token_t token = process->audit_token;
    if (audit_token_to_pid(token) != getpid()) {
        size_t i;
        for (i = 0; i < count; ++i) {
            if (audit_token_to_pid(members[i].token) == audit_token_to_pid(token) &&
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
        printf("{\"kind\":\"%s\",\"sequence\":%llu,\"token\":", kind,
               (unsigned long long)last_sequence);
        print_token(token);
        printf(",\"actor_token\":"); print_token(message->process->audit_token);
        printf("}\n");
    }
    pthread_mutex_unlock(&lock);
}

static bool drain(es_client_t *client) {
    if (es_sync_client(client, ^{ dispatch_semaphore_signal(synchronized); }) != ES_RETURN_SUCCESS) return false;
    return dispatch_semaphore_wait(synchronized, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0;
}

static size_t signal_members(int sig) {
    size_t live = 0;
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < count; ++i) {
        if (!members[i].live) continue;
        int error = signal_member(members[i].token, sig);
        if (error == ESRCH) members[i].live = false;
        else {
            ++live;
        }
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

int main(int argc, char **argv) {
    bool probe = argc == 2 && !strcmp(argv[1], "--probe");
    if (!probe && (argc < 5 || strcmp(argv[3], "--"))) return 64;
    char *end = NULL;
    long seconds = probe ? 0 : strtol(argv[1], &end, 10);
    if (!probe && (!end || *end || seconds < 1 || seconds > 10)) return 64;
    setvbuf(stdout, NULL, _IONBF, 0);
    synchronized = dispatch_semaphore_create(0);
    signal(SIGTERM, cancel);
    signal(SIGINT, cancel);
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client,
        ^(es_client_t *c, const es_message_t *m) { (void)c; event(m); });
    printf("{\"kind\":\"capability\",\"result\":%d,\"workload_released\":false}\n", result);
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) return 125;
    if (probe) return es_delete_client(client) == ES_RETURN_SUCCESS ? 0 : 125;
    es_event_type_t types[] = {ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT};
    if (es_subscribe(client, types, 3) != ES_RETURN_SUCCESS || !drain(client)) return 125;

    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr) || posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED)) return 125;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) ||
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600) ||
        posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO)) return 125;
    pid_t child;
    int error = posix_spawn(&child, argv[4], &actions, &attr, argv + 4, environ);
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&actions);
    if (error) {
        pthread_mutex_lock(&lock);
        printf("{\"kind\":\"spawn_error\",\"errno\":%d}\n", error);
        pthread_mutex_unlock(&lock);
        return 125;
    }
    bool admitted = false;
    if (drain(client)) {
        pthread_mutex_lock(&lock);
        for (size_t i = 0; i < count; ++i) {
            if (!gap && members[i].live && audit_token_to_pid(members[i].token) == child) {
                error = signal_member(members[i].token, SIGCONT);
                if (!error) admitted = true;
            }
        }
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_lock(&lock);
    printf("{\"kind\":\"release\",\"pid\":%d,\"released\":%s}\n", child, admitted ? "true" : "false");
    pthread_mutex_unlock(&lock);
    /* An unreaped direct child cannot have its PID reused. If admission fails,
       it is still suspended and has not executed workload code. */
    if (!admitted) kill(child, SIGKILL);
    double deadline = now() + seconds;
    while (admitted && !cancelled && now() < deadline) {
        pthread_mutex_lock(&lock);
        bool lost = gap;
        pthread_mutex_unlock(&lock);
        if (lost) break;
        usleep(10000);
    }
    pthread_mutex_lock(&lock);
    stopping = true;
    pthread_mutex_unlock(&lock);
    double stop = now();
    bool synced = true;
    size_t live;
    do {
        live = signal_members(SIGKILL);
        synced = drain(client);
        if (!synced) break;
        /* The audit-token signal API rejects signal zero with EINVAL.
           Drain EXIT events and count observed members instead. */
        live = live_members();
        if (live) usleep(10000);
    } while (live && now() - stop < 5);
    int status;
    bool reaped = waitpid(child, &status, WNOHANG) == child;
    pthread_mutex_lock(&lock);
    printf("{\"kind\":\"settled\",\"observed_live_members\":%zu,\"gap\":%s,"
           "\"synced\":%s,\"root_reaped\":%s,\"termination_ms\":%.3f,"
           "\"lifetime_contract_verified\":false}\n", live, gap ? "true" : "false",
           synced ? "true" : "false", reaped ? "true" : "false", (now() - stop) * 1000);
    bool complete = admitted && !live && !gap && synced && reaped;
    pthread_mutex_unlock(&lock);
    /* Exit closes the experimental client. Do not equate observed members
       with a complete tree or a successful production final-drain protocol. */
    return complete ? 0 : 125;
}
