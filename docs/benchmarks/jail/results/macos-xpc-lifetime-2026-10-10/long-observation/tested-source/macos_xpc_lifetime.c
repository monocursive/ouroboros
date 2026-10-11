/* Isolated-VM app-embedded XPC lifecycle research. No userspace cleanup. */
#define main native_fixture_main
#include "macos_native.c"
#undef main
#include <sys/sysctl.h>
#include <xpc/xpc.h>

static bool started;

static void service_peer(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            printf("{\"kind\":\"service_connection_error\",\"description\":\"%s\"}\n",
                   xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
            return; /* No signalling or workload teardown in this handler. */
        }
        if (xpc_get_type(event) != XPC_TYPE_DICTIONARY || started) return;
        started = true;
        const char *directory = xpc_dictionary_get_string(event, "directory");
        const char *fixture = xpc_dictionary_get_string(event, "fixture");
        int64_t host = xpc_dictionary_get_int64(event, "host_pid");
        if (!directory || !fixture || host <= 1 || host > INT32_MAX) _exit(64);
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/service.jsonl", directory) >= (int)sizeof(path)) _exit(64);
        int log = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (log < 0 || dup2(log, STDOUT_FILENO) < 0) _exit(3);
        close(log);
        info(getpid(), "service");
        printf("{\"kind\":\"request_received\",\"host_pid\":%lld}\n", (long long)host);
        char host_text[32], service_text[32];
        snprintf(host_text, sizeof(host_text), "%lld", (long long)host);
        snprintf(service_text, sizeof(service_text), "%d", getpid());
        if (setenv("OURO_RESEARCH_GUARDIAN_PID", host_text, 1) ||
            setenv("OURO_RESEARCH_WARD_PID", service_text, 1)) _exit(3);
        posix_spawnattr_t attr;
        posix_spawn_file_actions_t actions;
        if (posix_spawnattr_init(&attr) || posix_spawn_file_actions_init(&actions) ||
            posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT)) _exit(4);
        if (snprintf(path, sizeof(path), "%s/workload.jsonl", directory) >= (int)sizeof(path) ||
            posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, path, O_WRONLY | O_CREAT | O_EXCL, 0600) ||
            posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO)) _exit(4);
        char *args[] = {"/usr/bin/sandbox-exec", "-p",
            "(version 1)(allow default)(deny signal)(allow signal (target same-sandbox))",
            (char *)fixture, "tree-spawn", (char *)directory, NULL};
        pid_t child;
        int rc = posix_spawn(&child, args[0], &actions, &attr, args, environ);
        posix_spawnattr_destroy(&attr); posix_spawn_file_actions_destroy(&actions);
        printf("{\"kind\":\"spawn\",\"rc\":%d,\"pid\":%d}\n", rc, rc ? 0 : child);
        if (rc) _exit(4);
        xpc_object_t reply = xpc_dictionary_create_reply(event);
        if (!reply) _exit(4);
        xpc_dictionary_set_bool(reply, "started", true);
        xpc_connection_send_message(peer, reply);
        xpc_release(reply);
        /* Return to libxpc. No exit, cancellation, or death cleanup handler. */
    });
    xpc_connection_resume(peer);
}

static int host(const char *service, const char *directory, const char *fixture) {
    info(getpid(), "host");
    xpc_connection_t connection = xpc_connection_create(service, NULL);
    if (!connection) return 4;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            printf("{\"kind\":\"host_connection_error\",\"description\":\"%s\"}\n",
                   xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
        }
    });
    xpc_connection_resume(connection);
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, "directory", directory);
    xpc_dictionary_set_string(request, "fixture", fixture);
    xpc_dictionary_set_int64(request, "host_pid", getpid());
    xpc_connection_send_message_with_reply(connection, request, dispatch_get_main_queue(), ^(xpc_object_t response) {
        printf("{\"kind\":\"host_reply\",\"started\":%s}\n",
               xpc_get_type(response) == XPC_TYPE_DICTIONARY && xpc_dictionary_get_bool(response, "started") ? "true" : "false");
    });
    xpc_release(request);
    dispatch_main();
    return 0;
}

int main(int argc, char **argv) {
    int virtualized = 0; size_t count = sizeof(virtualized);
    if (sysctlbyname("kern.hv_vmm_present", &virtualized, &count, NULL, 0) || virtualized != 1) {
        fputs("Research helper requires an isolated VM.\n", stderr); return 125;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGTERM, SIG_IGN); signal(SIGALRM, timeout_exit); alarm(20);
    if (argc == 5 && !strcmp(argv[1], "--host")) {
        /* LaunchServices does not inherit the launcher's stdout. Record the
         * host's own identity in a task-owned file in both launch modes. */
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/host.jsonl", argv[3]) >= (int)sizeof(path)) return 64;
        int log = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (log < 0 || dup2(log, STDOUT_FILENO) < 0) return 3;
        close(log);
        return host(argv[2], argv[3], argv[4]);
    }
    if (argc == 1) { xpc_main(service_peer); return 0; }
    return 64;
}
