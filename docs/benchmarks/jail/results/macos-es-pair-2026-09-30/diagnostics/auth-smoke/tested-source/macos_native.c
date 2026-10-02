/* Disposable native lifecycle research fixture, not an ouro-jail backend. */
#include <dlfcn.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

/* Private ABI from Apple XNU; the research report pins the source revision. */
struct unique_info {
    uint8_t uuid[16];
    uint64_t uniqueid, parent_uniqueid;
    int32_t pidversion, original_parent_pidversion;
    uint64_t reserved[2];
};
struct coalition_info { uint64_t ids[2], reserved[3]; };
_Static_assert(sizeof(struct unique_info) == 56, "private ABI size");
extern char **environ;

static void die(const char *what) { perror(what); exit(2); }
static void timeout_exit(int sig) { (void)sig; _exit(90); }

static void info(pid_t pid, const char *role) {
    struct proc_bsdinfo b = {0};
    struct unique_info u = {0};
    struct coalition_info c = {0};
    int br = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof(b));
    int ur = proc_pidinfo(pid, 17, 0, &u, sizeof(u));
    int cr = proc_pidinfo(pid, 20, 0, &c, sizeof(c));
    printf("{\"role\":\"%s\",\"pid\":%d,\"ppid\":%u,\"pgid\":%u,"
           "\"sid\":%d,\"status\":%u,\"bsd_bytes\":%d,\"unique_bytes\":%d,"
           "\"coalition_bytes\":%d,\"uniqueid\":%llu,\"pidversion\":%d,"
           "\"coalitions\":[%llu,%llu]",
           role, pid, b.pbi_ppid, b.pbi_pgid, getsid(pid), b.pbi_status,
           br, ur, cr, (unsigned long long)u.uniqueid, u.pidversion,
           (unsigned long long)c.ids[0], (unsigned long long)c.ids[1]);
    if (pid == getpid()) {
        printf(",\"custody_fds_open\":%s", fcntl(198, F_GETFD) >= 0 || fcntl(199, F_GETFD) >= 0 ? "true" : "false");
        audit_token_t token;
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                                     (task_info_t)&token, &count);
        if (kr != KERN_SUCCESS) exit(3);
        printf(",\"audit_token\":[");
        for (int i = 0; i < 8; ++i) printf("%s%u", i ? "," : "", token.val[i]);
        printf("]");
    }
    puts("}");
}

static void capabilities(void) {
    int (*create)(uint64_t *, uint32_t) = dlsym(RTLD_DEFAULT, "coalition_create");
    int (*terminate)(uint64_t, uint32_t) = dlsym(RTLD_DEFAULT, "coalition_terminate");
    int (*reap)(uint64_t, uint32_t) = dlsym(RTLD_DEFAULT, "coalition_reap");
    uint64_t cid = 0;
    errno = 0;
    int rc = create ? create(&cid, 0) : -2;
    int error = errno;
    printf("{\"probe\":\"coalition_create\",\"symbol_available\":%s,"
           "\"rc\":%d,\"errno\":%d,\"id\":%llu}\n",
           create ? "true" : "false", rc, error, (unsigned long long)cid);
    /* Never operate on an existing coalition, including our inherited one. */
    if (rc == 0) {
        if (!terminate || !reap || terminate(cid, 0) || reap(cid, 0)) die("coalition cleanup");
    }
    int kq = kqueue();
    if (kq < 0) die("kqueue");
    struct kevent change, event;
    EV_SET(&change, getpid(), EVFILT_PROC, EV_ADD | EV_RECEIPT,
           NOTE_FORK | NOTE_TRACK | NOTE_EXIT, 0, NULL);
    struct timespec zero = {0};
    errno = 0;
    rc = kevent(kq, &change, 1, &event, 1, &zero);
    printf("{\"probe\":\"kqueue_note_track\",\"rc\":%d,\"errno\":%d,"
           "\"event_error\":%ld}\n", rc, errno,
           rc == 1 && (event.flags & EV_ERROR) ? (long)event.data : 0);
    close(kq);
    es_client_t *client = NULL;
    es_new_client_result_t es = es_new_descendants_client(&client,
        ^(es_client_t *c, const es_message_t *m) {
            if (m->action_type == ES_ACTION_TYPE_AUTH)
                es_respond_auth_result(c, m, ES_AUTH_RESULT_DENY, false);
        });
    printf("{\"probe\":\"es_new_descendants_client\",\"result\":%d,"
           "\"not_entitled\":%s}\n", es,
           es == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED ? "true" : "false");
    if (es == ES_NEW_CLIENT_RESULT_SUCCESS && es_delete_client(client) != ES_RETURN_SUCCESS) exit(12);
}

static void syscalls(const char *exe) {
    const char *names[] = {"setsid", "setpgid", "spawn-group", "spawn-session", "spawn-normal"};
    for (int i = 0; i < 5; ++i) {
        pid_t child = fork();
        if (child < 0) die("fork");
        if (!child) {
            int before = getpgrp(), rc, error;
            if (i < 2) {
                errno = 0;
                rc = i == 0 ? setsid() : setpgid(0, 0);
                error = errno;
            } else {
                posix_spawnattr_t attr;
                if (posix_spawnattr_init(&attr)) exit(4);
                short flags = i == 2 ? POSIX_SPAWN_SETPGROUP : i == 3 ? POSIX_SPAWN_SETSID : 0;
                if (posix_spawnattr_setflags(&attr, flags) || posix_spawnattr_setpgroup(&attr, 0)) exit(4);
                char *argv[] = {(char *)exe, "self", (char *)names[i], NULL};
                pid_t spawned;
                rc = posix_spawn(&spawned, exe, NULL, &attr, argv, environ);
                error = rc;
                if (!rc) {
                    int status;
                    if (waitpid(spawned, &status, 0) != spawned || status != 0) exit(5);
                }
                posix_spawnattr_destroy(&attr);
            }
            printf("{\"probe\":\"%s\",\"rc\":%d,\"errno\":%d,"
                   "\"before_pgid\":%d,\"after_pgid\":%d,\"pid\":%d}\n",
                   names[i], rc, error, before, getpgrp(), getpid());
            _exit(0);
        }
        int status;
        if (waitpid(child, &status, 0) != child || status != 0) exit(6);
    }
}

static void heartbeat(const char *directory, const char *role, int ready_fd) {
    signal(SIGTERM, !strcmp(role, "plain") ? SIG_DFL : SIG_IGN);
    signal(SIGALRM, timeout_exit);
    alarm(20);
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/%s.heartbeat", directory, role) >= (int)sizeof(path)) exit(7);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) die("heartbeat open");
    info(getpid(), role);
    if (write(ready_fd, "R", 1) != 1) exit(8);
    close(ready_fd);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    bool attempted = false;
    for (;;) {
        if (write(fd, ".", 1) != 1) _exit(9);
        if (!attempted && !strcmp(role, "plain")) {
            char trigger[4096], marker[4096], report[4096];
            if (snprintf(trigger, sizeof(trigger), "%s/after-loss.trigger", directory) >= (int)sizeof(trigger) ||
                snprintf(marker, sizeof(marker), "%s/after-loss.exec", directory) >= (int)sizeof(marker) ||
                snprintf(report, sizeof(report), "%s/after-loss-exec.json", directory) >= (int)sizeof(report)) _exit(17);
            if (access(trigger, F_OK) == 0) {
                attempted = true;
                char *args[] = {"/usr/bin/touch", marker, NULL};
                pid_t child;
                int error = posix_spawn(&child, args[0], NULL, NULL, args, environ);
                int status = -1;
                bool reaped = error == 0 && waitpid(child, &status, 0) == child;
                int output = open(report, O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (output < 0) _exit(18);
                dprintf(output, "{\"spawn_errno\":%d,\"reaped\":%s,\"wait_status\":%d}\n", error, reaped ? "true" : "false", status);
                close(output);
            }
        }
        usleep(10000);
    }
}

static void tree(const char *directory, const char *exe, bool spawn_children) {
    signal(SIGALRM, timeout_exit);
    alarm(20);
    info(getpid(), "root");
    if (spawn_children) {
        const char *variables[] = {"OURO_RESEARCH_GUARDIAN_PID", "OURO_RESEARCH_WARD_PID"};
        const int signals[] = {SIGTERM, SIGKILL};
        for (int i = 0; i < 2; ++i) {
            const char *text = getenv(variables[i]);
            if (!text) exit(14);
            char *end;
            long pid = strtol(text, &end, 10);
            if (*end || pid <= 1 || pid > INT32_MAX) exit(15);
            for (int j = 0; j < 2; ++j) {
                errno = 0;
                int rc = kill((pid_t)pid, signals[j]);
                int error = errno;
                printf("{\"probe\":\"custodian_signal\",\"target\":%ld,\"signal\":%d,\"rc\":%d,\"errno\":%d}\n",
                    pid, signals[j], rc, error);
                if (rc != -1 || error != EPERM) exit(16);
            }
        }
    }
    const char *roles[] = {"plain", "setsid", "double-fork", "stubborn"};
    for (int i = 0; i < 4; ++i) {
        int pipefd[2];
        if (pipe(pipefd)) die("pipe");
        pid_t child = fork();
        if (child < 0) die("fork");
        if (!child) {
            close(pipefd[0]);
            if ((i == 1 || i == 2) && setsid() < 0) die("setsid");
            if (i == 2) {
                pid_t grandchild = fork();
                if (grandchild < 0) die("second fork");
                if (grandchild) _exit(0);
            }
            heartbeat(directory, roles[i], pipefd[1]);
        }
        close(pipefd[1]);
        char byte;
        if (read(pipefd[0], &byte, 1) != 1) exit(10);
        close(pipefd[0]);
        if (i == 2 && waitpid(child, NULL, 0) != child) exit(11);
    }
    if (spawn_children) {
        /* Group/session changes inside posix_spawn bypass filters that only
           deny the separate setsid/setpgid syscall entry points. */
        const char *spawn_roles[] = {"spawn-group", "spawn-session"};
        for (int i = 0; i < 2; ++i) {
            int pipefd[2];
            if (pipe(pipefd)) die("spawn pipe");
            posix_spawnattr_t attr;
            posix_spawn_file_actions_t actions;
            if (posix_spawnattr_init(&attr) || posix_spawn_file_actions_init(&actions) ||
                posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT |
                    (i == 0 ? POSIX_SPAWN_SETPGROUP : POSIX_SPAWN_SETSID)) ||
                posix_spawnattr_setpgroup(&attr, 0) ||
                posix_spawn_file_actions_adddup2(&actions, pipefd[1], 197) ||
                posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO) ||
                posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO)) exit(12);
            char *args[] = {(char *)exe, "heartbeat", (char *)directory, (char *)spawn_roles[i], NULL};
            pid_t child;
            int error = posix_spawn(&child, exe, &actions, &attr, args, environ);
            posix_spawnattr_destroy(&attr);
            posix_spawn_file_actions_destroy(&actions);
            if (error) { errno = error; die("spawn heartbeat"); }
            close(pipefd[1]);
            char byte;
            if (read(pipefd[0], &byte, 1) != 1) exit(13);
            close(pipefd[0]);
        }
    }
    puts("{\"ready\":true}");
    for (;;) pause();
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "capabilities")) capabilities();
    else if (argc == 2 && !strcmp(argv[1], "syscalls")) syscalls(argv[0]);
    else if (argc == 3 && !strcmp(argv[1], "self")) info(getpid(), argv[2]);
    else if (argc == 3 && !strcmp(argv[1], "info")) info(atoi(argv[2]), "snapshot");
    else if (argc == 3 && !strcmp(argv[1], "tree")) tree(argv[2], argv[0], false);
    else if (argc == 3 && !strcmp(argv[1], "tree-spawn")) tree(argv[2], argv[0], true);
    else if (argc == 4 && !strcmp(argv[1], "heartbeat")) heartbeat(argv[2], argv[3], 197);
    else return 64;
    return 0;
}
