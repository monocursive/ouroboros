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
    for (;;) {
        if (write(fd, ".", 1) != 1) _exit(9);
        usleep(10000);
    }
}

static void tree(const char *directory) {
    signal(SIGALRM, timeout_exit);
    alarm(20);
    info(getpid(), "root");
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
    puts("{\"ready\":true}");
    for (;;) pause();
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "capabilities")) capabilities();
    else if (argc == 2 && !strcmp(argv[1], "syscalls")) syscalls(argv[0]);
    else if (argc == 3 && !strcmp(argv[1], "self")) info(getpid(), argv[2]);
    else if (argc == 3 && !strcmp(argv[1], "info")) info(atoi(argv[2]), "snapshot");
    else if (argc == 3 && !strcmp(argv[1], "tree")) tree(argv[2]);
    else return 64;
    return 0;
}
