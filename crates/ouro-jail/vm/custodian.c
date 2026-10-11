/* Own one VZ client as an unreaped child. No PID discovery, privileges, or
 * detached daemon. A stalled caller cannot renew the three-second lease. */
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static volatile sig_atomic_t stopping;
static void stop(int sig) { stopping = sig; }
static double now(void) {
    mach_timebase_info_data_t scale;
    if (mach_timebase_info(&scale)) _exit(125);
    return (double)mach_continuous_time() * scale.numer / scale.denom / 1e9;
}

int main(int argc, char **argv) {
    /* custodian LEASE_FD ACK_FD VZ DISK SEED NVRAM CONSOLE run */
    if (argc != 9) return 125;
    char *end;
    long parsed = strtol(argv[1], &end, 10);
    if (*end || parsed < 3 || parsed > 1024) return 125;
    int lease = (int)parsed;
    if (fcntl(lease, F_GETFD) < 0 || fcntl(lease, F_SETFD, FD_CLOEXEC)) return 125;
    parsed = strtol(argv[2], &end, 10);
    if (*end || parsed < 3 || parsed > 1024 || parsed == lease) return 125;
    int ack = (int)parsed;
    if (fcntl(ack, F_GETFD) < 0 || fcntl(ack, F_SETFD, FD_CLOEXEC)) return 125;
    struct sigaction action = {.sa_handler = stop};
    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&action.sa_mask);
    for (int i = 0; i < 3; i++) {
        int sig = (int[]){SIGTERM, SIGINT, SIGHUP}[i];
        if (sigaction(sig, &action, NULL)) return 125;
    }
    int life[2];
    if (pipe(life)) return 125;
    posix_spawn_file_actions_t files;
    if (posix_spawn_file_actions_init(&files)) return 125;
    /* Closing lease first permits it to be fd 3. The only lifeline writer
     * stays in the custodian; its death produces EOF in the VZ client. */
    if (posix_spawn_file_actions_addclose(&files, lease) ||
        posix_spawn_file_actions_addclose(&files, ack) ||
        posix_spawn_file_actions_adddup2(&files, life[0], 3) ||
        posix_spawn_file_actions_addclose(&files, life[1])) return 125;
    if (life[0] != 3 && posix_spawn_file_actions_addclose(&files, life[0])) return 125;
    char *child_argv[] = {argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], "3", NULL};
    pid_t child;
    int error = posix_spawn(&child, argv[3], &files, NULL, child_argv, environ);
    posix_spawn_file_actions_destroy(&files);
    close(life[0]);
    if (error) { close(life[1]); return 125; }
    double refreshed = now();
    int status;
    for (;;) {
        pid_t found = waitpid(child, &status, WNOHANG);
        if (found == child) { close(life[1]); return WIFEXITED(status) ? WEXITSTATUS(status) : 125; }
        if (found < 0 && errno != EINTR) break;
        if (stopping || now() - refreshed > 3) break;
        struct pollfd input = {.fd = lease, .events = POLLIN};
        int ready = poll(&input, 1, 50);
        if (ready < 0 && errno != EINTR) break;
        if (ready > 0) {
            char bytes[64];
            ssize_t count = read(lease, bytes, sizeof(bytes));
            if (count <= 0) break;
            /* One heartbeat, with no credit carried into later intervals. */
            for (ssize_t i = 0; i < count; i++) if (bytes[i] != '.') stopping = 1;
            refreshed = now();
            if (write(ack, ".", 1) != 1) break;
        }
    }
    /* The child has not been reaped, so its PID cannot be reused here. */
    kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    close(life[1]);
    return 125;
}
