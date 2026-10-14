/* The target of conformance_j3_agent.rs's characterization of an `agent`
   connect withdrawn before the mediator received it (the scenario is
   described above main). Each result is one `label<TAB>result<TAB>errno`
   line. It includes no common.h: it is a target, not a launcher. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void report(const char *label, long r, int err) {
    printf("%s\t%ld\t%d\n", label, r, err);
    fflush(stdout);
}

struct cj { int port; long r; int e; pid_t tid; };

static void *conn_thread(void *arg) {
    struct cj *c = arg;
    struct sockaddr_in a;
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    __atomic_store_n(&c->tid, (pid_t) syscall(SYS_gettid), __ATOMIC_RELEASE);
    if (s < 0) { c->r = -2; c->e = errno; return NULL; }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(c->port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    c->r = connect(s, (struct sockaddr *) &a, sizeof a);
    c->e = c->r < 0 ? errno : 0;
    return NULL;
}

static void on_usr1(int sig) { (void) sig; }

static int listener(int backlog, int *port) {
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (l < 0 || bind(l, (struct sockaddr *) &a, sizeof a) || listen(l, backlog)) return -1;
    getsockname(l, (struct sockaddr *) &a, &al);
    *port = ntohs(a.sin_port);
    return l;
}

/* A loopback listener whose accept queue is full: four connects to it each
   hold one of the mediator's four workers for its connect deadline. A fifth
   connect, to a second listener with room, is then still queued as a
   notification no worker has received, and a handler installed without
   SA_RESTART interrupts it. Every connect's result is reported, then
   whether anything ever reached the second listener. */
int main(void) {
    struct sigaction sa;
    struct cj first, slow[4], quick;
    pthread_t t;
    pthread_t ts[4];
    int full_port, open_port, full, open_l, i, got;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    full = listener(0, &full_port);
    open_l = listener(16, &open_port);
    if (full < 0 || open_l < 0) { report("listen", -1, errno); return 3; }
    /* Never block in the final accept: nothing is expected to arrive. */
    if (fcntl(open_l, F_SETFL, O_NONBLOCK)) { report("nonblock", -1, errno); return 3; }
    memset(&first, 0, sizeof first);
    first.port = full_port;
    pthread_create(&t, NULL, conn_thread, &first);
    pthread_join(t, NULL);
    report("connect_first", first.r, first.e);
    for (i = 0; i < 4; i++) {
        memset(&slow[i], 0, sizeof slow[i]);
        slow[i].port = full_port;
        pthread_create(&ts[i], NULL, conn_thread, &slow[i]);
    }
    /* Time for every worker to receive a slow connect; each then holds it
       for its 2 s connect deadline, so the signal below (1.2 s in) lands
       while all four are still busy, with margin on a loaded host. */
    usleep(700000);
    memset(&quick, 0, sizeof quick);
    quick.port = open_port;
    pthread_create(&t, NULL, conn_thread, &quick);
    while (!__atomic_load_n(&quick.tid, __ATOMIC_ACQUIRE)) sched_yield();
    usleep(500000);
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    report("connect_quick", quick.r, quick.e);
    for (i = 0; i < 4; i++) {
        pthread_join(ts[i], NULL);
        report("connect_slow", slow[i].r, slow[i].e);
    }
    /* Every worker is free again: a notification still queued would have
       been served by now. */
    usleep(500000);
    got = accept4(open_l, NULL, NULL, SOCK_CLOEXEC);
    report("quick_arrived", got >= 0, got < 0 ? errno : 0);
    return 0;
}
