/* The trusted-launcher stand-in of the unix-peer suite (unix_peer_linux.rs).
   unix_peer COORD_SOCKET ATTEMPT_DIR FILTER: connect to the supervisor's
   coordination socket, bind the attempt's listeners, open NETLINK_SOCK_DIAG,
   install the mediation filter in FILTER with a notification listener,
   announce both descriptors, then connect on command. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL<<3)
#endif
#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL<<5)
#endif
#define NETLINK_SOCK_DIAG 4

static int connect_un_type(int type, const char *name, int abstract) {
    int s = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
    if (s < 0) return errno;
    struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
    size_t n = strlen(name);
    socklen_t len;
    if (abstract) { a.sun_path[0]=0; memcpy(a.sun_path+1,name,n); len=2+1+n; }
    else { memcpy(a.sun_path,name,n); len=2+n+1; }
    int r = connect(s,(void*)&a,len);
    int e = r==0?0:errno;
    close(s);
    return e;
}

static int bind_listen(int type, const char *name, int abstract) {
    int s = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
    size_t n = strlen(name);
    socklen_t len;
    if (abstract) { a.sun_path[0]=0; memcpy(a.sun_path+1,name,n); len=2+1+n; }
    else { unlink(name); memcpy(a.sun_path,name,n); len=2+n+1; }
    if (bind(s,(void*)&a,len)) return -1;
    if (listen(s,64)) return -1;
    return s;
}

/* fill a pathname sockaddr_un for `path`; returns the length. */
static socklen_t fill_un(struct sockaddr_un *a, const char *path) {
    memset(a,0,sizeof *a); a->sun_family=AF_UNIX;
    size_t n = strlen(path);
    memcpy(a->sun_path, path, n);
    return (socklen_t)(2+n+1);
}

/* one stream connect to a pathname socket; returns 0 or errno. */
static int connect_stream(const char *path) {
    int s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (s < 0) return errno;
    struct sockaddr_un a; socklen_t len = fill_un(&a, path);
    int r = connect(s,(void*)&a,len);
    int e = r==0?0:errno;
    close(s);
    return e;
}

/* an x32 connect: shares the x86_64 audit arch but sets the x32 syscall bit,
   so the mediation filter must deny it (EPERM). __X32_SYSCALL_BIT | connect. */
static int x32_connect(const char *path) {
    int s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
    if (s < 0) return errno;
    struct sockaddr_un a; socklen_t len = fill_un(&a, path);
    long r = syscall((long)(0x40000000L | 42L), (long)s, (long)&a, (long)len);
    int e = r==0?0:(int)(r<0?-r:r);
    close(s);
    return e;
}

/* does the i386 int-0x80 ABI work here? i386 getpid == 20. Only an x86 host
   can even ask; elsewhere the ABI does not exist and the probe says so. */
#if defined(__x86_64__) || defined(__i386__)
static long i386_call0(long nr){ long ret; __asm__ volatile("int $0x80":"=a"(ret):"a"(nr):"memory"); return ret; }
static long i386_socketcall(long call, unsigned long *args){ long ret; __asm__ volatile("int $0x80":"=a"(ret):"a"(102),"b"(call),"c"(args):"memory"); return ret; }
#else
static long i386_call0(long nr){ (void)nr; return -ENOSYS; }
static long i386_socketcall(long call, unsigned long *args){ (void)call; (void)args; return -ENOSYS; }
#endif

int main(int argc, char **argv) {
    const char *coord_path = argv[1];
    const char *attempt_dir = argv[2];
    const char *filter_file = argv[3];

    int coord = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
    struct sockaddr_un ca; memset(&ca,0,sizeof ca); ca.sun_family=AF_UNIX;
    strncpy(ca.sun_path, coord_path, sizeof(ca.sun_path)-1);
    if (connect(coord,(void*)&ca,sizeof ca)) { return 3; }

    char p[512];
    snprintf(p,sizeof p,"%s/attempt.sock",attempt_dir);
    if (bind_listen(SOCK_STREAM,p,0) < 0) { dprintf(coord,"FATAL bind attempt"); return 1; }
    snprintf(p,sizeof p,"%s/attempt_seq.sock",attempt_dir);
    if (bind_listen(SOCK_SEQPACKET,p,0) < 0) { dprintf(coord,"FATAL bind seq"); return 1; }
    if (bind_listen(SOCK_STREAM,"ukai-attempt-abstract",1) < 0) { dprintf(coord,"FATAL bind abs"); return 1; }

    /* a TCP listener in this netns (for the domain-check test). lo may be down
       under bwrap; the port is reported and the connect result is what matters. */
    int tcpl = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    struct sockaddr_in ta; memset(&ta,0,sizeof ta); ta.sin_family=AF_INET; ta.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bind(tcpl,(void*)&ta,sizeof ta); listen(tcpl,16);
    socklen_t tl=sizeof ta; getsockname(tcpl,(void*)&ta,&tl);
    int tcp_port = ntohs(ta.sin_port);

    /* i386 int-0x80 availability probe (getpid). */
    long ip = i386_call0(20);
    int ia32_ok = (ip == getpid());

    /* read the filter file into a sock_filter array */
    /* The sock_diag socket before the filter, as the real launcher opens it:
       the mediation filter refuses every netlink socket once installed. */
    int diag = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    FILE *f = fopen(filter_file,"rb");
    if (!f) { dprintf(coord,"FATAL open filter"); return 1; }
    static struct sock_filter prog[256];
    size_t got = fread(prog,8,256,f); fclose(f);
    struct sock_fprog fp = { (unsigned short)got, prog };
    prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
    long listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER|SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, &fp);
    if (listener < 0) { dprintf(coord,"FATAL seccomp %d", errno); return 1; }

    dprintf(coord,"HELLO %ld %d %d %d", listener, diag, tcp_port, ia32_ok);

    char buf[512];
    for (;;) {
        ssize_t k = read(coord, buf, sizeof(buf)-1);
        if (k <= 0) return 0;
        buf[k]=0;
        if (buf[0]=='Q') return 0;
        /* GO: the supervisor has taken both fds with pidfd_getfd, so close our
           copies (as the real launcher closes them before exec). Only then does
           the supervisor closing its copy fully close the listener, which is
           what makes a later connect fail ENOSYS (fail-closed). */
        if (!strncmp(buf,"GO",2)) { close((int)listener); close(diag); continue; }
        /* "L <n>": loop n stream connects to attempt.sock (backlog stress). */
        if (buf[0]=='L') { int n=atoi(buf+2); snprintf(p,sizeof p,"%s/attempt.sock",attempt_dir); for(int i=0;i<n;i++) connect_stream(p); dprintf(coord,"done"); continue; }
        /* "K <path>": fork a child that connects `path` (blocks in mediation),
           then kill it mid-mediation. With the id revalidation, the mediator
           must drop the now-stale notification silently. */
        if (buf[0]=='K') {
            char *path = buf+2;
            pid_t c = fork();
            if (c==0) { connect_stream(path); _exit(0); }
            usleep(50*1000);
            kill(c, SIGKILL);
            int st; waitpid(c,&st,0);
            dprintf(coord,"killed"); continue;
        }
        /* "F <n>": fork n children that each connect concurrently, then wait. */
        if (buf[0]=='F') {
            int n=atoi(buf+2); snprintf(p,sizeof p,"%s/attempt.sock",attempt_dir);
            for(int i=0;i<n;i++){ pid_t c=fork(); if(c==0){ connect_stream(p); _exit(0);} }
            int done=0,st; while(wait(&st)>0) done++;
            dprintf(coord,"done %d", done); continue;
        }
        /* "C <t> <arg>" : p stream / s seqpacket / a abstract / d dgram / r raw
           / t tcp(port) / b bind-nolisten / w cwd-relative / x x32 / i i386
           / n connect on a descriptor that is not a socket */
        char t=buf[2];
        char *path = buf+4;
        int e;
        if (t=='d') { int s=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0); e=s<0?errno:0; if(s>=0)close(s); }
        else if (t=='r') { int s=socket(AF_UNIX,SOCK_RAW|SOCK_CLOEXEC,0); e=s<0?errno:0; if(s>=0)close(s); }
        else if (t=='a') e=connect_un_type(SOCK_STREAM,path,1);
        else if (t=='s') e=connect_un_type(SOCK_SEQPACKET,path,0);
        else if (t=='w') {
            if (chdir("/attempt/sub") != 0) e=errno;
            else { e=connect_stream(path); if (chdir("/") != 0) return 1; }
        }
        else if (t=='t') { int port=atoi(path); int s=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
            struct sockaddr_in d; memset(&d,0,sizeof d); d.sin_family=AF_INET; d.sin_addr.s_addr=htonl(INADDR_LOOPBACK); d.sin_port=htons(port);
            int r=connect(s,(void*)&d,sizeof d); e=r==0?0:errno; close(s); }
        else if (t=='b') { int s=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); struct sockaddr_un a; socklen_t len=fill_un(&a,path); unlink(path); e=bind(s,(void*)&a,len)?errno:0; /* keep fd open, no listen */ }
        else if (t=='x') e=x32_connect(path);
        else if (t=='n') { int f=open("/attempt", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
            struct sockaddr_un na; socklen_t len=fill_un(&na,path);
            int r=connect(f,(void*)&na,len); e=r==0?0:errno; close(f); }
        else if (t=='i') {
            if (!ia32_ok) { e=-1; }
            else { int s=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
                static struct sockaddr_un la; socklen_t len=fill_un(&la,path);
                unsigned long args[3]; args[0]=(unsigned long)s; args[1]=(unsigned long)&la; args[2]=len;
                long r=i386_socketcall(3 /*SYS_CONNECT*/, args); e=r==0?0:(int)(r<0?-r:r); close(s); }
        }
        else e=connect_un_type(SOCK_STREAM,path,0);
        dprintf(coord,"%d", e);
    }
}
