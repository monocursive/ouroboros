/* An LD_PRELOAD shim over libc's clock_gettime, for j5_lifetime_linux.rs's
   execution-deadline clock checks: once the file OURO_B3_CLOCK_TRIGGER names
   exists, it adds OURO_B3_CLOCK_OFFSET_NS to clock id OURO_B3_CLOCK_ID only,
   in every process that loads it. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
static int (*real)(clockid_t, struct timespec *);
static const char *trigger;
static int shifted = -1;
static long long offset;
static volatile int fired;
__attribute__((constructor)) static void init(void) {
    real = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    trigger = getenv("OURO_B3_CLOCK_TRIGGER");
    const char *id = getenv("OURO_B3_CLOCK_ID");
    const char *ns = getenv("OURO_B3_CLOCK_OFFSET_NS");
    if (id) shifted = atoi(id);
    if (ns) offset = atoll(ns);
}
int clock_gettime(clockid_t id, struct timespec *ts) {
    int rc = real(id, ts);
    if (rc != 0 || id != shifted || !trigger) return rc;
    if (!fired && access(trigger, F_OK) == 0) fired = 1;
    if (!fired) return rc;
    long long total = (long long)ts->tv_sec * 1000000000LL + ts->tv_nsec + offset;
    ts->tv_sec = total / 1000000000LL;
    ts->tv_nsec = total % 1000000000LL;
    return rc;
}
