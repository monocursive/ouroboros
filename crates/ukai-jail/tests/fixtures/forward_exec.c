/* A stand-in backend for j5_boundary_linux.rs's K04: it execs the real
   bubblewrap, whose path the build passes as the string literal FORWARD_TO,
   with its own argv. Capability probes then run the distribution backend
   unchanged (its file and its AppArmor profile), while the test owns a file
   it can replace or re-mode. */
#include <unistd.h>

int main(int argc, char **argv) {
    (void) argc;
    execv(FORWARD_TO, argv);
    return 127;
}
