//! `ukai-fixture`: the conformance child of `ukai-jail` (jail-v1 §15) and the
//! test harness that drives the jail around it.
//!
//! Two halves:
//!
//! * The **binary** runs *inside* the jail. Its only channels are stdio and
//!   files under the workspace or scratch. It performs one named syscall per
//!   operation through [`raw`] and prints one JSON line per operation:
//!   `{"op":"<syscall>","args":{…},"ret":<signed>,"errno":<name|null>}`. It
//!   exits 0 when every `--expect` held, 3 when one did not, 2 on a usage
//!   error (refused before anything ran) and 4 when it stopped after
//!   something ran (an operation it needed for itself failed, or a later
//!   script step was refused). It needs no credential and never prints an
//!   environment value.
//! * The **harness** ([`harness`]) runs in the test process, outside the jail.
//!   It builds a private state directory, plumbs the gate/control/trace pipes,
//!   runs `ukai-jail`, and reads back receipts, control messages and trace
//!   events. It never sleeps to synchronise.
//! * Between them, `perf-launch` (`perf`) is a mode of the binary that runs
//!   *outside* the jail, as the parent of the measured command, and reads
//!   the attempt back with the harness's trace recogniser.
//!
//! The modes, grouped by what they exercise:
//!
//! | Group | Modes |
//! |---|---|
//! | Filesystem, closed set | `open` (`--via openat\|open\|creat\|openat2`), `mkdir` (`mkdir\|mkdirat`), `rename` (`rename\|renameat\|renameat2`), `unlink` (`unlink\|unlinkat`), `rmdir` (`rmdir\|unlinkat`), `link` (`link\|linkat`), `symlink` (`symlink\|symlinkat`), `mknod` (`mknod\|mknodat`), `truncate` |
//! | Filesystem, outside the closed set | `ftruncate` (descriptor-based, names no path to the kernel), `write-mmap` |
//! | Network | `connect`, `udp-sendto`, `dns-query`, `http-get`, `http-connect` (proxy variables honoured, plain TCP) |
//! | Unix sockets | `unix-connect` (`--seqpacket`, `--len exact\|nul\|full`), `unix-abstract-connect`, `unix-listen`, `unix-socket-dgram`, `unix-socketpair-dgram`, `scm-send`, `scm-recv` |
//! | Inner sandbox | `sandbox-exec` (no_new_privs, Landlock, seccomp, then exec) |
//! | Process | `exec`, `exec-replace` (`--via execve\|execveat`), `background`, `fork-storm`, `thread`, `exit`, `raise` |
//! | Lifetime | `sleep`, `spin`, `ignore-term` |
//! | Introspection | `echo-args`, `stdout-bytes`, `stderr-bytes`, `env`, `fds`, `status` |
//! | Composition | `script` (a JSON array of argv arrays, run in one process) |
//!
//! Beside them, [`elf`] builds synthetic ELF headers for the jail's `--from-path`
//! resolution tests.
//!
//! The crate is test-only: jail-v1 §4 excludes it from packaging and from the
//! I02 vendor-name scan. No vendor name appears in it regardless.

pub mod bounded;
pub mod cli;
pub mod elf;
pub mod errno;
pub mod harness;
pub mod net;
pub mod ops;
pub mod perf;
pub mod raw;
pub mod report;
pub mod sandbox;
pub mod sockaddr;
pub mod unix;

/// Exit code when every expectation held.
pub const EXIT_OK: u8 = 0;
/// Exit code for a usage error, matching jail-v1 §6.4.
pub const EXIT_USAGE: u8 = 2;
/// Exit code when at least one operation did not match its `--expect`.
pub const EXIT_EXPECTATION_FAILED: u8 = 3;
/// Exit code when the fixture stopped after something ran, without its
/// result: an operation it needed for itself (a directory descriptor, a
/// pipe, a fork, its result file) failed, or a later script step was
/// refused. Not the operation under test, and not a usage error, which
/// promises that nothing ran.
pub const EXIT_FIXTURE_FAILED: u8 = 4;
