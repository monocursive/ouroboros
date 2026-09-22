//! `ouro-fixture`: the conformance child of `ouro-jail` (jail-v1 §15) and the
//! test harness that drives the jail around it.
//!
//! Two halves that never mix at run time:
//!
//! * The **binary** runs *inside* the jail. Its only channels are stdio and
//!   files under the workspace or scratch. It performs one named syscall per
//!   operation through [`raw`] and prints one JSON line per operation:
//!   `{"op":"<syscall>","args":{…},"ret":<signed>,"errno":<name|null>}`. It
//!   exits 0 when every `--expect` held, 3 when one did not, and 2 on a usage
//!   error. It needs no credential and never prints an environment value.
//! * The **harness** ([`harness`]) runs in the test process, outside the jail.
//!   It builds a private state directory, plumbs the gate/control/trace pipes,
//!   runs `ouro-jail`, and reads back receipts, control messages and trace
//!   events. It never sleeps to synchronise.
//!
//! The modes, grouped by what they exercise:
//!
//! | Group | Modes |
//! |---|---|
//! | Filesystem, closed set | `open` (`--via openat\|open\|creat\|openat2`), `mkdir` (`mkdir\|mkdirat`), `rename` (`rename\|renameat\|renameat2`), `unlink` (`unlink\|unlinkat`), `rmdir` (`rmdir\|unlinkat`), `link` (`link\|linkat`), `symlink` (`symlink\|symlinkat`), `mknod` (`mknod\|mknodat`), `truncate` |
//! | Filesystem, outside the closed set | `ftruncate` (descriptor-based, names no path to the kernel), `write-mmap` |
//! | Network | `connect` |
//! | Process | `exec`, `exec-replace` (`--via execve\|execveat`), `background`, `fork-storm`, `thread`, `exit`, `raise` |
//! | Lifetime | `sleep`, `spin`, `ignore-term` |
//! | Introspection | `echo-args`, `stdout-bytes`, `stderr-bytes`, `env`, `fds`, `status` |
//! | Composition | `script` (a JSON array of argv arrays, run in one process) |
//!
//! The crate is test-only: jail-v1 §4 excludes it from packaging and from the
//! I02 vendor-name scan. No vendor name appears in it regardless.

pub mod cli;
pub mod errno;
pub mod harness;
pub mod ops;
pub mod raw;
pub mod report;

/// Exit code when every expectation held.
pub const EXIT_OK: i32 = 0;
/// Exit code for a usage error, matching jail-v1 §6.4.
pub const EXIT_USAGE: i32 = 2;
/// Exit code when at least one operation did not match its `--expect`.
pub const EXIT_EXPECTATION_FAILED: i32 = 3;
