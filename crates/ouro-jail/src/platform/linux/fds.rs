//! The fixed descriptor numbers the jail's processes receive (§8.3), one
//! table per process, each checked at compile time to be distinct and to
//! spare stdio.
//!
//! The backend's map is what the bootstrap installs before it execs
//! bubblewrap: the channels below [`PINNED_BASE`], and from it up the pinned
//! binds and the credential views. bubblewrap closes each bind descriptor
//! once it has bound it, and keeps [`RELEASE`], [`ERROR`] and
//! [`TRACE_DATA`] for the launcher it runs. The launcher places the `agent`
//! descriptors itself ([`LISTENER`], [`SOCKDIAG`], [`BRIDGE_REPORT`]) and
//! refuses a number that is still open, so [`BRIDGE_REPORT`] may share 20
//! with [`PINNED_BASE`]: the two are numbers in different processes' tables,
//! and a backend that kept a bind open would refuse the run rather than mix
//! them. The outside watcher and `none`'s launcher have tables of their own.

use std::os::fd::RawFd;

// The backend's map.
/// The pinned backend the bootstrap execs; closed by that exec.
pub const BACKEND: RawFd = 8;
/// The attempt's narrowing `SECCOMP_RET_DATA`: two bytes, written before
/// the spawn; the launcher reads it and closes it.
pub const TRACE_DATA: RawFd = 9;
/// The seccomp program handed to bubblewrap.
pub const SECCOMP: RawFd = 10;
/// bubblewrap's JSON status.
pub const STATUS: RawFd = 11;
/// The pipe the launcher blocks reading (`__launch --release-fd`).
pub const RELEASE: RawFd = 12;
/// The pipe the launcher writes a failed exec's errno to
/// (`__launch --error-fd`).
pub const ERROR: RawFd = 13;
/// A long argument list, handed over by `--args`.
pub const ARGS: RawFd = 14;
/// The bootstrap's start pipe: one released byte lets it exec the backend.
pub const START: RawFd = 15;
/// The vendor-state directory, bound by `--bind-fd`.
pub const VENDOR_STATE: RawFd = 16;
/// The `agent` proxy directory, bound read-only by descriptor.
pub const PROXY_DIR: RawFd = 17;
/// The first pinned bind (`--ro-bind-fd`, `--bind-fd`); every fixed channel
/// of the backend's map is below it, and the credential views follow the
/// pins.
pub const PINNED_BASE: RawFd = 20;

// What the launcher places for the supervisor to take before release.
/// The unix-peer mediation listener.
pub const LISTENER: RawFd = 18;
/// The attempt-netns `sock_diag` socket.
pub const SOCKDIAG: RawFd = 19;
/// The supervisor's end of the bridge's report socket: one datagram for
/// every client the bridge turned away at capacity.
pub const BRIDGE_REPORT: RawFd = 20;

// The outside watcher's.
/// A pidfd of the supervisor that started it.
pub const WATCHER_SUPERVISOR: RawFd = 3;
/// A pidfd of the backend it guards.
pub const WATCHER_BACKEND: RawFd = 4;
/// The write end of its ready pipe.
pub const WATCHER_READY: RawFd = 5;
/// The leaf's `cgroup.kill`, when there is a leaf.
pub const WATCHER_CGROUP_KILL: RawFd = 6;
/// The read end of its release pipe.
pub const WATCHER_RELEASE: RawFd = 7;

// `none`'s launcher, started directly on the host.
/// The pipe it blocks reading.
pub const NONE_RELEASE: RawFd = 3;
/// The pipe it writes a failed exec's errno to.
pub const NONE_ERROR: RawFd = 4;

/// The backend's map below the pins.
const BACKEND_MAP: [RawFd; 10] = [
    BACKEND,
    TRACE_DATA,
    SECCOMP,
    STATUS,
    RELEASE,
    ERROR,
    ARGS,
    START,
    VENDOR_STATE,
    PROXY_DIR,
];
/// What the contained launcher holds before release.
const LAUNCHER_MAP: [RawFd; 6] = [
    RELEASE,
    ERROR,
    TRACE_DATA,
    LISTENER,
    SOCKDIAG,
    BRIDGE_REPORT,
];
const WATCHER_MAP: [RawFd; 5] = [
    WATCHER_SUPERVISOR,
    WATCHER_BACKEND,
    WATCHER_READY,
    WATCHER_CGROUP_KILL,
    WATCHER_RELEASE,
];
const NONE_LAUNCHER_MAP: [RawFd; 2] = [NONE_RELEASE, NONE_ERROR];

/// Every number in `table` is distinct, above stdio and below `bound`.
const fn well_formed(table: &[RawFd], bound: RawFd) -> bool {
    let mut i = 0;
    while i < table.len() {
        if table[i] <= 2 || table[i] >= bound {
            return false;
        }
        let mut j = i + 1;
        while j < table.len() {
            if table[i] == table[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(well_formed(&BACKEND_MAP, PINNED_BASE));
const _: () = assert!(well_formed(&LAUNCHER_MAP, RawFd::MAX));
const _: () = assert!(well_formed(&WATCHER_MAP, RawFd::MAX));
const _: () = assert!(well_formed(&NONE_LAUNCHER_MAP, RawFd::MAX));

#[cfg(test)]
mod tests {
    use super::*;

    /// The check the tables are held to refuses each way a table can break.
    #[test]
    fn a_table_that_collides_reaches_stdio_or_the_pins_is_refused() {
        assert!(well_formed(&[3, 4, 5], 6));
        assert!(!well_formed(&[3, 4, 3], 6), "a collision");
        assert!(!well_formed(&[2, 4], 6), "stdio");
        assert!(!well_formed(&[3, 6], 6), "the bound");
    }
}
