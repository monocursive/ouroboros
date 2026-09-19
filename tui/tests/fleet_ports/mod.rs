//! Loopback ports for a test fleet, claimed so no other test process takes them.
//!
//! Every fleet a test makes has to *bind* a gateway port and a distribution port, and
//! the only way to find a free one is to bind port 0, read the number back and let go.
//! That leaves a window — often seconds, because the port is chosen when a child is
//! spawned and bound when the child gets as far as `fleet::create` — in which the
//! kernel will happily hand the same number to somebody else. macOS draws ephemeral
//! ports at random from about sixteen thousand, and `cargo test` runs four or five
//! fleet binaries at once; over a whole run that collides often enough to be seen, and
//! what it looks like is `already in use` in whichever test lost, with nothing wrong in
//! the code it was testing.
//!
//! A per-process set is not enough, because the processes are the problem. The claim is
//! therefore a file per port in one directory under `TMPDIR`, created with `O_EXCL`:
//! whichever process creates it owns that number for the rest of the run. Claims from
//! an earlier run are swept on first use, so the directory does not grow without bound
//! and a crashed run does not poison the next one.
//!
//! This does not stop an unrelated program on the machine from taking a port — nothing
//! can — so callers that can retry still should. What it removes is the collision this
//! suite causes itself.

#![allow(dead_code)]

use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, SystemTime};

/// Claims older than this are another run's, and are swept.
const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

fn claim_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("ouro-test-ports");
    static SWEEP: Once = Once::new();
    SWEEP.call_once(|| {
        let _ = fs::create_dir_all(&dir);
        let Ok(entries) = fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            let stale = entry
                .metadata()
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|at| SystemTime::now().duration_since(at).ok())
                .is_some_and(|age| age > STALE_AFTER);
            if stale {
                let _ = fs::remove_file(entry.path());
            }
        }
    });
    dir
}

/// Whether this process may have the port: true exactly once per port per run.
fn claim(port: u16) -> bool {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(claim_dir().join(port.to_string()))
        .is_ok()
}

/// The window a port is drawn from: outside every production port space, and — the
/// point — outside the kernel's own ephemeral range.
///
/// Asking the kernel for a free port (`bind` to 0, read the number back, let go) picks
/// from that ephemeral range, which is exactly the range it hands to every *other*
/// `bind(0)` on the machine, including this suite's own. So a number reserved that way
/// could be handed to somebody else between the moment it was let go and the moment the
/// fleet that reserved it binds it — and two of this suite's own tests, racing inside
/// `one`, do precisely that to each other: the loser of a claim holds the winner's port
/// bound while it retries. What that looks like is `already in use` in a test with
/// nothing wrong in the code it is testing.
///
/// macOS draws ephemeral ports from 49152 and Linux from 32768, so a window well below
/// both is one the kernel never allocates on its own. A number here is taken only by a
/// program that asked for it by name.
const WINDOW: std::ops::Range<u16> = 20_000..30_000;

/// Whether a port is one this suite may use at all.
fn usable(port: u16) -> bool {
    port != 4369
        && port != 65_358
        && !(13_700..=13_729).contains(&port)
        && !(17_000..18_000).contains(&port)
}

/// A number from [`WINDOW`], spread by time, process and call so two processes starting
/// together do not walk the same sequence. No crate for this: what is needed is spread,
/// not randomness.
fn candidate() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.subsec_nanos())
        .unwrap_or(0);
    let mixed = nanos
        ^ (std::process::id().wrapping_mul(2_654_435_761))
        ^ NEXT.fetch_add(1, Ordering::Relaxed).wrapping_mul(97);
    let span = (WINDOW.end - WINDOW.start) as u32;
    WINDOW.start + (mixed % span) as u16
}

/// A port outside every production port space that nothing in this test run has claimed
/// and nothing on this machine is listening on.
///
/// The claim comes first and is kept whether or not the bind succeeds: a port this run
/// found occupied is a port this run should stop offering. The bind that follows is the
/// proof, and it is let go immediately — the fleet that reserved this number is the one
/// that binds it for real, seconds later, and until then nothing but an explicit request
/// for this exact number can take it.
fn one() -> u16 {
    for _ in 0..512 {
        let port = candidate();
        if !usable(port) || !claim(port) {
            continue;
        }
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(listener) => {
                drop(listener);
                return port;
            }
            Err(_occupied) => continue,
        }
    }
    panic!("no unclaimed loopback port was free after 512 attempts");
}

/// A gateway port and a distribution port, distinct and claimed.
pub fn reserve() -> (u16, u16) {
    let gateway = one();
    let dist = one();
    (gateway, dist)
}
