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

/// A port outside every production port space that nothing in this test run has claimed.
///
/// The listener stays bound while the claim is taken, so two processes racing here
/// cannot both be handed the same number by the kernel *and* both claim it.
fn one() -> u16 {
    for _ in 0..256 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free loopback port");
        let port = listener.local_addr().expect("a bound address").port();
        let usable = port != 4369
            && port != 65_358
            && !(13_700..=13_729).contains(&port)
            && !(17_000..18_000).contains(&port);
        if usable && claim(port) {
            return port;
        }
    }
    panic!("no unclaimed loopback port was free after 256 attempts");
}

/// A gateway port and a distribution port, distinct and claimed.
pub fn reserve() -> (u16, u16) {
    let gateway = one();
    let dist = one();
    (gateway, dist)
}
