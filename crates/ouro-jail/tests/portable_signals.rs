//! §8.3: INT, TERM and HUP received by the supervisor request termination.
//!
//! The handler only writes one byte into a self-pipe; it allocates nothing,
//! serializes nothing and performs no cleanup, so slow disk or trace I/O cannot
//! delay it. This test sends a real SIGTERM to this process from outside. It
//! can only pass if the handler is installed: without one, the default action
//! for SIGTERM would terminate the test binary before any assertion ran.
//!
//! It lives in its own integration test because installing process-wide signal
//! handlers is not something to do inside a shared test binary.

use std::process::Command;
use std::time::{Duration, Instant};

use ouro_jail::supervisor::signals;

#[test]
fn a_termination_signal_wakes_the_supervisor_through_the_self_pipe() {
    let pipe = signals::install().expect("the self-pipe and handlers install");
    assert!(
        !pipe.triggered(),
        "nothing has been signalled before the test sends anything"
    );

    let status = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
        .expect("/bin/kill is available on both supported platforms");
    assert!(status.success(), "the signal was delivered");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if pipe.triggered() {
            // A second read finds the pipe drained again, so the wakeup is
            // edge-like rather than a latch that never clears.
            assert!(!pipe.triggered(), "the pipe is drained after a read");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the signal never reached the self-pipe");
}
