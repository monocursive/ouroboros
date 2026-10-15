//! Shared support for the ledger's integration tests.
//!
//! Not a test target: Cargo builds only the top-level `.rs` files in
//! `tests/`, so this is compiled into each binary that declares
//! `mod common;`.

// Each binary uses the part of this module it needs.
#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long a fresh `ukai-ledger serve` may take to accept on its socket.
pub const WRITER_READY: Duration = Duration::from_secs(5);
/// How long one local CLI command may take: a bound against a hang, never a
/// way to order events.
pub const CLI_LIMIT: Duration = Duration::from_secs(10);
/// How long the writer may take to answer one request on its socket.
pub const REPLY_LIMIT: Duration = Duration::from_secs(5);
/// How often a bounded wait looks again.
const POLL: Duration = Duration::from_millis(10);
/// The most a drained pipe keeps: enough for every report these tests read.
const DRAIN_LIMIT: u64 = 2 * 1_048_576;

/// Whether `ready` came to hold within `bound`, looking every [`POLL`]: for
/// a caller that reports the timeout itself.
#[must_use]
pub fn within(bound: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(POLL);
    }
}

/// Wait until `ready` holds, looking every [`POLL`]; fail the test naming
/// `what` when `bound` passes first.
pub fn eventually(what: &str, bound: Duration, ready: impl FnMut() -> bool) {
    assert!(
        within(bound, ready),
        "timed out after {bound:?} waiting for {what}"
    );
}

/// [`eventually`] for a probe that finds something: wait until `probe`
/// returns it, and hand it back.
pub fn eventually_some<T>(what: &str, bound: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let mut found = None;
    eventually(what, bound, || {
        found = probe();
        found.is_some()
    });
    found.expect("the wait ended on a probe that found it")
}

/// A file only this user can read, created fresh: the subprocess output a
/// test keeps never lands in a pipe whose backpressure could stall it.
pub fn private_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A subprocess owned from spawn through wait: killed and reaped on drop, so
/// a failed assertion never leaves it running over a removed directory.
pub struct Process {
    pub child: Child,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

/// Read `reader` to its end (at most the drain limit) on a thread of its own.
pub fn drain(reader: impl std::io::Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.take(DRAIN_LIMIT).read_to_end(&mut bytes).unwrap();
        bytes
    })
}

impl Process {
    /// Spawn with stdin closed and stdout and stderr piped; stderr is always
    /// drained, stdout when `drain_stdout` (otherwise the test reads it).
    pub fn spawn(command: &mut Command, drain_stdout: bool) -> Self {
        Self::try_spawn(command, drain_stdout).expect("the subprocess starts")
    }

    /// [`Process::spawn`], reporting a failure to start.
    ///
    /// # Errors
    /// Why the command could not be started.
    pub fn try_spawn(command: &mut Command, drain_stdout: bool) -> std::io::Result<Self> {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(Self::from_child(child, drain_stdout))
    }

    /// Own a child spawned elsewhere, draining whichever of its stdout (when
    /// `drain_stdout`) and stderr are pipes.
    pub fn from_child(mut child: Child, drain_stdout: bool) -> Self {
        let stdout = drain_stdout
            .then(|| child.stdout.take().map(drain))
            .flatten();
        let stderr = child.stderr.take().map(drain);
        Self {
            child,
            stdout,
            stderr,
        }
    }

    /// Spawn with stdin closed and stdout and stderr written to private
    /// files the caller names.
    pub fn spawn_to_files(command: &mut Command, stdout: &Path, stderr: &Path) -> Self {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(private_file(stdout)))
            .stderr(Stdio::from(private_file(stderr)))
            .spawn()
            .expect("the subprocess starts");
        Self::from_child(child, false)
    }

    /// Wait for exit, failing the test if it takes longer than `limit`.
    pub fn wait_within(&mut self, limit: Duration, what: &str) -> ExitStatus {
        let mut status = None;
        let ended = within(limit, || {
            status = self.child.try_wait().expect("the subprocess status");
            status.is_some()
        });
        assert!(ended, "{what} did not terminate within {limit:?}");
        status.expect("the wait ended on an exit status")
    }

    /// Wait for exit within `limit` and collect what was drained, plus a
    /// stdout pipe the caller left undrained.
    pub fn finish(&mut self, limit: Duration) -> Output {
        let status = self.wait_within(limit, "the subprocess");
        let stdout = if let Some(reader) = self.stdout.take() {
            reader.join().unwrap()
        } else if let Some(stdout) = self.child.stdout.take() {
            let mut bytes = Vec::new();
            stdout.take(DRAIN_LIMIT).read_to_end(&mut bytes).unwrap();
            bytes
        } else {
            Vec::new()
        };
        let stderr = self
            .stderr
            .take()
            .map(|reader| reader.join().unwrap())
            .unwrap_or_default();
        Output {
            status,
            stdout,
            stderr,
        }
    }

    /// Kill and reap, now.
    pub fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    /// Whether it is still running.
    pub fn running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("the subprocess status")
            .is_none()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Run `command` to completion within `limit`, its stdout and stderr in
/// private files `<dir>/<name>.stdout` and `.stderr`.
pub fn run_to_files(command: &mut Command, dir: &Path, name: &str, limit: Duration) -> Output {
    let stdout = dir.join(format!("{name}.stdout"));
    let stderr = dir.join(format!("{name}.stderr"));
    let status = Process::spawn_to_files(command, &stdout, &stderr).wait_within(limit, name);
    Output {
        status,
        stdout: fs::read(stdout).expect("the command's stdout"),
        stderr: fs::read(stderr).expect("the command's stderr"),
    }
}

/// Start `serve` (the `command` given, ready to run) and wait until it
/// accepts on `<data>/ledger/serve.sock`, a socket only this user may use.
/// Its stderr goes to the private file `log`, quoted when it does not come
/// up in [`WRITER_READY`].
pub fn start_writer(command: &mut Command, data: &Path, log: &Path) -> Process {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(private_file(log)))
        .spawn()
        .expect("the writer starts");
    let mut writer = Process::from_child(child, false);
    let socket = data.join("ledger/serve.sock");
    let listening = within(WRITER_READY, || {
        if let Some(status) = writer.child.try_wait().expect("the writer status") {
            panic!(
                "the writer exited {status}: {}",
                fs::read_to_string(log).unwrap_or_default()
            );
        }
        fs::symlink_metadata(&socket).is_ok_and(|meta| {
            meta.file_type().is_socket() && meta.permissions().mode() & 0o777 == 0o600
        }) && UnixStream::connect(&socket).is_ok()
    });
    assert!(
        listening,
        "the writer did not listen within {WRITER_READY:?}: {}",
        fs::read_to_string(log).unwrap_or_default()
    );
    writer
}
