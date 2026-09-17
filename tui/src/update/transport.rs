//! Bounded, cancellable downloads. Curl is an argv-based HTTPS transport only;
//! downloaded bytes are never interpreted as a shell command.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

pub(crate) const MANIFEST_CAP: usize = 64 * 1024;
pub(crate) const BINARY_CAP: usize = 1024 * 1024 * 1024;

pub(crate) struct Curl {
    pub program: std::path::PathBuf,
    pub timeout: Duration,
    /// Cleartext HTTP, permitted only for a loopback origin a test harness supplied
    /// (see [`super::release::Origin`]). Production is `https` and nothing else; the
    /// checksum check is unchanged either way.
    pub allow_http: bool,
}

impl Default for Curl {
    fn default() -> Self {
        Self {
            program: "curl".into(),
            timeout: Duration::from_secs(600),
            allow_http: false,
        }
    }
}

impl Curl {
    fn command(&self, url: &str, head: bool) -> Command {
        let mut command = Command::new(&self.program);
        command.args([
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            if self.allow_http {
                "=https,http"
            } else {
                "=https"
            },
            "--proto-redir",
            if self.allow_http {
                "=https,http"
            } else {
                "=https"
            },
            "--tlsv1.2",
            "--max-redirs",
            "5",
            "--connect-timeout",
            "15",
            "--max-time",
            "600",
        ]);
        if head {
            command.args([
                "--head",
                "--output",
                "/dev/null",
                "--write-out",
                "%{url_effective}",
            ]);
        }
        command.arg("--url").arg(url);
        command
    }

    pub fn get(
        &self,
        url: &str,
        head: bool,
        sink: &mut impl Write,
        cap: usize,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        let status = stream(self.command(url, head), sink, cap, self.timeout, cancelled)
            .context("downloading release data (curl must be installed)")?;
        if !status.success() {
            return Err(CurlFailure(status.code()).into());
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CurlFailure(Option<i32>);
impl std::fmt::Display for CurlFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "curl failed (exit {:?}); check network access, TLS, and release availability",
            self.0
        )
    }
}
impl std::error::Error for CurlFailure {}

pub(crate) fn retryable(error: &anyhow::Error) -> bool {
    // A retry starts a completely new file/hash. Never retry a checksum refusal,
    // local write failure, certificate failure, cancellation, or HTTP 404.
    error
        .downcast_ref::<CurlFailure>()
        .is_some_and(|failure| matches!(failure.0, Some(5 | 6 | 7 | 18 | 28 | 35 | 52 | 55 | 56)))
}

pub(crate) fn capture(
    command: Command,
    cap: usize,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let status = stream(command, &mut bytes, cap, timeout, cancelled)?;
    if !status.success() {
        bail!("subprocess failed (exit {:?})", status.code());
    }
    Ok(bytes)
}

struct Group(Child, bool);
impl Drop for Group {
    fn drop(&mut self) {
        if self.1 {
            // This PID is unreaped and still identifies the process group we own.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
        }
        let _ = self.0.wait();
    }
}

fn stream(
    mut command: Command,
    sink: &mut impl Write,
    cap: usize,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<ExitStatus> {
    check_cancelled(cancelled)?;
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = Group(command.spawn().context("starting update subprocess")?, true);
    let mut stdout = child.0.stdout.take().expect("stdout pipe");
    let mut stderr = child.0.stderr.take().expect("stderr pipe");
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut received = 0;
    let mut errors = 0;
    let deadline = Instant::now() + timeout;
    loop {
        check_cancelled(cancelled)?;
        if Instant::now() >= deadline {
            bail!("update subprocess exceeded its deadline");
        }
        let out_done = drain(&mut stdout, sink, &mut received, cap)?;
        // Drain, but do not forward arbitrary remote/error bytes to the terminal.
        let err_done = drain(&mut stderr, &mut io::sink(), &mut errors, MANIFEST_CAP)?;
        if out_done && err_done {
            if let Some(status) = child.0.try_wait()? {
                child.1 = false;
                return Ok(status);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn check_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        bail!("update cancelled; executable was not replaced");
    }
    Ok(())
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error()).context("configuring update pipe");
    }
    Ok(())
}

fn drain(
    pipe: &mut impl Read,
    sink: &mut impl Write,
    received: &mut usize,
    cap: usize,
) -> Result<bool> {
    let mut bytes = [0; 64 * 1024];
    // Yield to cancellation and stderr even if the producer never stops writing.
    for _ in 0..16 {
        match pipe.read(&mut bytes) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if n > cap.saturating_sub(*received) {
                    bail!("update response exceeds {cap} bytes");
                }
                sink.write_all(&bytes[..n]).context("writing update data")?;
                *received += n;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}
