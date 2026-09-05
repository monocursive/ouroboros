//! Bounded Unix subprocesses for machine provisioning and service management.
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const OUTPUT_CAP: usize = 1024 * 1024;

struct ProcessGroup(Child, bool);

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // Only our freshly spawned process group is signalled. Also close descendants
        // retaining a pipe after the direct child exits.
        if self.1 {
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        }
        let _ = self.0.wait();
    }
}

pub fn output(
    mut command: Command,
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> Result<Output> {
    if cancelled() {
        bail!("cancelled by the operator");
    }
    command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut group = ProcessGroup(
        command.spawn().context("starting bounded subprocess")?,
        true,
    );
    let mut stdout = group.0.stdout.take().expect("piped stdout");
    let mut stderr = group.0.stderr.take().expect("piped stderr");
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        if cancelled() {
            bail!("cancelled by the operator; the remote command may have already changed the destination");
        }
        if Instant::now() >= deadline {
            bail!("subprocess exceeded its {} second deadline; inspect the destination before retrying", timeout.as_secs());
        }
        let out_done = drain(&mut stdout, &mut out)?;
        let err_done = drain(&mut stderr, &mut err)?;
        // Keep the leader unreaped until both pipes close. Its reserved PID then
        // cannot be reused for an unrelated process group during timeout cleanup,
        // even if a descendant keeps a pipe open after the leader exits.
        if out_done && err_done {
            if let Some(status) = group.0.try_wait().context("checking subprocess status")? {
                group.1 = false;
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error()).context("making subprocess output nonblocking");
    }
    Ok(())
}

fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool> {
    let mut chunk = [0; 8192];
    // A noisy child cannot keep us inside read forever and starve cancellation.
    for _ in 0..16 {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + count > OUTPUT_CAP {
                    bail!("subprocess output exceeded 1 MiB");
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]).stdin(Stdio::null());
        command
    }

    #[test]
    fn captures_both_streams_and_status() {
        let result = output(
            shell("printf hello; printf error >&2; exit 7"),
            Duration::from_secs(2),
            || false,
        )
        .unwrap();
        assert_eq!(result.stdout, b"hello");
        assert_eq!(result.stderr, b"error");
        assert_eq!(result.status.code(), Some(7));
    }

    #[test]
    fn deadline_reaps_a_process_even_when_a_descendant_holds_its_pipes() {
        let started = Instant::now();
        let error = output(
            shell("sleep 30 & exit 0"),
            Duration::from_millis(120),
            || false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cancellation_interrupts_an_inflight_command() {
        let started = Instant::now();
        let error = output(shell("sleep 30"), Duration::from_secs(20), || {
            started.elapsed() > Duration::from_millis(100)
        })
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn excessive_output_is_bounded() {
        assert!(
            output(shell("yes output"), Duration::from_secs(2), || false)
                .unwrap_err()
                .to_string()
                .contains("1 MiB")
        );
    }
}
