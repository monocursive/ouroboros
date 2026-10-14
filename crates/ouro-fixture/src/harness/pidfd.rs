//! Process handles that cannot be recycled (Linux).
//!
//! A pidfd names one process for as long as the descriptor is open, so a
//! signal sent through it never reaches a process that later reused the
//! number, and it turns readable when that process exits. Tests that signal
//! a process they did not spawn themselves (a writer found through its
//! socket peer, a reparented jail) pin it this way first.

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::Duration;

/// Pin process `pid`.
///
/// # Errors
/// The errno of `pidfd_open`: `ESRCH` when no such process exists.
pub fn open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: plain integers; the kernel returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(|_| io::Error::other("pidfd_open returned no fd"))?;
    // SAFETY: `fd` was just returned by `pidfd_open` and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Send `signal` to the process `fd` pins.
///
/// # Errors
/// The errno of `pidfd_send_signal`: `ESRCH` when the process has already
/// exited (its pidfd still names it, so the signal cannot go elsewhere).
pub fn send_signal(fd: BorrowedFd<'_>, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: a live pidfd, a signal number, a null siginfo (the kernel
    // fills in the default one) and no flags.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait up to `bound` for the process `fd` pins to exit: true when it did.
///
/// # Errors
/// The errno of `poll`, other than an interruption.
pub fn wait_exit(fd: BorrowedFd<'_>, bound: Duration) -> io::Result<bool> {
    let deadline = std::time::Instant::now() + bound;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, and the count passed is 1.
        match unsafe { libc::poll(&raw mut pfd, 1, ms) } {
            1 => return Ok(true),
            0 => return Ok(false),
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use super::*;

    /// A pinned child is signalled through its pidfd, the pidfd turns
    /// readable when it exits, and a signal after the exit is `ESRCH` rather
    /// than a signal to whatever reuses the number.
    #[test]
    fn a_pinned_process_is_signalled_and_seen_to_exit() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("sleep starts");
        let pid = libc::pid_t::try_from(child.id()).expect("a pid");
        let fd = open(pid).expect("the child is pinned");
        assert!(!wait_exit(fd.as_fd(), Duration::ZERO).unwrap());
        send_signal(fd.as_fd(), libc::SIGKILL).expect("the signal is sent");
        assert!(wait_exit(fd.as_fd(), Duration::from_secs(10)).unwrap());
        child.wait().expect("the child is reaped");
        let error = send_signal(fd.as_fd(), libc::SIGKILL).expect_err("no process left");
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    }
}
