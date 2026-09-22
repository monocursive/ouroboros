//! A host-side AF_UNIX listener that records whether anything connected.
//!
//! N05 asserts that a host socket was *never* reached. A connect to a
//! listening socket completes in the kernel as soon as it is queued, whether
//! or not anyone accepts it, so "nobody accepted" proves nothing. The probe
//! therefore accepts everything, closes each connection at once (a client
//! waiting for a reply gets EOF, never a hang), and on [`UnixProbe::stop`]
//! drains whatever is still queued before it answers. Call `stop` after the
//! process under test has exited: every connect it completed is then counted.

use std::ffi::c_int;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;

use crate::cli::UnixLen;
use crate::sockaddr::SockAddr;

/// The socket type a probe listens with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    Stream,
    /// Linux only; `bind` refuses it elsewhere.
    Seqpacket,
}

/// A listening host socket that counts connections. Stops when dropped.
pub struct UnixProbe {
    path: Option<PathBuf>,
    count: Arc<AtomicUsize>,
    wake: Option<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn listener(addr: &SockAddr, kind: ProbeKind) -> io::Result<OwnedFd> {
    let ty = match kind {
        ProbeKind::Stream => libc::SOCK_STREAM,
        ProbeKind::Seqpacket if cfg!(target_os = "linux") => libc::SOCK_SEQPACKET,
        ProbeKind::Seqpacket => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCK_SEQPACKET for AF_UNIX is Linux only",
            ));
        }
    };
    #[cfg(target_os = "linux")]
    let ty = ty | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    // SAFETY: plain integers; the kernel returns a new descriptor or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, ty, 0) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` was just created and is owned by nothing else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    #[cfg(not(target_os = "linux"))]
    {
        crate::bounded::set_cloexec(fd.as_raw_fd()).map_err(io::Error::from_raw_os_error)?;
        crate::bounded::set_nonblocking(fd.as_raw_fd()).map_err(io::Error::from_raw_os_error)?;
    }
    // SAFETY: `SockAddr` never claims more bytes than its live storage.
    if unsafe { libc::bind(fd.as_raw_fd(), addr.as_ptr(), addr.len()) } != 0 {
        return Err(last_error());
    }
    // SAFETY: plain integers on an owned descriptor.
    if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
        return Err(last_error());
    }
    Ok(fd)
}

/// Accept and close everything queued now. Returns how many.
fn drain(fd: c_int) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: NULL address arguments: the peer is not asked for.
        let c = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if c < 0 {
            if last_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return n;
        }
        n += 1;
        // SAFETY: `c` was just returned by `accept` and is owned here.
        unsafe { libc::close(c) };
    }
}

impl UnixProbe {
    /// Listen on a pathname socket at `path` with SOCK_STREAM.
    pub fn bind(path: &Path) -> io::Result<UnixProbe> {
        UnixProbe::bind_kind(path, ProbeKind::Stream)
    }

    /// Listen on a pathname socket at `path`.
    pub fn bind_kind(path: &Path, kind: ProbeKind) -> io::Result<UnixProbe> {
        let addr = SockAddr::unix_path(path.as_os_str().as_bytes(), UnixLen::Nul)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.reason))?;
        let fd = listener(&addr, kind)?;
        UnixProbe::run(fd, Some(path.to_path_buf()))
    }

    /// Listen on an abstract name (Linux): NAME without the leading NUL.
    #[cfg(target_os = "linux")]
    pub fn bind_abstract(name: &[u8], kind: ProbeKind) -> io::Result<UnixProbe> {
        let addr = SockAddr::unix_abstract(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.reason))?;
        let fd = listener(&addr, kind)?;
        UnixProbe::run(fd, None)
    }

    fn run(fd: OwnedFd, path: Option<PathBuf>) -> io::Result<UnixProbe> {
        let (wake_r, wake_w) = super::pipes::cloexec_pipe()?;
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let thread = std::thread::spawn(move || {
            let mut fds = [
                libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_r.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            loop {
                // SAFETY: a live array of two pollfds and its own length.
                let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
                if r < 0 && last_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // Count what is queued now, and once more after a stop so a
                // connection made just before it is not lost.
                seen.fetch_add(drain(fd.as_raw_fd()), Ordering::SeqCst);
                if r < 0 || fds[1].revents != 0 {
                    return;
                }
            }
        });
        Ok(UnixProbe {
            path,
            count,
            wake: Some(wake_w),
            thread: Some(thread),
        })
    }

    /// The socket's path, `None` for an abstract name.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Connections accepted so far. Only [`UnixProbe::stop`] is final.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Stop, drain the queue, and return the final count.
    #[must_use]
    pub fn stop(mut self) -> usize {
        self.shutdown();
        self.count.load(Ordering::SeqCst)
    }

    fn shutdown(&mut self) {
        drop(self.wake.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Some(p) = &self.path {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for UnixProbe {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_that_is_never_waited_for_is_still_counted() {
        let dir = super::super::TempDir::new("ouro-probe").unwrap();
        let path = dir.path().join("host.sock");
        let probe = UnixProbe::bind(&path).unwrap();
        assert_eq!(probe.connections(), 0);
        {
            let _c = std::os::unix::net::UnixStream::connect(&path).unwrap();
        }
        assert_eq!(probe.stop(), 1, "stop drains the queue before answering");
        assert!(!path.exists(), "the probe removes its socket");
    }

    #[test]
    fn a_connection_made_just_before_stop_is_never_lost() {
        // The accept thread may be woken by the connection and by the stop at
        // once; it must drain before it leaves. Repeated, because only some
        // interleavings put both wake-ups in one `poll`.
        let dir = super::super::TempDir::new("ouro-probe").unwrap();
        for i in 0..300 {
            let path = dir.path().join(format!("r{i}.sock"));
            let probe = UnixProbe::bind(&path).unwrap();
            drop(std::os::unix::net::UnixStream::connect(&path).unwrap());
            assert_eq!(probe.stop(), 1, "iteration {i}");
        }
    }

    #[test]
    fn an_untouched_probe_reports_zero() {
        let dir = super::super::TempDir::new("ouro-probe").unwrap();
        let probe = UnixProbe::bind(&dir.path().join("idle.sock")).unwrap();
        assert_eq!(probe.stop(), 0);
    }

    #[test]
    fn a_path_that_does_not_fit_is_refused_before_any_socket() {
        let long = PathBuf::from(format!("/tmp/{}", "p".repeat(200)));
        let err = UnixProbe::bind(&long).err().expect("must refuse");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("path_too_long"), "{err}");
    }

    #[test]
    fn seqpacket_is_linux_only() {
        let dir = super::super::TempDir::new("ouro-probe").unwrap();
        let r = UnixProbe::bind_kind(&dir.path().join("sp.sock"), ProbeKind::Seqpacket);
        if cfg!(target_os = "linux") {
            assert_eq!(r.unwrap().stop(), 0);
        } else {
            assert_eq!(r.err().unwrap().kind(), io::ErrorKind::Unsupported);
        }
    }
}
