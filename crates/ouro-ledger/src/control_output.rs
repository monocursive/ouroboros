//! CLI-only result delivery. The supplied descriptor belongs exclusively to this
//! invocation and is never inherited by the writer, Jail, or executed child.
use ouro_ledger::protocol::{LedgerError, MAX_FRAME_BYTES, Result};
use std::{
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::FileTypeExt,
    },
    sync::mpsc,
    time::{Duration, Instant},
};

const DELIVERY_LIMIT: Duration = Duration::from_secs(2);

pub(crate) struct ControlOutput(File);

fn error(message: impl std::fmt::Display) -> LedgerError {
    LedgerError(format!("--control-fd: {message}"))
}

fn stat(fd: RawFd) -> Option<libc::stat> {
    let mut result = std::mem::MaybeUninit::uninit();
    // SAFETY: fstat initializes the entire supplied stat on success.
    (unsafe { libc::fstat(fd, result.as_mut_ptr()) } == 0).then(|| unsafe { result.assume_init() })
}

fn connected_local_stream(fd: RawFd) -> Result<()> {
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: live fd and correctly sized output buffers.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
        || kind != libc::SOCK_STREAM
    {
        return Err(error("socket must be a connected Unix stream"));
    }
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the zeroed output buffer is large enough for a socket address.
    if unsafe { libc::getpeername(fd, address.as_mut_ptr().cast(), &mut length) } < 0
        || unsafe { address.assume_init() }.ss_family as libc::c_int != libc::AF_UNIX
    {
        return Err(error("socket must be a connected Unix stream"));
    }
    Ok(())
}

impl ControlOutput {
    /// # Safety
    /// `fd` is the caller-supplied, exclusively handed-over CLI descriptor, not
    /// one managed by another Rust object. Call before opening invocation files.
    pub(crate) unsafe fn take(fd: RawFd) -> Result<Self> {
        if fd < 3 {
            return Err(error("must be distinct from stdin, stdout and stderr"));
        }
        // SAFETY: scalar fcntl inspection does not dereference caller memory.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(error("descriptor is not open"));
        }
        // SAFETY: the caller hands ownership over; F_GETFL established an open fd.
        let file = unsafe { File::from_raw_fd(fd) };
        if ![libc::O_WRONLY, libc::O_RDWR].contains(&(flags & libc::O_ACCMODE)) {
            return Err(error("descriptor is not writable"));
        }
        let kind = file.metadata()?.file_type();
        if !(kind.is_file() || kind.is_fifo() || kind.is_socket()) {
            return Err(error(
                "expected a regular file, pipe, or connected Unix stream",
            ));
        }
        let identity = stat(fd).ok_or_else(|| error("cannot inspect descriptor"))?;
        for stdio in 0..=2 {
            if let Some(other) = stat(stdio)
                && identity.st_dev == other.st_dev
                && identity.st_ino == other.st_ino
                && identity.st_mode & libc::S_IFMT == other.st_mode & libc::S_IFMT
            {
                return Err(error("must not alias stdin, stdout or stderr"));
            }
        }
        if kind.is_socket() {
            connected_local_stream(fd)?;
        }
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one initialized pollfd; zero timeout never waits for capacity.
        if unsafe { libc::poll(&mut ready, 1, 0) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if ready.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(error("consumer is disconnected"));
        }
        // Descriptor flags are per-fd. Do not change the shared open-file flags:
        // O_NONBLOCK on a dup would also change the caller's descriptor behavior.
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if descriptor_flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(file))
    }

    /// One final NDJSON run record, matching batch --json. Delivery is not a
    /// durable state transition. A failed write must never rewrite the outcome.
    pub(crate) fn deliver(self, value: &impl serde::Serialize) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(error("result exceeds the 1 MiB frame bound"));
        }
        self.write(bytes, DELIVERY_LIMIT)
    }

    fn write(self, bytes: Vec<u8>, limit: Duration) -> Result<()> {
        let (done, receiver) = mpsc::sync_channel(1);
        // Even regular-file I/O can stall. This CLI-only worker never owns the
        // launch, and process exit tears it down if its final write times out.
        // A consumer must discard any incomplete frame after a delivery error.
        std::thread::Builder::new()
            .name("ledger-control".into())
            .spawn(move || {
                let mut file = self.0;
                let result = write_frame(&mut file, &bytes, Instant::now() + limit);
                let _ = done.send(result);
            })?;
        receiver
            .recv_timeout(limit)
            .map_err(|_| error("result delivery exceeded two seconds"))?
            .map_err(error)
    }
}

fn write_frame(file: &mut File, mut bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control delivery deadline",
            ));
        }
        match file.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let mut ready = libc::pollfd {
                    fd: file.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one live initialized descriptor, bounded retry wait.
                if unsafe { libc::poll(&mut ready, 1, 10) } < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
