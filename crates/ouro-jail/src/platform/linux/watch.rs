//! Close bubblewrap's startup parent-death window with an outside pidfd watcher.
//!
//! The backend first re-execs a trusted bootstrap, which retains PDEATHSIG and
//! blocks on a private pipe. Only after a watcher owns both pidfds and confirms
//! readiness can the bootstrap exec bubblewrap. The watcher inherits no stdio or
//! policy/evidence descriptors and stays outside the execution cgroup. If the
//! watcher dies, the live supervisor stops the boundary; if the supervisor dies,
//! the watcher kills the backend even while bubblewrap has cleared PDEATHSIG.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::{clock::Deadline, exec, identity};

pub const START_FD: i32 = 15;

pub struct Watcher {
    child: Child,
    fd: OwnedFd,
}

impl Watcher {
    pub fn start(exe: &Path, backend: i32, deadline: Deadline) -> io::Result<Self> {
        let supervisor = identity::pidfd_open(unsafe { libc::getpid() })?;
        let backend = identity::pidfd_open(backend)?;
        let (ready_r, ready_w) = exec::pipe()?;
        let mut fds = exec::FdMap::new();
        fds.add(supervisor, 3)?;
        fds.add(backend, 4)?;
        fds.add(ready_w, 5)?;
        let mut command = Command::new(exe);
        command
            .arg("__watch")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        fds.apply_watcher(&mut command);
        let mut child = command.spawn()?;
        drop(fds);
        let result = (|| {
            let fd = identity::pidfd_open(child.id() as i32)?;
            if !read_release(ready_r.as_raw_fd(), deadline) {
                return Err(io::Error::other("lifetime watcher did not become ready"));
            }
            Ok(fd)
        })();
        match result {
            Ok(fd) => Ok(Self { child, fd }),
            Err(err) => {
                let _ = child.kill();
                exec::reap_until(&mut child, deadline);
                Err(err)
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn ended(&self) -> bool {
        readable(self.fd.as_raw_fd())
    }
    pub fn reap(&mut self) {
        let _ = self.child.try_wait();
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // Normal settlement has already reaped it. Early preparation errors
        // still allow the watcher to observe backend death and exit itself.
        exec::reap_until(&mut self.child, Deadline::after(Duration::from_millis(100)));
    }
}

/// A pidfd is readable on process exit, including while its zombie is waiting
/// for this supervisor's tracer thread to reap it.
pub fn readable(fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&raw mut pfd, 1, 0) > 0 }
}

fn read_release(fd: i32, deadline: Deadline) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&raw mut pfd, 1, deadline.remaining_millis_capped(1000)) };
        if rc > 0 {
            let mut byte = 0u8;
            return unsafe { libc::read(fd, (&raw mut byte).cast(), 1) } == 1 && byte == 1;
        }
        if deadline.expired()
            || (rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
        {
            return false;
        }
    }
}

pub fn bootstrap_main(args: &[OsString]) -> ! {
    if args.is_empty() || !read_release(START_FD, Deadline::after(Duration::from_secs(30))) {
        std::process::exit(125);
    }
    unsafe {
        libc::close(START_FD);
    }
    let error = Command::new(&args[0]).args(&args[1..]).exec();
    // The supervisor reads the backend's status pipe while it waits for the
    // namespace init, so the reason the backend never started goes there and
    // reaches the refusal; stderr alone is not read back.
    let note = serde_json::json!({ "ouro-bootstrap": format!("backend exec failed: {error}") })
        .to_string()
        + "\n";
    // SAFETY: a live buffer of the stated length. The descriptor may be
    // closed, in which case the write fails and the note is only on stderr.
    unsafe {
        libc::write(super::platform::STATUS_FD, note.as_ptr().cast(), note.len());
    }
    eprintln!("ouro-jail: backend exec failed: {error}");
    std::process::exit(125);
}

pub fn watcher_main() -> ! {
    // pidfd validity is checked by poll below; malformed direct invocations
    // refuse rather than busy-looping or signalling a numeric pid.
    let byte = 1u8;
    if unsafe { libc::write(5, (&raw const byte).cast(), 1) } != 1 {
        std::process::exit(125);
    }
    unsafe {
        libc::close(5);
    }
    let mut fds = [
        libc::pollfd {
            fd: 3,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: 4,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            std::process::exit(125);
        }
        if fds
            .iter()
            .any(|fd| fd.revents & (libc::POLLNVAL | libc::POLLERR) != 0)
        {
            std::process::exit(125);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            std::process::exit(0);
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let _ = identity::pidfd_send_signal(4, libc::SIGKILL);
            std::process::exit(0);
        }
    }
}
