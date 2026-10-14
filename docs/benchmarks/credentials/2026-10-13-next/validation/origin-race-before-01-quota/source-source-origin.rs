//! Connection-initiating executable authority from the seccomp mediator and
//! sealed bridge. HTTP headers and child argv never supply process identity.
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    collections::HashMap,
    fs::File,
    sync::{Arc, Mutex},
    time::Instant,
};
#[derive(Clone, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    ctime: (i64, i64),
}
fn identity(file: &File) -> std::io::Result<Identity> {
    let m = file.metadata()?;
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}
pub(super) struct Executable {
    _file: File,
    identity: Identity,
}
impl Executable {
    pub(super) fn pin(path: &str) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "vault executable cannot be pinned")?;
        let m = file
            .metadata()
            .map_err(|_| "vault executable cannot be inspected")?;
        if !m.is_file() || m.mode() & 0o111 == 0 || m.mode() & 0o022 != 0 {
            return Err("vault executable needs a non-writable regular executable".into());
        }
        let identity = identity(&file).map_err(|_| "vault executable cannot be inspected")?;
        Ok(Self {
            _file: file,
            identity,
        })
    }
}
#[derive(Clone)]
pub(crate) struct Process(Arc<Pinned>);
struct Pinned {
    pid: i32,
    _exe: File,
    pidfd: File,
    identity: Identity,
    _reservation: Option<Reservation>,
}
struct Reservation(Arc<AtomicUsize>);
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Process {
    #[cfg(target_os = "linux")]
    #[cfg(test)]
    pub(crate) fn capture(pid: i32, start: u64) -> Option<Self> {
        Self::capture_reserved(pid, start, None)
    }
    #[cfg(target_os = "linux")]
    fn capture_reserved(pid: i32, start: u64, reservation: Option<Reservation>) -> Option<Self> {
        // SAFETY: scalar pidfd_open arguments; a successful fresh fd is owned here.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd < 0 {
            return None;
        }
        // SAFETY: syscall returned an owned descriptor.
        let pidfd = unsafe { File::from_raw_fd(fd) };
        if !alive(&pidfd) || crate::platform::linux::identity::start_time_ticks(pid).ok()? != start
        {
            return None;
        }
        // Follow only the kernel's proc executable link with the pidfd held.
        let exe = File::open(format!("/proc/{pid}/exe")).ok()?;
        let identity = identity(&exe).ok()?;
        if !alive(&pidfd) || crate::platform::linux::identity::start_time_ticks(pid).ok()? != start
        {
            return None;
        }
        Some(Self(Arc::new(Pinned {
            pid,
            _exe: exe,
            pidfd,
            identity,
            _reservation: reservation,
        })))
    }
    fn current(&self) -> Option<Identity> {
        if !alive(&self.0.pidfd) {
            return None;
        }
        let file = File::open(format!("/proc/{}/exe", self.0.pid)).ok()?;
        let seen = identity(&file).ok()?;
        (seen == self.0.identity && alive(&self.0.pidfd)).then_some(seen)
    }
    pub(super) fn permits(&self, allowed: &[Executable]) -> bool {
        let Some(current) = self.current() else {
            return false;
        };
        allowed
            .iter()
            .any(|e| e.identity == current && identity(&e._file).is_ok_and(|i| i == e.identity))
            && alive(&self.0.pidfd)
    }
}
fn alive(file: &File) -> bool {
    let mut fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd; timeout zero never blocks.
    unsafe { libc::poll(&mut fd, 1, 0) == 0 }
}
const MAGIC: &[u8; 8] = b"OUROPID1";
#[derive(Default)]
pub(crate) struct Origins {
    bridge: Mutex<Option<i32>>,
    enabled: AtomicBool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pins: Arc<AtomicUsize>,
    limit: AtomicUsize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    entries: Mutex<HashMap<(u16, u16), (Instant, Process)>>,
}
impl Origins {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_bridge(&self, pid: i32) {
        *self.bridge.lock().unwrap_or_else(|e| e.into_inner()) = Some(pid);
    }
    pub(crate) fn configure(&self, enabled: bool, limit: usize) {
        self.enabled.store(enabled, Ordering::SeqCst);
        self.limit.store(limit.min(128), Ordering::SeqCst);
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare(&self, pid: i32, start: u64) -> Option<Process> {
        if !self.enabled.load(Ordering::SeqCst) {
            return None;
        }
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (at, p)| at.elapsed() < Duration::from_secs(10) && alive(&p.0.pidfd));
        let limit = self.limit.load(Ordering::SeqCst);
        self.pins
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < limit).then_some(count + 1)
            })
            .ok()?;
        Process::capture_reserved(pid, start, Some(Reservation(self.pins.clone())))
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn connected(&self, process: Process, fd: RawFd) {
        if process.current().is_none() {
            return;
        }
        let mut local: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&local) as libc::socklen_t;
        // SAFETY: correctly sized address buffers and connected descriptor.
        if unsafe { libc::getsockname(fd, (&mut local as *mut libc::sockaddr_in).cast(), &mut len) }
            != 0
            || local.sin_family != libc::AF_INET as u16
        {
            return;
        }
        len = std::mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe { libc::getpeername(fd, (&mut peer as *mut libc::sockaddr_in).cast(), &mut len) }
            != 0
            || peer.sin_family != libc::AF_INET as u16
            || peer.sin_addr.s_addr != u32::from_ne_bytes([127, 0, 0, 1])
        {
            return;
        }
        let port = u16::from_be(peer.sin_port);
        if ![3128, 3129].contains(&port) {
            return;
        }
        self.publish((u16::from_be(local.sin_port), port), process);
    }
    #[cfg(target_os = "linux")]
    fn publish(&self, key: (u16, u16), process: Process) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, (at, p)| at.elapsed() < Duration::from_secs(10) && alive(&p.0.pidfd));
        if entries.len() >= 128 {
            return;
        }
        // Existing authority cannot be replaced by a later connection.
        entries.entry(key).or_insert((Instant::now(), process));
    }
    pub(crate) fn receive(
        &self,
        socket: &std::os::unix::net::UnixStream,
    ) -> Result<Option<Process>, crate::proxy::Reason> {
        let expected = *self.bridge.lock().unwrap_or_else(|e| e.into_inner());
        let Some(expected) = expected else {
            return Ok(None);
        };
        #[cfg(target_os = "linux")]
        {
            // The mediator performs connect on the sealed bridge's duplicated
            // descriptor. Linux stamps that connecting actor's credentials, not
            // the original socket creator. Direct child proxy-node connects are
            // already refused by restrict_authorized_connector(pid,start).
            let _sealed_bridge = expected;
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
            // SAFETY: a sized credential buffer and a live Unix socket.
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            } != 0
                || cred.pid != std::process::id() as i32
            {
                return Err(crate::proxy::Reason::CredentialProcessDenied);
            }
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|_| crate::proxy::Reason::InternalError)?;
            let mut bytes = [0u8; 12];
            (&*socket)
                .read_exact(&mut bytes)
                .map_err(|_| crate::proxy::Reason::CredentialProcessDenied)?;
            socket
                .set_read_timeout(None)
                .map_err(|_| crate::proxy::Reason::InternalError)?;
            if &bytes[..8] != MAGIC {
                return Err(crate::proxy::Reason::CredentialProcessDenied);
            }
            let key = (
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
            );
            let process = self
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key)
                .map(|(_, p)| p);
            Ok(process)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (socket, expected);
            Err(crate::proxy::Reason::CredentialProcessDenied)
        }
    }
}
pub(crate) fn preamble(client: &std::net::TcpStream) -> std::io::Result<[u8; 12]> {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&client.peer_addr()?.port().to_be_bytes());
    bytes[10..12].copy_from_slice(&client.local_addr()?.port().to_be_bytes());
    Ok(bytes)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    #[test]
    fn a_bridge_preamble_before_connect_publication_waits_for_pinned_authority() {
        let origins = Arc::new(Origins::default());
        let pid = std::process::id() as i32;
        origins.set_bridge(pid);
        origins.configure(true, 2);
        let start = crate::platform::linux::identity::start_time_ticks(pid).unwrap();
        let process = origins.prepare(pid, start).unwrap();
        let key = (40001u16, 3128u16);
        let (mut bridge, proxy) = UnixStream::pair().unwrap();
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&key.0.to_be_bytes());
        bytes[10..12].copy_from_slice(&key.1.to_be_bytes());
        bridge.write_all(&bytes).unwrap();
        let (tx, rx) = mpsc::channel();
        let receiving = origins.clone();
        let thread = std::thread::spawn(move || {
            tx.send(receiving.receive(&proxy).map(|p| p.is_some()))
                .unwrap();
        });
        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "the authenticated bridge can beat the connect worker's publication"
        );
        origins.publish(key, process);
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), Ok(true));
        thread.join().unwrap();
        assert!(origins.entries.lock().unwrap().is_empty());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn only_the_kernel_pinned_executable_can_authorize_a_connection() {
        let pid = std::process::id() as i32;
        let start = crate::platform::linux::identity::start_time_ticks(pid).unwrap();
        let process = Process::capture(pid, start).unwrap();
        let actual = std::env::current_exe().unwrap().canonicalize().unwrap();
        // Cargo's executable can be group writable under an operator umask.
        // This fixture tests kernel identity separately from the production
        // path constructor's stricter permission rule.
        let file = File::open(actual).unwrap();
        let authority = Executable {
            identity: identity(&file).unwrap(),
            _file: file,
        };
        assert!(process.permits(&[authority]));
        assert!(
            !process.permits(&[Executable::pin(
                std::path::Path::new("/usr/bin/true")
                    .canonicalize()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
            .unwrap()])
        );
        assert!(Process::capture(pid, start + 1).is_none());
    }
}
