//! Connection-initiating executable authority from the seccomp mediator and
//! sealed bridge. HTTP headers and child argv never supply process identity.
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    collections::HashMap,
    fs::File,
    sync::{Arc, Condvar, Mutex},
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
/// A pidfd polls readable once its process has exited.
fn alive(file: &File) -> bool {
    use std::os::fd::AsFd as _;
    crate::proxy::sys::ready(file.as_fd(), libc::POLLIN).is_ok_and(|exited| !exited)
}
const MAGIC: &[u8; 8] = b"OUROPID1";
#[derive(Default)]
pub(crate) struct Origins {
    bridge: Mutex<Option<i32>>,
    enabled: AtomicBool,
    stopped: AtomicBool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pins: Arc<AtomicUsize>,
    limit: AtomicUsize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    entries: Mutex<HashMap<(u16, u16), (Instant, Process)>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    published: Condvar,
}
impl Origins {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn set_bridge(&self, pid: i32) {
        *self.bridge.lock().unwrap_or_else(|e| e.into_inner()) = Some(pid);
    }
    pub(crate) fn configure(&self, enabled: bool, limit: usize) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.clear();
        self.stopped.store(false, Ordering::SeqCst);
        self.enabled.store(enabled, Ordering::SeqCst);
        self.limit.store(limit.min(128), Ordering::SeqCst);
    }
    pub(crate) fn stop(&self) {
        // The predicate and its wakeup share the table lock: shutdown cannot
        // race a waiter into sleeping for the whole authority deadline.
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        self.stopped.store(true, Ordering::SeqCst);
        entries.clear();
        self.published.notify_all();
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn prepare(&self, pid: i32, start: u64) -> Option<Process> {
        if !self.enabled.load(Ordering::SeqCst) || self.stopped.load(Ordering::SeqCst) {
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
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        entries.retain(|_, (at, p)| at.elapsed() < Duration::from_secs(10) && alive(&p.0.pidfd));
        if entries.len() >= 128 {
            return;
        }
        // Existing authority cannot be replaced by a later connection.
        entries.entry(key).or_insert((Instant::now(), process));
        self.published.notify_all();
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
            let deadline = Instant::now() + Duration::from_secs(2);
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
            if !self.enabled.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if self.stopped.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(None);
                }
                if let Some((_, process)) = entries.remove(&key) {
                    return Ok(Some(process));
                }
                // TCP accept and the sealed bridge's preamble can run before
                // the successful connect worker publishes its pinned process.
                // Wait only for this exact key; headers/argv never authorize.
                entries = self
                    .published
                    .wait_timeout(entries, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
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

    fn configured(enabled: bool) -> Arc<Origins> {
        let origins = Arc::new(Origins::default());
        origins.set_bridge(std::process::id() as i32);
        origins.configure(enabled, 2);
        origins
    }

    fn bridge(key: (u16, u16)) -> (UnixStream, UnixStream) {
        let (mut bridge, proxy) = UnixStream::pair().unwrap();
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&key.0.to_be_bytes());
        bytes[10..12].copy_from_slice(&key.1.to_be_bytes());
        bridge.write_all(&bytes).unwrap();
        (bridge, proxy)
    }

    fn prepare_self(origins: &Origins) -> Process {
        let pid = std::process::id() as i32;
        let start = crate::platform::linux::identity::start_time_ticks(pid).unwrap();
        origins.prepare(pid, start).unwrap()
    }

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
    fn a_published_origin_is_single_use_and_a_missing_origin_times_out() {
        let origins = configured(true);
        let key = (40002, 3128);
        origins.publish(key, prepare_self(&origins));
        let (_bridge, proxy) = bridge(key);
        assert!(origins.receive(&proxy).unwrap().is_some());
        let (_replay_bridge, replay_proxy) = bridge(key);
        let began = Instant::now();
        assert!(origins.receive(&replay_proxy).unwrap().is_none());
        assert!(began.elapsed() >= Duration::from_secs(2));
        assert!(began.elapsed() < Duration::from_secs(5));
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn another_connection_key_never_authorizes_a_waiter_and_stop_wakes_it() {
        let origins = configured(true);
        let (_bridge, proxy) = bridge((40003, 3128));
        let receiving = origins.clone();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(receiving.receive(&proxy).map(|p| p.is_some()))
                .unwrap();
        });
        origins.publish((40004, 3128), prepare_self(&origins));
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        origins.stop();
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), Ok(false));
        thread.join().unwrap();
        assert!(origins.entries.lock().unwrap().is_empty());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
        let pid = std::process::id() as i32;
        let start = crate::platform::linux::identity::start_time_ticks(pid).unwrap();
        assert!(origins.prepare(pid, start).is_none());
    }

    #[test]
    fn publication_keeps_the_first_authority_and_stopped_origins_stay_closed() {
        let origins = configured(true);
        let key = (40005, 3129);
        let first = prepare_self(&origins);
        origins.publish(key, first.clone());
        origins.publish(key, prepare_self(&origins));
        let (_bridge, proxy) = bridge(key);
        let seen = origins.receive(&proxy).unwrap().unwrap();
        assert!(Arc::ptr_eq(&seen.0, &first.0));
        drop(seen);
        drop(first);
        let pending = prepare_self(&origins);
        origins.stop();
        origins.publish(key, pending);
        let (_late_bridge, late_proxy) = bridge(key);
        assert!(origins.receive(&late_proxy).unwrap().is_none());
        assert_eq!(origins.pins.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_profile_without_process_binding_never_waits_for_origin_authority() {
        let origins = configured(false);
        let (_bridge, proxy) = bridge((40006, 3128));
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(origins.receive(&proxy).map(|p| p.is_some()))
                .unwrap();
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), Ok(false));
        thread.join().unwrap();
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
