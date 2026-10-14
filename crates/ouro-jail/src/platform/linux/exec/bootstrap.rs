//! Atomic creation of the trusted, blocked bootstrap in its execution leaf.
//!
//! No VM, descriptor table, signal handler table or stack is shared with the
//! parent. Every allocation and descriptor duplicate precedes clone3; the child
//! first arms parent-death protection, then uses only async-signal-safe calls
//! before exec. The ordinary Command path keeps the same guards when this
//! optional kernel mechanism is unavailable.

use std::ffi::{CString, OsStr, OsString};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};

use super::{FdMap, REAP_STEP, close_range_cloexec, die_with_parent_after_fork, pipe};
use crate::platform::linux::clock::Deadline;
use crate::platform::linux::identity::pidfd_send_signal;

/// Actual bootstrap mechanism, retained independently of child reaping.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BootstrapSpawn {
    Clone3IntoCgroup,
    Command { clone3_errno: Option<i32> },
}

impl BootstrapSpawn {
    pub(crate) fn evidence(self) -> serde_json::Value {
        match self {
            Self::Clone3IntoCgroup => serde_json::json!({"mechanism": "clone3_into_cgroup"}),
            Self::Command { clone3_errno } => serde_json::json!({
                "mechanism": "command", "clone3_errno": clone3_errno,
            }),
        }
    }
}

pub(crate) enum BootstrapChild {
    Command {
        child: Child,
        spawn: BootstrapSpawn,
    },
    Direct {
        pid: libc::pid_t,
        pidfd: OwnedFd,
        status: Option<ExitStatus>,
    },
}

impl BootstrapChild {
    pub(crate) fn id(&self) -> u32 {
        match self {
            Self::Command { child, .. } => child.id(),
            Self::Direct { pid, .. } => *pid as u32,
        }
    }

    pub(crate) fn spawn(&self) -> BootstrapSpawn {
        match self {
            Self::Command { spawn, .. } => *spawn,
            Self::Direct { .. } => BootstrapSpawn::Clone3IntoCgroup,
        }
    }

    pub(crate) fn created_in_cgroup(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Command { child, .. } => child.kill(),
            Self::Direct { pidfd, .. } => pidfd_send_signal(pidfd.as_raw_fd(), libc::SIGKILL),
        }
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self {
            Self::Command { child, .. } => child.try_wait(),
            Self::Direct { pid, status, .. } => {
                if status.is_some() {
                    return Ok(*status);
                }
                let mut raw = 0;
                // SAFETY: this is our unreaped child and raw is writable. No
                // wait is attempted while the boundary's tracer owns waitpid.
                let result = unsafe { libc::waitpid(*pid, &raw mut raw, libc::WNOHANG) };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    return if error.kind() == io::ErrorKind::Interrupted {
                        Ok(None)
                    } else {
                        Err(error)
                    };
                }
                if result != 0 {
                    *status = Some(ExitStatus::from_raw(raw));
                }
                Ok(*status)
            }
        }
    }

    pub(crate) fn reap_until(&mut self, deadline: Deadline) {
        while matches!(self.try_wait(), Ok(None)) && !deadline.expired() {
            std::thread::sleep(REAP_STEP);
        }
    }

    /// Kills the child and reaps it within a fresh tree budget. A spent
    /// preparation deadline must not spend the kill/reap budget too, or the
    /// refusal leaves a zombie, or a child still dying, behind.
    pub(crate) fn kill_and_reap(&mut self) {
        let _ = self.kill();
        self.reap_until(Deadline::after(crate::supervisor::TREE_BUDGET));
    }
}

/// A bootstrap child until preparation hands it to the boundary that owns
/// it: dropped before then (by any refusal between the spawn and the
/// hand-over), it is killed and reaped ([`BootstrapChild::kill_and_reap`]).
pub(crate) struct KillOnDrop(Option<BootstrapChild>);

impl KillOnDrop {
    pub(crate) fn new(child: BootstrapChild) -> Self {
        Self(Some(child))
    }

    /// The child, which this guard then no longer kills.
    pub(crate) fn hand_over(mut self) -> BootstrapChild {
        self.0
            .take()
            .expect("the child is held until it is handed over")
    }
}

impl std::ops::Deref for KillOnDrop {
    type Target = BootstrapChild;

    fn deref(&self) -> &BootstrapChild {
        self.0
            .as_ref()
            .expect("the child is held until it is handed over")
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            child.kill_and_reap();
        }
    }
}

// Linux UAPI clone_args v2, including its 64-bit flags and cgroup descriptor.
// CLONE_CLEAR_SIGHAND prevents inherited Rust handlers running in the fork
// window. SIG_IGN and the caller's signal mask are preserved, as across exec.
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

fn compatible_fallback(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ENOSYS
                | libc::EINVAL
                | libc::E2BIG
                | libc::EOPNOTSUPP
                | libc::EPERM
                | libc::EACCES
        )
    )
}

fn text(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bootstrap argument contains NUL",
        )
    })
}

/// Spawn only the trusted bootstrap. It still blocks on START_FD; no backend
/// fork/namespace operation is released until the existing watcher is ready.
pub(crate) fn spawn_bootstrap(
    executable: &Path,
    arguments: &[OsString],
    map: &FdMap,
    cgroup: Option<&OwnedFd>,
    deadline: Deadline,
) -> io::Result<BootstrapChild> {
    let fallback = |clone3_errno| {
        let mut command = Command::new(executable);
        command.args(arguments);
        map.apply(&mut command);
        Ok(BootstrapChild::Command {
            child: command.spawn()?,
            spawn: BootstrapSpawn::Command { clone3_errno },
        })
    };
    let Some(cgroup) = cgroup else {
        return fallback(None);
    };
    let executable_fd: OwnedFd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(executable)?
        .into();
    let executable_fd = map.reserve(executable_fd)?;
    let argv: Vec<CString> = std::iter::once(executable.as_os_str())
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(text)
        .collect::<io::Result<_>>()?;
    let environment: Vec<CString> = std::env::vars_os()
        .map(|(key, value)| {
            let mut pair = key;
            pair.push("=");
            pair.push(value);
            text(&pair)
        })
        .collect::<io::Result<_>>()?;
    let pointers = |values: &[CString]| {
        values
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>()
    };
    let argv_pointers = pointers(&argv);
    let env_pointers = pointers(&environment);
    let moves: Vec<_> = map
        .moves
        .iter()
        .map(|(fd, target)| (fd.as_raw_fd(), *target))
        .collect();
    let (error_read, error_write) = pipe()?;
    let error_write = map.reserve(error_write)?;
    // Read errors and EOF through a bounded parent-side handshake.
    // SAFETY: the read end is owned and F_GETFL takes no pointer argument.
    let flags = unsafe { libc::fcntl(error_read.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an owned descriptor and scalar file-status flags.
    if unsafe {
        libc::fcntl(
            error_read.as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let parent = crate::sys::own_pid();
    let mut pidfd = -1i32;
    let mut args = CloneArgs {
        flags: CLONE_INTO_CGROUP | CLONE_CLEAR_SIGHAND | libc::CLONE_PIDFD as u64,
        pidfd: (&raw mut pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup.as_raw_fd() as u64,
        ..CloneArgs::default()
    };
    // SAFETY: the v2 UAPI structure and output pointer are live. There is no
    // CLONE_VM, CLONE_VFORK, CLONE_FILES, CLONE_THREAD or shared handler table.
    // The child's stack/address space is a separate fork-style copy, and its
    // branch never returns, allocates, unwinds or drops inherited Rust objects.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw mut args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if pid == 0 {
        // SAFETY: first child operation is the existing parent-death guard;
        // all buffers/moves were built before clone. Remaining calls are
        // close, close_range, dup2, execveat, write and _exit only.
        unsafe {
            die_with_parent_after_fork(parent);
            libc::close(error_read.as_raw_fd());
            let result: io::Result<()> = close_range_cloexec().and_then(|()| {
                for (source, target) in &moves {
                    if libc::dup2(*source, *target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                let empty = c"";
                libc::syscall(
                    libc::SYS_execveat,
                    executable_fd.as_raw_fd(),
                    empty.as_ptr(),
                    argv_pointers.as_ptr(),
                    env_pointers.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                Err(io::Error::last_os_error())
            });
            report_failure_and_exit(
                error_write.as_raw_fd(),
                result
                    .err()
                    .and_then(|e| e.raw_os_error())
                    .unwrap_or(libc::EIO),
            );
        }
    }
    if pid < 0 {
        let error = io::Error::last_os_error();
        return if compatible_fallback(&error) {
            fallback(error.raw_os_error())
        } else {
            Err(error)
        };
    }
    // SAFETY: successful CLONE_PIDFD writes a new owned descriptor in parent.
    let mut child = BootstrapChild::Direct {
        pid: pid as libc::pid_t,
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
        status: None,
    };
    drop(error_write);
    let result = exec_handshake(error_read.as_fd(), deadline);
    if let Err(error) = result {
        child.kill_and_reap();
        return Err(error);
    }
    Ok(child)
}

unsafe fn report_failure_and_exit(descriptor: RawFd, errno: i32) -> ! {
    let bytes = crate::platform::linux::sys::errno_bytes(errno);
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: descriptor and remaining fixed-size errno bytes are live.
        let result = unsafe {
            libc::write(
                descriptor,
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        } else {
            break;
        }
    }
    // SAFETY: _exit takes a scalar and never returns; it runs no Rust
    // destructor in the forked child.
    unsafe { libc::_exit(crate::platform::linux::launch::EXIT_INTERNAL) }
}

fn exec_handshake(descriptor: BorrowedFd<'_>, deadline: Deadline) -> io::Result<()> {
    let mut bytes = [0u8; 4];
    let mut received = 0;
    loop {
        // SAFETY: the unread suffix of the errno buffer is writable.
        let result = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                bytes[received..].as_mut_ptr().cast(),
                bytes.len() - received,
            )
        };
        if result > 0 {
            received += result as usize;
            if received == bytes.len() {
                return Err(io::Error::from_raw_os_error(
                    crate::platform::linux::sys::errno_from_bytes(bytes),
                ));
            }
            continue;
        }
        if result == 0 {
            return if received == 0 {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete bootstrap exec errno",
                ))
            };
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
        if deadline.expired() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "bootstrap exec did not complete before preparation deadline",
            ));
        }
        crate::platform::linux::sys::poll_one(
            descriptor,
            libc::POLLIN,
            deadline.remaining_millis_capped(100),
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::cgroup::ExecutionCgroup;
    use std::io::{Read, Write};
    use std::time::Duration;

    struct ProbeChild(BootstrapChild);
    impl Drop for ProbeChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            self.0.reap_until(Deadline::after(Duration::from_secs(5)));
        }
    }

    fn leaf() -> Option<ExecutionCgroup> {
        let limits = crate::policy::LimitsSnapshot {
            wall: None,
            pids: None,
            mem: None,
            swap: None,
            storage: None,
            inodes: None,
            cpu: None,
        };
        match ExecutionCgroup::create(&limits) {
            Ok(leaf) => Some(leaf),
            Err(error) => {
                ouro_fixture::harness::skip_or_fail(&format!("bootstrap cgroup fixture: {error}"));
                None
            }
        }
    }

    fn nonblocking(fd: BorrowedFd<'_>) {
        crate::platform::linux::sys::set_nonblocking(fd).unwrap();
    }

    #[test]
    fn direct_creation_has_read_back_membership_parent_death_and_exact_fd_layout() {
        let Some(leaf) = leaf() else { return };
        let python = match Path::new("/usr/bin/python3").canonicalize() {
            Ok(path) => path,
            Err(error) => {
                ouro_fixture::harness::skip_or_fail(&format!("Python readback fixture: {error}"));
                return;
            }
        };
        let source = tempfile::tempfile().unwrap();
        // SAFETY: source is owned; the duplicate is new and checked below.
        let sentinel = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 777) };
        assert_eq!(sentinel, 777);
        // SAFETY: the successful fcntl returned this newly owned descriptor.
        let _sentinel = unsafe { OwnedFd::from_raw_fd(sentinel) };
        let (report, writer) = pipe().unwrap();
        let (release, gate) = pipe().unwrap();
        let mut descriptors = FdMap::with_target_limit(768);
        descriptors.add(writer, 700).unwrap();
        descriptors.add(release, 701).unwrap();
        let program = "import os,ctypes,json\ns=ctypes.c_int()\n\
            assert ctypes.CDLL(None).prctl(2,ctypes.byref(s),0,0,0)==0\n\
            data={'signal':s.value,'sentinel_closed':not os.path.exists('/proc/self/fd/777'),\
            'cgroup':open('/proc/self/cgroup').read().strip(),'pid':os.getpid()}\n\
            os.write(700,(json.dumps(data)+'\\n').encode())\nos.read(701,1)\n";
        let fd = leaf.spawn_handle().unwrap();
        let mut child = ProbeChild(
            spawn_bootstrap(
                &python,
                &["-c".into(), program.into()],
                &descriptors,
                Some(&fd),
                Deadline::after(Duration::from_secs(5)),
            )
            .unwrap(),
        );
        drop(descriptors);
        if !child.0.created_in_cgroup() {
            ouro_fixture::harness::skip_or_fail("direct cgroup creation is unavailable in fixture");
            return;
        }
        leaf.verify_member(child.0.id() as i32).unwrap();
        nonblocking(report.as_fd());
        let mut file = std::fs::File::from(report);
        let mut bytes = Vec::new();
        let deadline = Deadline::after(Duration::from_secs(5));
        while !bytes.ends_with(b"\n") {
            let mut block = [0u8; 512];
            match file.read(&mut block) {
                Ok(0) => panic!("readback fixture ended before its report"),
                Ok(size) => bytes.extend_from_slice(&block[..size]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("readback fixture: {error}"),
            }
            assert!(!deadline.expired(), "readback fixture deadline");
            std::thread::sleep(REAP_STEP);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["signal"], libc::SIGKILL);
        assert_eq!(value["sentinel_closed"], true);
        assert_eq!(value["pid"], child.0.id());
        assert_eq!(
            value["cgroup"],
            format!("0::{}", leaf.relative_path().unwrap())
        );
        std::fs::File::from(gate).write_all(b"x").unwrap();
        child.0.reap_until(deadline);
        let status = child.0.try_wait().unwrap().unwrap();
        assert!(status.success());
        assert_eq!(child.0.try_wait().unwrap(), Some(status));
        assert!(!leaf.populated().unwrap());
    }

    #[test]
    fn failed_exec_reports_errno_and_reaps_the_child_in_the_leaf() {
        let Some(leaf) = leaf() else { return };
        let file = tempfile::NamedTempFile::new().unwrap();
        let before = std::fs::read_to_string("/proc/thread-self/children").unwrap();
        let result = spawn_bootstrap(
            file.path(),
            &[],
            &FdMap::new(),
            Some(&leaf.spawn_handle().unwrap()),
            Deadline::after(Duration::from_secs(5)),
        );
        let error = match result {
            Err(error) => error,
            Ok(child) => {
                drop(ProbeChild(child));
                panic!("nonexecutable file unexpectedly executed");
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        assert!(!leaf.populated().unwrap());
        assert_eq!(
            std::fs::read_to_string("/proc/thread-self/children").unwrap(),
            before
        );
    }

    #[test]
    fn a_dropped_guard_kills_and_reaps_the_child() {
        let child = spawn_bootstrap(
            Path::new("/bin/sleep"),
            &["30".into()],
            &FdMap::new(),
            None,
            Deadline::after(Duration::from_secs(5)),
        )
        .unwrap();
        let pid = child.id();
        let guard = KillOnDrop::new(child);
        assert!(Path::new(&format!("/proc/{pid}")).exists());
        drop(guard);
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the child is killed and reaped, not left a zombie"
        );

        let child = spawn_bootstrap(
            Path::new("/bin/sleep"),
            &["30".into()],
            &FdMap::new(),
            None,
            Deadline::after(Duration::from_secs(5)),
        )
        .unwrap();
        let mut owned = KillOnDrop::new(child).hand_over();
        assert!(
            matches!(owned.try_wait(), Ok(None)),
            "a handed-over child is its owner's"
        );
        owned.kill_and_reap();
        assert!(matches!(owned.try_wait(), Ok(Some(_))));
    }

    #[test]
    fn exec_handshake_rejects_a_partial_errno_and_honors_its_deadline() {
        let (read, write) = pipe().unwrap();
        std::fs::File::from(write).write_all(&[1, 2]).unwrap();
        nonblocking(read.as_fd());
        let error =
            exec_handshake(read.as_fd(), Deadline::after(Duration::from_secs(1))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let (read, _write) = pipe().unwrap();
        nonblocking(read.as_fd());
        let error = exec_handshake(read.as_fd(), Deadline::after(Duration::ZERO)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn resource_and_leaf_failures_are_not_compatibility_retries() {
        for errno in [
            libc::EAGAIN,
            libc::ENOMEM,
            libc::EBUSY,
            libc::EBADF,
            libc::ENOENT,
        ] {
            assert!(!compatible_fallback(&std::io::Error::from_raw_os_error(
                errno
            )));
        }
    }
}
