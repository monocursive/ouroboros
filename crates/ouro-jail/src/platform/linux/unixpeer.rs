//! N05 host-socket isolation: seccomp user-notification mediation of `connect`.
//!
//! jail-v1 §10 and §9.2, CONTRACT §3.4. A network namespace does not isolate
//! *pathname* AF_UNIX sockets in shared mounts, so the `agent` profile mediates
//! every `connect` with a seccomp user-notification listener and decides, in
//! the trusted supervisor, whether the child may reach the named peer. The
//! mechanism was proved on the reference host before this module was written;
//! the measurements are in
//! `docs/specs/jail-v1/evidence/unixpeer-spike-2026-09-22-ouro-ci.txt` (draft in
//! the J3 scratch as of this writing) and every decision below cites the step
//! it implements.
//!
//! The decision, per connect (§3.4 step 3):
//!
//! 1. Read the notification; re-validate its id; take the child's socket with
//!    `pidfd_getfd` (the child is a same-uid descendant, so Yama scope 1 allows
//!    it). The duplicate is the same kernel object, immune to the child
//!    swapping the fd *number* afterwards.
//! 2. Read the `sockaddr` from the child's memory; re-validate the id again
//!    (the TOCTOU guard: a dead or reused task fails the re-validation and
//!    `NOTIF_SEND` returns `ENOENT`).
//! 3. Non-AF_UNIX: the mediator performs the connect on the duplicate. The
//!    socket keeps the child's netns, so this cannot grant egress the netns
//!    forbids; it is required so the child can reach the in-namespace proxy
//!    bridge. See [`NON_UNIX_NOTE`] for the S03 caveat this carries.
//! 4. Abstract AF_UNIX: connect the duplicate directly; abstract names are
//!    scoped by the socket's own netns.
//! 5. Pathname AF_UNIX: resolve the path in the child's view (`/proc/<pid>/root`
//!    for absolute, `/proc/<pid>/cwd` for relative) with `RESOLVE_IN_ROOT` so it
//!    cannot escape, pin the node `O_PATH`, require `S_ISSOCK`, and allow it
//!    only when a *listening* socket bound to that node's filesystem identity
//!    exists in the attempt's netns (`sock_diag` with `UDIAG_SHOW_VFS`). Then
//!    connect the duplicate through `/proc/self/fd/<pinned>`, so the kernel
//!    reaches exactly the checked node and not a path the child could swap.
//!
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE` is never used for a security decision:
//! CONTINUE re-runs the child's own `connect` from its registers after the
//! verdict, which the child can race (fd or memory swap). Every allowed connect
//! goes through the pinned node on the child's *duplicated* socket instead.

/// The S03 caveat measured in the spike (§5/Q3): because the mediator performs
/// a non-AF_UNIX connect in its own LSM context, an inner Landlock net rule
/// (deny TCP connect, or scope abstract unix) that the child installed does
/// **not** compose through this mediation — the mediated connect succeeds where
/// the child's own would be denied. The N05 pathname boundary is unaffected
/// (it never runs the child's connect and always checks node identity plus an
/// attempt-netns listener). The integrator owns the spec decision on whether
/// `agent`'s inner sandbox may rely on Landlock-net; this module implements the
/// egress-preserving choice (mediator connects) and records it honestly.
pub const NON_UNIX_NOTE: &str = "a mediated connect runs in the supervisor's LSM context, so an \
     inner sandbox's Landlock network rules and its abstract-socket scope do \
     not compose through it";

/// A test-only delay, in milliseconds, inserted at the start of servicing each
/// notification (before the first id revalidation). It defaults to zero and has
/// no effect in production; a live test raises it to force the task-death /
/// pid-reuse window that the id revalidation guards, so removing that guard
/// turns a test red (contract rule 6 / review fix 3). It is an atomic load per
/// mediation, which is negligible.
pub static MEDIATION_TEST_DELAY_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Step 1: the mediation filter
// ---------------------------------------------------------------------------

use super::bpf::Program;
pub use super::bpf::SockFilter;
use super::seccomp::AF_UNIX;
#[cfg(test)]
use super::seccomp::{NR_SOCKET, NR_SOCKETPAIR, SD_ARCH, SD_NR, sd_arg_low};

/// `SECCOMP_RET_USER_NOTIF`.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// `SECCOMP_RET_ALLOW`.
pub const SECCOMP_RET_ALLOW: u32 = super::seccomp::SECCOMP_RET_ALLOW;
/// `SECCOMP_RET_ERRNO`.
pub const SECCOMP_RET_ERRNO: u32 = super::seccomp::SECCOMP_RET_ERRNO;
/// `AUDIT_ARCH_X86_64`.
pub const AUDIT_ARCH_X86_64: u32 = super::seccomp::AUDIT_ARCH_X86_64;

#[cfg(test)]
use super::seccomp::{LINUX_EPERM, X32_SYSCALL_BIT};
pub use super::seccomp::{NR_CONNECT, SOCK_SEQPACKET, SOCK_STREAM, SOCK_TYPE_MASK};

/// The mediation filter, as a complete standalone program built with the
/// shared assembler ([`super::bpf::Asm`]).
///
/// It is the second of the `agent` profile's stacked seccomp filters, the one
/// the trusted launcher installs with its own notification listener (the
/// first is the agent baseline bubblewrap loads, see
/// [`super::seccomp::agent_baseline`]). Seccomp evaluates every installed
/// filter and takes the highest-priority action, so the two compose.
///
/// `connect` returns `SECCOMP_RET_USER_NOTIF`; AF_UNIX `socket`/`socketpair`
/// are allowed only for `SOCK_STREAM`/`SOCK_SEQPACKET` (the type masked with
/// `SOCK_TYPE_MASK` so the `SOCK_CLOEXEC`/`SOCK_NONBLOCK` bits do not defeat
/// it), and AF_UNIX `SOCK_DGRAM`/`SOCK_RAW` are refused with `EPERM` because a
/// datagram send can name a peer in `sendmsg`'s `msg_name`, which seccomp
/// cannot read (jail-v1 §10). This is the only filter that restricts AF_UNIX
/// for `agent`: the agent baseline leaves `socket` to it.
///
/// The program is **safe on its own**: it validates the architecture before
/// any syscall number and denies (`EPERM`) every ABI other than native x86_64,
/// and denies the x32 numbering (which shares the x86_64 audit arch), exactly
/// as the `tool` baseline does. It does not rely on a companion filter to
/// reject a compat ABI — the reference host does accept an i386 (int 0x80)
/// ABI, and a non-native `connect` there would otherwise fall through to
/// `SECCOMP_RET_ALLOW` and escape mediation entirely.
///
/// `USER_NOTIF` (0x7fc00000) outranks `SECCOMP_RET_TRACE` (0x7ff00000), so a
/// mediated connect is never a ptrace stop and the observer never sees it
/// (proved in the spike); the mediator reports it instead.
#[must_use]
pub fn mediation_program() -> Program {
    super::seccomp::mediation_filter()
        .expect("the mediation filter is a few dozen instructions and always assembles")
}

/// The mediation filter's instructions, in program order.
#[must_use]
pub fn filter_rules() -> Vec<SockFilter> {
    mediation_program().insns().to_vec()
}

/// The filter's kernel bytes: each instruction as `code` (LE u16), `jt`, `jf`,
/// `k` (LE u32). This is exactly what [`install_filter`] loads and what the
/// live test writes to a file for a launcher stand-in to install, so there is
/// one filter, not two that can drift.
#[must_use]
pub fn filter_bytes() -> Vec<u8> {
    mediation_program().to_bytes()
}

/// `sha256:<hex>` over the filter's kernel bytes, for the receipt.
#[must_use]
pub fn filter_digest() -> String {
    mediation_program().digest()
}

// ---------------------------------------------------------------------------
// Pure address handling (unit-tested without a kernel)
// ---------------------------------------------------------------------------

/// A peer address the child asked to connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerAddr {
    /// A pathname socket; the bytes are the path (no trailing NUL).
    Pathname(Vec<u8>),
    /// An abstract socket; netns-scoped, connected on the duplicate directly.
    Abstract(Vec<u8>),
    /// An unnamed/autobind or empty address.
    Unnamed,
    /// Not an AF_UNIX address; the family is reported.
    NonUnix(u16),
}

/// Classify a `sockaddr` copied from the child's memory.
///
/// A pathname is the `sun_path` bytes up to the first NUL; an abstract address
/// begins with a NUL; a two-byte address (family only) is unnamed. Pure, so the
/// classification is tested directly.
#[must_use]
pub fn classify(sockaddr: &[u8]) -> PeerAddr {
    if sockaddr.len() < 2 {
        return PeerAddr::Unnamed;
    }
    let family = u16::from_ne_bytes([sockaddr[0], sockaddr[1]]);
    if u32::from(family) != AF_UNIX {
        return PeerAddr::NonUnix(family);
    }
    let path = &sockaddr[2..];
    if path.is_empty() {
        return PeerAddr::Unnamed;
    }
    if path[0] == 0 {
        return PeerAddr::Abstract(path[1..].to_vec());
    }
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    if end == 0 {
        PeerAddr::Unnamed
    } else {
        PeerAddr::Pathname(path[..end].to_vec())
    }
}

/// The base directory to resolve a peer path against, in the child's view.
///
/// Absolute paths resolve under the child's root, relative under its cwd, and
/// neither may escape that view (`openat2` with `RESOLVE_IN_ROOT` enforces it).
#[must_use]
pub fn base_for(pid: libc::pid_t, path: &[u8]) -> String {
    if path.first() == Some(&b'/') {
        format!("/proc/{pid}/root")
    } else {
        format!("/proc/{pid}/cwd")
    }
}

/// The path relative to [`base_for`]'s directory (a leading slash removed, so
/// `openat2` resolves it under the pinned root rather than the caller's).
#[must_use]
pub fn relative_bytes(path: &[u8]) -> Vec<u8> {
    if path.first() == Some(&b'/') {
        path[1..].to_vec()
    } else {
        path.to_vec()
    }
}

/// A verdict the mediator delivered, for the wave-2 evidence sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The connect was allowed; the kernel result was returned to the child.
    Allowed,
    /// The connect was denied with this errno and a safe reason code.
    Denied(i32),
}

/// One mediation decision, delivered to the sink so the platform can emit
/// the `net.connect` evidence honestly (the tracer never sees a mediated
/// connect).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediationRecord {
    /// The connecting task's host pid (a thread id).
    pub pid: libc::pid_t,
    // J3-agent begin: what the audit event needs besides the verdict
    /// The thread group the task belonged to while its notification was
    /// pending, read before the verdict was sent; `None` when `/proc` would
    /// not say. The platform uses it to tell a helper's connect (the bridge)
    /// from the target's.
    pub tgid: Option<libc::pid_t>,
    /// The address family the child named, when its `sockaddr` was read.
    pub family: Option<u16>,
    /// Whether the whole `sockaddr` the child passed was read.
    pub address_complete: bool,
    // J3-agent end
    /// A short, safe reason code (never a path or payload).
    pub reason: &'static str,
    /// The verdict.
    pub verdict: Verdict,
}

/// Where the mediator delivers each decision.
pub trait MediationSink: Send + Sync {
    /// Record one decision. Must not block the mediation thread for long.
    fn record(&self, record: MediationRecord);
}

/// A sink that keeps the last decisions, for tests and doctor output.
#[derive(Default)]
pub struct CollectingSink {
    records: std::sync::Mutex<Vec<MediationRecord>>,
}

impl CollectingSink {
    /// Every decision recorded so far.
    #[must_use]
    pub fn drain(&self) -> Vec<MediationRecord> {
        std::mem::take(&mut self.records.lock().unwrap())
    }
}

impl MediationSink for CollectingSink {
    fn record(&self, record: MediationRecord) {
        self.records.lock().unwrap().push(record);
    }
}

#[cfg(target_os = "linux")]
mod live;
#[cfg(target_os = "linux")]
pub use live::{
    FLAG_NEW_LISTENER, FLAG_WAIT_KILLABLE_RECV, LauncherFds, LauncherSetup, MediatorHandle,
    PeerAuthority, install_filter, install_program, launcher_setup, pidfd_getfd, spawn,
    take_from_launcher,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::bpf::{
        CODE_ALU_AND_K as ALU_AND_K, CODE_JA as JA, CODE_JEQ_K as JEQ_K, CODE_JSET_K as JSET_K,
        CODE_LD_W_ABS as LD_W_ABS, CODE_RET_K as RET_K,
    };
    use crate::platform::linux::sockdiag::VfsId;

    #[test]
    fn a_pathname_address_is_read_up_to_its_nul() {
        let mut a = vec![1u8, 0]; // AF_UNIX, little-endian
        a.extend_from_slice(b"/attempt/x.sock\0\0\0");
        assert_eq!(
            classify(&a),
            PeerAddr::Pathname(b"/attempt/x.sock".to_vec())
        );
    }

    #[test]
    fn an_abstract_address_keeps_its_leading_nul_out_of_the_name() {
        let mut a = vec![1u8, 0];
        a.push(0);
        a.extend_from_slice(b"ouro-attempt");
        assert_eq!(classify(&a), PeerAddr::Abstract(b"ouro-attempt".to_vec()));
    }

    #[test]
    fn a_family_only_address_is_unnamed() {
        assert_eq!(classify(&[1u8, 0]), PeerAddr::Unnamed);
    }

    #[test]
    fn a_non_unix_family_is_reported() {
        // AF_INET == 2
        assert_eq!(classify(&[2u8, 0, 0, 80]), PeerAddr::NonUnix(2));
    }

    #[test]
    fn a_short_buffer_is_unnamed_not_a_panic() {
        assert_eq!(classify(&[]), PeerAddr::Unnamed);
        assert_eq!(classify(&[1]), PeerAddr::Unnamed);
    }

    #[test]
    fn absolute_and_relative_paths_pick_root_and_cwd() {
        assert_eq!(base_for(42, b"/a/b"), "/proc/42/root");
        assert_eq!(base_for(42, b"a/b"), "/proc/42/cwd");
        assert_eq!(relative_bytes(b"/a/b"), b"a/b");
        assert_eq!(relative_bytes(b"a/b"), b"a/b");
    }

    #[test]
    fn the_filter_table() {
        // Interpret the program the way the kernel would, so the test checks the
        // jump arithmetic rather than restating it.
        let eperm = SECCOMP_RET_ERRNO | LINUX_EPERM;
        // connect on the native ABI -> USER_NOTIF
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_CONNECT, 0, 0),
            SECCOMP_RET_USER_NOTIF
        );
        // AF_UNIX SOCK_DGRAM / SOCK_RAW -> EPERM; SOCK_STREAM (with CLOEXEC) and
        // SOCK_SEQPACKET -> ALLOW (type masked)
        assert_eq!(run_filter(AUDIT_ARCH_X86_64, NR_SOCKET, AF_UNIX, 2), eperm);
        assert_eq!(run_filter(AUDIT_ARCH_X86_64, NR_SOCKET, AF_UNIX, 3), eperm);
        assert_eq!(
            run_filter(
                AUDIT_ARCH_X86_64,
                NR_SOCKET,
                AF_UNIX,
                SOCK_STREAM | 0x0008_0000
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_SOCKET, AF_UNIX, SOCK_SEQPACKET),
            SECCOMP_RET_ALLOW
        );
        // non-AF_UNIX socket, socketpair DGRAM, and an unrelated syscall
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_SOCKET, 2, SOCK_STREAM),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_SOCKETPAIR, AF_UNIX, 2),
            eperm
        );
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, 1 /* write */, 0, 0),
            SECCOMP_RET_ALLOW
        );

        // Architecture coverage: the fragment fails closed on its own. Every
        // non-native ABI is denied EPERM regardless of the syscall, so a compat
        // connect cannot escape mediation.
        for arch in [
            0xc000_00b7u32, // aarch64
            0x4000_0003,    // i386
            0x4000_00b7,    // arm (32-bit)
            0,
            0xffff_ffff,
        ] {
            for nr in [NR_CONNECT, NR_SOCKET, 20 /* i386 getpid */, 39, 42] {
                assert_eq!(
                    run_filter(arch, nr, AF_UNIX, 0),
                    eperm,
                    "arch {arch:#x} nr {nr}"
                );
            }
        }
        // x32 shares the x86_64 audit arch but its numbering is distinct, so it
        // is denied even though the arch matches.
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, X32_SYSCALL_BIT | NR_CONNECT, 0, 0),
            eperm
        );
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, X32_SYSCALL_BIT | 59, 0, 0),
            eperm
        );
    }

    #[test]
    fn the_digest_is_stable_and_specific() {
        let d = filter_digest();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
        assert_eq!(d, filter_digest());
    }

    /// A tiny cBPF interpreter over the fields the filter reads.
    fn run_filter(arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        let prog = filter_rules();
        let mut pc = 0usize;
        let mut acc = 0u32;
        for _ in 0..1024 {
            let insn = prog[pc];
            match insn.code {
                LD_W_ABS => {
                    acc = match insn.k {
                        SD_ARCH => arch,
                        SD_NR => nr,
                        k if k == sd_arg_low(0) => arg0,
                        k if k == sd_arg_low(1) => arg1,
                        other => panic!("filter read an unexpected offset {other}"),
                    };
                    pc += 1;
                }
                ALU_AND_K => {
                    acc &= insn.k;
                    pc += 1;
                }
                JEQ_K => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                JSET_K => {
                    pc += 1 + usize::from(if acc & insn.k != 0 { insn.jt } else { insn.jf });
                }
                JA => {
                    pc += 1 + insn.k as usize;
                }
                RET_K => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
            assert!(pc < prog.len(), "jumped past the program");
        }
        panic!("filter did not terminate");
    }

    #[test]
    fn a_wide_inode_denies_via_the_sockdiag_identity() {
        // The mediator's identity gate refuses a node it cannot represent.
        assert!(VfsId::from_stat(u64::from(u32::MAX) + 1, 2049).is_none());
    }
}
