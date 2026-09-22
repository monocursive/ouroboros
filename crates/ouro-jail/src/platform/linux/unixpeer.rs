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
pub const NON_UNIX_NOTE: &str =
    "non-AF_UNIX connect runs in the mediator's LSM context; inner Landlock-net does not compose";

// ---------------------------------------------------------------------------
// Step 1: the agent filter
// ---------------------------------------------------------------------------

/// `SECCOMP_RET_USER_NOTIF`.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// `SECCOMP_RET_ALLOW`.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_ERRNO`.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// `AUDIT_ARCH_X86_64`.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

const NR_CONNECT: u32 = 42;
const NR_SOCKET: u32 = 41;
const NR_SOCKETPAIR: u32 = 53;
const AF_UNIX: u32 = 1;
const SOCK_TYPE_MASK: u32 = 0xf;
const SOCK_STREAM: u32 = 1;
const SOCK_SEQPACKET: u32 = 5;
const LINUX_EPERM: u32 = 1;

// classic-BPF opcodes (linux/bpf_common.h), spelled out like `bpf.rs`.
const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const ALU_AND_K: u16 = 0x54;
const RET_K: u16 = 0x06;
const SD_NR: u32 = 0;
const SD_ARCH: u32 = 4;
const fn sd_arg_low(index: u32) -> u32 {
    16 + 8 * index
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// One classic-BPF instruction, laid out as `struct sock_filter`.
///
/// A local copy of `bpf.rs`'s type: this fragment needs a `BPF_ALU|BPF_AND`
/// instruction to mask the socket type before comparison, which the shared
/// `bpf::Asm` assembler does not encode. Rather than edit the shared assembler
/// (owned by the integrator), the agent filter is built here from raw
/// instructions, exactly as the observer's narrowing filter is. See the report.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockFilter {
    /// Opcode.
    pub code: u16,
    /// Relative jump when true.
    pub jt: u8,
    /// Relative jump when false.
    pub jf: u8,
    /// Immediate.
    pub k: u32,
}

/// The agent mediation filter, as a complete standalone cBPF program.
///
/// It is installed as one of the `agent` profile's stacked seccomp filters
/// (seccomp evaluates every installed filter and takes the highest-priority
/// action, so this composes with the nesting filter). `connect` returns
/// `SECCOMP_RET_USER_NOTIF`; AF_UNIX `socket`/`socketpair` are allowed only for
/// `SOCK_STREAM`/`SOCK_SEQPACKET` (the type masked with `SOCK_TYPE_MASK` so the
/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` bits do not defeat it), and AF_UNIX
/// `SOCK_DGRAM`/`SOCK_RAW` are refused with `EPERM` because a datagram send can
/// name a peer in `sendmsg`'s `msg_name`, which seccomp cannot read (§3.4
/// step 1). A non-x86_64 architecture is allowed through so the nesting
/// filter's own architecture check judges it.
///
/// `USER_NOTIF` (0x7fc00000) outranks `SECCOMP_RET_TRACE` (0x7ff00000), so a
/// mediated connect is never a ptrace stop and the observer never sees it
/// (§3.4 step 4, proved in the spike).
#[must_use]
pub fn filter_rules() -> Vec<SockFilter> {
    vec![
        // architecture guard
        stmt(LD_W_ABS, SD_ARCH),
        jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(RET_K, SECCOMP_RET_ALLOW),
        // syscall number
        stmt(LD_W_ABS, SD_NR),
        // connect -> USER_NOTIF
        jump(JEQ_K, NR_CONNECT, 0, 1),
        stmt(RET_K, SECCOMP_RET_USER_NOTIF),
        // socket / socketpair -> the type allow-list (3 / 2 insns ahead)
        jump(JEQ_K, NR_SOCKET, 3, 0),
        jump(JEQ_K, NR_SOCKETPAIR, 2, 0),
        // everything else
        stmt(RET_K, SECCOMP_RET_ALLOW),
        stmt(RET_K, SECCOMP_RET_ALLOW), // padding: socket() jt lands here safely
        // socket type check: domain first
        stmt(LD_W_ABS, sd_arg_low(0)),
        jump(JEQ_K, AF_UNIX, 1, 0),
        stmt(RET_K, SECCOMP_RET_ALLOW), // non-AF_UNIX socket: allow
        stmt(LD_W_ABS, sd_arg_low(1)),
        stmt(ALU_AND_K, SOCK_TYPE_MASK),
        jump(JEQ_K, SOCK_STREAM, 2, 0),
        jump(JEQ_K, SOCK_SEQPACKET, 1, 0),
        stmt(RET_K, SECCOMP_RET_ERRNO | LINUX_EPERM),
        stmt(RET_K, SECCOMP_RET_ALLOW),
    ]
}

/// The filter's kernel bytes: each instruction as `code` (LE u16), `jt`, `jf`,
/// `k` (LE u32). This is exactly what [`install_filter`] loads and what the
/// live test writes to a file for a launcher stand-in to install, so there is
/// one filter, not two that can drift.
#[must_use]
pub fn filter_bytes() -> Vec<u8> {
    let rules = filter_rules();
    let mut out = Vec::with_capacity(rules.len() * 8);
    for insn in rules {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

/// `sha256:<hex>` over the filter's kernel bytes, for the receipt.
#[must_use]
pub fn filter_digest() -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(filter_bytes());
    let out = hasher.finalize();
    let mut hex = String::with_capacity(7 + out.len() * 2);
    hex.push_str("sha256:");
    for byte in out {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
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

/// One mediation decision, delivered to the sink so wave 2 can emit the
/// `net.connect` evidence honestly (the tracer never sees a mediated connect).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediationRecord {
    /// The connecting task's host pid.
    pub pid: libc::pid_t,
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
    LauncherFds, LauncherSetup, MediatorHandle, PeerAuthority, install_filter, launcher_setup,
    spawn, take_from_launcher,
};

#[cfg(test)]
mod tests {
    use super::*;
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
    fn the_filter_connect_rule_is_user_notif_and_dgram_is_denied() {
        // Interpret the program the way the kernel would, so the test checks the
        // jump arithmetic rather than restating it.
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_CONNECT, 0, 0),
            SECCOMP_RET_USER_NOTIF
        );
        // socket(AF_UNIX, SOCK_DGRAM=2) -> EPERM
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_SOCKET, AF_UNIX, 2),
            SECCOMP_RET_ERRNO | LINUX_EPERM
        );
        // socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC) -> ALLOW (type masked)
        assert_eq!(
            run_filter(
                AUDIT_ARCH_X86_64,
                NR_SOCKET,
                AF_UNIX,
                SOCK_STREAM | 0x0008_0000
            ),
            SECCOMP_RET_ALLOW
        );
        // socket(AF_INET, SOCK_STREAM) -> ALLOW
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_SOCKET, 2, SOCK_STREAM),
            SECCOMP_RET_ALLOW
        );
        // socketpair(AF_UNIX, SOCK_DGRAM) -> EPERM
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, NR_SOCKETPAIR, AF_UNIX, 2),
            SECCOMP_RET_ERRNO | LINUX_EPERM
        );
        // an unrelated syscall -> ALLOW
        assert_eq!(
            run_filter(AUDIT_ARCH_X86_64, 1 /* write */, 0, 0),
            SECCOMP_RET_ALLOW
        );
        // a non-x86_64 architecture -> ALLOW (deferred to the nesting filter)
        assert_eq!(
            run_filter(0xc000_00b7 /* aarch64 */, NR_CONNECT, 0, 0),
            SECCOMP_RET_ALLOW
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
