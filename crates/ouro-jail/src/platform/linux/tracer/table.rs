//! The published hook/syscall table of the ptrace observer (jail-v1 §11.2:
//! "The implementation must publish its exact hook/syscall table").
//!
//! Generated, never written by hand: every row comes from
//! [`CLOSED_SET`](super::closed_set::CLOSED_SET), every verdict from running
//! the installed program ([`super::narrowing_filter`]) the way the kernel
//! would, and the digest from the bytes the launcher installs. The copy kept
//! as evidence (`docs/specs/jail-v1/evidence/closed-set-x86_64.txt`) is
//! compared with this output by a test, and a live test reads the digest
//! back from a receipt, so the published table is the one this build traces.

use std::fmt::Write as _;

use super::closed_set::{CLOSED_SET, Entry, FlagSource};
use super::filter::{
    CLONE_SYSCALL, CLONE_UNTRACED, CLONE3_SYSCALL, LISTENER_SYSCALL, NARROWING_TRACE_DATA,
    SECCOMP_FILTER_FLAG_NEW_LISTENER, narrowing_filter, narrowing_filter_digest,
};
use super::sys;

/// What the program returns for one `(arch, nr, arg0, arg1)`, by running it.
fn verdict(arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
    let prog = narrowing_filter();
    let mut pc = 0usize;
    let mut acc: u32 = 0;
    for _ in 0..4096 {
        let Some(insn) = prog.get(pc) else {
            return u32::MAX;
        };
        match insn.code {
            c if c == sys::BPF_LD_W_ABS => {
                acc = match insn.k {
                    k if k == sys::SECCOMP_DATA_NR => nr,
                    k if k == sys::SECCOMP_DATA_ARCH => arch,
                    k if k == sys::SECCOMP_DATA_ARG0_LOW => arg0,
                    k if k == sys::SECCOMP_DATA_ARG1_LOW => arg1,
                    _ => return u32::MAX,
                };
                pc += 1;
            }
            c if c == sys::BPF_JEQ_K => {
                pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
            }
            c if c == sys::BPF_JSET_K => {
                pc += 1 + usize::from(if acc & insn.k != 0 { insn.jt } else { insn.jf });
            }
            c if c == sys::BPF_RET_K => return insn.k,
            _ => return u32::MAX,
        }
    }
    u32::MAX
}

fn name(verdict: u32) -> String {
    if verdict == sys::SECCOMP_RET_TRACE | u32::from(NARROWING_TRACE_DATA) {
        "TRACE".to_owned()
    } else if verdict == sys::SECCOMP_RET_ALLOW {
        "ALLOW".to_owned()
    } else if verdict == sys::SECCOMP_RET_ERRNO | sys::LINUX_ENOSYS {
        "ENOSYS".to_owned()
    } else {
        format!("{verdict:#010x}")
    }
}

fn arguments(entry: &Entry) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(i) = entry.dirfd {
        parts.push(format!("dirfd=a{i}"));
    }
    if let Some(i) = entry.path {
        parts.push(format!("path=a{i}"));
    }
    if let Some(i) = entry.dirfd2 {
        parts.push(format!("dirfd2=a{i}"));
    }
    if let Some(i) = entry.path2 {
        parts.push(format!("path2=a{i}"));
    }
    match entry.flags {
        FlagSource::None => {}
        FlagSource::Arg(i) => parts.push(format!("flags=a{i}")),
        FlagSource::ImpliedCreat => parts.push("flags=O_CREAT|O_WRONLY|O_TRUNC".to_owned()),
        FlagSource::OpenHow { ptr, size } => {
            parts.push(format!("flags=open_how(a{ptr}).flags if a{size}>=24"));
        }
    }
    if let Some((ptr, len)) = entry.sockaddr {
        parts.push(format!("sockaddr=a{ptr} len=a{len} (family only)"));
    }
    parts.join(" ")
}

fn operation(entry: &Entry) -> String {
    match entry.flags {
        FlagSource::ImpliedCreat => "fs.create".to_owned(),
        _ if entry.op == super::ClosedOp::Open => {
            "fs.create if O_CREAT, else fs.write; none if read-only".to_owned()
        }
        _ if entry.op == super::ClosedOp::Truncate => "fs.write (action truncated)".to_owned(),
        _ if entry.op == super::ClosedOp::Exec => {
            "proc.exec (confirmed transition, or failed return)".to_owned()
        }
        _ => entry.op.audit_operation(None).to_owned(),
    }
}

/// The table, as the evidence file holds it.
#[must_use]
pub fn closed_set_table() -> String {
    let x86 = sys::AUDIT_ARCH_X86_64;
    let mut out = String::new();
    out.push_str("ouro-jail observer closed set `linux-closed-v1` (x86_64, ptrace backend)\n");
    out.push_str(
        "jail-v1 §11.2, §11.4; generated from the observer's CLOSED_SET and the narrowing\n\
         filter the launcher installs (every verdict below is the program's own, run on\n\
         that input)\n\n",
    );
    let _ = writeln!(
        out,
        "precondition                 verdict  meaning\n\
         arch != 0x{x86:08x}          {}    another ABI: stopped, labelled foreign, never decoded\n\
         nr & 0x{:08x}             {}    x32: stopped, labelled foreign, never decoded",
        name(verdict(0x4000_0003, 59, 0, 0)),
        sys::X32_SYSCALL_BIT,
        name(verdict(x86, sys::X32_SYSCALL_BIT | 59, 0, 0)),
    );
    out.push_str(
        "\nclosed-set rows (a stop, then one result per return; EACCES or EPERM is\n\
         one fs.deny naming the operation below as attempted_operation)\n\n",
    );
    let _ = writeln!(
        out,
        "{:<12} {:<4} {:<7} {:<54} arguments read",
        "syscall", "nr", "verdict", "audit operation"
    );
    for entry in CLOSED_SET {
        let _ = writeln!(
            out,
            "{:<12} {:<4} {:<7} {:<54} {}",
            entry.name,
            entry.nr,
            name(verdict(x86, entry.nr as u32, 0, 0)),
            operation(entry),
            arguments(entry)
        );
    }
    let _ = writeln!(out, "rows: {}", CLOSED_SET.len());
    out.push_str("\nother stops the narrowing filter asks for (not results)\n\n");
    let (seccomp, nr) = LISTENER_SYSCALL;
    let _ = writeln!(
        out,
        "{seccomp:<12} {nr:<4} {:<7} when a1 & 0x{SECCOMP_FILTER_FLAG_NEW_LISTENER:08x} (SECCOMP_FILTER_FLAG_NEW_LISTENER); \
         a granted listener is a child_notification_listener gap, a refused one nothing\n\
         {seccomp:<12} {nr:<4} {:<7} otherwise",
        name(verdict(x86, nr, 1, SECCOMP_FILTER_FLAG_NEW_LISTENER)),
        name(verdict(x86, nr, 1, 0)),
    );
    let (clone, nr) = CLONE_SYSCALL;
    let _ = writeln!(
        out,
        "{clone:<12} {nr:<4} {:<7} when a0 & 0x{CLONE_UNTRACED:08x} (CLONE_UNTRACED); \
         a created task is an untraced_descendant gap, a failed call nothing\n\
         {clone:<12} {nr:<4} {:<7} otherwise (fork, vfork, threads: followed by ptrace events)",
        name(verdict(x86, nr, CLONE_UNTRACED | 17, 0)),
        name(verdict(x86, nr, 0x003d_0f00, 0)),
    );
    let (clone3, nr) = CLONE3_SYSCALL;
    let _ = writeln!(
        out,
        "{clone3:<12} {nr:<4} {:<7} its flags are in memory seccomp cannot read; glibc falls back to clone",
        name(verdict(x86, nr, 0, 0)),
    );
    let _ = writeln!(out, "everything else   {}", name(verdict(x86, 0, 0, 0)));
    out.push_str(
        "\nexcluded by name (§11.2): read, write, mmap, ftruncate and every other\n\
         descriptor-based mutation, io_uring, payloads and file contents; a read-only\n\
         open is outside the set (no event, not a loss)\n",
    );
    out.push_str(
        "\nper profile\n\
         tool, build  the baseline answers other ABIs, x32, a notification listener and\n\
         \x20            clone(CLONE_UNTRACED) with EPERM and clone3 with ENOSYS; ERRNO\n\
         \x20            outranks TRACE, so none of these ever stops here; AF_UNIX sockets\n\
         \x20            are refused, so connect is AF_INET or AF_INET6\n\
         agent        the same baseline refusals except the listener, which the jail's\n\
         \x20            own mediation listener makes fail with EBUSY; connect is mediated\n\
         \x20            (USER_NOTIF outranks TRACE) and its result carries\n\
         \x20            fields.observation = seccomp_user_notification\n\
         none         no baseline: every stop above can happen\n",
    );
    out.push_str(
        "\nnotes\n\
         - The trace data is 0x4f4a. A stop on a number this filter never traces, with\n\
         \x20 other data, was asked for by a child's own SECCOMP_RET_TRACE and is continued:\n\
         \x20 the call then runs, where with no tracer it would have returned ENOSYS. It is\n\
         \x20 neither a result nor a loss. The same stop with this filter's data means the\n\
         \x20 installed program is not this one: an unexpected_trace_stop gap.\n\
         - prctl(PR_SET_SECCOMP) is not traced: it cannot create a notification listener.\n\
         - A child's own filter that refuses a call (errno, trap, kill) before this one\n\
         \x20 stops it hides a call that had no effect: a named exclusion, not a gap.\n\
         - With no tracer attached, every TRACE verdict fails the call with ENOSYS: the\n\
         \x20 observer's death, and a CLONE_UNTRACED descendant, fail closed.\n",
    );
    let prog = narrowing_filter();
    let _ = writeln!(out, "\nnarrowing filter instructions: {}", prog.len());
    let _ = writeln!(
        out,
        "narrowing filter digest: {}",
        narrowing_filter_digest()
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_and_every_other_stop_is_in_the_table() {
        let table = closed_set_table();
        for entry in CLOSED_SET {
            let row = format!("{:<12} {:<4} TRACE", entry.name, entry.nr);
            assert!(table.contains(&row), "{row}");
        }
        for name in ["seccomp", "clone ", "clone3", "x32", "EBUSY", "0x4f4a"] {
            assert!(table.contains(name), "{name}");
        }
        assert!(table.contains(&narrowing_filter_digest()));
        assert!(table.contains("rows: 22"));
    }
}
