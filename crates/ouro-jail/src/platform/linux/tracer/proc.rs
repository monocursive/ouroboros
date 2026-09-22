//! The `/proc` reads the observer needs: task identity and descendant
//! discovery.
//!
//! [`descendants`] is how the supervisor finds the host pid of a process it
//! did not fork itself — the launcher inside a pid namespace, whose parent is
//! bubblewrap's namespace init (jail-v1 §3.6). It is shared with the linux
//! slice, which needs the same walk and the same `NSpid` check.
//!
//! Every function here reports what it read. A `/proc` file that is gone
//! (the task died between two reads) is `None`, never a guess.

use std::fs;
use std::path::PathBuf;

use libc::pid_t;

/// Cap on a single descendant walk, so a fork storm cannot make this
/// function unbounded work.
const MAX_DESCENDANTS: usize = 4096;
/// Cap on the depth of the walk. bubblewrap puts the launcher two levels
/// below the supervisor; anything past this is a tree we do not model.
const MAX_DEPTH: usize = 64;

fn proc_path(pid: pid_t, rest: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{rest}"))
}

/// The value of a `/proc/<pid>/status` line, without the key or the tab.
fn status_field(pid: pid_t, key: &str) -> Option<String> {
    let text = fs::read_to_string(proc_path(pid, "status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key)
            && rest.starts_with(':')
        {
            return Some(rest[1..].trim().to_string());
        }
    }
    None
}

/// The thread group this task belongs to, in this process's pid namespace.
#[must_use]
pub fn tgid(pid: pid_t) -> Option<pid_t> {
    status_field(pid, "Tgid")?.parse().ok()
}

/// The parent this task currently reports, or `None` when it is gone.
///
/// A child that has been reaped by somebody else has no `/proc` entry at all,
/// and one that was reparented reports a different parent. Either way this is
/// how a caller checks that a process it spawned is still its own before it
/// reads anything else about it.
#[must_use]
pub fn ppid(pid: pid_t) -> Option<pid_t> {
    status_field(pid, "PPid")?.parse().ok()
}

/// The task id of the thread tracing `pid`, or `None` when nothing traces it.
///
/// `TracerPid` names a *thread*, which is why a seize is confirmed against
/// [`super::sys::gettid`] and not against the process id.
#[must_use]
pub fn tracer_pid(pid: pid_t) -> Option<pid_t> {
    let raw: pid_t = status_field(pid, "TracerPid")?.parse().ok()?;
    if raw == 0 { None } else { Some(raw) }
}

/// The `NSpid` line: this task's id in each pid namespace from ours inward.
///
/// One entry means the task shares our namespace. Two or more mean it lives
/// in a nested namespace, and the first entry is the host pid the tracer
/// uses while the last is the pid the process sees for itself.
#[must_use]
pub fn nspid(pid: pid_t) -> Option<Vec<pid_t>> {
    let raw = status_field(pid, "NSpid")?;
    let ids: Vec<pid_t> = raw
        .split_whitespace()
        .filter_map(|f| f.parse().ok())
        .collect();
    if ids.is_empty() { None } else { Some(ids) }
}

/// Field 22 of `/proc/<pid>/stat`: the task's start time, in clock ticks
/// since boot.
///
/// A pid alone does not identify a task: the kernel recycles pids. A pid with
/// the start time the kernel recorded for it does, for as long as the boot
/// lasts, which is why every birth this module reports carries one
/// (jail-v1 §11.3, "internal attribution includes boot/birth identity").
#[must_use]
pub fn start_ticks(pid: pid_t) -> Option<u64> {
    let raw = fs::read_to_string(proc_path(pid, "stat")).ok()?;
    // The second field is the executable name in parentheses and may itself
    // contain spaces and parentheses, so the fields are counted from the last
    // closing parenthesis: field 3 (state) is the first one after it, and
    // field 22 is therefore the twentieth.
    let tail = &raw[raw.rfind(')')? + 1..];
    tail.split_whitespace().nth(19)?.parse().ok()
}

/// `/proc/<pid>/cmdline` split on NUL. Bytes, not text: an argv is not
/// required to be UTF-8 (jail-v1 §11.3).
///
/// Three answers, and they are not the same:
///
/// * `None` — there is no such task. It was never there, or it has been
///   reaped.
/// * `Some(&[])` — the task is there and has no argv *at this instant*. The
///   kernel serves this file from the task's memory map, so a task that is
///   inside `execve` (its old image gone and its new argv not yet installed)
///   and a zombie both read as empty. `posix_spawn` and
///   `std::process::Command` return to their caller during that window, so
///   the pid of a process that has just been spawned can read as empty for a
///   moment.
/// * `Some(argv)` — the argv the task has now.
///
/// A caller identifying a process by its argv — discovering the inside
/// launcher under bubblewrap, for instance — must treat the empty answer as
/// "not yet" and look again, not as "not the one".
#[must_use]
pub fn cmdline(pid: pid_t) -> Option<Vec<Vec<u8>>> {
    let raw = fs::read(proc_path(pid, "cmdline")).ok()?;
    let mut out: Vec<Vec<u8>> = raw.split(|b| *b == 0).map(<[u8]>::to_vec).collect();
    while out.last().is_some_and(Vec::is_empty) {
        out.pop();
    }
    Some(out)
}

/// The direct children of every thread of `pid`.
///
/// This reads `/proc/<pid>/task/<tid>/children`, which the kernel builds from
/// the real parent link, so it sees through a pid namespace boundary: a
/// process whose parent is bubblewrap's namespace init appears here under
/// that init's host pid.
#[must_use]
pub fn children(pid: pid_t) -> Vec<pid_t> {
    let mut out = Vec::new();
    let Ok(tasks) = fs::read_dir(proc_path(pid, "task")) else {
        return out;
    };
    for task in tasks.flatten() {
        let path = task.path().join("children");
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        for field in raw.split_whitespace() {
            if let Ok(child) = field.parse::<pid_t>()
                && !out.contains(&child)
            {
                out.push(child);
            }
        }
    }
    out
}

/// Every descendant of `pid`, breadth first, nearest first.
///
/// The order is what the caller wants: the first entry is a direct child,
/// so walking bubblewrap gives the namespace init before the launcher below
/// it. The walk is a snapshot of a moving tree and says so by returning what
/// it saw, bounded by [`MAX_DESCENDANTS`] and [`MAX_DEPTH`].
#[must_use]
pub fn descendants(pid: pid_t) -> Vec<pid_t> {
    let mut out: Vec<pid_t> = Vec::new();
    let mut frontier = vec![pid];
    for _ in 0..MAX_DEPTH {
        let mut next = Vec::new();
        for parent in frontier {
            for child in children(parent) {
                if child != pid && !out.contains(&child) {
                    out.push(child);
                    next.push(child);
                    if out.len() >= MAX_DESCENDANTS {
                        return out;
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_of_this_process() {
        let me = std::process::id() as pid_t;
        assert_eq!(tgid(me), Some(me), "a process's Tgid is its own pid");
        assert_eq!(tracer_pid(me), None, "this test is not being traced");
        let ns = nspid(me).expect("NSpid is present on every kernel this crate supports");
        assert_eq!(
            ns[0], me,
            "the first NSpid entry is the pid in our own namespace"
        );
    }

    #[test]
    fn start_ticks_of_this_process_is_stable_and_plausible() {
        let me = std::process::id() as pid_t;
        let a = start_ticks(me).expect("/proc/<pid>/stat field 22");
        assert!(a > 0, "a task started after boot");
        assert_eq!(start_ticks(me), Some(a), "a birth time never changes");
        // The tracer thread is a task of this process and started later than
        // or at the same tick as the process itself.
        let tid = super::super::sys::gettid();
        let t = start_ticks(tid).expect("a thread has a start time too");
        assert!(t >= a, "thread {t} started before its process {a}");
    }

    #[test]
    fn a_task_that_does_not_exist_is_none_not_a_guess() {
        // pid 0 is never a task in /proc.
        assert_eq!(tgid(0), None);
        assert_eq!(start_ticks(0), None);
        assert_eq!(nspid(0), None);
        assert_eq!(cmdline(0), None);
        assert!(children(0).is_empty());
        assert!(descendants(0).is_empty());
    }

    #[test]
    fn a_spawned_child_is_a_descendant_with_its_cmdline() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "read x; exit 0"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("/bin/sh must exist on the reference host");
        let pid = child.id() as pid_t;
        let me = std::process::id() as pid_t;
        // Everything below is about *this* child. A blocking `waitpid(-1)`
        // anywhere else in this test binary would reap it between these
        // lines, and the failure would look like a flake; asserting the
        // parent first makes a foreign reaper say its own name.
        assert_eq!(
            ppid(pid),
            Some(me),
            "the child {pid} is no longer ours: something in this test binary waited on \
             any child and reaped it"
        );
        let kids = children(me);
        assert!(
            kids.contains(&pid),
            "spawned child {pid} missing from {kids:?}"
        );
        let all = descendants(me);
        assert!(
            all.contains(&pid),
            "spawned child {pid} missing from {all:?}"
        );
        // A task that is still inside `execve` has no argv yet, and
        // `Command::spawn` returns during exactly that window. This is a
        // bounded wait for the argv to appear, not a retry of a flaky
        // assertion: the parent is checked again each time, so a reaper
        // still fails by name rather than by timeout.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let argv = loop {
            assert_eq!(
                ppid(pid),
                Some(me),
                "the child {pid} stopped being ours while we waited for its argv: \
                 something in this test binary waited on any child and reaped it"
            );
            match cmdline(pid) {
                Some(argv) if !argv.is_empty() => break argv,
                other => assert!(
                    std::time::Instant::now() < deadline,
                    "the child {pid} never showed an argv: cmdline={other:?} ppid={:?}",
                    ppid(pid)
                ),
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        assert_eq!(argv[0], b"/bin/sh".to_vec());
        assert_eq!(tgid(pid), Some(pid));
        assert_eq!(ppid(pid), Some(me), "and it was ours throughout");
        drop(child.stdin.take());
        let status = child.wait().expect("the child is ours to wait for");
        assert!(status.success());
    }

    /// The empty answer and the absent answer are different, and a caller
    /// that confuses them would mistake a process mid-`execve` for one that
    /// is not there.
    #[test]
    fn an_empty_cmdline_is_not_an_absent_one() {
        assert_eq!(cmdline(0), None, "no such task");
        let me = std::process::id() as pid_t;
        let mine = cmdline(me).expect("this process has an argv");
        assert!(!mine.is_empty(), "and it is not empty");
    }

    #[test]
    fn the_parent_of_a_task_that_does_not_exist_is_none() {
        assert_eq!(ppid(0), None);
        assert_eq!(ppid(1), Some(0), "init reports no parent");
    }
}
