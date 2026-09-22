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

/// `/proc/<pid>/cmdline` split on NUL. Bytes, not text: an argv is not
/// required to be UTF-8 (jail-v1 §11.3).
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
    fn a_task_that_does_not_exist_is_none_not_a_guess() {
        // pid 0 is never a task in /proc.
        assert_eq!(tgid(0), None);
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
        let kids = children(std::process::id() as pid_t);
        assert!(
            kids.contains(&pid),
            "spawned child {pid} missing from {kids:?}"
        );
        let all = descendants(std::process::id() as pid_t);
        assert!(
            all.contains(&pid),
            "spawned child {pid} missing from {all:?}"
        );
        let argv = cmdline(pid).expect("a live child has a cmdline");
        assert_eq!(argv[0], b"/bin/sh".to_vec());
        assert_eq!(tgid(pid), Some(pid));
        drop(child.stdin.take());
        let _ = child.wait();
    }
}
