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

use crate::platform::linux::identity;

/// Cap on a single descendant walk, so a fork storm cannot make this
/// function unbounded work.
const MAX_DESCENDANTS: usize = 4096;
/// Cap on the depth of the walk. bubblewrap puts the launcher two levels
/// below the supervisor; anything past this is a tree we do not model.
const MAX_DEPTH: usize = 64;

fn proc_path(pid: pid_t, rest: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{rest}"))
}

/// The value of a `/proc/<pid>/status` line, or `None` when the task is
/// gone or the line is absent.
fn status_field(pid: pid_t, key: &str) -> Option<String> {
    identity::status_field(pid, key).ok()
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

/// The image the kernel loaded for `tid`: the raw `/proc/<tid>/exe` link bytes
/// and the image's own `(dev, ino)`, read while the tracee is stopped at its
/// exec event, so the tracee cannot change either between the read and the
/// kernel's decision — the kernel has already made it. The bytes are **not**
/// stripped of the kernel's ` (deleted)` annotation: a decoy genuinely *named*
/// `tool (deleted)` produces the same link as an unlinked `tool`, and only the
/// inode can tell them apart, so the raw bytes plus identity travel together
/// and the confirmation logic decides. `None` when the link cannot be read; the
/// caller then has no corroboration, not a negative answer.
#[must_use]
pub fn kernel_exe(tid: pid_t, images: &[Vec<u8>]) -> Option<super::KernelImage> {
    use std::os::unix::ffi::OsStrExt as _;
    let link = fs::read_link(proc_path(tid, "exe")).ok()?;
    let path = link.as_os_str().as_bytes().to_vec();
    // The identity follows the same magic link to the image inode, which
    // still resolves when the image was unlinked after the exec (the link
    // holds the orphan). A failed stat leaves the bytes without identity;
    // the caller decides with the weaker fact.
    use std::os::unix::fs::MetadataExt as _;
    let identity = std::fs::metadata(proc_path(tid, "exe"))
        .ok()
        .map(|meta| (meta.dev(), meta.ino()));
    let candidates = images
        .iter()
        .map(|path| super::CandidateImage {
            path: path.clone(),
            identity: super::super::unixpeer::path_identity(tid, path).ok(),
        })
        .collect();
    Some(super::KernelImage {
        path,
        identity,
        candidates,
    })
}

/// The `#!` evidence for one target-image candidate, read through the tracee's
/// root while the tracee is stopped at its exec event: the interpreter the
/// script's first line names, its optional single argument, and the
/// interpreter's `(dev, ino)` in the tracee's root. An absolute spelling is
/// read through the root; any other spelling is read through the tracee's
/// `cwd`, which is the base the kernel itself resolved that spelling against
/// and which an exec does not change. `None` for a spelling that cannot be
/// read through either, or a first line that is not a shebang. The kernel's
/// own buffer for this line is 256 bytes: the interpreter name must fit,
/// while its optional argument may be truncated by the kernel.
#[must_use]
pub fn shebang_image(tid: pid_t, script: &[u8]) -> Option<super::ShebangImage> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let link = if script.first() == Some(&b'/') {
        "root"
    } else {
        "cwd"
    };
    let mut path = format!("/proc/{tid}/{link}").into_bytes();
    if script.first() == Some(&b'/') {
        path.extend_from_slice(script);
    } else {
        // A relative spelling joins the cwd with a separator; an empty
        // spelling names the cwd itself, which `image_header` rejects as a
        // non-file.
        path.push(b'/');
        path.extend_from_slice(script);
    }
    let head = image_header(std::ffi::OsStr::from_bytes(&path))?;
    let (interpreter, argument) = parse_shebang(&head)?;
    let identity = (interpreter.first() == Some(&b'/'))
        .then(|| {
            let mut interpreter_path = format!("/proc/{tid}/root").into_bytes();
            interpreter_path.extend_from_slice(&interpreter);
            std::fs::metadata(std::ffi::OsStr::from_bytes(&interpreter_path))
                .ok()
                .map(|meta| (meta.dev(), meta.ino()))
        })
        .flatten();
    Some(super::ShebangImage {
        interpreter,
        argument,
        identity,
    })
}

/// Pin and inspect the inode before opening it for data. A candidate may
/// have been replaced since exec: opening a FIFO for read would otherwise
/// block the tracer indefinitely. Reopening the pinned regular inode also
/// closes the type-check/path-replacement race.
fn image_header(path: &std::ffi::OsStr) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let pinned = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    if !pinned.metadata().ok()?.is_file() {
        return None;
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .ok()?;
    let mut head = [0u8; 256];
    let read = file.read(&mut head).ok()?;
    Some(head[..read].to_vec())
}

/// Linux binfmt_script treats spaces and tabs as blanks and passes the
/// entire remaining (trimmed) argument as one argv element.
fn parse_shebang(head: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    fn blank(byte: &u8) -> bool {
        matches!(*byte, b' ' | b'\t')
    }
    let rest = head.strip_prefix(b"#!")?;
    let end = rest.iter().position(|byte| matches!(*byte, b'\n' | 0));
    // Without a newline/NUL, a full kernel buffer must at least contain
    // the end of the interpreter name; a truncated name is not executable.
    if head.len() == 256 && end.is_none() {
        let start = rest.iter().position(|byte| !blank(byte))?;
        rest[start..].iter().position(blank)?;
    }
    // The kernel reserves the last byte of a full buffer for its terminator.
    let rest = &rest[..end.unwrap_or(rest.len().min(253))];
    let start = rest.iter().position(|byte| !blank(byte))?;
    let stop = rest.iter().rposition(|byte| !blank(byte))? + 1;
    let rest = &rest[start..stop];
    let split = rest.iter().position(blank).unwrap_or(rest.len());
    let interpreter = rest[..split].to_vec();
    let tail = &rest[split..];
    let argument = tail
        .iter()
        .position(|byte| !blank(byte))
        .map(|start| tail[start..].to_vec());
    Some((interpreter, argument))
}

/// One `/proc/sys/fs/binfmt_misc` registration, parsed from the status
/// text `fs/binfmt_misc.c` (`entry_status`) serves for it.
struct BinfmtRegistration {
    /// The interpreter path, the whole rest of its line: a registration has
    /// no argument field, so a space is part of the path.
    interpreter: Vec<u8>,
    /// An extension match: what follows the last `.` of the pathname.
    extension: Option<Vec<u8>>,
    /// A magic match: the candidate's bytes from `offset`, compared under
    /// `mask` (byte `i` of the mask applies to byte `i` of the magic; a
    /// registration without a mask compares every bit).
    magic: Option<Vec<u8>>,
    offset: usize,
    mask: Vec<u8>,
}

/// Parses one registration file's text. Returns `None` for disabled
/// registrations and malformed shapes.
fn parse_binfmt_registration(text: &str) -> Option<BinfmtRegistration> {
    let mut enabled = false;
    let mut interpreter: Option<Vec<u8>> = None;
    let mut extension: Option<Vec<u8>> = None;
    let mut magic: Option<Vec<u8>> = None;
    let mut offset = 0;
    let mut mask = Vec::new();
    for line in text.lines() {
        // The real files serve `enabled` as a bare word.
        if line == "enabled" {
            enabled = true;
            continue;
        }
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "interpreter" => interpreter = Some(value.as_bytes().to_vec()),
            // Served as `extension .<ext>`.
            "extension" => extension = Some(value.strip_prefix('.')?.as_bytes().to_vec()),
            "offset" => offset = value.parse().ok()?,
            "magic" => magic = Some(hex_bytes(value)?),
            "mask" => mask = hex_bytes(value)?,
            _ => {}
        }
    }
    if !enabled {
        return None;
    }
    if magic.is_none() && extension.is_none() {
        return None;
    }
    Some(BinfmtRegistration {
        interpreter: interpreter?,
        extension,
        magic,
        offset,
        mask,
    })
}

/// Hex to bytes; `None` on odd length or non-hex input.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..bytes.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Whether one registration matches a candidate, as the kernel's
/// `check_file` decides: by what follows the last `.` of the pathname, or by
/// the bytes at the registration's offset in the file's first block, under
/// its mask.
fn binfmt_matches(
    registration: &BinfmtRegistration,
    candidate: &[u8],
    candidate_head: Option<&[u8]>,
) -> bool {
    if let Some(extension) = &registration.extension {
        return candidate
            .iter()
            .rposition(|byte| *byte == b'.')
            .is_some_and(|dot| &candidate[dot + 1..] == extension.as_slice());
    }
    let Some(magic) = &registration.magic else {
        return false;
    };
    let Some(window) = candidate_head.and_then(|head| {
        head.get(registration.offset..registration.offset.checked_add(magic.len())?)
    }) else {
        return false;
    };
    magic
        .iter()
        .zip(window)
        .enumerate()
        .all(|(index, (byte, seen))| {
            let mask_byte = registration.mask.get(index).copied().unwrap_or(0xff);
            (byte ^ seen) & mask_byte == 0
        })
}

/// The `binfmt_misc` image a candidate would load, as the same evidence shape
/// the `#!` rule uses. The kernel hands a registered handler the file the way
/// it hands an interpreter a script — `[interpreter, pathname, ...]`
/// (`load_misc_binary`) — so the confirmation rule is the same, with no
/// optional argument: a registration has none. The `P` flag keeps the original
/// `argv[0]` *after* the pathname, so the pathname's slot is 1 either way.
///
/// Registrations are read from this process's view of
/// `/proc/sys/fs/binfmt_misc`, and only while the facility is enabled there.
/// A tracee in its own user namespace can mount an instance of its own
/// (Linux 6.7 and later); its handlers are not seen, which can only withhold
/// a confirmation, never grant one. A magic registration matches the
/// candidate's first block read through the tracee's root, and the
/// interpreter is resolved where the kernel resolved it when the handler was
/// registered, on the host. When several registrations match, the first
/// found decides; the kernel prefers the newest, so a different pick can
/// only fail the identity check. `None` when no enabled registration
/// matches.
#[must_use]
pub fn binfmt_image(tid: pid_t, candidate: &[u8]) -> Option<super::ShebangImage> {
    const BINFMT_MISC: &str = "/proc/sys/fs/binfmt_misc";
    if fs::read_to_string(format!("{BINFMT_MISC}/status"))
        .ok()?
        .trim()
        != "enabled"
    {
        return None;
    }
    let registrations = std::fs::read_dir(BINFMT_MISC).ok()?;
    let parsed: Vec<BinfmtRegistration> = registrations
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|text| parse_binfmt_registration(&text))
        .collect();
    if parsed.is_empty() {
        return None;
    }
    let head = {
        use std::os::unix::ffi::OsStrExt as _;
        let mut path = format!("/proc/{tid}/root").into_bytes();
        path.extend_from_slice(candidate);
        image_header(std::ffi::OsStr::from_bytes(&path))
    };
    for registration in parsed {
        if !binfmt_matches(&registration, candidate, head.as_deref()) {
            continue;
        }
        let identity = (registration.interpreter.first() == Some(&b'/'))
            .then(|| {
                use std::os::unix::ffi::OsStrExt as _;
                use std::os::unix::fs::MetadataExt as _;
                let path = std::ffi::OsStr::from_bytes(&registration.interpreter);
                // Where the kernel resolves the handler: the host root.
                // `/proc/1/root` is that root even from a containerised
                // supervisor; fall back to this namespace's view.
                std::fs::metadata(format!("/proc/1/root{}", path.to_string_lossy()))
                    .or_else(|_| std::fs::metadata(path))
                    .ok()
                    .map(|meta| (meta.dev(), meta.ino()))
            })
            .flatten();
        return Some(super::ShebangImage {
            interpreter: registration.interpreter,
            argument: None,
            identity,
        });
    }
    None
}

/// The raw `/proc/<tid>/cmdline` bytes: the argument area of the image the
/// kernel installed, read while the tracee is stopped at its exec event. The
/// kernel copied it from the tracee's argv vector into the new image's stack;
/// at that stop the exec has already destroyed every other thread and the new
/// image has run no instruction, so nothing can rewrite it before this read.
/// `None` when the file cannot be read.
#[must_use]
pub fn cmdline_bytes(tid: pid_t) -> Option<Vec<u8>> {
    fs::read(proc_path(tid, "cmdline")).ok()
}

/// The argv a `/proc/<tid>/cmdline` read holds.
///
/// Every argument ends in one NUL, so only that final terminator is
/// stripped: an empty argument is an argument, and dropping it would shift
/// every later position the command rules match on. An `execve` with an
/// empty argv reads as one empty argument, because the kernel inserts one
/// (Linux 5.18, "exec: Force single empty string when argv is empty").
/// `None` for an empty or unterminated area, which no image stopped at its
/// exec event has.
#[must_use]
pub fn parse_cmdline(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let body = bytes.strip_suffix(&[0])?;
    Some(body.split(|byte| *byte == 0).map(<[u8]>::to_vec).collect())
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
    identity::start_time_ticks(pid).ok()
}

/// `/proc/<pid>/cmdline` split on NUL. Bytes, not text: an argv is not
/// required to be UTF-8 (jail-v1 §11.3).
///
/// Three answers, and they are not the same:
///
/// * `None` — the file cannot be read or has no final terminator. The task
///   may have disappeared, or its argument area may have been rewritten.
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
    let raw = cmdline_bytes(pid)?;
    if raw.is_empty() {
        Some(Vec::new())
    } else {
        parse_cmdline(&raw)
    }
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

/// The child of `ancestor` through which `pid` descends: `pid` itself when it
/// is a direct child, else the child found by following each parent up from
/// `pid`, as `parent_of` reads it ([`ppid`] for the live tree). For the
/// launcher under bubblewrap it is bubblewrap.
///
/// `None` when a parent cannot be read, the walk reaches init first, or it
/// is deeper than [`MAX_DEPTH`]: then `pid` is not provably below
/// `ancestor` and the caller must not guess which child it came through.
#[must_use]
pub fn child_toward(
    ancestor: pid_t,
    pid: pid_t,
    parent_of: impl Fn(pid_t) -> Option<pid_t>,
) -> Option<pid_t> {
    let mut current = pid;
    for _ in 0..MAX_DEPTH {
        let parent = parent_of(current)?;
        if parent == ancestor {
            return Some(current);
        }
        if parent <= 1 {
            return None;
        }
        current = parent;
    }
    None
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
    #[test]
    fn script_headers_skip_fifos_and_pin_regular_files() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("script");
        fs::write(&script, b"#!/bin/sh\n").unwrap();
        assert_eq!(image_header(script.as_os_str()).unwrap(), b"#!/bin/sh\n");
        fs::remove_file(&script).unwrap();
        let name = std::ffi::CString::new(script.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and no pointers retained by mkfifo.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let before = std::time::Instant::now();
        assert!(image_header(script.as_os_str()).is_none());
        assert!(before.elapsed() < std::time::Duration::from_secs(1));
        assert!(image_header(dir.path().as_os_str()).is_none());
    }

    #[test]
    fn shebang_blanks_follow_kernel_argument_rules() {
        for header in [
            b"#!/bin/sh\n".as_slice(),
            b"#!\t /bin/sh\t \n",
            b"#!/bin/sh\t\n",
        ] {
            assert_eq!(parse_shebang(header), Some((b"/bin/sh".to_vec(), None)));
        }
        assert_eq!(
            parse_shebang(b"#! \t/bin/sh \t -e -u\t \n"),
            Some((b"/bin/sh".to_vec(), Some(b"-e -u".to_vec())))
        );
        assert_eq!(parse_shebang(b"#!\t \n"), None);
        let mut truncated = b"#!/".to_vec();
        truncated.resize(256, b'x');
        assert_eq!(parse_shebang(&truncated), None);
        let mut long_argument = b"#!/bin/sh ".to_vec();
        long_argument.resize(256, b'x');
        assert_eq!(parse_shebang(&long_argument).unwrap().1.unwrap().len(), 245);
    }

    #[test]
    fn shebang_image_reads_a_relative_spelling_through_cwd() {
        // Audit 2026-10-15 H2′: the kernel resolves a relative execve
        // spelling against the caller's cwd, which an exec does not change,
        // so the observer reads the same file through the tracee's cwd link.
        let here = tempfile::tempdir_in(".").unwrap();
        let relative = here
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let script = format!("./{relative}/script");
        fs::write(here.path().join("script"), b"#!/bin/sh -e\nbody\n").unwrap();
        let me = std::process::id() as pid_t;
        let image = shebang_image(me, script.as_bytes()).expect("relative spelling read via cwd");
        assert_eq!(image.interpreter, b"/bin/sh");
        assert_eq!(image.argument.as_deref(), Some(b"-e".as_slice()));
        assert!(image.identity.is_some(), "the interpreter stat resolves");
        // A spelling the cwd cannot satisfy stays `None`, never a guess.
        let missing = format!("./{relative}/absent");
        assert!(shebang_image(me, missing.as_bytes()).is_none());
    }

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
            .args(["-c", "read x; exit 0", "", ""])
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
        assert_eq!(
            argv,
            ["/bin/sh", "-c", "read x; exit 0", "", ""].map(|arg| arg.as_bytes().to_vec()),
            "launcher discovery must preserve trailing empty arguments"
        );
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

    /// The walk names the direct child a descendant came through, and refuses
    /// rather than guesses when the task is not below the ancestor.
    #[test]
    fn j5t_the_child_toward_a_descendant_is_the_one_it_came_through() {
        let me = std::process::id() as pid_t;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30 & echo $!; read x"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("/bin/sh must exist on the reference host");
        let sh = child.id() as pid_t;
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.as_mut().expect("stdout")),
            &mut line,
        )
        .expect("the grandchild's pid");
        let grandchild: pid_t = line.trim().parse().expect("a pid");
        assert_eq!(
            child_toward(me, sh, ppid),
            Some(sh),
            "a direct child is its own way down"
        );
        assert_eq!(
            child_toward(me, grandchild, ppid),
            Some(sh),
            "a grandchild came through its parent"
        );
        assert_eq!(
            child_toward(me, 1, ppid),
            None,
            "init is not below this process"
        );
        assert_eq!(child_toward(me, 0, ppid), None, "no such task");
        assert_eq!(
            child_toward(sh, me, ppid),
            None,
            "an ancestor is not below its child"
        );
        // SAFETY: the grandchild is alive (the shell is still waiting on
        // stdin, so it is not reaped and its number is not reused).
        unsafe { libc::kill(grandchild, libc::SIGKILL) };
        drop(child.stdin.take());
        let _ = child.wait();
    }

    #[test]
    fn the_parent_of_a_task_that_does_not_exist_is_none() {
        assert_eq!(ppid(0), None);
        assert_eq!(ppid(1), Some(0), "init reports no parent");
    }

    /// Only the final terminator is stripped, so empty arguments keep their
    /// positions, and the kernel's inserted argv for an `execve` with none
    /// reads as one empty argument, not as nothing.
    #[test]
    fn a_cmdline_keeps_empty_arguments_and_its_positions() {
        let argv = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(parse_cmdline(b"git\0push\0"), Some(argv(&["git", "push"])));
        assert_eq!(
            parse_cmdline(b"git\0push\0\0"),
            Some(argv(&["git", "push", ""]))
        );
        assert_eq!(
            parse_cmdline(b"tool\0\0x\0"),
            Some(argv(&["tool", "", "x"]))
        );
        assert_eq!(parse_cmdline(b"\0"), Some(argv(&[""])));
        assert_eq!(parse_cmdline(b""), None);
        assert_eq!(parse_cmdline(b"unterminated"), None);
        // This process's own area parses to its own argv.
        let me = std::process::id() as pid_t;
        let own: Vec<Vec<u8>> = std::env::args_os()
            .map(|arg| std::os::unix::ffi::OsStrExt::as_bytes(arg.as_os_str()).to_vec())
            .collect();
        assert_eq!(
            cmdline_bytes(me).as_deref().and_then(parse_cmdline),
            Some(own)
        );
    }

    /// A `binfmt_misc` registration parses and matches as `fs/binfmt_misc.c`
    /// does — by masked magic at its offset, or by the pathname's extension —
    /// and its interpreter is one path, never a path and an argument. The text
    /// is the shape `/proc/sys/fs/binfmt_misc` serves.
    #[test]
    fn binfmt_registrations_parse_and_match() {
        let text = concat!(
            "enabled\n",
            "interpreter /usr/bin/qemu-aarch64\n",
            "flags: OC\n",
            "offset 0\n",
            "magic 7f454c4602010100\n",
            "mask ffffffffffffff00\n",
        );
        let registration = parse_binfmt_registration(text).expect("parses");
        assert_eq!(registration.interpreter, b"/usr/bin/qemu-aarch64");
        // A matching ELF header; the masked byte is ignored either way.
        let elf = b"\x7f\x45\x4c\x46\x02\x01\x01\x9b";
        assert!(binfmt_matches(&registration, b"/w/any", Some(elf)));
        let elf_masked = b"\x7f\x45\x4c\x46\x02\x01\x01\x00";
        assert!(binfmt_matches(&registration, b"/w/any", Some(elf_masked)));
        let other = b"\x7f\x45\x4c\x46\x02\x01\x02\x00";
        assert!(!binfmt_matches(&registration, b"/w/any", Some(other)));
        // Without the candidate's bytes there is no magic match.
        assert!(!binfmt_matches(&registration, b"/w/any", None));

        // The magic is compared at its offset, not at the file's start.
        let text = concat!(
            "enabled\n",
            "interpreter /usr/lib/wine/wine\n",
            "flags: \n",
            "offset 2\n",
            "magic 4d5a\n",
        );
        let registration = parse_binfmt_registration(text).expect("parses");
        assert!(binfmt_matches(&registration, b"/w/x", Some(b"\0\0MZ..")));
        assert!(
            !binfmt_matches(&registration, b"/w/x", Some(b"MZ....")),
            "the magic at the start is not at offset 2"
        );
        assert!(
            !binfmt_matches(&registration, b"/w/x", Some(b"\0\0M")),
            "a file shorter than offset + magic does not match"
        );

        // An interpreter path with a space is one path: a registration has
        // no argument, so nothing shifts the pathname's slot.
        let text = concat!(
            "enabled\n",
            "interpreter /opt/My Runner/run\n",
            "flags: P\n",
            "extension .jar\n",
        );
        let registration = parse_binfmt_registration(text).expect("parses");
        assert_eq!(registration.interpreter, b"/opt/My Runner/run");
        assert!(binfmt_matches(&registration, b"/w/app.jar", None));
        assert!(binfmt_matches(&registration, b"/w/a.b.jar", None));
        assert!(!binfmt_matches(&registration, b"/w/app.ja", None));
        assert!(!binfmt_matches(&registration, b"/w/app.xjar", None));
        assert!(!binfmt_matches(&registration, b"/w/jar", None));

        // Disabled and malformed registrations refuse.
        assert!(parse_binfmt_registration("interpreter /bin/x\nmagic 00\n").is_none());
        assert!(parse_binfmt_registration("enabled\ninterpreter /bin/x\n").is_none());
        assert!(
            parse_binfmt_registration("enabled\ninterpreter /bin/x\noffset x\nmagic 00\n")
                .is_none()
        );
        assert!(
            parse_binfmt_registration("enabled\ninterpreter /bin/x\nextension jar\n").is_none()
        );
        assert!(hex_bytes("0g").is_none());
        assert!(hex_bytes("0").is_none());
        assert_eq!(hex_bytes("7fFF").as_deref(), Some(&[0x7f, 0xff][..]));
    }
}
