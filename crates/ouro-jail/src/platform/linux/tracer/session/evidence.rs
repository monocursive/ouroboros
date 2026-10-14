//! The kernel's own facts beside the tracee's: what corroborates a
//! pathname claim at an open's exit, and what an exec's event stop shows of
//! the image and argv the kernel installed.

use libc::pid_t;

use super::seams::ProcView;
use crate::platform::linux::tracer::proc;
use crate::platform::linux::tracer::{KernelImage, ShebangImage};

/// The named components of a raw pathname: empty components (`//`, a
/// trailing `/`) and `.` name nothing and are dropped.
fn components(path: &[u8]) -> impl DoubleEndedIterator<Item = &[u8]> {
    path.split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
}

/// Security 2026-09-29 (audit 6 N1, review fixes): whether the kernel's own
/// resolution of the descriptor a successful open returned — the
/// `/proc/<tid>/fd/<ret>` link, `resolved` — corroborates the pathname
/// snapshot the event would certify.
///
/// Components are compared, not only the final one, so an A-B-A rewrite of
/// a directory component is caught as well as one of the name: an absolute
/// snapshot must name exactly the resolved path; a relative one, resolved
/// against a cwd or dirfd the observer does not read, must be its tail; and
/// past a `..` only the components after the last one are comparable. An
/// `O_TMPFILE` open names a directory and its descriptor resolves to an
/// unnamed `#<ino>` inside it, so the directory is compared. Anything else —
/// a link that is no path (the `pipe:[…]` behind `/dev/stderr`), a symlink
/// along the way, a concurrent rename — does not corroborate, which only
/// ever weakens the claim.
///
/// What this cannot see: the descriptor table is shared with the sibling
/// threads, which run while this one is stopped, so a sibling can put a
/// same-named file at descriptor `ret` before the link is read. That is the
/// residual of reading a shared table from outside the process.
///
/// Audit 7 L7, the ` (deleted)` annotation: the kernel appends it to an
/// unlinked file's link, but a live file can also be
/// *named* that way, so the annotation alone would let a decoy named
/// `README.md (deleted)` pass an A-B-A race as a certified `README.md`
/// claim. When the annotation is present and the open is not an
/// `O_TMPFILE` (whose descriptor is legitimately unnamed), the link count
/// read from the descriptor decides: only a file whose count has reached 0
/// corroborates. `nlink` is `None` when the count could not be read or was
/// never asked for; an unreadable count does not corroborate. The check only
/// ever weakens.
pub(super) fn path_corroborated(
    snapshot: &[u8],
    resolved: &[u8],
    tmpfile: bool,
    nlink: Option<u64>,
) -> bool {
    if resolved.ends_with(b" (deleted)") && !tmpfile && nlink != Some(0) {
        return false;
    }
    let resolved = resolved.strip_suffix(b" (deleted)").unwrap_or(resolved);
    if !resolved.starts_with(b"/") {
        return false;
    }
    // Compare from the tail without allocating component vectors.
    let mut resolved = components(resolved).rev();
    if tmpfile && !resolved.next().is_some_and(|name| name.starts_with(b"#")) {
        return false;
    }
    let mut matched = false;
    for component in components(snapshot).rev() {
        if component == b".." {
            return matched;
        }
        if resolved.next() != Some(component) {
            return false;
        }
        matched = true;
    }
    if snapshot.starts_with(b"/") {
        resolved.next().is_none()
    } else {
        matched
    }
}

/// Security 2026-09-29 (audit 6 N2, review fixes): the command rules
/// re-checked at the exec event, against what the kernel installed.
///
/// `entry` is the argv the entry stop judged (tracee memory), `kernel` the
/// kernel's own copy (`/proc/<tid>/cmdline`), `claimed` the exec pathname
/// snapshot and `image` the `/proc/<tid>/exe` link.
///
/// - The same argv (or, for an `execve` with none, the one empty argument
///   the kernel inserts): the entry verdict stands for the arguments, and
///   the image the kernel loaded is the new evidence for element 0.
/// - An interpreter rewrite — a `#!` script or a `binfmt_misc` handler: the
///   kernel replaced `argv[0]` with the interpreter, its optional argument
///   and the file name, and kept `argv[1..]` as the tail. The rules judge
///   what the entry check judged, the script and its arguments, so they see
///   the kernel's copy of the element before the tail with that tail — never
///   the interpreter's argv, so `forbid = ["bash **"]` does not kill every
///   bash script the entry check let through.
/// - Any other difference: the argv changed between the entry read and the
///   kernel's copy, which is judged with the claimed path and the image as
///   element 0's identity.
/// - An unreadable kernel copy: refused, as an unreadable argv is at the
///   entry stop.
///
/// This stays an accident filter (jail-v2 §7.2): a tracee that races its
/// own argv into the shape of an interpreter rewrite is judged on that
/// shape, as a `sh -c` re-spelling is.
pub(super) fn exec_recheck(
    rules: &crate::commands::Filter,
    entry: &[Vec<u8>],
    kernel: Option<&[Vec<u8>]>,
    claimed: Option<&[u8]>,
    image: Option<&[u8]>,
) -> Option<crate::commands::Hit> {
    let image = image.map(|image| image.strip_suffix(b" (deleted)").unwrap_or(image));
    let Some(kernel) = kernel else {
        return rules.check(None, claimed);
    };
    if kernel == entry || (entry.is_empty() && kernel == [Vec::<u8>::new()]) {
        return rules.check(Some(kernel), image);
    }
    let tail = entry.get(1..).unwrap_or(&[]);
    if kernel.len() >= tail.len() + 2 && kernel.ends_with(tail) {
        return rules.check(Some(&kernel[kernel.len() - tail.len() - 1..]), claimed);
    }
    rules
        .check(Some(kernel), claimed)
        .or_else(|| rules.check(Some(kernel), image))
}

/// What the kernel shows of an exec at its event stop, read once while the
/// tracee is stopped there: the new image has run no instruction and the
/// exec has already destroyed every other thread, so nothing changes it
/// between these reads and the kernel's own decision.
pub(super) struct ExecEvidence {
    /// The image the kernel loaded (audit 3 A1), with the target candidates'
    /// identities. `None` when the link could not be read.
    pub(super) image: Option<KernelImage>,
    /// The kernel's copy of the new argv (audit 6 N2). `None` when nothing
    /// needed it or it could not be read.
    pub(super) argv: Option<Vec<Vec<u8>>>,
    /// The `#!` evidence per target candidate (audit 2026-10-08 H2); empty
    /// unless this is the target's exec and its image could be read.
    pub(super) scripts: Vec<Option<ShebangImage>>,
}

impl ExecEvidence {
    /// Read what this exec needs, each file once. `images` are the target's
    /// candidates (empty for any other process); `rejudge` says the command
    /// rules will re-check the exec against the kernel's argv and image.
    pub(super) fn read(
        procfs: &dyn ProcView,
        tid: pid_t,
        images: &[Vec<u8>],
        rejudge: bool,
    ) -> ExecEvidence {
        let image = procfs.kernel_image(tid, images);
        // A `#!` target loads the interpreter its script names, so the
        // kernel image is not one of the target's own spellings: the first
        // line of each candidate and the kernel's argv are the evidence of
        // that rewrite. Only the target's own exec pays for them.
        let script = image.is_some() && !images.is_empty();
        let argv = if rejudge || script {
            procfs.cmdline(tid).as_deref().and_then(proc::parse_cmdline)
        } else {
            None
        };
        let scripts = if script {
            images
                .iter()
                .map(|candidate| procfs.script_image(tid, candidate))
                .collect()
        } else {
            Vec::new()
        };
        ExecEvidence {
            image,
            argv,
            scripts,
        }
    }

    /// The kernel's argv as the exec event carries it: only beside the `#!`
    /// evidence it confirms a script target with.
    pub(super) fn event_argv(&self) -> Option<Vec<Vec<u8>>> {
        if self.scripts.is_empty() {
            None
        } else {
            self.argv.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_claim_is_corroborated_by_its_components_not_only_its_name() {
        // Absolute: exactly the resolved path.
        assert!(path_corroborated(b"/w/out.txt", b"/w/out.txt", false, None));
        assert!(path_corroborated(
            b"/w//./out.txt",
            b"/w/out.txt",
            false,
            None
        ));
        assert!(
            !path_corroborated(b"/w/public/x", b"/w/secret/x", false, None),
            "a rewritten directory component"
        );
        assert!(!path_corroborated(b"/w/a", b"/w/b", false, None));
        // Relative: the tail of the resolved path, bare names included.
        assert!(path_corroborated(b"out.txt", b"/w/out.txt", false, None));
        assert!(path_corroborated(
            b"sub/out.txt",
            b"/w/sub/out.txt",
            false,
            None
        ));
        assert!(
            !path_corroborated(b"a", b"/w/b", false, None),
            "a bare name is checked too"
        );
        assert!(!path_corroborated(
            b"sub/out.txt",
            b"/w/other/out.txt",
            false,
            None
        ));
        // Past a `..`, only what follows the last one.
        assert!(path_corroborated(b"../out/x", b"/w/out/x", false, None));
        assert!(!path_corroborated(b"../out/x", b"/w/in/x", false, None));
        assert!(!path_corroborated(b"a/..", b"/w", false, None));
        // Unlinked since: the annotation is the kernel's and the count
        // agrees; a live decoy *named* `gone (deleted)` or an unreadable
        // count does not corroborate (audit 7 L7).
        assert!(path_corroborated(
            b"/w/gone",
            b"/w/gone (deleted)",
            false,
            Some(0)
        ));
        assert!(!path_corroborated(
            b"/w/gone",
            b"/w/gone (deleted)",
            false,
            Some(1)
        ));
        assert!(!path_corroborated(
            b"/w/gone",
            b"/w/gone (deleted)",
            false,
            None
        ));
        // O_TMPFILE names the directory; its descriptor is `#<ino>` inside.
        assert!(path_corroborated(
            b"/tmp",
            b"/tmp/#1234 (deleted)",
            true,
            None
        ));
        assert!(path_corroborated(
            b"/tmp/",
            b"/tmp/#1234 (deleted)",
            true,
            None
        ));
        assert!(!path_corroborated(
            b"/tmp",
            b"/var/tmp/#1234 (deleted)",
            true,
            None
        ));
        assert!(
            !path_corroborated(b"/tmp", b"/tmp/#1234 (deleted)", false, Some(0)),
            "only an O_TMPFILE open drops the name"
        );
        // No path at all: the pipe or terminal behind /dev/stderr.
        assert!(!path_corroborated(
            b"/dev/stderr",
            b"pipe:[4242]",
            false,
            None
        ));
        assert!(!path_corroborated(
            b"/dev/stderr",
            b"/dev/pts/3",
            false,
            None
        ));
    }

    #[test]
    fn the_exec_recheck_judges_what_the_entry_judged_on_the_kernels_copy() {
        let rules = crate::commands::Rules {
            deny: vec![
                "git push --force".into(),
                "git push".into(),
                "deploy.sh --prod".into(),
            ],
            forbid: vec!["dangerous-tool **".into(), "bash **".into()],
        }
        .compile()
        .unwrap();
        let argv = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        let recheck = |entry: &[&str], kernel: &[&str], claimed: &str, image: &str| {
            exec_recheck(
                &rules,
                &argv(entry),
                Some(argv(kernel).as_slice()),
                Some(claimed.as_bytes()),
                Some(image.as_bytes()),
            )
            .map(|hit| (hit.pattern, hit.forbidden))
        };
        // An argv raced between the entry read and the kernel's copy: the
        // kernel's copy is judged.
        assert_eq!(
            recheck(
                &["git", "status"],
                &["git", "push", "--force"],
                "/usr/bin/git",
                "/usr/bin/git"
            ),
            Some(("git push --force".to_owned(), false))
        );
        // Unchanged, with an empty argument kept in its place: `git push ""`
        // is not `git push`.
        assert_eq!(
            recheck(
                &["git", "push", ""],
                &["git", "push", ""],
                "/usr/bin/git",
                "/usr/bin/git"
            ),
            None
        );
        // A `#!` script: the interpreter's argv is never judged...
        assert_eq!(
            recheck(
                &["./build.sh", "x"],
                &["/bin/bash", "./build.sh", "x"],
                "./build.sh",
                "/usr/bin/bash"
            ),
            None
        );
        // ...while the script and its arguments still are, past an
        // interpreter argument too.
        assert_eq!(
            recheck(
                &["./deploy.sh", "--prod"],
                &["/bin/sh", "-e", "./deploy.sh", "--prod"],
                "./deploy.sh",
                "/usr/bin/dash"
            ),
            Some(("deploy.sh --prod".to_owned(), false))
        );
        // An execve with no argv: the kernel's inserted empty argument is
        // that argv, and the image names the program.
        assert_eq!(
            recheck(&[], &[""], "/usr/bin/other-tool", "/usr/bin/other-tool"),
            None
        );
        assert_eq!(
            recheck(&[], &[""], "/usr/bin/other-tool", "/usr/bin/dangerous-tool"),
            Some(("dangerous-tool **".to_owned(), true))
        );
        // A raced exec path: the image the kernel loaded names what argv[0]
        // and the snapshot hide, unlinked or not.
        assert_eq!(
            recheck(
                &["benign"],
                &["benign"],
                "/usr/bin/benign",
                "/usr/bin/dangerous-tool (deleted)"
            ),
            Some(("dangerous-tool **".to_owned(), true))
        );
        // An unreadable kernel copy refuses, as an unreadable argv does at
        // the entry stop.
        assert_eq!(
            exec_recheck(&rules, &argv(&["ls"]), None, Some(b"/bin/ls"), None)
                .map(|hit| (hit.pattern, hit.forbidden)),
            Some(("<unreadable-or-oversized-argv>".to_owned(), false))
        );
    }
}
