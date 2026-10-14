//! Running programs: one way to run a command and one way to ask git.
//!
//! A program that cannot be started is a result with no status, never an
//! early exit: the tasks record every step's outcome as evidence, and a step
//! that did not run is as much a fact as one that failed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What one command produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// The exit status, or `None` for a signal or a program that did not
    /// start (then `stderr` says why).
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    #[must_use]
    pub fn status_text(&self) -> String {
        match self.code {
            Some(c) => c.to_string(),
            None => "without an exit status".to_string(),
        }
    }

    /// The result of a step that could not be attempted.
    #[must_use]
    pub fn not_run(why: impl Into<String>) -> Self {
        CommandResult {
            code: None,
            stdout: String::new(),
            stderr: why.into(),
        }
    }
}

/// Run `program` with `args`, its stdin from `stdin` (or empty), in `dir`
/// (or the current directory).
#[must_use]
pub fn run(
    program: &str,
    args: &[String],
    stdin: Option<&Path>,
    dir: Option<&Path>,
) -> CommandResult {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    match stdin.map(std::fs::File::open).transpose() {
        Ok(Some(file)) => {
            command.stdin(file);
        }
        Ok(None) => {
            command.stdin(Stdio::null());
        }
        Err(e) => {
            return CommandResult::not_run(format!("could not open the input of {program}: {e}"));
        }
    }
    match command.output() {
        Ok(out) => CommandResult {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => CommandResult::not_run(format!("could not run {program}: {e}")),
    }
}

/// `git -C <root> <args>`: its stdout bytes, or why there are none.
///
/// # Errors
/// git could not run, or exited nonzero (its stderr is the reason).
pub fn git_bytes(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(format!(
            "git {} exited {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// [`git_bytes`] as text, trimmed.
///
/// # Errors
/// As [`git_bytes`].
pub fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    git_bytes(root, args).map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
}

/// The root of the git worktree the current directory is in.
///
/// # Errors
/// Not inside a git worktree, or git could not run: the tasks read and
/// write files relative to the root, so guessing `.` would be worse.
pub fn worktree_root() -> Result<PathBuf, String> {
    git(Path::new("."), &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .map_err(|e| {
            format!(
                "the repository root could not be found ({e}); run from a checkout or pass --root"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_that_cannot_start_is_a_result_not_an_error() {
        let r = run("/nonexistent/program", &[], None, None);
        assert_eq!(r.code, None);
        assert!(r.stderr.contains("could not run"), "{}", r.stderr);
        assert!(!r.ok());
        let r = run("/bin/sh", &["-c".into(), "cat; exit 3".into()], None, None);
        assert_eq!(r.code, Some(3));
        let r = run("/bin/sh", &[], Some(Path::new("/nonexistent/input")), None);
        assert!(r.stderr.contains("could not open"), "{}", r.stderr);
    }

    #[test]
    fn git_reports_why_it_failed() {
        let dir = tempfile::tempdir().unwrap();
        let error = git(dir.path(), &["rev-parse", "HEAD"]).unwrap_err();
        assert!(error.contains("rev-parse"), "{error}");
    }
}
