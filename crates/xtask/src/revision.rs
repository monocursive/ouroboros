//! The revision a tree is at, as the suite prints it and the build records it.

use std::fmt;
use std::path::Path;

/// A commit, and whether the tree had uncommitted changes to tracked files.
/// Written `<40 hex>` or `<40 hex>+dirty`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// The full commit id, lowercase.
    pub sha: String,
    pub dirty: bool,
}

impl Revision {
    /// Parse `<40 hex>` or `<40 hex>+dirty`; anything else is no revision.
    #[must_use]
    pub fn parse(text: &str) -> Option<Revision> {
        let (sha, dirty) = match text.strip_suffix("+dirty") {
            Some(sha) => (sha, true),
            None => (text, false),
        };
        (sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Revision {
            sha: sha.to_ascii_lowercase(),
            dirty,
        })
    }

    /// The short form a run directory is named by.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.sha[..12]
    }

    /// The revision the repository at `root` is at: `HEAD`, dirty when
    /// tracked files have uncommitted changes.
    ///
    /// # Errors
    /// git could not say.
    pub fn of_repository(root: &Path) -> Result<Revision, String> {
        let head = crate::proc::git(root, &["rev-parse", "HEAD"])?;
        let mut revision =
            Revision::parse(&head).ok_or_else(|| format!("HEAD is `{head}`, not a commit"))?;
        revision.dirty =
            !crate::proc::git(root, &["status", "--porcelain", "--untracked-files=no"])?.is_empty();
        Ok(revision)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sha)?;
        if self.dirty {
            f.write_str("+dirty")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn a_revision_round_trips_and_nothing_else_parses() {
        for text in [SHA.to_owned(), format!("{SHA}+dirty")] {
            assert_eq!(Revision::parse(&text).unwrap().to_string(), text);
        }
        assert!(Revision::parse(&format!("{SHA}+dirty")).unwrap().dirty);
        assert_eq!(Revision::parse(SHA).unwrap().short(), &SHA[..12]);
        for bad in [
            "",
            "main",
            &SHA[..39],
            &format!("{SHA}0"),
            &format!("{SHA}+wip"),
            "+dirty",
        ] {
            assert_eq!(Revision::parse(bad), None, "{bad}");
        }
    }
}
