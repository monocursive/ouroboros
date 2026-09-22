//! The I02 vendor-name scan.
//!
//! jail-v1 §15 row I02 and the J1 contract rule 5: no vendor name may appear
//! in the execution core. They are allowed in launch profile data,
//! documentation, fixtures and tests, which is why the scan takes explicit
//! roots instead of walking the repository.

use std::path::{Path, PathBuf};

/// The forbidden tokens, matched case-insensitively.
pub const FORBIDDEN: &[&str] = &[
    "codex",
    "claude",
    "opencode",
    "anthropic",
    "openai",
    "cursor",
    "gemini",
    "copilot",
];

/// The roots the scan covers when they exist, relative to the repository root.
pub const ROOTS: &[&str] = &["crates/ouro-jail/src", "crates/ouro-ledger/src"];

#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub path: PathBuf,
    pub line: usize,
    pub token: &'static str,
}

impl std::fmt::Display for Hit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: vendor name `{}` in the execution core (I02)",
            self.path.display(),
            self.line,
            self.token
        )
    }
}

/// What a scan covered, so a run that found nothing can say why.
#[derive(Debug, Default)]
pub struct Scan {
    pub hits: Vec<Hit>,
    pub roots_scanned: Vec<PathBuf>,
    pub roots_absent: Vec<PathBuf>,
    pub files_scanned: usize,
}

/// Scan one file's bytes. Works on non-UTF-8 content: the tokens are ASCII.
#[must_use]
pub fn scan_bytes(path: &Path, bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let lower: Vec<u8> = line.iter().map(u8::to_ascii_lowercase).collect();
        for token in FORBIDDEN {
            if lower.windows(token.len()).any(|w| w == token.as_bytes()) {
                hits.push(Hit {
                    path: path.to_path_buf(),
                    line: i + 1,
                    token,
                });
            }
        }
    }
    hits
}

fn walk(dir: &Path, scan: &mut Scan) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, scan)?;
        } else if path.is_file() {
            let bytes = std::fs::read(&path)?;
            scan.files_scanned += 1;
            scan.hits.extend(scan_bytes(&path, &bytes));
        }
    }
    Ok(())
}

/// Scan the given roots. A root that does not exist is recorded as absent, not
/// silently treated as clean.
pub fn scan_roots(base: &Path, roots: &[&str]) -> std::io::Result<Scan> {
    let mut scan = Scan::default();
    for root in roots {
        let path = base.join(root);
        if path.is_dir() {
            walk(&path, &mut scan)?;
            scan.roots_scanned.push(path);
        } else {
            scan.roots_absent.push(path);
        }
    }
    scan.hits
        .sort_by(|a, b| (a.path.clone(), a.line, a.token).cmp(&(b.path.clone(), b.line, b.token)));
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_forbidden_token_is_found_in_any_case() {
        for token in FORBIDDEN {
            let upper = token.to_uppercase();
            let content = format!("// a comment mentioning {upper} in passing\n");
            let hits = scan_bytes(Path::new("x.rs"), content.as_bytes());
            assert_eq!(hits.len(), 1, "missed {upper}");
            assert_eq!(hits[0].token, *token);
            assert_eq!(hits[0].line, 1);
        }
    }

    #[test]
    fn a_token_inside_an_identifier_still_counts() {
        let hits = scan_bytes(Path::new("x.rs"), b"let launch_CoDeX_profile = 1;\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].token, "codex");
    }

    #[test]
    fn clean_content_and_non_utf8_bytes_produce_nothing() {
        assert!(scan_bytes(Path::new("x.rs"), b"fn main() {}\n").is_empty());
        assert!(scan_bytes(Path::new("x.rs"), &[0xff, 0xfe, b'\n', 0x00]).is_empty());
    }

    #[test]
    fn line_numbers_are_one_based_and_exact() {
        let hits = scan_bytes(Path::new("x.rs"), b"one\ntwo\nopenai\nfour\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 3);
    }

    #[test]
    fn a_planted_hit_in_a_temp_tree_is_reported_and_a_clean_tree_is_not() {
        let base = std::env::temp_dir().join(format!("xtask-i02-{}", std::process::id()));
        let src = base.join("crates/ouro-jail/src");
        std::fs::create_dir_all(src.join("platform/linux")).unwrap();
        std::fs::write(src.join("lib.rs"), b"pub mod policy;\n").unwrap();

        let clean = scan_roots(&base, ROOTS).unwrap();
        assert!(clean.hits.is_empty(), "{:?}", clean.hits);
        assert_eq!(clean.roots_scanned.len(), 1);
        assert_eq!(clean.roots_absent.len(), 1, "ouro-ledger is not here yet");
        assert_eq!(clean.files_scanned, 1);

        std::fs::write(
            src.join("platform/linux/launch.rs"),
            b"// ok\nconst NAME: &str = \"Anthropic\";\n",
        )
        .unwrap();
        let dirty = scan_roots(&base, ROOTS).unwrap();
        assert_eq!(dirty.hits.len(), 1, "{:?}", dirty.hits);
        assert_eq!(dirty.hits[0].line, 2);
        assert_eq!(dirty.hits[0].token, "anthropic");
        assert!(
            dirty.hits[0].to_string().contains("launch.rs:2:"),
            "{}",
            dirty.hits[0]
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn an_absent_root_is_reported_as_absent_not_as_clean() {
        let base = std::env::temp_dir().join(format!("xtask-i02-absent-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let scan = scan_roots(&base, ROOTS).unwrap();
        assert!(scan.roots_scanned.is_empty());
        assert_eq!(scan.roots_absent.len(), 2);
        assert_eq!(scan.files_scanned, 0);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
