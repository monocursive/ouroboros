//! The I02 vendor-name scan.
//!
//! jail-v1 §15 row I02 and the J1 contract rule 5: no vendor name may appear
//! in the execution core. They are allowed in launch profile data,
//! documentation, fixtures and tests, which is why the scan takes explicit
//! roots instead of walking the repository.
//!
//! §4 scopes the scan to `<crate>/src`, but §15 row I02 says "no vendor
//! names/**protocol dependencies** in the execution core", and a dependency
//! named after a vendor lives in `Cargo.toml`, not in `src/`. The roots below
//! therefore also carry each crate's manifest and its `build.rs`, and a test
//! next to the scan pins each core crate's direct dependencies to a reviewed
//! set, since a protocol client with a neutral name passes a name scan.
//!
//! The execution core is [`EXECUTION_CORE`]: one list drives both checks.
//!
//! What this cannot catch, by construction, because it is a text scan: a
//! token split across lines or across `concat!`, a Unicode look-alike
//! (Cyrillic `а` in `clаude`), and a `\u{..}` escape. Those are deliberate
//! evasions, not accidents; the scan is a guard against the accident.
//!
//! Pagination uses a homonym of one vendor name. Only reviewed exact source
//! lines in named files are exempt for that token; new uses, executable names,
//! dependencies and other vendor tokens on the same line still fail.

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

/// The execution core (§4, §15 row I02): the crates that run, contain or
/// record an attempt. `ouro-jail` and `ouro-ledger` are the ones §4 names;
/// `ouro-records` is compiled into both, so a vendor name or protocol
/// dependency there is in both. `ouro`, the fleet operator's command line,
/// is not in the core: it neither runs nor records an attempt, and the fleet
/// it drives is outside it (§4: "`fleet/` is outside Cargo"). The fixture
/// and `xtask` are test and repository tooling.
pub const EXECUTION_CORE: &[&str] = &["ouro-records", "ouro-jail", "ouro-ledger"];

/// The roots the scan covers, relative to the repository root: each core
/// crate's `src`, its manifest and its build script. A root may be a
/// directory, which is walked, or a single file; one that does not exist
/// is reported absent (a crate without a build script has none).
#[must_use]
pub fn roots() -> Vec<String> {
    EXECUTION_CORE
        .iter()
        .flat_map(|krate| {
            ["src", "Cargo.toml", "build.rs"].map(|part| format!("crates/{krate}/{part}"))
        })
        .collect()
}

const CURSOR_HOMONYMS: &str = include_str!("i02-cursor-homonyms.tsv");

fn reviewed_cursor_homonym(path: &Path, line: &[u8]) -> bool {
    CURSOR_HOMONYMS.lines().any(|entry| {
        entry.split_once('\t').is_some_and(|(file, source)| {
            path.ends_with(file) && line.trim_ascii() == source.as_bytes()
        })
    })
}

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
    /// Symlinks the walk did not follow, named so a reader knows what was not
    /// covered rather than assuming it was.
    pub symlinks_skipped: Vec<PathBuf>,
}

/// Scan one file's bytes. Works on non-UTF-8 content: the tokens are ASCII.
#[must_use]
pub fn scan_bytes(path: &Path, bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        let lower: Vec<u8> = line.iter().map(u8::to_ascii_lowercase).collect();
        for token in FORBIDDEN {
            if !lower.windows(token.len()).any(|w| w == token.as_bytes()) {
                continue;
            }
            if *token == "cursor" && reviewed_cursor_homonym(path, line) {
                continue;
            }
            hits.push(Hit {
                path: path.to_path_buf(),
                line: i + 1,
                token,
            });
        }
    }
    hits
}

fn walk(dir: &Path, scan: &mut Scan) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        // `symlink_metadata`, not `metadata`: following a directory symlink
        // made a `src/selfloop -> ../src` scan the tree repeatedly until the
        // kernel stopped it with ELOOP.
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_symlink() {
            scan.symlinks_skipped.push(path);
        } else if meta.is_dir() {
            walk(&path, scan)?;
        } else if meta.is_file() {
            scan_file(&path, scan)?;
        }
    }
    Ok(())
}

fn scan_file(path: &Path, scan: &mut Scan) -> std::io::Result<()> {
    let bytes = std::fs::read(path)?;
    scan.files_scanned += 1;
    scan.hits.extend(scan_bytes(path, &bytes));
    Ok(())
}

/// Scan the given roots. A root that does not exist is recorded as absent, not
/// silently treated as clean.
pub fn scan_roots<S: AsRef<str>>(base: &Path, roots: &[S]) -> std::io::Result<Scan> {
    let mut scan = Scan::default();
    for root in roots {
        let path = base.join(root.as_ref());
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {
                walk(&path, &mut scan)?;
                scan.roots_scanned.push(path);
            }
            Ok(m) if m.is_file() => {
                scan_file(&path, &mut scan)?;
                scan.roots_scanned.push(path);
            }
            _ => scan.roots_absent.push(path),
        }
    }
    scan.hits
        .sort_by(|a, b| (a.path.clone(), a.line, a.token).cmp(&(b.path.clone(), b.line, b.token)));
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn pagination_exceptions_are_exact_and_file_scoped() {
        for entry in CURSOR_HOMONYMS.lines().filter(|s| !s.starts_with('#')) {
            let Some((file, source)) = entry.split_once('\t') else {
                continue;
            };
            assert!(scan_bytes(Path::new(file), source.as_bytes()).is_empty());
            assert!(!scan_bytes(Path::new("unreviewed.rs"), source.as_bytes()).is_empty());
            for suffix in [" // cursor", " // codex"] {
                assert!(
                    !scan_bytes(Path::new(file), format!("{source}{suffix}").as_bytes()).is_empty()
                );
            }
        }
        let path = Path::new("crates/ouro-ledger/src/main.rs");
        for source in [
            "Command::new(\"cursor\");",
            "const VENDOR: &str = \"Cursor\";",
            "let cursor_vendor = 1;",
        ] {
            assert_eq!(scan_bytes(path, source.as_bytes()).len(), 1);
        }
        assert_eq!(
            scan_bytes(
                Path::new("crates/ouro-ledger/Cargo.toml"),
                b"cursor-protocol = \"1\""
            )
            .len(),
            1
        );
    }

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
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let src = base.join("crates/ouro-jail/src");
        std::fs::create_dir_all(src.join("platform/linux")).unwrap();
        std::fs::write(src.join("lib.rs"), b"pub mod policy;\n").unwrap();

        let clean = scan_roots(base, &roots()).unwrap();
        assert!(clean.hits.is_empty(), "{:?}", clean.hits);
        assert_eq!(clean.roots_scanned.len(), 1, "only src/ exists here");
        assert_eq!(
            clean.roots_absent.len(),
            roots().len() - 1,
            "{:?}",
            clean.roots_absent
        );
        assert_eq!(clean.files_scanned, 1);

        std::fs::write(
            src.join("platform/linux/launch.rs"),
            b"// ok\nconst NAME: &str = \"Anthropic\";\n",
        )
        .unwrap();
        let dirty = scan_roots(base, &roots()).unwrap();
        assert_eq!(dirty.hits.len(), 1, "{:?}", dirty.hits);
        assert_eq!(dirty.hits[0].line, 2);
        assert_eq!(dirty.hits[0].token, "anthropic");
        assert!(
            dirty.hits[0].to_string().contains("launch.rs:2:"),
            "{}",
            dirty.hits[0]
        );
    }

    #[test]
    fn a_vendor_named_dependency_and_a_build_script_are_caught() {
        // §15 row I02 covers "protocol dependencies", which live in the
        // manifest, and a build script can inject one into the build.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let crate_dir = base.join("crates/ouro-jail");
        std::fs::create_dir_all(crate_dir.join("src")).unwrap();
        std::fs::write(crate_dir.join("src/lib.rs"), b"pub mod policy;\n").unwrap();
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            b"[dependencies]\nanthropic-protocol = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            crate_dir.join("build.rs"),
            b"fn main() { println!(\"cargo:rustc-env=VENDOR=codex\"); }\n",
        )
        .unwrap();

        let scan = scan_roots(base, &roots()).unwrap();
        assert_eq!(scan.files_scanned, 3, "{:?}", scan.roots_scanned);
        let tokens: Vec<&str> = scan.hits.iter().map(|h| h.token).collect();
        assert!(tokens.contains(&"anthropic"), "{:?}", scan.hits);
        assert!(tokens.contains(&"codex"), "{:?}", scan.hits);
        assert_eq!(scan.hits.len(), 2, "{:?}", scan.hits);
    }

    #[test]
    fn a_directory_symlink_is_named_and_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let src = base.join("crates/ouro-jail/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), b"pub mod policy;\n").unwrap();
        std::os::unix::fs::symlink("../src", src.join("selfloop")).unwrap();

        let scan = scan_roots(base, &roots()).unwrap();
        assert_eq!(scan.files_scanned, 1, "the loop was followed");
        assert_eq!(scan.symlinks_skipped.len(), 1);
        assert!(scan.symlinks_skipped[0].ends_with("selfloop"));
    }

    #[test]
    fn an_absent_root_is_reported_as_absent_not_as_clean() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let scan = scan_roots(base, &roots()).unwrap();
        assert!(scan.roots_scanned.is_empty());
        assert_eq!(scan.roots_absent.len(), roots().len());
        assert_eq!(scan.files_scanned, 0);
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// I02: "no vendor names/protocol dependencies in the execution core".
    /// The vendor-name scan sees a dependency only through its name, so a
    /// protocol client with a neutral name would pass it. This pins each
    /// execution-core crate's shipped dependencies (every table but
    /// dev-dependencies): adding one fails here until it is reviewed against
    /// I02 and added to the reviewed set below.
    #[test]
    fn the_execution_core_dependencies_are_the_reviewed_set() {
        const REVIEWED: &[(&str, &[&str])] = &[
            ("ouro-records", &["base64", "serde", "serde_json", "sha2"]),
            (
                "ouro-jail",
                &[
                    "base64",
                    "clap",
                    "libc",
                    // The frozen receipt/event types and canonical encoding,
                    // shared with the ledger.
                    "ouro-records",
                    // Shared HTTP vault transport and in-memory CA, no vendor
                    // protocol.
                    "rcgen",
                    "rustls",
                    // Generic supervisor HTTP transport for operator-configured
                    // OAuth refresh; no vendor client, provider SDK, or
                    // protocol-specific dependency.
                    "ureq",
                    // RFC 6455's mandated upgrade challenge, not credential
                    // hashing.
                    "sha1",
                    "webpki-roots",
                    "zeroize",
                    // Explicit operator-reviewed proposal adoption preserves
                    // TOML comments.
                    "toml_edit",
                    "serde",
                    "serde_json",
                    "sha2",
                    "toml",
                    "uuid",
                ],
            ),
            (
                "ouro-ledger",
                &[
                    // Validates records against the frozen schemas.
                    "jsonschema",
                    "ouro-records",
                    "clap",
                    "libc",
                    // The local store: SQLite compiled in, no service.
                    "rusqlite",
                    "serde",
                    "serde_json",
                    "toml",
                    "sha2",
                    // Signatures over records; no vendor protocol.
                    "ring",
                    "uuid",
                ],
            ),
        ];
        let reviewed_crates: Vec<&str> = REVIEWED.iter().map(|(krate, _)| *krate).collect();
        assert_eq!(
            reviewed_crates, EXECUTION_CORE,
            "every execution-core crate has a reviewed set, and only those"
        );
        for (krate, reviewed) in REVIEWED {
            let path = repo_root().join(format!("crates/{krate}/Cargo.toml"));
            let manifest: toml::Value =
                toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let mut names = BTreeSet::new();
            let mut tables = vec![&manifest];
            if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
                tables.extend(targets.values());
            }
            for table in tables {
                for key in ["dependencies", "build-dependencies"] {
                    if let Some(deps) = table.get(key).and_then(toml::Value::as_table) {
                        names.extend(deps.keys().cloned());
                    }
                }
            }
            let reviewed: BTreeSet<String> = reviewed.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(
                names, reviewed,
                "{krate}'s dependencies changed: review the change against I02 \
                 (no protocol dependency) and update the reviewed set"
            );
        }
    }

    /// Every reviewed homonym still names a line of its file: an entry the
    /// code moved away from would otherwise exempt whatever line next reads
    /// the same.
    #[test]
    fn every_reviewed_homonym_is_a_line_of_its_file() {
        for entry in CURSOR_HOMONYMS.lines().filter(|l| !l.starts_with('#')) {
            let (file, source) = entry
                .split_once('\t')
                .unwrap_or_else(|| panic!("`{entry}` is not `path<TAB>source`"));
            let text =
                std::fs::read(repo_root().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert!(
                text.split(|b| *b == b'\n')
                    .any(|line| line.trim_ascii() == source.as_bytes()),
                "{file} no longer has the reviewed line `{source}`: remove or update the entry"
            );
        }
    }
}
