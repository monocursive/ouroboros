//! The operator's own preferences, on disk, and the resolution order every start surface
//! reads them through.
//!
//! ## What belongs here, and what deliberately does not
//!
//! Nothing in this file is a runtime fact. The data directory, the node name, the scope,
//! the provider probes — those come from the daemon and from [`crate::runtime`], and a
//! screen that shows one of them says so. What is kept here is the small set of answers a
//! person would otherwise retype into every `ouro new`: which provider, which workspace,
//! which approval mode. They are *defaults for a form*, not decisions: every one of them
//! is prefilled into the `n` dialog and stays editable there, and `ouro new` still accepts
//! a flag that overrides the file.
//!
//! This is what keeps the "not a choice this client makes for you" rule intact while
//! removing the retyping. The client still refuses to *invent* a provider. It will use one
//! the operator chose, once, explicitly, in a file they can read — which is a different
//! statement from a node's default silently deciding which vendor runs their code.
//!
//! ## Reading is total; writing is atomic
//!
//! [`load`] never fails. A missing file is the ordinary case, and a file that does not
//! parse is reported as a problem beside a default config rather than as a reason to
//! refuse to start a runtime: a corrupt preference file must not stand between an operator
//! and their agents. Every problem it collects names the file and what was wrong with it,
//! and the surfaces surface exactly those strings.
//!
//! [`Config::save`] writes a temporary file beside the target and renames it, so an
//! interrupted write leaves the previous file intact rather than half of this one. The
//! rewrite is whole: comments and key order in a hand-edited file do not survive a save,
//! which is why the file this client writes says so in its own header.
//!
//! ## Unknown keys are kept out of the way, not rejected
//!
//! A newer `ouro` may write keys this build has never heard of. Every struct here ignores
//! them on read (serde's default), for the same reason [`crate::model`] does: refusing a
//! file because it carries a field from a later version is how a client goes blind. They
//! are not *preserved* through a save, and that is stated rather than hidden — a save from
//! an older build is an older build's idea of the file.
//!
//! ## `--dev` reads the same file
//!
//! A development daemon gets its own data directory, because a `gateway.json` shared with
//! a real one would make each discoverable as the other. It does **not** get its own
//! preferences: which provider a person prefers is a fact about the person, not about
//! which runtime they happened to start.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::ApprovalMode;
use crate::runtime::xdg_root;

/// The directory this client keeps its preferences in, under the XDG config root.
pub const CONFIG_DIR: &str = "ouroboros";

/// The file itself.
pub const CONFIG_FILE: &str = "config.toml";

/// What a save writes above the tables, so someone who opens the file knows what wrote it
/// and what a later save will do to their edits.
const HEADER: &str = "\
# ouro preferences, schema 1. Hand-editing is fine: every key is optional, and keys this
# build does not know are ignored rather than refused.
#
# `ouro` rewrites this file whole when you save from the settings overlay (`,`), so
# comments and key order below this header are not preserved by that write.
";

/// Everything `ouro` remembers between runs. All of it optional, none of it a runtime
/// fact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub onboarding: Onboarding,
}

/// The answers the `n` dialog and `ouro new` prefill from.
///
/// Every field is a string rather than a parsed type because the file is the operator's to
/// edit and a value this build cannot read is reported, not crashed on. [`normalise`]
/// turns the unreadable ones back into "unset" and says so.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Defaults {
    /// A provider name. Not validated against a runtime here — which providers exist is a
    /// fact only a running node can report, and this file is read before there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// A workspace path, as the operator wrote it. Resolved where it is used, against the
    /// directory the command was typed in, exactly like `--workspace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// One of [`ApprovalMode::ALL`]. Anything else is dropped by [`normalise`] with a
    /// problem naming it, because sending it would be a `-32602` naming the parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<String>,
}

impl Defaults {
    /// The stored mode as the enum both start surfaces build parameters from.
    pub fn approval_mode(&self) -> Option<ApprovalMode> {
        self.approval_mode.as_deref().and_then(ApprovalMode::parse)
    }

    /// Whether anything at all has been stated. A settings screen shows a different
    /// sentence for "nothing is set" than for "these are your answers".
    pub fn is_empty(&self) -> bool {
        self.provider.is_none() && self.workspace.is_none() && self.approval_mode.is_none()
    }
}

/// Whether the first-run panel has been shown and dismissed.
///
/// A marker rather than a timestamp: the only question it answers is "has this person
/// already been told where things are", and a date would invite a client to decide the
/// answer expires.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Onboarding {
    #[serde(default)]
    pub welcomed: bool,
}

/// A config file as it was found: what it said, where it is, and what was wrong with it.
///
/// `problems` is separate from the config rather than folded into an error, because both
/// halves matter at once — the client runs on the defaults *and* says the file did not
/// parse, naming it. A caller that dropped one of the two would either hide a broken file
/// or refuse to start over one.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: Config,
    pub path: PathBuf,
    pub problems: Vec<String>,
}

/// Where the preferences live: `$XDG_CONFIG_HOME/ouroboros/config.toml` when that variable
/// names an absolute path, and `~/.config/ouroboros/config.toml` otherwise.
///
/// The same rule [`crate::runtime::Paths`] uses for the data and cache roots, and for the
/// same reason: this client follows the XDG variables directly rather than the platform
/// conventions `dirs` would apply, so a caller who sets one gets the directory they named.
pub fn path() -> Result<PathBuf> {
    Ok(xdg_root("XDG_CONFIG_HOME", ".config")?
        .join(CONFIG_DIR)
        .join(CONFIG_FILE))
}

/// Reads the file at [`path`], or reports why it could not be read.
///
/// Total by construction: every failure produces a default config and a sentence naming
/// this file. `ouro` starting a runtime must not depend on a preference file being
/// well-formed.
pub fn load_default() -> Loaded {
    match path() {
        Ok(path) => load(path),
        Err(error) => Loaded {
            config: Config::default(),
            // There is no path to name, so the one thing this can report is that there is
            // nowhere to keep preferences — which is the same condition `Paths::discover`
            // refuses on, and here it is only a lost default.
            path: PathBuf::from(CONFIG_FILE),
            problems: vec![format!("no config file location: {error:#}")],
        },
    }
}

/// [`load_default`] against a path the caller names. The tests drive this one.
pub fn load(path: PathBuf) -> Loaded {
    let mut problems = Vec::new();

    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        // The ordinary first run. Not a problem, and not worth a sentence.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Loaded {
                config: Config::default(),
                path,
                problems,
            }
        }
        Err(error) => {
            problems.push(format!(
                "{} could not be read ({error}); running on defaults",
                path.display()
            ));

            return Loaded {
                config: Config::default(),
                path,
                problems,
            };
        }
    };

    let mut config = match toml::from_str::<Config>(&text) {
        Ok(config) => config,
        Err(error) => {
            // The whole message, not the first line: toml points at the line and column,
            // which is the part that makes it fixable.
            problems.push(format!(
                "{} is not readable as TOML ({}); running on defaults",
                path.display(),
                one_line(&error.to_string())
            ));

            Config::default()
        }
    };

    normalise(&mut config, &path, &mut problems);

    Loaded {
        config,
        path,
        problems,
    }
}

/// Turns values this build cannot act on back into "unset", saying which and why.
///
/// A blank string is quietly treated as absent: `""` and "no answer" are the same
/// statement, and [`crate::model::StartRequest`] trims for the same reason. An approval
/// mode outside the schema is *not* quiet — the gateway refuses it by name, so a client
/// that carried it silently would fail a start with an error about a parameter the
/// operator never typed.
fn normalise(config: &mut Config, path: &Path, problems: &mut Vec<String>) {
    blank_to_none(&mut config.defaults.provider);
    blank_to_none(&mut config.defaults.workspace);
    blank_to_none(&mut config.defaults.approval_mode);

    if let Some(mode) = config.defaults.approval_mode.clone() {
        if ApprovalMode::parse(&mode).is_none() {
            problems.push(format!(
                "{}: defaults.approval_mode is {mode:?}, which is not one of {}; treating it \
                 as unset",
                path.display(),
                ApprovalMode::ALL
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));

            config.defaults.approval_mode = None;
        }
    }
}

fn blank_to_none(value: &mut Option<String>) {
    if value.as_deref().map(str::trim).unwrap_or("").is_empty() {
        *value = None;
    }
}

/// A multi-line error folded onto one line, for a notice line that is one row tall.
fn one_line(text: &str) -> String {
    text.split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

impl Config {
    /// Writes the file, creating its directory, without ever leaving a partial one behind.
    ///
    /// Temp-and-rename in the *same* directory: `rename` is atomic within a filesystem, so
    /// a reader either sees the whole previous file or the whole new one. A write straight
    /// onto the target would have a window in which the file is truncated, and a client
    /// that crashed inside it would have eaten the operator's preferences to save them.
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

        let body = toml::to_string_pretty(self).context("encoding the config file")?;

        let temp = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| CONFIG_FILE.to_string()),
            std::process::id()
        ));

        // 0600 like everything else this client writes into its own directories. Nothing
        // here is a secret, but a workspace path is nobody else's business either.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .with_context(|| format!("writing {}", temp.display()))?;

        let written = io::Write::write_all(&mut file, HEADER.as_bytes())
            .and_then(|()| io::Write::write_all(&mut file, body.as_bytes()))
            .and_then(|()| io::Write::flush(&mut file))
            // Durability before the rename, so a crash cannot publish a name that points
            // at bytes the filesystem has not committed.
            .and_then(|()| file.sync_all());

        if let Err(error) = written {
            let _ = fs::remove_file(&temp);
            return Err(anyhow::Error::from(error).context(format!("writing {}", temp.display())));
        }

        drop(file);

        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(anyhow::Error::from(error).context(format!(
                "renaming {} onto {}",
                temp.display(),
                path.display()
            )));
        }

        Ok(())
    }
}

/// What one `ouro new` invocation stated on its command line. `None` means the flag was
/// absent, which is what makes the config file reachable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartFlags {
    pub provider: Option<String>,
    pub workspace: Option<String>,
    pub approval_mode: Option<String>,
}

/// The parameters a start will be built from, and where each of them came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStart {
    pub provider: String,
    pub workspace: Option<String>,
    pub approval_mode: Option<String>,
}

/// The one thing no default can supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    Provider,
}

impl Missing {
    /// Names both ways to answer, because a person who hit this has not been told there is
    /// a second one.
    pub fn message(&self, config_path: &Path) -> String {
        match self {
            Self::Provider => format!(
                "no provider was named. Pass --provider NAME, or set one once with the \
                 settings overlay (`,`) inside `ouro`, which writes {}:\n\n    [defaults]\n \
                 \x20  provider = \"NAME\"\n\nWhich vendor runs your code stays a choice you \
                 make explicitly; this client will not pick one for you.",
                config_path.display()
            ),
        }
    }
}

/// Flag, then the config file, then a refusal. The same order for all three parameters.
///
/// Only the provider can fail: a workspace and an approval mode that nobody stated are
/// legitimately absent — the plane decides — while a provider that nobody stated would be
/// the node's default deciding which vendor runs the operator's code.
pub fn resolve_start(flags: &StartFlags, defaults: &Defaults) -> Result<ResolvedStart, Missing> {
    let provider = first(&flags.provider, &defaults.provider).ok_or(Missing::Provider)?;

    Ok(ResolvedStart {
        provider,
        workspace: first(&flags.workspace, &defaults.workspace),
        approval_mode: first(&flags.approval_mode, &defaults.approval_mode),
    })
}

/// The flag if it says something, the stored default if it does, otherwise nothing.
fn first(flag: &Option<String>, stored: &Option<String>) -> Option<String> {
    for candidate in [flag, stored] {
        let value = candidate.as_deref().unwrap_or("").trim();

        if !value.is_empty() {
            return Some(value.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SCRATCH: AtomicU32 = AtomicU32::new(0);

    /// A directory of this test's own under the OS temp root. The real home is never
    /// touched: every path below is built from here, and `path()` is exercised by pointing
    /// `XDG_CONFIG_HOME` at one of these rather than by reading the caller's environment.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ouro-config-{name}-{}-{}",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));

        fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[test]
    fn a_config_round_trips_through_the_file_it_writes() {
        let dir = scratch("round-trip");
        let path = dir.join(CONFIG_FILE);

        let config = Config {
            defaults: Defaults {
                provider: Some("claude".into()),
                workspace: Some("/home/me/project".into()),
                approval_mode: Some("auto_edit".into()),
            },
            onboarding: Onboarding { welcomed: true },
        };

        config.save(&path).expect("a written config");

        let loaded = load(path.clone());

        assert_eq!(loaded.config, config);
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
        assert_eq!(loaded.path, path);
        assert_eq!(
            loaded.config.defaults.approval_mode(),
            Some(ApprovalMode::AutoEdit)
        );

        // The file says what wrote it and what a save does to hand edits.
        let text = fs::read_to_string(&path).expect("a readable config");
        assert!(text.contains("schema 1"), "{text}");
        assert!(text.contains("[defaults]"), "{text}");
        assert!(text.contains("[onboarding]"), "{text}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_the_first_run_rather_than_a_problem() {
        let dir = scratch("absent");
        let loaded = load(dir.join(CONFIG_FILE));

        assert_eq!(loaded.config, Config::default());
        assert!(!loaded.config.onboarding.welcomed);
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keys_a_newer_ouro_wrote_are_ignored_rather_than_refused() {
        let dir = scratch("unknown-keys");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "schema = 2\n\
             [defaults]\n\
             provider = \"codex\"\n\
             telepathy = true\n\
             [onboarding]\n\
             welcomed = true\n\
             greeted_at = \"2031-01-01\"\n\
             [a_table_from_a_later_build]\n\
             enabled = true\n",
        )
        .expect("a forward-looking config");

        let loaded = load(path);

        assert_eq!(loaded.config.defaults.provider.as_deref(), Some("codex"));
        assert!(loaded.config.onboarding.welcomed);
        assert!(
            loaded.problems.is_empty(),
            "a newer file is not a broken one: {:?}",
            loaded.problems
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_file_falls_back_to_defaults_and_names_itself() {
        let dir = scratch("corrupt");
        let path = dir.join(CONFIG_FILE);

        fs::write(&path, "[defaults\nprovider = ").expect("a broken config");

        let loaded = load(path.clone());

        assert_eq!(loaded.config, Config::default());
        assert_eq!(loaded.problems.len(), 1, "{:?}", loaded.problems);
        assert!(
            loaded.problems[0].contains(&path.display().to_string()),
            "the problem must name the file: {}",
            loaded.problems[0]
        );
        assert!(
            loaded.problems[0].contains("defaults"),
            "and carry what TOML said: {}",
            loaded.problems[0]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_approval_mode_outside_the_schema_is_dropped_and_reported() {
        let dir = scratch("bad-mode");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "[defaults]\nprovider = \"codex\"\napproval_mode = \"yolo\"\n",
        )
        .expect("a config with a typo");

        let loaded = load(path);

        // The rest of the file still counts: one bad value is not a bad file.
        assert_eq!(loaded.config.defaults.provider.as_deref(), Some("codex"));
        assert_eq!(loaded.config.defaults.approval_mode, None);
        assert_eq!(loaded.config.defaults.approval_mode(), None);
        assert_eq!(loaded.problems.len(), 1);
        assert!(
            loaded.problems[0].contains("yolo") && loaded.problems[0].contains("auto_approve"),
            "the problem names the value and what would have been accepted: {}",
            loaded.problems[0]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_blank_value_is_the_same_statement_as_an_absent_one() {
        let dir = scratch("blank");
        let path = dir.join(CONFIG_FILE);

        fs::write(
            &path,
            "[defaults]\nprovider = \"\"\nworkspace = \"   \"\napproval_mode = \"\"\n",
        )
        .expect("a blank config");

        let loaded = load(path);

        assert!(loaded.config.defaults.is_empty());
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_save_replaces_the_previous_file_whole_and_leaves_no_temp_behind() {
        let dir = scratch("atomic");
        let path = dir.join(CONFIG_FILE);

        let first = Config {
            defaults: Defaults {
                provider: Some("claude".into()),
                ..Defaults::default()
            },
            onboarding: Onboarding { welcomed: false },
        };

        first.save(&path).expect("a first write");

        let second = Config {
            defaults: Defaults {
                workspace: Some("/srv/work".into()),
                ..Defaults::default()
            },
            onboarding: Onboarding { welcomed: true },
        };

        second.save(&path).expect("a second write");

        assert_eq!(load(path.clone()).config, second);

        // Nothing but the file itself: the temp is renamed onto the target, never left.
        let entries: Vec<String> = fs::read_dir(&dir)
            .expect("a readable directory")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .collect();

        assert_eq!(entries, vec![CONFIG_FILE.to_string()], "{entries:?}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_save_creates_the_directories_its_path_names() {
        let dir = scratch("mkdir");
        let path = dir.join("nested").join("deeper").join(CONFIG_FILE);

        Config::default().save(&path).expect("a written config");

        assert!(path.is_file());
        assert_eq!(load(path).config, Config::default());

        fs::remove_dir_all(&dir).ok();
    }

    /// `path()` reads process-wide environment, so the two cases it distinguishes are
    /// exercised in one test rather than in two that could interleave.
    #[test]
    fn the_config_root_follows_xdg_config_home_only_when_it_is_absolute() {
        let dir = scratch("xdg");

        let previous = std::env::var_os("XDG_CONFIG_HOME");
        let previous_home = std::env::var_os("HOME");

        // SAFETY: `cargo test` runs test functions on threads of one process, and this
        // test is the only one that touches these two variables; it restores both.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &dir);
        }

        assert_eq!(
            path().expect("a config path"),
            dir.join(CONFIG_DIR).join(CONFIG_FILE)
        );

        // Relative is not a root. The variable is ignored and the home fallback applies,
        // which is `xdg_root`'s rule and is checked here against a home of this test's own
        // rather than against the caller's.
        let home = dir.join("home");
        fs::create_dir_all(&home).expect("a scratch home");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", "relative/config");
            std::env::set_var("HOME", &home);
        }

        assert_eq!(
            path().expect("a config path"),
            home.join(".config").join(CONFIG_DIR).join(CONFIG_FILE)
        );

        unsafe {
            match previous {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }

            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_flag_beats_the_file_and_the_file_beats_nothing() {
        let defaults = Defaults {
            provider: Some("claude".into()),
            workspace: Some("/home/me/project".into()),
            approval_mode: Some("auto_edit".into()),
        };

        // Nothing stated: every answer comes from the file.
        let resolved = resolve_start(&StartFlags::default(), &defaults).expect("a resolution");

        assert_eq!(resolved.provider, "claude");
        assert_eq!(resolved.workspace.as_deref(), Some("/home/me/project"));
        assert_eq!(resolved.approval_mode.as_deref(), Some("auto_edit"));

        // Stated: the flag wins, field by field.
        let flags = StartFlags {
            provider: Some("codex".into()),
            approval_mode: Some("prompt".into()),
            ..StartFlags::default()
        };

        let resolved = resolve_start(&flags, &defaults).expect("a resolution");

        assert_eq!(resolved.provider, "codex");
        assert_eq!(
            resolved.workspace.as_deref(),
            Some("/home/me/project"),
            "a flag that was not passed does not clear the default"
        );
        assert_eq!(resolved.approval_mode.as_deref(), Some("prompt"));
    }

    #[test]
    fn nothing_anywhere_is_refused_by_naming_both_ways_to_answer() {
        let refusal =
            resolve_start(&StartFlags::default(), &Defaults::default()).expect_err("a refusal");

        assert_eq!(refusal, Missing::Provider);

        let message = refusal.message(Path::new("/home/me/.config/ouroboros/config.toml"));

        assert!(message.contains("--provider"), "{message}");
        assert!(
            message.contains("/home/me/.config/ouroboros/config.toml"),
            "{message}"
        );
        assert!(message.contains('`') && message.contains(','), "{message}");
        assert!(
            message.contains("[defaults]") && message.contains("provider ="),
            "the refusal shows the file it is asking for: {message}"
        );
    }

    #[test]
    fn a_workspace_and_an_approval_mode_are_allowed_to_be_unstated() {
        let flags = StartFlags {
            provider: Some("codex".into()),
            ..StartFlags::default()
        };

        let resolved = resolve_start(&flags, &Defaults::default()).expect("a resolution");

        assert_eq!(resolved.provider, "codex");
        assert_eq!(resolved.workspace, None);
        assert_eq!(resolved.approval_mode, None);
    }
}
