//! Argument parsing, hand-rolled for the same reason `computer-use` hand-rolls its own:
//! the surface is three verbs and four flags, and a derive-macro CLI would be a larger
//! dependency than the thing it parses.

use std::fmt;

/// Where the JSON request comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `--request '<json>'`. What the daemon uses.
    Inline(String),
    /// `--request-file PATH`.
    File(String),
    /// `--request-file -`: one newline-terminated line on stdin.
    Stdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Apply a policy and become the command.
    Exec {
        source: Source,
        /// The program and its argv, after `--`.
        target: Vec<String>,
    },
    /// Report what this kernel can enforce, as JSON, and exit.
    Doctor,
    Version,
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub const USAGE: &str = "\
ouro-sandbox — apply one Ouroboros native-session sandbox policy and exec a command.

USAGE:
    ouro-sandbox exec --request <JSON>      -- <program> [args...]
    ouro-sandbox exec --request-file <PATH> -- <program> [args...]
    ouro-sandbox exec --request-file -      -- <program> [args...]
    ouro-sandbox doctor
    ouro-sandbox --version

The request is one JSON object; see the `request` module for its shape. `-` reads a
single newline-terminated line from stdin, one byte at a time, so the bytes after the
newline are left for the command, which inherits this descriptor.

On success this process is replaced by the command, so the command's exit status is this
process's exit status. A failure to *apply* the policy is reported on stderr, prefixed
`ouro-sandbox: `, and exits 125 — never the command's own status, because
\"this node could not sandbox it\" and \"your command failed\" call for different fixes.";

pub fn parse<I: Iterator<Item = String>>(argv: I) -> Result<Command, UsageError> {
    let args: Vec<String> = argv.collect();
    let mut rest = args.iter();

    let verb = match rest.next() {
        Some(verb) => verb.as_str(),
        None => return Ok(Command::Help),
    };

    match verb {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" | "version" => return Ok(Command::Version),
        "doctor" => {
            return match rest.next() {
                None => Ok(Command::Doctor),
                Some(extra) => Err(UsageError(format!(
                    "doctor takes no arguments, got {extra:?}"
                ))),
            }
        }
        "exec" => {}
        other => {
            return Err(UsageError(format!(
                "unknown command {other:?}; expected `exec`, `doctor`, or `--version`"
            )))
        }
    }

    let mut source: Option<Source> = None;
    let mut target: Vec<String> = Vec::new();
    let mut saw_separator = false;

    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--" => {
                saw_separator = true;
                target.extend(rest.cloned());
                break;
            }
            "--request" => {
                let value = rest
                    .next()
                    .ok_or_else(|| UsageError("--request needs a JSON value".to_string()))?;
                set_source(&mut source, Source::Inline(value.clone()))?;
            }
            "--request-file" => {
                let value = rest
                    .next()
                    .ok_or_else(|| UsageError("--request-file needs a path or -".to_string()))?;
                let next = if value == "-" {
                    Source::Stdin
                } else {
                    Source::File(value.clone())
                };
                set_source(&mut source, next)?;
            }
            other => {
                return Err(UsageError(format!(
                    "unexpected argument {other:?} before `--`"
                )))
            }
        }
    }

    let source = source.ok_or_else(|| {
        UsageError(
            "exec needs --request or --request-file; refusing to run a command \
                    with no policy at all"
                .to_string(),
        )
    })?;

    if !saw_separator {
        return Err(UsageError(
            "exec needs `--` followed by the program to run".to_string(),
        ));
    }
    if target.is_empty() {
        return Err(UsageError("`--` was given no program to run".to_string()));
    }

    Ok(Command::Exec { source, target })
}

fn set_source(slot: &mut Option<Source>, next: Source) -> Result<(), UsageError> {
    if slot.is_some() {
        // Two sources means one of them is being silently ignored, and a policy that was
        // silently ignored is the failure mode this whole helper exists to prevent.
        return Err(UsageError(
            "give exactly one of --request or --request-file".to_string(),
        ));
    }
    *slot = Some(next);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_of(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_the_shape_the_daemon_sends() {
        assert_eq!(
            parse_of(&["exec", "--request", "{}", "--", "/bin/sh", "-c", "ls"]),
            Ok(Command::Exec {
                source: Source::Inline("{}".to_string()),
                target: vec!["/bin/sh".to_string(), "-c".to_string(), "ls".to_string()],
            })
        );
    }

    #[test]
    fn a_dash_means_stdin_and_a_path_means_a_file() {
        assert!(matches!(
            parse_of(&["exec", "--request-file", "-", "--", "/bin/true"]),
            Ok(Command::Exec {
                source: Source::Stdin,
                ..
            })
        ));
        assert!(matches!(
            parse_of(&["exec", "--request-file", "/p.json", "--", "/bin/true"]),
            Ok(Command::Exec {
                source: Source::File(ref p),
                ..
            }) if p == "/p.json"
        ));
    }

    #[test]
    fn everything_after_the_separator_belongs_to_the_command() {
        // Including things that look like this helper's own flags: the command's argv is
        // not this helper's business to interpret.
        let parsed = parse_of(&[
            "exec",
            "--request",
            "{}",
            "--",
            "/bin/sh",
            "-c",
            "echo --request",
        ]);
        assert_eq!(
            parsed,
            Ok(Command::Exec {
                source: Source::Inline("{}".to_string()),
                target: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo --request".to_string()
                ],
            })
        );
    }

    #[test]
    fn exec_without_a_policy_is_refused() {
        assert!(parse_of(&["exec", "--", "/bin/true"]).is_err());
    }

    #[test]
    fn exec_without_a_program_is_refused() {
        assert!(parse_of(&["exec", "--request", "{}"]).is_err());
        assert!(parse_of(&["exec", "--request", "{}", "--"]).is_err());
    }

    #[test]
    fn two_policy_sources_are_refused_rather_than_one_being_ignored() {
        assert!(parse_of(&[
            "exec",
            "--request",
            "{}",
            "--request-file",
            "/p.json",
            "--",
            "/bin/true"
        ])
        .is_err());
    }

    #[test]
    fn the_other_verbs() {
        assert_eq!(parse_of(&["doctor"]), Ok(Command::Doctor));
        assert_eq!(parse_of(&["--version"]), Ok(Command::Version));
        assert_eq!(parse_of(&[]), Ok(Command::Help));
        assert!(parse_of(&["frobnicate"]).is_err());
        assert!(parse_of(&["doctor", "extra"]).is_err());
    }
}
