//! Argument parsing for the helper: two subcommands and a small, fixed set of flags.
//!
//! Hand-rolled rather than clap: `ouro-computer-use` has exactly `serve` and `doctor`, one
//! repeatable flag, and one numeric flag, and keeping clap out of this member's graph is the
//! whole point of the member (the `ouro` crate uses clap; this one does not need to). Parsing
//! is a pure function over an argument iterator so it is unit-testable without touching real
//! argv.

use std::fmt;

pub const USAGE: &str = "\
ouro-computer-use — the Ouroboros Computer Use helper (macOS)

USAGE:
    ouro-computer-use <COMMAND> [OPTIONS]

COMMANDS:
    serve     Speak the JSON-RPC helper protocol on stdin/stdout.
    doctor    Probe host permissions, print the doctor JSON, and exit.

OPTIONS:
    --deny-app <BUNDLE_ID>     Refuse to observe or act on this app. Repeatable.
    --max-frame-bytes <N>      Cap on one JSON-RPC line, in bytes (default 8388608).
    -h, --help                 Print this message.
";

/// The default line cap, mirrored from [`crate::codec::DEFAULT_MAX_FRAME_BYTES`] so the CLI
/// help and the codec agree on one number.
pub const DEFAULT_MAX_FRAME_BYTES: usize = crate::codec::DEFAULT_MAX_FRAME_BYTES;

/// Which subcommand was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    Doctor,
}

/// The parsed invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub command: Command,
    /// Bundle ids the helper must refuse (doc §7.3, "helper also reads a --deny-app argv
    /// list"). Retained now; enforced in Phase 1 when `state`/`act` are real.
    pub deny_apps: Vec<String>,
    pub max_frame_bytes: usize,
}

/// A parse outcome that is not a usable [`Args`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// `-h`/`--help` was given: print usage and exit successfully.
    Help,
    /// Something was wrong with the arguments.
    Message(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help => f.write_str("help requested"),
            Self::Message(message) => f.write_str(message),
        }
    }
}

fn message(text: impl Into<String>) -> ParseError {
    ParseError::Message(text.into())
}

/// Parses arguments (the program name already stripped).
pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Args, ParseError> {
    let mut command: Option<Command> = None;
    let mut deny_apps: Vec<String> = Vec::new();
    let mut max_frame_bytes = DEFAULT_MAX_FRAME_BYTES;

    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(ParseError::Help),

            "--deny-app" => {
                let id = args
                    .next()
                    .ok_or_else(|| message("--deny-app needs a bundle id"))?;
                if id.trim().is_empty() {
                    return Err(message("--deny-app id must not be empty"));
                }
                deny_apps.push(id);
            }

            "--max-frame-bytes" => {
                let raw = args
                    .next()
                    .ok_or_else(|| message("--max-frame-bytes needs a number"))?;
                let value = raw
                    .trim()
                    .parse::<usize>()
                    .map_err(|error| message(format!("--max-frame-bytes: {error}")))?;
                if value == 0 {
                    return Err(message("--max-frame-bytes must be greater than zero"));
                }
                max_frame_bytes = value;
            }

            "serve" if command.is_none() => command = Some(Command::Serve),
            "doctor" if command.is_none() => command = Some(Command::Doctor),

            other if other.starts_with('-') => {
                return Err(message(format!("unknown option: {other}")))
            }
            other => return Err(message(format!("unexpected argument: {other}"))),
        }
    }

    let command =
        command.ok_or_else(|| message("no command given; expected `serve` or `doctor`"))?;

    Ok(Args {
        command,
        deny_apps,
        max_frame_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &[&str]) -> Result<Args, ParseError> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn doctor_command() {
        let args = parse_str(&["doctor"]).unwrap();
        assert_eq!(args.command, Command::Doctor);
        assert!(args.deny_apps.is_empty());
        assert_eq!(args.max_frame_bytes, DEFAULT_MAX_FRAME_BYTES);
    }

    #[test]
    fn serve_with_repeated_deny_app() {
        let args = parse_str(&[
            "serve",
            "--deny-app",
            "com.apple.Terminal",
            "--deny-app",
            "com.googlecode.iterm2",
        ])
        .unwrap();
        assert_eq!(args.command, Command::Serve);
        assert_eq!(
            args.deny_apps,
            vec![
                "com.apple.Terminal".to_string(),
                "com.googlecode.iterm2".to_string()
            ]
        );
    }

    #[test]
    fn deny_app_before_the_command_is_fine() {
        let args = parse_str(&["--deny-app", "com.apple.Terminal", "serve"]).unwrap();
        assert_eq!(args.command, Command::Serve);
        assert_eq!(args.deny_apps, vec!["com.apple.Terminal".to_string()]);
    }

    #[test]
    fn max_frame_bytes_override() {
        let args = parse_str(&["serve", "--max-frame-bytes", "4096"]).unwrap();
        assert_eq!(args.max_frame_bytes, 4096);
    }

    #[test]
    fn help_and_errors() {
        assert_eq!(parse_str(&["--help"]), Err(ParseError::Help));
        assert_eq!(
            parse_str(&[]),
            Err(message("no command given; expected `serve` or `doctor`"))
        );
        assert!(matches!(
            parse_str(&["--deny-app"]),
            Err(ParseError::Message(_))
        ));
        assert!(matches!(
            parse_str(&["serve", "--nope"]),
            Err(ParseError::Message(_))
        ));
        assert!(matches!(
            parse_str(&["frobnicate"]),
            Err(ParseError::Message(_))
        ));
        assert!(matches!(
            parse_str(&["serve", "--max-frame-bytes", "0"]),
            Err(ParseError::Message(_))
        ));
        assert!(matches!(
            parse_str(&["serve", "--max-frame-bytes", "lots"]),
            Err(ParseError::Message(_))
        ));
    }
}
