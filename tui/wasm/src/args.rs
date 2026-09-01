//! Argument parsing for the helper: two subcommands and one flag.
//!
//! Hand-rolled rather than clap, for the same reason `ouro-computer-use` hand-rolls its own:
//! this member exists to keep a large dependency out of `ouro`'s graph, and adding a second
//! large one to parse three words would be a strange way to honour that. Parsing is a pure
//! function over an argument iterator, so it is unit-testable without touching real argv.

use std::fmt;

pub const USAGE: &str = "\
ouro-wasm — the Ouroboros WebAssembly containment helper

USAGE:
    ouro-wasm <COMMAND> [OPTIONS]

COMMANDS:
    serve     Speak the JSON-RPC helper protocol on stdin/stdout.
    doctor    Report what this build can contain, and exit.

OPTIONS:
    --max-frame-bytes <N>      Cap on one JSON-RPC line, in bytes (default 8388608).
    -h, --help                 Print this message.
";

/// The default line cap, mirrored from [`crate::codec::DEFAULT_MAX_FRAME_BYTES`] so the CLI help
/// and the codec agree on one number.
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
    let mut max_frame_bytes = DEFAULT_MAX_FRAME_BYTES;

    let mut args = argv.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(ParseError::Help),

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
        assert_eq!(args.max_frame_bytes, DEFAULT_MAX_FRAME_BYTES);
    }

    #[test]
    fn the_default_frame_cap_is_eight_mebibytes() {
        assert_eq!(DEFAULT_MAX_FRAME_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn max_frame_bytes_override_either_side_of_the_command() {
        assert_eq!(
            parse_str(&["serve", "--max-frame-bytes", "4096"])
                .unwrap()
                .max_frame_bytes,
            4096
        );
        assert_eq!(
            parse_str(&["--max-frame-bytes", "4096", "serve"])
                .unwrap()
                .command,
            Command::Serve
        );
    }

    #[test]
    fn help_and_errors() {
        assert_eq!(parse_str(&["--help"]), Err(ParseError::Help));
        assert_eq!(
            parse_str(&[]),
            Err(message("no command given; expected `serve` or `doctor`"))
        );
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
        assert!(matches!(
            parse_str(&["serve", "doctor"]),
            Err(ParseError::Message(_))
        ));
    }
}
