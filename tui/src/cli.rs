//! The command surface.
//!
//! No subcommand is the common case — start or adopt a runtime and attach to it — so it
//! is the default rather than a word to type. Everything else names an action that
//! differs from it in exactly one way: `daemon` does not attach, `attach` does not
//! start, `stop` only stops.
//!
//! There is deliberately no `--token` flag. A secret on a command line is readable by
//! every process on the host for as long as the command runs, and the gateway prefers a
//! 0600 file for the same reason.
//!
//! Flags here are the *first* place an answer is looked for, not the only one:
//! [`crate::config`] holds the defaults an operator stated once, and
//! [`crate::config::resolve_start`] is the single function that decides which of the two
//! wins. Nothing below reads that file — a flag's job is to say what was typed.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ouro",
    version,
    about = "Terminal client for an Ouroboros runtime",
    long_about = None
)]
pub struct Cli {
    /// Start `mix run --no-halt` from an ouroboros checkout instead of an embedded
    /// release, in a data directory of its own so a development daemon and a real one
    /// never discover each other.
    #[arg(long, global = true)]
    pub dev: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start an interactive session and attach to it.
    ///
    /// Every option here is one the gateway's `interactive.start` allowlist accepts, and
    /// nothing else is sent. Each one resolves the same way: the flag, then
    /// `[defaults]` in the config file, then whatever the plane does on its own.
    ///
    /// The provider is the one parameter with no third step. This client still refuses to
    /// *invent* one — letting a node's default decide would be a terminal choosing which
    /// vendor runs your code — but it will use one you chose yourself, once, explicitly,
    /// in a file you can read. That is what `--provider` and the settings overlay (`,`)
    /// are two ways of saying.
    New {
        /// A provider this runtime serves. `ouro attach --print` lists them. Omitted, the
        /// config file's `defaults.provider` is used, and with neither this refuses.
        #[arg(long, value_name = "NAME")]
        provider: Option<String>,

        /// The directory the session works in, resolved by the *runtime*. Omitted, the
        /// config file's `defaults.workspace`, and with neither the plane decides.
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,

        /// One of: default, prompt, auto_edit, auto_approve. Omitted, the config file's
        /// `defaults.approval_mode`, and with neither the plane decides.
        #[arg(long, value_name = "MODE")]
        approval_mode: Option<String>,

        /// A first message, sent once the session is ready.
        #[arg(long, short = 'm', value_name = "TEXT")]
        message: Option<String>,

        /// Print the session id and exit instead of opening the terminal UI.
        #[arg(long)]
        print: bool,
    },

    /// Start a runtime, print how to reach it, and leave it running.
    Daemon,

    /// Connect to a runtime this client did not start.
    Attach {
        /// Where the gateway listens. Omitted, the local gateway.json is read instead.
        #[arg(long, value_name = "HOST:PORT")]
        addr: Option<String>,

        /// A file holding the gateway token. Omitted, the token beside gateway.json is
        /// used.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,

        /// Print one status page and exit instead of opening the terminal UI. This is the
        /// path for a pipe, a log, or a terminal that is not a tty.
        #[arg(long)]
        print: bool,
    },

    /// Stop the runtime this client started.
    Stop,

    /// Print the client version, the embedded release if there is one, and the protocol.
    Version,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ouro").chain(args.iter().copied()))
            .expect("a parseable command line")
    }

    #[test]
    fn ouro_new_takes_a_provider_and_no_longer_requires_one() {
        let Some(Command::New { provider, .. }) = parse(&["new", "--provider", "codex"]).command
        else {
            panic!("`ouro new --provider codex` must parse as New");
        };

        assert_eq!(provider.as_deref(), Some("codex"));

        // The flag being absent is what makes the config file reachable; the refusal, when
        // there is nothing in either place, is `config::resolve_start`'s and names both.
        let Some(Command::New { provider, .. }) = parse(&["new"]).command else {
            panic!("`ouro new` must parse without a provider");
        };

        assert_eq!(provider, None);
    }

    #[test]
    fn the_other_start_options_stay_optional_and_carry_what_was_typed() {
        let Some(Command::New {
            workspace,
            approval_mode,
            message,
            print,
            ..
        }) = parse(&[
            "new",
            "--workspace",
            "/srv/work",
            "--approval-mode",
            "auto_edit",
            "-m",
            "hello",
            "--print",
        ])
        .command
        else {
            panic!("a fully-specified `ouro new` must parse");
        };

        assert_eq!(workspace, Some(PathBuf::from("/srv/work")));
        assert_eq!(approval_mode.as_deref(), Some("auto_edit"));
        assert_eq!(message.as_deref(), Some("hello"));
        assert!(print);
    }

    /// There is no `--token` anywhere, and that is a property worth failing a build over.
    #[test]
    fn no_subcommand_accepts_a_token_on_the_command_line() {
        for args in [
            vec!["--token", "secret"],
            vec!["attach", "--token", "secret"],
            vec!["new", "--token", "secret"],
            vec!["daemon", "--token", "secret"],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("ouro").chain(args.iter().copied())).is_err(),
                "a secret on a command line is readable by every process on the host: {args:?}"
            );
        }
    }
}
