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
