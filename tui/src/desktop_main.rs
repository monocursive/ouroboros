use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "ouro-desktop",
    about = "Native GPUI client for an Ouroboros runtime"
)]
struct Args {
    /// Start or adopt the runtime from this source checkout.
    #[arg(long)]
    dev: bool,

    /// Attach to an explicit gateway instead of the local runtime.
    #[arg(long, value_name = "HOST:PORT")]
    addr: Option<SocketAddr>,

    /// Token for --addr. Local attachment reads the private local token automatically.
    #[arg(long, value_name = "PATH", requires = "addr")]
    token_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ouro::desktop::run(ouro::desktop::LaunchOptions {
        dev: args.dev,
        addr: args.addr,
        token_file: args.token_file,
    })
}
