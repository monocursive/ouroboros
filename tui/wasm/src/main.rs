//! `ouro-wasm`: the Ouroboros WebAssembly containment helper (docs/WASM.md §7.3, slice W0).
//!
//! It loads, instantiates, and calls signed capability components on behalf of the runtime, and
//! it is a separate process on the end of a pipe for a reason worth stating plainly: this is
//! the one program in the system whose job is to run bytes nobody trusts. A wasmtime panic —
//! or, one day, a wasmtime escape — costs a Port and a pool cooldown, not the node (D3). A
//! runtime whose own forge bans `load_nif` at three layers has no business hosting untrusted
//! code in its own address space.
//!
//! Three entry points, two of them like every helper in this house:
//!   * `serve` — read requests from stdin, write responses to stdout. The mode
//!     `Ouroboros.Wasm.Pool` spawns.
//!   * `doctor` — report what this build can contain, print the JSON, exit. No side effects and
//!     no engine left running.
//!   * `precompile` — compile one component into the serialized form a matching node may map,
//!     and exit (W8, docs/WASM.md D23). It is the *signing* side of the lane: the machine that
//!     signs is now the machine that pays for compilation, and it applies §7.3's structural
//!     bounds in full before it does, so a component past a bound is refused here with the name
//!     a node's `load` would have used.
//!
//! # What contains what
//!
//! * [`world`] is the one world this helper speaks, and the early check that some bytes are in
//!   it. Policy: it refuses a component that could never link, with a refusal that says why.
//! * [`shape`] is the bound in front of the compiler: a structural walk that refuses a component
//!   shaped to be expensive to compile *before* `Component::new` runs, because cranelift cannot
//!   be interrupted once it has started and this helper answers one request at a time.
//! * [`host`] is the boundary itself — a linker that defines `log` and nothing else, and three
//!   mandatory bounds (fuel, an epoch deadline, a memory ceiling) that no request can opt out
//!   of. Enforcement: an import this helper does not define has nothing to bind to.
//! * [`precompiled`] is the container a compiled artifact travels in, and the header a node
//!   reads — the wasmtime, the triple, the world and the source component — before it maps one.
//! * [`refusal`] is every way this helper says no, one private code and one stable name each.
//! * [`codec`] and [`server`] are the pipe: 8 MiB frames capped as they are read, a noise
//!   budget, six methods and no seventh.
//!
//! Nothing here decides whether a component *should* run. Signatures, provenance, and the
//! registry belong to the BEAM, exactly as policy and approvals do for the desktop helper.

mod args;
mod codec;
mod doctor;
mod host;
mod precompiled;
mod refusal;
mod server;
mod shape;
mod world;

use std::process::ExitCode;
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match args::parse(std::env::args().skip(1)) {
        Ok(args) => run(args).await,
        Err(args::ParseError::Help) => {
            print!("{}", args::USAGE);
            ExitCode::SUCCESS
        }
        Err(args::ParseError::Message(message)) => {
            eprintln!("ouro-wasm: {message}\n\n{}", args::USAGE);
            // 2 is the conventional "usage error" exit.
            ExitCode::from(2)
        }
    }
}

async fn run(args: args::Args) -> ExitCode {
    match args.command {
        args::Command::Doctor => {
            println!("{}", doctor::report_pretty());
            ExitCode::SUCCESS
        }
        args::Command::Precompile {
            input,
            output,
            kind,
        } => precompile(&input, &output, &kind),

        args::Command::Serve => {
            // A helper that cannot build an engine cannot contain anything, so it refuses to
            // pretend it is serving. The pool sees the process die on its handshake and enters
            // its broken state, which is the honest reading of what happened; `ouro-wasm
            // doctor` then says why in one line.
            let host = match host::Host::new() {
                Ok(host) => Arc::new(host),
                Err(error) => {
                    eprintln!("ouro-wasm: no wasmtime engine on this host: {error}");
                    return ExitCode::FAILURE;
                }
            };

            let reader = tokio::io::BufReader::new(tokio::io::stdin());
            let writer = tokio::io::stdout();
            match server::run(host, reader, writer, args.max_frame_bytes).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("ouro-wasm: serve ended on I/O error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// `precompile <in.wasm> <out.cwasm> [--kind]`.
///
/// Refusals print as the same JSON object the wire carries — `{"refusal": …, "message": …}` — so
/// a signer scripting this reads one shape whether it drove the helper over a pipe or over argv,
/// and exits 1. Success prints the census and what was produced, and exits 0.
fn precompile(input: &str, output: &str, kind: &str) -> ExitCode {
    let Some(kind) = world::Kind::parse(kind) else {
        let known: Vec<&str> = world::KINDS.iter().map(|world| world.name()).collect();
        eprintln!(
            "ouro-wasm: --kind must be one of {}; got `{kind}`",
            known.join(", ")
        );
        return ExitCode::from(2);
    };

    let host = match host::Host::new() {
        Ok(host) => host,
        Err(error) => {
            eprintln!("ouro-wasm: no wasmtime engine on this host: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Read through the same bounded reader `load` uses, so the signer refuses an over-cap or
    // not-a-file input exactly as a node would.
    let bytes = match host::read_source(input) {
        Ok(bytes) => bytes,
        Err(refusal) => return refused(refusal),
    };

    let (container, report) = match host.precompile(&bytes, kind) {
        Ok(produced) => produced,
        Err(refusal) => return refused(refusal),
    };

    if let Err(error) = std::fs::write(output, &container) {
        eprintln!("ouro-wasm: {output}: {error}");
        return ExitCode::FAILURE;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| report.to_string())
    );
    ExitCode::SUCCESS
}

fn refused(refusal: refusal::Refusal) -> ExitCode {
    eprintln!(
        "{}",
        serde_json::json!({ "refusal": refusal.refusal, "code": refusal.code, "message": refusal.message })
    );
    ExitCode::FAILURE
}
