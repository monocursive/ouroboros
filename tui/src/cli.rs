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

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ouro",
    version,
    about = "Terminal client for an Ouroboros runtime",
    long_about = None
)]
pub struct Cli {
    /// Start `mix run --no-halt` from an ouroboros checkout instead of an embedded
    /// release. Its default data directory is isolated as `ouroboros-dev`; an explicit
    /// OUROBOROS_DATA_DIR is used exactly and warns because it can name a release runtime.
    #[arg(long, global = true)]
    pub dev: bool,

    /// Draw for a screen reader: labelled lines instead of boxes, static spinners,
    /// numbered menus, spelled-out truncation markers, and a bell when the agent needs
    /// you. Also settable as `[accessibility] screen_reader = true` in config.toml or
    /// `OURO_SCREEN_READER=1`.
    #[arg(long = "ax-screen-reader", global = true)]
    pub ax_screen_reader: bool,

    /// Open the most recent session whose workspace is this directory — on any machine in
    /// the fleet, because `interactive.list` is fanned out over all of them — instead of
    /// landing on the sessions rail. With nothing to continue this refuses rather than
    /// starting a session; `--or-new` is how you ask for one.
    #[arg(long = "continue")]
    pub continue_session: bool,

    /// With `--continue` and nothing to continue, open the new-session dialog for this
    /// workspace instead of refusing.
    #[arg(long, requires = "continue_session")]
    pub or_new: bool,

    /// Which directory `--continue` means. Omitted, the one this command is typed in.
    #[arg(long, value_name = "PATH", requires = "continue_session")]
    pub workspace: Option<PathBuf>,

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
    /// With no `--provider` or stored default, the direct Native provider is used.
    New {
        /// A provider this runtime serves. Omitted, the config file's default and then
        /// `native`.
        #[arg(long, value_name = "NAME")]
        provider: Option<String>,
        /// A full direct model spec. Omitted, `[defaults].model` or the runtime default.
        #[arg(long, value_name = "SPEC")]
        model: Option<String>,

        /// The directory the session works in. Local relative paths resolve where this
        /// command is typed. With --machine, this must already be an absolute destination
        /// path on that machine. Omitted, the config file's `defaults.workspace` is used.
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,

        /// One of: default, prompt, auto_edit, auto_approve. Omitted, the config file's
        /// `defaults.approval_mode`, and with neither the plane decides.
        #[arg(long, value_name = "MODE")]
        approval_mode: Option<String>,

        /// One of: default, read_only, workspace_write, unrestricted. Omitted, the config
        /// file's `defaults.sandbox_mode`, and with neither the plane starts a session that
        /// can edit the workspace where the provider allows it.
        #[arg(long, value_name = "MODE")]
        sandbox_mode: Option<String>,

        /// A first message, sent once the session is ready.
        #[arg(long, short = 'm', value_name = "TEXT")]
        message: Option<String>,

        /// Run the agent on this fleet machine. Use its friendly name from
        /// `ouro fleet status`; omitted means the runtime chooses locally.
        #[arg(long, value_name = "NAME")]
        machine: Option<String>,

        /// Run in a fresh `git worktree` under the runtime's data directory instead of
        /// the workspace itself, so two sessions on one repository do not fight over its
        /// exclusive lease (D7). Refused where the workspace is not a git repository.
        #[arg(long)]
        worktree: bool,

        /// Start the session planning (B2): it reads and reasons but edits nothing, and
        /// at the end of a planning turn it asks whether to build the plan.
        ///
        /// The only way to reach plan mode on a transport that carries the posture on
        /// every launch — Claude refuses a mid-life change — so this is not merely a
        /// shortcut for `/plan on` once the session is open.
        #[arg(long)]
        plan: bool,

        /// Print the session id and exit instead of opening the terminal UI.
        #[arg(long)]
        print: bool,
    },

    /// Run one prompt without a screen and stream the normalised events.
    ///
    /// The scriptable surface: no alternate screen, ever, and stdout carries exactly one
    /// of three things — the agent's final text, the result object, or the event stream
    /// followed by the result object. Progress and warnings go to stderr so none of the
    /// three can be corrupted by them.
    Run(Box<RunArgs>),

    /// Print every session this runtime can see, grouped by what each one needs.
    ///
    /// The same grouping the Sessions rail draws — needs input, working, done — printed
    /// once and exited, for a terminal without a tty and for the thirty seconds where
    /// opening a UI to ask "is anything waiting on me" is thirty seconds too many.
    Agents {
        /// One JSON object with the counts and the runtime's own rows, instead of the
        /// plain page.
        #[arg(long)]
        json: bool,

        /// Where the gateway listens. Omitted, the local gateway.json is read instead.
        #[arg(long, value_name = "HOST:PORT")]
        addr: Option<String>,

        /// A file holding the gateway token. Omitted, the token beside gateway.json is
        /// used.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
    },

    /// The MCP servers this runtime runs for the native agent, and the files that declare
    /// them (D4).
    ///
    /// `list` reads the runtime. `add` and `remove` edit a JSON file and never touch the
    /// socket: there is no `mcp.add` on the wire, because a server definition is a command
    /// line that runs on somebody's machine and is never authored over a socket.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
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

    /// Open this daemon's browser surface (docs/WEB.md).
    ///
    /// Starts or adopts a local runtime exactly as the bare command does, reads the port
    /// the web endpoint published to `web.json`, and turns it and the operator token into
    /// the one URL that exchanges that token for a session cookie. The link is printed
    /// whatever happens, because it carries the credential and is the whole of what a
    /// browser needs.
    ///
    /// There is no `--addr` here, deliberately: the endpoint binds loopback and publishes
    /// its port without its address, so this is a command about the daemon on this
    /// machine. A remote surface is reached through the proxy in front of it.
    Web {
        /// Print the URL and exit instead of also opening a browser. The path for a
        /// script, a remote shell, and a terminal on a machine with no browser at all.
        #[arg(long)]
        print: bool,
    },

    /// Stop the runtime this client started.
    Stop,

    /// Print the durable effect ledger: what an agent was allowed to do, and what came
    /// of it.
    ///
    /// Reads a runtime that is already running; it never starts one, because a query is
    /// not a reason to bring a machine up. `--fleet` asks every connected core node
    /// instead of this one and names any that did not answer, on stderr, so `--json` stays
    /// a clean stream for a pipe.
    Ledger(LedgerArgs),

    /// Re-read a recorded session against its journal and print it, deterministically.
    ///
    /// Replay executes nothing, spends nothing, and writes no ledger entry: it reads the
    /// turn journal for provenance — the chain head, how far it verifies, what the budget
    /// dropped, one row per model call — and then renders the session's own events through
    /// the same projection the terminal draws. Two runs at the same width are the same
    /// bytes, which is what makes the output diffable.
    ///
    /// Reads a runtime that is already running; it never starts one, because replaying a
    /// session is a question about history. Native sessions only — every other transport
    /// has no journal to read, and says so.
    ///
    /// Re-calling the model is a *fork*, not a replay. See `ouro fork`.
    Replay(ReplayArgs),

    /// Branch a recorded session into a new one, optionally at a turn and on another model.
    ///
    /// The child id is minted here, before the call, so a reply lost in transit can only
    /// ever adopt the same child rather than silently create a second one.
    ///
    /// `--at` and `--model` are what make a fork an experiment rather than a copy: branch
    /// at the decision point, substitute the model, and the two journals are directly
    /// comparable records of the same prefix. A runtime whose fork envelope predates those
    /// two params refuses them by name, and this says so rather than printing the
    /// `invalid_params` it was given.
    Fork(ForkArgs),

    /// Computer Use operator surface. `ouro desktop doctor` reports node readiness.
    Desktop {
        #[command(subcommand)]
        command: DesktopCommand,
    },

    /// WebAssembly containment operator surface. `ouro wasm doctor` reports node readiness.
    Wasm {
        #[command(subcommand)]
        command: WasmCommand,
    },

    /// Create, join, and diagnose a secure group of Ouroboros machines.
    Fleet {
        #[command(subcommand)]
        command: FleetCommand,
    },

    /// Serve one Ouroboros session to an editor over the Agent Client Protocol.
    ///
    /// Not typed at a prompt: an ACP client — Zed, JetBrains, a Neovim or VS Code plugin —
    /// spawns this process and speaks newline-framed JSON-RPC to its stdio, so stdout is a
    /// protocol and carries nothing else. Omitted provider selection falls back to the
    /// direct Native provider; `--workspace` is only a fallback for a client that sends no
    /// `cwd`.
    ///
    /// Register it with your editor's ACP agent configuration (Zed and JetBrains both use
    /// an `agent_servers` map): the command is this binary and the argument is `acp`.
    Acp(Box<AcpArgs>),

    /// Run the packaged runtime in the foreground for a generated user service.
    #[command(hide = true)]
    ServiceRun,

    /// Serve the session's permission prompt to a vendor CLI over MCP on stdio.
    ///
    /// Never run by hand. `Ouroboros.Provider.ClaudeAdapter` names this subcommand in the
    /// `--mcp-config` it composes for a Claude session, and Claude Code spawns it as the
    /// server behind `--permission-prompt-tool mcp__ouroboros__approve`. It reads the
    /// runtime to ask from `OUROBOROS_GATEWAY_ADDR`, `OUROBOROS_GATEWAY_TOKEN_FILE`,
    /// `OUROBOROS_SESSION_ID`, and `OUROBOROS_SESSION_NODE`; started without them, every
    /// approval is denied with a message saying so.
    #[command(hide = true)]
    McpServe,

    /// Answer a vendor agent's own hook event.
    ///
    /// Never run by hand either. `Ouroboros.Provider.ClaudeAdapter` composes the hook into
    /// the `--settings` JSON a bridged Claude session is launched with, and Claude Code
    /// runs it with the same four `OUROBOROS_*` variables the MCP bridge gets. Every
    /// subcommand here reads one JSON object on stdin, writes one on stdout, and exits 0
    /// whatever happened: a hook that refuses is a hook that can send a model back to redo
    /// an edit that already succeeded.
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },

    /// Print the exact kernel incarnation of one process for the BEAM ownership protocol.
    #[command(hide = true)]
    ProcessBirth {
        #[arg(long, hide = true)]
        pid: i32,
    },

    /// Hold the BEAM runtime-owner recovery gate until stdin closes.
    #[command(hide = true)]
    HoldRuntimeRecoveryLock {
        #[arg(long, hide = true)]
        path: PathBuf,
    },

    /// Replace this binary with a signed release, or refuse and say why.
    ///
    /// Every path through this command needs the release public key compiled in from
    /// `dist/release.pub`: the Ed25519 signature over `SHA256SUMS` is the only thing that
    /// makes a download trustworthy, and a checksum fetched from the same place as the
    /// binary proves nothing on its own. A build without that key refuses rather than
    /// installing something it cannot check.
    ///
    /// Exit codes: 0 up to date or updated; 10 (`--check`) an update exists; 11 no
    /// release key in this build; 12 verification failed; 13 refused as a downgrade;
    /// 14 the installed binary is not this command's to replace; 15 nothing could be
    /// fetched; 16 no asset for this platform.
    ///
    /// There is no `--channel`: this project publishes one tag stream and no
    /// stable/nightly split exists to follow. `docs/DISTRIBUTION.md` says what would have
    /// to change first.
    Update(UpdateArgs),

    /// Print the client version, the embedded release if there is one, and the protocol.
    Version,
}

/// `ouro acp`'s flags, in one struct so the dispatch stays one line.
///
/// The start options are `ouro new`'s, resolved by the same
/// [`crate::config::resolve_start`] against the same `[defaults]`; `--addr`/`--token-file`
/// are `ouro attach`'s, and naming either one attaches instead of starting a runtime.
#[derive(Debug, Args)]
pub struct AcpArgs {
    /// A provider this runtime serves. Omitted, the config file's default and then
    /// `native`.
    #[arg(long, value_name = "NAME")]
    pub provider: Option<String>,

    /// The directory a session works in when the editor's `session/new` names no `cwd`.
    /// An editor that speaks ACP always sends one, so this is a fallback and not an
    /// override: the editor knows which project the person opened.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    /// One of: default, prompt, auto_edit, auto_approve. The posture every session this
    /// agent starts begins in; the editor moves it afterwards with `session/set_mode`.
    #[arg(long, value_name = "MODE")]
    pub approval_mode: Option<String>,

    /// One of: default, read_only, workspace_write, unrestricted.
    #[arg(long, value_name = "MODE")]
    pub sandbox_mode: Option<String>,

    /// Where the gateway listens. Omitted, a local runtime is adopted or started.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// `ouro ledger`'s flags. Sequences are minted per node, so `--since` is per node too.
#[derive(Debug, Args)]
pub struct LedgerArgs {
    /// Ask every connected core node rather than only this one.
    #[arg(long)]
    pub fleet: bool,

    /// Only effects after this sequence number.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub since: u64,

    /// One JSON object per entry on stdout instead of a table. Nodes that did not answer
    /// go to stderr either way.
    #[arg(long)]
    pub json: bool,

    /// How many entries at most. The runtime bounds this as well, and its bound wins.
    #[arg(long, value_name = "N")]
    pub limit: Option<u64>,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// `ouro replay`'s flags.
#[derive(Debug, Args)]
pub struct ReplayArgs {
    /// The session to replay.
    #[arg(value_name = "SESSION")]
    pub session: String,

    /// The machine that owns the session. Omitted, the one this command reached.
    #[arg(long, value_name = "NAME")]
    pub node: Option<String>,

    /// Also ask the runtime to re-derive the session from its record and print the
    /// verdict, or the divergence it found by name.
    #[arg(long)]
    pub verify: bool,

    /// The raw journal records and then the raw events, one JSON object per line, on
    /// stdout. The provenance header moves to stderr so the stream stays pipeable.
    #[arg(long)]
    pub json: bool,

    /// The measure the transcript wraps prose at. Fixed rather than the terminal's, so
    /// the same session renders the same bytes from any window.
    #[arg(long, value_name = "N", default_value_t = ouro_replay_default_width())]
    pub width: usize,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// Named rather than written twice: the help text and the renderer must agree about the
/// default, and a literal in both places is how they stop agreeing.
fn ouro_replay_default_width() -> usize {
    crate::replay_cli::DEFAULT_WIDTH
}

/// `ouro fork`'s flags.
#[derive(Debug, Args)]
pub struct ForkArgs {
    /// The session to branch.
    #[arg(value_name = "SESSION")]
    pub session: String,

    /// The machine that owns it. Omitted, the one this command reached.
    #[arg(long, value_name = "NAME")]
    pub node: Option<String>,

    /// Branch at this turn instead of at the tail. The child is seeded with the parent's
    /// conversation truncated to that point — the same turn ids `ouro` shows in the
    /// backtrack menu.
    #[arg(long, value_name = "TURN")]
    pub at: Option<String>,

    /// Run the child on this model spec instead of inheriting the parent's.
    #[arg(long, value_name = "SPEC")]
    pub model: Option<String>,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// `ouro desktop`'s subcommands. One so far.
#[derive(Debug, Subcommand)]
pub enum DesktopCommand {
    /// Report Computer Use readiness on the node — helper presence, permissions, and
    /// capabilities. Asks `computer_use.status` by default (starts nothing). `--probe`
    /// starts the helper so TCC is visible.
    Doctor(DesktopArgs),
}

/// `ouro desktop doctor`'s flags.
#[derive(Debug, Args)]
pub struct DesktopArgs {
    /// Emit the raw status JSON instead of a readable summary.
    #[arg(long)]
    pub json: bool,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,

    /// Start the helper and report live TCC (`computer_use.probe`). Default is
    /// start-nothing `computer_use.status`.
    #[arg(long)]
    pub probe: bool,
}

/// `ouro wasm`'s subcommands: one that asks a node, and five that ask a local helper.
///
/// `doctor` is the operator's readiness surface and starts nothing at all. The other five are
/// the component author's loop (W10): each starts a local `ouro-wasm` and speaks its protocol,
/// which is the deliberate difference — a readiness surface that spawned to answer whether
/// spawning works would be answering a different question, and a development loop that needed
/// a running node would not be a loop.
#[derive(Debug, Subcommand)]
pub enum WasmCommand {
    /// Report WebAssembly containment readiness on the node — helper presence and phase,
    /// the world and bounds it runs under, the hook-component budget, the component store,
    /// and lane-W rollouts. Asks `wasm.status`, which starts nothing.
    ///
    /// There is deliberately no `--probe`: starting the helper to see whether it starts is
    /// the one thing a read-scope readiness surface must not do.
    Doctor(WasmArgs),

    /// Scaffold a component project that builds, in the world this runtime speaks.
    ///
    /// Written from a template embedded in this binary, never fetched: a scaffold a command
    /// downloads is a command that runs somebody else's code the first time it is used.
    New(WasmNewArgs),

    /// What a component declares, how its shape sits against the bounds that decide whether
    /// it compiles at all, and whether the node would admit it — as a capability, as a hook
    /// component, or as neither, naming the refusal.
    ///
    /// It loads the component into a local helper, which compiles it under the same
    /// structural bound the node uses. It never instantiates it, so nothing runs.
    Inspect(WasmInspectArgs),

    /// Stand one instance up and send it messages, under the node's own default bounds.
    ///
    /// Every message goes to the *same* instance, because state in this world is
    /// instance-held: a fresh instance per message would quietly exercise a different
    /// component from the one that gets deployed.
    Run(WasmRunArgs),

    /// Run a component the way the node's hook seam would, and print both verdicts — what the
    /// component said, and what the node would keep of it after the untrusted narrowing.
    ///
    /// The second is the only one that ever reaches a turn, so an author who tests a hook by
    /// reading its own output is testing a verdict the runtime may already have dropped.
    Hook(WasmHookArgs),

    /// Validate a workspace's `ouroboros.toml` component entries the way the node would judge
    /// them for a workspace nobody trusts, and exit non-zero on any refusal.
    ///
    /// It never instantiates anything: admission is a question about a path, a size, a world
    /// and the count of an entry's siblings, and running a component answers none of it.
    Check(WasmCheckArgs),
    // W12 adds its variants below
    // W12
    /// Write an Ed25519 signer seed and print the two configuration lines that put it to
    /// work: the private half's path on the signer node, and the public half's entry in
    /// every core node's trusted signers. Contacts no runtime; the key never travels.
    Keygen(WasmKeygenArgs),

    /// Sign a component into a `.ouro-wasm` bundle. Uploads the bytes to the node, which
    /// hands them to its signing service — the whole policy runs there, on the host that
    /// holds the key, and the decision is journalled. This end never signs anything.
    Sign(WasmSignArgs),

    /// Deploy a `.ouro-wasm` bundle. The node verifies it against its own trust policy
    /// before the store, the helper or the rollout register hears about it; a bundle read
    /// off this disk is untrusted input all the way to the far side. Exits non-zero unless
    /// the rollout settled live.
    Deploy(WasmDeployArgs),

    /// Retire a live capability: stop its wrapper agent and mark the rollout. The component
    /// bytes stay in the store, so redeploying needs a new epoch and a new signature but no
    /// new build.
    Rollback(WasmRollbackArgs),

    /// List what a node holds: every lane-W rollout the register knows and every component
    /// in the store.
    Ls(WasmArgs),
}

/// `ouro wasm keygen`'s flags.
#[derive(Debug, Args)]
pub struct WasmKeygenArgs {
    /// Where to write the seed. Refuses to overwrite an existing file, because a key file
    /// that is already there may be the one a fleet trusts.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// The identity this key signs as. It must match `OUROBOROS_SIGNER_ID` on the signer
    /// node and the id every core node trusts the public half under.
    #[arg(long, value_name = "SIGNER_ID", default_value = "release-key")]
    pub id: String,
}

/// `ouro wasm sign`'s flags.
#[derive(Debug, Args)]
pub struct WasmSignArgs {
    /// The component to sign.
    pub component: PathBuf,

    /// The capability's name: lower case, starting with a letter or digit, then letters,
    /// digits, `.`, `_` or `-`. It is the rollout register's module and the durable id a
    /// start block claims cluster-wide, so it is not decoration.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Who built this. The signing policy requires provenance and will not sign without it.
    #[arg(long, value_name = "AUTHOR")]
    pub author: String,

    /// An import the component declares. Repeat it once per import, or pass none at all for
    /// a component that imports nothing.
    ///
    /// The node does not read the component to find out: those are unsigned bytes from a
    /// socket, and handing them to a helper to be parsed is what the containment lane
    /// exists to avoid (docs/WASM.md D15). Compute the list with the *operator's* own
    /// helper — `ouro wasm inspect --json` — and pass it here, or pipe it in with
    /// `--imports-from`. A list that does not match what the component actually imports is
    /// refused at stage by the cross-check.
    #[arg(long = "import", value_name = "NAME")]
    pub import: Vec<String>,

    /// Read the imports from `ouro wasm inspect --json` output — a file, or `-` for stdin.
    /// The explicit form of what this command otherwise does for itself: `ouro wasm inspect
    /// g.wasm --json | ouro wasm sign g.wasm --name g --author me --imports-from -`.
    #[arg(long, value_name = "PATH", conflicts_with = "import")]
    pub imports_from: Option<PathBuf>,

    /// Do not start a local `ouro-wasm` to read the component's imports; require `--import`
    /// or `--imports-from` instead.
    ///
    /// For a machine that has no helper. The node will not read the component either — it
    /// never parses bytes it has not verified (docs/WASM.md D15) — so on such a machine the
    /// import list has to arrive from somewhere a person named.
    #[arg(long)]
    pub no_local_helper: bool,

    /// Print the `wasm.sign` parameters this command would send and stop. Opens no socket
    /// and uploads nothing; `upload` is null because nothing was uploaded.
    ///
    /// It still reads the imports the way the real run would, so it is the way to see what
    /// your helper says about a component before a node is asked to sign it.
    #[arg(long)]
    pub dry_run: bool,

    /// The guest toolchain, recorded as provenance.
    #[arg(long, value_name = "LANGUAGE")]
    pub language: Option<String>,

    /// The source tree's digest, recorded as provenance. 64 lower-case hex.
    #[arg(long, value_name = "SHA256")]
    pub source_sha256: Option<String>,

    /// The JSON config the durable wrapper starts with. Naming it is what makes this
    /// capability run continuously and survive a reboot. The wrapper's *id* is derived
    /// from `--name` and is deliberately not a flag.
    #[arg(long, value_name = "JSON")]
    pub start_config: Option<String>,

    /// A JSON file holding the evaluation spec. Required by default: lane W has no build
    /// peer behind it, so the signed spec is the test story (D12).
    #[arg(long, value_name = "PATH")]
    pub eval: Option<PathBuf>,

    /// Where to write the bundle. Defaults to `<name>.ouro-wasm` in the working directory.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Emit the raw result JSON instead of a readable summary.
    #[arg(long)]
    pub json: bool,

    /// The machine that signs and stages. This one by default.
    #[arg(long, value_name = "MACHINE")]
    pub node: Option<String>,

    /// The helper that reads this component's imports, when neither `--import` nor
    /// `--imports-from` declared them. Resolved by the same three-place rule as
    /// `ouro wasm inspect`, and it never reaches the node.
    #[command(flatten)]
    pub helper: WasmHelperArgs,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// `ouro wasm deploy`'s flags.
#[derive(Debug, Args)]
pub struct WasmDeployArgs {
    /// The `.ouro-wasm` bundle to deploy.
    pub bundle: PathBuf,

    /// The machines to deploy to, comma separated. The driving node alone by default.
    /// Deploying to machines you are not driving from costs reboot survival, and the answer
    /// says so rather than refusing.
    #[arg(long, value_name = "LIST")]
    pub nodes: Option<String>,

    /// Emit the raw result JSON instead of a readable summary.
    #[arg(long)]
    pub json: bool,

    /// The machine that drives the rollout and holds its register entry. This one by
    /// default.
    #[arg(long, value_name = "MACHINE")]
    pub node: Option<String>,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// `ouro wasm rollback`'s flags.
#[derive(Debug, Args)]
pub struct WasmRollbackArgs {
    /// The live capability to retire.
    pub name: String,

    /// Emit the raw result JSON instead of a readable summary.
    #[arg(long)]
    pub json: bool,

    /// The machine holding the rollout's register entry. This one by default.
    #[arg(long, value_name = "MACHINE")]
    pub node: Option<String>,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// `ouro wasm doctor`'s flags.
#[derive(Debug, Args)]
pub struct WasmArgs {
    /// Emit the raw status JSON instead of a readable summary.
    #[arg(long)]
    pub json: bool,

    /// Where the gateway listens. Omitted, the local gateway.json is read instead.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

/// The one flag every local `ouro wasm` command takes, and the only way to name a helper
/// besides the environment.
///
/// `ouro wasm` derives no candidate from the working directory. It looks in exactly three
/// places — this flag, an absolute `OUROBOROS_WASM_HELPER`, and the `ouro-wasm` beside the
/// *resolved* `ouro` — because the helper *is* the containment boundary, and a cloned
/// repository that could drop a `priv/wasm/ouro-wasm` into the directory an author works in
/// would be choosing the binary this command spawns to contain untrusted code.
///
/// Naming a path inside a checkout is fine, and CI does exactly that: a person choosing is the
/// only thing that may choose. Every candidate is then canonicalised and must be an executable
/// regular file, owned by this account or root, that nobody else can rewrite — and the
/// canonical path is what is spawned, so the file checked is the file run (docs/WASM.md D14).
#[derive(Debug, Args)]
pub struct WasmHelperArgs {
    /// The `ouro-wasm` binary to use. Omitted, an absolute `$OUROBOROS_WASM_HELPER` is read,
    /// and failing that the `ouro-wasm` installed beside the resolved `ouro`. Nothing is
    /// derived from the working directory; a path you name is honoured wherever it points.
    #[arg(long, value_name = "PATH")]
    pub helper: Option<PathBuf>,
}

/// `ouro wasm new`'s flags.
#[derive(Debug, Args)]
pub struct WasmNewArgs {
    /// The project's name, which is also its crate name. Letters, digits, `-` and `_`.
    pub name: String,

    /// Scaffold a hook component — one that reads a hook payload and answers the verdict
    /// contract — instead of a plain capability.
    #[arg(long)]
    pub hook: bool,

    /// The directory to create the project in. Omitted, the current one.
    #[arg(long, value_name = "DIR")]
    pub into: Option<PathBuf>,

    /// The one line `describe` reports about this component. At most 200 characters, and
    /// untrusted wherever it is read. Omitted, a placeholder saying which shape this is.
    #[arg(long, value_name = "TEXT")]
    pub summary: Option<String>,

    /// Where `ouroboros-guest` lives, as the `path =` the generated `Cargo.toml` carries.
    ///
    /// The crate is not published yet, so a scaffolded project reaches the SDK by path.
    /// Omitted, this command walks up from `--into` looking for a checkout's
    /// `tui/wasm/guest`, and refuses rather than guessing when there is none above it.
    #[arg(long, value_name = "PATH")]
    pub sdk_path: Option<PathBuf>,
}

/// `ouro wasm inspect`'s flags.
#[derive(Debug, Args)]
pub struct WasmInspectArgs {
    /// The component to look at.
    pub file: PathBuf,

    /// Emit the helper's own report as JSON instead of a readable summary.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub helper: WasmHelperArgs,
}

/// `ouro wasm run`'s flags.
#[derive(Debug, Args)]
pub struct WasmRunArgs {
    /// The component to run.
    pub file: PathBuf,

    /// The JSON string handed to `init`, verbatim.
    #[arg(long, value_name = "JSON", default_value = "{}")]
    pub config: String,

    /// One message, as JSON. Repeatable; every message goes to the same instance.
    #[arg(long, value_name = "JSON")]
    pub message: Vec<String>,

    /// A file of JSON lines, one message per line. Read in order, after any `--message`.
    #[arg(long, value_name = "PATH")]
    pub messages: Option<PathBuf>,

    /// Also call `describe`, which is metadata and reads nothing.
    #[arg(long)]
    pub describe: bool,

    /// Instruction budget for one message. Defaults to the node's `capability_limits`; a
    /// value above what the helper accepts is clamped down to it and said out loud.
    #[arg(long, value_name = "N")]
    pub fuel: Option<u64>,

    /// Memory ceiling, summed across every memory the instance holds.
    #[arg(long, value_name = "N")]
    pub memory_bytes: Option<u64>,

    /// Wall-clock deadline for one message.
    #[arg(long, value_name = "MS")]
    pub deadline_ms: Option<u64>,

    /// Emit the whole run as JSON.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub helper: WasmHelperArgs,
}

/// `ouro wasm hook`'s flags.
///
/// There is no `--fuel` and no `--memory-bytes`, and that is the node's shape rather than an
/// omission: a hook declares one bound for itself, `timeout_ms`, and fuel and memory are
/// `config :ouroboros, :wasm`'s, where an operator can already see and move them.
#[derive(Debug, Args)]
pub struct WasmHookArgs {
    /// The component to run.
    pub file: PathBuf,

    /// The hook event, spelled as a hook declares it: `PreToolUse`, `PostToolUse`,
    /// `SessionStart`, and the rest.
    #[arg(long, value_name = "EVENT")]
    pub event: String,

    /// A file holding the hook payload as JSON, or `-` for standard input. Omitted, an empty
    /// object. The runtime's own `hook_event_name` is set over whatever this carries.
    #[arg(long, value_name = "PATH")]
    pub payload: Option<String>,

    /// The JSON string handed to `init`, verbatim — a hook's declared `config`.
    #[arg(long, value_name = "JSON", default_value = "{}")]
    pub config: String,

    /// Show the trusted lane: an operator's own hook, or a workspace they named. The default
    /// is the untrusted lane, because that is the one a cloned repository gets and the one
    /// whose narrowing an author needs to see.
    #[arg(long)]
    pub trusted: bool,

    /// The hook's declared `timeout_ms`, which becomes its deadline. Clamped to the component
    /// deadline ceiling exactly as the node clamps it.
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,

    /// Emit both verdicts and what was dropped as JSON.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub helper: WasmHelperArgs,
}

/// `ouro wasm check`'s flags.
#[derive(Debug, Args)]
pub struct WasmCheckArgs {
    /// The workspace holding the `ouroboros.toml`. Omitted, the current directory.
    #[arg(long, value_name = "DIR")]
    pub workspace: Option<PathBuf>,

    /// Emit the table as JSON.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub helper: WasmHelperArgs,
}

/// `ouro update`'s flags.
#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Print the running and published versions and exit 0 or 10. Downloads the signed
    /// manifest and verifies it — an unverifiable version number is not an answer — but
    /// fetches no asset and replaces nothing.
    #[arg(long)]
    pub check: bool,

    /// A mirror: the URL or directory holding `ouro-<version>-<triple>`, `SHA256SUMS`,
    /// and `SHA256SUMS.minisig`. `https://`, `http://`, `file:///`, or a path. The
    /// signature is checked exactly the same way wherever the bytes came from, which is
    /// what makes a mirror safe to use at all.
    #[arg(long, value_name = "URL")]
    pub from: Option<String>,

    /// Install a release older than the running binary. Refused without this, because a
    /// rollback is a thing to mean rather than a thing to be handed.
    #[arg(long)]
    pub allow_downgrade: bool,
}

/// The vendor hook events this build answers. One so far.
#[derive(Debug, Subcommand)]
pub enum HookCommand {
    /// Claude Code's `PostToolUse`: announce the edit to the runtime's language server,
    /// wait up to five seconds, and print the new diagnostics as `additionalContext`.
    PostToolUse,
}

/// `ouro run`'s flags, in one struct so the dispatch stays one line.
///
/// The start options are `ouro new`'s, resolved by the same
/// [`crate::config::resolve_start`] against the same `[defaults]`; `--addr`/`--token-file`
/// are `ouro attach`'s, and naming either one attaches instead of starting a runtime.
/// Nothing here is a second way to say something the other two commands already say.
/// D4. The three things an operator does with MCP servers.
///
/// `list` is a read of the runtime and starts nothing, like `ouro agents`. `add` and
/// `remove` edit the Claude-compatible `mcp.json` the runtime's loader reads and never
/// open a socket at all.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Every MCP server this runtime runs, and every entry its loader refused.
    List {
        /// The node to ask. Omitted, this runtime's own — a server runs where its session
        /// runs, so a fleet asks the machine the work is on.
        #[arg(long, value_name = "NODE")]
        node: Option<String>,

        /// Also report what is *configured* for this workspace but not started, and every
        /// entry the loader refused. Without it the answer is only what is running.
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,

        /// The runtime's own answer as one JSON object, unchanged.
        #[arg(long)]
        json: bool,

        /// Where the gateway listens. Omitted, the local gateway.json is read instead.
        #[arg(long, value_name = "HOST:PORT")]
        addr: Option<String>,

        /// A file holding the gateway token. Omitted, the token beside gateway.json is
        /// used.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
    },

    /// Declare a server in `mcp.json`. No runtime is contacted and nothing is started.
    Add {
        /// `[A-Za-z0-9_-]{1,64}`, and no `__`: a tool reaches the model as
        /// `mcp__<server>__<tool>` and is split on the first `__`.
        name: String,

        /// The program to run. Required unless `--url` is given.
        #[arg(long, value_name = "PROGRAM")]
        command: Option<String>,

        /// An HTTP/SSE endpoint. Written to the file as a valid Claude Code definition,
        /// and refused by this runtime as `unsupported_transport`: this build speaks
        /// stdio only, and says so rather than dropping the entry.
        #[arg(long, value_name = "URL", conflicts_with = "command")]
        url: Option<String>,

        /// One argument. Repeat for more; order is kept.
        ///
        /// `allow_hyphen_values` because an MCP server's arguments are overwhelmingly
        /// flags — `--arg --stdio` is the common case, not the exotic one — and a parser
        /// that read the value as a second option would make this unusable for the servers
        /// people actually run.
        #[arg(long = "arg", value_name = "ARG", allow_hyphen_values = true)]
        args: Vec<String>,

        /// One `KEY=VALUE`. Repeat for more. **Values are written and never printed
        /// back** — not by this command, and not by the runtime, which puts only a count
        /// on the wire.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// The directory the server runs in.
        #[arg(long, value_name = "PATH")]
        cwd: Option<String>,

        /// `user` writes `~/.config/ouroboros/mcp.json`; `workspace` writes
        /// `<workspace>/.ouroboros/mcp.json`, which the runtime reads only for a workspace
        /// it has been told to trust.
        #[arg(long, value_name = "SCOPE", default_value = "user")]
        scope: String,

        /// Which workspace, for `--scope workspace`. Omitted, the current directory.
        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,

        /// Replace a definition already recorded under this name. Without it a name
        /// already present with different bytes is refused.
        #[arg(long)]
        force: bool,

        /// Skip the check that `--command` resolves on PATH or is an existing file. The
        /// check only ever warns — the file may be written on one machine for a session
        /// that runs on another.
        #[arg(long)]
        no_check: bool,
    },

    /// Remove a server from `mcp.json`.
    Remove {
        name: String,

        #[arg(long, value_name = "SCOPE", default_value = "user")]
        scope: String,

        #[arg(long, value_name = "PATH")]
        workspace: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// The prompt to run.
    #[arg(value_name = "PROMPT")]
    pub prompt: String,

    /// Send the prompt into a session that already exists instead of starting one. The
    /// start options are refused with it: that session's provider and workspace were
    /// chosen when it started.
    #[arg(
        long,
        value_name = "SESSION-ID",
        conflicts_with_all = ["provider", "model", "workspace", "approval_mode", "sandbox_mode", "machine"]
    )]
    pub resume: Option<String>,

    /// Send the prompt into the most recent session whose workspace is `--workspace` (or
    /// this directory), on any machine in the fleet. It resolves to exactly what
    /// `--resume <id>` would have been given, which is why the two are refused together:
    /// one names a session and the other looks one up, and a command that accepted both
    /// would have to silently ignore one of them.
    ///
    /// With nothing to continue this refuses without starting a session. `--or-new` is
    /// how you ask for one instead, and the start options below are accepted only with it.
    #[arg(long = "continue", conflicts_with = "resume")]
    pub continue_session: bool,

    /// With `--continue` and nothing to continue, start a session and send the prompt into
    /// it instead of refusing.
    #[arg(long, requires = "continue_session")]
    pub or_new: bool,

    /// A provider this runtime serves. Omitted, the config file's default and then
    /// `native`.
    #[arg(long, value_name = "NAME")]
    pub provider: Option<String>,
    /// A full direct model spec. Omitted, `[defaults].model` or the runtime default.
    #[arg(long, value_name = "SPEC")]
    pub model: Option<String>,

    /// The directory the session works in. With --machine it must be an absolute
    /// destination path on that machine.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    /// One of: default, prompt, auto_edit, auto_approve.
    #[arg(long, value_name = "MODE")]
    pub approval_mode: Option<String>,

    /// One of: default, read_only, workspace_write, unrestricted.
    #[arg(long, value_name = "MODE")]
    pub sandbox_mode: Option<String>,

    /// Run the session on this fleet machine rather than locally.
    #[arg(long, value_name = "NAME")]
    pub machine: Option<String>,

    /// One JSON object per normalised event on stdout, then the result object. The event
    /// objects are the gateway's own, unchanged.
    #[arg(long, conflicts_with = "json")]
    pub stream_json: bool,

    /// The result object on stdout and nothing else.
    #[arg(long)]
    pub json: bool,

    /// Answer every approval request `approve` with scope `once`. Without it a headless
    /// run answers `deny`/`once` with a reason saying there was no approver — it never
    /// waits for one.
    #[arg(long)]
    pub approve_all: bool,

    /// Start the session planning (B2): it reads and reasons but edits nothing, and the
    /// plan it produced is reported in the result object as `plan`.
    ///
    /// The plan-exit question is answered `keep_planning`, **including under
    /// `--approve-all`**: nobody is at the keyboard, and a headless run that granted
    /// itself `auto_edit` would turn "plan this" into "do this" with no one to object.
    /// The session is left planning, so `ouro --continue` opens it where it was.
    #[arg(long)]
    pub plan: bool,

    /// Seconds before the turn is interrupted and reported as `timeout` (exit 4).
    #[arg(long, value_name = "SECS", default_value_t = 600)]
    pub timeout: u64,

    /// Progress on stderr. Stdout is never touched by it.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Where the gateway listens. Omitted, a local runtime is adopted or started.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<String>,

    /// A file holding the gateway token. Omitted, the token beside gateway.json is used.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum FleetCommand {
    /// Create a new secure fleet on this first machine.
    Create {
        /// A friendly label shown in Settings. Defaults to "MACHINE's fleet".
        #[arg(long, value_name = "FLEET")]
        name: Option<String>,

        /// A short label people will recognize, such as studio-mini.
        #[arg(long, value_name = "NAME")]
        machine: Option<String>,

        /// An IP address or DNS name every fleet machine can reach. A Tailscale
        /// MagicDNS name is usually the easiest choice.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,

        /// Pin the local-only operator gateway. Normally Ouroboros chooses a stable
        /// per-machine port; this override is useful for several test nodes on one host.
        #[arg(long, value_name = "PORT")]
        gateway_port: Option<u16>,

        /// Pin this machine's TLS distribution listener to one port. Normally a small
        /// firewall-friendly range is used.
        #[arg(long, value_name = "PORT")]
        dist_port: Option<u16>,
    },

    /// Make a private, one-machine invitation on the fleet's creator.
    Invite {
        /// Manage an invitation already recorded by the owner. With no action, creates
        /// an invitation using the flags below.
        #[command(subcommand)]
        command: Option<InviteCommand>,

        /// The new machine's friendly, unique label.
        #[arg(long, value_name = "NAME")]
        machine: Option<String>,

        /// The new machine's reachable IP address or DNS name.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,

        /// Where to write the mode-0600 invitation. Existing files are never replaced.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,

        /// Override the invited machine's stable local gateway port.
        #[arg(long, value_name = "PORT")]
        gateway_port: Option<u16>,

        /// Pin the invited machine's TLS distribution listener to one port.
        #[arg(long, value_name = "PORT")]
        dist_port: Option<u16>,

        /// Reissue credentials for the same machine and host after its local data was
        /// lost. This does not revoke a copied/compromised old credential.
        #[arg(long)]
        replace: bool,
    },

    /// Show known Tailscale peers and SSH config hosts this Mac can add.
    List,

    /// Create a private invitation, and either install the other machine over SSH or
    /// print the enroll recipe to run there.
    Add {
        /// `user@host` or a Tailscale MagicDNS name. Omit with --print-script.
        #[arg(value_name = "TARGET")]
        target: Option<String>,

        /// Friendly unique label for the new machine.
        #[arg(long, value_name = "NAME")]
        machine: Option<String>,

        /// How the fleet reaches the new machine. A Tailscale MagicDNS name or private
        /// IPv4 address. Omit to use what the SSH probe reports.
        #[arg(long, value_name = "HOST")]
        host: Option<String>,

        /// `ssh` (default) or `tailscale` for Tailscale SSH.
        #[arg(long, value_name = "VIA", default_value = "ssh")]
        via: String,

        /// A prebuilt ouro binary for the destination OS/CPU, when this Mac cannot copy
        /// its own (the usual Mac → Linux case).
        #[arg(long, value_name = "FILE")]
        binary: Option<PathBuf>,

        /// When the destination has no private address yet, install Tailscale there and
        /// sign it in. Runs the vendor's installer and `tailscale up` as root on that
        /// machine (passwordless sudo required) and prints the sign-in link here.
        #[arg(long)]
        setup_tailscale: bool,

        /// Do not SSH. Write the invitation and print the command to run on the other
        /// machine.
        #[arg(long)]
        print_script: bool,

        /// If this Mac is still standalone, create the fleet first. Requires a stopped
        /// runtime and --owner-host.
        #[arg(long)]
        init: bool,

        /// This Mac's fleet hostname when --init creates the owner profile.
        #[arg(long, value_name = "HOST")]
        owner_host: Option<String>,

        /// This Mac's friendly name when --init creates the owner profile.
        #[arg(long, value_name = "NAME")]
        owner_machine: Option<String>,
    },

    /// Join from a copied invitation, start the daemon, and delete the invitation.
    Enroll {
        /// The mode-0600 invitation file. Its contents are never printed.
        #[arg(value_name = "INVITE")]
        invitation: PathBuf,

        /// Delete the invitation after a successful join.
        #[arg(long)]
        delete: bool,

        /// Also write the recovery unit (does not activate it).
        #[arg(long)]
        service: bool,

        /// Override this machine's stable local gateway port.
        #[arg(long, value_name = "PORT")]
        gateway_port: Option<u16>,

        /// Pin this machine's TLS distribution listener to one port.
        #[arg(long, value_name = "PORT")]
        dist_port: Option<u16>,
    },

    /// Join using the private invitation copied from the fleet creator.
    Join {
        /// The mode-0600 invitation file. Its contents are never printed.
        #[arg(value_name = "INVITE")]
        invitation: PathBuf,

        /// Override this machine's stable local gateway port.
        #[arg(long, value_name = "PORT")]
        gateway_port: Option<u16>,

        /// Pin this machine's TLS distribution listener to one port.
        #[arg(long, value_name = "PORT")]
        dist_port: Option<u16>,
    },

    /// Show this machine's non-secret fleet identity and next action.
    Status,

    /// Check local security plus live fleet connectivity and compatibility when running.
    Doctor,

    /// Export or import a CA-attested membership roster after invitations change.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },

    /// Manage durable knowledge about sessions owned by removed fleet machines.
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },

    /// Remove this machine's fleet credentials after its runtime is stopped.
    Leave {
        /// Explicitly clear a partial setup whose profile.json is missing. Also requires
        /// --machine so Ouroboros can prove the matching recovery unit is inactive.
        #[arg(long, requires = "machine")]
        discard_incomplete: bool,

        /// The former machine name, required with --discard-incomplete to locate its
        /// launchd/systemd unit safely.
        #[arg(long, value_name = "NAME", requires = "discard_incomplete")]
        machine: Option<String>,
    },

    /// Install or inspect restart-on-failure integration for this fleet machine.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// Stop expecting an invitation that was abandoned or mistyped. This changes only
    /// saved membership and does not revoke a copied credential.
    Cancel {
        /// The recorded machine name to stop expecting.
        #[arg(long, value_name = "NAME")]
        machine: String,

        /// Write the signed roster that existing fleet machines must import.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Export the owner's current signed membership roster for existing machines.
    Export {
        /// A fresh mode-0600 output path; existing files are never overwritten.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Import a newer signed roster while this machine's runtime is stopped.
    Import {
        /// The mode-0600 roster file received privately from the fleet owner.
        #[arg(value_name = "ROSTER")]
        roster: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum SessionsCommand {
    /// Irreversibly forget this machine's saved routing evidence for a tombstoned,
    /// offline owner. Run this separately on every remaining fleet machine.
    Forget {
        /// The tombstoned machine whose offline session-owner evidence will be lost.
        #[arg(long, value_name = "NAME")]
        machine: String,

        /// Confirm that sessions known only through this local evidence may become
        /// undiscoverable while their former owner is offline.
        #[arg(long, required = true)]
        accept_state_loss: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Write a launchd (macOS) or systemd user unit and show the exact activation command.
    Install,
    /// Show the generated unit, activation guidance, and local runtime state.
    Status,
    /// Remove an inactive generated unit. Running services are refused.
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ouro").chain(args.iter().copied()))
            .expect("a parseable command line")
    }

    /// B2. `--plan` is a plain boolean on both surfaces, with no flag it fights.
    #[test]
    fn plan_is_a_boolean_on_new_and_on_run() {
        let Some(Command::New { plan, .. }) = parse(&["new", "--plan"]).command else {
            panic!("`ouro new --plan` must parse as New");
        };
        assert!(plan);

        let Some(Command::New { plan, .. }) = parse(&["new"]).command else {
            panic!("`ouro new` must parse");
        };
        assert!(!plan, "an unasked-for plan is not a plan");

        let Some(Command::Run(args)) = parse(&["run", "hi", "--plan"]).command else {
            panic!("`ouro run --plan` must parse as Run");
        };
        assert!(args.plan);

        // Deliberately compatible with --approve-all: the two say different things, and
        // the plan-exit answer stays `keep_planning` under both.
        let Some(Command::Run(args)) = parse(&["run", "hi", "--plan", "--approve-all"]).command
        else {
            panic!("`ouro run --plan --approve-all` must parse");
        };
        assert!(args.plan && args.approve_all);
    }

    /// D4. An MCP server's arguments are overwhelmingly flags, so `--arg --stdio` has to
    /// reach the file as the argument `--stdio` rather than being read as an option.
    ///
    /// Pinned because the first live run of this command failed on exactly that.
    #[test]
    fn mcp_add_takes_hyphenated_arguments() {
        let Some(Command::Mcp {
            command:
                McpCommand::Add {
                    name,
                    command,
                    args,
                    env,
                    scope,
                    ..
                },
        }) = parse(&[
            "mcp",
            "add",
            "fake",
            "--command",
            "/bin/cat",
            "--arg",
            "--stdio",
            "--arg",
            "-v",
            "--env",
            "TOKEN=x",
        ])
        .command
        else {
            panic!("`ouro mcp add` must parse");
        };

        assert_eq!(name, "fake");
        assert_eq!(command.as_deref(), Some("/bin/cat"));
        assert_eq!(args, vec!["--stdio".to_string(), "-v".to_string()]);
        assert_eq!(env, vec!["TOKEN=x".to_string()]);
        assert_eq!(scope, "user", "the default scope is the user file");
    }

    /// `--command` and `--url` are two transports, and naming both is refused by the
    /// parser rather than by the file writer.
    #[test]
    fn mcp_add_refuses_two_transports() {
        assert!(Cli::try_parse_from([
            "ouro",
            "mcp",
            "add",
            "fake",
            "--command",
            "/bin/cat",
            "--url",
            "https://example.invalid"
        ])
        .is_err());
    }

    /// `ouro mcp list` is a read with the same three flags every read-only subcommand has.
    #[test]
    fn mcp_list_carries_the_node_and_the_workspace() {
        let Some(Command::Mcp {
            command:
                McpCommand::List {
                    node,
                    workspace,
                    json,
                    ..
                },
        }) = parse(&[
            "mcp",
            "list",
            "--node",
            "ouroboros@golden",
            "--workspace",
            "/srv/repo",
            "--json",
        ])
        .command
        else {
            panic!("`ouro mcp list` must parse");
        };

        assert_eq!(node.as_deref(), Some("ouroboros@golden"));
        assert_eq!(workspace, Some(PathBuf::from("/srv/repo")));
        assert!(json);
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
            sandbox_mode,
            message,
            machine,
            print,
            ..
        }) = parse(&[
            "new",
            "--workspace",
            "/srv/work",
            "--approval-mode",
            "auto_edit",
            "--sandbox-mode",
            "read_only",
            "-m",
            "hello",
            "--machine",
            "builder-one",
            "--print",
        ])
        .command
        else {
            panic!("a fully-specified `ouro new` must parse");
        };

        assert_eq!(workspace, Some(PathBuf::from("/srv/work")));
        assert_eq!(approval_mode.as_deref(), Some("auto_edit"));
        assert_eq!(sandbox_mode.as_deref(), Some("read_only"));
        assert_eq!(message.as_deref(), Some("hello"));
        assert_eq!(machine.as_deref(), Some("builder-one"));
        assert!(print);
    }

    /// `--sandbox-mode unrestricted` reaches the start unmolested.
    ///
    /// The flag is a wire word by design: it is validated against `SandboxMode::ALL` and
    /// sent verbatim, with no client-side allowlist narrower than the gateway's own. The
    /// clients' *labels* say "full access"; nothing translates the flag on the way in.
    #[test]
    fn ouro_new_carries_every_documented_sandbox_mode_verbatim() {
        for mode in crate::model::SandboxMode::ALL {
            let Some(Command::New { sandbox_mode, .. }) =
                parse(&["new", "--sandbox-mode", mode.as_str()]).command
            else {
                panic!("`ouro new --sandbox-mode {}` must parse", mode.as_str());
            };

            assert_eq!(sandbox_mode.as_deref(), Some(mode.as_str()));
            assert_eq!(
                sandbox_mode
                    .as_deref()
                    .and_then(crate::model::SandboxMode::parse),
                Some(mode),
                "the string the flag carries is the string the start validates"
            );
        }
    }

    /// There is no `--token` anywhere, and that is a property worth failing a build over.
    #[test]
    fn no_subcommand_accepts_a_token_on_the_command_line() {
        for args in [
            vec!["--token", "secret"],
            vec!["attach", "--token", "secret"],
            vec!["new", "--token", "secret"],
            vec!["run", "prompt", "--token", "secret"],
            vec!["daemon", "--token", "secret"],
            vec!["fleet", "join", "invite", "--token", "secret"],
            vec!["fleet", "service", "install", "--token", "secret"],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("ouro").chain(args.iter().copied())).is_err(),
                "a secret on a command line is readable by every process on the host: {args:?}"
            );
        }
    }

    /// W5. `ouro wasm doctor` reports and never starts, so it takes the three flags every
    /// remote operator surface takes and deliberately not a fourth.
    #[test]
    fn ouro_wasm_doctor_reports_and_offers_no_way_to_start_the_helper() {
        let Some(Command::Wasm {
            command: WasmCommand::Doctor(args),
        }) = parse(&["wasm", "doctor", "--json"]).command
        else {
            panic!("`ouro wasm doctor --json` must parse");
        };

        assert!(args.json);
        assert_eq!(args.addr, None);
        assert_eq!(args.token_file, None);

        // Starting the helper to see whether it starts is the one thing this must not do,
        // so there is no flag that would.
        assert!(
            Cli::try_parse_from(["ouro", "wasm", "doctor", "--probe"]).is_err(),
            "a readiness surface with a --probe is a readiness surface that spawns"
        );

        // W10 gave `ouro wasm` five subcommands that *do* start a helper, locally and by
        // design. `doctor` did not inherit a way to: it still takes the three remote flags and
        // takes neither `--helper` nor anything else that names a binary to run.
        assert!(
            Cli::try_parse_from(["ouro", "wasm", "doctor", "--helper", "/bin/true"]).is_err(),
            "the readiness surface must not be able to name a helper, let alone start one"
        );
    }

    /// W10. The five local subcommands take `--helper` and nothing that reads the working
    /// directory: the helper is the containment boundary, so the set of paths that may supply
    /// it is what was typed, an absolute environment override, and this binary's own sibling.
    #[test]
    fn the_local_wasm_commands_name_a_helper_and_never_a_directory_to_search() {
        let Some(Command::Wasm {
            command: WasmCommand::Inspect(args),
        }) = parse(&[
            "wasm",
            "inspect",
            "guest.wasm",
            "--helper",
            "/opt/ouro-wasm",
        ])
        .command
        else {
            panic!("`ouro wasm inspect` must parse");
        };
        assert_eq!(args.file, PathBuf::from("guest.wasm"));
        assert_eq!(args.helper.helper, Some(PathBuf::from("/opt/ouro-wasm")));
        assert!(!args.json);

        // There is no flag that says "look for a helper under here": the only way to widen the
        // candidate set is to type a path, and that is one path rather than a directory to walk.
        for rejected in [
            vec!["wasm", "inspect", "g.wasm", "--helper-dir", "/tmp"],
            vec!["wasm", "inspect", "g.wasm", "--search-cwd"],
            vec!["wasm", "run", "g.wasm", "--helper-dir", "/tmp"],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("ouro").chain(rejected.iter().copied()))
                    .is_err(),
                "a way to search for a helper is a way for a clone to supply one: {rejected:?}"
            );
        }
    }

    /// `run` sends every message to one instance, so the messages are a list and there is no
    /// flag that would make them each their own instance.
    #[test]
    fn ouro_wasm_run_takes_repeatable_messages_and_optional_bounds() {
        let Some(Command::Wasm {
            command: WasmCommand::Run(args),
        }) = parse(&[
            "wasm",
            "run",
            "guest.wasm",
            "--config",
            r#"{"a":1}"#,
            "--message",
            r#"{"one":1}"#,
            "--message",
            r#"{"two":2}"#,
            "--deadline-ms",
            "250",
            "--describe",
        ])
        .command
        else {
            panic!("`ouro wasm run` must parse");
        };

        assert_eq!(args.config, r#"{"a":1}"#);
        assert_eq!(args.message, vec![r#"{"one":1}"#, r#"{"two":2}"#]);
        assert_eq!(args.deadline_ms, Some(250));
        assert!(args.describe);
        // Absent bounds are the node's defaults, resolved at dispatch rather than defaulted to
        // a number this file invents.
        assert_eq!(args.fuel, None);
        assert_eq!(args.memory_bytes, None);
    }

    /// `hook` defaults to the **untrusted** lane, because that is the lane a cloned repository
    /// gets and the one whose narrowing an author needs to see. `--trusted` is the opt-in, and
    /// there is deliberately no `--untrusted` to be the default nobody typed.
    #[test]
    fn ouro_wasm_hook_shows_the_untrusted_lane_unless_told_otherwise() {
        let Some(Command::Wasm {
            command: WasmCommand::Hook(args),
        }) = parse(&["wasm", "hook", "vet.wasm", "--event", "PreToolUse"]).command
        else {
            panic!("`ouro wasm hook` must parse");
        };

        assert!(!args.trusted, "the default lane is the strict one");
        assert_eq!(args.event, "PreToolUse");
        assert_eq!(args.payload, None);
        assert_eq!(args.config, "{}");
        assert_eq!(args.timeout_ms, None);

        // A hook declares one bound for itself and fuel and memory are the operator's, so there
        // is no flag here that would let a hook ask for either.
        for rejected in [
            vec!["wasm", "hook", "v.wasm", "--event", "Stop", "--fuel", "1"],
            vec![
                "wasm",
                "hook",
                "v.wasm",
                "--event",
                "Stop",
                "--memory-bytes",
                "1",
            ],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("ouro").chain(rejected.iter().copied()))
                    .is_err(),
                "a hook does not choose fuel or memory on a node either: {rejected:?}"
            );
        }

        // The event is not optional: there is no default event, because every event narrows
        // differently and guessing one would print the wrong narrowing convincingly.
        assert!(Cli::try_parse_from(["ouro", "wasm", "hook", "v.wasm"]).is_err());
    }

    #[test]
    fn ouro_wasm_check_and_new_take_their_one_argument_each() {
        let Some(Command::Wasm {
            command: WasmCommand::Check(args),
        }) = parse(&["wasm", "check", "--workspace", "/repo"]).command
        else {
            panic!("`ouro wasm check` must parse");
        };
        assert_eq!(args.workspace, Some(PathBuf::from("/repo")));

        let Some(Command::Wasm {
            command: WasmCommand::New(args),
        }) = parse(&["wasm", "new", "my-guard", "--hook"]).command
        else {
            panic!("`ouro wasm new` must parse");
        };
        assert_eq!(args.name, "my-guard");
        assert!(args.hook);
        assert_eq!(args.into, None);
    }

    /// W12. Signing takes the two facts a policy requires and nothing a policy decides.
    #[test]
    fn ouro_wasm_sign_names_what_is_signed_and_never_the_durable_id() {
        let Some(Command::Wasm {
            command: WasmCommand::Sign(args),
        }) = parse(&[
            "wasm",
            "sign",
            "greeter.wasm",
            "--name",
            "greeter",
            "--author",
            "ops",
            "--import",
            "log",
            "--start-config",
            r#"{"greeting":"hi"}"#,
            "--eval",
            "spec.json",
            "--out",
            "greeter.ouro-wasm",
        ])
        .command
        else {
            panic!("`ouro wasm sign` must parse");
        };

        assert_eq!(args.component, PathBuf::from("greeter.wasm"));
        assert_eq!(args.name, "greeter");
        assert_eq!(args.author, "ops");
        assert_eq!(args.start_config.as_deref(), Some(r#"{"greeting":"hi"}"#));
        assert_eq!(args.eval, Some(PathBuf::from("spec.json")));
        assert_eq!(args.out, Some(PathBuf::from("greeter.ouro-wasm")));
        // Imports are declared by the operator, one flag per import, and never inferred by
        // the node from bytes nobody signed.
        assert_eq!(args.import, vec!["log".to_string()]);
        assert_eq!(args.imports_from, None);

        // The durable wrapper's id is derived from the name by the runtime and by the
        // signing policy alike. A flag for it would be a way to sign a manifest claiming a
        // capability it does not describe.
        assert!(
            Cli::try_parse_from(["ouro", "wasm", "sign", "g.wasm", "--start-id", "wasm/other"])
                .is_err(),
            "a start id a caller may name is a start id a caller may lie about"
        );

        // And the two facts the policy requires are not optional.
        assert!(Cli::try_parse_from(["ouro", "wasm", "sign", "g.wasm"]).is_err());
        assert!(
            Cli::try_parse_from(["ouro", "wasm", "sign", "g.wasm", "--name", "greeter"]).is_err()
        );

        // There is no `--epoch`. A number a client chose could be placed at the rollout
        // register's plausibility ceiling, which leaves no epoch that is both fresh and
        // plausible: one call, and lane W on that node is wedged durably. The node
        // allocates it over the connected cluster instead.
        assert!(
            Cli::try_parse_from(["ouro", "wasm", "sign", "g.wasm", "--epoch", "7"]).is_err(),
            "an epoch a client may name is an epoch a client may wedge a register with"
        );

        // `--import` repeats, and `--imports-from` is the piped form of the same thing.
        // They are mutually exclusive, because two sources for one signed field is two
        // answers to what was signed.
        let Some(Command::Wasm {
            command: WasmCommand::Sign(repeated),
        }) = parse(&[
            "wasm", "sign", "g.wasm", "--name", "g", "--author", "o", "--import", "log",
            "--import", "clock",
        ])
        .command
        else {
            panic!("repeated --import must parse");
        };

        assert_eq!(
            repeated.import,
            vec!["log".to_string(), "clock".to_string()]
        );

        assert!(Cli::try_parse_from([
            "ouro",
            "wasm",
            "sign",
            "g.wasm",
            "--name",
            "g",
            "--author",
            "o",
            "--import",
            "log",
            "--imports-from",
            "-",
        ])
        .is_err());
    }

    /// W12. Deploy takes a file and the machines to put it on, and nothing that would let a
    /// client tell a node which signers to trust.
    #[test]
    fn ouro_wasm_deploy_names_a_bundle_and_its_targets_and_no_trust() {
        let Some(Command::Wasm {
            command: WasmCommand::Deploy(args),
        }) = parse(&["wasm", "deploy", "greeter.ouro-wasm", "--nodes", "a@h,b@h"]).command
        else {
            panic!("`ouro wasm deploy` must parse");
        };

        assert_eq!(args.bundle, PathBuf::from("greeter.ouro-wasm"));
        assert_eq!(args.nodes.as_deref(), Some("a@h,b@h"));
        assert_eq!(args.node, None);

        // A loading node reads its own trust policy. A flag that named one would make this
        // client the authority over what that node will run.
        for flag in ["--trusted-signers", "--allow-unsigned", "--signer"] {
            assert!(
                Cli::try_parse_from(["ouro", "wasm", "deploy", "b.ouro-wasm", flag, "x"]).is_err(),
                "{flag} would move a trust decision to the client"
            );
        }
    }

    /// W12. Rollback names one capability. There is no `--force` and no `--purge`: the
    /// bytes are durable by design (D6), and stopping a wrapper is the whole verb.
    #[test]
    fn ouro_wasm_rollback_names_one_capability_and_nothing_destructive() {
        let Some(Command::Wasm {
            command: WasmCommand::Rollback(args),
        }) = parse(&["wasm", "rollback", "greeter", "--json"]).command
        else {
            panic!("`ouro wasm rollback` must parse");
        };

        assert_eq!(args.name, "greeter");
        assert!(args.json);

        for flag in ["--force", "--purge", "--delete-bytes"] {
            assert!(
                Cli::try_parse_from(["ouro", "wasm", "rollback", "greeter", flag]).is_err(),
                "{flag} would make rollback something other than stop-and-mark"
            );
        }
    }

    /// W12. Keygen contacts nothing, so it takes no endpoint flags at all — the key is set
    /// up on the operator's machine and must never travel.
    #[test]
    fn ouro_wasm_keygen_writes_a_key_and_talks_to_no_runtime() {
        let Some(Command::Wasm {
            command: WasmCommand::Keygen(args),
        }) = parse(&[
            "wasm",
            "keygen",
            "--out",
            "release.key",
            "--id",
            "release-key",
        ])
        .command
        else {
            panic!("`ouro wasm keygen` must parse");
        };

        assert_eq!(args.out, Some(PathBuf::from("release.key")));
        assert_eq!(args.id, "release-key");

        for flag in ["--addr", "--token-file"] {
            assert!(
                Cli::try_parse_from(["ouro", "wasm", "keygen", flag, "x"]).is_err(),
                "{flag} on keygen would imply a key that travels"
            );
        }

        // The default writes beside the operator rather than into a runtime's data
        // directory, which is a place a key does not belong.
        let Some(Command::Wasm {
            command: WasmCommand::Keygen(bare),
        }) = parse(&["wasm", "keygen"]).command
        else {
            panic!("`ouro wasm keygen` must parse with no flags");
        };

        assert_eq!(bare.out, None);
        assert_eq!(bare.id, "release-key");
    }

    /// W12. `ls` is the listing surface, and it takes the same three flags every remote
    /// operator surface takes.
    #[test]
    fn ouro_wasm_ls_renders_a_listing_and_takes_no_filters() {
        let Some(Command::Wasm {
            command: WasmCommand::Ls(args),
        }) = parse(&["wasm", "ls", "--json"]).command
        else {
            panic!("`ouro wasm ls` must parse");
        };

        assert!(args.json);
        assert_eq!(args.addr, None);

        // The runtime bounds and sorts both lists itself; a filter here would be a second,
        // laxer definition of what a node holds.
        assert!(Cli::try_parse_from(["ouro", "wasm", "ls", "--state", "live"]).is_err());
    }

    #[test]
    fn ouro_run_takes_a_prompt_and_defaults_the_rest() {
        let Some(Command::Run(args)) = parse(&["run", "fix the tests"]).command else {
            panic!("`ouro run \"fix the tests\"` must parse as Run");
        };

        assert_eq!(args.prompt, "fix the tests");
        assert_eq!(args.resume, None);
        // The one number with a default, because a headless run that never ends is the
        // failure this command exists to prevent.
        assert_eq!(args.timeout, 600);
        assert!(!args.json && !args.stream_json && !args.approve_all && !args.verbose);
    }

    #[test]
    fn the_two_json_surfaces_are_mutually_exclusive() {
        assert!(
            Cli::try_parse_from(["ouro", "run", "hi", "--json", "--stream-json"]).is_err(),
            "stdout is one contract, not two"
        );
    }

    /// A resumed session's provider and workspace were chosen when it started. Accepting
    /// them again would look like they applied.
    #[test]
    fn resume_refuses_the_start_options_rather_than_ignoring_them() {
        for flag in [
            vec!["--provider", "native"],
            vec!["--model", "openai:gpt-5.6"],
            vec!["--workspace", "/srv/work"],
            vec!["--approval-mode", "auto_edit"],
            vec!["--sandbox-mode", "read_only"],
            vec!["--machine", "beta"],
        ] {
            let args = ["ouro", "run", "hi", "--resume", "s-1"];
            assert!(
                Cli::try_parse_from(args.iter().copied().chain(flag.iter().copied())).is_err(),
                "--resume {flag:?} must be refused, not quietly dropped"
            );
        }
    }

    /// One names a session, the other looks one up. A command that took both would have to
    /// ignore one of them, and the same refusal `--resume` already makes for the start
    /// options is the honest answer here (F2).
    #[test]
    fn continue_and_resume_are_refused_together_rather_than_one_winning() {
        assert!(
            Cli::try_parse_from(["ouro", "run", "hi", "--continue", "--resume", "s-1"]).is_err(),
            "--continue with --resume must be refused, not quietly resolved to one of them"
        );
    }

    /// `--or-new` only means something with `--continue`, so typing it alone is a mistake
    /// worth naming rather than a no-op.
    #[test]
    fn or_new_without_continue_is_refused_on_both_surfaces() {
        assert!(Cli::try_parse_from(["ouro", "--or-new"]).is_err());
        assert!(Cli::try_parse_from(["ouro", "run", "hi", "--or-new"]).is_err());
        assert!(
            Cli::try_parse_from(["ouro", "--workspace", "/srv/work"]).is_err(),
            "a bare `ouro` has no workspace to take; it is `--continue`'s parameter"
        );
    }

    #[test]
    fn continue_parses_on_both_surfaces_and_defaults_to_this_directory() {
        let cli = parse(&["--continue"]);
        assert!(cli.continue_session && !cli.or_new);
        assert_eq!(cli.workspace, None);
        assert!(cli.command.is_none());

        let cli = parse(&["--continue", "--or-new", "--workspace", "/srv/work"]);
        assert!(cli.continue_session && cli.or_new);
        assert_eq!(cli.workspace, Some(PathBuf::from("/srv/work")));

        let Some(Command::Run(args)) = parse(&["run", "carry on", "--continue"]).command else {
            panic!("`ouro run --continue` must parse as Run");
        };
        assert!(args.continue_session && !args.or_new);
        assert_eq!(args.resume, None);
        assert_eq!(args.workspace, None);

        let Some(Command::Run(args)) = parse(&[
            "run",
            "carry on",
            "--continue",
            "--or-new",
            "--workspace",
            "/srv/work",
        ])
        .command
        else {
            panic!("`ouro run --continue --or-new` must parse as Run");
        };
        assert!(args.continue_session && args.or_new);
        assert_eq!(args.workspace, Some(PathBuf::from("/srv/work")));
    }

    #[test]
    fn ouro_run_carries_every_surface_it_was_typed_with() {
        let Some(Command::Run(args)) = parse(&[
            "run",
            "fix the tests",
            "--provider",
            "codex",
            "--workspace",
            "/srv/work",
            "--approval-mode",
            "auto_edit",
            "--sandbox-mode",
            "workspace_write",
            "--machine",
            "beta",
            "--stream-json",
            "--approve-all",
            "--timeout",
            "30",
            "--verbose",
            "--addr",
            "127.0.0.1:4560",
            "--token-file",
            "/tmp/token",
        ])
        .command
        else {
            panic!("a fully-specified `ouro run` must parse");
        };

        assert_eq!(args.provider.as_deref(), Some("codex"));
        assert_eq!(args.workspace, Some(PathBuf::from("/srv/work")));
        assert_eq!(args.approval_mode.as_deref(), Some("auto_edit"));
        assert_eq!(args.sandbox_mode.as_deref(), Some("workspace_write"));
        assert_eq!(args.machine.as_deref(), Some("beta"));
        assert!(args.stream_json && args.approve_all && args.verbose);
        assert_eq!(args.timeout, 30);
        assert_eq!(args.addr.as_deref(), Some("127.0.0.1:4560"));
        assert_eq!(args.token_file, Some(PathBuf::from("/tmp/token")));
    }

    #[test]
    fn fleet_commands_keep_networking_details_optional() {
        let Some(Command::Fleet {
            command:
                FleetCommand::Create {
                    name,
                    machine,
                    host,
                    gateway_port,
                    dist_port,
                },
        }) = parse(&[
            "fleet",
            "create",
            "--machine",
            "studio-mini",
            "--host",
            "studio.tailnet.ts.net",
        ])
        .command
        else {
            panic!("fleet create must parse");
        };
        assert_eq!(machine.as_deref(), Some("studio-mini"));
        assert_eq!(host.as_deref(), Some("studio.tailnet.ts.net"));
        assert_eq!(name, None);
        assert_eq!(gateway_port, None);
        assert_eq!(dist_port, None);

        let Some(Command::Fleet {
            command:
                FleetCommand::Join {
                    invitation,
                    gateway_port,
                    dist_port,
                },
        }) = parse(&[
            "fleet",
            "join",
            "worker.ouro",
            "--gateway-port",
            "48101",
            "--dist-port",
            "44101",
        ])
        .command
        else {
            panic!("fleet join must parse");
        };
        assert_eq!(invitation, PathBuf::from("worker.ouro"));
        assert_eq!(gateway_port, Some(48_101));
        assert_eq!(dist_port, Some(44_101));

        let Some(Command::Fleet {
            command:
                FleetCommand::Invite {
                    replace,
                    machine,
                    host,
                    ..
                },
        }) = parse(&[
            "fleet",
            "invite",
            "--machine",
            "worker",
            "--host",
            "worker.tailnet.ts.net",
            "--out",
            "worker.ouro",
            "--replace",
        ])
        .command
        else {
            panic!("fleet invite --replace must parse");
        };
        assert!(replace);
        assert_eq!(machine.as_deref(), Some("worker"));
        assert_eq!(host.as_deref(), Some("worker.tailnet.ts.net"));
        assert!(matches!(
            parse(&[
                "fleet",
                "invite",
                "cancel",
                "--machine",
                "worker",
                "--out",
                "roster.ouro-roster"
            ])
            .command,
            Some(Command::Fleet {
                command: FleetCommand::Invite {
                    command: Some(InviteCommand::Cancel { machine, out }),
                    ..
                }
            }) if machine == "worker" && out == std::path::Path::new("roster.ouro-roster")
        ));
        assert!(
            Cli::try_parse_from(["ouro", "fleet", "invite", "cancel", "--machine", "worker"])
                .is_err()
        );
        assert!(matches!(
            parse(&[
                "fleet",
                "sync",
                "import",
                "roster.ouro-roster"
            ])
            .command,
            Some(Command::Fleet {
                command: FleetCommand::Sync {
                    command: SyncCommand::Import { roster }
                }
            }) if roster == std::path::Path::new("roster.ouro-roster")
        ));
        assert!(matches!(
            parse(&[
                "fleet",
                "sessions",
                "forget",
                "--machine",
                "retired-vps",
                "--accept-state-loss"
            ])
            .command,
            Some(Command::Fleet {
                command: FleetCommand::Sessions {
                    command: SessionsCommand::Forget {
                        machine,
                        accept_state_loss: true
                    }
                }
            }) if machine == "retired-vps"
        ));
        assert!(
            Cli::try_parse_from([
                "ouro",
                "fleet",
                "sessions",
                "forget",
                "--machine",
                "retired-vps"
            ])
            .is_err(),
            "irreversible local evidence loss must require an explicit acknowledgement"
        );

        let Some(Command::Fleet {
            command:
                FleetCommand::Leave {
                    discard_incomplete,
                    machine,
                },
        }) = parse(&[
            "fleet",
            "leave",
            "--discard-incomplete",
            "--machine",
            "worker",
        ])
        .command
        else {
            panic!("explicit incomplete cleanup must parse");
        };
        assert!(discard_incomplete);
        assert_eq!(machine.as_deref(), Some("worker"));
        assert!(Cli::try_parse_from(["ouro", "fleet", "leave", "--machine", "worker"]).is_err());

        assert!(matches!(
            parse(&["fleet", "service", "install"]).command,
            Some(Command::Fleet {
                command: FleetCommand::Service {
                    command: ServiceCommand::Install
                }
            })
        ));
        assert!(matches!(
            parse(&["service-run"]).command,
            Some(Command::ServiceRun)
        ));

        let Some(Command::Fleet {
            command:
                FleetCommand::Add {
                    target,
                    machine,
                    host,
                    via,
                    print_script,
                    init,
                    ..
                },
        }) = parse(&[
            "fleet",
            "add",
            "op@vps",
            "--machine",
            "vps",
            "--host",
            "vps.tailnet.ts.net",
            "--via",
            "tailscale",
            "--init",
        ])
        .command
        else {
            panic!("fleet add must parse");
        };
        assert_eq!(target.as_deref(), Some("op@vps"));
        assert_eq!(machine.as_deref(), Some("vps"));
        assert_eq!(host.as_deref(), Some("vps.tailnet.ts.net"));
        assert_eq!(via, "tailscale");
        assert!(init);
        assert!(!print_script);

        // Guided Tailscale enrollment is opt-in and off unless the operator names it.
        let Some(Command::Fleet {
            command: FleetCommand::Add {
                setup_tailscale, ..
            },
        }) = parse(&["fleet", "add", "op@vps"]).command
        else {
            panic!("fleet add must parse without options");
        };
        assert!(!setup_tailscale);
        let Some(Command::Fleet {
            command:
                FleetCommand::Add {
                    setup_tailscale,
                    host,
                    ..
                },
        }) = parse(&["fleet", "add", "op@vps", "--setup-tailscale"]).command
        else {
            panic!("fleet add --setup-tailscale must parse");
        };
        assert!(setup_tailscale);
        assert!(host.is_none());
        assert!(matches!(
            parse(&["fleet", "list"]).command,
            Some(Command::Fleet {
                command: FleetCommand::List
            })
        ));
        assert!(matches!(
            parse(&["fleet", "enroll", "vps.ouro", "--delete", "--service"]).command,
            Some(Command::Fleet {
                command: FleetCommand::Enroll {
                    delete: true,
                    service: true,
                    ..
                }
            })
        ));
    }
}
