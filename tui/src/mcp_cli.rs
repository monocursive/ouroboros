//! D4. `ouro mcp list | add | remove` — the MCP servers this runtime runs for the native
//! agent, and the files that declare them.
//!
//! ## Two halves that meet only in a file
//!
//! `list` is a **read of the runtime**: `mcp.list` over the gateway, the same answer
//! `/mcp` draws, printed as a table or as `--json`. Like `ouro agents` it starts nothing —
//! a command whose whole job is to say what is running must not answer by creating
//! something.
//!
//! `add` and `remove` never touch the socket. **There is no `mcp.add` on the wire, by
//! design**: a server definition is a command line that runs on somebody's machine, and
//! `docs/TUI.md` states plainly that one is never authored over a socket. So these two
//! edit the same JSON file the runtime's loader reads, in the same shape Claude Code
//! already uses, and the runtime picks the change up on its own terms.
//!
//! ## The file
//!
//! ```json
//! {"mcpServers": {"fake": {"command": "./bin/fake", "args": ["--stdio"],
//!                          "env": {"TOKEN": "…"}}}}
//! ```
//!
//! Two scopes, matching `Ouroboros.Provider.Native.Mcp.Servers`:
//!
//! * **user** — `~/.config/ouroboros/mcp.json`
//! * **workspace** — `<workspace>/.ouroboros/mcp.json`, which the runtime reads only for a
//!   workspace an operator has *trusted*, because a repository that ships its own
//!   `mcp.json` is a repository that runs commands on every machine that clones it. This
//!   command writes the file either way and says so: refusing to write it would not make
//!   the workspace trusted, and the operator is the one who decides that.
//!
//! There is a third, node scope, and it is deliberately not writable here: it is the
//! operator's `config :ouroboros, :mcp_servers`, which lives in the runtime's own
//! configuration and wins over both files.
//!
//! ## What this command will not do
//!
//! * **It never prints an environment value back.** `add` takes `--env K=V` and writes it;
//!   every line it prints afterwards says how many variables an entry carries and never
//!   which or what. The runtime holds the same rule (`env_count` on the wire, never `env`),
//!   and a CLI that echoed the token it had just been handed would undo it at the last
//!   step.
//! * **It never silently replaces a definition.** A name already present with different
//!   bytes is refused, and `--force` is the way to say it on purpose.
//! * **It does not pretend a `url` entry will work.** The entry is written — it is a valid
//!   Claude Code definition and this build is not the only reader of the file — and the
//!   command says the runtime will refuse it as `unsupported_transport`, because this
//!   slice implements stdio only.
//! * **It resolves nothing over the network**, and the only filesystem question it asks is
//!   whether the command exists (a warning, never a refusal — the file may be written on
//!   one machine for a session that runs on another).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::{Map, Value};

use crate::model::{McpList, McpServer};

/// The file both scopes are spelled in, and the one key it holds.
const DOCUMENT_KEY: &str = "mcpServers";

/// `~/.config/ouroboros/mcp.json`'s two leaves.
const CONFIG_DIR: &str = "ouroboros";
const USER_FILE: &str = "mcp.json";

/// `<workspace>/.ouroboros/mcp.json`'s two.
const WORKSPACE_DIR: &str = ".ouroboros";

/// `Ouroboros.Provider.Native.Mcp.Servers`' own name rule, transcribed rather than
/// approximated: `[A-Za-z0-9_-]{1,64}`, and no `__` anywhere in it.
///
/// The `__` rule is not cosmetic. A tool reaches the model as `mcp__<server>__<tool>`,
/// split on the first `__`; a server name containing one would make that split ambiguous,
/// so the loader refuses it as `invalid_name`. Checked here so the refusal arrives at the
/// person typing it rather than three commands later in a status listing.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains("__")
        && name
            .chars()
            .all(|found| found.is_ascii_alphanumeric() || found == '_' || found == '-')
}

/// Which of the two files an operation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Workspace,
}

impl Scope {
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "user" => Some(Self::User),
            "workspace" => Some(Self::Workspace),
            _unknown => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Workspace => "workspace",
        }
    }
}

/// Where a scope's file lives.
///
/// The user file follows `XDG_CONFIG_HOME` exactly as [`crate::config::path`] does, so a
/// caller who set that variable gets the directory they named. **The runtime resolves the
/// same file from `System.user_home()` and does not read `XDG_CONFIG_HOME`**, so the two
/// agree whenever the variable is unset or points at `$HOME/.config` — and [`add`] says so
/// out loud when they do not, rather than writing a file nothing will read.
pub fn path(scope: Scope, workspace: Option<&Path>) -> Result<PathBuf> {
    match scope {
        Scope::User => Ok(crate::runtime::xdg_root("XDG_CONFIG_HOME", ".config")?
            .join(CONFIG_DIR)
            .join(USER_FILE)),
        Scope::Workspace => {
            let root = workspace.ok_or_else(|| {
                anyhow!(
                    "--scope workspace needs a workspace; pass --workspace <PATH> or run \
                     this from inside one"
                )
            })?;

            Ok(root.join(WORKSPACE_DIR).join(USER_FILE))
        }
    }
}

/// Where the *runtime* will look for the user file, which is not always where [`path`]
/// puts it. `None` when this process cannot tell.
fn runtime_user_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join(CONFIG_DIR).join(USER_FILE))
}

/// One `add`, fully stated.
#[derive(Debug, Clone, Default)]
pub struct Definition {
    pub name: String,
    /// The program to run. Exactly one of this and [`Self::url`] is required.
    pub command: Option<String>,
    /// An HTTP/SSE endpoint. Accepted into the file and refused by this runtime.
    pub url: Option<String>,
    pub args: Vec<String>,
    /// `K=V` pairs, unparsed. Values are written and never echoed.
    pub env: Vec<String>,
    pub cwd: Option<String>,
}

impl Definition {
    /// The JSON object one entry becomes, or the reason it is not one.
    fn entry(&self) -> Result<Value> {
        let mut entry = Map::new();

        match (self.command.as_deref(), self.url.as_deref()) {
            (Some(command), None) => {
                let command = command.trim();

                if command.is_empty() {
                    return Err(anyhow!("--command cannot be empty"));
                }

                entry.insert("command".into(), Value::String(command.to_string()));
            }
            (None, Some(url)) => {
                let url = url.trim();

                if url.is_empty() {
                    return Err(anyhow!("--url cannot be empty"));
                }

                entry.insert("url".into(), Value::String(url.to_string()));
            }
            (Some(_), Some(_)) => {
                return Err(anyhow!(
                    "--command and --url are two different transports; name one"
                ))
            }
            (None, None) => return Err(anyhow!("an MCP server needs --command (or --url)")),
        }

        if !self.args.is_empty() {
            entry.insert(
                "args".into(),
                Value::Array(
                    self.args
                        .iter()
                        .map(|arg| Value::String(arg.clone()))
                        .collect(),
                ),
            );
        }

        if !self.env.is_empty() {
            let mut env = Map::new();

            for pair in &self.env {
                // Split on the *first* `=` only: a value may contain them, and a key may
                // not.
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| anyhow!("--env takes KEY=VALUE; {pair:?} has no `=`"))?;

                let key = key.trim();

                if key.is_empty() {
                    return Err(anyhow!("--env needs a name before the `=`"));
                }

                // The value is not echoed here or anywhere: the error names the key.
                env.insert(key.to_string(), Value::String(value.to_string()));
            }

            entry.insert("env".into(), Value::Object(env));
        }

        if let Some(cwd) = self.cwd.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            entry.insert("cwd".into(), Value::String(cwd.to_string()));
        }

        Ok(Value::Object(entry))
    }

    /// How many environment variables this entry carries. The only thing about them that
    /// is ever printed.
    fn env_count(&self) -> usize {
        self.env.len()
    }
}

/// Reads the document at `path`, or an empty one where there is no file yet.
///
/// A file that exists and is not a JSON object is an error rather than something to
/// overwrite: an operator's `mcp.json` with a typo in it is a file they want to hear about,
/// not one this command should silently replace.
fn read_document(path: &Path) -> Result<Map<String, Value>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };

    if text.trim().is_empty() {
        return Ok(Map::new());
    }

    let document: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;

    match document {
        Value::Object(document) => Ok(document),
        _other => Err(anyhow!(
            "{} does not hold a JSON object; refusing to replace it",
            path.display()
        )),
    }
}

/// Writes the document, creating the directory 0700 and the file 0600.
///
/// Through a temporary file and a rename, like every other file this client owns: a crash
/// midway must not leave an operator with half an `mcp.json` and a runtime that refuses
/// the whole thing.
fn write_document(path: &Path, document: &Map<String, Value>) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;

    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    // Pretty, with a trailing newline: this file is read and edited by people, and a
    // one-line blob is one an operator cannot diff.
    let mut body = serde_json::to_string_pretty(&Value::Object(document.clone()))
        .context("encoding mcp.json")?;
    body.push('\n');

    let temp = parent.join(format!(".mcp.json.{}.tmp", std::process::id()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("writing {}", temp.display()))?;

    let written = file
        .write_all(body.as_bytes())
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());

    if let Err(error) = written {
        let _ = fs::remove_file(&temp);
        return Err(anyhow::Error::from(error).context(format!("writing {}", temp.display())));
    }

    drop(file);

    fs::rename(&temp, path).with_context(|| format!("publishing {}", path.display()))?;

    // A pre-existing file may have been created by something else with a wider mode; the
    // rename keeps the temporary file's, but say it plainly rather than relying on that.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;

    Ok(())
}

/// The servers a document declares, by name.
fn servers_of(document: &Map<String, Value>) -> Map<String, Value> {
    document
        .get(DOCUMENT_KEY)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// `ouro mcp add`.
///
/// `check` asks whether the command resolves — on `PATH`, or as an existing file — and
/// **warns** rather than refusing. The file may legitimately be written on one machine for
/// a session that runs on another, and a command that is installed later is not a mistake
/// now.
pub fn add<W: std::io::Write>(
    path: &Path,
    scope: Scope,
    definition: &Definition,
    force: bool,
    check: bool,
    out: &mut W,
) -> Result<()> {
    if !valid_name(&definition.name) {
        return Err(anyhow!(
            "{:?} is not a usable server name: this runtime accepts 1-64 characters of \
             [A-Za-z0-9_-] and no `__`, because a tool reaches the model as \
             mcp__<server>__<tool> and is split on the first `__`",
            definition.name
        ));
    }

    let entry = definition.entry()?;

    let mut document = read_document(path)?;
    let mut servers = servers_of(&document);

    if let Some(existing) = servers.get(&definition.name) {
        if existing == &entry {
            writeln!(
                out,
                "{} already declares {} exactly like this; nothing to do",
                path.display(),
                definition.name
            )?;
            return Ok(());
        }

        if !force {
            return Err(anyhow!(
                "{} already declares {} differently; pass --force to replace it, or \
                 `ouro mcp remove {} --scope {}` first",
                path.display(),
                definition.name,
                definition.name,
                scope.as_str()
            ));
        }
    }

    servers.insert(definition.name.clone(), entry);
    document.insert(DOCUMENT_KEY.into(), Value::Object(servers));

    write_document(path, &document)?;

    writeln!(
        out,
        "wrote {} to {} ({} scope)",
        definition.name,
        path.display(),
        scope.as_str()
    )?;

    // Every line below is a caveat about what the runtime will do with what was just
    // written. The value of an env var is never among them.
    if definition.env_count() > 0 {
        writeln!(
            out,
            "  {} environment variable(s) recorded; their values are never printed back",
            definition.env_count()
        )?;
    }

    if definition.url.is_some() {
        writeln!(
            out,
            "  this entry names a url: the file is valid, and this runtime speaks stdio \
             only, so it will refuse the entry as `unsupported_transport` and say so in \
             `ouro mcp list`"
        )?;
    }

    if scope == Scope::Workspace {
        writeln!(
            out,
            "  a workspace mcp.json is read only for a workspace this runtime trusts; \
             until then `ouro mcp list` reports it declined"
        )?;
    }

    if scope == Scope::User {
        if let Some(expected) = runtime_user_path() {
            if expected != path {
                writeln!(
                    out,
                    "  note: this runtime reads the user file from {}, not from here — \
                     XDG_CONFIG_HOME moved this command's path but not the runtime's",
                    expected.display()
                )?;
            }
        }
    }

    if check {
        if let Some(command) = definition.command.as_deref() {
            if !resolves(command) {
                writeln!(
                    out,
                    "  warning: {command} was not found on PATH and is not an existing \
                     file; the entry is written, and the runtime will report it broken \
                     unless it exists where the session runs"
                )?;
            }
        }
    }

    Ok(())
}

/// `ouro mcp remove`.
pub fn remove<W: std::io::Write>(path: &Path, name: &str, out: &mut W) -> Result<()> {
    let mut document = read_document(path)?;
    let mut servers = servers_of(&document);

    if servers.remove(name).is_none() {
        writeln!(out, "{} declares no server named {name}", path.display())?;
        return Ok(());
    }

    // An empty map is left as an empty map rather than the key being dropped: the file
    // then says "this scope declares nothing", which is a different statement from a file
    // that was never written.
    document.insert(DOCUMENT_KEY.into(), Value::Object(servers));

    write_document(path, &document)?;

    writeln!(out, "removed {name} from {}", path.display())?;

    Ok(())
}

/// Whether a command would be found: an existing path, or a name on `PATH`.
///
/// No execution, no network, and no `which` subprocess — reading `PATH` is the whole of it.
fn resolves(command: &str) -> bool {
    let candidate = Path::new(command);

    if candidate.is_absolute() || command.contains('/') {
        return candidate.is_file();
    }

    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|directory| directory.join(command).is_file())
        })
        .unwrap_or(false)
}

/// `mcp.list`'s params: the node to ask, and the workspace to ask about.
///
/// Both optional, and both meaningful. Without `workspace` the answer is only the servers
/// already *running* — the configured-but-never-started entries and every refusal are
/// missing, and those refusals are the only way to tell "my mcp.json was ignored" from
/// "my mcp.json was read and found wanting".
pub fn list_params(node: Option<&str>, workspace: Option<&Path>) -> Value {
    let mut params = Map::new();

    if let Some(node) = node.map(str::trim).filter(|node| !node.is_empty()) {
        params.insert("node".into(), Value::String(node.to_string()));
    }

    if let Some(workspace) = workspace {
        params.insert(
            "workspace".into(),
            Value::String(workspace.display().to_string()),
        );
    }

    Value::Object(params)
}

/// The plain page: one block per server, then the refusals.
pub fn render(list: &McpList) -> String {
    let mut page = String::new();

    if !list.enabled {
        page.push_str("MCP is off on this node\n");
    }

    if let Some(node) = &list.node {
        page.push_str(&format!("node {node}\n"));
    }

    if let Some(version) = &list.protocol_version {
        page.push_str(&format!("protocol {version}\n"));
    }

    if !list.transports.is_empty() {
        page.push_str(&format!("transports {}\n", list.transports.join(", ")));
    }

    page.push('\n');

    if list.servers.is_empty() {
        page.push_str("no MCP servers are running or configured\n");
    } else {
        for server in &list.servers {
            page.push_str(&server_block(server));
        }
    }

    if !list.refusals.is_empty() {
        page.push_str(&format!("\nREFUSED  {}\n", list.refusals.len()));

        for refusal in &list.refusals {
            page.push_str(&format!(
                "  {}  {}\n",
                refusal.name.as_deref().unwrap_or("(unnamed entry)"),
                refusal.reason.as_deref().unwrap_or("refused")
            ));

            if let Some(detail) = &refusal.detail {
                page.push_str(&format!("    {detail}\n"));
            }
        }
    }

    page
}

fn server_block(server: &McpServer) -> String {
    let state = server.state.as_deref().unwrap_or("unknown");
    let mut facts = vec![state.to_string()];

    if let Some(scope) = &server.scope {
        facts.push(scope.clone());
    }

    // A tool count means something only once a server has started. `configured` has not,
    // and "0 tools" beside it would read as "it advertises none".
    if state == "ready" {
        facts.push(format!("{} tool(s)", server.tools));
    }

    if server.env_count > 0 {
        facts.push(format!("{} env var(s)", server.env_count));
    }

    if server.restarts > 0 {
        facts.push(format!("{} restart(s)", server.restarts));
    }

    let mut block = format!("{}  {}\n", server.name, facts.join(" · "));

    if let Some(command) = &server.command {
        let argv = if server.args.is_empty() {
            command.clone()
        } else {
            format!("{command} {}", server.args.join(" "))
        };

        block.push_str(&format!("  {argv}\n"));
    }

    if let Some(source) = &server.source {
        block.push_str(&format!("  from {source}\n"));
    }

    if let Some(reason) = &server.broken_reason {
        block.push_str(&format!("  broken: {reason}\n"));
    }

    if !server.tool_names.is_empty() {
        block.push_str(&format!("  tools: {}\n", server.tool_names.join(" ")));
    }

    block
}

/// `--json`: the runtime's own answer, unchanged.
///
/// Not a projection. A second schema kept in step by hand is a second schema that is wrong
/// within a release, and everything a caller needs is already in the bytes the gateway
/// sent — the same argument `ouro agents --json` makes for carrying `session` verbatim.
pub fn render_json(answer: &Value) -> String {
    serde_json::to_string(answer).unwrap_or_else(|_| "{}".to_string())
}

/// The `mcpServers` a file declares, for `ouro mcp list` to say what is on disk that the
/// runtime has not picked up. Names only — never an entry's `env`.
pub fn declared(path: &Path) -> Result<BTreeMap<String, usize>> {
    let document = read_document(path)?;

    Ok(servers_of(&document)
        .into_iter()
        .map(|(name, entry)| {
            let env = entry
                .get("env")
                .and_then(Value::as_object)
                .map(Map::len)
                .unwrap_or(0);

            (name, env)
        })
        .collect())
}
