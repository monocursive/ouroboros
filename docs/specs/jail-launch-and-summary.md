# Jail proposal: zero-config agent launch and the end-of-run summary

Status: design proposal, 2026-10-16. Nothing here is implemented, scheduled
or claimed. It becomes plan of record only when the operator accepts it and
its open decisions (§7) are settled; until then the
[north star](../../north-star.md), [Jail v1](jail-v1.md) (revision 24) and
[Jail v2](jail-v2.md) govern unchanged. Where this proposal would amend them,
§5 says so row by row. The milestone names
J12 and J13 and the row numbers K33–K52 are provisional, chosen to follow
jail-v2's sequence.

Two features, one aim: make the jail's cost small and its benefit visible.
Today a sandboxed agent needs a long command line and a hand-edited
credential profile, and the evidence the jail produced ends as a single path
on stderr:

```text
ukai-jail run --launch opencode --ro ~/.opencode/bin -- ~/.opencode/bin/opencode run "…"
ukai-jail: receipt /home/u/.local/share/ukai/attempts/att_…/jail.json
```

and Claude Code has no working default at all: the bundled
[`claude`](../../crates/ukai-jail/profiles/launch/claude.toml) profile has its
credential inputs commented out, and the
[`claude-vault`](../../crates/ukai-jail/profiles/launch/claude-vault.toml)
starter needs a copied operator file, a raw API key and a `/bin/sh -c`
wrapper, with "No automatic OAuth refresh". After this proposal (illustrative
output, not a recorded run):

```text
ukai-jail claude -p "fix the failing test in parser.rs"
…the agent's own output…
ukai-jail: settled · exited 0 · 3m41s exec→settled · survivors: none (verified)
ukai-jail: workspace: 4 paths opened for writing, 1 renamed, 1 removed
ukai-jail: network: allowed api.anthropic.com:443 (41) · denied github.com:443 (1)
ukai-jail: credential claude-oauth: vault, never staged · loaded · 0 refusals
ukai-jail: evidence: 6/6 classes active, no gaps · reads and file contents are not observed
ukai-jail: receipt /home/u/.local/share/ukai/attempts/att_…/jail.json
```

Normative words follow jail-v2: **must** is a release gate, **initial** is a
tunable default that must be recorded, **candidate** is unproved until the
named measurement passes. Vendor facts quoted below come from the Claude Code
documentation as read on 2026-10-16; each one the design depends on is
re-checked by the compatibility run (§6.3), because documentation is not a
recorded run.

## 1. Scope

In scope:

- **J12, zero-config launch**: `ukai-jail NAME [ARG]...` and its long form
  `ukai-jail run --launch NAME --from-path [-- ARG...]`, with the workspace
  defaulting to the repository top level, the agent's binary resolved from
  the operator's `PATH` and its install root granted read-only, and a vault
  credential the agent finds under its own variable name.
- **J13, the end-of-run summary**: a few lines on stderr after `run`
  settles, computed only from the final receipt and the attempt journal,
  with `--quiet` to turn it off.

Excluded, each for a stated reason:

- **A support claim for interactive sessions.** Every recorded agent run is
  headless, and the backend detaches the child from the terminal (§3.7).
- **Persistent vendor state.** Vendor state is attempt-private and removed at
  settlement (jail-v1 §12); keeping session history across runs changes that
  invariant and needs its own proposal (§7, decision 7).
- **Reading the operator's existing agent configuration.** jail-v1 §12: "the
  runtime does not discover and mount all files in an agent's home
  directory". The alias stages no file from `~/.claude`, `~/.codex` or
  `~/.local/share/opencode` on its own.
- **The managed gate.** An owner computes its plan from its own inputs
  (jail-v1 §8.2); `--from-path` derives argv and grants, so it refuses with
  `--gate-fd` and `--attempt-id` (exit 2). Owners keep passing explicit argv.
- **macOS**, which refuses execution until J11.

## 2. Invariants kept

| Invariant | Source | How this proposal keeps it |
|---|---|---|
| A project `ukai.toml` can only narrow | jail-v1 §6.3 | No new project-file key. The derived grant and the profile's hosts enter resolution as operator layers, so a project file can still deny-read the install root or shrink `network.allow`; it cannot add a credential, a host or a grant, or select `--from-path`. |
| Nothing widens silently | jail-v1 §6.2 (a widening layer "must never load silently"); north star §4.3 (no widening during an attempt) | Every derived grant is shown by `explain --from-path` (text and JSON), carried in the policy snapshot with provenance origin `program-resolution`, listed in the receipt's `policy.grants`, and printed before exec when stderr is a terminal (§3.3). |
| The binary is outside every writable grant | jail-v2 §3.3 (extended) | The resolved program, its interpreter and their install roots refuse when they lie inside, or contain, any child-writable root (§3.3, step 4). |
| Launch profiles never supply argv | jail-v1 §12; north star §4.5 | Profile data still never names or rewrites a command: `argv[0]` is the name the operator typed, resolved on the operator's `PATH`, and the data only bounds the grant (`program_root`). The north star's stronger wording, that argv is always the operator's `--` arguments, is **amended** for `--from-path` only (§5). |
| No agent names in the execution core | jail-v1 §15 I02 | Every new key is generic. The word `claude` appears only in profile data, documentation and fixtures. |
| The contained `PATH` is fixed | `profiles.rs` (`CONTAINED_PATH`) | The operator's `PATH` is read by the supervisor to resolve one name; it is never handed to the child. |
| Child stdio matches direct execution | jail-v1 §15 X05 | All new output (the pre-exec grant line, the summary) is written only when stderr is a terminal, as the existing receipt line is (`main.rs`). |
| No host configuration | [operating.md](jail-v1/operating.md#install) | Nothing here needs a sysctl, AppArmor profile, capability or service. |
| Support lives in the compatibility record | jail-v1 §§14.1, 15 | `doctor` keeps reporting every launch profile `experimental`; the claim is the A-row in §6.3. |

## 3. Zero-config agent launch (J12)

### 3.1 Command surface

```text
ukai-jail NAME [ARG]...
ukai-jail run --launch NAME --from-path [run options] [-- ARG...]
ukai-jail explain --launch NAME --from-path [run options] [--json]
ukai-jail doctor --launch NAME --from-path [--json]
```

- **The alias.** When the first word is not a built-in verb, it names a
  launch profile (operator file first, then embedded, exactly as
  `--launch` resolves today). Every following word is passed to the agent
  verbatim; the alias parses no jail option, so an agent flag can never be
  taken for a jail flag. It is exactly
  `ukai-jail run --launch NAME --from-path -- ARG...`: same policy digest,
  same argv digest. Use the long form to add jail options.
- **Built-in verbs win.** `run`, `tail`, `learn`, `explain`, `doctor`, `gc`,
  `version`, `help` and the proposed `credential` are never launch names on
  the alias path; a launch profile with one of those names stays reachable
  through `run --launch`, and `doctor --launch` warns about the shadowing. An
  unknown word exits 2 naming both readings ("no verb or launch profile
  `claud`").
- **`--from-path`** is the only switch that turns the defaults below on.
  Without it, `run --launch NAME -- PROGRAM` behaves exactly as today
  (invocation directory as workspace, `PROGRAM` resolved with the child's
  `PATH`), so no existing script changes meaning.
- `--from-path` with `--gate-fd`, `--attempt-id` or `--profile none` exits 2.

### 3.2 Workspace default

With `--from-path` and no `--workspace`:

1. Walk from the invocation directory toward `/` with no-follow `lstat`,
   stopping at the first directory holding a `.git` entry that is either a
   directory containing `HEAD`, or a regular file of at most 4 KiB whose
   first line begins `gitdir: `. Stop, as git does by default, at a mount
   boundary (`st_dev` changes). The supervisor never runs `git` for this:
   a repository's own configuration can make `git` execute commands
   (`core.fsmonitor`, for one) with the operator's authority before any
   boundary exists, and it would add an unpinned executable from the
   operator's `PATH` to the trusted path that jail-v2 §3.3 pins.
2. No repository found: refuse before preparing, `invalid_config`, key
   `--workspace`: "not inside a git repository; pass --workspace PATH". An
   explicit choice beats a guessed home directory.
3. The chosen workspace refuses, `policy_widening`, key `--workspace`, when
   it is `/`, the operator's home, or an ancestor of it. A home directory
   that is itself a repository (dotfile managers) is exactly the case this
   catches. (With the default data directory such a workspace is already
   refused indirectly today, `unsafe_state_path`, because the runtime state
   under `~/.local/share/ukai` would lie inside a grant; the new check holds
   whatever `UKAI_DATA_DIR` says and names the real reason.)
4. **The child's working directory** becomes the invocation directory when
   it lies beneath the workspace, and the workspace root otherwise. Today the
   backend always `--chdir`s to the workspace root, so an agent started from
   `repo/sub` would start at `repo`. The directory is recorded in the policy
   snapshot as `roots.cwd`, workspace-relative, so it enters the policy digest
   (a snapshot schema change, §5).
5. The project `ukai.toml` is read at the new workspace root, as today. From
   a subdirectory this now picks up the repository-root file, so its
   narrowing applies whatever directory the agent was started from.

Named limits: a **linked worktree** or a **submodule** has its `.git` as a
file pointing outside the workspace; the common git directory stays
invisible, so the agent's `git` commands there fail. `--from-path` does not
grant it (it holds the main repository's hooks and config); `doctor` reports
it. The `agent` profile keeps `.git/hooks` and `.git/config` read-only where
they exist at launch (`profiles.rs`, audit 2026-10-08 M5).

### 3.3 Program resolution and the read-only install grant

1. **Find.** Look up the launch name on the supervisor's own `PATH` with the
   rule bubblewrap resolution already uses ([operating.md](jail-v1/operating.md#install)):
   the first **absolute** entry holding an executable regular file of that
   name; empty and relative entries are never searched. No match refuses,
   `invalid_config`, key `--from-path`.
2. **Pin.** Canonicalize symlinks to the real file `E`, then open it `O_PATH`
   no-follow and record its identity `(dev, ino, uid, mode)`, as the backend
   is pinned (jail-v2 §3.3). `E` must not be group- or other-writable, nor
   any directory from the install root down to it (the vault's executable
   binding already refuses such objects).
3. **Install root.** `R` is the directory `program_root` levels above `E`
   (launch-profile data, default 1: `E`'s own directory). For Claude Code's
   native installer the documentation says `~/.local/bin/claude` is a symlink
   into `~/.local/share/claude/versions/`, so `R` is that `versions`
   directory; for OpenCode it is `~/.opencode/bin`, the grant the A01 rows
   passed by hand. The root is bound read-only through an `O_PATH` handle
   (`--ro-bind-fd`, as credentials are), and `E`'s identity is rechecked
   under that handle before release, so a swap between resolution and exec
   refuses instead of running another file.
4. **Refusals** (`policy_widening` unless noted, each naming the root): `R`
   is `/`, the operator's home or an ancestor of it; `R` contains the config
   directory, the data directory or a credential source of this launch; `R`
   lies inside or contains the workspace, scratch, vendor state or any `--rw`
   root (this is the "binary outside writable grants" rule: a contained agent
   that could rewrite its own executable would run that code with the
   operator's authority on the next host launch); `R` is or contains `/proc`,
   `/sys` or the cgroup filesystem (the existing grant rule).
5. **Interpreter.** Read at most 256 bytes of `E` through the pinned handle.
   An ELF file needs nothing more when its loader lies in the runtime roots
   (otherwise refuse, `exec_interpreter_missing`). A `#!` interpreter inside
   the runtime roots needs nothing more. `#!/usr/bin/env X` where `X`
   resolves on the operator's `PATH` outside the runtime roots cannot work as
   written, because `env` searches the fixed contained `PATH`; the argv
   becomes `[X', E, ARG...]` (`X'` canonical), which is what the kernel would
   run after `env`, and `X'`'s own directory gets the same read-only grant
   and refusals. Every other form (`env -S`, several interpreter arguments, a
   nested script) refuses naming the interpreter. The expansion is shown by
   `explain` and is the argv the digest covers. The Claude Code
   documentation says npm installs ship the same native binary, so the
   expansion should not be needed for it; the compatibility run records which
   case applied.
6. **Disclosure.** `explain --from-path` prints the resolved program, the
   argv and every derived grant; `--json` adds them to the snapshot. The
   snapshot's provenance gains entries with origin `program-resolution`. The
   receipt lists the grant as `{kind: "read_only", value: R, by: "operator"}`,
   which needs no schema change, because the operator's own name and `PATH`
   determined it (decision 4 offers a distinct `by` value instead). When
   stderr is a terminal, one line precedes exec:

   ```text
   ukai-jail: claude = /home/u/.local/share/claude/versions/<version> (read-only: /home/u/.local/share/claude/versions)
   ```

7. **Binding the credential to the program.** A vault credential may say
   `binaries = ["@program"]`: the token stands for the pinned `E` (or `X'`
   after an expansion, which binds the interpreter, so any script that
   interpreter runs could use the credential; `doctor` says so). The existing
   kernel-origin check then refuses the placeholder from anything else the
   agent spawns, such as `curl` in its shell tool (`credential_process_denied`).

The install root is read-only inside, so the agent cannot update itself. The
profile switches the updater off (`DISABLE_AUTOUPDATER=1` for Claude Code,
per its documentation); updates happen on the host, between runs.

### 3.4 Launch-profile grammar additions (amends jail-v1 §12)

All data-only and agent-agnostic; validated at load like every existing key.

| Key | Where | Meaning | Validation |
|---|---|---|---|
| `program_root = N` | top level | Levels above the canonical executable granted read-only (default 1). | 1 ≤ N ≤ 4; the §3.3 refusals apply to the result. |
| `env = "NAME"` | `[credentials.<id>]`, `vault` only | Binds the placeholder to `NAME` instead of `UKAI_VAULT_<ID>`, which removes the `/bin/sh -c` wrapper the vault starters document. | `check_env_name` (no `LD_*`, `UKAI_*`, proxy, runtime-control or generated name); unique across bindings, `state_var` and other credentials' `env`. |
| `binaries = ["@program"]` | `[credentials.<id>]`, `vault` only | The pinned resolved program (§3.3, step 7). | With `--from-path`, the resolved program. Without it, `PROGRAM` when that is an absolute path; otherwise the run refuses, naming the key, so `run --launch claude -- /abs/path/claude` keeps working. |
| `hint = "…"` | `[credentials.<id>]` | Operator-facing text: how to provide this source. Printed by `doctor --launch` and by the refusal below; never by a run that succeeds. | Printable, at most 512 bytes. |
| `credentials_one_of = ["a", "b"]` | top level | Stage the **first** listed credential whose source exists; skip the rest. | Ids must be declared. Only `ENOENT` on the final path component counts as absent: a wrong mode, owner, link count or a symlink still refuses, as today. None present refuses before exec, `credential_unavailable`, listing each id with its `hint`. The receipt's `credentials` array lists only the staged one (unchanged shape); provenance records each skipped id with `skipped: absent`. |
| `source = "@config/…"` | `[credentials.<id>]` | Resolves against the config directory, so a moved `UKAI_CONFIG_DIR` and `ukai-jail credential set` (§3.5) agree. | Same normalization as `~/`. |

### 3.5 Credentials: how a Claude Code subscription user gets a working session

What the vendor documents, paraphrased from the
[authentication](https://code.claude.com/docs/en/authentication) and
[network configuration](https://code.claude.com/docs/en/network-config) pages
as read on 2026-10-16:

- A subscription (`/login`) login on Linux is stored in
  `~/.claude/.credentials.json`, mode 0600, or under `CLAUDE_CONFIG_DIR` when
  that is set. Claude Code refreshes it itself, and for claude.ai accounts
  the token exchange, refresh and revocation go to `platform.claude.com`.
- `claude setup-token` runs the same browser flow and prints an OAuth token
  valid for one year, for Pro, Max, Team or Enterprise plans; the page
  presents it for CI pipelines and scripts where a browser login is not
  possible. Claude Code does not save it; the client reads it from
  `CLAUDE_CODE_OAUTH_TOKEN`. It is limited to model requests (no claude.ai
  connectors, no Remote Control). `--bare` ignores it.
- Precedence: `ANTHROPIC_AUTH_TOKEN`, then `ANTHROPIC_API_KEY`, then
  `apiKeyHelper`, then `CLAUDE_CODE_OAUTH_TOKEN`, then profiles, then the
  `/login` subscription. Under `-p` a present API key is always used.
- The documentation does **not** say which header carries
  `CLAUDE_CODE_OAUTH_TOKEN` (it documents `Authorization: Bearer` for
  `ANTHROPIC_AUTH_TOKEN` and `X-Api-Key` for `ANTHROPIC_API_KEY`), nor
  whether the client checks the token's shape locally.

This changes the north star's initial input for `claude` (§4.5 table, and
jail-v1 §12's table): it named `.credentials.json` and `settings.json` from
the node's Claude directory. The north star itself records the problem for
Codex, that `copy_rw` can rotate a refresh token the node's own file then
lacks; the same applies here, so the recommended default below stages
neither file.

The options, and the one recommended:

| Option | What the child holds | Verdict |
|---|---|---|
| Stage `~/.claude/.credentials.json` `copy_rw` (the commented input in today's `claude.toml`) | The real refresh token, in a readable file | **Not a default.** A refresh inside the jail goes to `platform.claude.com`; `copy_rw` never writes the result back, so if the issuer rotates refresh tokens the host's own login is left with a dead one. Whether it rotates is unknown and must not be discovered on a user's account. Stays available as an explicit operator file. |
| `bind_ro` of the same file | The same token, read-only | **Not a default.** Same exposure; a refresh cannot persist at all. |
| Supervisor-owned refresh of the subscription grant (the existing `refresh = {…}` machinery) | A placeholder | **Refused.** It needs a token endpoint and client id the vendor does not document as a contract, it rotates the grant away from the host's own `claude`, and it puts Ukai inside one vendor's login protocol. |
| **`setup-token` through the vault** | **A placeholder** | **Recommended.** The real token stays in supervisor memory; nothing needs refreshing for its documented year. |
| An API key through the vault | A placeholder | Supported as the fallback; this transport ran in the [12 October](../benchmarks/credentials/2026-10-12/README.md) and [13 October](../benchmarks/credentials/2026-10-13/README.md) credential benchmarks (Claude Code 2.1.295, `-p`, `x-api-key` at `https://api.anthropic.com`), which are benchmark evidence, not a compatibility row. |

The subscription user's path, once per host:

```sh
claude setup-token                          # browser flow; prints the token, saves nothing
ukai-jail credential set claude-oauth       # paste it; stored mode 0600, no trailing newline
```

and then every run is `ukai-jail claude …`. Per run the supervisor rereads
the token live from `<config-dir>/credentials/claude-oauth`, the child sees
`CLAUDE_CODE_OAUTH_TOKEN=vault:<attempt>:claude-oauth`, and the proxy puts the
real value in `Authorization: Bearer …` only for `https://api.anthropic.com`,
only on connections the pinned Claude Code executable initiated. Deleting the
file (or `ukai-jail credential rm claude-oauth`) revokes live leases within the
documented 100 ms poll. When the token expires, the upstream rejects it and
the agent reports the failure (the jail has nothing to refresh); the operator
mints a new token. A first run with no source
refuses before exec and prints both hints, so nobody meets a confusing
"not logged in" from inside the jail.

**`ukai-jail credential set ID` / `credential rm ID`** (new operator verbs,
no agent names): read one value from stdin (no echo on a terminal), strip
exactly one trailing LF, require 1–8192 printable ASCII bytes (the vault's
rule), and create `<config-dir>/credentials/ID` through an anchored no-follow
walk, directory 0700, file 0600, `O_EXCL` unless `--force` (which replaces by
checked rename). The value is never printed, logged or echoed. The config
directory is already isolated from every child-visible root on every run
(jail-v1 revision 23). Decision 6 asks whether to ship the verb or document a
shell recipe instead.

The bundled `claude` profile this implies (data, subject to the measurements
in §6.3):

```toml
name = "claude"
jail = "agent"
state_var = "CLAUDE_CONFIG_DIR"
credentials_one_of = ["claude-oauth", "anthropic"]   # order: decision 3

[environment]
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
DISABLE_AUTOUPDATER = "1"

[credentials.claude-oauth]
mode = "vault"
source = "@config/credentials/claude-oauth"
env = "CLAUDE_CODE_OAUTH_TOKEN"
hosts = ["https://api.anthropic.com"]
header = { name = "authorization", prefix = "Bearer " }   # measured, not documented
binaries = ["@program"]
hint = "run `claude setup-token` on this host, then `ukai-jail credential set claude-oauth`"

[credentials.anthropic]
mode = "vault"
source = "@config/credentials/anthropic"
env = "ANTHROPIC_API_KEY"
hosts = ["https://api.anthropic.com"]
header = { name = "x-api-key" }
binaries = ["@program"]
hint = "put a Claude Console API key in it: `ukai-jail credential set anthropic`"

[network]
allow = ["api.anthropic.com"]
```

`credentials_one_of` guarantees exactly one credential reaches the child, so
the vendor's own precedence (an API key outranks the setup token) never
decides silently which account pays. Whether `home_is_state = true` is also
needed is measured (§6.3): the benchmarks ran headless with `HOME` unset, and
the journal's `fs.deny` events will show whether the agent tries to write
under a home it does not have.

### 3.6 What the agent can and cannot see

For `ukai-jail claude …` with the profile above, on Linux under `agent`:

| | Visible to the agent | Not visible |
|---|---|---|
| **Files** | The repository top level, writable (except `.git/hooks` and `.git/config` existing at launch, read-only); its working directory is where the operator stood. Scratch, writable, as `TMPDIR`. Vendor state at `/run/ukai/state` (`CLAUDE_CONFIG_DIR`), empty at start, deleted at settlement. The install root, read-only. The runtime roots, read-only: `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/ssl`, a sanitized `/etc/resolv.conf`, `/etc/passwd`, `/etc/group`, `/etc/hosts`, `/etc/localtime`. | The rest of the home directory: `~/.claude` (settings, user `CLAUDE.md`, history, `.credentials.json`), `~/.claude.json`, `~/.ssh`, `~/.gitconfig`, cloud credentials, the Ukai config and data directories, every other repository. Host `/tmp`, `/var`, `/opt`, `/srv`, other users' homes. Project-level `.claude/` files are visible because they are in the workspace. |
| **Environment** | `PATH` (fixed), `LANG`, `TERM`, `TZ`, `TMPDIR`, `CLAUDE_CONFIG_DIR`, the profile's variables, the proxy and CA-trust variables, and one placeholder (`CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`). | Everything else in the operator's shell: an `ANTHROPIC_API_KEY` exported there does not pass through, nor `SSH_AUTH_SOCK`, `GH_TOKEN` or `AWS_*`. |
| **Network** | Only through the attempt's proxy, only to `api.anthropic.com:443`; every other destination is refused and journaled. | `github.com` (no push or fetch), `registry.npmjs.org` (no `npx` MCP servers), `downloads.claude.ai` (no updates), the telemetry hosts, `mcp-proxy.anthropic.com` (claude.ai connectors, which the setup token cannot fetch anyway). Each can be added with `--allow-host`, visibly. |
| **Sockets and processes** | Its own PID namespace and the attempt's own Unix sockets. | Host Unix sockets (Docker, ssh-agent, D-Bus) through the existing connect mediation. |
| **Credentials** | A placeholder that is useless outside this attempt's proxy and, with `@program`, outside the pinned executable. | The token's value: it is never staged in a file or the environment. A server can still reflect a secret back; vaulting cannot promise the child never learns it (jail-v2 §1). |

What stays refused, whatever the operator types into a project file or the
agent does: selecting `none` through a launch profile; a project `ukai.toml`
that adds a credential, host or grant; an install root inside a writable
grant, at `/` or at or above the home directory; a credential source inside
a child-visible grant; any automatic read of `~/.claude/.credentials.json`,
`~/.claude.json` or `~/.claude/settings.json`; inheriting the operator's
environment or `PATH`; `--from-path` with the managed gate. Claude Code's own
sandbox is off by default and, per its documentation, fails open when
bubblewrap cannot start; inside `agent` on stock Ubuntu its nested user
namespace is denied (operating.md, "Named limits"), so its commands run with
the agent's jail authority, which is the boundary this jail provides.

What the agent loses compared with a host session, said plainly: no user
settings, memory, skills or MCP servers from `~/.claude`; no `--resume`
across runs (history lives in vendor state, removed at settlement); no git
push or SSH; no self-update; no network beyond the allowlist.

### 3.7 Interactive sessions: why the first claim is headless

jail-v1 §8.3 runs the command in a new session and provides no PTY or
job-control emulation (bubblewrap's `--new-session` in `bwrap.rs`), so the
agent runs without a controlling terminal: it still reads and writes the
terminal through inherited descriptors, but terminal resizes (`SIGWINCH`) do
not reach it, opening `/dev/tty` fails, and a terminal-generated `SIGINT`
goes to the jail, where §8.3 makes it a request to end the attempt. Every recorded agent run so far
is headless (`opencode run`, `claude -p`). In addition, with empty vendor
state each run is a first launch, and the authentication page says a new
configuration directory goes through login and setup on first use; whether
the setup token skips all of it is unmeasured.

So J12's support claim is `ukai-jail claude -p …` and its equivalents. An
interactive claim needs two decisions (§7, decision 7): a terminal mode that
omits `--new-session` only when stdin is a terminal, resting on the filter's
existing `TIOCSTI` denial (a security review must cover `TIOCLINUX` and the
kernel's `legacy_tiocsti` default too), and persistent per-profile vendor
state with its own receipt semantics. Until both exist, the alias still
starts an interactive session when asked, and `doctor --launch` says that
mode is unrecorded.

## 4. End-of-run summary (J13)

### 4.1 When and how it prints

- After `run` finishes supervising and the final receipt is durable, whether
  the attempt settled or not, and before the existing
  `ukai-jail: receipt <path>` line, which stays last.
- **Only when stderr is a terminal**, the rule the receipt line already
  follows for X05: with stderr a pipe or file the jail adds no byte to it.
  `--quiet` suppresses the summary and the receipt line (errors still
  print); `summary = false` under `[jail]` in `config.toml` makes that the
  default.
  `--label-only` never prints it. The exit code never depends on it.
- At most eight lines; at most five hosts per list, then `+N more`. Every
  child-chosen string (paths, hosts) goes through the existing control-byte
  escaping (audit 2026-10-08 M1).
- **A pure function of evidence.** `summary(receipt, journal) -> lines` takes
  the final `jail.json` and the attempt's `trace.ndjson`, reads nothing else
  (no supervisor memory, no counters kept on the side), and reuses
  `journal.rs`, which never counts a partial final frame. Anyone can therefore
  recompute it. The same function serves attempts after the fact and non-TTY
  callers as `ukai-jail tail --summary [--attempt ID]` (decision 8).
- **Initial cost budget**: at most 50 ms added on the reference host for an
  A01-sized journal (the milestone A01 receipt counted 13,091 `fs.write`
  events). A journal over 16 MiB (initial) is not scanned; the lines that need
  it say `journal not scanned (N MiB)` and the receipt-only lines still print.

### 4.2 The lines and their sources

Receipt fields are JSON pointers into
[`ukai.jail.receipt/1`](jail-v1/jail-receipt.schema.json); journal selectors
name [`ukai.event/1`](jail-v1/jail-event.schema.json) frames in the attempt's
`trace.ndjson`.

| Line | Shows | Source | Rule when evidence is missing or partial |
|---|---|---|---|
| Status | Phase, outcome, duration, survivors | `/phase`; `/outcome/kind`, `/code`, `/signal`, `/cause`; `/errors/*/code`; `/lifetime/tree_empty`, `/verification_scope`, `/integrity`. Duration: `monotonic_ns` of the note `{operation: "note", fields.kind: "lifecycle", fields.transition: "exec_confirmed"}` to that of the `{operation: "jail.receipt", fields.phase: "settled"}` note (one supervisor clock). | Not `settled`: `NOT settled (<phase>)` with the error codes and, for `tree_unknown`, "run `ukai-jail gc`". No `exec_confirmed` note: no duration. No journal: `/created_at` to `/updated_at`, labelled `attempt` (wall clock, can step). `tree_empty` true prints `survivors: none (verified)`, with `registered cgroup only` when the scope is `registered_boundary` (`none`); false or null prints `survivors: NOT verified`. `/integrity` `lost` prints `integrity lost: state retained`. |
| Workspace | Distinct workspace paths opened for writing, renamed or removed; unnamed ones; refused writes | Journal: `source: "audit"`, `stage: "result"`, `outcome.ok: true`, `operation` in `fs.create`, `fs.write` (`fields.action` `opened_for_mutation` or `truncated`), `fs.rename` (`fields.path` and `fields.path2`), `fs.unlink`; distinct `fields.path.value` where `fields.path.kind` is `workspace_relative`. Unnamed: the same events with path kind `unavailable` or `digest`. Refused: `operation: "fs.deny"` with a file `fields.attempted_operation`. Gate: `/coverage/fs.write/status` (that class covers all four operations, jail-v1 §11.4), `/coverage/fs.deny/status`. | `active`: exact numbers. `degraded`, or an incomplete journal: every number prefixed `at least`. `unsupported` (observation off): `workspace: not observed (--observe off)`, never `0`. `fs.create` and `fs.write` are both printed as "opened for writing", never "created", "changed" or "written": jail-v1 §11.2 says such an event proves neither bytes written nor a newly created file. `fs.rename` prints "renamed", `fs.unlink` "removed". Refused writes outside known roots are recorded as a path digest (`outside_known_roots`), so they are counted, never named. |
| Network | Destinations allowed and denied, with counts | Journal: `source: "proxy"`, `operation: "net.connect"`, `stage: "result"`, grouped by `fields.destination`; allowed is `decision: "allow"` (with `outcome.ok: false` counted as `connect failed`), denied is `decision: "deny"` with its `fields.reason`. `/coverage/proxy.net/resolver_refused` when present (capacity, not policy). Gate: `/applied/network/mode`, `/coverage/proxy.net/status`. | The unit is a proxy result (a tunnel, or one request on the vault's TLS lane), never "requests". Mode `none`: `network: none`. Mode `host` (`none` profile): `network: host, not observed`. `proxy.net` degraded: `at least`. |
| Credentials | Per credential: mode, staging, lifecycle, refusals | `/credentials/*/id`, `/mode`, `/never_staged`; journal notes `fields.kind: "credential"` with `credential_id` and `transition` (`loaded`, `refreshed`, `revoked`, `refresh_failed`); proxy results whose `fields.reason` begins `credential_`. | Uses are **not** printed: no event records that a placeholder was substituted (§4.3). `copy_rw` and `bind_ro` print `staged (readable by the agent)`, so the vault's difference is visible. |
| Evidence | Observation mode, class status, gaps, journal completeness | `/policy/observe`, `/policy/evidence`, `/observer/attached`, `/coverage/<class>/status`, `/coverage/<class>/gaps/*/reason` and `lost_count`; completeness: the journal's last frame is the `jail.receipt` note whose `receipt_digest` matches the final receipt (jail-v1 §13.3). | All six active and complete: `6/6 classes active, no gaps`. Otherwise each non-active class with its first gap reason and lost count (or `unknown`). Always appended when any audit class is shown: `reads and file contents are not observed`. Incomplete journal: `journal incomplete: counts above are lower bounds`. |
| Limits (only when relevant) | A hit ceiling or an unapplied one | `/applied/limits/*` with `hit: true`, or `applied: false`. | Absent when nothing was hit and everything applied. |
| Cleanup and protection (only when relevant) | Pending vendor-state removal; an uncontained run | `/state_cleanup` `pending`; `/child_protection` `unprotected`. | `vendor state cleanup pending: run ukai-jail gc`; `uncontained (none): nothing above was enforced`. |
| Receipt | The canonical receipt path | Existing line. | Unchanged. |

Consistency check: for a complete journal, the number of events per class
must equal `/coverage/<class>/observed_count`, the equality the performance
protocol already requires ([jail-v1 §5.2](jail-v1.md#52-observer-candidate-and-privilege-boundary)).
On a mismatch the summary prints `journal and receipt disagree on <class>` and
no number for that class.

### 4.3 What the evidence can and cannot support today

| Question | Supported? | Why |
|---|---|---|
| Which files did the agent read? | **No, never printed.** | `linux-closed-v1` excludes reads ([operating.md](jail-v1/operating.md#reading-a-receipt)); only `learn` records reads, and `run` is not `learn`. |
| How many bytes did it write? | **No.** | Opens for mutation, truncation, creation, rename and unlink are observed; `write(2)`, `mmap` writes and payloads are not. |
| Which workspace paths were opened for writing, renamed or removed? | Yes, with `observe on` and the class `active`; a lower bound when degraded. | Dirfd-relative calls can leave the path `unavailable`: counted as unnamed. Whether a file was newly created or its content changed is not established. |
| What did it try to write outside its grants? | Count only. | Denied paths outside known roots are digests. |
| Which hosts did it reach or try? | Yes, under `agent` with `proxy.net` active. | The network namespace leaves the proxy as the only route, so the list is complete for an active class. Names are what the client asked the proxy for; DNS (`net.dns`) is not recorded. |
| How often did it use each credential? | **No, today.** | Proxy results carry no credential id. Proposed: an optional `fields.credentials` array on proxy results listing the ids substituted on that connection (ids only; an event-schema change, decision 5). Until then the line shows lifecycle and refusals only. |
| Did any process survive? | Yes: `/lifetime/tree_empty` for `attempt_tree`. | Under `none` only the identity-checked cgroup is verified (`registered_boundary`), and the line says so. |
| Anything with `--observe off`? | Proxy and limits only. | The audit classes are `unsupported`; the summary says `not observed`, never zero. |
| Anything with `--trace-fd`? | Receipt-only lines. | The journal is streamed to the descriptor, not kept locally (jail-v1 §13.3); the summary says `journal streamed to fd N`. |
| Under `--evidence best-effort` after a loss? | Lower bounds. | The receipt marks the lost intervals; the summary prefixes `at least` and names the gap. |

### 4.4 Examples of the degraded forms

```text
ukai-jail: settled · exited 0 · 1m03s exec→settled · survivors: none (verified)
ukai-jail: workspace: not observed (--observe off)
ukai-jail: network: allowed api.anthropic.com:443 (12)
ukai-jail: evidence: observation off: exec, file and connect classes not observed
```

```text
ukai-jail: NOT settled (enforced) · outcome unknown · tree_unknown: run ukai-jail gc
ukai-jail: workspace: at least 3 paths opened for writing
ukai-jail: evidence: fs.write degraded (trace_transport_loss, lost unknown) · journal incomplete: counts above are lower bounds
```

## 5. Contract changes this implies

| Change | Kind | Notes |
|---|---|---|
| `ukai-jail NAME`, `run/explain/doctor --from-path`, `run --quiet`, `credential set/rm`, `tail --summary` | CLI | `--from-path` refuses with the gate flags and `none`. |
| Under `--from-path`, argv is the operator's words with the first resolved to an absolute path (and, for `#!/usr/bin/env X`, the interpreter made explicit) | Amends north star §4.5 ("`argv` is always the operator's `--` arguments") | Profile data still never names or rewrites a command; the expansion is the CLI's, shown by `explain`. |
| A missing credential source is skipped when its id is in `credentials_one_of` and another listed source exists | Amends north star §4.5 ("A missing source refuses the launch") and jail-v1 §12 | Every other missing or unsafe source still refuses. |
| `claude`'s declared inputs become a vault setup token or API key, not `.credentials.json` and `settings.json` | Amends the north star §4.5 and jail-v1 §12 profile tables | §3.5 gives the reason. |
| `program_root`, `env`, `binaries = ["@program"]`, `hint`, `credentials_one_of`, `@config/` | Launch-profile grammar (jail-v1 §12) | Data-only; the I02 source test keeps agent names out of code. |
| `roots.cwd`; provenance origin `program-resolution` | Policy snapshot schema | Changes policy digests; fixtures re-blessed together, per jail-v2's no-legacy rule. |
| `jail.summary` | `config.toml` | Presentation only; not a policy input. |
| Optional `fields.credentials` on proxy results | Event schema | Only if decision 5 says yes. |
| Optional `by: "program_resolution"` | Receipt schema | Only if decision 4 says yes. |

## 6. Tests and the compatibility run required before "supported"

### 6.1 J12 rows

| Row | Claim |
|---|---|
| K33 | The alias equals `run --launch NAME --from-path -- ARG...` (identical policy and argv digests); built-in verbs win; an unknown word exits 2; `--from-path` with `--gate-fd`, `--attempt-id` or `--profile none` exits 2. |
| K34 | Workspace discovery: a `.git` directory, a `.git` file (worktree, submodule), none (refusal naming `--workspace`), a mount boundary, a symlinked invocation directory; home, its ancestors and `/` refuse; a recording `git` placed first on `PATH` is never executed. |
| K35 | The child starts in the invocation directory beneath the workspace; `roots.cwd` is in the snapshot and changes the digest. |
| K36 | Resolution: first absolute `PATH` entry; empty and relative entries skipped; symlink chains canonicalized; the install root is read-only inside (a write fails and is journaled as `fs.deny`); every §3.3 refusal fires with its key and names the root. |
| K37 | Replacing the executable or its root between resolution and release refuses (identity mismatch); no other file runs. |
| K38 | Interpreters: ELF, `#!` inside the runtime roots, `#!/usr/bin/env node` with node outside them (argv expanded, interpreter granted), and each unsupported form refusing with the interpreter named. |
| K39 | Disclosure: each derived grant appears in `explain --from-path` text and JSON, in provenance, in the receipt's `policy.grants`, and in the pre-exec line on a terminal; with stderr not a terminal nothing is added (X05 suite rerun). |
| K40 | Project `ukai.toml` under the alias: may deny-read the install root and shrink hosts (the agent then fails visibly); every widening key still refuses with its existing code. |
| K41 | Vault `env`: an in-jail fixture prints its environment and finds only the placeholder under the declared name (as K14 does for `UKAI_VAULT_*`); reserved and colliding names refuse at load. |
| K42 | `credentials_one_of`: the first present source is staged and the rest skipped; only `ENOENT` counts as absent (bad mode, extra link, symlink still refuse); none present refuses before exec with every hint; the receipt lists only the staged id. |
| K43 | `binaries = ["@program"]`: the resolved program's request is substituted; the same placeholder sent by `curl` inside the jail is refused `credential_process_denied`; the expanded-interpreter case is reported by `doctor`. |
| K44 | `credential set/rm`: modes 0700/0600, one trailing LF stripped, value never on stdout, stderr, logs or argv; refuses symlinked, foreign-owned or shared-writable paths; `O_EXCL` without `--force`; `rm` revokes a live lease within the lifecycle fixture's bound. |

### 6.2 J13 rows

| Row | Claim |
|---|---|
| K45 | Golden fixtures (receipt plus journal → exact lines): clean settled, observation off, degraded with gaps, refused before exec, unsettled with `tree_unknown`, `none`, `--trace-fd` (no journal), incomplete journal, best-effort after a loss. |
| K46 | Never overclaims (property test over generated journals): no printed count exceeds the evidence; every count from a degraded class or incomplete journal carries `at least`; an unsupported class prints `not observed`, never a number; no read count is ever printed. |
| K47 | Per-class event totals equal `/coverage/<class>/observed_count` on complete journals; a seeded disagreement prints the disagreement and no number. |
| K48 | Control bytes and escape sequences in child-chosen paths and hosts are escaped; lists truncate with `+N more`; never more than eight lines. |
| K49 | X05 with the summary built in: stderr not a terminal, bytes identical to direct execution; under a pseudo-terminal harness, the summary follows the child's last byte. |
| K50 | `--quiet` and `jail.summary = false` suppress summary and receipt line, errors still print, and the exit code is unchanged in every K45 case. |
| K51 | Cost on the reference host: an A01-sized journal within the 50 ms budget; a journal past the scan cap prints the receipt-only lines and says so. |
| K52 | `tail --summary` on a settled attempt prints exactly what the live run printed, and an independent script recomputes every number from the archived receipt and journal. |

### 6.3 The Claude Code compatibility record (A-row)

[agent-compatibility.md](jail-v1/agent-compatibility.md) has no Claude Code
row. The benchmark runs prove a transport, not a profile. The row that makes
`ukai-jail claude` supported for one build:

- **Where and what.** The reference host (Ubuntu 26.04.1, kernel 7.0.0-31,
  x86_64, stock, lingering on), a clean `ukai-jail` revision with its binary
  SHA-256 recorded, Claude Code installed by the native installer with
  `claude --version` and the SHA-256 of the resolved executable recorded, the
  bundled `claude` profile unchanged, a fresh git repository, an operator
  account with a test subscription.
- **Runs.** (1) The A01 fixture: `ukai-jail claude -p "Create a file named
  greeting.txt containing the single word hello."` (2) A real small task in
  the same repository. (3) The same pair with the `anthropic` API key
  instead (only one source present). (4) No source present: refusal before
  exec with both hints. (5) The source deleted mid-run: revocation recorded
  and the stream interrupted. (6) Ten repetitions of (1), each failure kept:
  the OpenCode record shows that a few clean runs do not rule out an
  intermittent start-up stall.
- **Pass conditions for (1) to (3).** The file contains `hello`; the receipt
  is settled, exit 0, no error, all six classes active without gaps,
  `tree_empty` true, `state_cleanup` complete; `credentials` lists exactly
  one id with `never_staged: true`; `policy.grants` lists the derived install
  root and nothing unexpected; the summary's numbers reproduce from the
  archived receipt and journal (K52); the token's value is absent from the
  receipt, journal, workspace, the agent's output and its sampled
  environments (the benchmarks' exposure sampler).
- **Vendor facts this run settles**, each recorded with its evidence: the
  header Claude Code sends for `CLAUDE_CODE_OAUTH_TOKEN` (the profile's
  `header` is wrong if it is not `Authorization: Bearer`); that the client
  accepts the placeholder (no local shape check); which hosts a first run
  contacts (the journal's denials name them; the network-configuration page
  says the first-run connectivity check involves `api.anthropic.com` and
  `platform.claude.com`); whether `home_is_state` is needed; whether any
  request comes from an executable other than the pinned one (it would show
  as `credential_process_denied`); which interpreter case of §3.3 applied.
- **Not covered**: interactive sessions (§3.7), npm installs, the Raspberry
  Pi, and every other version. Each needs its own row.

Because the alias changes OpenCode's grant (derived instead of `--ro
~/.opencode/bin`) and its workspace default, the OpenCode A01 run is
repeated under `ukai-jail opencode run "…"` before its existing row is
extended to the alias.

## 7. Open decisions

1. **Alias surface.** Ship `ukai-jail NAME` (recommended: it is the
   install-and-go form), or only `run --launch NAME --from-path`; and the
   flag's name.
2. **Workspace outside a repository.** Refuse and ask for `--workspace`
   (recommended), or fall back to the invocation directory. Separately:
   apply the new home/ancestor refusal to every `run`, or only to
   `--from-path` (recommended for now, so existing scripts keep working).
3. **Credential order** when both a setup token and an API key exist:
   subscription first (proposed above), or the vendor's own precedence (key
   first).
4. **Receipt attribution** of derived grants: keep `by: "operator"` (no
   schema change, proposed), or add `by: "program_resolution"`.
5. **Credential uses** in the summary: add `fields.credentials` to proxy
   results (an event-schema change), or keep the line to lifecycle and
   refusals.
6. **`ukai-jail credential set/rm`** as verbs, or a documented `umask 077 &&
   printf` recipe.
7. **Interactive support**: a terminal mode without the new session, and
   persistent per-profile vendor state. Both change v1 invariants (§8.3 and
   §12); neither is proposed here beyond naming the work.
8. **Off-terminal summaries**: `tail --summary` (proposed), a new verb, or
   none.
