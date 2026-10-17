# Jail proposal: zero-config agent launch and the end-of-run summary

Status: design proposal, 2026-10-16; its decisions were settled by the
operator the same day (§7). J13 (§4) and J12 (§3) are implemented; §8 lists
where the J12 implementation departs from or adds to this text. No agent
compatibility is claimed: the Claude Code A-row (§6.3) and the OpenCode
rerun under the alias are separate, unrecorded steps. Where this proposal is
not implemented the [north star](../../north-star.md),
[Jail v1](jail-v1.md) (revision 24) and [Jail v2](jail-v2.md) govern
unchanged; where this proposal amends them, §5 says so row by row. The
milestone names J12, J13 and J14 and the row numbers K33–K54 are
provisional, chosen to follow jail-v2's sequence.

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
ukai-jail: credential claude-oauth: vault, never staged · used on 41 proxy results · 0 refusals
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
  credential the agent finds under its own variable name. J12 also tightens
  plain `run`: a workspace that is `/`, the operator's home or an ancestor
  of it refuses on every run (§3.2, step 3).
- **J13, the end-of-run summary**: a few lines on stderr after `run`
  settles, computed only from the final receipt and the attempt journal,
  with `--quiet` to turn it off, and the same summary off the terminal as
  `tail --summary [--json]` (§4.5).

Deferred to the next named milestone, **J14, interactive sessions** (outline
in §3.8):

- **A support claim for interactive sessions.** Every recorded agent run is
  headless, and the backend detaches the child from the terminal (§3.7).
- **Persistent vendor state.** Vendor state is attempt-private and removed at
  settlement (jail-v1 §12); keeping session history across runs changes that
  invariant.

Excluded, each for a stated reason:
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
| Nothing widens silently | jail-v1 §6.2 (a widening layer "must never load silently"); north star §4.3 (no widening during an attempt) | Every derived grant is shown by `explain --from-path` (text and JSON), carried in the policy snapshot with provenance origin `program-resolution`, listed in the receipt's `policy.grants` with `by: "program_resolution"` so it is never mistaken for one the operator typed, and printed before exec when stderr is a terminal (§3.3). |
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
  same argv digest. Use the long form to add jail options. The fleet front
  door `ukai` does not forward `ukai NAME`; the alias belongs to `ukai-jail`
  alone.
- **Built-in verbs win.** `run`, `tail`, `learn`, `explain`, `doctor`, `gc`,
  `version`, `help` and the proposed `credential` are never launch names on
  the alias path; a launch profile with one of those names stays reachable
  through `run --launch`, and `doctor --launch` warns about the shadowing. An
  unknown word exits 2 naming both readings ("no verb or launch profile
  `claud`").
- **`--from-path`** is the only switch that turns the defaults below on.
  Without it, `run --launch NAME -- PROGRAM` behaves as today (invocation
  directory as workspace, `PROGRAM` resolved with the child's `PATH`), with
  one exception that applies to every `run`: the home-directory refusal of
  §3.2, step 3.
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
3. **On every contained `run` (`agent`, `tool`, `build`), not only
   `--from-path`**, a workspace that is `/`, the operator's home, or an
   ancestor of it refuses, `policy_widening`, key `--workspace`, whether it
   came from discovery, from `--workspace` or from the invocation directory.
   (`none` grants no workspace: it shows the host's view unchanged, so the
   check has nothing to protect there.) A home directory that is itself a repository
   (dotfile managers) is exactly the case discovery would otherwise pick.
   With the default data directory such a workspace is already refused
   indirectly today (`unsafe_state_path`, because the runtime state under
   `~/.local/share/ukai` would lie inside a grant); the new check holds
   whatever `UKAI_DATA_DIR` says and names the real reason. Applying it to
   plain `run` is a deliberate contract change (§5): the product is a
   developer preview, jail-v2's no-legacy rule says current behaviour is
   updated rather than preserved for compatibility, and a writable home
   directory, with its shell start-up files, SSH keys and agent
   credentials, is the footgun this jail is sold against. There is no flag
   to bypass the check; `--profile none` remains the uncontained path.
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
   receipt lists the grant as
   `{kind: "read_only", value: R, by: "program_resolution"}` (and the
   interpreter's root, after an expansion, the same way), so a reader can
   tell a derived grant from one the operator typed. The receipt schema's
   `by` changes from the constant `operator` to the enum `operator`,
   `program_resolution`: an additive value, re-blessed in place under
   `ukai.jail.receipt/1` in the same commit as the snapshot change for
   `roots.cwd` (§5). When stderr is a terminal, one line precedes exec:

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
  whether the client checks the token's shape locally. Both were since
  measured for Claude Code 2.1.295 in the
  [setup-token spike](../benchmarks/jail/claude-setup-token-spike-2026-10-16.md):
  `Authorization: Bearer`, and no local shape check.

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
(jail-v1 revision 23). The verbs ship as specified (§7, decision 6).

The bundled `claude` profile this implies (data, subject to the measurements
in §6.3):

```toml
name = "claude"
jail = "agent"
state_var = "CLAUDE_CONFIG_DIR"
credentials_one_of = ["claude-oauth", "anthropic"]   # subscription first (§7, decision 3)

[environment]
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
DISABLE_AUTOUPDATER = "1"

[credentials.claude-oauth]
mode = "vault"
source = "@config/credentials/claude-oauth"
env = "CLAUDE_CODE_OAUTH_TOKEN"
hosts = ["https://api.anthropic.com"]
header = { name = "authorization", prefix = "Bearer " }   # measured (setup-token spike), not documented
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
that adds a credential, host or grant; a workspace at `/`, the home
directory or above it, on any contained run; an install root inside a writable
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
goes to the jail, where §8.3 makes it a request to end the attempt. Every
recorded agent run so far is headless (`opencode run`, `claude -p`). In
addition, with empty vendor state each run is a first launch, and the
authentication page says a new configuration directory goes through login
and setup on first use; whether the setup token skips all of it is
unmeasured.

So J12's support claim is `ukai-jail claude -p …` and its equivalents
(§7, decision 7). The alias still starts an interactive session when asked;
`doctor --launch` says that mode is unrecorded, and nothing claims it works
until J14 (§3.8) records it.

### 3.8 Next milestone: J14, interactive sessions (outline)

Named here so the headless boundary of J12 has a destination; it is not
designed in this document and gets its own proposal before any code.

- **Terminal mode.** When stdin is a terminal, run the agent in the
  caller's session instead of a new one, so resizes, `/dev/tty` and
  terminal signals reach it. This amends jail-v1 §8.3 ("The command runs in
  a new session"), so it ships only after a security review that covers
  `TIOCSTI` injection (the filter's existing denial), `TIOCLINUX` on virtual
  consoles, and hosts where the kernel's `legacy_tiocsti` setting still
  allows injection; the review also decides how `SIGINT` from the terminal
  is split between the agent and the jail's own stop request. Off a
  terminal, nothing changes.
- **Persistent per-profile vendor state.** An operator-owned state
  directory per launch profile that survives attempts, so login state,
  settings the agent writes and session history (`--resume`) persist. This
  amends jail-v1 §12 (vendor state removed at settlement) and needs receipt
  semantics of its own: which state an attempt started from (identity and
  digest, never content), what it changed, that a later attempt inherits
  what an earlier, possibly compromised one wrote, and how `gc` and
  `state_cleanup` treat a directory that is meant to outlive the tree.
- **Exit criteria.** Both mechanisms pass their acceptance rows on the
  reference host, and a Claude Code compatibility row records an
  interactive session (resize, interrupt, resume) separately from the J12
  headless row.

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
- **A pure function of evidence.** `summary(receipt, journal) -> Summary`
  takes the final `jail.json` and the attempt's `trace.ndjson`, reads
  nothing else (no supervisor memory, no counters kept on the side), and
  reuses `journal.rs`, which never counts a partial final frame. Anyone can
  therefore recompute it. The terminal lines and the JSON form of §4.5 are
  two renderings of that one value, never two computations.
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
| Credentials | Per credential: mode, staging, uses, lifecycle, refusals | `/credentials/*/id`, `/mode`, `/never_staged`; uses: the number of proxy results whose new `fields.credentials` array contains the id (§4.3); journal notes `fields.kind: "credential"` with `credential_id` and `transition` (`loaded`, `refreshed`, `revoked`, `refresh_failed`); refusals: proxy results whose `fields.reason` begins `credential_`. | The unit is "proxy results that substituted it" (`used on N proxy results`), never "requests" or "calls". A use means the real value was placed into a request the proxy sent upstream, not that the upstream accepted it: response status is not recorded. `proxy.net` degraded or the journal incomplete: `at least`. A journal from a build that predates the field (decided by `/jail/version`) prints `uses not recorded`, never `0`. `copy_rw` and `bind_ro` credentials have no uses to count (the agent holds the value itself) and print `staged (readable by the agent)`, so the vault's difference is visible. |
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
| How often did it use each credential? | **Not today; yes after J13**, counted as proxy results. | Proxy results carry no credential id today. J13 adds an optional `fields.credentials` to proxy-source `net.connect` results: the ids (never values, placeholders or digests) whose placeholder the proxy replaced in at least one request it sent upstream on that connection, sorted and unique; absent when it replaced none, so a run without a vault journals the same frames as before. A refused request is not a use; it stays a `credential_*` reason. On the vault's TLS lane each connection carries one request (or one WebSocket upgrade), so the count is close to a request count there, but the summary still names its unit. |
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

### 4.5 Off the terminal: `tail --summary [--json]`

```text
ukai-jail tail --summary [--attempt ID] [--json]
```

Prints the summary of a recorded attempt (the most recent one by default,
as `tail` already selects) on stdout, for CI logs and for a future GitHub
Action that appends it to the job summary; the Action itself is not part of
this proposal. It reads only the attempt's `jail.json` and `trace.ndjson`
through the same pure function as the live run, so for a settled attempt it
prints exactly the lines the run printed (K52). It works on live attempts
too and then reports what is recorded so far, with the phase saying so.
`--summary` refuses with `--follow` and `--since` (exit 2); it exits 0 when
it printed a summary and 1 when the attempt cannot be read. It never
returns the agent's exit code.

`--json` prints one `ukai.jail.summary/1` object (a new versioned record;
its schema file `jail-v1/jail-summary.schema.json` and a `[[frozen]]` entry
in `frozen-schemas.toml` ship with it):

```json
{
  "schema": "ukai.jail.summary/1",
  "attempt_id": "att_…",
  "receipt_digest": "sha256:…",
  "journal": "complete",
  "lines": [
    {"line": "status", "text": "settled · exited 0 · 3m41s exec→settled · survivors: none (verified)",
     "facts": {"phase": "settled", "outcome": "exited", "code": 0, "exec_to_settled_ms": 221000,
               "survivors": "none_verified"}},
    {"line": "workspace", "text": "workspace: 4 paths opened for writing, 1 renamed, 1 removed",
     "facts": {"bound": "exact", "opened_for_writing": 4, "renamed": 1, "removed": 1, "unnamed": 0,
               "refused": 0, "paths": [{"kind": "workspace_relative", "value": "src/parser.rs"}],
               "omitted": 0}},
    {"line": "network", "text": "network: allowed api.anthropic.com:443 (41) · denied github.com:443 (1)",
     "facts": {"bound": "exact",
               "allowed": [{"destination": "api.anthropic.com:443", "results": 41, "connect_failed": 0}],
               "denied": [{"destination": "github.com:443", "reason": "host_not_allowed", "results": 1}],
               "omitted": 0}},
    {"line": "credentials", "text": "credential claude-oauth: vault, never staged · used on 41 proxy results · 0 refusals",
     "facts": {"credentials": [{"id": "claude-oauth", "mode": "vault", "never_staged": true,
                                "uses": 41, "uses_bound": "exact", "transitions": ["loaded"],
                                "refusals": 0}]}},
    {"line": "evidence", "text": "evidence: 6/6 classes active, no gaps · reads and file contents are not observed",
     "facts": {"observe": "on", "evidence": "strict", "classes": {"exec": "active", "fs.write": "active",
               "fs.deny": "active", "net": "active", "proxy.net": "active", "limits": "active"}, "gaps": []}}
  ]
}
```

- `receipt_digest` is the SHA-256 over the final receipt's canonical bytes
  (the value the journal's last `jail.receipt` note carries), so a CI
  artifact names exactly the receipt it summarizes.
- `journal` is `complete`, `incomplete`, `streamed` (`--trace-fd`),
  `not_scanned` (over the scan cap) or `absent`.
- Each entry's `text` is the terminal line without its `ukai-jail: `
  prefix, with the same escaping; `facts` carries the numbers behind it.
  Every count has a bound, `exact`, `at_least` or `not_observed`, and a
  `not_observed` count is `null`, never `0`. Lines absent from the terminal
  form (limits, cleanup) are absent here too, and the terminal's receipt
  path line is replaced by `attempt_id` and `receipt_digest`.
- Lists are capped at 64 entries each with an `omitted` count; the terminal
  shows five. Paths keep the event schema's `{kind, value}` path form;
  destinations are the proxy result's normalized `destination` string.

## 5. Contract changes this implies

| Change | Kind | Notes |
|---|---|---|
| `ukai-jail NAME`, `run/explain/doctor --from-path`, `run --quiet`, `credential set/rm`, `tail --summary [--json]` | CLI | `--from-path` refuses with the gate flags and `none`. `ukai NAME` is not forwarded. |
| **Plain `run`**: a workspace that is `/`, the operator's home or an ancestor of it refuses on every contained run, `policy_widening`, key `--workspace` | Behaviour change for existing `run` invocations (jail-v1 §6.2 defaults the workspace to the invocation directory and has no such refusal) | Deliberate (§3.2, step 3; §7, decision 2). [operating.md](jail-v1/operating.md#commands) and the guide change with it; a script that ran from `~` now refuses with a message naming `--workspace`. |
| Under `--from-path`, argv is the operator's words with the first resolved to an absolute path (and, for `#!/usr/bin/env X`, the interpreter made explicit) | Amends north star §4.5 ("`argv` is always the operator's `--` arguments") | Profile data still never names or rewrites a command; the expansion is the CLI's, shown by `explain`. |
| A missing credential source is skipped when its id is in `credentials_one_of` and another listed source exists | Amends north star §4.5 ("A missing source refuses the launch") and jail-v1 §12 | Every other missing or unsafe source still refuses. |
| `claude`'s declared inputs become a vault setup token or API key, not `.credentials.json` and `settings.json` | Amends the north star §4.5 and jail-v1 §12 profile tables | §3.5 gives the reason. |
| `program_root`, `env`, `binaries = ["@program"]`, `hint`, `credentials_one_of`, `@config/` | Launch-profile grammar (jail-v1 §12) | Data-only; the I02 source test keeps agent names out of code. |
| `roots.cwd`; provenance origin `program-resolution` | Policy snapshot schema (`ukai.jail.policy-snapshot/1`) | Additive; changes policy digests. Re-blessed in place with its fixtures and a dated rationale in [frozen-schemas.toml](jail-v1/frozen-schemas.toml), as earlier additive changes were. |
| `policy.grants[].by` gains the value `program_resolution` (was the constant `operator`) | Receipt schema (`ukai.jail.receipt/1`) | Required (§7, decision 4). Additive value; re-blessed in place in the same commit as the snapshot change. |
| Optional `fields.credentials` (credential ids only) on proxy-source `net.connect` results | Event schema (`ukai.event/1` via `jail-event.schema.json`) | Required (§7, decision 5). Additive and absent when nothing was substituted; `jail-event.schema.json` re-blessed in place with its examples (a new `event-proxy-vault.json`) and a dated rationale in `frozen-schemas.toml`. |
| `ukai.jail.summary/1` | New record (`jail-v1/jail-summary.schema.json`) | A new `[[frozen]]` entry; `validate_contract.py` validates its fixtures (§4.5). |
| `jail.summary` | `config.toml` | Presentation only; not a policy input. |

## 6. Tests and the compatibility run required before "supported"

### 6.1 J12 rows

| Row | Claim |
|---|---|
| K33 | The alias equals `run --launch NAME --from-path -- ARG...` (identical policy and argv digests); built-in verbs win; an unknown word exits 2; `--from-path` with `--gate-fd`, `--attempt-id` or `--profile none` exits 2. |
| K34 | Workspace discovery: a `.git` directory, a `.git` file (worktree, submodule), none (refusal naming `--workspace`), a mount boundary, a symlinked invocation directory; home, its ancestors and `/` refuse, from discovery, from `--workspace` and from the invocation directory of a plain `run` under `agent`, `tool` and `build` (and still run under `none`); a recording `git` placed first on `PATH` is never executed. |
| K35 | The child starts in the invocation directory beneath the workspace; `roots.cwd` is in the snapshot and changes the digest. |
| K36 | Resolution: first absolute `PATH` entry; empty and relative entries skipped; symlink chains canonicalized; the install root is read-only inside (a write fails and is journaled as `fs.deny`); every §3.3 refusal fires with its key and names the root. |
| K37 | Replacing the executable or its root between resolution and release refuses (identity mismatch); no other file runs. |
| K38 | Interpreters: ELF, `#!` inside the runtime roots, `#!/usr/bin/env node` with node outside them (argv expanded, interpreter granted), and each unsupported form refusing with the interpreter named. |
| K39 | Disclosure: each derived grant appears in `explain --from-path` text and JSON, in provenance, in the receipt's `policy.grants` with `by: "program_resolution"` (and an operator's own `--ro` of the same path stays `by: "operator"`), and in the pre-exec line on a terminal; the re-blessed receipt and snapshot schemas validate every example and fixture; with stderr not a terminal nothing is added (X05 suite rerun). |
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
| K53 | `fields.credentials`: present on exactly the proxy results whose upstream request carried a substituted value, listing ids sorted and unique; absent on results with no substitution, on refused requests (`credential_*` reasons) and in every run without a vault credential (journal frames unchanged); never a value, placeholder or digest (searched as the benchmarks' exposure checks do); the re-blessed `jail-event.schema.json` validates the new example; the summary's use count equals the number of results carrying the id, with `at least` when `proxy.net` is degraded and `uses not recorded` for a journal from a build without the field. |
| K54 | `tail --summary --json` validates against `ukai.jail.summary/1`; its `text` fields equal the terminal lines of the same attempt byte for byte (one value, two renderings); `receipt_digest` matches the final receipt; every count from a degraded class carries `at_least`, every unobserved one is `null` with `not_observed`; lists cap at 64 with `omitted`; `--summary` with `--follow` or `--since` exits 2. |

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
  one id with `never_staged: true`, and the summary shows that id's use
  count; `policy.grants` lists the derived install root with
  `by: "program_resolution"` and nothing unexpected; the summary's numbers,
  text and `--json` alike, reproduce from the
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

## 7. Decisions (settled 2026-10-16)

The operator settled the eight questions the first draft left open. Two of
them (2 and 4) override that draft's recommendation; the body above already
follows every choice.

1. **Alias surface.** `ukai-jail NAME` ships as the short form of
   `run --launch NAME --from-path -- ARG...`, and `--from-path` stays the
   long-form flag. The fleet front door does not forward `ukai NAME` (§3.1).
2. **Workspace.** Outside a git repository `--from-path` refuses and asks
   for `--workspace`. The refusal of `/`, the home directory and its
   ancestors applies to every contained `run`, not only `--from-path`. **The
   operator overrode the draft**, which had recommended limiting it to
   `--from-path` so existing scripts kept working: this is a developer
   preview, jail-v2's no-legacy rule updates current behaviour rather than
   preserving it, and a home-directory workspace is the footgun the product
   is sold against (§3.2, step 3; listed in §5 as a contract change for
   plain `run`). Applying it to contained profiles only, since `none`
   grants no workspace, is this document's reading of "every `run`".
3. **Credential order.** Subscription first:
   `credentials_one_of = ["claude-oauth", "anthropic"]`, as proposed (§3.5).
4. **Receipt attribution.** Derived grants are recorded as
   `by: "program_resolution"`. **The operator overrode the draft**, which had
   proposed keeping `by: "operator"` to avoid a receipt schema change; the
   change rides on the snapshot re-bless that `roots.cwd` already needs
   (§3.3, step 6; §5).
5. **Credential uses.** Proxy results gain the optional `fields.credentials`
   (ids only, never values), and the summary prints per-credential use
   counts in proxy results that substituted the credential (§4.2, §4.3, §5,
   K53).
6. **Credential verbs.** `ukai-jail credential set ID` and
   `credential rm ID` ship as specified in §3.5.
7. **Interactive sessions.** J12 stays headless (`-p`). Interactive support
   is the next named milestone, J14 (provisional): a terminal mode without
   the new session when stdin is a terminal, after a security review of
   `TIOCSTI`, `TIOCLINUX` and `legacy_tiocsti`, plus persistent per-profile
   vendor state with its receipt semantics. Outlined in §3.8, not designed
   here.
8. **Off-terminal summaries.** `ukai-jail tail --summary [--attempt ID]`
   with a `--json` form, `ukai.jail.summary/1`, rendered from the same pure
   summary function, for CI logs and a future GitHub Action job summary
   (§4.5, K54).

## 8. J12 as implemented: departures and additions

Recorded with the implementation (2026-10-16), each with its reason. Where
the code is stricter than §3 the text above still describes the intent.

1. **`credentials_one_of` absence.** A source counts as absent when its file
   or a directory on its path does not exist (§3.4 says `ENOENT` on the
   final component only). A fresh host has no `<config-dir>/credentials/`
   at all, and the first run must refuse with every hint (§3.5) rather than
   with one credential's missing directory. A source that exists and is
   unsafe (mode, owner, a second link, a symlink anywhere on its path) is
   still refused, never skipped for the next one.
2. **`@program` on a `#!` script run by a system interpreter refuses**
   (§3.3 step 7 is silent). The kernel reports the interpreter as the
   connecting executable, so a binding to the script would refuse every
   request, and a binding to the interpreter (`/bin/sh`) would admit every
   script it runs. ELF programs and `#!/usr/bin/env X` expansions bind as
   §3.3 says.
3. **The pin also checks owners, and reads "group-writable" as the jail's
   other directory rules do.** The executable and every directory on its
   no-follow walk must be owned by root or the operator, and directories
   above the install root must not be writable by others without the sticky
   bit (§3.3 step 2 names only the write bits from the install root down): a
   file another local user owns can be rewritten in place under the very
   identity a vault credential is bound to. From the install root down, a
   directory's group write is accepted when the group is the owner's private
   group (only the owner is in it), the exception the state, launch and
   credential walks already make: with Ubuntu's default umask 002 a user's
   own install directories are 0775, and the strict reading refused them on
   the reference host. The executable file itself stays strictly neither
   group- nor other-writable, the vault's own executable pin.
4. **"The operator's home"** is both `HOME` and the user database's entry for
   the effective uid, each canonicalized: a workspace or install root at or
   above either refuses.
5. **Where the home refusal applies.** On `run` (with `--label-only`) and
   `learn` under `agent`, `tool` and `build`, and on any verb with
   `--from-path`. `explain` and `doctor` without `--from-path` inspect a plan
   and do not refuse it, so `ukai-jail doctor` still works from a home
   directory.
6. **`roots.cwd` applies to every run**, not only `--from-path` (§3.2 step
   4): the child starts in the invocation directory whenever it lies
   strictly beneath the workspace. The field is omitted from the canonical
   form at the workspace root, so a policy run from its workspace root keeps
   its bytes and digest.
7. **`#!/usr/bin/env X` follows §3.3 step 5 literally**: it is expanded only
   when `X` resolves outside the runtime roots and that `env` is the runtime
   roots' own; with `X` inside them it is a `#!` script with a system
   interpreter, so `@program` refuses it as in item 2 (adversarial review F2:
   binding the credential to `/bin/sh` or `/usr/bin/node` would admit every
   script it runs).
8. **Identity mismatch is `policy_widening`** at key `--from-path` (exit 125),
   before release (§3.3 step 3 names no code). A staged `@program` credential
   whose pinned executable is not the resolved one refuses the same way.
9. **`doctor` additions are text only**: credential hints, the
   `credentials_one_of` line, the verb shadowing, "interactive sessions
   unrecorded", the resolved program and its roots, the expanded-interpreter
   binding note and the linked-worktree note. The `ukai.jail.doctor/1` JSON
   is unchanged (§5 lists no doctor schema change). `doctor --from-path`
   that cannot resolve the program fails with that refusal instead of
   printing a report.
10. **`explain` resolves `credentials_one_of` as `run` does**, so with no
    source present it refuses with every hint; `doctor` inspects every
    declared credential instead.
11. **`explain --json`** carries a top-level `program` object (name, path,
    format, interpreter, argv prefix, each root with `granted` or `covered`)
    beside the snapshot; the snapshot itself gains the derived read-only
    roots and `roots.cwd`. The program path and argv are not snapshot
    fields: argv has its own digest.
12. **Vault `env`** additionally refuses `SSL_CERT_FILE`,
    `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE`, which the vault points at
    its per-attempt CA (a placeholder there would never arrive).
13. **The pre-exec line** lists every root: `read-only: R` for a grant,
    `already readable: R under ROOT` for a covered one (the npm layout of the
    spike record, where the install root lies under `/usr`).
14. **`credential set` on a terminal reads until end of input** (Enter, then
    Ctrl-D), with echo off: reading one line would silently keep the first
    half of a wrapped paste, the spike's failure. A malformed id exits 2,
    a refusal 1; `credential rm` of an absent id exits 1.
15. **Mach-O** is accepted as a native executable on macOS, where execution
    is refused; it only decides what `explain` reports there.
16. **The milestone freeze records `program_root` and `credentials_one_of`**
    per bundled launch profile: one changes what is mounted, the other which
    credential is staged.
17. **K34's mount boundary** is tested on the walk's decision function with
    synthetic devices; a test cannot mount a filesystem unprivileged.
18. **Symbolic links the `PATH` lookup follows** must lie outside every
    child-writable root (bind aliases included) and in a directory owned by
    root or the operator and not writable by others without the sticky bit
    (adversarial review F1). §3.3 step 1 skips relative entries because the
    repository would otherwise pick the program; an absolute entry inside
    the repository (direnv, `node_modules/.bin`, a `.venv`) shipping a link
    to some other trusted file did the same. The `env` word lookup is held to
    the same rule.
19. **A program the operator owns must have exactly one name** (review F3),
    as a credential source must: a second name inside the workspace (a
    bun or pnpm hard-linked store) would let the agent rewrite the host
    program in place. A root-owned file with several names is accepted (a
    non-root operator's agent cannot write it). The recheck before release
    also compares size, modification and change times and the link count.
20. **The window §3.3 step 3 leaves, closed for the program's own file
    when it is ELF** (review F5). The recheck before release covers the
    program up to the release. After the release, as the last thing before
    the exec, the launcher checks every pinned executable again against what
    resolution recorded: `(dev, ino)`, size, modification and change times,
    link count and mode (its `--pin` options). Not the owner: inside the
    jail's user namespace a root-owned program's owner reads as the overflow
    uid, and a `chown` moves the change time anyway; the recheck before
    release compares the owner on the host.
    - **An ELF file at argv 0** (`E`, or `X'` after an expansion) is opened
      `O_PATH` by the launcher before the release, checked through that
      descriptor, and executed through it with
      `execveat(fd, "", AT_EMPTY_PATH)`: no rename after the check can make
      another file the program. The link count and the change time catch a
      file renamed over it, given another name, written in place, `chmod`ed
      or `chown`ed since resolution.
    - **A `#!` script** (`E` run by a system interpreter, or `E` after an
      expansion) is opened again by its path, by the kernel and then by the
      interpreter, so it is checked by path immediately before the exec.
    - A changed program is refused after the release as an exec error:
      `outcome.cause` `ESTALE`, `outcome.error.code` `policy_widening` at
      `--from-path`, exit 125, nothing executed. A pinned file the launcher
      cannot open (before the release) or stat (after it) is refused with
      that call's errno as an ordinary `exec_failed`, nothing executed.

    Proved on the reference host, through the CLI with a test seam
    (`UKAI_JAIL_TEST_PROGRAM_SWAP`) that holds the supervisor after its
    recheck (`from_path_linux.rs`, `f5_*`): an ELF program renamed over or
    written in place, and a script renamed over, are refused under `tool`
    and `agent`; with the program's directory renamed away and another file
    put at its path after the launcher's open, the pinned program is what
    runs, and the observer confirms its exec by the pinned inode; a
    root-owned program runs. On the launcher directly
    (`linux_mechanisms.rs`): the descriptor is held before the release and
    not by the target, a directory swapped around the launcher's open is
    refused, and X04's interpreter-missing detail holds for an exec through
    the descriptor. What remains:
    - **Files other than the program.** The pin covers the executable file
      alone; whatever else the program runs is opened by path. Since review
      F2 of this fix (item 24), its ELF loader, and every place its dynamic
      section lets the loader open a library from, must lie in the runtime
      roots where only root can change them. What the loader takes from the
      system's own directories and configuration, and files the program
      opens once it runs, remain (item 24).
    - **A write in place in the last instant:** a write and a close that both
      fall between the launcher's `fstat` and the kernel's refusal of writers
      inside `execveat` (two consecutive calls of the launcher). A writer
      still holding the file open then makes the exec fail with `ETXTBSY`,
      and no writer can open the file while it runs (both checked by hand on
      the reference host, kernel 7.0).
    - **Coarse change times:** where the kernel or filesystem keeps change
      times at clock-tick granularity, a same-size write within the same
      tick as the file's previous change leaves size and times unchanged.
      This bounds the recheck before release as much as the launcher's
      check.
    - **A script** renamed over, or a directory above it renamed, between
      its check by path and the kernel's or the interpreter's open. The
      replacement runs contained; a system-interpreter script carries no
      `@program` credential (item 2), and after an expansion the credential
      is bound to `X'`, which already admits any script it runs (§3.3
      step 7).

    The exec of a pinned ELF program is recorded as the call it is: the
    audit's `proc.exec` names `execveat` with an empty path
    (`{kind: unavailable, reason: empty_path}`) and `path_dirfd` (the
    `f5_*` test checks the call and the path). The program can tell it was
    executed this way: its `AT_EXECFN` is `/dev/fd/N`, not its path (argv 0
    and `/proc/self/exe` are unchanged; `linux_mechanisms.rs` shows it under
    `LD_SHOW_AUXV`). A program that names itself from `AT_EXECFN` sees a
    descriptor number: on the reference host, uutils' multi-call coreutils
    then refuses to run ("unknown program '4'", checked by hand), and
    `/proc/PID/comm` is the file's name there; older kernels are reported
    to name a process executed this way after the descriptor number (not
    checked here).
21. **The home refusal also compares identities** (review F4): a workspace or
    install root that is the home, `/` or an ancestor of the home by
    `(dev, ino)` refuses, so a bind-mount alias of the home does too.
22. **Disclosure of a denied root and of a nested repository** (review F6,
    F7): a derived root a `deny_read` covers is shown as denied in `explain`
    (`denied_by`) and the pre-exec line; from inside a nested repository
    `explain` and `doctor` name the outer repository whose `ukai.toml` does
    not apply.
23. **`credential set` restores the terminal on a signal** (review I3):
    Ctrl-C, TERM, HUP or QUIT puts echo back before the process ends.
24. **The loader and the library search path stay in the runtime roots,
    where only root can change them** (review F2 of the F5 fix,
    2026-10-17). The kernel opens an ELF program's loader by path at the
    exec, and the loader opens its libraries by path, so a file a process
    running as the operator replaces there would run inside the pinned
    program, which a `@program` credential is bound to. J12 accepted a
    loader inside the install root and did not look at libraries.
    - **One rule for every such path** (`program::reach_in_runtime_roots`):
      followed as the kernel follows it (links, `..` after the link before
      it, at most 40 links), every location it passes through and the one
      it ends at must lie in the runtime roots (`/usr`, `/bin`, `/lib`,
      `/lib64`, which every contained profile binds read-only at their own
      paths), and every one of them, `/` included, must be owned by root
      and writable by neither its group nor others (a link's own mode
      aside: replacing a link takes a write to its directory). A path that
      ends at a missing name, a file used as a directory or a link loop
      inside them names nothing there; any other resolution error refuses.
      So a location in an install root, in a child-writable root, in the
      working directory, or in a directory under `/usr` that the operator
      owns (a chowned `/usr/local`) or a group can write, refuses.
    - **§3.3 step 5 is enforced as written:** the loader (`PT_INTERP`) must
      pass that rule. A loader in an install root outside the runtime
      roots, a link
      outside the runtime roots to a system loader, and a `..` that leads
      outside them refuse with `exec_interpreter_missing`, as do a missing
      loader and one that cannot be followed: inside the jail such a path
      names something else or nothing. A loader in the runtime roots that
      someone other than root could replace refuses with `policy_widening`.
    - **The library search path passes the same rule.** The dynamic
      section of the pinned ELF file (`E`, or `X'` after an expansion) is
      read as the dynamic loader reads it: at its address, mapped through
      the `PT_LOAD` segments (not at `PT_DYNAMIC`'s file offset), up to
      `DT_NULL`. Every `DT_RPATH` and `DT_RUNPATH` entry (separated by `:`,
      and by a newline as musl does), with `$ORIGIN` expanded to the
      program's own directory (what `/proc/self/exe` names inside), and
      every library named by a path in `DT_NEEDED`, `DT_FILTER`,
      `DT_AUXILIARY`, `DT_AUDIT` or `DT_DEPAUDIT` must pass it. A name with
      neither a `/` nor a `$` is searched for on that path and in the
      system's own directories. Refused, `policy_widening` at
      `--from-path`, naming the program, the tag and the entry: an entry or
      library path that fails the rule (so any `$ORIGIN` entry of a program
      in an install root the operator owns); an empty entry, which glibc
      searches as the working directory, and a relative one, searched from
      the working directory, inside the repository the agent writes; an
      entry with another `$` token (`$LIB`, `$PLATFORM`), whose value
      resolution does not know; a library name holding a `$` anywhere
      (glibc expands a token there before deciding whether the name is a
      path, so `${ORIGIN}x` becomes one; musl never expands it); and a
      relative library path. In each search directory that exists and
      passes, the file the loader would take for a name without a `/`
      (there, or in the directory's `glibc-hwcaps` subdirectories) must pass
      too: only root can add a name to the directory, but a file in it need
      not be root's (an operator's library moved there with `sudo mv`). The
      check runs whether or not the file names a loader, and follows each
      distinct path once.
    - **Headers this check would read otherwise than a loader** refuse as
      `invalid_config`, among them: a dynamic section or string table outside the
      loaded segments, a string outside its table, a table with no
      `DT_NULL` within its size (the loaders read on), several `PT_INTERP`
      headers (the kernel opens the first; musl names itself after the
      last) or several `PT_DYNAMIC` headers (glibc reads the last), a
      program header size other than the kernel's, and more than 1 MiB of
      library names and search paths in all (real programs hold a few
      hundred bytes).
    - **Why refuse rather than pin those libraries:** the loader opens them
      by path after the exec, which no descriptor the launcher holds can
      govern, so a pin would narrow that window, not close it. The refusal
      breaks no agent checked: on the reference host, the native binary of
      Claude Code 2.1.295 (the npm package's `claude.exe`) and OpenCode
      1.19.0's binary both name `/lib64/ld-linux-x86-64.so.2`, carry no
      `DT_RPATH` or `DT_RUNPATH`, and need only system libraries named
      without a `/` (`readelf`), and `explain --from-path` with this change
      resolves both. Codex 0.159.2's Linux binary (a copy an earlier
      benchmark left on the reference host) is a static-pie executable: a
      dynamic section, no loader and no library entries; it resolves too.
      Installed through npm (0.156.1, inspected on macOS), Codex's entry
      point is a `#!/usr/bin/env node` script, so its pinned ELF file would
      be `node`. Ubuntu's `/usr/bin/node`, as the program itself
      (`ukai-jail node`), carries `DT_RUNPATH` `$ORIGIN/../lib:$ORIGIN/`,
      which stays in root's `/usr`, so it resolves; the same file copied
      into an install root is refused. All checked by hand on the
      reference host with this change, 2026-10-17. Programs that find libraries shipped beside them
      through `$ORIGIN`, such as a conda or uv Python, an Electron app or a
      JDK unpacked in the home directory, are refused under `--from-path`;
      run them with explicit grants and without `@program`.
    - The runtime roots here are the four every contained profile binds.
      `tool` also binds `/sbin`, `/lib32` and `/libx32`, so a loader there
      (an x32 program's) is refused, which J12 accepted.

    Proved by unit tests in `program.rs` (`review_f2_*`, with the review's
    `review_f2k_*` and `review_f2r2_*`): each refusal above, under `DT_RUNPATH` and `DT_RPATH`
    alike, and the forms that pass; the loader read and a `DT_RUNPATH`
    refusal in 32- and 64-bit images of both byte orders; a decoy table at
    `PT_DYNAMIC`'s file offset; an entry past `DT_NULL` (ignored); virtual
    addresses and file sizes, not physical addresses or memory sizes;
    `$ORIGIN` as the program's own directory, not its install root; the
    interpreter an expansion pins; each header refusal and bound; the owner
    and mode rule on this operator's home directory, on `/tmp` and on a
    group-writable directory root owns (`/var/mail` where one exists), each
    taken as runtime roots for the test, on `/` through a test seam that
    stands another directory in for it, and a system file passing it; a
    41st link as unreachable; and, on Linux, the host shell's real headers.
    Where `/usr/bin` holds a file root does not own alone (macOS, whose uucp
    tools belong to `_uucp`), the review's tests also show it refused as a
    loader (`policy_widening`), as a library path and as a library found by
    name in a passing `DT_RUNPATH` directory; on the reference host no such
    file exists, so there those three say so and pass. On the reference host through
    the CLI (`from_path_linux.rs`, `f2_*`), under `tool` and `agent`: the
    host's `/bin/sh` patched to use a copy of the host's loader in its
    install root, and patched with a relative `DT_RUNPATH`, each runs on
    the host and is refused by the jail with nothing run; synthetic
    programs with a `$ORIGIN` entry and with an entry inside the
    repository are refused the same way; and `/proc/self/exe` names a
    program executed through the launcher's descriptor by its own path.
    What remains:
    - **What the loader takes without a path to check:** the system's own
      library directories; a library a dependency needs, which glibc also
      seeks in the program's `DT_RPATH` directories (only the program's own
      names are looked up there); the hardware-capability subdirectories
      other than `glibc-hwcaps` that glibc before 2.37 searched; and its
      configuration (`/etc/ld.so.cache`, bound where present, can name
      directories elsewhere). These are trusted as the system's own.
    - **Owners and modes are taken as the filesystem reports them:** a
      FUSE filesystem the operator mounted on a directory it owns under
      `/usr` could report root's for files it serves (by reading; none on a
      stock host, and the directory would have to exist first).
    - **Files the program opens once it runs:** a library it loads later by
      a path of its own, or scripts and data it reads from the install
      root. A process running as the operator that replaces one runs its
      code inside the program the credential is bound to.
    - **A program file crafted to disagree with itself** (a `PT_INTERP`
      whose address shows another string than its file offset, overlapping
      `PT_LOAD` segments, a `PT_PHDR` the loader would read otherwise) is
      not refused: its own code runs as the program anyway.
    - Out of this item's scope: a process inside the jail that starts the
      pinned program again chooses its environment (`LD_PRELOAD`,
      `LD_LIBRARY_PATH`), and the vault identifies a connection's process by
      its executable. No file rule addresses that (by reading; not tested
      here).
