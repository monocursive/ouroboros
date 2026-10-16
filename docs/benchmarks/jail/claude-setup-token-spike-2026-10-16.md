# Claude Code setup token through the vault — 16 October 2026

The [launch-and-summary proposal](../../specs/jail-launch-and-summary.md)
recommends giving Claude Code subscription users a `claude setup-token`
OAuth token through the vault, so the agent only ever holds a placeholder.
Its §6.3 lists vendor facts that had to be measured before J12 is built:
which header carries `CLAUDE_CODE_OAUTH_TOKEN`, whether the client accepts a
placeholder, which hosts a first run contacts, whether `home_is_state` is
needed, whether any request comes from another executable, and which
interpreter case applies. This record measures them.

It is a spike, not the §6.3 compatibility row and not a support claim. The
jail was an archive build without git metadata, Claude Code came from npm
rather than the native installer, the profile was an operator file rather
than the bundled one, the launch used today's long form (no alias exists
yet), and the task was one fixture.

## What ran

The operator profile [claude-oauth.toml](results/claude-setup-token-spike-2026-10-16/claude-oauth.toml),
in a private `UKAI_CONFIG_DIR`, vaults the token from a 0600 source outside
every child grant, declares `header = { name = "authorization", prefix = "Bearer " }`
for `https://api.anthropic.com` only, and binds the credential to the
Claude Code executable with `binaries`. [run.sh](results/claude-setup-token-spike-2026-10-16/run.sh)
starts each run in a fresh git repository:

```sh
ukai-jail run --launch claude-oauth --workspace "$ws" --limit wall=240s --receipt "$rd/jail.json" -- \
  /bin/sh -c 'export CLAUDE_CODE_OAUTH_TOKEN="$UKAI_VAULT_CLAUDE_OAUTH"; exec /usr/bin/claude "$@"' claude-wrap \
  -p "Create a file named greeting.txt containing the single word hello." \
  --model sonnet --max-turns 15 --dangerously-skip-permissions --output-format json
```

The `--model`, `--max-turns`, permission and output flags match the
[credential benchmark](../credentials/2026-10-12/README.md)'s Claude Code
invocation; `sonnet` resolved to `claude-sonnet-5-5`.

Before the jailed runs, a direct control (no jail, the raw token in
`CLAUDE_CODE_OAUTH_TOKEN`, a throwaway `CLAUDE_CONFIG_DIR`, prompt "Reply
with the single word ok.") answered `ok` in 3.22 s. An earlier control with
a token cut at a terminal line wrap (79 of 108 bytes) got
`401 OAuth access token is invalid`, which is how the truncation was found.
The control runs' files stayed on the host and are not part of this record.

## Where

From [host.txt](results/claude-setup-token-spike-2026-10-16/host.txt):

| Fact | Value |
| --- | --- |
| Host | The Linux reference host: Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic, x86_64, account `ubuntu` |
| Backend | bubblewrap 0.11.1 |
| Source | `git archive` of local `dev` at `945fd370d`, so the build reports `revision unknown` |
| Build | `cargo +1.98.1 build --release --locked -p ukai-jail`, build inputs `sha256:20fa57b7322c69a757340c06c23bb518b6486ed7de6988cf5b34ddf8d8b49651` |
| Jail binary | `sha256:f1e40288bf6668e09c1d7d51d55c5f51005aacd929f2b55518a5cae6d14ff9fe` |
| Claude Code | 2.1.295, npm global install; `/usr/bin/claude` links to `/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`, an x86_64 ELF, `sha256:4503bfe11a6c7fcc1e0b39b5e0d347c04248f750b03b0977b3ad6b531fe6f358` |
| State | `UKAI_CONFIG_DIR` and `UKAI_DATA_DIR` in private scratch directories |

`doctor --launch claude-oauth` reported `ready true`, with the launch
`experimental` (`no_recorded_run`) and the credential `available`.

## Results

Eleven consecutive runs, all passing
([runs-summary.txt](results/claude-setup-token-spike-2026-10-16/runs-summary.txt),
[runs-exit.txt](results/claude-setup-token-spike-2026-10-16/runs-exit.txt)):

| | Every run (11/11) |
| --- | --- |
| Task | `greeting.txt` is `hello\n`; Claude Code reports `is_error: false` after 2 turns |
| Receipt | `settled`, exited 0, no errors, `tree_empty: true`, `state_cleanup: complete` |
| Coverage | All six classes `active`, no gaps |
| Credential | `claude-oauth`, mode `vault`, `never_staged: true`; journal note `loaded` |
| Network | 4 proxy results, all `api.anthropic.com:443`, `allow`, `relayed`; no denied destination |
| Files | 0 `fs.deny` events |
| Wall | Median 8.45 s, range 3.72–15.09 s, measured around `ukai-jail run` |

The wall times include the model's own latency and have no direct baseline
for the same fixture, so they support no overhead figure. r1's
[receipt](results/claude-setup-token-spike-2026-10-16/r1-jail.json),
[policy](results/claude-setup-token-spike-2026-10-16/r1-policy.json),
[journal](results/claude-setup-token-spike-2026-10-16/r1-trace.ndjson) and
[Claude Code output](results/claude-setup-token-spike-2026-10-16/r1-claude-stdout.json)
are kept; its receipt counts 23 `exec`, 122 `fs.write`, 8 `net` and 4
`proxy.net` events.

## The vendor facts

| §6.3 question | Answer on this build | Evidence |
| --- | --- | --- |
| Which header carries `CLAUDE_CODE_OAUTH_TOKEN`? | `Authorization: Bearer <token>` | The vault refuses any request line containing `vault:` unless its name and prefix match a declared header exactly (`inject_bound` in `crates/ukai-jail/src/vault.rs`, `CredentialPlacementDenied`). All 44 proxy results were relayed and the model answered, so the placeholder appeared only in `Authorization` after `Bearer `. |
| Does the client check the token's shape? | No | The child held `vault:att_…:claude-oauth` ([child-env.txt](results/claude-setup-token-spike-2026-10-16/child-env.txt)), nothing like `sk-ant-oat01-…`, and still sent its requests. |
| Which hosts does a first run contact? | Only `api.anthropic.com:443`, with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | 4 proxy results per run, none denied; `platform.claude.com` was not contacted. Without that variable: not measured. |
| Is `home_is_state` needed? | Not for this `-p` fixture | `HOME` is unset in the child and every run recorded 0 `fs.deny` events. |
| Does a request come from another executable? | No | The credential was bound to `claude.exe` with `binaries`; no `credential_process_denied` result occurred. |
| Which §3.3 interpreter case applies? | ELF, no expansion | The npm package ships the native binary. Its directory lies under `/usr`, already a read-only runtime root, so the derived install grant would add nothing on this layout. |

**Exposure.** A fixed-string search for the token's value (`grep -rlF -f`
on its source file) found it in none of the eleven workspaces, run outputs
(Claude Code's stdout and stderr), attempt directories (receipt, policy,
journal, jail state) or the exported files in this record. This covers
files only; unlike the credential benchmarks' sampler, it did not sample
process memory or other processes' environments. The child's environment
listing shows only the placeholder.

## What this changes in the proposal

- The bundled profile's `header = { name = "authorization", prefix = "Bearer " }`
  is measured, not guessed, for Claude Code 2.1.295; §3.5's "measured, not
  documented" note can cite this record.
- `home_is_state` is not needed for headless runs on this version.
- A token pasted from a wrapped terminal line arrives with a line break.
  `read -r` silently kept only the first line, and the result failed with a
  401 only when used. The proposed `ukai-jail credential set` requires
  printable ASCII, so it would refuse such a paste. Its refusal should
  name the cause ("the value contains a line break; a token copied from a
  wrapped terminal line must be rejoined") rather than only the byte rule.
- On npm installs the install root is under `/usr`, so `--from-path`
  derives a grant that duplicates a runtime root. `explain` should show it
  as such rather than as new access.

## Not established

The §6.3 row itself: a clean revision, the native installer, the bundled
profile and the alias. Interactive sessions. The API-key fallback and
`credentials_one_of` (not implemented). Live revocation and expiry with
this source (the vault's revocation path is source-agnostic and was
measured with API keys on [13 October](../credentials/2026-10-13/README.md)).
Runs without `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`. Other Claude Code
versions and hosts. Real tasks beyond the fixture.
