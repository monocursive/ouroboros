# Agent compatibility

Real agent runs under `ouro-jail` (jail-v1 §15 row A01, north star §7.4). A
record marks only the tested profile, vendor version, platform and jail mode
supported; every other combination stays experimental. No record stores a
token, a credential, or a vendor-state archive.

| Agent | Vendor version | Ouroboros revision | Platform | Jail mode | Credential | Result |
|---|---|---|---|---|---|---|
| OpenCode | 1.18.32 | `3c3638c4` (profile at `156e645d`) | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64, bubblewrap 0.11.1, stock host | `agent`, observation on, strict evidence | none (OpenCode Zen free model `big-pickle`) | Passed: wrote the requested workspace file; receipt settled, exit 0, every coverage class active |
| OpenCode | 1.18.32 | — | same | same | operator's own provider (`opencode auth login`) | Not yet run |

## OpenCode 1.18.32, `agent`, no credential (2026-09-23)

Evidence: [run record](evidence/a01-opencode-run-2026-09-23-ubuntu.txt) and
[receipt](evidence/a01-opencode-receipt-2026-09-23-ubuntu.json).

- **How it ran.** As the operator's own account, with the bundled
  [`opencode` launch profile](../../../crates/ouro-jail/profiles/launch/opencode.toml)
  copied to `~/.config/ouro/launch/`, the OpenCode install granted read-only
  (`--ro ~/.opencode/bin`) and a git repository as the workspace:
  `ouro-jail run --launch opencode --ro ~/.opencode/bin -- ~/.opencode/bin/opencode run "…"`.
- **What it did.** Its write tool created `greeting.txt` containing `hello`;
  the audit source recorded that `fs.create`. It reached `opencode.ai` (model
  API), `models.opencode.ai` (catalog) and `registry.npmjs.org` (packages it
  installs at run time) through the proxy, and nothing else.
- **What the jail needed fixing first.** Connects from worker threads were
  refused by the unix-peer mediation (`92e7db7c`), and the default state root
  was refused on a stock Ubuntu home (`3c3638c4`). Both are fixed and pinned
  by tests on the reference host; the full conformance suite passes with them
  ([run `20260923T135525Z-156e645db813`](evidence/a01-test-log-2026-09-23-ouro-ci.txt),
  1022 passed, 0 failed).
- **Known behaviour.** In 1 of 16 repeat runs a file operation was still in
  flight in a thread when OpenCode exited; strict evidence reported the loss
  and `ouro-jail` exited 1, with the target's own exit 0 kept in the receipt.
  Several runs stalled in OpenCode's start-up, after its run-time package
  installs, until the wall limit (the run record gives the counts); the cause
  is not established and is an open item.
- **Operator notes.** Use a git repository as the workspace: OpenCode walks up
  from the working directory looking for `.opencode` directories, and outside
  a repository it can reach its own install directory above the workspace,
  which the jail shows read-only. Another provider needs its credential
  staged (the profile's commented `auth.json` input) and its API host added to
  `network.allow`.
