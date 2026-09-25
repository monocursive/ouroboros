# Agent compatibility

Real agent runs under `ouro-jail` (jail-v1 §15 row A01, north star §7.4). A
record marks only the tested profile, vendor version, platform and jail mode
supported; every other combination stays experimental. The support claim
lives here, not in the binary: `doctor` reports every launch profile
`experimental` (jail-v1 §§14.1, 15, revision 19). No record stores a token, a
credential, or a vendor-state archive.

| Agent | Vendor version | Ouroboros revision | Platform | Backend | Jail mode | Credential | Result |
|---|---|---|---|---|---|---|---|
| OpenCode | **TO BE FILLED** | **TO BE FILLED** (the milestone revision) | **TO BE FILLED** | bubblewrap adapter and ptrace observer; filter digests **TO BE FILLED** from the receipt | `agent`, observation on, strict evidence | none | **TO BE FILLED** ([milestone run](#opencode-agent-no-credential-at-the-milestone-revision)) |
| OpenCode | 1.18.32 | `3c3638c4` (profile at `156e645d`) | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64, stock host | bubblewrap 0.11.1, ptrace observer; pre-J4 filters (below) | `agent`, observation on, strict evidence | none (OpenCode Zen free model `big-pickle`) | Passed: wrote the requested workspace file; receipt settled, exit 0, every coverage class active |
| OpenCode | 1.18.32 | `3c3638c4` (profile at `156e645d` with its `auth` input enabled and `api.z.ai` allowed) | same | same | same | the operator's own Z.AI Coding Plan key (`opencode auth login`), staged `copy_rw` | Passed: GLM-5.3 wrote the requested workspace file; receipt settled, exit 0, every coverage class active; the key reached no record |

The two 2026-09-23 runs predate J4 and the milestone freeze. Their receipts
record the `agent` filter `sha256:e2108d4f9e9e9b222f946f375af699707a491a637e9914df45a95b3f33affb75`
and the narrowing filter
`sha256:4e2c1ab0a6ca9263da038faae8b71fb59d2989a259efc8a067ccddd372a3e2d8`;
the frozen ones are in [milestone-1-freeze.toml](milestone-1-freeze.toml).
They are kept as the history of what the first real runs required; the
milestone's A01 record is the run below.

## OpenCode, `agent`, no credential, at the milestone revision

**TO BE FILLED** by the milestone run: the date; the Ouroboros revision (the
milestone revision, and the receipt's `build.revision` if the binary carries
it); the OS, kernel and architecture; the backend and its version, and the
`agent`, mediation and narrowing filter digests the receipt records, compared
with [milestone-1-freeze.toml](milestone-1-freeze.toml); the OpenCode version;
the launch profile (the bundled `opencode` profile, and any change to it); the
command; the result (receipt phase, outcome, exit code, coverage, and what the
proxy reached); and the evidence files (`evidence/a01-opencode-run-<date>-ubuntu.txt`
and `evidence/a01-opencode-receipt-<date>-ubuntu.json`). Whether the
start-up stall recorded below recurred: **TO BE FILLED**.

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
  and with `8a5ab780` merged
  ([run `20260923T152341Z-6c6588d174e3`](evidence/a01-test-log-2026-09-23-ouro-ci.txt),
  1026 passed, 0 failed).
- **Known behaviour.** In 1 of 16 repeat runs a file operation was still in
  flight in a thread when OpenCode exited; strict evidence reported the loss
  and `ouro-jail` exited 1, with the target's own exit 0 kept in the receipt.
  Several runs stalled in OpenCode's start-up, after its run-time package
  installs, until the wall limit (the run record gives the counts); the cause
  is not established and is an open item (see also the credentialed run).
## OpenCode 1.18.32, `agent`, the operator's own credential (2026-09-23)

Evidence: [run record](evidence/a01-opencode-zai-run-2026-09-23-ubuntu.txt) and
[receipt](evidence/a01-opencode-zai-receipt-2026-09-23-ubuntu.json).
The public copy of the credentialed receipt omits the credential's content
digest: it carries `digest: null` with `digest_unavailable_reason:
"redacted_in_public_copy"`, because the real digest is a hash of the
operator's credential. The product wrote a digest; every other field is as
the product wrote it.

- **How it ran.** The operator logged in with `opencode auth login` on the host
  (Z.AI Coding Plan). The profile's `auth` input copied
  `~/.local/share/opencode/auth.json` into vendor state; `api.z.ai`, found as a
  proxy denial on a first run, was added to `network.allow`;
  `opencode run --model zai-coding-plan/glm-5.3 "…"`.
- **What it did.** GLM-5.3 wrote `greeting-zai.txt` containing `hello`; the
  audit source recorded the `fs.create`; the proxy reached `api.z.ai`, the
  catalog and the npm registry only.
- **Credential hygiene.** Vendor state, with the staged copy, was removed at
  settlement; the key's value is in none of the receipt, trace, jail state,
  policy, receipt copy or OpenCode's output (searched without printing it).
- **Stall.** The first run with this profile stalled like the others. Every
  stalled run completed OpenCode's run-time plugin install before its first
  model request and then went silent; the downloads themselves had completed.
  It did not recur in 110 later runs on either the merged or the pre-merge
  build (the run record has the hunts), so no fix is claimed and the trigger
  stays open.

## Notes for both runs

- **Operator notes.** Use a git repository as the workspace: OpenCode walks up
  from the working directory looking for `.opencode` directories, and outside
  a repository it can reach its own install directory above the workspace,
  which the jail shows read-only. Another provider needs its credential
  staged (the profile's commented `auth.json` input) and its API host added to
  `network.allow`.
