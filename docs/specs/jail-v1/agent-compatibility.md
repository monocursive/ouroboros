# Agent compatibility

Real agent runs under `ouro-jail` (jail-v1 §15 row A01, north star §7.4). A
record marks only the tested profile, vendor version, platform and jail mode
supported; every other combination stays experimental. The support claim
lives here, not in the binary: `doctor` reports every launch profile
`experimental` (jail-v1 §§14.1, 15, revision 19). No record stores a token, a
credential, or a vendor-state archive.

Current embedded starter profiles: `opencode`, `claude`, `codex`, `cursor`,
`aider`, `goose`, `gemini`, `amp`, `cline`, `copilot`, `kilo`, `auggie`,
`droid`, and `pi`. Combinations remain **experimental** beyond the exact evidence recorded below.
The October 8 current-input matrix has mixed results and incomplete repetitions;
its successful cases do not establish general reliability.
`doctor --launch` proves resolution and host capabilities, not vendor
compatibility. The historical rows below retain their original scope.

| Agent | Vendor version | Ouroboros revision | Platform | Backend | Jail mode | Credential | Result |
|---|---|---|---|---|---|---|---|
| OpenCode | 1.18.32 | clean `16ee37fe`; current Jail inputs `2989fb4983de…` | Fresh Ubuntu 26.04.1 VM, Linux 7.0.0-34, x86_64 QEMU TCG | bubblewrap + ptrace; bubblewrap version unrecorded | `agent`, observation on, strict evidence; separate `learn` run | none (`opencode/big-pickle`) | Signed installation, contained `true`, real glob/read/write workflow and verified settlement passed in 62.2 s. Learning proposed an evidence-supported exact-read subset with receipt-bound coverage. Single fixture only; reliability remains experimental ([October 10 record](../../benchmarks/jail/release-preview-2026-10-10.md)) |
| OpenCode | 1.18.32 | clean `f933105e`; inputs `0abe3b09146a…`, unchanged at `d0bc346d` | Fresh Ubuntu 26.04 VM, x86_64 | bubblewrap 0.11.1, ptrace | `agent`, observation on, strict evidence | none (`opencode/big-pickle`) | Signed install, real glob/read/write workflow and clean settlement passed in 82.85 s; exact fixture scope only ([October 8 evidence](../../benchmarks/jail/validation-2026-10-08.md)) |
| Gemini CLI | 0.63.0 (npm, `#!/usr/bin/env node` shim) | clean `38a51a43` | Reference VPS, Ubuntu 26.04.1, Linux 7.0.0-31, x86_64 | bubblewrap 0.11.1, ptrace | `agent`, observation on, strict evidence | none | Passed: the npm-shim entry exec'd and confirmed under strict evidence (`exec_observed`, coverage active, no gaps), printed its version and settled at exit 0 — the `#!`-shim shape the 2026-10-08 H2 fix opened. Version-flag scope only, no provider traffic; the first npm-shim row. Under plain `agent` the CLI's exit-time cleanup warns about `$HOME/.gemini`; the bundled `gemini` launch profile maps those directories (`home_is_state`) and remains experimental and unrecorded |
| OpenCode | 1.18.32 | clean `f933105e`; current inputs `0abe3b09146a…` | Reference VPS, Ubuntu 26.04.1, Linux 7.0.0-31, x86_64 | bubblewrap 0.11.1, ptrace | `agent` on/off plus direct controls | none (`opencode/big-pickle`) | Mixed, incomplete matrix: deadlines and provider rate limits; missing ripgrep reproduced and supplied-tool regression fixed. Remains experimental ([record](../../benchmarks/jail/validation-2026-10-08.md)) |
| OpenCode | 1.18.32 | archive build, null git metadata; current inputs `0abe3b09146a…` | Raspberry Pi, Debian 13, Linux 6.18.50+rpt-rpi-v8, aarch64 | bubblewrap 0.12.0, ptrace; provisioned Unix diagnostics | `agent` on/off plus direct controls | none (`opencode/big-pickle`) | Real tasks passed, but repeated matrix hit deadlines and remained incomplete; supplied-tool regression passes. Memory cgroups/Landlock still unavailable ([record](../../benchmarks/jail/validation-2026-10-08.md)) |
| OpenCode | 1.18.32 | `41d8c230716877b5da6e6db3220017b7eb685344`, clean; inputs `f5486df58917…` | Fresh Ubuntu 26.04.1 VM, Linux 7.0.0-34, x86_64 QEMU TCG | bubblewrap 0.11.1, ptrace | `agent`, observation on, strict evidence; embedded profile | none (`opencode/big-pickle`) | Passed A01 execution and signed non-TTY onboarding in 67.32 seconds ([fresh VM evidence](../../benchmarks/jail/onboarding-2026-09-30.md)); other distributions retain explicit refusals |
| OpenCode | 1.18.32 | `2c8f28dc` + dirty implementation; inputs `fa366f0c8236…` | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64 | bubblewrap 0.11.1, ptrace | `agent`, observation on, strict evidence | none (`opencode/big-pickle`) | Passed execution, learning and proposal validation ([current evidence](#opencode-current-implementation-2026-09-28)) |
| OpenCode | 1.18.32 | `027de7d2` (the milestone revision; the bundled profile at that revision) | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64, stock host | bubblewrap 0.11.1, ptrace observer; the frozen filters | `agent`, observation on, strict evidence | none (OpenCode Zen free model `big-pickle`) | Passed: wrote the requested workspace file; receipt settled, exit 0, every coverage class active ([milestone run](#opencode-agent-no-credential-at-the-milestone-revision)) |
| OpenCode | 1.18.32 | `3c3638c4` (profile at `156e645d`) | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64, stock host | bubblewrap 0.11.1, ptrace observer; pre-J4 filters (below) | `agent`, observation on, strict evidence | none (OpenCode Zen free model `big-pickle`) | Passed: wrote the requested workspace file; receipt settled, exit 0, every coverage class active |
| OpenCode | 1.18.32 | `3c3638c4` (profile at `156e645d` with its `auth` input enabled and `api.z.ai` allowed) | same | same | same | the operator's own Z.AI Coding Plan key (`opencode auth login`), staged `copy_rw` | Passed: GLM-5.3 wrote the requested workspace file; receipt settled, exit 0, every coverage class active; the key reached no record |

The two 2026-09-23 runs predate J4 and the milestone freeze. Their receipts
record the `agent` filter `sha256:e2108d4f9e9e9b222f946f375af699707a491a637e9914df45a95b3f33affb75`
and the narrowing filter
`sha256:4e2c1ab0a6ca9263da038faae8b71fb59d2989a259efc8a067ccddd372a3e2d8`;
the frozen ones are in [milestone-1-freeze.toml](milestone-1-freeze.toml).
They are kept as the history of what the first real runs required; the
milestone's A01 record is the run below.

## OpenCode, current implementation (2026-09-28)

This row applies only to source-input digest
`sha256:fa366f0c82364e99146c6a65573709799830f1904b026ed20f4b060ca31db501`, Rust 1.98.1,
x86_64 optimized build, revision `2c8f28dc` with uncommitted changes. It is not a
clean-release or all-agent compatibility claim.

The [current execution report](../../benchmarks/jail/README.md) links raw
receipts, traces and the script. A fresh fixture project, no credentials and the
embedded profile completed execution in 8.89 seconds and learning in 6.92
seconds. Both wrote exactly `hello\n`, exited zero, had no coverage gaps and
settled with `tree_empty: true`. Learning proposed no new grants; ungrantable
pseudo-filesystem reads stayed unresolved. A contained launch with every
proposed grant also passed. This small sample does not close the intermittent
startup/evidence issues documented below.

## OpenCode, `agent`, no credential, at the milestone revision

Evidence: [run record](evidence/a01-opencode-run-2026-09-25-ubuntu.txt) and
[receipt](evidence/a01-opencode-receipt-2026-09-25-ubuntu.json). This is
milestone 1's A01 record: it marks OpenCode 1.18.32 under `agent`, without a
credential, on this platform, supported. The binary still reports the
profile `experimental`; this record carries the claim.

- **What ran.** On 2026-09-25 at 07:28 UTC, on the reference host (Ubuntu
  26.04.1, kernel 7.0.0-31, x86_64, bubblewrap 0.11.1), as the account
  `ubuntu` from a plain SSH session with lingering on. `ouro-jail` at revision
  `027de7d284b19a8cb7ecc4a1ba496d4408b46627`, clean, optimised, SHA-256
  `aa2d77aa7efa322fef0afd3e3ae47a3da9ec2776bc91941d2c85ba7773724677`: the same
  binary the milestone conformance run and the performance run tested. OpenCode
  1.18.32 from `~/.opencode/bin`; the launch profile is the bundled
  [`opencode.toml`](../../../crates/ouro-jail/profiles/launch/opencode.toml)
  at that revision, unchanged; a fresh git repository as the workspace; no
  credential (OpenCode Zen's free model `big-pickle`).
- **Command.** `ouro-jail run --launch opencode --ro ~/.opencode/bin --receipt
  ~/a01-j5-final-receipt.json -- ~/.opencode/bin/opencode run "Create a file named
  greeting.txt containing the single word hello."`
- **Result.** The jail exited 0 after 12 seconds and `greeting.txt` contains
  `hello`. The receipt is settled: outcome `exited` 0, no error, every
  coverage class active (`exec` 162, `fs.write` 13,091, `fs.deny` 0, `net` 31,
  `limits` 0, `proxy.net` 31 results), lifetime integrity verified,
  `tree_empty` true, the supervisor's scope step `entered` (so the attempt had
  its execution leaf and its preferred pids ceiling applied), vendor state
  cleanup complete. The proxy's allowed hosts are the profile's:
  `opencode.ai`, `models.opencode.ai` and `registry.npmjs.org`.
- **Filters.** The receipt records the `agent` filter
  `sha256:6f7b5d4cfbc45831d7737d5ab5ee659523f1c96197e4cd8e10bcab5e76ca3ab9`,
  the mediation filter
  `sha256:28c98e72b91a22c212d5dfdddfcc1f1ca153c5a8e89c15833c26724b263ebeff`
  and the narrowing filter
  `sha256:9e63101563d550ff9aca317797385047c6af0e62ecfd1352cdbbb191135b0a66`,
  the digests frozen at that milestone. The current
  [freeze manifest](milestone-1-freeze.toml) records the updated contracts.
- **The start-up stall.** It did not recur in this run, nor in the superseded
  run at `4380241f` earlier the same day. Two runs are not evidence that it is
  gone; the item stays open.

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
