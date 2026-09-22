# North star: three tools, September 2026

Status: **specification, revision 13.** Written 2026-09-21, revised 2026-09-22. Revision 6 cut the
product to a jail, a ledger, and a fleet around existing agents. Revision 7
answered five review findings by specifying the mechanism that would close
each hole. Revision 8 keeps the findings as named limits and stops there.
Ouroboros ships no agent of its own. The first agents are Codex, Claude Code,
and OpenCode. The jail is the audit sensor. The ledger only stores what that
sensor emits. Decisions settled with these revisions are dated in §2. The rest
stay recommendations until a date is recorded. Every value marked *initial* is
a default to implement first and measure. Nothing described as new exists yet.

Revision 9 names this document the north star and records Linux and macOS as
the long-term host platforms. Linux remains the first execution release.
The [jail implementation specification](docs/specs/jail-v1.md) defines milestone
1, its first implementation slice, and the platform boundaries needed for macOS.
The current tooling tree starts fresh; source and migration references below
describe the previous implementation preserved on `legacy`, not files that
must be restored into this tree. The historical cut in §9 is not a new deletion
instruction for this checkout.

Revision 10 aligns the jail contract with reviewed containment, lifetime,
coverage, canonicalization and receipt requirements. The executable schemas,
golden fixtures and platform-specific gates live beside the jail spec; none
establishes that a backend has passed live conformance.

Revision 11 adds [managed teams](docs/specs/managed-teams-v1.md): company-owned
policy, authenticated developer submission, isolated inputs, scoped service
credentials, bounded artifacts and project-scoped evidence. These compose the
three tools. A single Linux worker can serve Linux and macOS clients after jail
and ledger; multiple workers add fleet. Native macOS execution remains separate.

Revision 12 (2026-09-22) records state and closes five review findings without
adding a subsystem. Nothing in §§3–7 is implemented; the next change to this
tree is J0 of the jail specification, and specification revisions before J0's
report are corrections and recorded measurements (§8). The Linux reference host
is an operator-provisioned x86_64 virtual private server (D9). The preserved
implementation must stay reachable on the remote before `dev` is replaced
there, and D2's archive is restated against `legacy` (§9). Observer provisioning
on the reference host is named as the critical-path risk: J0 measures it first,
the fallback candidates are named, and a blocked observer never turns
`--observe off` into J1's acceptance run (§11, jail-v1 §5.2).

Revision 13 (2026-09-22) pins the reference host to the release it runs,
Ubuntu 26.04 LTS on a 7.0-series kernel, with its first measured manifest
checked in as evidence (D9, jail-v1 §3.2); fixes the repository layout and the
crate split rules under D7 (jail-v1 §4); and sets the conformance runner model
(jail-v1 §16). The bootstrap files that layout needs, the license, ignore
rules, toolchain pin, workflows and link validator, exist from this revision.
No crate does.

## 0. Why

`core.md` §1 tried to say how an Ouroboros agent would differ from Claude Code,
Codex, Cursor, and OpenCode. That agent is the thing this revision drops. Those
products are the agents an operator already runs. Measured at `0d8d3cdf`, an
Ouroboros-shaped agent is still the bulk of the tree:

| Plane | Lines | Serves |
|---|---|---|
| `provider/native/` | 41,037 | loop, tools, context, models, MCP, hooks, skills, subagents |
| `web/` | 32,016 | a chat client |
| `wasm/` + `upgrade/` | 35,651 | capability execution, signing, self-improvement |
| `gateway/` | 17,231 | the wire the chat clients speak |
| `interactive/` | 12,961 | native sessions |
| `tui/src/` chat paths | ~18,000 | a chat client |
| `cluster/`, `mesh/`, `fleet/`, `workspace/`, `storage/`, `session/`, `audit/`, `agent/effect_ledger.ex` | ~22,000 | distributed execution, durable state, evidence |
| `provider/native/sandbox*` | 2,426 | the OS boundary |

Codex, Claude Code, and OpenCode already ship the loop, the client, and the
model. Ouroboros does not compete with them. It contains them, records them,
and places them on a machine the operator trusts. Removing the in-tree agent
is a consequence of that. The criterion is §8.

The jail category is occupied. Anthropic's [`sandbox-runtime`](https://github.com/anthropics/sandbox-runtime)
(`srt`, Apache-2.0) wraps processes in Seatbelt or bubblewrap with deny-by-default
proxy-filtered egress. It has no resource limits, no receipt of a run, and it needs
Node. [`Greywall`](https://github.com/GreyhavenHQ/greywall) is another candidate for
the D8 evaluation. Existing tools are implementation candidates. The pinned backend
and the integration in this spec pass the same gates.

## 1. The thesis

**Ouroboros is not an agent.** It is tooling for people and companies running
Codex, Claude Code, OpenCode, and the same kind of agent after them. It does
not call a model, does not keep a transcript, and does not decide the next
tool call. Three tools wrap a process those agents already are:

```text
ouro-jail    enforce a policy, report coverage, contain the tree     (one per attempt)
ouro-ledger  admit, record, retain, and answer queries               (one daemon per node, one launch owner per attempt)
ouro-fleet   place an agent on a trusted machine, sandbox optional   (one per node)
child        codex, claude, opencode, or any other argv
```

- **Jail** answers: what may this process tree touch, and which restrictions were actually applied?
- **Ledger** answers: what was authorised, what each observer established, and what is unknown?
- **Fleet** answers: who owns this attempt, where does it run, and what is its outcome?

Of `core.md` §1's four theses this keeps work across machines as independently
supervised remote processes; keeps the OS boundary and generalises it to any
command; narrows durable sessions to durable supervision of a process the operator
started; and parks self-improvement on a preserved ref.

Four rules govern every later question:

1. **Composition is processes and versioned records.** Each tool has a CLI, a wire
   contract, and a test suite that runs without the other two booted. Execution
   takes `argv`. A launch profile is declarative data — environment, credential
   files, allowed hosts, default jail — and is the only place a vendor is named.
2. **No tool speaks a vendor protocol.** Start data lives in the launch profile.
   A session protocol, a remote approval, or a resume of someone else's thread is
   a different product and is unscheduled.
3. **Every guarantee has a coverage statement and a refusal condition.** A required
   boundary that cannot be applied refuses before exec. Missing observation is
   recorded as missing. An unreachable worker leaves the outcome unknown until
   reconciled.
4. **A ledger-backed attempt has one launch owner, `ouro-ledger run`.** That owner
   outlives the operator's session on a fleet node. Fleet liveness is not the
   attempt's lifetime. Standalone `ouro-jail run` needs neither a ledger nor a fleet.

**Enough.** Ship the product at the row "what ships." The remaining hole is
accepted. A later review does not add a subsystem to close it; that is a new
proposal.

| Topic | What ships | Accepted hole |
|---|---|---|
| `none` evidence | every read of that run says `child_protection: unprotected` | a same-UID child can alter the record; `verify` does not detect it |
| `none` lifetime | the supervisor creates a cgroup and kills it on stop and on `wall` | if the supervisor dies first, the outcome is unknown; there is no second watchdog |
| Fleet output | no terminal; stdin is `/dev/null`; `--capture` keeps a bounded prefix | the rest of the stream is discarded |
| Vendor state | the managed directory is deleted after the tree is dead; `gc` retries leftovers | copies the agent made elsewhere, and leftover disk blocks, are out of scope |
| Real agents | one recorded run of one agent before that profile is called supported, and before the cut | the other profiles stay experimental; milestones 1 and 2 do not wait on credentials |

Out of the product, including as a reference implementation: an Ouroboros agent
loop, a chat UI, prompt or context management, an MCP or ACP server, a plugin
runtime. Another team's agent is the child. This tree does not grow a
replacement for it.

**Named and unscheduled.** Each item needs its own proposal. Nothing below is
implied by a milestone shipping:

- a vendor session adapter, and remote human approval with it
- general workspace synchronization, automatic checking/merging/pushing, and deployment
- an external witness key and independent custody
- a web view of the ledger, and a gateway in front of it
- the production macOS backend (a required long-term platform; not milestone 1)

"Record and see" means the closed audit set in §4.8, plus the coverage on every
answer. The jail supervisor emits those events. The ledger stores them and does
not attach a probe of its own. An empty result in an unsupported or gapped class
is unobserved. `--observe off` is the run that leaves filesystem and descendant
exec unsupported.

### 1.1 Company-managed developer agents

A company must be able to let developers use an existing agent on internal code,
untrusted contributions or confidential IP while controlling which assets and
services the agent can reach. The first useful deployment returns a reviewable
patch and test report from one managed Linux worker. Developers on macOS use the
same Rust submission client; their laptop does not become a trusted fleet peer.

The company controls workers, identity mapping, immutable policy revisions,
registered inputs, approved model/tool services and result access. Developers
submit within organization/project ceilings and may only narrow them. Managed
attempts require containment, strict observation, ledger evidence and explicit
resource limits. They cannot select `none`, turn evidence off or supply arbitrary
host mounts/credential sources. Broader access needs an authorized new policy
revision and a new attempt. Standalone operators retain the existing controls.

The jail trusts its operator. It cannot enforce company policy against someone
who administers that same laptop. Company enforcement therefore depends on
managed infrastructure and external services that protect company assets and
credentials. Model processing permissions, data location and API actions are
separate from a network allowlist; the company provisions those integrations.
Ouroboros does not infer GDPR compliance from a sandbox or an EU worker.

[Managed teams v1](docs/specs/managed-teams-v1.md) specifies the roles, policy
intersection, admission, private input materialization, bounded artifact export,
privacy and acceptance gates. This explicitly schedules those bounded additions
in milestone 4. Live workspace synchronization, vendor protocols and publishing
remain outside the product. The single-worker pilot does not wait for fleet.

## 2. Decisions

| # | Decision | Recommendation | Accepted |
|---|---|---|---|
| D0 | What is the product | A jail, a ledger, and a fleet around existing agents. The first launch profiles are Codex, Claude Code, and OpenCode. Milestone 1 is the jail alone. Milestone 2 wraps it in the ledger. Milestone 3 places the agent through the fleet, with a jail policy or an explicit `none`. There is no Ouroboros agent beside them. | 2026-09-21 |
| D1 | The in-tree agent | Delete `provider/native/` (including its sandbox modules once the D8 implementation covers their contracts) and `interactive/` in the cut after milestone 3, once nothing in the three tools calls them. The cut also needs the one real-agent run in §7.4. Conformance tests use a scripted child. No reference agent remains. | 2026-09-21 |
| D2 | Self-improvement | The archive is branch `legacy` at `f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82`, which holds `wasm/`, `upgrade/`, `self/`, capability tools, their Rust clients, bench and self-development assets, docs, skills and workflows in full, plus the tag `thesis-4-preserved` at that same commit. Both refs must exist on the remote before `dev` is replaced there (§9). No separate `thesis-4` branch is needed. Deletion of that code happens on the legacy line, in the cut after milestone 3, never from this tree. | 2026-09-21; restated 2026-09-22 |
| D3 | Vendor boundary | Launch profiles are data: environment, credential files, allowed hosts, and a default jail. No adapter package and no vendor RPC. A dependency test asserts `jail/` and `ledger/` contain no vendor identifier outside the profile table and test fixtures. | 2026-09-21 |
| D4 | Trust and credentials | One fleet is one trust domain; a connected node owns every other. Credentials are provisioned on each node by the operator or its approved issuer and no fleet verb moves them. The jail contains the child, not a peer. Managed developer clients are submitters, never fleet peers; only company-administered workers join that fleet. FLEET.md's first paragraph says both. | 2026-09-21 |
| D5 | Ledger ownership | One canonical Rust ledger, one writer per stream (`ouro-ledger serve`). No dual-write and no merge-on-query. `audit/` and `agent/effect_ledger.ex` go in the cut, after the history export in §5.4. Independent witness custody is unscheduled. | 2026-09-21 |
| D6 | Packaging | After milestone 3: three executables (`ouro`, `ouro-jail`, `ouro-ledger`), the pinned D8 dependencies, and a separately fetched BEAM runtime for nodes that run the fleet. `doctor` refuses a missing required component. Packaging is not a gate for milestone 1. The BEAM runtime is not embedded in the jail or the ledger. | 2026-09-21 |
| D7 | Repository | One workspace, laid out as jail-v1 §4 specifies: Rust crates under `crates/` (one per process the north star names; `ouro-records` carved out of the jail only when the ledger becomes its second consumer; a test-only fixture crate; a BPF object crate outside the default members if J0 selects eBPF; `xtask` for repository tasks), the Elixir fleet as a sibling Mix project outside Cargo, contracts and measured evidence under `docs/specs/`, proposals under `docs/proposals/`, packaging under `packaging/` after milestone 3. Directories are created when their milestone starts; their names and split rules are fixed now. A tool moves to its own repository only after a later decision, once its CLI, contracts and tests stand alone. | 2026-09-21; layout 2026-09-22 |
| D8 | Jail implementation | Before milestone 1 is declared green, evaluate pinned `srt`, Greywall and the existing in-tree sandbox against §4. Prefer reuse behind `ouro-jail`, with the smallest policy, admission and receipt integration that passes. The enforcement backend is not the audit sensor (§4.8). A backend that leaves no supervisor outside the child, or that hides descendant syscalls from a host probe, fails the evaluation. Record boundary and nesting failures, coverage, lifecycle and limit support, startup cost, dependency footprint, licensing and maintenance cost. A runtime dependency such as Node is a measured packaging tradeoff. Implement or port a missing mechanism only when a named failing gate justifies it. Freeze one backend, version and integration, with provenance and a gap-to-gate plan, in `docs/specs/jail-v1/backend-evaluation.md`. Independent §4 fixtures are authoritative. Differential runs against other candidates are supporting evidence, not an oracle and not a permanent shipping dependency. The decision is scheduled, not made: it is taken in J0's report, whose checked-in skeleton at [`backend-evaluation.md`](docs/specs/jail-v1/backend-evaluation.md) records `not_started` for every measurement until the reference host produces them. J0 measures the observer privilege model before the enforcement candidates, because a blocked observer changes which backend is worth integrating. | pending; scheduled as J0 on 2026-09-22 |
| D9 | First lane | Linux (bubblewrap, seccomp, cgroup v2 where the host delegates one). Initial launch profiles for Codex, Claude Code, and OpenCode. A profile is experimental until its own §7.4 run. `--jail none` is a real run, still observed unless `--observe off`, and its evidence is unprotected. macOS execution, including Claude's Keychain credential, follows a separate platform implementation; shared contracts must accommodate it now. On Ubuntu 24.04+, an operator-installed scoped AppArmor profile may grant `userns` to the required executables, or on a dedicated host the operator may turn the restriction sysctl off; the reference host does the latter (2026-09-22). `doctor` measures the sandbox, the cgroup, and the audit sensor, and never changes host policy. The initial conformance host is an operator-provisioned x86_64 virtual private server that runs its own Linux kernel under hardware virtualization, pinned to the release it runs: Ubuntu 26.04 LTS on the 7.0-series kernel, with the measured manifest recorded in jail-v1 §3.2. A container-based host that cannot create user namespaces, delegate a cgroup v2 subtree or attach the observer is ineligible, whatever the provider calls it. aarch64 is a later, separately conformed lane, not the reference host (jail-v1 §3.2). | 2026-09-21; host added 2026-09-22 |
| D10 | Audit sensor | The jail supervisor is the only syscall sensor. It attaches before exec, outside the child, including when containment is `none`. The ledger is the store. The closed set and the `--observe` default are §4.8. Seccomp notification is not that sensor. | 2026-09-21 |
| D11 | The five limits | `none` is labelled unprotected. Its tree kill is the supervisor's cgroup, and supervisor death is an unknown. Fleet I/O is batch with opt-in bounded capture. Vendor state is deleted after tree death. One real-agent run marks that profile supported. The accepted holes are the Enough table in §1. | 2026-09-21 |
| D12 | Language and platform boundary | Rust owns the local CLI, jail and ledger; Elixir/OTP owns fleet coordination. Linux and macOS share policy semantics, lifecycle states, events and receipts. Containment, observation, process identity and tree termination have OS-specific implementations and measured capabilities. Linux mechanisms are not required fields in portable records. A missing required guarantee refuses; compilation on macOS is not execution support. | 2026-09-21 |
| D13 | Managed teams | Company-controlled workers resolve organization/project/attempt policy, authenticate developers and enforce project access. Managed v1 requires contained execution, strict evidence, explicit limits and approved services. Rust owns the submission/composition path, private inputs and bounded artifacts; Elixir adds multi-worker placement. Existing company identity, model gateway and publishing systems remain external. The full contract and MT01–MT16 gates are in managed-teams-v1.md. | 2026-09-21 |

## 3. `ouro`, the front door

| # | Functionality | Contract |
|---|---|---|
| O1 | Dispatch | `ouro jail …`, `ouro ledger …`, `ouro fleet …`, `ouro doctor`, `ouro version`; milestone 4 adds `ouro managed …`. `jail`, `ledger`, and the managed client/single-worker composition execute in Rust without BEAM. `fleet` execs the release launcher. Every inspection and control verb takes `--json`. |
| O2 | Doctor | Sections for the tools that are installed: jail capabilities (§4.9), ledger daemon and store health, fleet membership and readiness (§6.2 F5). Each section is the same output as the tool's own `doctor`. Presence of a binary, a directory, or a peer is not readiness. |
| O3 | Configuration | `~/.config/ouro/config.toml` with `[jail]`, `[ledger]`, `[fleet]`, overridable by `OURO_*`. A project `ouro.toml` at the workspace root may only narrow the operator's jail policy. Any widening key, any credential path, any extra allow-host, and `none` are refused with the key's path. The resolved policy is snapshotted and digested outside the workspace before launch. An edit by the child does not change an active attempt. |
| O4 | Streams and exit codes | Foreground execution passes child stdout and stderr unchanged. Diagnostics and ids go to stderr or `--control-fd N`. Exit codes: the child's code, or `128+signal`; 1 tool error; 2 usage; 125 pre-exec refusal. A receipt distinguishes a tool refusal from a child that exits 125. `fleet run [--json]` returns after durable admission with the job id. `fleet wait JOB --json` reports the process outcome and renders an unknown outcome as unknown. |

Packaging, install, and update are D6. They follow milestone 3 and are not part of
the milestone 1 contract.

O3 describes trusted operator configuration. For managed submission, local config
selects the endpoint and client behavior only. The server owns immutable company
policies and supplies the effective jail configuration; submitter `OURO_*`, paths
and CLI arguments never become operator overrides. Managed policy provenance and
business authorization are bound to, but separate from, the canonical jail policy.

Source seams: `tui/src/{cli,main,config,runtime}.rs`.

## 4. `ouro-jail`

The jail applies one policy to one process tree and writes a machine-readable
account of what it applied, what it observed, and what it could not. The
supervisor is also the audit sensor (§4.8). The first lane is Linux. This
section claims neither macOS parity nor a trace of every syscall number.

The jail's operator is trusted. In a managed deployment that operator is the
company-owned launch owner, not the developer submitting the task. The jail
reports local boundaries; identity, business authorization and service scope
are enforced by the composition described in managed teams v1.

### 4.1 Verbs

```text
ouro-jail run     [--profile agent|tool|build|none|FILE] [--launch NAME]
                  [--workspace P] [--scratch P] [--rw P]… [--ro P]… [--deny-read P]…
                  [--allow-host H[:PORT]]… [--limit K=V]…
                  [--observe on|off] [--evidence strict|best-effort] [--trace-fd N]
                  [--receipt PATH] [--gate-fd N] [--control-fd N] [--attempt-id ID]
                  [--label-only] -- <argv>
ouro-jail doctor  [--profile NAME|FILE] [--launch NAME] [--json]
ouro-jail explain [--profile …] [same flags]     # rendered policy, no probe, no exec
ouro-jail gc      [--dry-run] [--json]          # recover pending vendor-state cleanup
```

`run` prepares the boundary and writes the *prepared* receipt. With no `--gate-fd`,
its local supervisor starts the child with `argv`, forwards stdio, handles signals,
enforces the deadline, reaps the tree, and writes the *settled* receipt. The
supervisor stays outside the contained tree. Neither a ledger nor a fleet is
required.

`--gate-fd` is the composition option: an inherited private pipe from the launch
owner, closed before child exec along with every producer and control fd. When
supplied, the jail waits for exactly one release after durable admission (§7.1).
EOF, a malformed release, or owner death before release refuses without exec.
`--label-only` probes and prints the label without exec. It is not evidence about
any run.

`--profile none` skips filesystem, network, and seccomp containment. The
supervisor still creates a cgroup, enforces `wall`, kills that cgroup on stop,
and writes `containment: none` and `child_protection: unprotected`. It does not
require the enforcement backend. Observation still defaults on (§4.8). Fleet
accepts it as `--jail none`. If the cgroup cannot be created, the run exits 125.
It does not fall back to a process-group kill and call that tree death. Any
other profile that cannot be applied also refuses and does not fall through to
`none`.

`--launch NAME` loads a launch profile (§4.5). The profile adds environment,
credential mounts, and allow-hosts. It does not replace `argv` and it cannot
select `none`.

### 4.2 Profiles

Initial values. Every path reaches the backend as an argument, never as policy
text the backend evaluates. A profile file (TOML, same keys) may only narrow the
base it `extends`. Operator flags (`--rw`, `--allow-host`) are separate explicit
grants, recorded in the receipt.

| | `agent` | `tool` | `build` | `none` |
|---|---|---|---|---|
| Purpose | Codex, Claude Code, OpenCode, or another agent under the same shape | that agent's shell, or a test command it spawned | a package build | an explicit uncontained run |
| Read-write | `<workspace>`, `<scratch>`, `<vendor-state>` (§4.5) | `<workspace>` with `.git` and `.ouroboros` segments denied (coverage §4.4); `<scratch>` | `<scratch>` only | the host, unchanged |
| Read-only | system roots (`/usr`, `/bin`, `/lib*`, `/etc/{ssl,resolv.conf,passwd,group,hosts,localtime}`), declared credential inputs | system roots | system roots, declared inputs | n/a |
| Denied read | everything under `$HOME` not listed; `<data>/ledger` | same, plus every credential | same | n/a |
| Network | proxy only; hosts from the launch profile plus `--allow-host` | none | none | the host network |
| Limits (initial) | `wall=2h`, preferred `pids=512`; `mem` and `cpu` optional | `wall=30m`, preferred `pids=256` | `wall=1h`, preferred `pids=512`, `mem` required | `wall=2h`; a cgroup the supervisor can kill; no default `pids` or `mem` ceiling; explicit limits remain unprotected |
| Environment | allow-list: `PATH`, `HOME` (set to `<vendor-state>` when a launch profile says so), `LANG`, `TERM`, `TZ`, proxy variables, and the launch profile's variables | `PATH`, `LANG`, `TERM`, `TZ` | same as `tool` | inherited, except names that point at the data directory, the ledger socket, or a token; the receipt says `inherited` and lists the removed names, not the values |
| Process | `--new-session`, `--die-with-parent`, own pid, net, ipc, and uts namespaces | same | same | new session, no namespaces; supervisor-owned cgroup (§4.9) |

The workspace is the directory the operator passed. The jail bind-mounts it. A
git worktree, a hardlinked object, or an alternate is not a boundary: a write can
land outside the mount through a shared inode. This spec does not provision a
private repository, and the receipt does not claim that git metadata stays inside
the workspace. The operator passes a directory they accept as the writable root.

### 4.3 Filesystem and mounts (Linux)

Applied for every profile other than `none`.

- bubblewrap with `--unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts`,
  `--die-with-parent`, `--new-session`, `--ro-bind` for read-only roots, `--bind`
  for writable ones, `--tmpfs` over denied subtrees inside otherwise-visible
  parents, `--dev /dev`, `--proc /proc`. Nothing else from the host is visible.
- Read visibility and write permission are separate lists. A path may be visible
  and read-only, writable, or absent. Roots, symlinks, and protected literals are
  resolved before launch. The rendered mount table is in the receipt.
- A common seccomp baseline denies `ptrace`, `process_vm_*`, `kexec*`, `bpf`,
  `perf_event_open`, `keyctl`, `add_key`, and all three `io_uring_*` entry points
  (`setup`, `enter`, `register`); no ring fd is inherited. `tool` and `build` additionally deny
  mount and unmount operations and creation or joining of further namespaces after
  outer setup. Architecture-specific syscall variants and indirect interfaces are
  covered by the filter. A rule that cannot inspect an argument safely does not
  claim it did.
- `agent` uses a separate, versioned nesting profile. It permits the namespace and
  mount setup an inner sandbox needs, including `mount` and `umount2` where the
  fixture requires them. Seccomp filters are inherited across fork and exec.
  Creating a user namespace cannot relax an outer denial. The receipt records the
  filter digest and the allowed setup operations. A namespace-creation probe by
  itself is not evidence of working nesting.
- Those setup operations cannot recover host paths, sockets, mounts, or
  capabilities the outer boundary excluded. The outer mount view, the locked
  mounts, the capability set, and the network namespace remain the authority.
  The nesting fixture tries to undo them (§4.6). A profile that cannot preserve
  them refuses.
- Ledger sockets are absent from the child's mount namespace. Seccomp cannot
  filter a Unix socket by path. `tool` and `build` deny `socket` and `socketpair`
  for `AF_UNIX` and inherit no such socket. `agent` permits the sockets a vendor
  agent opens inside the jail. No profile inherits host-namespace fds or control
  sockets that could bypass the outer view.
- The jail never widens policy during an attempt. A wider policy is a new attempt.

### 4.4 Protected paths

Linux bind mounts can hide or read-only a directory that exists at launch. They
cannot deny a `.git` created later, five levels deep. Seatbelt's regex rules can.
A profile declares the coverage it requires. The receipt states the coverage it got.

| Coverage | Meaning | Linux | Seatbelt |
|---|---|---|---|
| `existing_and_root` | protected segments that exist at launch, plus the workspace's own `.git` and `.ouroboros` when those literals are protected | yes | yes |
| `all_descendants` | any protected segment created at any depth during the run | no; refuses if required | yes |

The `tool` profile requires `existing_and_root` and prefers `all_descendants`. A
profile that requires `all_descendants` on Linux exits 125.

### 4.5 Launch profiles

A launch profile is operator data. It tells the jail how to start an existing
agent without speaking that agent's protocol. Profiles live in
`~/.config/ouro/launch/<name>.toml`, mode 0600. A profile inside the workspace is
refused. The resolved profile is copied outside the workspace and digested before
launch.

```toml
name = "codex"
jail = "agent"                       # default when --launch is set and --jail is omitted
state_var = "CODEX_HOME"             # points at the per-attempt state directory
home_is_state = true

[credentials.auth]
source = "~/.codex/auth.json"        # on this node; never fetched from another
dest = "auth.json"
mode = "copy_rw"                     # or bind_ro

[credentials.config]
source = "~/.codex/config.toml"
dest = "config.toml"
mode = "bind_ro"

[network]
allow = ["api.openai.com:443", "*.openai.com:443"]
```

`argv` is always the operator's `--` arguments. The profile does not rewrite the
command. `jail = "none"` inside a profile is refused; `none` is only a CLI flag,
so the invocation shows it. A project `ouro.toml` cannot add a launch profile, a
credential, or an allow-host.

The per-attempt state directory is `<data>/attempts/<id>/vendor-state`, created
mode 0700, and mounted at the path `state_var` names. It is outside the workspace.
`copy_rw` copies the source in at launch and never writes it back. `bind_ro`
mounts the node's file read-only. The child can read what it was given. With
containment enforced, no other environment variable, socket, or home path
reaches the child. All managed state has the lifecycle in §4.5.1.

The initial profiles are `codex`, `claude`, and `opencode`. An operator may add
another file beside them. A profile is experimental until that agent's own run
in §7.4 is recorded. Recording a version does not pin the operator's binary.
Ouroboros speaks no vendor protocol.

| Name | State variable | Declared inputs (initial) | Mode (initial) |
|---|---|---|---|
| `codex` | `CODEX_HOME` | `auth.json`, `config.toml` from the node's `~/.codex` | `copy_rw` for `auth.json`; `bind_ro` for `config.toml`. `copy_rw` can rotate a refresh token the node's file then lacks. `bind_ro` is the alternative, and refresh then fails. |
| `claude` | `CLAUDE_CONFIG_DIR` | `.credentials.json`, `settings.json` from the node's Claude config directory | file credentials only. A Keychain credential is a macOS problem and is unscheduled. |
| `opencode` | `XDG_CONFIG_HOME` and `XDG_DATA_HOME` under the state directory | provider keys and config from the node's OpenCode directories | `bind_ro` for keys, `copy_rw` for mutable config |

`doctor --launch NAME` checks that each declared source exists and prints
neither contents nor paths beyond the profile's own names. A missing source
refuses the launch. It reports the profile as experimental or supported,
separately from whether the host probes passed.

### 4.5.1 Vendor-state lifecycle

`<vendor-state>` holds the credential copies and whatever the agent writes
there. It is not part of the ledger, a bundle, or an export. Ledger retention
does not keep it.

The jail registers the directory before the first copy. When the tree is dead,
or when the run refuses before exec, it deletes that directory and does not
follow links out of it. The operator's source files stay where they are.
`state_cleanup` on the receipt is `pending` until that delete finishes, then
`complete`. A failed delete stays `pending` and `ouro-jail gc` retries it.
`gc` deletes a directory only after pre-exec refusal and helper teardown, or
verified termination within the receipt's declared lifetime scope. Detected
boundary-integrity loss retains it; a live or unproved tree keeps its directory.
An unknown execution outcome alone does not prevent cleanup after verified
termination. None's registered-boundary scope never proves migrated descendants
dead or supplies tamper protection.

This is an unlink of the managed directory. Copies the agent made elsewhere
are the accepted hole in §1.

### 4.6 Nesting

Codex, Claude Code, and OpenCode may start their own bubblewrap, Landlock, or
seccomp. The `agent` profile exists so that inner sandbox can start: the setup syscalls in §4.3 are permitted,
the helper binaries the fixture needs are visible read-only, `/proc` is mounted,
and the inner network namespace may be empty because the proxy is a Unix socket
the inner sandbox can reach. Creating a namespace cannot relax an outer denial.

The fixture is a scripted inner sandbox, not a vendor binary. It must start, deny
a write it should deny, and fail at each of: remount, unmount, joining a
namespace, reading a protected path, and direct egress. A failed nesting probe
refuses the `agent` profile (125). It does not disable either boundary. Host
prerequisites, including any scoped AppArmor profile, are recorded with the
kernel, helper, and filter versions.

### 4.7 Network

Applied when the profile's network is `proxy`. `none` does not install a proxy
and does not claim to filter.

- The child has no membership in the host network namespace. The proxy socket
  lives in the protected `<data>/attempts/<id>/proxy/proxy.sock`, exposed at
  `/run/ouro/proxy/proxy.sock` through a dedicated read-only directory. The
  bridge listens on `127.0.0.1:3128`; its namespace and pinned endpoint cannot
  be redirected by child path/mount replacement. Upper/lowercase HTTP_PROXY,
  HTTPS_PROXY and ALL_PROXY use `http://127.0.0.1:3128`; NO_PROXY is empty.
  Pathname Unix sockets require separate host-peer isolation: network namespaces
  alone do not protect shared mounts. Agent nesting retains same-attempt IPC,
  but refuses if a tested mechanism cannot block unauthorized host peers,
  including sockets created after launch. See jail §10 and S03/N05.
- The proxy speaks `CONNECT` and plain HTTP. Policy is normalised `host[:port]`,
  with wildcard labels (`*.openai.com`), evaluated on the request host and on
  every resolved address. The jail's versioned [network rules](docs/specs/jail-v1/network-rules.md)
  pin IDNA and numeric normalization and default-deny special/metadata ranges.
  Only an explicit numeric address/port grant overrides a numeric denial;
  hostname permission does not. DNS is resolved
  by the proxy. A denial returns `403` with a reason header and emits one
  `net.connect` event with `decision: deny`.
- No TLS interception in this specification.
- `tool` and `build` start no proxy and mount no socket.

### 4.8 Trace, receipt, and coverage

Observation and containment are separate. The supervisor always parents the
child, whether or not it mounts a jail. The audit sensor lives in that
supervisor, never in the child and never in the ledger. It attaches before
exec. The enforcement backend does not own this sensor and cannot be the only
way a descendant syscall is seen. An inner sandbox shares the kernel, so a host
probe still sees its calls.

`--observe` defaults to `on`, including for `--profile none`. The probe loads
before exec. If it cannot load, the run exits 125. `--observe off` is explicit:
the supervisor records the direct child only, and the receipt marks the audit
classes `unsupported`.

The sensor emits a closed set. Ordinary syscall results pair entry with the
return code; exec success pairs entry with a confirmed kernel exec transition.
`stage: attempt` is not success. The set is:

| Operation | Attached calls (initial) | Result means |
|---|---|---|
| `proc.exec` | `execve`, `execveat` | a confirmed exec transition or failed exec return; executable identity and a complete argv digest when available, otherwise an explicit unavailable digest |
| `proc.exit` | final thread-group termination of a process with witnessed exec | the process is gone; a worker or leader thread exiting alone is insufficient |
| `fs.create`, `fs.write` | native open-family variants that request write, create, or truncate (§11.2 of the jail spec) | the open returned success; the path was opened for mutation |
| `fs.create`, `fs.rename`, `fs.unlink` | native directory-entry creation, rename and removal variants (§11.2 of the jail spec) | the directory change returned success |
| `fs.deny` | a failed call from the rows above, or a failed `connect`, whose errno is a denial (`EACCES`, `EPERM`) | that call was denied; not every denial on the system, and not a failed read |
| `net.connect` | `connect` | the connect returned; fields carry the address the kernel was given |

`write`, `read`, `mmap`, `futex`, and the rest of the syscall table are not
attached. A file audit is the successful open-for-write or the directory
change, not the bytes and not every write a compiler issues. Paths stored on
the trace are workspace-relative when they fall inside the workspace, and
digested otherwise. The probe may hold a raw path only long enough to redact
it. It does not claim a path is stable against a parent renamed after the
kernel copied the argument.

Each source establishes some facts and implies none of the others. Events leave
on `--trace-fd`, an inherited pipe the child cannot reach, in the envelope of
§7.2. That envelope is frozen with the jail, so the ledger cannot invent a
second shape for the same facts.

| Source | May establish | Must not imply |
|---|---|---|
| Wrapper (the jail process) | launch attempt, exec and reaped status of the direct child, verified tree termination, limits applied and hit | every descendant exec or exit; correctness; absence of effects |
| Audit sensor | a result in the closed set above, for the tree the probe was attached to | calls outside the set; payload meaning; that a path survived a later rename; completeness across a gap |
| Proxy | requested host and port, the policy decision, connect result, bytes in and out, duration | payload meaning; that the application request succeeded; what the audit sensor saw |

Seccomp user-notification is not this sensor. It intercepts before execution,
`continue` is not success, and pathname arguments can change between inspection
and use ([seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)).
`SECCOMP_RET_LOG` logs and allows execution. A read-only mount's filesystem
error is not, by itself, an `fs.deny` event. `fs.deny` counts are the denial
results the sensor emitted. Unsupported counts are `null`.

Every attempt declares, per class (`exec`, `fs.write`, `fs.deny`, `net`,
`proxy.net`, `limits`), one of `supported`, `active`, `degraded`, `unsupported`, with
intervals and reasons for gaps. Queries carry coverage. A requested trace that
cannot start refuses before exec (125). Loss or backpressure during a run
records a gap. Under `--evidence strict` the supervisor stops and terminates the
tree. Under `best-effort` the run continues with `degraded`.
Audit `net` and proxy `proxy.net` are separate counts/scopes; a working proxy
cannot claim syscall coverage. All directory-entry operations belong to
`fs.write`. Denied connect belongs to `fs.deny` with attempted_operation
`net.connect`; every audit decision is null. Explicitly excluded interfaces
are not coverage loss. The jail spec §11.4 defines the full mapping.

Observation coverage is separate from protection against the child. Receipts,
run records, query results, bundles, and status carry `child_protection`:
`enforced` for a successfully applied contained profile, `unprotected` for
`none`. An active sensor does not upgrade this field. In `none`, a same-UID
child may modify the store, signal its owner, or interfere with source channels;
recorded provenance and a valid local hash chain cannot disprove that. `strict`
controls the response to detected evidence loss; it does not provide tamper
resistance. Every successful result still displays this protection label.

`jail.json` is written at *prepared* and replaced atomically at *enforced* and
*settled*, with a separate pre-exec *refused* variant. The executable draft shape
and synthetic examples are in the [jail receipt contract](docs/specs/jail-v1.md#132-receipt-lifecycle-and-shape).
The [contained](docs/specs/jail-v1/examples/receipt-tool.json),
[none](docs/specs/jail-v1/examples/receipt-none.json),
[prepared](docs/specs/jail-v1/examples/receipt-prepared.json), and
[macOS refusal](docs/specs/jail-v1/examples/receipt-macos-refused.json) examples
are executable contract fixtures with synthetic identities, not real runs.
Credential provenance and byte-valued paths use that same receipt schema.

A `none` receipt sets `containment` to `none`, `child_protection` to
`unprotected`, the enforcement `backend` to `none`, and `lifetime.boundary` to
`supervisor_cgroup`. `tree_empty` stays null until the supervisor has seen the
registered cgroup empty, with verification_scope=registered_boundary and no
detected integrity loss. Healthy `--observe on` records active audit coverage;
loss records degraded coverage. `--observe off` marks audit classes unsupported.
Proxy coverage is separate. The same schema covers these cases.

The full resolved policy is operational state under `<data>/attempts/<id>/policy.json`,
not part of the receipt. A *prepared* receipt is not proof of exec. A missing
*settled* receipt is incomplete evidence. It is not proof the child was unjailed.

### 4.9 Refusal, limits, doctor

- Exit 125 before exec when a required backend or capability is missing, a profile
  requires coverage the backend lacks, a policy file widens its base, a nesting
  probe fails for `agent`, a trace cannot start, `--observe on` cannot attach
  the sensor, a required limit cannot be applied, or `none` cannot create its
  cgroup. `none` does not require the enforcement backend. It still requires
  the sensor unless `--observe off`.
- The supervisor enforces `wall` with a monotonic deadline starting at gate
  release, or at standalone launch. Linux uses CLOCK_BOOTTIME, including suspend.
  Reattachment does not reset it. `pids` and
  `mem` apply on a cgroup v2 leaf when the host delegates one. Otherwise they are
  recorded absent, and refused when the profile marks them required. A limit hit
  records `applied.limits[].hit`, `outcome.cause` and the actual signal. It does
  not force every case into 137. Built-in pids ceilings are preferred; every
  explicit ceiling is required. Observer-required cgroup support does not imply
  the pids controller is required. Jail §6.4 is the authoritative defaults table.
- Contained profiles die with their pid namespace (`--die-with-parent` plus the
  jail's `PR_SET_PDEATHSIG`). When a cgroup is in use it is emptied and checked.
  The direct child's exit is not, by itself, proof the tree is dead.
- `none` puts the child in a cgroup the supervisor created, before exec.
  Stop and `wall` use `cgroup.kill` and then check that the cgroup is empty.
  The supervisor is the only killer. If it dies first, reconciliation leaves
  the outcome unknown and does not invent a second watchdog. `gc` may remove
  a recorded cgroup that is still populated after that unknown, and it records
  that it did. `none` still has no filesystem or network containment and no
  protected ledger.
  Its receipt uses verification_scope=registered_boundary: an empty leaf does
  not certify that migrated descendants died. Target exit is independently
  observed. Detected migration/identity loss prevents settlement and cleanup;
  unobserved same-UID interference remains an accepted limit, not tree proof.
- `doctor` runs the probes: create a namespace, bind a mount, load the filter,
  take a cgroup leaf and kill it, start the bridge, run the scripted nested
  setup, load the audit sensor, and inspect the applicable AppArmor policy.
  It reports each as measured and does not change host policy. A skipped probe
  is reported skipped.

### 4.10 Jail acceptance (milestone 1)

On the D9 kernel, with the ledger and the fleet absent:

- A fixture build runs under standalone `tool`. Stdio, signal forwarding, `wall`,
  tree reaping, and all three receipt phases work. A supplied gate never execs
  before release. EOF and a malformed release refuse.
- Direct egress fails. An allowed proxy request and a denied one each produce
  exactly one proxy `net.connect` with the matching decision. A scripted child
  that execs, opens a file for write, renames, unlinks, and connects produces
  one audit `result` per succeeded call, with native completion evidence. A
  covered failure returning EACCES or EPERM produces one `fs.deny`; EROFS stays
  a failed result of its original operation. A fixture that noticed a denial
  by some other means does not count. `write` and `mmap` produce no events.
- Under `tool`, a write into an exact `a/b/c/.git` that existed at launch fails,
  and replacing that protected mount fails. If that `.git` was absent at launch,
  creating it later may succeed. The harness shows this limit. The receipt says
  `existing_and_root` and does not invent a runtime denial. Requiring
  `all_descendants` refuses.
- A symlink from the workspace to `$HOME/.ssh` reads as absent.
- The scripted inner sandbox starts under `agent`, enforces its own restriction,
  and fails to undo each outer restriction in §4.6. `wall` kills the whole tree.
  A cgroup in use is verified empty.
- `--profile none` writes `containment: none` and `child_protection: unprotected`,
  mounts nothing, and kills its cgroup on `wall`. A child that ignores `SIGTERM`
  still dies with that cgroup. If the cgroup cannot be created, the run refuses.
  `--observe off` emits no audit-source events from the closed set. An observer that cannot attach
  refuses before exec. The same child inside the scripted inner sandbox is still
  visible to the host sensor. Receipts validate against the schema.
- Vendor state: a normal exit and a pre-exec refusal both leave the managed
  directory gone and the operator's source files in place. `gc` retries a
  delete that stopped halfway. A cgroup that is still populated is not deleted.

Run the boundary fixtures against the selected D8 integration. Differential runs
against other candidates record coverage differences. An empty event list does
not prove that an unobserved action was allowed or denied.

Source: `provider/native/sandbox/{sandbox_exec,bwrap}.ex`, the detect, label,
refusal, and violation halves of `sandbox.ex`, and `core.md` §7.

## 5. `ouro-ledger`

The ledger joins authorisation and attributed observation into one ordered record,
keeps that record outside a contained child's write authority, and separates
completeness, local consistency, and protection from the child. Under `none`,
the record is explicitly unprotected (§5.4). It stores the jail's audit events.
It does not load a probe, attach to a process, or reinterpret a syscall. An
outside witness is unscheduled. Local `verify` is the check this spec provides.

Milestone 4 adds managed admission/provenance records, project-scoped readers,
access decisions and event/capture/artifact retention under company policy.
These are owner/store responsibilities, not new audit probes. An authenticated
principal comes from trusted ingress, never a submitter-provided actor field.
The ordinary operator/reader roles below do not themselves provide a managed
multi-project authorization system; MT01 and MT13 must pass before that claim.

### 5.1 Processes

- **`ouro-ledger serve`**: one node-local daemon. It owns every stream under
  `<data>/ledger/` and is the only writer. It listens on `<data>/ledger/serve.sock`
  (mode 0600), authenticates peers by `SO_PEERCRED` and role credentials, and
  hands per-attempt producer tokens over a private authenticated channel or an
  inherited fd. Tokens never enter the environment, unit arguments, or files.
  Roles are `owner` (the launch owner), `producer` (the jail), `operator` (fleet
  and CLI), and `reader`. The daemon is started on demand by a standalone verb.
  On a fleet node it survives a restart of the fleet worker.
- **`ouro-ledger run`**: the launch owner, one per attempt (rule 4). It prepares
  or adopts a run, spawns `ouro-jail run` as its direct child with the trace pipe
  and the gate pipe, handles stdio, watches the deadline, holds the launch
  lease, and settles the run. `setsid` detaches the terminal. It does not put
  the owner in a process the fleet worker can take down with it. Foreground
  stdio follows O4; detached fleet stdio follows §6.1 and has no client fd dependency.

The launch owner is the attempt's lifetime. On a fleet node the owner is started
so that it survives the operator disconnecting and the fleet worker restarting.
The owner is not a child of the worker or of the operator's shell. If the host
cannot provide that independence, `fleet run` refuses. `doctor` reports whether
a fleet attempt would survive disconnect, and it does not change host policy to
get there. Lingering, or whatever else the host needs, is operator provisioning.
Standalone invocation detaches from the terminal and does not promise to survive
the caller's service stopping.

For contained runs, owner death delivers `PR_SET_PDEATHSIG` to the jail and the
pid namespace takes the tree down. In `none`, the supervisor's cgroup kill is
the tree kill; if the supervisor is already dead, the outcome stays unknown
(§4.9). A dead owner is not restarted. Record pid, pidfd birth identity, and
boot id with the attempt, and use them to recognise the same owner after a
reattach.

### 5.2 Verbs

```text
ouro-ledger prepare  --request-id ID [--json]
ouro-ledger run      [--prepared RUN] [--jail PROFILE …] [--launch NAME]
                     [--observe on|off] [--evidence strict|best-effort]
                     [--io foreground|batch]
                     [--capture stdout|stderr|argv]… [--capture-limit BYTES]
                     [--tag K=V]… [--control-fd N] [--json] -- <argv>
ouro-ledger append   --run RUN --request-id ID
                     --kind admitted|denied|settled|note
                     --effect ID --body-file F [--json]
ouro-ledger settle-orphans [--json]
ouro-ledger runs | show RUN | tail -f RUN | query … | diff RUN RUN | verify [RUN] | bundle RUN
ouro-ledger hold RUN | release RUN | gc [--dry-run] | export RUN --ndjson
ouro-ledger serve | doctor
```

`--io foreground` is the standalone default: inherited stdin and unchanged
stdout/stderr, with selected captures teeing those streams. `--io batch` applies
§6.1's no-terminal, stdin-EOF, and independent output-sink contract. Fleet always
starts its owner with `--io batch`. The resolved mode and descriptors' intended
roles are recorded in `run.json`; raw output is never mixed into a JSON control
response. Foreground JSON control uses `--control-fd` if child output is present.

| # | Functionality | Contract |
|---|---|---|
| L1 | Prepare and run | `prepare` allocates `run_id` durably for a `request_id`. The same id and payload returns the same run. A different payload for the same id refuses. `run` without `--prepared` prepares itself. `--jail` starts exactly one jail. `--jail none` still starts the jail, in the `none` mode of §4.1, so supervision and the receipt exist. A prepared run is not a launch authorisation. §7.1 is. |
| L2 | Events | Producers send source events (§7.2) with their own `source_seq`. The writer adds `run_id`, global `seq`, `received_at`, verified `provenance` from the channel's role, canonical encoding, and `prev`. Payloads carry `operation`, `stage` (`attempt`, `decision`, `result`), `decision` when applicable, and `outcome` only when the source observed it. |
| L3 | Intent | `append` is the only mutation path for a non-jail producer, and it goes to the daemon. `actor` is derived from the authenticated role and peer, not from the body. Success returns `{seq, digest}`. The same `request_id` and body returns the original receipt. A conflicting payload refuses. `settle-orphans` reconciles attempts whose launch owner is gone: it records what the pidfd and boot id establish and marks the rest `outcome_unknown`. It does not infer that an effect did not happen. |
| L4 | Verification | `verify` checks canonical bytes, `prev` chains, and segment manifests, and reports local consistency, coverage, and `child_protection` as separate results. A consistent `none` run stays `unprotected`. `bundle` exports records, receipts, and selected captures, never vendor state. A signature identifies this node as the signer. |
| L5 | Capture | `--capture` is opt-in. Each artifact keeps at most `--capture-limit` bytes, initially 1048576. The child is not blocked at the cap; the rest is discarded and `truncated` is set. An unselected stream is `not_captured`. `show --with-transcript` uses those words. |
| L6 | Query | `runs [--since] [--launch] [--tag] [--outcome]`, `show RUN`, `tail -f RUN`, `query [--run RUN]… --hosts\|--paths\|--execs\|--denials [--stage] [--since]`, `diff A B`. Results carry `coverage`, `stage`, `provenance`, and `child_protection`. `diff` compares classes both runs cover and reports the rest incomparable, retaining each run's protection label. An empty result with `unsupported` coverage is rendered as unobserved. Paginated, `--json`. |
| L7 | Retention | `[ledger] retain = "90d"` (initial), including explicit captures. `hold` and `release` manage operator holds. A run that is active or `outcome_unknown` is never garbage-collected. Vendor state still deletes once the tree is dead (§4.5.1). `gc` records what it removed and keeps chain anchors. |
| L8 | Store | `<data>/ledger/<run_id>/{run.json, events-000N.ndjson, artifacts/, receipts/}`. `<data>/ledger/index.sqlite` is a projection, rebuilt from the directories on demand. One writer per stream, by the daemon's process-lifetime lock. Recovery verifies durable frames before appending. |
| L9 | Privacy | Default metadata is workspace-relative paths, executable identity, an `argv` digest, host and port, and byte counts. External paths are digested. Raw environment values, `argv`, file bodies, and model payloads are not default events or artifacts. `--capture` may contain secrets. `run.json` records the capture settings, sizes, truncation, and retention. `--redact` minimises structured fields before append and makes no promise about captured bytes. |

### 5.3 `run.json`

```json
{
  "schema": "ouro.ledger.run/1",
  "run_id": "run_01J…",
  "request_id": "fix-123",
  "attempt_id": "att_01J…",
  "jail_profile": "agent",
  "child_protection": "enforced",
  "launch_profile": "codex",
  "evidence": "strict",
  "io": { "mode": "batch", "stdin": "null", "pty": false },
  "capture": { "stdout": { "state": "captured", "limit_bytes": 1048576, "observed_bytes": 1048576, "stored_bytes": 1048576, "truncated": false, "retain": "90d" }, "stderr": { "state": "not_captured" } },
  "state_cleanup": "complete",
  "owner": { "pid": 41200, "pidfd_birth": "boot:…:start:…", "boot_id": "…", "started_at": "…" },
  "state": "settled",
  "settlement": "recorded",
  "outcome": { "kind": "exited", "code": 0, "signal": null, "unknown": false, "unknown_reason": null },
  "coverage": {
    "exec": "active",
    "fs.write": "active",
    "fs.deny": "active",
    "net": "degraded",
    "proxy.net": "active",
    "limits": "active",
    "gaps": [ { "class": "net", "from_seq": 812, "to_seq": 830, "reason": "producer backpressure" } ]
  },
  "chain": { "head_seq": 1442, "head_digest": "sha256:…" },
  "holds": [],
  "receipts": ["receipts/jail-prepared.json", "receipts/jail-enforced.json", "receipts/jail-settled.json"]
}
```

`jail_profile: none` is a settled uncontained run, not a missing field. Tree exit
and canonical settlement are separate. An owner can prove `exited` locally while
`settlement` is `pending`. Status shows that. It does not show the run as fully
recorded.

### 5.4 Durability

This is the gate for trusting the ledger, and later for removing `audit/` and
`agent/effect_ledger.ex`. Each property has a test. References:
[`audit/store.ex`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/audit/store.ex),
[`agent/effect_ledger.ex`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/agent/effect_ledger.ex).

1. **One owner, and an honest label for `none`.** Under an enforced profile the
   child cannot reach `serve.sock`, the store, or a producer token: they are
   outside its mount and pid namespace, and `ptrace` is denied. Under `none`
   the same user can read and write the store. The receipt says
   `child_protection: unprotected`, and `verify` does not upgrade that label.
   Stripping token variables is hygiene. It is not a boundary. The accepted
   hole is §1.
2. **Durable acknowledgement.** `fsync` the event data and the directory before
   returning. Replace `run.json` by write, sync, rename, directory sync. Index
   after acknowledgement. Test disk-full, interrupted writes, and lost replies
   at every boundary.
3. **Ambiguous appends stop admission.** Uncertain durability poisons the stream.
   Dependent dispatch stops. No sequence is reused. Recovery never truncates a
   stream to make `verify` pass.
4. **Idempotent identities.** `request_id`, `effect_id`, and `attempt_id` are
   stable. A replay returns the same receipt or refuses a conflicting payload.
   Deduplication state lives at least as long as the run and its reconciliation
   window. A successful append whose reply was lost never launches a second child.
5. **Live failure.** Producer queues and capture sizes are bounded. `strict`:
   loss of the daemon stops admission and the launch owner terminates the tree.
   If the launch owner dies, the tree dies with it and reconciliation records
   `outcome_unknown` for effects not already in the ledger. `best-effort`: an
   already admitted run may continue with degraded evidence. Bounded pending
   records and gap summaries are reconciled when the daemon returns. No new
   admission bypasses the durable gate. Failure to persist a local exit record
   terminates the tree and leaves the transition unknown. It does not fabricate
   an acknowledgement.
6. **History at the cut.** When `audit/` and the effect ledger are removed,
   ship a read-only export of those stores, or a lossless import that preserves
   bytes, ids, and receipts. A new chain over imported summaries is not
   historical custody. This is an obligation of the cut, not a feature of the
   new ledger.

Acceptance: crash injection at every admission, append, and settlement boundary;
concurrent appends; forged producer messages; store and index recovery; privacy
fixtures. Killing the writer mid-run yields a known shutdown or an explicit
unknown with a gap, never a fabricated settlement. A contained child cannot
open the store. A `none` run's `verify` output still says `unprotected`. A
capture past the cap is `truncated`. Vendor state is gone once the cgroup is
empty, including when the outcome is unknown.

Source: `audit/`, `agent/effect_ledger.ex`.

## 6. `ouro-fleet`

The fleet places **jobs**. A job is one operator request to run Codex, Claude
Code, OpenCode, or another `argv` on a machine they trust. Each execution is an
**attempt** with its own ledger run and launch owner. The worker node is
authoritative for a live attempt. A controller's projection may be stale, and
that staleness does not move ownership.

### 6.1 Verbs

These are trusted infrastructure-operator verbs. A developer submission endpoint
must not expose them directly. Milestone 4's `ouro managed` interface authorizes
each operation, forbids uncontained/unobserved jobs and limits placement to
company-administered eligible workers.

Membership verbs stay as in [FLEET.md](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/docs/FLEET.md) §2: `setup`, `add`, `leave`,
`forget`, `status`, `doctor`, `devices`, `service`, `tag`.

```text
ouro fleet run   --request-id ID [--on MACHINE|auto] [--dir PATH]
                 [--jail agent|tool|build|none|FILE] [--launch NAME]
                 [--observe on|off] [--limit K=V]… [--evidence strict|best-effort]
                 [--capture stdout|stderr]… [--capture-limit BYTES]
                 [--tag K=V]… [--json] -- <argv>
ouro fleet wait JOB [--json]
ouro fleet status [JOB]
ouro fleet kill JOB [--signal S]
ouro fleet ledger JOB <ledger query flags>       # routed to the owning worker
```

`--jail` defaults to the launch profile's `jail` when `--launch` is set, and to
`tool` otherwise. `--jail none` is admitted. The receipt says `containment: none`.
A policy that cannot be applied refuses before exec and does not become `none`.
`--observe` defaults to `on` for every jail mode. The fleet passes it through
to the jail and does not record syscalls itself. `--observe off` is admitted
and status shows the audit classes as unsupported.

Fleet jobs are batch. They have no terminal, and stdin is `/dev/null`. The
operator puts the agent's batch command in `argv`. A child that reads stdin
gets EOF. Stdout and stderr go to `/dev/null` unless `--capture` names that
stream. Capture uses §5.2 L5. The owner drains the pipes; the operator
disconnecting does not close them or hang up the child. The admission response
is the job id and the I/O settings, not the child's output. Changing capture
settings under an existing `request_id` refuses.

`ouro fleet ledger JOB show --with-transcript` returns the captured prefix, or
`not_captured` for a stream that was not selected. An unreachable worker is
`unavailable`. This is byte output, not a parsed session and not a workspace
export.

`--dir PATH` is a directory that already exists on the worker. It is the
workspace. The fleet does not copy, clone, or mirror it. Omitted, the workspace
is the attempt's empty scratch. In milestone 3, getting a tree onto the worker
is the operator's job. Managed milestone 4's Rust materializer supplies a fresh
private tree from an authorized pinned input; the developer selects a logical
input id and cannot supply `--dir` or another worker path.

There is no adapter flag, no approval verb, and no collect verb.

### 6.2 Functionalities

| # | Functionality | Contract |
|---|---|---|
| F1 | Membership and trust | As FLEET.md. A connected node owns every other. The jail contains the child, not a peer. Credentials are provisioned per node. No verb moves them. |
| F2 | Admission | Digest the request, including `argv`, directory, resolved policy, launch profile, observation/evidence modes, and I/O/capture settings. Register `{request_id → job}` durably on the controller. Select a worker (§6.2 F6). The worker reserves the attempt, calls `ledger prepare`, persists the reservation, and starts the launch owner. The owner takes the exclusive launch lease and is the only writer of `admitted`, after the jail is prepared and before it releases the gate (§7.1). A lost reply retries the same `request_id` and the same attempt. It never creates a second job or a second child. |
| F3 | Records | Job: `job_id, request_id, request_digest, dir, argv_digest, policy_digest, launch_profile, jail_profile, io, capture, created_at`. Attempt: `attempt_id, node, owner{pid, pidfd_birth, boot_id}, workspace, lifetime, lease, run_id, reachability, evidence_health, child_protection, state_cleanup, settlement, outcome, timestamps`. Status responses carry neither credentials nor raw `argv`. |
| F4 | Supervision | The launch owner owns the tree and is not a child of the fleet worker (§5.1). The ledger daemon survives a worker restart. The worker reattaches by attempt id and checks pidfd birth and boot id before treating the owner as the same process. `kill` goes through the owner and stays `pending` until termination is observed. Owner loss kills the tree. Reconciliation records what is known. |
| F5 | Readiness | `doctor` on each node: jail probes when the node is expected to jail, a cgroup the supervisor can kill, launch-profile sources present and unprinted (§4.5), ledger daemon healthy, and an attempt that would outlive operator disconnect. A profile's experimental or supported mark is separate (§7.4). Uncertain required capabilities are ineligible. A readable directory is not readiness. |
| F6 | Placement | Eligible means a trusted node whose readiness matches the job. A jailed job needs the jail backend and any limit the profile requires. A `none` job needs the launch owner, the ledger, and a cgroup; it does not need the jail backend. Observation on needs the sensor. Then fewest active attempts. Refusals are per node, with reasons. Eligibility is rechecked under the lease before launch. |
| F7 | Reconciliation | At boot and on reconnect: read local attempt records, verify each owner by pidfd birth and boot id, reattach to live owners, settle confirmed exits from receipts, and keep the rest `outcome_unknown`. Missing connectivity does not mark a remote attempt failed. |

### 6.3 Ownership and uncertainty

Execution moves `queued → prepared → starting → running → exited`. `refused` is a
pre-exec 125. `killed` requires an observed signal. `outcome_unknown` means the
execution or its effects cannot be settled. `reachability` (`reachable` /
`unreachable`), `evidence_health` (`ok` / `degraded` / `poisoned`), and
`settlement` (`pending` / `recorded` / `unknown`) are separate fields. An unknown
outcome is shown as unknown on every surface that shows success.

`child_protection` is its own field. `none` stays `unprotected` on a clean exit
with a full audit tape. `state_cleanup` is its own field too: a finished run
can still say `pending`.

The critical window is **admitted, and the launch acknowledgement is missing**.
Reconcile the same attempt against its launch-owner record. Do not assume it
failed to start. A replacement owner must prove the old tree cannot execute
(pidfd dead, and the cgroup empty when one was used) or leave the attempt
unknown. A higher generation number does not stop a partitioned worker.

No automatic retry. Confirmed local death does not prove a remote request the
child already made had no effect. Silence is not success. `wall` is the deadline.

### 6.4 What the fleet does not do

The fleet starts `argv` under a launch owner. It does not speak a vendor
protocol, relay an approval, resume a vendor session, push a branch or render a
page. Milestone 4's Rust owner collects bounded artifacts after verified tree
death; fleet only places and reconciles that owner. General workspace sync and
publishing remain unscheduled. A launch profile that grew a protocol parser
would violate D3.

Source: `fleet/`, [FLEET.md](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/docs/FLEET.md). Reuse membership. Do not keep
`cluster/`, `mesh/`, `session/`, or `gateway/` on the grounds that the fleet
once used them (§9).

## 7. The composition contract

The jail's draft schemas live under `docs/specs/jail-v1/`: `jail-receipt.schema.json`,
`event.schema.json`, its `jail-event.schema.json` producer restriction and the
canonical policy snapshot freeze at milestone 1, because the jail's trace is already
the audit record. The future ledger implementation will define `run.schema.json`
at milestone 2. Job and attempt records are frozen with milestone 3. Components announce the schema ranges they accept in
`ouro version --json`. A mismatch refuses before dispatch. The ledger implements
the writer against the event schema the jail already froze.

### 7.1 Process tree and admission

For managed submissions, the owner also applies the authenticated policy/input/
service checks in [managed teams §7](docs/specs/managed-teams-v1.md#7-admission-revocation-and-reconciliation).
It compares the prepared policy, argv and applied capabilities with the authorized
plan, then durably binds authorization before step 5 can release the gate. Gate
possession alone is not company authorization. The managed-record schema freezes
with milestone 4, without changing the jail's canonical policy or gate schema.

```text
fleet worker                         control client; not the parent's cgroup
ledger daemon                        store only; survives the worker
launch owner: ouro-ledger run        one per attempt; reads the trace, writes the store
  └─ ouro-jail supervisor            sensor, proxy, and the none cgroup live here
       └─ child                      argv, contained or --profile none
```

1. The controller registers `{request_id → job_id, worker}` durably. The same
   payload returns the job. A different payload refuses. Nothing is dispatched
   before this record.
2. The worker reserves `attempt_id`, calls `ledger prepare`, and persists the
   cross-references. No child can execute from this reservation alone.
3. The worker starts `ouro-ledger run` for that attempt. The owner takes the
   exclusive launch lease under `<data>/attempts/<id>/` and checks the
   reservation. The daemon checks the peer's uid and pid birth identity before
   issuing the owner token. A duplicate start attaches to the existing owner. A
   dead owner enters reconciliation and is not restarted.
4. The owner starts `ouro-jail run` with the gate closed. The jail writes the
   *prepared* receipt and blocks on the gate. For `none`, preparation creates
   the cgroup and records `child_protection: unprotected`. For a fleet job,
   stdin is `/dev/null` and the output sinks exist. Failures here are `refused`.
5. The owner appends `admitted` and, once that append is durable, releases the
   gate once. The jail execs the child and writes the *enforced* receipt.
   Events flow. Verified tree termination yields the *settled* receipt. The
   canonical `settled` event is appended separately. Until it is acknowledged,
   `settlement` is `pending`. Vendor-state cleanup starts once the tree is
   dead, including when the outcome is still unknown.

On reconnect the worker recovers the attempt by id. It does not launch again
because an acknowledgement is missing. Standalone `ouro-ledger run` performs
preparation and steps 4–5 locally, without fleet records. Standalone
`ouro-jail run` uses its local supervisor and does not perform this handshake.
The handshake prevents a duplicate launch. It does not promise exactly-once
effects outside the machine. Every window between the steps has a
fault-injection test.

### 7.2 Records

A source event is one JSON object per line, length-prefixed on sockets.
The complete draft envelope is specified in [Jail v1 §13](docs/specs/jail-v1.md#13-wire-records-receipts-and-bounded-trace);
this sketch omits some required envelope fields:

```json
{
  "schema": "ouro.event/1",
  "attempt_id": "att_01J…",
  "source": "proxy",
  "source_seq": 17,
  "observed_at": "2026-09-21T11:02:03.412Z",
  "operation": "net.connect",
  "stage": "result",
  "decision": "allow",
  "outcome": { "ok": true, "bytes_in": 18211, "bytes_out": 902, "ms": 341 },
  "fields": { "host": "api.openai.com", "port": 443, "resolved": ["104.18.7.192"] }
}
```

The canonical event is the source event plus `run_id`, `seq`, `received_at`,
`provenance: {role, peer_pid, token_id}`, and `prev`. Operations: `proc.exec`,
`proc.exit`, `fs.create`, `fs.write`, `fs.rename`, `fs.unlink`, `fs.deny`,
`net.connect`, `net.dns`, `limit.hit`, `jail.receipt`, `intent.admitted`,
`intent.denied`, `intent.settled`, `note`. `fs.create`, `fs.write`, `fs.rename`
and `fs.unlink` share the `fs.write` coverage class. `source` is `wrapper`,
`audit`, or `proxy`; proxy network evidence uses `proxy.net` coverage.
Jail v1 writers are restricted by the [producer schema](docs/specs/jail-v1/jail-event.schema.json)
to audit operations, proxy net.connect, and wrapper note/jail.receipt.
net.dns, limit.hit and intent.* remain reserved in that producer contract;
future ledger-owner intent events retain the shared envelope and their own
authenticated producer-role checks.

Ledger sequence is ingestion order. It is not causal order and it is not
wall-clock order across machines. A timestamp does not repair a missing record.

### 7.3 Milestone proofs

**Milestone 1.** §4.10, with the ledger and the fleet absent from `PATH`.

**Milestone 2.** The §5.4 suite against a scripted child, with the fleet absent.
The jail suite still passes with the ledger absent. A contained child cannot
write the store. A `none` run stays labelled `unprotected`. A killed writer
leaves a gap or an explicit unknown. An unsupported query renders as unobserved.

**Milestone 3.** Two nodes. A scripted child under a jail policy, and the same
child under `--jail none`. Disconnect the operator: the attempt continues.
Restart the fleet worker: the same owner is still the parent, and reattach
does not launch a second child. Lose the admission reply: one child. Kill the
owner of a contained run: the tree is dead, and any effect not already recorded
is `outcome_unknown`. Kill the ledger under `strict`: the tree stops and the
gap is recorded. Kill it under `best-effort`: the run may finish, evidence is
degraded, and settlement is not fabricated. `status` shows `none` as
uncontained and unprotected. A batch child sees EOF on stdin. A captured stream
past the cap is `truncated`. An unselected stream is `not_captured`. Disconnecting
the client does not hang up the child. Vendor state is removed only after the
jail verifies its declared lifetime scope without detected integrity loss;
none retains its unprotected limits.

A launch-profile smoke that needs a vendor binary or a credential is reported
skipped when either is absent. A skip does not mark the profile supported. A
skip is not a pass.

### 7.4 One real agent

Scripted fixtures are the milestone gates. Calling a profile supported, and
deleting the in-tree agent, each wait on one further run: the real binary, with
real credentials, recorded in `docs/specs/jail-v1/agent-compatibility.md`.
The note names the Ouroboros revision, the profile, the vendor version, the OS,
and the jail mode. It stores no tokens and no vendor-state archive.

The run is the agent's normal batch command. It reaches its API through the
profile's hosts, does one observable thing, and exits. The receipt matches.
For the cut, that same shape also runs on a second node, and disconnecting the
operator does not start a second copy. One of Codex, Claude Code, or OpenCode
is enough. The other two stay experimental until they have their own note.
An `agent` run does not mark `none` supported. A credential missing in CI skips
the smoke and leaves the profile experimental. The tools still ship.

## 8. Milestones

Dependencies, not a calendar. Milestone 2 needs milestone 1's receipt contract.
Milestone 3 needs milestone 2. Milestone 4's single-worker pilot needs milestones
1 and 2 and can proceed alongside 3; its multi-worker stage needs 3 as well.
The D8 evaluation is recorded before milestone 1 is declared green. No schema
is frozen before the milestone that ships it.

Status 2026-09-22: no milestone has started and no code exists in this tree.
The next change is J0 (jail-v1 §16) on the reference host. Until J0's report
is recorded, revisions of these specifications are corrections and measured
results, not new requirements or subsystems.

| Milestone | Deliverable | Exit |
|---|---|---|
| 1. Jail | `ouro-jail` on the D9 kernel: profiles including `none`, the audit sensor, the three launch profiles, enforcement, the supervisor cgroup, receipts, vendor-state cleanup, doctor, and the scripted nesting fixture. The event schema freezes here. | §4.10 passes. Profiles stay experimental. No other backend is a permanent test oracle. |
| 2. Ledger | `ouro-ledger serve` and `run`, the verbs in §5.2, the §5.4 suite, bounded capture. | A contained child cannot write the store. `none` stays labelled unprotected. A killed writer leaves a gap or an explicit unknown. |
| 3. Fleet | Batch jobs: admission, supervision, placement, reconciliation, `--capture`, `--jail` and `--jail none`. | §7.3 passes on two nodes. A lost reply does not start a second child. An unproved outcome stays unknown. |
| 4. Managed teams | Authenticated Linux/macOS client, company/project policies, approved services, isolated inputs, bounded artifacts and project-scoped evidence. T1 uses one Linux worker; T2 adds fleet. | T1 passes MT01–MT14 plus actual internal-code, untrusted-contribution and confidential-model workflows. T2 adds MT15–MT16. A green jail suite alone does not establish managed readiness. |

After milestone 3 is green, one cut does §9 and the D6 packaging. That change
adds no features.

## 9. The cut

Deletion sets come from live dependencies after milestone 3, not from this table.
The cut cannot proceed on scripted fixtures alone. §7.4's one real-agent note
must be recorded for at least one of Codex, Claude Code, or OpenCode.

**Preserved.** The whole previous tree is branch `legacy` at
`f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82`, and the tag `thesis-4-preserved`
marks the same commit. Both refs must exist on the remote before the tooling
tree replaces `dev` there: every link in these specifications to a preserved
file uses that hash, and a hash link stays valid only while some ref reaches
the commit. The self-improvement set D2 names lives there in full: `wasm/`,
`wasm.ex`, `upgrade/`, `self/`, `runtime/capabilities.ex`, `tools/forge.ex`,
the wasm Rust clients, `bench/`, `priv/self`, `priv/wasm`, the self-development
and wasm scripts, the related make targets and workflows, `SELF.md`, `WASM.md`,
`WASM_GUIDE.md`, `BENCHMARKS.md`, `docs/self/`, `.agents/skills/forge/`.
Nothing is deleted from this tree; the cut below acts on the legacy line.

**Delete in the cut, once unreferenced.** `provider/native/` and `provider/*.ex`;
`interactive/` and `interactive_session.ex`; the chat paths of `web/`, `gateway/`,
and `tui/src/`; `prompt/`, `attachments/`, `poll/`, `action/`; `agent/effect_ledger.ex`
and `audit/` after the §5.4 history export; `jido*`, `req_llm`, `earmark`, and
the Phoenix surface. `cluster/`, `mesh/`, and `session/` go in the same cut
unless milestone 3's membership still calls them. `workspace/` mirrors,
provisioning, and return go. Milestone 4's bounded input/artifact contract does
not retain the former workspace synchronization subsystem by implication.

**Reuse.** Fleet membership as FLEET.md describes it, for as long as milestone 3
places jobs through it: the trust model, the secret bundle, and `setup` / `add`
/ `leave`. The data directory. The release plumbing the three binaries need.
Shared authentication and configuration stay only where the fleet worker still
reads them.

A plane is not kept because a chat client, a session, or a mesh once used it.

## 10. Gates

For code that remains: `mix compile --warnings-as-errors`, `mix format --check-formatted`,
`mix test`, `mix dialyzer`; `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test` for the new crates; `make boot-gate` for as long as the BEAM
application remains.

Added by milestone: jail conformance (1); ledger durability, the unprotected
label, and capture (2); fleet fault tests (3); managed identity/policy/input/
artifact/privacy gates MT01–MT16 (4). §7.4 is one real-agent note
before a profile is called supported and before the cut. A credential-dependent
skip leaves the profile experimental. It does not fail the scripted suite, and
it is not a support claim. At milestone 3 each tool's suite still runs with the
other two stopped.

Managed team readiness additionally needs the real company identity, model/
service and storage integrations tested by MT01–MT14. A simulator or a standalone
agent smoke cannot establish those deployment guarantees.

Rules carried from `core.md` §5: the cut adds no features; tests travel with
the code; a durable-format change sweeps retired atoms and states the blast
radius per store; `docs/experiments/` is never added.

## 11. Risks and limits

- **The category is occupied.** `srt` and Greywall are candidates to reuse. The
  product is the receipt, the queryable record, and remote spawn around a
  boundary.
- **Integration owns the guarantee.** Reusing a backend does not prove this
  policy, this nesting rule, or this evidence contract. The backend must leave
  a supervisor outside the child so the audit sensor can attach. A missing
  mechanism needs a failing gate. A rewrite is not the default.
- **Evidence is the closed set.** A hash chain preserves order and integrity
  relative to this node's store. The sensor sees the calls in §4.8, not every
  syscall, and not a path race after the kernel copied the argument. A gap
  makes that interval unobserved. Independent custody is unscheduled.
  `--observe off` is a blind run and the receipt says so.
- **Platform asymmetry.** Linux bind mounts cannot promise `all_descendants`.
  The coverage matrix is part of the receipt. A fixture on one kernel does not
  speak for another.
- **Launch profiles go stale.** `codex`, `claude`, and `opencode` name files
  and hosts those agents use today. A missing file refuses the launch. A
  vendor moving its credential path is a profile change. The tools do not
  track the agent's protocol.
- **Partitions and external effects.** A missing reply is not a failure. Killing
  the local tree does not undo a request the child already sent. This spec
  promises no exactly-once external effect.
- **Credentials and captures.** The child can read a credential it was given.
  `copy_rw` on a refresh token can rotate the node's copy out of usefulness.
  Managed credential copies are deleted with the vendor-state directory after
  the tree is dead (§4.5.1). Explicit captures may contain secrets, keep a
  bounded prefix, and follow ledger retention. An uncaptured fleet stream is
  discarded.
- **`--jail none` is uncontained.** The ledger label says `unprotected`. The
  supervisor kills the cgroup; if the supervisor dies first, the outcome is
  unknown. Status shows both.
- **Ubuntu 24.04+.** Restricted user namespaces can block the outer or the
  nested sandbox. `doctor` measures both. The operator owns any host-policy change.
- **Observer provisioning is the critical path.** J1 requires observation on,
  from a non-root supervisor, with no setuid helper and no host-policy change by
  the tools. Ubuntu 24.04 restricts unprivileged user namespaces through
  AppArmor and gates BPF tracing behind capabilities the operator must
  provision. J0 measures this on the reference host before anything else
  (jail-v1 §5.2). If the eBPF candidate cannot attach under a provisioning the
  operator accepts, the fallback candidates named there are measured against
  the same closed set. If none passes, the blocker is recorded and J1 does not
  ship with `--observe off` as its acceptance run.
- **The workspace is not a git boundary.** Shared inodes and alternates are the
  operator's problem until a later proposal says otherwise.

The product proof is Codex, Claude Code, or OpenCode — or any other agent
started the same way — contained, recorded, and placed on another machine,
with uncertainty visible wherever the tools cannot see. Ouroboros does not
supply the agent.

## 12. References

Checked 2026-09-21. Revalidate a pinned backend when milestone 1 starts.

- [Anthropic `sandbox-runtime`](https://github.com/anthropics/sandbox-runtime):
  Seatbelt and bubblewrap profiles, Unix-socket bridge, proxy filtering.
- [Greywall](https://github.com/GreyhavenHQ/greywall): containment candidate for
  D8. Pin a revision before relying on it.
- [seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
  and [seccomp filter semantics](https://docs.kernel.org/userspace-api/seccomp_filter.html).
- [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html): `cgroup.kill`
  and subtree membership. The supervisor uses them. A process-group signal does
  not replace them.
- [setsid(2)](https://man7.org/linux/man-pages/man2/setsid.2.html) and
  [PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html):
  a descendant can leave a process group; the death-signal setting is cleared
  on fork. Neither mechanism alone establishes whole-tree death.
- [systemd termination](https://github.com/systemd/systemd/blob/main/man/systemd.kill.xml):
  a child of a service dies with that service. The launch owner is not a child
  of the fleet worker.
- Preserved implementation (branch `legacy`, tag `thesis-4-preserved`, commit f3b2dbfd): [`audit/store.ex`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/audit/store.ex),
  [`agent/effect_ledger.ex`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/agent/effect_ledger.ex),
  [`sandbox/bwrap.ex`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/provider/native/sandbox/bwrap.ex),
  [`sandbox/sandbox_exec.ex`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/lib/ouroboros/provider/native/sandbox/sandbox_exec.ex),
  [FLEET.md](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/docs/FLEET.md), [`core.md`](https://github.com/monocursive/ouroboros/blob/f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82/docs/proposals/core.md) §7.
