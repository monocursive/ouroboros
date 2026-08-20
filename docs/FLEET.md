# Ouroboros Fleet

An implemented secure core plus the evolution design for a fleet of Ouroboros runtimes
— a Mac, a Linux laptop, a VPS — joined as one BEAM cluster.

## Current shipped core (2026-08-20)

The beginner path no longer requires the environment/OpenSSL runbook described later in
this document:

```sh
# First machine
ouro fleet create
ouro fleet invite --machine laptop --host laptop.example-tailnet.ts.net --out laptop.ouro

# Invited machine, after privately copying the mode-0600 file
ouro fleet join laptop.ouro
ouro daemon

# On both machines, for crash/login recovery. Review and run the activation command it prints.
ouro fleet service install

# Either machine
ouro fleet status
ouro fleet doctor
ouro new --machine laptop --provider codex --workspace /absolute/path/on/laptop/project

# If an expected invitation is abandoned, publish the signed membership change
ouro fleet invite cancel --machine laptop --out fleet.ouro-roster
# On every existing member, inspect service ownership before stopping anything
ouro fleet service status
# Deactivate an installed recovery unit with the exact command above; otherwise: ouro stop
ouro fleet sync import fleet.ouro-roster
# Reactivate that unit with its printed command; otherwise: ouro daemon
ouro fleet doctor

# Only for a permanently lost machine that owned sessions, after inspecting/exporting
# any recoverable owner-local state. Run locally on every gateway that may have seen it.
ouro fleet sessions forget --machine laptop --accept-state-loss
```

`fleet status` is fleet-wide. `fleet doctor` merges live fleet facts with host-local
certificate, interface, port, log, and recovery-service checks, so run doctor locally on
each machine during setup.

Each machine's `OUROBOROS_DATA_DIR` leaf must be a real same-user directory at mode
`0700`. The packaged launcher creates a missing leaf privately, but refuses symlinks,
foreign ownership, non-directories, and broader existing modes without changing them.
If an imported path is refused, inspect its ownership and contents before applying
`chmod 700` (only when it is truly yours), or select a fresh absolute path; do this
before installing or retrying the generated fleet service.

Cancel/import changes membership bookkeeping; it does not revoke credentials and does not
erase positive session-owner evidence. An offline former owner therefore continues to
make session lists fail closed after restart. If the machine is permanently lost, first
inspect or export any recoverable owner-local state, then run `ouro fleet sessions forget
--machine NAME --accept-state-loss` locally on every gateway/data directory that may have
observed it. The authenticated operate call requires the matching signed-roster tombstone,
refuses while that node is connected, and syncs both evidence planes before success. It is
an irreversible local discoverability boundary only: it neither deletes files on the lost
machine nor revokes its credential.

Implemented now:

- a private per-machine profile, generated fleet CA, per-node TLS certificate/key, 0600
  cookie file, dynamic `vm.args`, stable identity/ports, owner-attested invitations and
  membership rosters, and create/invite/join/sync/leave validation in the packaged
  `ouro` binary;
- no real fleet cookie in argv or the environment; a disposable boot cookie is replaced
  from the validated private file before supervised formation starts;
- private-interface TLS distribution with a fleet-specific EPMD port, supervised static
  reconnect, a last-known expected/connected/offline machine directory, compatibility
  and transport diagnostics, plus `fleet.status` and `fleet.doctor` gateway methods;
- one local gateway routing remote starts, session lists, calls, replay, subscriptions,
  and follow-ups over BEAM distribution using owner-qualified references;
- durable positive session-owner evidence that survives gateway/runtime recovery, plus an
  explicit tombstoned-offline state-loss command instead of implicit deletion on cancel;
- Settings → Machines guidance, a connected-machine New Session picker, and retained
  cursor recovery when a remote owner temporarily disappears;
- remote Team worker reconciliation after the worker's machine restarts;
- generated launchd/systemd-user recovery units, with activation kept explicit;
- separate private service logs: OTP live-rotates `runtime.log` after 2 MiB with three
  archives while restart-rotated `daemon.log` retains bootstrap/VM/crash diagnostics,
  with no shared rotated inode between their writers; and
- downloadable per-platform release assets plus checksums in the tag workflow (the
  workflow remains honestly unproven until the first tag runs).

The checked-in packaged exercise builds a three-node TLS mesh with reverse/cold boot,
late join, hub loss/rejoin, automatic service-run crash restart, and final cleanup. CI
runs that exercise on Linux before a release artifact may publish. This remains an
isolated same-host proof, not a claim that a release has already been installed on three
physical networks.

For a real network, run `tailscale status`, `tailscale ip -4`, and `tailscale ping PEER`
before `fleet create`. Create prints the exact fleet-specific EPMD port and TLS
distribution range to allow only between the private fleet addresses. The full
copy/paste setup, signed roster flow, recovery-service steps, and honest limits live in
the README's **Running a cluster** section.

Fleet placement has one explicit, manually maintained protocol fence:
`fleet_protocol_revision: 1`. A machine is compatible only when that revision, the
Ouroboros version, and the OTP release match. CPU architecture and Elixir version remain
inventory rather than placement fences. Bump the integer whenever fleet posture, remote
session routing, or distributed ownership semantics become unsafe across revisions; do
not replace it with a build-path or source hash.

Still intentionally deferred: automatic Tailscale LocalAPI discovery, free-form tags,
logical workspace maps, heterogeneous forge orchestration, replicated journals, live
provider migration, quorum/fencing, and multi-cluster federation. One Erlang cluster is
one trust domain. A network partition can produce independent views; no section below
should be read as a claim of partition-safe consensus.

## Historical design record (pre-implementation snapshot)

Everything below this heading is the original adversarial evolution survey that led to
the implemented core above. It is retained as design history, **not** as current setup or
feature documentation. In particular, its “does not exist” statements and file:line
citations describe the pre-fleet tree and are now intentionally stale. Use the current
core section above or the README for operation; use the remainder only to understand
decisions and deferred ideas such as tags, Tailscale discovery, logical workspaces, and
HA.

The longer-term design targets discovery without a hand-maintained host list and routing
by **tags**: free-form, node-advertised capability labels (`gpu`, `docker`,
`provider:claude`, `workspace:ouroboros`, `arch:aarch64-apple-darwin`) layered beside the
existing closed role enum.

This historical record was produced by a four-way adversarial code survey (cluster/distribution,
gateway/TUI, mesh/team/orchestration/workspace, upgrade/forge/rollout) on branch
`review-fixes`. Its citations were verified against that earlier snapshot, not the
current working tree. Sections: what existed (§1), decisions (§2), defects identified
(§3), the design (§4–§12), security posture and honest limits (§13), implementation
slices (§14), deferred (§15).

---

## 1. Historical baseline at survey time

What the fleet vision can already stand on:

- **Distribution-aware identity exists below the gateway.** Session refs carry their
  owner node (`lib/ouroboros/interactive/ref.ex:4-12`,
  `lib/ouroboros/coding/task_ref.ex:4-13`) and `call/2` routes to the owner over
  `:erpc` with typed `{:owner_unavailable, node}` refusals
  (`lib/ouroboros/interactive_session.ex:254-266`,
  `lib/ouroboros/coding_session.ex:171-183`). `start_on/2,3` exists on both planes.
  The mesh (`:pg` scope) is already cluster-wide, and `agents.list/state/stop` through
  the gateway already sees the whole cluster (`lib/ouroboros/mesh.ex:109-127,198-216`).
- **The per-node fact channel exists.** `Cluster.local_posture/0` returns
  `%{node, role, running}` (`lib/ouroboros/cluster.ex:229-231`), is probed via bounded
  `:erpc` (`cluster.ex:504-517`) and multicalled fleet-wide (`cluster.ex:488-502`).
  Its consumers pattern-match with open maps — verified — so **adding keys is a safe
  rolling change**.
- **Placement is a single funnel.** `Cluster.ensure_placeable/1`
  (`cluster.ex:264-271`) has exactly two callers: `mesh.ex:67` and
  `team/server.ex:363`. `ensure_role/2` already special-cases `:any`
  (`cluster.ex:243`) — the shape a tag predicate extends.
- **Formation is pluggable.** libcluster 3.5 with `none|epmd|gossip|dns`
  (`cluster.ex:105,341-388`); a new strategy is one atom, one `build_topologies/1`
  clause, one module.
- **A working precedent for a cross-node gateway method** with typed transport
  failures and an inner timeout below the method ceiling: `signing.decisions`
  (`lib/ouroboros/gateway/methods.ex:756-792`).

What did not exist in that pre-implementation snapshot (not current claims):

- No Tailscale/tailnet/MagicDNS awareness of any kind.
- No tag, label, or capability-advertisement concept; `nodes_by_role/1` is the only
  "give me candidate nodes" primitive (`cluster.ex:191-196`).
- No selector anywhere — every "where" is a concrete `node()` atom a caller names.
- No cross-node listing of sessions, teams, plans, rollouts, or provider
  availability; `interactive.list`/`coding.list` filter `&(&1.node == node())`
  (`interactive_session.ex:70`, `coding_session.ex:52`).
- No `node` parameter on `interactive.start`/`coding.start`
  (`gateway/methods.ex:235-247`); no `agents.start` gateway verb at all.
- No host field in `gateway.json`; every client dials `127.0.0.1`
  (`tui/src/main.rs:962-964`).
- No fleet registry in `ouro`; one transport, one cursor table, one `(Plane, id)`
  keyspace (`tui/src/ui/app.rs:419-439,1298-1333`).
- No workspace advertisement or logical naming; no grant replication; no per-arch
  builder selection; no reconciliation between the N per-node rollout registries.

At that survey point, the environment for a sleeping-laptop fleet was hostile: epoch allocation
refuses fleet-wide if any *named* target is unreachable (`upgrade/epoch.ex:94-96`),
recovery adopts only node-local work (`coding/recovery.ex:89`,
`interactive/recovery.ex:64`), `Cluster.Monitor` logs nodeup/nodedown and does
nothing else (`cluster.ex:19-38`), and the gateway cannot even *name* a
currently-disconnected member (`gateway/methods.ex:943-955`).

---

## 2. Decisions

**D1 — One Erlang cluster over the tailnet, not gateway federation.** The BEAM
advantage this project is built on — pids, monitors, `:pg`, `:erpc` routing — only
exists inside a cluster. Gateway-to-gateway federation would re-implement stream
multiplexing and hold N tokens server-side for strictly less capability. The cost is
stated plainly in §13: one cluster is one trust domain.

**D2 — The tailnet is the network boundary; the runtime still refuses cleartext by
name.** Tailscale gives WireGuard encryption, device identity, and ACLs that can
restrict who reaches EPMD and the distribution ports. That addresses the link-layer
harm the cleartext refusal (`config/runtime.exs:76-87`) names. The posture is made
explicit rather than smuggled through `OUROBOROS_ALLOW_INSECURE_DIST=1`: a new
`OUROBOROS_DIST_TAILNET=1` acknowledgment that requires the distribution listener to
actually sit on a tailnet address (§4). TLS distribution remains recommended
defense-in-depth; the cookie is still the only *authentication* between tailnet
members either way.

**D3 — Roles stay closed; tags are a new, advisory axis.** Role decides which
supervision tree boots and is security-adjacent; it stays the 3-enum
(`cluster.ex:104`). Tags are routing hints a node advertises about itself. A hostile
node advertises whatever it likes — tags inherit the role doctrine verbatim
(`cluster.ex:92-99`): placement checks are misconfiguration detection, never an
authority boundary.

**D4 — Self-discovery is a custom libcluster strategy over the Tailscale LocalAPI.**
Both community packages are dead ends (one archived 2023, one polling the cloud API
with an API key on every node, neither filters by ACL tag). Gossip is structurally
dead over a tailnet (multicast; and `cluster.ex:362-371` exposes no interface
binding). DNSPoll bypasses the OS resolver (`:inet_res`) so MagicDNS is invisible on
macOS, and it names nodes `basename@<ip>`. The LocalAPI (`tailscale status --json`)
is local, keyless, live, and carries the peer facts we want: DNS name, tailnet IPs,
ACL tags, online state. §5.

**D5 — Tags resolve to a concrete node at admission; the concrete node is what
persists.** Selection happens once, at the placement seam, against the currently
visible fleet; everything durable (worker snapshots, task states, delegations) keeps
storing a `node()` exactly as today. No dynamic re-binding, no migration. This keeps
every existing recovery and ownership invariant untouched.

**D6 — Workspaces get logical names; absolute paths never cross nodes.** A fleet
node advertises `workspace:<name>` tags from a configured name→root map; a
delegation carries the logical name and the *owner* resolves it. Leases stay
node-local admission, and two nodes sharing a network filesystem remain out of
scope, stated (§9, §13).

**D7 — Fleet view = server-side listing + attach switching; not N live streams.**
Any gateway can answer `fleet.status`/`fleet.sessions` by bounded multicall
(precedent: `signing.decisions`). Opening a session that lives elsewhere switches
`ouro`'s connection to the owner's gateway (the fleet registry knows its address and
token). Holding N concurrent gateway connections with live streams — and the
cross-node subscription rework it implies (`gateway/conn.ex:680-697` resolves
coordinators via a node-local Registry) — is deferred, not designed away (§15).

**D8 — Heterogeneous forge means per-triple builds; the verifier stays strict.** An
artifact is refused on any node whose `{otp_release, elixir_version,
system_architecture}` differs (`upgrade/verifier.ex:115-124`), and the triple is
inside the signed manifest (`upgrade/artifact.ex:90-94`). We do not relax the
comparison; we group targets by triple and forge one artifact per group with a
matching builder (§11). Same source, N artifacts, N signatures, N epochs — honest and
mechanical.

**D9 — Sleep is normal.** Placement and fleet views select from the currently
visible fleet and say who was unreachable. Operations that *name* an unreachable
target keep refusing loudly (epoch, rollout) — but they must refuse *cleanly*, which
today they do not (F5, §3). Sessions owned by a sleeping node are listed with an
unreachable owner and are not adopted; that is a statement, not a TODO (§12).

---

## 3. Fix first — defects that predate the fleet

The survey found real defects that the fleet would trip constantly. Each is
independent of any new feature and should land first (Slice 1).

**F1 — `validate_coding_node/1` checks `is_atom/1` and nothing else**
(`team/server.ex:1845-1846`). The one placement decision that starts *paid provider
work* has no connectivity, runtime, or role check — asymmetric with `add_worker`
thirty lines above (`team/server.ex:362-367`). A typo'd node keeps the delegation
`:starting` for `:delegation_start_retry_ms` (default 300s) because
`ambiguous_start?/1` treats `owner_unavailable` as retryable ambiguity
(`team/server.ex:1417-1420`). Fix: route through `Cluster.ensure_placeable/1`;
refusal `{:invalid_coding_node, node, reason}`.

**F2 — The delegating node canonicalizes the target node's workspace**
(`team/server.ex:1657-1660`, `canonical_workspace/1` at `:1711-1718` calls
`WorkspacePath.canonicalize/1`, which stats the **local** filesystem;
`TaskState.new/4` then re-checks `File.dir?` locally). Cross-node delegation to a
node that has the repo is refused on the node that does not; divergent symlink
resolution between nodes produces a permanent `{:coding_task_owner_conflict, id}` on
every poll (`team/server.ex:2106-2145`). Fix: build the request fingerprint on the
coding node (the pattern `CodingSession.start_on/3` already uses — the whole start
routes through `:erpc` and validation runs on the owner), or carry the workspace
unresolved and let the owner canonicalize before the durable checkpoint. §9 layers
logical names on top; this fix is prior and independent.

**F3 — Default team ids are VM-unique while coordinator ids join a cluster-wide
namespace.** `team_id` defaults to `"team-#{System.unique_integer([:positive])}"`
(`team/server.ex:82`) and `coordinator_id` defaults to `team_id <> ":coordinator"`
(`team/server.ex:1855-1863`), which lands in the `:pg` mesh namespace. Two nodes
minting `"team-1"` silently share one coordinator — the exact bug class this codebase
already diagnosed and fixed twice, with the rule written down: *any id joining a
cluster-visible namespace must carry `node()`*
(`upgrade/rollout/evaluation.ex:575-588`, `upgrade/rollout/probe.ex:155-166`). Fix:
embed the node in the default team id (existing snapshots load unchanged — explicit
ids are untouched).

**F4 — `gateway.json` publishes no host.** The publication carries
`port/protocol/node/pid/scope[/token_file]` (`gateway/listener.ex:185-203`) and every
reader dials `127.0.0.1:port` (`tui/src/main.rs:962-964`). A gateway bound to any
non-loopback address publishes an actively misleading file today. Fix: add a
`"host"` field (the bound address), clients prefer it, absent means loopback —
backward compatible in both directions.

**F5 — A zero-effect deployment records permanent quarantine.** `Rollout.deploy/4`
checkpoints `:deploying` (`rollout.ex:191-205`) *before*
`Coordinator.validate_nodes/1` refuses a disconnected target
(`coordinator.ex:685-694`). The validation-failed receipt carries deployment
recovery `:unchanged`, not `:complete` (`coordinator.ex:666-668`), so `proven?` is
false (`rollout.ex:397-407`) and the registry records `:quarantined` — an operator
debt with no automatic exit (`registry.ex:63`) that later blocks `ForgeExecutor` for
the same module (`forge_executor.ex:248-249`), for a deployment that provably touched
nothing. Fix: validate the target set (connectivity, shape) *before* the
`:deploying` checkpoint, so a sleeping named target is a clean typed refusal with no
registry entry. (Also honest: treat all-`:unchanged` validation receipts as proven
compensation; but refusing before the checkpoint is the correct primary fix.)

**F6 — The builder-must-match-targets invariant is documented, not enforced.**
`build_peer.ex:36-37` claims the artifact's triple is "whatever the peer observed";
in fact `Artifact.build/2` stamps the **forging node's** triple
(`upgrade/artifact.ex:54-56`, called from `forge.ex:150-158` locally), and the
builder's actual triple lands in `metadata.forge.peer_runtime`
(`forge.ex:98,172`) which — verified — is never compared to anything anywhere.
`check_builder/1` checks role only (`build_peer.ex:138-145`). A mismatched remote
builder produces beams whose artifact *claims* the forging node's triple and fails
only at target-side verification, or worse, passes it while carrying beams compiled
under a different ERTS. Fix: at assembly, refuse when
`peer_runtime != local triple` — `{:builder_runtime_mismatch, expected, actual}` —
and correct the `build_peer.ex` doc claim. §11 extends this to per-triple builder
selection; the assertion is prior and independent.

**F7 — Workspace admission is silently absent when roots are unconfigured.**
`Coding.Task.admit_workspace/1` skips leasing entirely when the manager is not
running (`coding/task.ex:205-237`), and the manager only starts when roots are
configured (`application.ex:171-176`). A fleet routes work onto nodes with silently
different safety postures. Minimum fix: surface `workspace: :disabled` as a named
fact in the posture/fleet directory (§7) so placement *can* see it; refusing is a
policy choice left to a required tag (`workspace-admission`).

---

## 4. Substrate: the tailnet posture

The fleet is one Erlang cluster whose members reach each other only over the
tailnet. This section is configuration and policy; the only new code is one
acknowledgment flag.

**Node identity.** Each machine sets its own name to its MagicDNS FQDN:

```sh
OUROBOROS_NODE=ouroboros@mac.<tailnet>.ts.net
OUROBOROS_COOKIE=<one shared secret, generated once, distributed by the operator>
```

Long names are already mandatory (`rel/env.sh.eex:65-71`); MagicDNS resolves through
the OS resolver, which `Node.connect/1` uses. Nothing about `rel/env.sh.eex`'s
refusal ladder changes.

**Ports, pinned.** Build with `OUROBOROS_DIST_PORT_MIN/MAX` (`rel/vm.args.eex:61-65`)
so the distribution listener range is fixed, e.g. 9100–9105. EPMD (4369) is
unavoidable for the epmd strategy and remains reachable tailnet-only.

**Tailnet ACLs are the perimeter.** Fleet machines carry a tailnet tag (e.g.
`tag:ouroboros`); the ACL grants 4369 + 9100–9105 + the gateway port only between
`tag:ouroboros` devices. This is the boundary loopback used to be. It is enforced by
Tailscale, not by this runtime, and the runtime does not check it — stated in §13.

**Transport acknowledgment.** A cleartext-dist cluster still refuses to boot
(`config/runtime.exs:76-87`). The fleet posture adds one explicit escape beside the
generic one:

- `OUROBOROS_DIST_TAILNET=1` — asserts "distribution traffic crosses only the
  tailnet". Accepted **only if** the distribution listener's resolved address is in
  `100.64.0.0/10` or `fd7a:115c:a1e0::/48`; otherwise the boot refuses, naming the
  address it found. This is deliberately narrower than
  `OUROBOROS_ALLOW_INSECURE_DIST=1`, which remains the blunt operator override.
- TLS distribution (`OUROBOROS_DIST_TLS=1` at build) remains recommended on top; the
  two compose.

**Roles across the three machines.** The reference layout: both laptops and the VPS
are `:core`. The signer stays on the most-trusted, least-exposed host — a laptop,
not the VPS (§13). A dedicated `:builder` is optional until Slice 6; forge builds
default local.

**Runbook (Slice 0 — zero code).** The fleet works *today*, manually, with the epmd
strategy and a static host list:

```sh
OUROBOROS_CLUSTER_STRATEGY=epmd
OUROBOROS_CLUSTER_HOSTS=ouroboros@mac.X.ts.net,ouroboros@linux.X.ts.net,ouroboros@vps.X.ts.net
```

plus the identity block above on each machine, TLS-built releases (or the insecure
acknowledgment), and the ACL. Its limits are exactly the fleet gaps this spec
closes: hand-maintained host list, no tags, single-node gateway view, cross-node
delegation blocked by F2.

---

## 5. Formation: `Cluster.Strategy.Tailscale`

A new libcluster strategy module plus one atom in `@strategies` (`cluster.ex:105`),
one `build_topologies/1` clause, and the mirrored validation in
`config/runtime.exs:59-62`. `formation_children/0` (`cluster.ex:327-339`) is
untouched.

**Mechanism.** On each `:timeout` tick (reuse `OUROBOROS_CLUSTER_RECONNECT_MS`,
default 5000):

1. Run `tailscale status --json` (subprocess; the portable path across macOS's GUI
   variant and Linux's `tailscaled` socket — the socket path differs per platform,
   the CLI abstracts it).
2. Parse `Peer` entries; keep those matching the configured filter **and**
   currently `Online`.
3. Derive candidate node names `<basename>@<DNSName-without-trailing-dot>`.
4. `Cluster.Strategy.connect_nodes/4`, exactly as the epmd strategy does
   (`deps/libcluster/lib/strategy/epmd.ex:59-64`).

Offline peers are left alone — distribution's own tick notices a dropped link; the
strategy only ever adds. (DNSPoll's active-disconnect behavior was considered and
rejected: a laptop mid-sleep-transition should not be forcibly disconnected by a
poll race.)

**Configuration.**

```sh
OUROBOROS_CLUSTER_STRATEGY=tailscale
OUROBOROS_TAILNET_TAG=tag:ouroboros        # peer filter: ACL tag, or
OUROBOROS_TAILNET_HOSTS=mac,linux,vps      # peer filter: hostname allowlist
OUROBOROS_CLUSTER_BASENAME=ouroboros       # default "ouroboros"
```

At least one filter is required; naming neither is
`{:missing_cluster_configuration, "OUROBOROS_TAILNET_TAG or OUROBOROS_TAILNET_HOSTS"}`,
refusing the boot through the existing `formation_children/0` raise. The tag filter
suits tagged (server-style) devices like the VPS; the hostname filter suits personal
laptops, whose devices are typically untagged. Both may be set; a peer passing
either is a candidate.

**Refusals, named.** CLI absent → `{:tailscale_unavailable, :cli_not_found}`;
daemon unreachable ("failed to connect to local Tailscale service") →
`{:tailscale_unavailable, :daemon_not_running}`; unparseable JSON →
`{:tailscale_unavailable, {:bad_status, reason}}`. First occurrence at boot refuses
(consistent with misconfiguration policy); a *later* poll failure logs and retries —
a tailscaled restart must not take the formation supervisor down with it.

**Verify at implementation time** (external interface, not this repo): exact field
names in `tailscale status --json` (`Peer` map; `DNSName` carries a trailing dot;
`Tags` present only on tagged devices; `Online` boolean), and CLI behavior when
logged out vs. stopped.

**Tests.** The strategy takes the peer-list source as an injectable function
(default: the CLI), so `test/cluster_test.exs`'s existing patterns cover it: fixture
JSON → derived node set, filter semantics, refusal shapes, trailing-dot handling —
no tailscaled in CI.

---

## 6. Identity: tags

**Boot.** `boot_role!/0` (`cluster.ex:130-141`) grows into `boot_identity!/0`:
resolves role exactly as today, plus a validated tag set into `:persistent_term`.
Malformed tags raise, like an unknown role does.

Tag sources, merged at boot:

- **Static:** `OUROBOROS_NODE_TAGS=gpu,docker` → `config :ouroboros, :node_tags`.
  Parsed in `config/runtime.exs` standing on `System` alone (the `DataDir`
  pattern, `data_dir.ex:1-28`). Comma-separated, trimmed, each matching
  `^[a-z0-9][a-z0-9_.:-]*$`; anything else refuses the boot by name.
- **Derived, free:** `os:darwin` / `os:linux` (from `:os.type/0`),
  `arch:<system_architecture>`, `otp:<release>`, `elixir:<version>` — the verifier
  triple, advertised (§11 consumes it).
- **Derived, configured:** `workspace:<name>` for each entry of the logical
  workspace map (§9); `workspace-admission` when roots are configured (F7).
- **Derived, probed and cached:** `provider:<name>` for each provider whose local
  `provider_status/1` reports a usable installation. Probing shells out, so this is
  resolved once at boot and refreshable on demand (`Cluster.refresh_tags/0`), never
  in the posture hot path.

**Publication.** `local_posture/0` gains two keys —
`tags :: MapSet.t(String.t())` and `runtime :: %{otp, elixir, arch}` — and nothing
else changes: probe and multicall consumers already tolerate extra keys (verified),
so old and new nodes interoperate during a rolling upgrade in both directions.

**Selection.** Beside `nodes_by_role/1`:

```elixir
@spec nodes_by_tags([String.t()], keyword()) :: %{
        matching: [node()],
        unreachable: [node()]
      }
# opts: role: :core (default), match: :all | :any
@spec ensure_placeable(node(), [String.t()]) :: :ok | {:error, term()}
```

`ensure_placeable/2` composes onto `ensure_role/2`'s existing preconditions with one
new refusal, `{:missing_tags, target, missing}`. `ensure_placeable/1` remains and
means "no required tags". The `:placement_role_check` escape keeps its current
meaning (skip everything).

**Wire surfaces that move in lockstep** (all golden-pinned; regenerate via
`mix ouroboros.gateway.golden`): `hello` gains `"tags"` (`gateway/conn.ex:624`),
`runtime.status` gains per-node tags in `cluster` (`lib/ouroboros.ex:19-21`), the
model-facing envelope names this node's tags (`runtime/exposure.ex:51,131`).

**Doctrine, restated.** A tag is the node's claim about itself, read over the same
`:erpc` that a hostile connected node could answer arbitrarily. Tags route; they
never authorize. Grants, signing, and the verifier are unchanged by any tag.

---

## 7. The fleet directory

`Cluster.Monitor` (`cluster.ex:19-38`) stops being log-only. It becomes the cache of
last-known peer postures:

- On `nodeup`: probe the arrival (bounded, async), cache
  `{posture, observed_at, :reachable}`.
- On `nodedown`: mark the cached entry `:unreachable` with the down reason —
  **keep it**. The cache is what lets a fleet view say "the linux laptop was here,
  carried these tags, and is asleep" instead of forgetting it existed — the exact
  thing `nodes_by_role/1` cannot say today (`cluster.ex:481-484` buckets slow nodes
  as unreachable and drops their facts).
- Periodic refresh of `:reachable` entries at the reconnect interval; entries older
  than a TTL are re-probed on read.

`Cluster.fleet/0` returns the cache: per node — role, tags, runtime triple,
running, reachability, observed_at. `nodes_by_tags/2` reads it (never probing
inline) and returns unreachable-but-matching nodes separately, so callers can name
what they skipped.

This stays a cache of observations, not a membership authority: it never blocks
placement on its own staleness, and it is per-node state — each node's directory is
its own view, which is all an eventually-consistent fleet can honestly offer.

---

## 8. Placement by tags

Selection resolves tags → concrete node **once, at admission** (D5). The persisted
artifact of every placement remains a `node()`.

| Seam | Change | Refusal |
| --- | --- | --- |
| `Mesh.start_agent_on/3` (`mesh.ex:64-84`) | accepts `tags:`; passes to `ensure_placeable/2` | existing `{:placement_refused, node, reason}` wraps `{:missing_tags, ...}` |
| `Mesh.start_agent_where/2` (new) | `nodes_by_tags` → deterministic pick (sorted, first) → `start_agent_on/3` | `{:no_node_matching_tags, tags, %{unreachable: [...]}}` |
| `Team.add_worker/3` (`team/server.ex:330-360`) | `tags:` joins `[:role, :node]` in `@worker_options` (`:78`); resolves to a node *before* `finish_add_worker`; the **resolved node** persists in the worker snapshot so recovery re-places deterministically (`team/server.ex:827-845`) | `{:invalid_worker_node, ...}` unchanged; `{:no_node_matching_tags, ...}` for an unsatisfiable selector |
| `Team.delegate/4` | `coding_tags:` beside `coding_node:`; resolved before the fingerprint; requires F1+F2 landed | as above |
| `Orchestration` steps | `step.metadata[:placement][:tags]` — metadata already reaches executors (`scheduler.ex:635-647`, precedent `team_executor.ex:84-93`); `TeamExecutor` resolves at claim time | step failure `{:placement_unsatisfiable, step_id, tags}` |
| Gateway | `"tags"` validator (list of strings matching the tag grammar, no atom minting — beside the `:node` validator at `methods.ex:942-955`) on `teams.add_worker`, `teams.delegate`; `interactive.start`/`coding.start` gain **both** `"node"` and `"tags"` (§10) | `invalid_params` naming the grammar; `-32007`-style refusal carrying the unsatisfiable selector |

Not tag-gated, deliberately: `Upgrade.Coordinator.validate_nodes/1` (deploy targets
are code-custody, named explicitly), `Signer.Remote` (custody is a role), and
`Forge.BuildPeer` (builder selection is by *triple*, §11 — a stricter predicate than
any tag).

The planner schema stays closed: model-authored steps still cannot name nodes — and
now also cannot name tags — without the operator widening the schema; placement
selectors enter through trusted step metadata only, the same trust line
`forge_executor.ex:5-11` draws. (F-list aside: `:coding_node` currently escapes
`TeamExecutor`'s reserved-option list, `team_executor.ex:113` — close that while
adding the placement metadata path.)

---

## 9. Workspaces across the fleet

**Logical names.** New config, per node:

```elixir
config :ouroboros, workspaces: %{"ouroboros" => "/Users/m/code/ouroboros"}
# env: OUROBOROS_WORKSPACES="ouroboros=/Users/m/code/ouroboros:blog=/srv/blog"
```

Each entry is canonicalized at boot against the local filesystem (the manager
already owns that logic, `workspace/manager.ex:186-198`) and advertised as a
`workspace:<name>` tag. Roots named here are implicitly allowed roots.

**Resolution at the owner.** A cross-node start or delegation may say
`workspace: {:name, "ouroboros"}`. The **owner node** resolves the name against its
own map — after F2, all workspace validation already runs owner-side — and the
durable task state stores the owner's absolute path exactly as today. A name the
owner does not carry refuses `{:unknown_workspace, name}` before anything durable is
written. Absolute paths remain accepted for local starts; what is forbidden is an
absolute path crossing a node boundary (refused `{:nonportable_workspace, path}` when
paired with a remote target), because the delegating node's path is a fact about the
wrong filesystem.

**What this is not.** No provisioning: nothing clones, fetches, or creates
worktrees (`workspace.ex:9-13` stays true). No shared-filesystem coordination:
leases are node-local admission (`workspace.ex:14-17`); a `workspace:` tag matching
two nodes over one NFS mount is a data-corruption path, not a scheduling
opportunity, and the docs must say so wherever tags are documented.

---

## 10. Gateway and `ouro` across the fleet

### 10.1 Gateway on the tailnet

The refusal machinery already exists (`config.ex:207-219`,
`config/runtime.exs:401-411`); it gains a narrower acknowledgment, mirroring §4:

- `OUROBOROS_GATEWAY_ALLOW_TAILNET=1` accepts a bind address **only** inside
  `100.64.0.0/10` / `fd7a:115c:a1e0::/48`. `OUROBOROS_GATEWAY_ALLOW_REMOTE=1`
  remains the blunt form and still permits anything.
- `gateway.json` gains `"host"` (F4).
- The fleet convention pins `OUROBOROS_GATEWAY_PORT` (one number fleet-wide, e.g.
  4560) so a peer's gateway address is `<magicdns>:4560` — discoverable from the
  tailnet peer list alone, no remote file read.
- Token custody is unchanged: one token per node, path-not-value, 0600. The operator
  copies each fleet member's token once (`scp`/`tailscale file cp`) into the client
  registry (§10.3). A shared fleet token was considered and rejected: one leak would
  open every node at `operate` scope.
- Scope stays per-listener: the VPS can run `read` while laptops run `operate`, and
  `runtime.shutdown` stays gated by `ALLOW_SHUTDOWN` per node.

### 10.2 Fleet methods

Two new read-scope methods, both following the `signing.decisions` shape — inner
per-node timeout below the method ceiling, typed per-node failures, partial results:

- **`fleet.status`** → this node's directory (§7): per node — role, tags, runtime
  triple, running, reachability, observed_at, plus gateway advertisement
  (host/port/scope) when the peer publishes one in its posture.
- **`fleet.sessions`** → fan-out of `interactive.list` + `coding.list` over
  reachable `:core` nodes (`:erpc.multicall`, the `postures/0` shape,
  `cluster.ex:488-502`), merged with each entry's existing `node` field, plus
  `unreachable: [...]` naming who did not answer. No streaming, no subscriptions —
  listing only.

`interactive.start` and `coding.start` gain optional `"node"` and `"tags"`
(mutually exclusive; both absent means local, exactly today's behavior). The
server resolves tags via `nodes_by_tags/2`, then calls the existing `start_on`
(`interactive_session.ex:55-60`, `coding_session.ex:38-42`). The `:node` validator
already exists (`methods.ex:942-955`); it must also accept nodes known to the fleet
directory but currently unreachable — refusing those with
`{:node_unreachable, node}` rather than pretending they do not exist.

Session verbs (`info`, `replay`, `subscribe`, …) gain an optional `"node"` param
that builds the existing `Ref`/`TaskRef` structs — the seam is one function,
`session_identity/1` (`interactive_session.ex:320-322`), whose struct clause already
routes correctly. **Cross-node `subscribe` is explicitly out of scope for this
slice**: `Conn`'s coordinator lookup is a node-local Registry read
(`gateway/conn.ex:680-697` via `methods.ex:379-381`) and would silently end every
remote stream at open. Until that rework (§15), `subscribe` with a foreign `"node"`
refuses `{:subscription_not_local, node}` — a named limit instead of a silent
`stream.ended`.

Protocol stays `1`: every change is additive (new optional params, new methods, new
result keys). Goldens updated; the TUI's serde models already carry
`SessionInfo.node` (`tui/src/model.rs:452,470,503`).

### 10.3 `ouro` fleet client

**Registry.** `config.toml` grows:

```toml
[[fleet.node]]
name = "mac"
addr = "mac.tailXXXX.ts.net:4560"
token_file = "~/.config/ouroboros/tokens/mac.token"
```

`ouro fleet` lists registry entries merged with live `fleet.status` from whichever
node answers first. An `ouro fleet add <magicdns>` helper fills an entry from the
tailnet peer list + port convention; the token file the operator still copies
deliberately by hand.

**Attach switching, not N streams (D7).** The TUI keeps exactly one live gateway
connection. A new fleet panel (fed by `fleet.status`/`fleet.sessions` through the
current connection) shows every node and every session fleet-wide; opening a session
owned elsewhere reconnects to that owner's gateway via the registry, restoring
today's single-connection invariants against a different address. Sessions on
unreachable nodes render dimmed with the owner named. The Rust cost is bounded: the
connection-scoped state (`Cursors`, `watches`, `open`, `in_flight`) is already
keyed per session and is torn down and rebuilt on switch — the multi-connection
keyspace refactor (`(node, plane, id)` everywhere) is deferred with §15's
multi-stream work. `Mode::Spawned` supervision remains local-only: `ouro` never
spawns a remote runtime.

---

## 11. Forge and rollout across a heterogeneous fleet

Per D8, targets group by triple; the verifier (`verifier.ex:115-124`) is untouched.

- **Triple advertisement.** In the posture (§6): `runtime: %{otp, elixir, arch}`.
- **Builder selection.** `config :ouroboros, :forge_builder_nodes` — a map
  `%{"aarch64-apple-darwin" => :"ouroboros@mac...", ...}` beside the existing scalar
  (which keeps meaning "the builder for my own triple"). `BuildPeer.builder_node/1`
  (`build_peer.ex:124-136`) resolves per requested triple; `check_builder/1` gains
  the F6 assertion generalized: the chosen builder's advertised triple must equal
  the target group's, refusal `{:builder_triple_mismatch, builder, expected, actual}`.
- **Grouped forging.** `Runtime.Capabilities.admit/3` and
  `Orchestration.ForgeExecutor` partition their node list by advertised triple and
  run one forge per group — N artifacts from one source, each signed and
  epoch-stamped independently (the signer is deliberately triple-blind,
  `signing/policy.ex:200-224`, and needs no change). A group whose triple has no
  configured builder and no local match refuses
  `{:no_builder_for_triple, triple, nodes}` before any build starts.
- **Registry.** `Rollout.Registry.Entry` gains a `platform` field (checkpoint v3 via
  the established widen-on-read pattern, `registry.ex:364-379`); `deployed?/3`'s
  exact-node-set idempotency check becomes per-group so re-admitting the same
  source to the same per-platform sets reattaches instead of reforging.
- **Operator surface.** `capabilities.admit` accepts `"nodes"` / `"tags"`
  (`gateway/methods.ex:692-702` currently pins `[node()]` via
  `capabilities.ex:418-423`); tags resolve through the directory, then group by
  triple as above.

Registries remain per-driving-node journals (`registry.ex:5-7,90-93`);
reconciliation across them is deferred (§15) and `fleet.status` at least makes the
divergence *visible* by naming which node's registry answered.

---

## 12. Sleep and partition semantics

Rules, stated once and applied everywhere:

1. **Selection sees the visible fleet.** `nodes_by_tags/2` resolves against
   reachable nodes and names the unreachable-but-matching ones in its answer; a
   selector satisfiable only by a sleeping node refuses
   `{:no_node_matching_tags, tags, %{unreachable: [...]}}` rather than waiting.
2. **Named targets keep refusing loudly — and cleanly.** Epoch allocation
   (`epoch.ex:94-96`) and rollout deploys still refuse when an explicitly named
   target is unreachable; after F5 the refusal leaves no registry debt. "Deploy to
   whatever is awake" is expressed by selecting first (rule 1), then naming the
   result — never by the deploy tolerating absence.
3. **Sessions do not migrate.** Work owned by a sleeping node stays owned by it:
   recovery remains node-local by design (`coding/recovery.ex:89`,
   `interactive/recovery.ex:64`) because the provider process, the workspace lease,
   and the filesystem are physical facts of that host. Fleet views list such
   sessions with `owner: unreachable`; `ouro` renders them dimmed. On wake, the
   owner's own recovery adopts them exactly as today.
4. **Wake reconciliation is observation, not repair.** On `nodeup` the directory
   re-probes (§7); `:pg` re-syncs mesh membership itself. Duplicate mesh replicas
   after a partition remain visible-by-design (`mesh.ex:109-127` reports
   `replicas:`), and F3 removes the one path that made duplicates *silent*.
5. **`:global` stays best-effort.** Epoch and mesh-start serialization
   (`epoch.ex:81`, `mesh.ex:50`) are unchanged and their non-partition-safety stays
   documented; the defenses that do not need coordination (target-side epoch
   monotonicity, deterministic-owner visibility) carry the weight, as they already
   do.

---

## 13. Security posture and honest limits

- **One cluster is one trust domain.** Any node that completes the distribution
  handshake holds full `:erpc` authority over every other
  (`cluster.ex:92-99`, `docs/ARCHITECTURE.md` "Safety boundaries"). Joining the VPS
  to the laptops means a compromised VPS owns the laptops. The mitigations are
  perimeter and placement, not containment: tailnet ACLs restrict which devices
  reach EPMD/dist/gateway ports at the network layer; TLS distribution narrows
  on-path exposure; the signer lives on the most-trusted host and its key never
  crosses the wire. An operator who cannot accept this for the VPS should run the
  VPS un-clustered with only its gateway on the tailnet — the fleet view degrades to
  what the gateway offers, and that trade is theirs to make.
- **Tailscale is trusted infrastructure and this runtime does not verify it.** The
  tailnet posture flags check address ranges, not WireGuard; ACLs are enforced by
  Tailscale; MagicDNS answers are taken at face value. A tailnet admin mistake (a
  mistagged device, an over-broad ACL) is invisible here. The cookie remains the
  only in-band authentication and crosses no wire in the clear only because the
  tailnet encrypts it.
- **Tags are claims.** Self-advertised over `:erpc`, cached in per-node directories,
  never authorization. Grants remain node-local and deny-by-default — placing an
  agent by tag onto the VPS produces an agent with no grants there until someone
  grants on that node; that friction is a feature.
- **Fleet views are observations.** `fleet.status`/`fleet.sessions` merge bounded
  per-node answers and name non-answers; they are eventually consistent and each
  node's directory may disagree. Nothing here is membership consensus, quorum, or a
  partition policy (`docs/ARCHITECTURE.md`, still true).
- **The gateway's authority model is unchanged.** A token still opens one node at
  one scope; attach switching means the client holds N tokens, and a stolen client
  config is N tokens — the registry file deserves the same 0600 discipline as the
  tokens it names.
- **Leases, grants, registries, stores stay node-local.** Nothing in this spec
  replicates state. Every "fleet-wide" surface is a read-time merge with the
  unreachable named.

---

## 14. Slices

Each lands independently, keeps the full suite green, and extends the named test
files.

**Slice 0 — Runbook (docs only).** §4's manual epmd+MagicDNS cluster documented in
README's "Running a cluster", with the ACL sketch, port pinning, and current limits
named (F2 blocks cross-node delegation; single-node gateway view). Acceptance:
performed once by the operator on real hardware.

**Slice 1 — Fixes F1–F7.** Tests: cross-node delegation to a peer-only workspace
(F2, `:peer` test), duplicate default-team-id collision across two nodes (F3),
rollout refusal-before-checkpoint leaves no registry entry (F5,
`test/upgrade/rollout_test.exs`), builder mismatch refusal via injected
`peer_runtime` (F6), `gateway.json` host round-trip (F4, both sides).

**Slice 2 — Tags.** `boot_identity!/0`, posture keys, `nodes_by_tags/2`,
`ensure_placeable/2`, seam table of §8, gateway validators, exposure/goldens.
Tests extend `test/cluster_test.exs` (posture shape old↔new interop, selector
semantics, boot refusal on malformed tags) and the golden suite.

**Slice 3 — `Cluster.Strategy.Tailscale`.** Injectable peer source; fixture-driven
tests per §5. Acceptance: three real machines form the cluster with no
`OUROBOROS_CLUSTER_HOSTS` anywhere.

**Slice 4 — Fleet directory + gateway.** `Cluster.Monitor` cache, `Cluster.fleet/0`,
`fleet.status`, `fleet.sessions`, `node`/`tags` on both starts, `Ref`-building
session verbs with the `{:subscription_not_local, node}` limit, tailnet bind
acknowledgments. Tests: two-node `:peer` gateway tests (the golden/streaming
harness already runs multi-VM), directory staleness transitions, partial-result
shapes with a ghost node.

**Slice 5 — `ouro` fleet.** Registry parsing (total, like `[defaults]`), fleet
panel, attach switching with cursor-state teardown/rebuild, dimmed unreachable
owners. Tests extend `tui/tests/` with the existing fake-gateway harness, plus a
two-gateway switch test.

**Slice 6 — Heterogeneous forge.** Builder map, triple grouping, registry v3
`platform`, `capabilities.admit` nodes/tags. Tests: same-triple `:peer` groups with
injected foreign-triple postures (real cross-arch peers are impossible in CI —
stated in the tests), registry v2→v3 widen-on-read.

---

## 15. Deferred, not designed away

- **Cross-node streaming through one gateway** — requires the `Conn` coordinator
  lookup (`conn.ex:680-697`) and subscription keys to become node-aware, and node
  fields on every stream notification; until then, attach switching covers it.
- **True multi-connection `ouro`** — N live gateways, `(node, plane, id)` keyspaces
  throughout (`tui/src/ui/app.rs:419-439,1298-1333`).
- **Grant replication / fleet-visible grants**, and any per-principal budget that
  spans nodes.
- **Rollout-registry reconciliation** across driving nodes; operator exit from
  `:quarantined` beyond `reconcile_quarantine/1`.
- **Workspace provisioning** (clone/worktree on target) and shared-filesystem lease
  coordination.
- **Session migration/adoption** across nodes; consensus placement, quorum,
  partition policy — the standing architecture non-claims remain non-claims.
- **Per-token scopes** on the gateway; a signer outside the distribution trust
  domain — both already on the project's deferral lists and unchanged here.
