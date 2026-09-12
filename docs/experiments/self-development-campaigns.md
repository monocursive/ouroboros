# Self-development campaigns

`scripts/self-development-campaign.py` is a bounded local runner for deterministic
validation campaigns and matched benchmark contracts. Manifests use schema version 2.
Each command declares direct `argv`, a canonical workspace `cwd`, disjoint coverage
units, and one artifact. Executables are absolute, non-symlink paths whose SHA-256 is
pinned in `allowed_executables`. Commands never use a shell.

The runner supplies the manifest environment without inheriting the caller's ambient
values. Only `CI`, `LANG`, `LC_ALL`, `NO_COLOR`, `PATH`, `SOURCE_DATE_EPOCH`, `TERM`, and
`TZ` are eligible globally, and each allowed executable declares the subset it accepts
in `env_allowlist`. `PATH` is therefore explicit, authenticated input rather than an
ambient/default search path. Language/module search paths, dynamic-loader controls,
credentials, sockets, Git/CA overrides, askpass, and plugin/config endpoints remain
rejected. `MIX_ENV`, `SHELL`, `CARGO_NET_OFFLINE`, and `OUROBOROS_REQUIRE_WASM` are
additionally eligible only as command-specific values. The following command-only path
values are accepted for the concrete campaign inventory: `BOOT_GATE_OUT`, `CARGO_HOME`,
`CARGO_TARGET_DIR`, `HOME`, `J2_BOOT_GATE_OUT`,
`J3_BOOT_GATE_OUT`, `MIX_BUILD_PATH`, `MIX_HOME`, `OUROBOROS_PROCESS_ID_HELPER`,
`OUROBOROS_WASM_EXAMPLES_ROOT`, `OUROBOROS_WASM_GUEST`, `OUROBOROS_WASM_HELPER`, and
`OUROBOROS_WASM_SKEW_DIR`. Each must be absolute, canonical, and workspace-contained;
it need not pre-exist when it names campaign-owned output. `HOME` retains its ordinary
child-process meaning and is neither inherited nor used as a supervisor-shell control;
the campaign operator may seed its owned directory without copying credentials. `SHELL`
must be an absolute
canonical existing path. Each executable's
`env_allowlist` must authorize both common and command-specific keys. A command needing
anything else requires a purpose-built executable.

Commands may declare an `environment` overlay, `deadline_ms`, and `requires` IDs naming
only earlier commands. The effective child environment is the common map updated by that
overlay, with no ambient inheritance. Both maps and per-command deadlines are authenticated
effective conditions. A failed prerequisite makes its dependent `skipped`, which cannot
satisfy coverage or produce passing/reusable campaign evidence.

`artifact_mode` defaults to `declared`, retaining the compatibility route where a command
writes `OUROBOROS_CAMPAIGN_ARTIFACT`. `artifact_mode: stdout` instead has the runner create
a private mode-0600 artifact exclusively from bounded combined stdout/stderr, so direct
Mix, Cargo, Python, and npm commands need no wrapper or redirection. The true child exit is
preserved; nonzero output may be retained as failed evidence, while overflow is marked and
cannot pass.

The whole campaign has one authenticated effective deadline, capped at 153,600,000 ms,
while every command has its own deadline capped at 600,000 ms and receives no more than
the smaller of that value and the campaign time remaining. Every command runs in a new
process group; timeout sends TERM, waits one second, then sends KILL. A process-created
regular file is limited to 256 MiB. Combined stdout/stderr capture is independently limited
to 1 MiB, and the retained receipt artifact is independently limited to 64 MiB; crossing
any applicable bound prevents a pass. The purpose-built
gate gives a small supervisor and the validation process a nested process group. A private
pipe owned by the gate is the supervisor's parent-death signal: EOF makes the supervisor
kill its exact group even when the outer gate group was abruptly killed and no gate handler
or `finally` block can run. Catchable cancellation and
local timeout also apply targeted group cleanup. Ordinary descendants in either group are
therefore cleaned up; `containment.required: cooperative_pgid` states this limited policy.
`strong_descendants` **fails closed before any command executes**, because this runner has
no cgroup/job-object descendant supervisor; intentionally detached sessions can escape a
process group. Output is digested and bounded. Successful status is derived from exit
zero **and** a regular, non-symlink artifact at the declared path. The runner adds two
controller-owned control variables: `OUROBOROS_CAMPAIGN_ARTIFACT` contains that exact
validated artifact path, and `OUROBOROS_CAMPAIGN_DECLARED_ENV` contains a canonical copy
of the authenticated manifest environment. The purpose-built gate consumes both controls
without forwarding either and executes validation under exactly the declared map. It
streams combined output through bounded memory into a UTF-8 artifact subject to the
1 MiB capture bound. Overflow appends an explicit incomplete marker and exits nonzero,
so partial output cannot be accepted as complete evidence. Control variables are not
caller-controlled or part of the ambient allowlist.

For bounded orchestration, `execute-manifest --command-id ID --reuse-receipt PRIOR` runs at
most one not-yet-passed constituent. It atomically writes an authenticated `in_progress`
receipt before spawn and replaces it with the completed partial receipt afterward, under an
exclusive no-follow owner-only lock scoped to the key and manifest digest (not the chosen
output pathname). A campaign invocation ID is created before its first started marker and
retained across every authenticated partial continuation. A later call imports only
authenticated, current passed
constituents and keeps exact manifest coverage accounting; omitted commands adjudicate
`missing` until all are present. An `in_progress` receipt means effects are uncertain after
caller/process death and is refused for automatic rerun. Operators must investigate and
explicitly choose a new campaign/nonce rather than infer completion.

The workspace must be a Git worktree. Before and after execution the runner measures
`HEAD` and a deterministic digest of the manifest's explicit `source.roots` (default
`["."]`). `source.exclusions` names exact workspace-relative files or directory subtrees
that are intentionally outside receipt source coverage; generated build, dependency, cache,
and report trees should be declared transparently there. Roots and exclusions are normalized,
unique workspace-relative paths, and a root cannot equal or descend from an exclusion.
Every component of an explicit root and every encountered included entry is checked without
following links: directory symlinks (whether they target inside or outside the workspace),
file symlinks, FIFOs, sockets, devices, and other nonregular entries are rejected rather than
omitted. Declared command artifacts and `.git` are also excluded. Path, opened-file identity,
and content are bound, so even byte-identical source replacement invalidates evidence. The
`roots` and `exclusions` declarations remain in the manifest, receipt and workload identity;
put the measured `revision` and `tree_digest` alongside them. Exclusions are selection, not
containment: the runner cannot prove excluded state is non-influential to an allowed executable.
`start_mode: clean` additionally rejects tracked modifications.
`outer_sandbox: required` refuses execution: this script does not provide a host sandbox.
Use `forbidden` only where the trusted operator has decided unsandboxed local execution
is appropriate.

Create a controller-owned local receipt key once:

```sh
umask 077
python3 -c 'import os; open("/secure/local/campaign.key", "wb").write(os.urandom(32))'
python3 scripts/self-development-campaign.py execute-manifest \
  --manifest /absolute/manifest.json \
  --receipt-out /absolute/receipt.json \
  --key-file /secure/local/campaign.key
```

The key must be an absolute canonical, controller-owned regular file, contain 32–64
bytes, have exactly one link, and have no group/other permissions. No-follow opening and
opened-fd checks reject symlinks and replacement during open. The key must be outside the
workspace and must not alias a manifest, events/reuse input, receipt output, or declared
artifact (including hard-link identity). Receipts bind the canonical manifest digest,
measured source, effective environment/deadline/posture/platform, executable path,
digest and opened identity, invocation ID, derived outcomes, and artifact path/content/
identity. Effective conditions carry `conditions_version: 3` and authenticate the
process-file, captured-stdout, and receipt-artifact limits independently; authenticated schema-v2
receipts issued before this conditions version are intentionally inconclusive and
non-reusable. Their historical command environments/deadlines are never inferred. Receipts
carry a key ID and HMAC plus signer ID, controller nonce, and freshness.
The only supported `receipt_policy.mode` is `local_integrity`: validation rejects every
other mode, and execution refuses it before commands run. In particular, this local HMAC
issuer does not issue, classify, or reuse receipts under an `independent` policy; signer
text, nonces, and freshness cannot prove external custody. Validation and comparison
require the same local key when receipts are supplied:

```sh
python3 scripts/self-development-campaign.py validate-manifest \
  --manifest /absolute/manifest.json --receipt /absolute/receipt.json \
  --key-file /secure/local/campaign.key

python3 scripts/self-development-campaign.py compare-contract \
  --candidate-manifest /absolute/candidate.json --candidate-receipt /absolute/candidate-receipt.json \
  --baseline-manifest /absolute/baseline.json --baseline-receipt /absolute/baseline-receipt.json \
  --key-file /secure/local/campaign.key
```

`--reuse-receipt` imports only current authenticated passing constituents from either a
complete receipt or a partial receipt issued by `--command-id`. One structural assessment
authority validates authentication/freshness, exact manifest/source/effective conditions,
live source and executable/artifact identities, known unique command IDs, exact coverage
bindings, manifest order, dependency closure, and passing status. An incomplete receipt is
continuation-eligible only when every constituent it does contain passes those checks;
aggregate `missing` alone does not disqualify a valid nonempty partial receipt. Human-readable reason
text never controls continuation. Any source or manifest change invalidates reuse. Missing,
failed, timed-out, skipped, in-progress, legacy-condition, unauthenticated, and inconclusive
constituents never pass or transfer as completed.
Host-only gates
should be explicit excluded coverage with a reason; if attempted without supporting host
context they must produce inconclusive evidence, not a synthetic pass.

Benchmark mode freezes corpus, scope, model/runtime/environment/posture, bounds, event
boundaries, action taxonomy, inclusion rules, and the list of permissible variant
JSON-pointer paths. Comparison computes differences over workspace/source,
receipt policy, complete execution (command IDs, argv, cwd, artifacts, executable
path/digest/environment allowlists, containment and deadlines), and coverage; every
difference must be explicitly predeclared by both manifests. It then requires two
separately executed, locally authenticated, currently passing receipts with distinct
invocation IDs. Distinct invocation IDs prevent accidental sample reuse but do not make
receipt provenance independent. Thus artifact
identity is checked in each sample's own workspace while workload differences remain
explicit, and contract comparability is distinct from descriptive telemetry.

An optional `--events` JSON document carries one invocation ID and bounded
request/action events between exact start and terminal boundary records. The graph must
be ordered, rooted, and acyclic with exactly one root request; child requests and actions
can only name request parents. Actions must belong to the benchmark taxonomy. IDs are
deduplicated exactly once (identical retransmission is accepted; conflicting duplicates
are refused). Inclusion is derived from the benchmark's parent/child/action classes and
passed/failed/refused statuses; only matching records contribute. Telemetry is summed
once across those included records. Counters are bounded integers; all values must be
finite and non-negative. Missing fields remain JSON `null`; no non-cached total is
inferred when cache data is absent.

## Security boundary

This is a trusted-caller local-development control, not isolation. Direct argv,
environment replacement, path/digest checks, deadlines, process-group cleanup, source
measurement, and authenticated receipts prevent accidental ambiguity and untrusted
manifest assertion from becoming success. They do not constrain the authority of an
allowed executable, stop it escaping the workspace, eliminate path replacement races,
or withstand a caller with the same UID. A same-UID process can read/replace a locally
accessible key, ptrace or interfere with the runner, mutate files between checks, and
forge receipts. Keep the key and manifests controller-owned, do not expose them to the
agent under test, and use an external account/VM/sandbox and externally custodied signing
service when that threat is in scope. This tranche intentionally refuses to claim such a
host boundary.
