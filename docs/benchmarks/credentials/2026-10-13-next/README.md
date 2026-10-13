# Follow-up: release proof, real expiry, fair lifecycle comparison and startup

The complete five-part goal remains active. Previously sealed benchmark roots
and their scored results are preserved.

1. CI: repair vault-aware freeze validation and freeze the entire credential
   definition, preserving the absence of file staging for vaults. Local portable
   freeze 12/12 and xtask 206/206 pass; a changed frozen origin is mutation-tested
   to fail the full credential-authority assertion. Hosted CI must also pass.
2. Reference proof: only the five previously named inactive CI target caches
   were removed after no process references were found. Sources remain. Reclaim
   and disk evidence are saved. Run full reference conformance, retain its logs,
   then record its validated doctor in the freeze and pass `freeze --check`.
3. Natural expiry: the current real issuer grant expires 23 October 2026 at
   09:22:33 UTC. Prepare a real-clock long-running test; do not backdate metadata,
   replace it with a synthetic expiry, or count an uncompleted soak as a pass.
4. Competitors: apply the same request/lifecycle fixtures through ordinary Ouro,
   Greywall/Greyproxy, OpenShell provider and MXC configurations. Save capability
   refusals and unsupported features explicitly, with original product versions,
   equivalent application work and each product’s configured observation surface.
5. Startup: profile the remaining current-binary cost, optimize with fresh
   isolation/capability checks and full observer/settlement semantics, then rerun
   randomized matched controls and preserve candidates, failures and intervals.

Private credentials and natural-expiry state remain outside Git. All publication
requires exact-value, encoded-value and token-pattern audits, including archives.

## Current verified progress

The CI freeze repair is committed at `28e7c0a8528874dba0ddd10830a95006e8fc002e`.
The reference job passed the disk prerequisite and completed with failures
retained below. Hosted tests reached further: Ubuntu exposed an audit-note
synchronization race in a test; Mac reached two stale VM onboarding-evidence
gates. The test keeps the five-second
deadline and requires both committed token bytes and the mandatory refreshed note.
The VM gates remain strict and require new real-vendor evidence for current inputs.

The real-clock supervisor is live on VPS with its original JWT expiry metadata
unchanged. The separate configuration preflight completes a real Codex task with
unchanged/hidden checks and zero HTTPS fallback. The current proof is startup and
preflight only; natural-expiry completion remains pending until 23 October.
Only one imported source is used by the long-running supervisor. Other copied
login caches are not used as refresh owners by this soak. Any outside grant
rotation remains a possible test failure and must be retained.

Pi diagnostic instrumentation (excluded from scored timings) shows about 70–83 ms
in boundary preparation, 28–40 ms in the shared fresh probe, about 19–36 ms in
initial claim/policy persistence, and 28–31 ms in prepared durability. All six
instrumented no-op attempts succeed. These figures guide optimization; they are
not a scored improvement or a substitute for matched uninstrumented controls.

Frozen primary source checkouts used for competitor fixture design:
Greyproxy v0.4.5 `017a3a7e480315443b0c53ffd10575b31b91a0f1` and OpenShell v0.1.3
`e1f3c82caa3ed3b65de22889ae7ef32a774878ef`. Credential rotation/delete operations
must use each product's supported operator API, while application request intent
and resource-server observations stay the same. Different missing capabilities,
process-attribution scopes, active-stream revocation and observation surfaces
will remain explicit rather than being simulated by a shared custom broker.

The preview gate now reads an explicit repository index under `results/` so new
records can be selected while historical records remain unchanged. It still
requires the compiled current input digest, clean optimized provenance, real
vendor workflow, signed/corrupted install controls, and complete receipt-bound
learning evidence. The index now selects the fresh a03c record after both
independent verifiers pass. The historical record remains unchanged.

The pinned [official Ubuntu image checksum](https://cloud-images.ubuntu.com/resolute/20260927/SHA256SUMS)
was checked before preparing a fresh disposable x86_64 VM. Its image and all test
signing keys remain outside Git. No production release or signing is performed.

The first full reference run at 28e7 is retained as failed. Besides stale preview
inputs, two tests require the stock AppArmor user-namespace restriction, which
had been disabled during the original shared competitor setup. The restriction
was restored from 0 to 1. Both exact failing host-manifest/probe tests then pass
in the delegated reference user scope; no assertion was weakened. Native timing
cohorts must explicitly record their host-policy setting and keep both arms
identical, rather than mixing settings or reusing old numbers as new scores.

A kernel witness confirms the natural-expiry target remains traced under enforced
containment. The on-disk running receipt is an initial phase record, not the final
observer/settlement report.

Fresh VM onboarding completed using the clean a03c x86_64 release build with
current inputs `sha256:669a9b9bdfa076c70ac4cbd29b31e719a59033cfeb20e91774c92ea24f40d063`.
The main workflow took 68.705 seconds, including signed installation, contained
`true`, a real OpenCode task and upgrade. Corrupted archive and signature controls
were rejected. Both independent onboarding and receipt-bound learning checks pass,
and the disposable VM was destroyed. The deliberate learning fixture was not
proposed; the verifier checks every actual proposed grant against exact journal
events and leaves unresolved reads ungranted. This emulated VM is onboarding and
compatibility evidence, not a native Mac containment or performance score.

## 13 October reference proof and diagnostic follow-up

All four hosted workflows passed at `d9f4741197bf0f350d55369b18f3d3459538df95`:
contracts, fleet, Rust on macOS/Ubuntu, and the full serialized Linux reference
job. The reference evidence is retained in `validation/reference-d9-passed/` and
its validated optimized, clean doctor is recorded in the milestone freeze.
`freeze --check` passes. The suite log totals 2,110 passed, zero failed and 17
ignored tests across 90 summaries. Gate/ignored details remain in the raw log;
the Linux developer-release acceptance scope explicitly leaves native macOS
requirements unsupported. This does not establish full native Mac conformance.
The preceding failed reference record remains retained.

The six finer Pi diagnostics all settle with enforced containment, observed
execution and verified empty trees. Median boundary stages include 19.56 ms for
cgroup registration/configuration, 15.47 ms for post-spawn placement/cleanup,
18.99 ms for namespace discovery/readback and 8.91 ms for mounts. Tracer attach
takes 0.354 ms. Full policies, journals, receipts, patches and build metadata are
saved, and every instrumented timing remains excluded from scored performance.

The standalone Python placement write took 20.21 ms, while member-list and
process-cgroup reads took about 0.10 and 0.08 ms. Separate libc controls, including
fresh leaves for both arms, take under 0.5 ms for spawn-plus-move and under 0.4 ms
for spawn directly into the leaf. They use a small trusted sleep process and do
not reproduce Ouro's blocked bootstrap or its descriptor/lifetime safeguards.
Both warm-leaf and fresh-leaf controls are saved. They do not prove an Ouro
startup improvement; the exact descriptor-cleanup/write/kill-handle split is
being measured before choosing a production change. The clean Pi d9 baseline
is saved separately, with its current input digest and honest release provenance.

The first completed Greywall/Greyproxy HTTP diagnostic is retained under
`validation/greywall-lifecycle-pi/http-03/`. Valid substitution, live rotation,
stopping substitution on a new request after deletion, and hiding the key in
the child environment pass. Requests on another path, an escaped path and from
another executable still receive the synthetic key; the established SSE stream
remains open after deletion. These are observed limits of destination/session
credential substitution in the configured frozen version. The resource oracle,
operator API responses, exact command/configuration and logs are retained.

Two unsuccessful configuration pilots are retained. The first used sandbox
loopback incorrectly; the second moved traffic ports but did not move Greywall
0.3.7's fixed credential API at `localhost:43080`. The corrected run temporarily
replaced the inactive previous benchmark proxy at that port, preserved its store,
and restored it afterwards. The private environment backup is outside Git. The
pilots are not scored capability results. This HTTP run is synthetic private-host
traffic, not HTTPS/provider timing. Ouro/MXC/OpenShell executions of the same
resource/client/oracle and the remaining WebSocket/refresh/concurrency fixtures
are still required before the matched competitor comparison is complete.

The subsequent six-attempt move split isolates the slow operation inside Ouro:
the `cgroup.procs` write takes median 20.46 ms (12.25–27.43 ms), whereas descriptor
cleanup takes 0.021 ms, membership verification 0.066 ms and opening the kill
handle 0.020 ms. All six receipts have strict evidence, attached observers,
five active coverage classes without gaps, enforced containment and verified
empty trees. The network-disabled `tool` profile correctly reports `proxy.net`
as unsupported; these runs do not claim proxy observation.
These results are retained separately from the first profile and from the libc
controls. A candidate to test is self-placement in the existing pre-exec hook,
after parent-death protection and before exec, while keeping the pinned registered
leaf, parent readback, watcher, release ordering and descriptor checks. No production
startup improvement is claimed yet. The latest natural-expiry kernel witness still
finds the original supervisor and traced waiter alive with the original expiry
unchanged and no terminal result.

Fair-comparison follow-up must also test ordinary session-scoped network rules
and their revocation, alongside per-credential revocation with destination
permission retained. The current SSE result uses a global destination allow rule;
it does not establish the result of deleting a scoped network rule. Synthetic
broker fixtures also do not prove failure of a client's own OAuth refresh in an
environment/staged-file configuration; that end-to-end workflow must be assessed
separately from the product's managed-credential capabilities.
