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
The reference job passed the disk prerequisite and is building. Hosted tests now
reach further: Ubuntu exposed an audit-note synchronization race in a test;
Mac reaches two stale VM onboarding-evidence gates. The test keeps the five-second
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
learning evidence. The current index intentionally still points to the historical
record and must remain failing until new evidence is captured.

The pinned [official Ubuntu image checksum](https://cloud-images.ubuntu.com/resolute/20260927/SHA256SUMS)
was checked before preparing a fresh disposable x86_64 VM. Its image and all test
signing keys remain outside Git. No production release or signing is performed.
