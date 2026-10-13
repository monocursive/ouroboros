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
