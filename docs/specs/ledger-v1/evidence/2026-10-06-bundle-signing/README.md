# Explicit bundle signing and signer verification, 2026-10-06

Implementation and native source: `86e4194e5e60b90aff3d57e87ba1fa13547f9c9c`
on `dev`. `source.json` records the clean archive digest. All 417 source paths
and hashes in the local and native inventories match; the native inventory also
passed its post-test checksum check. The evidence and tested-freeze refresh
follow the implementation without changing its runtime or tests.

## Behavior and trust boundary

`bundle-keygen --output DIR` explicitly provisions a new private signing
directory and refuses to replace an existing one. It generates an Ed25519
PKCS#8 v2 private key and a canonical public-key record. Signing reads the
private key through pinned file descriptors with ownership, mode, regular-file,
link and size checks. No ambient SSH, fleet or release key is reused.

`bundle RUN --output DIR --signing-key PRIVATE_KEY` creates a signed v2 bundle.
The message is `ouro.ledger.bundle-signature/1`, one NUL byte, and the exact
canonical manifest including its final LF. The mandatory signature binds the
historical run projection and every inventoried member hash. It uses `ring`
0.17.14, already present in the lockfile; adding the direct ledger dependency
changes one lockfile dependency edge without introducing a package or version.

`verify-bundle DIR` verifies the signature and canonical contents but labels a
signature without a supplied public-key pin as `signature.trust: untrusted`.
`--trusted-key PUBLIC_KEY`
requires exactly that separately supplied public key. It rejects unsigned
bundles, removed signatures, downgraded manifests and substituted signers.
Signing itself pins the public key derived from its supplied private key before
publication. Unsigned v1 bundles retain their existing format and reports.

A pinned signature cannot override canonical replay failures or upgrade
coverage, capture completeness or `child_protection`. It identifies a key,
not hardware, managed authorization, an independent witness or a trusted
timestamp. `external_custody` remains false. Original capture content hashes
are still taken at bundle time; a signature does not prove that a node owner
left capture bytes unchanged before packaging.

## Validation

| Layer | Result | Scope |
|---|---|---|
| Local macOS ledger suite | 145 passed; zero failures or ignored tests | Linux execution tests excluded |
| Native VPS ledger suite | 167 passed; zero failures, ignored tests or skips | Optimized clean archive; `OURO_CONFORMANCE=1` |
| Real Linux launch tests | 21 passed | New signed test covers both `tool` and `none`, selected output and offline verification after private-key/store deletion |
| Additional native smoke | Two signed launches passed | Public identity, actual signed bundles, receipts and verification reports retained |
| Independent OpenSSL verification | Both signatures accepted; altered messages rejected | Exact domain and manifest bytes, public SPKI key, OpenSSL 3.5.5 |
| Linux-to-macOS portability | Both bundles passed in pinned and untrusted modes | Four reports exactly match Linux |
| Local Clippy, formatting, contracts, links, I02 | Passed | Includes signed/unsigned schema fixtures; no private key in fixtures |
| Refreshed portable freeze tests and `freeze --check` | 12 tests passed; freeze check passed | Tested dependency baseline tied to the clean conformance revision |
| Full reference-host conformance | Passed: 1,937 tests, zero failures | 79 optimized test binaries and four doc-test groups; 16 declared ignored entries, no live capability skips |
| Combined Linux and macOS acceptance | 43 pass, seven pass with documented limits | Every noncredential gate passes; A01 still requires a real agent |
| Hosted Rust and contracts CI | Passed | Includes macOS refusal/portable lane, dependency policy, and compile-only cross-target checks |
| Raspberry Pi | Unavailable | SSH timeout; Tailscale reports the node offline |

Eight new unit tests cover private and unique key provisioning, no-overwrite,
signature byte/domain binding, explicit trust, malformed/linked/oversized keys,
forged fingerprints, signature/capture/manifest changes, downgrade/substitution,
and rejection of semantically forged history even when its signature is valid
under the pinned key. An additional real local CLI test removes the source store
and private key before verifying with the public pin alone.

The schema fixtures were captured from the real CLI over a synthetic prepared
run. The native smoke uses actual contained and explicit `none` shell commands,
each emitting eleven stdout and eleven stderr bytes. Both captures are limited
to four bytes, and the bundle includes only selected stdout (`stdo`). Capture
truncation, receipt bodies, coverage and protection survive signing and offline
verification. All temporary private keys and source stores are deleted.

## Inspectable proof

- [Smoke procedure](linux/signing-smoke.sh) and [result](linux/signing-smoke.log).
- [Test public identity](linux/signing-smoke/public-key.json),
  [protected signed manifest](linux/signing-smoke/tool/bundle.json),
  [signature](linux/signing-smoke/tool/signature.json), and
  [pinned verification](linux/signing-smoke/tool-verified.json).
- [Unprotected signed manifest](linux/signing-smoke/none/bundle.json),
  [signature](linux/signing-smoke/none/signature.json), and
  [pinned verification](linux/signing-smoke/none-verified.json).
- Independent OpenSSL results for [tool](linux/signing-smoke/tool-openssl.txt)
  and [none](linux/signing-smoke/none-openssl.txt).
- macOS pinned verification of [tool](local/tool-pinned-verified.json)
  and [none](local/none-pinned-verified.json), plus [source/report comparison](local/source-comparison.log).
- Full conformance [summary](conformance/summary.txt), [test log](conformance/test.log),
  [doctor](conformance/doctor.json), and [plain-session smoke](conformance/smoke-transcript.txt).
- [Combined acceptance verdict](conformance/combined-gates.txt),
  [freeze check](local/freeze-check.log), and [refreshed freeze tests](local/portable-freeze-refreshed.log).

This is an ephemeral test identity, not an operational node or production trust
anchor. Only its public key is retained. From the repository root, repeat:

```sh
cargo +1.98.1 run -q -p ouro-ledger -- verify-bundle \
  docs/specs/ledger-v1/evidence/2026-10-06-bundle-signing/linux/signing-smoke/tool \
  --trusted-key docs/specs/ledger-v1/evidence/2026-10-06-bundle-signing/linux/signing-smoke/public-key.json --json
```

## Dependency freeze

Adding the direct dependency invalidated the previous tested freeze. The
baseline regeneration deliberately removed the stale tested-run claim.
[Reference-host conformance 37484337062](https://github.com/monocursive/ouroboros/actions/runs/37484337062)
passed for this exact implementation revision. Its `doctor.json` reports
`ready: true`, a clean optimized build, and build-input digest
`sha256:4f45c7d14a754af0a72906747725c99cfadd8e673805e2b2412cf90c3e475512`.
The tested freeze was restored from that artifact; `freeze --check` validates
the input digest, revision ancestry and unchanged frozen inputs.

The [hosted Rust run](https://github.com/monocursive/ouroboros/actions/runs/37484336997)
and [contracts run](https://github.com/monocursive/ouroboros/actions/runs/37484336781)
also passed at that revision. `conformance/macos-test.log` is the Rust run's
macOS `Tests` step with only the GitHub job/step/timestamp prefix removed,
starting at the actual suite marker. The combined verdict uses it with the
reference-host log and the successful `contract_validation`, `i01_absent`,
`i01_scrubbed_path` and `i02_scan` driver checks recorded by the reference-host
verdict. The macOS lane proves native refusal and portable behavior, not
contained macOS execution.
Trailing display padding is removed from the text gate reports and host
manifest. JSON artifacts and signed bundle bytes are preserved unchanged.

Signing does not complete ledger milestone 2. Best-effort writer-outage
reconciliation, the remaining durability gates, historical-custody migration
and managed project authorization remain open. This evidence does not establish
fresh ARM64 Linux execution, native macOS containment or production readiness.
