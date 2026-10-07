# Structured redaction — 2026-10-07

Implementation: `e3de84a94665a3cce2a22f6cfa1136210b0081a2`.
Native fixture corrections: `58035302e9a3732c6cc7a3db81453164b264ffff`,
`256bd42b8083bab60ce7e24da177c40c641408f9`, and
`15b77b4fb4f449a2010c4b3f6bb1b8ca6600cc82`.
[source.json](source.json) identifies the final tested Git archive;
[source.sha256](source.sha256) binds 437 runtime, test, contract and validation
helper inputs. Native suites check every input before and after execution.

## Behavior

`run --redact paths --redact destinations` records a sorted immutable selection.
Either selector can be used alone. `paths` removes audit path values and digests;
`destinations` removes proxy destinations, connected addresses and origins.
Changed events carry an explicit ledger redaction marker listing their affected
fields. Already unavailable observations retain their original reason.
The transformation retains no digest of removed field values. Captures, operator
annotations, tags, profile names and receipts are outside this fixed field policy.

The owner validates and minimizes before either sending an event or writing its
outage journal. The writer independently enforces the prepared policy before
canonical append. Replay, recovery and offline bundle verification reject
policy bypass and invalid markers without rewriting history. Retry identity
covers minimized content, so differences only in removed values are intentionally
indistinguishable. Retained facts still conflict if changed under the same id.

Outcomes, decisions, counters, source sequence and receipt correlation remain
intact. Redaction is not a coverage gap, but target comparisons mark removed
identities unavailable and their affected class incomparable. Unselected legacy
requests preserve their existing event bytes. This does not sanitize capture
bytes: explicit argv/stdout captures and their transcript display retain the
original test values.

## Tests and validation

Five new portable tests cover native binary paths, both rename paths, external
digests, already unavailable paths, independent selectors, idempotence, immutable
policy, direct writer enforcement, restart/replay, forged markers, canonical
policy bypass and rejection of forbidden raw metadata before transformation.

Native launches cover `tool` and `none`, observable absolute rename paths,
unchanged captures, one execution across replay, restart verification, offline
bundles and target-comparison limits. The existing writer-SIGKILL/overflow test
also selects redaction and checks the pending prefix, source tails and recovered
events. Interrupted canonical frames still require conservative refusal and
unchanged bytes; the test never repairs a poisoned history.

The proxy fixture uses the proxy-enabled `agent` profile and requests a denied
test destination. On the VPS, the actual proxy result retains its denial and
zero-byte counters while removing the destination. The Pi kernel lacks
`CONFIG_UNIX_DIAG`; there the test instead verifies the exact missing-capability
refusal, no admission, no child execution and unchanged denied replay. That
asserted refusal is **not** evidence of a working Pi proxy or destination
redaction on a live Pi proxy. Portable writer tests exercise proxy-field
minimization on both architectures.

The separate [production CLI probe](probe-cli.py) saves real run responses and
canonical events, verifies private captures and exact one-execution replay, and
records proxy success/refusal separately. [validate-cli.py](validate-cli.py)
checks both responses and both streams against their schemas and canonical
encoding. All probe contents are synthetic test data.

The native [validation script](../2026-10-06-writer-outage/validate-native.sh)
uses Rust 1.98.1, `OURO_CONFORMANCE=1`, `RUST_TEST_NOCAPTURE=1` and a delegated
user scope. [verify-results.py](verify-results.py) checks test counts, exit
statuses, 72 pending-owner fault cases, 66 lifecycle cases, previous feature
markers, binary hashes and absence of test controls in the production binary.

- VPS: **220 passed**, zero failed, ignored or skipped. Live proxy redaction
  verified. [Summary](linux/summary.json), [full log](linux/ledger.log),
  [path response](linux/redaction-cli.json), [proxy response](linux/proxy-cli.json).
- Raspberry Pi: **220 passed**, zero failed, ignored or skipped. The proxy test
  verifies the explicit host-capability refusal described above.
  [Summary](pi/summary.json), [full log](pi/ledger.log),
  [path response](pi/redaction-cli.json), [proxy refusal](pi/proxy-cli.json).
- Local macOS: **180 passed**, zero failed or ignored.
  [Summary](local/summary.json), [full log](local/ledger.log).
  Linux launch modules are compiled out on macOS.

The initial fixtures expected relative paths to retain identities and used the
network-disabled `tool` profile for a proxy request. They correctly failed;
the fixes use absolute observed paths and `agent`, with a separately asserted
Pi host limit. Initial failures are retained for [VPS](initial-linux-ledger.log)
and [Pi](initial-pi-ledger.log), along with the
[initial production probe](initial-linux-probe.log) and
[initial source identity](initial-source.json).

The Pi also exposed a race in the existing file-size-limit test: a pending
source write could fail before the child finished its work. The corrected test
stops only the owner, waits for the child's settled receipt and empty tree,
then applies the real kernel write limit and resumes the owner. The ledger must
still report an unknown outcome when final evidence cannot be persisted.
The correction commits change only tests and validation helpers; production
code is unchanged. The synchronized post-exit failure test also passes 20
additional repetitions per native host; logs are retained alongside each suite.

Formatting, Clippy, schemas, links, I02 and the unchanged Jail freeze pass.
Installed commands and kernel settings remain unchanged. This evidence does not
establish physical power-loss safety, external custody, real-agent/provider
compatibility or managed readiness. Historical custody remains required at the
later legacy-store removal boundary.
