# Comparison of recorded targets, 2026-10-06

Implementation: `96cfef72` on `dev`. The final native source archive is
`a2af4cc9`, which corrects and extends the Linux-only test fixture. Runtime code
is unchanged between those commits. Full revision and clean archive SHA-256
are in `source.json`; the evidence commit follows it.

## Behavior and limits

- `diff A B --by targets --json` groups source observations by recorded path or
  proxy destination, in addition to class, source, operation, stage, decision
  and complete outcome. Default `--by counts` preserves count-only behavior.
- Path representations, root kind, digest reason and observation basis are
  retained exactly. Renames require both ordered paths. Optional action and
  attempted-operation fields remain part of the key. No filesystem lookup,
  path normalization, external-path decoding or host resolution occurs.
- `target_scope` names supported operations. Process exits are outside target
  comparison; audit network and limit classes are explicitly unsupported.
  Proxy destinations stay separate from audit evidence. Resolved addresses,
  process IDs and proxy request IDs are not target keys.
- Incomplete or unavailable target evidence makes the whole affected class
  incomparable. Each side reports the number of such observations and a first
  canonical sequence/provenance reference, preserving original coverage and
  protection labels. Other healthy classes can still be compared.
- Continuation binds the comparison mode, run order and snapshot heads. Each
  invocation verifies both streams afresh. Restart/retry is stable for unchanged
  snapshots; mode or head changes refuse. Corrupt evidence fails explicitly.
- Existing bounds apply: 64 MiB and 4,096 pages per side, 4,096 keys and 8 MiB
  of key bytes per side, 8 KiB per key, 128 KiB of serialized changes per page,
  and a 120-second read budget checked between socket calls. Oversized keys
  produce incomplete reports, never truncated or silently discarded targets.

These are counts by recorded labels. Equal workspace or scratch names are
relative to each run's own roots, and do not establish the same filesystem
object, executable image, contents or remote peer. Empty changes are meaningful
only alongside class comparability. Signatures, bundles, best-effort recovery,
managed authorization and the remaining durability/custody gates remain open.
The roadmap and North Star now reflect implemented catalogs and comparisons.

## Validation

| Layer | Result | Scope |
|---|---|---|
| Local macOS ledger suite | 126 passed; zero failures or ignored tests | Linux launch tests excluded |
| Native VPS ledger suite | 146 passed; zero failures, ignored tests or skips | Exact committed archive, optimized build, all 19 real Linux launch tests with `OURO_CONFORMANCE=1` |
| Comparison unit suite | 7 passed on both platforms | Three new tests cover rename endpoints, native path bytes, namespaces, destination identity, missing targets and key budgets |
| Reader CLI integration suite | 19 passed on both platforms | Two new actual CLI/socket tests distinguish changed targets with equal counts, continue across restart, refuse mode/head rebinding and report missing/corrupt evidence |
| Clippy, formatting, schemas, links, I02 and Jail freeze | Passed locally | Frozen Jail inputs unchanged |
| Raspberry Pi | SSH connection timed out | No ARM64 Linux execution result claimed |

The initial native suite passed 145 tests and failed the positive test's
comparability expectation. The observer accurately recorded both relative
arguments as `relative_to_unobserved_cwd`, and comparison correctly refused to
infer their identity. A separate real reproduction confirmed that explicit
absolute arguments produce workspace-relative recorded labels and a comparable
class. The fixture now tests both the positive and negative cases; it does not
weaken the observer or comparison. `linux-initial/` preserves the original
failure, reproduction scripts and actual reports. The final suite above
supersedes that fixture failure.

The new native test executes two contained shell commands using absolute path
arguments, each creating a separate workspace file. It compares the recorded targets and corroborates
each reported path and first-record provenance against the canonical event
stream. A third real launch uses a relative argument and must remain explicitly
incomparable with a canonical reference to the unavailable path. All three
runs are then verified. Existing real-launch tests cover replay,
protected/unprotected labels, tagged discovery, capture, writer/owner loss,
cancellation and detached ownership.

`linux/validate.sh` is the exact native runner. It builds Jail, ledger and the
fixture executable, runs doctor, and runs the full ledger suite with
`OURO_CONFORMANCE=1` in the provisioned user's systemd scope. Source and binary
hashes and before/after source checks accompany the logs. Local logs and source
hashes bind the macOS results to the same runtime source. The only source
difference from final native validation is the Linux-only test correction. The target schema
fixture was captured from the actual CLI over synthetic canonical streams;
contract validation does not establish runtime containment.

The Jail freeze remains at `2dd1c3b4`, input digest
`sha256:d5a0e965cfba1184b72d88370771812dd9544d31a52316bec75e4a4b15b881b6`.
This package validation is not a full-workspace conformance run, deployment or
release. Hosted CI is tracked separately. The evidence commit adds a link from
the specification and explains the relative-path limitation; those documentation
updates are outside the tested archive.
No host kernel, boot, network or trusted configuration policy was changed.
