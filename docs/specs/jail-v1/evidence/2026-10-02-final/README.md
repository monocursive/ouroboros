# Final jail and detached-ledger validation, 2026-10-02

Source revision: `52b546038b69d8647021399371b5236bb43f2275`.
This includes detached ledger ownership and the corrected observer allocation
accounting. All three workflows passed:

- [Contracts](https://github.com/monocursive/ouroboros/actions/runs/37064623890).
- [Hosted Linux and macOS Rust checks](https://github.com/monocursive/ouroboros/actions/runs/37064623876),
  including formatting, strict Clippy, cross-target compilation, dependency
  policy, I02 and tests. Cross-target checks establish compilation only.
- [Reference-host conformance](https://github.com/monocursive/ouroboros/actions/runs/37064623888),
  with the complete optimized workspace suite in strict conformance mode.

`summary.txt` records `conformance PASS 20261002T210538Z-52b546038b69`.
`binaries-check.txt` confirms unchanged jail, fixture and ledger executable
hashes after the suite. `doctor.json` reports a clean optimized Linux x86_64
build with inputs
`sha256:a5fe16ac97675c2573050942de9bb9b952db8815e348c6eb85cfbe48781bc52b`.

The independently run native macOS workspace log is also at this revision.
Combined acceptance is **43 pass and 7 pass with existing limits**.
The real-agent A01 credential gate remains separate. `freeze-check.txt` records
the successful updated tested freeze; its source inputs match this tree and the
tested revision.

The Linux suite includes all **15 ledger launch tests**, including six detached
lifecycle cases. The earlier [SSH disconnect record](../../../ledger-v1/evidence/2026-10-02-detached/README.md)
preserves the same-owner reconnect, one execution and 64-byte bounded capture of
a 5,000-byte stream. Its exact development binaries are pinned separately.
The [queue regression history](../2026-10-02-baseline/README.md) preserves both
the failing allocation reproducer and the fix; no memory budget was increased.

This validates local Linux operator execution and the macOS inspection/refusal
lane. It does not establish native macOS execution, managed-team authorization,
a complete ledger milestone or a real coding-agent task. The agent/model-service
choice for that last task remains pending.
