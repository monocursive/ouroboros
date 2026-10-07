# Ledger milestone-2 closeout, 2026-10-07

The [acceptance map](../../milestone-2-acceptance.md) records the completed
L1–L9 contracts and the scripted §5.4 suite. The frozen inventory contains 67
schemas and golden fixtures. Validation checks both each hash and the exact
file inventory, and rejects changed, missing, added or symlinked inputs.

The fleet bridge resolves immutable metadata without effects, reserves a run
without an owner, and launches only through the existing exclusive owner lease.
Its native test proves no child before owner start, same-request replay, one
execution and conflict refusal on both x86_64 Linux and Raspberry Pi aarch64.
No existing ledger schema bytes changed for this bridge.

## CI incident and repair

The initial conformance run at `d6b09db26b5a2f5a62c359c6c398b42fd8690bdf`
failed while linking on a full reference-host filesystem. The
[failed build log](ci/failed-build.log) is retained. Two inactive, reproducible
Cargo target directories were removed after checking that no live process used
them; source and evidence were kept. The driver now refuses before building
when less than 4 GiB is available and always copies the build log into evidence.
This is a headroom check, not a disk-space reservation.

The first rerun built successfully but correctly failed I01: Elixir/OTP had
been installed on the same VPS for the new fleet tests while CI was running.
The [refusal](ci/beam-host-refusal/summary.txt) and
[I01 inventory](ci/beam-host-refusal/i01.txt) are preserved. The gate was not
weakened. Fleet testing now has a separate hosted CI lane. The temporary fleet
services and exactly the 11 newly installed VPS packages are removed before
final reference conformance; Pi runtime packages are independent of that lane.

## Validation and limits

The local macOS ledger suite passes 180 tests with no failures or ignored tests;
its [log](local-ledger-test.log) is portable/refusal evidence, not native launch
proof. The build-headroom regression and conformance-driver tests pass 69 tests
in [this log](ci/preflight-tests.log). Contract freeze and fixture validation pass.
The final native Raspberry Pi suite passes **221 tests**, with no failures,
ignored tests or capability skips: [log](pi/ledger.log), [summary](pi/summary.json).
This includes the real proxy path with Unix diagnostics and the fleet reservation
bridge. The [source and binary hashes](../../../fleet-v1/evidence/2026-10-07-two-node/pi-source-binaries.json)
bind the production sources; only fleet formatter compatibility and documentation
changed after those execution tests. Final CI evidence is recorded below when
the reference run completes.

The [Pi proxy follow-up](../../../jail-v1/evidence/2026-10-07-pi-proxy/README.md)
records the exact-kernel module, all 220 ledger tests at the pre-bridge source,
and the production proxy-redaction proof. Memory cgroups and Landlock remain
unavailable on that Pi. Fleet execution evidence is
[separate](../../../fleet-v1/evidence/2026-10-07-two-node/README.md).

No physical power loss, managed authorization or new external-agent/provider
acceptance is claimed. Historical custody remains a requirement before the later
legacy cut; this change removes no legacy history.
