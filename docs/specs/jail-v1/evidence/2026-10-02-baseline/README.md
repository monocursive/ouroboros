# Jail baseline, 2026-10-02

Reference-host [conformance run 37058422292](https://github.com/monocursive/ouroboros/actions/runs/37058422292)
passed at `aceed908b804315dfe71524d66885bf4f203d5f4`. The directory contains
the driver's original outputs. The jail build inputs are
`sha256:f5a3d1816d5ae070fc9af25c51075ab11ecf22fde57d80696f6a98c976150f94`.
All three product executable hashes remain unchanged after the suite
(`binaries-check.txt`). The freeze checkpoint at `9ad6313d` records this run.

The native macOS workspace suite passed at the same revision. Its raw log
includes the PATH, revision and conformance markers printed before execution.
Combined acceptance is **43 pass, 7 pass with existing limits**. A01 is a
separate real-agent credential gate, not exercised here. macOS evidence covers
inspection and refusal; it does not establish native sandbox execution.

The VPS previously had no free space. `remote-cleanup.json` records removal of
12 inactive CI build directories after checking live process paths and retaining
their product binaries, sources and evidence. This recovered 6.65 GiB without
changing host policy or deleting active build directories.

Subsequent hosted-CI fixes preserve the reference-host requirements: an absent
new syscall definition in an older distribution header is explicitly reported
as unavailable on generic CI and still fails in conformance mode. Cross-target
Linux compilation installs the required AArch64 C compiler. I02 exceptions
permit only reviewed exact pagination-homonym source lines.

The hosted debug queue regression measured 6.73 MiB of process RSS for a queue
whose own accounting reported 3.94 MiB. RSS includes allocator arenas, freed
pages and thread stacks. The follow-up test uses an independent counting system
allocator to assert live requested allocations below the unchanged 4 MiB bound;
RSS remains diagnostic. `queue-live-allocation-debug.log` records 4,127,632 live
bytes on the reference host, with 15,500 dropped results. This test change does
not alter the jail runtime or its frozen build inputs.

That initial reference measurement did not close the issue: the independent
allocator check subsequently caught 7,055,628 live bytes on hosted Linux.
Page-aligned fixture strings then reproduced **7,295,632 bytes** on the VPS.
`event_bytes` charged vector lengths rather than retained capacities; path
snapshots that grow across a page boundary can reserve almost twice their
visible length. The runtime now charges capacities, including nested executable
candidates and boxed command-rule allocations. The same deterministic fixture
then retains **4,121,232 bytes**, dropping 15,718 results within the existing
budget (`queue-aligned-before.log`, `queue-aligned-after.log`). The stronger test
keeps process RSS as a diagnostic and independently enforces the live allocation
bound. This runtime correction changes the build inputs and requires a new
conformance run and tested freeze; the original baseline above remains historical.
The [final committed-workspace run](../2026-10-02-final/README.md) subsequently
passed and supplies the current tested freeze.

The conformance driver's I02 scan now invokes the precompiled driver, avoiding
an unnecessary feature/provenance rebuild between suite preparation and execution.
The full baseline here precedes detached ledger ownership. That feature has its
own lifecycle evidence and subsequent source-specific CI run.
