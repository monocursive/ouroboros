# Pre-J2 synthetic storage corpus

Captured on 2026-09-10 before changing runtime types, using the pre-J2 `_build/dev`
BEAM files and the real `Jido.Harness` request/event/error constructors. The writer
is `scripts/fixture/build_j2_fixture.exs`; it refuses to replace an existing capture.
`SHA256.json` records every captured checkpoint's digest. The older
`test/support/integration_fixture/fixture-datadir.tar.gz` remains unchanged.

The eight sessions cover idle, running, a running turn plus queued follow-up,
awaiting approval, closed, resumed, forked, and a removed Claude provider. Every
record includes distinct legacy runtime/native conversation IDs, usage totals, and
an event payload with nested baseline session request, event, and denial structs.
Running/queued/approval/terminal records also include a legacy turn request struct
and its historical transport turn ID. The resumed record's public cursor is 41,
sequence offset 40, and resume count 1. One terminal effect-ledger record contains
a nested baseline validation exception in its error classification.

These are synthetic states written through `DurableFile.put_checkpoint/3`, not
model/tool execution evidence. The awaiting approval row represents a durable
unanswered state; no live PID or waiter is serialized. Paths and prompts are
synthetic and there are no credentials. The writer node is `nonode@nohost`.

Run `sh scripts/fixture/j2_boot_gate.sh` to boot fresh copies under both lazy and
preloaded module order (10 runs each; `BOOT_GATE_RUNS=1` for a smoke gate). The
reader uses a different node name so opening history cannot resume work or take
workspace leases. It checks all eight records, nested values, usage, identity and
cursor migration, the ledger row, unchanged original bytes, and no quarantine.
`make boot-gate` runs both the original and additional corpora on fresh copies.
