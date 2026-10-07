# Two-node fleet execution, 2026-10-07

The first fleet execution slice passed **12 production-CLI fault scenarios** on
the x86_64 VPS and Raspberry Pi aarch64. This report is scripted-child evidence,
not full milestone-3 closure or external-agent/provider support.

[Result inventory](results/summary.json), [VPS log](vps-native.log),
[Pi log](pi-native.log), [extra checks](results/extra-summary.json),
[VPS source and binary hashes](vps-source-binaries.json),
[Pi source and binary hashes](pi-source-binaries.json).
The source manifests were compared with the local tree after testing: no mismatch
on either node. The ledger/Jail/CLI source files, manifests and lockfile are bound
by exact hashes; the build is a working-tree validation preceding the final commit.

| Case, on each node | Required result |
| --- | --- |
| `tool` | SSH submission ends; restart the entire OTP worker VM; the identical Rust owner/run survives; child runs once and exits 0. |
| `none` | Same lifecycle, always explicitly unprotected; cleanup says `not_needed`. |
| Lost reply | Close CLI stdout, retry the exact request, observe only one execution and unchanged IDs. |
| Owner SIGKILL | Verify boot/start identity through a pidfd before killing; tree becomes empty, outcome/settlement remain unknown, vendor state is removed. |
| Strict writer SIGKILL | Tree stops; outcome/settlement remain unknown; verified cleanup and no relaunch. |
| Best-effort writer SIGKILL | Child exits during the outage; restart the writer; retain observed exit with degraded evidence and unchanged identity. |

Every normal-output case reads EOF on stdin, produces 5,003 bytes, stores a
64-byte captured prefix marked truncated, and leaves stderr `not_captured`.
Every replay preserves the run and owner identity and the one-byte execution
marker. Changing the capture limit under the same request ID refuses.
Contained cases create synthetic vendor state; only verified empty-tree receipts
permit its deletion. Each case preserves the authoritative Jail receipt and
cleanup state, separately from the fleet's status snapshot.

The [extra probe](extra.py) also passed live job-scoped show/transcript, verify,
query and tail; selector/store override refusals; `wait`; Pi memory-controller
ineligibility before launch; stopping the Pi fleet service while a child lives;
stale status without invented failure; retry pinned to the unreachable Pi;
reattachment to the same owner after service recreation; and cancellation ending
with an observed signal. [Extra log](extra-native.log).
A TLS client without a peer certificate was
[refused at handshake](no-client-certificate.log). Successful fleet calls used
mutual TLS and a private cookie, with leaf private keys generated on their own
nodes. Private keys, cookies and TLS credential files are not in this evidence.

The fleet contract suite passes nine tests on both native OTP 27/Elixir 1.18
hosts ([VPS](vps-mix-test.log), [Pi](pi-mix-test.log)) and on the local Mac.
It covers JSON null preservation, bounded commands, private durable checkpoints,
request identity, schema mismatch before effects, stale observations, bound
reader routing, degraded evidence and unknown settlement display.

## Reproduction and test corrections

Build and provision private nodes as described in the [source guide](../../README.md).
The checked-in probe uses the explicitly authorized test addresses and isolated
`ouro-fleet-lab-20261007` directories. Choose a fresh request prefix:

```sh
OURO_PROBE_ID=your-new-prefix python3 probe.py results
python3 extra.py results
```

`OURO_PROBE_NODES=pi` reruns only Pi cases and preserves the other node's summary.
The final recorded VPS cases use `native-r7`; Pi cases use `native-r8`. The initial
fixture incorrectly expected a tree-empty field in the cleanup file and expected
vendor cleanup for `none`; it now reads the receipt and checks `not_needed`.
The trusted launch profile is temporarily removed from the isolated test config
for `none`, matching that mode's required refusal of inherited operator grants.

A real status regression was found and repaired: the ledger's durably recorded
unknown outcome must map to fleet settlement `unknown`, while preserving
`ledger_settlement: recorded`. The [initial failure](status-mapping-regression.log)
is retained. Another run correctly refused group-writable rebuilt executables;
the test installation was corrected to mode 0700, without weakening the guard.
The [initial installation refusal](initial-executable-mode.log) is preserved.
The VPS log contains that final Pi installation refusal after all six VPS cases
passed; the separate Pi rerun completes the twelve-case inventory.

After collection, both temporary fleet services and their private lab writers
were stopped. The 11 Elixir/OTP packages installed solely for this test were
removed from the VPS before restoring the reference conformance lane. Pi keeps
its runtime packages and the exact-kernel Unix diagnostics module. No user
workspace, existing deployment or kernel image was replaced.

Manual membership provisioning, final fleet record freeze, packaged installation,
the second-node real-agent run and historical custody are still separate work.
The Pi still lacks usable memory cgroups and Landlock. No production availability,
physical power-loss durability or managed authorization is established here.
