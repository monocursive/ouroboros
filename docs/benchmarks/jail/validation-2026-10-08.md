# Current Jail validation — 2026-10-08

The current frozen Linux Jail inputs pass the fixed-workload performance gate
and fresh Ubuntu 26.04 signed onboarding. Real OpenCode trials produced both
successful tasks and failures; **the repeated compatibility matrices did not
complete and are not a blanket support claim**. Fleet and native macOS execution
were outside this work.

## Changes and reproduced failure

OpenCode 1.18.32's file-search tool needs `rg`. Neither test host had it on the
contained path. The agent tried to fetch ripgrep from `github.com`, and the
starter profile correctly refused that destination. The provider-independent
[regression runner](opencode_tools.py) reproduces this using the real OpenCode
binary. Its [upstream lookup logic](https://github.com/anomalyco/opencode/blob/v1.18.32/packages/core/src/ripgrep/binary.ts)
uses an installed `rg` before attempting its download.

The workflow now provisions ripgrep before agent testing; a missing dependency
refuses before contacting a model. A private tool directory receives an explicit
read-only grant and the child is invoked through `/usr/bin/env PATH=…`, because
contained profiles deliberately replace the host's path. The first private-tool
probe omitted that child override and still failed; those
[VPS](results/validation-2026-10-08/vps/tools/result.json) and
[Pi](results/validation-2026-10-08/pi/tools/result.json) failures are retained.
After correction, all **seven cases per host** passed: one expected denial
without rg, then three file-listing and three search successes. Every case has
healthy coverage, a settled receipt and verified tree cleanup:
[VPS](results/validation-2026-10-08/vps/tools-fixed/result.json),
[Pi](results/validation-2026-10-08/pi/tools-fixed/result.json).
These probes make no model request and do not count as full agent tasks.

The network allowlist and Jail runtime are unchanged. Ripgrep was downloaded
from each distribution's package repository and extracted in private test
storage, without installing system packages: 15.1.0 on the VPS, 14.1.1 on Pi.
Fresh VMs install the distribution package during prerequisite bootstrap.

The [agent matrix](agent_matrix.py) uses isolated configuration, an empty vendor
home, disposable git workspaces, a fixed model, shuffled direct/off/on order,
and bounded runs. An independent judge runs the generated repair under the
`tool` profile and refuses changes to the fixture tests. Failed and timed-out
runs are retained. The runner stops on an explicit provider rate limit, saves
active-trial identity for interrupted runs, and never treats incomplete evidence
as a completed matrix. The [verifier](verify_agent_matrix.py) checks inventories,
summary consistency, schema/semantic validity, attempt attribution and trace
hashes. Its regression checks are wired into the contracts workflow.

## Build binding

The tested Jail input digest is
`sha256:0abe3b09146a35ad31793908f78cec33ea3400d9e2400c29c6e7510e77276f32`.
It matches integration revision `d0bc346da1145c838b5b47a428c012bb2a9437d6`;
[freeze validation](results/validation-2026-10-08/freeze-check.txt) confirms the
frozen runtime inputs have not changed since the tested clean revision.
The x86_64 executable was built clean at
`f933105ebfcbdfee0133986e21cfe7423e7aeb75` with Rust 1.98.1, optimization 3.
Its SHA256 is `73f3de8cdb17eb6b74996f6d7f4d8c43c893a423a6547cd3708abfd8b94b8395`.
The ARM64 executable reports null git revision/dirty metadata because it was
built from an archive; its identical source-input digest and SHA256
`10b53fa587fe7fb0f6a69d6d5050513c987fb811d1521a99666b4414c137fab9` identify it.
This is current-input validation, not a claim that the two binaries are identical
or that either is a new public release.

OpenCode is pinned to 1.18.32. The ARM64 release archive was independently checked
against its GitHub release SHA256
`568461b7d4d8c19865c97e9a1102e613049c6039d01fe772154de873c1865840`.
The VM's x86_64 archive is pinned by the onboarding runner. The model is
`opencode/big-pickle`, with no operator credential. Its
[public pricing](https://opencode.ai/docs/zen/#pricing) was checked on October 8;
only synthetic fixtures and their prompts were sent.

## Agent reliability and workload timings

The initial matrix planned five rounds of each task and execution mode.
The VPS stopped after **21 trials: 17 passed, four failed**. Two failures hit
the 120-second Jail wall limit; two explicitly reported provider rate limiting,
one also exposing the missing-rg dependency. The Pi stopped after **19 trials:
14 passed, five failed**. Four hit the Jail wall limit and one uncontained
baseline hit the 140-second outer deadline. In the deadline cases the requested
file or repair was correct, but the process did not finish successfully.
A separate VPS smoke also reached its wall limit; the Pi smoke passed in 43.49 s.

A diagnostic VPS retry with the provisioned tool directory stopped at the first
provider rate-limit response, after OpenCode's own backoff. Its remaining five
planned trials were not attempted. This retry precedes the explicit child-PATH
correction and makes no claim about the file-search fix. The later offline
regression and fresh VM establish that fix. Earlier startup stalls are not
claimed resolved: direct runs also vary widely, and provider errors do not
explain every deadline case.

The table shows **passed / attempted; successful-run median wall time**.
Failures remain in the denominators; each cell has at most five observations.
Fresh vendor state, package downloads, model latency and tool choices are part
of these times. They are not a causal estimate of Jail or observer overhead.

| Task | Mode | VPS | Pi |
| --- | --- | --- | --- |
| greeting | direct | 4/4; 18.02 s | 3/4; 71.48 s |
| greeting | off | 3/3; 10.96 s | 3/3; 67.89 s |
| greeting | on | 2/3; 46.10 s | 3/3; 26.57 s |
| repair | direct | 3/4; 39.00 s | 3/3; 88.46 s |
| repair | off | 2/3; 85.37 s | 1/3; 49.21 s |
| repair | on | 3/4; 56.97 s | 1/3; 108.56 s |

[Initial VPS matrix](results/validation-2026-10-08/vps/matrix/result.json),
[initial Pi matrix](results/validation-2026-10-08/pi/matrix/result.json),
[provider-limited retry](results/validation-2026-10-08/vps/corrected/result.json).
The [VPS](results/validation-2026-10-08/vps/matrix-verification.json),
[Pi](results/validation-2026-10-08/pi/matrix-verification.json), and
[retry](results/validation-2026-10-08/vps/corrected-verification.json) evidence
checks explicitly report `complete: false`.
The initial harness checked greeting contents live but did not retain the files.
Those two audits additionally report `fixture_evidence_complete: false` and name
the missing greeting artifacts. They require the explicit legacy
`--allow-missing-greetings` option; the current harness retains the files and the
verifier refuses missing artifacts by default. The original live verdicts are
preserved, with this limit on independent rechecking.

Contained attempts, including failures, report empty trees and complete state
cleanup. The direct baseline has no Jail lifetime guarantee. Its two stopped
runs retain disposable scratch directories for diagnosis; the
[VPS](results/validation-2026-10-08/vps/cleanup-audit.json) and
[Pi](results/validation-2026-10-08/pi/cleanup-audit.json) audits only check current
same-user file references and do not claim complete descendant tracking.
The final [record audit](results/validation-2026-10-08/record-audit.json) validated
81 receipts and 179,627 events across 61 traces against the frozen schemas and
semantic rules. All 80 enforced receipts show verified empty trees and complete
cleanup; the remaining receipt records the Ubuntu 24 refusal.

## Fixed-workload performance

**K17 passed:** five warmups and 30 measured samples per arm, direct/off/on,
plain and delegated sessions, no-op, 200 child executions and 5,000 file rounds.
There are 630 launch records: 90 warmups and **540 measured samples, zero
exclusions**. The predeclared maximum one-minute load was 3.0; observed maximum
was 1.64. This run started after the VPS agent matrix stopped.

| Session | Worst added startup p95 | File post-start overhead, off versus direct |
| --- | ---: | ---: |
| Plain | 131.3 ms | 34.9% |
| Delegated | 114.9 ms | 37.9% |

The file-heavy observer cost remains substantial: post-start observation-on
versus off is +326.7% plain and +339.3% delegated. These are measurements of the
current implementation, not an optimization claim. All 60 observation-off
no-op samples retain the documented `exec_unconfirmed` flag/exit 1; their target
phase timestamps permit timing under the existing gate rules. They are not
successful execution receipts.

[Raw records and summary](results/validation-2026-10-08/vps/perf/summary.md),
[K17 verdict](results/validation-2026-10-08/vps/k17.json),
[independent Mac recomputation](results/validation-2026-10-08/vps/recomputation.json).
Every summary field except recomputation provenance matched.

## Fresh-machine onboarding

Three disposable x86_64 QEMU VMs ran on the local Mac under TCG. They had no
Rust toolchain, credentials, host mounts or production signing keys. Dependencies
were installed before the user-workflow timer. The binary's signature, revision,
target and source digest were checked; new identity-check regressions reject a
dirty, mismatched or debug artifact.

- Ubuntu 26.04: the original signed install → contained command → OpenCode write
  workflow passed in **66.86 s**.
- Ubuntu 26.04 with the corrected ripgrep prerequisite: signed install → contained
  command → OpenCode **glob, read, write and comparison** passed in **82.85 s**.
  Its transcript confirms that the real agent used the glob tool. These timings
  describe different tasks and should not be treated as a performance regression.
- Stock Ubuntu 24.04: signature verification, upgrades and corrupt-archive and
  corrupt-signature rejection passed; contained `true` still refused with exit
  125 because the stock bubblewrap/user-namespace combination is unavailable.
  Host security policy was not altered to make it pass.

All three runs checked that corrupt artifacts leave an existing installation
unchanged. All VMs and ephemeral private signing/SSH keys were removed afterward.
The [first Ubuntu 26 record](results/validation-2026-10-08/onboarding-ubuntu26/vm.json),
[corrected Ubuntu 26 record](results/validation-2026-10-08/onboarding-ubuntu26-rg/vm.json),
and [Ubuntu 24 refusal](results/validation-2026-10-08/onboarding-ubuntu24/vm.json)
retain the manifests, package checks and receipts. Public publishing and a
production signing identity remain separate operator decisions.

## Reproduce

Use the exact optimized Jail input digest and pinned OpenCode binary named above.
Keep binaries and the read-only ripgrep directory outside writable workspaces.

```sh
python3 docs/benchmarks/jail/agent_matrix.py \
  --binary /private/bin/ouro-jail --agent /private/agent/opencode \
  --tool-dir /private/tools --inputs sha256:0abe3b09146a35ad31793908f78cec33ea3400d9e2400c29c6e7510e77276f32 \
  --out /private/evidence/new-agent-matrix --rounds 5 --diagnostic-logs
python3 docs/benchmarks/jail/opencode_tools.py \
  --binary /private/bin/ouro-jail --agent /private/agent/opencode \
  --tool-dir /private/tools --inputs sha256:0abe3b09146a35ad31793908f78cec33ea3400d9e2400c29c6e7510e77276f32 \
  --out /private/evidence/new-tool-probe
```

The missing-rg regression requires a host without a system rg; use a disposable
host rather than uninstalling an operator's tools. `verify_agent_matrix.py`
requires all planned trials by default; `--allow-incomplete` validates retained
failures while explicitly reporting missing trials. Do not convert that result
into a successful compatibility claim.

The archived [record-audit script](results/validation-2026-10-08/audit_records.py)
rechecks all retained receipts and traces when run from the repository root with
the evidence directory as its argument. Local harness tests cover evidence
omissions, incomplete inventories, failed-run timing, and build identity.
