# Startup and Pi write follow-up

Baseline: ac1263a0961d5e676c2a03e516848a9fd00dde9b. Original and first-after evidence are unchanged.

- 2026-10-12: clean tree verified; all three hosts reachable; baseline profiling and disk/provenance inspection begun.
- VPS root has 341 MB free. Build target will use /dev/shm; no previous evidence is removed.
- Scored runs retain the same clients, versions, models, fixtures, policies, operation checks and observer validation.

- Baseline and v1 parent traces captured on both Linux hosts; v1 doctor status/reason/mechanism rows match all 30 baseline rows on each host.
- Pi instrumentation and 36-cell truncate/overwrite/fresh matrix captured. Direct close median: ~805 ms for truncation versus ~2 ms for overwrite/fresh; old observed truncation remains variable. These are excluded diagnostics.
- Source v3 builds pass on both architectures. Local Clippy and portable units pass 267 tests with 1 ignored. Linux observer/security validation is in progress.
- VPS temporary storage quota interrupted compilation before unit tests ran; log retained and owned debug cache removed after verifying the release binary unchanged. Validation restarts with debug symbols disabled, assertions/optimization/runtime policies unchanged.
- Mac full rerun PID 8407 is active, using the exact retained agent image. Native small tasks are complete, workflows in progress.
- Stopped VPS before working state privately offloaded: 57,339 entries verified; executables/login caches retained, public original evidence unchanged.

- Final product source validated on VPS: 565 unit tests and 206 observer/isolation integration tests pass; both new mechanism regressions pass. Missing CapEff now refuses explicitly.
- Pi full unit suite passes 565 tests. All 45 current failures in the exercised broader suites also occur with the baseline; its baseline additionally fails one timing-sensitive same-UID proc test. This is not a pinned-host conformance pass. The slow-consumer test takes about 20 seconds on this Pi against a 10-second absolute bound in both versions.
- Matched VPS timing score is complete: no-op old 106.8 ms, new 83.4 ms, MXC 19.4 ms; paired median reduction 22.5%, paired delta interval [-28.3,-19.9] ms. All seven paired workload intervals are negative. Both binaries retain matching safety statuses.
- Full native coding rerun underway on both Linux hosts. Pi scored timing run follows all compilation and write diagnostics. Mac container workflows and timings continue.

- Final corrected source retains fresh backend-version receipt readback. Final paired no-op medians: VPS 108.9→88.1 ms (paired median reduction 17.7%), Pi 279.0→234.2 ms (17.3%). All 840 paired Ouro samples validate strict observation/coverage and all 120,000 write observations; safety and syscall results match.
- Pi final write median 808.5→531.9 ms, wide paired change interval [-407.2,-18.1] ms; the close/writeback hotspot remains. Pi Git p95 worsens 459.3→475.8 ms. No universal storage/tail improvement is claimed.
- An additional Pi queue-pressure/exit-race stress failure reproduces with baseline source and again with final source. Tests/limits unchanged, all logs retained. Final scored timings begin after that compilation/diagnostic phase.
- Mac full rerun imported: 1,260 timing samples; container small tasks 53/54 (one Codex model-capacity refusal, retained without retry), workflows 9/9. Final Linux native coding/workflows and container phases continue.

- Entries above describe historical candidates at their measurement time. V3,
v4 native and v5 Ouro scores are superseded, retained and excluded. Final v6
guards file hints by local filesystem/change-second age; VPS passes 567 unit
tests and the same observer/isolation checks with all 30 doctor statuses equal.
Final selection uses fresh guarded Ouro calls/timings and unaffected competitor
controls. Final metrics will be generated from the verified selected datasets.
