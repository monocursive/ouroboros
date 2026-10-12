# Protocol selection and retained exclusions

No failed launch contributes a successful timing. All originals are retained. `report-v1.md` and `feature-matrix-v1.md` are superseded pilot interpretations, not final conclusions. In particular, the old claim that Pi namespace writes used a faster backing store was unsupported; do not reuse it.

| Dataset or pilot | Treatment | Reason |
|---|---|---|
| Native original agent batches, v1/v2/v3 on Linux | Setup diagnostics | Proxy DNS/ports, CA generation, missing Codex helper, inner Codex sandbox and weak original checker differed |
| Every native v4 OpenCode row, including apparent passes | Excluded | OpenCode used inherited PWD instead of the fresh repository; replaced with explicit-dir v5 |
| Pi v5 MXC OpenCode | Excluded | SSH PATH omitted installed `/usr/sbin/iptables`; replaced with v6 MXC |
| Mac v2/v5 MXC OpenCode | Excluded | First had PWD issue; v5 omitted a read-only Homebrew runtime grant; replaced with v6 MXC |
| Mac v2 Codex | Excluded | Old inner-sandbox protocol; replaced with outer-only v4 |
| Mac v2 Claude | Selected for small tasks | Same fixtures, independent checker and normal native configuration; no OpenCode PWD issue |
| Original native safety socket results | Excluded from equal-grant comparison | Only MXC was granted the socket's parent directory |
| Linux perf-v2/resource-v2 Ouro | Setup/feature diagnostic | File deny inside an RO directory fails bubblewrap setup; retained as an Ouro limitation, replaced with common denied-directory layout |
| Linux perf-v3-folder-deny | Selected performance and safety | Equal requested grants; Greywall's denyWrite-parent/denyRead-child interaction reported explicitly and checked separately with minimal rules |
| Ouro observation-off | Diagnostic only in headline comparison | Very short execs can be unconfirmed; per-case successes remain available |
| OpenShell original OpenCode lane | Excluded | Raw env credential and weaker original checker, replaced with provider-backed fixed-dir lane |
| OpenShell smoke/bootstrap/image pilots | Setup diagnostics | YAML truncation/profile update errors, warm-name length, denied optional cgroup diagnostics, Codex identity/routing bootstrap and image build failures |
| VPS combined-client OCI build | Capacity diagnostic | ENOSPC on the nearly full VPS; final single-client images keep identical Docker/OpenShell controls |
| Mac OpenShell perf-v2 host-egress rows | Egress excluded; timing retained | Linux bridge IP was not the Mac host; both Docker positive controls failed. Replaced by container-egress-v3 using host.docker.internal |
| Small task vs larger workflow timing | Separate | Different amount of work; n=1 workflow is compatibility evidence |
| Native wrapper vs container/VM timing | Separate classes | Different lifecycle and guest/kernel/filesystem environment |

Final small-agent selection:

- VPS: v4 Claude/Codex, v5 OpenCode; all native modes. OpenShell single-client v2-final Claude/OpenCode and v3-final Codex batches.
- Pi: v4 Claude/Codex; v5 direct/Ouro/Greywall OpenCode and v6 MXC OpenCode. OpenShell cold v2-final records18 startup failures; Docker controls18 passes. Warm availability is a separate attempt for each client.
- Mac: v2 Claude, v4 Codex, v5 direct/Greywall OpenCode and v6 MXC OpenCode. No native Ouro agent lane. OpenShell v2-final.
- Workflows: workflow-v2-final native; openshell-workflow-v2-final, split by client on VPS, with Codex v3. Pi warm workflows are unavailable, with no invented attempts.
- Performance: Linux perf-v3-folder-deny; Mac perf-v2-final native; openshell-perf-v2-final for all container lanes. Mac's unavailable native arms remain unavailable.

The final machine-readable selection includes source hashes and filters in `results/2026-10-11/analysis/selected-results.json`. The all-dataset audit includes pilots for inspection, not for pooling into a ranking.


The VPS expired-provider Codex v2 batch is retained as a credential-lifecycle diagnostic. Its original provider expired after a gateway refresh, and the next gateway refresh returned401. Fresh-provider v3 uses the still-valid authorized cache and explicit expiry metadata and passes all controls/tasks. Creating a provider does not accept the expiry flag; updating the new provider does. Failed recovery command pilots remain alongside the successful setup.

The Mac OpenShell filesystem-v3 probe omitted normal runtime read grants and failed before Python started; v4 supplies those grants and has valid positive/negative controls. The original Mac container recorder omitted CSV from returned source files. Baseline committed CSV bytes are in the immutable workflow fixture, and tracked changes are in the patch; this is not a retrospective byte-for-byte dump of temporary CSV files. The original recorder is retained from the actual image.

The Pi all-agent image build succeeds. Its first warm smoke, three client warm attempts, a default thin `/bin/true` and every cold task attempt fail runtime provisioning. Supervisor `--version` works; a final Docker-event diagnostic shows the workload container exits1 and subsequent supervisor cleanup exits137, without an OOM event. The deeper cause is unknown. Docker-only performance controls are selected on Pi; OpenShell timings remain unavailable. No kernel or policy hardening was disabled to manufacture a pass.
