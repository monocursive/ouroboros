# Benchmark methods and reproduction

The comparison has two purposes: measure the cost of a sandbox around fixed local work, and check whether normal coding workflows complete. It does not estimate a security escape rate or certify any product. Product source was not modified to make a competitor pass. Ouro was built from the recorded clean revision using Rust 1.98.1.

## Execution classes

Native command wrappers are compared on the same host against an uncontained direct command. Ouro uses its observed `tool` profile for offline workloads and `agent` profile for online coding. Greywall uses its namespace or Seatbelt backend and a separate Greyproxy. MXC uses its shipped bubblewrap or Seatbelt executor. macOS native Ouro execution is unsupported; its disposable offline VM preview is a separate diagnostic lane.

OpenShell runs Linux containers behind a gateway. Each of its images is also run by plain Docker on the same daemon. Fresh `docker run` is compared with fresh OpenShell `create --no-keep`; retained `docker exec` is compared with retained OpenShell `sandbox exec`. Warm creation is saved separately and excluded from warm command timings. Neither warm execution nor a Linux container on OrbStack is compared as equivalent to booting a fresh Ouro VM.

## Normal configurations

All coding lanes have a writable fresh repository, read-only client installations, private writable agent state and scratch space, and the provider destinations required for that client. Vendor approval prompts are disabled uniformly so the outer sandbox determines containment. Codex uses `--dangerously-bypass-approvals-and-sandbox` in every direct/outer lane; nested Codex sandboxing inside Ouro failed during setup. This measures the outer products, with the direct command as the uncontained control.

Ouro stages Codex auth into private vendor state and receives the Anthropic API key through the environment. The optional Ouro credential vault is not timed. Its observed `agent` profile uses the external proxy bridge and explicit destination grants. Greywall uses default credential substitution and the shipped Greyproxy configuration, generated MITM CA, standard 430xx ports, and UDP/TCP DNS. MXC uses its documented external HTTP proxy mode, explicit process environment and CA trust. On Mac, native MXC grants the Homebrew installation read-only and standard client temporary directories writable. It does not use `profileOverride`, broad keychain access or GUI privileges.

OpenShell uses provider credentials with the documented endpoint contract. The Codex provider uses NVIDIA's versioned bootstrap and token refresh; CLI 0.159.2 also needs its non-secret account ID for routing discovery. The access credential in the sandbox remains a provider handle. Plain Docker has real credentials in transient environment/state, providing the simpler runtime control. A single-client image is used on the nearly full VPS; its Docker and OpenShell arms use exactly the same image ID. Pi and Mac use an image containing all three clients. No secret is baked into an image.

Native safety probes grant the same read-only private directory and deny the same child directory. Greywall's explicit `denyWrite` on that parent interacts with `denyRead` and re-exposes the child; a separate minimal-configuration probe removes the redundant parent `denyWrite`. Both results are retained. An explicitly exposed Unix socket can remain usable through a read-only directory; this is reported separately from an ungranted path escape.

## Performance protocol

Seven workloads: one no-op; Python startup; Git status over 1,003 indexed files; 1,000 reads of 4 KiB; 1,000 buffered create/truncate/write operations of 1 KiB; 100 child process launches; 20 million fixed integer operations. There are three discarded warm-up rounds followed by 30 measured rounds. Arm/workload order is shuffled within each round with seed 20261011. Each host serializes its benchmark phases. These are shared test machines, so background load is recorded with every sample; they are not controlled bare-metal lab machines.

The host uses a monotonic timer around the full command. The child separately reports work time, operation count and checksum. A successful sample must exit zero, avoid timeout and match the reference completion record. Ouro must also report an exited outcome, an empty process tree and no coverage gaps. Failed or unconfirmed launches are never treated as fast successful samples. The headline uses observation-on Ouro; observation-off failures and partial availability remain in the raw datasets.

Medians are the mathematical median, including averaging the middle two values for even sample counts. p95 uses nearest rank, `ceil(0.95*n)-1` in sorted zero-based values. Raw samples, minimum and maximum remain available. No statistical significance claim is made. Buffered writes do not call `fsync`; their speed is not durable-write throughput. Separate nonce/device/inode probes check whether native writes reach the same host backing file. Different overlay/cache/lifecycle states in fresh and warm containers are inherent and recorded.

## Coding tasks and checkers

Every agent gets the same three small tasks in a fresh Git repository: add multiplication and tests, correct a parser boundary case, and replace YAML storage with JSON. Each agent/arm performs the three tasks twice. Task order and wrapper order are randomized within repetition blocks. OpenCode receives an explicit `--dir` and matching `PWD`. Claude and OpenCode use `claude-sonnet-4-5`; Codex uses `gpt-6.1-sol`, low reasoning effort. Client versions are Claude Code 2.1.295, OpenCode 1.19.0, Codex 0.159.2 with its matching Code Mode helper.

The independent checker verifies supplied tests are unchanged, runs those tests, and checks hidden behavior outside the agent's write access. A pass additionally requires a zero client/wrapper exit and no timeout. Every run retains the prompt, stdout, stderr, patch, resulting source, checker verdict and redacted configuration. Negative fixture controls fail before a repair.

One larger inventory CLI task adds CSV validation, Decimal aggregation, category/filter flags, sorted JSON output, error handling and a documentation example. Ten supplied tests and hidden CLI checks validate it. This single workflow run per arm is compatibility evidence. Claude has a 15-turn cap in all arms: a nonzero max-turns exit is a strict failure even if its patch passes the checker, and is identified as such.

Coding latency includes network/provider/model variation. Native timing encloses the client/wrapper; the independent checker runs afterward. Container total timing also includes fixture initialization and checking; `container_result.work_ms` isolates client execution. Comparisons are within an agent, host and execution class. Six small-task runs and one workflow run cannot establish a general productivity ranking, large-repository compatibility, or model-cost advantage.

## Host provisioning and limits

The Ubuntu VPS has two recorded AppArmor overrides: its unprivileged-user-namespace restriction was disabled during setup, and the distro bubblewrap executable was copied byte-for-byte to a path without the capability-denying pathname profile. Every final native arm has the same copy available. Results are not an untouched Ubuntu installation. The Pi lacks the memory cgroup controller and Landlock and required the exact-kernel Unix diagnostics module for Ouro networking. Docker 29.1.3 was installed from Docker's official Debian repository because the Debian package was below OpenShell's minimum Docker version. These deployment costs matter alongside command latency.

Resource checks are bounded and separate from default timings. Ouro is explicitly asked for wall=1s, mem=64MiB/swap=0, pids=16, cpu=25%, storage=8MiB and inodes=64. A 96 MiB allocation, at most 32 short-lived children and 0.2 CPU-seconds of work supply positive controls. MXC is explicitly asked for its 1,000 ms process timeout. Unsupported shared ceilings are labelled unsupported rather than simulated by the benchmark's timeout. Container resource probes compare unbounded and explicitly limited Docker/OpenShell runs. Missing controllers or a refusal are recorded as such. Defaults are not automatically equivalent across products.

## Reproduction and evidence

The executable hashes, host facts, image IDs, Dockerfiles, policy files, source snapshots, schedules and raw records are saved in each host export. `harness/agentbench.py` defines the original small fixtures; `workflow_fixture.py` defines the larger task. The installed harness in each export and each run's source hashes identify the exact executed version. Credentials, auth caches, private provider databases and transient homes are excluded from the reusable evidence.

Prepare a new run directory on a host already provisioned with the recorded binaries and isolated proxy/gateway. Keep measured batches serial on that host. Example native performance run:

```sh
bench_root="$HOME/bench-ouro"
bench_run="$bench_root/runs/new-perf"
mkdir -p "$bench_run"
ln -s "$bench_root/bin" "$bench_run/bin"
ln -s "$bench_root/harness" "$bench_run/harness"
python3 "$bench_root/harness/suite.py" --root "$bench_run" \
  --out "$bench_root/results/new-perf" --samples 30 --warmup 3
```

Coding runs use `agentbench_v2.py`, or `agentbench_workflow.py --tasks inventory-workflow`. Pass a new output path, local `--key-file`, and `--auth-file`; do not place secret text in argv. On Pi ensure `/usr/sbin:/sbin` is in PATH. The Mac needs `/opt/homebrew/bin`, the recorded `DOCKER_HOST`, `OPENSHELL_LOCAL_TLS_DIR` and `XDG_STATE_HOME` for its gateway. See the saved orchestration scripts for the exact run commands; their wait PIDs are specific to this run.

OpenShell coding uses `openshell_agent_v2.py`; on VPS pass `--agents CLIENT --single-agent-image`. Provider setup is done once; later runs use `--skip-provider-setup`, and `--skip-build` only when the saved image exists. `openshell_perf_v2.py` measures both lifecycle modes with both Docker controls. Provider/profile installation must finish before timed work. `container_egress_probe.py` repeats the reachable-host canary, using `host.docker.internal` on Mac.

The reusable provider setup records the cache access-token expiry through a separate provider update before configuring refresh. The expired VPS v2 provider is retained; recovery used a fresh v3 provider with the same profile. Pi records actual cold attempts and separate warm-start availability; its `--docker-only` performance lane measures controls after default OpenShell startup failures, without inventing successful OpenShell samples. Requested Docker memory on Pi is ignored with a missing-controller warning; Ouro refuses its explicit request.

Temporary benchmark proxies and gateways were stopped after measurement. Docker, binaries, configurations, private credential caches and raw evidence remain on the test hosts. `service-cleanup.json` records only the task-owned PIDs stopped. To repeat, restart the gateway before timed work. On Pi/Mac the stored local mTLS setup uses:

```sh
export OPENSHELL_LOCAL_TLS_DIR="$HOME/bench-ouro/openshell/tls"
export XDG_STATE_HOME="$HOME/bench-ouro/openshell/state"
openshell-gateway --compute-driver docker \
  --tls-cert "$OPENSHELL_LOCAL_TLS_DIR/server/tls.crt" \
  --tls-key "$OPENSHELL_LOCAL_TLS_DIR/server/tls.key" \
  --tls-client-ca "$OPENSHELL_LOCAL_TLS_DIR/ca.crt"
```

On Mac also set the recorded OrbStack DOCKER_HOST and empty Docker config. The VPS's local gateway used plaintext loopback: `openshell-gateway --compute-driver docker --disable-tls --bind-address 127.0.0.1`; use its existing CLI registration. Proxy preparation in the native agent harness starts the isolated Greyproxy when its health endpoint is absent. Treat saved orchestration scripts as the actual run recipe; their PID waits and output names must be changed for a new run.

The original Mac container recorder omitted CSV from returned workspace files. Its committed CSV input is preserved in the immutable fixture specification, and tracked changes are in the patch. Temporary untracked CSV files are not a retrospective filesystem snapshot. The actual image recorder source is preserved; the current reusable recorder includes CSV.

Run `export_results.py` on the host for a sanitized archive and file hashes. `audit_results.py` derives descriptive summaries without modifying raw data. `finalize_analysis.py` applies the fixed dataset selection and fails on missing coverage or invalid successful-work counts. Original pilot results remain readable, but must not be mixed into the final comparison. See [the exclusion register](EXCLUSIONS.md).

Documentation sources: [Greywall v0.3.7 configuration](https://github.com/GreyhavenHQ/greywall/blob/v0.3.7/docs/configuration.md), [OpenShell architecture](https://docs.nvidia.com/openshell/latest/about/architecture), [NVIDIA Codex bootstrap](https://github.com/NVIDIA/OpenShell/blob/v0.1.3/examples/codex-app-server/start-codex-app-server), [MXC bubblewrap](https://github.com/microsoft/mxc/blob/main/docs/backends/bwrap/bubblewrap-backend.md), [MXC Seatbelt](https://github.com/microsoft/mxc/blob/main/docs/backends/seatbelt/seatbelt-backend.md), [Codex authentication](https://developers.openai.com/codex/auth), [Docker Debian installation](https://docs.docker.com/engine/install/debian/).
