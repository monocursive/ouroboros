# NVIDIA OpenShell — Feature Summary (v0.1.3)

All URLs are versioned `latest` = v0.1.3 unless noted. Docs pattern: append `.md` for clean markdown.

## 1. Identity / Version / License
- **Latest stable:** v0.1.3 (docs header: "Latest (v0.1.3) (default)"; release feed shows v0.1.4-pre.2 prerelease and rolling `dev`). Weekly-ish stable cadence (Tuesdays), N-1 minor support policy. https://docs.nvidia.com/openshell/latest/about/support-matrix.md ; https://github.com/NVIDIA/OpenShell/releases
- **License:** Apache License 2.0. Written in Rust. https://github.com/NVIDIA/OpenShell
- **SDKs:** Python (`uv add openshell`), TypeScript (`@nvidia/openshell-sdk`), Go, Rust. https://github.com/NVIDIA/OpenShell

## 2. Platform Support
| Host | Status |
|---|---|
| Linux (Debian/Ubuntu) x86_64 & arm64 | Supported (CLI is static musl, no glibc needed) |
| macOS Apple Silicon (Docker Desktop) | Supported |
| Windows WSL 2 + Docker Desktop x86_64 | Experimental |
Source: https://docs.nvidia.com/openshell/latest/about/support-matrix.md
- Standalone gateway binary: linux amd64/arm64 (glibc ≥2.28), macOS aarch64. Sandbox runtime binary: static musl linux amd64/arm64. Prover: linux musl amd64/arm64 + macOS aarch64 (same page).
- **Runtimes:** Docker (28.0+; local/single-machine), Podman (5.x; rootless), Kubernetes (1.29+ via Helm chart), MicroVM (libkrun; Hypervisor.framework on macOS, KVM on Linux). Same page. A Windows-native MXC compute driver also exists as a Cargo feature (`compute-driver-mxc`) with its own audit path. https://docs.nvidia.com/openshell/latest/observability/telemetry.md

## 3. Isolation Model
- Two-sided design: **gateway** (control plane) → **compute driver** provisions a **workload** + separate **supervisor**; the **sandbox** (`openshell-sandbox` binary) lives inside the boundary with the agent and never makes policy decisions. https://docs.nvidia.com/openshell/latest/about/architecture.md
- **Kernel-level enforcement claims:** "instruments the kernel to enforce policy on every file access, system call, and network connection". Landlock LSM (ABI ≥3, Linux 6.2+) for filesystem; seccomp user-notification for network mediation; workload sockets bound to loopback via `SO_BINDTODEVICE`; non-root single identity, no Linux capabilities; fail-closed active probes. https://docs.nvidia.com/openshell/latest/about/support-matrix.md ; https://docs.nvidia.com/openshell/latest/about/architecture.md
- **Outer network fence per runtime:** Docker/Podman: workload networking off + authenticated Unix socket; Kubernetes: NetworkPolicy allows only supervisor Service + mTLS; VM: guest has no network device + authenticated vsock. (architecture page)
- **Channel/auth:** one mutually authenticated HTTP/2 Sandbox Protocol; gateway issues per-generation Gateway JWT + Sandbox JWT (mTLS); agent freezes if supervisor disconnects; only the same supervisor can resume. (architecture page)
- Policy enforcement itself happens inside the sandbox "through the proxy, OPA, Landlock, and seccomp". https://docs.nvidia.com/openshell/latest/how-it-works/gateways/overview.md

## 4. Policy Model
- **Format:** YAML, `version: 1`, up to five sections: `filesystem_policy` (Landlock, at startup), `landlock` (best_effort/hard_requirement), `process` (run_as_user/run_as_group), `network_policies` (per-binary destinations + request rules incl. REST/GraphQL/MCP/WebSocket; hot-reloadable), `network_middlewares`. **Default deny** everything not allowed. https://docs.nvidia.com/openshell/latest/how-it-works/policies/overview.md
- **Selection order:** global policy (admin) > saved policy (`--policy` > `OPENSHELL_SANDBOX_POLICY`) > image-embedded policy > restrictive default. Effective policy = base + provider-contributed rules. (same page)
- **Default policy contents:** workdir RW; RO `/bin /usr /lib /proc /dev/urandom /etc /var/log`; RW `/tmp /dev/null`; **no network rules (all egress denied)**; Landlock `best_effort`; process identity per driver (non-root USER or UID/GID 1000; root images rejected unless policy sets non-root). Baseline system paths auto-added when network rules exist; `/.openshell` protected by a mandatory Landlock baseline. https://docs.nvidia.com/openshell/latest/how-it-works/policies/default-policy.md

## 5. Formal Verification (Prover)
- SMT-solver engine. Two checks: **boundary check** (`openshell-prover check candidate.yaml --boundary boundary.yaml`, standalone, gateway-independent, for CI/agents) and **proposal risk check** (runs in the gateway on every advisor proposal). https://docs.nvidia.com/openshell/latest/how-it-works/policies/prover.md
- Coverage domains: `filesystem, network_l4, network_rest, process, landlock`. Results: `within_boundary` (0) / `exceeds_boundary` (1, with counterexample) / `error` (2) / `unsupported`, `inconclusive` (3). Limits: >1,024 network rules or >4,096 endpoints → `inconclusive`; default 10 s timeout. (same page)
- Proposal risk findings: `link_local_reach`, `l7_bypass_credentialed`, `credential_reach_expansion`, `capability_expansion`; any finding blocks auto-approval. https://docs.nvidia.com/openshell/latest/how-it-works/policies/advisor.md

## 6. Providers / Credential Model
- Providers bind a service name to stored credentials; created via `--from-existing` (env discovery), explicit values, bare env keys, or `--from-oidc-token`. Gateway-managed refresh: OAuth2 refresh-token, OAuth2 client-credentials, Google service-account JWT, AWS STS AssumeRole (`--runtime-credentials`). https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview.md
- **Credentials injected only at approved endpoints:** workload sees only opaque placeholder env vars; the supervisor substitutes real credentials only at endpoints the provider profile authorizes (`credential_endpoint_mismatch` on mismatch). Provider list output exposes key names, never values. https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview.md ; https://docs.nvidia.com/openshell/latest/how-it-works/inference.md
- **Inference routing (0.1.x):** managed workspace-global inference routes and `openshell inference` commands were **removed**; model access now = provider profiles + per-sandbox attachments; the workload calls the provider's native endpoint. Example profiles in `providers/` (nvidia, openrouter, codex, …). https://docs.nvidia.com/openshell/latest/how-it-works/inference.md
- Extras: AWS SigV4 proxy-side signing (agent never holds AWS keys) https://docs.nvidia.com/openshell/latest/how-it-works/providers/aws.md ; Kubernetes Secrets credential driver for storing credentials as K8s Secrets https://docs.nvidia.com/openshell/latest/kubernetes/setup.md

## 7. Learning / Advisor Tooling
- **Policy advisor** (off by default; `agent_policy_proposals_enabled` gateway- or sandbox-wide): when a request is denied, the agent reads an injected guide (`/etc/openshell/skills/policy_advisor.md`, skill + `/AGENTS.md`) and calls the sandbox-local `http://policy.local` API (`GET /v1/policy/current`, `GET /v1/denials`, `POST /v1/proposals`, `GET /v1/proposals/{id}[/wait]`). Proposals are scoped network rules (host/port/binary, method/path); cannot touch filesystem/process or propose uninspectable `protocol: tcp`. https://docs.nvidia.com/openshell/latest/how-it-works/policies/advisor.md
- **Mechanistic mapper** drafts proposals from blocked connections in *every* sandbox even without the advisor; approval via `openshell rule get/approve/reject/approve-all`; approved rules hot-reload without restart. https://docs.nvidia.com/openshell/latest/about/run-your-first-agent.md
- **Auto-approval** (`proposal_approval_mode=auto` or `--approval-mode auto`): approves only when the prover risk check is clean and the destination is not flagged (private IPs, wildcards, ports >49152, DB/cache ports). (advisor page)

## 8. Agent Support
- **Any agent in a user-owned OCI image**; default workload image `nvcr.io/nvidia/base/ubuntu:24.04` (no agents baked in). https://docs.nvidia.com/openshell/latest/about/support-matrix.md
- **OpenCode:** canonical first-agent walkthrough (`ghcr.io/anomalyco/opencode` + OpenRouter provider, free model). https://docs.nvidia.com/openshell/latest/about/run-your-first-agent.md
- **Claude Code:** provider type `claude-code` (reads `ANTHROPIC_API_KEY`/`CLAUDE_API_KEY`) https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview.md ; tutorial "GitHub Push Access" launches Claude Code in a sandbox https://docs.nvidia.com/openshell/latest/tutorials/llms.txt
- **Codex:** `examples/codex-app-server` (sandboxed Codex app-server, provider with oauth2-refresh-token rotation, WebSocket exposure with SHA-256 capability-token auth). https://github.com/NVIDIA/OpenShell/tree/main/examples/codex-app-server
- **Skills package:** `npx skills add NVIDIA/OpenShell` installs public skills — `openshell-cli`, `generate-sandbox-policy`, `debug-inference`, `debug-openshell-cluster` — that teach an agent to drive the CLI, write policies, and debug gateways/inference routing. https://github.com/NVIDIA/OpenShell ; https://github.com/NVIDIA/OpenShell/tree/main/skills
- Also: Pi tutorial, VS Code/Cursor `--editor` integration, `/AGENTS.md` conventions, MCP docs server at https://docs.nvidia.com/openshell/_mcp/server.

## 9. Resource Controls
- `--cpu` (K8s-style: `500m`, `1`, `2.5`) and `--memory` (`512Mi`, `4Gi`, `8G`): Docker/Podman runtime limits; K8s sets request=limit; **VM driver accepts but does not apply** them. `--gpu` / `--gpu N`: K8s `nvidia.com/gpu` limit; Docker/Podman select default NVIDIA CDI devices round-robin; VM accepts exactly one GPU; explicit CDI IDs via `--driver-config-json {"docker":{"cdi_devices":[...]}}`. `--driver-config-json` for other experimental driver-specific settings. https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview.md

## 10. Observability
- **Logs:** `openshell logs` (gRPC stream; shorthand + OCSF lines; filters `--tail/--source/--level/--since`); gateway keeps up to 2,000 lines/sandbox in memory (not durable); supervisor writes `/var/log/openshell.YYYY-MM-DD.log` (+JSONL) on its own filesystem; workload container logs via docker/podman/kubectl. Loss-aware resumable cursors. https://docs.nvidia.com/openshell/latest/observability.md
- **OCSF JSON export:** `ocsf_json_enabled` setting (global or per-sandbox, ~10 s poll, no restart); OCSF **v1.8.0** native, one JSON object per line (`OCSF-JSON` marker on stderr; `class_uid` 4001 Network, 4002 HTTP, 4007 SSH, 1007 Process, 2004 Finding, 5019 Config, 6002 Lifecycle, 0 Base); lossy downgrade to 1.1/1.3 for AWS Security Lake / Splunk; gateway `[openshell.gateway.ocsf_log]` JSONL sink; Windows MXC ETW audit sink. https://docs.nvidia.com/openshell/latest/observability/ocsf-json-export.md
- **TUI:** `openshell term` — real-time dashboard with Gateways / Providers (or Global Settings) / Sandboxes panels, live log panel, sandbox creation (`c`), proposal review (rejects without reason). https://docs.nvidia.com/openshell/latest/observability.md ; https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview.md
- Optional OTLP export (`[openshell.gateway.otlp]`). https://docs.nvidia.com/openshell/latest/how-it-works/gateways/configuration.md

## 11. Deployment
- **One-liner:** `curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh` (CLI + prover + local gateway). https://docs.nvidia.com/openshell/latest/about/installation.md
- **Packages:** Homebrew (macOS, brew service at `https://localhost:17670`); Debian (Ubuntu/Debian) & RPM (Fedora/RHEL) via systemd user service at `https://127.0.0.1:17670`; Snap (`OPENSHELL_INSTALL_METHOD=snap`, system service, requires Docker Engine — not the Docker snap). (installation page)
- **Gateway ports:** built-in default primary listener `127.0.0.1:17670`; configurable `bind_address` (example `0.0.0.0:8080`) with optional `health_bind_address` (8081) and `metrics_bind_address` (9090); Kubernetes Service port 8080 (`kubectl port-forward svc/openshell 8080:8080`). https://docs.nvidia.com/openshell/latest/how-it-works/gateways/configuration.md ; https://docs.nvidia.com/openshell/latest/kubernetes/setup.md
- **Helm:** `helm upgrade --install openshell oci://ghcr.io/nvidia/openshell/helm-chart --version <version>`; StatefulSet default (SQLite) / Deployment for external Postgres; requires k8s-sigs **Agent Sandbox controller** CRDs and a CNI that actually enforces NetworkPolicy; cert-manager and Gateway API optional; split gateway/workspace charts; K8s Secrets credential driver. https://docs.nvidia.com/openshell/latest/kubernetes/setup.md
- **Container:** `ghcr.io/nvidia/openshell/gateway:latest` via docker run/compose; supervisor & sandbox-runtime images also published. https://docs.nvidia.com/openshell/latest/about/support-matrix.md ; container-deployment page linked from installation page.

## 12. Sandbox Lifecycle
- **Create:** `openshell sandbox create --name X --from <image|rootfs.tar> [--policy …] [--provider …] [--env …] [--upload src:dst] [--expose N] [--detach] [--restart-policy …] [--no-keep] [--approval-mode auto] -- <cmd>` (trailing cmd = canonical main process; exit 0 → `Completed`, nonzero → `Error/MainProcessFailed`; no cmd → login shell). Phases: Provisioning → Ready → Stopping/Stopped/Starting → Completed/Error → Deleting; image-prep deadline 1800 s default; admission-repair window 300 s. https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview.md
- **Ephemeral:** `--no-keep` drains output, captures result, deletes sandbox after exit (combinable with `--detach`; not with `--upload` or `--expose`). **Restart policies:** `never` (default) / `on-failure` / `always`; backoff 1 s doubling to 3 min, reset after 10 s running; replacement = new supervisor + main process, same identity/config. (same page)
- **Exec:** `openshell sandbox exec -n X [--tty|--no-tty] [--env] [--timeout] [--workdir] [--no-login-shell] -- cmd`; exit code propagated; 4 MiB pending-stdin limit. **Connect:** `openshell sandbox connect` (SSH attach to canonical process, replays ≤1 MiB, auto-reattach/recovery, `--editor vscode|cursor`). **Upload/Download:** `openshell sandbox upload/download` (gitignore-aware, symlink-preserving, downloads confined to working dir). **Stop/Start:** idempotent, retains policy/providers/settings/persistent workspace; **Delete:** stops processes, purges credentials. Also port forwarding (`openshell forward start/list/stop`, `--forward`), service exposure (`openshell service expose`, `*.openshell.localhost` URLs, bearer-passthrough), per-sandbox SSH host keys + `SHA256:` fingerprint. (same page)

## 13. Telemetry
- Anonymous, operational categories/counts only (sandbox lifecycle outcomes, provider profile buckets, policy decision counts, denial categories); explicitly **does not** collect sandbox names/IDs, hostnames, file paths, binary paths, prompts, credentials, provider or model names, or user content. Biweekly published aggregate reports in `telemetry/`. Opt-out: `OPENSHELL_TELEMETRY_ENABLED=false` (gateway) or `server.telemetryEnabled=false` (Helm); or compile out entirely (`--no-default-features --features defaults-without-telemetry`). https://docs.nvidia.com/openshell/latest/observability/telemetry.md ; https://github.com/NVIDIA/OpenShell

## 14. Notable UNKNOWNs / Caveats
- Windows-native (MXC driver) maturity beyond "WSL 2 experimental" is not stated in the support matrix; MXC appears only in Cargo features/audit docs. https://docs.nvidia.com/openshell/latest/observability/telemetry.md
- Prover does not model GraphQL/MCP/WebSocket/JSON-RPC rules (returns `unsupported`), and its guarantees apply only to the modeled policy subset. https://docs.nvidia.com/openshell/latest/how-it-works/policies/prover.md
- Exposed services share the gateway listener/TLS in this release; bearer-passthrough delivers the caller's credential to the sandbox service. https://docs.nvidia.com/openshell/latest/how-it-works/sandboxes/overview.md
- Supervisor/sandbox container log files are tmpfs/emptyDir — not durable; OCSF collection is best-effort, not a complete audit guarantee. https://docs.nvidia.com/openshell/latest/observability.md
