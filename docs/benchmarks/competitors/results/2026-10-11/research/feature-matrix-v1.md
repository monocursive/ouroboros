# Ouroboros Jail vs Greywall vs NVIDIA OpenShell vs Microsoft MXC — Feature Matrix

Date: 2026-10-11. Versions compared: **ouro-jail 0.1.0-rc.1** (+ `ouro-vm` 0.1.0-preview.1, both built from source revision `c364e3cb` for measurement), **Greywall 0.3.7** + Greyproxy 0.4.5, **NVIDIA OpenShell 0.1.3**, **Microsoft MXC 1.0.0**.

Sources: the four per-product research reports in `results/2026-10-11/research/` (each claim cited there). This matrix condenses them; measurement-derived rows cite the benchmark records beside it.

## Summary positioning

| | Ouroboros Jail | Greywall (+greyproxy) | NVIDIA OpenShell | Microsoft MXC |
|---|---|---|---|---|
| **Shape** | Single Rust binary wrapping one command | Go CLI wrapping one command + companion proxy service | Gateway (control plane) + container/VM sandbox fleet | SDK + executor binaries embedded in your app |
| **Primary user** | Operator running an agent/CLI on their host | Developer running coding agents locally | Platform/team running fleets of agents | Application executing untrusted model output |
| **License** | MIT | greywall Apache-2.0 / greyproxy MIT | Apache-2.0 | MIT |
| **First-party agent support** | 14 embedded launch profiles (opencode, claude, codex, …), experimental | 13+ agent profiles (Claude Code, Codex, Cursor, OpenCode, …) + `--inject` credentials | Providers for claude-code/codex/OpenRouter + skills package + MCP docs server | None first-party (powers GitHub Copilot local sandboxing; Hyperlight `agent` runtime) |

## Platforms and isolation class

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Linux x86_64 | ✅ namespaces+seccomp+ptrace (bubblewrap ≥0.10) | ✅ bubblewrap+Landlock+seccomp+eBPF+TUN | ✅ container (Docker/Podman/K8s) or MicroVM, Landlock+seccomp inside | ✅ bubblewrap (default), LXC, microvm, hyperlight |
| Linux arm64 | ✅ (Pi 4/Debian 13 recorded) | ✅ (arm64 release) | ✅ (arm64 artifacts) | ✅ (arm64 executor) |
| macOS arm64 | ❌ native execution refused (inspection only); `ouro-vm` disposable offline Linux VM preview (macOS 27+) | ⚠️ Seatbelt build exists but **v0.3.7 fails** (`sandbox-exec: unsupported syntax: kleene star` — reproduced 2026-10-11 on macOS 27.0.1) | ✅ Docker Desktop + Hypervisor.framework | ✅ Seatbelt (macOS 15+) |
| macOS x86_64 | ❌ | ⚠️ (build ships; same Seatbelt path) | ❌ (Apple Silicon only) | ✅ (seatbelt target) |
| Windows | ❌ | ❌ | ⚠️ WSL2 experimental | ✅ first-class (ProcessContainer default, Windows Sandbox, WSLC, IsolationSession) |
| Isolation class | Namespace wrapper (process tree, no VM/container) | Namespace wrapper | Container/VM boundary + in-sandbox kernel policy | Process sandbox → VM spectrum per backend |

## Filesystem policy

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Default | Closed view; only declared roots bound | Deny-by-default reads+writes (CWD visible) | Default-deny Landlock policy (workdir RW, system RO) | Deny-by-default RO baseline; empty grants |
| Grants | `--ro` / `--rw` by resolved object, not path spelling | allowRead/allowWrite (+`--allow-path`) | Landlock paths in YAML policy | readonlyPaths/readwritePaths |
| Denials | `--deny-read`; policy_widening refusals for pseudo-fs grants | denyRead/denyWrite (deny wins) | not-allowed = denied | deniedPaths (backend-dependent; rejected by Nanvix/IsolationSession) |
| Repo/git protection | `tool` protects existing `.git`/`.ouroboros`; `agent` blocks `.git/hooks`+config writes | Dangerous-file protection: `.git/hooks/*`, shell rc files | `/.openshell` mandatory baseline | — |
| Project narrowing | `ouro.toml` can only narrow policy | `extends` templates | global > saved > image policy | — |

## Network policy

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Default | `tool`/`build`: none; `agent`: proxy-only | All via SOCKS5 proxy; no proxy = blocked | Default policy: no rules = all egress denied | egress/ingress default deny |
| Hostname rules | ✅ `--allow-host host:443`, wildcards, IDNA pinning; SNI/Host origin binding at bridge | ✅ greyproxy glob rules by destination+port+container; pending-request approval | ✅ per-binary destinations + REST/GraphQL/MCP/WS request rules, hot-reload | ❌ **no hostname rules anywhere in v1** (CIDR+port only; DNS names rejected) |
| Credential protection | Vault mode: placeholders, substitution at bridge, per-attempt CA for TLS lane; staged copy/bind modes | Placeholder tokens; greyproxy substitutes at HTTP layer (`--inject`/`--secret`); no body/non-HTTP substitution | Providers: placeholders in workload, real creds only at approved endpoints (mismatch = error); OAuth2/AWS SigV4 refresh | ❌ none (environment passthrough only) |
| UDP | ❌ unsupported | Via TUN on Linux | Per runtime fence | Bubblewrap: tcp/udp/icmp via slirp4netns |
| Local/loopback | Forbidden-address table unless granted | allowLocalOutbound flag (macOS) | Loopback via SO_BINDTODEVICE | ingress.hostLoopback toggle |

## Resource ceilings

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Wall time | ✅ supervisor CLOCK_BOOTTIME | ❌ none | ✅ image-prep deadline; exec `--timeout`; sandbox phases | ✅ `process.timeout` |
| PIDs | ✅ cgroup pids.max (required if explicit) | ❌ | ❌ (not exposed) | ❌ |
| Memory | ✅ memory.max + separate swap.max | ❌ | ✅ `--memory` (Docker/Podman/K8s; VM accepts but ignores) | ⚠️ WSLC-only memoryMb; Nanvix fixed 256 MB |
| CPU | ✅ cpu.max bandwidth | ❌ | ✅ `--cpu` (+GPU CDI/NFG) | ⚠️ WSLC-only cpuCount |
| Disk/inodes | ✅ storage+inodes quotas (verified) | ❌ | ❌ | ❌ |
| Enforcement posture | Every explicit limit required or refuse | n/a | Runtime limits | Timeout enforced; sizing backend-specific |

## Observation and audit

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Per-run record | `jail.json` receipt (phase/outcome/coverage/gaps) + `trace.ndjson`; strict evidence stops run on loss | Proxy decision logs + transactions in SQLite; dashboard | Logs (CLI/TUI), OCSF v1.8.0 JSON export, OTLP | Local JSON-lines audit records (exit/timeout/kill, policy hash, correlation id) |
| Syscall/exec observation | ptrace observer, closed set, per-class coverage with explicit gaps | eBPF violation monitoring (needs CAP_BPF) | Process events in OCSF class 1007 | Windows ETW learning mode (denials capture) |
| Cross-run tooling | `ouro-ledger` store: admission, verify, signed bundles, tail -f | Dashboard history, REST API | Gateway state, `sandbox list/logs`, TUI | — |
| Sensitive-data handling | No paths/headers/tokens logged; receipts digest-only | Header redaction at capture; LLM conversation tracking (dissectors) | Telemetry excludes names/paths/prompts | Verbose artifacts redact paths/usernames |

## Policy verification and learning

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Learning | `learn`: evidence-derived exact RO paths + denied destinations; interactive adopt | `--learning` (strace/eslogger) → learned profile auto-load | Advisor: agent proposes scoped network rules via policy.local API; mechanistic mapper from denials; auto-approve gated by prover | Windows `--audit` / captureDenials → regenerated policy artifacts |
| Formal verification | ❌ | ❌ | ✅ SMT prover (boundary check + proposal risk) over modeled domains | ❌ |
| Command deny-rules | ✅ exec-gate deny/forbid globs (accident filter) | ✅ prefix lists surviving pipes/chains/nested shells | ✅ process section + per-binary network rules | ❌ (documented: no tool allowlist concept) |

## Deployment footprint

| | Ouroboros Jail | Greywall | OpenShell | MXC |
|---|---|---|---|---|
| Install | 1 binary (~3.5 MB tarball) + distro bubblewrap; no daemon/sudo | 2 binaries (~7 MB + ~8 MB) + bwrap + socat (Linux); systemd/launchd service for proxy | deb/rpm/brew/snap/Helm + Docker 28+/Podman 5/K8s 1.29+; gateway service on 127.0.0.1:17670 | SDK packages (Rust/.NET/Node) or executor binaries (~5-12 MB); no daemon on Linux/macOS |
| Privileges needed | None (unprivileged user namespaces + delegated cgroups; linger) | None (TUN needs dev access else env-var fallback) | Docker group / K8s cluster admin | None on Linux/macOS; Windows uses OS primitives |
| Per-command overhead (measured 2026-10-11, VPS) | noop +130 ms (obs on) | noop +1596 ms | create+exec+delete ≈ seconds (container class) | noop +18 ms |
| Work-phase cost (measured) | file ops +54–128 % (obs on) | ≈ native | native inside sandbox | ≈ native (Linux); macOS python/git 50–170× (seatbelt) |

## Notable gaps (documented)

- **Ouroboros:** native macOS execution refused (by design until lifetime gate closes); observation multiplies file-heavy work; `--observe off` cannot confirm very short execs (`exec_unconfirmed`); no Windows.
- **Greywall:** no resource limits (explicitly out of scope); macOS release currently broken (kleene-star); not for hostile code; proxy API unauthenticated (localhost-only).
- **OpenShell:** container/VM class (heavier per-command lifecycle); prover limited to modeled domains; supervisor logs not durable; VM driver ignores cpu/memory flags.
- **MXC:** no hostname network rules (CIDR only) — agent API access needs caller-resolved IPs or an external proxy; no cross-backend CPU/mem limits; lifecycle persistence Windows-only; detached descendants survive wrapper exit on macOS seatbelt (measured); host Unix sockets reachable from bubblewrap sandbox (measured).
