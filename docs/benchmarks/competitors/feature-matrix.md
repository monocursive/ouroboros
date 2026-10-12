# Feature comparison — audited scope

Products tested: Ouro Jail source revision `c364e3cb3678eb9120901f71bf3881d85e3c4911` (CLI version `0.1.0`, Rust 1.98.1 release build), Greywall 0.3.7 with Greyproxy 0.4.5, OpenShell 0.1.3, and MXC SDK/executors 1.0.0. Date: 2026-10-11. Exact executable hashes accompany each dataset.

This table distinguishes documented capabilities from configured lanes. It is not a security certification or release-readiness check. Measured availability, resource and canary results are linked in the report. The unaudited original is retained in `results/2026-10-11/research/feature-matrix-v1.md`.

| Capability | Ouro Jail | Greywall + Greyproxy | OpenShell | MXC |
|---|---|---|---|---|
| Tested execution model | Linux process tree: namespaces, seccomp, ptrace observation | Linux namespace wrapper plus proxy; macOS Seatbelt | Docker workloads and separate supervisor/gateway; Mac Docker uses OrbStack Linux VM | Linux bubblewrap; macOS Seatbelt |
| Linux x86/ARM | VPS/Pi with recorded provisioning | VPS/Pi; active layers depend on capabilities | VPS/Mac Docker execution works; Pi provisioning fails before workload execution | Both executors tested |
| macOS | Native refused by design. Offline disposable ouro-vm preview measured separately; no online agent lane | 0.3.7 refuses tested tasks on macOS 27.0.1: unsupported syntax, kleene star | All54 small-task and9 workflow runs pass through its native gateway and Linux ARM64 Docker on OrbStack | Claude/OpenCode pass; Codex fails CFPreferences initialization |
| Other backends | No Windows | No Windows | Podman, Kubernetes, MicroVM documented; untested | Several Windows and other Linux backends documented; untested |
| Filesystem | RO/RW roots, deny-read; tool protects existing git metadata, agent protects hooks/config | Default deny, grants/denies, dangerous-file protection | Landlock path policy; startup-fixed filesystem rules; default best_effort posture | RO/RW/denied paths; backend-specific enforcement |
| Network | Tool offline; agent proxy-only with destination grants/origin checks | Wrapper confines egress to proxy; Greyproxy decides hostname/port | Default deny; per-binary destinations and optional request rules; provider contributes rules | Native Linux CIDR/port rules. **Documented external proxy mode works**; proxy supplies hostname filtering |
| Credential options | Staged files/environment; optional vault at exact origins | Automatic environment placeholders through Greyproxy | Providers, endpoint binding, gateway refresh | Caller-managed files/environment |
| Credential mode timed | API key in environment, staged Codex auth; vault not timed | API-key substitution on; staged Codex file | Anthropic provider; Codex provider + NVIDIA bootstrap and non-secret account routing hint | API key in environment, staged Codex file |
| Wall time | Supervisor ceiling; profile defaults | No built-in resource timeout documented; outer benchmark guard | Exec timeout; distinct lifecycle/image-prep deadlines | process.timeout in ms |
| PIDs | cgroup ceiling; explicit request required or refusal | No ceiling interface documented | No portable PID CLI ceiling found | No common ceiling in tested backends |
| Memory/swap | Explicit cgroup ceilings or refusal; Pi lacks memory controller | No ceiling interface documented | Docker/Podman/Kubernetes memory flag; VM enforcement differs, untested | No shared limit for bubblewrap/Seatbelt; other backends have sizing |
| CPU | cgroup bandwidth percentage; 100 = one core, not CPU-seconds | No ceiling interface documented | Docker runtime CPU limit flag | No shared limit in tested backends |
| Storage/inodes | Requires bounded tmpfs or verified user hard quota; unbounded workspace must refuse explicit cap | No quota interface documented | No common interface found | No common interface found |
| Default resource posture | Agent wall 2h, preferred pids 512; **no automatic memory/CPU/storage/inode caps** | No product ceiling | Runtime defaults unless requested | Timeout if configured; backend defaults vary |
| Evidence | Receipt, coverage/gaps, lifetime settlement, journal; strict mode timed | Proxy decisions/transactions/dashboard; privileged eBPF mode was not enabled in these user runs | Gateway/supervisor logs; optional OCSF/OTLP, different durability | Executor diagnostics/local audit; Windows ETW not exercised |
| Policy authoring | Evidence-derived narrowing proposal | Trace learning with relaxed filesystem and platform prerequisites | Network proposals/advisor; SMT checks over modeled domains | Backend-specific audit/learning, chiefly Windows |
| Persistence | Per-command attempt; separate ledger documented, untested here | Per-command wrapper, persistent proxy | Retained sandbox: exec/stop/start/delete | Selected Windows backends; tested Linux/macOS transient |
| Descendant settlement probe | VPS/Pi heartbeat stops after root exit; successful receipts require empty tree | Linux heartbeat stops; Mac unavailable | Persistence is explicit; command return and sandbox deletion are separate lifecycles | Linux heartbeat stops; Mac heartbeat continues after wrapper return while still subject to Seatbelt |
| License | MIT | Apache-2.0 / MIT | Apache-2.0 | MIT |

Native wrappers use writable workspaces, RO executable installations, private agent state, and default-deny egress with required provider destinations. Offline safety probes grant every wrapper the same RO private canary directory and deny its child directory. Ouro's file-denial variant fails during setup; Greywall's explicit parent denyWrite re-exposes a denied child in the tested configuration, with a minimal-rule followup recorded separately. Connecting to an explicitly visible Unix socket is not an ungranted path escape. The unequal original socket probe remains a pilot.

Mac Docker/OpenShell matched resource probes enforce CPU500m and kill a touched320MiB allocation with128MiB memory requested. Docker supplies an additional128MiB swap by default; inspect/cgroup evidence verifies the OpenShell configuration. A192MiB allocation within that combined budget succeeds as expected. The initial Docker swap=0 variant is retained as a diagnostic, not a failed OpenShell ceiling.

The Mac Codex failure also reproduces with MXC's documented `keychainAccess` opt-in. Read-only workspace policy in OpenShell is checked separately with a writable Docker positive control; its first probe omitted runtime system read grants and is retained as an invalid setup pilot.

The VPS has recorded deployment overrides: earlier setup disabled its unprivileged-user-namespace AppArmor restriction, and a byte-identical distro bubblewrap copy avoids a pathname-attached profile denying network setup capabilities. Every final wrapper can use that copy. The Pi's Ouro network lane requires an exact-kernel Unix diagnostics module provisioned for this benchmark. These are not untouched-distribution results.

OpenShell Codex uses NVIDIA's versioned bootstrap: externally managed access tokens and a non-secret identity JWT. CLI 0.159.2 also matches account IDs against routing discovery, so the launcher passes its account identifier as ordinary metadata; the access token remains a provider handle. Stock opaque-ID attempts are retained. Product sources were not patched.

Sources:

- [Ouro guide](../../guide.md), [jail v1 operating rules](../../specs/jail-v1/operating.md), measured source revision.
- [Greywall 0.3.7 docs](https://github.com/GreyhavenHQ/greywall/tree/v0.3.7/docs), [Greyproxy 0.4.5 source](https://github.com/GreyhavenHQ/greyproxy/tree/v0.4.5).
- [OpenShell architecture](https://docs.nvidia.com/openshell/latest/about/architecture), [policies](https://docs.nvidia.com/openshell/latest/how-it-works/policies/overview), [provider profiles](https://docs.nvidia.com/openshell/latest/how-it-works/providers/profiles), [v0.1.3 Codex bootstrap](https://github.com/NVIDIA/OpenShell/blob/v0.1.3/examples/codex-app-server/start-codex-app-server).
- [MXC schema](https://github.com/microsoft/mxc/blob/main/docs/schema.md), [bubblewrap external proxy](https://github.com/microsoft/mxc/blob/main/docs/backends/bwrap/bubblewrap-backend.md), [Seatbelt](https://github.com/microsoft/mxc/blob/main/docs/backends/seatbelt/seatbelt-backend.md).

Detailed source notes are preserved under `results/2026-10-11/research/`. Untested backends, resource interfaces, learning and formal checks are documentation-derived; agent passes do not validate every feature.

Pi OpenShell does not reach workload execution with its default thin image or the agent image. Its resource/filesystem probes are unavailable. Docker on Pi ignores the requested memory cap with a warning, while Ouro explicitly refuses it. The observed OpenShell startup cause remains unknown; a Docker-event diagnostic records workload exit1 and subsequent supervisor cleanup137 with no OOM event.
