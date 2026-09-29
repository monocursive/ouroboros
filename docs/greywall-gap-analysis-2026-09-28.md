# Greywall gap analysis and plan — 2026-09-28

Companion to [the benchmark](benchmark-2026-09-28-greywall.md). Objective:
close every gap where greywall 0.3.7 leads, keep the gaps where we lead,
and make the comparison unambiguous.

## Where we already mog them (defend, don't redo)

- **Agents run at all on a stock unprivileged host**: their network layer
  needs TUN privileges; every mode fails closed. Our bridge is userspace.
  A01 end-to-end: 8.05 s (+4.8 %) vs their "Cannot connect to API".
- **Speed**: ~124–147 ms per invocation vs ~1.6 s on the same host
  (~11x); our observer adds ~nothing.
- **Syscall posture**: flat EPERM on the escape class; their seccomp let
  `unshare(CLONE_NEWUSER)`, `ptrace(TRACEME)` succeed and `mount`,
  `clone3`, `process_vm_*`, `pidfd_getfd`, `io_uring`, `bpf`, `setns`
  reach the kernel.
- **Threat model**: we are specified for hostile containment with five
  public audits; their own security-model doc disclaims hostile
  containment, ships no resource limits and no per-run attestation.
- **Same-uid hardening**: our guard system is designed; their own binary
  survives rename only by accident of the Landlock wrapper mount, and
  other binaries in a granted dir are replaceable (demonstrated).

## Where they lead (the gaps, ranked by adoption impact)

1. **macOS execution** — they run on macOS (Seatbelt); we inspect only
   and refuse execution with 125. Most agent users are on macOS. The
   single biggest gap.
2. **Install friction** — brew tap, `curl | sh`, goreleaser releases;
   we are clone-and-cargo. Time-to-first-sandboxed-agent is minutes for
   them, an afternoon for us.
3. **Agent breadth** — 14 agent profiles + toolchain profiles, applied
   with one interactive prompt; we ship 3 experimental examples the
   binary never reads.
4. **Learning mode** — `--learning` traces a run and emits a
   least-privilege profile. We have no generator — despite already
   recording everything it would need.
5. **Live view** — greyproxy dashboard + `greywatch`; we have receipts
   (better artifacts) but no live surface.
6. **Credential vaulting** — placeholder env vars with the proxy
   substituting real secrets at the HTTP layer (MITM CA); our staging
   puts real credential bytes inside the sandbox (`copy_rw`/`bind_ro`).
7. **Proxy-unaware tools** — TUN transparency (where privileged); our
   bridge speaks HTTP CONNECT only, so env-honoring tools only.
8. **Command deny-rules** — `rm -rf /`, `git push --force` blocking.
   Optics, but users ask for it.

## The plan

### Phase 1 — win the eval (highest impact per week)

1. **macOS execution lane.** Map the policy snapshot to a
   `sandbox-exec` profile: rw/ro grants → `(allow-read*|allow-write*
   subpath)`, no-network by omission, scratch/tmpfs via profile. No
   closed-set observer on macOS in v1 of the lane — the receipt marks
   observation `unsupported` honestly (the contracts already carry that
   vocabulary; the refusal lane at exit 125 becomes the execution
   lane). This is a milestone, not a task — but it converts the
   majority platform from "not supported" to "supported with honest
   evidence labels".
2. **`ouro-jail learn`.** Run the target under `tool` with observation
   on; consume the attempt's own event stream (`open`, `exec`,
   `rename`, `unlink`, `truncate`, `connect`, `proxy.net` — already in
   the closed set and the receipt); emit a proposed narrowing launch
   profile (ro grants for out-of-workspace reads, rw for writes,
   `network.allow` for observed hosts, argv for the exec) plus a diff
   against the current policy. It is a transformer over data we already
   attest — and it beats their Landlock trace on the one axis we care
   about: the proposal cites a receipt digest.
3. **Ship validated profiles.** Bundle launch profiles for the agent
   zoo (claude, codex, cursor, aider, goose, gemini, opencode, amp,
   cline, copilot, kilo, auggie, droid, pi) and the toolchains (node,
   python, go, rust, java, ruby, containers, scm) — each with a
   `doctor --launch` check and a recorded compatibility row
   (agent-compatibility.md). Their profiles are registry entries; ours
   become receipts.
4. **Distribution.** cargo-dist (or a release workflow) producing
   per-target tarballs, checksums, an install.sh, and a brew tap.
   CI already exists (`contracts`, `rust`, `conformance`); add
   `release`. One afternoon of workflow work against a whole adoption
   moat.

### Phase 2 — match the features that matter

5. **SOCKS5 listener in the bridge.** `socks5h://127.0.0.1:3129` in
   the child netns: the bridge resolves, checks the allowlist by name,
   connects, and relays. Proxy-unaware tools work (no TUN, no
   privileges); DNS never leaves the supervisor; mediation is
   unaffected (AF_INET connect already passes through). Also the
   natural place to tighten C1 (below), since the tunnel target is
   checked at connect time.
6. **Credential vaulting.** Placeholder env vars plus bridge-side
   substitution (our own per-attempt CA, like their NODE_EXTRA_CA_CERTS
   approach) so the child never sees real tokens. Big-ticket: CA
   generation, trust-store plumbing, and a receipt that says "credential
   X: vaulted, never staged". Until then, `bind_ro` + the digest-only
   receipt is the honest interim.
7. **`ouro-jail tail`.** A live view over the trace journal (the events
   exist; the control/trace-fd plumbing exists). Receipts remain the
   artifact; this is presentation.
8. **Opt-in command deny-rules.** argv patterns enforced at the exec
   gate — we observe every exec already; a refusal before exec with the
   pattern named in the receipt. Small, on-machinery, and it removes a
   checklist line.

### Phase 3 — close our own public gaps first

They will read our audit reports; every open finding is their rebuttal.
Land the fifth-audit fix order before marketing the comparison:

9. **C1** — origin-bound allowlist (first-bytes SNI/Host inspection on
   tunnels, or explicit-port entries with :80 closed) so "allowed
   hosts" means origins, not CDN edges.
10. **C3** — isolation guards + fd-exec for the supervisor and bwrap
    binaries. **C4** — compat `clone3` refusal. **C2** — model `none`'s
    real visibility. (Details and fix directions are in
    [the fifth audit](security-audit-2026-09-27-2.md).)

### Tell the story

11. Publish the benchmark (scripts are in the repo and on the reference
    host; every number is reproducible), the audit trail (five passes,
    every fix verified live) against their "not a strong isolation
    boundary" disclaimer, and a compatibility table backed by receipts.
    Their 304 stars are a head start, not a moat.

## Mog-metrics

| Metric | Them (measured) | Us (measured) | Target |
|---|---|---|---|
| Per-invocation cost, `true` | 1 612 ms | 124 ms | keep ≥10x |
| Agent e2e on stock host | fails (no network) | 8.05 s (+4.8 %) | 100 % of profiled agents |
| Escape-class syscalls | reach kernel / succeed | flat EPERM | keep |
| Resource ceilings | none | pids/mem/cpu/wall | keep |
| Per-run attestation | logs | receipts + gaps | keep |
| Platforms that execute | Linux + macOS | Linux | macOS lane |
| Time-to-first-agent | minutes | hours | < 10 min |
| Profiled agents | 14 | 3 (examples) | 14, receipt-validated |
| Learning mode | Landlock trace | — | receipt-backed generator |
| Public security audits | 0 | 5 | keep adding |
