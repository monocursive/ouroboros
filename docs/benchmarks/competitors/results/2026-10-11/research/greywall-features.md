# Greywall Feature Summary (for benchmark feature matrix)

**Product**: Greywall (+ companion greyproxy) — container-free, deny-by-default sandbox for AI coding agents
**Vendor**: GreyhavenHQ · **Language**: Go (site badge: Go 1.25) · **License**: greywall Apache-2.0; greyproxy MIT (fork of GOST)
**Latest versions**: greywall v0.3.7 (published 2026-06-01, changelog: NixOS support #93); greyproxy v0.4.5 (published 2026-06-02). Note: greywall.io release badge still shows v0.3.1 (stale); GitHub 'Latest' is v0.3.7.

## 1. Platform support

| Aspect | Linux | macOS |
|---|---|---|
| Sandbox engine | bubblewrap (`bwrap --unshare-net`) | sandbox-exec (Seatbelt, dynamically generated profiles) |
| Syscall filtering | seccomp BPF | via Seatbelt |
| Filesystem ACL | Landlock (kernel 5.13+) + bubblewrap mounts | Seatbelt |
| Violation monitoring | eBPF (needs CAP_BPF/root; grantable via setcap) | Seatbelt denial logs |
| Transparent network capture | TUN device + tun2socks → SOCKS5/HTTP proxy; socat DNS bridge → DNS proxy | ❌ none — routes via HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars + Seatbelt localhost exception; proxy-ignoring apps fail hard (no silent bypass) |
| Network isolation | network namespace (`--unshare-net`) | N/A (shares host stack) |
| D-Bus isolation | yes (blocks session-bus escape: GVFS, gnome-keyring, Flatpak portals) | n/a |
| Learning tracer | strace (needs ptrace) | eslogger / Endpoint Security (tracer runs under sudo; command as user) |
| External deps | bubblewrap, socat (required); xdg-dbus-proxy, libsecret-tools (optional) | none (sandbox-exec, eslogger ship with macOS) |

"Five security layers on Linux": Bubblewrap, Landlock, Seccomp, eBPF, TUN capture. Features degrade gracefully when kernel/permissions lack support (`greywall --linux-features`). Windows: not supported. In Docker: partial — falls back to proxy env vars unless `--cap-add=NET_ADMIN`. If TUN unavailable, falls back to HTTP_PROXY/HTTPS_PROXY/ALL_PROXY inside the namespace.
Sources: https://github.com/GreyhavenHQ/greywall (README), https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/platform-support.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/architecture.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/faq.md

## 2. Filesystem policy

- **Default deny**: deny-by-default reads AND writes; without config only CWD (+ system paths) is accessible. `filesystem.defaultDenyRead` defaults true; set false to opt out of deny-by-default reads.
- **Config fields** (`~/.config/greywall/greywall.json` Linux / `~/Library/Application Support/greywall/greywall.json` macOS; JSONC): `allowRead`, `denyRead` (overrides allowRead), `allowWrite`, `denyWrite` (takes precedence over allowWrite), `allowGitConfig`.
- **One-shot grants**: `--allow-path <path>` (read+write, session-only, nothing persisted, repeatable, dir or file) and `--allow-read-path <path>` (read-only); compose on top of profiles.
- **Unconditional protections**: "dangerous file protection" blocks writes regardless of config to `.git/hooks/*`, shell startup files (`.zshrc`, `.bashrc`, …), some editor config dirs.
- Config inheritance: `extends` templates or files (append+dedupe slices, OR booleans, override-wins ints, chain depth 10, cycle detection).
Sources: https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/configuration.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/cli-reference.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/agents.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/faq.md

## 3. Network policy (greyproxy)

- **Delegation model**: greywall never inspects destinations; all allow/deny decisions live in the external proxy (default greyproxy at `socks5://localhost:43052`; any SOCKS5 proxy works via `--proxy`; no proxy ⇒ network fully blocked).
- **Proxy services** (single greyproxy binary): HTTP CONNECT :43051, SOCKS5 :43052, DNS :43053, dashboard+REST API :43080. Multi-protocol with forwarding chains, DNS caching + hostname enrichment (GOST-derived).
- **Rule engine**: SQLite-persisted rules with glob `container_pattern` (source process/container), `destination_pattern` (hostname glob, case-insensitive), `port_pattern`, `action` allow/deny, `notes`, `expires_at` (RFC 3339). Stored rules survive restarts and apply immediately.
- **Rule source layers / priority**: Global (dashboard/API, persistent) > Session (pushed by greywall at session creation; auto-deleted when session ends/expires/superseded; TTL extended on heartbeat; pinned to the session's exact container; only match while that session is current — prevents stale allow-lists leaking into new sessions) > Built-in (loopback defaults 127.0.0.1/::1/localhost). Within a layer: most-specific pattern wins; tie → deny wins; **no match → pending request** (never silently dropped). Global deny always overrides session rules (org hard-denylists).
- **Pending-request approval workflow**: unmatched connections queue in dashboard "Pending" tab (destination, port, source, timestamp) with Allow/Deny buttons that create persistent rules; API: `GET /api/pending`, `POST /api/pending/:id/allow|deny`, `bulk-allow`, `bulk-dismiss`. Recommended workflow: start with no allow rules → run agent → approve legitimate destinations → export rules via `GET /api/rules` for repo commit.
- **Other network knobs**: `-p/--port` expose inbound ports (dev servers); `-f/--forward` forward host localhost ports into sandbox (socat bridge Linux / Seatbelt allow macOS); `allowLocalOutbound` (macOS only), `allowUnixSockets`, `allowLocalBinding`; SSH host/command policy (see §5); `--no-network-rules` skips pushing profile network rules.
- **Platform caveat**: on macOS only env-var-honoring apps are proxied (others hit Seatbelt denial); Linux TUN capture is transparent for all binaries.
Sources: https://raw.githubusercontent.com/GreyhavenHQ/greyproxy/main/docs/rules.md, https://github.com/GreyhavenHQ/greyproxy (README ports/features), https://raw.githubusercontent.com/GreyhavenHQ/greyproxy/main/docs/api.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/architecture.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/cli-reference.md

## 4. Credential substitution

- **Mechanism**: at startup greywall auto-detects credential-shaped env vars (known names e.g. `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`; suffixes `_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`), replaces values with opaque placeholders `greyproxy:credential:v1:gw-<id>:<digest>`, registers placeholder→secret mapping with greyproxy's sessions API, rewrites the sandbox environment; greyproxy substitutes real values back **at the HTTP layer** (request headers and URL query params) before forwarding upstream; session deleted on sandbox exit. Requires greyproxy ≥ v0.3.4. No config needed for heuristics.
- **Flags**: `--secret VAR` (force-treat as credential), `--inject LABEL` (pull dashboard-stored credential into sandbox env as placeholder — value never exists in your shell), `--ignore-secret VAR`, `--no-credential-protection`; config equivalents `credentials.secrets|inject|ignore`.
- **Session lifecycle**: TTL 15 min default, 60 s heartbeat, auto re-registration after proxy restart; active sessions visible in dashboard (Settings → Credentials → Active Sessions).
- **.env files**: Linux full support via bubblewrap `--ro-bind` mount of rewritten file; macOS cannot redirect reads ⇒ `.env` denied entirely while substitution active (workaround: `--inject`).
- **Limits**: no substitution in request bodies or non-HTTP protocols (raw TCP, post-upgrade WebSocket frames). Sandbox denies read access to greyproxy's `session.key` and `ca-key.pem` on both platforms.
Sources: https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/credential-protection.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/configuration.md

## 5. Command deny rules

- `command.deny` / `command.allow` prefix lists; `useDefaults` (default true) blocks: shutdown/reboot/halt/poweroff/init, insmod/rmmod/modprobe/kexec, mkfs*/fdisk/parted/`dd if=`, `docker run -v /:/` and `docker run --privileged`, chroot/unshare/nsenter.
- **Detection scope**: direct commands, chains (`&&`, `;`), pipelines (`|`), shell invocations (`bash -c`, `sh -lc`) — rules apply inside pipes, chains, nested shells.
- **SSH sub-policy** (default allowlist mode): `allowedHosts`/`deniedHosts` wildcard patterns (`*.example.com`, `prod-*.us-east.*`), `allowedCommands`/`deniedCommands`, `allowAllCommands` (denylist mode), `inheritDeny` (apply global+default denies to SSH); documented 8-step evaluation order; on macOS SSH routed through proxy via `GIT_SSH_COMMAND`.
- Also: child processes inherit the sandbox; `LD_PRELOAD`/`LD_LIBRARY_PATH` stripped (environment sanitization); `GREYWALL_SANDBOX=1` marker.
Sources: https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/configuration.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/faq.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/cli-reference.md

## 6. Learning mode

- `greywall --learning -- <cmd>`: relaxed filesystem + tracer (Linux strace on openat/creat/mkdir/…; macOS eslogger streaming open/create/write/unlink/truncate/rename/link/fork for the process tree); network still sandboxed.
- On exit: parses trace, filters system paths/CWD/sensitive paths, collapses paths into minimal directory sets (~/.cache, ~/.config, ~/.local/{share,state,lib}, ~/.data grouping; sub-path dedupe; never collapses direct-$HOME to `~/`), emits JSONC template with `allowRead`/`allowWrite`/`denyWrite`/`denyRead` to `~/.config/greywall/learned/<command>.json`; auto-loads on next plain run; `--profile <name>` forces a specific profile; `greywall profiles list|show|edit` manage both built-in and learned.
- Sensitive paths (SSH keys, `~/.gnupg/**`, `.env`, `.env.*`) never land in allow lists even if accessed; shell startup files always in denyWrite. Documented caveats: heuristic (single-session extrapolation), relaxed FS during learning (don't use with untrusted code), ptrace/sudo requirements, possible hangs on long-lived children.
Source: https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/learning-mode.md

## 7. Agent support

- **Mechanism**: agent-agnostic — prefix any local command (`greywall -- claude --dangerously-skip-permissions`, `greywall -- codex --yolo`, `greywall -- opencode`); sits under the agent process, no agent-specific setup.
- **Built-in profiles** (first run shows allow/deny summary with apply/edit/skip/don't-ask prompt): Claude Code, Codex, Cursor, Aider, Goose, Gemini CLI, OpenCode, Amp, Cline, Copilot, Kilo, Auggie, Droid; toolchain profiles: Node, Python, Go, Rust, Java, Ruby, Docker/containers, IaC, SCM. Combinable: `--profile claude,python`.
- Generic templates: `code` (proxy-routed, secrets protected) and `code-relaxed` (for TUN-less envs; Cursor Agent needs it since Node undici ignores HTTP_PROXY). Marketing site lists compatibility incl. Claude Code, Codex, Cursor, Aider, Goose, Amp, Gemini CLI, Cline, OpenCode, Copilot.
- Caveat: on Linux, OpenCode/Gemini installed via Linuxbrew can be blocked by Landlock unless installed under $HOME.
Sources: https://github.com/GreyhavenHQ/greywall (README + internal/profiles/agents tree), https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/agents.md, https://greywall.io/

## 8. Resource limits

- **None.** No CPU, memory, disk, wall-clock timeout, or PID/process-count limits exist in the CLI reference or configuration reference, and the FAQ states explicitly greywall "doesn't prevent resource exhaustion (CPU, memory, disk)" — it is defense-in-depth for semi-trusted code, not untrusted/malicious code (also no exfiltration-to-allowed-domains or kernel-exploit protection). The only time-based behaviors are greyproxy session TTL (15 min, heartbeat 60 s) and rule `expires_at` timestamps — policy lifetimes, not process limits.
Sources: https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/faq.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/cli-reference.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/configuration.md

## 9. Observation / audit

- **Modes**: `greywatch` (symlink/`--watch`) = allow-by-default observability — no profile, `*/*` allow rule pushed to greyproxy, permissive FS, everything logged; `greywall -m` monitor mode shows violations/blocked requests; `-d` debug shows full sandbox command + proxy decisions.
- **Dashboard** (http://localhost:43080): Overview (active connections, recent traffic, stats), Pending Requests, Rules editor, Activity log (timestamp/source/destination/decision + expandable HTTP/WS transactions with redacted headers), Conversations, Settings (MITM, conversations, redaction patterns, stored credentials, active sessions); WebSocket live updates; entire UI embedded in the single binary.
- **REST API** (localhost, no auth): `/api/health`, `/api/dashboard`; rules CRUD + `ingest`; pending + bulk allow/dismiss; `/api/logs` + `/logs/stats`; `/api/transactions(/:id)` — captured HTTP/WS transactions incl. request/response headers, bodies, credential-substitution metadata; conversations (+ `/:id/subagents`), `/api/dissectors`, endpoint-rules CRUD; sessions + credentials CRUD; settings; cert generate/download/reload; notifications; `/api/allowall` (silent allow-all debug mode); maintenance (`rebuild-conversations`, `redact-headers`, status); `/ws` control WebSocket. Full OpenAPI-style surface embedded in the binary.
- **LLM conversation tracking** (default on; needs MITM/CA trust): dissectors `anthropic` (POST /v1/messages), `openai` (/v1/responses), `openai-ws` (WS /v1/responses), `openai-chat` (/v1/chat/completions, any host), `google-ai` (Gemini); reconstructs system prompts, messages, tool calls, assistant replies, subagent threads, token counts, timing; groups sessions per client (Claude Code, Codex, Aider, OpenCode, Gemini CLI…); custom endpoint rules (host/path glob + method + decoder) via UI or `POST /api/endpoint-rules`; auto-detects OpenAI-compatible endpoints (`model`+`messages` body) and auto-creates rules.
- **Header redaction**: values replaced with `[REDACTED]` at capture time before SQLite write — defaults Authorization, Proxy-Authorization, Cookie, Set-Cookie, `*api-key*`, `*token*`, `*secret*` (case-insensitive); custom patterns via settings API; retroactive redaction maintenance job (idempotent, 409 on concurrent).
Sources: https://github.com/GreyhavenHQ/greywall (README greywatch), https://raw.githubusercontent.com/GreyhavenHQ/greyproxy/main/docs/dashboard.md, https://raw.githubusercontent.com/GreyhavenHQ/greyproxy/main/docs/api.md, https://raw.githubusercontent.com/GreyhavenHQ/greyproxy/main/docs/conversations.md, https://raw.githubusercontent.com/GreyhavenHQ/greyproxy/main/docs/header-redaction.md

## 10. License

- greywall: **Apache-2.0** (https://github.com/GreyhavenHQ/greywall — LICENSE; also site badge).
- greyproxy: **MIT**, "Copyright (c) 2026 The Greyproxy Authors", fork of GOST (go-gost/gost, MIT) (https://github.com/GreyhavenHQ/greyproxy — License section).

## 11. Version / release info

- greywall **v0.3.7**, published **2026-06-01T15:05:14Z** (created 15:01:13Z), tag `v0.3.7`, changelog: "feat: add NixOS support (#93)"; signed/immutable release; 1 commit to main since. (https://api.github.com/repos/GreyhavenHQ/greywall/releases/latest, https://github.com/GreyhavenHQ/greywall/releases/tag/v0.3.7)
- greyproxy **v0.4.5**, published **2026-06-02T15:59:03Z**, changelog: index http_transactions.container_name to speed up pending page (#55). (https://api.github.com/repos/GreyhavenHQ/greyproxy/releases/latest)

## 12. Installation footprint

- **greywall**: single static Go binary (+ `greywatch` symlink, same binary via argv[0]). install.sh → `~/.local/bin/greywall`, sha256-checksum verified, always runs `greywall setup` (installs greyproxy + registers systemd user service / launchd agent) and `greywall check`. Also Homebrew (`brew tap greyhavenhq/tap && brew install greywall` — pulls greyproxy as dependency), `go install …/cmd/greywall@latest`, mise, or source (`make setup && make build`).
- **Tarball sizes (compressed)**: greywall v0.3.7 — Linux x86_64 ≈7.30 MB, Linux arm64 ≈6.91 MB, Darwin arm64 ≈3.44 MB, Darwin x86_64 ≈3.71 MB. greyproxy v0.4.5 — linux_amd64 ≈7.79 MB, linux_arm64 ≈6.44 MB, darwin_arm64 ≈9.93 MB, darwin_amd64 ≈10.59 MB (dashboard UI embedded).
- **Runtime footprint**: greyproxy service binds 43080/43051/43052/43053 on localhost; SQLite DB at `~/.local/share/greyproxy/greyproxy.db` (Linux) / `~/Library/Application Support/greyproxy/greyproxy.db` (macOS); CA cert generated and installed into OS trust store (one-time sudo; without it HTTPS MITM/conversations don't work); greywall config at `~/.config/greywall/greywall.json` (Linux) / `~/Library/Application Support/greywall/greywall.json` (macOS), learned profiles under `~/.config/greywall/learned/`.
- **Dependencies**: Linux — bubblewrap + socat required (xdg-dbus-proxy, libsecret-tools optional); macOS — none (uses shipped sandbox-exec/eslogger). No containers/Docker required.
- **Overhead**: startup ≈215 ms Linux / ≈22 ms macOS per invocation (paid once for long-running agents; child processes run at native speed).
Sources: https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/install.sh, https://api.github.com/repos/GreyhavenHQ/greywall/releases/latest, https://api.github.com/repos/GreyhavenHQ/greyproxy/releases/latest, https://github.com/GreyhavenHQ/greywall (README), https://github.com/GreyhavenHQ/greyproxy (README), https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/faq.md, https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/docs/cli-reference.md

## 13. Notable gaps / caveats for the matrix

- macOS network capture is weaker by design (env-var routing only; proxy-ignoring binaries fail rather than bypass) — documented as a fundamental macOS limitation.
- macOS `.env` credential rewriting unsupported (files denied instead).
- Credential substitution skips request bodies and non-HTTP protocols.
- No resource limits of any kind (CPU/mem/disk/pids/timeouts) — explicitly out of threat model.
- greyproxy REST API/dashboard unauthenticated by design (localhost-only tool; public exposure unsupported).
- Not intended for actively malicious code (defense-in-depth for semi-trusted workloads).
- Everything requested was verifiable from primary sources; no UNKNOWN entries remain except items explicitly documented as absent (resource limits).
