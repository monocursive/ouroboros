# R1 — The Interaction Model of Developer Coding Agents (as of 2026-08-22)

Scope: how the user and the agent talk to each other in the 18 agents named in the brief. Every non-obvious claim carries a URL; items I could not confirm from a primary or 2026-dated source are marked **unverified**. Official docs were fetched directly on 2026-08-22; star counts were read from the GitHub API the same day.

## 0. Who developers actually use (to weight the rest)

JetBrains' Developer Ecosystem Survey 2026 (15,000+ professional developers, fielded May–July 2026) reports weekly AI-agent use at 90% and daily at 68%. Tool adoption: **Claude Code 39%** (47% in the US; up from 18% in January), **GitHub Copilot 21%** (down from 29%), **Codex 16%** (up from 3% in January), **Cursor 12%** (down from 18%), **OpenCode 7%**, **Google Antigravity 6%**, JetBrains AI/Junie 9%. Claude Code converts to "primary tool" at almost 80% and "is used twice as often as GitHub Copilot." (https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/)

GitHub stars on 2026-08-22 (api.github.com): anomalyco/opencode 200,253; anthropics/claude-code 142,421; openai/codex 112,662; google-gemini/gemini-cli 106,608 (still pushed 2026-08-22 despite the consumer sunset, see §3); cline/cline 66,656; aaif-goose/goose 53,242 (repo moved from block/goose); Aider-AI/aider 48,402 (last push 2026-05-22); charmbracelet/crush 27,575; github/copilot-cli 11,111. pi-mono's repo has moved and its count is **unverified**.

So the top-5 by usage are Claude Code, Copilot (CLI + IDE), Codex, Cursor, OpenCode; Antigravity CLI is the new Google entrant. Those six get the deepest treatment; the rest are covered for the patterns they contribute.

---

## 1. Cross-product matrix

### 1a. Prompt / compose

| Product | Multiline | External editor | @-mentions | Images | Slash/palette | Vim | Shell passthrough |
|---|---|---|---|---|---|---|---|
| Claude Code | Shift+Enter / Ctrl+J / paste mode | Ctrl+G or Ctrl+X Ctrl+E | `@path` (dirs, MCP `@server:resource`, other sessions) | Ctrl+V (Alt+V Win/WSL), drag-drop, path | `/` menu with fuzzy match, `?` help panel, `:` emoji | Full NORMAL/VISUAL, text objects, `jj` remaps | `!cmd` (Claude auto-responds to output) |
| Codex CLI | standard | Ctrl+G | `@` fuzzy | Ctrl+V, `--image` | `/` commands | Yes (expanded Aug 2026: `cw`, `c$`, `cc`) | `!cmd` |
| Gemini CLI → Antigravity (`agy`) | Shift+Enter / Ctrl+J / Alt+Enter | Ctrl+G | `@file` | paste | `/`; `?` shortcuts panel | `/vim` | `!` shell mode |
| OpenCode | Shift/Ctrl/Alt+Enter, Ctrl+J | `<leader>e` / `/editor` | `@` fuzzy | drag-drop | Ctrl+P palette + `/` | — (keybinds configurable) | `!cmd` |
| Amp | Shift+Enter (capable terminals), Ctrl+J, `\`+Enter | Ctrl+G | `@` files, `@T-…` threads, images by path | Ctrl+V | Ctrl+O palette | — | — |
| Pi | Shift+Enter / Ctrl+J | Ctrl+G | `@` fuzzy | Ctrl+V / drag | `/` | — | `!cmd`, `!!cmd` hidden |
| Cursor CLI | — | — | `@` | — | `/` (incl. `/vim`) | `/vim` | `/shell` mode |
| Aider | `/multiline-mode` | Ctrl-X Ctrl-E, `/editor` | `/add`, `/read-only` | `/paste` | `/` (41 commands) | `--vim` | `/run`, `/test` |
| Copilot CLI | — | — | `@file`, `#issue`/`#PR` | drag/paste, PDFs | `/` | — | `!cmd` |
| Factory Droid | Shift+Enter | — | `@` fuzzy | Ctrl+V | `/` (40+) | — | `!` bash mode |
| Kiro CLI | Shift+Enter / Ctrl+J / Alt+Enter | `/editor` | `/context add` | — | `/` + Ctrl+S fuzzy | — | `!cmd` |
| Zed panel | editor | n/a | files, dirs, symbols, threads, skills, diagnostics, branch diffs, URLs | yes | `/` + cmd palette | Zed vim | terminal thread |

Sources: Claude Code interactive mode (https://code.claude.com/docs/en/interactive-mode); Codex (https://blakecrosley.com/guides/codex, third-party, cross-checked against https://learn.chatgpt.com/docs/changelog); Gemini CLI shortcuts (https://geminicli.com/docs/reference/keyboard-shortcuts/); OpenCode keybinds (https://opencode.ai/docs/keybinds/) and TUI (https://opencode.ai/docs/tui/); Amp manual (https://ampcode.com/manual); pi usage/keybindings (https://pi.dev/docs/latest/usage, https://pi.dev/docs/latest/keybindings); Cursor CLI slash commands (https://cursor.com/docs/cli/reference/slash-commands); Aider commands (https://aider.chat/docs/usage/commands.html); Copilot CLI docs (https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli) and https://www.devleader.ca/2026/07/17/github-copilot-cli-slash-commands-inside-the-session-modes-and-shortcuts; Droid CLI reference (https://docs.factory.ai/droid-cli/cli-reference); Kiro chat (https://kiro.dev/docs/cli/chat/); Zed agent panel (https://zed.dev/docs/ai/agent-panel).

### 1b. Modes

| Product | Plan/read-only mode | Permission tiers | Mode key | Effort / thinking | Model switch |
|---|---|---|---|---|---|
| Claude Code | `plan` (approve → pick execution mode; Ctrl+G edits plan) | `default`(Manual), `acceptEdits`, `plan`, `auto` (classifier), `dontAsk`, `bypassPermissions` | Shift+Tab cycles default→acceptEdits→plan | Opt+T thinking, `/effort`, Opt+O fast | Opt+P, `/model` |
| Codex CLI | `/plan` (read-only until approved) | `approval_policy`: `untrusted` / `on-request` / `never`; sandbox `read-only` / `workspace-write` / `danger-full-access`; `--approve-for-me` reviewed approvals (v0.147) | `/permissions` | `/model` picks effort `minimal…xhigh`; Alt+, / Alt+. | `/model` |
| Antigravity CLI | `plan` / `/planning` | presets `request-review`, `proceed-in-sandbox`, `always-proceed`, `strict` | Shift+Tab default→accept-edits→plan | `/effort` | `/model` |
| OpenCode | `plan` primary agent (read-only) vs `build` | per-agent `allow`/`ask`/`deny` | Tab cycles agents | `/thinking` toggles visibility | `<leader>m`, `/models` |
| Amp | none (modes are capability dials) | **"does not ask for approval before running tools"** by default; plugin `tool.call` hooks add approvals | Ctrl+S/Ctrl+J switch; Ctrl+O `mode` | low / medium / high / ultra; Alt+D effort; Alt+R fast | in mode |
| Pi | none by design | none by design (no permission popups) | — | Shift+Tab cycles thinking level; editor border colour shows it | Ctrl+P cycle, Ctrl+L picker |
| Cursor CLI/IDE | Plan (clarifying Qs → plan → build), Ask, Debug | `/run-everything`, `/sandbox`, sudo via IPC | Shift+Tab | `/max-mode` | `/model` |
| Aider | `ask`, `architect` (planner/editor split), `code` | git-commit-per-edit, `/undo` | `/chat-mode` | — | `/model` |
| Cline | Plan / Act (separate models per mode) | 8 auto-approve categories; YOLO | toggle in UI; `--plan` in CLI | — | per mode |
| Factory Droid | Spec mode (ExitSpecMode asks approval → choose autonomy), Mission mode | Autonomy Off / Low / Medium / High | Shift+Tab (Spec), Ctrl+L (autonomy) | `/model`, Ctrl+N cycles | `/model` |
| Kiro CLI | spec workflow; `/tools trust` | `/tools`, `--trust-all-tools` | — | `/effort` | `/model` |
| Copilot CLI | Plan; Autopilot | 3-option prompt: yes / yes for session / no + redirect | Shift+Tab standard→plan→autopilot | Ctrl+T shows reasoning | `/model` |
| Goose | `chat` mode | `auto`, `approve`, `smart_approve` (LLM classifier), tool-level AlwaysAllow/AskBefore/NeverAllow | `/mode` | — | — |
| Crush | — | `permissions allow view edit`; `--yolo` | — | — | Ctrl+L preserves context |
| Warp | — | Agent Profiles (Default / YOLO / Prod patterns), per-action "Always allow / Agent decides / Always ask" | — | — | model picker |
| Zed/ACP | ACP `session/set_mode` (e.g. ask / architect / code) | Profiles + tool permissions | mode selector | burn mode | Cmd+Alt+/ |

Sources: https://code.claude.com/docs/en/permission-modes; Codex https://blakecrosley.com/guides/codex (third-party) + https://aiopsschool.com/blog/complete-codex-slash-commands-and-cli-options-guide-updated-april-2026/; Antigravity cheatsheet https://github.com/jqueryscript/antigravity-cli-cheatsheet/blob/main/readme.md (third-party); OpenCode agents https://opencode.ai/docs/agents/; Amp manual; pi docs; Cursor CLI overview https://cursor.com/docs/cli/overview; Aider modes https://aider.chat/docs/usage/modes.html; Cline https://docs.cline.bot/features/auto-approve and https://docs.cline.bot/features/plan-and-act; Factory https://docs.factory.ai/autonomy-and-safety/specification-mode and https://docs.factory.ai/autonomy-and-safety/auto-run; Kiro https://kiro.dev/docs/reference/slash-commands/; Copilot docs; Goose https://deepwiki.com/block/goose/6.2-permission-modes-and-tool-approval (derived from source, cross-checked with https://github.com/block/goose/discussions/4324); Crush README https://github.com/charmbracelet/crush; Warp https://docs.warp.dev/agent-platform/local-agents/code-diffs/; ACP https://agentclientprotocol.com/protocol/session-modes.

### 1c. Turn control

| Product | Interrupt | Queue while working | Steer mid-turn | Edit previous / backtrack | File rewind | Fork |
|---|---|---|---|---|---|---|
| Claude Code | Esc (keeps work) | Enter queues; list shown above input; Up takes it back | queued message delivered "as soon as those tool calls finish, within the same turn" | Esc Esc → rewind menu (restores prompt to input) | `/rewind`: code+conv / conv / code / summarize from-here / up-to-here; 100 checkpoints; bash & subagent edits not tracked | `/branch`, `--fork-session`, `/subtask` (bg fork w/ prompt cache), `/fork` (bg session) |
| Codex CLI | Esc | Tab queues | Enter during turn steers (issue history below) | Esc Esc edits previous message | — (git) | `/fork`, `codex exec fork`, fork "from any earlier message" |
| Gemini/agy | Ctrl+C / Esc | Tab queues | — | double Esc clears or rewinds | `/restore` (Gemini), `/rewind` (agy) | `/fork` (agy) |
| OpenCode | Esc | — | — | `<leader>u` undo message | `/undo` `/redo` git-backed | fork from timeline (keybind `none` by default) |
| Amp | Esc Esc interrupts and sends now | Enter queues | Enter twice = send at next step boundary | Tab to prior message, `e` to edit | — | handoff/threads |
| Pi | Esc aborts and restores queued text | Alt+Enter = follow-up (after all work) | Enter = steer (after current tool calls) | `/tree` jump anywhere | — (git) | `/fork`, `/clone`, `/tree` w/ branch summary |
| Cursor | — | Enter queues | Cmd+Enter immediate; since Aug 19 2026 "Follow-ups wait for the next tool call instead of cutting the agent off mid-action" | `/rewind` | checkpoints in chat timeline | `/fork` |
| Copilot CLI | Esc | Ctrl+Q / Ctrl+Enter | — | Esc Esc rewind | `/rewind` "without requiring git or discarding user edits" | — |
| Cline | cancel | — | — | — | shadow-git: Restore Files / Task / Files & Task + Compare | — |
| Zed | stop | — | — | — | "Restore Checkpoint" after every edit; hunk accept/reject | threads |
| Droid | — | — | — | — | — | `/fork`, `--fork` |
| Kiro | Ctrl+C | — | — | `/tangent` (Ctrl+T) checkpoint & return | `/checkpoint` (experimental) | `/spawn` |

Sources: Claude Code https://code.claude.com/docs/en/interactive-mode#queue-messages-while-claude-works and https://code.claude.com/docs/en/checkpointing and https://code.claude.com/docs/en/sessions; Codex https://blakecrosley.com/guides/codex, https://codex.danielvaughan.com/2026/03/27/codex-cli-in-2026-whats-new/, https://learn.chatgpt.com/docs/changelog; Gemini shortcuts page; OpenCode keybinds + https://github.com/anomalyco/opencode/issues/12580; Amp manual; pi usage; Cursor https://cursor.com/docs/agent/overview and https://cursor.com/changelog (Aug 19 2026); Copilot https://github.blog/changelog/2026-08-13-github-copilot-weekly-releases-august-10/ (via search summary) and GA post; Cline https://docs.cline.bot/features/checkpoints; Zed agent panel; Kiro https://kiro.dev/docs/cli/experimental/tangent-mode/.

### 1d. Sessions, context, memory

| Product | Resume | Picker/search | Naming | Compaction | Context meter | Memory/rules | Hooks |
|---|---|---|---|---|---|---|---|
| Claude Code | `--continue`, `--resume <name>`, `--from-pr`, `/resume` | search, Ctrl+A all projects, Ctrl+W worktrees, Ctrl+B branch, Space preview, paste PR URL | `-n`, `/rename`, Haiku auto-title, plan-accept title | auto + `/compact [focus]`; "Resume from summary" dialog for >100k-token sessions | `/context` (+ warning when over window) | CLAUDE.md hierarchy, auto memory, rules, skills | full lifecycle incl. TeammateIdle/TaskCompleted |
| Codex CLI | `codex resume --last`, `/resume`, archive/restore in picker | picker | `codex agents` rename | `/compact` | `/status` shows context + credits/cost | AGENTS.md, AGENTS.override.md | async hooks, can invoke MCP (v0.148) |
| OpenCode | `/sessions` (`/resume`), `--continue`, `--session` | home palette search | Ctrl+R rename | `/compact` | — | AGENTS.md via `/init` | plugins |
| Amp | threads (durable, URL) | feed with `label:`/`file:`/`author:`/`after:` filters | — | handoff | `$` cost sidebar | AGENTS.md (globs frontmatter, `@include`), skills | plugins (`tool.call`) |
| Pi | `-c`, `-r`, `/resume` | picker w/ Ctrl+N named-only, Ctrl+S sort | `/name`, `--name` | auto at `contextWindow-reserveTokens`; `/compact [instr]`; branch summaries | footer tokens/cost | AGENTS.md or CLAUDE.md | extensions |
| Cursor CLI | `agent ls`, `agent resume`, `--continue`, `/resume` | — | `/rename` | `/summarize` | — | rules, AGENTS.md | hooks |
| Aider | — | — | — | `/clear`, `/copy-context` | — | repo-map, conventions file | — |
| Cline | — | — | — | — | — | .clinerules | — |
| Droid | `--resume`, `/sessions` | — | — | `/compress` → new session | `/context` progress bar, `/cost` | AGENTS.md | hooks |
| Kiro | `--resume`, `--resume-id`, `--resume-picker`, `/chat save/load` | picker | — | `/compact` | `/context`, `/usage` | steering files, specs, knowledge | hooks |
| Copilot CLI | `/resume`, `--continue`, `--cloud` | — | — | auto-compaction ("infinite sessions") + `/compact` | `/context`, `/usage` | copilot-instructions.md, `.github/instructions/**` | — |
| Crush | session manager | Ctrl+S | — | — | — | CRUSH.md, AGENTS.md | — |
| Goose | `goose session -r` | — | — | — | — | recipes | — |
| Zed | threads sidebar, history | grouped by project | — | "New From Summary" | depends on agent | rules | — |

Sources: https://code.claude.com/docs/en/sessions; Codex changelog Aug 2026; https://opencode.ai/docs/cli/; Amp manual; https://pi.dev/docs/latest/sessions and https://pi.dev/docs/latest/compaction; Cursor CLI docs; Droid CLI reference; Kiro chat/slash docs; Copilot GA post; Zed panel docs.

### 1e. Multi-agent UX

| Product | Subagent display | Background tasks | Parallel sessions/worktrees | Fleet view |
|---|---|---|---|---|
| Claude Code | agent panel below prompt; ↑/↓, Enter opens transcript & lets you message it, `x` stops, `(+N)` nested tree (3 levels); `/tasks` | Ctrl+B backgrounds bash; MCP calls >2 min auto-background | `--worktree`; experimental agent teams (in-process or tmux/iTerm2 panes, shared task list, mailbox, plan approval for teammates) | `claude agents`: Needs input / Working / Ready for review groups, Space peek + reply, Alt+1..9, ← to background |
| Codex CLI | subagents GA v0.115 (Mar 16 2026), 6 concurrent | — | remote TUI | `codex agents` dashboard (search/start/rename/stop), `codex queue` to message sessions (v0.149) |
| Antigravity | `/agents` subagent panel, Ctrl+K quick-approve, async subagents | `/tasks` | — | — |
| OpenCode | child sessions: `<leader>↓` enter, ←/→ cycle, ↑ parent; `@general` mentions | — | `serve`/`attach` | — |
| Amp | automatic subagents; Oracle second-opinion model; agents spawn/message each other (Jul 17 2026) | orbs (remote) | multiplayer orbs | web + mobile "watch and drive your agents from anywhere" (Jun 4 2026), Puck meta-agent |
| Cursor | subagents on own VMs (Aug 19 2026) | cloud handoff with `&` | worktrees (3.2, Apr 2026), Agents Window across local/worktree/cloud/SSH | Agents Window |
| Copilot CLI | `/fleet` parallel subagents; `&` cloud delegation | — | `--cloud` sessions; unified sessions view in JetBrains (May 13 2026) | — |
| Droid | Mission mode orchestrator | `--worktree` + `&` | yes | Mission Control |
| Kiro | `/spawn`, `/delegate` (async), subagents | yes | — | — |
| Goose | subagents only in `auto` mode, isolated sessions, JSON summaries back | — | — | — |
| Warp | — | Oz cloud agents | tabs/panes, isolated worktrees | Agent Management Panel |
| Devin | Managed Devins (Mar 19 2026): coordinator + child VMs, sleep/terminate children | all cloud | up to 10 parallel (third-party claim) | web app |
| Jules | — | all async in cloud VM | — | `jules remote list`, TUI `/remote` |

Sources: https://code.claude.com/docs/en/sub-agents, https://code.claude.com/docs/en/agent-teams, https://code.claude.com/docs/en/agent-view; Codex changelog + danielvaughan; Antigravity cheatsheet; OpenCode agents; Amp chronicle https://ampcode.com/chronicle; Cursor changelog; Copilot GA + https://github.blog/changelog/2026-05-13-introducing-copilot-cli-agent-and-unified-sessions-view-in-github-copilot-for-jetbrains-ides/; Factory; Kiro; Goose subagents (https://goose-docs.ai/docs/guides/context-engineering/subagents/ via search); Warp https://docs.warp.dev/agent-platform/getting-started/agents-in-warp/; Devin https://docs.devin.ai/release-notes; Jules https://developers.googleblog.com/en/meet-jules-tools-a-command-line-companion-for-googles-async-coding-agent/.

### 1f. Onboarding / non-interactive

| Product | Install | Auth | Headless | SDK/protocol |
|---|---|---|---|---|
| Claude Code | npm/brew/native | OAuth (Pro/Max/Team), API key, Bedrock/Vertex/Foundry | `claude -p`, `--output-format json|stream-json`, `-p --resume <id>` | Agent SDK (TS/Py), hooks, ACP (via Claude Agent) |
| Codex | `curl … install.sh`, npm, brew cask | "Sign in with ChatGPT" or API key | `codex exec`, `--ask-for-approval never` | MCP server mode; ACP listed |
| Antigravity | `curl … antigravity.google/cli/install.sh` | Google login (SSH flow w/ one-time code) | `agy -p` | plugins, hooks |
| OpenCode | `curl opencode.ai/install`, npm, brew, scoop | `/connect` (OpenCode Zen or any provider) | `opencode run --format json`, `serve`, `web`, `attach` | SDK, `opencode acp` |
| Amp | installer | Amp account; free tier | `amp -x`, `--stream-json(-input)` | plugins |
| Pi | npm / curl | `/login` subscription providers or API keys | `-p`, RPC (stdin/stdout JSONL), JSON event stream | Node SDK |
| Cursor CLI | `curl cursor.com/install` | Cursor account | `-p --output-format text` | cloud agents API |
| Aider | pip | API keys | scriptable | Python |
| Cline | npm `cline`, VS Code | `cline auth` | auto-headless on pipe/`--json`; `--auto-approve` default **true** | SDK |
| Droid | installer | Factory account | `droid exec`, `--mission --auto high` | — |
| Kiro | `curl cli.kiro.dev/install` | AWS Builder ID / IdC | headless w/ API keys | ACP |
| Copilot CLI | npm/brew | `/login` GitHub | `-p`; `--plan` + `--mode autopilot` headless (Aug 2026) | SDK ("Copilot App 2026") |
| Crush | brew/winget/yay | Hyper provider free tier (zero retention) or env keys | run mode | — |
| Goose | brew/installer | any provider | `goose run` | MCP-native |
| Warp | app; open source Apr 28 2026 | Warp account | `warp` CLI | Oz API |
| Devin | web; `curl cli.devin.ai/install.sh` | Cognition account | CLI → "send longer tasks to cloud Devin" | API, MCP marketplace |
| Jules | web; `jules` CLI | Google | `jules remote new --repo … --session …` | API |

---

## 2. Product notes (what is distinctive, with evidence)

### Claude Code (Anthropic)
- **Compose.** The richest terminal input of the set: `?` toggles a shortcut help panel, `@` opens a path picker (and, in sessions with cross-session messaging, mentions another live session by name), `!` is shell mode where "Claude responds to the command output automatically once it lands in the transcript," `:` inserts emoji, Ctrl+S stashes a half-written prompt, spellcheck underlines as you type, and vim mode covers text objects, visual mode and `vimInsertModeRemaps` (`jj`). `keybindings.json` and a `keybindingFlavor: "readline"` option (v2.1.238) exist, but double-Esc is still not rebindable (issue below). (https://code.claude.com/docs/en/interactive-mode; https://www.gradually.ai/en/changelogs/claude-code/)
- **Modes.** Six permission modes; on Pro/Max/Team "the built-in starting permission mode is auto mode," where "a second model, the classifier, reviews actions instead of you," with documented fallback rules ("if the classifier blocks an action 3 times in a row or 20 times total, auto mode pauses"). Plan mode approval offers "Yes, and use auto mode" / "Yes, manually approve edits" / "No, keep planning," and Ctrl+G opens the plan in `$EDITOR`. Accepting a plan auto-titles the session. (https://code.claude.com/docs/en/permission-modes)
- **Turn control.** Enter queues; queued messages are passed "as soon as those tool calls finish, within the same turn"; Esc interrupts and "keeps what you queued and sends it right away"; Up takes the queue back into the editor. Esc Esc opens a rewind menu with five actions including "Summarize from here." Limits are documented honestly: bash-made changes and most subagent edits are not restorable. (https://code.claude.com/docs/en/checkpointing)
- **Sessions.** `/resume` picker filters by project/worktree/branch, previews with Space, and accepts a pasted PR URL; `--from-pr 1234` opens sessions linked to a PR. Long idle sessions get a "Resume from summary / Resume full session / Don't ask again" dialog. `/branch` copies the transcript in-process; `/fork` (v2.1.212) copies into a background session. (https://code.claude.com/docs/en/sessions)
- **Multi-agent.** Subagents run in the background by default (v2.1.232) and appear in an agent panel under the prompt; Enter opens a transcript you can message; nested subagents render as a tree with `(+N)`. `claude agents` is a fleet view grouping sessions by "Needs input / Working / Ready for review," with Space to peek and reply and PR labels that turn green when checks pass. Agent teams (experimental, env-flag) add a shared task list and mailbox, in-process or as tmux/iTerm2 split panes, but "/resume and /rewind do not restore in-process teammates." (https://code.claude.com/docs/en/sub-agents; https://code.claude.com/docs/en/agent-view; https://code.claude.com/docs/en/agent-teams)
- **Situational awareness.** `/btw` asks a side question in an overlay without touching history, even while Claude is working; a one-line "session recap" appears when you return after three minutes unfocused; a footer PR badge shows review state; prompt suggestions are generated off the warm cache. (interactive-mode doc)
- **Complaints (2026).** Real-time steering is the most-requested gap: "messages typed during processing are queued and delivered at the next turn boundary, by which point Claude may have already completed significant work in the wrong direction" (https://github.com/anthropics/claude-code/issues/30492; https://github.com/anthropics/claude-code/issues/64624). Double-Esc "is hardcoded and cannot be rebound," breaking terminal vi-mode users (https://github.com/anthropics/claude-code/issues/43717). Rewind "doesn't work most of the time" for multi-file changes (https://github.com/anthropics/claude-code/issues/18516) and once froze the terminal (https://github.com/anthropics/claude-code/issues/52209); Esc interrupt was disabled when queued messages or background tasks existed (https://github.com/anthropics/claude-code/issues/16905). Reddit threads report post-compaction slowdowns (18 min vs 4.5 min for the same task) and that "many developers do not discover [/compact, /memory] until months into using Claude Code" (https://www.morphllm.com/claude-code-reddit). Rate-limit burn is the top complaint in comparative reviews (https://www.firecrawl.dev/blog/claude-code-vs-codex).

### OpenAI Codex CLI
- Approval is a two-axis model: `approval_policy` (`untrusted` / `on-request` / `never`) × OS-enforced sandbox (`read-only` / `workspace-write` / `danger-full-access`), plus `--approve-for-me` (v0.147) where a review pass adjudicates requests, and "Smart Approvals" where "a lightweight guardian subagent reviews pending actions and routes them — approve silently, escalate to user, or block." Reasoning effort runs `minimal…xhigh` with Alt+,/Alt+. to step mid-session. (https://blakecrosley.com/guides/codex; https://codex.danielvaughan.com/2026/03/27/codex-cli-in-2026-whats-new/)
- Turn control is the clearest "queue vs steer" split in the field: Enter steers the running turn, Tab queues for the next one, Esc Esc edits a previous message. That split has been fragile: a March 2026 regression made "both 'enter' and 'tab' … queuing steer messages" (https://github.com/openai/codex/issues/13595), and in April "queued prompts behave like steer prompts; multiple queued prompts sent simultaneously" (https://github.com/openai/codex/issues/17285). Plan mode dead-ends are recurring ("Getting stuck in plan mode," https://github.com/openai/codex/issues/24331).
- August 2026 (v0.148–0.149) added `/export` to Markdown, `codex exec fork`, archive/restore in the resume picker, async hooks that can invoke MCP tools, thread cost in `/status`, an interactive `codex agents` dashboard, `/cd` `/pwd`, `codex queue` "for sending messages to existing local or remote sessions," and more vim motions. (https://learn.chatgpt.com/docs/changelog)
- Subagents went GA in v0.115 (Mar 16 2026) with up to 6 concurrent; conversations can be forked "from any earlier message." (danielvaughan)

### Gemini CLI → Antigravity CLI (Google)
- **Status change.** On May 19 2026 Google announced that on June 18 "Gemini CLI and Gemini Code Assist IDE extensions will stop serving requests for Google AI Pro and Ultra, as well as those using it free of charge"; enterprise licences are unaffected; Agent Skills, Hooks, Subagents and Extensions carry over to the Go-based Antigravity CLI, but "There won't be 1:1 feature parity right out of the gate." The open-source repo is still being pushed (2026-08-22). (https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/; https://www.theregister.com/ai-ml/2026/05/20/bye-bye-gemini-cli-google-nudges-devs-toward-antigravity/5243605)
- **Gemini CLI model** (still relevant for enterprise and as the lineage): Shift+Tab cycles default → auto_edit → plan; Ctrl+Y toggles YOLO; Tab queues; Ctrl+G external editor; `/restore` checkpoints; plan mode writes plans to a plans directory, "will stop and wait for your confirmation before drafting the formal plan," opens the plan with Ctrl+X, and approval reads "Yes, automatically accept edits"; in non-interactive runs it "automatically switches to YOLO mode." (https://geminicli.com/docs/reference/keyboard-shortcuts/; https://geminicli.com/docs/cli/plan-mode/)
- **agy**: Shift+Tab cycles default → accept-edits → plan; approval presets `request-review` / `proceed-in-sandbox` / `always-proceed` / `strict`; `/agents` subagent panel with Ctrl+K quick-approve; `/fork`, `/rewind`, `/effort`, `/tasks`; reads GEMINI.md and AGENTS.md. (third-party cheatsheet https://github.com/jqueryscript/antigravity-cli-cheatsheet; hands-on https://dev.to/arindam_1729/antigravity-cli-a-hands-on-guide-to-googles-terminal-coding-agent-5bc7)
- **Complaints.** The free tier "exhausts in twenty to thirty minutes of real work and then locks the weekly bucket" and the 2.0 auto-update "removed the built-in code editor … and wiped stored configurations" (https://www.developersdigest.tech/blog/antigravity-cli-vs-claude-code-vs-codex-2026; https://chatforest.com/reviews/google-antigravity-2-agent-first-dev-platform-review/). Async subagents "consume quota in parallel" (dev.to).

### OpenCode (anomalyco, formerly sst)
- Leader-key TUI (`ctrl+x`), Tab cycles `build`/`plan` primary agents, subagents are invoked with `@general`, child sessions are navigable with `<leader>↓` then ←/→/↑. `/undo` and `/redo` are git-backed; `/share` produces a link; `/export` to Markdown; `opencode run --format json`, `serve`, `web`, `attach` (remote TUI) and `opencode acp`. (https://opencode.ai/docs/keybinds/; https://opencode.ai/docs/agents/; https://opencode.ai/docs/cli/)
- Complaints: fork is "easy to miss and can feel like a 'switch'" and the default keybind is `none` (https://github.com/anomalyco/opencode/issues/12580); `/compact` "does not compress — context increases instead" (https://github.com/anomalyco/opencode/issues/17557); an "auto-compaction loop" that stops generation (https://github.com/anomalyco/opencode/issues/30680). A May 2026 PRD asks for a durable "Goal Mode" across "turns, compaction, restarts" (https://github.com/anomalyco/opencode/issues/27339).

### Amp (Sourcegraph)
- No permission prompts by default ("Amp does not ask for approval before running tools"); guardrails come from plugins hooking `tool.call` (`allow`, `reject-and-continue`, `modify`, `synthesize`). Modes are a capability dial (low/medium/high/ultra, Jul 9 2026) not a model picker. Queue vs steer: "Press Enter twice to send when agent completes current step … Press Esc twice to interrupt." Threads are durable URLs with workspace/group/unlisted visibility, searchable with `file:`/`author:`/`after:` filters, and mentionable (`@T-…`). Oracle is an explicit "second opinion" model. 2026 additions: orbs (remote), multiplayer orbs, Puck meta-agent, realtime voice with Puck (Aug 18), agents that "spawn other agents, message them, and exchange files" (Jul 17), "watch and drive your agents from anywhere: web, CLI, and mobile" (Jun 4). (https://ampcode.com/manual; https://ampcode.com/chronicle)

### Pi (pi.dev, Mario Zechner)
- Four tools (read, write, edit, bash), system prompt under 1k tokens, and a deliberate refusal list: "MCP, sub-agents, plan mode, permission popups, built-in todos, background bash" are left to extensions. Zechner "wanted an AI harness that behaves in a stable, consistent way" after finding Claude Code's feature velocity made "bugs multiplied and the tool's behavior started to change." (https://explainx.ai/blog/pi-minimal-agent-harness-mario-zechner-guide-2026; https://newsletter.pragmaticengineer.com/p/building-pi-and-what-makes-self-modifying)
- Where it leads on interaction: **tree-structured sessions** ("Every entry has an `id` and `parentId`"), `/tree` to jump anywhere, `/fork`, `/clone`, and branch summarization that "summarize[s] the abandoned branch and attach[es] that summary at the new position." Steer vs follow-up is two keys (Enter vs Alt+Enter), Esc aborts "and restore[s] queued text to the editor," Alt+Up pulls queued messages back. Shift+Tab cycles thinking level and the editor border colour shows it; the footer shows tokens, cost and model. Compaction parameters are explicit (`reserveTokens` 16,384, `keepRecentTokens` 20,000) and the summary has a fixed structure (Goal / Constraints / Progress / Decisions / Next steps). (https://pi.dev/docs/latest/sessions; https://pi.dev/docs/latest/usage; https://pi.dev/docs/latest/compaction)

### Cursor (CLI + IDE)
- CLI: Shift+Tab to Plan, `/ask`, `/debug`, `/goal` ("a long-lived objective to work towards until it's fully complete"), `/fork`, `/rewind`, `/summarize`, `/vim`, `/run-everything`, `/sandbox`; prefix `&` to "Push your conversation to a Cloud Agent to continue running while you're away"; sudo password goes "directly to sudo via a secure IPC channel; the AI model never sees it." (https://cursor.com/docs/cli/overview; https://cursor.com/docs/cli/reference/slash-commands)
- IDE: checkpoints "automatically … before making significant changes," restorable from the chat timeline; Enter queues, Cmd+Enter sends immediately; Aug 19 2026 changed steering so "Follow-ups wait for the next tool call instead of cutting the agent off mid-action," added subscriptions (agent wakes on thread events), custom modes, and subagents on their own VMs. Cursor 3's Agents Window runs agents "locally, in worktrees, in the cloud, and on remote SSH"; worktrees landed in 3.2 (Apr 24 2026, third-party dating). (https://cursor.com/docs/agent/overview; https://cursor.com/changelog; https://www.digitalapplied.com/blog/cursor-3-agents-window-complete-guide)
- Complaints: "Worktree agents disappeared" and inconsistent worktree setup between agent and editor windows (https://forum.cursor.com/t/worktree-agents-disappeared/165623; https://forum.cursor.com/t/inconsistent-worktree-setup-between-agent-and-editor-windows/157668); adoption slid to 12% (JetBrains).

### Aider
- Still the reference for explicit context control: `/add`, `/drop`, `/read-only`, repo-map, `/undo` ("Undo the last git commit if it was done by aider"), `/diff`, `/voice`, `/paste`, `/web`, `/editor`, `--vim`, and the architect/editor split ("an architect model will propose changes and an editor model will translate that proposal into specific file edits"). v0.86.2 shipped Feb 12 2026; the repo's last push was May 22 2026, so treat it as slowing. (https://aider.chat/docs/usage/modes.html; https://aider.chat/docs/usage/commands.html; GitHub API)

### Cline
- Plan/Act with "different models for Plan and Act"; checkpoints via "a shadow Git repository separate from your project's actual Git history" with Restore Files / Restore Task Only / Restore Files & Task and a Compare diff; eight auto-approve categories plus YOLO that "disables all safety checks." The CLI (`cline`, v3 "CLI 2.0") defaults `--auto-approve` to **true** and goes headless on pipe or `--json`. (https://docs.cline.bot/features/plan-and-act; https://docs.cline.bot/features/checkpoints; https://docs.cline.bot/features/auto-approve; https://docs.cline.bot/cline-cli/overview)

### Factory Droid
- Two orthogonal dials: Shift+Tab toggles Normal ↔ Spec mode ("Uses read-only planning behavior, then calls `ExitSpecMode` to ask for approval"), Ctrl+L cycles autonomy Off → Low → Medium → High, and on plan approval "users select their desired autonomy level for the execution phase." Mission mode runs an orchestrator "with Mission Control." `/context` shows a progress bar, `/compress` summarizes into a new session, Ctrl+N cycles models while typing, `--worktree` sessions can be backgrounded with `&`. (https://docs.factory.ai/autonomy-and-safety/specification-mode; https://docs.factory.ai/autonomy-and-safety/auto-run; https://docs.factory.ai/droid-cli/cli-reference)

### Kiro (AWS)
- Spec-first: "the spec is source-of-truth and code is a build artifact"; steering files and hooks ("a trigger plus a glob filter plus an action"). The CLI adds `/tangent` (Ctrl+T): "Created a conversation checkpoint (↯)" … on exit the "Tangent conversation is discarded," with `/tangent tail` keeping the last exchange; `/spawn` "a new agent session that runs a task in parallel," `/delegate`, `/goal`, `/effort`, `/usage`, `/context`, `/compact`, `/todos`, `/checkpoint`; local-Whisper voice mode; ACP. (https://kiro.dev/docs/cli/experimental/tangent-mode/; https://kiro.dev/docs/reference/slash-commands/; https://kiro.dev/docs/cli/; https://www.developersdigest.tech/blog/aws-kiro-developer-guide-2026)

### GitHub Copilot CLI
- GA Feb 25 2026 for all Copilot subscribers. Shift+Tab cycles standard → plan → autopilot (autopilot runs "until it completes, hits a problem, you stop it, or a continuation limit is reached"); `/fleet` for parallel subagents; `&` delegates to the cloud agent; `#issue`/`#PR` pulls GitHub context; Ctrl+Q / Ctrl+Enter queues; Esc Esc or `/rewind` restores "without requiring git or discarding user edits"; auto-compaction "maintains infinite sessions"; the permission prompt explicitly warns that "approve TOOL for the rest of the running session" on `rm` would let it delete anything. Headless `--plan` + `--mode autopilot` arrived Aug 2026. (https://github.blog/changelog/2026-02-25-github-copilot-cli-is-now-generally-available/; https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli; devleader.ca)

### Charm Crush
- Ctrl+L switches models "while preserving context"; Ctrl+P palette; Ctrl+S sessions; LSPs "for additional context, just like you do"; per-tool `permissions allow`; `--yolo` ("Be very, very careful"); skills with `user-invocable: true`; Hyper provider with a free tier and zero data retention. (https://github.com/charmbracelet/crush)

### Goose (Block → aaif-goose)
- Modes `auto` / `approve` / `smart_approve` / `chat` via `/mode`; smart approve uses an LLM classifier to auto-run operations "that retrieve information without modifying state"; tool-level AlwaysAllow / AskBefore / NeverAllow; subagents "are disabled in manual approval, smart approval, and chat-only modes." (https://deepwiki.com/block/goose/6.2-permission-modes-and-tool-approval; https://github.com/block/goose/discussions/4324)

### Zed agent panel + ACP
- @-mentions cover files, directories, symbols, previous threads, skills, diagnostics, branch diffs and URLs; after edits the panel shows "which files, how many of them, and how many lines have been edited," and Review Changes lets you "accept or reject each individual change hunk, or the whole set"; a crosshair lets you "Follow the agent as it reads and edits files"; "Every time the model performs an edit, you should see a 'Restore Checkpoint' button"; a worktree picker isolates parallel threads; notifications when the agent is waiting. (https://zed.dev/docs/ai/agent-panel)
- ACP (Zed + JetBrains, Jan 2026) is JSON-RPC over stdio (HTTP/WebSocket remote), with session modes agents "MAY return … and the currently active mode" (e.g. ask / architect / code), `session/set_mode`, an "exit mode" tool pattern for plan → code, and an agent plan primitive (entries with content / priority / status, replaced wholesale on each update). The registry lists 40+ agents including Claude Agent, Codex CLI, Gemini CLI, Cursor, GitHub Copilot (preview), Goose, OpenCode, Pi, Kiro CLI, Factory Droid, Cline, Junie. (https://agentclientprotocol.com/overview/introduction; https://agentclientprotocol.com/protocol/session-modes; https://agentclientprotocol.com/protocol/agent-plan; https://agentclientprotocol.com/overview/agents; https://zed.dev/blog/acp-registry)

### Warp
- Open-sourced Apr 28 2026; Oz cloud orchestrator (Feb 10 2026). Diffs open in a built-in editor "grouped into clear hunks," Enter accepts, `R` refines "in natural language," `E` edits by hand; "modifications will not be applied to the files unless you explicitly accept them," unless the profile's "Apply Code Diffs" is "Always allow." Agent Profiles (Default / YOLO / Prod patterns) gate commands, edits and MCP; an Agent Management Panel tracks parallel conversations across tabs/panes/worktrees; voice and `warp` CLI. (https://docs.warp.dev/agent-platform/local-agents/code-diffs/; https://docs.warp.dev/agent-platform/getting-started/agents-in-warp/; https://www.warp.dev/newsroom/2026/4/28/warp-open-sources-its-agentic-development-environment)

### Devin (Cognition)
- Interactive planning: an "Initial Assessment" then a "Detailed Plan" with code citations you can click to "deep-link directly into the Devin IDE"; "By default, Devin will wait thirty seconds for feedback from you before automatically proceeding," unless you click "Wait for my approval." Confidence scores can be requested on Linear/Jira issues without starting sessions. 2026: Managed Devins (Mar 19), wake sleeping sessions on PR re-trigger (May 29), `/ask` and `/btw` slash commands in the message box (Jul 17), a model picker to "choose a capability, toggle Fusion, adjust speed" (Jul 24), `!ultra`/`!fast` from Slack, CLI `/resume`. (https://docs.devin.ai/work-with-devin/interactive-planning; https://docs.devin.ai/release-notes; https://docs.devin.ai/get-started/devin-intro)

### Jules (Google)
- Fully async: pick repo + branch, prompt, "Jules will generate a plan. You can review and approve it before any code changes are made," then "You are free to leave Jules while it is running" and get notified. Jules Tools CLI is scriptable (`jules remote new --repo … --session …`, `gh issue list | …`), with a TUI where "/remote give[s] you a dashboard view of tasks." (https://jules.google/docs; https://developers.googleblog.com/en/meet-jules-tools-a-command-line-companion-for-googles-async-coding-agent/)

---

## 3. Community signal: delighters and complaints (2026)

**Delighters repeatedly called out**
- Claude Code `/btw` side questions, session recap, PR badge, `claude agents` peek-and-reply; `/rewind` with "summarize from here." (docs above; Reddit round-up https://www.morphllm.com/claude-code-reddit)
- Codex's token efficiency and OS sandbox ("roughly 4x fewer tokens … for equivalent tasks," Terminal-Bench lead) and the Enter/Tab steer-queue split (https://www.firecrawl.dev/blog/claude-code-vs-codex; https://github.com/Yeachan-Heo/oh-my-codex/issues/2701 requesting the same Tab-queue in another harness).
- Pi's tree sessions and predictability; "the most token-efficient coding harness" (https://academy.kspl.tech/blog/2026-06-05-pi-agent-deep-dive-2026).
- Amp thread URLs for team knowledge, Oracle, voice with Puck (manual, chronicle).
- Zed's follow-the-agent crosshair and hunk-level review; Warp's Refine-in-natural-language on a diff.
- Devin's plan citations that deep-link into the IDE, and `&`-prefix cloud handoff in Cursor and Copilot.

**Complaints with evidence**
- Queue ≠ steer: Claude Code issues #30492/#64624; Codex #13595/#17285 (semantics changed under users twice).
- Unrebindable chords: Claude Code #43717 (double-Esc vs terminal vi-mode).
- Rewind trust: Claude Code #18516 (files "often don't revert"), #52209 (freeze); Cline and Claude Code both document bash-made changes as untracked.
- Compaction opacity: OpenCode #17557/#30680; Reddit post-compaction slowdowns; Claude Code added an explicit over-window warning in `/context` only in v2.1.214.
- Plan-mode dead-ends: Codex #24331/#10565.
- Approval fatigue → YOLO: "98.9% of analyzed Claude Code configurations contained zero deny rules" and NIST's security-fatigue findings (https://sysid.github.io/your-agent-has-root/); "by the fortieth 'Allow this command?' popup, developers have stopped reading them" (https://www.buildmvpfast.com/blog/approval-fatigue-agent-permission-ux-2026); a Claude Code `rm -rf tests/ patches/ plan/ ~/` that wiped a home directory, and the 2025 Replit/SaaStr production-DB deletion (same source); a March 2026 threat-detection rule for "Human Approval Fatigue Exploitation" (same search).
- Platform rug-pulls and quota surprises: Gemini CLI's June 18 cutoff and Antigravity's 20-request/day free tier with weekly lockouts; Antigravity 2.0 wiping configs; Claude Code rate-limit burn.
- Multi-agent visibility: Cursor worktree agents "disappeared"; Claude Code agent teams' documented "Task status can lag" and no resumption of in-process teammates.
- Over-scoping models: Opus 5 (Jul 24 2026) "tends to out-plan and out-execute the actual ask" (https://www.explainx.ai/blog/opus-5-over-engineering-reddit-reaction-august-2026).

---

## 4. Synthesis

### (a) Fifteen interaction patterns that are table stakes in 2026

A top-5 agent cannot lack these; each is present in at least four of the six most-used tools.

1. **Shift+Tab mode cycling with a visible status-bar indicator** (Claude Code, Gemini/agy, Copilot, Cursor, Droid; OpenCode uses Tab). Status text like `⏸ plan mode on` / `⏵⏵ accept edits on` is expected.
2. **A read-only plan mode with an explicit approval gate that sets the execution autonomy** ("Yes, and use auto mode" / "Yes, auto-accept edits" in Claude Code and Gemini; Droid's ExitSpecMode picks an autonomy level; ACP's "exit mode" tool formalizes it).
3. **Esc interrupts without destroying work; Esc Esc backtracks** (rewind menu in Claude Code/Gemini/Copilot, edit-previous-message in Codex/Amp).
4. **Queueing while the agent works, with the queue visible and retractable** (Claude Code lists entries above the input and Up pulls them back; pi Alt+Up; Codex Tab; Copilot Ctrl+Q; Cursor Enter).
5. **`@` fuzzy file/dir mention, `!` shell passthrough, and a `/` command menu with fuzzy matching** — universal across terminal agents.
6. **Multiline (Shift+Enter/Ctrl+J), Ctrl+G to `$EDITOR`, and Ctrl+V image paste**; vim keys are near-universal (Claude Code, Codex, Gemini, Cursor `/vim`, Aider `--vim`).
7. **Resume by `--continue` plus a searchable picker, with human names and auto-generated titles** (Claude Code, Codex, OpenCode, pi, Cursor, Kiro, Copilot).
8. **Forking/branching a conversation** (`/branch`, `/fork`, `codex exec fork`, pi `/fork`/`/clone`, OpenCode timeline fork, agy `/fork`).
9. **Context management triad: auto-compaction, `/compact [focus]`, and a `/context`/`/status` meter** (Claude Code, Codex, Copilot, Kiro, Droid, pi footer).
10. **Git-independent file checkpoints and rewind** (Claude Code, Cline shadow git, Cursor checkpoints, Gemini `/restore`, Copilot `/rewind`, Zed Restore Checkpoint, OpenCode `/undo`).
11. **Graduated permissions rather than binary YOLO**: allow/ask/deny rules, "allow for this session," sandboxed command tiers (Claude Code rules + auto classifier, Codex policy × sandbox, Droid Off/Low/Medium/High, Warp profiles, Goose smart approve).
12. **AGENTS.md (with CLAUDE.md/GEMINI.md fallback) plus lifecycle hooks** (Codex, OpenCode, Amp, pi, Droid, agy, Jules all read AGENTS.md; hooks in Claude Code, Codex, Cursor, Kiro, Droid, agy).
13. **Model and reasoning-effort switching mid-session with an on-screen indicator** (`/model`, Opt+P, Ctrl+L in Crush preserving context, Codex `xhigh`, Amp dial, pi border colour).
14. **Non-interactive `-p`/`exec` with streaming JSON and resumable session IDs, plus an SDK or protocol** (Claude Code `stream-json` + Agent SDK, `codex exec`, `opencode run --format json`/ACP, `amp -x --stream-json`, pi RPC, Copilot `-p`).
15. **Subagents that are visible and inspectable**, not silent: a panel or child-session navigation where you can open a transcript and message or stop the worker (Claude Code agent panel, OpenCode child sessions, agy `/agents`, Codex dashboard, Copilot `/fleet`).

### (b) Ten patterns that differentiate the leaders

1. **True mid-turn steering delivered at the next tool boundary**, distinct from queueing (pi Enter vs Alt+Enter; Amp Enter-twice vs Esc-twice; Codex Enter vs Tab; Cursor since Aug 19 2026). Claude Code's queue-within-turn is close but users still file steering requests.
2. **Classifier-mediated autonomy as the default** instead of prompts or YOLO (Claude Code auto mode with documented 3/20 fallbacks; Codex `--approve-for-me` and guardian subagent; Goose smart approve).
3. **Tree-structured history with branch summarization** (pi `/tree`), versus everyone else's linear transcript plus fork.
4. **A fleet view that triages by "needs input"** with peek-and-reply and PR state (Claude Code `claude agents`, Codex `codex agents` + `codex queue`, Cursor Agents Window, Warp panel, Amp web/mobile).
5. **Side-channel questions that do not pollute context** (Claude Code `/btw`, Kiro `/tangent` with `tail`, Devin `/btw`).
6. **Hunk-level review surfaces with refine-in-place** (Zed Review Changes, Warp `R` refine / `E` edit, Cursor timeline) — terminal agents mostly still dump diffs.
7. **One-keystroke cloud handoff from a local conversation** (`&` in Cursor and Copilot, Claude Code `/bg`, Amp orbs, Devin CLI → cloud).
8. **Durable, shareable thread URLs with search filters** as team memory (Amp; OpenCode `/share`).
9. **Effort as a first-class dial, separate from model** (Amp low/medium/high/ultra; Codex `minimal…xhigh` with Alt+,/.; Claude Code `/effort` + fast mode; pi thinking levels on Shift+Tab).
10. **Ambient situational awareness**: session recap on return, PR badge, prompt suggestions, plan citations that deep-link into code (Claude Code; Devin).

### (c) Five emerging patterns not yet standard

1. **ACP as the editor/agent contract and agents as headless servers** — 40+ agents registered, JetBrains + Zed as clients, `opencode serve`/`attach`, Codex remote TUI, Claude Code Remote Control. Mode and plan primitives are now protocol-level.
2. **Long-lived goals / subscriptions**: `/goal` in Cursor and Kiro, Codex "persistent goals by default" (May 2026), Claude Code goals that survive resume, Cursor "subscriptions" that wake on thread events, Devin wake-on-retrigger, OpenCode's Goal Mode PRD.
3. **Agent-to-agent messaging the user can see and address**: Claude Code cross-session `SendMessage` and `@session` mentions, Amp agents that "spawn other agents, message them, and exchange files," Devin Managed Devins, Claude Code agent teams' mailbox.
4. **Voice as a first-class channel**: Claude Code voice dictation, Amp realtime voice with Puck, Kiro local Whisper, Warp and Copilot voice.
5. **User-programmable harnesses**: pi extensions that let the agent modify its own harness, Amp plugins that register tools, agent modes and `tool.call` permission hooks, OpenCode's TUI plugin runtime PRD, Claude Code plugins/skills marketplaces.

### (d) UX mistakes to avoid (each with evidence)

1. **Hardcoded chords that collide with the terminal or vim.** Claude Code #43717: double-Esc "cannot be rebound or disabled," breaking zsh vi-mode. Make every chord rebindable from day one.
2. **Blurring queue and steer, or changing their semantics silently.** Codex #13595 and #17285; Claude Code #30492/#64624. Two explicit keys (pi's Enter/Alt+Enter) and a visible queue are the fix.
3. **Disabling the interrupt when state exists.** Claude Code #16905: Esc stopped working with queued messages or background tasks. Esc must always work.
4. **Rewind that silently under-delivers.** Claude Code #18516; both Claude Code and Cline document that bash-made changes are untracked. Show what is and isn't restorable before the user commits (Claude Code's "Restored the code, but skipped N files" warning is the right instinct).
5. **Opaque or broken compaction.** OpenCode #17557 (`/compact` increases context), #30680 (auto-compaction loop); Reddit slowdowns after repeated compactions. Show the meter, show the summary, let the user guide it (pi's structured template, Claude Code's "add context (optional)").
6. **Plan-mode dead-ends.** Codex #24331/#10565 ("stuck in plan mode"). Shift+Tab must always exit; the approval prompt must have a "keep planning" path.
7. **Prompt fatigue that pushes users to YOLO.** 98.9% of analyzed configs had zero deny rules; `rm -rf … ~/` and Replit incidents. Use graduated tiers and a classifier, and warn explicitly on session-wide approvals (Copilot's `rm` warning).
8. **Undiscoverable power features.** OpenCode fork keybind defaults to `none` (#12580); Reddit: users "do not discover [/compact] until months in." Ship a `?` panel, keybind tooltips (OpenCode added them), and `/powerup`-style lessons.
9. **Breaking the harness under users.** Gemini CLI's 30-day sunset "without 1:1 feature parity"; Antigravity 2.0 wiping configs; Zechner's critique that feature velocity made Claude Code's "behavior … change." Stability of semantics is itself a feature.
10. **Quota surprises in the compose loop.** Antigravity's weekly lockout after ~25 minutes; Claude Code's rate-limit burn. Surface usage (`/usage`, footer cost) before the wall, not after.
11. **Multi-agent visibility gaps.** Cursor worktree agents disappearing; Claude Code's own limitations list ("Task status can lag," idle rows hiding, no resumption of in-process teammates). Every worker needs a persistent, addressable row.
12. **Letting the model over-scope.** Opus 5 over-engineering reports; the antidote is the plan gate plus "boundaries you state in conversation" that the classifier enforces (Claude Code docs).

---

## 5. Source index (primary unless noted)

- Claude Code: interactive-mode, permission-modes, sessions, checkpointing, sub-agents, agent-teams, agent-view, common-workflows at https://code.claude.com/docs/en/…; changelog digest https://www.gradually.ai/en/changelogs/claude-code/ (mirror of official); issues #43717, #64624, #30492, #52209, #18516, #16905 at https://github.com/anthropics/claude-code/issues/…
- Codex: https://learn.chatgpt.com/docs/changelog (official, redirected from developers.openai.com); README https://github.com/openai/codex; guides https://blakecrosley.com/guides/codex, https://codex.danielvaughan.com/2026/03/27/codex-cli-in-2026-whats-new/, https://aiopsschool.com/blog/complete-codex-slash-commands-and-cli-options-guide-updated-april-2026/ (third-party); issues #13595, #17285, #24331, #18712, #26294.
- Gemini/Antigravity: https://geminicli.com/docs/…; https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/; The Register 2026-05-20; https://github.com/jqueryscript/antigravity-cli-cheatsheet; dev.to hands-on; developersdigest and chatforest reviews (third-party).
- OpenCode: https://opencode.ai/docs/ (keybinds, tui, agents, cli); issues #12580, #17557, #30680, #27339 at https://github.com/anomalyco/opencode.
- Amp: https://ampcode.com/manual; https://ampcode.com/chronicle.
- Pi: https://pi.dev/docs/latest/{usage,sessions,keybindings,compaction}; https://newsletter.pragmaticengineer.com/p/building-pi-and-what-makes-self-modifying; explainx/kspl (third-party).
- Cursor: https://cursor.com/docs/cli/overview, …/reference/slash-commands, https://cursor.com/docs/agent/overview, https://cursor.com/changelog; forum threads 165623, 157668.
- Aider: https://aider.chat/docs/usage/{modes,commands}.html; HISTORY.
- Cline: https://docs.cline.bot/features/{plan-and-act,checkpoints,auto-approve}; https://docs.cline.bot/cline-cli/overview.
- Factory: https://docs.factory.ai/autonomy-and-safety/{specification-mode,auto-run}; https://docs.factory.ai/droid-cli/cli-reference.
- Kiro: https://kiro.dev/docs/cli/, …/cli/chat/, …/reference/slash-commands/, …/cli/experimental/tangent-mode/.
- Copilot CLI: https://github.blog/changelog/2026-02-25-github-copilot-cli-is-now-generally-available/; https://docs.github.com/en/copilot/how-tos/use-copilot-agents/use-copilot-cli; devleader.ca 2026-07-17 (third-party).
- Crush: https://github.com/charmbracelet/crush. Goose: deepwiki 6.2 + discussion #4324.
- Zed/ACP: https://zed.dev/docs/ai/agent-panel; https://agentclientprotocol.com/{overview/introduction,protocol/session-modes,protocol/agent-plan,overview/agents}; https://zed.dev/blog/acp-registry.
- Warp: https://docs.warp.dev/agent-platform/local-agents/code-diffs/; https://docs.warp.dev/agent-platform/getting-started/agents-in-warp/; newsroom 2026-04-28.
- Devin: https://docs.devin.ai/work-with-devin/interactive-planning; https://docs.devin.ai/release-notes. Jules: https://jules.google/docs; Google Developers Blog (Jules Tools).
- Adoption: https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/. Approval fatigue: https://sysid.github.io/your-agent-has-root/; https://www.buildmvpfast.com/blog/approval-fatigue-agent-permission-ux-2026.

**Unverified / caveats:** pi-mono star count (repo moved); "up to 10 parallel Devin sessions" and "Jules GA at I/O 2026" come from third-party roundups; Cursor 3.2 worktree date and Codex TUI key table are from third-party guides consistent with official changelogs; Antigravity shortcut names are from a community cheatsheet.
