# R2 — Display & Rendering in Developer Coding Agents (state as of 2026-08-22)

Research lens: what the user *sees* in the best coding agents — transcript layout, tool-call display, diffs, status/footer, progress structures, widgets, performance, and the public debates around them. Every non-obvious claim carries a URL; anything I could not verify against a primary source is marked **unverified**. Products covered: Claude Code, Codex CLI, Gemini CLI, OpenCode, Amp, Pi, Cursor CLI, Aider, Cline, Factory Droid, Kiro CLI, Charm Crush, Goose, Zed agent panel, Warp. Libraries: ratatui, Ink, Bubble Tea, OpenTUI, pi-tui.

Two corrections to the brief's premise, both important:

1. **Claude Code did not move away from full-screen — it moved toward it.** Fullscreen (alternate-screen, virtualized) rendering is a "research preview" that is now the *default* for anyone who first used Claude Code on or after May 6, 2026 (or whose first launch was v2.1.239+ without feature-flag fetching); earlier users keep the classic scrollback renderer unless they run `/tui fullscreen`. Source: https://code.claude.com/docs/en/fullscreen
2. **Codex CLI is the one keeping native scrollback.** Its ratatui TUI runs an *inline viewport* and commits finalized history into the terminal's own scrollback with scroll-region escape sequences ("Codex uses the terminal scrollback itself for finalized chat history, so inserting a history cell is an escape-sequence operation rather than a normal ratatui render"). Alt-screen is used for overlays or when `tui.alternate_screen = "always"`. Sources: https://raw.githubusercontent.com/openai/codex/main/codex-rs/tui/src/insert_history.rs , https://learn.chatgpt.com/docs/config-file/config-reference

So the field has split: **Claude Code, OpenCode, Crush, Droid (and optionally Pi, Gemini) own the screen; Codex, Kiro, Cursor CLI, Warp CLI, Goose, Aider, and default Pi/Gemini print into the terminal's scrollback.**

---

## 1. Rendering architecture and scrollback strategy

| Product | Stack | Screen model (default) | Synchronized output (DEC 2026) | Mouse |
|---|---|---|---|---|
| Claude Code | React + custom renderer (scene graph → layout → raster → diff → ANSI, per an Anthropic engineer; originally Ink) — https://news.ycombinator.com/item?id=46699072 | Classic: inline, native scrollback. Fullscreen: alt-screen, only visible messages in render tree, "memory stays constant regardless of conversation length" — https://code.claude.com/docs/en/fullscreen | Probes terminal at startup; `CLAUDE_CODE_FORCE_SYNC_OUTPUT=1` for terminals it can't detect (e.g., Emacs eat); tmux ≤3.6 lacks it — https://code.claude.com/docs/en/terminal-config | Fullscreen captures SGR mouse: click-to-expand, click menus, drag-select (copy on release), wheel; `CLAUDE_CODE_DISABLE_MOUSE`, `…_DISABLE_MOUSE_CLICKS` opt-outs |
| Codex CLI | Rust, ratatui (0.30.2 as of Aug 2026 — https://releasebot.io/updates/openai/codex) | Inline viewport + history into native scrollback via scroll regions; `FullScreen` insertion mode for Zellij; `tui.alternate_screen = auto\|always\|never` ("auto skips it in Zellij to preserve scrollback") — https://raw.githubusercontent.com/openai/codex/main/codex-rs/tui/src/tui.rs | Draws wrapped in `stdout().sync_update(...)` (crossterm synchronized update) — tui.rs | Copy/paste with mouse support; no "cut" (https://github.com/openai/codex/issues/9132) |
| Gemini CLI | Ink (React) | Inline by default; `ui.useAlternateBuffer` default **false** (reverted in 0.17.1, Nov 22 2025, until "copying on all terminals without requiring Ctrl+S" and scroll responsiveness are fixed) — https://github.com/google-gemini/gemini-cli/discussions/13632 ; `ui.incrementalRendering` (default true) "only supported when useAlternateBuffer is enabled"; experimental `ui.terminalBuffer` "new terminal buffer architecture" — https://geminicli.com/docs/reference/configuration/ | Not documented (**unverified**) | `Ctrl+S` toggles mouse mode; F9 copy mode in alt-buffer — https://geminicli.com/docs/reference/keyboard-shortcuts/ |
| OpenCode | TypeScript + Solid on OpenTUI (Zig core via Bun FFI) — https://github.com/anomalyco/opentui | OpenTUI renderer default is alternate screen; also "main screen" and "split-footer" modes where captured stdout becomes "ordered scrollback commits above the footer" — https://opentui.com/docs/core-concepts/renderer/ | Not documented (**unverified**) | `mouse: true` default; disabling "preserves the terminal's native mouse selection/scrolling" — https://opencode.ai/docs/tui/ |
| Pi | pi-tui (own differential renderer) | `tuiMode: "regular"` = `TuiMainScreen` ("renders into the main terminal buffer and preserves terminal scrollback"); experimental `"fullscreen"` = `TuiAltScreen` — https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/tui/README.md , https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/coding-agent/docs/settings.md | Both renderers wrap updates in `\x1b[?2026h … \x1b[?2026l` | — |
| Kiro CLI | Custom TUI (framework **unverified**) | Top-to-bottom flow preserved ("Terminals print from top to bottom, and we wanted to preserve that natural flow"), input omnipresent — https://kiro.dev/blog/new-look-for-cli/ | "Terminals that support synchronized output get flicker-free updates" — https://kiro.dev/docs/cli/terminal-ui/ | — |
| Crush | Go, Bubble Tea v2 ("Cursed Renderer", ncurses-style cell diffing, uses mode 2026) — https://deepwiki.com/charmbracelet/crush , https://github.com/charmbracelet/bubbletea/releases/tag/v2.0.0 | Full-screen app with sidebar; `compact_mode` — https://github.com/charmbracelet/crush/blob/main/internal/config/config.go | Via Bubble Tea v2 | Yes (wiki has a "Mouse Interaction" section) |
| Amp CLI ("Neo", GA May 27 2026) | Rebuilt; framework **unverified** | **unverified** | **unverified** | `amp.terminal.copyOnSelect` default true — https://ampcode.com/manual |
| Cursor CLI | **unverified** | Inline; "Full repaints render only recent turns (`/full-conversation` to opt out)" — https://cursor.com/docs/cli/changelog | **unverified** | — |
| Goose CLI | Rust; prints via `bat` — https://deepwiki.com/block/goose/3.2-command-line-interface | Inline streaming; separate TUI diff viewer | **unverified** | — |
| Warp | Rust, GPU-rendered terminal with typed block list | Agent CLI: "scrollable transcript directly in your terminal" — https://docs.warp.dev/agents/cli/agent-conversations/ ; desktop app: two-level virtualization — https://www.warp.dev/blog/block-model-behind-warps-agentic-development-environment | n/a (own renderer) | native |
| Aider | Python, Rich + prompt_toolkit | Inline; `--pretty`/`--stream` default on — https://aider.chat/docs/config/options.html | n/a | native |

Library notes: ratatui 0.29 added the `scrolling-regions` feature so `Terminal::insert_before` no longer flickers (https://ratatui.rs/highlights/v029/) — this is the mechanism Codex builds on. Ink 7.0 (Apr 9 2026) added an alternate-screen mode and `useEffectEvent`-based input; `maxFps` defaults to 30; `incrementalRendering` is experimental; the docs warn terminals "can't rerender output taller than the terminal window" (https://www.heise.de/en/news/React-in-the-Terminal-Ink-7-0-fundamentally-revises-input-handling-11249949.html , https://raw.githubusercontent.com/vadimdemedes/ink/master/readme.md). OpenTUI frames are "demand-driven" (`requestRender()` schedules one-shot frames) with a `maxFps` cap (https://opentui.com/docs/core-concepts/renderer/).

**The Claude Code flicker saga (timeline).** Ink-style full clear-and-redraw caused tearing whenever output exceeded the viewport; a renderer rewrite ("only ~1/3 of sessions see at least a flicker") and DEC-2026 patches to VS Code's terminal and tmux followed; a PTY proxy called Claude Chill hit HN in ~Jan 2026 (192 points, 148 comments) with commenters calling Codex "smooth as butter" (https://news.ycombinator.com/item?id=46699072). v2.1.89 (Apr 1 2026) enabled "flicker-free alt-screen rendering with virtualized scrollback" by default and immediately drew a regression report — the banner re-printed three times and scrollback was "destroyed" — closed as duplicate of #41814 (https://github.com/anthropics/claude-code/issues/41965). The May 2026 default switch came with a startup dialog (offered at most three launches) and automatic fallback after two failed fullscreen starts (v2.1.236+) (https://code.claude.com/docs/en/fullscreen).

**What fullscreen costs.** `Cmd+F`/tmux search no longer see the conversation; the fix is `Ctrl+O` → `[` ("writes the full conversation into your terminal's native scrollback buffer, with all tool output expanded") or `v` to open it in `$EDITOR`. Native selection needs a modifier (`Fn` Terminal.app, `Option` iTerm2, `Shift` elsewhere). Open complaints: silent mouse capture breaking GNOME Terminal copy/paste (https://github.com/anthropics/claude-code/issues/72681 , Jul 2026) and chunky, non-proportional scrolling in Terminal.app (https://github.com/anthropics/claude-code/issues/56546 , May 2026).

---

## 2. Transcript layout, streaming, markdown, code blocks

**Speaker distinction.** Claude Code colors the `You`/`Claude` labels (`briefLabelYou`, `briefLabelClaude` tokens) and, in fullscreen, paints a background behind user messages (`userMessageBackground`), `!` shell entries and `#` memory entries get their own backgrounds (https://code.claude.com/docs/en/terminal-config). In screen-reader mode every message is prefixed `you:`, `claude:`, `thinking:`, `tool:`, `tool error:`, `error:`, `warning:`, `Permission Required:` — a good canonical taxonomy (https://code.claude.com/docs/en/accessibility). Crush caps user messages at 120 columns and renders them through the same Glamour/Chroma markdown path as assistant text (https://deepwiki.com/charmbracelet/crush/5.3-message-rendering). Aider uses distinct colors per stream (`--user-input-color` #00cc00, `--assistant-output-color` #0088ff, tool error/warning colors) (https://aider.chat/docs/config/options.html). Gemini can show the model name per turn (`ui.showModelInfoInChat`, default false) and line numbers in chat (`ui.showLineNumbers`, default true) (https://geminicli.com/docs/reference/configuration/).

**Streaming markdown.** The hard problem is rendering markdown while it is still arriving. Goose's `MarkdownBuffer` "tracks open markdown constructs (bold, code blocks, links, etc.) and only flushes content to the terminal when constructs are complete" — fixing the earlier "partial, broken output" (https://github.com/block/goose/issues/7223 , https://deepwiki.com/block/goose/3.2-command-line-interface). Codex keeps an `active_cell` that streams in the viewport and commits to history at boundary events — which is also why the Ctrl+T transcript briefly omits in-flight tool groups (https://github.com/openai/codex/issues/7998). Claude Code recently fixed "long responses partly disappearing while streaming and being printed twice" (2.1.230) and "nested markdown list items misaligning at depth 3+" (2.1.235) (https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md).

**Tables, math, diagrams.** Cursor CLI wraps markdown tables to terminal width with correct CJK/emoji alignment and renders LaTeX as Unicode (Aug 2026) (https://cursor.com/docs/cli/changelog). Droid converts inline/display TeX to Unicode and renders Mermaid as ASCII flowcharts/sequence/state/class/ER diagrams in-terminal (https://docs.factory.ai/droid-cli/cli-reference); Cursor keeps Mermaid diagrams "drawn after a turn finishes" (https://cursor.com/docs/cli/changelog). Warp CLI shows Mermaid as source and images as alt text (https://docs.warp.dev/agents/cli/agent-conversations/). Claude Code screen-reader mode turns tables into `Header: value` sentences.

**Syntax highlighters (verified where stated).**

| Product | Highlighter | Theme source |
|---|---|---|
| Codex CLI | syntect | 32 bundled `.tmTheme`s; custom in `~/.codex/themes/`; `/theme` picker with live preview — https://codex.danielvaughan.com/2026/05/05/codex-cli-tui-customisation-keymaps-themes-status-lines/ |
| Crush | Chroma (via Glamour) | Lip Gloss styles — https://deepwiki.com/charmbracelet/crush/5.3-message-rendering |
| Goose | `bat` library | light/dark/ansi — https://deepwiki.com/block/goose/3.2-command-line-interface |
| Aider | Pygments via Rich | `--code-theme` (monokai, solarized-*, any Pygments style) — https://aider.chat/docs/config/options.html |
| Claude Code | **unverified** library; `Ctrl+T` inside `/theme` toggles code-block highlighting — https://code.claude.com/docs/en/interactive-mode | JSON themes with diff/word-diff tokens |
| Cursor CLI | **unverified**; caps "very long lines … before syntax highlighting, so minified files can't stall the UI" | auto light/dark repaint — https://cursor.com/docs/cli/changelog |
| Gemini CLI, OpenCode, Kiro, Pi, Amp, Droid | **unverified** | Gemini: 17 built-in themes, custom via `customThemes` — https://geminicli.com/docs/cli/themes/ |

**Copy fidelity.** Codex's `/raw` (Alt+R, `tui.raw_output_mode`) strips "decorative left padding/gutter and Codex-inserted line wrapping" so the terminal soft-wraps and selections copy as logical lines — motivated by paragraphs copying "as separate lines" and commands gaining "unwanted line breaks" (merged May 5 2026, https://github.com/openai/codex/pull/20819). Codex's Ctrl+O copies the latest response (https://learn.chatgpt.com/docs/cli/slash-commands); Claude Code's `/btw` overlay offers `c` to copy raw Markdown because mouse selection "captures the hard-wrapped terminal rendering" (https://code.claude.com/docs/en/interactive-mode). Cursor CLI stopped injecting zero-width spaces into long shell output so copied paths stay intact (Aug 2026).

---

## 3. Tool-call display

| Product | Default collapsed form | Expand / verbose | Grouping | Long output policy |
|---|---|---|---|---|
| Claude Code | One-line tool row with truncated result; MCP calls "collapse to a single line like 'Called slack 3 times'" | `Ctrl+O` transcript viewer (adds timestamp + model per assistant message); classic renderer `Ctrl+E` "show all"; fullscreen: click a collapsed result to expand; `/focus` shows only last prompt + one-line tool summary with edit diffstats + final response — https://code.claude.com/docs/en/interactive-mode , https://code.claude.com/docs/en/commands | `/focus` "counts subagents launched in the turn and collapses completed background-task notifications into a single count" | Bash output >30k chars is middle-truncated; oversized output persisted to disk (up to 64MB) with a ~5KB preview + path; `BASH_MAX_OUTPUT_LENGTH` — https://github.com/anthropics/claude-code/issues/19901 |
| Codex CLI | Grouped "• Exploring / • Explored" cell listing `Read …`, `Search …`, `List …`; "Edited …" block with filename; exec cells show head/tail with "… +N lines" | `Ctrl+T` transcript overlay (full output, ephemeral); inline hint "ctrl + t to view transcript" on truncated exec output (Apr 9 2026) — https://github.com/openai/codex/pull/17076 , https://github.com/openai/codex/issues/7998 | Filesystem exploration coalesced into one in-flight cell | Head/tail truncation before wrap, then row-budget truncation after wrap; overlay does not wrap very long lines — https://github.com/openai/codex/issues/7454 |
| Gemini CLI | `ui.compactToolOutput` (now default true): `DenseToolMessage` one-liners "status, description, and diff stats" e.g. `→ Returned 5 lines of text`; grep/ls/read_many_files return structured results; shell tools keep "their own bordered boxes" | `Ctrl+O` expands/collapses blocks (non-alt-buffer) or all tool results of last turn; click status indicator in alt buffer — https://github.com/google-gemini/gemini-cli/pull/20974 | `ToolGroupMessage` "densely packs consecutive compact outputs" | `tools.truncateToolOutputThreshold` default 40000 chars — https://geminicli.com/docs/reference/configuration/ |
| Kiro CLI | Per-tool component with descriptive title, spinner, ✓/✗/⏸ icons, parameter summaries | `Ctrl+O` toggles output; thinking collapses to a tail view | Dedicated components for shell, file ops, grep, glob, code intelligence | Shell: live line-by-line stream; long output "head + tail view"; progress bars for long MCP ops — https://kiro.dev/docs/cli/terminal-ui/ |
| Cursor CLI | Tool rows; "Completed tool rows no longer disappear for a frame" (Jul 2026); "hidden tool-call groups no longer leave blank lines" | — | Tool-call groups | "Long shell output truncates from the top. You see the latest output of a streaming command, not the oldest" (Jun 2026) — https://cursor.com/docs/cli/changelog |
| Warp CLI | "one-line status row with a state glyph and a label … like 'reading a file'" | Diffs expand during approval (`E`) | Agent-run commands become "compact summaries inside the conversation view, expandable on demand" | "Long code blocks are truncated to keep the transcript responsive" — https://docs.warp.dev/agents/cli/agent-conversations/ |
| Crush | Per-tool renderers routed by name (bash with spinner/background jobs, view/write/edit, glob/grep/ls, agent as nested tree) with status badge (awaiting permission, running, success, error, canceled) | Expansion per tool; thinking: collapsed 10 lines → tail 200 lines → full | Agent/agentic_fetch nest as trees | Output truncation with expand — https://deepwiki.com/charmbracelet/crush/5.3-message-rendering |
| Goose | "Group consecutive tool calls into one summarized chain card" (`GOOSE_DISABLE_TOOL_CALL_SUMMARY`) | `--debug` / `GOOSE_SHOW_FULL_OUTPUT` | Chain cards | Large tool responses truncated by default — https://github.com/aaif-goose/goose/releases/tag/v1.36.0 , https://deepwiki.com/block/goose/3.2-command-line-interface |
| Amp | Collapsed thinking/tool blocks | `Alt+T`; `amp.terminal.detailsExpandedByDefault` (false) — https://ampcode.com/manual | — | — |
| Pi | Collapsed tool output | `Ctrl+O` tool output, `Ctrl+T` thinking — https://www.npmjs.com/package/@mariozechner/pi-coding-agent | — | — |
| OpenCode | `/details` toggles tool execution details; `/thinking` toggles reasoning blocks — https://opencode.ai/docs/tui/ | — | — | — |
| Droid | `Ctrl+O` "detailed transcript view (full message details)"; `Alt+E` approval details view — https://docs.factory.ai/droid-cli/cli-reference | — | — | — |
| Zed | Edit/terminal cards; `expand_edit_card`, `expand_terminal_card`, `thinking_display: "always_collapsed"` — https://github.com/zed-industries/zed/discussions/58333 | Click cards; "Review Changes" | Proposal to collapse finished turns into Thinking / Commands run / Files edited sections — https://github.com/zed-industries/zed/discussions/58314 | ACP (external agent) blocks not collapsible by default (open request) |

Note the near-universal convergence on **`Ctrl+O` = show more** (Claude Code, Gemini, Kiro, Pi, Droid) — except Codex (`Ctrl+T`) and Amp (`Alt+T`, since Ctrl+O is its command palette). Claude Code's `Ctrl+O` is a *transcript mode*, not a live verbose toggle, which users keep filing as a bug (https://github.com/anthropics/claude-code/issues/14511 , https://github.com/anthropics/claude-code/issues/54719).

---

## 4. Diff display

| Product | Format | Highlighting | Review affordances | Post-turn summary |
|---|---|---|---|---|
| Claude Code | Unified, in-terminal, with line numbers and +/- markers even in narrow layouts (2.1.212 fix) | Word-level: theme tokens `diffAddedWord`/`diffRemovedWord`, plus dimmed context backgrounds — https://code.claude.com/docs/en/terminal-config | `/diff`: interactive viewer; ←/→ switch between current git diff and individual Claude turns, ↑/↓ files, Enter opens file diff, auto-refreshes on external git changes — https://code.claude.com/docs/en/commands ; IDE extension opens diff tabs | `/focus` one-line tool summary "with edit diffstats"; `cost.total_lines_added/removed` exposed to status line |
| Codex CLI | Unified "Edited …" cells in transcript; `/diff` "Show the Git diff, including files Git isn't tracking yet" scrolled in-CLI | syntect; diffs "always render with bright green/red backgrounds" ignoring `.tmTheme` overrides (bug since 0.105) — https://codex.danielvaughan.com/2026/03/28/codex-cli-feature-flags-tui-tuning/ | `Ctrl+T` to read long diffs while an approval is pending (regressed 0.128–0.130) — https://github.com/openai/codex/issues/22263 | Diff summary with file paths (paths with spaces not clickable — https://github.com/openai/codex/issues/7477) |
| Cursor CLI | "git-style unified diffs with context lines, accurate new-file diffs"; edits render "borderless (an `Editing`/`Edited` header plus the diff)" | Character-level highlights "legible on light terminal themes" | `/changes` (`Ctrl+R`) review view with Session tab, `i` to add instructions, ←/→ switch files, `o`/`O` open in editor, zen toggle — https://cursor.com/docs/cli/changelog | — |
| Crush | `diff_mode: "unified" \| "split"` | Chroma | Apply/reject inline | — |
| OpenCode | `diff_style: "auto"` (side-by-side when width allows) or `"stacked"` — https://opencode.ai/docs/tui/ | **unverified** | — | — |
| Zed | Multibuffer "Review Changes" tab (`Ctrl+Shift+R`) with per-hunk keep/reject; **split diff view** added 1.1.5 (May 6 2026); inline hunks via `agent.single_file_review` — https://zed.dev/docs/ai/agent-panel , https://zed.dev/releases/stable/1.1.5 | Editor highlighting | Per-hunk accept/reject; follow-the-agent crosshair | Panel shows "which files, how many of them, and how many lines have been edited" |
| Cline | Inline red/green decorations in the live editor before writing to disk; Approve/Reject under each proposal — https://docs.cline.bot/usage/ide | Editor | Checkpoints: Compare / Restore per step | Task header tokens/cost; v4.0.0 regression lost the diff view — https://github.com/cline/cline/issues/11934 |
| Warp | Per-file headers "showing the action taken and the lines added or removed"; multi-file nests under collapsible summary headers | — | "expand while the agent waits for your approval, then collapse to their headers once the edits are applied"; `E` expands all — https://docs.warp.dev/agents/cli/agent-conversations/ | Header +N/−M |
| Kiro | "line-by-line diffs" integrated into the unified flow — https://kiro.dev/blog/new-look-for-cli/ | — | — | — |
| Goose | Separate TUI diff viewer (v1.36.0) | `bat` | — | — |
| Amp | "Diffs" (Jun 16 2026): "review and stage changes directly in Amp" — https://ampcode.com/news (surface **unverified**: CLI vs web) | — | — | — |
| Gemini CLI | Compact diff summary line per edit; theme `background.diff.added/removed` — https://geminicli.com/docs/cli/themes/ | — | Click status indicator to expand diff (alt buffer) | — |
| Aider | `--show-diffs` on commit only; edits land via git commits | Pygments | — | Commit hash per change |

Known sore spot: Claude Code's Edit preview sometimes renders "the entire new file content as one large green block" with no removals or context (https://github.com/anthropics/claude-code/issues/59078 , May 2026, closed as duplicate).

---

## 5. Status line, footer, notifications, thinking

| Product | Footer / status contents | Thinking display | Notifications |
|---|---|---|---|
| Claude Code | Custom `statusLine` script fed JSON: model, effort, context `used_percentage`, cost USD, lines added/removed, 5h/7d rate limits, vim mode, PR badge, worktree; debounced 300ms, runs on new message/compact/mode change; multi-line + ANSI + OSC 8 allowed; renders "in its own row above the built-in footer badges"; notifications and verbose token counter share the row — https://code.claude.com/docs/en/statusline . Built-in footer: permission-mode indicator (border colors per mode), clickable PR/MR badge with review-state underline, `esc to interrupt`, `? for shortcuts`; `/context` "colored grid"; `/usage` meter — https://code.claude.com/docs/en/interactive-mode | `Option+T` toggles extended thinking; `thinking:` label in a11y mode; shimmer spinner with `activeForm` text | Desktop notifications only in Ghostty/Kitty/iTerm2 by default; `preferredNotifChannel` = `terminal_bell`, `iterm2_with_bell`, …; tab title `🔔 Claude Code - project ⏸` (community-documented); OSC 133 turn markers; `terminalProgressBarEnabled` — https://code.claude.com/docs/en/terminal-config |
| Codex CLI | `tui.status_line` ordered items (docs list `model`, `approval`, `context_usage`, `session_id`, `sandbox`, `cwd`, `spinner`; the `/statusline` picker now also offers tokens, git branch, hostname, thread title); rate limits as progress bars ("5h limit", "Weekly limit"); `StatusIndicatorWidget` above composer: animated "Working", elapsed "4m 07s", "esc to interrupt", `└` detail lines — https://deepwiki.com/openai/codex/4.1.4-status-line-and-footer-rendering ; `tui.terminal_title` default `["spinner","project"]` with Braille spinner at 100ms | Reasoning streams as commentary cells | `tui.notifications` (osc9 / bel / auto), `notification_condition: unfocused\|always` — https://learn.chatgpt.com/docs/config-file/config-reference |
| Gemini CLI | `ui.footer.items` with optional label line; context percentage hidden by default (`hideContextPercentage: true`); `dynamicWindowTitle` icons "Ready: ◇, Action Required: ✋, Working: ✦"; `showStatusInTitle` puts model thoughts in the title; `loadingPhrases` default off — https://geminicli.com/docs/reference/configuration/ | `ui.inlineThinkingMode: off\|full` | Title icons |
| Pi | "Working directory, session name, total token/cache usage (↑ input, ↓ output, R cache read, W cache write, CH cache hit rate), cost, context usage, current model" — https://www.npmjs.com/package/@mariozechner/pi-coding-agent | `Ctrl+T` | — |
| Kiro | Status bar "grows in real time"; tab/title progress indicator (streaming / pending approval / error); `Ctrl+X` activity tray — https://kiro.dev/docs/cli/terminal-ui/ | Inline above response, tail view, `chat.showThinking` | Title |
| Cursor CLI | "Working status pinned": progress, token counts, optional elapsed time; footer cwd, git branch, clickable PR; custom `statusLine` with live token data; `/context` breakdown — https://cursor.com/docs/cli/changelog | Thinking blocks render markdown | Desktop notifications incl. tmux/screen passthrough |
| Amp | `amp.showCosts`; thread sidebar `Ctrl+\` | `Alt+T` | `amp.notifications.enabled` sound/bell — https://ampcode.com/manual |
| Zed | Token count "near the profile selector"; model selector with provider logos | Collapsed "Thought process" (regressed to expanded Mar 2026 — https://github.com/zed-industries/zed/issues/52536) | `notify_when_agent_waiting`, `play_sound_when_agent_done` — https://zed.dev/docs/ai/agent-panel |
| Cline | Task header with tokens, cost, context-window progress bar — https://cline.bot/blog/understanding-the-new-context-window-progress-bar-in-cline | — | — |
| Crush / OpenCode / Aider | Crush `notifications: auto\|native\|osc\|bell\|disabled`; OpenCode `attention` sound/volume; Aider `--notifications` bell | — | — |

---

## 6. Progress structures: todos, plans, subagents

- **Claude Code:** `Ctrl+T` toggles the task checklist (max five rows; "not the background-task view"); empty on Opus 4.8 / Sonnet 5 / Fable 5 unless `CLAUDE_CODE_ENABLE_TODO_TOOLS=1`; `/tasks` lists background shells and subagents; subagents get one of eight named colors and a row `name · description · token count` that `subagentStatusLine` can re-render; `Ctrl+B` backgrounds a task, `Ctrl+X Ctrl+K` stops all subagents — https://code.claude.com/docs/en/interactive-mode , https://code.claude.com/docs/en/statusline . Users want more than five tasks visible (https://github.com/anthropics/claude-code/issues/54355).
- **Codex:** `update_plan` task list is not re-rendered while idle (https://github.com/openai/codex/issues/18920); `/plan` mode with Enter vs Tab mechanics and inline editing (https://codex.danielvaughan.com/2026/04/08/plan-mode-mechanics/).
- **Gemini:** `Ctrl+T` "Toggle the full TODO list"; `Ctrl+X` opens a displayed plan in an external editor for comments (https://geminicli.com/docs/reference/keyboard-shortcuts/).
- **Warp CLI:** plan documents with status headers; glyphs `◌` pending, `●` in progress, `✓` done; `Ctrl+Shift+P` expands/collapses the latest plan.
- **Amp:** Thread Map (Dec 11 2025) — "a birdseye view of the threads you forked, handed off, and referenced" (https://ampcode.com/news).
- **Kiro:** `Ctrl+G` crew monitor for multi-agent work; **Droid:** `Ctrl+T` Mission Control overlay for orchestrator sessions; **Crush:** agent tool calls render as nested trees with animation propagated recursively; **Cursor:** background task viewer with arrow-key navigation and kill shortcuts (Jun 2026).

---

## 7. Interactive widgets

**Approval prompts.** Claude Code: Yes / "Yes, and don't ask again" (offered only "when the prompt can show you everything they would allow") / No; `Tab` on Yes/No opens a comment field sent to Claude as reason; `Esc` = No; `Shift+Tab` selects the session-wide allow (https://code.claude.com/docs/en/permissions). Codex: "Yes, proceed (y)", "Yes, and don't ask again for commands that start with <program> (p)", "No, and tell Codex what to do differently (esc)" (https://github.com/openai/codex/issues/22181). Kiro renders permissions as a "snack bar" above the input with grant/deny/trust so the prompt never scrolls away (https://kiro.dev/blog/new-look-for-cli/). Cursor stacks queued "+N more pending" approval previews (Aug 2026). Zed users still ask for tool input arguments to be visible before approving (https://github.com/zed-industries/zed/discussions/46241). Warp expands diffs during approval then collapses them.

**Selection lists, pickers, mouse.** Claude Code fullscreen: click rows in `/model`, `/config`, permission menus (v2.1.187+), multi-select (v2.1.208+), hover highlights, `Cmd/Ctrl+click` opens URLs and file paths (UNC paths deliberately not linked), `/scroll-speed` dialog with a live ruler (https://code.claude.com/docs/en/fullscreen). Codex keymaps cover `pager`, `list`, `approval` contexts (https://codex.danielvaughan.com/2026/05/05/codex-cli-tui-customisation-keymaps-themes-status-lines/). OpenCode: `Ctrl+P` command palette, `/sessions`, leader `Ctrl+X`. Crush: `Ctrl+L` model picker, `Ctrl+P` commands, session picker with busy/attached-clients signals.

**Themes.** Claude Code: built-ins incl. `dark-daltonized`/`light-daltonized`/ANSI variants, `auto` follows terminal background, custom JSON themes in `~/.claude/themes/` hot-reloaded, tokens for diff/word-diff/subagent colors (https://code.claude.com/docs/en/terminal-config). Codex: syntax-only theming; semantic UI colors not configurable (https://github.com/openai/codex/issues/21130). Gemini: 10 dark + 7 light built-ins, `autoThemeSwitching` on terminal background polling (60s). Kiro: dark/light/"safe" ANSI fallback using named ANSI colors so remapped palettes work; honors `NO_COLOR`. Pi: hot-reloading themes. Amp Neo *removed* custom themes "favoring a single polished interface" (https://ampcode.com/news/neo). Goose: light/dark/ansi.

**Images.** Pi renders inline via Kitty graphics (Kitty/Ghostty/WezTerm) or iTerm2 protocol, width `terminal.imageWidthCells` (60) — but falls back to text placeholders in alt-screen on iTerm2 "to prevent stale images" (https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/tui/README.md). Cursor CLI: "Attached and generated images render inline in terminals that support it, with text fallbacks everywhere else" (Aug 2026). Claude Code (https://github.com/anthropics/claude-code/issues/54546), Codex (https://github.com/openai/codex/issues/29451 ; `codex resume` once dumped raw base64 in non-graphics terminals — https://github.com/openai/codex/issues/31521) and OpenCode (https://github.com/anomalyco/opencode/issues/12075) do not render inline images; all accept pasted images as `[Image #N]`-style chips.

**Accessibility / no-color.** Claude Code screen-reader mode (`--ax-screen-reader`, v2.1.181+): flat labeled text, no box drawing, static spinners, numbered menus, 50ms cursor "pre-park" before rewritten lines, bell on completion/prompt/slow tool, OSC 133 markers; `prefersReducedMotion`; `CLAUDE_CODE_ACCESSIBILITY` keeps a visible hardware cursor for magnifiers (https://code.claude.com/docs/en/accessibility). Gemini `ui.accessibility.screenReader` plain text. Kiro `NO_COLOR`. Others: **unverified**.

**Narrow terminals.** Claude Code fixed RangeError crashes on narrow markdown tables (2.1.230) and keeps diff line numbers in narrow layouts; Codex truncates status and reserves space for the Ctrl+T hint; Cursor keeps prompts within six visual lines.

---

## 8. Performance

- **Claude Code:** fullscreen sends "only the cells that changed between frames"; ConPTY hosts may need `CLAUDE_CODE_ALT_SCREEN_FULL_REPAINT=1`; `Ctrl+L` forces a repaint; keeps full pre-compaction history across repeated compactions (2.1.228) (https://code.claude.com/docs/en/fullscreen). Engineer's description of the cost: a ~16ms frame budget and GC pressure from JSX allocation (HN thread).
- **Codex:** `frame_rate_limiter::MIN_FRAME_INTERVAL` scheduling, synchronized updates, history insertion batched by wrap policy; cursor hide/show leaking outside the synchronized frame causes visible cursor flicker in WezTerm (https://github.com/openai/codex/issues/32546 , Jul 2026); hyperlink layout limited to the viewport (0.149.0).
- **Amp Neo:** on a 5,000-message thread, CPU 84.1% → 17.4% and idle memory 1,814 MB → 540 MB (https://ampcode.com/news/neo).
- **Cursor CLI:** fixed ~1s event-loop stall on large repos, repaint only recent turns, memoized diff rendering, capped long lines pre-highlighting, fixed layout-feedback-loop freezes (https://cursor.com/docs/cli/changelog).
- **Crush:** raw-render cache per width/height, prefixed-style cache, FNV-64a hash to skip re-rendering unchanged thinking/content; animation invalidates via version counters (https://deepwiki.com/charmbracelet/crush/5.3-message-rendering).
- **Warp:** virtualizes at block level and row level so cost is "for what you can actually see" (https://www.warp.dev/blog/block-model-behind-warps-agentic-development-environment).
- **OpenCode:** despite the Zig core, users report sessions becoming "extremely laggy after extended conversation" (https://github.com/anomalyco/opencode/issues/30101), instability on complex sessions (https://github.com/anomalyco/opencode/issues/12078), and a tmux non-render bug in 1.2.21 (https://github.com/anomalyco/opencode/issues/16566).
- **Gemini CLI:** long-standing flicker epic (https://github.com/google-gemini/gemini-cli/issues/10673) and resize-duplication reports (https://github.com/google-gemini/gemini-cli/issues/22615); a separate "Ink render process" (`ui.renderProcess`) and a new terminal-buffer architecture flag exist.

---

## 9. Delighters and complaints (2025–2026)

**Delighters:** Claude Code's `/diff` per-turn viewer and `/focus`; `Ctrl+O` → `[` handing the transcript back to native scrollback; Codex's grouped "Explored" cells, `/raw` copy mode, and elapsed-time "Working" widget; Kiro's snack-bar permissions and unified live flow; Warp's diffs that auto-collapse after apply; Cursor's `Ctrl+R` review with open-in-editor; Pi's inline images and cache-hit footer; Crush's three-state thinking collapse; Gemini's structured one-line tool summaries.

**Complaints:** Claude Code flicker (HN, Jan 2026) then fullscreen's loss of `Cmd+F`, mouse capture, janky scroll, banner re-print regression; Codex transcript overlay not wrapping long lines, `Ctrl+T` dead during approvals, diff colors ignoring themes, no "cut", `tui.alternate_screen="always"` ignored on Linux (https://github.com/openai/codex/issues/24552); Gemini flicker/duplication on resize and alt-buffer selection needing `Ctrl+S`; OpenCode lag in long sessions and no images; Zed thinking blocks expanding by default and ACP blocks not collapsible; Cline 4.0.0 losing the editor diff; Claude Code `Ctrl+T` task list capped at five.

---

## 10. Synthesis

### (a) Table stakes for a top-5 agent in 2026
1. **No visible flicker** — synchronized output (mode 2026) wrapped around every frame, and either cell-level diffing (Codex/ratatui, Bubble Tea v2, OpenTUI, pi-tui) or virtualization (Claude Code fullscreen, Warp).
2. **A scrollback story the user can predict**: either native scrollback preserved (Codex default, Kiro, Pi regular) *or* an explicit escape hatch back to it (Claude Code `[`/`v`, Codex `/raw`). Shipping alt-screen without a search/copy story is what generated Claude Code's and Gemini's loudest issues.
3. **Collapsed-by-default tool rows with one consistent expand key** (`Ctrl+O` is the de-facto standard) plus a transcript/verbose view that shows *everything*.
4. **Head/tail truncation of long tool output with a visible "+N lines" marker and a hint to where the rest lives** (Codex, Kiro, Claude Code's disk spill).
5. **Unified diffs in-terminal with line-level color and word/character-level emphasis**, per-file +N/−M, and a post-turn diffstat (Claude Code, Cursor, Warp).
6. **A persistent footer carrying model, permission/approval mode, context %, and an interrupt hint**, configurable (Claude Code `statusLine`, Codex `tui.status_line`, Gemini `ui.footer.items`, Cursor `statusLine`).
7. **Terminal-title and bell/OSC 9 notifications**, gated on unfocused state (Codex `notification_condition`), with tmux passthrough documented.
8. **Light/dark auto-detection and at least an ANSI-safe theme**, `NO_COLOR`, and a plain-text/screen-reader mode.
9. **Approval prompts that show the exact command/diff, offer a scoped "don't ask again", and let the user attach a reason for "No".**

### (b) What the leaders do that others don't
- **Claude Code:** full mouse semantics inside the TUI (click-to-expand, click menus, drag-copy with platform clipboard fallbacks incl. OSC 52), a scriptable status line with cost/rate-limit/PR data, an a11y mode designed with labels + OSC 133 + timed cursor parking, per-turn `/diff`, `/focus`, hot-reloaded JSON themes with word-diff tokens, subagent color coding.
- **Codex CLI:** the cleanest native-scrollback implementation (scroll-region insertion, Zellij fallback, raw mode), grouped exploration cells, syntect theming with 32 themes, elapsed-time status widget, per-context keymaps, title-bar spinner.
- **Cursor CLI:** review-first diff UX (`Ctrl+R`, Session tab, open-in-editor, zen), inline images with text fallback, LaTeX→Unicode, aggressive perf hygiene (recent-turn repaint, memoized diffs, capped lines).
- **Kiro:** snack-bar permissions above an always-available input, per-tool components with ✓/✗/⏸, head+tail shell streaming, ANSI-named-color "safe" theme.
- **Warp:** diffs expanded during approval and collapsed after apply; nested multi-file headers; two-level virtualization.
- **Pi:** inline images today; synchronized output everywhere; token/cache footer (↑ ↓ R W CH).
- **Crush:** split-or-unified diff choice; three-state thinking; nested agent trees; serious render caching.

### (c) Rendering recipes worth copying (best implementation named)
1. **Inline viewport + scroll-region history insertion (Codex).** Keep a fixed-height live region at the bottom; commit finished cells above it with `DECSTBM` scroll regions inside a synchronized update; detect Zellij/tmux quirks and fall back to full-line insertion. Gives native search/copy for free.
2. **Alt-screen virtualization with an exit hatch (Claude Code).** If you do own the screen: render only visible messages, float a "Jump to bottom · 3 new messages" pill when auto-follow is paused, and provide `[` (dump to scrollback) and `v` (open in `$EDITOR`).
3. **Sync-output bracketing on every frame (pi-tui, Bubble Tea v2, Codex):** `\x1b[?2026h … \x1b[?2026l`; include cursor hide/show inside the bracket (Codex's cursor-flicker bug is what happens when you don't).
4. **Three-state collapsible long blocks (Crush):** collapsed (≈10 lines) → tail window (last ≈200 lines with "earlier content" indicator) → full; apply to thinking and shell output alike. Kiro's head+tail for shell output is the two-state variant.
5. **Grouped exploration cell (Codex):** coalesce consecutive Read/Search/List calls into "• Exploring …" that flips to "• Explored" with a count; Gemini's `→ Returned N lines` one-liners are the per-call equivalent.
6. **Approval-state-driven diff expansion (Warp):** expanded while awaiting approval, collapsed to a +N/−M header once applied; `E` toggles all.
7. **Per-turn diff viewer (Claude Code `/diff`):** tabs for git diff vs. turn T1/T2…, file list with stats, Enter to open, auto-refresh on external git changes.
8. **Truncation with provenance (Codex/Claude Code):** "… +N lines — ctrl+t to view transcript" in the row; for huge outputs spill to a file and show path + 5KB preview.
9. **Footer as data, not layout (Claude Code `statusLine`):** emit JSON (context %, cost, rate limits, PR state, vim mode) to a user script; debounce 300 ms; allow multi-line + ANSI + OSC 8.
10. **Raw/copy mode (Codex `/raw`):** a toggle that removes gutters and app-side wrapping so terminal selection yields logical lines.
11. **Screen-reader mode as a first-class renderer (Claude Code):** labeled lines, numbered menus, static spinners, OSC 133 marks, bell on attention events.
12. **Snack-bar permission prompt near the input (Kiro):** never make the user scroll to find the thing blocking the agent.
13. **Degrade images to text placeholders when they would smear (pi-tui on iTerm2 alt-screen).**

### (d) Mistakes to avoid
- **Changing the screen model by default without telling the user** (Claude Code v2.1.89 regression; Gemini reverting `useAlternateBuffer`). Ship a startup dialog, a one-time hint about mouse capture, and documented env overrides.
- **Alt-screen without search, copy, and scroll parity** — `Cmd+F`, tmux copy mode, and native selection are muscle memory; provide `[`/`/raw`-style escape hatches from day one.
- **Capturing the mouse silently** (Claude Code #72681); always print the "hold Shift/Option to select natively" hint.
- **Overlays that don't wrap** (Codex #7454) or that die during modal states (Codex #22263).
- **Diff colors that ignore the theme** (Codex) and **fallback diff paths that render whole files as additions** (Claude Code #59078).
- **Thinking/tool blocks expanded by default** in long sessions (Zed regression #52536; Zed ACP blocks).
- **Clear-and-redraw renderers for content taller than the viewport** (Ink's documented limitation) — the root of most 2025 flicker reports.
- **Capping progress views arbitrarily** (five-task list) and **letting live plan widgets vanish when idle** (Codex #18920).
- **Redesigns that remove affordances users relied on** (Amp Neo dropping themes and `$` shell) without an equivalent.
- **Performance cliffs in long threads** — measure at 5k messages (Amp publishes numbers; OpenCode's lag reports show what happens otherwise).
