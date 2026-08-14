# Design QA

Result: passed

Reference: `exec-a4dc5130-b0f4-4f61-a5ec-5bb6ff06b418.png` (option 2)

Implementation capture: `design-qa-implementation.png` from the real `ouro --dev` PTY at 149 x 50 cells, with the connected ChatGPT account and `ctrl+p` palette filtered to `dist`.

Combined comparison: `design-qa-comparison.png`

## Findings

- P0: 0
- P1: 0
- P2: 0

The shell hierarchy matches the selected direction: compact workspace/account header, coding-first body, persistent bottom composer, and a right-aligned searchable command palette that keeps runtime and distribution secondary.

The first PTY capture exposed stale boot copy behind sparse areas of the harness frame. The terminal handoff now clears the physical screen before the first harness draw; the final capture has no residual boot content.

The implementation capture intentionally shows the honest new-session state rather than fabricating the reference transcript. Transcript rendering, streaming, approvals, reconnect replay, and the persistent follow-up composer are covered by the interactive UI suites.

## Interaction checks

- Existing ChatGPT subscription opens directly on the current-folder composer.
- Unauthenticated local clients use Codex browser login; attached clients use device-code login on the runtime host.
- `ctrl+p`, search-to-select, New session, Switch session, ChatGPT account, runtime, agents, teams, nodes, plans, upgrades, logs, and settings are keyboard-operable.
- Secondary operator panels return to coding with Esc.
- Starting a session uses provider `codex`, preserves the current workspace, sends the first message after the session exists, subscribes to the transcript, and leaves the follow-up composer open.
