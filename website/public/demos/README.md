# Ouroboros product captures

Real product captures made on 2026-09-13 from development commit
`9f78cc6a520bebfb676223b8292f105fb38f088e` (runtime/client `0.1.4`).
These show that development build, not a claim that every pictured detail is in
the currently announced stable release.

## Files

| Asset | GIF | Website video | Poster / screenshot |
| --- | --- | --- | --- |
| Fleet disconnect and reconnect, 11 seconds | [fleet.gif](fleet.gif) | [fleet.mp4](fleet.mp4) | [fleet.png](fleet.png) |
| Agent process crash and recovery, 15 seconds | [recovery.gif](recovery.gif) | [recovery.mp4](recovery.mp4) | [recovery.png](recovery.png) |
| Coding session, 22 seconds | [coding.gif](coding.gif) | [coding.mp4](coding.mp4) | [coding.png](coding.png) |

- [TUI session screenshot](tui-session.png): 2480 × 1760.
- [Compact web UI screenshot](web-session.png): 765 × 964.
- [Full desktop web UI screenshot](web-desktop.png): 2397 × 1009.
- [Fleet overview screenshot](fleet.png): 2480 × 1760.

All loops are silent, use 8 captured frames per second, and have pauses shortened.
MP4s use H.264, YUV420P, and fast-start metadata. GIFs repeat indefinitely.
The website uses poster images and user-initiated playback, with no autoplay.

## What was actually demonstrated

**Fleet:** two separate Ouroboros BEAM nodes, `studio` and `worker`, running on
the same Mac in private demo data directories. Real TLS distribution reported
two connected nodes. The worker was stopped through `ouro stop`; the TUI then
reported one connected node and one offline. Restarting the worker restored
two connected nodes. This is a same-machine demonstration, not evidence of
multi-machine operation, network partition tolerance, or session migration.

**Recovery:** a native coding agent read the small `taskboard` project's code
and tests. Its runtime process was then terminated with BEAM's untrappable
`Process.exit(pid, :kill)`, while the agent was idle. The coordinator replaced
that process, retained the same logical session and native conversation ID,
and incremented `resumes` from 0 to 1. Asked which tests it had just inspected,
the recovered agent correctly recalled the mixed, empty, and all-completed cases.
The captions above the terminal are editorial annotations of these recorded
actions; they are outside the product viewport.

Recovery is deliberately bounded: the current implementation makes one
automatic resume decision per coordinator incarnation. A second process loss
in that same incarnation was also checked and correctly ended as `lost`.
This clip demonstrates the single-crash case. An interrupted in-flight turn
is finalized as outcome-unknown rather than automatically replaying effects.
See `lib/ouroboros/interactive/task/resume.ex` at the captured commit.

**Coding:** the real `openai_codex:gpt-5.6-sol` native provider inspected and
edited a disposable JavaScript project. The initial `summarizeTasks` always
returned zero completed tasks. The first `npm test` run had one passing and
one failing test. The agent fixed the completed/pending counts and added an
all-completed regression case. Both its final run and an independent rerun
passed all three tests. Both shell commands were explicitly approved through
the web interface. The original turn took approximately 79 seconds.

## Capture and editing

The TUI ran in a real 120 × 36 pseudoterminal. Its ANSI output was recorded and
rendered faithfully with xterm.js in a restrained terminal frame. This was
necessary because the computer-use tool did not permit native terminal apps.
The application text, state, output, and transitions were not generated or
reconstructed as a mock UI. The terminal palette and outer frame are presentation
choices; the application itself was not modified for capture.

Web frames came from the authenticated, running LiveView interface through
browser screenshots and CDP screencasting. FFmpeg trimmed timing and encoded
the GIF/MP4 versions. Static holds give the final results time to be read.
No generated video, invented tool output, music, or voice was used.
No Hubfluencer credits were spent.

The capture runtime, credentials, source recordings, and example repository were
kept separate from normal user sessions. Only the finished public media and
these notes belong in the website build. No authentication tokens are included.
