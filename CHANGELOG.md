# Changelog

Notable changes in published Ouroboros releases, newest first. Each entry focuses
on what changes for users and any action needed when upgrading. Downloads are on
[GitHub Releases](https://github.com/monocursive/ouroboros/releases); platform
requirements and upgrade instructions are in the
[installation and release guide](docs/RELEASING.md).

## [Unreleased]

## [0.1.10] - 2026-09-19

### Devices

- The web Devices page is one list instead of two sections. This machine is first,
  labelled "This Mac" or "This machine"; the fleet's members follow, then the other
  devices on your network. Each row says what it is, whether it is online and how
  long ago it was seen, what Ouroboros knows about it, and offers one button — *Set
  up this Mac*, *Add to fleet*, *Open*, *Continue*, *Retry* or *Details* — or none,
  when there is nothing to do about it.
- The words on the page are written for a person rather than copied from the
  specification. A row that read "Discovered peer; Ouroboros installation unknown"
  now reads "not set up", and the legend explaining that vocabulary is gone with it.
  Times are relative ("seen 3 days ago"); the exact timestamp is in a device's
  details. The search box and the filter appear only when there are more than eight
  devices.
- Adding a machine asks for a name, an address and an SSH user, and nothing else up
  front. The name is pre-filled with a valid fleet name rather than a display name,
  so a setup no longer fails at the end because "Monocursive's MacBook Pro" is not a
  machine name. *Add a device by address* now has a name field, which is what it was
  missing. There is no authentication method to choose: the default SSH identity is
  used and you are asked for a password only if the machine asks for one. A specific
  key stays under Advanced — a disclosure that no longer closes itself while you type.
- A device can be removed from the fleet, from its details panel: it stops there,
  gives up its credentials and leaves every roster, and its sessions and data stay
  on that machine.
- When a setup's worker stops without finishing, the page says what the worker said
  and offers Retry, instead of showing an operation that never moves. A development
  runtime (`ouro --dev`) now says it cannot set a machine up, rather than building a
  fleet it could never start.
- A failure to reach Tailscale is reported in Tailscale's own words, and no longer
  guesses that your Ouroboros may be out of date.
- The terminal client's Devices view (`ctrl+x D`) draws the same list and the same
  flows: one line per device, the details of the selected one underneath, `a` to add a
  device by address, `x` to remove a member, and a setup that keeps following its
  operation across the restart it causes.
- Failed removals stay retryable even while the member is connected. Roster-forgetting
  advice is shown only when the failed attempt recorded no target steps, and recovery
  commands preserve the full machine name.
- Web details open for IPv6-only peers without a deployment address. Terminal setup
  forms show fixed addresses; paging can reach the selected device's details without
  acting on a hidden row. A refused status read after reconnect shows the error and
  lets the operator return to the list instead of reviving a cached prompt.
- Deployment attachment preserves the journal owner's access controls. Retrying a
  slow worker no longer blocks unrelated broker reads, and bounded worker-log tails
  discard partial first lines before redaction so truncated credential lines cannot leak.

### Fleet

- Discovery works from a daemon on a Mac with the Tailscale app installed. A client
  that answers with a sentence instead of a status document, or fails outright, is
  skipped for the next one (the app bundle's CLI needs a GUI session; the Homebrew one
  does not); before this, every runtime on such a Mac listed no devices and named this
  machine "this device".
- A Linux machine added to the fleet gets a working startup service. The generated
  systemd unit quoted `WorkingDirectory=`, which systemd 257 refuses; the unit is now
  written the way systemd reads it, the error shown is the real one rather than the
  "Created symlink" line before it, and `install` enables lingering for the account
  so the service starts at boot and survives logout when the account permits it.
  Accounts that cannot enable lingering report the administrator action required.
- The default SSH identity falls back to a password prompt when the machine asks for
  one, so `ouro fleet add` without `--ask-password` works against a machine that only
  takes passwords, and the web and terminal forms need no authentication picker.
- `ouro fleet leave --machine` is reachable through the deployment worker and the
  gateway (`fleet.deployment.prepare` with `kind: "leave"`), which is what the Devices
  pages remove a member with.
- A fleet created under a symlinked data directory (`/tmp` on macOS is one) starts under
  its service: the generated TLS policy names the directory's resolved path, and the
  strict policy check resolves the paths a policy file names before comparing.
- The web port stays the same across a clean stop and start, so the browser tab that
  asked for a local setup reconnects after the restart it causes. Every device row from
  `ouro fleet devices --json` carries `suggested_machine`, a valid fleet name derived
  from the display name.
- Retry offers a fresh plan when another admission changes the roster before
  credentials are issued. Cancellation removes only that operation's uninstalled
  preparation; older helpers report any remaining preparation and recovery commands.
- Rechecking an existing member reuses its authenticated SSH connection. Password
  prompts for different hosts no longer inherit a previous host's cancelled prompt.
- Downloads and uploads report bytes and elapsed time. Progress survives worker
  reattachment, completed steps replace running markers, and CLI operations appear
  in the web history. A finished worker no longer delays an immediate Retry.
- Installing a matching but stopped startup service starts it when no runtime owns
  the data directory. Host-key review includes a concrete independent fingerprint
  check, and service failures retain their useful error details.
- Previously approved plans without a summary remain resumable when their deployment
  facts are unchanged. Reconnected terminal views refuse input to stale prompts.

### Terminal

- Image-draft recovery releases its file lock immediately when its owner closes,
  even while a forked child still holds the inherited file descriptor.

## [0.1.9] - 2026-09-18

### Added

- A Devices page in the web UI and the TUI, plus `ouro fleet setup`, `add`,
  `leave --machine`, `doctor`, `devices` and `service`, so a second machine can join
  over the existing Tailscale network instead of by copying a directory by hand.
- `runtime.activity` and `runtime.shutdown` with `require_idle`, so a managed stop
  can refuse while work is in flight.

### Changed

- Provider requests use Anthropic prompt-cache breakpoints and stable conversation
  identifiers for OpenAI, ChatGPT/Codex, xAI and Grok. Compaction and handoff reuse
  the conversation prefix, and turn-budget updates preserve earlier messages.
- The web chat composer is more compact, with an inline image attachment control
  and accessible touch targets.
- Cooperative leave and `ouro fleet service disable`/`remove` gate the runtime first
  (`ouro stop --require-idle`: exit 0 when nothing is running, 10 busy, 11 unknown)
  and then disable or remove the unit, which gates itself.
- A deployment holds the issuer lock only for the mutation phase. Inspection, host
  trust, passwords and review no longer block every other deployment on the host; a
  waiter is told which operation holds the lock.
- The request file is kept while an operation can still be resumed, then folded into
  the journal and deleted at completion or cancel. SSH reuses one ControlMaster so a
  password is typed once.

### Fixed

- Linux shutdown confirms a stopped runtime when the process exits during the
  final identity check, instead of reporting a spurious "No such process" error.
- ChatGPT/Codex sessions resolve their model context window so the context meter
  and automatic compaction work. Compaction uses the lower of the model threshold
  and the configured token cap, which defaults to 200,000 tokens.
- Subscription sessions report unknown cost when no API price applies.
- xAI and Grok requests retain prior reasoning text, including across checkpoint
  recovery, so later requests can reuse the provider's cached prefix.

### Security

- Credential delivery no longer holds the local lifecycle lock across the SSH
  install. A Tailscale node key recorded for an address is refused
  `peer_identity_changed` if a later add or resume sees a different one.

### Upgrade notes

- Run `ouro update` from an official standalone installation. Finish active work,
  then run `ouro stop` and `ouro` to activate the new runtime. Reload open web views.
- `ouro stop --require-idle` now exits 0 when nothing is running here. Exit 10 is
  still busy work, 11 is still unknown activity. Scripts that treated any zero as
  "a pid was stopped" should read the printed outcome.
- Web and TUI Devices views, and `ouro fleet setup`/`add`/`leave`, need a runtime
  that serves the `fleet.deployment.*` and `runtime.activity` methods. `ouro fleet
  doctor` prints the fleet protocol revision this build speaks.

## [0.1.8] - 2026-09-15

### Added

- Paste, drop, or choose images in web chat, or use Ctrl+V, `/paste-image`, and
  `/attach` in the TUI. Send images with or without text, including the first
  message in a new conversation; accepted images remain visible in history.
- Image uploads support progress, removal, retries, and remote conversation
  owners. Browser drafts survive conversation switches, and private TUI draft
  recovery survives runtime restarts and gateway token rotation.
- Web chat gains a searchable command palette, keyboard shortcuts, message copy
  and transcript export, plus controls for steering, model changes, per-turn
  thinking effort, and plan mode.
- Web conversation tools now include backtrack, fork, rewind, compaction,
  handoff, context inspection, operator shell commands, and an MCP server panel.

### Changed

- Web and TUI command palettes share one catalogue and consistent wording.
  TUI help, shortcut hints, and command discovery follow the configured key map.
- Web navigation shares one top bar, with working session activity, notifications,
  and a separate vitals panel. Palette selection and message-copy controls remain
  usable on compact screens and with reduced motion.

### Fixed

- Palette Send and Queue submit the current browser form, preserving images and
  refusing pending or failed uploads. Image-only TUI sends respect disabled or
  rebound Send keys.
- Repeated web submissions reuse the original turn ID and thinking-effort input;
  deliberate draft or effort edits still create a new turn.
- Backtrack restores and saves the chosen browser draft without sending it.
  Session keyboard shortcuts and modal guards no longer act on the wrong surface.
- Fleet machines retain operator-assigned names, including offline roster
  members. Unnamed machines use their hostname so shared release names do not
  make different computers appear identical.

### Upgrade notes

- Run `ouro update` from an official standalone installation. Finish active work,
  then run `ouro stop` and `ouro` to activate the new runtime. Reload open web views.
- Source builds require `make media` for the image decoder; `make dev` and release
  packaging include it. Image uploads require working runtime OS containment.
- Encrypted owners keep client image drafts in memory.

## [0.1.7] - 2026-09-14

### Settings

- Grok subscriptions now appear in web and TUI Settings with sign-in guidance and
  a status refresh action, alongside the separately billed xAI API connection.
- Provider logos, connection status and credential sources make accounts and API
  keys easier to identify. Settings group connections, defaults and runtime options.
- The TUI supports masked entry for Anthropic and xAI API keys, saved through the
  runtime's credential store.

### Fixed

- Missing or malformed credential reports no longer prevent Settings from
  loading. Saving an API key refreshes its connection status even when a previous
  refresh is still running.
- TUI connection refreshes preserve the selected provider, ChatGPT logout returns
  to Settings, and long Anthropic workspace values remain editable in compact views.

### Website

- The release badge links to this version.

### Upgrade notes

- Run `ouro update` from an official standalone installation. Finish active work,
  then run `ouro stop` and `ouro` to activate the new runtime. Reload open web views.
- To connect a Grok subscription, run `grok login` on the computer hosting
  Ouroboros, then refresh its status in Settings. The status reports the local
  sign-in; model access and allowances remain controlled by xAI.

## [0.1.6] - 2026-09-14

### Fixed

- Web chat now shows complete retained reviews and conversations. The latest 50
  display cells load first; scrolling up or choosing **Load earlier messages**
  loads earlier pages without splitting streamed replies.
- Replayed events and repaired history gaps preserve message identities, reading
  position, expanded blocks and review links. Automatic and manual page loading
  share one request to keep messages in chronological order.
- The TUI retains every delivered event and renders complete conversation text,
  so scrolling can reach earlier messages and the end of long replies. An
  excerpted final event no longer replaces a complete reply received in deltas.
- TUI scrolling reuses settled message layouts. Live updates to an older running
  tool no longer reformat the entire conversation after it.

### Website

- Shared website links include dedicated social preview images.
- The release badge links to this version.

### Upgrade notes

- Run `ouro update` from an official standalone installation. Finish active work,
  then run `ouro stop` and `ouro` to activate the new runtime. Reload open web views.
- History already pruned by the runtime cannot be recovered by these changes;
  unavailable ranges remain visible as history-gap markers. Retaining more
  conversation history increases the memory used by an open view.

## [0.1.5] - 2026-09-14

### Added

- Native Grok coding subscription support, including SuperGrok Heavy. Select
  `grok:grok-4.6` or `grok:grok-4.5` to use the subscription while Ouroboros keeps
  its own agent loop and tools.
- Grok subscription choices in the model picker and a web connection card that
  checks the local sign-in and lets you refresh its status.

### Reliability

- Queued Grok requests read credentials after acquiring model capacity, so they
  use renewed sign-ins and reject credentials that expired while waiting.
- The subscription connection accepts both map and keyword HTTP options while
  keeping its endpoint and authentication fixed.

### Upgrade notes

- Run `ouro update` from an official standalone installation. Finish active work,
  then run `ouro stop` and `ouro` to load the new runtime.
- Run `grok login` on the computer hosting Ouroboros before selecting a `grok:`
  model. Ouroboros reads the private local sign-in; Grok owns its refresh tokens,
  so expired credentials require another `grok login`.
- `xai:` models still use separately billed API keys. Subscription requests never
  fall back to API-key billing, and model access and allowances remain controlled
  by xAI.

## [0.1.4] - 2026-09-13

### Fixed

- GPT-6 Astra now appears in the model picker with its context limits and supported
  thinking levels, including when another model is configured as the default.
- Updated the bundled model catalogue to `llm_db` 2026.9.1 and the model transport
  to ReqLLM 1.22.0, which includes Astra Responses support.

### Upgrade notes

- Run `ouro update` from an official standalone installation. Finish active work,
  then run `ouro stop` and `ouro` to load the updated catalogue and runtime.
- Model access still depends on the connected account. This update adds Astra to
  the catalogue without changing the configured default model.

## [0.1.3] - 2026-09-13

### Added

- `ouro update` installs a newer stable release for official standalone
  installations. It verifies the download's SHA-256 checksum and reported version
  before replacing the executable atomically.
- `ouro update --check` checks for a newer stable release without changing files.
  Local source builds can also use this check.
- An Astro project website with installation instructions, runtime capabilities,
  and model access guidance.

### Upgrade notes

- Binaries from 0.1.2 and older do not have the update command. Finish active work,
  stop the runtime, and rerun the installer once to obtain it.
- Updating the executable leaves an existing runtime on its current code. Finish
  active work, then run `ouro stop` and `ouro` to activate the installed runtime.
- Self-updates require an official standalone installation owned by the current
  user. Run without sudo; package-manager installations should use their package
  manager's update process.

## [0.1.2] - 2026-09-13

### Added

- First public binary release: a terminal client and local web interface for
  durable AI coding sessions, with the Erlang/Elixir runtime and WebAssembly
  helper embedded. Installation requires no Elixir, Rust, or compiler.
- Native executables for Apple Silicon and Intel macOS, and ARM64 and x86-64
  GNU/Linux, with a checksum-verifying installer and `SHA256SUMS`.

### Compatibility

- macOS 15 or newer; GNU/Linux with glibc 2.39 or newer, using Ubuntu 24.04 as the
  build baseline. See the installation guide for system libraries and Linux shell
  containment requirements.

Earlier `v0.1.0` and `v0.1.1` tags have no published release assets.

[Unreleased]: https://github.com/monocursive/ouroboros/compare/v0.1.10...dev
[0.1.10]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.10
[0.1.9]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.9
[0.1.8]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.8
[0.1.7]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.7
[0.1.6]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.6
[0.1.5]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.5
[0.1.4]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.4
[0.1.3]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.3
[0.1.2]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.2
