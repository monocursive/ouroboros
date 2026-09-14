# Changelog

Notable changes in published Ouroboros releases, newest first. Each entry focuses
on what changes for users and any action needed when upgrading. Downloads are on
[GitHub Releases](https://github.com/monocursive/ouroboros/releases); platform
requirements and upgrade instructions are in the
[installation and release guide](docs/RELEASING.md).

## [Unreleased]

No unreleased changes recorded yet.

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

[Unreleased]: https://github.com/monocursive/ouroboros/compare/v0.1.5...dev
[0.1.5]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.5
[0.1.4]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.4
[0.1.3]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.3
[0.1.2]: https://github.com/monocursive/ouroboros/releases/tag/v0.1.2
