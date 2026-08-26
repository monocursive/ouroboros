defmodule Ouroboros.Provider.Native.Desktop do
  @moduledoc """
  Computer Use configuration, readiness, and app identity for the native provider.

  This is the Elixir side of `docs/COMPUTER_USE.md`. In Phase 0 it owns no helper
  process and touches no pixels: it reads the `:computer_use` application environment,
  answers whether the feature is genuinely usable on this node, and canonicalises app
  identity. The helper pool, image staging, and per-session snapshot map (D11) arrive in
  later phases; this module is deliberately the honest predicate they will build on.

  ## The one honest predicate

  `enabled?/0` is true only when the flag is on **and** a helper binary actually exists on
  disk. There is no bundled helper in Phase 0, so the second half is false unless
  `OUROBOROS_COMPUTER_USE_HELPER` points at a binary a developer built themselves. That is
  the honesty invariant applied to a feature flag: a node cannot claim it can drive the
  desktop when there is nothing on it that can. `Tools.specs/3` and `Tools.lookup/3` gate
  on this, so an off node never teaches the model a tool name it cannot use (D9).

  ## Configuration bounds

  Same posture as `Ouroboros.Provider.Native.Mcp.Config` — everything here is a bound and a
  malformed value falls back to the shipped default rather than removing the bound. It is
  slightly stricter for caps than the MCP reader, because §4 requires that a *raised* cap
  also fall back: an operator typo must not widen how much a helper may capture, only
  narrow it. Timeouts fall back only when non-positive; a longer timeout is the operator's
  to grant.

  ## The denylist floor

  `denied_app_ids/0` returns the union of the configured list and a baked floor
  (`@denied_app_ids`). The floor is the invariant #9 apps — this runtime's own surfaces,
  the terminals, the OS auth and secret panes — and unioning means an operator may *add*
  denials but a shorter or malformed config can never remove one. The node denylist is
  operator configuration and is not writable through `remember/4` (D12).
  """

  # The bundle ids Computer Use must never drive, baked so config can only widen the deny,
  # never narrow it. Mirrors `config/config.exs`'s `denied_app_ids` default; the two are
  # kept in step by `test/provider/native/desktop_test.exs`.
  @denied_app_ids [
    "com.ouroboros.desktop",
    "com.ouroboros.tui",
    "com.apple.Terminal",
    "com.googlecode.iterm2",
    "com.mitchellh.ghostty",
    "net.kovidgoyal.kitty",
    "com.apple.systempreferences",
    "com.apple.loginwindow",
    "dev.warp.Warp-Stable",
    "org.alacritty",
    "com.github.wez.wezterm",
    "co.zeit.hyper",
    "org.tabby",
    "com.1password.1password",
    "com.apple.keychainaccess",
    "com.apple.SecurityAgent"
  ]

  # A small alias table so a model may pass `app: "Safari"` and the classifier still names
  # a bundle id the denylist and rules reason about (§16.4, §6.3 step 2). Deliberately tiny
  # and obvious; an unknown name passes through to the helper's own resolver, unchanged.
  @app_aliases %{
    "Safari" => "com.apple.Safari",
    "Calculator" => "com.apple.calculator",
    "Finder" => "com.apple.finder",
    "Notes" => "com.apple.Notes",
    "Mail" => "com.apple.mail",
    "Preview" => "com.apple.Preview",
    "System Settings" => "com.apple.systempreferences",
    "System Preferences" => "com.apple.systempreferences",
    "Terminal" => "com.apple.Terminal"
  }

  @defaults [
    enabled: false,
    helper_path: :bundled,
    handshake_timeout_ms: 5_000,
    state_timeout_ms: 5_000,
    act_timeout_ms: 10_000,
    shutdown_grace_ms: 2_000,
    max_frame_bytes: 8 * 1024 * 1024,
    max_image_bytes: 2 * 1024 * 1024,
    max_image_width: 1920,
    max_image_height: 1920,
    max_nodes: 1_000,
    max_depth: 32,
    max_snapshots_per_session: 8,
    jpeg_quality: 80,
    denied_app_ids: @denied_app_ids
  ]

  # Timeouts fall back only when non-positive; a bigger value only makes this node wait
  # longer for its own helper, which is the operator's call to make.
  @timeout_keys [:handshake_timeout_ms, :state_timeout_ms, :act_timeout_ms, :shutdown_grace_ms]

  # Caps and limits fall back when non-positive *or raised above the shipped default*: a
  # value over the cap widens what a helper may consume on this node, which a typo must
  # never do (§4).
  @bound_keys [
    :max_frame_bytes,
    :max_image_bytes,
    :max_image_width,
    :max_image_height,
    :max_nodes,
    :max_depth,
    :max_snapshots_per_session
  ]

  @doc """
  Whether Computer Use is genuinely usable on this node.

  True only when the flag is on and the resolved helper binary exists on disk. With no
  bundled helper this is false unless `OUROBOROS_COMPUTER_USE_HELPER` points at a built
  binary — the feature does not claim a capability it cannot back.
  """
  @spec enabled?() :: boolean()
  def enabled?, do: config(:enabled) == true and helper_present?()

  @doc "Whether the resolved helper binary exists on disk as a regular file."
  @spec helper_present?() :: boolean()
  def helper_present?, do: File.regular?(helper_path())

  @doc """
  The absolute path the helper would be spawned from.

  `OUROBOROS_COMPUTER_USE_HELPER` wins, then the configured `:helper_path`, then the
  bundled location. In Phase 0 nothing ships at the bundled location, so it resolves to a
  path that does not exist and `enabled?/0` stays honestly false.
  """
  @spec helper_path() :: String.t()
  def helper_path do
    case System.get_env("OUROBOROS_COMPUTER_USE_HELPER") do
      path when is_binary(path) and path != "" -> path
      _unset -> configured_helper_path()
    end
  end

  defp configured_helper_path do
    case config(:helper_path) do
      path when is_binary(path) and path != "" -> path
      _bundled_or_invalid -> bundled_helper_path()
    end
  end

  defp bundled_helper_path do
    case :code.priv_dir(:ouroboros) do
      priv when is_list(priv) ->
        Path.join([List.to_string(priv), "computer-use", "ouro-computer-use"])

      # An unloaded application has no priv dir; resolve somewhere that does not exist so
      # `helper_present?/0` is false rather than raising.
      _bad_name ->
        "/nonexistent/ouro-computer-use"
    end
  end

  @doc """
  The bundle ids this node refuses to drive, floor unioned with operator config.

  The baked floor can never be removed by a shorter or malformed config; an operator may
  only add ids. This is invariant #9 and D12: ouro and the terminals are always denied.
  """
  @spec denied_app_ids() :: [String.t()]
  def denied_app_ids do
    configured =
      case config(:denied_app_ids) do
        list when is_list(list) -> Enum.filter(list, &(is_binary(&1) and &1 != ""))
        _malformed -> []
      end

    Enum.uniq(@denied_app_ids ++ configured)
  end

  @doc "Whether a claimed or resolved app id is on this node's denylist."
  @spec denied_app?(String.t() | nil) :: boolean()
  def denied_app?(app) when is_binary(app), do: app_alias(app) in denied_app_ids()
  def denied_app?(_app), do: false

  @doc """
  Canonicalises a claimed app name to a bundle id when it is an obvious alias.

  Known names map to their bundle id; anything else passes through unchanged for the
  helper's own resolver to handle. Non-binaries pass through untouched.
  """
  @spec app_alias(term()) :: term()
  def app_alias(name) when is_binary(name), do: Map.get(@app_aliases, name, name)
  def app_alias(name), do: name

  @doc "The alias table, for tests and operator surfaces."
  @spec app_aliases() :: %{String.t() => String.t()}
  def app_aliases, do: @app_aliases

  @doc """
  A readiness map for operator surfaces, clearly marked not-yet-wired in Phase 0.

  There is no helper process, no capture, and no input in this phase, so `wired` is false
  and `note` says so. Later phases replace this with the helper's own `doctor` output.
  """
  @spec status() :: map()
  def status do
    %{
      enabled: enabled?(),
      flag: config(:enabled) == true,
      helper_path: helper_path(),
      helper_present: helper_present?(),
      denied_app_ids: denied_app_ids(),
      phase: 0,
      wired: false,
      note:
        "Phase 0 stub: no helper process, no screen capture, and no input injection are " <>
          "wired. computer use is not enabled on this node."
    }
  end

  @doc "One effective setting, after the shipped-default fallback."
  @spec config(atom()) :: term()
  def config(key) when is_atom(key) do
    default = Keyword.fetch!(@defaults, key)
    configured = Application.get_env(:ouroboros, :computer_use, [])

    value =
      if Keyword.keyword?(configured), do: Keyword.get(configured, key, default), else: default

    if valid?(key, default, value), do: value, else: default
  end

  @doc "Every setting and its effective value, for status surfaces and tests."
  @spec all() :: keyword()
  def all, do: Enum.map(@defaults, fn {key, _default} -> {key, config(key)} end)

  defp valid?(:enabled, _default, value), do: is_boolean(value)
  defp valid?(:helper_path, _default, :bundled), do: true
  defp valid?(:helper_path, _default, value), do: is_binary(value) and value != ""
  defp valid?(:denied_app_ids, _default, value), do: is_list(value)

  defp valid?(:jpeg_quality, _default, value),
    do: is_integer(value) and value >= 1 and value <= 95

  defp valid?(key, _default, value) when key in @timeout_keys, do: is_integer(value) and value > 0

  defp valid?(key, default, value) when key in @bound_keys,
    do: is_integer(value) and value > 0 and value <= default

  defp valid?(_key, _default, _value), do: true
end
