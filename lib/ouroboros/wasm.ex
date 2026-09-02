defmodule Ouroboros.Wasm do
  @moduledoc """
  Lane W's entry point: where the `ouro-wasm` helper is, and the bounds this node speaks to
  it under.

  The helper is the containment boundary (docs/WASM.md §7.3). It is an isolated workspace
  member carrying a whole wasmtime, built by `make wasm` into `priv/wasm/` and fanned out to
  `_build/*/lib/ouroboros/priv/wasm/`. Nothing here builds it and nothing here requires it:
  **presence on disk is the operator opt-in**, exactly as it is for the Computer Use helper
  (`Ouroboros.Provider.Native.Desktop.helper_path/0`), and absence is an error tuple rather
  than a raise so a node that never built one boots and runs unchanged.

  Resolution order, same shape as the desktop helper's:

    1. `OUROBOROS_WASM_HELPER` — an absolute path to an operator build;
    2. a configured absolute `helper_path` under `config :ouroboros, :wasm`;
    3. the first existing candidate: the application's `priv/` (which is the `_build`
       fan-out `make wasm` writes), or a sibling of `ouro` itself.

  **Nothing in that order is derived from the working directory** (F1). The helper *is* the
  containment boundary, so the set of paths that may supply it has to be a property of the
  installation and never of where the daemon happens to have been started: a walk up the
  cwd's ancestors for `priv/wasm/ouro-wasm` meant any repository a user cloned and any
  directory an agent could write could hand this node the binary it spawns to contain
  untrusted code. A checkout that wants its own build says so with `OUROBOROS_WASM_HELPER`
  or with the `_build` fan-out `make wasm` already writes; a worktree that wants one says so
  with the env override or its own `priv/wasm/`.

  Settings are bounds on somebody else's program, so a malformed value falls back to the
  default rather than widening anything — the `Ouroboros.Provider.Native.Desktop.config/1`
  posture, for the same reason.
  """

  @helper "ouro-wasm"

  # The world this node speaks. It is not configurable: admitting a component against a
  # world this build does not implement is exactly the lie the linker exists to prevent
  # (docs/WASM.md D5), so the handshake compares against this constant and nothing else.
  @world "ouroboros:capability@0.1.0"

  @defaults [
    helper_path: :bundled,
    # A `doctor` answer needs no wasm work at all, so a helper that cannot produce one
    # within this window is not slow, it is wrong.
    handshake_timeout_ms: 5_000,
    # Everything that is not `call`/`instantiate`: `doctor`, `inspect`, `load`, `drop`.
    # Sized by `load`, which compiles a component — the helper accepts up to 64 MiB of
    # them — rather than by `drop`, which is a map delete.
    request_timeout_ms: 30_000,
    # Added to a request's own `limits.deadline_ms` to get the transport's deadline for
    # `call` and `instantiate`. The guest's bound is the helper's epoch deadline; this is
    # headroom for the work around it — compiling, linking, lifting the reply out of guest
    # memory, and the trip back up the pipe.
    call_margin_ms: 10_000,
    # The helper's own read-bounded frame cap (`tui/wasm/src/main.rs`), matched here so a
    # frame this node would refuse is one the helper would never have sent.
    max_frame_bytes: 8 * 1024 * 1024,
    # How long a broken helper is left alone before a request may reconnect it. The same
    # window `Ouroboros.Provider.Native.Desktop.Pool` uses, for the same reason.
    broken_ms: 15_000,
    # What `Ouroboros.Wasm.Store` will hold before pruning evicts unreferenced bytes.
    # Eight components at the helper's 64 MiB per-component ceiling: far more than a
    # realistic corpus of capabilities, and still a number an operator would notice.
    store_budget_bytes: 512 * 1024 * 1024,
    # The bounds `Ouroboros.Wasm.Capability` stands an instance up under when its own
    # `initial_state` does not name them. Conservative on purpose: a capability that needs
    # more says so in the state it is deployed with, where the number is visible to whoever
    # signs it, rather than inheriting a generous node-wide default it never declared.
    #
    # Declared whole, and validated whole (see `valid?/2`): all three or none. A half-stated
    # bound is not a bound, and the helper refuses a request that omits one for the same
    # reason — "there is no unlimited default" is its sentence.
    capability_limits: [
      # About a tenth of a second of guest computation on this hardware, and three orders of
      # magnitude above what a JSON step function costs.
      fuel: 100_000_000,
      memory_bytes: 64 * 1024 * 1024,
      deadline_ms: 5_000
    ],
    # The **ceiling** the bounds above may be raised to, per capability, by the state a
    # capability is deployed with. `capability_limits` is the default; this is the most any
    # declaration can ask for, and `Ouroboros.Wasm.Capability.limits/1` clamps element-wise
    # against it (F3).
    #
    # It exists because `:limits` arrives in `initial_state`, `Ouroboros.Mesh.start_agent/2`
    # is remote-reachable, and Jido does not validate `initial_state` against the agent's
    # schema — so before this, a remote starter simply wrote the helper's own maxima into the
    # state it started a capability with and got them: a full trillion units of fuel, a
    # gibibyte, and sixty seconds of wall clock per message, on a node that had never agreed
    # to any of it. A ceiling is the only place that decision can honestly live, because it
    # is the node's and not the deployment's.
    #
    # Conservative on purpose, and still two orders of magnitude above the default: a
    # hundredth of the helper's fuel ceiling, a quarter of its memory ceiling, half its
    # deadline. Declared whole and validated whole, exactly as `capability_limits` is.
    capability_limits_max: [
      fuel: 10_000_000_000,
      memory_bytes: 256 * 1024 * 1024,
      deadline_ms: 30_000
    ],
    # Whether a capability's `initial_state` may name the directory its component bytes are
    # read from. Default **false**, and true only in this repository's test environment.
    #
    # `:store_root` is a test seam — it lets one agent read its own directory without touching
    # anything global — and on a remote-reachable start surface a test seam is an arbitrary
    # read: a starter that names a root runs whatever unsigned, unregistered bytes sit at
    # `<root>/wasm/components/sha256-<hex>.wasm` for any directory the BEAM user can read.
    # With this false the node's own store root is used whatever the state says (F3).
    allow_store_root_override: false
  ]

  @timeout_keys [:handshake_timeout_ms, :request_timeout_ms, :call_margin_ms, :broken_ms]
  @byte_keys [:max_frame_bytes, :store_budget_bytes]
  @limit_keys [:fuel, :memory_bytes, :deadline_ms]
  @limits_keys [:capability_limits, :capability_limits_max]

  @doc """
  The default instance bounds, as the map `Ouroboros.Wasm.Pool.instantiate/5` takes.

  `Ouroboros.Wasm.Capability` uses these when the state it was deployed with names none of
  its own. They are a floor an operator may raise, never a ceiling this build invents per
  request: the three bounds are always sent explicitly.
  """
  @spec capability_limits() :: %{
          fuel: pos_integer(),
          memory_bytes: pos_integer(),
          deadline_ms: pos_integer()
        }
  def capability_limits, do: Map.new(config(:capability_limits))

  @doc """
  The ceiling a deployed capability's own `:limits` may reach.

  `Ouroboros.Wasm.Capability.limits/1` clamps element-wise against this, so a declaration
  that asks for more runs under this instead and says so in the agent's `:error`. Read from
  `config :ouroboros, :wasm, :capability_limits_max`, whole or not at all.
  """
  @spec capability_limits_max() :: %{
          fuel: pos_integer(),
          memory_bytes: pos_integer(),
          deadline_ms: pos_integer()
        }
  def capability_limits_max, do: Map.new(config(:capability_limits_max))

  @doc """
  Whether a capability's `initial_state` may name its own component store root.

  False on any node that has not deliberately said otherwise, because the key arrives on a
  remote-reachable start surface and naming a root is naming which bytes run.
  """
  @spec allow_store_root_override?() :: boolean()
  def allow_store_root_override?, do: config(:allow_store_root_override) == true

  @doc "The world id this node admits a component against."
  @spec world() :: String.t()
  def world, do: @world

  @doc """
  The absolute path the helper would be spawned from.

  Always a string, even when nothing is there: `available?/0` is the question about disk,
  and the pool answers `{:error, :unavailable}` rather than raising.
  """
  @spec helper_path() :: String.t()
  def helper_path do
    case System.get_env("OUROBOROS_WASM_HELPER") do
      path when is_binary(path) and path != "" ->
        if absolute_path?(path), do: path, else: configured_helper_path()

      _unset ->
        configured_helper_path()
    end
  end

  defp configured_helper_path do
    case config(:helper_path) do
      path when is_binary(path) and path != "" ->
        path

      _bundled ->
        # The first candidate that exists; failing that, the first candidate as the name
        # a `doctor` would report; failing even that, the bare helper name. Always a
        # string and never `hd([])`, and none of these paths reads the working directory
        # — so a removed cwd cannot raise here and a planted one cannot be selected.
        Enum.find(candidates(), &File.regular?/1) || List.first(candidates()) || @helper
    end
  end

  @doc "Whether a helper is actually on disk. This is the operator opt-in, nothing else."
  @spec available?() :: boolean()
  def available?, do: File.regular?(helper_path())

  @doc "One setting, falling back to the default when the configured value is unusable."
  @spec config(atom()) :: term()
  def config(key) when is_atom(key) do
    default = Keyword.fetch!(@defaults, key)
    configured = Application.get_env(:ouroboros, :wasm, [])

    value =
      if Keyword.keyword?(configured), do: Keyword.get(configured, key, default), else: default

    if valid?(key, value), do: value, else: default
  end

  @doc "Every setting and its effective value, for status surfaces and tests."
  @spec all() :: keyword()
  def all, do: Enum.map(@defaults, fn {key, _default} -> {key, config(key)} end)

  defp valid?(:helper_path, :bundled), do: true

  defp valid?(:helper_path, value),
    do: is_binary(value) and value != "" and absolute_path?(value)

  # All three bounds or none of them. An operator who writes two of the keys gets the
  # documented default for all three rather than a silently half-configured instance, which
  # is the same fallback-on-typo posture as every other setting here — applied to the value
  # this one actually is.
  defp valid?(key, value) when key in @limits_keys do
    Keyword.keyword?(value) and Keyword.keys(value) -- @limit_keys == [] and
      Enum.all?(@limit_keys, fn key ->
        case Keyword.fetch(value, key) do
          {:ok, bound} -> is_integer(bound) and bound > 0
          :error -> false
        end
      end)
  end

  defp valid?(:allow_store_root_override, value), do: is_boolean(value)

  defp valid?(key, value) when key in @timeout_keys, do: is_integer(value) and value > 0
  defp valid?(key, value) when key in @byte_keys, do: is_integer(value) and value > 0

  defp absolute_path?(path), do: Path.type(path) == :absolute

  defp candidates do
    # Two candidates, and neither is derived from the working directory (F1). A bare
    # `Path.expand("priv/wasm/…")` and a walk up the cwd's ancestors were both here and both
    # are gone: they let whatever directory the daemon happened to be started in — a cloned
    # repository, a worktree an agent wrote — name the binary this node spawns as its
    # containment boundary, and the bare form additionally raised `File.Error` when the
    # working directory had been removed out from under a running node. What remains is the
    # installation's own `priv/` and the binary that ships beside `ouro`, both of which are
    # as trusted as the release itself.
    [
      priv_helper(),
      sibling_helper(:os.find_executable(~c"ouro"))
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp priv_helper do
    case :code.priv_dir(:ouroboros) do
      priv when is_list(priv) -> Path.join([List.to_string(priv), "wasm", @helper])
      _bad_name -> nil
    end
  end

  defp sibling_helper(false), do: nil

  defp sibling_helper(path) when is_list(path),
    do: Path.join(Path.dirname(List.to_string(path)), @helper)
end
