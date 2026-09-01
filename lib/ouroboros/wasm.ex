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

    1. `OUROBOROS_WASM_HELPER` — an operator pointing at a build of their own;
    2. a configured absolute `helper_path` under `config :ouroboros, :wasm`;
    3. the first existing candidate: the application's `priv/` (which is the `_build`
       fan-out `make wasm` writes), the checkout's `priv/wasm/`, a parent walk from the
       working directory, or a sibling of `ouro` itself.

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
    store_budget_bytes: 512 * 1024 * 1024
  ]

  @timeout_keys [:handshake_timeout_ms, :request_timeout_ms, :call_margin_ms, :broken_ms]
  @byte_keys [:max_frame_bytes, :store_budget_bytes]

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
        path

      _unset ->
        case config(:helper_path) do
          path when is_binary(path) and path != "" ->
            path

          _bundled ->
            # The first candidate that exists; failing that, the first candidate as the name
            # a `doctor` would report; failing even that, the bare helper name. Always a
            # string and never `hd([])` — none of these paths touches the working directory,
            # so a removed cwd cannot raise here.
            Enum.find(candidates(), &File.regular?/1) || List.first(candidates()) || @helper
        end
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
  defp valid?(:helper_path, value), do: is_binary(value) and value != ""
  defp valid?(key, value) when key in @timeout_keys, do: is_integer(value) and value > 0
  defp valid?(key, value) when key in @byte_keys, do: is_integer(value) and value > 0

  defp candidates do
    # No bare `Path.expand("priv/wasm/…")` candidate: it raises `File.Error` when the working
    # directory has been removed out from under a running node — turning `Pool.init/1` into a
    # supervisor restart storm — and it is attacker-influenceable through cwd. `walk_priv_helper/0`
    # subsumes it (its first iteration is the checkout's own `priv/wasm/`) and guards `File.cwd()`.
    [
      priv_helper(),
      walk_priv_helper(),
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

  defp walk_priv_helper do
    case File.cwd() do
      {:ok, cwd} ->
        cwd
        |> Stream.iterate(&Path.dirname/1)
        |> Enum.take(6)
        |> Enum.find_value(fn dir ->
          path = Path.join([dir, "priv", "wasm", @helper])
          if File.regular?(path), do: path
        end)

      {:error, _reason} ->
        nil
    end
  end

  defp sibling_helper(false), do: nil

  defp sibling_helper(path) when is_list(path),
    do: Path.join(Path.dirname(List.to_string(path)), @helper)
end
