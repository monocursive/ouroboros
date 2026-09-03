defmodule Ouroboros.Wasm.ForgeFixture do
  @moduledoc """
  What a lane-W forge needs from the machine, and the projects the suites forge.

  `Ouroboros.Wasm.LiveFixture` answers the same question for the helper and the acceptance
  guest. Building a component needs more than either: cargo, the `wasm32-wasip2` target, a
  registry cache somebody warmed (D19), a checkout of the guest SDK to link against, and an
  OS sandbox to build inside — because `Ouroboros.Wasm.Forge` refuses to build without one.

  The same rule as `LiveFixture`: a developer's machine skips with the command that fixes
  it, and under `OUROBOROS_REQUIRE_WASM=1` the tests run anyway and `setup_all` fails them,
  because there a missing toolchain is a build step that did not happen.
  """

  alias Ouroboros.Wasm.Forge
  alias Ouroboros.Wasm.LiveFixture

  @project Path.expand("wasm_forge", __DIR__)
  @counter Path.expand("../../tui/wasm/guest/examples/counter", __DIR__)

  @doc "The scaffolded project every C9 test mutates, as a path-to-bytes map."
  @spec project() :: %{String.t() => binary()}
  def project, do: files(@project)

  @doc "Where that project lives, for a suite that needs a directory rather than a map."
  @spec project_root() :: Path.t()
  def project_root, do: @project

  @doc """
  The `counter` example, renamed so two runs cannot claim one mesh id.

  The name lives in three places that have to agree — the package, the lock's own entry, and
  the file cargo emits — which is exactly the identity `Ouroboros.Wasm.Forge` derives from
  the manifest rather than accepts from a caller.
  """
  @spec counter(String.t()) :: %{String.t() => binary()}
  def counter(name) do
    ~w(Cargo.toml Cargo.lock src/lib.rs)
    |> Map.new(fn path ->
      {path,
       @counter
       |> Path.join(path)
       |> File.read!()
       |> String.replace(~s(name = "counter"), ~s(name = "#{name}"))}
    end)
  end

  @doc "The `@tag` a test that builds a component should carry: `[]`, or `[skip: reason]`."
  @spec tag() :: keyword()
  def tag do
    case missing() do
      nil -> LiveFixture.tag()
      reason -> if LiveFixture.required?(), do: [], else: [skip: reason]
    end
  end

  @doc "Raises when this run requires a live build and this machine cannot do one."
  @spec ensure!() :: :ok
  def ensure! do
    LiveFixture.ensure!()

    case missing() do
      nil -> :ok
      reason -> if LiveFixture.required?(), do: raise(reason), else: :ok
    end
  end

  @doc """
  The cargo home these suites build against, as an operator naming their own would.

  `Ouroboros.Wasm.Forge`'s default is node-local — `<data_dir>/wasm/cargo-home`, warmed by
  `make wasm-sdk-cache` — and a test that used it would warm a fresh cache per temporary data
  directory, which is a download per test rather than a build. Naming `~/.cargo` is the same
  thing an operator does on a developer machine, and the node-local default has a test of its
  own that does not build.
  """
  @spec cargo_home() :: Path.t()
  def cargo_home do
    case System.get_env("CARGO_HOME") do
      path when is_binary(path) and path != "" -> path
      _unset -> Path.expand("~/.cargo")
    end
  end

  @doc "The first thing that is not here, said the way an operator has to fix it."
  @spec missing() :: String.t() | nil
  def missing do
    toolchain = Forge.toolchain(cargo_home: cargo_home())

    cond do
      is_nil(toolchain.cargo) ->
        "no cargo on PATH; a :builder node needs the Rust toolchain to forge a component"

      not toolchain.target_installed? ->
        "no wasm32-wasip2 target; run `rustup target add wasm32-wasip2`"

      toolchain.cache != :warm ->
        "cold cargo registry cache at #{toolchain.cargo_home || "(no data directory)"}; " <>
          "run `make wasm-sdk-cache`"

      is_nil(toolchain.sdk) ->
        "no guest SDK checkout at tui/wasm/guest to build a component against"

      toolchain.sandbox == "none" ->
        "no OS sandbox backend on this node; the forge refuses to build without one"

      true ->
        nil
    end
  end

  defp files(root) do
    root
    |> Path.join("**")
    |> Path.wildcard()
    |> Enum.filter(&File.regular?/1)
    |> Map.new(fn path -> {Path.relative_to(path, root), File.read!(path)} end)
  end
end
