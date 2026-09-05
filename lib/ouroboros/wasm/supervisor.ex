defmodule Ouroboros.Wasm.Supervisor do
  @moduledoc """
  Owns the one `ouro-wasm` helper pool on a `:core` node, and since W22 on a `:builder` too:
  a builder reads the imports off the component it just built through this pool
  (`Ouroboros.Wasm.Forge`, docs/WASM.md D18), and without one it cannot finish a forge.

  The same tail posture as `Ouroboros.Provider.Native.Desktop.Supervisor` and
  `Ouroboros.Provider.Native.Mcp.Supervisor`: somebody else's program on the end of a pipe,
  spawned lazily, downstream of the gateway. It is unconditional because it is lazy — no
  helper exists until a request needs one, and a node that never built one never spawns one.

  Its runtime parent restarts the boot recovery task after this supervisor is replaced.
  Unrelated language-server, desktop, MCP, and web failures leave guest instances alive.

  Tests start their own named `Pool` and never touch this supervisor.
  """

  use Supervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    pool = Keyword.get(opts, :pool_name, Ouroboros.Wasm.Pool)

    children = [
      {Ouroboros.Wasm.Pool, opts |> Keyword.drop([:name, :pool_name]) |> Keyword.put(:name, pool)}
    ]

    Supervisor.init(children, strategy: :one_for_one, max_restarts: 10, max_seconds: 60)
  end
end
