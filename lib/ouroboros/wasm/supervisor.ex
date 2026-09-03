defmodule Ouroboros.Wasm.Supervisor do
  @moduledoc """
  Owns the one `ouro-wasm` helper pool on a `:core` node.

  The same tail posture as `Ouroboros.Provider.Native.Desktop.Supervisor` and
  `Ouroboros.Provider.Native.Mcp.Supervisor`: somebody else's program on the end of a pipe,
  spawned lazily, downstream of the gateway. It is unconditional because it is lazy — no
  helper exists until a request needs one, and a node that never built one never spawns one.

  It leads those two in the tail, which is the one thing about it that is not a copy. Under
  `rest_for_one` the child that goes first is the one whose state the others' crashes must
  not discard, and a wasm pool restart discards live instances: guest state that only `init`
  and every message since can approximate, with no snapshot anywhere to rebuild it from. The
  desktop pool's per-session map is rebuilt by the next capture and MCP's ports are
  disposable, so paying for an improbable wasm crash with those is the cheaper trade than
  paying for an improbable MCP crash with a running guest.

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
