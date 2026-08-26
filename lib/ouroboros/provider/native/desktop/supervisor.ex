defmodule Ouroboros.Provider.Native.Desktop.Supervisor do
  @moduledoc """
  Owns the one Computer Use helper pool on a `:core` node.

  Same tail posture as `Ouroboros.Provider.Native.Mcp.Supervisor`: the pool is lazy (it
  does not spawn the helper until a request or `probe` needs it), owns nothing any plane
  rebuilds from, and sits downstream of the gateway so a helper crash restarts nothing
  else. Tests start their own named `Pool` and never touch this supervisor.
  """

  use Supervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    pool = Keyword.get(opts, :pool_name, Ouroboros.Provider.Native.Desktop.Pool)

    children = [
      {Ouroboros.Provider.Native.Desktop.Pool, Keyword.merge(opts, name: pool)}
    ]

    Supervisor.init(children, strategy: :one_for_one, max_restarts: 10, max_seconds: 60)
  end
end
