defmodule Ouroboros.Provider.Native.Desktop.Supervisor do
  @moduledoc """
  Owns the one Computer Use helper pool on a `:core` node.

  The pool is lazy (it does not spawn the helper until a request or `probe` needs it)
  and owns nothing any plane rebuilds from. Its parent keeps it independent of the
  gateway and other helpers. Tests start their own named `Pool`.
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
