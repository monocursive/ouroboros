defmodule Ouroboros.Provider.Native.Mcp.Supervisor do
  @moduledoc """
  The MCP subtree: a dynamic supervisor for server processes and the pool that decides
  what runs under it.

  `rest_for_one`, because the pool's table of live servers is only true while the
  supervisor holding them is the one it started them under. If that supervisor dies the
  pool must rebuild rather than hand out pids to processes that no longer exist.

  One instance runs where the native provider runs, unconditionally, because it is lazy:
  no MCP server exists until a session asks for one. `config :ouroboros, :mcp,
  enabled: false` makes every entry point in `Ouroboros.Provider.Native.Mcp` answer as
  if nothing were configured, without changing the tree. Tests start their own instance
  under a different name so they can shorten idle windows and point at a fake server
  without touching the node's.

  The restart intensity is deliberately generous, for the same reason
  `Ouroboros.CodeIntel.Supervisor`'s is: this subtree sits in the application's
  `rest_for_one` tail, so escalating would restart the gateway — and an MCP server
  failing is a state inside the pool, never a crash of it.
  """

  use Supervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    pool = Keyword.get(opts, :pool_name, Ouroboros.Provider.Native.Mcp.Pool)
    servers = Module.concat(pool, ServerSupervisor)

    pool_opts =
      opts
      |> Keyword.drop([:name, :pool_name])
      |> Keyword.merge(name: pool, server_supervisor: servers)

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: servers},
      {Ouroboros.Provider.Native.Mcp.Pool, pool_opts}
    ]

    Supervisor.init(children, strategy: :rest_for_one, max_restarts: 10, max_seconds: 60)
  end
end
