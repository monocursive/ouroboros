defmodule Ouroboros.CodeIntel.Supervisor do
  @moduledoc """
  The code-intelligence subtree: a dynamic supervisor for language-server processes and
  the pool that decides what runs under it.

  `rest_for_one`, because the pool's table of live servers is only true while the
  supervisor holding them is the one it started them under. If that supervisor dies, the
  pool must rebuild rather than hand out pids to processes that no longer exist.

  One instance runs on a `:core` node, unconditionally, because it is lazy: no language
  server exists until a caller asks for one. `OUROBOROS_CODE_INTEL=0` makes every entry
  point in `Ouroboros.CodeIntel` answer `{:error, :disabled}` without changing the tree.
  Tests start their own instance under a different name so they can shorten idle windows
  and inject a memory reader without touching the node's.

  The restart intensity is deliberately generous. This subtree sits in the application's
  `rest_for_one` tail, so escalating restarts the account boundary and the gateway — and a
  language-server failure is a state inside the pool, never a crash of it. The pool has to
  be genuinely, repeatedly broken before anything outside code intelligence notices.
  """

  use Supervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    pool = Keyword.get(opts, :pool_name, Ouroboros.CodeIntel.LspPool)
    servers = Module.concat(pool, ServerSupervisor)

    pool_opts =
      opts
      |> Keyword.drop([:name, :pool_name])
      |> Keyword.merge(name: pool, server_supervisor: servers)

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: servers},
      {Ouroboros.CodeIntel.LspPool, pool_opts}
    ]

    Supervisor.init(children, strategy: :rest_for_one, max_restarts: 10, max_seconds: 60)
  end
end
