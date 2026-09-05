defmodule Ouroboros.Application.RegistryOwner do
  @moduledoc false

  use GenServer

  # A Registry supervisor can report its own death before its named partition has
  # finished terminating. Restarting it immediately spins on :already_started and
  # can exhaust the parent supervisor's restart intensity. Keep that race inside a
  # tiny ownership boundary and only let rest_for_one proceed after cleanup has had
  # a scheduler turn.
  @cleanup_delay_ms 25

  def child_spec(opts) do
    name = Keyword.fetch!(opts, :name)

    %{
      id: {__MODULE__, name},
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor,
      shutdown: :infinity
    }
  end

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    parent = opts |> Keyword.get(:parent, List.first(Process.get(:"$ancestors")))
    registry_opts = Keyword.delete(opts, :parent)

    case Registry.start_link(registry_opts) do
      {:ok, registry} -> {:ok, %{parent: parent, registry: registry}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_info({:EXIT, registry, reason}, %{registry: registry} = state) do
    Process.sleep(@cleanup_delay_ms)
    {:stop, {:registry_exited, reason}, %{state | registry: nil}}
  end

  def handle_info({:EXIT, parent, reason}, %{parent: parent} = state),
    do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{registry: registry}) when is_pid(registry) do
    if Process.alive?(registry) do
      try do
        Supervisor.stop(registry, :shutdown, :infinity)
      catch
        :exit, _reason -> :ok
      end
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok
end

defmodule Ouroboros.Application do
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    # Resolved before anything is supervised, because it decides what gets supervised.
    # An unrecognized role raises here rather than booting the privileged tree.
    role = Ouroboros.Cluster.boot_role!()

    Supervisor.start_link(children(role),
      strategy: :rest_for_one,
      name: Ouroboros.Supervisor
    )
  end

  # D7's recoverable half runs as a supervised one-shot task after the workspace manager
  # starts, so boot never waits on Git or on a slow filesystem.
  #
  # It runs **once per VM**, not once per manager restart: the child spec below is
  # `restart: :temporary`, and a supervisor drops temporary children from the list it
  # restarts after a sibling's crash rather than starting them again. Reconciliation is a
  # boot-time sweep of worktrees that outlived a previous run, and a manager restart does not
  # create more of those, so once is the right number — but the `rest_for_one` chain is not
  # what makes it happen, and this comment used to claim it was (F6). The lane-W boot task
  # beside it needs the opposite and is `:transient` for that reason.
  defp reconcile_worktrees do
    if Application.get_env(:ouroboros, :workspace_allowed_roots, []) != [] do
      report = Ouroboros.Workspace.Worktree.reconcile()

      if report.removed != [] or report.kept != [] do
        Logger.info(
          "worktree reconcile: removed #{length(report.removed)}, " <>
            "kept #{length(report.kept)} holding uncommitted changes, " <>
            "forgot #{length(report.missing)} already gone" <> retained(report.kept)
        )
      end
    end
  rescue
    error -> Logger.warning("worktree reconcile failed: #{Exception.message(error)}")
  end

  defp retained([]), do: ""

  defp retained(kept),
    do: "; retained: " <> Enum.map_join(kept, ", ", & &1.path)

  # A `:builder` node is a least-privileged member of the same release: it holds the code
  # and the cluster membership needed to be asked for a build, and nothing else. A lane-B
  # build is `:peer.start/1` plus a call, so cluster formation alone was the honest minimum
  # for it. A lane-W build is not: `Ouroboros.Wasm.Forge.forge_here/2` reads the imports off
  # the component it just built through this node's own helper pool (docs/WASM.md D18), and a
  # builder with no pool answered every forwarded forge `{:imports_unreadable,
  # {:pool_unavailable, …}}` — found the first time a forward crossed a real node boundary
  # (W22, §13 W-F31). The pool is lazy and owns nothing durable, so the posture is unchanged:
  # no teams, stores, schedulers, registries, workspaces, recovery loops, or control plane
  # exist on that host to be reached.
  defp children(:builder), do: [Ouroboros.Cluster, Ouroboros.Wasm.Supervisor]

  # A `:signer` node is the same posture plus the one process its role names. The service
  # owns a key, a policy, and a durable decision journal; it refuses to boot without all
  # three, so a signer host that is misconfigured fails here rather than at the first
  # request. After the role-neutral durable-directory owner, it leads the role-specific
  # chain for the reason cluster formation trails it everywhere else: formation connects
  # this node to a cluster that can then ask it for signatures, and there is no reason to
  # be askable before the key is loaded.
  defp children(:signer) do
    runtime_boundary_children([]) ++
      [Ouroboros.Upgrade.Signing.Service, Ouroboros.Cluster]
  end

  defp children(:core) do
    children =
      runtime_boundary_children([Ouroboros.Provider.RuntimeCache]) ++
        [
          # The effect ledger leads every process that can originate an effect. If its
          # durable authority restarts, rest_for_one stops Jido's runners and agent
          # servers too; unfinished acknowledged attempts then recover as ambiguous
          # instead of continuing beside a replacement empty ledger.
          Ouroboros.Agent.EffectLedger,
          # Native model admission is in-memory scheduling, not durable authority. It
          # sits after the ledger and before Jido so a lease-server crash restarts the
          # sessions that consume its leases — otherwise Finch connections outlive the
          # bound — without taking the ledger down with it.
          native_model_admission(),
          Ouroboros.Jido,
          %{
            id: Ouroboros.Mesh.Scope,
            start: {:pg, :start_link, [Ouroboros.Mesh.Scope]},
            type: :worker
          },
          Ouroboros.Mesh.Directory,
          Ouroboros.Upgrade.NodeExecutor,
          Ouroboros.Upgrade.Rollout.Registry,
          Ouroboros.Coding.Store,
          Ouroboros.Interactive.Store,
          Ouroboros.Team.Store,
          Ouroboros.Control.Grants,
          # The permission engine sits with the other durable authority, above every
          # session that consults it. If its store restarts, rest_for_one takes the
          # sessions down with it rather than letting a live provider session keep
          # answering approvals from a replacement empty rule set.
          Ouroboros.Control.Permissions,
          release_runtime()
        ] ++
        workspace_children() ++
        [
          # D3/D9. The native transport's own name space, keyed by `provider_session_id`.
          # `compact`/`handoff`/`context` are not harness callbacks, so the coordinator
          # has no worker method to reach them through; this is how it finds the process
          # without reading another supervisor's private state.
          {Ouroboros.Application.RegistryOwner,
           keys: :unique, name: Ouroboros.Provider.Native.Registry},
          # C4. The same idea for the remaining ACP JSONL transport, keyed by harness
          # session id. The pinned harness exposes its worker but not the transport handle
          # underneath it; ACP `session/set_mode` is a dialect verb the worker cannot carry.
          {Ouroboros.Application.RegistryOwner,
           keys: :unique, name: Ouroboros.Provider.Session.Registry},
          subtree(
            Ouroboros.Session.Supervisor,
            [
              subtree(
                Ouroboros.Coding.Supervisor,
                [
                  {Ouroboros.Application.RegistryOwner,
                   keys: :unique, name: Ouroboros.Coding.Registry},
                  {DynamicSupervisor,
                   strategy: :one_for_one, name: Ouroboros.Coding.TaskSupervisor},
                  Ouroboros.Coding.Recovery
                ],
                :rest_for_one
              ),
              subtree(
                Ouroboros.Interactive.Supervisor,
                [
                  {Ouroboros.Application.RegistryOwner,
                   keys: :unique, name: Ouroboros.Interactive.Registry},
                  {DynamicSupervisor,
                   strategy: :one_for_one, name: Ouroboros.Interactive.TaskSupervisor},
                  Ouroboros.Interactive.Recovery
                ],
                :rest_for_one
              ),
              subtree(
                Ouroboros.Team.RuntimeSupervisor,
                [
                  {Ouroboros.Application.RegistryOwner,
                   keys: :unique, name: Ouroboros.Team.Registry},
                  {DynamicSupervisor, strategy: :one_for_one, name: Ouroboros.Team.Supervisor},
                  Ouroboros.Team.Recovery
                ],
                :rest_for_one
              )
            ] ++ automation_children(),
            :one_for_one
          )
        ]

    # Shared durable stores stay above Workspace: it rebuilds reservations from them.
    # Ledger, admission, permissions, leases and provider registries still restart all
    # consumers downstream. Independent helper/surface failures stay within their tier.
    children ++
      [
        subtree(
          Ouroboros.Surface.Supervisor,
          [Ouroboros.Cluster, Ouroboros.Provider.OpenAIAuth, Ouroboros.Provider.GrokAuth] ++
            gateway_children() ++
            [
              Ouroboros.CodeIntel.Supervisor,
              subtree(
                Ouroboros.Wasm.RuntimeSupervisor,
                [Ouroboros.Wasm.Supervisor] ++ wasm_restart_children(),
                :rest_for_one
              ),
              Ouroboros.Provider.Native.Desktop.Supervisor,
              Ouroboros.Provider.Native.Mcp.Supervisor
            ] ++ web_children(),
          :one_for_one
        )
      ]
  end

  defp subtree(name, children, strategy) do
    %{
      id: name,
      start: {Supervisor, :start_link, [children, [strategy: strategy, name: name]]},
      type: :supervisor,
      shutdown: :infinity
    }
  end

  # Preserve existing behavior by default. Permission rules and grants remain core when
  # objective automation is disabled; session and native subagent APIs remain available.
  defp automation_children do
    if Application.get_env(:ouroboros, :automation_enabled, true) do
      [
        subtree(
          Ouroboros.Automation.Supervisor,
          [
            Ouroboros.Orchestration.Store,
            Ouroboros.Control.Store,
            orchestration_scheduler()
          ] ++ control_children(),
          :rest_for_one
        )
      ]
    else
      []
    end
  end

  # The lane-W half of the same idea as `reconcile_worktrees`: a supervised one-shot task,
  # started after the thing it needs — here the helper pool and, far upstream, the rollout
  # registry — so boot never waits on it.
  #
  # `restart: :transient` and not `:temporary`, which is what makes the sentence above about
  # the `rest_for_one` chain true (F6). A supervisor drops every *temporary* child from the
  # list it restarts after a sibling's crash — `supervisor:terminate_children/2` terminates
  # them and does not return them — so a temporary task here was started exactly once per VM
  # and a pool restart reran nothing, however the comment read. Transient is the shape this
  # needs: not restarted on its own normal exit (`Wasm.Boot.run/0` returns `:ok` and never
  # raises, so that is every ordinary run), and restarted when the chain takes it down.
  #
  # It is safe to rerun because it is idempotent by construction: a mesh id already claimed
  # by this component counts as started (`Ouroboros.Wasm.Boot`'s "Idempotent, by
  # construction"), and an id held by a *different* component is reported as failed rather
  # than fought over.
  #
  # Skipped entirely on a node with no durable data directory: no store means no manifests
  # and nothing that could have survived a reboot, which is every library start and every
  # test run.
  #
  # Public (undocumented) so `test/wasm/pool_test.exs` can read the restart type off the spec
  # this tree actually starts, rather than restating it.
  @doc false
  @spec wasm_restart_children() :: [Supervisor.child_spec()]
  def wasm_restart_children do
    if Ouroboros.Wasm.Boot.enabled?() do
      [
        %{
          id: Ouroboros.Wasm.Boot,
          start: {Task, :start_link, [&Ouroboros.Wasm.Boot.run/0]},
          restart: :transient
        }
      ]
    else
      []
    end
  end

  # A discovery publication is not runtime ownership. When this node has a durable data
  # directory, claim it before the first store, registry, session, signing journal, or
  # provider process can touch anything beneath it. Role-specific children run only after
  # the claim succeeds, and a restarted owner takes them and every consumer beneath it
  # through the `rest_for_one` recovery path. Test and library-only starts that configure
  # no data directory retain their in-memory posture. Core adds provider cache setup at
  # this boundary; signer owns only its key, policy, and durable decision journal.
  defp runtime_boundary_children(after_owner) do
    case Application.get_env(:ouroboros, :data_dir) do
      data_dir when is_binary(data_dir) and data_dir != "" ->
        [{Ouroboros.RuntimeOwner, data_dir: data_dir} | after_owner]

      _unset ->
        # Only the owner of a durable directory is dropped. The children behind it own no
        # durable state of their own and still belong in an in-memory tree.
        after_owner
    end
  end

  defp native_model_admission do
    {Ouroboros.Provider.Native.Model.Admission,
     limit: Application.get_env(:ouroboros, :native_model_max_concurrency, 8),
     queue_limit: Application.get_env(:ouroboros, :native_model_queue_limit, 32),
     queue_timeout_ms: Application.get_env(:ouroboros, :native_model_queue_timeout_ms, 120_000)}
  end

  # Absent configuration means no gateway at all — not a disabled one — so a test run, a
  # `:builder`, and a `:signer` never acquire a listener by inheriting a default.
  defp gateway_children do
    if Ouroboros.Gateway.Config.enabled?() do
      [{Ouroboros.Gateway, ready_application: :ouroboros}]
    else
      []
    end
  end

  # The same rule for the same reason: absent configuration means no web surface at all,
  # not a disabled one, so a test run, a `:builder`, and a `:signer` never acquire an
  # endpoint — or a bound port, or a published `web.json` — by inheriting a default.
  defp web_children do
    if Ouroboros.Web.Config.enabled?() do
      [Ouroboros.Web]
    else
      []
    end
  end

  defp workspace_children do
    case Application.get_env(:ouroboros, :workspace_allowed_roots, []) do
      [_ | _] ->
        [
          {Ouroboros.Workspace, recover_reservations: true},
          %{
            id: Ouroboros.Workspace.Worktree.Reconciler,
            start: {Task, :start_link, [fn -> reconcile_worktrees() end]},
            restart: :temporary
          }
        ]

      [] ->
        []
    end
  end

  defp orchestration_scheduler do
    opts =
      [
        max_concurrency: Application.get_env(:ouroboros, :orchestration_max_concurrency, 4),
        executors: orchestration_executors()
      ]

    {Ouroboros.Orchestration.Scheduler, opts}
  end

  # Each step kind gets its own executor. An explicit `:orchestration_executors`
  # entry wins over the per-kind configuration below, so an operator can name an
  # adapter this application does not know about. A kind with no executor is one
  # the scheduler refuses to accept plans for, which is why forge dispatch stays
  # off until `:orchestration_forge_options` says otherwise.
  defp orchestration_executors do
    configured = Application.get_env(:ouroboros, :orchestration_executors, %{})

    %{}
    |> put_executor(:coding, team_executor())
    |> put_executor(:forge, forge_executor())
    |> Map.merge(if(is_map(configured), do: configured, else: %{}))
  end

  defp put_executor(executors, _kind, nil), do: executors
  defp put_executor(executors, kind, executor), do: Map.put(executors, kind, executor)

  defp team_executor do
    case Application.get_env(:ouroboros, :orchestration_team_id) do
      team_id when is_binary(team_id) and byte_size(team_id) > 0 ->
        {Ouroboros.Orchestration.TeamExecutor,
         [
           team_id: team_id,
           worker_id: Application.get_env(:ouroboros, :orchestration_worker_id),
           coding_options: Application.get_env(:ouroboros, :orchestration_coding_options, [])
         ]}

      _other ->
        nil
    end
  end

  defp forge_executor do
    case Application.get_env(:ouroboros, :orchestration_forge_options, []) do
      [_ | _] = options -> {Ouroboros.Orchestration.ForgeExecutor, options}
      _other -> nil
    end
  end

  defp control_children do
    if Application.get_env(:ouroboros, :control_enabled, false) do
      [
        {Ouroboros.Control.Server,
         [
           store: Ouroboros.Control.Store,
           scheduler: Ouroboros.Orchestration.Scheduler,
           planner: Application.fetch_env!(:ouroboros, :control_planner),
           evaluator: Application.fetch_env!(:ouroboros, :control_evaluator),
           poll_interval: Application.get_env(:ouroboros, :control_poll_interval, 1_000)
         ]}
      ]
    else
      []
    end
  end

  defp release_runtime do
    {Ouroboros.Release.Runtime,
     [
       storage:
         Application.get_env(
           :ouroboros,
           :release_storage,
           {Jido.Storage.ETS, table: :ouroboros_releases}
         ),
       adapter:
         Application.get_env(
           :ouroboros,
           :release_handler_adapter,
           Ouroboros.Release.HandlerAdapter.OTP
         ),
       authorizer:
         Application.get_env(
           :ouroboros,
           :release_authorizer,
           Ouroboros.Release.Authorizer.Deny
         )
     ]}
  end
end
