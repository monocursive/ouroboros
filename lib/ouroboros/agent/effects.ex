defmodule Ouroboros.Agent.Effects do
  @moduledoc """
  The actions that let an agent act on the world, and the grant that gates each one.

  Every other action in this codebase is a pure state projection: it reads a signal and
  writes the agent's own state. These six reach outside — they start and stop mesh
  agents, message them, delegate real coding work through a team, forge a capability from
  source, and deploy that capability onto nodes. They are wired into
  `Ouroboros.Agent.Worker` as ordinary signal routes, so an agent acts by receiving a
  typed signal, exactly like everything else it does.

  Each action does the same four things, through `Ouroboros.Agent.Effects.Runner`:

    * the acting principal is `context.agent.id`, the identity the agent server holds.
      The `from` field on the signal is recorded as `claimed_from` and authorizes
      nothing, so one agent cannot spend another's grants by claiming its name;
    * the concrete attempt — this module, this team, these nodes — is put to
      `Ouroboros.Control.Grants`, which is deny-by-default;
    * a permitted effect runs in a supervised task bounded by
      `config :ouroboros, :effect_timeout`, never on the agent's own process;
    * the outcome settles back into `last_effects`, a bounded ring, alongside the
      refusals.

  A refusal is returned as `{:error, {:effect_denied, effect, reason}}` — an ordinary
  action error, so Jido records an error directive and the agent keeps running. A
  failure *after* the effect started is returned to nobody, because the request already
  succeeded in starting it; it settles into the trail as
  `{:effect_failed, effect, reason}`, timeouts included. The trail, not the reply, is
  where an effect's outcome lives.

  This surface has no grant action, so an agent cannot widen its own authority through
  it. That is a property of the surface and not of the VM — see
  `Ouroboros.Control.Grants` for what this does and does not defend against.
  """

  alias Ouroboros.Agent.Effects.Runner
  alias Ouroboros.Mesh
  alias Ouroboros.Team
  alias Ouroboros.Upgrade.Forge
  alias Ouroboros.Upgrade.Forge.Source
  alias Ouroboros.Upgrade.Rollout

  @doc "Every grant-gated effect action, plus the settlement action that records them."
  @spec actions() :: [module()]
  def actions do
    [
      __MODULE__.StartAgent,
      __MODULE__.StopAgent,
      __MODULE__.SendMessage,
      __MODULE__.DelegateTask,
      __MODULE__.ForgeCapability,
      __MODULE__.DeployCapability,
      __MODULE__.RecordEffect
    ]
  end

  @doc "The signal routes an agent needs to reach them."
  @spec signal_routes() :: [{String.t(), module()}]
  def signal_routes do
    [
      {"ouroboros.agent.effect.start_agent", __MODULE__.StartAgent},
      {"ouroboros.agent.effect.stop_agent", __MODULE__.StopAgent},
      {"ouroboros.agent.effect.send_message", __MODULE__.SendMessage},
      {"ouroboros.agent.effect.delegate", __MODULE__.DelegateTask},
      {"ouroboros.agent.effect.forge", __MODULE__.ForgeCapability},
      {"ouroboros.agent.effect.deploy", __MODULE__.DeployCapability},
      {"ouroboros.agent.effect.settled", __MODULE__.RecordEffect}
    ]
  end

  defmodule StartAgent do
    @moduledoc false

    use Jido.Action,
      name: "start_mesh_agent",
      description: "Start another mesh agent, if this agent is granted :start_agent",
      schema: [
        from: [type: :string, required: true],
        agent_id: [type: :string, required: true],
        module: [type: :atom, required: true],
        role: [type: :any, default: nil],
        objective: [type: :any, default: nil],
        initial_state: [type: :map, default: %{}]
      ]

    @impl true
    def run(params, context) do
      Runner.dispatch(:start_agent, %{module: params.module}, &start(params, &1), params, context)
    end

    # The grant admits the module; `Ouroboros.Mesh` still applies its own namespace
    # allow-list, so `modules: :any` is "anything the mesh would start", not "anything".
    defp start(params, _principal) do
      case Mesh.start_agent(params.agent_id, start_opts(params)) do
        {:ok, pid} ->
          {:ok, %{agent_id: params.agent_id, module: params.module, node: node(pid)}}

        {:error, reason} ->
          {:error, reason}
      end
    end

    # Only what the signal asked for is seeded. A helpfully-added `:parent_id` would seed
    # a key a forged capability's schema has never heard of and fail its start.
    defp start_opts(params) do
      [agent: params.module, role: params.role, objective: params.objective]
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Keyword.put(:initial_state, params.initial_state)
    end
  end

  defmodule StopAgent do
    @moduledoc false

    use Jido.Action,
      name: "stop_mesh_agent",
      description: "Stop a mesh agent, if this agent is granted :stop_agent",
      schema: [
        from: [type: :string, required: true],
        agent_id: [type: :string, required: true]
      ]

    @impl true
    def run(params, context) do
      Runner.dispatch(:stop_agent, %{agent: params.agent_id}, &stop(params, &1), params, context)
    end

    defp stop(params, _principal) do
      case Mesh.stop_agent(params.agent_id) do
        :ok -> {:ok, %{agent_id: params.agent_id}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defmodule SendMessage do
    @moduledoc false

    use Jido.Action,
      name: "send_mesh_message",
      description: "Message another mesh agent, if this agent is granted :send_message",
      schema: [
        from: [type: :string, required: true],
        to: [type: :string, required: true],
        body: [type: :any, required: true]
      ]

    @impl true
    def run(params, context) do
      Runner.dispatch(:send_message, %{agent: params.to}, &send_to(params, &1), params, context)
    end

    # The `from` that travels on the wire is the principal, not the claim, so the
    # receiving agent's inbox records who actually sent it.
    defp send_to(params, principal) do
      case Mesh.send_message(principal, params.to, params.body) do
        {:ok, agent} ->
          {:ok,
           %{
             to: params.to,
             from: principal,
             messages_received: Map.get(agent.state, :messages_received)
           }}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defmodule DelegateTask do
    @moduledoc false

    use Jido.Action,
      name: "delegate_team_task",
      description: "Delegate an objective through a team, if this agent is granted :delegate",
      schema: [
        from: [type: :string, required: true],
        team: [type: :string, required: true],
        worker_id: [type: :string, required: true],
        objective: [type: :string, required: true],
        options: [type: :keyword_list, default: []]
      ]

    @impl true
    def run(params, context) do
      Runner.dispatch(:delegate, %{team: params.team}, &delegate(params, &1), params, context)
    end

    defp delegate(params, _principal) do
      with pid when is_pid(pid) <- Team.whereis(params.team),
           {:ok, delegation} <-
             Team.delegate(pid, params.worker_id, params.objective, params.options),
           {:ok, delivered} <- Team.await(pid, delegation.id, await_timeout()) do
        {:ok,
         %{
           team: params.team,
           worker_id: params.worker_id,
           delegation_id: delegation.id,
           status: delivered.status,
           delivery: delivered.delivery,
           result: delivered.result
         }}
      else
        nil -> {:error, {:team_not_found, params.team}}
        {:error, reason} -> {:error, reason}
      end
    end

    # The await has to lose the race with the runner's deadline. A brutally killed
    # awaiter would leave a waiter registered on a team that is still perfectly healthy;
    # a graceful `{:error, :timeout}` withdraws it.
    defp await_timeout, do: max(Runner.timeout() - 5_000, 1_000)
  end

  defmodule ForgeCapability do
    @moduledoc false

    use Jido.Action,
      name: "forge_capability",
      description: "Forge a capability from source, if this agent is granted :forge",
      schema: [
        from: [type: :string, required: true],
        module: [type: :atom, required: true],
        source: [type: :string, required: true],
        test_source: [type: :any, default: nil],
        nodes: [type: {:list, :atom}, default: []],
        signer_id: [type: :any, default: nil]
      ]

    @impl true
    def run(params, context) do
      Runner.dispatch(:forge, %{module: params.module}, &forge(params, &1), params, context)
    end

    # The recorded author is the principal, so the provenance inside the signed manifest
    # names the agent this VM believes acted, not the one the signal claimed to be.
    defp forge(params, principal) do
      nodes = nodes(params.nodes)

      with {:ok, source} <- source(params, principal),
           {:ok, artifact} <- Forge.forge(source, forge_opts(params, nodes)) do
        {:ok,
         %{
           artifact: artifact,
           artifact_id: artifact.id,
           module: params.module,
           epoch: artifact.epoch,
           signer: artifact.signature.signer,
           source_sha256: source.sha256,
           nodes: nodes
         }}
      end
    end

    defp source(params, principal) do
      Source.new(
        module: params.module,
        source: params.source,
        test_source: params.test_source,
        author: principal
      )
    end

    defp forge_opts(%{signer_id: signer_id}, nodes) when is_binary(signer_id),
      do: [nodes: nodes, signer_id: signer_id]

    defp forge_opts(_params, nodes), do: [nodes: nodes]

    defp nodes([]), do: [node()]
    defp nodes(nodes), do: nodes
  end

  defmodule DeployCapability do
    @moduledoc false

    use Jido.Action,
      name: "deploy_capability",
      description: "Deploy a forged artifact, if this agent is granted :deploy",
      schema: [
        from: [type: :string, required: true],
        artifact_id: [type: :string, required: true],
        nodes: [type: {:list, :atom}, default: []]
      ]

    @impl true
    def run(params, context) do
      nodes = nodes(params.nodes)

      Runner.dispatch(
        :deploy,
        %{nodes: nodes},
        &deploy(params, forged(context), nodes, &1),
        params,
        context
      )
    end

    defp forged(%{agent: %{state: %{forged: forged}}}) when is_list(forged), do: forged
    defp forged(_context), do: []

    # The artifact is resolved from what this agent forged, never from the signal, so a
    # deploy can only ship bytes that already came back through a granted forge.
    defp deploy(params, forged, nodes, _principal) do
      case Enum.find(forged, &(&1.artifact_id == params.artifact_id)) do
        %{artifact: artifact, module: module} ->
          artifact |> Rollout.deploy(module, nodes) |> settle(params, module, nodes)

        nil ->
          {:error, {:unknown_artifact, params.artifact_id}}
      end
    end

    defp settle({:ok, outcome}, params, module, nodes) do
      {:ok,
       %{
         artifact_id: params.artifact_id,
         module: module,
         epoch: outcome.epoch,
         nodes: nodes,
         state: outcome.state
       }}
    end

    # A deployment receipt carries per-node evidence that belongs in the rollout
    # registry, which already has it. The trail keeps the verdict and the pointer.
    defp settle({:error, {state, outcome}}, params, module, nodes) when is_atom(state) do
      {:error,
       {:rollout_not_live,
        %{
          state: state,
          artifact_id: params.artifact_id,
          module: module,
          nodes: nodes,
          epoch: Map.get(outcome, :epoch)
        }}}
    end

    defp settle({:error, reason}, _params, _module, _nodes), do: {:error, reason}

    defp nodes([]), do: [node()]
    defp nodes(nodes), do: nodes
  end

  defmodule RecordEffect do
    @moduledoc false

    use Jido.Action,
      name: "record_agent_effect",
      description: "Fold a settled effect outcome into this agent's audit trail",
      schema: [
        effect_id: [type: :string, required: true],
        effect: [type: :atom, required: true],
        status: [type: :atom, required: true],
        principal: [type: :any, default: nil],
        claimed_from: [type: :any, default: nil],
        attempt: [type: :map, default: %{}],
        result: [type: :any, default: nil],
        error: [type: :any, default: nil]
      ]

    @impl true
    def run(params, %{agent: agent}), do: Runner.settle(agent.state, params)
  end
end
