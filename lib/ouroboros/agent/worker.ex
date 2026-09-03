defmodule Ouroboros.Agent.Worker do
  @moduledoc """
  The inspectable state projection for one coding subagent, and its effect surface.

  `Ouroboros.Team.Server` connects these typed assignments to detached provider runs
  through `Ouroboros.CodingSession`; this agent retains the worker-facing task and
  result state in a supervised BEAM process.

  The task and message actions are pure state projections. The effect actions from
  `Ouroboros.Agent.Effects` are not: they start and stop mesh agents, delegate through
  teams, and drive the forge. Every one of them is deny-by-default and gated by
  `Ouroboros.Control.Grants` against this agent's own server-side identity, and every
  outcome — refusals included — lands in the durable `Agent.EffectLedger` and the
  agent-local `last_effects` projection.
  """

  alias Ouroboros.Agent.Effects

  use Jido.Agent,
    name: "ouroboros_worker",
    description: "A supervised member of an Ouroboros coding-agent team",
    schema: [
      role: [type: :string, default: "worker"],
      objective: [type: :any, default: nil],
      status: [type: :atom, default: :idle],
      parent_id: [type: :any, default: nil],
      current_task: [type: :any, default: nil],
      inbox: [type: :list, default: []],
      messages_received: [type: :non_neg_integer, default: 0],
      last_message: [type: :any, default: nil],
      last_answer: [type: :any, default: nil],
      # The bounded audit trail of everything this agent tried to do to the world,
      # newest first, alongside the effects still running and the artifacts it forged.
      # All three are lists because Jido merges an action's result into agent state
      # deeply: a key removed from a returned map is merged back in, a replaced list is
      # not, and settling an effect has to be able to forget it.
      last_effects: [type: :list, default: []],
      effects_in_flight: [type: :list, default: []],
      forged: [type: :list, default: []],
      error: [type: :any, default: nil]
    ],
    signal_routes: [
      {"ouroboros.agent.message", __MODULE__.ReceiveMessage},
      {"ouroboros.agent.task.assigned", __MODULE__.AssignTask},
      {"ouroboros.agent.task.completed", __MODULE__.CompleteTask},
      {"ouroboros.agent.effect.start_agent", Ouroboros.Agent.Effects.StartAgent},
      {"ouroboros.agent.effect.stop_agent", Ouroboros.Agent.Effects.StopAgent},
      {"ouroboros.agent.effect.send_message", Ouroboros.Agent.Effects.SendMessage},
      {"ouroboros.agent.effect.delegate", Ouroboros.Agent.Effects.DelegateTask},
      {"ouroboros.agent.effect.forge", Ouroboros.Agent.Effects.ForgeCapability},
      {"ouroboros.agent.effect.deploy", Ouroboros.Agent.Effects.DeployCapability},
      {"ouroboros.agent.effect.forge_wasm", Ouroboros.Agent.Effects.ForgeWasmCapability},
      {"ouroboros.agent.effect.deploy_wasm", Ouroboros.Agent.Effects.DeployWasmCapability},
      {"ouroboros.agent.effect.settled", Ouroboros.Agent.Effects.RecordEffect}
    ]

  @doc "Every action this agent can execute, effect actions included."
  def actions do
    super() ++
      [__MODULE__.ReceiveMessage, __MODULE__.AssignTask, __MODULE__.CompleteTask] ++
      Effects.actions()
  end

  defmodule ReceiveMessage do
    @moduledoc false

    use Jido.Action,
      name: "receive_agent_message",
      description: "Record a typed message from another agent",
      schema: [
        from: [type: :string, required: true],
        body: [type: :any, required: true],
        correlation_id: [type: :string, required: true],
        causation_id: [type: :any, default: nil]
      ]

    @max_inbox 64
    @max_inbox_bytes 1024 * 1024

    # W13/F9. The inbox keeps the newest #{@max_inbox} messages and at most
    # #{div(@max_inbox_bytes, 1024)} KiB of them, oldest dropped first.
    #
    # It was unbounded, and `agents.message` is what made that reachable: any `:operate`
    # gateway client, from any node in the cluster, can now send this agent a 64 KiB body as
    # often as it likes, and every one of them was retained forever in a list nothing
    # pruned. A mailbox is a *recent* record — that is what makes it useful to a reader and
    # what makes `last_message` the field the rest of this runtime actually reads — so the
    # bound is on both counts, because either one alone is a way past the other: sixty-four
    # 64 KiB bodies is four megabytes, and four million one-byte bodies is the same problem
    # spelled differently.
    @impl true
    def run(params, %{agent: agent}) do
      message = %{
        from: params.from,
        body: params.body,
        correlation_id: params.correlation_id,
        causation_id: params.causation_id
      }

      {:ok,
       %{
         inbox: bound_inbox(agent.state.inbox ++ [message]),
         last_message: message,
         messages_received: agent.state.messages_received + 1
       }}
    end

    # Newest kept, oldest dropped, count first and then bytes. `external_size/1` measures a
    # term without building the binary, so measuring a megabyte costs nothing.
    defp bound_inbox(inbox) do
      inbox
      |> Enum.take(-@max_inbox)
      |> trim_bytes()
    end

    defp trim_bytes([_only] = inbox), do: inbox

    defp trim_bytes([_ | rest] = inbox) do
      if :erlang.external_size(inbox) > @max_inbox_bytes, do: trim_bytes(rest), else: inbox
    end

    defp trim_bytes([]), do: []
  end

  defmodule AssignTask do
    @moduledoc false

    use Jido.Action,
      name: "assign_agent_task",
      description: "Assign an objective to an agent",
      schema: [
        from: [type: :string, required: true],
        task_id: [type: :string, required: true],
        objective: [type: :string, required: true],
        correlation_id: [type: :string, required: true]
      ]

    @impl true
    def run(params, _context) do
      {:ok,
       %{
         parent_id: params.from,
         current_task: params.task_id,
         objective: params.objective,
         status: :working,
         error: nil
       }}
    end
  end

  defmodule CompleteTask do
    @moduledoc false

    use Jido.Action,
      name: "complete_agent_task",
      description: "Complete the current objective and retain its result",
      schema: [
        task_id: [type: :string, required: true],
        result: [type: :any, required: true]
      ]

    @impl true
    def run(%{task_id: task_id, result: result}, %{agent: agent}) do
      if agent.state.current_task == task_id do
        {:ok, %{status: :completed, last_answer: result}}
      else
        {:error, {:task_mismatch, agent.state.current_task, task_id}}
      end
    end
  end
end
