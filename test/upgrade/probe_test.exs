defmodule Ouroboros.Capability.ProbeStartSpec do
  @moduledoc false

  # A capability whose reply is decided by the state it was started with. That is what makes
  # the start-spec generalization observable through the probe's own contract: `:echo_body`
  # seeded as `:verbatim` echoes the message and satisfies the echo check, and anything else
  # answers with that value instead and fails it. Nothing outside this module has to be
  # inspected to know whether the seed arrived.

  use Jido.Agent,
    name: "ouroboros_capability_probe_start_spec",
    description: "A capability whose echo is whatever its initial state says it is",
    schema: [
      echo_body: [type: :any, default: :verbatim],
      last_message: [type: :any, default: nil],
      messages_received: [type: :non_neg_integer, default: 0]
    ],
    signal_routes: [
      {"ouroboros.agent.message", __MODULE__.Answer}
    ]

  def actions, do: super() ++ [__MODULE__.Answer]

  defmodule Answer do
    @moduledoc false

    use Jido.Action,
      name: "probe_start_spec_answer",
      description: "Echo the body, or whatever the seeded state named instead",
      schema: [
        from: [type: :string, required: true],
        body: [type: :any, required: true],
        correlation_id: [type: :string, required: true],
        causation_id: [type: :any, default: nil]
      ]

    @impl true
    def run(params, %{agent: agent}) do
      echoed =
        case agent.state.echo_body do
          :verbatim -> params.body
          other -> other
        end

      {:ok,
       %{
         last_message: %{body: echoed},
         messages_received: agent.state.messages_received + 1
       }}
    end
  end
end

defmodule Ouroboros.Capability.SlowProbeAnswer do
  @moduledoc false

  # Starts instantly, answers slowly. That is what makes "the caller's deadline fired while
  # the throwaway agent was alive" a fact rather than a race: the probe is still inside its
  # message exchange, several seconds from finishing, when it is killed.

  use Jido.Agent,
    name: "ouroboros_capability_slow_probe_answer",
    description: "A capability that answers long after any deadline a caller sets",
    schema: [last_message: [type: :any, default: nil]],
    signal_routes: [{"ouroboros.agent.message", __MODULE__.Wait}]

  def actions, do: super() ++ [__MODULE__.Wait]

  defmodule Wait do
    @moduledoc false

    use Jido.Action,
      name: "slow_probe_answer_wait",
      description: "Sleeps past the deadline, then echoes",
      schema: [
        from: [type: :string, required: true],
        body: [type: :any, required: true],
        correlation_id: [type: :string, required: true],
        causation_id: [type: :any, default: nil]
      ]

    @impl true
    def run(params, _context) do
      Process.sleep(3_000)
      {:ok, %{last_message: %{body: params.body}}}
    end
  end
end

defmodule Ouroboros.Upgrade.ProbeTest do
  # Not async: every probe joins the node-wide `:pg` mesh namespace under an id of its own,
  # and `Ouroboros.Mesh` is a singleton.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.Worker
  alias Ouroboros.Capability.ProbeStartSpec
  alias Ouroboros.Capability.SlowProbeAnswer
  alias Ouroboros.Upgrade.Rollout.Probe

  describe "the bare module form, which is lane B's and always was" do
    test "an agent that starts, answers, and echoes is ready" do
      assert :ok = Probe.ready?(Worker)
    end

    test "a module that cannot be a mesh agent is a named refusal, not an exception" do
      assert {:error, {:probe_failed, Enum, {:probe_start_failed, _reason}}} = Probe.ready?(Enum)

      assert {:error,
              {:probe_failed, Ouroboros.Capability.NeverForged, {:capability_not_loaded, :nofile}}} =
               Probe.ready?(Ouroboros.Capability.NeverForged)
    end

    test "a term that is not a start spec at all is refused before anything is started" do
      assert {:error, {:invalid_probe_module, _rendered}} = Probe.ready?("not a module")
      assert {:error, {:invalid_probe_module, _rendered}} = Probe.ready?(nil)
      assert {:error, {:invalid_probe_module, _rendered}} = Probe.ready?({Worker, :not_a_map})
    end
  end

  describe "the {module, initial_state} form (D7)" do
    test "the seed reaches the agent, and the probe's own check proves it" do
      # Seeded to echo verbatim: the agent answers with the body the probe sent, which is
      # exactly what `sane_reply?/2` demands.
      assert :ok = Probe.ready?({ProbeStartSpec, %{echo_body: :verbatim}})

      # Seeded to answer with something else: the same module, the same probe, and a failure
      # naming what came back. Only the seed differs, so only the seed can explain it.
      assert {:error, {:probe_failed, ProbeStartSpec, {:probe_reply_not_echoed, rendered}}} =
               Probe.ready?({ProbeStartSpec, %{echo_body: "a different answer"}})

      assert rendered =~ "a different answer"
    end

    test "an empty seed is the bare module, which is what keeps lane B unchanged" do
      # `Ouroboros.Agent.Worker` is lane B's reference shape and is seeded with nothing by
      # either form. Both must be `:ok`, and for the same reason.
      assert :ok = Probe.ready?({Worker, %{}})
      assert :ok = Probe.ready?(Worker)
    end

    test "each probe gets its own agent, so no seed outlives the run that supplied it" do
      assert {:error, {:probe_failed, ProbeStartSpec, {:probe_reply_not_echoed, _rendered}}} =
               Probe.ready?({ProbeStartSpec, %{echo_body: "sticky"}})

      assert :ok = Probe.ready?({ProbeStartSpec, %{echo_body: :verbatim}})
      assert :ok = Probe.ready?(ProbeStartSpec)
    end
  end

  test "no probe agent outlives the probe that started it" do
    assert :ok = Probe.ready?({ProbeStartSpec, %{echo_body: :verbatim}})

    assert Ouroboros.Mesh.list_agents()
           |> Enum.all?(&(not String.starts_with?(&1.id, "ouroboros-probe-")))
  end

  test "and none outlives a probe its caller killed at a deadline" do
    # A probe runs under somebody else's deadline, and a deadline that fires kills this
    # process outright — `after` does not run for an exit signal from outside. So the
    # throwaway agent kept its cluster-wide mesh id, and its helper instance where it had
    # one, with nothing linked to it that would ever notice. `Ouroboros.Wasm.Rollout`'s
    # local gate is the caller that does this; the agent below is slow enough that the
    # deadline always fires while it is alive.
    before = probe_agent_ids()

    task =
      Task.async(fn ->
        Probe.ready?({SlowProbeAnswer, %{}})
      end)

    # Exactly what `Ouroboros.Wasm.Rollout.bounded_call/5`'s local branch does at a
    # deadline, and it reads the same way: nothing came back, so the gate is ambiguous.
    assert nil == Task.yield(task, 300)
    refute match?({:ok, _result}, Task.shutdown(task, :brutal_kill))

    assert await_probe_agents(before, 200) == before,
           "a killed probe left an agent behind: #{inspect(probe_agent_ids() -- before)}"
  end

  defp probe_agent_ids do
    Ouroboros.Mesh.list_agents()
    |> Enum.map(& &1.id)
    |> Enum.filter(&String.starts_with?(&1, "ouroboros-probe-"))
    |> Enum.sort()
  end

  # The janitor stops the id after the killed process goes down, which is asynchronous.
  defp await_probe_agents(expected, 0), do: probe_agent_ids() || expected

  defp await_probe_agents(expected, attempts) do
    if probe_agent_ids() == expected do
      expected
    else
      Process.sleep(20)
      await_probe_agents(expected, attempts - 1)
    end
  end
end
