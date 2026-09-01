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

defmodule Ouroboros.Upgrade.ProbeTest do
  # Not async: every probe joins the node-wide `:pg` mesh namespace under an id of its own,
  # and `Ouroboros.Mesh` is a singleton.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.Worker
  alias Ouroboros.Capability.ProbeStartSpec
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
end
