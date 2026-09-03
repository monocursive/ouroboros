defmodule Ouroboros.Upgrade.EvaluationTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.Rollout.Evaluation
  alias Ouroboros.Upgrade.{Artifact, Verifier}

  @echo Ouroboros.Capability.EvalEcho
  @answering Ouroboros.Capability.EvalAnswering
  @faulty Ouroboros.Capability.EvalFaulty
  @slow Ouroboros.Capability.EvalSlow
  @signed Ouroboros.Capability.EvalSigned

  @signer "evaluation-test-signer"

  setup do
    on_exit(fn ->
      for module <- [@echo, @answering, @faulty, @slow, @signed], do: unload(module)
    end)

    :ok
  end

  describe "spec validation" do
    test "normalizes a minimal spec and names its defaults" do
      assert {:ok, spec} = Evaluation.validate(%{probes: [%{input: "x", expect: :any_reply}]})

      assert spec.budget_ms == 10_000
      assert spec.max_latency_ms == nil
      assert spec.required == :all
      assert spec.initial_state == %{}
      assert spec.probes == [%{input: "x", expect: :any_reply}]

      # An absent expectation is the weakest one, never no expectation at all.
      assert {:ok, %{probes: [%{expect: :any_reply}]}} =
               Evaluation.validate(%{probes: [%{input: "x"}]})
    end

    test "refuses a term that could not be signed, shipped, or replayed" do
      # A spec travels inside a signed manifest and over `:erpc`. Anything that is only
      # meaningful in the VM that wrote it is refused at the door.
      assert {:error, {:invalid_eval_spec, {:probe_input_not_portable, 0}}} =
               Evaluation.validate(%{probes: [%{input: self(), expect: :any_reply}]})

      assert {:error, {:invalid_eval_spec, {:probe_input_not_portable, 0}}} =
               Evaluation.validate(%{probes: [%{input: fn -> :ok end, expect: :any_reply}]})

      assert {:error, {:invalid_eval_spec, {:probe_input_not_portable, 1}}} =
               Evaluation.validate(%{
                 probes: [
                   %{input: "fine", expect: :any_reply},
                   %{input: %{ref: make_ref()}, expect: :any_reply}
                 ]
               })

      assert {:error, {:invalid_eval_spec, {:expectation_not_portable, 0}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: {:equals, self()}}]})
    end

    test "refuses expectation forms this build cannot evaluate" do
      assert {:error, {:invalid_eval_spec, {:unknown_expectation, 0, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: :probably_fine}]})

      # A regex is the obvious thing to reach for and the obvious thing to refuse: it is
      # a struct holding a compiled pattern, not a term a manifest can carry.
      assert {:error, {:invalid_eval_spec, {:unknown_expectation, 0, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: {:matches, ~r/x/}}]})

      assert {:error, {:invalid_eval_spec, {:invalid_contains_expectation, 0, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: {:contains, ""}}]})

      assert {:error, {:invalid_eval_spec, {:invalid_contains_expectation, 0, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: {:contains, :ping}}]})

      assert {:error, {:invalid_eval_spec, {:invalid_state_key, 0, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: {:state_matches, "k", 1}}]})

      assert {:error, {:invalid_eval_spec, {:unknown_probe_keys, 0, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: :any_reply, retries: 3}]})

      assert {:error, {:invalid_eval_spec, {:unknown_spec_keys, _rendered}}} =
               Evaluation.validate(%{probes: [%{input: "x", expect: :any_reply}], timeout: 5})
    end

    test "refuses a spec whose size or arithmetic makes it unrunnable" do
      probe = %{input: "x", expect: :any_reply}

      assert {:error, {:invalid_eval_spec, :probes_required}} = Evaluation.validate(%{})
      assert {:error, {:invalid_eval_spec, :probes_required}} = Evaluation.validate(%{probes: []})

      assert {:error, {:invalid_eval_spec, {:invalid_probes, _rendered}}} =
               Evaluation.validate(%{probes: "one probe please"})

      assert {:error, {:invalid_eval_spec, {:too_many_probes, 21, 20}}} =
               Evaluation.validate(%{probes: List.duplicate(probe, 21)})

      assert {:error, {:invalid_eval_spec, {:eval_spec_too_large, size, 16_384}}} =
               Evaluation.validate(%{
                 probes: [%{input: String.duplicate("x", 20_000), expect: :any_reply}]
               })

      assert size > 16_384

      assert {:error, {:invalid_eval_spec, {:invalid_budget_ms, _rendered}}} =
               Evaluation.validate(%{probes: [probe], budget_ms: 0})

      assert {:error, {:invalid_eval_spec, {:invalid_budget_ms, _rendered}}} =
               Evaluation.validate(%{probes: [probe], budget_ms: 500_000})

      # A latency gate above the deadline it lives inside can never fire.
      assert {:error, {:invalid_eval_spec, {:invalid_max_latency_ms, _rendered}}} =
               Evaluation.validate(%{probes: [probe], budget_ms: 100, max_latency_ms: 200})

      # A gate that gates nothing reads like evidence in a registry entry and proves none.
      assert {:error, {:invalid_eval_spec, {:invalid_required, _rendered}}} =
               Evaluation.validate(%{probes: [probe], required: {:at_least, 0}})

      assert {:error, {:invalid_eval_spec, {:invalid_required, _rendered}}} =
               Evaluation.validate(%{probes: [probe], required: {:at_least, 2}})

      assert {:error, {:invalid_eval_spec, {:not_a_map, _rendered}}} =
               Evaluation.validate(probes: [probe])
    end
  end

  describe "run/3" do
    test "a capability that satisfies its probes reports how long each one took" do
      compile!(@echo, echo_source())

      spec = %{
        probes: [
          %{input: %{op: "ping"}, expect: {:contains, "ping"}},
          %{input: "second", expect: {:state_matches, :messages_received, 2}},
          %{input: "third", expect: :any_reply}
        ],
        budget_ms: 5_000
      }

      assert {:ok, report} = Evaluation.run(@echo, spec)

      assert report.module == @echo
      assert report.node == node()
      assert report.probes == 3
      assert report.passed == 3
      assert report.failed == 0
      assert report.within_budget?
      assert Evaluation.passed?(report)
      assert is_integer(report.total_ms) and report.total_ms >= 0
      assert [%{index: 0}, %{index: 1}, %{index: 2}] = report.results
      assert Enum.all?(report.results, &(&1.outcome == :passed and is_integer(&1.ms)))

      # Probes share one throwaway agent in order, which is the only reason a state
      # expectation about the *second* message can say anything.
      assert Enum.at(report.results, 1).outcome == :passed

      # The throwaway agent does not outlive the run.
      assert Ouroboros.Mesh.list_agents()
             |> Enum.all?(&(not String.starts_with?(&1.id, "ouroboros-eval-")))
    end

    test "an expectation the capability does not meet is a failed probe, not an error" do
      compile!(@answering, answering_source())

      passing = %{probes: [%{input: "x", expect: {:equals, "pong"}}], budget_ms: 5_000}
      assert {:ok, report} = Evaluation.run(@answering, passing)
      assert report.passed == 1
      assert Evaluation.passed?(report)

      failing = %{
        probes: [
          %{input: "x", expect: {:equals, "pong"}},
          %{input: "y", expect: {:equals, "something else"}},
          %{input: "z", expect: {:state_matches, :messages_received, 99}}
        ],
        budget_ms: 5_000
      }

      assert {:ok, report} = Evaluation.run(@answering, failing)
      assert report.passed == 1
      assert report.failed == 2
      refute Evaluation.passed?(report)

      assert [_passed, %{outcome: :failed, reason: {:not_equal, _}}, third] = report.results
      assert third.reason == {:state_mismatch, :messages_received, "3"}

      # `{:at_least, 1}` is a different question about the same run, and the report
      # answers whichever one the spec asked.
      assert {:ok, lenient} =
               Evaluation.run(@answering, Map.put(failing, :required, {:at_least, 1}))

      assert Evaluation.passed?(lenient)
    end

    test "a capability whose handler raises fails a probe rather than escaping" do
      compile!(@faulty, faulty_source())

      spec = %{probes: [%{input: "x", expect: :any_reply}], budget_ms: 5_000}

      assert {:ok, report} = Evaluation.run(@faulty, spec)
      assert report.passed == 0
      assert report.failed == 1
      refute Evaluation.passed?(report)
      assert [%{outcome: :failed, reason: {:message_failed, rendered}}] = report.results

      # The reason crosses `:erpc` into a durable registry, so a term full of pids is
      # rendered rather than shipped.
      assert is_binary(rendered)
    end

    test "a capability nobody loaded is a refusal, and never an exception" do
      spec = %{probes: [%{input: "x", expect: :any_reply}], budget_ms: 5_000}

      assert {:error, {:evaluation_unavailable, Ouroboros.Capability.NeverForged, reason}} =
               Evaluation.run(Ouroboros.Capability.NeverForged, spec)

      assert reason == {:capability_not_loaded, :nofile}

      # A module outside the capability namespace cannot be started as a mesh agent, and
      # that is a refusal with a name too.
      assert {:error, {:evaluation_unavailable, Enum, _reason}} = Evaluation.run(Enum, spec)

      assert {:error, {:invalid_eval_module, _rendered}} = Evaluation.run("not a module", spec)
    end

    test "a slow capability exhausts its budget and misses its latency gate" do
      compile!(@slow, slow_source())

      latency = %{
        probes: [%{input: "x", expect: :any_reply}],
        budget_ms: 5_000,
        max_latency_ms: 50
      }

      # The answer arrived; it arrived too late. Recording that is more useful than
      # recording a timeout that cannot say whether it answered at all.
      assert {:ok, report} = Evaluation.run(@slow, latency)
      assert report.failed == 1
      refute Evaluation.passed?(report)
      assert [%{outcome: :failed, reason: {:latency_exceeded, observed, 50}}] = report.results
      assert observed > 50

      budgeted = %{
        probes: List.duplicate(%{input: "x", expect: :any_reply}, 4),
        budget_ms: 400
      }

      assert {:ok, report} = Evaluation.run(@slow, budgeted)

      # The capability works: the first probe passes. What it cannot do is answer four
      # times inside the deadline the artifact declared.
      assert Enum.at(report.results, 0).outcome == :passed
      assert report.failed >= 1
      refute Evaluation.passed?(report)
    end

    test "no evaluation agent outlives an evaluation its caller killed at a deadline" do
      # An evaluation runs under somebody else's deadline — `Ouroboros.Wasm.Rollout`'s
      # local gate kills the task that holds it — and `after` does not run for an exit
      # signal from outside. So the throwaway agent kept its cluster-wide mesh id, and the
      # helper instance a lane-W capability would be holding, with nothing linked to it
      # that would ever notice.
      compile!(@slow, slow_source())
      before = eval_agent_ids()

      spec = %{
        probes: List.duplicate(%{input: "x", expect: :any_reply}, 20),
        budget_ms: 30_000
      }

      task = Task.async(fn -> Evaluation.run(@slow, spec) end)

      assert nil == Task.yield(task, 400)
      refute match?({:ok, _result}, Task.shutdown(task, :brutal_kill))

      assert await_eval_agents(before, 200) == before,
             "a killed evaluation left an agent behind: #{inspect(eval_agent_ids() -- before)}"
    end

    test "a spec can seed the state its expectations are about" do
      compile!(@echo, echo_source())

      spec = %{
        probes: [%{input: "x", expect: {:state_matches, :role, "seeded-by-the-spec"}}],
        initial_state: %{role: "seeded-by-the-spec"},
        budget_ms: 5_000
      }

      assert {:ok, report} = Evaluation.run(@echo, spec)
      assert Evaluation.passed?(report)

      # Without the seed the same expectation is a failure, which is the only way to know
      # the seed is what satisfied it.
      assert {:ok, unseeded} = Evaluation.run(@echo, Map.delete(spec, :initial_state))
      refute Evaluation.passed?(unseeded)
      assert [%{reason: {:state_mismatch, :role, "\"capability\""}}] = unseeded.results

      # A seed that could not survive the manifest it is signed inside is refused.
      assert {:error, {:invalid_eval_spec, :initial_state_not_portable}} =
               Evaluation.validate(%{spec | initial_state: %{owner: self()}})
    end

    test "an invalid spec is refused before anything is started" do
      compile!(@echo, echo_source())

      assert {:error, {:invalid_eval_spec, :probes_required}} = Evaluation.run(@echo, %{})

      assert {:error, {:invalid_eval_spec, {:probe_input_not_portable, 0}}} =
               Evaluation.run(@echo, %{probes: [%{input: self(), expect: :any_reply}]})
    end

    test "summarize keeps counts and the first failures, never a transcript" do
      compile!(@answering, answering_source())

      spec = %{
        probes: List.duplicate(%{input: "x", expect: {:equals, "never"}}, 8),
        budget_ms: 5_000
      }

      assert {:ok, report} = Evaluation.run(@answering, spec)
      assert report.failed == 8

      summary = Evaluation.summarize(report)
      assert summary.node == node()
      assert summary.probes == 8
      assert summary.passed == 0
      assert summary.failed == 8
      refute summary.satisfied?
      assert length(summary.failures) == 5
      refute Map.has_key?(summary, :results)

      assert Evaluation.summarize(:not_a_report) == %{
               satisfied?: false,
               failures: [],
               reason: ":not_a_report"
             }
    end
  end

  describe "the {module, initial_state} start spec (D7)" do
    test "a bare module and an empty seed are the same thing, which is lane B unchanged" do
      compile!(@echo, echo_source())

      spec = %{probes: [%{input: "x", expect: :any_reply}], budget_ms: 5_000}

      assert {:ok, bare} = Evaluation.run(@echo, spec)
      assert {:ok, seeded} = Evaluation.run({@echo, %{}}, spec)

      assert bare.module == @echo
      assert seeded.module == @echo
      assert Evaluation.passed?(bare)
      assert Evaluation.passed?(seeded)
    end

    test "the start spec seeds state the spec never mentioned" do
      # This is what lane W needs: `Ouroboros.Wasm.Capability` is one module standing in for
      # every component, so which capability is under evaluation is a fact about its state.
      compile!(@echo, echo_source())

      spec = %{
        probes: [%{input: "x", expect: {:state_matches, :role, "named-by-the-start-spec"}}],
        budget_ms: 5_000
      }

      assert {:ok, report} = Evaluation.run({@echo, %{role: "named-by-the-start-spec"}}, spec)
      assert Evaluation.passed?(report)

      # Without the start spec the same expectation fails, which is the only way to know the
      # start spec is what satisfied it.
      assert {:ok, unseeded} = Evaluation.run(@echo, spec)
      refute Evaluation.passed?(unseeded)
    end

    test "both seeds are merged, and the start spec wins the keys they share" do
      compile!(@echo, echo_source())

      # The spec is signed and travels with the bytes it judges; the start spec is the
      # deployment's own statement of *what* is being judged. A signed spec that could
      # overwrite the start spec would be a test able to redirect the thing it is testing, so
      # the start spec wins — and everything it does not name, the spec still seeds.
      base = %{
        initial_state: %{role: "named-by-the-spec", from_spec: "kept"},
        budget_ms: 5_000
      }

      contested =
        Map.put(base, :probes, [
          %{input: "x", expect: {:state_matches, :role, "named-by-the-start-spec"}}
        ])

      assert {:ok, report} =
               Evaluation.run(
                 {@echo, %{role: "named-by-the-start-spec", from_start: "kept"}},
                 contested
               )

      assert Evaluation.passed?(report)

      # And the key only the spec named survived the merge rather than being replaced by it.
      uncontested =
        Map.put(base, :probes, [
          %{input: "x", expect: {:state_matches, :from_spec, "kept"}},
          %{input: "y", expect: {:state_matches, :from_start, "kept"}}
        ])

      assert {:ok, merged} =
               Evaluation.run(
                 {@echo, %{role: "named-by-the-start-spec", from_start: "kept"}},
                 uncontested
               )

      assert Evaluation.passed?(merged)

      # The spec alone still seeds what it always did: nothing about lane B changed.
      assert {:ok, spec_only} =
               Evaluation.run(
                 @echo,
                 Map.put(base, :probes, [
                   %{input: "x", expect: {:state_matches, :role, "named-by-the-spec"}}
                 ])
               )

      assert Evaluation.passed?(spec_only)
    end

    test "a start spec that is not one is refused before anything is started" do
      spec = %{probes: [%{input: "x", expect: :any_reply}], budget_ms: 5_000}

      assert {:error, {:invalid_eval_module, _rendered}} =
               Evaluation.run({@echo, :not_a_map}, spec)

      assert {:error, {:invalid_eval_module, _rendered}} = Evaluation.run({nil, %{}}, spec)
      assert {:error, {:invalid_eval_module, _rendered}} = Evaluation.run({@echo, %{}, %{}}, spec)
    end
  end

  describe "signed criteria" do
    test "a spec rewritten after signing invalidates the artifact it came in" do
      {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

      {:ok, spec} =
        Evaluation.validate(%{
          probes: [%{input: "ping", expect: {:contains, "ping"}}],
          budget_ms: 1_000,
          required: :all
        })

      binary = compile!(@signed, echo_source(@signed))
      unload(@signed)

      {:ok, artifact} =
        Artifact.build([{@signed, binary, disposition: :introduce}],
          epoch: System.unique_integer([:positive, :monotonic]),
          metadata: %{forge: %{eval: spec}}
        )

      signed = Artifact.sign(artifact, @signer, private_key)
      policy = [trusted_signers: %{@signer => public_key}]

      assert :ok = Verifier.verify(signed, policy)

      # Loosening the gate is the interesting tamper: the bytes are untouched, the module
      # is untouched, and only the criteria by which it would be judged have changed.
      loosened = put_in(signed.metadata.forge.eval.required, {:at_least, 1})
      assert loosened.modules == signed.modules

      assert {:error, {tag, @signer}} = Verifier.verify(loosened, policy)
      assert tag in [:invalid_signature, :untrusted_signer]

      # So is deleting them outright.
      stripped = %{signed | metadata: %{forge: %{}}}
      assert {:error, {:invalid_signature, @signer}} = Verifier.verify(stripped, policy)

      # And an unsigned artifact carrying gates proves nothing about who chose them:
      # criteria are only evidence when somebody's key stands behind them.
      assert {:error, :signature_required} = Verifier.verify(artifact, [])

      assert Signer.Deny.sign(Artifact.signing_payload(artifact, @signer), @signer) ==
               {:error, :signing_denied}
    end
  end

  defp eval_agent_ids do
    Ouroboros.Mesh.list_agents()
    |> Enum.map(& &1.id)
    |> Enum.filter(&String.starts_with?(&1, "ouroboros-eval-"))
    |> Enum.sort()
  end

  # The janitor stops the id after the killed process goes down, which is asynchronous.
  defp await_eval_agents(expected, 0), do: eval_agent_ids() || expected

  defp await_eval_agents(expected, attempts) do
    if eval_agent_ids() == expected do
      expected
    else
      Process.sleep(20)
      await_eval_agents(expected, attempts - 1)
    end
  end

  defp compile!(module, source) do
    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)

    try do
      [{^module, binary}] = Code.compile_string(source, "#{inspect(module)}.ex")
      binary
    after
      Code.put_compiler_option(:ignore_module_conflict, previous)
    end
  end

  defp unload(module) do
    :code.soft_purge(module)
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp echo_source(module \\ @echo) do
    """
    defmodule #{inspect(module)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_eval_echo",
        description: "A capability agent that records what it is told",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]
    end
    """
  end

  # This one publishes an answer, so `{:equals, _}` is a statement about what it replied
  # rather than about everything it happens to hold.
  defp answering_source do
    """
    defmodule #{inspect(@answering)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_eval_answering",
        description: "A capability agent that publishes a constant answer",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          last_answer: [type: :any, default: "pong"],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]
    end
    """
  end

  defp faulty_source do
    """
    defmodule #{inspect(@faulty)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_eval_faulty",
        description: "A capability agent whose message handler always fails",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]

      @impl true
      def on_before_cmd(_agent, _action) do
        raise "forged capability handler is broken"
      end
    end
    """
  end

  defp slow_source do
    """
    defmodule #{inspect(@slow)} do
      @vsn 1

      use Jido.Agent,
        name: "ouroboros_capability_eval_slow",
        description: "A capability agent that answers, eventually",
        schema: [
          role: [type: :string, default: "capability"],
          inbox: [type: :list, default: []],
          last_message: [type: :any, default: nil],
          messages_received: [type: :non_neg_integer, default: 0]
        ],
        signal_routes: [
          {"ouroboros.agent.message", Ouroboros.Agent.Worker.ReceiveMessage}
        ]

      @impl true
      def on_before_cmd(agent, action) do
        Process.sleep(120)
        {:ok, agent, action}
      end
    end
    """
  end
end
