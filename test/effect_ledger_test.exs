defmodule Ouroboros.Agent.EffectLedgerTest.RefusingStorage do
  @moduledoc false

  def get_checkpoint(key, opts), do: Jido.Storage.ETS.get_checkpoint(key, opts)
  def put_checkpoint(_key, _checkpoint, _opts), do: {:error, :storage_offline}
end

defmodule Ouroboros.Agent.EffectLedgerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Agent.EffectLedger.Entry
  alias Ouroboros.Agent.EffectLedgerTest.RefusingStorage

  @secret "the objective and provider answer must never enter the effect ledger"

  test "the application supervises a bounded, inspectable ledger" do
    assert is_pid(Process.whereis(EffectLedger))

    assert %{
             durability: :ephemeral_checkpoint,
             retained: retained,
             in_flight: in_flight,
             retention_limit: 1_000
           } = EffectLedger.status()

    assert retained >= 0
    assert in_flight >= 0
    assert {:error, :invalid_query} = EffectLedger.list(limit: 501)
    assert {:error, :invalid_query} = EffectLedger.list(unknown: true)
  end

  test "attempts settle idempotently and expose only content-minimized projections" do
    ledger = start_ledger!()
    attrs = attrs("effect-content", :delegate, %{team: "review", objective: @secret})

    assert {:ok, %Entry{status: :started, sequence: 1, started_sequence: 1}, :created} =
             EffectLedger.record_started(attrs, ledger)

    assert {:ok, %Entry{sequence: 1}, :existing} =
             EffectLedger.record_started(attrs, ledger)

    outcome = %{
      status: :ok,
      result: %{
        team: "review",
        worker_id: "worker",
        delegation_id: "delegation",
        status: :completed,
        delivery: :delivered,
        result: %{text: @secret}
      }
    }

    assert {:ok, %Entry{} = settled, :updated} =
             EffectLedger.settle(attrs.id, outcome, ledger)

    assert settled.sequence == 2
    assert settled.started_sequence == 1
    assert settled.attempt == %{team: "review"}
    assert settled.cause == %{signal_id: "signal-effect-content", signal_type: "effect.delegate"}
    assert settled.authority.decision == :granted
    assert settled.result.team == "review"
    assert settled.result.status == :completed
    assert %{bytes: bytes, sha256: sha256} = settled.result.result_fingerprint
    assert bytes > 0
    assert byte_size(sha256) == 64
    refute inspect(settled) =~ @secret

    assert {:ok, %Entry{sequence: 2}, :existing} =
             EffectLedger.settle(attrs.id, outcome, ledger)

    assert {:ok, [^settled]} =
             EffectLedger.list(
               [principal: "actor", effect: :delegate, status: :ok, since_sequence: 1],
               ledger
             )
  end

  test "free-form failures are classified and fingerprinted without retaining text" do
    ledger = start_ledger!()

    attrs =
      attrs("effect-error", :forge, %{module: Ouroboros.Capability.Example, source: @secret})

    assert {:ok, _entry, :created} = EffectLedger.record_started(attrs, ledger)

    assert {:ok, %Entry{status: :failed, error: error} = settled, :updated} =
             EffectLedger.settle(
               attrs.id,
               %{status: :failed, error: {:compiler_error, @secret}},
               ledger
             )

    assert error.classification == {:compiler_error, :text}
    assert byte_size(error.fingerprint.sha256) == 64
    refute inspect(settled) =~ @secret
  end

  test "a denied stable request cannot become a new effect after authority changes" do
    ledger = start_ledger!()
    denied = attrs("denied-stable", :start_agent, %{module: Ouroboros.Agent.Worker})

    assert {:ok, %Entry{status: :denied}, :created} =
             EffectLedger.record_denied(denied, ledger)

    admitted =
      put_in(denied, [:authority], %{
        decision: :granted,
        reason: :granted,
        constraints: %{modules: [Ouroboros.Agent.Worker]},
        granted_at: "2026-08-22T00:01:00Z"
      })

    effect_id = denied.id

    assert {:error, {:effect_id_conflict, ^effect_id}} =
             EffectLedger.record_started(admitted, ledger)
  end

  test "a durable restart marks unfinished work ambiguous and still accepts a late settlement" do
    path = temporary_path("restart")
    on_exit(fn -> File.rm_rf(path) end)
    storage = {Ouroboros.Storage.DurableFile, path: path}
    ledger = start_ledger!(storage: storage)
    attrs = attrs("effect-restart", :send_message, %{agent: "peer", body: @secret})

    assert {:ok, %Entry{status: :started, sequence: 1}, :created} =
             EffectLedger.record_started(attrs, ledger)

    stop_supervised!(ledger)
    replacement = start_ledger!(storage: storage)

    assert {:ok, %Entry{} = recovered} = EffectLedger.get(attrs.id, replacement)
    assert recovered.status == :ambiguous
    assert recovered.sequence == 2
    assert recovered.error.classification == :runtime_restarted_before_settlement
    assert EffectLedger.durability(replacement) == :synced_checkpoint

    assert {:ok, %Entry{status: :ambiguous}, :existing} =
             EffectLedger.record_started(attrs, replacement)

    assert {:ok, %Entry{status: :ok, sequence: 3}, :updated} =
             EffectLedger.settle(
               attrs.id,
               %{status: :ok, result: %{to: "peer", from: "actor", messages_received: 1}},
               replacement
             )
  end

  test "retention never evicts in-flight work and settlement advances the query cursor" do
    ledger = start_ledger!(retention_limit: 2)
    active = attrs("active", :start_agent, %{module: Ouroboros.Agent.Worker})
    assert {:ok, _entry, :created} = EffectLedger.record_started(active, ledger)

    for number <- 1..3 do
      denied = attrs("denied-#{number}", :stop_agent, %{agent: "target-#{number}"})
      assert {:ok, _entry, :created} = EffectLedger.record_denied(denied, ledger)
    end

    assert {:ok, retained} = EffectLedger.list([limit: 10], ledger)
    assert Enum.any?(retained, &(&1.id == active.id and &1.status == :started))
    assert length(Enum.filter(retained, &(&1.status == :denied))) == 2

    assert {:ok, %Entry{sequence: 5}, :updated} =
             EffectLedger.settle(
               active.id,
               %{
                 status: :ok,
                 result: %{agent_id: "started", module: Ouroboros.Agent.Worker, node: node()}
               },
               ledger
             )

    assert {:ok, [%Entry{id: "active"}]} =
             EffectLedger.list([since_sequence: 4, order: :asc], ledger)
  end

  test "a watched runner that exits before settlement makes the attempt ambiguous" do
    ledger = start_ledger!()
    attrs = attrs("watched-runner", :stop_agent, %{agent: "peer"})
    runner = spawn(fn -> Process.sleep(:infinity) end)

    assert {:ok, _entry, :created} = EffectLedger.record_started(attrs, ledger)
    assert :ok = EffectLedger.watch_runner(attrs.id, runner, ledger)
    Process.exit(runner, :kill)

    assert_eventually(fn ->
      case EffectLedger.get(attrs.id, ledger) do
        {:ok, %Entry{status: :ambiguous, sequence: 2} = entry} ->
          entry.error.classification == {:effect_runner_exited_before_settlement, :killed}

        _other ->
          false
      end
    end)
  end

  @tag :capture_log
  test "an ambiguity nobody could checkpoint is not believed in memory either" do
    path = temporary_path("ambiguity-refused")
    on_exit(fn -> File.rm_rf(path) end)

    {:ok, gate} = Agent.start_link(fn -> :allow end)
    on_exit(fn -> if Process.alive?(gate), do: Agent.stop(gate) end)

    hook = fn
      :before_write ->
        if Agent.get(gate, & &1) == :refuse, do: {:error, :injected_write_failure}, else: :ok

      _event ->
        :ok
    end

    storage = {Ouroboros.Storage.DurableFile, path: path, durability_hook: hook}
    ledger = start_ledger!(storage: storage)
    attrs = attrs("effect-unwritable-ambiguity", :stop_agent, %{agent: "peer"})
    runner = spawn(fn -> Process.sleep(:infinity) end)

    assert {:ok, _entry, :created} = EffectLedger.record_started(attrs, ledger)
    assert :ok = EffectLedger.watch_runner(attrs.id, runner, ledger)

    Agent.update(gate, fn _state -> :refuse end)
    Process.exit(runner, :kill)

    assert_eventually(fn -> :sys.get_state(ledger).runner_monitors == %{} end)

    # The checkpoint was refused, so the transition did not happen — in memory any more
    # than on disk. A reader who trusts this process and a reader who reloads the
    # checkpoint are told the same thing.
    assert {:ok, %Entry{status: :started, sequence: 1}} = EffectLedger.get(attrs.id, ledger)
    assert EffectLedger.status(ledger).next_sequence == 2

    assert {:ok, %{entries: [%Entry{status: :started, sequence: 1}], next_sequence: 2}} =
             Ouroboros.Storage.DurableFile.get_checkpoint(EffectLedger.checkpoint_key(),
               path: path
             )
  end

  test "a failed initial checkpoint prevents an effect from becoming admissible" do
    table = unique_name("refusing_table")
    ledger = start_ledger!(storage: {RefusingStorage, table: table})

    assert {:error, {:effect_ledger_checkpoint_failed, :storage_offline}} =
             EffectLedger.record_started(
               attrs("never-admitted", :start_agent, %{module: Ouroboros.Agent.Worker}),
               ledger
             )

    assert {:ok, []} = EffectLedger.list([], ledger)
  end

  test "a checkpoint from an unknown ledger version stops instead of erasing history" do
    table = unique_name("future_storage")
    storage = {Jido.Storage.ETS, table: table}

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(
               EffectLedger.checkpoint_key(),
               %{version: 99, entries: [], next_sequence: 1},
               table: table
             )

    name = unique_name("future_ledger")

    assert {:error, {{:unsupported_effect_ledger_checkpoint, 99}, _child_spec}} =
             start_supervised({EffectLedger, name: name, storage: storage}, id: name)
  end

  describe "the :permission effect kind" do
    test "a decision is one terminal entry, written and settled in the same instant" do
      ledger = start_ledger!()

      assert :permission in EffectLedger.effects()
      refute :permission in Ouroboros.Control.Grants.effects()

      attrs = %{
        id: "perm-1",
        effect: :permission,
        principal: "session-1",
        attempt: %{
          tool: "bash",
          mode: :execute,
          provider: :codex,
          fingerprint: %{sha256: String.duplicate("a", 64), bytes: 12},
          command: @secret
        },
        authority: %{decision: :approve, reason: nil},
        cause: %{signal_id: "perm-1", signal_type: "permission"},
        result: %{
          decision: :approve,
          scope: :once,
          actor: :rule,
          rule_id: "rule-x",
          note: @secret
        }
      }

      assert {:ok, entry, :created} = EffectLedger.record_settled(attrs, ledger)
      assert entry.status == :ok
      assert is_binary(entry.settled_at)

      # Only the declared fields survive; the command line and the free-form note do not.
      assert entry.attempt == %{
               tool: "bash",
               mode: :execute,
               provider: :codex,
               fingerprint: %{sha256: String.duplicate("a", 64), bytes: 12}
             }

      assert entry.result == %{decision: :approve, scope: :once, actor: :rule, rule_id: "rule-x"}
      refute inspect(entry) =~ "objective"

      # Idempotent on the caller-minted id, like the other two writes.
      assert {:ok, ^entry, :existing} = EffectLedger.record_settled(attrs, ledger)
    end

    test "a refused decision is a terminal denied entry, and both are queryable" do
      ledger = start_ledger!()

      base = %{
        effect: :permission,
        principal: "session-2",
        attempt: %{tool: "write", mode: :write},
        authority: %{decision: :deny, reason: "rule"},
        cause: %{signal_id: "perm-2", signal_type: "permission"},
        result: %{decision: :deny, scope: :once, actor: :rule, rule_id: "rule-y"},
        error: :permission_denied
      }

      assert {:ok, denied, :created} =
               EffectLedger.record_denied(Map.put(base, :id, "perm-2"), ledger)

      assert denied.status == :denied

      assert {:ok, allowed, :created} =
               EffectLedger.record_settled(
                 base
                 |> Map.put(:id, "perm-3")
                 |> Map.put(:result, %{decision: :approve, scope: :session, actor: :human})
                 |> Map.delete(:error),
                 ledger
               )

      assert allowed.status == :ok
      assert {:ok, entries} = EffectLedger.list([effect: :permission], ledger)
      assert Enum.map(entries, & &1.id) == ["perm-3", "perm-2"]
      assert {:ok, [^denied]} = EffectLedger.list([effect: :permission, status: :denied], ledger)
    end
  end

  describe "the :tool_call and :approval effect kinds (I1)" do
    test "both are ledger-only kinds nobody can be granted" do
      assert :tool_call in EffectLedger.effects()
      assert :approval in EffectLedger.effects()
      refute :tool_call in Ouroboros.Control.Grants.effects()
      refute :approval in Ouroboros.Control.Grants.effects()
      assert EffectLedger.tool_call_statuses() == [:completed, :failed, :refused, :timed_out]
    end

    test "a subject keeps identities, drops everything else, and bounds what it keeps" do
      ledger = start_ledger!()

      assert {:ok, entry, :created} =
               EffectLedger.record_started(
                 %{
                   id: "tool-1",
                   effect: :tool_call,
                   principal: "session:s1",
                   attempt: %{
                     session_id: "s1",
                     turn_id: "t1",
                     call_id: "c1",
                     tool: "bash",
                     provider: :native,
                     node: node(),
                     permission_entry_id: "ndec_1",
                     # Everything below is what a careless caller might hand in.
                     input: @secret,
                     subject: %{
                       paths: Enum.map(1..40, &"lib/#{&1}.ex") ++ [:not_a_path],
                       command_sha256: String.duplicate("a", 64),
                       hosts: ["example.com"],
                       mcp_server: "linear",
                       mcp_tool: "create_issue",
                       command: @secret,
                       contents: @secret
                     }
                   },
                   authority: %{decision: :allow, reason: "rule"},
                   cause: %{signal_id: "tool-1", signal_type: "native.tool_call"}
                 },
                 ledger
               )

      refute Map.has_key?(entry.attempt, :input)
      assert entry.attempt.permission_entry_id == "ndec_1"

      # Bounded at sixteen paths, non-strings dropped, and no key this ledger does not name.
      assert length(entry.attempt.subject.paths) == 16

      assert Map.keys(entry.attempt.subject) |> Enum.sort() ==
               [:command_sha256, :hosts, :mcp_server, :mcp_tool, :paths]

      refute inspect(entry) =~ "objective"
    end

    test "a command digest that is not a digest is dropped rather than stored" do
      ledger = start_ledger!()

      assert {:ok, entry, :created} =
               EffectLedger.record_started(
                 %{
                   id: "tool-2",
                   effect: :tool_call,
                   principal: "session:s1",
                   attempt: %{tool: "bash", subject: %{command_sha256: "rm -rf /"}},
                   authority: %{decision: :allow},
                   cause: %{signal_id: "tool-2"}
                 },
                 ledger
               )

      assert entry.attempt.subject == %{}
      refute inspect(entry) =~ "rm -rf"
    end

    test "a Computer Use subject keeps app, action, and window_id" do
      ledger = start_ledger!()

      assert {:ok, entry, :created} =
               EffectLedger.record_started(
                 %{
                   id: "tool-cu",
                   effect: :tool_call,
                   principal: "session:s1",
                   attempt: %{
                     session_id: "s1",
                     tool: "desktop_act",
                     provider: :native,
                     subject: %{
                       app: "com.apple.calculator",
                       desktop_action: "click",
                       window_id: "w_1",
                       input: @secret
                     }
                   },
                   authority: %{decision: :allow},
                   cause: %{signal_id: "tool-cu"}
                 },
                 ledger
               )

      assert entry.attempt.subject == %{
               app: "com.apple.calculator",
               desktop_action: "click",
               window_id: "w_1"
             }

      refute inspect(entry) =~ @secret
    end

    test "an outcome status outside the vocabulary is dropped, not coerced" do
      ledger = start_ledger!()

      base = %{
        id: "tool-3",
        effect: :tool_call,
        principal: "session:s1",
        attempt: %{tool: "read"},
        authority: %{decision: :allow},
        cause: %{signal_id: "tool-3"}
      }

      assert {:ok, _started, :created} = EffectLedger.record_started(base, ledger)

      assert {:ok, settled, :updated} =
               EffectLedger.settle(
                 "tool-3",
                 %{status: :ok, result: %{status: :whatever, duration_ms: 4, output_bytes: 9}},
                 ledger
               )

      refute Map.has_key?(settled.result, :status)
      assert settled.result == %{duration_ms: 4, output_bytes: 9}
    end

    test "an approval records what a person decided and never what they typed" do
      ledger = start_ledger!()

      assert {:ok, entry, :created} =
               EffectLedger.record_settled(
                 %{
                   id: "approval-1",
                   effect: :approval,
                   principal: "session:s1",
                   attempt: %{
                     session_id: "s1",
                     request_id: "req-1",
                     tool: "bash",
                     provider: :codex,
                     node: node(),
                     subject: %{command_sha256: String.duplicate("b", 64)},
                     reason: @secret
                   },
                   authority: %{decision: :allow, reason: "human"},
                   cause: %{signal_id: "req-1", signal_type: "interactive.respond_approval"},
                   result: %{
                     decision: :allow,
                     scope: :session,
                     actor: :human,
                     rule_id: "rule-1",
                     origin: "provider",
                     note: @secret
                   }
                 },
                 ledger
               )

      assert entry.status == :ok
      refute Map.has_key?(entry.attempt, :reason)

      assert entry.result == %{
               decision: :allow,
               scope: :session,
               actor: :human,
               rule_id: "rule-1",
               origin: "provider"
             }

      refute inspect(entry) =~ "objective"
    end
  end

  describe "the :inference effect kind (R1)" do
    test "it is a ledger-only kind with its own closed status vocabulary" do
      assert :inference in EffectLedger.effects()
      refute :inference in Ouroboros.Control.Grants.effects()

      assert EffectLedger.inference_statuses() == [
               :completed,
               :failed,
               :capacity_timeout,
               :stream_failed
             ]
    end

    # The hazard this pins: `sanitize_attempt/2` and `sanitize_result/2` both reach the
    # field lists with `Map.fetch!`, inside `handle_call`. A kind added to `effects/0`
    # without both entries is not a validation error, it is a GenServer crash — and this
    # process leads a rest_for_one tree, so it takes the core down with it. Recording *and*
    # settling in one test is what makes both lookups run.
    test "records and settles without reaching for a field list that is not there" do
      ledger = start_ledger!()

      attrs = %{
        id: "inference-1",
        effect: :inference,
        principal: "session:s1",
        attempt: %{
          session_id: "s1",
          turn_id: "t1",
          iteration: 2,
          model: "anthropic:claude-sonnet-4",
          provider: :native,
          prompt_sha256: String.duplicate("a", 64),
          node: node(),
          # Not in the field list, and carrying the one thing that must never land.
          prompt: @secret
        },
        authority: %{decision: :allow, reason: "session"},
        cause: %{signal_type: "native.inference", signal_id: "inference-1"}
      }

      assert {:ok, %Entry{status: :started} = started, :created} =
               EffectLedger.record_started(attrs, ledger)

      assert started.attempt == %{
               session_id: "s1",
               turn_id: "t1",
               iteration: 2,
               model: "anthropic:claude-sonnet-4",
               provider: :native,
               prompt_sha256: String.duplicate("a", 64),
               node: node()
             }

      assert {:ok, %Entry{} = settled, :updated} =
               EffectLedger.settle(
                 "inference-1",
                 %{
                   status: :ok,
                   result: %{
                     status: :completed,
                     duration_ms: 1_400,
                     output_bytes: 900,
                     journal_seq: 12,
                     input_tokens: 4_000,
                     output_tokens: 220,
                     # Not in the field list either.
                     text: @secret
                   }
                 },
                 ledger
               )

      assert settled.result == %{
               status: :completed,
               duration_ms: 1_400,
               output_bytes: 900,
               journal_seq: 12,
               input_tokens: 4_000,
               output_tokens: 220
             }

      refute inspect(settled) =~ @secret
    end

    test "a status outside the vocabulary is dropped rather than coerced" do
      ledger = start_ledger!()

      assert {:ok, _entry, :created} =
               EffectLedger.record_started(
                 %{
                   id: "inference-2",
                   effect: :inference,
                   principal: "session:s1",
                   attempt: %{session_id: "s1", turn_id: "t1", iteration: 1},
                   authority: %{decision: :allow, reason: "session"},
                   cause: %{signal_id: "inference-2"}
                 },
                 ledger
               )

      assert {:ok, settled, :updated} =
               EffectLedger.settle(
                 "inference-2",
                 %{status: :failed, result: %{status: :exploded, duration_ms: 3}},
                 ledger
               )

      refute Map.has_key?(settled.result, :status)
      assert settled.result.duration_ms == 3
    end

    test "a crash between the request and its answer reconciles to ambiguous at boot" do
      path = temporary_path("inference-restart")
      on_exit(fn -> File.rm_rf(path) end)
      storage = {Ouroboros.Storage.DurableFile, path: path}
      ledger = start_ledger!(storage: storage)

      attrs = %{
        id: "inference-restart",
        effect: :inference,
        principal: "session:s1",
        attempt: %{session_id: "s1", turn_id: "t1", iteration: 1, model: "m"},
        authority: %{decision: :allow, reason: "session"},
        cause: %{signal_type: "native.inference", signal_id: "inference-restart"}
      }

      assert {:ok, %Entry{status: :started}, :created} =
               EffectLedger.record_started(attrs, ledger)

      stop_supervised!(ledger)
      replacement = start_ledger!(storage: storage)

      # The hard replay boundary R1 §5.3 names: the runtime acknowledged the request and
      # never recorded what came back, so the entry says exactly that rather than guessing.
      assert {:ok, %Entry{} = recovered} = EffectLedger.get("inference-restart", replacement)
      assert recovered.status == :ambiguous
      assert recovered.error.classification == :runtime_restarted_before_settlement

      # A late settlement still lands, which is what keeps an isolated restart honest.
      assert {:ok, %Entry{status: :ok}, :updated} =
               EffectLedger.settle(
                 "inference-restart",
                 %{status: :ok, result: %{status: :completed, journal_seq: 4}},
                 replacement
               )
    end

    test "the cause names which of the three model-call sites this was" do
      ledger = start_ledger!()

      for {id, cause} <- [
            {"inf-loop", "native.inference"},
            {"inf-child", "native.subagent.inference"},
            {"inf-compact", "native.compaction.inference"}
          ] do
        assert {:ok, entry, :created} =
                 EffectLedger.record_started(
                   %{
                     id: id,
                     effect: :inference,
                     principal: "session:s1",
                     attempt: %{session_id: "s1", turn_id: "t1", iteration: 1},
                     authority: %{decision: :allow, reason: "session"},
                     cause: %{signal_type: cause, signal_id: id}
                   },
                   ledger
                 )

        assert entry.cause.signal_type == cause
      end
    end
  end

  describe "the version-2 checkpoint (R1)" do
    test "a version-1 checkpoint is upgraded on read rather than refused" do
      table = unique_name("v1_storage")
      storage = {Jido.Storage.ETS, table: table}

      # Written the way a build that predates `:inference` would have written it.
      entry = %Entry{
        sequence: 1,
        started_sequence: 1,
        id: "tool-legacy",
        effect: :tool_call,
        principal: "session:s1",
        attempt: %{session_id: "s1", turn_id: "t1", call_id: "c1", tool: "read"},
        authority: %{decision: :allow},
        cause: %{signal_id: "sig-1"},
        status: :ok,
        result: %{status: :completed},
        error: nil,
        started_at: "2026-08-22T00:00:00Z",
        settled_at: "2026-08-22T00:00:01Z",
        origin_node: node()
      }

      assert :ok =
               Jido.Storage.ETS.put_checkpoint(
                 EffectLedger.checkpoint_key(),
                 %{version: 1, entries: [entry], next_sequence: 2},
                 table: table
               )

      name = unique_name("v1_ledger")
      start_supervised!({EffectLedger, name: name, storage: storage}, id: name)

      # The whole point of the bump being a widening: the history survives it.
      assert {:ok, %Entry{id: "tool-legacy", status: :ok}} = EffectLedger.get("tool-legacy", name)

      # And the next write stamps the new version, with the new kind alongside the old.
      assert {:ok, _entry, :created} =
               EffectLedger.record_started(
                 %{
                   id: "inference-after-upgrade",
                   effect: :inference,
                   principal: "session:s1",
                   attempt: %{session_id: "s1", turn_id: "t1", iteration: 1},
                   authority: %{decision: :allow, reason: "session"},
                   cause: %{signal_id: "inference-after-upgrade"}
                 },
                 name
               )

      assert {:ok, %{version: 2}} =
               Jido.Storage.ETS.get_checkpoint(EffectLedger.checkpoint_key(), table: table)
    end

    test "a checkpoint from a version this build does not know is still refused" do
      table = unique_name("v3_storage")
      storage = {Jido.Storage.ETS, table: table}

      assert :ok =
               Jido.Storage.ETS.put_checkpoint(
                 EffectLedger.checkpoint_key(),
                 %{version: 3, entries: [], next_sequence: 1},
                 table: table
               )

      name = unique_name("v3_ledger")

      assert {:error, {{:unsupported_effect_ledger_checkpoint, 3}, _child_spec}} =
               start_supervised({EffectLedger, name: name, storage: storage}, id: name)
    end
  end

  describe "retention is fair across effect kinds (I1)" do
    test "a fifth kind takes its share and no more" do
      ledger = start_ledger!(retention_limit: 10)

      # One of each of the four rare kinds, then a flood of the fifth.
      for {id, effect, attempt} <- [
            {"denied-forge", :forge, %{module: A}},
            {"denied-permission", :permission, %{tool: "Bash", mode: :prompt}},
            {"denied-approval", :approval, %{session_id: "s1", request_id: "r1"}},
            {"denied-shell", :operator_shell, %{session_id: "s1", cwd: "/tmp"}}
          ] do
        assert {:ok, _entry, :created} =
                 EffectLedger.record_denied(attrs(id, effect, attempt), ledger)
      end

      for number <- 1..100 do
        assert {:ok, _entry, :created} =
                 EffectLedger.record_denied(
                   %{
                     id: "denied-inference-#{number}",
                     effect: :inference,
                     principal: "session:s1",
                     attempt: %{session_id: "s1", turn_id: "t1", iteration: number},
                     authority: %{decision: :deny},
                     cause: %{signal_id: "inference-#{number}"},
                     result: %{status: :failed}
                   },
                   ledger
                 )
      end

      assert {:ok, retained} = EffectLedger.list([limit: 100], ledger)
      assert length(retained) == 10

      # Five kinds present, limit 10, so the quota is 2 and the four rare kinds each keep
      # their one entry; the six slots nobody claimed go to the newest overall.
      for id <- ~w(denied-forge denied-permission denied-approval denied-shell) do
        assert Enum.any?(retained, &(&1.id == id)),
               "the highest-volume kind evicted #{id}"
      end

      assert length(Enum.filter(retained, &(&1.effect == :inference))) == 6
      assert Enum.any?(retained, &(&1.id == "denied-inference-100"))
      refute Enum.any?(retained, &(&1.id == "denied-inference-1"))
    end

    test "a flood of tool calls cannot evict the only forge this node ever ran" do
      ledger = start_ledger!(retention_limit: 10)

      assert {:ok, _forge, :created} =
               EffectLedger.record_denied(attrs("denied-forge", :forge, %{module: A}), ledger)

      for number <- 1..200 do
        assert {:ok, _entry, :created} =
                 EffectLedger.record_denied(
                   %{
                     id: "denied-tool-#{number}",
                     effect: :tool_call,
                     principal: "session:s1",
                     attempt: %{tool: "read", call_id: "c#{number}"},
                     authority: %{decision: :deny},
                     cause: %{signal_id: "tool-#{number}"},
                     result: %{status: :refused}
                   },
                   ledger
                 )
      end

      assert {:ok, retained} = EffectLedger.list([limit: 100], ledger)
      assert length(retained) == 10

      assert Enum.any?(retained, &(&1.id == "denied-forge")),
             "a high-volume kind evicted a rare one"

      # The rest of the budget is the flood's, newest first.
      assert length(Enum.filter(retained, &(&1.effect == :tool_call))) == 9
      assert Enum.any?(retained, &(&1.id == "denied-tool-200"))
      refute Enum.any?(retained, &(&1.id == "denied-tool-1"))
    end

    test "one kind alone still gets the whole budget" do
      ledger = start_ledger!(retention_limit: 5)

      for number <- 1..12 do
        assert {:ok, _entry, :created} =
                 EffectLedger.record_denied(
                   attrs("denied-#{number}", :stop_agent, %{agent: "a#{number}"}),
                   ledger
                 )
      end

      assert {:ok, retained} = EffectLedger.list([limit: 100], ledger)
      assert length(retained) == 5
      assert Enum.map(retained, & &1.id) |> Enum.sort() |> List.first() == "denied-10"
    end
  end

  defp attrs(id, effect, attempt) do
    %{
      id: id,
      effect: effect,
      principal: "actor",
      claimed_from: "claimed-actor",
      attempt: attempt,
      authority: %{
        decision: if(String.starts_with?(id, "denied"), do: :denied, else: :granted),
        reason: if(String.starts_with?(id, "denied"), do: :not_granted, else: :granted),
        constraints: %{scope: :test},
        granted_at: "2026-08-22T00:00:00Z"
      },
      cause: %{
        signal_id: "signal-#{id}",
        signal_type: "effect.#{effect}",
        objective: @secret
      },
      error: if(String.starts_with?(id, "denied"), do: {:effect_denied, effect, @secret})
    }
  end

  defp start_ledger!(opts \\ []) do
    name = unique_name("effect_ledger")
    storage = Keyword.get(opts, :storage, {Jido.Storage.ETS, table: unique_name("storage")})
    retention_limit = Keyword.get(opts, :retention_limit, 1_000)

    start_supervised!(
      {EffectLedger, name: name, storage: storage, retention_limit: retention_limit},
      id: name
    )

    name
  end

  defp temporary_path(suffix) do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-effect-ledger-#{suffix}-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_name(prefix),
    do: String.to_atom("#{prefix}_#{System.unique_integer([:positive, :monotonic])}")

  defp assert_eventually(fun, attempts \\ 50)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end
end
