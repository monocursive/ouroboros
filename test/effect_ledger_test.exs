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
