defmodule Ouroboros.Control.PolicyPromotionTest.FlakyStorage do
  @moduledoc """
  An ETS adapter whose writes can be made to fail on demand.

  `Ouroboros.Control.GrantsTest.FlakyStorage`, verbatim and for its reason: the ack ordering is
  only observable from outside, as the difference between what the caller was told and what the
  authority still believes afterwards.
  """

  @flag :policy_promotion_test_storage_fails

  def fail!, do: Application.put_env(:ouroboros, @flag, true)
  def heal!, do: Application.delete_env(:ouroboros, @flag)

  def get_checkpoint(key, opts), do: Jido.Storage.ETS.get_checkpoint(key, opts)

  def put_checkpoint(key, data, opts) do
    if Application.get_env(:ouroboros, @flag, false),
      do: {:error, :storage_offline},
      else: Jido.Storage.ETS.put_checkpoint(key, data, opts)
  end
end

defmodule Ouroboros.Control.PolicyPromotionTest do
  @moduledoc """
  S2's record: what a policy component has earned the right to resolve, and how it loses it.

  The claims: a promotion is not applied until its checkpoint is acknowledged, one record holds
  one policy at one sha, a demotion newer than a promotion withdraws it, every write leaves a
  `:policy_promotion` ledger entry, and the ledger sits on opposite sides of a widening and a
  narrowing — a promotion nobody can account for does not happen, and a demotion an audit
  failure could block would be a narrowing that fails open.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Control.PolicyPromotionTest.FlakyStorage

  @sha String.duplicate("a", 64)
  @other_sha String.duplicate("b", 64)

  setup do
    on_exit(&FlakyStorage.heal!/0)
    :ok
  end

  test "the record is supervised by the application and starts empty" do
    assert is_pid(Process.whereis(PolicyPromotion))
    assert PolicyPromotion.allowable_tools("anything") == []
  end

  describe "a promotion" do
    test "binds the record to one policy at one sha and lists the tool", context do
      record = start_record!(context)

      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert PolicyPromotion.policy(record) == {"guard", @sha}
      assert PolicyPromotion.allowable_tools("guard", record) == ["read"]

      # A promotion is a statement about one component's judgement. Carrying it to another
      # component's name would be transferring a reputation. Drop the name check in
      # `allowable/2` and this goes red.
      assert PolicyPromotion.allowable_tools("other", record) == []
    end

    test "for a different policy name is refused until the record is cleared", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert {:error, {:policy_promotion_bound_to, "guard", @sha}} =
               promote(record, "other", @sha, "read")

      assert :ok = PolicyPromotion.clear("operator:ana", record)
      assert PolicyPromotion.policy(record) == nil
      assert {:ok, _state} = promote(record, "other", @sha, "read")
      assert PolicyPromotion.allowable_tools("other", record) == ["read"]
    end

    test "for the same name at different bytes is refused too", context do
      # The point rather than a simplification: a re-deployed policy is different bytes and has
      # earned nothing. A record that carried a tool across a re-deploy would be a widening
      # nobody performed.
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert {:error, {:policy_promotion_bound_to, "guard", @sha}} =
               promote(record, "guard", @other_sha, "read")
    end

    test "requires a named human actor, a real sha, and countable evidence", context do
      record = start_record!(context)

      assert {:error, {:invalid_promotion_actor, ""}} =
               PolicyPromotion.promote("guard", @sha, "read", evidence(), "", record)

      assert {:error, {:invalid_promotion_actor, nil}} =
               PolicyPromotion.promote("guard", @sha, "read", evidence(), nil, record)

      assert {:error, {:invalid_component_sha256, "nope"}} =
               PolicyPromotion.promote("guard", "nope", "read", evidence(), "ana", record)

      assert {:error, {:invalid_policy_name, "Not A Name"}} =
               PolicyPromotion.promote("Not A Name", @sha, "read", evidence(), "ana", record)

      assert {:error, {:invalid_promoted_tool, ""}} =
               PolicyPromotion.promote("guard", @sha, "", evidence(), "ana", record)

      assert {:error, {:invalid_promotion_evidence, _keys}} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "read",
                 %{decisions: 60, contradictions: 0},
                 "ana",
                 record
               )

      assert PolicyPromotion.policy(record) == nil
    end

    test "keeps the numbers it was promoted on", context do
      record = start_record!(context)

      assert {:ok, _state} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "read",
                 %{report_sha256: "deadbeef", decisions: 61, contradictions: 0},
                 "operator:ana",
                 record
               )

      status = PolicyPromotion.status(record)
      assert status.tools["read"].actor == "operator:ana"
      assert status.tools["read"].evidence.decisions == 61
      assert status.tools["read"].evidence.contradictions == 0
      assert status.tools["read"].evidence.report_sha256 == "deadbeef"
      assert status.allowable_tools == ["read"]
    end
  end

  describe "a demotion" do
    test "newer than the promotion withdraws the tool, and only that tool", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")
      assert {:ok, _state} = promote(record, "guard", @sha, "bash")

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "read",
                 %{reason: :human_contradiction, fingerprint: @other_sha, session_id: "s-1"},
                 record
               )

      # Drop the newer-than check in `allowable/2` and `read` comes back.
      assert PolicyPromotion.allowable_tools("guard", record) == ["bash"]
    end

    test "older than a re-promotion does not withdraw it", context do
      # The order is the record's own sequence rather than the wall clock, so a promotion and a
      # demotion in the same microsecond cannot be read the wide way round.
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")
      assert :ok = PolicyPromotion.demote("guard", "read", %{reason: :test}, record)
      assert PolicyPromotion.allowable_tools("guard", record) == []

      assert {:ok, _state} = promote(record, "guard", @sha, "read")
      assert PolicyPromotion.allowable_tools("guard", record) == ["read"]
    end

    test "of a tool that is not promoted, or of another policy, is a no-op", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert :ok = PolicyPromotion.demote("guard", "bash", %{reason: :test}, record)
      assert :ok = PolicyPromotion.demote("other", "read", %{reason: :test}, record)
      assert PolicyPromotion.allowable_tools("guard", record) == ["read"]
    end

    test "keeps the digest of the answer that caused it and never a command", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "read",
                 %{
                   reason: :human_contradiction,
                   fingerprint: @other_sha,
                   session_id: "session-77",
                   command: "rm -rf /"
                 },
                 record
               )

      assert [demotion] = PolicyPromotion.status(record).demotions
      assert demotion.reason == :human_contradiction
      assert demotion.fingerprint == @other_sha
      assert demotion.session_id == "session-77"
      refute Map.has_key?(demotion, :command)
      refute inspect(demotion) =~ "rm -rf"
    end

    test "a fingerprint that is not a digest is dropped rather than stored", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "read",
                 %{reason: :human_contradiction, fingerprint: "the command was rm -rf /"},
                 record
               )

      assert [%{fingerprint: nil}] = PolicyPromotion.status(record).demotions
    end
  end

  describe "storage faults" do
    test "a promotion whose checkpoint fails is refused and never takes effect", context do
      record = start_record!(context, {FlakyStorage, table: unique_table()})
      FlakyStorage.fail!()

      assert {:error, {:policy_promotion_checkpoint_failed, :storage_offline}} =
               promote(record, "guard", @sha, "read")

      assert PolicyPromotion.allowable_tools("guard", record) == []
      assert PolicyPromotion.policy(record) == nil

      FlakyStorage.heal!()
      assert {:ok, _state} = promote(record, "guard", @sha, "read")
      assert PolicyPromotion.allowable_tools("guard", record) == ["read"]
    end

    test "a demotion whose checkpoint fails leaves the tool promoted and says so", context do
      # `Control.Grants`' uncomfortable direction, on purpose: an authority that forgot a
      # promotion it could not durably forget would hand it straight back at the next restart.
      record = start_record!(context, {FlakyStorage, table: unique_table()})
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      FlakyStorage.fail!()

      assert {:error, {:policy_promotion_checkpoint_failed, :storage_offline}} =
               PolicyPromotion.demote("guard", "read", %{reason: :test}, record)

      assert PolicyPromotion.allowable_tools("guard", record) == ["read"]

      FlakyStorage.heal!()
      assert :ok = PolicyPromotion.demote("guard", "read", %{reason: :test}, record)
      assert PolicyPromotion.allowable_tools("guard", record) == []
    end

    test "the record survives a restart of the authority", context do
      table = unique_table()
      storage = {Jido.Storage.ETS, table: table}
      record = start_record!(context, storage)

      assert {:ok, _state} = promote(record, "guard", @sha, "read")
      assert {:ok, _state} = promote(record, "guard", @sha, "bash")
      assert :ok = PolicyPromotion.demote("guard", "bash", %{reason: :test}, record)

      stop_supervised!(record)
      restarted = start_record!(context, storage)

      assert PolicyPromotion.policy(restarted) == {"guard", @sha}

      # The demotion is durable too. A restart that resurrected `bash` would be the same
      # failure as never having written the demotion.
      assert PolicyPromotion.allowable_tools("guard", restarted) == ["read"]
    end

    test "a checkpoint this build cannot interpret stops the record instead of emptying it" do
      table = unique_table()

      :ok =
        Jido.Storage.ETS.put_checkpoint(PolicyPromotion.checkpoint_key(), %{version: 99},
          table: table
        )

      assert {:error, {{:unsupported_policy_promotion_checkpoint, 99}, _spec}} =
               start_supervised(
                 {PolicyPromotion, name: unique_name(), storage: {Jido.Storage.ETS, table: table}}
               )
    end
  end

  describe "the ledger" do
    test "holds one entry per write, naming the bytes and the numbers", context do
      record = start_record!(context)

      assert {:ok, _state} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "read",
                 %{report_sha256: "r1", decisions: 60, contradictions: 0},
                 "operator:ana",
                 record
               )

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "read",
                 %{reason: :human_contradiction, fingerprint: @other_sha, session_id: "s-9"},
                 record
               )

      assert :ok = PolicyPromotion.clear("operator:ana", record)

      assert [promoted, demoted, cleared] = entries(context)

      assert promoted.attempt.action == :promote
      assert promoted.attempt.policy_name == "guard"
      assert promoted.attempt.tool == "read"
      assert promoted.attempt.component_sha256 == @sha
      assert promoted.principal == "operator:ana"
      assert promoted.result.decisions == 60
      assert promoted.result.contradictions == 0
      assert promoted.result.report_sha256 == "r1"
      assert promoted.status == :ok

      assert demoted.attempt.action == :demote
      assert demoted.result.reason == :human_contradiction
      assert demoted.result.fingerprint == @other_sha
      assert demoted.principal == "s-9"

      assert cleared.attempt.action == :clear
      assert cleared.attempt.tool == nil
      assert cleared.principal == "operator:ana"
    end

    test "a ledger that refuses refuses the promotion", context do
      # A widening nobody can account for afterwards is exactly what this lane exists to
      # prevent. Reorder `handle_call({:promote, …})` to checkpoint before the ledger and this
      # goes red.
      record = start_record!(context, nil, :a_ledger_that_is_not_running)

      assert {:error, {:policy_promotion_unrecordable, _reason}} =
               promote(record, "guard", @sha, "read")

      assert PolicyPromotion.allowable_tools("guard", record) == []
      assert PolicyPromotion.policy(record) == nil
    end

    test "a ledger that refuses does not block a demotion", context do
      # The other half, and `Control.Permissions`' rule verbatim: an allow nobody can account
      # for has not been granted, but refusing without an audit entry is still refusing. Move
      # the demotion's ledger write in front of its checkpoint and a broken audit trail becomes
      # a permission surface nobody can narrow.
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      :ok = GenServer.stop(context.ledger)

      assert :ok = PolicyPromotion.demote("guard", "read", %{reason: :test}, record)
      assert PolicyPromotion.allowable_tools("guard", record) == []
    end
  end

  ## helpers

  setup context do
    name = :"policy_promotion_ledger_#{System.unique_integer([:positive, :monotonic])}"

    ledger =
      start_supervised!(
        {EffectLedger,
         name: name, storage: {Jido.Storage.ETS, table: unique_table()}, retention_limit: 100},
        id: name
      )

    Map.put(context, :ledger, ledger)
  end

  defp start_record!(context, storage \\ nil, ledger \\ nil) do
    name = unique_name()
    storage = storage || {Jido.Storage.ETS, table: unique_table()}

    start_supervised!(
      {PolicyPromotion, name: name, storage: storage, ledger: ledger || context.ledger},
      id: name
    )

    name
  end

  defp promote(record, name, sha, tool),
    do: PolicyPromotion.promote(name, sha, tool, evidence(), "operator:ana", record)

  defp evidence, do: %{report_sha256: "report-digest", decisions: 60, contradictions: 0}

  defp entries(context) do
    {:ok, entries} = EffectLedger.list([effect: :policy_promotion, order: :asc], context.ledger)
    entries
  end

  defp unique_name,
    do: String.to_atom("policy_promotion_#{System.unique_integer([:positive, :monotonic])}")

  defp unique_table,
    do: String.to_atom("policy_promotion_store_#{System.unique_integer([:positive, :monotonic])}")
end
