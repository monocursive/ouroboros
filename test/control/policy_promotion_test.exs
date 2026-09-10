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

  def get_checkpoint(key, opts), do: Ouroboros.Storage.ETS.get_checkpoint(key, opts)

  def put_checkpoint(key, data, opts) do
    if Application.get_env(:ouroboros, @flag, false),
      do: {:error, :storage_offline},
      else: Ouroboros.Storage.ETS.put_checkpoint(key, data, opts)
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
    assert PolicyPromotion.allowable_shapes("anything", @sha, "bash") == []
    assert PolicyPromotion.allowable("anything", @sha) == %{}
  end

  describe "a promotion" do
    test "binds the record to one policy at one sha and lists the shape", context do
      record = start_record!(context)

      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")

      assert PolicyPromotion.policy(record) == {"guard", @sha}
      assert shapes(record, "guard") == ["mix test"]
      assert PolicyPromotion.allowable("guard", @sha, record) == %{"bash" => ["mix test"]}

      # A promotion is a statement about one component's judgement at one set of bytes.
      # Carrying it to another name, or to other bytes, would be transferring a reputation —
      # and both gates live in this one function, so no caller can hold half the check.
      assert shapes(record, "other") == []
      assert PolicyPromotion.allowable_shapes("guard", @other_sha, "bash", record) == []
      assert PolicyPromotion.allowable("guard", @other_sha, record) == %{}

      # A shape is not a tool: the promotion says nothing about the rest of `bash`.
      assert PolicyPromotion.allowable_shapes("guard", @sha, "read", record) == []
    end

    test "for a different policy name is refused until the record is cleared", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "read")

      assert {:error, {:policy_promotion_bound_to, "guard", @sha}} =
               promote(record, "other", @sha, "read")

      assert :ok = PolicyPromotion.clear("operator:ana", record)
      assert PolicyPromotion.policy(record) == nil
      assert {:ok, _state} = promote(record, "other", @sha, "bash")
      assert shapes(record, "other") == ["mix test"]
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
               PolicyPromotion.promote("guard", @sha, "bash", "mix", evidence(), "", record)

      assert {:error, {:invalid_promotion_actor, nil}} =
               PolicyPromotion.promote("guard", @sha, "bash", "mix", evidence(), nil, record)

      assert {:error, {:invalid_component_sha256, "nope"}} =
               PolicyPromotion.promote("guard", "nope", "bash", "mix", evidence(), "ana", record)

      assert {:error, {:invalid_policy_name, "Not A Name"}} =
               PolicyPromotion.promote(
                 "Not A Name",
                 @sha,
                 "bash",
                 "mix",
                 evidence(),
                 "ana",
                 record
               )

      assert {:error, {:invalid_promoted_tool, ""}} =
               PolicyPromotion.promote("guard", @sha, "", "mix", evidence(), "ana", record)

      # A shape is written into a checkpoint, a ledger entry and an operator's terminal, so it
      # is held to what an operator could have typed in a `Bash(<shape> *)` rule.
      assert {:error, {:invalid_promoted_shape, ""}} =
               PolicyPromotion.promote("guard", @sha, "bash", "", evidence(), "ana", record)

      assert {:error, {:invalid_promoted_shape, "mix "}} =
               PolicyPromotion.promote("guard", @sha, "bash", "mix ", evidence(), "ana", record)

      assert {:error, {:invalid_promoted_shape, "mix\ntest"}} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "bash",
                 "mix\ntest",
                 evidence(),
                 "ana",
                 record
               )

      assert {:error, {:invalid_promoted_shape, _long}} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "bash",
                 String.duplicate("x", 129),
                 evidence(),
                 "ana",
                 record
               )

      assert {:error, {:invalid_promotion_evidence, _keys}} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "bash",
                 "mix",
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
                 "bash",
                 "mix test",
                 %{
                   report_sha256: "deadbeef",
                   decisions: 61,
                   contradictions: 0,
                   distinct_fingerprints: 22,
                   distinct_sessions: 3,
                   would_resolve: 19
                 },
                 "operator:ana",
                 record
               )

      status = PolicyPromotion.status(record)
      promoted = status.tools["bash"]["mix test"]
      assert promoted.actor == "operator:ana"
      assert promoted.evidence.decisions == 61
      assert promoted.evidence.contradictions == 0
      assert promoted.evidence.distinct_fingerprints == 22
      assert promoted.evidence.distinct_sessions == 3
      assert promoted.evidence.would_resolve == 19
      assert promoted.evidence.report_sha256 == "deadbeef"
      assert status.allowable == %{"bash" => ["mix test"]}
      assert status.allowable_tools == ["bash"]
    end
  end

  describe "a demotion" do
    test "newer than the promotion withdraws the shape, and only that shape", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "git status")

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "bash",
                 "mix test",
                 %{reason: :human_contradiction, fingerprint: @other_sha, session_id: "s-1"},
                 record
               )

      # Drop the newer-than check in `shapes_of/4` and `mix test` comes back.
      assert shapes(record, "guard") == ["git status"]
    end

    test "older than a re-promotion does not withdraw it", context do
      # The order is the record's own sequence rather than the wall clock, so a promotion and a
      # demotion in the same microsecond cannot be read the wide way round.
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")
      assert :ok = PolicyPromotion.demote("guard", "bash", "mix test", %{reason: :test}, record)
      assert shapes(record, "guard") == []

      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")
      assert shapes(record, "guard") == ["mix test"]
    end

    test "of a shape that is not promoted, or of another policy, is a no-op", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")

      assert :ok = PolicyPromotion.demote("guard", "bash", "mix format", %{reason: :test}, record)
      assert :ok = PolicyPromotion.demote("guard", "read", "mix test", %{reason: :test}, record)
      assert :ok = PolicyPromotion.demote("other", "bash", "mix test", %{reason: :test}, record)
      assert shapes(record, "guard") == ["mix test"]
    end

    test "keeps the digest of the answer that caused it and never a command", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "bash",
                 "mix test",
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
      assert demotion.shape == "mix test"
      assert demotion.fingerprint == @other_sha
      assert demotion.session_id == "session-77"
      refute Map.has_key?(demotion, :command)
      refute inspect(demotion) =~ "rm -rf"
    end

    test "a fingerprint that is not a digest is dropped rather than stored", context do
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "bash",
                 "mix test",
                 %{reason: :human_contradiction, fingerprint: "the command was rm -rf /"},
                 record
               )

      assert [%{fingerprint: nil}] = PolicyPromotion.status(record).demotions
    end
  end

  describe "the shadow counter (S-D29)" do
    test "counts per (tool, shape), is not durable, and resets when the shape changes",
         context do
      record = start_record!(context)

      assert PolicyPromotion.shadow_tick("bash", "mix test", record) == 1
      assert PolicyPromotion.shadow_tick("bash", "mix test", record) == 2
      assert PolicyPromotion.shadow_tick("bash", "git status", record) == 1
      assert PolicyPromotion.shadow_tick("bash", "mix test", record) == 3

      # A promotion or a demotion of that shape starts the sample again: the phase belongs to
      # the promotion, and a re-promoted shape has not been sampled yet.
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")
      assert PolicyPromotion.shadow_tick("bash", "mix test", record) == 1
      assert PolicyPromotion.shadow_tick("bash", "git status", record) == 2

      assert :ok = PolicyPromotion.demote("guard", "bash", "mix test", %{reason: :test}, record)
      assert PolicyPromotion.shadow_tick("bash", "mix test", record) == 1
    end

    test "an authority that cannot answer says so, and the engine shadows on that" do
      assert PolicyPromotion.shadow_tick("bash", "mix test", :no_such_record) == :error
    end
  end

  describe "storage faults" do
    test "a promotion whose checkpoint fails is refused and never takes effect", context do
      record = start_record!(context, {FlakyStorage, table: unique_table()})
      FlakyStorage.fail!()

      assert {:error, {:policy_promotion_checkpoint_failed, :storage_offline}} =
               promote(record, "guard", @sha, "bash")

      assert shapes(record, "guard") == []
      assert PolicyPromotion.policy(record) == nil

      FlakyStorage.heal!()
      assert {:ok, _state} = promote(record, "guard", @sha, "bash")
      assert shapes(record, "guard") == ["mix test"]
    end

    test "a demotion whose checkpoint fails leaves the tool promoted and says so", context do
      # `Control.Grants`' uncomfortable direction, on purpose: an authority that forgot a
      # promotion it could not durably forget would hand it straight back at the next restart.
      record = start_record!(context, {FlakyStorage, table: unique_table()})
      assert {:ok, _state} = promote(record, "guard", @sha, "bash")

      FlakyStorage.fail!()

      assert {:error, {:policy_promotion_checkpoint_failed, :storage_offline}} =
               PolicyPromotion.demote("guard", "bash", "mix test", %{reason: :test}, record)

      assert shapes(record, "guard") == ["mix test"]

      FlakyStorage.heal!()
      assert :ok = PolicyPromotion.demote("guard", "bash", "mix test", %{reason: :test}, record)
      assert shapes(record, "guard") == []
    end

    test "the record survives a restart of the authority", context do
      table = unique_table()
      storage = {Ouroboros.Storage.ETS, table: table}
      record = start_record!(context, storage)

      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "mix test")
      assert {:ok, _state} = promote(record, "guard", @sha, "bash", "git status")
      assert :ok = PolicyPromotion.demote("guard", "bash", "git status", %{reason: :test}, record)

      stop_supervised!(record)
      restarted = start_record!(context, storage)

      assert PolicyPromotion.policy(restarted) == {"guard", @sha}

      # The demotion is durable too. A restart that resurrected `git status` would be the same
      # failure as never having written the demotion.
      assert shapes(restarted, "guard") == ["mix test"]
    end

    test "a checkpoint this build cannot interpret stops the record instead of emptying it" do
      table = unique_table()

      :ok =
        Ouroboros.Storage.ETS.put_checkpoint(PolicyPromotion.checkpoint_key(), %{version: 99},
          table: table
        )

      assert {:error, {{:unsupported_policy_promotion_checkpoint, 99}, _spec}} =
               start_supervised(
                 {PolicyPromotion,
                  name: unique_name(), storage: {Ouroboros.Storage.ETS, table: table}}
               )
    end

    test "a version-1 record is one of those: tool-level promotions are not translated" do
      # Version 1 held `tools: %{tool => entry}` — "this component may resolve every call to
      # this tool", which is the claim the review proved carries no information. Reading one as
      # a set of shapes would be inventing shapes nobody measured; reading it as empty would
      # silently discard an operator's record. It stops.
      table = unique_table()

      :ok =
        Ouroboros.Storage.ETS.put_checkpoint(
          PolicyPromotion.checkpoint_key(),
          %{
            version: 1,
            seq: 4,
            record: %{
              policy_name: "guard",
              component_sha256: @sha,
              tools: %{"bash" => %{promoted_at: "2026-09-08T00:00:00Z", seq: 4}},
              demotions: []
            }
          },
          table: table
        )

      assert {:error, {{:unsupported_policy_promotion_checkpoint, 1}, _spec}} =
               start_supervised(
                 {PolicyPromotion,
                  name: unique_name(), storage: {Ouroboros.Storage.ETS, table: table}}
               )
    end
  end

  describe "the ledger" do
    test "holds one entry per write, naming the bytes, the shape and the numbers", context do
      record = start_record!(context)

      assert {:ok, _state} =
               PolicyPromotion.promote(
                 "guard",
                 @sha,
                 "bash",
                 "mix test",
                 %{
                   report_sha256: "r1",
                   decisions: 60,
                   contradictions: 0,
                   distinct_fingerprints: 24,
                   distinct_sessions: 3,
                   would_resolve: 20
                 },
                 "operator:ana",
                 record
               )

      assert :ok =
               PolicyPromotion.demote(
                 "guard",
                 "bash",
                 "mix test",
                 %{reason: :human_contradiction, fingerprint: @other_sha, session_id: "s-9"},
                 record
               )

      assert :ok = PolicyPromotion.clear("operator:ana", record)

      assert [promoted, demoted, cleared] = entries(context)

      assert promoted.attempt.action == :promote
      assert promoted.attempt.policy_name == "guard"
      assert promoted.attempt.tool == "bash"
      assert promoted.attempt.shape == "mix test"
      assert promoted.attempt.component_sha256 == @sha
      assert promoted.principal == "operator:ana"
      assert promoted.result.decisions == 60
      assert promoted.result.contradictions == 0
      assert promoted.result.distinct_fingerprints == 24
      assert promoted.result.distinct_sessions == 3
      assert promoted.result.would_resolve == 20
      assert promoted.result.report_sha256 == "r1"
      assert promoted.status == :ok

      assert demoted.attempt.action == :demote
      assert demoted.attempt.shape == "mix test"
      assert demoted.result.reason == :human_contradiction
      assert demoted.result.fingerprint == @other_sha
      assert demoted.principal == "s-9"

      assert cleared.attempt.action == :clear
      assert cleared.attempt.tool == nil
      assert cleared.attempt.shape == nil
      assert cleared.principal == "operator:ana"
    end

    test "a promotion is started before the checkpoint and settled after it (M4)", context do
      # Every other ledger-gated effect in this runtime records `started` first and settles the
      # real outcome. This one wrote a single settled `:ok` entry *before* `persist/4`, so a
      # promotion the checkpoint then refused left the only durable record of what widened this
      # node's permission surface saying, settled and `:ok`, that it had.
      record = start_record!(context, {FlakyStorage, table: unique_table()})
      FlakyStorage.fail!()

      assert {:error, {:policy_promotion_checkpoint_failed, :storage_offline}} =
               promote(record, "guard", @sha, "bash")

      # The authority is correct...
      assert shapes(record, "guard") == []
      assert PolicyPromotion.policy(record) == nil

      # ...and now so is the audit.
      assert [refused] = entries(context)
      assert refused.attempt.action == :promote
      assert refused.attempt.shape == "mix test"
      assert refused.status == :failed
      assert refused.error

      FlakyStorage.heal!()
      assert {:ok, _state} = promote(record, "guard", @sha, "bash")

      assert [_refused, settled] = entries(context)
      assert settled.status == :ok
      assert settled.result.decisions == 60
    end

    test "a ledger that refuses refuses the promotion", context do
      # A widening nobody can account for afterwards is exactly what this lane exists to
      # prevent. Reorder `handle_call({:promote, …})` to checkpoint before the ledger and this
      # goes red.
      record = start_record!(context, nil, :a_ledger_that_is_not_running)

      assert {:error, {:policy_promotion_unrecordable, _reason}} =
               promote(record, "guard", @sha, "bash")

      assert shapes(record, "guard") == []
      assert PolicyPromotion.policy(record) == nil
    end

    test "a ledger that refuses does not block a demotion", context do
      # The other half, and `Control.Permissions`' rule verbatim: an allow nobody can account
      # for has not been granted, but refusing without an audit entry is still refusing. Move
      # the demotion's ledger write in front of its checkpoint and a broken audit trail becomes
      # a permission surface nobody can narrow.
      record = start_record!(context)
      assert {:ok, _state} = promote(record, "guard", @sha, "bash")

      :ok = GenServer.stop(context.ledger)

      assert :ok = PolicyPromotion.demote("guard", "bash", "mix test", %{reason: :test}, record)
      assert shapes(record, "guard") == []
    end
  end

  ## helpers

  setup context do
    name = :"policy_promotion_ledger_#{System.unique_integer([:positive, :monotonic])}"

    ledger =
      start_supervised!(
        {EffectLedger,
         name: name, storage: {Ouroboros.Storage.ETS, table: unique_table()}, retention_limit: 100},
        id: name
      )

    Map.put(context, :ledger, ledger)
  end

  defp start_record!(context, storage \\ nil, ledger \\ nil) do
    name = unique_name()
    storage = storage || {Ouroboros.Storage.ETS, table: unique_table()}

    start_supervised!(
      {PolicyPromotion, name: name, storage: storage, ledger: ledger || context.ledger},
      id: name
    )

    name
  end

  defp promote(record, name, sha, tool, shape \\ "mix test"),
    do: PolicyPromotion.promote(name, sha, tool, shape, evidence(), "operator:ana", record)

  defp evidence,
    do: %{
      report_sha256: "report-digest",
      decisions: 60,
      contradictions: 0,
      distinct_fingerprints: 25,
      distinct_sessions: 2,
      would_resolve: 25
    }

  defp shapes(record, name, sha \\ @sha, tool \\ "bash"),
    do: PolicyPromotion.allowable_shapes(name, sha, tool, record)

  defp entries(context) do
    {:ok, entries} = EffectLedger.list([effect: :policy_promotion, order: :asc], context.ledger)
    entries
  end

  defp unique_name,
    do: String.to_atom("policy_promotion_#{System.unique_integer([:positive, :monotonic])}")

  defp unique_table,
    do: String.to_atom("policy_promotion_store_#{System.unique_integer([:positive, :monotonic])}")
end
