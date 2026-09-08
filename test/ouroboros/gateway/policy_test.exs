defmodule Ouroboros.Gateway.PolicyTest do
  # Not async: three of these verbs write to the node's one `Control.PolicyPromotion`
  # process, which is a singleton by design, and `Audit.Identity` is per-process state
  # this module installs and removes.
  use ExUnit.Case, async: false

  @moduledoc """
  The five `policy.*` verbs (docs/SELF.md §S2, S-D27–S-D29).

  The claim that matters most is a negative one: **no part of the evidence corpus crosses
  this boundary.** The corpus holds the exact document a policy component would have been
  shown for every permission request a human answered on this node — command lines, paths
  and domains, redacted only as far as `PolicyEngine.document/1` redacts them — and what
  these verbs say about it is `PolicyEvidence.count/0` and nothing else. So there is a test
  here that walks the whole reply looking for a document, and it is the one to keep.

  The rest: the table's scopes and the ceiling admission, closed envelopes on all five, the
  contract's restated thresholds held equal to the engine's own, the record's presentation
  under both an empty and a populated record, the named refusals, and the two verbs that
  refuse an unattributed caller rather than promoting under a placeholder.
  """

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Audit.Identity
  alias Ouroboros.Control.PolicyEvidence
  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Contract
  alias Ouroboros.Wasm.PolicyEngine

  @moduletag :capture_log

  @verbs ~w(policy.status policy.replay policy.promote policy.demote policy.clear)
  @operators ~w(policy.replay policy.promote policy.demote policy.clear)

  # A name and bytes this node has certainly never deployed, so nothing here can be confused
  # with a live rollout.
  @name "gateway-policy-test"
  @sha String.duplicate("9", 64)

  # The subject `Gateway.Conn` installs for the local owner when no identities are
  # configured. Reaching `Methods.invoke/2` directly leaves no subject at all, which is what
  # the unattributed tests exercise.
  @owner %{"local" => true, "id" => "local-owner"}

  setup do
    on_exit(fn -> PolicyPromotion.clear("gateway-policy-test-teardown") end)
    :ok
  end

  describe "the table" do
    test "status reads and the other four operate" do
      assert {:ok, %{scope: :read}} = Methods.fetch("policy.status")

      for verb <- @operators do
        assert verb in Methods.names()
        assert {:ok, %{scope: :operate}} = Methods.fetch(verb)
      end
    end

    test "promote admits an unknown outcome, because a ceiling does not stop a checkpoint" do
      # The replay it re-runs and the record it writes outlive this socket exactly as
      # `wasm.deploy`'s rollout does. A client reconciles with `policy.status`.
      assert {:ok, %{outcome: :unknown}} = Methods.fetch("policy.promote")

      for verb <- @verbs -- ["policy.promote"] do
        assert {:ok, entry} = Methods.fetch(verb)
        refute Map.get(entry, :outcome) == :unknown
      end
    end

    test "every envelope is closed, including the two that take nothing" do
      for verb <- @verbs do
        assert {:ok, %{envelope: :closed}} = Methods.params(verb)

        assert {:error, -32_602, message} = Methods.invoke(verb, %{"actor" => "somebody"})
        assert message =~ "unsupported fields: actor"
      end
    end

    test "there is no verb that serves a corpus row" do
      # `policy.export`, `policy.evidence` and friends would be the shape of a mistake: the
      # corpus is the one file on this node holding the requests themselves.
      for absent <- ~w(policy.evidence policy.export policy.corpus policy.document) do
        refute absent in Methods.names(),
               "#{absent} would put the decision corpus on a socket"
      end
    end

    test "the contract's restated thresholds are the engine's own" do
      # The generated reference states `50` and `0` in prose. This is what keeps that prose
      # true when the engine's numbers move.
      assert PolicyEngine.promotion_thresholds() == %{
               decisions: Contract.policy_min_decisions(),
               contradictions: Contract.policy_max_contradictions()
             }
    end
  end

  describe "policy.status" do
    test "answers the record, its durability, the thresholds and the corpus's counts" do
      assert {:ok, status} = Methods.invoke("policy.status", %{})

      assert status.node == node()
      assert status.policy == nil
      assert status.tools == []
      assert status.demotions == []
      assert status.allowable_tools == []
      assert status.durability in [:ephemeral_checkpoint, :synced_checkpoint, :durable_checkpoint]
      assert status.thresholds == PolicyEngine.promotion_thresholds()

      # Counts, and exactly the counts `PolicyEvidence` offers.
      assert Map.keys(status.evidence) |> Enum.sort() ==
               Map.keys(PolicyEvidence.count()) |> Enum.sort()
    end

    test "carries no document, no command and no path, however deep the record is" do
      promote!(@name, @sha, "bash")
      promote!(@name, @sha, "read")
      :ok = PolicyPromotion.demote(@name, "bash", %{reason: :human_contradiction})

      assert {:ok, status} = Methods.invoke("policy.status", %{})

      # The whole reply, flattened to its keys and its strings. A corpus row's own keys are
      # `document`, `command`, `paths`, `write_paths` and `domains`; none of them may appear
      # here at any depth, and neither may the corpus's path on disk.
      {keys, strings} = walk(status)

      for forbidden <- ~w(document command input paths write_paths domains) do
        refute forbidden in keys, "policy.status leaked a #{forbidden} key: #{inspect(keys)}"
      end

      refute Enum.any?(strings, &String.contains?(&1, "evidence.ndjson"))
      refute Enum.any?(strings, &String.contains?(&1, "/"))
    end

    test "renders a populated record: tools sorted, demotions newest first and bounded" do
      promote!(@name, @sha, "read")
      promote!(@name, @sha, "bash")

      # Twenty-five demotions so the bound is a bound rather than a description.
      for index <- 1..25 do
        :ok =
          PolicyPromotion.demote(@name, "tool-#{index}", %{
            reason: :human_contradiction,
            session_id: "session-#{index}"
          })

        # A demotion of a tool that is not promoted is `:ok` with no write, so the tools have
        # to exist for the list to grow.
        promote!(@name, @sha, "tool-#{index}")

        :ok =
          PolicyPromotion.demote(@name, "tool-#{index}", %{
            reason: :human_contradiction,
            session_id: "session-#{index}"
          })
      end

      assert {:ok, status} = Methods.invoke("policy.status", %{})

      assert status.policy == %{name: @name, component_sha256: @sha}
      assert Enum.map(status.tools, & &1.tool) == Enum.sort(Enum.map(status.tools, & &1.tool))
      assert "bash" in Enum.map(status.tools, & &1.tool)

      # Promoted and never demoted since.
      assert "bash" in status.allowable_tools
      assert "read" in status.allowable_tools
      refute "tool-25" in status.allowable_tools

      assert length(status.demotions) == 20
      sequences = Enum.map(status.demotions, & &1.seq)
      assert sequences == Enum.sort(sequences, :desc)

      # Each promoted tool carries who promoted it and the numbers it was promoted on.
      entry = Enum.find(status.tools, &(&1.tool == "bash"))
      assert entry.actor == "operator:test"
      assert entry.evidence.decisions == 60
      assert entry.evidence.contradictions == 0
    end

    test "answers the same keys the golden fixture pins" do
      # `policy_status_result.json` is what a second implementation decodes. A field added
      # here and not there is a field the Rust client never learns about.
      assert {:ok, status} = Methods.invoke("policy.status", %{})

      fixture =
        Golden.path("policy_status_result")
        |> File.read!()
        |> JSON.decode!()
        |> Map.fetch!("result")

      assert status |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture |> Map.keys() |> Enum.sort()

      assert status.evidence |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture["evidence"] |> Map.keys() |> Enum.sort()
    end
  end

  describe "policy.replay" do
    test "requires a name, and refuses one this node does not run by name" do
      assert {:error, -32_602, message} = Methods.invoke("policy.replay", %{})
      assert message =~ "params.name is required"

      assert {:error, -32_602, blank} = Methods.invoke("policy.replay", %{"name" => ""})
      assert blank =~ "params.name must be a nonempty string"

      assert {:error, code, sentence, data} =
               Methods.invoke("policy.replay", %{"name" => @name})

      assert code == Methods.code(:not_found)
      assert data["reason"] == "no_live_policy"
      assert data["name"] == @name
      assert sentence =~ "no live lane-W policy"
    end

    test "since is an optional string and is refused when it is anything else" do
      assert {:error, -32_602, message} =
               Methods.invoke("policy.replay", %{"name" => @name, "since" => 17})

      assert message =~ "params.since must be a nonempty string when present"
    end
  end

  describe "policy.promote" do
    test "takes name, tool and a report object, and no actor" do
      assert {:ok, %{envelope: :closed, params: params}} = Methods.params("policy.promote")
      names = Enum.map(params, & &1.name)

      assert Enum.sort(names) == ["name", "report", "tool"]
      refute "actor" in names

      assert {:error, -32_602, message} =
               Methods.invoke("policy.promote", %{"name" => @name, "tool" => "bash"})

      assert message =~ "params.report is required"

      assert {:error, -32_602, shape} =
               Methods.invoke("policy.promote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "report" => "a report"
               })

      assert shape =~ "params.report must be an object"
    end

    test "refuses a policy this node does not run before it looks at the report" do
      assert {:error, code, _sentence, data} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.promote", %{
                   "name" => @name,
                   "tool" => "bash",
                   "report" => %{"component_sha256" => @sha}
                 })
               end)

      assert code == Methods.code(:not_found)
      assert data["reason"] == "no_live_policy"
    end

    test "refuses a caller with no resolvable identity rather than promoting as one" do
      # `Audit.Identity.actor/0` cannot fail: with nobody behind the socket it answers the
      # placeholder `runtime-unattributed`, which is a fine ledger principal for something
      # the runtime did to itself and is not a human. S2's rule is that a promotion has one.
      assert {:error, code, sentence, data} =
               Methods.invoke("policy.promote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "report" => %{}
               })

      assert code == Methods.code(:scope_denied)
      assert data["reason"] == "unattributed_actor"
      assert sentence =~ "no resolvable identity"

      # And it is checked before the plane is asked, so an unattributed caller learns
      # nothing about what this node runs.
      refute sentence =~ "no live lane-W policy"
    end
  end

  describe "policy.demote" do
    test "narrows without an identity, because narrowing is always safe" do
      # The asymmetry is deliberate: `promote` and `clear` are the two calls
      # `PolicyPromotion` requires an actor for, and a demotion nobody can name is still a
      # demotion.
      assert {:ok, record} =
               Methods.invoke("policy.demote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "reason" => "it asked to curl an internal host"
               })

      assert record.policy == nil
    end

    test "echoes the operator's sentence and stores an enumerated atom instead" do
      promote!(@name, @sha, "bash")
      sentence = "it allowed a curl a human denied on 2026-09-08"

      assert {:ok, record} =
               Methods.invoke("policy.demote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "reason" => sentence
               })

      assert record.reason == sentence
      refute "bash" in record.allowable_tools

      # The record itself never saw the sentence: a checkpoint fsynced on every write is not
      # where free text belongs, and a demotion's reason is a term this build enumerates.
      stored = PolicyPromotion.status()
      demotion = Enum.find(stored.demotions, &(&1.tool == "bash"))
      assert demotion.reason == :operator_demotion
      refute Enum.any?(Map.values(demotion), &(&1 == sentence))
    end

    test "bounds the reason, because it is echoed into a reply frame" do
      limit = Contract.policy_reason_bytes()

      assert {:error, -32_602, message} =
               Methods.invoke("policy.demote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "reason" => String.duplicate("x", limit + 1)
               })

      assert message =~ "between 1 and #{limit} bytes"

      assert {:ok, _record} =
               Methods.invoke("policy.demote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "reason" => String.duplicate("x", limit)
               })
    end

    test "a name this record does not hold narrows nothing and is not an error" do
      promote!(@name, @sha, "bash")

      assert {:ok, record} =
               Methods.invoke("policy.demote", %{
                 "name" => "some-other-policy",
                 "tool" => "bash",
                 "reason" => "wrong record"
               })

      assert record.allowable_tools == ["bash"]
    end
  end

  describe "policy.clear" do
    test "refuses an unattributed caller, and empties the record for a named one" do
      promote!(@name, @sha, "bash")

      assert {:error, code, _sentence, data} = Methods.invoke("policy.clear", %{})
      assert code == Methods.code(:scope_denied)
      assert data["reason"] == "unattributed_actor"

      # Nothing was cleared by the refusal.
      assert PolicyPromotion.policy() == {@name, @sha}

      assert {:ok, record} =
               Identity.with_subject(@owner, fn -> Methods.invoke("policy.clear", %{}) end)

      assert record.policy == nil
      assert record.tools == []
      assert record.allowable_tools == []
      assert PolicyPromotion.policy() == nil
    end
  end

  # ---------------------------------------------------------------------------

  defp promote!(name, sha, tool) do
    assert {:ok, _record} =
             PolicyPromotion.promote(
               name,
               sha,
               tool,
               %{report_sha256: String.duplicate("f", 64), decisions: 60, contradictions: 0},
               "operator:test"
             )
  end

  # Every key and every string in a term, at any depth. Cheap, and the only honest way to
  # assert that something is *not* in a reply.
  defp walk(term), do: walk(term, {[], []})

  defp walk(term, {keys, strings}) when is_map(term) and not is_struct(term) do
    Enum.reduce(term, {keys ++ Enum.map(Map.keys(term), &to_string/1), strings}, fn {_key, value},
                                                                                    acc ->
      walk(value, acc)
    end)
  end

  defp walk(term, acc) when is_list(term), do: Enum.reduce(term, acc, &walk/2)
  defp walk(term, {keys, strings}) when is_binary(term), do: {keys, [term | strings]}

  defp walk(term, {keys, strings}) when is_atom(term) and not is_nil(term),
    do: {keys, [to_string(term) | strings]}

  defp walk(_term, acc), do: acc
end
