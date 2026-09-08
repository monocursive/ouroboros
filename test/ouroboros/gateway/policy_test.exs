defmodule Ouroboros.Gateway.PolicyTest do
  # Not async: four of these verbs write to the node's one `Control.PolicyPromotion` process,
  # which is a singleton by design; `Audit.Identity` and `:policy_evidence_root` are application
  # environment this module installs and removes.
  use ExUnit.Case, async: false

  @moduledoc """
  The five `policy.*` verbs (docs/SELF.md §S2, S-D27–S-D29 and S2b's S-D20–S-D24).

  The claim that matters most is a negative one: **no part of the evidence corpus crosses this
  boundary.** The corpus holds the exact document a policy component would have been shown for
  every permission request a human answered on this node — command lines, paths and domains,
  redacted only as far as `PolicyEngine.document/1` redacts them — and what these verbs say
  about it is a bounded projection of `PolicyEvidence.count/0` and nothing else. So there is a
  test here that walks the whole reply looking for a document, and it is the one to keep.

  The rest, in the order the S2b adversarial review left them: the role a policy verb needs
  (MEDIUM-1), the demotion's attributed actor and its ledger principal (MEDIUM-2), the digest's
  honest name (MEDIUM-3), the bounded corpus projection (MEDIUM-4), `since` as a real instant
  (LOW-1), a bounded name and a bounded detail in a refusal (LOW-2, LOW-3), the per-`(tool,
  shape)` record the S2a redesign made this verb answer, the twelve named refusals one by one,
  and a real `no-network-shell` replayed over a seeded corpus through the handler itself.
  """

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Audit.Identity
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Request
  alias Ouroboros.Control.PolicyEvidence
  alias Ouroboros.Control.PolicyPromotion
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Contract
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.{Artifact, LiveFixture, PolicyEngine, Pool, Rollout, SandboxFixture}

  @moduletag :capture_log

  @verbs ~w(policy.status policy.replay policy.promote policy.demote policy.clear)
  @operators ~w(policy.replay policy.promote policy.demote policy.clear)

  # A name and bytes this node has certainly never deployed, so nothing here can be confused
  # with a live rollout.
  @name "gateway-policy-test"
  @sha String.duplicate("9", 64)
  @shape "mix test"

  # The subject `Gateway.Conn` installs for the local owner when no identities are configured.
  # Reaching `Methods.invoke/2` directly leaves no subject at all, which is what the
  # unattributed tests exercise.
  @owner %{"local" => true, "id" => "local-owner"}

  @component Path.expand(
               "../../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
               __DIR__
             )
  @signer "gateway-policy-test-key"
  @needs_live LiveFixture.tag(@component)

  @eval %{
    cases: [
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "curl https://example.test"}},
        expect: %{decision: :deny}
      },
      %{
        request: %{"tool" => "bash", "input" => %{"command" => "ls -la"}},
        expect: %{decision: :ask}
      }
    ],
    budget_ms: 20_000
  }

  setup_all do
    if LiveFixture.required?() do
      LiveFixture.ensure!()

      unless File.regular?(@component) do
        raise "OUROBOROS_REQUIRE_WASM is set and there is no #{@component}; `make wasm-examples`"
      end
    end

    :ok
  end

  setup do
    tmp = Path.join(System.tmp_dir!(), "ouro-gw-policy-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)

    saved =
      Map.new(
        [
          :audit,
          :policy_evidence_root,
          :permissions_engine,
          :upgrade_trust_policy,
          :wasm_policy,
          :wasm_policy_opts
        ],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    on_exit(fn ->
      PolicyPromotion.clear("gateway-policy-test-teardown")
      File.rm_rf(tmp)

      Enum.each(saved, fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)
    end)

    %{tmp: tmp}
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
      # The generated reference states the five numbers in prose. This is what keeps that prose
      # true when the engine's numbers move.
      assert PolicyEngine.promotion_thresholds() == Contract.policy_thresholds()
      assert Contract.policy_shape_bytes() == PolicyPromotion.max_shape_bytes()
    end
  end

  # ---------------------------------------------------------------------------
  # MEDIUM-1. The role a policy verb needs.
  # ---------------------------------------------------------------------------

  describe "the role these verbs need under required audit" do
    test "an operator who may not add a permission rule may not promote a policy either",
         context do
      Application.put_env(:ouroboros, :audit,
        mode: :required,
        root: Path.join(context.tmp, "audit"),
        identities: [
          %{
            "id" => "ana",
            "token_sha256" => String.duplicate("a", 64),
            "roles" => ["operator"]
          },
          %{
            "id" => "root",
            "token_sha256" => String.duplicate("b", 64),
            "roles" => ["administrator"]
          }
        ]
      )

      ana = %{"id" => "ana", "token_sha256" => String.duplicate("a", 64)}
      root = %{"id" => "root", "token_sha256" => String.duplicate("b", 64)}

      # The company `policy.*` keeps. Each of these widens what may run without a person, which
      # is why each of them is an administrator's.
      for method <- ~w(permissions.add grants.grant wasm.deploy credentials.set upgrade.apply) do
        refute Identity.permits?(ana, method, :operate),
               "#{method} unexpectedly admits a bare operator"
      end

      # And what S2b adds beside them. `policy.promote` hands a wasm component the authority to
      # answer `allow` for a shape of `bash` on every future request; the reviewer's F1 stood on
      # exactly this pair.
      for method <- ~w(policy.promote policy.clear policy.demote policy.replay) do
        refute Identity.permits?(ana, method, :operate),
               "#{method} still falls through to \"operator\""

        assert Identity.permits?(root, method, :operate)
      end

      # Reading the record is not widening anything, and an operator keeps it.
      assert Identity.permits?(ana, "policy.status", :read)
    end
  end

  describe "policy.status" do
    test "answers the record, its durability, the thresholds and the corpus's counts" do
      assert {:ok, status} = Methods.invoke("policy.status", %{})

      assert status.node == node()
      assert status.policy == nil
      assert status.tools == []
      assert status.demotions == []
      assert status.allowable == %{}
      assert status.allowable_tools == []
      assert status.durability in [:ephemeral_checkpoint, :synced_checkpoint, :durable_checkpoint]
      assert status.thresholds == PolicyEngine.promotion_thresholds()
      assert status.shadow_every == PolicyEngine.shadow_every()
    end

    test "the corpus's counts are read from the corpus rather than stated", context do
      # M18 survived the review because nothing ever compared these numbers to a corpus. Replace
      # `evidence_counts/0` with a constant and this goes red.
      seed_corpus!(context, [{"bash", "ls -la", "approve"}, {"read", nil, "deny"}])

      assert {:ok, status} = Methods.invoke("policy.status", %{})
      assert {:ok, counted} = PolicyEvidence.count()

      assert status.evidence.records == 2
      assert status.evidence.records == counted.records
      assert status.evidence.by_tool == %{"bash" => 1, "read" => 1}
      assert status.evidence.other_tools == 0
      assert status.evidence.other_records == 0
      assert status.evidence.error == nil
    end

    test "by_tool is the busiest 32 tools and says what it left out", context do
      # MEDIUM-4. The corpus is bounded at rows and bytes; the number of *distinct tool names*
      # those rows carry is bounded by nothing, and one key per name is a reply nobody can
      # render. The rest is counted rather than dropped silently.
      rows =
        for index <- 1..500 do
          {"mcp__server__tool_#{index}_" <> String.duplicate("x", 400), nil, "approve"}
        end

      seed_corpus!(context, rows)

      assert {:ok, status} = Methods.invoke("policy.status", %{})

      assert map_size(status.evidence.by_tool) == 32
      assert status.evidence.records == 500
      assert status.evidence.other_tools == 468
      assert status.evidence.other_records == 468

      # And a tool name is a string a request chose, so it is bounded like every other string
      # on this boundary.
      for {tool, _count} <- status.evidence.by_tool do
        assert byte_size(tool) <= 131, tool
      end

      bytes = status |> JSON.encode!() |> byte_size()
      assert bytes < 65_536, "policy.status answered #{bytes} bytes"
    end

    test "a corpus nobody can read is a different fact from an empty one", context do
      # `error` is a key rather than a missing one for the same reason `durability` is: a client
      # that cannot tell "no answers yet" from "the corpus is unreadable" will report the first
      # when it is looking at the second.
      File.mkdir_p!(Path.join(context.tmp, "evidence"))
      Application.put_env(:ouroboros, :policy_evidence_root, Path.join(context.tmp, "evidence"))

      assert {:ok, status} = Methods.invoke("policy.status", %{})
      assert status.evidence.records == 0
      assert status.evidence.error == nil
    end

    test "carries no document, no command and no path, however deep the record is" do
      promote!(@name, @sha, "bash", "mix test")
      promote!(@name, @sha, "bash", "mix format")
      demote!(@name, "bash", "mix format")

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

    test "a promoted row is one (tool, shape), built key by key rather than passed through" do
      # M5 and M5b survived the review because nothing pinned the projection: the record's entry
      # crossed the wire whole, and a field the record grew tomorrow would have gone with it.
      # These keys are the contract, and `report_sha256_as_submitted` is what makes a
      # pass-through fail — the record's own key is `report_sha256` (MEDIUM-3).
      promote!(@name, @sha, "bash", @shape)

      assert {:ok, status} = Methods.invoke("policy.status", %{})
      assert [row] = status.tools

      assert row |> Map.keys() |> Enum.sort() ==
               [:actor, :allowed, :evidence, :promoted_at, :seq, :shape, :tool]

      assert row.tool == "bash"
      assert row.shape == @shape
      assert row.allowed == true
      assert row.actor == "operator:test"

      assert row.evidence |> Map.keys() |> Enum.sort() == [
               :contradictions,
               :decisions,
               :distinct_fingerprints,
               :distinct_sessions,
               :replayed_at,
               :report_sha256_as_submitted,
               :would_resolve
             ]

      # The digest is a plain sha256 over the report's own contents with no key in it: it says
      # the file was not edited, and nothing about who produced the numbers. So the wire calls
      # it what it is, and the numbers beside it are the node's own re-run.
      assert row.evidence.report_sha256_as_submitted == String.duplicate("f", 64)
      refute Map.has_key?(row.evidence, :report_sha256)
      assert row.evidence.decisions == 60
      assert row.evidence.distinct_fingerprints == 22
    end

    test "renders a populated record: rows sorted, demotions newest first and bounded" do
      promote!(@name, @sha, "bash", "mix test")
      promote!(@name, @sha, "bash", "git status")

      # Twenty-five demotions so the bound is a bound rather than a description.
      for index <- 1..25 do
        shape = "tool-#{index}"
        promote!(@name, @sha, "bash", shape)
        demote!(@name, "bash", shape)
      end

      assert {:ok, status} = Methods.invoke("policy.status", %{})

      assert status.policy == %{name: @name, component_sha256: @sha}

      pairs = Enum.map(status.tools, &{&1.tool, &1.shape})
      assert pairs == Enum.sort(pairs)

      # Promoted and never demoted since — and a demoted shape is still a row, with `allowed`
      # saying which of the two facts is current.
      assert status.allowable == %{"bash" => ["git status", "mix test"]}
      assert status.allowable_tools == ["bash"]
      assert Enum.find(status.tools, &(&1.shape == "mix test")).allowed
      refute Enum.find(status.tools, &(&1.shape == "tool-25")).allowed

      assert length(status.demotions) == 20
      sequences = Enum.map(status.demotions, & &1.seq)
      assert sequences == Enum.sort(sequences, :desc)
      assert Enum.all?(status.demotions, &is_binary(&1.shape))
    end

    test "answers the same keys the golden fixture pins" do
      # `policy_status_result.json` is what a second implementation decodes. A field added here
      # and not there is a field the Rust client never learns about.
      assert {:ok, status} = Methods.invoke("policy.status", %{})

      fixture = golden("policy_status_result")

      assert status |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture |> Map.keys() |> Enum.sort()

      assert status.evidence |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture["evidence"] |> Map.keys() |> Enum.sort()
    end

    test "a promoted row's keys are the golden fixture's too" do
      promote!(@name, @sha, "bash", @shape)
      demote!(@name, "bash", @shape)

      assert {:ok, status} = Methods.invoke("policy.status", %{})
      fixture = golden("policy_promote_result")

      assert hd(status.tools) |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture["tools"] |> hd() |> Map.keys() |> Enum.sort()

      assert hd(status.tools).evidence |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture["tools"] |> hd() |> Map.fetch!("evidence") |> Map.keys() |> Enum.sort()

      assert hd(status.demotions) |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort() ==
               fixture["demotions"] |> hd() |> Map.keys() |> Enum.sort()
    end
  end

  describe "policy.replay" do
    test "requires a name, and refuses one this node does not run by name" do
      assert {:error, -32_602, message} = Methods.invoke("policy.replay", %{})
      assert message =~ "params.name is required"

      assert {:error, -32_602, blank} = Methods.invoke("policy.replay", %{"name" => ""})
      assert blank =~ "params.name must be a nonempty string"

      assert {:error, code, sentence, data} = Methods.invoke("policy.replay", %{"name" => @name})

      assert code == Methods.code(:not_found)
      assert data["reason"] == "no_live_policy"
      assert data["name"] == @name
      assert sentence =~ "no live lane-W policy"
    end

    test "since must be a real instant, because an unparseable one narrows nothing" do
      # LOW-1. `PolicyEvidence.stream/1` reads an instant it cannot parse as *no filter*, so a
      # typo replayed the whole corpus and the sealed report stated the typo in its `since`.
      assert {:error, -32_602, message} =
               Methods.invoke("policy.replay", %{"name" => @name, "since" => 17})

      assert message =~ "params.since must be a nonempty string when present"

      for typo <- ["2020-01-04", "yesterday", "2020-13-01T00:00:00Z", "🙈"] do
        assert {:error, -32_602, refusal} =
                 Methods.invoke("policy.replay", %{"name" => @name, "since" => typo})

        assert refusal =~ "ISO 8601", "#{typo} was accepted"
      end

      # A real one gets past the contract and is refused by the plane instead.
      assert {:error, code, _sentence, data} =
               Methods.invoke("policy.replay", %{
                 "name" => @name,
                 "since" => "2026-08-01T00:00:00Z"
               })

      assert code == Methods.code(:not_found)
      assert data["reason"] == "no_live_policy"
    end

    test "an oversized name comes back bounded rather than mirrored" do
      # LOW-2. `fetch_string/2` has no ceiling and `data.name` was `to_string/1`, so a
      # half-megabyte parameter came back verbatim in the refusal.
      name = String.duplicate("z", 500_000)

      assert {:error, _code, sentence, data} = Methods.invoke("policy.replay", %{"name" => name})

      assert data["reason"] == "no_live_policy"
      assert byte_size(data["name"]) <= 132
      assert String.ends_with?(data["name"], "…")
      assert byte_size(sentence) < 8_192
    end
  end

  describe "policy.promote" do
    test "takes name, tool, shape and a report object, and no actor" do
      assert {:ok, %{envelope: :closed, params: params}} = Methods.params("policy.promote")
      names = Enum.map(params, & &1.name)

      assert Enum.sort(names) == ["name", "report", "shape", "tool"]
      refute "actor" in names

      assert {:error, -32_602, message} =
               Methods.invoke("policy.promote", %{"name" => @name, "tool" => "bash"})

      assert message =~ "params.shape is required"

      assert {:error, -32_602, missing} =
               Methods.invoke("policy.promote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "shape" => @shape
               })

      assert missing =~ "params.report is required"

      assert {:error, -32_602, shape} =
               Methods.invoke("policy.promote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "shape" => @shape,
                 "report" => "a report"
               })

      assert shape =~ "params.report must be an object"

      assert {:error, -32_602, wide} =
               Methods.invoke("policy.promote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "shape" => String.duplicate("m", Contract.policy_shape_bytes() + 1),
                 "report" => %{}
               })

      assert wide =~ "between 1 and #{Contract.policy_shape_bytes()} bytes"
    end

    test "refuses a tool no shape language covers, before it looks at anything else" do
      assert {:error, code, sentence, data} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.promote", %{
                   "name" => @name,
                   "tool" => "read",
                   "shape" => @shape,
                   "report" => %{}
                 })
               end)

      assert code == Methods.code(:invalid_params)
      assert data["reason"] == "tool_not_promotable"
      assert data["tool"] == "read"
      assert sentence =~ "only `bash`"
    end

    test "refuses a policy this node does not run before it looks at the report" do
      assert {:error, code, _sentence, data} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.promote", %{
                   "name" => @name,
                   "tool" => "bash",
                   "shape" => @shape,
                   "report" => %{"component_sha256" => @sha}
                 })
               end)

      assert code == Methods.code(:not_found)
      assert data["reason"] == "no_live_policy"
    end

    test "refuses a caller with no resolvable identity rather than promoting as one" do
      # `Audit.Identity.actor/0` cannot fail: with nobody behind the socket it answers the
      # placeholder `runtime-unattributed`, which is a fine ledger principal for something the
      # runtime did to itself and is not a human. S2's rule is that a promotion has one.
      assert {:error, code, sentence, data} =
               Methods.invoke("policy.promote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "shape" => @shape,
                 "report" => %{}
               })

      assert code == Methods.code(:scope_denied)
      assert data["reason"] == "unattributed_actor"
      assert sentence =~ "no resolvable identity"

      # And it is checked before the plane is asked, so an unattributed caller learns nothing
      # about what this node runs.
      refute sentence =~ "no live lane-W policy"
    end
  end

  describe "policy.demote" do
    test "requires an attributed actor, because a narrowing an audit cannot name is not one" do
      # MEDIUM-2. The first version of this verb narrowed for anybody: "narrowing is always
      # safe". Narrowing is safe; a ledger that says the runtime withdrew a promotion a person
      # withdrew is not, and it is the trail an investigation reads.
      assert {:error, code, _sentence, data} =
               Methods.invoke("policy.demote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "shape" => @shape,
                 "reason" => "it asked to curl an internal host"
               })

      assert code == Methods.code(:scope_denied)
      assert data["reason"] == "unattributed_actor"
    end

    test "records the operator as the demotion's ledger principal" do
      # The reviewer's F6, inverted: the entry said `runtime` for a demotion `local-owner` made.
      promote!(@name, @sha, "bash", @shape)
      before = demote_entry_ids()

      assert {:ok, _record} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.demote", %{
                   "name" => @name,
                   "tool" => "bash",
                   "shape" => @shape,
                   "reason" => "ana withdrew it by hand"
                 })
               end)

      assert {:ok, entries} = EffectLedger.list(effect: :policy_promotion, limit: 50)

      entry =
        Enum.find(entries, fn entry ->
          action(entry) == :demote and entry.id not in before
        end)

      assert entry, "no :policy_promotion demote entry was written"
      assert entry.principal == "local-owner"
      refute entry.principal == "runtime"
      assert entry.attempt.shape == @shape

      # And the record itself says who, so `policy.status` can too.
      stored = PolicyPromotion.status()
      demotion = Enum.find(stored.demotions, &(&1.shape == @shape))
      assert demotion.actor == "local-owner"
    end

    test "narrows one shape and leaves the others standing" do
      promote!(@name, @sha, "bash", "mix")
      promote!(@name, @sha, "bash", "mix test")

      assert {:ok, record} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.demote", %{
                   "name" => @name,
                   "tool" => "bash",
                   "shape" => "mix test",
                   "reason" => "too wide after all"
                 })
               end)

      assert record.allowable == %{"bash" => ["mix"]}
      assert record.allowable_tools == ["bash"]
    end

    test "echoes the operator's sentence and stores an enumerated atom instead" do
      promote!(@name, @sha, "bash", @shape)
      sentence = "it allowed a curl a human denied on 2026-09-08"

      assert {:ok, record} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.demote", %{
                   "name" => @name,
                   "tool" => "bash",
                   "shape" => @shape,
                   "reason" => sentence
                 })
               end)

      assert record.reason == sentence
      assert record.allowable == %{}

      # The record itself never saw the sentence: a checkpoint fsynced on every write is not
      # where free text belongs, and a demotion's reason is a term this build enumerates.
      stored = PolicyPromotion.status()
      demotion = Enum.find(stored.demotions, &(&1.shape == @shape))
      assert demotion.reason == :operator_demotion
      refute Enum.any?(Map.values(demotion), &(&1 == sentence))
    end

    test "bounds the reason, because it is echoed into a reply frame" do
      limit = Contract.policy_reason_bytes()

      assert {:error, -32_602, message} =
               Methods.invoke("policy.demote", %{
                 "name" => @name,
                 "tool" => "bash",
                 "shape" => @shape,
                 "reason" => String.duplicate("x", limit + 1)
               })

      assert message =~ "between 1 and #{limit} bytes"

      assert {:ok, _record} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.demote", %{
                   "name" => @name,
                   "tool" => "bash",
                   "shape" => @shape,
                   "reason" => String.duplicate("x", limit)
                 })
               end)
    end

    test "a name this record does not hold narrows nothing and is not an error" do
      promote!(@name, @sha, "bash", @shape)

      assert {:ok, record} =
               Identity.with_subject(@owner, fn ->
                 Methods.invoke("policy.demote", %{
                   "name" => "some-other-policy",
                   "tool" => "bash",
                   "shape" => @shape,
                   "reason" => "wrong record"
                 })
               end)

      assert record.allowable == %{"bash" => [@shape]}
    end
  end

  describe "policy.clear" do
    test "refuses an unattributed caller, and empties the record for a named one" do
      promote!(@name, @sha, "bash", @shape)

      assert {:error, code, _sentence, data} = Methods.invoke("policy.clear", %{})
      assert code == Methods.code(:scope_denied)
      assert data["reason"] == "unattributed_actor"

      # Nothing was cleared by the refusal.
      assert PolicyPromotion.policy() == {@name, @sha}

      assert {:ok, record} =
               Identity.with_subject(@owner, fn -> Methods.invoke("policy.clear", %{}) end)

      assert record.policy == nil
      assert record.tools == []
      assert record.allowable == %{}
      assert record.allowable_tools == []
      assert PolicyPromotion.policy() == nil
    end
  end

  # ---------------------------------------------------------------------------
  # The named refusals, one by one. Eleven of the twelve were untested when the review ran;
  # most of them are reachable only by breaking a checkpoint or a ledger on purpose, so the
  # mapping is held here and the reachable ones are also driven through `invoke/2` above.
  # ---------------------------------------------------------------------------

  describe "the named refusals" do
    test "every clause answers a closed reason, a sentence and bounded data" do
      long = String.duplicate("q", 4_000)

      cases = [
        {{:no_live_policy, long}, :not_found, "no_live_policy"},
        {{:policy_not_verifiable, {:signature, long}}, :upstream_error, "policy_not_verifiable"},
        {{:report_names_other_bytes, long}, :invalid_params, "report_names_other_bytes"},
        {:report_unsealed, :invalid_params, "report_unsealed"},
        {:report_digest_mismatch, :invalid_params, "report_digest_mismatch"},
        {{:tool_not_promotable, long}, :invalid_params, "tool_not_promotable"},
        {{:no_decisions_for_tool, long}, :upstream_error, "no_decisions_for_tool"},
        {{:no_decisions_for_shape, "bash", long}, :upstream_error, "no_decisions_for_shape"},
        {{:policy_contradicted_a_human, "bash", 3}, :upstream_error, "policy_contradicted_a_human"},
        {{:policy_verdict_unreadable_on_shape, "bash", long, 2}, :upstream_error,
         "policy_verdict_unreadable_on_shape"},
        {{:not_enough_distinct_requests, "bash", long, 4, 20}, :upstream_error,
         "not_enough_distinct_requests"},
        {{:not_enough_sessions, "bash", long, 1, 2}, :upstream_error, "not_enough_sessions"},
        {{:promotion_would_resolve_nothing, "bash", long}, :upstream_error,
         "promotion_would_resolve_nothing"},
        {{:policy_promotion_bound_to, long, long}, :upstream_error, "policy_promotion_bound_to"},
        {{:policy_promotion_unrecordable, :ledger_is_gone}, :upstream_error,
         "policy_promotion_unrecordable"},
        {{:policy_promotion_checkpoint_failed, :enospc}, :upstream_error,
         "policy_promotion_checkpoint_failed"},
        {{:policy_dry_exception, long}, :upstream_error, "policy_dry_exception"},
        {{:policy_dry_refused, long}, :upstream_error, "policy_dry_refused"},
        {{:policy_replay_exception, long}, :upstream_error, "policy_replay_exception"},
        {:invalid_promotion, :invalid_params, "invalid_promotion"},
        {:invalid_replay, :invalid_params, "invalid_replay"}
      ]

      for {reason, code, named} <- cases do
        assert {:error, answered, sentence, data} = Methods.policy_refusal(reason)

        assert answered == Methods.code(code), "#{named} answered #{answered}"
        assert data["reason"] == named
        assert String.length(sentence) > 20

        # Nothing from another plane crosses unbounded, and nothing carries a path.
        for {_key, value} <- data, is_binary(value) do
          assert byte_size(value) <= 264, "#{named} answered #{byte_size(value)} bytes"
          refute String.contains?(value, "/"), "#{named} answered a path separator"
        end
      end
    end

    test "an unavailable record is the transport's own refusal rather than a named one" do
      assert {:error, code, sentence} =
               Methods.policy_refusal({:policy_promotion_unavailable, :noproc})

      assert code == Methods.code(:unavailable)
      assert sentence =~ "not running on this node"
    end

    test "a File.Error from the plane reaches data.detail with no path in it" do
      # LOW-3. `bounded_reason/1` in the engine is S2a's; this is the handler's half, and the
      # term that made the reviewer look is an exception whose message is a filename.
      planted = %File.Error{
        reason: :enoent,
        action: "read file",
        path: "/Users/somebody/.ouroboros/policy/evidence.ndjson"
      }

      assert {:error, _code, _sentence, data} =
               Methods.policy_refusal({:policy_not_verifiable, planted})

      assert byte_size(data["detail"]) <= 264
      refute String.contains?(data["detail"], "/")
      refute String.contains?(data["detail"], "evidence.ndjson/")
    end

    test "an unenumerated term is the same upstream_error every other verb answers with" do
      assert {:error, code, _sentence, _data} = Methods.policy_refusal({:something_new, 1})
      assert code == Methods.code(:upstream_error)
    end
  end

  # ---------------------------------------------------------------------------
  # A real policy, replayed over a real corpus, through the handler.
  # ---------------------------------------------------------------------------

  describe "policy.replay against a live no-network-shell" do
    @tag @needs_live
    test "answers a sealed report of counts, per tool and per shape, and never a request",
         context do
      %{sha: sha} = live_policy!(context)

      seed_corpus!(
        context,
        for(n <- 1..6, do: {"bash", "curl https://example.test/#{n}", "deny", "s#{rem(n, 2)}"}) ++
          for(n <- 1..4, do: {"bash", "ls -la /tmp/#{n}", "approve", "s#{rem(n, 2)}"})
      )

      assert {:ok, report} =
               Methods.invoke("policy.replay", %{"name" => "no-network-shell"})

      assert report["policy_name"] == "no-network-shell"
      assert report["component_sha256"] == sha
      assert report["corpus_size"] == 10
      assert report["unreadable"] == 0
      assert report["since"] == nil
      assert is_binary(report["report_sha256"])

      # The thresholds travel inside the report so an operator reading one file can see why a
      # shape is or is not promotable.
      assert report["thresholds"] == %{
               "contradictions" => 0,
               "unreadable" => 0,
               "distinct_fingerprints" => 20,
               "distinct_sessions" => 2,
               "would_resolve" => 1
             }

      bash = report["per_tool"]["bash"]
      assert bash["decisions"] == 10
      assert bash["agreements"] == 6
      assert bash["contradictions"] == 0
      assert bash["asks"] == 4

      curl = report["per_shape"]["bash"]["curl"]
      assert curl["decisions"] == 6
      assert curl["distinct_fingerprints"] == 6
      assert curl["distinct_sessions"] == 2
      assert curl["human_denies"] == 6
      assert curl["contradiction_rows"] == []

      # The negative claim, over the whole reply this time rather than over a fixture: not a
      # document, not a command line, not a path.
      {keys, strings} = walk(report)

      for forbidden <- ~w(document command input paths write_paths domains) do
        refute forbidden in keys, "policy.replay leaked a #{forbidden} key"
      end

      refute Enum.any?(strings, &String.contains?(&1, "curl https://"))
      refute Enum.any?(strings, &String.contains?(&1, "/tmp/"))
      refute Enum.any?(strings, &String.contains?(&1, "evidence.ndjson"))
    end

    @tag @needs_live
    test "since narrows the corpus the report is over", context do
      live_policy!(context)

      seed_corpus!(context, for(n <- 1..4, do: {"bash", "curl https://example.test/#{n}", "deny"}),
        at: fn n -> "2026-09-0#{n}T00:00:00.000000Z" end
      )

      assert {:ok, whole} = Methods.invoke("policy.replay", %{"name" => "no-network-shell"})
      assert whole["corpus_size"] == 4

      assert {:ok, narrowed} =
               Methods.invoke("policy.replay", %{
                 "name" => "no-network-shell",
                 "since" => "2026-09-03T00:00:00Z"
               })

      assert narrowed["corpus_size"] == 2
      assert narrowed["since"] == "2026-09-03T00:00:00Z"
      refute narrowed["report_sha256"] == whole["report_sha256"]
    end
  end

  # ---------------------------------------------------------------------------

  defp promote!(name, sha, tool, shape) do
    assert {:ok, _record} =
             PolicyPromotion.promote(
               name,
               sha,
               tool,
               shape,
               %{
                 report_sha256: String.duplicate("f", 64),
                 decisions: 60,
                 contradictions: 0,
                 distinct_fingerprints: 22,
                 distinct_sessions: 2,
                 would_resolve: 7
               },
               "operator:test"
             )
  end

  defp demote!(name, tool, shape),
    do: :ok = PolicyPromotion.demote(name, tool, shape, %{reason: :human_contradiction})

  defp golden(name) do
    Golden.path(name) |> File.read!() |> JSON.decode!() |> Map.fetch!("result")
  end

  defp action(entry) do
    case get_in(entry.attempt, [:action]) do
      nil -> get_in(entry.attempt, ["action"])
      action -> action
    end
  end

  defp demote_entry_ids do
    case EffectLedger.list(effect: :policy_promotion, limit: 200) do
      {:ok, entries} -> Enum.map(entries, & &1.id)
      _unavailable -> []
    end
  end

  # The corpus, written the way `Control.PolicyEvidence` writes it: the exact bytes
  # `PolicyEngine.document/1` produces for the request, and the digest `Control.Permissions`
  # computes. That write path is proved in `test/control/policy_evidence_test.exs`.
  defp seed_corpus!(context, rows, opts \\ []) do
    root = Path.join(context.tmp, "evidence")
    File.mkdir_p!(root)
    Application.put_env(:ouroboros, :policy_evidence_root, root)
    at = Keyword.get(opts, :at, fn _index -> "2026-09-08T00:00:00.000000Z" end)

    lines =
      rows
      |> Enum.with_index(1)
      |> Enum.map(fn {row, index} ->
        {tool, command, decision, session} =
          case row do
            {tool, command, decision} -> {tool, command, decision, "corpus-session"}
            {tool, command, decision, session} -> {tool, command, decision, session}
          end

        request =
          Request.new(%{
            principal: %{session_id: session, provider: :native, node: node()},
            tool: tool,
            command: command,
            mode: :execute,
            paths: [],
            domains: [],
            context: %{}
          })

        {:ok, encoded} = PolicyEngine.document(request)
        fingerprint = Permissions.fingerprint(request)

        JSON.encode!(%{
          "at" => at.(index),
          "node" => to_string(node()),
          "session_id" => session,
          "tool" => tool,
          "mode" => "execute",
          "fingerprint" => %{"sha256" => fingerprint.sha256, "bytes" => fingerprint.bytes},
          "decision" => decision,
          "scope" => "once",
          "permission_entry_id" => "seeded",
          "document" => encoded
        })
      end)

    File.write!(PolicyEvidence.path(), Enum.map_join(lines, "", &(&1 <> "\n")))
  end

  # `test/wasm/policy_promotion_test.exs`' fixture, narrowed to what this file needs: the real
  # component, signed by the real signing service and deployed through the real rollout, with
  # the engine's seams left in application environment so the *handler* — which passes no
  # options — reaches them exactly as it would in production.
  defp live_policy!(context) do
    key_path = Path.join(context.tmp, "signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    service =
      start_supervised!(
        {Service,
         [
           name: nil,
           key_path: key_path,
           signer_id: @signer,
           storage:
             {Jido.Storage.ETS,
              table: String.to_atom("gw_policy_journal_#{System.unique_integer([:positive])}")}
         ]},
        id: {Service, System.unique_integer([:positive])}
      )

    {:ok, %{public_key: public}} = Service.public_info(service)
    trust_policy = [allow_unsigned: false, trusted_signers: %{@signer => public}]
    Application.put_env(:ouroboros, :upgrade_trust_policy, trust_policy)

    registry = start_registry!()
    store_root = Path.join(context.tmp, "store")
    pool = live_pool!(context.tmp)

    bytes = File.read!(@component)
    {:ok, epoch} = Epoch.next([node()])

    {:ok, artifact} =
      Artifact.build(bytes,
        name: "no-network-shell",
        epoch: epoch,
        kind: :policy,
        imports: ["log"],
        author: "gateway-policy-test",
        eval: @eval
      )

    {:ok, value} =
      Service.sign_artifact(
        artifact,
        @signer,
        %{
          requester: node(),
          payload: Artifact.signing_payload(artifact, @signer),
          component_bytes: bytes
        },
        service
      )

    {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer, value: value})

    assert {:ok, outcome} =
             Rollout.deploy(signed, bytes, [node()],
               registry: registry,
               store_root: store_root,
               trust_policy: trust_policy,
               pool: pool
             )

    assert outcome.state == :live

    Application.put_env(:ouroboros, :permissions_engine, PolicyEngine)
    Application.put_env(:ouroboros, :wasm_policy, "no-network-shell")

    Application.put_env(:ouroboros, :wasm_policy_opts,
      registry: registry,
      store_root: store_root,
      pool: pool
    )

    %{sha: signed.component_sha256, pool: pool, registry: registry, store_root: store_root}
  end

  defp live_pool!(dir) do
    name = :"gw_policy_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start([name: name, handshake_timeout_ms: 15_000] ++ SandboxFixture.pool_opts(dir))

    on_exit(fn -> stop(pid) end)
    pid
  end

  defp start_registry! do
    name = String.to_atom("gw_policy_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("gw_policy_rollouts_#{System.unique_integer([:positive])}")}
      )

    on_exit(fn -> stop(pid) end)
    name
  end

  defp stop(pid) do
    if Process.alive?(pid) do
      try do
        GenServer.stop(pid, :normal, 5_000)
      catch
        :exit, _reason -> :ok
      end
    end
  end

  # Every key and every string in a term, at any depth. Cheap, and the only honest way to assert
  # that something is *not* in a reply.
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
