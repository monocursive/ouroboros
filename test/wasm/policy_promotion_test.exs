defmodule Ouroboros.Wasm.PolicyPromotionTest.DeadLedger do
  @moduledoc """
  A ledger that cannot record anything.

  Hoisted to top level deliberately: a `defmodule` nested inside a test module takes that
  module's prefix and shadows every alias whose last segment matches.
  """
  def record_settled(_attrs, _ledger), do: {:error, :ledger_is_gone}
  def record_denied(_attrs, _ledger), do: {:error, :ledger_is_gone}
end

defmodule Ouroboros.Wasm.PolicyPromotionTest do
  @moduledoc """
  Earned widening, end to end: the dry path, the replay, the promotion and the canary (S2).

  Two harnesses, because there are two different subjects.

  **The real `no-network-shell`**, signed by the real `Upgrade.Signing.Service` and deployed
  through the real `Wasm.Rollout` — `test/wasm/policy_acp_test.exs`' fixture, verbatim — settles
  what a dry evaluation *is*: a verdict from bytes this node verified, recorded nowhere, against
  an instance that is not the one deciding this node's live permissions. It also settles the
  replay's arithmetic against a component whose answers are a pure function of the request,
  which is what makes the order-independence and determinism claims worth anything.

  **A scripted helper**, `Ouroboros.Wasm.PolicyEngineTest`'s and for its reason, settles what
  happens to an `allow` — because `no-network-shell` never says one. It denies three fetchers
  and asks about everything else, deliberately (that is the shape the default configuration
  rewards), so the honouring half of a promotion and the whole of the demotion canary are
  unreachable with it. A scripted verdict is the only way to put "the component would have
  allowed what a human denied" in a test at all.
  """

  # Not async: `:permissions_engine`, `:wasm_policy`, `:wasm_policy_opts`,
  # `:policy_allowable_tools`, `:policy_evidence_root` and `:permissions` are application
  # environment, the promotion record is the node's own, and both harnesses spawn an OS child.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Request
  alias Ouroboros.Control.{PolicyEvidence, PolicyPromotion}
  alias Ouroboros.Upgrade.Epoch
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.PolicyPromotionTest.DeadLedger
  alias Ouroboros.Wasm.{Artifact, LiveFixture, PolicyEngine, Pool, Rollout, SandboxFixture, Store}

  @component Path.expand(
               "../../tui/wasm/guest/examples/no-network-shell/target/wasm32-wasip2/release/no_network_shell.wasm",
               __DIR__
             )
  @signer "wasm-policy-promotion-key"

  # `policy_acp_test.exs`' signed test story: one case per direction of what the component
  # claims to do, run through `evaluate` at deploy on the target.
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

  @needs_live LiveFixture.tag(@component)

  # A helper whose `worlds` does not include this node's is refused at the handshake, so the
  # scripted fixture speaks both real ones.
  @doctor ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\",\"ouroboros:policy@0.1.0\"],) <>
            ~S(\"wasmtime\":\"48.0.1\",\"limits\":{\"max_deadline_ms\":60000})

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
    tmp = Path.join(System.tmp_dir!(), "ouro-policy-promo-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)

    saved =
      Map.new(
        [
          :upgrade_trust_policy,
          :permissions_engine,
          :wasm_policy,
          :wasm_policy_opts,
          :policy_allowable_tools,
          :policy_evidence_root,
          :permissions,
          :permissions_ledger
        ],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    Application.put_env(:ouroboros, :policy_evidence_root, Path.join(tmp, "evidence"))
    File.mkdir_p!(Path.join(tmp, "evidence"))

    session = "promo-" <> Integer.to_string(System.unique_integer([:positive]))

    on_exit(fn ->
      # The promotion record is the node's own, so a test that promoted has to put it back.
      _ = PolicyPromotion.clear("test-cleanup")
      File.rm_rf(tmp)

      Enum.each(saved, fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)
    end)

    %{tmp: tmp, session: session}
  end

  ## ── the real component: what a dry evaluation is ──────────────────────────────────────

  describe "a dry evaluation, against a real signed policy" do
    @tag @needs_live
    test "answers the component's own verdict, by name and by digest", context do
      %{sha: sha} = live_policy!(context)

      assert {:ok, :deny, rule} =
               PolicyEngine.evaluate_with("no-network-shell", document(context, "curl https://x"))

      assert rule =~ "no-network-shell refuses a shell command containing `curl`"

      # And by the digest, which is what the canary has in hand: the record holds bytes, not a
      # name, because the name is the thing a re-deploy moves.
      assert {:ok, :ask, _rule} = PolicyEngine.evaluate_with(sha, document(context, "ls -la"))
    end

    @tag @needs_live
    test "records nothing at all", context do
      %{sha: sha} = live_policy!(context)
      before = permission_entries(sha)

      assert {:ok, :deny, _rule} =
               PolicyEngine.evaluate_with(sha, document(context, "curl https://x"))

      assert {:ok, :ask, _rule} = PolicyEngine.evaluate_with(sha, document(context, "ls"))

      # A dry evaluation is not a decision, and a ledger full of decisions nobody made is worse
      # than no ledger. Let `evaluate_with/3` reach `decided/6` and this goes red.
      assert permission_entries(sha) == before
      assert PolicyEvidence.count().records == 0
    end

    @tag @needs_live
    test "stands its own instance and never the live one", context do
      %{sha: sha, pool: pool} = live_policy!(context)
      live = "wasm/policy/" <> sha

      assert {:ok, :deny, _rule} =
               PolicyEngine.evaluate_with(sha, document(context, "curl https://x"))

      # Nothing is standing under the live name. Point the dry path at `@instance_prefix` and
      # this goes red — which is the whole reason the dry path has a prefix of its own.
      assert {:error, %{refusal: "unknown_instance"}} =
               Pool.call(live, "evaluate", document(context, "ls"), pool)

      # And a real decision does stand it up, so the assertion above is about the dry path
      # rather than about a pool that instantiates nothing.
      assert {:deny, _stated} = PolicyEngine.evaluate(request(context, "curl https://x"))

      assert {:ok, %{"payload" => _payload}} =
               Pool.call(live, "evaluate", document(context, "ls"), pool)
    end

    @tag @needs_live
    test "a name with no live policy rollout is a named refusal", context do
      live_policy!(context)

      assert {:error, {:no_live_policy, "not-deployed"}} =
               PolicyEngine.evaluate_with("not-deployed", document(context, "ls"))

      assert {:error, {:no_live_policy, _sha}} =
               PolicyEngine.evaluate_with(String.duplicate("f", 64), document(context, "ls"))
    end
  end

  ## ── the real component: the replay's arithmetic ───────────────────────────────────────

  describe "replaying a real policy over a corpus of human answers" do
    @tag @needs_live
    test "counts agreements, asks and contradictions the way the corpus implies", context do
      %{sha: sha} = live_policy!(context)

      # Forty commands the component denies that a human also denied, and twenty it has no
      # opinion about that a human approved. `no-network-shell` never says `allow`, so there is
      # nothing here for it to contradict — which is what makes it promotable and is exactly
      # what a corpus of this shape should say.
      seed_corpus!(context, denied(40) ++ approved(20))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      assert report["policy_name"] == "no-network-shell"
      assert report["component_sha256"] == sha
      assert report["corpus_size"] == 60
      assert report["unreadable"] == 0

      assert report["per_tool"]["bash"] == %{
               "decisions" => 60,
               "agreements" => 40,
               "contradictions" => 0,
               "would_resolve" => 0,
               "stricter" => 0,
               "asks" => 20,
               "unreadable" => 0,
               "contradiction_rows" => []
             }

      assert is_binary(report["report_sha256"])
      assert {:ok, _at, _offset} = DateTime.from_iso8601(report["replayed_at"])
    end

    @tag @needs_live
    test "the same corpus in a different order is the same report", context do
      live_policy!(context)
      rows = denied(30) ++ approved(20)

      seed_corpus!(context, rows)
      assert {:ok, first} = PolicyEngine.replay("no-network-shell")

      seed_corpus!(context, Enum.shuffle(rows))
      assert {:ok, shuffled} = PolicyEngine.replay("no-network-shell")

      # Counts, and the digest over them. Sort the contradiction rows out of `finish/1` and a
      # report over a reordered corpus stops being the same report.
      assert shuffled["per_tool"] == first["per_tool"]
      assert shuffled["report_sha256"] == first["report_sha256"]
    end

    @tag @needs_live
    test "two replays over one corpus produce one digest", context do
      live_policy!(context)
      seed_corpus!(context, denied(10) ++ approved(5))

      assert {:ok, first} = PolicyEngine.replay("no-network-shell")
      assert {:ok, second} = PolicyEngine.replay("no-network-shell")

      # `replayed_at` is deliberately outside the digest: it is the one field that differs
      # between two replays of the same corpus, and a digest that changed every time would say
      # nothing about whether the evidence was the same.
      assert second["report_sha256"] == first["report_sha256"]
      assert second["replayed_at"] != first["replayed_at"]
    end

    @tag @needs_live
    test "a torn line is counted and never attributed to a tool", context do
      live_policy!(context)
      seed_corpus!(context, denied(3))
      File.write!(PolicyEvidence.path(), "{not json\n", [:append])

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")
      assert report["corpus_size"] == 4
      assert report["unreadable"] == 1
      assert report["per_tool"]["bash"]["decisions"] == 3
    end
  end

  ## ── the real component: promotion ─────────────────────────────────────────────────────

  describe "promoting a real policy" do
    @tag @needs_live
    test "records the re-run's numbers and the report's digest", context do
      %{sha: sha} = live_policy!(context)
      seed_corpus!(context, denied(40) ++ approved(20))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      assert {:ok, _record} =
               PolicyEngine.promote("no-network-shell", "bash", report, "operator:ana")

      assert PolicyPromotion.policy() == {"no-network-shell", sha}
      assert PolicyPromotion.allowable_tools("no-network-shell") == ["bash"]

      status = PolicyPromotion.status()
      assert status.tools["bash"].actor == "operator:ana"
      assert status.tools["bash"].evidence.report_sha256 == report["report_sha256"]
      assert status.tools["bash"].evidence.decisions == 60
      assert status.tools["bash"].evidence.contradictions == 0
    end

    @tag @needs_live
    test "refuses a corpus that has not shown it enough", context do
      live_policy!(context)
      seed_corpus!(context, denied(20) ++ approved(9))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      assert {:error, {:not_enough_decisions, "bash", 29, 50}} =
               PolicyEngine.promote("no-network-shell", "bash", report, "operator:ana")

      assert PolicyPromotion.policy() == nil
    end

    @tag @needs_live
    test "refuses a tool the corpus says nothing about", context do
      live_policy!(context)
      seed_corpus!(context, denied(60))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      assert {:error, {:no_decisions_for_tool, "read"}} =
               PolicyEngine.promote("no-network-shell", "read", report, "operator:ana")
    end

    @tag @needs_live
    test "refuses a report about other bytes, and one somebody edited", context do
      live_policy!(context)
      seed_corpus!(context, denied(40) ++ approved(20))
      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      other = Map.put(report, "component_sha256", String.duplicate("c", 64))

      assert {:error, {:report_names_other_bytes, _sha}} =
               PolicyEngine.promote("no-network-shell", "bash", other, "operator:ana")

      # The gate that makes the file an operator carries around worth carrying: a report whose
      # numbers were edited no longer hashes to its own digest.
      edited = put_in(report, ["per_tool", "bash", "decisions"], 5_000)

      assert {:error, :report_digest_mismatch} =
               PolicyEngine.promote("no-network-shell", "bash", edited, "operator:ana")

      assert {:error, :report_unsealed} =
               PolicyEngine.promote(
                 "no-network-shell",
                 "bash",
                 Map.delete(report, "report_sha256"),
                 "operator:ana"
               )

      assert PolicyPromotion.policy() == nil
    end
  end

  ## ── the scripted helper: what happens to an `allow` ───────────────────────────────────

  describe "a promoted allow" do
    test "is honoured for the promoted tool and no other" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))

      assert {:ok, _record} = promote!("guard", env.sha, "bash")

      assert {:allow, stated} = PolicyEngine.evaluate(bash_request())
      assert stated =~ "[untrusted policy component]"
      assert stated =~ "fine"

      # Everything else is the posture it has always been: an `allow` for a tool nobody listed
      # and no replay earned is the question it was already going to be.
      assert {:ask, :no_rule} = PolicyEngine.evaluate(read_request())
    end

    test "is not honoured for a policy the record is not bound to" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 4))

      # The record names another component. Drop the name match in `honoured_allow_tools/2` and
      # one policy's earned reputation becomes every policy's.
      assert {:ok, _record} = promote!("somebody-else", env.sha, "bash")
      assert {:ask, :no_rule} = PolicyEngine.evaluate(bash_request())
    end

    test "is not honoured for bytes the record was not promoted for" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 4))

      # A re-deployed policy is different bytes and has earned nothing. Drop the sha match in
      # `honoured_allow_tools/2` and widening a policy becomes a one-time cost every later
      # version of it inherits.
      assert {:ok, _record} = promote!("guard", String.duplicate("e", 64), "bash")
      refute env.sha == String.duplicate("e", 64)
      assert {:ask, :no_rule} = PolicyEngine.evaluate(bash_request())
    end

    test "still needs the ledger, exactly as the configured list does" do
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 4))
      assert {:ok, _record} = promote!("guard", scripted_sha(), "bash")
      Application.put_env(:ouroboros, :permissions_ledger, DeadLedger)

      # An approval nobody can later account for has not been granted, however it was earned.
      assert {:ask, :unrecordable} = PolicyEngine.evaluate(bash_request())
    end
  end

  describe "the demotion canary" do
    test "a human deny the policy would have allowed demotes the tool inside record/2" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash")
      assert PolicyPromotion.allowable_tools("guard") == ["bash"]

      assert :ok =
               PolicyEngine.record("canary-1", %{
                 decision: :deny,
                 scope: :once,
                 actor: :human,
                 request: bash_request()
               })

      # One contradiction is enough: the threshold a promotion cleared was *zero* over fifty
      # decisions, so a single one is the evidence for that promotion being false.
      assert PolicyPromotion.allowable_tools("guard") == []
      assert [demotion] = PolicyPromotion.status().demotions
      assert demotion.reason == :human_contradiction
      assert demotion.tool == "bash"
      assert demotion.session_id == "canary-session"

      assert demotion.fingerprint ==
               Permissions.fingerprint(Request.new(bash_request())).sha256

      # And the answer that caused it is recorded exactly as it would have been.
      assert [row] = corpus_rows()
      assert row["decision"] == "deny"
      assert row["tool"] == "bash"
    end

    test "a rule's deny is not a human contradiction" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash")

      assert :ok =
               PolicyEngine.record("canary-2", %{
                 decision: :deny,
                 actor: :rule,
                 rule_ref: %{scope: :node, id: "n", pattern: "Bash(*)"},
                 request: bash_request()
               })

      # Widen the actor check in `canary/1` and a node's own rules start demoting the policy
      # that was promoted for the calls those rules never see.
      assert PolicyPromotion.allowable_tools("guard") == ["bash"]
    end

    test "a human approve is not a contradiction either" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash")

      assert :ok =
               PolicyEngine.record("canary-3", %{
                 decision: :approve,
                 actor: :human,
                 request: bash_request()
               })

      assert PolicyPromotion.allowable_tools("guard") == ["bash"]
    end

    test "a deny the policy would also have denied leaves the promotion standing" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("deny", "no")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash")

      assert :ok =
               PolicyEngine.record("canary-4", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request()
               })

      # The canary is about the component being *more permissive* than a human, which is the
      # only direction a promotion can be wrong in.
      assert PolicyPromotion.allowable_tools("guard") == ["bash"]
    end

    test "a deny for a tool nobody promoted costs nothing" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash")

      assert :ok =
               PolicyEngine.record("canary-5", %{
                 decision: :deny,
                 actor: :human,
                 request: read_request()
               })

      assert PolicyPromotion.allowable_tools("guard") == ["bash"]
    end
  end

  describe "promotion re-runs the replay rather than believing the report" do
    test "a contradiction the corpus grew after the report refuses the promotion" do
      # The mutation this test exists for: delete the `replay/2` call inside `promote/5` and
      # believe the report's own numbers, and a promotion is decided by a file an operator is
      # holding rather than by the corpus as it stands when they hand it in.
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 200))

      # Sixty human approvals the component would have resolved: a clean report, and exactly
      # the file `ouro policy replay` writes for an operator to carry to `promote`.
      seed_scripted_corpus!(60, "approve")
      assert {:ok, report} = PolicyEngine.replay("guard")
      assert report["per_tool"]["bash"]["decisions"] == 60
      assert report["per_tool"]["bash"]["contradictions"] == 0
      assert report["per_tool"]["bash"]["would_resolve"] == 60

      # Then the corpus grows by the one answer nobody looked at: a human denied a call this
      # component says `allow` to. The report is still valid — it is still about these bytes
      # and it still hashes to its own digest — and the promotion is still refused.
      append_scripted_corpus!(1, "deny")

      assert {:error, {:policy_contradicted_a_human, "bash", 1}} =
               PolicyEngine.promote("guard", "bash", report, "operator:ana")

      assert PolicyPromotion.policy() == nil

      # And the report a fresh replay writes now says so out loud, with the fingerprint and the
      # session of the answer that contradicted — never the command.
      assert {:ok, rerun} = PolicyEngine.replay("guard")
      assert rerun["per_tool"]["bash"]["contradictions"] == 1
      assert [row] = rerun["per_tool"]["bash"]["contradiction_rows"]
      assert String.match?(row["fingerprint"], ~r/\A[0-9a-f]{64}\z/)
      assert row["session_id"] == "scripted-session"
      refute Map.has_key?(row, "document")
    end
  end

  describe "a report is a function of the corpus and not of its order" do
    test "contradiction rows come out in one order however they went in" do
      # `no-network-shell` never says `allow`, so a corpus with contradictions in it needs a
      # scripted verdict. Reverse the corpus and the digest has to be the same digest: delete
      # the sort in `finish/1` and a report over the same evidence stops being the same report.
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 40))

      rows = for n <- 1..6//1, do: {"bash", "contradicted #{n}", "deny"}

      seed_corpus!(%{session: "order-session"}, rows)
      assert {:ok, forwards} = PolicyEngine.replay("guard")

      seed_corpus!(%{session: "order-session"}, Enum.reverse(rows))
      assert {:ok, backwards} = PolicyEngine.replay("guard")

      assert forwards["per_tool"]["bash"]["contradictions"] == 6
      assert length(forwards["per_tool"]["bash"]["contradiction_rows"]) == 6

      assert backwards["per_tool"]["bash"]["contradiction_rows"] ==
               forwards["per_tool"]["bash"]["contradiction_rows"]

      assert backwards["report_sha256"] == forwards["report_sha256"]
    end
  end

  describe "the engine's other two seams" do
    test "a policy this node cannot verify is not dry-evaluable" do
      # Unsigned, which is what a store somebody else wrote looks like. Drop the
      # `Verifier.verify_manifest/2` call from `dry_provenance/2` and unsigned bytes answer.
      env = scripted_policy([evaluate: [result(verdict("allow", "unsigned"))]], signed?: false)

      assert {:error, {:policy_not_verifiable, _reason}} =
               PolicyEngine.evaluate_with(env.sha, document_for("ls"))
    end

    test "a row naming bytes the signed manifest does not describe is not dry-evaluable" do
      env =
        scripted_policy([evaluate: [result(verdict("allow", "planted"))]], plant_other_sha: true)

      refute env.register_sha == env.sha

      assert {:error, {:policy_not_verifiable, _reason}} =
               PolicyEngine.evaluate_with("guard", document_for("ls"))
    end

    test "the configured name outranks the record's, and the record answers when there is none" do
      scripted_policy(evaluate: [result(verdict("ask", "x"))])
      assert PolicyEngine.configured_policy() == "guard"

      Application.delete_env(:ouroboros, :wasm_policy)
      assert PolicyEngine.configured_policy() == nil

      assert {:ok, _record} = promote!("guard", scripted_sha(), "bash")
      assert PolicyEngine.configured_policy() == "guard"

      Application.put_env(:ouroboros, :wasm_policy, "somebody-else")
      assert PolicyEngine.configured_policy() == "somebody-else"
    end

    test "allowable_tools/1 is the configured list plus what that name earned" do
      Application.put_env(:ouroboros, :policy_allowable_tools, ["read"])
      assert PolicyEngine.allowable_tools() == ["read"]
      assert PolicyEngine.allowable_tools("guard") == ["read"]

      assert {:ok, _record} = promote!("guard", String.duplicate("d", 64), "bash")
      assert Enum.sort(PolicyEngine.allowable_tools("guard")) == ["bash", "read"]

      # The operator's half is not name-scoped and the earned half is.
      assert PolicyEngine.allowable_tools("other") == ["read"]
      assert PolicyEngine.allowable_tools() == ["read"]
    end
  end

  ## ── the real component's fixture (policy_acp_test.exs') ───────────────────────────────

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
              table: String.to_atom("wasm_promo_journal_#{System.unique_integer([:positive])}")}
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
        author: "promotion-test",
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

    # `Pool.call/4` in the assertions below needs the pool by name, and nothing else here does.
    Process.put(:promotion_test_pool, pool)
    %{sha: signed.component_sha256, pool: pool, registry: registry, store_root: store_root}
  end

  defp live_pool!(dir) do
    name = :"wasm_policy_promo_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start([name: name, handshake_timeout_ms: 15_000] ++ SandboxFixture.pool_opts(dir))

    on_exit(fn -> stop(pid) end)
    pid
  end

  ## ── the scripted fixture (policy_engine_test.exs') ────────────────────────────────────

  defp scripted_policy(plans, opts \\ []) do
    dir =
      Path.join(System.tmp_dir!(), "ouro-promo-scripted-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    root = Path.join(dir, "store")
    File.mkdir_p!(root)

    bytes =
      "\0asm\x0d\x00\x01\x00 a policy component the scripted helper never parses " <>
        Integer.to_string(System.unique_integer([:positive]))

    {:ok, %{sha256: sha}} = Store.put(bytes, nil, root: root)

    {:ok, artifact} =
      Artifact.build(bytes,
        name: "guard",
        epoch: System.unique_integer([:positive, :monotonic]) + 1_000_000,
        kind: :policy,
        imports: ["log"],
        author: "promotion-test"
      )

    {:ok, signed} = signature(artifact, Keyword.get(opts, :signed?, true))
    {:ok, _manifest} = Store.put_manifest(signed, root: root)

    register_sha =
      if Keyword.get(opts, :plant_other_sha, false) do
        {:ok, %{sha256: planted}} = Store.put(bytes <> " and not these", nil, root: root)
        planted
      else
        sha
      end

    registry = start_registry!()

    {:ok, _entry} =
      Registry.deploying(
        %{
          artifact_id: artifact.id,
          module: "wasm/guard",
          epoch: artifact.epoch,
          nodes: [node()],
          component_sha256: register_sha,
          kind: :policy
        },
        registry
      )

    {:ok, _live} = Registry.mark(artifact.id, :live, [], registry)

    plan_files =
      Map.new([:evaluate, :instantiate, :load, :drop], fn method ->
        path = Path.join(dir, "plan-#{method}")
        File.write!(path, plan_lines(Keyword.get(plans, method, [])))
        {method, path}
      end)

    journal = Path.join(dir, "journal")
    File.write!(journal, "")
    pool = start_scripted_pool(write_helper(dir, journal, plan_files), dir)

    Application.put_env(:ouroboros, :permissions_engine, PolicyEngine)
    Application.put_env(:ouroboros, :wasm_policy, "guard")

    Application.put_env(:ouroboros, :wasm_policy_opts,
      registry: registry,
      store_root: root,
      pool: pool
    )

    Process.put(:promotion_test_scripted_sha, sha)

    %{sha: sha, register_sha: register_sha, journal: journal, pool: pool, plans: plan_files}
  end

  defp signature(artifact, false) do
    Application.put_env(:ouroboros, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{}
    )

    {:ok, artifact}
  end

  defp signature(artifact, true) do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, :crypto.strong_rand_bytes(32))

    Application.put_env(:ouroboros, :upgrade_trust_policy,
      allow_unsigned: false,
      trusted_signers: %{@signer => public}
    )

    value =
      :crypto.sign(:eddsa, :none, Artifact.signing_payload(artifact, @signer), [private, :ed25519])

    Artifact.with_signature(artifact, %{signer: @signer, value: value})
  end

  defp write_helper(dir, journal, files) do
    body = """
    #!/bin/sh
    exec awk '
    {
      print $0 >> "#{journal}"
      close("#{journal}")
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      method = $0
      sub(/.*"method":"/, "", method)
      sub(/".*/, "", method)
      file = ""
      if (method == "call") { file = "#{files.evaluate}" } else if (method == "instantiate") { file = "#{files.instantiate}" } else if (method == "load") { file = "#{files.load}" } else if (method == "drop") { file = "#{files.drop}" }
      plan = ""
      if (file != "") { if ((getline plan < file) <= 0) { plan = "" } }
      if (plan != "") {
        kind = substr(plan, 1, index(plan, " ") - 1)
        rest = substr(plan, index(plan, " ") + 1)
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"%s\\":%s}\\n", id, kind, rest)
      } else if (method == "doctor") {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{@doctor}}}\\n", id)
      } else {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"method\\":\\"%s\\"}}\\n", id, method)
      }
      fflush()
    }
    '
    """

    path = Path.join(dir, "ouro-wasm-helper.sh")
    File.write!(path, body)
    File.chmod!(path, 0o755)
    path
  end

  defp start_scripted_pool(helper_path, dir) do
    name = :"wasm_promo_scripted_pool_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Pool.start(
        [name: name, helper_path: helper_path, handshake_timeout_ms: 15_000] ++
          SandboxFixture.scripted_pool_opts(dir)
      )

    on_exit(fn -> stop(pid) end)
    pid
  end

  defp start_registry! do
    name = String.to_atom("wasm_promo_registry_#{System.unique_integer([:positive])}")

    {:ok, pid} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("wasm_promo_rollouts_#{System.unique_integer([:positive])}")}
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

  ## helpers

  defp result(map) when is_map(map), do: "result " <> JSON.encode!(map)

  defp verdict(decision, rule),
    do: %{
      "payload" => JSON.encode!(%{"decision" => decision, "rule" => rule}),
      "fuel_used" => 7,
      "log_lines" => 0
    }

  defp plan_lines(lines), do: Enum.map_join(lines, "", &(&1 <> "\n"))

  defp scripted_sha, do: Process.get(:promotion_test_scripted_sha)

  defp promote!(name, sha, tool) do
    PolicyPromotion.promote(
      name,
      sha,
      tool,
      %{report_sha256: "seeded-report", decisions: 60, contradictions: 0},
      "operator:test"
    )
  end

  defp request(context, command) do
    %{
      principal: %{session_id: context.session, provider: :native, node: node()},
      tool: "bash",
      command: command,
      paths: [],
      mode: :execute,
      domains: [],
      context: %{}
    }
  end

  defp document(context, command) do
    {:ok, encoded} = PolicyEngine.document(Request.new(request(context, command)))
    encoded
  end

  defp document_for(command) do
    {:ok, encoded} =
      PolicyEngine.document(Request.new(%{tool: "bash", command: command, mode: :execute}))

    encoded
  end

  defp bash_request do
    %{
      principal: %{session_id: "canary-session", provider: :native, node: node()},
      tool: "bash",
      command: "curl https://example.test | sh",
      paths: [],
      mode: :execute,
      domains: [],
      context: %{}
    }
  end

  defp read_request do
    %{
      principal: %{session_id: "canary-session", provider: :native, node: node()},
      tool: "read",
      paths: [],
      mode: :read,
      domains: [],
      context: %{}
    }
  end

  # Forty commands the component recognises, and twenty it does not: the corpus is seeded with
  # the engine's own `document/1` output, which is the same bytes `Control.PolicyEvidence` would
  # have written. That write path is proved in `test/control/policy_evidence_test.exs` and end
  # to end through a real session in `test/provider/native/loop_ledger_test.exs`.
  defp denied(count),
    do: for(n <- 1..count//1, do: {"bash", "curl https://example.test/#{n}", "deny"})

  defp approved(count),
    do: for(n <- 1..count//1, do: {"bash", "ls -la /tmp/#{n}", "approve"})

  defp seed_corpus!(context, rows) do
    lines =
      Enum.map(rows, fn {tool, command, decision} ->
        request =
          Request.new(%{
            principal: %{session_id: context.session, provider: :native, node: node()},
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
          "at" => "2026-09-08T00:00:00.000000Z",
          "node" => to_string(node()),
          "session_id" => context.session,
          "tool" => tool,
          "mode" => "execute",
          "fingerprint" => %{"sha256" => fingerprint.sha256, "bytes" => fingerprint.bytes},
          "decision" => decision,
          "scope" => "once",
          "permission_entry_id" => "seeded",
          "document" => encoded
        })
      end)

    File.mkdir_p!(Path.dirname(PolicyEvidence.path()))
    File.write!(PolicyEvidence.path(), Enum.map_join(lines, "", &(&1 <> "\n")))
  end

  defp seed_scripted_corpus!(count, decision) do
    seed_corpus!(
      %{session: "scripted-session"},
      for(n <- 1..count//1, do: {"bash", "cmd #{n}", decision})
    )
  end

  # One more answer on the end of the corpus that is already there, which is what a corpus
  # growing between a replay and a promotion looks like.
  defp append_scripted_corpus!(count, decision) do
    existing = File.read!(PolicyEvidence.path())

    seed_corpus!(
      %{session: "scripted-session"},
      for(n <- 1..count//1, do: {"bash", "later cmd #{n}", decision})
    )

    File.write!(PolicyEvidence.path(), existing <> File.read!(PolicyEvidence.path()))
  end

  defp corpus_rows do
    PolicyEvidence.stream()
    |> Enum.map(fn
      {:ok, row} -> row
      :unreadable -> nil
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp permission_entries(sha) do
    {:ok, entries} = EffectLedger.list(effect: :permission, limit: 500)
    Enum.filter(entries, &(&1.result[:rule_id] == "wasm/policy/" <> sha))
  end
end
