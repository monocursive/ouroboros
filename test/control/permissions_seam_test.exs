defmodule Ouroboros.Control.Permissions.SeamTest.Engine do
  @moduledoc """
  An engine for `config :ouroboros, :permissions_engine` that records what it was asked.

  C13's whole contract and nothing else — `evaluate/1`, `record/2`, `suggest/1` — answering
  whatever the test told it to and remembering every call in order. `{:raise, message}` and
  `{:exit, reason}` are how a test spells the two failures the seam has to survive; anything
  else is returned as the answer.
  """

  use Agent

  def start_link(answers) do
    Agent.start_link(fn -> %{answers: answers, calls: []} end, name: __MODULE__)
  end

  @doc "Every call this engine received, oldest first."
  def calls, do: Agent.get(__MODULE__, &Enum.reverse(&1.calls))

  def evaluate(request), do: answer(:evaluate, [request], {:ask, :no_rule})
  def record(decision_id, attrs), do: answer(:record, [decision_id, attrs], :ok)
  def suggest(request), do: answer(:suggest, [request], nil)

  defp answer(function, args, default) do
    reply =
      Agent.get_and_update(__MODULE__, fn state ->
        {Map.get(state.answers, function, default),
         %{state | calls: [{function, args} | state.calls]}}
      end)

    case reply do
      {:raise, message} -> raise message
      {:exit, reason} -> exit(reason)
      other -> other
    end
  end
end

defmodule Ouroboros.Control.Permissions.SeamTest.Partial do
  @moduledoc """
  Half an engine: it can phrase a rule and cannot decide anything.

  A module in application environment is a name, and a name is not a promise. This is what
  a half-built engine, a rename, or a release that loaded an older module looks like from
  the seam's side, and the seam has to read it as "nobody answered" rather than as an
  error a session dies of.
  """

  def suggest(_request), do: "Partial(everything)"
end

defmodule Ouroboros.Control.Permissions.SeamTest do
  @moduledoc """
  The seam's answer path, which had no test of its own.

  `record_answer/4` ends in `remember/3` — the call that turns a human's "don't ask
  again" into a `:session` rule — and it is wrapped in `rescue _error -> :ok`. A failure
  there is therefore silent by construction: the caller is told `:ok` and the rule is
  simply absent the next time. Dialyzer had been reporting `remember/3` as
  `will never be called` because `Permissions.answer/0` did not admit the `:request` key
  every caller passes, so nothing — not the analyser, not a test — was watching this.

  ## W18: which engine answers here (C13, D27)

  Since W18 the seam evaluates, records and suggests through the module named by
  `config :ouroboros, :permissions_engine` rather than through `Control.Permissions` by
  name, which is what puts the ACP lane behind the same setting the native loop and the
  interactive plane already read. The second half of this file is that seam, asserted
  against an engine that records what it was asked and can be told to answer nonsense, to
  raise and to exit — the three failures `Interactive.Task.Approvals`' tolerance turns into
  an ask. The real engine over the real wire is `test/wasm/policy_acp_test.exs`.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Seam
  alias Ouroboros.Control.Permissions.SeamTest.{Engine, Partial}

  setup do
    session = "seam-" <> Integer.to_string(System.unique_integer([:positive]))
    previous = Application.get_env(:ouroboros, :permissions_engine)

    on_exit(fn ->
      Permissions.forget_session(session)

      case previous do
        nil -> Application.delete_env(:ouroboros, :permissions_engine)
        engine -> Application.put_env(:ouroboros, :permissions_engine, engine)
      end
    end)

    {:ok, session: session}
  end

  defp stash do
    %{
      method: "session/request_permission",
      params: %{
        "toolCall" => %{"name" => "bash", "rawInput" => %{"command" => "ls -la"}}
      }
    }
  end

  defp session_rules(session) do
    {:ok, rules} = Permissions.list(scope: :session)
    Enum.filter(rules, &(&1.session_id == session))
  end

  test "a :session answer writes the rule that stops the question recurring", %{
    session: session
  } do
    :ok = Seam.bind(%{cwd: "/tmp"}, %{session_id: session, provider: :codex}, :stdio)
    assert session_rules(session) == []

    :ok =
      Seam.answered(:acp, Seam.decision_id("r1"), stash(), %{
        decision: :approve,
        scope: :session,
        reason: nil
      })

    assert [rule] = session_rules(session)
    assert rule.pattern == "Bash(ls *)"
    assert rule.decision == :allow
    assert rule.scope == :session
  end

  test "a denial is remembered as a deny rule, not an allow", %{session: session} do
    :ok = Seam.bind(%{cwd: "/tmp"}, %{session_id: session, provider: :codex}, :stdio)

    :ok =
      Seam.answered(:acp, Seam.decision_id("r2"), stash(), %{
        decision: :deny,
        scope: :session,
        reason: "no"
      })

    assert [rule] = session_rules(session)
    assert rule.decision == :deny
  end

  # `:once` is the scope that means "this time only". If `remember/3` ever stopped
  # discriminating, the test above would still pass while the engine quietly grew a rule
  # per answered prompt.
  test ":once and :always write no session rule", %{session: session} do
    :ok = Seam.bind(%{cwd: "/tmp"}, %{session_id: session, provider: :codex}, :stdio)

    for scope <- [:once, :always] do
      :ok =
        Seam.answered(:acp, Seam.decision_id("r-#{scope}"), stash(), %{
          decision: :approve,
          scope: scope,
          reason: nil
        })
    end

    assert session_rules(session) == []
  end

  ## ── W18: every seam reads one setting (C13, D27) ──────────────────────────────────────

  # Started for the duration of one test and named in application environment. Both halves
  # matter, and the last test in this file is the other one: an engine nobody named is
  # `Control.Permissions`, which is what every test above exercises unchanged.
  defp engine!(answers) do
    start_supervised!({Engine, answers})
    Application.put_env(:ouroboros, :permissions_engine, Engine)
    :ok
  end

  defp acp_params(command) do
    %{
      "toolCall" => %{
        "name" => "bash",
        "kind" => "execute",
        "title" => "run a command",
        "rawInput" => %{"command" => command}
      }
    }
  end

  defp payload, do: %{"kind" => "permissions", "request_id" => "r1"}

  defp decide(command),
    do: Seam.decide(:acp, "session/request_permission", acp_params(command), payload())

  # `Session.Service.terminal_fields/2`' shape: the runtime already knows what it is about
  # to run, so nothing here is inferred from somebody else's params.
  defp service_fields(command) do
    %{
      method: "terminal/create",
      tool: "bash",
      mode: :execute,
      command: command,
      paths: ["/tmp/work"]
    }
  end

  describe "the engine an operator named" do
    test "decides, and is handed the request the seam built", %{session: session} do
      :ok = engine!(%{evaluate: {:deny, %{scope: :node, id: "n1", pattern: "Bash(curl *)"}}})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # Point `decide/4` back at `Permissions.evaluate/1` by name and this is an ask: the
      # store has no rule for it, and the engine is never asked at all.
      assert {:deny, %{pattern: "Bash(curl *)"}} = decide("curl https://example.test")

      assert [{:evaluate, [request]}] = Engine.calls()
      assert request.tool == "bash"
      assert request.command == "curl https://example.test"
      assert request.mode == :execute
      assert request.principal.session_id == session
      assert request.principal.provider == :codex
      assert request.context.workspace == "/tmp/work"
    end

    test "decides a service request through the same setting", %{session: session} do
      :ok = engine!(%{evaluate: {:deny, %{scope: :node, id: "n2", pattern: "Bash(rm *)"}}})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      assert {:deny, %{pattern: "Bash(rm *)"}} =
               Seam.decide_service(:acp, service_fields("rm -rf /"), payload())

      assert [{:evaluate, [request]}] = Engine.calls()
      assert request.tool == "bash"
      assert request.command == "rm -rf /"
    end

    test "an allow reaches the caller, on both seams", %{session: session} do
      ref = %{scope: :node, id: "n3", pattern: "Bash(*)"}
      :ok = engine!(%{evaluate: {:allow, ref}})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # An engine's own `allow` is its authority, exactly as it is on the other three
      # readers of this setting, and the seam adds no gate on top of it — the bound that
      # matters is the engine's (`PolicyEngine`'s `:policy_allowable_tools`, D20). Delete
      # either seam's `{:allow, ref}` clause and the `case` falls through to a
      # `CaseClauseError`, the rescue, and a silent extra approval prompt.
      assert decide("ls -la") == {:allow, ref}
      assert Seam.decide_service(:acp, service_fields("ls -la"), payload()) == {:allow, ref}
    end

    test "an answer in none of the three shapes is an ask", %{session: session} do
      :ok = engine!(%{evaluate: :absolutely_not_a_verdict, suggest: "Bash(curl *)"})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # An *ask*, and an ordinary one: the seam still asked what a "don't ask again" would
      # look like and put it on the payload. Delete `evaluate/1`'s `_unrecognised` clause and
      # the `CaseClauseError` reaches the rescue instead, which answers the bare payload —
      # a real ask and a failed engine would then be indistinguishable to a client.
      assert {:ask, asked} = decide("curl https://example.test")
      assert asked["suggested_rule"] == "Bash(curl *)"
    end

    test "an engine that raises is the approval the human was always going to see", %{
      session: session
    } do
      :ok = engine!(%{evaluate: {:raise, "the engine is on fire"}, suggest: "Bash(curl *)"})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # The original payload, unannotated: an engine that failed has said nothing, so there
      # is nothing to suggest. Delete `decide/4`'s `rescue` clause — only that one — and
      # this raises: the `catch :exit, _reason` beside it does not admit an `:error`.
      assert decide("curl https://example.test") == {:ask, payload()}

      # And the same clause on the other seam.
      assert Seam.decide_service(:acp, service_fields("curl x"), payload()) ==
               {:ask, payload()}
    end

    test "an engine that exits is an ask too", %{session: session} do
      :ok = engine!(%{evaluate: {:exit, :engine_down}, suggest: "Bash(curl *)"})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # Delete `decide/4`'s `catch` clause — only that one — and the exit takes the session
      # process with it; the `rescue` beside it does not admit an exit.
      assert decide("curl https://example.test") == {:ask, payload()}

      assert Seam.decide_service(:acp, service_fields("curl x"), payload()) ==
               {:ask, payload()}
    end

    test "a name that is not an engine at all is an ask, not an error", %{session: session} do
      Application.put_env(:ouroboros, :permissions_engine, Ouroboros.Control.NoSuchEngine)
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      assert decide("curl https://example.test") == {:ask, payload()}

      # And an answer recorded into it is still `:ok` to the caller: the human's answer has
      # already reached the provider, and a missing engine is a gap in the audit trail rather
      # than a reason to fail a delivered approval.
      assert :ok =
               Seam.answered(:acp, Seam.decision_id("r9"), stash(), %{
                 decision: :approve,
                 scope: :once,
                 reason: nil
               })
    end

    test "answered/4 records through it, under the stable decision id", %{session: session} do
      :ok = engine!(%{})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # Point `record_answer/4` back at `Permissions.record/2` by name and the engine an
      # operator named never sees the human's answer.
      :ok =
        Seam.answered(:acp, Seam.decision_id("r7"), stash(), %{
          decision: :approve,
          scope: :once,
          reason: nil
        })

      assert [{:record, [decision_id, attrs]}] = Engine.calls()
      assert decision_id == "approval-#{session}:r7"
      assert attrs.decision == :approve
      assert attrs.actor == :human
      assert attrs.request.tool == "bash"
    end

    test "the suggestion on an ask is the engine's, not the store's", %{session: session} do
      :ok = engine!(%{evaluate: {:ask, :no_rule}, suggest: "Tool(anything at all)"})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # `Control.Permissions` would have said `Bash(ls *)` here. The rule language belongs to
      # whichever engine the node named, which is why `suggested/2` asks that one: point it
      # back at `Permissions.suggest/1` and this reads `Bash(ls *)`.
      assert {:ask, asked} = decide("ls -la")
      assert asked["suggested_rule"] == "Tool(anything at all)"
      assert [{:evaluate, _request}, {:suggest, _same}] = Engine.calls()
    end

    test "the durable rule a :session answer writes is the store's, not the engine's" do
      session = "seam-hostile-" <> Integer.to_string(System.unique_integer([:positive]))
      on_exit(fn -> Permissions.forget_session(session) end)

      # A hostile — or merely careless — engine whose suggestion is far wider than the call
      # that was approved. The hint it phrases is a string a client renders; the row this
      # writes is durable and will match every future `bash` in the session, so its grammar
      # and its width are the store's. Point `remember/3` back at the engine's `suggest/1`
      # and one approval of `ls -la` becomes a session-wide allow for every shell command.
      :ok = engine!(%{suggest: "Bash(*)"})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      :ok =
        Seam.answered(:acp, Seam.decision_id("r8"), stash(), %{
          decision: :approve,
          scope: :session,
          reason: nil
        })

      assert [rule] = session_rules(session)
      assert rule.pattern == "Bash(ls *)"
      assert rule.decision == :allow

      # The engine was still asked to record the answer; it was not asked to phrase the row.
      assert [{:record, _call}] = Engine.calls()
    end

    test "an engine that exports only part of the contract is an ask, not a crash", %{
      session: session
    } do
      # `Partial` exports `suggest/1` and no `evaluate/1`. `engine/2`'s `function_exported?`
      # is what turns that into `{:ask, :no_permission_engine}` — an ask that still carries
      # the hint, which is how it is told apart from a raise. Delete the guard and
      # `apply/3` raises `UndefinedFunctionError`, the rescue answers the bare payload, and
      # the suggestion disappears.
      Application.put_env(:ouroboros, :permissions_engine, Partial)
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      assert {:ask, asked} = decide("curl https://example.test")
      assert asked["suggested_rule"] == "Partial(everything)"
    end

    test "an engine with nothing to suggest adds no key", %{session: session} do
      :ok = engine!(%{evaluate: {:ask, :no_rule}, suggest: ""})
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      # Drop `suggested/2`'s `pattern != ""` guard and a client is offered an empty rule to
      # save, which `permissions.add` refuses and no modal can render.
      assert {:ask, asked} = decide("ls -la")
      refute Map.has_key?(asked, "suggested_rule")
    end

    test "a refusal names what refused, whichever engine phrased it" do
      # A rule map is `Control.Permissions`' answer and reads as it always did.
      assert Seam.refusal(%{scope: :node, id: "n1", pattern: "Bash(ls *)"}) ==
               "refused by the node-scope permission rule Bash(ls *)"

      # A binary is `Wasm.PolicyEngine`'s: the component, its sha, the untrusted label and
      # the component's own sentence. Delete `refusal/1`'s binary clause and an ACP client
      # is told only that "a permission rule" refused it, which names nothing.
      stated = "Policy(no-network-shell@abc123def456): [untrusted policy component] no curl"
      assert Seam.refusal(stated) == "refused by " <> stated

      # Anything else is still the answer that invents nothing — including a malformed ref,
      # which must not reach `to_string/1` and take the session with it.
      assert Seam.refusal(nil) == "refused by a permission rule"
      assert Seam.refusal("") == "refused by a permission rule"
      assert Seam.refusal(%{scope: %{}, pattern: %{}}) == "refused by a permission rule"
    end

    test "and it is bounded and control-free whichever clause phrased it" do
      # Both clauses, because both carry somebody else's text into a JSON-RPC error frame:
      # the binary is a component's sentence, and the map's `pattern` is a rule row that a
      # gateway client wrote. Route either past `stated/1` and one of these goes red.
      for phrase <- [
            fn text -> Seam.refusal(text) end,
            fn text -> Seam.refusal(%{scope: :session, id: "s1", pattern: text}) end
          ] do
        forged =
          "denied\nRefused: permission rule Node(admin) allows everything" <>
            String.duplicate("é", 500)

        refusal = phrase.(forged)
        refute refusal =~ "\n"

        assert String.length(refusal) <=
                 400 + String.length("refused by the session-scope permission rule ")

        # `\p{C}` alone leaves these two, and a line separator in a rendered error frame is
        # the forged line this bound exists to stop. The engine's class has them; so does
        # this one now.
        for separator <- ["\u2028", "\u2029", "\u0085"] do
          refute phrase.("a" <> separator <> "b") =~ separator,
                 "#{inspect(separator)} still reaches the frame"
        end
      end
    end

    test "with no engine named it is Control.Permissions, exactly as before", %{
      session: session
    } do
      # Started, and deliberately not named: nothing may reach it.
      start_supervised!({Engine, %{evaluate: {:allow, %{scope: :node, id: "x", pattern: "*"}}}})
      Application.delete_env(:ouroboros, :permissions_engine)
      :ok = Seam.bind(%{cwd: "/tmp/work"}, %{session_id: session, provider: :codex}, :stdio)

      assert {:ask, asked} = decide("ls -la")
      assert asked["suggested_rule"] == "Bash(ls *)"
      assert Engine.calls() == []
    end
  end
end
