defmodule Ouroboros.Control.Permissions.SeamTest do
  @moduledoc """
  The seam's answer path, which had no test of its own.

  `record_answer/4` ends in `remember/3` — the call that turns a human's "don't ask
  again" into a `:session` rule — and it is wrapped in `rescue _error -> :ok`. A failure
  there is therefore silent by construction: the caller is told `:ok` and the rule is
  simply absent the next time. Dialyzer had been reporting `remember/3` as
  `will never be called` because `Permissions.answer/0` did not admit the `:request` key
  every caller passes, so nothing — not the analyser, not a test — was watching this.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.Seam

  setup do
    session = "seam-" <> Integer.to_string(System.unique_integer([:positive]))
    on_exit(fn -> Permissions.forget_session(session) end)
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
end
