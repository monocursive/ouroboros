defmodule Ouroboros.Provider.Session.DialectTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Session
  alias Ouroboros.Provider.Session.Dialect

  test "every shipped dialect implements the full callback set" do
    dialects = Session.dialects()
    assert Dialect.Codex in dialects
    assert Dialect.ACP in dialects

    for module <- Session.dialects() do
      assert :ok = Dialect.verify!(module)
      caps = module.capabilities()
      assert caps.approvals == :native
      assert caps.interrupt == :native
    end

    # Steering is the one interaction the two dialects no longer answer alike, so each
    # one's refusal is asserted by name rather than through a shared loop. ACP has no
    # steer verb at all and says so; the app server has `turn/steer` but its
    # `expectedTurnId` is a precondition, so a runtime with no open thread is refused
    # here rather than on the wire.
    assert Dialect.ACP.capabilities().steer == false
    assert Dialect.ACP.steer(%{}, %{prompt: "x"}, "req") == {:error, :unsupported}

    assert Dialect.Codex.capabilities().steer == :native
    assert Dialect.Codex.steer(%{}, %{prompt: "x"}, "req") == {:error, :session_not_open}

    assert Dialect.Codex.steer(
             %{provider_session_id: "thread-1", provider_turn_id: nil},
             %{prompt: "x"},
             "req"
           ) == {:error, :no_active_turn}

    # `configure` is where the two dialects genuinely differ, so the completeness test
    # asserts each one's own answer rather than a shared refusal. The app server rebuilds
    # model, effort, approval policy and sandbox on every `turn/start`, so a change is
    # accepted and lands next turn. ACP's only configuration verb takes an agent-invented
    # mode id that Ouroboros's normalized vocabulary does not map onto, so it refuses.
    assert Dialect.Codex.configure(%{}, %{approval_mode: :auto_approve}) == :ok
    assert Dialect.Codex.configure(%{}, %{}) == :ok

    assert Dialect.Codex.configure(%{}, %{system_prompt: "x"}) ==
             {:error, {:unsupported_configuration, :system_prompt}}

    assert Dialect.ACP.configure(%{}, %{approval_mode: :auto_approve}) == {:error, :unsupported}
  end

  test "a dialect that omits a callback is refused by name" do
    defmodule Incomplete do
    end

    assert_raise ArgumentError, ~r/missing/, fn ->
      Dialect.verify!(Incomplete)
    end
  end

  test "kimi and opencode interactive sessions use the shared ACP adapter" do
    {:ok, kimi} = Jido.Harness.Registry.spec(:kimi)
    {:ok, opencode} = Jido.Harness.Registry.spec(:opencode)

    assert hd(kimi.session_transports).adapter == Session.ACP
    assert hd(opencode.session_transports).adapter == Session.ACP
    assert hd(kimi.session_transports).capabilities.approvals == :native
    assert hd(opencode.session_transports).capabilities.approvals == :native
  end
end
