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
      assert module.steer(%{}, %{prompt: "x"}, "req") == {:error, :unsupported}
      assert module.configure(%{}, %{}) == {:error, :unsupported}
    end
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
