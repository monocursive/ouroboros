defmodule Ouroboros.Provider.Session.DialectTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Session
  alias Ouroboros.Provider.Session.Dialect

  test "the remaining ACP dialect implements the full callback set" do
    assert Session.dialects() == [Dialect.ACP]
    assert :ok = Dialect.verify!(Dialect.ACP)
    assert Dialect.ACP.capabilities().approvals == :native
    assert Dialect.ACP.capabilities().interrupt == :native
    assert Dialect.ACP.capabilities().steer == false
    assert Dialect.ACP.steer(%{}, %{prompt: "x"}, "req") == {:error, :unsupported}
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
