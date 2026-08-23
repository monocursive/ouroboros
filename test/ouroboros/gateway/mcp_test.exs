defmodule Ouroboros.Gateway.McpTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Provider.Native.Mcp.Pool

  @moduletag :capture_log

  @script Path.expand("../../support/fake_mcp_server.exs", __DIR__)

  setup do
    root = Path.join(System.tmp_dir!(), "gateway-mcp-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)
    user_path = Path.join(root, "user-mcp.json")

    previous_servers = Application.get_env(:ouroboros, :mcp_servers)
    previous_user = Application.get_env(:ouroboros, :mcp_user_path)

    Application.put_env(:ouroboros, :mcp_user_path, user_path)
    Application.put_env(:ouroboros, :mcp_servers, %{})

    on_exit(fn ->
      Pool.stop_workspace(Pool, workspace)
      restore(:mcp_servers, previous_servers)
      restore(:mcp_user_path, previous_user)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, user_path: user_path}
  end

  test "mcp.list is in the table, at read scope, because it starts nothing" do
    assert "mcp.list" in Methods.names()
    assert {:ok, %{scope: :read}} = Methods.fetch("mcp.list")
  end

  test "there is no verb for adding a server over the wire" do
    refute Enum.any?(Methods.names(), &String.starts_with?(&1, "mcp.add"))
    refute Enum.any?(Methods.names(), &(&1 == "mcp.remove"))
  end

  test "mcp.list describes this node without a workspace and without starting anything" do
    assert {:ok, status} = Methods.invoke("mcp.list", %{})

    assert status.node == node()
    assert status.enabled == true
    assert status.supervised == true
    assert status.protocol_version == "2026-07-28"
    assert status.transports == [:stdio]
    assert is_list(status.servers)
    assert is_list(status.refusals)
  end

  test "a workspace adds the servers this node has configured but not started", context do
    Application.put_env(:ouroboros, :mcp_servers, %{
      "fake" => %{command: "/bin/false", args: []}
    })

    assert {:ok, status} = Methods.invoke("mcp.list", %{"workspace" => context.workspace})

    assert [server] =
             Enum.filter(
               status.servers,
               &(&1.name == "fake" and &1.workspace == context.workspace)
             )

    assert server.state == :configured
    assert server.workspace == context.workspace
    assert server.tools == 0
    assert server.transport == :stdio
  end

  test "a running server is reported with its state and tool names", context do
    Application.put_env(:ouroboros, :mcp_servers, %{
      "fake" => %{command: elixir(), args: [@script, "--tools", "echo,add"]}
    })

    assert Enum.map(
             Ouroboros.Provider.Native.Mcp.specs(context.workspace),
             & &1.name
           ) == ["mcp__fake__echo", "mcp__fake__add"]

    assert {:ok, status} = Methods.invoke("mcp.list", %{"workspace" => context.workspace})

    assert [server] =
             Enum.filter(
               status.servers,
               &(&1.name == "fake" and &1.workspace == context.workspace)
             )

    assert server.state == :ready
    assert server.tools == 2
    assert server.tool_names == ["mcp__fake__echo", "mcp__fake__add"]
    assert server.claims == 0
  end

  test "an environment value never reaches the wire, only its count", context do
    Application.put_env(:ouroboros, :mcp_servers, %{
      "fake" => %{command: "/bin/false", env: %{"TOKEN" => "s3cret"}}
    })

    assert {:ok, status} = Methods.invoke("mcp.list", %{"workspace" => context.workspace})

    refute inspect(status) =~ "s3cret"

    assert [%{env_count: 1}] =
             Enum.filter(
               status.servers,
               &(&1.name == "fake" and &1.workspace == context.workspace)
             )
  end

  test "a refused entry is reported with its reason rather than dropped", context do
    File.write!(
      context.user_path,
      JSON.encode!(%{"mcpServers" => %{"remote" => %{"url" => "https://example.com/mcp"}}})
    )

    assert {:ok, status} = Methods.invoke("mcp.list", %{"workspace" => context.workspace})
    assert [refusal] = Enum.filter(status.refusals, &(&1.name == "remote"))

    assert refusal.reason == :unsupported_transport
    assert refusal.workspace == context.workspace
  end

  test "an untrusted workspace's declined servers are counted in refusals", context do
    File.mkdir_p!(Path.join(context.workspace, ".ouroboros"))

    File.write!(
      Path.join([context.workspace, ".ouroboros", "mcp.json"]),
      JSON.encode!(%{"mcpServers" => %{"repo" => %{"command" => "./bin/x"}}})
    )

    assert {:ok, status} = Methods.invoke("mcp.list", %{"workspace" => context.workspace})
    assert [refusal] = Enum.filter(status.refusals, &(&1.reason == :untrusted_workspace))
    assert refusal.detail =~ "not trusted"
  end

  test "an unknown parameter is rejected rather than ignored" do
    assert {:error, _code, message} = Methods.invoke("mcp.list", %{"nope" => 1})
    assert message =~ "nope"
  end

  test "a workspace that is not a nonempty string is rejected" do
    assert {:error, _code, message} = Methods.invoke("mcp.list", %{"workspace" => ""})
    assert message =~ "workspace"
  end

  defp elixir, do: System.find_executable("elixir") || raise("elixir executable not found")

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
