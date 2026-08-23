defmodule Ouroboros.Provider.Native.McpServersTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Mcp.Servers

  @moduletag :capture_log

  setup do
    root = Path.join(System.tmp_dir!(), "mcp-servers-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, ".ouroboros"))
    user_path = Path.join(root, "user-mcp.json")

    previous = Application.get_env(:ouroboros, :mcp_servers)
    Application.put_env(:ouroboros, :mcp_servers, %{})

    on_exit(fn ->
      if previous, do: Application.put_env(:ouroboros, :mcp_servers, previous)
      unless previous, do: Application.delete_env(:ouroboros, :mcp_servers)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, user_path: user_path}
  end

  describe "the file shape" do
    test "the documented `mcpServers` wrapper and a bare map both load", context do
      write(context.user_path, %{"mcpServers" => %{"a" => %{"command" => "a-mcp"}}})
      assert [%{name: "a", command: "a-mcp"}] = load(context).servers

      write(context.user_path, %{"b" => %{"command" => "b-mcp"}})
      assert [%{name: "b", command: "b-mcp"}] = load(context).servers
    end

    test "args, env and cwd are carried through, and env is never in the description",
         context do
      write(context.user_path, %{
        "mcpServers" => %{
          "a" => %{
            "command" => "a-mcp",
            "args" => ["--stdio"],
            "env" => %{"TOKEN" => "s3cret"},
            "cwd" => context.workspace
          }
        }
      })

      assert [server] = load(context).servers
      assert server.args == ["--stdio"]
      assert server.env == %{"TOKEN" => "s3cret"}
      assert server.cwd == Path.expand(context.workspace)

      described = Servers.describe(server)
      refute Map.has_key?(described, :env)
      assert described.env_count == 1
      assert described.transport == :stdio
    end

    test "a definition never prints its environment values, even through inspect",
         context do
      write(context.user_path, %{
        "mcpServers" => %{"a" => %{"command" => "a", "env" => %{"T" => "s3cret"}}}
      })

      [server] = load(context).servers

      refute inspect(server) =~ "s3cret"
      refute inspect(%{holder: server}) =~ "s3cret"
    end

    test "a disabled entry is neither loaded nor refused", context do
      write(context.user_path, %{
        "mcpServers" => %{
          "on" => %{"command" => "on-mcp"},
          "off" => %{"command" => "off-mcp", "disabled" => true}
        }
      })

      loaded = load(context)
      assert Enum.map(loaded.servers, & &1.name) == ["on"]
      assert loaded.refusals == []
    end
  end

  describe "refusals" do
    test "a `url` server is refused as unsupported_transport, never ignored", context do
      write(context.user_path, %{
        "mcpServers" => %{"remote" => %{"url" => "https://example.com/mcp"}}
      })

      assert %{servers: [], refusals: [refusal]} = load(context)
      assert refusal.name == "remote"
      assert refusal.reason == :unsupported_transport
      assert refusal.detail =~ "stdio only"
    end

    test "a `type` of http or sse is refused the same way", context do
      for type <- ["http", "sse", "streamable-http"] do
        write(context.user_path, %{
          "mcpServers" => %{"remote" => %{"command" => "x", "type" => type}}
        })

        assert %{servers: [], refusals: [%{reason: :unsupported_transport}]} = load(context)
      end
    end

    test "node configuration is atom-keyed, and its `url:` is refused as the wrong transport",
         context do
      Application.put_env(:ouroboros, :mcp_servers, %{
        "remote" => %{url: "https://example.com/mcp"},
        "local" => %{command: "x", args: ["--stdio"], env: %{"T" => "v"}}
      })

      loaded = load(context)

      assert [%{name: "local", args: ["--stdio"], env: %{"T" => "v"}}] = loaded.servers
      assert [%{name: "remote", reason: :unsupported_transport}] = loaded.refusals
    end

    test "a `type` of stdio is not a refusal", context do
      write(context.user_path, %{
        "mcpServers" => %{"local" => %{"command" => "x", "type" => "stdio"}}
      })

      assert %{servers: [%{name: "local"}], refusals: []} = load(context)
    end

    test "a server name containing `__` is refused, because the split would be ambiguous",
         context do
      write(context.user_path, %{"mcpServers" => %{"a__b" => %{"command" => "x"}}})

      assert %{servers: [], refusals: [%{reason: :invalid_name, detail: detail}]} = load(context)
      assert detail =~ "ambiguous"
    end

    test "malformed entries are refused by name, one reason each", context do
      write(context.user_path, %{
        "mcpServers" => %{
          "nocommand" => %{"args" => []},
          "badcommand" => %{"command" => 7},
          "badargs" => %{"command" => "x", "args" => "not-a-list"},
          "badenv" => %{"command" => "x", "env" => %{"K" => 7}},
          "badcwd" => %{"command" => "x", "cwd" => 7},
          "notanobject" => "just a string"
        }
      })

      reasons = load(context).refusals |> Map.new(&{&1.name, &1.reason})

      assert reasons["nocommand"] == :missing_command
      assert reasons["badcommand"] == :invalid_command
      assert reasons["badargs"] == :invalid_args
      assert reasons["badenv"] == :invalid_env
      assert reasons["badcwd"] == :invalid_cwd
      assert reasons["notanobject"] == :invalid_entry
    end

    test "a refusal about `env` names no key and no value", context do
      write(context.user_path, %{
        "mcpServers" => %{"a" => %{"command" => "x", "env" => %{"TOKEN" => 7}}}
      })

      assert [%{reason: :invalid_env, detail: detail}] = load(context).refusals
      refute detail =~ "TOKEN"
    end

    test "a file that is not JSON is an error, not a silent empty list", context do
      File.write!(context.user_path, "{not json")

      assert %{servers: [], errors: [error]} = load(context)
      assert error =~ "invalid JSON"
    end

    test "an absent file is not an error", context do
      assert %{servers: [], errors: [], refusals: []} = load(context)
    end
  end

  describe "precedence" do
    test "node beats user beats workspace for the same name", context do
      trust(context)

      write(workspace_file(context), %{
        "mcpServers" => %{"a" => %{"command" => "workspace"}, "w" => %{"command" => "w-only"}}
      })

      write(context.user_path, %{
        "mcpServers" => %{"a" => %{"command" => "user"}, "u" => %{"command" => "u-only"}}
      })

      Application.put_env(:ouroboros, :mcp_servers, %{
        "a" => %{command: "node"},
        "n" => %{command: "n-only"}
      })

      by_name = load(context).servers |> Map.new(&{&1.name, &1})

      assert by_name["a"].command == "node"
      assert by_name["a"].scope == :node
      assert by_name["u"].command == "u-only"
      assert by_name["w"].command == "w-only"
      assert by_name["n"].command == "n-only"
    end

    test "user beats workspace when the node names nothing", context do
      trust(context)
      write(workspace_file(context), %{"mcpServers" => %{"a" => %{"command" => "workspace"}}})
      write(context.user_path, %{"mcpServers" => %{"a" => %{"command" => "user"}}})

      assert [%{command: "user", scope: :user}] = load(context).servers
    end
  end

  describe "workspace trust" do
    test "an untrusted workspace's servers are declined, counted, and not run", context do
      write(workspace_file(context), %{"mcpServers" => %{"a" => %{"command" => "x"}}})

      assert %{servers: [], declined: 1, trusted?: false} = load(context)
    end

    test "a workspace trusted by configuration loads its servers", context do
      trust(context)
      write(workspace_file(context), %{"mcpServers" => %{"a" => %{"command" => "x"}}})

      assert %{servers: [%{name: "a", scope: :workspace}], declined: 0, trusted?: true} =
               load(context)
    end

    test "a `.ouroboros/trusted` marker trusts the workspace, exactly as it does for hooks",
         context do
      File.write!(Path.join([context.workspace, ".ouroboros", "trusted"]), "")
      write(workspace_file(context), %{"mcpServers" => %{"a" => %{"command" => "x"}}})

      assert %{servers: [%{name: "a"}], trusted?: true} = load(context)
    end

    test "no workspace at all still loads node and user servers", context do
      write(context.user_path, %{"mcpServers" => %{"a" => %{"command" => "x"}}})

      assert %{servers: [%{name: "a"}], trusted?: false, declined: 0} =
               Servers.load(nil, user_path: context.user_path)
    end
  end

  describe "fetch/3" do
    test "a configured server resolves, an unknown one is named, a refused one keeps its reason",
         context do
      write(context.user_path, %{
        "mcpServers" => %{
          "a" => %{"command" => "x"},
          "remote" => %{"url" => "https://example.com"}
        }
      })

      opts = [user_path: context.user_path]

      assert {:ok, %{name: "a"}} = Servers.fetch("a", context.workspace, opts)
      assert {:error, :unknown_server} = Servers.fetch("nope", context.workspace, opts)
      assert {:error, :unsupported_transport} = Servers.fetch("remote", context.workspace, opts)
    end
  end

  defp load(context) do
    Servers.load(context.workspace, user_path: context.user_path)
  end

  defp workspace_file(context), do: Servers.workspace_path(context.workspace)

  defp trust(context) do
    previous = Application.get_env(:ouroboros, :trusted_workspaces, [])
    Application.put_env(:ouroboros, :trusted_workspaces, [context.workspace | previous])
    on_exit(fn -> Application.put_env(:ouroboros, :trusted_workspaces, previous) end)
  end

  defp write(path, document) do
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, JSON.encode!(document))
  end
end
