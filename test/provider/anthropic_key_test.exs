defmodule Ouroboros.Provider.AnthropicKeyTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.AnthropicKey

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-anthropic-key-#{System.unique_integer([:positive])}"
      )

    Ouroboros.DataDir.ensure_private!(root)
    path = Path.join(root, "anthropic.key")
    previous = System.get_env("ANTHROPIC_API_KEY")
    previous_workspace = System.get_env("ANTHROPIC_WORKSPACE_ID")
    System.delete_env("ANTHROPIC_API_KEY")
    System.delete_env("ANTHROPIC_WORKSPACE_ID")

    on_exit(fn ->
      restore_env("ANTHROPIC_API_KEY", previous)
      restore_env("ANTHROPIC_WORKSPACE_ID", previous_workspace)
      File.rm_rf(root)
    end)

    %{path: path}
  end

  test "publishes and replaces one private key without returning its value", %{path: path} do
    secret = "sk-ant-test-private-value"

    assert {:ok,
            %{
              provider: :anthropic,
              env: "ANTHROPIC_API_KEY",
              present: true,
              source: :stored
            } = status} = AnthropicKey.put(secret, path: path)

    refute inspect(status) =~ secret

    assert %{
             "version" => 1,
             "api_key" => ^secret,
             "workspace_id" => nil
           } = Jason.decode!(File.read!(path))

    assert {:ok, stat} = File.lstat(path)
    assert stat.type == :regular
    assert Bitwise.band(stat.mode, 0o777) == 0o600
    assert {:ok, ^secret, :stored} = AnthropicKey.fetch(path: path)

    assert {:ok, %{source: :stored}} = AnthropicKey.put("sk-ant-replacement", path: path)

    assert %{"api_key" => "sk-ant-replacement", "workspace_id" => nil} =
             Jason.decode!(File.read!(path))

    assert Path.wildcard(path <> ".tmp-*") == []
  end

  test "the operator environment remains the effective source", %{path: path} do
    assert {:ok, %{source: :stored}} = AnthropicKey.put("sk-ant-stored", path: path)
    System.put_env("ANTHROPIC_API_KEY", "sk-ant-environment")
    System.put_env("ANTHROPIC_WORKSPACE_ID", "wrkspc_Environment123")

    assert {:ok, "sk-ant-environment", :environment} = AnthropicKey.fetch(path: path)

    assert {:ok, %{api_key: "sk-ant-environment", workspace_id: "wrkspc_Environment123"},
            :environment} = AnthropicKey.fetch_credentials(path: path)

    assert %{present: true, source: :environment, workspace_configured: true} =
             AnthropicKey.status(path: path)

    assert %{"api_key" => "sk-ant-stored"} = Jason.decode!(File.read!(path))
  end

  test "blank, whitespace-bearing, and relative credentials are refused", %{path: path} do
    assert {:error, :empty_api_key} = AnthropicKey.put("  ", path: path)
    assert {:error, :invalid_api_key} = AnthropicKey.put("sk-ant bad", path: path)

    assert {:error, :invalid_workspace_id} =
             AnthropicKey.put("sk-ant-valid", "workspace-not-prefixed", path: path)

    assert {:error, {:credential_write_failed, message}} =
             AnthropicKey.put("sk-ant-valid", path: "relative/anthropic.key")

    assert message =~ "must be absolute"
    refute File.exists?(path)
  end

  test "adds a workspace without requiring the stored key again and migrates legacy files", %{
    path: path
  } do
    File.write!(path, "sk-ant-legacy-key")
    File.chmod!(path, 0o600)

    assert {:ok, %{api_key: "sk-ant-legacy-key", workspace_id: nil}, :stored} =
             AnthropicKey.fetch_credentials(path: path)

    assert {:ok, %{source: :stored, workspace_configured: true}} =
             AnthropicKey.configure(nil, "wrkspc_Legacy123", path: path)

    assert {:ok, %{api_key: "sk-ant-legacy-key", workspace_id: "wrkspc_Legacy123"}, :stored} =
             AnthropicKey.fetch_credentials(path: path)

    assert %{"api_key" => "sk-ant-legacy-key", "workspace_id" => "wrkspc_Legacy123"} =
             Jason.decode!(File.read!(path))
  end

  test "replacing the key clears a stored workspace unless a new one is supplied", %{path: path} do
    assert {:ok, _} =
             AnthropicKey.put("sk-ant-original", "wrkspc_Original123", path: path)

    assert {:ok, %{workspace_configured: false}} =
             AnthropicKey.configure("sk-ant-rotated", nil, path: path)

    assert {:ok, %{api_key: "sk-ant-rotated", workspace_id: nil}, :stored} =
             AnthropicKey.fetch_credentials(path: path)

    assert {:ok, %{workspace_configured: true}} =
             AnthropicKey.configure("sk-ant-rotated-again", "wrkspc_Fresh456", path: path)

    assert {:ok, %{api_key: "sk-ant-rotated-again", workspace_id: "wrkspc_Fresh456"}, :stored} =
             AnthropicKey.fetch_credentials(path: path)
  end

  test "an empty workspace_id clears the stored workspace without requiring the key", %{
    path: path
  } do
    assert {:ok, _} = AnthropicKey.put("sk-ant-keep", "wrkspc_Keep123", path: path)
    assert {:ok, %{workspace_configured: false}} = AnthropicKey.configure(nil, :clear, path: path)

    assert {:ok, %{api_key: "sk-ant-keep", workspace_id: nil}, :stored} =
             AnthropicKey.fetch_credentials(path: path)
  end

  test "an invalid ANTHROPIC_WORKSPACE_ID does not disable a valid environment key", %{
    path: path
  } do
    System.put_env("ANTHROPIC_API_KEY", "sk-ant-environment")
    System.put_env("ANTHROPIC_WORKSPACE_ID", "not-a-workspace")

    assert {:ok, %{api_key: "sk-ant-environment", workspace_id: nil}, :environment} =
             AnthropicKey.fetch_credentials(path: path)

    assert %{present: true, source: :environment, workspace_configured: false} =
             AnthropicKey.status(path: path)
  end

  test "configure serializes concurrent updates so a key is not dropped", %{path: path} do
    assert {:ok, _} = AnthropicKey.put("sk-ant-original", path: path)

    tasks =
      for i <- 1..8 do
        Task.async(fn ->
          AnthropicKey.configure(nil, "wrkspc_Parallel#{i}AAA", path: path)
        end)
      end

    results = Task.await_many(tasks, 5_000)
    assert Enum.all?(results, &match?({:ok, %{present: true}}, &1))

    assert {:ok, %{api_key: "sk-ant-original", workspace_id: workspace_id}, :stored} =
             AnthropicKey.fetch_credentials(path: path)

    assert workspace_id =~ ~r/\Awrkspc_Parallel\d+AAA\z/
  end

  test "a stored file with broad permissions is ignored", %{path: path} do
    File.write!(path, "sk-ant-exposed")
    File.chmod!(path, 0o644)

    assert {:error, {:unsafe_credential_file, ^path, {:mode, 0o644}}} =
             AnthropicKey.fetch(path: path)

    assert %{present: false, source: nil} = AnthropicKey.status(path: path)
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
