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
    System.delete_env("ANTHROPIC_API_KEY")

    on_exit(fn ->
      restore_env("ANTHROPIC_API_KEY", previous)
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
    assert File.read!(path) == secret
    assert {:ok, stat} = File.lstat(path)
    assert stat.type == :regular
    assert Bitwise.band(stat.mode, 0o777) == 0o600
    assert {:ok, ^secret, :stored} = AnthropicKey.fetch(path: path)

    assert {:ok, %{source: :stored}} = AnthropicKey.put("sk-ant-replacement", path: path)
    assert File.read!(path) == "sk-ant-replacement"
    assert Path.wildcard(path <> ".tmp-*") == []
  end

  test "the operator environment remains the effective source", %{path: path} do
    assert {:ok, %{source: :stored}} = AnthropicKey.put("sk-ant-stored", path: path)
    System.put_env("ANTHROPIC_API_KEY", "sk-ant-environment")

    assert {:ok, "sk-ant-environment", :environment} = AnthropicKey.fetch(path: path)
    assert %{present: true, source: :environment} = AnthropicKey.status(path: path)
    assert File.read!(path) == "sk-ant-stored"
  end

  test "blank, whitespace-bearing, and relative credentials are refused", %{path: path} do
    assert {:error, :empty_api_key} = AnthropicKey.put("  ", path: path)
    assert {:error, :invalid_api_key} = AnthropicKey.put("sk-ant bad", path: path)

    assert {:error, {:credential_write_failed, message}} =
             AnthropicKey.put("sk-ant-valid", path: "relative/anthropic.key")

    assert message =~ "must be absolute"
    refute File.exists?(path)
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
