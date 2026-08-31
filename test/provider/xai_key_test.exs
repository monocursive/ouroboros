defmodule Ouroboros.Provider.XAIKeyTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.XAIKey

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-xai-key-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(root)
    path = Path.join(root, "xai.key")
    previous = System.get_env("XAI_API_KEY")
    System.delete_env("XAI_API_KEY")

    on_exit(fn ->
      restore_env("XAI_API_KEY", previous)
      File.rm_rf(root)
    end)

    %{path: path}
  end

  test "publishes and replaces one private key without returning its value", %{path: path} do
    secret = "xai-test-private-value"

    assert {:ok, %{provider: :xai, env: "XAI_API_KEY", present: true, source: :stored} = status} =
             XAIKey.put(secret, path: path)

    refute inspect(status) =~ secret
    assert File.read!(path) == secret

    assert {:ok, stat} = File.lstat(path)
    assert stat.type == :regular
    assert Bitwise.band(stat.mode, 0o777) == 0o600
    assert {:ok, ^secret, :stored} = XAIKey.fetch(path: path)

    assert {:ok, %{source: :stored}} = XAIKey.put("xai-replacement", path: path)
    assert File.read!(path) == "xai-replacement"
    assert Path.wildcard(path <> ".tmp-*") == []
  end

  test "the operator environment remains the effective source", %{path: path} do
    assert {:ok, %{source: :stored}} = XAIKey.put("xai-stored", path: path)
    System.put_env("XAI_API_KEY", "xai-environment")

    assert {:ok, "xai-environment", :environment} = XAIKey.fetch(path: path)
    assert %{present: true, source: :environment} = XAIKey.status(path: path)
    assert File.read!(path) == "xai-stored"
  end

  test "blank, whitespace-bearing, relative, and broadly-readable keys are refused", %{
    path: path
  } do
    assert {:error, :empty_api_key} = XAIKey.put("  ", path: path)
    assert {:error, :invalid_api_key} = XAIKey.put("xai bad", path: path)

    assert {:error, {:credential_write_failed, message}} =
             XAIKey.put("xai-valid", path: "relative/xai.key")

    assert message =~ "must be absolute"

    File.write!(path, "xai-exposed")
    File.chmod!(path, 0o644)

    assert {:error, {:unsafe_credential_file, ^path, {:mode, 0o644}}} =
             XAIKey.fetch(path: path)

    assert %{present: false, source: nil} = XAIKey.status(path: path)
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
