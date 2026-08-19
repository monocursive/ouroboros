defmodule Ouroboros.Upgrade.RuntimeConfigTest do
  use ExUnit.Case, async: false

  @data_dir "OUROBOROS_DATA_DIR"
  @signers "OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
  @forge_workspace "OUROBOROS_ORCHESTRATION_FORGE_WORKSPACE"
  @forge_signer "OUROBOROS_FORGE_SIGNER_ID"

  setup do
    previous = System.get_env()

    data_dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-runtime-config-#{System.unique_integer([:positive])}"
      )

    System.put_env(@data_dir, data_dir)

    on_exit(fn ->
      File.rm_rf(data_dir)
      restore_env(@data_dir, previous)
      restore_env(@signers, previous)
      restore_env(@forge_workspace, previous)
      restore_env(@forge_signer, previous)
    end)

    {:ok, data_dir: data_dir}
  end

  test "production trusts nobody until signer keys are injected" do
    System.delete_env(@signers)
    assert trust_policy() == [allow_unsigned: false, trusted_signers: %{}]

    System.put_env(@signers, "")
    assert trust_policy() == [allow_unsigned: false, trusted_signers: %{}]
  end

  test "production parses injected signer keys and never accepts a malformed one" do
    {first_key, _private} = :crypto.generate_key(:eddsa, :ed25519)
    {second_key, _private} = :crypto.generate_key(:eddsa, :ed25519)

    System.put_env(
      @signers,
      "release-key:#{Base.encode64(first_key)}, break-glass:#{Base.encode64(second_key)}"
    )

    assert [allow_unsigned: false, trusted_signers: signers] = trust_policy()
    assert signers == %{"release-key" => first_key, "break-glass" => second_key}

    for value <- [
          "release-key",
          ":#{Base.encode64(first_key)}",
          "release-key:not-base64!",
          "release-key:#{Base.encode64(<<0, 1, 2>>)}",
          "release-key:#{Base.encode64(first_key)},release-key:#{Base.encode64(second_key)}"
        ] do
      System.put_env(@signers, value)

      # A narrowed trusted set must not be reachable by mistyping a deployment variable.
      assert_raise RuntimeError, fn -> trust_policy() end
    end
  end

  test "a signer id alone does not enable the forge executor" do
    System.delete_env(@forge_workspace)
    System.put_env(@forge_signer, "release-key")

    assert forge_options() == []
  end

  test "a named workspace enables forge options and can carry a signer" do
    workspace = Path.join(System.tmp_dir!(), "ouroboros-forge-workspace")
    System.put_env(@forge_workspace, workspace)
    System.delete_env(@forge_signer)

    assert forge_options() == [workspace: workspace]

    System.put_env(@forge_signer, "release-key")
    assert Map.new(forge_options()) == %{workspace: workspace, signer_id: "release-key"}

    System.put_env(@forge_signer, "   ")
    assert forge_options() == [workspace: workspace]
  end

  defp trust_policy do
    config = Config.Reader.read!("config/runtime.exs", env: :prod, target: :host)
    get_in(config, [:ouroboros, :upgrade_trust_policy])
  end

  defp forge_options do
    config = Config.Reader.read!("config/runtime.exs", env: :prod, target: :host)
    get_in(config, [:ouroboros, :orchestration_forge_options])
  end

  defp restore_env(name, previous) do
    case Map.fetch(previous, name) do
      {:ok, value} -> System.put_env(name, value)
      :error -> System.delete_env(name)
    end
  end
end
