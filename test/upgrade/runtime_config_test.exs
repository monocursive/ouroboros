defmodule Ouroboros.Upgrade.RuntimeConfigTest do
  use ExUnit.Case, async: false

  @data_dir "OUROBOROS_DATA_DIR"
  @xdg_data_home "XDG_DATA_HOME"
  @signers "OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
  @forge_workspace "OUROBOROS_ORCHESTRATION_FORGE_WORKSPACE"
  @forge_signer "OUROBOROS_FORGE_SIGNER_ID"
  @runtime_log_file "OUROBOROS_RUNTIME_LOG_FILE"
  @runtime_log_max_bytes "OUROBOROS_RUNTIME_LOG_MAX_BYTES"
  @runtime_log_max_files "OUROBOROS_RUNTIME_LOG_MAX_FILES"

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
      restore_env(@xdg_data_home, previous)
      restore_env(@signers, previous)
      restore_env(@forge_workspace, previous)
      restore_env(@forge_signer, previous)
      restore_env(@runtime_log_file, previous)
      restore_env(@runtime_log_max_bytes, previous)
      restore_env(@runtime_log_max_files, previous)
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

  test "production stores and gateway discovery share the trimmed explicit directory", %{
    data_dir: scratch
  } do
    data_dir = Path.join(scratch, "explicit")
    System.put_env(@data_dir, " \t#{data_dir}\n")

    config = runtime_config(:prod)

    assert get_in(config, [:ouroboros, :data_dir]) == data_dir

    assert {Jido.Storage.File, path: Path.join(data_dir, "coding")} ==
             get_in(config, [:ouroboros, :coding_storage])

    assert {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "upgrades")} ==
             get_in(config, [:ouroboros, :upgrade_storage])
  end

  test "a blank production override still derives the XDG default", %{data_dir: scratch} do
    xdg = Path.join(scratch, "xdg")
    expected = Path.join(xdg, "ouroboros")
    System.put_env(@data_dir, " \t\n")
    System.put_env(@xdg_data_home, xdg)

    config = runtime_config(:prod)

    assert get_in(config, [:ouroboros, :data_dir]) == expected

    assert {Jido.Storage.File, path: Path.join(expected, "interactive")} ==
             get_in(config, [:ouroboros, :interactive_storage])
  end

  test "the all-environment gateway override trims absolute paths and refuses relatives", %{
    data_dir: scratch
  } do
    data_dir = Path.join(scratch, "development")
    System.put_env(@data_dir, "  #{data_dir}\t")

    assert get_in(runtime_config(:dev), [:ouroboros, :data_dir]) == data_dir

    System.put_env(@data_dir, " relative/gateway ")

    assert_raise RuntimeError, ~r/nonblank absolute durable directory/, fn ->
      runtime_config(:dev)
    end
  end

  test "an unsafe explicit durable leaf is refused before the production probe writes", %{
    data_dir: data_dir
  } do
    File.mkdir!(data_dir)
    File.chmod!(data_dir, 0o755)
    File.write!(Path.join(data_dir, "sentinel"), "unchanged")

    error = assert_raise RuntimeError, fn -> runtime_config(:prod) end

    assert error.message =~ "mode-0700 durable data directory"
    assert error.message =~ "will not chmod or replace"
    assert File.read!(Path.join(data_dir, "sentinel")) == "unchanged"
    assert File.ls!(data_dir) == ["sentinel"]
    assert Bitwise.band(File.stat!(data_dir).mode, 0o777) == 0o755
  end

  test "a symlinked explicit durable leaf is refused without touching its target", %{
    data_dir: data_dir
  } do
    target = data_dir <> "-target"
    on_exit(fn -> File.rm_rf(target) end)
    File.mkdir!(target)
    File.chmod!(target, 0o700)
    File.write!(Path.join(target, "sentinel"), "unchanged")
    File.ln_s!(target, data_dir)

    error = assert_raise RuntimeError, fn -> runtime_config(:prod) end

    assert error.message =~ "mode-0700 durable data directory"
    assert File.read!(Path.join(target, "sentinel")) == "unchanged"
    assert File.ls!(target) == ["sentinel"]
    assert File.lstat!(data_dir).type == :symlink
  end

  test "a managed runtime uses one OTP-owned live rotating Logger sink", %{data_dir: data_dir} do
    log = prepare_runtime_log(data_dir, max_bytes: 512, max_files: 3)
    config = runtime_config(:prod)

    assert [config: handler_config] = get_in(config, [:logger, :default_handler])
    handler_config = Map.new(handler_config)

    assert handler_config.type == :file
    assert handler_config.file == String.to_charlist(log)
    assert handler_config.file_check == 0
    assert handler_config.filesync_repeat_interval == 5_000
    assert handler_config.max_no_bytes == 512
    assert handler_config.max_no_files == 3
    assert handler_config.compress_on_rotate == false

    id = :"ouroboros_rotation_test_#{System.unique_integer([:positive])}"
    filter_id = :"suppress_#{id}"
    marker = Atom.to_string(id)

    assert :ok =
             :logger.add_handler_filter(
               :default,
               filter_id,
               {fn event, expected ->
                  if get_in(event, [:meta, :ouroboros_rotation_test]) == expected,
                    do: :stop,
                    else: event
                end, marker}
             )

    assert :ok =
             :logger.add_handler(id, :logger_std_h, %{
               config: handler_config,
               formatter: {:logger_formatter, %{template: [:msg, ~c"\n"]}},
               level: :all
             })

    on_exit(fn ->
      :logger.remove_handler(id)
      :logger.remove_handler_filter(:default, filter_id)
    end)

    Enum.each(1..80, fn index ->
      :logger.log(
        :notice,
        "runtime-log-rotation-#{index}-#{String.duplicate("x", 80)}",
        %{
          ouroboros_rotation_test: marker,
          time: System.system_time(:microsecond)
        }
      )
    end)

    assert :ok = :logger_std_h.filesync(id)
    assert :ok = :logger.remove_handler(id)
    assert :ok = :logger.remove_handler_filter(:default, filter_id)

    assert File.regular?(log)
    assert Enum.all?(0..2, &File.regular?(log <> ".#{&1}"))
    refute File.exists?(log <> ".3")
    assert File.read!(log <> ".0") =~ "runtime-log-rotation-"
  end

  test "managed Logger preflight refuses a symlinked archive", %{data_dir: data_dir} do
    log = prepare_runtime_log(data_dir, max_bytes: 512, max_files: 3)
    target = Path.join(data_dir, "outside-runtime-log")
    File.write!(target, "do not touch")
    File.chmod!(target, 0o600)
    File.ln_s!(target, log <> ".1")

    assert_raise RuntimeError, ~r/must be a regular, non-symlink runtime log/, fn ->
      runtime_config(:prod)
    end

    assert File.read!(target) == "do not touch"
    assert File.lstat!(log <> ".1").type == :symlink
  end

  test "managed Logger preflight refuses an old compressed archive", %{data_dir: data_dir} do
    log = prepare_runtime_log(data_dir, max_bytes: 512, max_files: 3)
    compressed = log <> ".0.gz"
    File.write!(compressed, "must not be decompressed or replaced")
    File.chmod!(compressed, 0o600)

    assert_raise RuntimeError, ~r/unexpected compressed runtime log archive/, fn ->
      runtime_config(:prod)
    end

    assert File.read!(compressed) == "must not be decompressed or replaced"
  end

  defp trust_policy do
    config = runtime_config(:prod)
    get_in(config, [:ouroboros, :upgrade_trust_policy])
  end

  defp forge_options do
    config = runtime_config(:prod)
    get_in(config, [:ouroboros, :orchestration_forge_options])
  end

  defp runtime_config(env), do: Config.Reader.read!("config/runtime.exs", env: env, target: :host)

  defp prepare_runtime_log(data_dir, options) do
    Ouroboros.DataDir.ensure_private!(data_dir)
    log = Path.join(data_dir, "runtime.log")
    File.write!(log, "")
    File.chmod!(log, 0o600)
    System.put_env(@runtime_log_file, log)
    System.put_env(@runtime_log_max_bytes, Integer.to_string(Keyword.fetch!(options, :max_bytes)))
    System.put_env(@runtime_log_max_files, Integer.to_string(Keyword.fetch!(options, :max_files)))
    log
  end

  defp restore_env(name, previous) do
    case Map.fetch(previous, name) do
      {:ok, value} -> System.put_env(name, value)
      :error -> System.delete_env(name)
    end
  end
end
