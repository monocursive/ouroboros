defmodule Ouroboros.ProviderRuntimeCacheTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.State
  alias Ouroboros.Provider

  setup do
    data_dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-provider-cache-#{System.unique_integer([:positive, :monotonic])}"
      )

    previous_data_dir = Application.get_env(:ouroboros, :data_dir)
    previous_managed = Application.get_env(:ouroboros, :managed_cargo_cache)
    previous_cargo_home = Application.get_env(:ouroboros, :codex_cargo_home)

    previous_execution_defaults =
      Application.get_env(:ouroboros, :provider_execution_defaults)

    previous_provider_config = Application.get_env(:jido_harness, :provider_config)

    on_exit(fn ->
      restore(:ouroboros, :data_dir, previous_data_dir)
      restore(:ouroboros, :managed_cargo_cache, previous_managed)
      restore(:ouroboros, :codex_cargo_home, previous_cargo_home)
      restore(:ouroboros, :provider_execution_defaults, previous_execution_defaults)
      restore(:jido_harness, :provider_config, previous_provider_config)
      File.rm_rf(data_dir)
    end)

    Application.put_env(:ouroboros, :data_dir, data_dir)
    Application.delete_env(:ouroboros, :managed_cargo_cache)
    Application.delete_env(:ouroboros, :codex_cargo_home)
    Application.put_env(:jido_harness, :provider_config, %{})

    %{data_dir: data_dir}
  end

  test "configures one runtime-owned Cargo cache for Codex runs and sessions", %{
    data_dir: data_dir
  } do
    assert :ok = Provider.configure_runtime_cache()

    cargo_home = Path.join([data_dir, "provider-cache", "codex", "cargo"])
    assert File.dir?(cargo_home)
    assert Application.get_env(:ouroboros, :managed_cargo_cache) == cargo_home

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex
    assert codex.env["CARGO_HOME"] == cargo_home
    assert cargo_home in codex.request_defaults.add_dirs
    assert cargo_home in codex.session_defaults.add_dirs

    request = Provider.apply_execution_directories(%{add_dirs: ["/caller-dir"]}, :codex)
    assert request.add_dirs == [cargo_home, "/caller-dir"]

    assert {:ok, task} =
             TaskState.new("cache-coding", "build", provider: :codex, add_dirs: ["/caller-dir"])

    assert TaskState.request(task).add_dirs == [cargo_home, "/caller-dir"]

    assert {:ok, session} =
             State.new("cache-interactive", provider: :codex, add_dirs: ["/caller-dir"])

    assert State.request(session).add_dirs == [cargo_home, "/caller-dir"]
  end

  test "an operator Cargo home remains authoritative", %{data_dir: data_dir} do
    operator_home = Path.join(data_dir, "operator-cargo")

    Application.put_env(:jido_harness, :provider_config, %{
      codex: %{
        env: %{"CARGO_HOME" => operator_home, "RUST_BACKTRACE" => "1"},
        session_defaults: %{add_dirs: ["/already-authorized"]}
      }
    })

    assert :ok = Provider.configure_runtime_cache()

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex
    assert codex.env == %{"CARGO_HOME" => operator_home, "RUST_BACKTRACE" => "1"}
    assert codex.session_defaults.add_dirs == [operator_home, "/already-authorized"]
    assert codex.request_defaults.add_dirs == [operator_home]
    refute Application.get_env(:ouroboros, :managed_cargo_cache)

    request = Provider.apply_execution_directories(%{add_dirs: ["/caller-dir"]}, :codex)
    assert request.add_dirs == [operator_home, "/caller-dir"]
  end

  test "string node defaults and atom caller overrides have one unambiguous key" do
    Application.put_env(:ouroboros, :provider_execution_defaults, %{
      codex: %{"network_access_enabled" => true, "skip_git_repo_check" => true}
    })

    assert Provider.execution_options(:codex, %{"network_access_enabled" => false}) == %{
             network_access_enabled: false,
             skip_git_repo_check: true
           }
  end

  defp restore(application, key, nil), do: Application.delete_env(application, key)
  defp restore(application, key, value), do: Application.put_env(application, key, value)
end
