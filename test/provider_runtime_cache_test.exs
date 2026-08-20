defmodule Ouroboros.ProviderRuntimeCacheTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.State
  alias Ouroboros.Provider
  alias Ouroboros.Provider.RuntimeCache
  alias Ouroboros.RuntimeOwner

  @cache_layout [
    {"CARGO_HOME", ["cargo"], :codex_cargo_home, :managed_cargo_cache},
    {"MIX_HOME", ["mix"], :codex_mix_home, :managed_mix_home},
    {"MIX_ARCHIVES", ["mix", "archives"], :codex_mix_archives, :managed_mix_archives},
    {"HEX_HOME", ["hex"], :codex_hex_home, :managed_hex_home},
    {"REBAR_CACHE_DIR", ["rebar", "cache"], :codex_rebar_cache_dir, :managed_rebar_cache},
    {"REBAR_GLOBAL_CONFIG_DIR", ["rebar", "config"], :codex_rebar_global_config_dir,
     :managed_rebar_config}
  ]

  @cache_runtime_keys [
    :codex_cache_dirs,
    :codex_injected_cache_dirs,
    :managed_codex_launcher,
    :codex_upstream_cli_path,
    :codex_runtime_readiness
    | Enum.flat_map(@cache_layout, fn {_env, _path, effective, managed} ->
        [effective, managed]
      end)
  ]

  setup do
    data_dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-provider-cache-#{System.unique_integer([:positive, :monotonic])}"
      )

    ouroboros_keys =
      [
        :data_dir,
        :provider_execution_defaults,
        :codex_cache_policy_probe_timeout_ms,
        :codex_probe_isolation,
        :codex_probe_setsid_paths
        | @cache_runtime_keys
      ]

    previous_ouroboros = Map.new(ouroboros_keys, &{&1, Application.get_env(:ouroboros, &1)})
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)

    on_exit(fn ->
      Enum.each(previous_ouroboros, fn {key, value} -> restore(:ouroboros, key, value) end)
      restore(:jido_harness, :provider_config, previous_provider_config)
      File.rm_rf(data_dir)
    end)

    Application.put_env(:ouroboros, :data_dir, data_dir)
    Enum.each(@cache_runtime_keys, &Application.delete_env(:ouroboros, &1))
    Application.put_env(:jido_harness, :provider_config, %{})

    %{data_dir: data_dir}
  end

  test "configures runtime-owned Cargo and Elixir caches for Codex runs and sessions", %{
    data_dir: data_dir
  } do
    assert :ok = Provider.configure_runtime_cache()

    entries = cache_entries(data_dir)
    directories = Enum.map(entries, & &1.path)
    assert Application.get_env(:ouroboros, :codex_cache_dirs) == directories

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex

    Enum.each(entries, fn entry ->
      assert File.dir?(entry.path)
      assert codex.env[entry.env] == entry.path
      assert Application.get_env(:ouroboros, entry.effective) == entry.path
      assert Application.get_env(:ouroboros, entry.managed) == entry.path
    end)

    refute Map.has_key?(codex, :request_defaults)
    refute Map.has_key?(codex, :session_defaults)

    request = Provider.apply_execution_directories(%{add_dirs: ["/caller-dir"]}, :codex)
    assert request.add_dirs == directories ++ ["/caller-dir"]

    assert {:ok, task} =
             TaskState.new("cache-coding", "build", provider: :codex, add_dirs: ["/caller-dir"])

    assert TaskState.request(task).add_dirs == directories ++ ["/caller-dir"]

    assert {:ok, session} =
             State.new("cache-interactive", provider: :codex, add_dirs: ["/caller-dir"])

    assert State.request(session).add_dirs == directories ++ ["/caller-dir"]

    policy = Provider.public_execution_policy(:codex, %{})
    assert policy.managed_cargo_cache

    assert policy.managed_elixir_caches == %{
             mix_home: true,
             mix_archives: true,
             hex_home: true,
             rebar_cache: true,
             rebar_config: true
           }
  end

  test "operator cache homes remain authoritative independently", %{data_dir: data_dir} do
    operator_cargo = Path.join(data_dir, "operator-cargo")
    operator_mix_archives = Path.join(data_dir, "operator-mix-archives")
    operator_hex = Path.join(data_dir, "operator-hex")
    operator_rebar_config = Path.join(data_dir, "operator-rebar-config")

    Application.put_env(:jido_harness, :provider_config, %{
      "codex" => %{
        "env" => %{
          "CARGO_HOME" => operator_cargo,
          "MIX_ARCHIVES" => operator_mix_archives,
          "HEX_HOME" => operator_hex,
          "REBAR_GLOBAL_CONFIG_DIR" => operator_rebar_config,
          "RUST_BACKTRACE" => "1"
        },
        "request_defaults" => %{
          "add_dirs" => [operator_cargo, "relative-request", "/request-authorized"]
        },
        "session_defaults" => %{"add_dirs" => ["relative-session", "/session-authorized"]}
      }
    })

    assert :ok = Provider.configure_runtime_cache()

    entries = cache_entries(data_dir)
    managed_mix = entry(entries, "MIX_HOME").path
    managed_rebar_cache = entry(entries, "REBAR_CACHE_DIR").path

    effective_directories = [
      operator_cargo,
      managed_mix,
      operator_mix_archives,
      operator_hex,
      managed_rebar_cache,
      operator_rebar_config
    ]

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex

    assert codex.env == %{
             "CARGO_HOME" => operator_cargo,
             "MIX_HOME" => managed_mix,
             "MIX_ARCHIVES" => operator_mix_archives,
             "HEX_HOME" => operator_hex,
             "REBAR_CACHE_DIR" => managed_rebar_cache,
             "REBAR_GLOBAL_CONFIG_DIR" => operator_rebar_config,
             "RUST_BACKTRACE" => "1"
           }

    assert codex.request_defaults.add_dirs == [
             operator_cargo,
             "relative-request",
             "/request-authorized"
           ]

    assert codex.session_defaults.add_dirs == ["relative-session", "/session-authorized"]

    assert Application.get_env(:ouroboros, :codex_cache_dirs) == effective_directories
    refute Application.get_env(:ouroboros, :managed_cargo_cache)
    assert Application.get_env(:ouroboros, :managed_mix_home) == managed_mix
    refute Application.get_env(:ouroboros, :managed_mix_archives)
    refute Application.get_env(:ouroboros, :managed_hex_home)
    assert Application.get_env(:ouroboros, :managed_rebar_cache) == managed_rebar_cache
    refute Application.get_env(:ouroboros, :managed_rebar_config)

    request = Provider.apply_execution_directories(%{add_dirs: [operator_hex]}, :codex)
    assert request.add_dirs == effective_directories

    assert {:ok, task} =
             TaskState.new("operator-default-cache-coding", "build",
               provider: :codex,
               add_dirs: ["/task-authorized"]
             )

    assert TaskState.request(task).add_dirs ==
             effective_directories ++
               ["relative-request", "/request-authorized", "/task-authorized"]

    assert {:ok, session} =
             State.new("operator-default-cache-interactive",
               provider: :codex,
               add_dirs: ["/session-caller-authorized"]
             )

    assert State.request(session).add_dirs ==
             effective_directories ++
               ["relative-session", "/session-authorized", "/session-caller-authorized"]

    policy = Provider.public_execution_policy(:codex, %{})
    refute policy.managed_cargo_cache

    assert policy.managed_elixir_caches == %{
             mix_home: true,
             mix_archives: false,
             hex_home: false,
             rebar_cache: true,
             rebar_config: false
           }
  end

  test "one unavailable managed directory does not poison the other caches", %{
    data_dir: data_dir
  } do
    entries = cache_entries(data_dir)
    hex = entry(entries, "HEX_HOME")
    File.mkdir_p!(Path.dirname(hex.path))
    File.write!(hex.path, "not a directory")

    log = capture_log(fn -> assert :ok = Provider.configure_runtime_cache() end)
    assert log =~ "Codex HEX_HOME directory"

    successful_entries = Enum.reject(entries, &(&1.env == "HEX_HOME"))
    successful_directories = Enum.map(successful_entries, & &1.path)
    codex = Application.fetch_env!(:jido_harness, :provider_config).codex

    refute Map.has_key?(codex.env, "HEX_HOME")
    refute Application.get_env(:ouroboros, :codex_hex_home)
    refute Application.get_env(:ouroboros, :managed_hex_home)
    refute Map.has_key?(codex, :request_defaults)
    refute Map.has_key?(codex, :session_defaults)
    assert Application.get_env(:ouroboros, :codex_cache_dirs) == successful_directories

    Enum.each(successful_entries, fn entry ->
      assert File.dir?(entry.path)
      assert codex.env[entry.env] == entry.path
      assert Application.get_env(:ouroboros, entry.managed) == entry.path
    end)

    assert Provider.apply_execution_directories(%{}, :codex).add_dirs == successful_directories

    assert Provider.public_execution_policy(:codex, %{}).managed_elixir_caches == %{
             mix_home: true,
             mix_archives: true,
             hex_home: false,
             rebar_cache: true,
             rebar_config: true
           }
  end

  test "relative and invalid operator homes are preserved but never granted", %{
    data_dir: data_dir
  } do
    Application.put_env(:jido_harness, :provider_config, %{
      codex: %{
        env: %{"MIX_HOME" => "../mix-cache", "HEX_HOME" => ""},
        request_defaults: %{add_dirs: ["/caller-authorized"]}
      }
    })

    log = capture_log(fn -> assert :ok = Provider.configure_runtime_cache() end)
    assert log =~ "MIX_HOME has an operator-supplied relative path"
    assert log =~ "HEX_HOME has an operator-supplied value that is not a non-empty path"

    entries = cache_entries(data_dir)

    granted =
      entries
      |> Enum.reject(&(&1.env in ["MIX_HOME", "HEX_HOME"]))
      |> Enum.map(& &1.path)

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex
    assert codex.env["MIX_HOME"] == "../mix-cache"
    assert codex.env["HEX_HOME"] == ""
    assert codex.request_defaults.add_dirs == ["/caller-authorized"]
    refute "../mix-cache" in codex.request_defaults.add_dirs
    refute "" in codex.request_defaults.add_dirs
    refute Application.get_env(:ouroboros, :codex_mix_home)
    refute Application.get_env(:ouroboros, :codex_hex_home)
    assert Application.fetch_env!(:ouroboros, :codex_cache_dirs) == granted

    assert Provider.apply_execution_directories(%{}, :codex, :request).add_dirs ==
             granted ++ ["/caller-authorized"]

    assert Provider.public_execution_policy(:codex, %{}).managed_elixir_caches == %{
             mix_home: false,
             mix_archives: true,
             hex_home: false,
             rebar_cache: true,
             rebar_config: true
           }
  end

  test "managed provider configuration is idempotent" do
    Application.put_env(:jido_harness, :provider_config, %{
      codex: %{
        env: %{"RUST_BACKTRACE" => "1"},
        request_defaults: %{add_dirs: ["/request-authorized"]},
        session_defaults: %{add_dirs: ["/session-authorized"]}
      }
    })

    assert :ok = Provider.configure_runtime_cache()
    first_config = Application.fetch_env!(:jido_harness, :provider_config)
    first_directories = Application.fetch_env!(:ouroboros, :codex_cache_dirs)

    assert :ok = Provider.configure_runtime_cache()
    assert Application.fetch_env!(:jido_harness, :provider_config) == first_config
    assert Application.fetch_env!(:ouroboros, :codex_cache_dirs) == first_directories

    assert first_config.codex.request_defaults.add_dirs == ["/request-authorized"]
    assert first_config.codex.session_defaults.add_dirs == ["/session-authorized"]
  end

  test "managed launcher keeps caller PATH and cache env past Codex login-shell policy", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "operator's codex")
    operator_mix_archives = Path.join(data_dir, "operator's mix archives")
    write_codex_fixture(upstream)

    Application.put_env(:jido_harness, :provider_config, %{
      "codex" => %{
        "cli_path" => upstream,
        "env" => %{
          "MIX_ARCHIVES" => operator_mix_archives,
          "OPERATOR_SENTINEL" => "preserved"
        }
      }
    })

    assert :ok = Provider.configure_runtime_cache()

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    assert codex.cli_path == launcher
    assert Application.fetch_env!(:ouroboros, :codex_upstream_cli_path) == upstream
    assert codex.env["OPERATOR_SENTINEL"] == "preserved"
    assert codex.env["MIX_ARCHIVES"] == operator_mix_archives

    assert {:ok, %{type: :regular, mode: mode}} = File.lstat(launcher)
    assert Bitwise.band(mode, 0o777) == 0o700

    caller_path = "/caller/toolchain/bin:/usr/bin:/bin"

    assert {output, 0} =
             System.cmd(launcher, ["exec", "--json"],
               env: [{"PATH", caller_path} | Enum.to_list(codex.env)],
               stderr_to_stdout: true
             )

    policy_args =
      Enum.flat_map(@cache_layout, fn {env_name, _path, _effective, _managed} ->
        [
          "-c",
          "shell_environment_policy.set.#{env_name}=#{Jason.encode!(codex.env[env_name])}"
        ]
      end)

    expected_args =
      Enum.map_join(policy_args ++ ["exec", "--json"], "", fn arg -> "ARG=<#{arg}>\n" end)

    assert output == "PATH=<#{caller_path}>\n" <> expected_args
    refute output =~ "OPERATOR_SENTINEL"

    assert :ok = Provider.configure_runtime_cache()
    assert Application.fetch_env!(:jido_harness, :provider_config).codex.cli_path == launcher
    assert Application.fetch_env!(:ouroboros, :codex_upstream_cli_path) == upstream

    bypass = Path.join(data_dir, "request-bypass")

    assert {:ok, task} =
             TaskState.new("protected-codex-task", "inspect",
               provider: :codex,
               provider_options: %{cli_path: bypass}
             )

    assert TaskState.request(task).provider_options.cli_path == launcher

    assert {:ok, session} =
             State.new("protected-codex-session",
               provider: :codex,
               provider_options: %{"cli_path" => bypass}
             )

    assert State.request(session).provider_options.cli_path == launcher

    turn =
      Jido.Harness.TurnRequest.new!(%{
        prompt: "continue",
        provider_options: %{cli_path: bypass}
      })

    assert Provider.apply_runtime_provider_policy(turn, :codex).provider_options.cli_path ==
             launcher
  end

  test "a losing runtime owner cannot reach the provider artifact initializer", %{
    data_dir: data_dir
  } do
    parent = self()
    launcher = Path.join([data_dir, "provider-cache", "codex", "bin", "codex"])
    live_config = %{codex: %{cli_path: launcher, owner: "live-runtime"}}

    first_configure = fn ->
      File.mkdir_p!(Path.dirname(launcher))
      File.write!(launcher, "live-runtime\n", [:binary, :sync])
      Application.put_env(:jido_harness, :provider_config, live_config)
      :ok
    end

    first =
      runtime_boundary_supervisor(data_dir, "live-runtime", 71_001, first_configure, fn _pid ->
        :alive
      end)

    assert {:ok, first_supervisor} = first
    Process.unlink(first_supervisor)

    on_exit(fn ->
      if Process.alive?(first_supervisor), do: Supervisor.stop(first_supervisor, :shutdown)
    end)

    assert File.read!(launcher) == "live-runtime\n"
    assert Application.fetch_env!(:jido_harness, :provider_config) == live_config

    losing_configure = fn ->
      send(parent, :losing_cache_initializer_ran)
      File.write!(launcher, "losing-runtime\n", [:binary, :sync])
      Application.put_env(:jido_harness, :provider_config, %{codex: %{owner: "loser"}})
      :ok
    end

    previous_trap = Process.flag(:trap_exit, true)

    try do
      assert {:error,
              {:shutdown,
               {:failed_to_start_child, :runtime_owner, {:runtime_data_dir_owned, message}}}} =
               runtime_boundary_supervisor(
                 data_dir,
                 "losing-runtime",
                 71_002,
                 losing_configure,
                 fn
                   71_001 -> :alive
                   _other -> :dead
                 end
               )

      assert message =~ RuntimeOwner.marker_path(data_dir)
    after
      Process.flag(:trap_exit, previous_trap)
    end

    refute_receive :losing_cache_initializer_ran
    assert File.read!(launcher) == "live-runtime\n"
    assert Application.fetch_env!(:jido_harness, :provider_config) == live_config
  end

  test "a symlink alias to the managed launcher is refused before it can recurse", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "real-codex")
    alias_path = Path.join(data_dir, "codex-alias")
    write_codex_fixture(upstream)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})

    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    File.ln_s!(launcher, alias_path)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: alias_path}})

    assert :ok = Provider.configure_runtime_cache()
    assert_codex_refusal(launcher, alias_path)
    assert_codex_refusal(launcher, "managed launcher")
    assert File.lstat!(alias_path).type == :symlink
    assert Application.fetch_env!(:ouroboros, :managed_codex_launcher) == launcher
    assert Application.fetch_env!(:jido_harness, :provider_config).codex.cli_path == launcher
  end

  test "a bare Codex path resolving through PATH to the managed launcher is refused", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "real-codex")
    write_codex_fixture(upstream)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})

    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    previous_path = System.get_env("PATH")

    try do
      System.put_env("PATH", Path.dirname(launcher) <> ":" <> (previous_path || ""))
      Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: "codex"}})

      assert :ok = Provider.configure_runtime_cache()
      assert_codex_refusal(launcher, "\"codex\"")
      assert_codex_refusal(launcher, "managed launcher")
      assert Application.fetch_env!(:ouroboros, :managed_codex_launcher) == launcher
    after
      if previous_path, do: System.put_env("PATH", previous_path), else: System.delete_env("PATH")
    end
  end

  test "effective Codex include_only filtering fails before installing a misleading launcher", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "filtering-codex")
    write_codex_fixture(upstream, filter: ["MIX_ARCHIVES"])
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})

    assert :ok = Provider.configure_runtime_cache()

    launcher = Path.join([data_dir, "provider-cache", "codex", "bin", "codex"])
    assert_codex_refusal(launcher, "MIX_ARCHIVES")
    assert_codex_refusal(launcher, "append")
    assert_codex_refusal(launcher, "CARGO_HOME")
    assert Application.fetch_env!(:ouroboros, :managed_codex_launcher) == launcher
    assert Application.fetch_env!(:jido_harness, :provider_config).codex.cli_path == launcher
    refute Provider.public_execution_policy(:codex, %{}).runtime_ready

    assert Provider.public_execution_policy(:codex, %{}).runtime_error ==
             :codex_cache_policy_filtered
  end

  test "the effective-policy probe is bounded and degrades only Codex", %{data_dir: data_dir} do
    upstream = Path.join(data_dir, "hanging-codex")
    probe_pid_file = Path.join(data_dir, "startup-probe.pid")
    descendant_pid_file = Path.join(data_dir, "startup-descendant.pid")

    write_codex_fixture(upstream,
      sandbox_delay: 2,
      delay_pid_file: probe_pid_file,
      delay_descendant_pid_file: descendant_pid_file
    )

    Application.put_env(:ouroboros, :codex_cache_policy_probe_timeout_ms, 1_000)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})
    started = System.monotonic_time(:millisecond)

    assert :ok = Provider.configure_runtime_cache()
    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed < 2_500

    launcher = Path.join([data_dir, "provider-cache", "codex", "bin", "codex"])
    assert_codex_refusal(launcher, "probe timeout")
    assert is_pid(Process.whereis(Ouroboros.Supervisor))

    probe_pid = read_pid!(probe_pid_file)
    descendant_pid = read_pid!(descendant_pid_file)

    assert eventually_value(fn ->
             not os_process_alive?(probe_pid) and
               not os_process_alive?(descendant_pid) and
               process_listing(upstream) == [] and
               process_listing("ouroboros-probe-watchdog") == []
           end)
  end

  test "the probe refuses before Codex when no isolated process group is available", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "never-started-codex")
    write_codex_fixture(upstream)
    Application.put_env(:ouroboros, :codex_probe_isolation, :unavailable)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})

    assert :ok = Provider.configure_runtime_cache()
    launcher = Path.join([data_dir, "provider-cache", "codex", "bin", "codex"])
    assert_codex_refusal(launcher, "process_group_unavailable")
    refute File.exists?(upstream <> ".provider-argv")
    assert process_listing(upstream) == []
  end

  test "the setsid fallback isolates and reaps a non-exec descendant", %{data_dir: data_dir} do
    upstream = Path.join(data_dir, "setsid-workspace-codex")
    setsid = Path.join(data_dir, "setsid")
    marker = ".hang-setsid-cache-policy-probe"
    probe_pid_file = Path.join(data_dir, "setsid-probe.pid")
    descendant_pid_file = Path.join(data_dir, "setsid-descendant.pid")

    File.mkdir_p!(data_dir)

    File.write!(setsid, """
    #!/bin/sh
    exec /usr/bin/perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV; exit 127' "$@"
    """)

    File.chmod!(setsid, 0o700)

    write_codex_fixture(upstream,
      sandbox_delay: 2,
      delay_when_file: marker,
      delay_pid_file: probe_pid_file,
      delay_descendant_pid_file: descendant_pid_file
    )

    Application.put_env(:ouroboros, :codex_probe_isolation, :setsid_only)
    Application.put_env(:ouroboros, :codex_probe_setsid_paths, [setsid])
    Application.put_env(:ouroboros, :codex_cache_policy_probe_timeout_ms, 500)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})
    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    codex_env = Application.fetch_env!(:jido_harness, :provider_config).codex.env
    refute File.read!(launcher) =~ "set -m"
    workspace = Path.join(data_dir, "setsid-workspace")
    File.mkdir_p!(workspace)

    assert {output, 0} =
             System.cmd(launcher, ["exec", "--json"],
               cd: workspace,
               env: Enum.to_list(codex_env),
               stderr_to_stdout: true
             )

    assert output =~ "ARG=<exec>"
    File.write!(Path.join(workspace, marker), "hang\n")

    assert {refusal, 78} =
             System.cmd(launcher, ["exec", "--json"],
               cd: workspace,
               env: Enum.to_list(codex_env),
               stderr_to_stdout: true
             )

    assert refusal =~ "preflight failed or exceeded 0.500 seconds"
    probe_pid = read_pid!(probe_pid_file)
    descendant_pid = read_pid!(descendant_pid_file)

    assert eventually_value(fn ->
             not os_process_alive?(probe_pid) and
               not os_process_alive?(descendant_pid) and
               process_listing(setsid) == [] and
               process_listing(upstream) == [] and
               process_listing("ouroboros-probe-watchdog") == []
           end)
  end

  test "the launcher rechecks workspace-local policy before the provider invocation", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "workspace-aware-codex")
    marker = ".filter-managed-caches"
    write_codex_fixture(upstream, filter: ["HEX_HOME"], filter_when_file: marker)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})

    # Startup runs outside the marked workspace and establishes the ordinary launcher.
    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    codex_env = Application.fetch_env!(:jido_harness, :provider_config).codex.env
    clean_workspace = Path.join(data_dir, "clean-workspace")
    filtered_workspace = Path.join(data_dir, "filtered-workspace")
    File.mkdir_p!(clean_workspace)
    File.mkdir_p!(filtered_workspace)
    File.write!(Path.join(filtered_workspace, marker), "filter\n")

    started = System.monotonic_time(:millisecond)

    assert {ordinary, 0} =
             System.cmd(launcher, ["exec", "--json"],
               cd: clean_workspace,
               env: Enum.to_list(codex_env),
               stderr_to_stdout: true
             )

    ordinary_overhead = System.monotonic_time(:millisecond) - started
    assert ordinary_overhead < 500
    assert ordinary =~ "ARG=<exec>"

    assert {refusal, 78} =
             System.cmd(launcher, ["exec", "--json"],
               cd: filtered_workspace,
               env: Enum.to_list(codex_env),
               stderr_to_stdout: true
             )

    assert refusal =~ "this workspace's effective shell_environment_policy"
    assert refusal =~ "HEX_HOME"
    refute refusal =~ "ARG=<exec>"
  end

  test "the workspace policy watchdog is bounded and never dispatches provider argv", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "workspace-hanging-codex")
    marker = ".hang-cache-policy-probe"
    probe_pid_file = Path.join(data_dir, "timeout-probe.pid")
    descendant_pid_file = Path.join(data_dir, "timeout-descendant.pid")

    write_codex_fixture(upstream,
      sandbox_delay: 2,
      delay_when_file: marker,
      delay_pid_file: probe_pid_file,
      delay_descendant_pid_file: descendant_pid_file
    )

    Application.put_env(:ouroboros, :codex_cache_policy_probe_timeout_ms, 1_000)
    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})

    # Startup is unmarked, so only the preflight in the eventual working directory hangs.
    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    codex_env = Application.fetch_env!(:jido_harness, :provider_config).codex.env
    workspace = Path.join(data_dir, "hanging-workspace")
    File.mkdir_p!(workspace)
    File.write!(Path.join(workspace, marker), "hang\n")
    started = System.monotonic_time(:millisecond)

    assert {refusal, 78} =
             System.cmd(launcher, ["exec", "--json"],
               cd: workspace,
               env: Enum.to_list(codex_env),
               stderr_to_stdout: true
             )

    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed < 2_500
    assert refusal =~ "preflight failed or exceeded 1.000 seconds"
    assert refusal =~ "ensure `codex sandbox` works locally"
    refute refusal =~ "ARG=<exec>"

    probe_pid = read_pid!(probe_pid_file)
    descendant_pid = read_pid!(descendant_pid_file)

    assert eventually_value(fn ->
             not os_process_alive?(probe_pid) and
               not os_process_alive?(descendant_pid) and
               process_listing(launcher) == [] and
               process_listing("ouroboros-probe-watchdog") == []
           end)
  end

  test "terminating the launcher during preflight promptly reaps its children", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "cancellable-workspace-codex")
    marker = ".hang-cancellable-cache-policy-probe"
    probe_pid_file = Path.join(data_dir, "probe.pid")
    descendant_pid_file = Path.join(data_dir, "probe-descendant.pid")

    write_codex_fixture(upstream,
      sandbox_delay: 20,
      delay_when_file: marker,
      delay_pid_file: probe_pid_file,
      delay_descendant_pid_file: descendant_pid_file
    )

    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})
    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    codex_env = Application.fetch_env!(:jido_harness, :provider_config).codex.env
    workspace = Path.join(data_dir, "cancellable-workspace")
    File.mkdir_p!(workspace)
    File.write!(Path.join(workspace, marker), "hang\n")

    port =
      Port.open(
        {:spawn_executable, String.to_charlist(launcher)},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:args, [~c"exec", ~c"--json"]},
          {:cd, String.to_charlist(workspace)},
          {:env,
           Enum.map(codex_env, fn {key, value} ->
             {String.to_charlist(key), String.to_charlist(value)}
           end)}
        ]
      )

    {:os_pid, launcher_pid} = Port.info(port, :os_pid)

    probe_pid = eventually_value(fn -> read_pid(probe_pid_file) end)
    descendant_pid = eventually_value(fn -> read_pid(descendant_pid_file) end)

    assert is_integer(probe_pid)
    assert is_integer(descendant_pid)
    assert os_process_alive?(launcher_pid)
    assert os_process_alive?(probe_pid)
    assert os_process_alive?(descendant_pid)
    assert os_process_group(probe_pid) == probe_pid
    assert os_process_group(descendant_pid) == probe_pid
    refute os_process_group(launcher_pid) == probe_pid
    started = System.monotonic_time(:millisecond)
    assert {_, 0} = System.cmd("/bin/kill", ["-TERM", Integer.to_string(launcher_pid)])
    assert receive_port_exit(port, 1_000) == 143
    assert System.monotonic_time(:millisecond) - started < 1_000

    assert eventually_value(fn ->
             not os_process_alive?(probe_pid) and
               not os_process_alive?(descendant_pid) and
               process_listing(launcher) == [] and
               process_listing(upstream) == [] and
               process_listing("ouroboros-probe-watchdog") == []
           end)

    refute File.exists?(upstream <> ".provider-argv")
  end

  test "a successful preflight preserves provider argv, status, and signal semantics", %{
    data_dir: data_dir
  } do
    upstream = Path.join(data_dir, "provider-exec-codex")
    marker = ".hang-real-provider"
    provider_pid_file = Path.join(data_dir, "provider.pid")

    write_codex_fixture(upstream,
      provider_exit_status: 37,
      provider_delay: 20,
      provider_delay_when_file: marker,
      provider_pid_file: provider_pid_file
    )

    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})
    assert :ok = Provider.configure_runtime_cache()
    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    codex_env = Application.fetch_env!(:jido_harness, :provider_config).codex.env
    workspace = Path.join(data_dir, "provider-exec-workspace")
    File.mkdir_p!(workspace)

    assert {_output, 37} =
             System.cmd(launcher, ["exec", "--json", "payload"],
               cd: workspace,
               env: Enum.to_list(codex_env),
               stderr_to_stdout: true
             )

    argv = (upstream <> ".provider-argv") |> File.read!() |> String.split("\n", trim: true)
    assert Enum.take(argv, -3) == ["exec", "--json", "payload"]

    File.write!(Path.join(workspace, marker), "hang\n")

    port =
      Port.open(
        {:spawn_executable, String.to_charlist(launcher)},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:args, [~c"exec", ~c"--json", ~c"payload"]},
          {:cd, String.to_charlist(workspace)},
          {:env,
           Enum.map(codex_env, fn {key, value} ->
             {String.to_charlist(key), String.to_charlist(value)}
           end)}
        ]
      )

    {:os_pid, launcher_pid} = Port.info(port, :os_pid)
    provider_pid = eventually_value(fn -> read_pid(provider_pid_file) end)
    assert provider_pid == launcher_pid
    assert {_, 0} = System.cmd("/bin/kill", ["-TERM", Integer.to_string(launcher_pid)])
    assert receive_port_exit(port, 1_000) == 143
    refute os_process_alive?(provider_pid)
    assert process_listing("ouroboros-probe-watchdog") == []
  end

  test "a stale managed cli path never becomes its own upstream", %{data_dir: data_dir} do
    upstream = Path.join(data_dir, "temporary-codex")
    File.mkdir_p!(data_dir)
    File.write!(upstream, "#!/bin/sh\nexit 0\n")
    File.chmod!(upstream, 0o700)

    Application.put_env(:jido_harness, :provider_config, %{codex: %{cli_path: upstream}})
    assert :ok = Provider.configure_runtime_cache()

    launcher = Application.fetch_env!(:ouroboros, :managed_codex_launcher)
    assert Application.fetch_env!(:jido_harness, :provider_config).codex.cli_path == launcher

    Application.delete_env(:ouroboros, :codex_upstream_cli_path)
    File.rm!(upstream)
    assert :ok = Provider.configure_runtime_cache()

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex
    recovered_upstream = Application.get_env(:ouroboros, :codex_upstream_cli_path)

    if codex[:cli_path] == launcher do
      assert is_binary(recovered_upstream)
      refute Path.expand(recovered_upstream) == Path.expand(launcher)
    else
      refute Map.has_key?(codex, :cli_path)
      refute File.exists?(launcher)
    end
  end

  test "legacy cache grants are removed without disturbing operator defaults", %{
    data_dir: data_dir
  } do
    cargo = data_dir |> cache_entries() |> entry("CARGO_HOME")

    Application.put_env(:ouroboros, :managed_cargo_cache, cargo.path)

    Application.put_env(:jido_harness, :provider_config, %{
      codex: %{
        env: %{"CARGO_HOME" => cargo.path},
        request_defaults: %{
          add_dirs: [cargo.path, "relative-request", "/operator-request"]
        }
      }
    })

    assert :ok = Provider.configure_runtime_cache()

    codex = Application.fetch_env!(:jido_harness, :provider_config).codex
    assert codex.env["CARGO_HOME"] == cargo.path
    assert codex.request_defaults.add_dirs == ["relative-request", "/operator-request"]
    refute Map.has_key?(codex, :session_defaults)
  end

  test "read-only Codex requests receive no writable roots", %{data_dir: data_dir} do
    Application.put_env(:jido_harness, :provider_config, %{
      codex: %{
        request_defaults: %{add_dirs: ["/operator-request-writable"]},
        session_defaults: %{add_dirs: ["/operator-session-writable"]}
      }
    })

    assert :ok = Provider.configure_runtime_cache()
    directories = cache_entries(data_dir) |> Enum.map(& &1.path)
    codex = Application.fetch_env!(:jido_harness, :provider_config).codex

    assert codex.request_defaults.add_dirs == ["/operator-request-writable"]
    assert codex.session_defaults.add_dirs == ["/operator-session-writable"]

    assert Provider.apply_execution_directories(
             %{sandbox_mode: :read_only, add_dirs: ["/caller-writable"]},
             :codex
           ).add_dirs == []

    assert {:ok, task} =
             TaskState.new("read-only-cache-coding", "inspect",
               provider: :codex,
               sandbox_mode: :read_only,
               add_dirs: ["/caller-writable"]
             )

    assert TaskState.request(task).add_dirs == []

    assert {:ok, session} =
             State.new("read-only-cache-interactive",
               provider: :codex,
               sandbox_mode: :read_only,
               add_dirs: ["/caller-writable"]
             )

    assert State.request(session).add_dirs == []
    assert Application.fetch_env!(:ouroboros, :codex_cache_dirs) == directories
  end

  test "a cache is managed only after a real write probe succeeds", %{data_dir: data_dir} do
    cargo = data_dir |> cache_entries() |> entry("CARGO_HOME")
    File.mkdir_p!(cargo.path)
    File.chmod!(cargo.path, 0o500)
    on_exit(fn -> File.chmod(cargo.path, 0o700) end)

    log = capture_log(fn -> assert :ok = Provider.configure_runtime_cache() end)
    assert log =~ "Codex CARGO_HOME directory"

    refute Application.get_env(:ouroboros, :managed_cargo_cache)
    refute cargo.path in Application.fetch_env!(:ouroboros, :codex_cache_dirs)
    refute cargo.path in Provider.apply_execution_directories(%{}, :codex).add_dirs
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

  defp cache_entries(data_dir) do
    cache_root = Path.join([data_dir, "provider-cache", "codex"])

    Enum.map(@cache_layout, fn {env, relative_path, effective, managed} ->
      %{
        env: env,
        path: Path.join([cache_root | relative_path]),
        effective: effective,
        managed: managed
      }
    end)
  end

  defp entry(entries, env), do: Enum.find(entries, &(&1.env == env))

  defp runtime_boundary_supervisor(data_dir, identity, os_pid, configure, pid_state) do
    suffix = System.unique_integer([:positive, :monotonic])
    birth = "runtime-boundary-birth-#{os_pid}"

    children = [
      Supervisor.child_spec(
        {RuntimeOwner,
         data_dir: data_dir,
         name: String.to_atom("runtime_owner_boundary_#{suffix}"),
         identity: identity,
         os_pid: os_pid,
         birth: birth,
         pid_state: pid_state,
         birth_state: fn pid, _birth -> pid_state.(pid) end},
        id: :runtime_owner
      ),
      Supervisor.child_spec(
        {RuntimeCache,
         name: String.to_atom("runtime_cache_boundary_#{suffix}"), configure: configure},
        id: :runtime_cache
      )
    ]

    Supervisor.start_link(children, strategy: :rest_for_one)
  end

  defp write_codex_fixture(path, opts \\ []) do
    filtered = Keyword.get(opts, :filter, [])
    unsets = Enum.map_join(filtered, "\n", &"    unset #{&1}")
    filter_when_file = Keyword.get(opts, :filter_when_file)

    filter_commands =
      if filter_when_file do
        "    if [ -f #{inspect(filter_when_file)} ]; then\n#{unsets}\n    fi"
      else
        unsets
      end

    delay = Keyword.get(opts, :sandbox_delay)
    delay_when_file = Keyword.get(opts, :delay_when_file)
    delay_pid_file = Keyword.get(opts, :delay_pid_file)
    delay_descendant_pid_file = Keyword.get(opts, :delay_descendant_pid_file)

    record_delay_pid =
      if delay_pid_file do
        "      printf '%s\\n' \"$$\" > #{shell_quote(delay_pid_file)}\n"
      else
        ""
      end

    delayed_child =
      if delay_descendant_pid_file do
        "      /bin/sleep #{delay} &\n" <>
          "      ouroboros_fixture_child=$!\n" <>
          "      printf '%s\\n' \"$ouroboros_fixture_child\" > " <>
          "#{shell_quote(delay_descendant_pid_file)}\n" <>
          "      wait \"$ouroboros_fixture_child\"\n"
      else
        "      /bin/sleep #{delay}\n"
      end

    delay_command =
      cond do
        delay && delay_when_file ->
          "    if [ -f #{shell_quote(delay_when_file)} ]; then\n" <>
            record_delay_pid <>
            delayed_child <>
            "    fi\n"

        delay ->
          record_delay_pid <> delayed_child

        true ->
          ""
      end

    provider_delay = Keyword.get(opts, :provider_delay)
    provider_delay_when_file = Keyword.get(opts, :provider_delay_when_file)
    provider_pid_file = Keyword.get(opts, :provider_pid_file)
    provider_exit_status = Keyword.get(opts, :provider_exit_status)

    provider_delay_command =
      if provider_delay && provider_delay_when_file && provider_pid_file do
        "if [ -f #{shell_quote(provider_delay_when_file)} ]; then\n" <>
          "  printf '%s\\n' \"$$\" > #{shell_quote(provider_pid_file)}\n" <>
          "  exec /bin/sleep #{provider_delay}\n" <>
          "fi\n"
      else
        ""
      end

    provider_exit_command =
      if is_integer(provider_exit_status), do: "exit #{provider_exit_status}\n", else: ""

    provider_argv_file = shell_quote(path <> ".provider-argv")

    File.mkdir_p!(Path.dirname(path))

    File.write!(path, """
    #!/bin/sh
    for arg do
      if [ "$arg" = "sandbox" ]; then
        while [ "$1" != "sandbox" ]; do shift; done
        shift
    #{delay_command}#{filter_commands}
        exec "$@"
      fi
    done
    printf 'PATH=<%s>\n' "$PATH"
    for arg do
      printf 'ARG=<%s>\n' "$arg"
    done
    : > #{provider_argv_file}
    for arg do
      printf '%s\n' "$arg" >> #{provider_argv_file}
    done
    #{provider_delay_command}#{provider_exit_command}
    """)

    File.chmod!(path, 0o700)
  end

  defp assert_codex_refusal(launcher, fragment) do
    assert {output, 78} = System.cmd(launcher, ["exec", "--json"], stderr_to_stdout: true)
    assert output =~ "Ouroboros refused Codex"
    assert output =~ fragment
  end

  defp receive_port_exit(port, timeout) do
    receive do
      {^port, {:exit_status, status}} -> status
      {^port, {:data, _output}} -> receive_port_exit(port, timeout)
    after
      timeout -> flunk("launcher did not exit after TERM")
    end
  end

  defp os_process_alive?(pid) when is_integer(pid) do
    match?(
      {_, 0},
      System.cmd("/bin/kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
    )
  end

  defp os_process_group(pid) when is_integer(pid) do
    case System.cmd("/bin/ps", ["-p", Integer.to_string(pid), "-o", "pgid="]) do
      {output, 0} -> output |> String.trim() |> String.to_integer()
      {_output, _status} -> nil
    end
  end

  defp process_listing(fragment) do
    {listing, _status} = System.cmd("ps", ["-A", "-ww", "-o", "pid=,command="])

    listing
    |> String.split("\n", trim: true)
    |> Enum.filter(&String.contains?(&1, fragment))
  end

  defp read_pid!(path) do
    case read_pid(path) do
      pid when is_integer(pid) -> pid
      _missing_or_invalid -> flunk("fixture did not record a pid at #{path}")
    end
  end

  defp read_pid(path) do
    with {:ok, contents} <- File.read(path),
         {pid, ""} <- Integer.parse(String.trim(contents)) do
      pid
    else
      _missing_or_invalid -> false
    end
  end

  defp eventually_value(fun, attempts \\ 40)

  defp eventually_value(fun, attempts) when attempts > 0 do
    case fun.() do
      false ->
        Process.sleep(25)
        eventually_value(fun, attempts - 1)

      nil ->
        Process.sleep(25)
        eventually_value(fun, attempts - 1)

      value ->
        value
    end
  end

  defp eventually_value(fun, 0), do: fun.()

  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\"'\"'") <> "'"

  defp restore(application, key, nil), do: Application.delete_env(application, key)
  defp restore(application, key, value), do: Application.put_env(application, key, value)
end
