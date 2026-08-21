defmodule Ouroboros.Provider do
  @moduledoc """
  What a provider will actually accept for the two options the planes default.

  Both planes want to start under a usable posture: approvals prompted and the workspace
  writable. Four of the nine bundled providers cannot be told that. Amp declares neither
  option, OpenCode declares no `sandbox_mode`, Kimi declares both but accepts only
  `:default` for each, and Pi refuses `:prompt` approvals. `Jido.Harness` refuses any
  normalized option a provider has not declared, so injecting the pair unconditionally
  did not make those four providers safe — it made them unstartable. A read-only session
  is still available: pass `sandbox_mode: :read_only`.

  The lookup answers per plane because the harness validates the two surfaces against
  different lists. A run is checked against the adapter's own `normalized_options`
  (`Jido.Harness.Run.RequestResolver`); a session is checked against the selected
  transport's `session_options`, which inherit the adapter's list only when the
  transport declares `:adapter` (`Jido.Harness.SessionManager`). OpenCode is the case
  that makes the distinction load-bearing: its adapter accepts `approval_mode`, its ACP
  session transport does not.

  What a plane does with the answer is the plane's business, and the two differ:

    * The interactive plane omits a default the provider cannot take, which leaves the
      harness request at `:default` — the provider's own behavior, which is what "the
      caller said nothing" has always meant.
    * The coding plane refuses at creation, because its workspace-write default is a
      promise the README makes to whoever starts a task, and quietly dropping it would
      break that promise in the one direction that matters.

  Neither plane rewrites or drops an option the caller stated. A sandbox the provider
  cannot enforce has to fail loudly rather than quietly become no sandbox at all, so a
  stated value travels to the harness untouched and the harness refuses it by name.
  """

  alias Jido.Harness.Registry

  require Logger

  @typedoc """
  Which harness surface the options are bound for. An interactive session also carries
  the transport the caller selected, or `nil` when it takes the adapter's default.
  """
  @type plane :: :coding | {:interactive, atom() | nil}

  # The default posture, in the order a refusal reports it. Read-only is opt-in.
  @plane_defaults [approval_mode: :prompt, sandbox_mode: :workspace_write]

  # Codex's non-interactive transport otherwise refuses an empty directory before the
  # model sees the first turn, and its workspace-write sandbox cannot fetch a dependency
  # unless network access is stated. These are execution facts of the node, not knobs a
  # terminal should have to smuggle through `provider_options`. Explicit caller values
  # still win below, including `false`.
  @execution_defaults %{
    codex: %{skip_git_repo_check: true, network_access_enabled: true}
  }

  # Language tools keep mutable state outside the working directory even when all
  # project output belongs inside it. Codex's workspace-write sandbox needs both the
  # environment override and an explicit writable-directory grant for every effective
  # path. Each entry is independent so one unavailable cache cannot disable the rest.
  @codex_cache_specs [
    {"CARGO_HOME", ["cargo"], :codex_cargo_home, :managed_cargo_cache},
    {"MIX_HOME", ["mix"], :codex_mix_home, :managed_mix_home},
    {"MIX_ARCHIVES", ["mix", "archives"], :codex_mix_archives, :managed_mix_archives},
    {"HEX_HOME", ["hex"], :codex_hex_home, :managed_hex_home},
    {"REBAR_CACHE_DIR", ["rebar", "cache"], :codex_rebar_cache_dir, :managed_rebar_cache},
    {"REBAR_GLOBAL_CONFIG_DIR", ["rebar", "config"], :codex_rebar_global_config_dir,
     :managed_rebar_config}
  ]

  # Unified exec may choose an interactive login shell. Startup code such as a version
  # manager can then unset and replace the cache homes Harness injected into Codex's
  # process. Codex applies `shell_environment_policy.set` after that startup boundary,
  # so pin only this allowlist of non-secret path variables there. The caller's PATH and
  # login-shell behavior remain untouched, and arbitrary provider env (which can contain
  # credentials) never enters process arguments. A tiny launcher is necessary because
  # the pinned Harness adapter deliberately exposes no arbitrary Codex argv escape hatch.
  @codex_shell_policy_prefix "shell_environment_policy.set."
  @codex_launcher_relative_path ["bin", "codex"]
  @codex_launcher_key :managed_codex_launcher
  @codex_upstream_key :codex_upstream_cli_path
  @codex_readiness_key :codex_runtime_readiness
  @codex_cache_policy_probe_timeout_ms 5_000

  # `Jido.Harness` reads each of these as "the caller said nothing" and never checks it
  # against a provider's allowlist. `:default` is therefore always legal to send, which
  # is what makes it the override a refusal can honestly recommend.
  @unset_values [nil, [], %{}, :default]

  @doc "Merges this node's safe provider execution defaults under caller options."
  @spec execution_options(atom(), map() | nil) :: map() | nil
  def execution_options(provider, options) when options in [nil, %{}] do
    defaults = provider |> provider_defaults(%{}) |> normalize_default_keys(provider)

    result = if defaults == %{} and is_nil(options), do: nil, else: defaults
    enforce_managed_cli_path(provider, result)
  end

  def execution_options(provider, options) when is_map(options) do
    defaults = provider |> provider_defaults(%{}) |> normalize_default_keys(provider)

    defaults
    |> Map.merge(normalize_default_keys(options, provider))
    |> then(&enforce_managed_cli_path(provider, &1))
  end

  def execution_options(_provider, options), do: options

  @doc "Returns the non-secret execution policy safe to show in public session state."
  @spec public_execution_policy(atom(), map() | nil) :: map()
  def public_execution_policy(:codex, options) when is_map(options) do
    {runtime_ready, runtime_error} = codex_runtime_readiness()

    %{
      runtime_ready: runtime_ready,
      runtime_error: runtime_error,
      network_access_enabled: execution_value(options, :network_access_enabled) == true,
      git_repository_required: execution_value(options, :skip_git_repo_check) != true,
      managed_cargo_cache: managed_cache?(:managed_cargo_cache),
      managed_elixir_caches: %{
        mix_home: managed_cache?(:managed_mix_home),
        mix_archives: managed_cache?(:managed_mix_archives),
        hex_home: managed_cache?(:managed_hex_home),
        rebar_cache: managed_cache?(:managed_rebar_cache),
        rebar_config: managed_cache?(:managed_rebar_config)
      },
      interactive_approvals: false,
      escalation_behavior: :deny_when_provider_cannot_prompt
    }
  end

  def public_execution_policy(_provider, _options), do: %{}

  defp codex_runtime_readiness do
    case Application.get_env(:ouroboros, @codex_readiness_key) do
      {:error, {reason, _message}} when is_atom(reason) -> {false, reason}
      _ready_or_unmanaged -> {true, nil}
    end
  end

  @doc false
  @spec apply_runtime_provider_policy(map(), atom()) :: map()
  def apply_runtime_provider_policy(request, provider) when is_map(request) do
    options = Map.get(request, :provider_options, Map.get(request, "provider_options"))

    case enforce_managed_cli_path(provider, options) do
      protected when is_map(protected) ->
        request
        |> Map.delete("provider_options")
        |> Map.put(:provider_options, protected)

      _unset_or_invalid ->
        request
    end
  end

  defp enforce_managed_cli_path(:codex, options) when is_map(options) do
    case Application.get_env(:ouroboros, @codex_launcher_key) do
      launcher when is_binary(launcher) and launcher != "" ->
        options
        |> Map.delete("cli_path")
        |> Map.put(:cli_path, launcher)

      _unmanaged ->
        options
    end
  end

  defp enforce_managed_cli_path(_provider, options), do: options

  @doc false
  @spec apply_execution_directories(map(), atom()) :: map()
  def apply_execution_directories(request, provider),
    do: apply_execution_directories(request, provider, nil)

  @doc false
  @spec apply_execution_directories(map(), atom(), :request | :session | nil) :: map()
  def apply_execution_directories(request, :codex, defaults_kind) when is_map(request) do
    sandbox_mode = Map.get(request, :sandbox_mode, Map.get(request, "sandbox_mode"))

    if sandbox_mode in [:read_only, "read_only"] do
      # Codex defines --add-dir as another writable root. A stated read-only sandbox
      # must therefore suppress managed and caller-provided add_dirs alike; keeping the
      # environment homes is useful for reads, but none is granted for writes.
      request |> Map.delete("add_dirs") |> Map.put(:add_dirs, [])
    else
      cache_directories = codex_cache_directories()
      configured_directories = configured_default_directories(defaults_kind)

      caller_directories =
        case Map.get(request, :add_dirs, Map.get(request, "add_dirs", [])) do
          dirs when is_list(dirs) -> dirs
          _invalid -> []
        end

      add_dirs = Enum.uniq(cache_directories ++ configured_directories ++ caller_directories)
      request = Map.delete(request, "add_dirs")

      if add_dirs == [] and not Map.has_key?(request, :add_dirs) do
        request
      else
        Map.put(request, :add_dirs, add_dirs)
      end
    end
  end

  def apply_execution_directories(request, _provider, _defaults_kind), do: request

  @doc false
  @spec configure_runtime_cache() :: :ok
  def configure_runtime_cache do
    case Application.get_env(:ouroboros, :data_dir) do
      data_dir when is_binary(data_dir) and data_dir != "" ->
        cache_root = Path.join([data_dir, "provider-cache", "codex"])
        configure_codex_caches(cache_root)

      _unset ->
        :ok
    end
  end

  defp configure_codex_caches(cache_root) do
    providers =
      case Application.get_env(:jido_harness, :provider_config, %{}) do
        value when is_map(value) or is_list(value) -> Map.new(value)
        _invalid -> %{}
      end

    codex =
      case Map.get(providers, :codex, Map.get(providers, "codex", %{})) do
        value when is_map(value) or is_list(value) -> Map.new(value)
        _invalid -> %{}
      end

    previous_injected_directories = previously_injected_cache_directories()

    {env, cache_directories} =
      Enum.reduce(@codex_cache_specs, {config_map(codex, :env), []}, fn spec,
                                                                        {env, directories} ->
        {env, directory} = configure_codex_cache(spec, cache_root, env)
        {env, append_directory(directories, directory)}
      end)

    codex =
      codex
      |> Map.delete("env")
      |> Map.put(:env, env)
      |> remove_injected_cache_defaults(:request_defaults, previous_injected_directories)
      |> remove_injected_cache_defaults(:session_defaults, previous_injected_directories)

    {:ok, codex} = configure_codex_launcher(codex, cache_root, env)
    providers = providers |> Map.delete("codex") |> Map.put(:codex, codex)
    Application.put_env(:jido_harness, :provider_config, providers)
    Application.put_env(:ouroboros, :codex_cache_dirs, cache_directories)
    Application.delete_env(:ouroboros, :codex_injected_cache_dirs)
    :ok
  end

  defp configure_codex_launcher(codex, cache_root, env) do
    previous_launcher = Application.get_env(:ouroboros, @codex_launcher_key)
    previous_upstream = Application.get_env(:ouroboros, @codex_upstream_key)
    launcher = Path.join([cache_root | @codex_launcher_relative_path])

    configured =
      case fetch_config_value(codex, :cli_path) do
        {:ok, value} -> value
        :error -> nil
      end

    policy_args = codex_cache_policy_args(env)

    with {:ok, upstream} <-
           select_codex_upstream(configured, previous_launcher, previous_upstream, launcher),
         :ok <- verify_codex_cache_policy(upstream, policy_args, env),
         :ok <- provision_codex_launcher(launcher, upstream, policy_args, env) do
      Application.put_env(:ouroboros, @codex_launcher_key, launcher)
      Application.put_env(:ouroboros, @codex_upstream_key, upstream)
      Application.delete_env(:ouroboros, @codex_readiness_key)

      {:ok,
       codex
       |> Map.delete("cli_path")
       |> Map.put(:cli_path, launcher)}
    else
      {:error, :no_upstream} ->
        install_codex_refusal_launcher(
          codex,
          launcher,
          {:codex_upstream_unavailable,
           "no safe upstream Codex executable is available; configure the real executable " <>
             "at the node provider boundary and restart"}
        )

      {:error, {kind, _message} = reason}
      when kind in [
             :codex_launcher_recursion,
             :codex_cache_policy_filtered,
             :codex_cache_policy_probe_failed
           ] ->
        install_codex_refusal_launcher(codex, launcher, reason)

      {:error, reason} ->
        refusal =
          {:codex_launcher_unavailable,
           "could not install the managed Codex launcher at #{launcher}: " <>
             format_launcher_error(reason)}

        Logger.warning(
          elem(refusal, 1) <> "; Codex turns will be refused while other providers remain usable"
        )

        install_codex_refusal_launcher(codex, launcher, refusal)
    end
  end

  defp select_codex_upstream(configured, previous_launcher, previous_upstream, launcher) do
    cond do
      nonempty_path?(configured) and configured == previous_launcher ->
        case resolve_codex_upstream(previous_upstream, launcher) do
          {:ok, upstream} -> {:ok, upstream}
          {:error, _unavailable_or_recursive} -> {:ok, discovered_codex(launcher)}
        end

      nonempty_path?(configured) ->
        case resolve_codex_upstream(configured, launcher) do
          {:ok, upstream} ->
            {:ok, upstream}

          {:error, :recursive} ->
            {:error,
             {:codex_launcher_recursion,
              "configured Codex cli_path #{inspect(configured)} resolves to Ouroboros's " <>
                "managed launcher #{launcher}; choose the real upstream executable"}}

          {:error, :not_found} ->
            {:ok, nil}
        end

      is_nil(configured) ->
        {:ok, discovered_codex(launcher)}

      true ->
        {:ok, nil}
    end
  end

  defp discovered_codex(launcher) do
    case resolve_codex_upstream("codex", launcher) do
      {:ok, upstream} -> upstream
      {:error, _unavailable_or_recursive} -> nil
    end
  end

  # `Path.expand/1` is not executable resolution. In particular, a bare `codex` uses
  # PATH and a symlink keeps its own lexical name while still following the managed
  # launcher at exec time. Resolve the former exactly as execvp does and dereference the
  # latter before deciding whether a wrapper would call itself forever.
  defp resolve_codex_upstream(path, launcher) when is_binary(path) and path != "" do
    resolved =
      cond do
        Path.type(path) == :absolute -> Path.expand(path)
        String.contains?(path, "/") -> Path.expand(path)
        true -> System.find_executable(path)
      end

    cond do
      is_nil(resolved) ->
        {:error, :not_found}

      canonical_executable_path(resolved) == canonical_executable_path(launcher) ->
        {:error, :recursive}

      true ->
        {:ok, resolved}
    end
  rescue
    _invalid_path -> {:error, :not_found}
  end

  defp resolve_codex_upstream(_path, _launcher), do: {:error, :not_found}

  defp canonical_executable_path(path) do
    expanded = Path.expand(path)

    case :file.read_link_all(String.to_charlist(expanded)) do
      {:ok, resolved} -> resolved |> List.to_string() |> Path.expand()
      {:error, _reason} -> expanded
    end
  rescue
    _invalid_path -> Path.expand(path)
  end

  defp clear_codex_launcher_state do
    Application.delete_env(:ouroboros, @codex_launcher_key)
    Application.delete_env(:ouroboros, @codex_upstream_key)
    Application.delete_env(:ouroboros, @codex_readiness_key)
  end

  defp discard_stale_launcher(launcher) do
    # This path is beneath the data directory whose RuntimeOwner has already won. A
    # wrapper without a safe upstream must disappear so PATH discovery fails normally
    # instead of finding a stale program that can call itself.
    _ = File.rm(launcher)
  end

  defp install_codex_refusal_launcher(codex, launcher, {_kind, message} = reason) do
    clear_codex_launcher_state()
    discard_stale_launcher(launcher)

    case provision_codex_refusal_launcher(launcher, message) do
      :ok -> :ok
      {:error, _write_reason} -> discard_stale_launcher(launcher)
    end

    # Keep the path authoritative even if the filesystem refused the tiny script: a
    # missing executable is still safer than falling through to an unwrapped Codex.
    # `execution_options/2` and every concrete request boundary pin this path, so an
    # inline provider_options.cli_path cannot bypass either form of refusal.
    Application.put_env(:ouroboros, @codex_launcher_key, launcher)
    Application.put_env(:ouroboros, @codex_readiness_key, {:error, reason})

    Logger.warning(
      "Codex is unavailable in this Ouroboros runtime: #{message}; other providers remain usable"
    )

    {:ok,
     codex
     |> Map.delete("cli_path")
     |> Map.put(:cli_path, launcher)}
  end

  defp codex_cache_policy_args(env) do
    Enum.flat_map(@codex_cache_specs, fn {env_name, _path, _effective, _managed} ->
      case Map.fetch(env, env_name) do
        # JSON strings are valid TOML basic strings for the escapes Jason emits. Passing
        # the complete override as one argv entry also avoids a second shell parse.
        {:ok, value} when is_binary(value) ->
          ["-c", @codex_shell_policy_prefix <> env_name <> "=" <> Jason.encode!(value)]

        _unset_or_invalid ->
          []
      end
    end)
  end

  # Codex applies `set` before `include_only`. A user policy such as
  # `include_only = ["PATH", "HOME"]` therefore removes paths the launcher just pinned.
  # Ouroboros cannot safely reconstruct Codex's layered configuration and must not widen
  # the user's allowlist by replacing it. Exercise the effective policy through Codex's
  # local sandbox command instead; if even one configured cache path is absent, refuse
  # the runtime before a provider consumer can make an out-of-bound write.
  defp verify_codex_cache_policy(upstream, policy_args, env)
       when is_binary(upstream) and upstream != "" do
    pairs = codex_cache_policy_pairs(env)

    if pairs == [] do
      :ok
    else
      script = cache_policy_probe_script(pairs)
      values = Enum.map(pairs, &elem(&1, 1))
      timeout_ms = codex_cache_policy_probe_timeout_ms()

      command =
        [upstream | policy_args] ++
          ["sandbox", "/bin/sh", "-c", script, "ouroboros-cache-policy-probe"] ++ values

      command = Enum.map_join(command, " ", &shell_quote/1)

      supervised =
        codex_supervised_probe(command, timeout_ms, "") <>
          "exit \"$ouroboros_probe_status\"\n"

      case run_cache_policy_probe(supervised, pairs, timeout_ms) do
        {:ok, {_output, 0}} ->
          :ok

        {:ok, {output, status}} ->
          cache_policy_probe_error(output, Enum.map(pairs, &elem(&1, 0)), status)

        {:error, reason} ->
          cache_policy_probe_failed(reason)
      end
    end
  end

  defp verify_codex_cache_policy(_upstream, _policy_args, _env), do: :ok

  defp codex_cache_policy_pairs(env) do
    Enum.flat_map(@codex_cache_specs, fn {env_name, _path, _effective, _managed} ->
      case Map.fetch(env, env_name) do
        {:ok, value} when is_binary(value) and value != "" -> [{env_name, value}]
        _unset_or_invalid -> []
      end
    end)
  end

  defp cache_policy_probe_script(pairs) do
    checks =
      pairs
      |> Enum.with_index(1)
      |> Enum.map_join("\n", fn {{env_name, _value}, index} ->
        "[ \"${#{env_name}+x}\" = x ] && [ \"$#{env_name}\" = \"$#{index}\" ] || " <>
          "missing=\"${missing}#{env_name},\""
      end)

    "missing=\n" <>
      checks <>
      "\nif [ -n \"$missing\" ]; then\n" <>
      "  printf 'OUROBOROS_CACHE_POLICY_MISSING=%s\\n' \"${missing%,}\"\n" <>
      "  exit 78\n" <>
      "fi\n"
  end

  defp cache_policy_probe_error(output, configured_names, status) do
    missing =
      case Regex.run(
             ~r/^OUROBOROS_CACHE_POLICY_MISSING=([A-Z0-9_,]+)$/m,
             output,
             capture: :all_but_first
           ) do
        [names] ->
          names
          |> String.split(",", trim: true)
          |> Enum.filter(&(&1 in configured_names))

        _no_marker ->
          []
      end

    cond do
      missing != [] ->
        {:error,
         {:codex_cache_policy_filtered,
          "Codex's effective shell_environment_policy removed #{Enum.join(missing, ", ")}. " <>
            "Preserve the existing include_only policy and append Ouroboros's configured " <>
            "cache names (#{Enum.join(configured_names, ", ")}), then restart"}}

      String.contains?(output, "OUROBOROS_PROBE_GROUP_UNAVAILABLE=1") ->
        cache_policy_probe_failed(:process_group_unavailable)

      status == 137 ->
        cache_policy_probe_failed(:timeout)

      true ->
        cache_policy_probe_failed(:unexpected_output)
    end
  end

  defp run_cache_policy_probe(script, env, timeout_ms) do
    port =
      Port.open(
        {:spawn_executable, ~c"/bin/sh"},
        [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:args, [~c"-c", String.to_charlist(script)]},
          {:env,
           Enum.map(env, fn {key, value} ->
             {String.to_charlist(key), String.to_charlist(value)}
           end)}
        ]
      )

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    deadline = System.monotonic_time(:millisecond) + timeout_ms + 1_000

    case receive_cache_policy_probe(port, "", deadline) do
      {:ok, result} ->
        {:ok, result}

      :timeout ->
        # The supervisor shell owns no provider work itself. TERM runs its trap, which
        # KILLs only the already-verified probe PGID and reaps both probe and watchdog.
        # The extra outer bound protects boot even if a future shell change regresses
        # the internal watchdog.
        _ = System.cmd("/bin/kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)
        _ = receive_cache_policy_probe(port, "", System.monotonic_time(:millisecond) + 1_000)
        if Port.info(port), do: Port.close(port)
        {:error, :timeout}
    end
  rescue
    _port_error -> {:error, :command_failed}
  end

  defp receive_cache_policy_probe(port, output, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} ->
        receive_cache_policy_probe(port, output <> data, deadline)

      {^port, {:exit_status, status}} ->
        {:ok, {output, status}}
    after
      remaining -> :timeout
    end
  end

  defp codex_cache_policy_probe_timeout_ms do
    case Application.get_env(
           :ouroboros,
           :codex_cache_policy_probe_timeout_ms,
           @codex_cache_policy_probe_timeout_ms
         ) do
      timeout when is_integer(timeout) and timeout > 0 -> min(timeout, 30_000)
      _invalid -> @codex_cache_policy_probe_timeout_ms
    end
  end

  defp cache_policy_probe_failed(reason) do
    {:error,
     {:codex_cache_policy_probe_failed,
      "could not verify Codex's effective shell environment with `codex sandbox`; " <>
        "the managed cache launcher was replaced by a Codex-only refusal " <>
        "(probe #{reason})"}}
  end

  defp provision_codex_launcher(_launcher, upstream, _policy_args, _env)
       when not is_binary(upstream),
       do: {:error, :no_upstream}

  defp provision_codex_launcher(_launcher, "", _policy_args, _env),
    do: {:error, :no_upstream}

  defp provision_codex_launcher(launcher, upstream, policy_args, env) do
    fixed_args = Enum.map_join(policy_args, " ", &shell_quote/1)
    fixed_args = if fixed_args == "", do: "", else: fixed_args <> " "
    preflight = codex_launcher_preflight(upstream, policy_args, env)

    contents =
      "#!/bin/sh\n" <>
        preflight <>
        "exec #{shell_quote(upstream)} #{fixed_args}\"$@\"\n"

    write_codex_launcher(launcher, contents)
  end

  defp codex_launcher_preflight(upstream, policy_args, env) do
    pairs = codex_cache_policy_pairs(env)

    if pairs == [] do
      ""
    else
      script = cache_policy_probe_script(pairs)
      values = Enum.map(pairs, &elem(&1, 1))

      command =
        [upstream | policy_args] ++
          ["sandbox", "/bin/sh", "-c", script, "ouroboros-cache-policy-probe"] ++ values

      command = Enum.map_join(command, " ", &shell_quote/1)

      timeout =
        codex_cache_policy_probe_timeout_ms()
        |> Kernel./(1_000)
        |> :erlang.float_to_binary(decimals: 3)

      names = pairs |> Enum.map(&elem(&1, 0)) |> Enum.join(", ")

      refusal =
        "Ouroboros refused Codex: this workspace's effective shell_environment_policy " <>
          "could not be verified before dispatch because the local `codex sandbox` " <>
          "preflight failed or exceeded #{timeout} seconds. Preserve the existing " <>
          "include_only entries and append #{names}, ensure `codex sandbox` works " <>
          "locally, then retry"

      # The probe is a local Codex configuration operation: it never authenticates,
      # starts a model turn, or uses the network. It inherits the eventual command's cwd
      # so project configuration is covered. The staged child cannot exec Codex until it
      # is stopped and verified as the leader of a process group distinct from the
      # wrapper. Timeout and cancellation can then kill that exact group without ever
      # signalling Harness's provider group. Once the check passes, the final exec
      # preserves the real provider argv, exit status, and signals.
      supervised =
        codex_supervised_probe(command, codex_cache_policy_probe_timeout_ms(), ">/dev/null 2>&1")

      supervised <>
        "if [ \"$ouroboros_probe_status\" -ne 0 ]; then\n" <>
        "  printf '%s\\n' #{shell_quote(refusal)} >&2\n" <>
        "  exit 78\n" <>
        "fi\n"
    end
  end

  # A non-interactive `/bin/sh` does not portably create a process group for `&`: macOS
  # supports monitor mode while Debian's dash may not. Stage an inert, self-stopped shell
  # first. Job control is accepted only when ps proves PGID == PID and state `T`; Linux
  # otherwise retries through an absolute util-linux `setsid`. No upstream command runs
  # before that proof, so an unavailable isolation mechanism can be refused by killing a
  # child that has no descendants. The direct child remains stopped and unreaped until
  # CONT, eliminating both PID-reuse and reparenting races at the signalling boundary.
  defp codex_supervised_probe(command, timeout_ms, redirect) do
    sleep_seconds = div(timeout_ms + 999, 1_000)

    staged = shell_quote("/bin/kill -STOP \"$$\"\nexec #{command}\n")

    watchdog_staged =
      shell_quote(
        "/bin/kill -STOP \"$$\"\n" <>
          "/bin/sleep #{sleep_seconds}\n" <>
          "/bin/kill -KILL -- \"-$1\" 2>/dev/null\n"
      )

    isolation = Application.get_env(:ouroboros, :codex_probe_isolation, :auto)

    job_control_stage =
      if isolation == :auto do
        "set -m 2>/dev/null\n" <>
          "ouroboros_spawning_probe=true\n" <>
          "/bin/sh -c #{staged} #{redirect} &\n" <>
          "ouroboros_probe_pid=$!\n" <>
          "ouroboros_spawning_probe=false\n" <>
          "if ouroboros_await_isolated_probe; then\n" <>
          "  ouroboros_probe_job_control=true\n" <>
          "else\n" <>
          "  ouroboros_kill_probe_group\n" <>
          "  wait \"$ouroboros_probe_pid\" 2>/dev/null\n" <>
          "  ouroboros_probe_pid=\n" <>
          "  ouroboros_probe_pgid=\n" <>
          "  set +m 2>/dev/null\n" <>
          "fi\n"
      else
        "set +m 2>/dev/null\n"
      end

    setsid_paths =
      if isolation == :unavailable do
        []
      else
        Application.get_env(
          :ouroboros,
          :codex_probe_setsid_paths,
          ["/usr/bin/setsid", "/bin/setsid"]
        )
        |> List.wrap()
        |> Enum.filter(&(is_binary(&1) and Path.type(&1) == :absolute))
      end

    setsid_discovery =
      Enum.map_join(setsid_paths, "", fn path ->
        quoted = shell_quote(path)

        "  if [ -z \"$ouroboros_setsid\" ] && [ -x #{quoted} ]; then\n" <>
          "    ouroboros_setsid=#{quoted}\n" <>
          "  fi\n"
      end)

    ~S"""
    ouroboros_probe_pid=
    ouroboros_probe_pgid=
    ouroboros_watchdog_pid=
    ouroboros_watchdog_pgid=
    ouroboros_spawning_probe=false
    ouroboros_spawning_watchdog=false
    ouroboros_probe_job_control=false
    ouroboros_read_probe_state() {
      /bin/ps -p "$1" -o pgid= -o stat= 2>/dev/null | /usr/bin/awk 'NR == 1 { print $1 ":" $2 }'
    }
    ouroboros_read_child_pgid() {
      /bin/ps -p "$1" -o ppid= -o pgid= 2>/dev/null | /usr/bin/awk -v ouroboros_owner="$$" \
        'NR == 1 && $1 == ouroboros_owner { print $2 }'
    }
    ouroboros_await_isolated_probe() {
      ouroboros_probe_attempt=0
      while [ "$ouroboros_probe_attempt" -lt 100 ]; do
        ouroboros_probe_state=$(ouroboros_read_probe_state "$ouroboros_probe_pid")
        ouroboros_candidate_pgid=${ouroboros_probe_state%%:*}
        ouroboros_candidate_state=${ouroboros_probe_state#*:}
        case "$ouroboros_candidate_state" in
          *T*)
            if [ "$ouroboros_candidate_pgid" = "$ouroboros_probe_pid" ]; then
              ouroboros_probe_pgid=$ouroboros_candidate_pgid
              return 0
            fi
            ;;
        esac
        /bin/kill -0 "$ouroboros_probe_pid" 2>/dev/null || return 1
        ouroboros_probe_attempt=$((ouroboros_probe_attempt + 1))
        /bin/sleep 0.005
      done
      return 1
    }
    ouroboros_await_isolated_watchdog() {
      ouroboros_watchdog_attempt=0
      while [ "$ouroboros_watchdog_attempt" -lt 100 ]; do
        ouroboros_watchdog_state=$(ouroboros_read_probe_state "$ouroboros_watchdog_pid")
        ouroboros_candidate_pgid=${ouroboros_watchdog_state%%:*}
        ouroboros_candidate_state=${ouroboros_watchdog_state#*:}
        case "$ouroboros_candidate_state" in
          *T*)
            if [ "$ouroboros_candidate_pgid" = "$ouroboros_watchdog_pid" ]; then
              ouroboros_watchdog_pgid=$ouroboros_candidate_pgid
              return 0
            fi
            ;;
        esac
        /bin/kill -0 "$ouroboros_watchdog_pid" 2>/dev/null || return 1
        ouroboros_watchdog_attempt=$((ouroboros_watchdog_attempt + 1))
        /bin/sleep 0.005
      done
      return 1
    }
    ouroboros_kill_probe_group() {
      ouroboros_current_pgid=$(ouroboros_read_child_pgid "$ouroboros_probe_pid")
      if [ -n "$ouroboros_probe_pid" ] && [ "$ouroboros_probe_pgid" = "$ouroboros_probe_pid" ] && \
          [ "$ouroboros_current_pgid" = "$ouroboros_probe_pgid" ]; then
        /bin/kill -KILL -- "-$ouroboros_probe_pgid" 2>/dev/null
      elif [ -n "$ouroboros_probe_pid" ] && [ -n "$ouroboros_current_pgid" ]; then
        /bin/kill -KILL "$ouroboros_probe_pid" 2>/dev/null
      fi
    }
    ouroboros_kill_watchdog_group() {
      ouroboros_current_pgid=$(ouroboros_read_child_pgid "$ouroboros_watchdog_pid")
      if [ -n "$ouroboros_watchdog_pid" ] && [ "$ouroboros_watchdog_pgid" = "$ouroboros_watchdog_pid" ] && \
          [ "$ouroboros_current_pgid" = "$ouroboros_watchdog_pgid" ]; then
        /bin/kill -KILL -- "-$ouroboros_watchdog_pgid" 2>/dev/null
      elif [ -n "$ouroboros_watchdog_pid" ] && [ -n "$ouroboros_current_pgid" ]; then
        /bin/kill -KILL "$ouroboros_watchdog_pid" 2>/dev/null
      fi
    }
    ouroboros_cancel_preflight() {
      ouroboros_cancel_signal=$1
      trap - TERM HUP INT
      if [ "$ouroboros_spawning_probe" = true ] && [ -z "$ouroboros_probe_pid" ] && [ -n "$!" ]; then
        ouroboros_probe_pid=$!
      fi
      if [ "$ouroboros_spawning_watchdog" = true ] && [ -z "$ouroboros_watchdog_pid" ] && [ -n "$!" ]; then
        if [ "$!" != "$ouroboros_probe_pid" ]; then
          ouroboros_watchdog_pid=$!
        fi
      fi
      ouroboros_kill_watchdog_group
      ouroboros_kill_probe_group
      if [ -n "$ouroboros_probe_pid" ]; then
        wait "$ouroboros_probe_pid" 2>/dev/null
      fi
      if [ -n "$ouroboros_watchdog_pid" ]; then
        wait "$ouroboros_watchdog_pid" 2>/dev/null
      fi
      [ "$ouroboros_probe_job_control" = true ] && set +m 2>/dev/null
      case "$ouroboros_cancel_signal" in
        HUP) ouroboros_cancel_status=129 ;;
        INT) ouroboros_cancel_status=130 ;;
        TERM) ouroboros_cancel_status=143 ;;
      esac
      /bin/kill "-$ouroboros_cancel_signal" "$$" 2>/dev/null
      exit "$ouroboros_cancel_status"
    }
    trap 'ouroboros_cancel_preflight TERM' TERM
    trap 'ouroboros_cancel_preflight HUP' HUP
    trap 'ouroboros_cancel_preflight INT' INT
    """ <>
      job_control_stage <>
      "if [ -z \"$ouroboros_probe_pgid\" ]; then\n" <>
      "  ouroboros_setsid=\n" <>
      setsid_discovery <>
      "  if [ -n \"$ouroboros_setsid\" ]; then\n" <>
      "    ouroboros_spawning_probe=true\n" <>
      "    \"$ouroboros_setsid\" /bin/sh -c #{staged} #{redirect} &\n" <>
      "    ouroboros_probe_pid=$!\n" <>
      "    ouroboros_spawning_probe=false\n" <>
      "    ouroboros_await_isolated_probe\n" <>
      "  fi\n" <>
      "fi\n" <>
      "if [ -n \"$ouroboros_probe_pid\" ] && " <>
      "[ \"$ouroboros_probe_pgid\" = \"$ouroboros_probe_pid\" ]; then\n" <>
      "  ouroboros_spawning_watchdog=true\n" <>
      "  if [ \"$ouroboros_probe_job_control\" = true ]; then\n" <>
      "    /bin/sh -c #{watchdog_staged} ouroboros-probe-watchdog " <>
      "\"$ouroboros_probe_pgid\" &\n" <>
      "  else\n" <>
      "    \"$ouroboros_setsid\" /bin/sh -c #{watchdog_staged} " <>
      "ouroboros-probe-watchdog \"$ouroboros_probe_pgid\" &\n" <>
      "  fi\n" <>
      "  ouroboros_watchdog_pid=$!\n" <>
      "  ouroboros_spawning_watchdog=false\n" <>
      "  if ouroboros_await_isolated_watchdog; then\n" <>
      "    /bin/kill -CONT -- \"-$ouroboros_watchdog_pgid\" 2>/dev/null\n" <>
      "    /bin/kill -CONT -- \"-$ouroboros_probe_pgid\" 2>/dev/null\n" <>
      "    wait \"$ouroboros_probe_pid\" 2>/dev/null\n" <>
      "    ouroboros_probe_status=$?\n" <>
      "    ouroboros_probe_pid=\n" <>
      "    ouroboros_probe_pgid=\n" <>
      "    ouroboros_kill_watchdog_group\n" <>
      "    wait \"$ouroboros_watchdog_pid\" 2>/dev/null\n" <>
      "    ouroboros_watchdog_pid=\n" <>
      "    ouroboros_watchdog_pgid=\n" <>
      "  else\n" <>
      "    ouroboros_kill_watchdog_group\n" <>
      "    wait \"$ouroboros_watchdog_pid\" 2>/dev/null\n" <>
      "    ouroboros_watchdog_pid=\n" <>
      "    ouroboros_watchdog_pgid=\n" <>
      "    ouroboros_kill_probe_group\n" <>
      "    wait \"$ouroboros_probe_pid\" 2>/dev/null\n" <>
      "    ouroboros_probe_pid=\n" <>
      "    ouroboros_probe_pgid=\n" <>
      "    printf '%s\\n' 'OUROBOROS_PROBE_GROUP_UNAVAILABLE=1' >&2\n" <>
      "    ouroboros_probe_status=78\n" <>
      "  fi\n" <>
      "else\n" <>
      "  ouroboros_kill_probe_group\n" <>
      "  if [ -n \"$ouroboros_probe_pid\" ]; then " <>
      "wait \"$ouroboros_probe_pid\" 2>/dev/null; fi\n" <>
      "  ouroboros_probe_pid=\n" <>
      "  ouroboros_probe_pgid=\n" <>
      "  printf '%s\\n' 'OUROBOROS_PROBE_GROUP_UNAVAILABLE=1' >&2\n" <>
      "  ouroboros_probe_status=78\n" <>
      "fi\n" <>
      "[ \"$ouroboros_probe_job_control\" = true ] && set +m 2>/dev/null\n" <>
      "trap - TERM HUP INT\n"
  end

  defp provision_codex_refusal_launcher(launcher, message) do
    contents =
      "#!/bin/sh\n" <>
        "printf '%s\\n' #{shell_quote("Ouroboros refused Codex: " <> message)} >&2\n" <>
        "exit 78\n"

    write_codex_launcher(launcher, contents)
  end

  defp write_codex_launcher(launcher, contents) do
    temporary =
      launcher <> ".tmp-#{System.unique_integer([:positive, :monotonic])}"

    try do
      with :ok <- File.mkdir_p(Path.dirname(launcher)),
           :ok <- File.write(temporary, contents, [:binary, :exclusive, :sync]),
           :ok <- File.chmod(temporary, 0o700),
           {:ok, %{type: :regular, mode: mode}} <- File.lstat(temporary),
           true <- Bitwise.band(mode, 0o777) == 0o700,
           :ok <- File.rename(temporary, launcher) do
        :ok
      else
        false -> {:error, :unsafe_permissions}
        {:ok, stat} -> {:error, {:unsafe_type, stat.type}}
        {:error, reason} -> {:error, reason}
      end
    after
      _ = File.rm(temporary)
    end
  end

  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\"'\"'") <> "'"

  defp format_launcher_error(:unsafe_permissions), do: "result did not have mode 0700"
  defp format_launcher_error({:unsafe_type, type}), do: "result was #{inspect(type)}, not a file"
  defp format_launcher_error(reason), do: to_string(:file.format_error(reason))

  defp configure_codex_cache(
         {env_name, relative_path, effective_key, managed_key},
         cache_root,
         env
       ) do
    managed_path = Path.join([cache_root | relative_path])
    previous_managed_path = Application.get_env(:ouroboros, managed_key)

    managed_env? =
      nonempty_path?(previous_managed_path) and
        Map.get(env, env_name) == previous_managed_path

    if Map.has_key?(env, env_name) and not managed_env? do
      operator_cache(env_name, effective_key, managed_key, env)
    else
      env = if managed_env?, do: Map.delete(env, env_name), else: env
      managed_cache(env_name, managed_path, effective_key, managed_key, env)
    end
  end

  defp operator_cache(env_name, effective_key, managed_key, env) do
    Application.delete_env(:ouroboros, managed_key)

    case Map.fetch!(env, env_name) do
      path when is_binary(path) and path != "" ->
        if Path.type(path) == :absolute do
          Application.put_env(:ouroboros, effective_key, path)
          {env, path}
        else
          Application.delete_env(:ouroboros, effective_key)

          Logger.warning(
            "Codex #{env_name} has an operator-supplied relative path; Ouroboros left it " <>
              "unchanged and did not grant an ambiguous external directory"
          )

          {env, nil}
        end

      _invalid ->
        Application.delete_env(:ouroboros, effective_key)

        Logger.warning(
          "Codex #{env_name} has an operator-supplied value that is not a non-empty path; " <>
            "Ouroboros left it unchanged and cannot authorize it"
        )

        {env, nil}
    end
  end

  defp managed_cache(env_name, path, effective_key, managed_key, env) do
    case ensure_writable_directory(path) do
      :ok ->
        Application.put_env(:ouroboros, managed_key, path)
        Application.put_env(:ouroboros, effective_key, path)
        {Map.put(env, env_name, path), path}

      {:error, reason} ->
        Application.delete_env(:ouroboros, managed_key)
        Application.delete_env(:ouroboros, effective_key)

        Logger.warning(
          "Codex #{env_name} directory #{path} is unavailable: #{:file.format_error(reason)}; " <>
            "turns using that tool may need a workspace-local #{env_name}"
        )

        {env, nil}
    end
  end

  # Older Ouroboros builds injected the managed Cargo directory into Harness defaults.
  # Remove only paths this runtime previously injected; operator defaults remain intact.
  # New requests receive managed grants at the state boundary where sandbox_mode is known.
  defp remove_injected_cache_defaults(config, field, previous_directories) do
    case fetch_config_value(config, field) do
      :error ->
        # Cache grants belong on concrete requests, where the sandbox is known. Do not
        # create an empty Harness default merely as a side effect of cache setup.
        config

      {:ok, configured} when is_map(configured) or is_list(configured) ->
        defaults = Map.new(configured)

        defaults =
          case fetch_config_value(defaults, :add_dirs) do
            {:ok, directories} when is_list(directories) ->
              defaults
              |> Map.delete("add_dirs")
              |> Map.put(:add_dirs, directories -- previous_directories)

            {:ok, invalid} ->
              # Preserve invalid operator input so Harness can reject it honestly instead
              # of cache setup silently turning it into an empty list.
              defaults |> Map.delete("add_dirs") |> Map.put(:add_dirs, invalid)

            :error ->
              defaults
          end

        config
        |> Map.delete(Atom.to_string(field))
        |> Map.put(field, defaults)

      {:ok, invalid} ->
        config |> Map.delete(Atom.to_string(field)) |> Map.put(field, invalid)
    end
  end

  defp previously_injected_cache_directories do
    case Application.get_env(:ouroboros, :codex_injected_cache_dirs) do
      directories when is_list(directories) -> Enum.filter(directories, &absolute_path?/1)
      _unset -> legacy_injected_cargo_directory()
    end
  end

  defp legacy_injected_cargo_directory do
    case Application.get_env(:ouroboros, :managed_cargo_cache) do
      path when is_binary(path) -> if absolute_path?(path), do: [path], else: []
      _unset -> []
    end
  end

  defp ensure_writable_directory(path) do
    probe =
      Path.join(
        path,
        ".ouroboros-write-probe-#{System.unique_integer([:positive, :monotonic])}"
      )

    with :ok <- File.mkdir_p(path) do
      try do
        File.write(probe, "writable", [:binary, :exclusive, :sync])
      after
        _ = File.rm(probe)
      end
    end
  end

  defp append_directory(directories, nil), do: directories
  defp append_directory(directories, directory), do: Enum.uniq(directories ++ [directory])

  defp configured_default_directories(kind) when kind in [:request, :session] do
    field = if kind == :request, do: :request_defaults, else: :session_defaults

    providers =
      case Application.get_env(:jido_harness, :provider_config, %{}) do
        value when is_map(value) or is_list(value) -> Map.new(value)
        _invalid -> %{}
      end

    defaults = providers |> config_map(:codex) |> config_map(field)

    case Map.get(defaults, :add_dirs, Map.get(defaults, "add_dirs", [])) do
      # These are operator-authored Harness defaults, not paths Ouroboros inferred.
      # Preserve their values and order exactly; Harness remains responsible for
      # validating them. Otherwise our explicit cache grants would override and erase
      # a relative default before Harness ever saw it.
      directories when is_list(directories) -> directories
      _invalid -> []
    end
  end

  defp configured_default_directories(_kind), do: []

  defp codex_cache_directories do
    case Application.get_env(:ouroboros, :codex_cache_dirs) do
      directories when is_list(directories) ->
        Enum.filter(directories, &absolute_path?/1)

      _unset ->
        case Application.get_env(:ouroboros, :codex_cargo_home) do
          cargo_home when is_binary(cargo_home) and cargo_home != "" ->
            if Path.type(cargo_home) == :absolute, do: [cargo_home], else: []

          _unset ->
            []
        end
    end
  end

  defp managed_cache?(key), do: :ouroboros |> Application.get_env(key) |> absolute_path?()

  defp nonempty_path?(path), do: is_binary(path) and path != ""
  defp absolute_path?(path), do: nonempty_path?(path) and Path.type(path) == :absolute

  defp config_map(config, field) do
    case Map.get(config, field, Map.get(config, Atom.to_string(field), %{})) do
      value when is_map(value) or is_list(value) -> Map.new(value)
      _invalid -> %{}
    end
  end

  defp fetch_config_value(config, field) do
    cond do
      Map.has_key?(config, field) ->
        {:ok, Map.fetch!(config, field)}

      Map.has_key?(config, Atom.to_string(field)) ->
        {:ok, Map.fetch!(config, Atom.to_string(field))}

      true ->
        :error
    end
  end

  defp normalize_default_keys(options, :codex) do
    Map.new(options, fn
      {"skip_git_repo_check", value} -> {:skip_git_repo_check, value}
      {"network_access_enabled", value} -> {:network_access_enabled, value}
      pair -> pair
    end)
  end

  defp normalize_default_keys(options, _provider), do: options

  defp execution_value(options, key),
    do: Map.get(options, key, Map.get(options, Atom.to_string(key)))

  defp provider_defaults(provider, fallback) do
    case Application.get_env(:ouroboros, :provider_execution_defaults, @execution_defaults) do
      configured when is_map(configured) ->
        case Map.get(configured, provider, fallback) do
          defaults when is_map(defaults) -> defaults
          _invalid -> fallback
        end

      _invalid ->
        Map.get(@execution_defaults, provider, fallback)
    end
  end

  @doc """
  Returns the `approval_mode` and `sandbox_mode` a request for `provider` may carry.

  Options the caller stated in `opts` are returned unchanged. Options the caller left
  unset take the plane's default when the provider can accept it. On the interactive
  plane an unacceptable default is omitted from the result; on the coding plane it is
  refused, and so is a stated value the provider cannot enforce.

  When the provider's spec cannot be resolved — an unregistered atom, or a session
  transport no adapter declares — the defaults are returned as they always were, so the
  harness produces its own error about the thing that is actually wrong.
  """
  @spec safety_options(term(), keyword(), plane()) :: {:ok, keyword()} | {:error, term()}
  def safety_options(provider, opts, plane) when is_list(opts) do
    capability = capability(provider, plane)

    # A refusal names every option the provider cannot take, not just the first. Amp and
    # Kimi can take neither, and answering them one at a time would send the operator
    # around the loop twice to learn one thing.
    {taken, unsupported} =
      Enum.reduce(@plane_defaults, {[], []}, fn {field, plane_default}, {taken, unsupported} ->
        stated? = Keyword.has_key?(opts, field)
        value = Keyword.get(opts, field, plane_default)

        case {plane, evaluate(capability, field, value)} do
          {{:interactive, _transport}, {:unsupported, _accepted}} when not stated? ->
            {taken, unsupported}

          {:coding, {:unsupported, accepted}} ->
            {taken, unsupported ++ [refused(field, value, stated?, accepted)]}

          _supported_or_unresolvable ->
            {taken ++ [{field, value}], unsupported}
        end
      end)

    if unsupported == [],
      do: {:ok, taken},
      else: {:error, refusal(provider, unsupported)}
  end

  # The options this provider declares for this plane, and the value allowlists that
  # narrow them. Resolved once per call: `Registry.spec/1` re-parses the adapter's spec
  # every time it is asked.
  defp capability(provider, plane) do
    with {:ok, spec} <- Registry.spec(provider),
         {:ok, declared} <- normalized_options(spec, plane) do
      {declared, spec.normalized_values}
    else
      _unresolvable -> :unresolvable
    end
  end

  defp evaluate(:unresolvable, _field, _value), do: :unknown

  defp evaluate({declared, allowlists}, field, value) do
    allowed = Map.get(allowlists, field)

    cond do
      value in @unset_values -> :supported
      field not in declared -> {:unsupported, [:default]}
      is_nil(allowed) -> :supported
      value in allowed -> :supported
      true -> {:unsupported, allowed}
    end
  end

  # A run is validated against the adapter's own list and nothing else.
  defp normalized_options(spec, :coding), do: {:ok, spec.normalized_options}

  # A session is validated against the transport the manager will select, which inherits
  # the adapter's list only when it declares `:adapter`. A transport name no adapter
  # declares is left unresolved on purpose: the harness refuses it by name, and that is a
  # better error than anything this module could invent about sandboxes.
  defp normalized_options(spec, {:interactive, transport}) do
    selected = transport || spec.default_session_transport || first_transport(spec)

    case Enum.find(spec.session_transports, &(&1.name == selected)) do
      %{session_options: :adapter} -> {:ok, spec.normalized_options}
      %{session_options: options} -> {:ok, options}
      # The manager synthesizes a managed transport for an adapter that declares none,
      # and that synthetic transport inherits the adapter's list.
      nil when selected == :managed -> {:ok, spec.normalized_options}
      nil -> :error
    end
  end

  defp first_transport(spec) do
    case spec.session_transports do
      [transport | _rest] -> transport.name
      [] -> :managed
    end
  end

  defp refused(field, value, stated?, accepted) do
    %{
      field: field,
      value: value,
      source: if(stated?, do: :stated, else: :plane_default),
      accepted_values: accepted
    }
  end

  defp refusal(provider, unsupported) do
    override = Enum.map_join(unsupported, ", ", &"#{&1.field}: :default")

    {:unsupported_safety_options,
     %{
       plane: :coding,
       provider: provider,
       options: unsupported,
       override: override,
       message: message(provider, unsupported, override)
     }}
  end

  # The message is the whole point of refusing here rather than letting the harness say
  # "provider does not support normalized option": it names the plane that chose the
  # value, and the one spelling that accepts the provider's own behavior instead.
  defp message(provider, unsupported, override) do
    Enum.map_join(unsupported, " ", &clause(provider, &1)) <>
      " The coding plane refuses rather than silently downgrading a policy it promised," <>
      " so the downgrade has to be typed out: pass #{override} to accept " <>
      "#{inspect(provider)}'s own behavior."
  end

  defp clause(provider, %{source: :plane_default} = refused) do
    "#{inspect(provider)} cannot enforce the coding plane's default #{refused.field}: " <>
      "#{inspect(refused.value)}; it accepts #{inspect(refused.accepted_values)}."
  end

  defp clause(provider, %{source: :stated} = refused) do
    "#{inspect(provider)} cannot enforce #{refused.field}: #{inspect(refused.value)}; " <>
      "it accepts #{inspect(refused.accepted_values)}."
  end
end

defmodule Ouroboros.Provider.RuntimeCache do
  @moduledoc false

  use GenServer

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    server_options =
      case Keyword.fetch(opts, :name) do
        {:ok, nil} -> []
        {:ok, name} -> [name: name]
        :error -> [name: __MODULE__]
      end

    GenServer.start_link(__MODULE__, opts, server_options)
  end

  @impl true
  def init(opts) do
    configure = Keyword.get(opts, :configure, &Ouroboros.Provider.configure_runtime_cache/0)

    case configure.() do
      :ok -> {:ok, :configured}
      {:error, reason} -> {:stop, reason}
      other -> {:stop, {:invalid_provider_runtime_cache_result, other}}
    end
  end
end
