defmodule Ouroboros.Provider.Native.Exec do
  @moduledoc """
  One bounded child-process runner for the native provider.

  `grep`, hooks, checks, and the native `bash` tool all cross this boundary. Every child
  runs through `priv/provider-exec` for the workspace umask and through Erlexec in its own
  process group. A deadline signals that whole group with TERM, waits a bounded grace,
  then sends KILL. A shell child does not survive merely because it was backgrounded.

  Output is bounded while the process runs and while it is being drained after a signal.
  stdout and stderr can be merged for ordinary argv commands or retained separately for
  hook contracts. No temporary stderr file exists for an untrusted command to fill.

  `run/3` takes an executable and argv with no shell. `run_shell/2` takes an operator
  command line through `/bin/sh -c`; stdin is supplied through one private temporary file
  so a command that reads to EOF does not wait for an open port.
  """

  @default_timeout_ms 60_000
  @default_max_bytes 1024 * 1024
  @max_timeout_ms 600_000
  @max_max_bytes 64 * 1024 * 1024
  @drain_ms 500
  @exit_drain_ms 50
  @exit_drain_deadline_ms @exit_drain_ms * 4
  @startup_timeout_ms 5_000
  @release_runtime_env ~w(BINDIR EMU PROGNAME ROOTDIR)

  # A native tool is an operator-controlled child, not part of the service process. It
  # needs the ordinary login and toolchain environment, but it must not inherit model
  # keys, database URLs, deployment credentials, or arbitrary application settings from
  # the daemon. Keep this list deliberately about process execution and builds. Explicit
  # `env:` entries still work (after the credential checks below), which is how a caller
  # supplies a command-specific setting without widening ambient inheritance again.
  @inherited_env_names MapSet.new(~w(
                           AR AS CC CFLAGS CI CLICOLOR CLICOLOR_FORCE COLORTERM
                           COMMAND_MODE CPP CPPFLAGS CPATH CXX CXXFLAGS
                           C_INCLUDE_PATH CPLUS_INCLUDE_PATH DEVELOPER_DIR EDITOR
                           FORCE_COLOR GITLAB_CI GIT_EDITOR GIT_PAGER HOME INFOPATH
                           LANG LANGUAGE LD LDFLAGS LD_LIBRARY_PATH LESS LIBRARY_PATH
                           LOGNAME MAKE MAKEFLAGS MAKELEVEL MANPAGER MallocNanoZone
                           NINJA_STATUS NM NO_COLOR OBJCOPY OBJDUMP OLDPWD OSLogRateLimit
                           PAGER PATH PREFIX PWD RANLIB SDKROOT SHELL SHLVL STRIP
                           TEAMCITY_VERSION TERM TERM_PROGRAM TERM_PROGRAM_VERSION
                           TF_BUILD TMP TMPDIR TEMP TRAVIS USER VISUAL
                           __CF_USER_TEXT_ENCODING
                         ))

  @inherited_env_prefixes ~w(
    ANDROID_ ASDF_ BUNDLE_ BUN_ CARGO_ CMAKE_ CONDA_ DENO_ DOTNET_ ELIXIR_ ERL_
    GEM_ GOENV_ GRADLE_ HEX_ HOMEBREW_ JAVA_ JDK_ KERL_ LC_ MAVEN_ MESON_ MISE_
    MIX_ M2_ NODE_ NPM_ NUGET_ NVM_ OPENSSL_ PIP_ PKG_CONFIG_ PNPM_ POETRY_
    PYENV_ PYTHON_ RBENV_ REBAR_ RUBY_ RUST_ RUSTUP_ SWIFT_ UV_ VIRTUAL_ENV
    VOLTA_ XCODE_ YARN_
  )

  @type result :: %{
          status: integer(),
          output: binary(),
          stderr: binary(),
          timed_out?: boolean(),
          truncated?: boolean()
        }

  @doc """
  Runs `executable` with `args`, with no shell between them.

  Options: `cd`, `env` (non-credential `{name, value}` string pairs), `timeout_ms`
  (default #{@default_timeout_ms}, capped at #{@max_timeout_ms}), `max_bytes` (default
  #{@default_max_bytes}). Ambient inheritance is limited to login, terminal, and
  toolchain variables; arbitrary daemon settings and credentials do not cross this
  boundary.

  stdout and stderr are merged: the callers of this shape want ripgrep's diagnostics
  interleaved where they happened, and none of them reads stderr as a contract.
  """
  @spec run(String.t(), [String.t()], keyword()) :: {:ok, result()} | {:error, term()}
  def run(executable, args, opts \\ []) when is_binary(executable) and is_list(args) do
    with {:ok, wrapper} <- wrapper() do
      spawn_and_collect(wrapper, [executable | args], false, opts)
    end
  end

  @doc """
  Runs one command line through `/bin/sh -c`, with optional stdin and stderr kept apart.

  Same options as `run/3`, plus `stdin`. The result's `stderr` carries whatever the
  command wrote to file descriptor 2, capped like stdout, which is what makes `exit 2`
  usable as a hook's block-with-a-reason.
  """
  @spec run_shell(String.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def run_shell(command, opts \\ []) when is_binary(command) do
    with {:ok, wrapper} <- wrapper(),
         {:ok, stdin_path} <- scratch_file(stdin_of(opts)) do
      script = "exec <" <> shell_quote(stdin_path) <> "\n" <> command

      try do
        spawn_and_collect(wrapper, ["/bin/sh", "-c", script], true, opts)
      after
        _ = File.rm(stdin_path)
      end
    end
  end

  @doc "Where an executable lives on this node's PATH, or `nil`."
  @spec which(String.t()) :: String.t() | nil
  def which(name) when is_binary(name), do: System.find_executable(name)

  # ---------------------------------------------------------------- internals

  alias Jido.Harness.ProcessDriver.Erlexec

  defp spawn_and_collect(wrapper, args, separate_stderr?, opts) do
    timeout = timeout_ms(opts)
    max_bytes = max_bytes(opts)

    options =
      [
        :monitor,
        {:group, 0},
        :kill_group,
        {:stdin, :close},
        {:stdout, self()},
        if(separate_stderr?, do: {:stderr, self()}, else: {:stderr, :stdout})
      ]
      |> maybe_cd(Keyword.get(opts, :cd))
      |> maybe_env(Keyword.get(opts, :env))

    case :exec.run([wrapper | args], options, @startup_timeout_ms) do
      {:ok, exec_pid, os_pid} ->
        state = empty_output()
        deadline = System.monotonic_time(:millisecond) + timeout

        case collect(exec_pid, os_pid, state, max_bytes, deadline) do
          {:ok, output, status} ->
            {:ok, result(output, status, false)}

          {:timeout, output} ->
            output = terminate_group(exec_pid, os_pid, output, max_bytes)
            {:ok, result(output, 124, true)}
        end

      {:error, reason} ->
        {:error, {:spawn_failed, reason}}
    end
  rescue
    error -> {:error, {:spawn_failed, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:spawn_failed, kind, reason}}
  end

  defp terminate_group(exec_pid, os_pid, output, max_bytes) do
    _ = Erlexec.signal(os_pid, :sigterm)
    deadline = System.monotonic_time(:millisecond) + @drain_ms

    case collect(exec_pid, os_pid, output, max_bytes, deadline) do
      {:ok, drained, _status} ->
        drained

      {:timeout, drained} ->
        _ = Erlexec.signal(os_pid, :sigkill)

        case collect(
               exec_pid,
               os_pid,
               drained,
               max_bytes,
               System.monotonic_time(:millisecond) + @drain_ms
             ) do
          {:ok, killed, _status} -> killed
          {:timeout, killed} -> killed
        end
    end
  end

  defp result(output, status, timed_out?) do
    %{
      status: status,
      output: IO.iodata_to_binary(output.stdout),
      stderr: IO.iodata_to_binary(output.stderr),
      timed_out?: timed_out?,
      truncated?: output.truncated?
    }
  end

  defp empty_output do
    %{stdout: [], stdout_bytes: 0, stderr: [], stderr_bytes: 0, truncated?: false}
  end

  defp maybe_cd(options, path) when is_binary(path), do: [{:cd, path} | options]
  defp maybe_cd(options, _other), do: options

  defp maybe_env(options, env) do
    overrides =
      env
      |> List.wrap()
      |> Enum.flat_map(fn
        {name, value} when is_binary(name) and is_binary(value) -> [{name, value}]
        _other -> []
      end)
      |> Enum.reject(fn {name, value} -> Ouroboros.ProcessEnvironment.sensitive?(name, value) end)
      |> Map.new()

    # Erlexec's manager was started with the VM and does not observe later
    # `System.put_env/2` calls. Passing a filtered snapshot of the current environment
    # preserves the execution variables a child actually needs without handing an
    # operator-controlled process every secret owned by the daemon. A release VM also
    # carries the boot wrapper's ROOTDIR/BINDIR/EMU/PROGNAME and its embedded ERTS
    # directories at the front of PATH. Those describe this daemon, not an operator
    # command. Letting them cross the
    # boundary makes a plain `mix` or `elixir` look for start.boot inside the cached
    # Ouroboros release. Strip only that inherited release context, then apply explicit
    # tool variables so an operator-provided override still wins.
    inherited =
      System.get_env()
      |> without_release_environment()
      |> execution_environment()
      |> Map.merge(overrides)

    # `:clear` matters: erlexec otherwise overlays these values onto the environment its
    # manager captured when the release booted, so merely omitting ROOTDIR still leaves
    # the stale value in the child.
    [{:env, [:clear | Map.to_list(inherited)]} | options]
  end

  defp without_release_environment(environment) do
    runtime_paths =
      [Map.get(environment, "BINDIR"), release_bin(Map.get(environment, "ROOTDIR"))]
      |> Enum.reject(&is_nil/1)
      |> MapSet.new()

    environment
    |> Map.reject(fn {name, _value} ->
      name in @release_runtime_env or String.starts_with?(name, "RELEASE_")
    end)
    |> without_runtime_paths(runtime_paths)
  end

  defp execution_environment(environment) do
    Ouroboros.ProcessEnvironment.select(
      environment,
      @inherited_env_names,
      @inherited_env_prefixes
    )
  end

  defp release_bin(root) when is_binary(root) and root != "", do: Path.join(root, "bin")
  defp release_bin(_root), do: nil

  defp without_runtime_paths(environment, runtime_paths) do
    case Map.fetch(environment, "PATH") do
      {:ok, path} ->
        cleaned =
          path
          |> String.split(":")
          |> Enum.reject(&MapSet.member?(runtime_paths, &1))
          |> Enum.join(":")

        Map.put(environment, "PATH", cleaned)

      :error ->
        environment
    end
  end

  defp collect(exec_pid, os_pid, output, max_bytes, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {:stdout, ^os_pid, data} ->
        collect(exec_pid, os_pid, append(output, :stdout, data, max_bytes), max_bytes, deadline)

      {:stderr, ^os_pid, data} ->
        collect(exec_pid, os_pid, append(output, :stderr, data, max_bytes), max_bytes, deadline)

      {:DOWN, ^os_pid, :process, ^exec_pid, reason} ->
        now = System.monotonic_time(:millisecond)

        drained =
          drain_after_down(
            os_pid,
            output,
            max_bytes,
            now + @exit_drain_ms,
            now + @exit_drain_deadline_ms
          )

        {:ok, drained, exit_status(reason)}
    after
      remaining -> {:timeout, output}
    end
  end

  defp drain_after_down(os_pid, output, max_bytes, idle_deadline, hard_deadline) do
    now = System.monotonic_time(:millisecond)
    remaining = max(min(idle_deadline, hard_deadline) - now, 0)

    receive do
      {:stdout, ^os_pid, data} ->
        drain_after_down(
          os_pid,
          append(output, :stdout, data, max_bytes),
          max_bytes,
          min(System.monotonic_time(:millisecond) + @exit_drain_ms, hard_deadline),
          hard_deadline
        )

      {:stderr, ^os_pid, data} ->
        drain_after_down(
          os_pid,
          append(output, :stderr, data, max_bytes),
          max_bytes,
          min(System.monotonic_time(:millisecond) + @exit_drain_ms, hard_deadline),
          hard_deadline
        )
    after
      remaining -> output
    end
  end

  defp append(output, stream, data, max_bytes) when is_binary(data) do
    bytes_key = if stream == :stdout, do: :stdout_bytes, else: :stderr_bytes
    used = Map.fetch!(output, bytes_key)
    available = max(max_bytes - used, 0)
    kept = if byte_size(data) <= available, do: data, else: binary_part(data, 0, available)

    output
    |> Map.update!(stream, &[&1, kept])
    |> Map.put(bytes_key, used + byte_size(kept))
    |> Map.update!(:truncated?, &(&1 or byte_size(kept) != byte_size(data)))
  end

  defp exit_status(:normal), do: 0

  defp exit_status({:exit_status, status}) when is_integer(status) do
    case :exec.status(status) do
      {:status, exit_status} -> exit_status
      {:signal, signal, _core?} -> 128 + :exec.signal_to_int(signal)
    end
  rescue
    _error -> status
  end

  defp exit_status(status) when is_integer(status), do: exit_status({:exit_status, status})
  defp exit_status(_reason), do: 1

  defp stdin_of(opts) do
    case Keyword.get(opts, :stdin) do
      value when is_binary(value) -> value
      _absent -> ""
    end
  end

  defp scratch_file(content) do
    name = "ouro-exec-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    path = Path.join(System.tmp_dir!(), name)

    case File.write(path, content) do
      :ok ->
        _ = File.chmod(path, 0o600)
        {:ok, path}

      {:error, reason} ->
        {:error, {:scratch_file_unavailable, reason}}
    end
  end

  defp shell_quote(value), do: "'" <> String.replace(value, "'", "'\\''") <> "'"

  defp wrapper do
    with directory when is_list(directory) <- :code.priv_dir(:ouroboros),
         path = directory |> List.to_string() |> Path.join("provider-exec"),
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.lstat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      failure -> {:error, {:wrapper_unavailable, failure}}
    end
  end

  defp timeout_ms(opts) do
    case Keyword.get(opts, :timeout_ms) do
      value when is_integer(value) and value > 0 -> min(value, @max_timeout_ms)
      _unset -> @default_timeout_ms
    end
  end

  defp max_bytes(opts) do
    case Keyword.get(opts, :max_bytes) do
      value when is_integer(value) and value > 0 -> min(value, @max_max_bytes)
      _unset -> @default_max_bytes
    end
  end
end
