defmodule Ouroboros.DataDir do
  @moduledoc """
  Where this node keeps its durable state, decided from the environment alone.

  `config/runtime.exs` calls the resolution and validation functions directly rather
  than reading application environment: the production block of a config provider is
  awkward to enter from a normal unit test, so the decisions it makes are extracted
  here and tested independently too.

  Nothing here reads application environment or touches another application module. A
  config provider runs before this application's modules are guaranteed loadable, and a
  module that pulled in more of the tree would fail a boot rather than a compile. The
  permission check uses only `File`, `System`, and trusted absolute operating-system
  tools, so the same boundary is available to direct/dev starts too.

  ## The cross-language contract

  `tui/src/runtime.rs` (`Paths::discover`, `resolve_data_dir`, `xdg_root`) derives the
  client's data directory from the same variables, and the two must produce the same
  path byte for byte: the client spawns the daemon and then looks in that directory for
  the `gateway.json` the daemon publishes. A disagreement is not a wrong path, it is a
  client that starts a daemon it can never find.

  Both sides therefore treat a blank or relative `XDG_DATA_HOME` as unset — which is also
  what the XDG basedir specification says to do — and neither expands `~`. The one case
  where they differ is an unset `HOME`: the Rust side falls back to the passwd database,
  and this raises instead, because a config provider that guessed this directory wrong
  would write durable state where nobody looks for it.
  """

  # `ouro` joins the same leaf onto the same root; see `Paths::discover`. Its `--dev` mode
  # uses a different leaf, but that mode runs `mix run` rather than a release, so no
  # production boot ever derives it.
  @leaf "ouroboros"
  @id_paths ["/usr/bin/id", "/bin/id"]
  @mkdir_paths ["/bin/mkdir", "/usr/bin/mkdir"]

  @doc """
  Resolves the data directory from `OUROBOROS_DATA_DIR`, `XDG_DATA_HOME`, and `HOME`.

  Each argument is the raw environment value or `nil`. Surrounding whitespace on the
  explicit override is normalized and the result must be absolute: this is the root of
  every journal on the host, and a relative path would name a different directory for
  every working directory the daemon happens to be started from. Otherwise the XDG
  default applies —
  `$XDG_DATA_HOME/ouroboros` when that variable holds an absolute path, and
  `$HOME/.local/share/ouroboros` when it does not.
  """
  @spec resolve!(String.t() | nil, String.t() | nil, String.t() | nil) :: String.t()
  def resolve!(configured, xdg_data_home, home) do
    case configured!(configured) do
      nil ->
        default!(present(xdg_data_home), present(home))

      path ->
        path
    end
  end

  @doc """
  Normalizes an explicit `OUROBOROS_DATA_DIR` without deriving a default.

  Runtime gateway configuration is evaluated in development as well as production, so
  it uses this function independently of `resolve!/3`. Blank means no explicit override;
  a nonblank value is trimmed and must be absolute in every environment.
  """
  @spec configured!(String.t() | nil) :: String.t() | nil
  def configured!(nil), do: nil

  def configured!(value) when is_binary(value) do
    case String.trim(value) do
      "" ->
        nil

      path ->
        unless Path.type(path) == :absolute do
          raise "OUROBOROS_DATA_DIR must be a nonblank absolute durable directory"
        end

        path
    end
  end

  @doc """
  Establishes the durable-directory leaf as a private same-user boundary.

  A missing leaf is created atomically at mode `0700`. A pre-existing symlink,
  non-directory, foreign-owned directory, or directory with broader permissions is
  refused without being replaced or chmodded: it may already expose or redirect durable
  state, so only its operator can decide whether it is safe to repair.
  """
  @spec ensure_private!(Path.t()) :: :ok
  def ensure_private!(path) when is_binary(path) do
    unless Path.type(path) == :absolute do
      raise "durable data directory must be an absolute path, got: #{inspect(path)}"
    end

    if ".." in Path.split(path) do
      raise "durable data directory must not contain `..`; choose its normalized absolute path"
    end

    normalized = Path.expand(path)
    parent = Path.dirname(normalized)
    ensure_parents_private!(parent)

    case File.lstat(normalized, time: :posix) do
      {:ok, stat} ->
        validate_private!(normalized, stat)

      {:error, :enoent} ->
        mkdir_private!(normalized)

        case File.lstat(normalized, time: :posix) do
          {:ok, stat} -> validate_private!(normalized, stat)
          {:error, reason} -> raise_inspection!(normalized, reason)
        end

      {:error, reason} ->
        raise_inspection!(normalized, reason)
    end
  end

  # Components that already exist are left exactly as they are, whatever their mode:
  # a parent such as `/srv/x` may predate this runtime and be shared by design. Only the
  # directories this boundary itself creates get the private mode, so an explicit
  # `OUROBOROS_DATA_DIR=/srv/new/place` never leaves a umask-shaped directory behind.
  defp ensure_parents_private!(parent) do
    parts = Path.split(parent)

    Enum.each(1..length(parts), fn depth ->
      path = parts |> Enum.take(depth) |> Path.join()

      unless File.dir?(path) do
        mkdir_parent_private!(path)
      end
    end)
  end

  defp mkdir_parent_private!(path) do
    mkdir = trusted_executable!(@mkdir_paths, "mkdir")

    case trusted_command(mkdir, ["-m", "700", path]) do
      {_output, 0} ->
        :ok

      {output, _status} ->
        case File.lstat(path, time: :posix) do
          {:ok, %File.Stat{type: type}} when type in [:directory, :symlink] ->
            :ok

          {:ok, _stat} ->
            raise "cannot create private parent directory #{path}: a non-directory is in the way"

          {:error, _reason} ->
            raise "cannot create private parent directory #{path}: #{String.trim(output)}"
        end
    end
  end

  defp validate_private!(path, stat) do
    uid = current_uid!()
    mode = Bitwise.band(stat.mode, 0o777)

    if stat.type == :directory and stat.uid == uid and mode == 0o700 do
      :ok
    else
      raise "#{path} must be a real mode-0700 durable data directory owned by uid #{uid} " <>
              "(type: #{stat.type}, uid: #{stat.uid}, mode: #{mode |> Integer.to_string(8) |> String.pad_leading(4, "0")}). " <>
              "Ouroboros will not chmod or replace a pre-existing unsafe directory. " <>
              "Verify its ownership and contents, then run `chmod 700 #{path}` if it is truly yours, " <>
              "or choose a fresh absolute OUROBOROS_DATA_DIR"
    end
  end

  defp mkdir_private!(path) do
    mkdir = trusted_executable!(@mkdir_paths, "mkdir")

    case trusted_command(mkdir, ["-m", "700", path]) do
      {_output, 0} ->
        :ok

      {output, _status} ->
        # Another same-user launcher may have won the atomic mkdir race. The caller
        # always lstat-validates the resulting leaf; a missing or unsafe result still
        # fails closed.
        case File.lstat(path, time: :posix) do
          {:ok, _stat} ->
            :ok

          {:error, _reason} ->
            raise "cannot create private data directory #{path}: #{String.trim(output)}"
        end
    end
  end

  @doc false
  def current_uid! do
    id = trusted_executable!(@id_paths, "id")

    case trusted_command(id, ["-u"]) do
      {output, 0} ->
        case Integer.parse(String.trim(output)) do
          {uid, ""} when uid >= 0 -> uid
          _other -> raise "trusted id helper returned an invalid uid"
        end

      {output, status} ->
        raise "trusted id helper failed with status #{status}: #{String.trim(output)}"
    end
  end

  # `File.stat/2` follows symlinks: the trust anchor is the absolute system path itself,
  # not the file's link count. Ubuntu 25.10+ ships coreutils as a multi-call binary, so
  # `/usr/bin/id` is a root-owned symlink into `/usr/lib` — refusing it (as the previous
  # `lstat` did) made every release refuse to boot there, and anyone who can plant a
  # symlink at these paths could as easily plant a regular file.
  @doc false
  def trusted_executable!(paths, name) do
    Enum.find(paths, fn path ->
      case File.stat(path, time: :posix) do
        {:ok, %File.Stat{type: :regular, mode: mode}} -> Bitwise.band(mode, 0o111) != 0
        _other -> false
      end
    end) || raise "cannot find a trusted absolute #{name} executable"
  end

  # `System.cmd/3` owns a linked Port. Some lifecycle processes deliberately trap exits,
  # so running it in their mailbox would leave a normal Port exit that looks like an
  # unexpected dependency death after the command has returned. Keep the Port inside an
  # unlinked monitored worker and consume only that worker's exact result/down pair.
  defp trusted_command(executable, args) do
    caller = self()
    result_ref = make_ref()

    {worker, monitor} =
      spawn_monitor(fn ->
        result =
          System.cmd(executable, args,
            env: [{"PATH", ""}],
            stderr_to_stdout: true
          )

        send(caller, {result_ref, result})
      end)

    receive do
      {^result_ref, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^worker, reason} ->
        raise "trusted operating-system helper exited: #{inspect(reason)}"
    after
      5_000 ->
        Process.exit(worker, :kill)

        receive do
          {:DOWN, ^monitor, :process, ^worker, _reason} -> :ok
        end

        raise "trusted operating-system helper did not finish in 5 seconds"
    end
  end

  defp raise_inspection!(path, reason) do
    raise "cannot inspect durable data directory #{path}: #{:file.format_error(reason)}"
  end

  defp default!(xdg, home) do
    cond do
      is_binary(xdg) and Path.type(xdg) == :absolute ->
        Path.join(xdg, @leaf)

      is_nil(home) ->
        raise "OUROBOROS_DATA_DIR is unset and so is HOME, so there is nowhere to keep this " <>
                "node's durable state. Set OUROBOROS_DATA_DIR to an absolute path, or run " <>
                "this release with a home directory."

      Path.type(home) != :absolute ->
        raise "OUROBOROS_DATA_DIR is unset and HOME=#{home} is not an absolute path, so the " <>
                "default data directory cannot be derived. Set OUROBOROS_DATA_DIR to an " <>
                "absolute path."

      true ->
        Path.join([home, ".local", "share", @leaf])
    end
  end

  defp present(nil), do: nil

  defp present(value) when is_binary(value) do
    if String.trim(value) == "", do: nil, else: value
  end
end
