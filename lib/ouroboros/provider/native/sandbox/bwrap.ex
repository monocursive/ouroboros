defmodule Ouroboros.Provider.Native.Sandbox.Bwrap do
  @moduledoc """
  The Linux backend: a bubblewrap argv that mounts the policy as a namespace.

  Where Seatbelt describes what a process may do, bubblewrap describes what a process
  can *see*. The whole filesystem is bound read-only, the writable roots are re-bound
  read-write on top of it, and anything that must stay read-only inside them is bound
  read-only on top of that again — bind order is the policy, exactly as rule order is
  the policy on macOS.

  This is the mechanism Claude Code and Codex both use on Linux (R3 §2), minus the
  seccomp filter each of them adds. **Seccomp is out of scope for this slice**: the
  filesystem and the network namespace are constrained, the syscall surface is not.

  ## Verified where the live suite runs

  The argv is still pinned byte for byte in `test/provider/native/sandbox_test.exs`.
  Before this backend is selected, `probe/1` runs a representative read-only mount around
  the host's `true` executable, then a second command that also unshares the network
  namespace. Merely finding `bwrap` or reading its version is not enough: some container
  and hosted-runner policies allow the binary to start but refuse the namespace setup.
  Filesystem isolation is enough to select the backend; a host that can mount but cannot
  unshare the network still wraps commands, omitting `--unshare-net` so they do not fail
  closed into an unsandboxed shell. Live behaviour is claimed only where the filesystem
  probe succeeds; elsewhere detection reports no usable backend and the live suite says
  why it skipped. There is still no seccomp filter.

  ## The argv, and why it is in this order

    * `--die-with-parent` first, so a bubblewrap that outlives the BEAM cannot exist.
    * `--ro-bind / /` — the entire host, read-only. Everything after this narrows or
      widens a subtree of it.
    * `--dev /dev` and `--proc /proc` — a read-only bind of `/` would otherwise leave
      `/dev/null` unwritable and `/proc` stale, and both are load-bearing for ordinary
      shell tools.
    * `--bind <root> <root>` per writable root (`workspace_write` only).
    * `--ro-bind <path> <path>` for each protected directory that exists.
    * `--ro-bind <scratch> <path>` for each protected segment that does not exist yet.
      The empty scratch directory is a read-only placeholder at that destination, so a
      command cannot create `.git` or `.ouroboros` after admission.
    * `--tmpfs <scratch>` — a fresh, private, in-memory `$TMPDIR` for this one command,
      at the same path the macOS backend makes writable, so both backends give the
      shell the same `$TMPDIR` contract.
    * `--unshare-net` when the policy denies the network.
    * `--chdir <root>`, then `--setenv LD_PRELOAD` / `OUROBOROS_FS_DENY` when the
      name-based create filter is on disk, then `--` and the program.

  `--new-session` is deliberately absent. It is a real hardening (it blocks `TIOCSTI`
  push-back into a controlling terminal), but this provider's children are spawned onto
  pipes and never have a controlling terminal, and `setsid` would put the child in a
  process group the tool's TERM-then-close reaping does not reach. A hardening that
  costs a deadline its teeth, for a channel that does not exist here, is a bad trade.

  ## Protected segments

  Bubblewrap has no path-regex rule. Existing `.git` and `.ouroboros` paths are rebound
  read-only. Missing ones are covered by read-only bind mounts of the command's empty
  scratch directory. Both cases deny creation and writes at the protected destination;
  a path being absent when the command starts is not an authority to create it.

  A protected segment is not only the writable root's own: a submodule's or a vendored
  dependency's `.git` is bound read-only too, found by a walk bounded in depth and in
  directories visited. Where Seatbelt writes one regex — `/\\.git($|/)` — that covers
  every such path for free, bubblewrap needs one bind per directory, and a bind can only
  name a destination that is known when the namespace is set up. A `.git` created after
  the command starts is therefore denied by an `LD_PRELOAD` filter inside the sandbox
  (`libouro_fs_filter.so`, `OUROBOROS_FS_DENY`) rather than by a bind: the filter refuses
  mkdir/open/rename of any path component named in the policy's protected segments.
  Static binaries that never call libc are outside that net; ordinary `mkdir`, `git`,
  and `/bin/sh` are not.
  """

  # The walk is bounded twice: a repository with a deep `node_modules` must not turn
  # every sandboxed command into a filesystem crawl. Past the bound the argv is short a
  # bind rather than late — which is why this is defence in depth and not the guard.
  @max_segment_depth 6
  @max_segment_visits 2_048

  @doc """
  Proves this binary can apply the namespace primitives this backend depends on.

  A version check only proves that bubblewrap is installed. The filesystem probe exercises
  the read-only root, `/dev`, and `/proc`. A second command also unshares the network
  namespace. Refusing the network namespace must not discard filesystem isolation: the
  wrap then omits `--unshare-net` rather than falling through to an unsandboxed shell.
  The probe runs once through `Sandbox.detect/0`'s cache.
  """
  @type probe_error :: :no_true_executable | :filesystem_namespace_refused | :probe_exception
  @type probe :: %{version: String.t() | nil, notes: String.t(), unshare_net: boolean()}

  @spec probe(String.t()) :: {:ok, probe()} | {:error, probe_error()}
  def probe(path) when is_binary(path) do
    with target when is_binary(target) <- System.find_executable("true") do
      case run_probe(path, filesystem_args(target)) do
        :ok ->
          unshare_net = run_probe(path, network_args(target)) == :ok

          notes =
            if unshare_net do
              "filesystem and network namespace capability probes passed"
            else
              "filesystem capability probe passed; network namespace unavailable on this host"
            end

          {:ok, %{version: version(path), notes: notes, unshare_net: unshare_net}}

        :refused ->
          {:error, :filesystem_namespace_refused}
      end
    else
      _no_true_executable -> {:error, :no_true_executable}
    end
  rescue
    _error -> {:error, :probe_exception}
  end

  defp version(path) do
    case System.cmd(path, ["--version"], stderr_to_stdout: true) do
      {output, 0} -> output |> String.trim() |> String.slice(0, 64)
      _unavailable -> nil
    end
  rescue
    _error -> nil
  end

  @doc """
  The executable and argv that run `command` under this policy.

  `bwrap` is the executable; everything else is argv. The caller spawns it through the
  same `priv/provider-exec` umask wrapper every other child of this provider crosses.
  """
  @spec wrap(
          Ouroboros.Provider.Native.Sandbox.command(),
          map(),
          Ouroboros.Provider.Native.Sandbox.policy(),
          String.t(),
          boolean()
        ) :: {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, scope, policy, executable, unshare_net \\ true)

  def wrap(command, scope, policy, executable, unshare_net)
      when is_binary(executable) and is_boolean(unshare_net) do
    case argv(command) do
      {:ok, target} ->
        {:ok,
         {executable,
          options(scope, policy, unshare_net) ++ filter_env(policy) ++ ["--"] ++ target}}

      {:error, _reason} = error ->
        error
    end
  end

  def wrap(_command, _scope, _policy, _executable, _unshare_net),
    do: {:error, :no_bwrap_executable}

  @doc "Just the bubblewrap options, without the program — the half a test can pin."
  @spec options(map(), Ouroboros.Provider.Native.Sandbox.policy(), boolean()) :: [String.t()]
  # Later binds overlay earlier ones, so the order is the policy: the protected roots go
  # read-only first, the writable roots are bound on top — which is what keeps a worktree
  # under the node's data directory (D7) writable while the rest of that directory stays
  # read-only — and the `.git`/`.ouroboros` directories beneath each writable root are
  # re-bound read-only last.
  def options(scope, policy, unshare_net \\ true) when is_boolean(unshare_net) do
    ["--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"] ++
      Enum.flat_map(on_disk(policy.protected), &["--ro-bind", &1, &1]) ++
      Enum.flat_map(writable(policy), &["--bind", &1, &1]) ++
      protected_segment_binds(policy) ++
      ["--tmpfs", policy.scratch] ++
      network(policy, unshare_net) ++
      chdir(scope)
  end

  # The filter is argv of `wrap/4`, not of `options/2`: the options half is pinned
  # byte-for-byte and must not grow when a `.so` happens to be on disk.
  defp filter_env(policy) do
    segments = List.wrap(policy.protected_segments)

    case {segments, filter_library()} do
      {[_ | _] = names, path} when is_binary(path) ->
        ["--setenv", "LD_PRELOAD", path, "--setenv", "OUROBOROS_FS_DENY", Enum.join(names, ":")]

      _absent ->
        []
    end
  end

  defp filter_library do
    path = Application.app_dir(:ouroboros, "priv/native/libouro_fs_filter.so")
    if File.regular?(path), do: path, else: nil
  rescue
    ArgumentError -> nil
  end

  defp writable(policy), do: Enum.reject(policy.writable, &(&1 == policy.scratch))

  defp segment_dirs(policy) do
    for root <- writable(policy),
        segment <- policy.protected_segments,
        do: Path.join(root, segment)
  end

  defp protected_segment_binds(policy) do
    top_level =
      Enum.flat_map(segment_dirs(policy), fn destination ->
        source = if File.exists?(destination), do: destination, else: policy.scratch
        ["--ro-bind", source, destination]
      end)

    top_level ++ Enum.flat_map(nested_segment_dirs(policy), &["--ro-bind", &1, &1])
  end

  # Every `.git`/`.ouroboros` directory beneath a writable root, not just the root's own
  # one: `deps/foo/.git` is as much a repository as `./.git`, and the permission engine
  # never sees the `cp` or `dd` that would rewrite it.
  defp nested_segment_dirs(policy) do
    top_level = MapSet.new(segment_dirs(policy))

    {found, _budget} =
      Enum.reduce(writable(policy), {[], @max_segment_visits}, fn root, acc ->
        descend(root, policy.protected_segments, @max_segment_depth, acc)
      end)

    found
    |> Enum.reverse()
    |> Enum.reject(&MapSet.member?(top_level, &1))
    |> Enum.uniq()
  end

  defp descend(_dir, _segments, _depth, {_found, 0} = exhausted), do: exhausted
  defp descend(_dir, _segments, 0, acc), do: acc

  defp descend(dir, segments, depth, {found, budget}) do
    case File.ls(dir) do
      # Sorted, because the argv is pinned byte for byte and `File.ls/1` returns whatever
      # order the directory is stored in.
      {:ok, entries} ->
        Enum.reduce(Enum.sort(entries), {found, budget - 1}, fn entry, acc ->
          child = Path.join(dir, entry)
          {found, budget} = acc

          cond do
            not directory?(child) -> acc
            # A matched directory is bound whole; there is nothing below it left to find.
            entry in segments -> {[child | found], budget}
            true -> descend(child, segments, depth - 1, acc)
          end
        end)

      {:error, _reason} ->
        {found, budget - 1}
    end
  end

  # `File.dir?/1` follows symlinks, and following them is how a bounded walk becomes an
  # unbounded one — and how a bind could name a destination outside the writable root
  # that the link happens to point at.
  defp directory?(path), do: match?({:ok, %File.Stat{type: :directory}}, File.lstat(path))

  # Protected roots are mounted only when present. Unlike protected *segments*, these are
  # absolute operator locations outside writable roots; an absent one stays unreachable
  # through the read-only `/` bind and needs no destination placeholder.
  defp on_disk(paths), do: Enum.filter(paths, &File.exists?/1)

  defp filesystem_args(target),
    do: [
      "--die-with-parent",
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--proc",
      "/proc",
      "--",
      target
    ]

  defp network_args(target),
    do: [
      "--die-with-parent",
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--proc",
      "/proc",
      "--unshare-net",
      "--",
      target
    ]

  defp run_probe(path, args) do
    case System.cmd(path, args, stderr_to_stdout: true) do
      {_output, 0} -> :ok
      _refused -> :refused
    end
  end

  defp network(%{network: true}, _unshare_net), do: []
  defp network(_denied, true), do: ["--unshare-net"]
  defp network(_denied, false), do: []

  defp chdir(%{root: root}) when is_binary(root) and root != "", do: ["--chdir", root]
  defp chdir(_absent), do: []

  defp argv({:shell, line}) when is_binary(line), do: {:ok, ["/bin/sh", "-c", line]}

  defp argv({:argv, [executable | _rest] = list}) when is_binary(executable),
    do: {:ok, Enum.map(list, &to_string/1)}

  defp argv(other), do: {:error, {:uninterpretable_command, other}}
end
