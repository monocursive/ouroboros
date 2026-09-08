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
    * `--ro-bind <path> <path>` for each protected *file* that exists, and
      `--ro-bind /dev/null <path>` for each that does not (S1). That is the workspace hook
      manifest: one path per writable root, denied whether or not it is there.
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

  ## Protected files (S1)

  A protected *file* is a bind rather than a filter, and unlike a protected segment it needs
  no `LD_PRELOAD` half: the path is known before the namespace is set up, so the destination
  can be created and made read-only whether or not anything is there. `/dev/null` is the
  source for the absent case — a read-only character device is a mount point a create cannot
  overwrite, a rename cannot replace and an unlink cannot remove, and it reads back as an
  empty file rather than as the `EISDIR` an empty directory would give. Verified live by
  `scripts/sandbox-linux-test.sh`.
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
  def options(scope, policy, unshare_net \\ true)

  # The builder's namespace (docs/WASM.md D18), and the difference from every other policy
  # here is the first bind: `/` is **not** bound at all, so the roots named below are the
  # whole of what the build can see. Unverified — no Linux build has run under this — which
  # is why `Ouroboros.Wasm.Forge` states it as unverified rather than as a claim.
  def options(scope, %{mode: :builder} = policy, unshare_net) when is_boolean(unshare_net) do
    ["--die-with-parent", "--dev", "/dev", "--proc", "/proc"] ++
      Enum.flat_map(on_disk(Map.get(policy, :readable, [])), &["--ro-bind", &1, &1]) ++
      Enum.flat_map(on_disk(writable(policy)), &["--bind", &1, &1]) ++
      ["--tmpfs", policy.scratch] ++
      network(policy, unshare_net) ++
      chdir(scope)
  end

  def options(scope, policy, unshare_net) when is_boolean(unshare_net) do
    ["--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"] ++
      Enum.flat_map(on_disk(policy.protected), &["--ro-bind", &1, &1]) ++
      Enum.flat_map(writable(policy), &["--bind", &1, &1]) ++
      protected_segment_binds(policy) ++
      protected_file_binds(policy) ++
      exception_binds(policy) ++
      hidden_file_binds(policy) ++
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
        ["--setenv", "LD_PRELOAD", path, "--setenv", "OUROBOROS_FS_DENY", Enum.join(names, ":")] ++
          if Map.has_key?(policy, :write_exceptions) do
            [
              "--setenv",
              "OUROBOROS_FS_WRITE_EXCEPTIONS",
              Enum.map_join(policy.write_exceptions, ":", &Base.encode16(&1, case: :lower))
            ]
          else
            []
          end

      _absent ->
        []
    end
  end

  defp exception_binds(policy) do
    roots = Map.get(policy, :write_exceptions, [])

    {nested, _} =
      Enum.reduce(roots, {[], @max_segment_visits}, fn root, acc ->
        descend(root, policy.protected_segments, @max_segment_depth, acc)
      end)

    Enum.flat_map(roots, &["--bind", &1, &1]) ++ Enum.flat_map(nested, &["--ro-bind", &1, &1])
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

  @doc """
  The destinations bubblewrap has to *create* as mount points for this policy — and leaves
  behind on the host when the command exits.

  Two binds above name a path that may not exist yet: `--ro-bind /dev/null <file>` for an
  absent hook manifest (`protected_file_binds/1`) and `--ro-bind <scratch> <dir>` for an
  absent `.git`/`.ouroboros` under a writable root (`protected_segment_binds/1`). bubblewrap
  makes the mount point inside the writable bind, which *is* the host's directory, and its
  teardown unmounts but never unlinks. Measured with bubblewrap 0.8.0 in a
  `debian:bookworm-slim` container: `cp template ouroboros.toml` is `Permission denied`
  inside the namespace **and** `/ws/ouroboros.toml` exists on the host afterwards, mode
  0444, size 0; the same for an absent `.git`, which is left as an empty directory. CI's
  ubuntu-24.04 job failed the "present or absent" test on exactly that file.

  So the caller that spawned the command clears these afterwards with
  `clear_mount_point_stubs/1`, and only where the path is still the stub — a zero-byte
  regular file or an empty directory. Anything else there was not bubblewrap's and is left
  alone. This is computed from the same `File.exists?/1` answers `options/3` reads, at the
  same moment, so the argv and this list agree.
  """
  @spec mount_point_stubs(Ouroboros.Provider.Native.Sandbox.policy()) :: [String.t()]
  def mount_point_stubs(policy) do
    files = policy |> Map.get(:protected_files, []) |> Enum.reject(&File.exists?/1)
    dirs = policy |> segment_dirs() |> Enum.reject(&File.exists?/1)
    Enum.uniq(files ++ dirs)
  end

  @doc """
  Removes the stubs `mount_point_stubs/1` named, where each is still a stub. Total: a path
  holding bytes, a directory with entries, a symlink, or nothing at all is left as it is.
  """
  @spec clear_mount_point_stubs([String.t()]) :: :ok
  def clear_mount_point_stubs(paths) when is_list(paths) do
    Enum.each(paths, &clear_stub/1)
    :ok
  end

  def clear_mount_point_stubs(_none), do: :ok

  defp clear_stub(path) when is_binary(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: 0}} -> _ = File.rm(path)
      # `rmdir` refuses a directory with entries, which is the point: only the empty
      # placeholder goes.
      {:ok, %File.Stat{type: :directory}} -> _ = File.rmdir(path)
      _other -> :ok
    end

    :ok
  rescue
    _error -> :ok
  end

  defp clear_stub(_other), do: :ok

  # S1. The workspace hook manifest, one bind per writable root, after the writable binds
  # and before the delivery exceptions — the same place the Seatbelt profile puts its
  # `literal` deny, and the same order `Rules.protected_write?/1` reads the policy in.
  #
  # Two cases, and the second is the one that matters. **The file exists**: a read-only bind
  # of it over itself, exactly as an existing `.git` is handled — a write is `EROFS`. **The
  # file does not exist**: a read-only bind of `/dev/null` onto the path. bubblewrap creates
  # the mount point (it makes a regular file when the source is not a directory), so the
  # destination is there, is read-only, and is a mount point — `cp`/`tee`/`sed -i` fail
  # `EROFS`, `mv` over it and `rm` of it fail `EBUSY`, and the empty scratch *directory* the
  # segment binds use would have been the wrong shape here: a directory named
  # `ouroboros.toml` fails a create with `EISDIR`, which is a refusal that reads like a bug.
  #
  # `/dev/null` is resolved in the host's root, which bubblewrap keeps open for exactly this,
  # so `--dev /dev` earlier in the argv does not take it away.
  defp protected_file_binds(policy) do
    policy
    |> Map.get(:protected_files, [])
    |> Enum.flat_map(fn destination ->
      source = if File.exists?(destination), do: destination, else: "/dev/null"
      ["--ro-bind", source, destination]
    end)
  end

  # S4. This node's own credentials — the signing seed, the gateway and web tokens, the web
  # cookie secret — hidden from a **read**, which is what `protected_file_binds/1` above
  # cannot do: it binds the file over itself, so the bytes are still there to `cat`.
  #
  # `/dev/null` over the path is the mask. bubblewrap resolves the source in the host root it
  # keeps open for exactly this, so `--dev /dev` earlier in the argv does not take it away,
  # and it creates the mount point when the destination is absent — which is the case worth
  # having: a token file written by a daemon *after* this namespace was built is written to
  # an inode outside it and stays invisible here. The shell sees a zero-length character
  # device, not an `EPERM`; that is a weaker signal than Seatbelt's and the same containment.
  #
  # Emitted last, after the delivery re-allows, for the reason the Seatbelt profile puts its
  # deny last: later binds overlay earlier ones and this one must be the one on top.
  #
  # **Only where the file is actually there**, and that is not a nicety — it is what keeps
  # this from breaking every command on a Linux node. Measured, in a privileged
  # `debian:bookworm-slim` container with bubblewrap 0.8.0:
  #
  #     bwrap --ro-bind / / --ro-bind $DATA $DATA --ro-bind /dev/null $DATA/gateway.token
  #       -> starts; `cat` of the token is `Permission denied` and the bytes never appear,
  #          a write to it is denied, and the host's file is unchanged.
  #     bwrap ... --ro-bind /dev/null $DATA/web.secret   (with no such file)
  #       -> "bwrap: Can't create file at /tmp/data/web.secret: Read-only file system",
  #          and the command does not run at all.
  #
  # The difference from `protected_file_binds/1` above, which does bind `/dev/null` onto a
  # path that is not there: the hook manifest sits under a *writable* root, where bubblewrap
  # can make the mount point. A credential sits under the node's data directory, which this
  # very argv has already bound read-only. So an absent credential is left out, and the gap
  # is the honest one: a file created after this namespace was built. These are written when
  # the node boots, before any session has a command to run, and the *next* command builds a
  # new namespace in which the file exists and is masked. Seatbelt has no such gap — a
  # `literal` deny needs no mount point.
  defp hidden_file_binds(policy) do
    policy
    |> Map.get(:hidden_files, [])
    |> Enum.filter(&File.regular?/1)
    |> Enum.flat_map(&["--ro-bind", "/dev/null", &1])
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

          case File.lstat(child) do
            {:ok, %{type: type}} when type in [:directory, :regular] ->
              cond do
                Enum.any?(segments, &(String.downcase(entry) == String.downcase(&1))) ->
                  {[child | found], budget}

                type == :directory ->
                  descend(child, segments, depth - 1, acc)

                true ->
                  acc
              end

            _ ->
              acc
          end
        end)

      {:error, _reason} ->
        {found, budget - 1}
    end
  end

  # `File.dir?/1` follows symlinks, and following them is how a bounded walk becomes an
  # unbounded one — and how a bind could name a destination outside the writable root
  # that the link happens to point at.

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
