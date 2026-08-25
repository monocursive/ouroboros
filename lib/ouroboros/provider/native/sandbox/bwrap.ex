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
  Live behaviour — a read-only bind denying writes, a workspace bind allowing them,
  `$HOME` and `.git` staying read-only — is claimed only on Linux CI with `bwrap`
  installed (ubuntu-24.04). It is not claimed on the Mac this backend was written on,
  which still has no `bwrap`, and there is still no seccomp filter.

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
    * `--chdir <root>`, then the program.

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
  """

  @doc """
  The executable and argv that run `command` under this policy.

  `bwrap` is the executable; everything else is argv. The caller spawns it through the
  same `priv/provider-exec` umask wrapper every other child of this provider crosses.
  """
  @spec wrap(
          Ouroboros.Provider.Native.Sandbox.command(),
          map(),
          Ouroboros.Provider.Native.Sandbox.policy(),
          String.t()
        ) :: {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, scope, policy, executable) when is_binary(executable) do
    case argv(command) do
      {:ok, target} -> {:ok, {executable, options(scope, policy) ++ ["--"] ++ target}}
      {:error, _reason} = error -> error
    end
  end

  def wrap(_command, _scope, _policy, _executable), do: {:error, :no_bwrap_executable}

  @doc "Just the bubblewrap options, without the program — the half a test can pin."
  @spec options(map(), Ouroboros.Provider.Native.Sandbox.policy()) :: [String.t()]
  # Later binds overlay earlier ones, so the order is the policy: the protected roots go
  # read-only first, the writable roots are bound on top — which is what keeps a worktree
  # under the node's data directory (D7) writable while the rest of that directory stays
  # read-only — and the `.git`/`.ouroboros` directories beneath each writable root are
  # re-bound read-only last.
  def options(scope, policy) do
    ["--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"] ++
      Enum.flat_map(on_disk(policy.protected), &["--ro-bind", &1, &1]) ++
      Enum.flat_map(writable(policy), &["--bind", &1, &1]) ++
      protected_segment_binds(policy) ++
      ["--tmpfs", policy.scratch] ++
      network(policy) ++
      chdir(scope)
  end

  defp writable(policy), do: Enum.reject(policy.writable, &(&1 == policy.scratch))

  defp segment_dirs(policy) do
    for root <- writable(policy),
        segment <- policy.protected_segments,
        do: Path.join(root, segment)
  end

  defp protected_segment_binds(policy) do
    Enum.flat_map(segment_dirs(policy), fn destination ->
      source = if File.exists?(destination), do: destination, else: policy.scratch
      ["--ro-bind", source, destination]
    end)
  end

  # Protected roots are mounted only when present. Unlike protected *segments*, these are
  # absolute operator locations outside writable roots; an absent one stays unreachable
  # through the read-only `/` bind and needs no destination placeholder.
  defp on_disk(paths), do: Enum.filter(paths, &File.exists?/1)

  defp network(%{network: true}), do: []
  defp network(_denied), do: ["--unshare-net"]

  defp chdir(%{root: root}) when is_binary(root) and root != "", do: ["--chdir", root]
  defp chdir(_absent), do: []

  defp argv({:shell, line}) when is_binary(line), do: {:ok, ["/bin/sh", "-c", line]}

  defp argv({:argv, [executable | _rest] = list}) when is_binary(executable),
    do: {:ok, Enum.map(list, &to_string/1)}

  defp argv(other), do: {:error, {:uninterpretable_command, other}}
end
