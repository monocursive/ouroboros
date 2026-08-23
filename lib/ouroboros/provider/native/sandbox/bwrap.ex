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

  ## Not verified on a machine

  `bwrap` was not installed on the node this backend was written on, so nothing here
  claims observed behaviour. What is tested is the argv — pinned byte for byte in
  `test/provider/native/sandbox_test.exs` — and what that argv means is read from
  bubblewrap's own documented options. The first person to run it on a Linux node
  should expect to correct something.

  ## The argv, and why it is in this order

    * `--die-with-parent` first, so a bubblewrap that outlives the BEAM cannot exist.
    * `--ro-bind / /` — the entire host, read-only. Everything after this narrows or
      widens a subtree of it.
    * `--dev /dev` and `--proc /proc` — a read-only bind of `/` would otherwise leave
      `/dev/null` unwritable and `/proc` stale, and both are load-bearing for ordinary
      shell tools.
    * `--bind <root> <root>` per writable root (`workspace_write` only).
    * `--ro-bind <path> <path>` for each protected directory that exists — the `.git`
      and `.ouroboros` directories directly under a writable root, the node's data
      directory, and the user's config. Only paths that exist are bound, because
      bubblewrap fails on a source that is not there.
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

  ## The segment limit

  Where macOS denies writes to *any* `.git` segment with one regular expression,
  bubblewrap can only bind paths that exist. Only the `.git` and `.ouroboros`
  directories directly beneath a writable root are protected here; a vendored
  dependency's nested `.git` is not. That is a real difference between the two
  backends and it is stated in the README rather than papered over.
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
  def options(scope, policy) do
    ["--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"] ++
      Enum.flat_map(writable(policy), &["--bind", &1, &1]) ++
      Enum.flat_map(read_only_within(policy), &["--ro-bind", &1, &1]) ++
      ["--tmpfs", policy.scratch] ++
      network(policy) ++
      chdir(scope)
  end

  defp writable(policy), do: Enum.reject(policy.writable, &(&1 == policy.scratch))

  # Every protected location that is actually on disk. `--ro-bind` of a source that
  # does not exist is a bubblewrap error, and a sandbox that refuses to start because a
  # workspace has no `.git` would be worse than one that binds fewer paths: the
  # underlying `--ro-bind / /` already makes a path that does not exist unwritable.
  defp read_only_within(policy) do
    segments =
      for root <- writable(policy),
          segment <- policy.protected_segments,
          do: Path.join(root, segment)

    Enum.filter(segments ++ policy.protected, &File.exists?/1)
  end

  defp network(%{network: true}), do: []
  defp network(_denied), do: ["--unshare-net"]

  defp chdir(%{root: root}) when is_binary(root) and root != "", do: ["--chdir", root]
  defp chdir(_absent), do: []

  defp argv({:shell, line}) when is_binary(line), do: {:ok, ["/bin/sh", "-c", line]}

  defp argv({:argv, [executable | _rest] = list}) when is_binary(executable),
    do: {:ok, Enum.map(list, &to_string/1)}

  defp argv(other), do: {:error, {:uninterpretable_command, other}}
end
