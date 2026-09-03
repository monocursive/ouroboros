defmodule Ouroboros.Provider.Native.Sandbox.SandboxExec do
  @moduledoc """
  The macOS backend: a Seatbelt profile handed to `/usr/bin/sandbox-exec -p`.

  The profile's *shape* is Codex CLI's published base policy, which R3 §2 records as
  the mechanism Codex and Cursor both use: start closed (`(deny default)`), allow
  reads everywhere, allow the handful of operations any `/bin/sh` needs to exist at all
  (`process-exec`, `process-fork`, `signal`, `sysctl-read`, `mach-lookup`, and writing
  to `/dev/null`), and then name the writable places explicitly. The rules underneath
  that shape are this runtime's own, and every one of them was verified against
  `/usr/bin/sandbox-exec` on macOS 26 rather than copied on faith.

  ## Paths are parameters, never text

  Every path reaches the profile as a `sandbox-exec -D NAME=VALUE` parameter and is
  read back with `(param "NAME")`. A workspace whose name contains a quote or a
  newline therefore cannot alter the policy, because it never becomes part of the
  policy's source. It also makes the generated profile depend only on *how many* roots
  a session has, which is what lets `test/provider/native/sandbox_test.exs` compare it
  byte for byte.

  ## Order is the policy

  SBPL is last-match-wins. The allows for the writable roots come first and the denies
  come after, so a protected directory that happens to sit inside a writable root — the
  common case, `<workspace>/.git` — is denied. Written the other way round the sandbox
  would silently permit exactly the write it exists to stop.

  The `.git` and `.ouroboros` denials are regular expressions rather than subpaths,
  because the rule being enforced is the *segment* rule
  (`Ouroboros.Control.Permissions.Rules`): a vendored dependency's `.git` five
  directories down is as protected as the workspace's own, and a subpath list can only
  name the ones that existed when the command started. `.gitignore` and a directory
  called `mygit` are unaffected — the expression anchors on a slash and on the end of
  the segment.

  ## Denials, as they actually appear

  Seatbelt returns `EPERM`, so a denied write surfaces as the program's own
  `Operation not permitted` and a denied external connection as
  `nc: connectx to … failed: Operation not permitted` — distinguishable from a closed
  loopback port, which is `ECONNREFUSED` and reads `Connection refused`.
  `Ouroboros.Provider.Native.Sandbox.violation/3` matches only the former.
  """

  @doc """
  The Seatbelt profile for a policy, as the text `-p` receives.

  Deterministic: the same policy shape always produces the same bytes, because the
  paths are parameters.
  """
  @spec profile(Ouroboros.Provider.Native.Sandbox.policy()) :: String.t()
  def profile(%{mode: :builder} = policy) do
    [
      "(version 1)",
      "; Ouroboros forge builder (docs/WASM.md D18). Closed by default on reads as well as",
      "; on writes: a build may read the toolchain roots it was given and nothing else, so",
      "; what a compiler can carry into its output is bounded. Paths arrive as -D parameters.",
      "(deny default)",
      "(allow process-exec)",
      "(allow process-fork)",
      "(allow signal (target self))",
      "(allow sysctl-read)",
      "(allow mach-lookup)",
      # Metadata everywhere and the root directory itself: a compiler stats its way down a
      # path before it opens anything, and a `stat` denial reads as a missing file rather
      # than as a fence. The contents of `/` are still only what the allows below name.
      "(allow file-read-metadata (subpath \"/\"))",
      "(allow file-read* (literal \"/\"))",
      "(allow file-write-data (require-all (path \"/dev/null\") (vnode-type CHARACTER-DEVICE)))"
    ]
    |> Enum.concat(rules(readable(policy), "allow file-read*", "OURO_READABLE"))
    # Writable implies readable: a build that could write its object files and not read
    # them back is not a build.
    |> Enum.concat(rules(policy.writable, "allow file-read*", "OURO_WRITABLE"))
    |> Enum.concat(rules(policy.writable, "allow file-write*", "OURO_WRITABLE"))
    |> Enum.concat(network_rules(policy))
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end

  def profile(policy) do
    [
      "(version 1)",
      "; Ouroboros native agent, sandbox_mode: #{policy.mode}.",
      "; Shape after Codex CLI's Seatbelt base policy: closed by default, reads open,",
      "; writes only where a parameter names them. Paths arrive as -D parameters.",
      "(deny default)",
      "(allow file-read*)",
      "(allow process-exec)",
      "(allow process-fork)",
      "(allow signal (target self))",
      "(allow sysctl-read)",
      "(allow mach-lookup)",
      "(allow file-write-data (require-all (path \"/dev/null\") (vnode-type CHARACTER-DEVICE)))"
    ]
    |> Enum.concat(writable_rules(policy))
    |> Enum.concat(protected_rules(policy))
    |> Enum.concat(reallow_rules(policy))
    |> Enum.concat(segment_rules(policy))
    |> Enum.concat(network_rules(policy))
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end

  @doc """
  The `-D` parameters the profile reads its paths back from.

  Returned separately from the profile so both halves can be asserted on their own, and
  so a reader can see that the only place a path appears is an argv entry.
  """
  @spec parameters(Ouroboros.Provider.Native.Sandbox.policy()) :: [String.t()]
  def parameters(%{mode: :builder} = policy),
    do: named(policy.writable, "OURO_WRITABLE") ++ named(readable(policy), "OURO_READABLE")

  def parameters(policy) do
    named(policy.writable, "OURO_WRITABLE") ++ named(policy.protected, "OURO_PROTECTED")
  end

  defp readable(policy), do: Map.get(policy, :readable, [])

  @doc """
  The executable and argv that run `command` under this policy.

  `sandbox-exec` `execve`s the target in place rather than forking it, so the pid the
  caller holds is the pid of the shell — which is what keeps
  `Ouroboros.Provider.Native.Tools.Bash`'s TERM-then-close reaping working unchanged.
  """
  @spec wrap(
          Ouroboros.Provider.Native.Sandbox.command(),
          map(),
          Ouroboros.Provider.Native.Sandbox.policy(),
          String.t()
        ) :: {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, _scope, policy, executable) when is_binary(executable) do
    case argv(command) do
      {:ok, target} ->
        {:ok, {executable, ["-p", profile(policy)] ++ parameters(policy) ++ target}}

      {:error, _reason} = error ->
        error
    end
  end

  def wrap(_command, _scope, _policy, _executable), do: {:error, :no_sandbox_exec_executable}

  defp argv({:shell, line}) when is_binary(line), do: {:ok, ["/bin/sh", "-c", line]}

  defp argv({:argv, [executable | _rest] = list}) when is_binary(executable),
    do: {:ok, Enum.map(list, &to_string/1)}

  defp argv(other), do: {:error, {:uninterpretable_command, other}}

  defp writable_rules(policy),
    do: rules(policy.writable, "allow", "OURO_WRITABLE")

  defp protected_rules(policy),
    do: rules(policy.protected, "deny", "OURO_PROTECTED")

  # A writable root that sits inside a protected one — a worktree under the node's data
  # directory (D7) — is allowed again *after* the denies, because SBPL is last-match-wins
  # and the deny above would otherwise swallow it. The segment denies still come last, so
  # the worktree's own `.git` stays read-only. The parameter is the root's own, so the
  # path is never spliced into the profile here either.
  defp reallow_rules(policy) do
    policy.writable
    |> Enum.with_index()
    |> Enum.filter(fn {path, _index} -> Enum.any?(policy.protected, &nested?(path, &1)) end)
    |> Enum.map(fn {_path, index} ->
      "(allow file-write* (subpath (param \"OURO_WRITABLE_#{index}\")))"
    end)
  end

  defp nested?(path, root), do: path == root or String.starts_with?(path, root <> "/")

  defp rules(paths, verb, prefix) when verb in ["allow", "deny"] do
    paths
    |> Enum.with_index()
    |> Enum.map(fn {_path, index} ->
      "(#{verb} file-write* (subpath (param \"#{prefix}_#{index}\")))"
    end)
  end

  # The builder's form: the operation is part of the rule rather than always `file-write*`.
  defp rules(paths, operation, prefix) do
    paths
    |> Enum.with_index()
    |> Enum.map(fn {_path, index} ->
      "(#{operation} (subpath (param \"#{prefix}_#{index}\")))"
    end)
  end

  defp named(paths, prefix) do
    paths
    |> Enum.with_index()
    |> Enum.flat_map(fn {path, index} -> ["-D", "#{prefix}_#{index}=#{path}"] end)
  end

  defp segment_rules(policy) do
    Enum.map(policy.protected_segments, fn segment ->
      "(deny file-write* (regex #\"/#{escape(segment)}($|/)\"))"
    end)
  end

  @regex_metacharacters [".", "^", "$", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|", "\\"]

  defp escape(segment) do
    segment
    |> String.graphemes()
    |> Enum.map_join(fn
      character when character in @regex_metacharacters -> "\\" <> character
      character -> character
    end)
  end

  defp network_rules(%{network: true}), do: ["(allow network*)"]

  # `loopback: false` (W16, D25): no local exception at all, so `(deny network*)` is the whole
  # of it. `Ouroboros.Provider.Native.Sandbox.helper_policy/1` is the caller — the `ouro-wasm`
  # helper speaks stdio and has no use for a socket, and a loopback socket it *could* open
  # reaches every service on this machine, this node's own gateway included. Proved by a probe
  # under this exact policy: a loopback listener that the builder policy connects to is
  # `Operation not permitted` under the helper's.
  defp network_rules(%{loopback: false}), do: ["(deny network*)"]

  # Mix coordinates concurrent compilers and its event bus through TCP sockets bound
  # to loopback. Denying network* without this local exception makes ordinary
  # `mix compile` fail with :eperm even though it is not reaching another machine.
  # SBPL is last-match-wins, so the narrow allows must follow the broad deny.
  defp network_rules(_denied) do
    [
      "(deny network*)",
      "(allow network-bind (local ip \"localhost:*\"))",
      "(allow network-inbound (local ip \"localhost:*\"))",
      "(allow network-outbound (remote ip \"localhost:*\"))"
    ]
  end
end
