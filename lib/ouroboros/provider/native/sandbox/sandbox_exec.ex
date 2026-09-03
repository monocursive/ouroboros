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

  ## The sealed profile (W21)

  A `process: :sealed` policy — `Ouroboros.Provider.Native.Sandbox.helper_policy/1`'s
  default — drops the "operations any `/bin/sh` needs" half of that shape, because the
  `ouro-wasm` helper is not a shell: `process-exec` is allowed for **one literal**, the
  executable the child was spawned as; there is no `process-fork` and no `mach-lookup`;
  `sysctl-read` is allowed under the `hw.` prefix only; and `file-read-metadata` is allowed
  on `/` itself and nowhere the `file-read*` grants do not already reach. Every line was
  measured rather than reasoned: a profile with no `process-exec` at all cannot start the
  child, because `sandbox-exec` applies the profile and then `execvp`s the target inside it;
  with no `sysctl-read` the Rust runtime aborts before `main` (`failed to allocate a guard
  page`), and with `hw.pagesize_compat` alone it runs but `precompile` produces a
  **different artifact** from the same component than the unsealed helper does, because
  cranelift reads `hw.optional.*` to detect the CPU — so the prefix is the narrowest set
  that keeps a sealed signer and an unsealed loader agreeing about the machine.

  **The exec literal is the resolved path.** Seatbelt matches `process-exec (literal …)`
  against the path the kernel resolves, not the spelling `execvp` was given: a literal naming
  `_build/test/lib/ouroboros/priv/wasm/ouro-wasm` (a path through a symlinked `priv/`) never
  matches, and one naming the canonical path matches either spelling — *provided* the
  kernel may read the symlink on the way, which needs `file-read-metadata` on that link and a
  sealed profile does not grant it outside the readable roots. So `wrap/4` resolves argv[0]
  (`Ouroboros.Workspace.Path.canonicalize_file/1`) and spawns the child by that path, and
  the one `-D OURO_EXEC` parameter is that same path. A target that does not resolve is
  passed as spelled, and its exec fails as it would have anyway.

  The same mechanism reaches the roots. A root spelled `/var/folders/…` is
  `/private/var/folders/…` to the kernel, and following `/var` is a metadata read on that
  link; the builder's `(allow file-read-metadata (subpath "/"))` granted it everywhere, and the
  sealed profile grants it on each symlink along a root's spelled path and nowhere else
  (`links/1`, one `-D OURO_LINK_n` each) — measured to be the link alone, with `/var/root`
  still absent beside it.

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
  def profile(%{mode: :builder, process: :sealed} = policy) do
    [
      "(version 1)",
      "; Ouroboros wasm helper (docs/WASM.md 7.3a, D25). Closed by default on reads as well",
      "; as on writes, and sealed as a process: it may exec only the binary it was spawned",
      "; as, may not fork, and reaches no mach service. Paths arrive as -D parameters.",
      "(deny default)",
      # The one exec: the child's own executable, by the path the kernel resolves. Not a
      # removal — `sandbox-exec` applies the profile and then `execvp`s the target inside it,
      # so a profile with no `process-exec` at all starts nothing.
      "(allow process-exec (literal (param \"OURO_EXEC\")))",
      "(allow signal (target self))",
      # `hw.pagesize_compat` is what the Rust runtime needs to map a thread's guard page, and
      # `hw.optional.*` is what cranelift reads to detect the CPU; `kern.` and the rest are not
      # needed and not granted. A hardware fact is not a secret.
      "(allow sysctl-read (sysctl-name-prefix \"hw.\"))",
      # The root directory itself, and nothing beyond what `file-read*` below already implies:
      # metadata over `/` would be an existence oracle over the whole filesystem, and a process
      # that is not a compiler does not stat its way down paths it may not read.
      "(allow file-read-metadata (literal \"/\"))",
      "(allow file-read* (literal \"/\"))",
      "(allow file-write-data (require-all (path \"/dev/null\") (vnode-type CHARACTER-DEVICE)))"
    ]
    # Each symlink on the way to a root, by name (`links/1`): the kernel reads a link to
    # resolve a path through it, that read is `file-read-metadata` on the link itself, and a
    # root spelled `/var/folders/…` is unreadable without it while `/private/var/folders/…` —
    # the same directory — is fine. Measured: the link alone, and `/var/root` stays absent.
    |> Enum.concat(literal_rules(links(policy), "allow file-read-metadata", "OURO_LINK"))
    |> Enum.concat(rules(readable(policy), "allow file-read*", "OURO_READABLE"))
    |> Enum.concat(rules(policy.writable, "allow file-read*", "OURO_WRITABLE"))
    |> Enum.concat(rules(policy.writable, "allow file-write*", "OURO_WRITABLE"))
    |> Enum.concat(network_rules(policy))
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end

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
  def parameters(%{mode: :builder, process: :sealed} = policy) do
    named(policy.writable, "OURO_WRITABLE") ++
      named(readable(policy), "OURO_READABLE") ++ named(links(policy), "OURO_LINK")
  end

  def parameters(%{mode: :builder} = policy),
    do: named(policy.writable, "OURO_WRITABLE") ++ named(readable(policy), "OURO_READABLE")

  def parameters(policy) do
    named(policy.writable, "OURO_WRITABLE") ++ named(policy.protected, "OURO_PROTECTED")
  end

  defp readable(policy), do: Map.get(policy, :readable, [])

  @doc """
  The symlinks a sealed child has to be able to read to reach its roots by the spellings the
  policy names them under (W21).

  A sealed profile grants `file-read-metadata` on `/` and inside the roots only, and the kernel
  resolves a path one component at a time: reaching `/var/folders/…` reads the `/var` link,
  and that read is a metadata read on the link. So every ancestor of every readable and
  writable root that is itself a symlink — `/var`, a `_build/…/priv`, a temporary directory's
  `/tmp` — is named as one `literal`, which is exactly the set the kernel needs and no oracle:
  a link's own existence is the node's own fact, and a `stat` beside it stays denied. Read off
  the disk at profile time, the way `Bwrap.options/3` filters its binds to what exists.
  """
  @spec links(Ouroboros.Provider.Native.Sandbox.policy()) :: [String.t()]
  def links(policy) do
    (readable(policy) ++ policy.writable)
    |> Enum.flat_map(&ancestors/1)
    |> Enum.uniq()
    |> Enum.filter(&symlink?/1)
    |> Enum.sort()
  end

  # `/a/b/c` → `/`, `/a`, `/a/b`, `/a/b/c`. The root itself is included: a root that *is* a
  # link has to be read to be followed too.
  defp ancestors(path) do
    path
    |> Path.split()
    |> Enum.scan(&Path.join(&2, &1))
  end

  defp symlink?(path) do
    match?({:ok, %File.Stat{type: :symlink}}, File.lstat(path))
  end

  @doc """
  The executable and argv that run `command` under this policy.

  `sandbox-exec` `execve`s the target in place rather than forking it, so the pid the
  caller holds is the pid of the shell — which is what keeps
  `Ouroboros.Provider.Native.Tools.Bash`'s TERM-then-close reaping working unchanged.

  Under a sealed policy the target's argv[0] is **resolved** and the child is spawned by
  that path, which is also the `-D OURO_EXEC` parameter the profile's one `process-exec`
  literal reads (see the moduledoc for why the resolved spelling is the only one that
  matches). `Ouroboros.Provider.Native.Sandbox.wrap/4` has already refused a `{:shell, _}`
  and a relative argv[0] by the time a sealed policy reaches here.
  """
  @spec wrap(
          Ouroboros.Provider.Native.Sandbox.command(),
          map(),
          Ouroboros.Provider.Native.Sandbox.policy(),
          String.t()
        ) :: {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, _scope, %{process: :sealed} = policy, executable)
      when is_binary(executable) do
    case argv(command) do
      {:ok, [target | rest]} ->
        exec = resolved(target)

        {:ok,
         {executable,
          ["-p", profile(policy), "-D", "OURO_EXEC=" <> exec] ++
            parameters(policy) ++ [exec | rest]}}

      {:error, _reason} = error ->
        error
    end
  end

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

  # The path the kernel will match the exec literal against. A target that cannot be resolved
  # — absent, or not a regular file — is kept as spelled: its exec fails as it would have, and
  # a fence with a hole is not the alternative.
  defp resolved(target) do
    case Ouroboros.Workspace.Path.canonicalize_file(target) do
      {:ok, canonical} -> canonical
      {:error, _unresolved} -> target
    end
  end

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

  # The same, on the path itself rather than the tree beneath it.
  defp literal_rules(paths, operation, prefix) do
    paths
    |> Enum.with_index()
    |> Enum.map(fn {_path, index} ->
      "(#{operation} (literal (param \"#{prefix}_#{index}\")))"
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
