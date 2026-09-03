defmodule Ouroboros.Provider.Native.Sandbox.Helper do
  @moduledoc """
  The preferred Linux backend: `ouro-sandbox`, a helper this repo builds and owns.

  Where the bubblewrap backend shells out to a binary the operator installed and describes
  the policy in that binary's vocabulary, this one hands a JSON policy to a helper compiled
  from `tui/sandbox/` and lets it apply namespaces, Landlock, and seccomp directly. The
  reason to prefer it is narrow and specific: bubblewrap constrains what a process can
  *see*, and everything it cannot express in mounts had to be pushed into an `LD_PRELOAD`
  shim whose own header admits that "static binaries that never call libc are outside this
  net". Landlock is a kernel LSM. What it enforces, it enforces for every process, however
  it was linked.

  It does **not** replace `LD_PRELOAD` entirely, and the table below says exactly where it
  does and does not. bubblewrap remains the fallback and is untouched.

  ## What each layer enforces

  | `fs_filter.c` / bwrap semantic | enforced now by |
  |---|---|
  | writes outside the workspace denied | read-only mounts (`EROFS`) **and** Landlock |
  | writes into an existing `.git` / `.ouroboros` denied | read-only bind **and** Landlock |
  | a *vendored* dependency's existing `.git` denied | read-only bind per directory **and** Landlock |
  | the node's data dir / config kept read-only inside a writable root | read-only bind **and** Landlock |
  | a writable worktree *under* the read-only data dir stays writable | bind order (bound before the read-only sweep) |
  | external network denied | `unshare(CLONE_NEWNET)` (`ENETUNREACH`) |
  | loopback still usable | loopback brought up inside the namespace |
  | **creating a `.git` that did not exist when the command started** | **`LD_PRELOAD` only — unchanged, and still leaky** |
  | reads fenced to an allow-set, in `builder` mode only | Landlock alone (`EACCES`) — there is no mount that can express it |
  | a build's `/dev` and `/proc`, in `builder` mode only | `/dev/null` by name, `/proc` read-only, a sealed tmpfs over `/dev/shm` |
  | remounting out of the policy | capabilities dropped, seccomp denial, **and** Landlock, which survives both |
  | narrowing the syscall surface | seccomp (the bwrap backend has none) |

  The one row in bold is the honest gap. Landlock attaches rights to inodes, so a rule can
  only be written for a path that exists when the ruleset is built; `mkdir deps/foo/.git`
  names a path that does not exist yet, and the only Landlock right governing it —
  `LANDLOCK_ACCESS_FS_MAKE_DIR` on the parent — would have to deny every legitimate `mkdir`
  in the workspace to catch it. So that case is still carried by `c_src/fs_filter.c`, with
  the same reach and the same hole it always had. This backend carries the shim rather than
  claiming to have replaced it.

  ## Why a helper binary and not a NIF

  Two independent reasons, either sufficient. The Forge admission policy structurally bans
  `load_nif` (`Ouroboros.Upgrade.Forge.Source`, `Upgrade.Signing.Policy`). And the work is
  *irreversibly restricting the calling thread* — `landlock_restrict_self`,
  `PR_SET_NO_NEW_PRIVS`, a seccomp filter — which is the one thing that must never happen
  to a BEAM scheduler. The helper applies the policy to itself and then `execve`s the
  command, so there is no supervisor left over and nothing to reap.

  ## The request protocol

  One JSON object, one command, no handshake. It is passed as `--request <json>` in argv
  rather than on stdin because `Ouroboros.Provider.Native.Exec` spawns every child with
  `{:stdin, :close}`, so a stdin-delivered request would arrive at a closed descriptor. The
  helper accepts `--request-file -` as well, for a human at a terminal.

      ouro-sandbox exec --request '{"version":1,...}' -- /bin/sh -c '...'

  `request/2` is the pure half — the policy, as the helper will read it — and is what the
  tests pin.

  ## Failures are legible on purpose

  A failure to *apply* the policy exits `125` with a message on stderr prefixed
  `ouro-sandbox: `, which is exactly what `Sandbox.backend_failure/3` matches against the
  backend label. A denial the command provoked surfaces as `EROFS`
  ("Read-only file system") or `ENETUNREACH` ("Network is unreachable") — the same strings
  bubblewrap produces and `Sandbox.violation/3` already recognises. That is not a
  coincidence: the Landlock layer is deliberately kept *congruent* with the mount layer
  precisely so that every denial a command can actually provoke is decided by the mount
  check, which the kernel consults first. A Landlock denial would arrive as `EACCES`, which
  this runtime correctly refuses to treat as a sandbox signal.

  The one exception is `builder` (docs/WASM.md D26), where a **read** denial has no mount
  layer to arrive through — this helper stays in the host's own path namespace, and a mount
  can make a path read-only but not unreadable. So a builder read denial *is* `EACCES`, and
  it is legible there for a reason that does not generalise: a build is one program this
  node spawned with a policy it wrote, not an opaque shell line, so the string is read as a
  fence in `Ouroboros.Wasm.Forge`'s own suite and nowhere else.

  ## What the helper says it can do

  `doctor` carries `"features": {"read_allow_set": true}`, and `probe/1` turns that into
  `read_fence: true` in the detection map. It is asked rather than assumed because a helper
  binary installed before W17 speaks the same protocol version and applies the same
  policies, and silently has no read allow-set: a node that inferred the fence from the
  backend's name would run a build under one that helper does not have.
  """

  @helper_name "ouro-sandbox"
  @protocol_version 1

  @doc """
  The absolute path the helper would be spawned from, or `nil` when nothing is installed.

  An absolute `OUROBOROS_SANDBOX_HELPER` wins, then a configured absolute path, then the first existing
  candidate — the application's own `priv/`, or a sibling of `ouro`. The same precedence the
  Computer Use helper uses, for the same reason: an operator testing a build needs a way to
  point the runtime at it without a release.

  No candidate is derived from the working directory (F1). This helper applies namespaces,
  Landlock and seccomp and then `execve`s the command, so what supplies it decides what
  contains an untrusted command; a `Path.expand("priv/sandbox/…")` and a walk up the cwd's
  ancestors were both here, and either let a cloned repository supply that binary.
  """
  @spec executable() :: String.t() | nil
  def executable do
    case System.get_env("OUROBOROS_SANDBOX_HELPER") do
      path when is_binary(path) and path != "" ->
        if absolute_path?(path), do: regular(path), else: configured_executable()

      _unset ->
        configured_executable()
    end
  end

  defp configured_executable do
    case Application.get_env(:ouroboros, :native_sandbox_helper) do
      path when is_binary(path) and path != "" ->
        if absolute_path?(path),
          do: regular(path),
          else: Enum.find(candidates(), &File.regular?/1)

      _bundled ->
        Enum.find(candidates(), &File.regular?/1)
    end
  end

  defp regular(path), do: if(File.regular?(path), do: path, else: nil)
  defp absolute_path?(path), do: Path.type(path) == :absolute

  defp candidates do
    # No cwd-derived candidate, in either of the two shapes this used to carry (F1): see
    # `executable/0`.
    [priv_helper(), sibling_helper(:os.find_executable(~c"ouro"))]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp sibling_helper(false), do: nil

  defp sibling_helper(path) when is_list(path),
    do: Path.join(Path.dirname(List.to_string(path)), @helper_name)

  defp priv_helper do
    case :code.priv_dir(:ouroboros) do
      priv when is_list(priv) -> Path.join([List.to_string(priv), "sandbox", @helper_name])
      _bad_name -> nil
    end
  end

  @doc """
  Asks an installed helper what this kernel can enforce, or `nil` if it cannot enforce.

  This is what lets the helper sit *ahead* of bubblewrap in the detection order without
  guessing. A helper binary shipped to a node whose kernel predates Landlock reports
  `"usable": false`, this returns `nil`, and detection falls through to bubblewrap rather
  than selecting a backend that would refuse every command. A binary that cannot be run at
  all is treated the same way.

  `read_fence` is the second thing this asks, and it is a question about the *binary*
  rather than about the kernel: only a helper whose report carries
  `"features": {"read_allow_set": true}` gets it, so a node still running a pre-W17
  `ouro-sandbox` answers `false` and `Sandbox.fences_reads?/1` refuses the forge that
  backend rather than fencing a build with a field the helper would refuse to parse.
  """
  @spec probe(String.t()) ::
          %{version: String.t() | nil, notes: String.t(), read_fence: boolean()} | nil
  def probe(path) when is_binary(path) do
    with {output, 0} <- System.cmd(path, ["doctor"], stderr_to_stdout: true),
         {:ok, report} <- JSON.decode(output),
         true <- Map.get(report, "usable") == true do
      %{
        version: report |> Map.get("version") |> version_string(report),
        notes: Map.get(report, "notes", ""),
        read_fence: read_fence?(report)
      }
    else
      _unusable -> nil
    end
  rescue
    _error -> nil
  end

  defp version_string(version, report) when is_binary(version) do
    case get_in(report, ["landlock", "abi"]) do
      abi when is_integer(abi) -> "#{version} (landlock abi #{abi})"
      _absent -> version
    end
  end

  defp version_string(_absent, _report), do: nil

  # Pattern-matched rather than `get_in`, so a report whose `features` is a string — a
  # helper from some other lineage, or a truncated read — is a helper that does not claim
  # the fence rather than an exception on the detection path.
  defp read_fence?(%{"features" => %{"read_allow_set" => true}}), do: true
  defp read_fence?(_no_claim), do: false

  @doc """
  The executable and argv that run `command` under this policy.

  The caller spawns it through the same `priv/provider-exec` umask wrapper every other
  child of this provider crosses.
  """
  @spec wrap(
          Ouroboros.Provider.Native.Sandbox.command(),
          map(),
          Ouroboros.Provider.Native.Sandbox.policy(),
          String.t()
        ) :: {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, scope, policy, executable) when is_binary(executable) do
    case argv(command) do
      {:ok, target} ->
        encoded = policy |> request(scope) |> JSON.encode!()
        {:ok, {executable, ["exec", "--request", encoded, "--"] ++ target}}

      {:error, _reason} = error ->
        error
    end
  end

  def wrap(_command, _scope, _policy, _executable), do: {:error, :no_helper_executable}

  @doc """
  The policy as the helper will read it — the half a test can pin.

  Mirrors what the bubblewrap backend expresses in its argv, field for field: the writable
  roots, the protected absolute locations, the name-based fences, and the network posture.
  Nothing is computed here that the helper could compute itself; the enumeration of which
  `.git` directories exist is deliberately left to the helper, because the sandbox should
  read the filesystem at the moment it locks it rather than trusting a list assembled a few
  milliseconds earlier.

  A `builder` policy is the one shape that carries `readable`, and it is the only change
  this function makes for it: the read allow-set is a field the helper fences with Landlock
  and refuses under any other mode, so emitting it for a shell would be a request the helper
  rejects rather than a shell with a narrower fence.
  """
  @spec request(Ouroboros.Provider.Native.Sandbox.policy(), map()) :: map()
  def request(policy, scope) do
    base = %{
      "version" => @protocol_version,
      "mode" => Atom.to_string(policy.mode),
      "scratch" => policy.scratch,
      "writable" => Enum.reject(policy.writable, &(&1 == policy.scratch)),
      "protected" => policy.protected,
      "denied_names" => List.wrap(policy.protected_segments),
      "network" => policy.network == true
    }

    base
    |> readable(policy)
    |> maybe_put("cwd", chdir(scope))
    |> maybe_put("fs_filter_library", filter_library(policy))
  end

  # The policy carries every root as it was named *and* as the kernel resolves it
  # (`Sandbox.builder_policy/1`): bubblewrap needs the name to bind, Landlock attaches a rule
  # to the inode either spelling reaches. A name that is itself a symlink is dropped here,
  # because the helper refuses one by design (`plan::symlinked_read_roots` — a rule opened
  # through a link grants its target under a name that does not say so) and the target it
  # points at is already in the list under its own name.
  defp readable(request, %{mode: :builder} = policy) do
    roots =
      policy
      |> Map.get(:readable, [])
      |> List.wrap()
      |> Enum.reject(&symlink?/1)

    Map.put(request, "readable", roots)
  end

  defp readable(request, _shell), do: request

  defp symlink?(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :symlink}} -> true
      _other -> false
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp chdir(%{root: root}) when is_binary(root) and root != "", do: root
  defp chdir(_absent), do: nil

  # The same `.so` the bubblewrap backend loads, from the same place the
  # `compile.ouroboros_fs_filter` task puts it. Absent on a node where no C compiler was
  # available at build time, and absent on macOS, in which case the helper simply has no
  # name-based create filter — which is the documented gap, not a silent one.
  #
  # Never for a builder. The shim fences the *creation* of a `.git`, a build has no
  # workspace and no such fence, and the builder plan carries no preload — so sending the
  # library was a layer this side named and the helper dropped. The helper refuses the field
  # under `builder` now, which makes this omission a rule rather than a courtesy.
  defp filter_library(%{mode: :builder}), do: nil

  defp filter_library(_shell) do
    path = Application.app_dir(:ouroboros, "priv/native/libouro_fs_filter.so")
    if File.regular?(path), do: path, else: nil
  rescue
    ArgumentError -> nil
  end

  defp argv({:shell, line}) when is_binary(line), do: {:ok, ["/bin/sh", "-c", line]}

  defp argv({:argv, [executable | _rest] = list}) when is_binary(executable),
    do: {:ok, Enum.map(list, &to_string/1)}

  defp argv(other), do: {:error, {:uninterpretable_command, other}}
end
