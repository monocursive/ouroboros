defmodule Ouroboros.Provider.Native.Sandbox do
  @moduledoc """
  The OS sandbox the native agent's shell runs inside, and the honest answer when none.

  Every leader ships one and every leader ships the same two halves (R3 §2): a
  filesystem policy and a network policy, because "effective sandboxing requires both"
  and a single-axis sandbox is a promise with a hole in it. Codex uses macOS
  `sandbox-exec -p` and Linux `bwrap`; Claude Code uses Seatbelt and bubblewrap +
  seccomp; Cursor uses Seatbelt and Landlock + seccomp. This module is the same shape,
  narrowed to what this runtime can prove on the node it is running on.

  ## What it decides

  `decide/2` turns a session's `sandbox_mode` and the detected backend into one of
  three outcomes, and `Ouroboros.Provider.Native.Tools.Bash` does exactly what it says:

    * `{:sandboxed, label, policy}` — the command runs wrapped.
    * `{:unsandboxed, reason}` — the command runs plain, and the reason is reported
      rather than hidden. `workspace_write` on a node with no backend is this: it is
      what this provider did before C5 and calling it a regression to keep doing it
      would be worse than saying so.
    * `{:refused, reason}` — the command does not run. `read_only` without a backend is
      this, because a shell that cannot be made read-only under a read-only label is a
      lie about the label, not a convenience.

  Nothing degrades quietly. A mode this module does not recognise is refused rather
  than treated as the nearest thing it does recognise, and a backend that fails to
  apply its policy is reported as a backend failure rather than folded into the
  command's own exit status.

  ## What each mode enforces

  | mode | filesystem | network |
  |---|---|---|
  | `:read_only` | reads anywhere the process could already read; writes **only** into a per-call scratch directory that `$TMPDIR` points at | denied |
  | `:workspace_write` | the above, plus writes under `scope.root` and every `scope.roots` entry — with any `.git` or `.ouroboros` segment beneath them, the node's data directory, and `$XDG_CONFIG_HOME/ouroboros` (or `~/.config/ouroboros`) kept read-only | denied unless the node opts in |
  | `:unrestricted` | no sandbox, logged | no sandbox |

  The protected set mirrors `Ouroboros.Control.Permissions.Rules`' own protected paths
  — the same policy, enforced a second time by the kernel rather than by a rule the
  shell never crosses. It is recomputed here rather than imported so the sandbox keeps
  working if the rule engine's shape changes; the two lists are checked against each
  other in `test/provider/native/sandbox_test.exs`.

  **The `.git` consequence is real and is not a bug.** A sandboxed `git commit` fails,
  because committing writes into `.git`. That is Codex's rule and it is kept for
  Codex's reason: the repository's history is the one thing a session must not be able
  to rewrite behind the operator's back. Commits go through a human or through a
  session the operator moved off the sandbox.

  ## What it does not do

  No seccomp filter on Linux, so a bubblewrap session constrains the filesystem and the
  network namespace but not the syscall surface. No domain allowlist and no proxy:
  network is on or off, never "these hosts". `sandbox-exec` is deprecated by Apple —
  it still works on macOS 26 and it is what Codex ships, but it carries that warning.
  The bubblewrap path is unit-tested only: `bwrap` is not installed on the machine this
  slice was written on, so its argv is pinned byte for byte and its behaviour is not
  claimed.
  """

  require Logger

  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.SandboxExec

  @typedoc "Which OS mechanism this node can actually use."
  @type backend :: :sandbox_exec | :bwrap | :none

  @typedoc "What `detect/0` found, once, for this node."
  @type detection :: %{
          backend: backend(),
          executable: String.t() | nil,
          version: String.t() | nil,
          notes: String.t()
        }

  @typedoc "The resolved rules one wrapped command runs under."
  @type policy :: %{
          mode: :read_only | :workspace_write,
          writable: [String.t()],
          protected: [String.t()],
          protected_segments: [String.t()],
          scratch: String.t(),
          network: boolean()
        }

  @typedoc "A command to wrap: a shell line, or an executable and its argv."
  @type command :: {:shell, String.t()} | {:argv, [String.t()]}

  @cache_key {__MODULE__, :detection}

  # `.git` is Codex's rule; `.ouroboros` is this runtime's own, and both are already the
  # protected write segments `Ouroboros.Control.Permissions.Rules` denies.
  @protected_segments [".git", ".ouroboros"]

  @scratch_prefix "ouroboros-sandbox-"
  # Six hours against a ten-minute command ceiling: wide enough that a live scratch
  # directory can never be mistaken for an abandoned one.
  @abandoned_after_seconds 6 * 60 * 60
  @sweep_limit 200

  @none %{
    backend: :none,
    executable: nil,
    version: nil,
    notes: "no OS sandbox on this node: neither sandbox-exec nor bwrap is available"
  }

  # ------------------------------------------------------------------ detection

  @doc """
  What this node can sandbox with, probed once and cached.

  Cached in `:persistent_term` because it is a property of the machine, not of a
  session, and every `bash` call would otherwise stat the same two paths. The
  configuration override is read *before* the cache so an operator who sets
  `config :ouroboros, native_sandbox: :none` does not have to restart the node to be
  believed.
  """
  @spec detect() :: detection()
  def detect do
    case Application.get_env(:ouroboros, :native_sandbox) do
      :none ->
        %{@none | notes: "OS sandbox disabled by `config :ouroboros, native_sandbox: :none`"}

      _probe ->
        case :persistent_term.get(@cache_key, nil) do
          nil ->
            detection = probe()
            :persistent_term.put(@cache_key, detection)
            detection

          cached ->
            cached
        end
    end
  end

  @doc "Forgets the cached probe. For tests and for an operator who installed a backend."
  @spec forget() :: :ok
  def forget do
    _ = :persistent_term.erase(@cache_key)
    :ok
  end

  @doc "The string a client shows for a backend: `sandbox-exec`, `bwrap`, or `none`."
  @spec label(detection() | backend()) :: String.t()
  def label(%{backend: backend}), do: label(backend)
  def label(:sandbox_exec), do: "sandbox-exec"
  def label(:bwrap), do: "bwrap"
  def label(:none), do: "none"

  @doc """
  The `sandbox` field a `bash` tool call carries, so a client can name it per command.

  `%{}` for every other tool: only `bash` runs an uninspected program, so only `bash`
  has a sandbox to report. The value is what the command *will* run under, derived from
  the same `decide/2` the tool uses, not from the backend alone — a `workspace_write`
  session on a node with a backend says `"sandbox-exec"`, the same session with the
  sandbox configured off says `"none"`.
  """
  @spec tool_call_marker(String.t(), map(), detection()) :: map()
  def tool_call_marker(name, scope, detection \\ detect())

  def tool_call_marker("bash", scope, detection) do
    case decide(scope, detection) do
      {:sandboxed, label, _policy} -> %{"sandbox" => label}
      _unsandboxed_or_refused -> %{"sandbox" => "none"}
    end
  end

  def tool_call_marker(_other_tool, _scope, _detection), do: %{}

  # ------------------------------------------------------------------- decision

  @doc """
  Whether this command runs wrapped, runs plain, or does not run.

  See the moduledoc for the three outcomes. An unrecognised `sandbox_mode` is refused:
  a mode nobody wrote a policy for is not the same as `workspace_write`, and guessing
  which way to round it is how a containment check grows a hole.
  """
  @spec decide(map(), detection()) ::
          {:sandboxed, String.t(), policy()} | {:unsandboxed, term()} | {:refused, term()}
  def decide(scope, detection \\ detect()) do
    case normalize(Map.get(scope, :sandbox_mode)) do
      mode when mode in [:read_only, :workspace_write] ->
        case detection.backend do
          :none when mode == :read_only -> {:refused, {:read_only_without_backend, detection}}
          :none -> {:unsandboxed, {:no_backend, detection}}
          _present -> {:sandboxed, label(detection), policy(scope, mode)}
        end

      :unrestricted ->
        Logger.warning(
          "native bash running with no OS sandbox: sandbox_mode: :unrestricted was requested"
        )

        {:unsandboxed, :unrestricted}

      other ->
        {:refused, {:unknown_sandbox_mode, other}}
    end
  end

  @doc """
  The rules a wrapped command runs under, before a scratch directory is attached.

  `scratch/0` fills the last field; `policy/2` is separate from it so the profile can be
  generated and compared in a test without a directory being created on disk.
  """
  @spec policy(map(), :read_only | :workspace_write) :: policy()
  def policy(scope, mode) do
    %{
      mode: mode,
      writable: writable(scope, mode),
      protected: protected_roots(),
      protected_segments: @protected_segments,
      scratch: nil,
      network: network_allowed?()
    }
  end

  @doc "Attaches a scratch directory to a policy, so `$TMPDIR` has somewhere to point."
  @spec with_scratch(policy(), String.t()) :: policy()
  def with_scratch(policy, scratch) when is_binary(scratch),
    do: %{policy | scratch: scratch, writable: [scratch | policy.writable]}

  # -------------------------------------------------------------------- scratch

  @doc """
  A private directory this one command may write into, whatever its mode.

  Read-only means read-only about the *workspace*, not about the process's own
  scratch space: `mktemp`, `make`, `cc` and every configure script want a `$TMPDIR`,
  and a sandbox that denies one turns "read-only" into "cannot run a compiler". The
  directory is `0700`, outside every session root, and removed when the command ends.

  It also sweeps abandoned ones on the way in, because "removed when the command ends"
  is not always in this runtime's gift: `Ouroboros.Provider.Native.Tools.execute/4`
  ends a tool that overran its own deadline with `Task.shutdown(task, :brutal_kill)`,
  and a killed process runs no `after` clause. The sweep is the only thing that keeps
  that from being an unbounded leak. It is deliberately not a timer or a supervised
  process: a directory nobody is sweeping on a node where nobody is running `bash` is
  not a problem worth a process tree.
  """
  @spec scratch() :: {:ok, String.t()} | {:error, term()}
  def scratch do
    sweep()

    name = @scratch_prefix <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    path = Path.join(System.tmp_dir!(), name)

    with :ok <- File.mkdir_p(path),
         :ok <- File.chmod(path, 0o700),
         {:ok, canonical} <- Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical}
    else
      {:error, reason} -> {:error, {:scratch_unavailable, reason}}
    end
  end

  @doc """
  Removes scratch directories left behind by commands that were killed rather than ended.

  Older than #{div(@abandoned_after_seconds, 3600)} hours, which cannot be a live one:
  a `bash` command's own ceiling is ten minutes (`Tools.Bash`'s `@max_timeout_ms`), so
  anything this old belongs to a process that is gone. Bounded at
  #{@sweep_limit} directories per call so a crowded temp directory costs a bounded
  amount of work rather than a growing one.
  """
  @spec sweep() :: :ok
  def sweep do
    root = System.tmp_dir!()
    cutoff = System.os_time(:second) - @abandoned_after_seconds

    case File.ls(root) do
      {:ok, entries} ->
        entries
        |> Stream.filter(&String.starts_with?(&1, @scratch_prefix))
        |> Stream.map(&Path.join(root, &1))
        |> Stream.filter(&abandoned?(&1, cutoff))
        |> Enum.take(@sweep_limit)
        |> Enum.each(&File.rm_rf/1)

      {:error, _unreadable} ->
        :ok
    end

    :ok
  end

  defp abandoned?(path, cutoff) do
    match?(
      {:ok, %File.Stat{type: :directory, mtime: mtime}} when mtime < cutoff,
      File.stat(path, time: :posix)
    )
  end

  @doc "Removes a scratch directory and everything the command left in it."
  @spec release(String.t() | nil) :: :ok
  def release(path) when is_binary(path) do
    _ = File.rm_rf(path)
    :ok
  end

  def release(_absent), do: :ok

  # ----------------------------------------------------------------------- wrap

  @doc """
  Turns one command into its sandboxed form for the detected backend.

  Returns the executable to spawn and its argv. `{:error, :no_backend}` when the node
  has nothing to wrap with — the caller decides whether that is a refusal or a
  documented weaker posture, because only the caller knows the mode.
  """
  @spec wrap(command(), map(), policy(), detection()) ::
          {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, scope, policy, detection \\ detect())

  def wrap(_command, _scope, %{scratch: nil}, _detection), do: {:error, :no_scratch_directory}

  def wrap(command, scope, policy, %{backend: :sandbox_exec, executable: executable}),
    do: SandboxExec.wrap(command, scope, policy, executable)

  def wrap(command, scope, policy, %{backend: :bwrap, executable: executable}),
    do: Bwrap.wrap(command, scope, policy, executable)

  def wrap(_command, _scope, _policy, %{backend: :none}), do: {:error, :no_backend}

  @doc "The environment a sandboxed child needs, on top of whatever it inherits."
  @spec env(policy()) :: [{String.t(), String.t()}]
  def env(%{scratch: scratch}) when is_binary(scratch),
    do: [{"TMPDIR", scratch}, {"TMP", scratch}, {"TEMP", scratch}]

  def env(_policy), do: []

  # ------------------------------------------------------------------ violation

  @doc """
  Whether the backend itself failed to apply the policy, rather than the command failing.

  `sandbox-exec` reports a profile it cannot compile on stderr with its own name in
  front of the message and exits `65`; a backend failure is not the command's exit
  status and must not be reported as one, because the difference between "your command
  is wrong" and "this node could not sandbox it" is the difference between fixing a
  command and reconfiguring a session.
  """
  @spec backend_failure(String.t(), String.t(), integer()) :: String.t() | nil
  def backend_failure(label, output, status) do
    first = output |> String.split("\n", parts: 2) |> List.first() |> Kernel.||("")

    if status != 0 and String.starts_with?(first, label <> ": "), do: first, else: nil
  end

  @doc """
  Names the constraint a failed sandboxed command looks to have hit, or `nil`.

  This is evidence, not divination. A Seatbelt denial reaches a program as `EPERM` and
  every program spells `EPERM` the same way — `Operation not permitted` — which is why
  that string, and only that string, is what is matched here; `Permission denied` is
  `EACCES`, an ordinary file mode, and treating it as a sandbox denial would be a
  guess. bubblewrap denies differently: a read-only bind answers `EROFS`
  (`Read-only file system`) and an unshared network answers `ENETUNREACH`
  (`Network is unreachable`). The matched line is quoted back, so a reader can judge
  the attribution instead of trusting it.

  Returns `%{constraint: :network | :filesystem, evidence: line}`.
  """
  @spec violation(policy(), String.t(), integer()) :: map() | nil
  def violation(_policy, _output, 0), do: nil

  def violation(policy, output, _status) do
    output
    |> String.split("\n")
    |> Enum.find(&denial_line?/1)
    |> case do
      nil -> nil
      line -> %{constraint: constraint(line, policy), evidence: String.trim(line)}
    end
  end

  @doc """
  What to say to the model when the sandbox stopped a command.

  Cursor's rule (R3 §11): surface the *violated constraint* and recommend the
  escalation, so the model asks a human for a different posture rather than retrying
  the same command until the loop detector stops it.
  """
  @spec escalation(map(), policy(), String.t()) :: String.t()
  def escalation(%{constraint: constraint, evidence: evidence}, policy, label) do
    "\nThe sandbox (#{label}, sandbox_mode: #{policy.mode}) appears to have stopped this " <>
      "command: #{evidence}\n" <>
      constraint_text(constraint, policy) <>
      "\nDo not retry the same command. Ask the human — with `ask_user` — whether to " <>
      escalation_text(constraint, policy) <>
      " If they say no, find a way to do this that stays inside the sandbox."
  end

  @doc "The refusal text for a `read_only` session on a node with no backend."
  @spec no_backend_refusal(detection()) :: String.t()
  def no_backend_refusal(detection) do
    "this session runs with sandbox_mode: read_only and this node has no OS sandbox " <>
      "backend — #{detection.notes}. Without one a shell cannot be made read-only, so " <>
      "read_only refuses `bash` entirely rather than pretending. Install bubblewrap " <>
      "(Linux), run on macOS where `sandbox-exec` is present, or ask the human to " <>
      "reconfigure this session with sandbox_mode: workspace_write."
  end

  # ---------------------------------------------------------------- internals

  defp probe do
    case :os.type() do
      {:unix, :darwin} -> probe_darwin()
      {:unix, _other} -> probe_linux()
      _unsupported -> @none
    end
  end

  defp probe_darwin do
    case executable("/usr/bin/sandbox-exec") do
      nil ->
        %{@none | notes: "macOS without /usr/bin/sandbox-exec"}

      path ->
        %{
          backend: :sandbox_exec,
          executable: path,
          # `sandbox-exec` has no version flag; claiming one would mean inventing it.
          version: nil,
          notes:
            "macOS Seatbelt through #{path}. Apple marks sandbox-exec deprecated; it is " <>
              "still functional and is the mechanism Codex CLI and Cursor use."
        }
    end
  end

  defp probe_linux do
    case System.find_executable("bwrap") do
      nil ->
        %{@none | notes: "Linux without bwrap (bubblewrap) on PATH"}

      path ->
        %{
          backend: :bwrap,
          executable: path,
          version: bwrap_version(path),
          notes:
            "Linux bubblewrap through #{path}. Filesystem and network namespace only: " <>
              "no seccomp filter, so the syscall surface is not narrowed."
        }
    end
  end

  defp bwrap_version(path) do
    case System.cmd(path, ["--version"], stderr_to_stdout: true) do
      {output, 0} -> output |> String.trim() |> String.slice(0, 64)
      _unavailable -> nil
    end
  rescue
    _error -> nil
  end

  defp executable(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, mode: mode}} ->
        if Bitwise.band(mode, 0o111) != 0, do: path, else: nil

      _absent ->
        nil
    end
  end

  # `Ouroboros.Provider.Native.Loop.sandbox_mode/1`'s vocabulary, plus Codex's own name
  # for the mode the harness calls `:unrestricted`, so a caller who writes what Codex
  # documents is understood rather than refused.
  defp normalize(mode) when mode in [nil, :default], do: :workspace_write
  defp normalize(:danger_full_access), do: :unrestricted
  defp normalize(mode), do: mode

  defp writable(_scope, :read_only), do: []

  defp writable(scope, :workspace_write) do
    scope
    |> Map.get(:roots, [])
    |> List.wrap()
    |> Enum.concat(List.wrap(Map.get(scope, :root)))
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp protected_roots do
    [
      Application.get_env(:ouroboros, :data_dir),
      Application.get_env(:ouroboros, :native_data_dir)
    ]
    |> Enum.concat([config_dir()])
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.flat_map(fn root ->
      case Ouroboros.Workspace.Path.canonicalize(root) do
        {:ok, canonical} -> [canonical]
        {:error, _absent} -> []
      end
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp config_dir do
    case System.get_env("XDG_CONFIG_HOME") do
      dir when is_binary(dir) and dir != "" ->
        Path.join(dir, "ouroboros")

      _unset ->
        case System.user_home() do
          home when is_binary(home) and home != "" -> Path.join([home, ".config", "ouroboros"])
          _no_home -> nil
        end
    end
  end

  defp network_allowed?,
    do: Application.get_env(:ouroboros, :native_sandbox_network, false) == true

  defp denial_line?(line) do
    String.contains?(line, "Operation not permitted") or
      String.contains?(line, "Read-only file system") or
      String.contains?(line, "Network is unreachable")
  end

  @network_signatures [
    "connect",
    "connectx",
    "bind:",
    "getaddrinfo",
    "resolve host",
    "Network is unreachable",
    "socket"
  ]

  defp constraint(line, _policy) do
    if Enum.any?(@network_signatures, &String.contains?(line, &1)),
      do: :network,
      else: :filesystem
  end

  defp constraint_text(:network, _policy),
    do: "This session's sandbox denies all network access."

  defp constraint_text(:filesystem, %{mode: :read_only}),
    do:
      "This session's sandbox allows no writes at all outside $TMPDIR, which points at a " <>
        "scratch directory this command owns."

  defp constraint_text(:filesystem, %{mode: :workspace_write, writable: writable}),
    do:
      "This session's sandbox allows writes only under " <>
        Enum.join(writable, ", ") <>
        " — and never into a `.git` or `.ouroboros` directory beneath them, the node's " <>
        "data directory, or the user's ouroboros config."

  defp escalation_text(:network, _policy),
    do:
      "allow this session's shell to reach the network. This node turns that on with " <>
        "`config :ouroboros, native_sandbox_network: true`, which lifts it for every " <>
        "native session on the node — there is no per-domain allowlist yet."

  defp escalation_text(:filesystem, %{mode: :read_only}),
    do:
      "move this session to `sandbox_mode: workspace_write`, which makes the workspace " <>
        "writable while keeping `.git` and the runtime's own config read-only."

  defp escalation_text(:filesystem, %{mode: :workspace_write}),
    do:
      "add the directory this needs to the session's `add_dirs`, or — if the write was " <>
        "into `.git` — do it themselves. A commit is deliberately outside what this " <>
        "sandbox permits, and this provider does not offer a full-access mode to escape " <>
        "into."
end
