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
  | `:read_only` | reads anywhere the process could already read; writes **only** into a per-call scratch directory that `$TMPDIR` points at | external network denied; loopback available for local IPC |
  | `:workspace_write` | the above, plus writes under `scope.root` and every `scope.roots` entry — with any `.git` or `.ouroboros` segment beneath them, the node's data directory, and `$XDG_CONFIG_HOME/ouroboros` (or `~/.config/ouroboros`) kept read-only | external network denied unless the node opts in; loopback available for local IPC |
  | `:unrestricted` | no sandbox, logged | no sandbox |

  An approved one-command filesystem escalation uses a fourth, internal policy:
  `:workspace_write_escalated`. It keeps the same writable roots, protected data/config
  roots, `.ouroboros` segment fence, and network policy as `workspace_write`; it lifts
  only the `.git` segment fence. That is sufficient for the ordinary escalation case
  (`git commit`) without ever turning an opaque shell command into an unsandboxed one.

  The protected set mirrors `Ouroboros.Control.Permissions.Rules`' own protected paths
  — the same policy, enforced a second time by the kernel rather than by a rule the
  shell never crosses. It is recomputed here rather than imported so the sandbox keeps
  working if the rule engine's shape changes; the two lists are checked against each
  other in `test/provider/native/sandbox_test.exs`.

  **The `.git` consequence is real and is not a bug.** A sandboxed `git commit` fails,
  because committing writes into `.git`. That is Codex's rule and it is kept for
  Codex's reason: the repository's history is the one thing a session must not be able
  to rewrite behind the operator's back. What has changed is what happens next: a
  filesystem denial under `workspace_write` is now escalatable — `escalatable?/3` says
  whether this particular denial is one an operator may lift, and
  `Ouroboros.Provider.Native.Loop` asks them, once, per command. A commit therefore
  still goes through a human; it no longer goes through a human *and* a restarted
  session.

  `escalatable?/3` is deliberately narrow, and never says yes for:

    * a **network** denial — external network is a node-level setting
      (`config :ouroboros, native_sandbox_network: true`), not something one command's
      approval can lift for one command;
    * a **`read_only`** session — the honest advice there is still `workspace_write`,
      because a read-only label the shell can step out of is the lie this module was
      written to stop telling;
    * a denial whose evidence, or whose command line, names one of `protected_names/0`
      or an `.ouroboros` directory. Those are the runtime's own state and the
      operator's own configuration; the answer there stays "do it yourself". The check
      is textual — a shell command cannot be decomposed into the paths it will touch —
      so it is conservative by construction: it refuses to offer an escalation whenever
      those names appear at all, in either the configured or the canonicalized spelling.

  That text check is only a user-experience filter, not the security boundary. A shell
  can hide a path behind an environment variable, symlink, command substitution, or
  another process. The approved re-run therefore remains inside the OS sandbox, whose
  protected roots are path-based and still enforced after every such indirection.

  ## What it does not do

  Linux has two backends and they are not equally strong. `ouro-sandbox`
  (`Sandbox.Helper`) is preferred where the kernel supports it: read-only mounts *and* a
  Landlock domain for the filesystem, an unshared network namespace, and a small seccomp
  denylist. `bwrap` is the fallback and constrains the filesystem and the network namespace
  but not the syscall surface.

  **Both** still depend on the `LD_PRELOAD` name filter for one case: denying the creation
  of a `.git` / `.ouroboros` directory that did not exist when the command started. Landlock
  attaches rights to inodes, so it cannot write a rule for a path that does not exist, and
  the only right that would cover it — `MAKE_DIR` on the parent — would deny every
  legitimate `mkdir` in the workspace. Static binaries that never call libc are outside that
  net, on either backend. `Sandbox.Helper`'s moduledoc has the layer-by-layer table.

  All three backends now fence **reads** as well, in the one policy that asks for it:
  `builder_policy/1` names its read roots and everything else is denied — Seatbelt by
  `(deny default)`, bubblewrap by never binding `/` into the namespace, `ouro-sandbox` by a
  Landlock read set that is the allow-list rather than `/`. `fences_reads?/1` is the
  question a caller asks first, and for `ouro-sandbox` it is answered by the probed helper
  rather than by the backend's name, because a helper binary older than the field would
  apply the rest of the policy and silently drop the fence.

  No domain allowlist and no proxy: external network is on or off, never "these hosts". A
  network-denied macOS command retains loopback for build-tool IPC; both Linux backends
  keep an isolated network namespace with loopback up. `sandbox-exec` is deprecated by
  Apple — it still works on macOS 26 and it is what Codex ships, but it carries that
  warning.

  Live bubblewrap behaviour is claimed only where the live suite runs: Linux CI on
  ubuntu-24.04, which installs `bwrap` and exercises the filesystem denials. The
  `ouro-sandbox` helper's enforcement was observed on Linux 7.0 with Landlock ABI 8 —
  filesystem denials, the network posture, capability drop, the seccomp belt, and the
  builder read fence (a build reads the roots it was given, is refused a canary beside them
  with `Permission denied`, and gets no root at all from an empty allow-set) — by
  `tui/sandbox/tests/linux_enforcement.rs`, which is skipped with a printed reason where
  the kernel or the container cannot enforce. Neither Linux suite runs on a Mac.
  """

  require Logger

  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.Helper
  alias Ouroboros.Provider.Native.Sandbox.SandboxExec

  @typedoc "Which OS mechanism this node can actually use."
  @type backend :: :sandbox_exec | :ouro_sandbox | :bwrap | :none

  @typedoc """
  What `detect/0` found, once, for this node.

  `read_fence` says whether this particular backend, as installed here, can enforce a
  builder policy's read allow-set. It is part of the detection rather than a property of
  the backend name because one of the three backends is a helper binary this repository
  ships: an `ouro-sandbox` older than W17 is the same backend under the same name with no
  read allow-set in its wire format, and `fences_reads?/1` asks the probe rather than the
  name so that node refuses to forge instead of forging unfenced.
  """
  @type detection :: %{
          backend: backend(),
          executable: String.t() | nil,
          version: String.t() | nil,
          notes: String.t(),
          read_fence: boolean()
        }

  @typedoc """
  The resolved rules one wrapped command runs under.

  `network` is the external network. `loopback` is separate and defaults to **true** where it
  is absent, because every policy but the helper's wants it: `network: false` on macOS has
  always re-allowed `localhost` bind, inbound and outbound, since `mix` coordinates its
  concurrent compilers over loopback sockets and a build that cannot open one fails `:eperm`
  without ever reaching another machine. `loopback: false` takes that exception away — the
  helper speaks stdio and has no use for a socket, and a loopback it could open is every
  service on this machine, this node's own gateway included (W16, D25).

  `process` is the process posture, and it defaults to **`:open`** where it is absent: the
  child may fork, may exec anything it can read, and may look up mach services — what a shell
  needs to exist and what a forge needs, because cargo forks and execs rustc. `:sealed` (W21)
  is what `helper_policy/1` asks for: the child may exec only the executable it was spawned
  as, may not fork, has no `mach-lookup`, reads `sysctl` only under the `hw.` prefix, and can
  `stat` only the root directory itself and what it may already read. Only Seatbelt can
  express it (`seals_process?/1`); the two Linux backends render a sealed policy exactly as
  they render an open one, and the pool's status says which of the two actually applied.
  """
  @type policy :: %{
          optional(:readable) => [String.t()],
          optional(:loopback) => boolean(),
          optional(:process) => :sealed | :open,
          mode: :read_only | :workspace_write | :workspace_write_escalated | :builder,
          writable: [String.t()],
          protected: [String.t()],
          protected_segments: [String.t()],
          scratch: String.t() | nil,
          network: boolean()
        }

  @typedoc "A command to wrap: a shell line, or an executable and its argv."
  @type command :: {:shell, String.t()} | {:argv, [String.t()]}

  @cache_key {__MODULE__, :detection}

  # `.git` is Codex's rule; `.ouroboros` is this runtime's own, and both are already the
  # protected write segments `Ouroboros.Control.Permissions.Rules` denies.
  @protected_segments [".git", ".ouroboros"]

  # The read set every build starts from on this OS: the toolchain's own world and nothing
  # else. A compiler has to read a great deal — its libraries, its linker, the SDK it links
  # against, the caches it keeps — and the mistake the first cut of the builder made was
  # concluding from that that reads could not be fenced at all. They can; the set is just
  # long. Everything a *project* could want to read that is not in here plus the roots the
  # caller names is denied, and that is the whole of D18's read half.
  @darwin_readable [
    "/usr/lib",
    "/usr/bin",
    "/usr/share",
    "/bin",
    "/System",
    "/private/var/db",
    "/dev",
    "/private/etc",
    "/Library/Preferences",
    "/Applications/Xcode.app"
  ]

  # Observed under both Linux backends on kernel 7.0.14, but no longer by the same run:
  # `scripts/forge-linux-test.sh` proved the bubblewrap form in W14 and, since W17 builds
  # `ouro-sandbox` in that container, now proves the `ouro-sandbox` form instead — because
  # detection prefers the helper once it is installed. bubblewrap's half is CI's ubuntu-24.04
  # job, which installs `bwrap` and does not build the helper. Either way the escape tests —
  # `include_str!` of a planted secret, a `#[path]` module outside the project — are red
  # without the fence, with the honest fixture building beside them.
  #
  # Two things this list does not fence, on any backend, and both are D26's to state: `/etc`
  # is in it, so an operator's secrets under `/etc` are readable by build-time code; and a
  # path outside it is still *stat*-able, because a read fence governs opening a file and not
  # learning that it is there. What remains unverified is the composition of this list with a
  # distribution whose toolchain lives somewhere it does not name; a build there fails closed,
  # loudly, rather than reading more than it should.
  # No `/dev` and no `/proc`: bubblewrap mounts a fresh devtmpfs and a fresh procfs for the
  # namespace, and a read-only bind of the host's over the top of either replaces it — which
  # is how the first cut of this list produced a build whose very first act was
  # `cannot create /dev/null: Permission denied`. They are the backend's to provide, not
  # this list's to name. `ouro-sandbox` keeps both writable in every mode for the same
  # reason and adds them to the builder read set itself, so neither belongs here for either
  # backend.
  @linux_readable ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32", "/etc", "/opt"]

  @scratch_prefix "ouroboros-sandbox-"
  # Six hours against a ten-minute command ceiling: wide enough that a live scratch
  # directory can never be mistaken for an abandoned one.
  @abandoned_after_seconds 6 * 60 * 60
  @sweep_limit 200

  @none %{
    backend: :none,
    executable: nil,
    version: nil,
    notes:
      "no OS sandbox on this node: none of ouro-sandbox, sandbox-exec, or bwrap is available",
    unshare_net: false,
    read_fence: false
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
  def label(:ouro_sandbox), do: "ouro-sandbox"
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
    case decision(scope, detection) do
      {:sandboxed, label, _policy} -> %{"sandbox" => label}
      _unsandboxed_or_refused -> %{"sandbox" => "none"}
    end
  end

  def tool_call_marker(_other_tool, _scope, _detection), do: %{}

  # ------------------------------------------------------------------- decision

  @doc """
  The pure sandbox decision shared by execution, event metadata, and the system prompt.

  An unrecognised `sandbox_mode` is refused: a mode nobody wrote a policy for is not the
  same as `workspace_write`, and guessing which way to round it is how a containment
  check grows a hole.
  """
  @spec decision(map(), detection()) ::
          {:sandboxed, String.t(), policy()} | {:unsandboxed, term()} | {:refused, term()}
  def decision(scope, detection \\ detect()) do
    case normalize(Map.get(scope, :sandbox_mode)) do
      mode when mode in [:read_only, :workspace_write] ->
        case detection.backend do
          :none when mode == :read_only -> {:refused, {:read_only_without_backend, detection}}
          :none -> {:unsandboxed, {:no_backend, detection}}
          _present -> {:sandboxed, label(detection), policy(scope, mode)}
        end

      :workspace_write_escalated ->
        case detection.backend do
          :none -> {:refused, {:escalation_without_backend, detection}}
          _present -> {:sandboxed, label(detection), policy(scope, :workspace_write_escalated)}
        end

      :unrestricted ->
        {:unsandboxed, :unrestricted}

      other ->
        {:refused, {:unknown_sandbox_mode, other}}
    end
  end

  @doc """
  Whether this command runs wrapped, runs plain, or does not run.

  This is the operational form of `decision/2`: it additionally logs an explicitly
  unrestricted posture. Prompt construction and event metadata use `decision/2` so
  inspecting a session does not emit an execution warning.
  """
  @spec decide(map(), detection()) ::
          {:sandboxed, String.t(), policy()} | {:unsandboxed, term()} | {:refused, term()}
  def decide(scope, detection \\ detect()) do
    result = decision(scope, detection)

    if result == {:unsandboxed, :unrestricted} do
      Logger.warning(
        "native bash running with no OS sandbox: sandbox_mode: :unrestricted was requested"
      )
    end

    result
  end

  @doc """
  The rules a wrapped command runs under, before a scratch directory is attached.

  `scratch/0` fills the last field; `policy/2` is separate from it so the profile can be
  generated and compared in a test without a directory being created on disk.
  """
  @spec policy(map(), :read_only | :workspace_write | :workspace_write_escalated) :: policy()
  def policy(scope, mode) do
    %{
      mode: mode,
      writable: writable(scope, mode),
      protected: protected_roots(),
      protected_segments: protected_segments(mode),
      scratch: nil,
      network: network_allowed?()
    }
  end

  @doc """
  The policy a build runs under: deny-by-default on **reads** as well as on writes.

  Every other policy this module makes allows `file-read*` everywhere, because a shell that
  cannot read is not a shell. A build is the case where that is wrong: the thing being
  contained is a compiler running code an author wrote, and the whole point of the fence is
  that what it can carry into its output is bounded. So a builder policy names its readable
  roots and everything else is denied — a `readable` list on top of `platform_readable/0`,
  with the writable roots readable by construction.

  It is not a `sandbox_mode` and does not come out of `decide/2`: no session picks it, no
  operator configures it, and there is no way to ask for it from a signal. The callers are
  `Ouroboros.Wasm.Forge` (docs/WASM.md D18) and, through `helper_policy/1`, the `ouro-wasm`
  helper (D25). Network is off, flatly, rather than following the node's
  `native_sandbox_network` opt-in — that setting is about a human's shell.
  """
  @spec builder_policy(keyword()) :: policy()
  def builder_policy(opts) do
    %{
      mode: :builder,
      writable: roots(Keyword.get(opts, :writable, [])),
      readable: roots(platform_readable() ++ Keyword.get(opts, :readable, [])),
      protected: [],
      protected_segments: [],
      scratch: nil,
      network: false,
      # A build keeps the loopback exception: `mix` and `cargo` coordinate concurrent
      # compilers over `localhost` sockets, and a build that cannot open one fails `:eperm`
      # without ever having reached another machine. `helper_policy/1` is the caller that
      # does not want it.
      loopback: Keyword.get(opts, :loopback, true) == true,
      # A forge is a process tree: cargo forks and execs rustc, rustc forks and execs the
      # linker. `helper_policy/1` is the caller that is one process and says so.
      process: :open
    }
  end

  @doc """
  The policy the `ouro-wasm` helper runs under (docs/WASM.md §7.3a, D25).

  `builder_policy/1`'s shape with the scratch already attached: closed by default on reads,
  a named read allow-set, writable only where the caller says, no network, and — since W21
  — **sealed as a process**. The mode is **`:builder`** and that is deliberate — `:builder`
  is this module's vocabulary for "closed on reads", every backend already implements it
  (`SandboxExec.profile/1`, `Bwrap.options/3`, and W17's `ouro-sandbox` request). What
  differs between a build and the helper is the *lists* and the *process posture*, and both
  are fields of the policy rather than a profile of their own: `loopback` was added that way
  in W16 and `process` the same way here, so the Seatbelt profile is a function of the
  policy's fields and there is no fourth profile to keep in step.

  `opts` takes `:readable`, `:writable`, `:scratch` and `:process`. The scratch is required
  in practice — `wrap/4` refuses a policy without one — and it is passed here rather than
  applied by the caller so that "the policy the helper runs under" is one function with one
  answer, which is what `Ouroboros.Wasm.Pool`'s load-path fence compares a path against.

  What the helper actually needs, and the fence is that there is no more: the platform's own
  toolchain roots (`platform_readable/0`, for the dynamic loader and the C library it links),
  the directory its own binary lives in (which bubblewrap has to bind into the namespace
  before it can `execve` it), and the roots the caller names — this node's component store,
  and at signing time the one directory that signature's files live in. It writes into the
  scratch and nowhere else.

  **And it is one process, so the policy says so.** `process: :sealed` is the default: on
  Seatbelt the child may exec only the executable it was spawned as (`SandboxExec.wrap/4`
  names it as a `-D` parameter, resolved, because the kernel matches the resolved path), may
  not fork, has no `mach-lookup` — no launchd domain, no pasteboard — reads `sysctl` only
  under `hw.` (`hw.pagesize_compat` is what the Rust runtime needs to map a guard page, and
  `hw.optional.*` is what cranelift's feature detection reads: a helper denied those
  compiles for a different CPU than the same helper unsealed, which was measured as a
  different artifact from the same component), and can `stat` only `/` itself and what it
  may already read. The `ouro-wasm` helper is a stdio Rust binary running wasmtime: it never
  forks, never execs and never talks to launchd, so every one of those is a right it did not
  use and a compromised one could — `osascript`'s `do shell script` runs its command outside
  the sandbox, `pbpaste` is the pasteboard over mach, and `stat` over `/` is an existence
  oracle over the whole filesystem. `process: :open` is the opt-out, and it exists for one
  reason: a **scripted** fake helper in this repository's own suites is a `#!/bin/sh` line
  that needs its interpreter exec'd and `awk` forked, which a sealed profile cannot name. A
  sealed policy refuses a `{:shell, _}` command in `wrap/4` for the same reason.

  **And it opens no socket at all, loopback included.** Every other policy this module makes
  keeps a `localhost` exception on macOS, because `mix` and `cargo` coordinate concurrent
  compilers over loopback and a build without it fails `:eperm`. The helper speaks stdio; a
  loopback socket buys it nothing and reaches every service on this machine — this node's own
  gateway among them. So `loopback: false`, which is what `SandboxExec.network_rules/1` reads.
  The two Linux backends unshare the network namespace outright, so the host's loopback is not
  in the child's namespace to begin with and there is nothing there to take away.
  """
  @spec helper_policy(keyword()) :: policy()
  def helper_policy(opts) do
    policy =
      Keyword.take(opts, [:readable, :writable])
      |> Kernel.++(loopback: false)
      |> builder_policy()
      |> Map.put(:process, process_option(Keyword.get(opts, :process)))

    case Keyword.get(opts, :scratch) do
      dir when is_binary(dir) and dir != "" -> with_scratch(policy, dir)
      _none -> policy
    end
  end

  # Sealed unless the caller spells `:open`. Anything else — a typo, a boolean — is sealed,
  # because the wider posture is the one that has to be asked for by name.
  defp process_option(:open), do: :open
  defp process_option(_sealed), do: :sealed

  @doc "The read roots a build gets before its caller names any, for this operating system."
  @spec platform_readable() :: [String.t()]
  def platform_readable do
    case :os.type() do
      {:unix, :darwin} -> @darwin_readable
      {:unix, _other} -> @linux_readable
      _unsupported -> []
    end
  end

  @doc """
  Whether this backend can enforce a policy's **network** denial on this host (W16, D25).

  A second question beside `fences_reads?/1`, and a separate one because a backend can be
  present, apply its filesystem rules, and still leave the child on the host's network.
  `bwrap` is exactly that case: `Bwrap.probe/1` records `unshare_net: false` when the host
  refuses an unshared network namespace (an unprivileged container without
  `CLONE_NEWNET`), and `Bwrap.options/3` then emits no `--unshare-net`, so a policy that says
  `network: false` runs with the host's network anyway. For a shell that is a documented
  weaker posture; for the helper it is a wall with a hole in it, so `Wasm.Pool` asks this
  beside `fences_reads?/1` and refuses `{:cannot_fence_network, backend}` rather than
  reporting a child as sandboxed when it is not.

  Seatbelt denies `network*` in the profile itself, and since W16 a `loopback: false` policy
  emits no local exception either. `ouro-sandbox` unshares the network namespace in its own
  plan and fails to apply — exit 125, which `backend_failure/3` surfaces — rather than running
  the command unfenced.
  """
  @spec fences_network?(detection() | backend()) :: boolean()
  def fences_network?(%{backend: :bwrap} = detection),
    do: Map.get(detection, :unshare_net) == true

  def fences_network?(%{backend: backend}), do: fences_network?(backend)
  def fences_network?(:sandbox_exec), do: true
  def fences_network?(:ouro_sandbox), do: true
  # A backend with no detection map to read `unshare_net` from is not one this can vouch for.
  def fences_network?(:bwrap), do: false
  def fences_network?(:none), do: false

  @doc """
  Whether this backend can seal a policy's **process** (W21, D25): exec only the executable
  the child was spawned as, no fork, no `mach-lookup`, `sysctl` under `hw.` only, and
  metadata reads only where reads are already allowed.

  The third question beside `fences_reads?/1` and `fences_network?/1`, and unlike those two
  it is **not** one `Ouroboros.Wasm.Pool` refuses on: `:required` keeps meaning what D25 says
  — reads and network fenced — and a Linux node runs its helper with an open process posture
  and says so in its status. Seatbelt is the one backend whose policy language names
  `process-exec`, `process-fork`, `mach-lookup` and `sysctl-read` as operations, so it is the
  one that seals. Bubblewrap binds the readable roots into a namespace in which `/usr/bin` is
  readable and executable, and `ouro-sandbox`'s Landlock domain fences reads by inode and does
  not fence `stat` or `execve` at all; both render a sealed policy exactly as they render an
  open one, and `Bwrap.options/3` and `Helper.request/2` are pinned to that.
  """
  @spec seals_process?(detection() | backend()) :: boolean()
  def seals_process?(%{backend: backend}), do: seals_process?(backend)
  def seals_process?(:sandbox_exec), do: true
  def seals_process?(:ouro_sandbox), do: false
  def seals_process?(:bwrap), do: false
  def seals_process?(:none), do: false

  @doc """
  The process posture a policy **actually** gets on this backend: `:sealed` only where the
  policy asks for it and the backend can express it, `:open` otherwise.
  """
  @spec process_posture(policy(), detection() | backend()) :: :sealed | :open
  def process_posture(%{process: :sealed}, detection) do
    if seals_process?(detection), do: :sealed, else: :open
  end

  def process_posture(_open, _detection), do: :open

  @doc """
  Whether this backend can enforce a builder policy's read fence.

  Two of the three answer by name. Seatbelt's `(deny default)` and bubblewrap's refusal to
  bind `/` are properties of mechanisms an operator installs and this repository does not
  version, so `builder_policy/1` either compiles to a fence there or it does not compile
  at all.

  `ouro-sandbox` is the exception and the reason this takes a detection: it is a binary
  *this* repository ships, and one installed before W17 speaks the same protocol version,
  applies the same shell policies, and has no `readable` field to fence a build with. So
  the answer comes from what the probed helper said about itself (`read_fence`, from
  `doctor`'s `features.read_allow_set`), and a detection with no such key — a stale cache,
  a map a test built by hand — is a `false`. Failing closed here costs a node the forge;
  failing open would cost it the fence the forge's whole claim rests on (docs/WASM.md D26).
  """
  @spec fences_reads?(detection() | backend()) :: boolean()
  def fences_reads?(%{backend: :ouro_sandbox} = detection),
    do: Map.get(detection, :read_fence, false) == true

  def fences_reads?(%{backend: backend}), do: fences_reads?(backend)
  def fences_reads?(:sandbox_exec), do: true
  def fences_reads?(:bwrap), do: true
  # A bare `:ouro_sandbox` is a backend name with no probe behind it, and the capability is
  # the helper's to claim rather than the name's, so the name alone claims nothing.
  def fences_reads?(:ouro_sandbox), do: false
  def fences_reads?(:none), do: false

  # Canonicalised, because a root that is a symlink is its *target* to every backend that
  # applies one: Seatbelt's `subpath` resolves it and Landlock's `O_PATH` open follows it, so
  # a policy naming the link would grant the thing it points at under a name that does not
  # say so. `Wasm.Forge.read_set/2` already canonicalises what it puts in the list; doing it
  # here as well means the property belongs to the policy rather than to one caller.
  #
  # A path that cannot be canonicalised — it does not exist yet — is kept exactly as it was
  # written. Dropping it would narrow the policy silently, and a relative one left in is a
  # refusal the helper makes out loud (exit 125) rather than a fence with a hole.
  # Each root as it was named **and** as the kernel resolves it, when the two differ. Seatbelt
  # matches the resolved form (`/var/folders/…` is `/private/var/folders/…` by the time `open`
  # sees it), so the canonical spelling is the one that carries the rule there. Bubblewrap
  # binds nothing it was not told about: on a merged-`/usr` Linux `/bin`, `/lib` and `/lib64`
  # are symlinks into `/usr`, and a list that had resolved them away left a namespace with no
  # `/bin/sh` for a script and no `/lib64/ld-linux-*.so` for a binary — every `execvp` failed
  # with `ENOENT` while the fence looked correct. So the name a process will use is bound too,
  # with bwrap resolving the source; a rule on a spelling the kernel never sees is harmless.
  defp roots(paths) do
    paths
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.flat_map(&[&1, canonical_root(&1)])
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp canonical_root(path) do
    case Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _absent} -> path
    end
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

  A **sealed** policy (W21) wraps only an `{:argv, [absolute | _]}` command, on every
  backend: a `{:shell, _}` is `{:error, :shell_under_sealed_policy}`, because a shell is
  exec and fork and wrapping one sealed would be a child that fails for reasons the profile
  cannot name; a relative argv[0] is `{:error, {:relative_exec_under_sealed_policy, name}}`,
  because the one exec the profile allows is a literal path and a name resolved through
  `$PATH` is not one.
  """
  @spec wrap(command(), map(), policy(), detection()) ::
          {:ok, {String.t(), [String.t()]}} | {:error, term()}
  def wrap(command, scope, policy, detection \\ detect())

  def wrap(_command, _scope, %{scratch: nil}, _detection), do: {:error, :no_scratch_directory}

  def wrap({:shell, _line}, _scope, %{process: :sealed}, _detection),
    do: {:error, :shell_under_sealed_policy}

  def wrap({:argv, [target | _rest]}, _scope, %{process: :sealed}, _detection)
      when not (is_binary(target) and byte_size(target) > 0 and
                  binary_part(target, 0, 1) == "/"),
      do: {:error, {:relative_exec_under_sealed_policy, target}}

  def wrap(command, scope, policy, %{backend: :sandbox_exec, executable: executable}),
    do: SandboxExec.wrap(command, scope, policy, executable)

  def wrap(command, scope, policy, %{backend: :ouro_sandbox, executable: executable}),
    do: Helper.wrap(command, scope, policy, executable)

  def wrap(command, scope, policy, %{backend: :bwrap, executable: executable} = detection),
    do: Bwrap.wrap(command, scope, policy, executable, Map.get(detection, :unshare_net, true))

  def wrap(_command, _scope, _policy, %{backend: :none}), do: {:error, :no_backend}

  @doc "The environment a sandboxed child needs, on top of whatever it inherits."
  @spec env(policy()) :: [{String.t(), String.t()}]
  def env(%{scratch: scratch}) when is_binary(scratch),
    do: [{"TMPDIR", scratch}, {"TMP", scratch}, {"TEMP", scratch}]

  def env(_policy), do: []

  @doc "Marks one approved re-run for the fenced escalation policy."
  @spec escalated_scope(map()) :: map()
  def escalated_scope(scope), do: Map.put(scope, :sandbox_mode, :workspace_write_escalated)

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
  guess. That rule is unchanged by W17, which made `EACCES` the signal a *builder* read
  denial arrives as: this function reads the output of an opaque shell line, where a
  chmod nobody thought about produces the same string, while a build is one program this
  node spawned under a policy it wrote and its denial is read where that is known
  (`Ouroboros.Wasm.Forge`'s suite). One errno, two contexts, and only one of them can
  tell them apart. bubblewrap denies differently: a read-only bind answers `EROFS`
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

  `offered: true` is passed by a caller that has an escalation channel — the loop, which
  puts the denial to the operator itself. The text then says so, and says that reading
  it means no escalation was granted, because on a granted one the re-run's result
  replaces this text entirely. Everywhere else the advice stays what it was: ask a human
  with `ask_user`.
  """
  @spec escalation(map(), policy(), String.t(), keyword()) :: String.t()
  def escalation(violation, policy, label, opts \\ [])

  def escalation(%{constraint: constraint, evidence: evidence}, policy, label, opts) do
    "\nThe sandbox (#{label}, sandbox_mode: #{policy.mode}) appears to have stopped this " <>
      "command: #{evidence}\n" <>
      constraint_text(constraint, policy) <>
      "\n" <> advice(constraint, policy, Keyword.get(opts, :offered, false) == true)
  end

  defp advice(constraint, policy, false),
    do:
      "Do not retry the same command. Ask the human — with `ask_user` — whether to " <>
        escalation_text(constraint, policy) <>
        " If they say no, find a way to do this that stays inside the sandbox."

  defp advice(constraint, policy, true),
    do:
      "Do not retry the same command. This runtime offers the operator a one-command " <>
        "escalation for a denial like this one: approving it re-runs the command once " <>
        "inside a fenced profile that permits workspace `.git` writes but still protects " <>
        "runtime data, config, `.ouroboros`, and the network. That re-run's result is what " <>
        "you would be reading instead of this. Reading this means no escalation was " <>
        "granted — so do not ask " <>
        "for one again with `ask_user`. Either " <>
        escalation_text(constraint, policy) <>
        " Or find a way to do this that stays inside the sandbox."

  @doc """
  The `reason` an escalation approval carries: what was stopped, and which constraint.

  One paragraph, no advice — the advice in an approval modal is the operator's to give,
  not this runtime's to write into the question it is asking them.
  """
  @spec escalation_reason(map(), policy(), String.t()) :: String.t()
  def escalation_reason(%{constraint: constraint, evidence: evidence}, policy, label) do
    "The #{label} sandbox (sandbox_mode: #{policy.mode}) stopped this command: " <>
      "#{evidence}. " <> constraint_text(constraint, policy)
  end

  @doc """
  Whether this denial is one an operator may lift by approving a single fenced re-run.

  Filesystem only, `workspace_write` only, and never when the evidence or the command
  line names a protected root or an `.ouroboros` directory. See the moduledoc for why
  each of those three is a hard no. `command` may be `nil`; then only the evidence is
  read, which is the weaker check and is why the caller should pass the command it ran.
  """
  @spec escalatable?(map() | nil, policy() | nil, String.t() | nil) :: boolean()
  def escalatable?(%{constraint: :filesystem} = violation, %{mode: :workspace_write}, command),
    do: not protected_text?(Map.get(violation, :evidence)) and not protected_text?(command)

  def escalatable?(_violation, _policy, _command), do: false

  # Textual, conservative, and stated as such in the moduledoc. A protected root that
  # appears anywhere in the command line or in the denial the kernel produced is enough
  # to withhold the offer, because this cannot know which of a shell line's several paths
  # the kernel actually refused.
  #
  # `protected_names/0` rather than `protected_roots/0`: a root is matched in *both* the
  # form an operator configured and the form it canonicalizes to, because a shell command
  # and a kernel error message do not agree on which one they use. On macOS the data
  # directory an operator writes as `/var/folders/…` canonicalizes to `/private/var/…`,
  # and matching only the canonical form would have offered an escalation into the
  # runtime's own store.
  defp protected_text?(text) when is_binary(text) do
    Enum.any?(protected_names(), &String.contains?(text, &1)) or ouroboros_dir?(text)
  end

  defp protected_text?(_absent), do: false

  defp ouroboros_dir?(text) do
    String.contains?(text, "/.ouroboros/") or String.ends_with?(text, "/.ouroboros") or
      String.contains?(text, " .ouroboros/") or text == ".ouroboros" or
      String.starts_with?(text, ".ouroboros/")
  end

  @doc "The refusal text for a `read_only` session on a node with no backend."
  @spec no_backend_refusal(detection()) :: String.t()
  def no_backend_refusal(detection) do
    "this session runs with sandbox_mode: read_only and this node has no OS sandbox " <>
      "backend — #{detection.notes}. Without one a shell cannot be made read-only, so " <>
      "read_only refuses `bash` entirely rather than pretending. Install the " <>
      "`ouro-sandbox` helper or bubblewrap (Linux), run on macOS where `sandbox-exec` " <>
      "is present, or ask the human to reconfigure this session with " <>
      "sandbox_mode: workspace_write."
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
          read_fence: true,
          notes:
            "macOS Seatbelt through #{path}. Apple marks sandbox-exec deprecated; it is " <>
              "still functional and is the mechanism Codex CLI and Cursor use."
        }
    end
  end

  # `ouro-sandbox` first, bubblewrap second. The helper is preferred where it can actually
  # enforce — it adds a Landlock domain and a seccomp filter over the same mount semantics
  # — and `Helper.probe/1` returns `nil` rather than a detection when it cannot, so a node
  # whose kernel predates Landlock falls through to bubblewrap instead of selecting a
  # backend that would refuse every command.
  defp probe_linux do
    case probe_helper() do
      nil -> probe_bwrap()
      detection -> detection
    end
  end

  defp probe_helper do
    with path when is_binary(path) <- Helper.executable(),
         %{version: version, notes: notes, read_fence: read_fence} <- Helper.probe(path) do
      %{
        backend: :ouro_sandbox,
        executable: path,
        version: version,
        # What the helper said about itself, not what this node hopes: a binary from before
        # the read allow-set existed reports no feature and this stays `false`.
        read_fence: read_fence,
        notes:
          "Linux ouro-sandbox through #{path}. #{notes}. Filesystem via read-only mounts " <>
            "and a Landlock domain, network via an unshared namespace, and a minimal " <>
            "seccomp denylist#{read_fence_note(read_fence)}. Creating a `.git` that did " <>
            "not exist when the command started is still carried by the LD_PRELOAD " <>
            "filter, not by the kernel."
      }
    else
      _absent_or_unusable -> nil
    end
  end

  defp read_fence_note(true),
    do: ", and a Landlock read allow-set for builder policies"

  defp read_fence_note(false),
    do:
      ". This build has no read allow-set, so a builder policy cannot be fenced with it " <>
        "(docs/WASM.md D26)"

  defp probe_bwrap do
    case System.find_executable("bwrap") do
      nil ->
        %{@none | notes: "Linux without ouro-sandbox or bwrap (bubblewrap) on PATH"}

      path ->
        case Bwrap.probe(path) do
          {:ok, %{version: version, notes: notes, unshare_net: true}} ->
            %{
              backend: :bwrap,
              executable: path,
              version: version,
              read_fence: true,
              notes:
                "Linux bubblewrap through #{path}. #{notes}. Filesystem and network " <>
                  "namespace only: no seccomp filter, so the syscall surface is not narrowed.",
              unshare_net: true
            }

          {:ok, %{version: version, notes: notes, unshare_net: false}} ->
            %{
              backend: :bwrap,
              executable: path,
              version: version,
              read_fence: true,
              notes:
                "Linux bubblewrap through #{path}. #{notes}. Filesystem namespace only: " <>
                  "the host refused an unshared network, so commands keep the host network. " <>
                  "No seccomp filter.",
              unshare_net: false
            }

          {:error, :no_true_executable} ->
            %{
              @none
              | notes:
                  "Linux bubblewrap at #{path} is installed but `true` is not on PATH, " <>
                    "so the capability probe cannot run"
            }

          {:error, :filesystem_namespace_refused} ->
            %{
              @none
              | notes:
                  "Linux bubblewrap at #{path} is installed but cannot apply its read-only " <>
                    "mount on this host"
            }

          {:error, :probe_exception} ->
            %{
              @none
              | notes:
                  "Linux bubblewrap at #{path} is installed but the capability probe failed " <>
                    "unexpectedly"
            }
        end
    end
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

  defp writable(scope, mode) when mode in [:workspace_write, :workspace_write_escalated] do
    scope
    |> Map.get(:roots, [])
    |> List.wrap()
    |> Enum.concat(List.wrap(Map.get(scope, :root)))
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp protected_segments(:workspace_write_escalated), do: [".ouroboros"]
  defp protected_segments(_ordinary), do: @protected_segments

  @doc """
  The roots the sandbox keeps read-only under every mode, canonicalized.

  The node's data directory, the native provider's own data directory, and the user's
  `ouroboros` config. Public because `escalatable?/3` is defined in terms of it and a
  test that checks the two agree should not have to re-derive the list.
  """
  @spec protected_roots() :: [String.t()]
  def protected_roots do
    configured_roots()
    |> Enum.flat_map(fn root ->
      case Ouroboros.Workspace.Path.canonicalize(root) do
        {:ok, canonical} -> [canonical]
        {:error, _absent} -> []
      end
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  @doc """
  Every spelling of a protected root this node might see written down.

  `protected_roots/0` canonicalizes, which is right for a sandbox profile — the kernel
  is given real directories — and wrong for reading a shell command, which says whatever
  the operator or the model typed. This returns both forms, and includes a configured
  root that does not exist yet rather than dropping it: a name nothing is under is a
  name a command should still not be escalated toward.
  """
  @spec protected_names() :: [String.t()]
  def protected_names do
    configured_roots()
    |> Enum.flat_map(fn root ->
      case Ouroboros.Workspace.Path.canonicalize(root) do
        {:ok, canonical} -> [root, canonical]
        {:error, _absent} -> [root]
      end
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp configured_roots do
    [
      Application.get_env(:ouroboros, :data_dir),
      Application.get_env(:ouroboros, :native_data_dir),
      config_dir()
    ]
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
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
    do: "This session's sandbox denies external network access; loopback remains local-only."

  defp constraint_text(:filesystem, %{mode: :builder, writable: writable}),
    do:
      "This build's sandbox allows writes only under " <>
        Enum.join(writable, ", ") <>
        " and reads only under the toolchain roots it was given."

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

  defp constraint_text(:filesystem, %{
         mode: :workspace_write_escalated,
         writable: writable
       }),
       do:
         "This approved re-run still allows writes only under " <>
           Enum.join(writable, ", ") <>
           " — including `.git`, but never `.ouroboros`, the node's data directory, or " <>
           "the user's ouroboros config."

  defp escalation_text(:network, _policy),
    do:
      "allow this session's shell to reach the network. This node turns that on with " <>
        "`config :ouroboros, native_sandbox_network: true`, which lifts it for every " <>
        "native session on the node — there is no per-domain allowlist yet. Moving the " <>
        "session to `sandbox_mode: unrestricted` also lifts it, by removing the sandbox " <>
        "altogether rather than by opening one axis of it."

  defp escalation_text(:filesystem, %{mode: :read_only}),
    do:
      "move this session to `sandbox_mode: workspace_write`, which makes the workspace " <>
        "writable while keeping `.git` and the runtime's own config read-only."

  defp escalation_text(:filesystem, %{mode: :workspace_write}),
    do:
      "approve the one-command fenced re-run if this is a `.git` write, or add the " <>
        "directory this needs to the session's `add_dirs`. The fenced re-run keeps the " <>
        "runtime's own data, config, `.ouroboros`, and network protections in force."
end
