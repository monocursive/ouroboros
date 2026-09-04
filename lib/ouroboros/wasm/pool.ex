defmodule Ouroboros.Wasm.Pool do
  @moduledoc """
  Owns the one `ouro-wasm` helper process this node runs, and speaks its six methods.

  There is exactly one helper on a node, for the reason `Ouroboros.Provider.Native.Desktop.Pool`
  has exactly one: the expensive thing — here a wasmtime engine, its epoch ticker, and the
  compiled-component cache — is per-binary, not per-caller, and a second helper pid would
  buy nothing but a second copy of all of it. This GenServer is that single owner. It spawns
  the resolved helper with the `serve` subcommand, speaks the newline-delimited JSON-RPC of
  `Ouroboros.Wasm.Codec` over its stdio, keeps at most one request in flight, and hands
  every request a hard deadline.

  ## Lazy, always

  Nothing is spawned until a request needs it — including in tests, which is why this pool
  has no eager-connect option at all. A node that never built a helper never spawns one, and
  the *absence* of the binary is `{:error, :unavailable}`, not a fault: presence on disk is
  the operator opt-in (docs/WASM.md §7.3), so an absent helper leaves the pool idle and it
  recovers the moment one is installed, with no cooldown to sit through.

  ## Broken is a state, not a crash

  A helper that fails to spawn, fails or refuses its handshake, dies, floods stdout with
  noise, sends a frame this side will not buffer, or does not answer in time is marked
  **broken** for a cooldown window; every request against it answers at once rather than
  waiting, and the window keeps a helper that fails on every spawn from being respawned on
  every request. A request after the window reconnects.

  A **timeout is broken**, unlike the desktop pool's abandon-and-recover path, and that is a
  fact about this helper rather than a stricter policy: `ouro-wasm` runs every guest under a
  fuel budget, an epoch deadline, and a memory ceiling, so a request that outlives its own
  deadline plus the transport's margin is not slow work — it is a helper wedged somewhere no
  deadline reaches, and a wedged helper answers nothing ever again. The child is killed by
  its os pid before the port closes, so it cannot outlive the pool that owns it.

  ## The handshake is an admission decision

  The handshake is a `doctor` request, and its answer is checked rather than logged: a
  helper whose report is not `usable` (its own probe of whether an engine can be built on
  this host) or whose `worlds` does not include `Ouroboros.Wasm.world/0` is refused and the
  pool goes broken. Admitting it would trade one honest line of JSON for a refusal on every
  later `load`. The accepted report is kept in state and reported by `status/1`, because it
  carries the bounds `instantiate` will accept and there is no other way to learn them.

  ## Wire data is data

  Everything the helper says is somebody else's string. Refusals surface as
  `%{code: integer, refusal: binary, message: binary}` — peers match on `data.refusal`, per
  `tui/wasm/src/refusal.rs` — and nothing on this side is ever turned into an atom, because
  a forged atom is a leak that survives the process that read it. Helper prose is bounded
  before it is stored or replied with, and the frame cap bounds the bytes read but not the
  term they decode to (`Ouroboros.Wasm.Codec`), so the pool also runs its own process under
  a soft `max_heap_size` ceiling: a decode blow-up on a hostile frame is logged, not a
  silent balloon and not a crash of a process holding live-instance bookkeeping.

  ## Instances have owners, because nothing else would ever drop them

  The helper holds `MAX_INSTANCES` and evicts none of them: an instance stands until somebody
  drops it. That is the right policy for a containment helper — forgetting a live guest's
  state on a timer would be a worse bug than holding it — and it makes the *owner* this
  side's problem. `instantiate/6` therefore takes `owner: pid`; the pool monitors that
  process and, when it goes, schedules a `drop` for its instances on this same sequential
  wire, behind whatever callers are already waiting.

  Without it every throwaway agent leaks: a rollout probe and an evaluation each stand an
  instance up under an id carrying a unique integer, stop, and never come back for it, so
  a node walks into `too_many_instances` after a couple of hundred deploys — and a *full*
  helper is not a *broken* one, so nothing here would ever respawn it.

  The reclaim is best-effort by construction and says so: a broken pool forgets its
  ownership entirely (the child is killed and its table with it), the scheduled drops are
  bounded like every other map here, and a drop that cannot be issued is forgotten rather
  than retried forever. An instance with no owner is still perfectly legitimate — it is one
  whose lifetime its caller manages.

  ## Env is deny-by-default

  The helper is spawned with an **allow-list** environment: `PATH`, `HOME`, `TMPDIR`, and
  nothing else this node happens to be holding. It runs untrusted guest code behind a linker
  that imports one host function; it has no business holding this runtime's credentials, and
  a child that cannot read them cannot leak them to the thing it contains.

  A deny-list stood here before and did not hold (F4). It was a regex over names —
  `API_KEY`, `_TOKEN`, `SECRET`, `OAUTH`, `PASSWORD`, `CREDENTIAL`, `GATEWAY_TOKEN` — and
  the real distribution cookie is called `RELEASE_COOKIE` (`rel/env.sh.eex` puts the fleet's
  own cookie there), which that regex does not match; neither do `AWS_ACCESS_KEY_ID`,
  `SSH_AUTH_SOCK`, `DATABASE_URL`, `AUTHORIZATION`, or a `*_PRIVATE_KEY`. Enumerating what a
  secret is called is a losing shape for a containment boundary, so this is the posture
  `Ouroboros.Provider.Native.Exec` already takes: name what the child needs, drop the rest,
  and check the values that survive as well as the names.

  ## The child runs under the OS sandbox, or it does not run (W16, D25)

  Since W8 the helper maps machine code a signer produced — `Component::deserialize` is
  `unsafe` because wasmtime does not validate a serialized artifact against a malicious
  producer (D24) — so the process itself is now something worth walling in. It is spawned
  through `Ouroboros.Provider.Native.Sandbox.wrap/4` under `Sandbox.helper_policy/1`: closed
  by default on reads, readable in the platform's toolchain roots, its own binary's
  directory, this node's **component store**, the forge's build directory and whatever
  `helper_readable` names once `Ouroboros.Wasm.helper_readable/0` has vetted it; writable in a
  per-child scratch this node creates 0700 under `<data_dir>/wasm/scratch/` and nowhere else.
  `$TMPDIR` points at that scratch, and the scratch is removed when the child is.

  **And sealed as a process (W21).** The helper is one stdio Rust binary running wasmtime: it
  never forks, never execs and never talks to launchd, so `Sandbox.helper_policy/1` says
  `process: :sealed` and on Seatbelt the child may exec only the binary it was spawned as (by
  its resolved path, as one `-D` parameter), may not fork, has no `mach-lookup`, reads
  `sysctl` under `hw.` only and can `stat` nothing it may not read. The two Linux backends
  cannot express that and render the policy as they render a build's; the pool does not
  refuse on it — `:required` still means reads and network fenced — and `status/1`'s
  `sandbox.process` says which posture the child actually got: `:sealed`, `:open`, `:off`.
  The one way to an open process posture on Seatbelt is `scripted_helper: true`, a pool start
  option for this repository's own scripted fake helpers, which are shell scripts and must
  exec; there is no configuration key behind it.

  **No network, and that now includes loopback.** Every other policy this runtime makes keeps
  a `localhost` exception on macOS, because `mix` and `cargo` coordinate concurrent compilers
  over loopback sockets. The helper speaks stdio, so `Sandbox.helper_policy/1` sets
  `loopback: false` and the Seatbelt profile emits `(deny network*)` and nothing after it. A
  review proved why it matters: under the old policy a probe connected to a loopback listener,
  and a loopback socket reaches every service on this machine — this node's own gateway
  included. The two Linux backends unshare the network namespace, so the host's loopback is
  not in the child's namespace at all; a `bwrap` that could not unshare one is a refusal to
  spawn (`Sandbox.fences_network?/1`) rather than a child on the host's network.

  **Nothing degrades quietly.** `config :ouroboros, :wasm, helper_sandbox:` is `:required` by
  default, and under it a node with no backend, a backend that cannot fence reads
  (`Sandbox.fences_reads?/1`), or no data directory to put a scratch in **refuses to spawn**:
  the pool goes broken with `{:helper_sandbox_unavailable, reason}` and `wasm.status` names
  it. A node with no fence is a node that does not run wasm, rather than one that runs it a
  little less safely. `:off` spawns plain, says so in the status, and logs one line per spawn.

  ## The fence is stated twice

  Every `load` this pool issues names a file in this node's own **component store** — all five
  call sites, the hook lane included since it stages its bytes there — and the one `inspect`
  names a product the forge just built in this node's own build directory. The sandbox is one
  of the two things that say so. The other is here: a `load` or an `inspect` whose path is not
  under the policy's readable roots is `{:error, {:refused, :path_outside_roots}}` **before** a
  frame is built, so the kernel denies what the pool has already refused. Two statements of
  one rule, because a fence stated only by a backend is a fence that a node without one does
  not have.

  The pool's half resolves symlinks in a path's *directory* and not in its leaf, so a
  symlinked file inside a readable root passes here and is caught by the kernel, which
  evaluates what the link resolves to. A directory this side cannot resolve at all is
  measured as written and is therefore refused. That asymmetry is why there are two walls.
  """

  use GenServer

  require Logger

  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Codec
  alias Ouroboros.Wasm.Store
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  # The only environment variables the helper is given. Deny-by-default, not a deny-list
  # (F4): see the moduledoc for why the name-shaped deny-list this replaces could not hold.
  #
  # The list is short because `ouro-wasm` is a static-ish Rust binary that opens no files it
  # was not handed a path to and makes no network call. `PATH` and `HOME` are what any child
  # is entitled to; `TMPDIR` is what the platform expects a process to write scratch under,
  # and on macOS it is per-user and per-session. `Port.open/2` itself needs nothing here — it
  # `execve`s an absolute path — so this is the child's environment and not the spawn's.
  @inherited_env ~w(PATH HOME TMPDIR)

  # An allowed *name* is not yet an allowed *value*. The three variables above are paths, and
  # a path is not supposed to look like this; a node whose `PATH` somehow carries a
  # credential URI hands the helper one anyway if only the name is checked. The same shape
  # `Ouroboros.Provider.Native.Exec.sensitive_environment?/2` applies, narrowed to what a
  # path can plausibly contain.
  @credential_value ~r{([a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@)|(-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----)}i

  # Lines of non-JSON stdout tolerated before the transport is treated as broken. The helper
  # writes its diagnostics to stderr and its answers to stdout; anything else on stdout is a
  # helper that has stopped speaking the protocol.
  @max_noise 20

  # In-flight is one helper request — the helper is sequential by design, so the queue is
  # how two callers overlap rather than one of them failing `:busy` on arrival.
  @max_queue 8

  # How much helper-written prose is kept or replied with. Every string on this pipe is
  # somebody else's, and the helper's own bound is not this side's to rely on.
  @max_message_bytes 2_048

  # The most live instances the pool tracks a deadline for. Above the helper's own
  # `MAX_INSTANCES` (256, `tui/wasm/src/host.rs`) so it never fights a legitimate corpus,
  # and bounded oldest-first so a peer that instantiates under caller-chosen names — and
  # never `drop`s a trapped one — cannot grow this map without limit. The drift itself is
  # harmless (a stale deadline only picks a wait for a name the helper no longer knows); the
  # unbounded growth is what this caps.
  @max_instances 512

  # The most *distinct* untrusted-hook components one helper's life may admit to its cache.
  # Untrusted only: `lane: :hook`, the operator's own node- and user-scope component hooks,
  # is not budgeted at all (F7). Sharing one counter between the two made the bound
  # self-defeating — a cloned repository spent it on sixteen shas of its own and the
  # operator's trusted `deny` hook then could not load, which is the failure the budget was
  # written to prevent, arrived at from the other side.
  #
  # The helper holds `MAX_COMPONENTS` (64, `tui/wasm/src/host.rs`) in a cache every lane on
  # this node shares, and since W6 it evicts at that ceiling: the least recently used
  # component no live instance holds, named in the `load` that took it. So the hook lane can
  # no longer *fill* the table — the attack W4 found, where one untrusted clone shipping 64
  # components left every later `load` on the node answering `too_many_components`, the
  # capability lane's rollouts quarantined and the operator's own component hook silent, is
  # answered structurally by the helper. What a repository can still do is *churn* the
  # table: its bytes are the one kind nobody signed, every distinct sha it ships is a compile
  # that nothing time-bounds (cranelift runs under the pool's transport deadline and nothing
  # finer), and past the ceiling each one evicts a component somebody else then compiles
  # again. Sixteen per helper lifetime is far above any honest repository and bounds that
  # churn at a quarter of the table.
  #
  # It is a budget and not an eviction, so a *clone* that ships seventeen distinct components
  # within one helper's life hits it even though the helper has room. The operator editing
  # their own hook seventeen times no longer does: that is `lane: :hook`, and nothing counts
  # it. Any respawn — a restart, a broken transition — clears the set.
  @hook_component_budget 16

  # The most evicted shas one debug line names. The helper evicts one component per `load`,
  # so a longer list is a helper misbehaving, and a log line is no place to repeat it.
  @max_evicted_logged 8

  # The longest instance name this side will send. The helper only ever echoes back
  # `MAX_ECHO_BYTES` (256) of a name, so a longer one is both pointless on the wire and a
  # larger key than the deadline map should hold; refused at the API boundary rather than
  # spent on a frame.
  @max_instance_bytes 256

  # A soft ceiling on this process's own heap, in words. `JSON.decode` of a hostile frame —
  # 8 MiB of deeply nested JSON within the wire cap — can transiently allocate hundreds of
  # mebibytes of term on this process's heap (the wire cap bounds the bytes read, not the
  # heap they decode to; see the moduledoc). 128 MiB is far above any legitimate frame's
  # decode (a `call` result is at most 1 MiB helper-side, a few MiB as an Elixir term) and
  # below that pathological figure, so `kill: false` logging makes a hostile helper
  # observable without crashing a pool that holds live-instance bookkeeping.
  @max_heap_words div(128 * 1024 * 1024, :erlang.system_info(:wordsize))

  # The outer bound on a caller's `GenServer.call`, and not the request's deadline: the pool
  # owns that, derives it per request, and answers long before this. This exists only so a
  # caller is never stranded by a wedged pool process. It is comfortably above the largest
  # in-contract wait — the helper's own 60 s `max_deadline_ms` plus the transport margin.
  @client_ceiling_ms 180_000

  # The helper's own bounds on the three per-instance limits, mirrored from
  # `tui/wasm/src/host.rs` (`MAX_FUEL`, `MIN_MEMORY_BYTES`, `MAX_MEMORY_BYTES`,
  # `MAX_DEADLINE_MS`). They are duplicated here rather than only asked of the helper because
  # `instantiate/6` refuses *before* it has a helper: the pool is lazy, the first request is
  # what spawns one, and a limit this side would never send is not one worth spawning a child
  # to have refused. A connected helper's own `doctor.limits` is checked too and wins when it
  # is narrower (`within_helper_limits/2`), so a build with tighter bounds than these is
  # honoured rather than overridden.
  @max_fuel 1_000_000_000_000
  @min_memory_bytes 65_536
  @max_memory_bytes 1_073_741_824
  @max_deadline_ms 60_000

  # The hard ceiling on any interval this pool hands `Process.send_after/3`, whatever a
  # caller's `limits.deadline_ms` and whatever an operator's `call_margin_ms` and
  # `request_timeout_ms` say (F2). `Process.send_after/3` raises `badarg` above
  # `4_294_967_295` ms, and a `badarg` raised inside `handle_call/3` kills this GenServer —
  # so a caller-chosen integer reaching a timer unclamped is a remote crash of the pool, and
  # forty-odd of them exhaust `Ouroboros.Wasm.Supervisor` and take the `:rest_for_one` parent
  # with it. `wire_limits/1` already refuses such a value; this is the independent bound that
  # holds even if some other path ever computes one. Comfortably above the largest legitimate
  # wait (`@max_deadline_ms` plus a generous margin) and below `@client_ceiling_ms`, so a
  # request still answers before the caller's own ceiling fires.
  @max_timeout_ms 120_000

  # The per-child scratch directories, under `<data_dir>/wasm/scratch/`. The prefix is what a
  # sweep recognises; the suffix is 96 bits of randomness, because a name another process can
  # predict is a name it can create first.
  @scratch_prefix "helper-"

  # The owner marker that sits **beside** a scratch, `<name>.owner`, holding the OS pid of the
  # BEAM that made it. Beside and not inside, so it is outside the child's one writable root:
  # a helper cannot rewrite its own marker to a pid that never dies.
  @owner_suffix ".owner"

  # Half of what makes a scratch reclaimable; the owner marker is the other half.
  #
  # Age alone was wrong and a review proved it: two BEAMs sharing one data directory is an
  # ordinary thing, a pool whose helper writes no temp files leaves its scratch's mtime at
  # creation, and after six hours the *sibling's* sweep deleted a live child's only writable
  # directory. "A helper's life is bounded by the pool that owns it" is true and is not a
  # bound on wall-clock time. So a directory is reclaimed only when it is this old **and** the
  # BEAM named in its marker is gone.
  @scratch_abandoned_after_seconds 6 * 60 * 60

  # Bounded per sweep, so a crowded scratch root costs a bounded amount of work on the way in
  # rather than a growing one.
  @scratch_sweep_limit 200

  @typedoc """
  The OS sandbox this node's helper runs under (W16, D25).

  `posture` is `:sandboxed` (a child is wrapped, or would be), `:off` (the operator wrote
  `helper_sandbox: :off`) or `:refused` (`:required` on a node that cannot apply one — the
  pool spawns nothing and `reason` says why). Before a child exists this is the posture the
  next spawn *would* take; `phase` is how a reader tells the two apart.

  `readable` is the **effective** read set — what the child was actually fenced to, or what
  the next one would be. It is here because a fence assembled from four sources and a vetted
  configuration key is a fence an operator cannot otherwise read back off the node, and
  because `helper_readable` rejects a whole list on one bad entry: the difference between
  "configured" and "in force" has to be visible somewhere.

  `process` (W21) is the process posture the child **actually** got, answered by the backend
  and not by the policy: `:sealed` — exec only itself, no fork, no `mach-lookup`, `sysctl`
  under `hw.` only — where the policy asked for it and the backend is Seatbelt; `:open` on
  the two Linux backends, which cannot express it, and for a pool started with
  `scripted_helper: true`; `:off` under `helper_sandbox: :off`; `nil` where the pool refused
  to spawn. A node that cannot seal is **not** refused — `:required` means reads and network
  fenced (D25) — it is a node whose status says `open`.
  """
  @type sandbox :: %{
          posture: :sandboxed | :off | :refused,
          process: :sealed | :open | :off | nil,
          backend: String.t(),
          reason: term() | nil,
          readable: [String.t()]
        }

  @typedoc """
  What `status/1` reports about the helper.

  `hook_components` is the count of **budgeted untrusted** hook shas this helper has
  accepted, not every hook component it holds: the operator's own `lane: :hook` loads are
  not budgeted and are not counted (F7).
  """
  @type status :: %{
          phase: :idle | :handshaking | :ready | :broken,
          helper_path: String.t(),
          os_pid: pos_integer() | nil,
          doctor: map() | nil,
          instances: non_neg_integer(),
          owned: non_neg_integer(),
          pending_drops: non_neg_integer(),
          hook_components: non_neg_integer(),
          sandbox: sandbox(),
          broken_reason: term() | nil
        }

  @typedoc """
  Which lane a `load` is for. Only `:untrusted_hook` is budgeted; `:capability` and the
  operator's own `:hook` are not.
  """
  @type lane :: :capability | :hook | :untrusted_hook

  @typedoc "A refusal frame from the helper. `refusal` is the name peers match on."
  @type refusal :: %{code: integer(), refusal: String.t(), message: String.t()}

  @typedoc "Everything a caller can be told that is not a helper result."
  @type failure ::
          refusal()
          | :unavailable
          | :broken
          | :busy
          | :timeout
          | :hook_component_budget
          | {:refused, :path_outside_roots}
          | {:frame_too_large, non_neg_integer(), pos_integer()}
          | {:invalid_lane, term()}
          | {:invalid_limits, term()}
          | {:invalid_instance, term()}
          | {atom(), term()}

  @typedoc "The three bounds every instance runs under. All three are required."
  @type limits :: %{fuel: pos_integer(), memory_bytes: pos_integer(), deadline_ms: pos_integer()}

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Starts a detached pool. Tests use this so a child's exit does not travel through the test
  process. The node supervisor starts the named singleton via `start_link/1`.
  """
  @spec start(keyword()) :: GenServer.on_start()
  def start(opts \\ []) do
    GenServer.start(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  The helper's readiness report, fresh from the helper.

  Connects lazily, so this is also how an operator surface asks "is there a helper here and
  what can it contain". The report accepted at handshake is also kept in `status/1`.
  """
  @spec doctor(GenServer.server()) :: {:ok, map()} | {:error, failure()}
  def doctor(server \\ __MODULE__), do: request(server, "doctor", %{}, :fixed)

  @doc "What the bytes at `path` are, without admitting them to anything."
  @spec inspect(String.t(), GenServer.server()) :: {:ok, map()} | {:error, failure()}
  def inspect(path, server \\ __MODULE__) when is_binary(path) do
    request(server, "inspect", %{"path" => path}, :fixed)
  end

  @doc """
  Admits the bytes at `path` to the helper's component cache under `sha256`.

  The helper recomputes the digest from what it read and refuses `sha_mismatch` before
  compiling anything, so this is safe to call against a path another process may have
  replaced.

  ## `lane:` — whose bytes these are

  `opts` takes one option, `lane: :capability | :hook | :untrusted_hook`, defaulting to
  `:capability`, and it exists because the helper's component cache is a **shared**
  resource. An unrecognized lane is `{:error, {:invalid_lane, _}}`.

  Exactly one of the three is budgeted: **`:untrusted_hook`**, the bytes that come out of a
  repository somebody cloned rather than out of a signed artifact or an operator's own
  configuration. Distinct shas loaded under it are counted against
  `#{@hook_component_budget}` for the life of the current helper, and a new one past that is
  refused `{:error, :hook_component_budget}` here, before a frame is built.

  `:hook` — the operator's own node- and user-scope component hooks — is **not** budgeted,
  and that separation is the whole point (F7). One counter for both lanes meant an untrusted
  clone could spend the budget on sixteen shas of its own and the operator's trusted `deny`
  hook then failed to load: a bound meant to protect the trusted lane instead disarmed it.
  Trusted churn is bounded by the helper, which evicts least-recently-used at its own
  ceiling and never a component with a live instance.

  A sha already counted is free, so re-running the same hook forever costs one slot. The
  count is taken **when the helper answers `{:ok, _}`**, not when the request is issued: a
  `load` the helper refused compiled nothing and evicted nothing, so counting it let sixteen
  refusals — a sha mismatch, bytes that are not a component — spend a budget on a cache they
  never touched. `status/1` reports the count as `hook_components`, which therefore means
  *budgeted untrusted shas* and not every hook component this helper holds.

  ## `evicted` — what this load cost somebody else

  A successful answer carries `"evicted"`: the shas the helper let go to admit this one,
  empty for a cache hit and for a cache with room. An evicted component is simply unknown
  again — `instantiate/6` naming it is refused `unknown_component`, and the caller loads it
  again, which is why every caller in this repository loads before it instantiates. Each
  eviction is logged here at debug level, and `doctor/1` reports the count and the most
  recent of them under `held`.

  ## `kind:` — which of the helper's two worlds these bytes are offered as (W15)

  `kind: :capability | :policy`, defaulting to `:capability`. The helper implements two closed
  worlds and checks the bytes against the one it is told (docs/WASM.md D21), so a policy
  component offered as a capability is refused `unsupported_world` and so is the reverse.

  It is not a preference: on the deploy path it comes from the **signed manifest's** `kind`
  (contract C7), which is what makes "this component decides permissions" a claim a signature
  covers rather than a flag somebody set at load time. An unrecognized kind is
  `{:error, {:invalid_kind, _}}` here, before a frame is built, for `lane:`'s reason — a caller
  whose kind this build does not know has said something this build cannot honour either way.

  ## `precompiled:` — which form of the bytes is at `path` (W8)

  `precompiled: <sha of the artifact>` says that `path` holds wasmtime's serialized form of the
  component `sha256` names, and that this is its digest. The helper then recomputes that digest,
  reads the container's header, refuses `precompiled_mismatch` unless its own wasmtime version
  and target triple are exactly the ones the artifact was built for, checks that the artifact
  names *this* component, and only then `Component::deserialize`s it — under `world::check`
  exactly as a compiled component is (D24).

  It is not a preference either. `Ouroboros.Wasm.Store.form/4` decides it, out of a **verified**
  manifest's `precompiled` block and this node's own `doctor` reading, and a node whose readings
  do not match loads the source form instead. Passing the option for bytes no manifest named is
  refused by the helper, which is the point of the artifact's digest being a parameter rather
  than something read off the file.

  The cache key is still the **component**'s sha, whichever form was loaded: identity in lane W
  is the component's bytes (D2), so `instantiate/6` names what it always named and nothing above
  this function has to know which form ran. The answer says which one it was, under
  `"precompiled"`.

  `opts` follows the server, as `instantiate/6`'s does and for the same reason.
  """
  @spec load(String.t(), String.t(), GenServer.server(), keyword()) ::
          {:ok, map()} | {:error, failure()}
  def load(sha256, path, server \\ __MODULE__, opts \\ [])
      when is_binary(sha256) and is_binary(path) and is_list(opts) do
    with {:ok, lane} <- lane(opts),
         {:ok, kind} <- kind(opts),
         {:ok, params} <- load_params(sha256, path, kind, opts) do
      request(server, "load", params, :fixed, nil, lane)
    end
  end

  # The two shapes of a `load` frame. The source form names the component and the file; the
  # precompiled form names the artifact's digest as `sha256` — that is what the helper will
  # recompute from the file it reads — and the component's separately, because that is the
  # identity the cache is keyed under and the fact the container's header is held to.
  defp load_params(sha256, path, kind, opts) do
    case Keyword.get(opts, :precompiled) do
      nil ->
        {:ok, %{"sha256" => sha256, "path" => path, "kind" => kind}}

      artifact when is_binary(artifact) and artifact != "" ->
        {:ok,
         %{
           "precompiled" => true,
           "sha256" => artifact,
           "component" => sha256,
           "path" => path,
           "kind" => kind
         }}

      other ->
        {:error, {:invalid_precompiled, other}}
    end
  end

  # W15. The same shape `lane/1` has, and a refusal rather than a default for the same reason.
  # The wire spelling is the short name the helper's `world::Kind::parse` reads, not the
  # version-bearing package id: a peer that had to reproduce `ouroboros:policy@0.1.0` to load a
  # component would be pinned to this build's world version by its own request.
  defp kind(opts) do
    case Keyword.get(opts, :kind, :capability) do
      :capability -> {:ok, "capability"}
      :policy -> {:ok, "policy"}
      other -> {:error, {:invalid_kind, other}}
    end
  end

  # An unrecognized lane is a refusal, not a silent default. It used to fall through to the
  # budgeted lane, which was safe in the only direction that mattered then; now that one of
  # the three lanes is *exempt*, guessing at all is the wrong shape — a caller whose `lane:`
  # this build does not know has said something this build cannot honour either way.
  defp lane(opts) do
    case Keyword.get(opts, :lane, :capability) do
      lane when lane in [:capability, :hook, :untrusted_hook] -> {:ok, lane}
      other -> {:error, {:invalid_lane, other}}
    end
  end

  @doc """
  Instantiates a loaded component as `instance`, running its `init` under `limits`.

  All three limits are required and none is defaulted here. The helper refuses a request
  that omits one — "there is no unlimited default" is its sentence, not this pool's — and
  inventing a value on this side would be this node deciding, silently, how much of the
  machine a guest may have.

  ## `owner:` — who this instance belongs to

  `opts` takes `owner: pid` and `kind: :capability | :policy` (W15, defaulting to
  `:capability`, and the same value `load/4` was given for this sha). `owner:` is the answer to
  the only unbounded thing this pool otherwise has: an instance nobody drops. The helper holds
  `MAX_INSTANCES` (256)
  and evicts none of them, so a caller that stands instances up under fresh names and stops
  without dropping — every rollout probe and every evaluation does exactly that, under an id
  carrying a unique integer — walks the helper into `too_many_instances` forever. A full
  table is not a *broken* helper, so nothing here would ever respawn it.

  An owned instance is monitored, and its owner's `:DOWN` schedules a `drop` on this pool's
  own wire. That is a reclaim, not a guarantee: a pool that goes broken forgets its
  ownership (the child is killed and the table with it), and a drop that cannot be issued is
  forgotten rather than retried forever. `owner:` is optional because an instance whose
  owner this side cannot name is still a legitimate instance — it is simply one whose
  lifetime its caller has to manage.

  `opts` follows the server rather than preceding it: the server is the last *required*
  argument here as it is in every other function, and moving it would silently rebind every
  existing five-argument call.
  """
  @spec instantiate(String.t(), String.t(), String.t(), limits(), GenServer.server(), keyword()) ::
          {:ok, map()} | {:error, failure()}
  def instantiate(instance, sha256, config, limits, server \\ __MODULE__, opts \\ [])
      when is_binary(instance) and is_binary(sha256) and is_binary(config) and is_list(opts) do
    with :ok <- valid_instance(instance),
         {:ok, kind} <- kind(opts),
         {:ok, wire} <- wire_limits(limits) do
      request(
        server,
        "instantiate",
        %{
          "instance" => instance,
          "sha256" => sha256,
          "config" => config,
          # W15. Asserted here as well as at `load`, because the two are separate requests and
          # a peer that loaded a sha as one world and stood it up as the other would be
          # dispatching against a table nobody checked these bytes for. The helper refuses a
          # disagreement `unsupported_world`.
          "kind" => kind,
          "limits" => wire
        },
        :derived,
        owner(opts)
      )
    else
      {:error, _reason} = error -> error
      :error -> {:error, {:invalid_limits, limits}}
    end
  end

  # A non-pid `owner:` is no owner. This is a bound on somebody else's bookkeeping, so it
  # falls back rather than refusing an otherwise valid instantiate.
  defp owner(opts) do
    case Keyword.get(opts, :owner) do
      pid when is_pid(pid) -> pid
      _absent -> nil
    end
  end

  @doc """
  One message into a live instance, under the bounds it was instantiated with.

  A trap poisons the instance server-side, so an `{:error, %{refusal: "trapped"}}` is
  followed by `unknown_instance` on the next call: the caller re-instantiates.
  """
  @spec call(String.t(), String.t(), String.t(), GenServer.server()) ::
          {:ok, map()} | {:error, failure()}
  def call(instance, export, payload, server \\ __MODULE__)
      when is_binary(instance) and is_binary(export) and is_binary(payload) do
    with :ok <- valid_instance(instance) do
      request(
        server,
        "call",
        %{"instance" => instance, "export" => export, "payload" => payload},
        :derived
      )
    end
  end

  @doc """
  The instance's own `describe`, under the same bounds its messages run under.

  The world exports exactly two callable functions and `call/4` dispatches both
  (`tui/wasm/src/world.rs`), so this is `call/4` with the export named and an empty payload
  — `describe` takes no argument, and sending one would be inventing a parameter the world
  does not have. It is here rather than at each caller because "which export is metadata"
  is a fact about the world, not about the caller, and W13 has two readers of it.

  Everything `call/4` says still holds: the answer is the guest's, it is bounded by the
  helper's result cap, and a trap poisons the instance exactly as it does for a message.
  """
  @spec describe(String.t(), GenServer.server()) :: {:ok, map()} | {:error, failure()}
  def describe(instance, server \\ __MODULE__) when is_binary(instance),
    do: call(instance, "describe", "", server)

  @doc "Drops an instance. Idempotent, because the caller may be recovering from a refusal."
  @spec drop(String.t(), GenServer.server()) :: {:ok, map()} | {:error, failure()}
  def drop(instance, server \\ __MODULE__) when is_binary(instance) do
    with :ok <- valid_instance(instance) do
      request(server, "drop", %{"instance" => instance}, :fixed)
    end
  end

  # An instance name longer than the helper will ever echo back is refused here rather than
  # spent on a frame or held as an oversize key in the deadline map (F9).
  defp valid_instance(instance) when byte_size(instance) <= @max_instance_bytes, do: :ok
  defp valid_instance(instance), do: {:error, {:invalid_instance, byte_size(instance)}}

  @doc """
  The most distinct **untrusted** hook components one helper's life may admit. See
  `@hook_component_budget`.

  Public because a spent budget is an operator-visible fact: the turn loop says so once per
  turn (docs/WASM.md W-F3) and `wasm.status` reports it beside `hook_components`. Reading
  the number off the module rather than restating it in two other files is how those three
  cannot disagree.
  """
  @spec hook_component_budget() :: pos_integer()
  def hook_component_budget, do: @hook_component_budget

  @doc """
  Loads one component in whichever form this node can, falling back when it cannot (W8, H3).

  This is the one place a lane-W load happens outside the untrusted hook lane, and it exists
  because "otherwise it falls back to the source form" was a sentence `refusal.rs`, D24 and the
  helper's own `doctor` note all made and nothing carried out. `Ouroboros.Wasm.Store.form/4`
  chooses; if the helper then refuses the artifact for a reason that means *these bytes are not
  this node's to map* — `precompiled_mismatch`, `sha_mismatch`, `unreadable_component` — the
  source form is loaded under §7.3's bounds and **one** line says why.

  The refusals it falls back on are exactly the ones the source form answers. A guest that is
  not in its world, a component past a structural bound, a full cache: those are facts about
  the component, they will be true of the source form too, and retrying would spend a second
  load to hear the same thing.

  `opts` takes `:kind` and `:lane` as `load/4` does, plus `:store` — the keyword list the store
  is read under. `precompiled` is the **verified manifest's** block, or `nil`.

  A fault reading the store answers `{:error, {:store, reason}}`, tagged so a caller can tell it
  from a refusal about the component: a component this node does not hold reaches no helper, and
  saying so is the difference between "your store is missing bytes" and "your component is
  wrong".
  """
  @spec load_component(String.t(), map() | nil, GenServer.server(), keyword()) ::
          {:ok, map()} | {:error, failure()}
  def load_component(component_sha256, precompiled, server \\ __MODULE__, opts \\ [])
      when is_binary(component_sha256) and is_list(opts) do
    store = Keyword.get(opts, :store, [])
    load_opts = Keyword.take(opts, [:kind, :lane])

    case Store.form(component_sha256, precompiled, fn -> helper_build(server) end, store) do
      {:precompiled, path, artifact} ->
        mapped(component_sha256, path, artifact, server, load_opts, store)

      {:source, path, why} ->
        note_fallback(component_sha256, why)
        load(component_sha256, path, server, load_opts)

      # Tagged, because the caller has to tell "this node does not hold these bytes" from
      # "the helper refused them": one is a store fault and reaches no helper at all, and the
      # other is a component fact. `Ouroboros.Wasm.Capability` records them at different stages
      # for exactly that reason.
      {:error, reason} ->
        {:error, {:store, reason}}
    end
  end

  # The refusals that mean "not this node's to map", and therefore the ones a source load can
  # answer. Everything else is a fact about the component and is reported as it stands.
  @fallback_refusals ~w(precompiled_mismatch sha_mismatch unreadable_component)

  defp mapped(sha, path, artifact, server, load_opts, store) do
    case load(sha, path, server, Keyword.put(load_opts, :precompiled, artifact)) do
      {:ok, report} ->
        {:ok, report}

      {:error, %{refusal: refusal} = reason} when refusal in @fallback_refusals ->
        case Store.path(sha, store) do
          {:ok, source} ->
            note_fallback(sha, {:helper_refused, refusal})
            load(sha, source, server, load_opts)

          {:error, _absent} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # One line, at every call site rather than only at stage (M7): a node that quietly compiles
  # what it was told it could map is a node whose operator cannot explain its own latency.
  # A manifest that declares no artifact is not a fallback and says nothing.
  defp note_fallback(_sha, :not_precompiled), do: :ok

  defp note_fallback(sha, why) do
    Logger.info("wasm load #{String.slice(sha, 0, 12)}: the source form (#{Kernel.inspect(why)})")
  end

  @doc """
  The wasmtime and the target triple this node's helper reports, or `nil` (W8).

  The pair a precompiled artifact is bound to, read off the `doctor` report the pool already
  accepted at handshake rather than by asking again: `Ouroboros.Wasm.Store.form/4` calls this
  on the way to every load, and a round trip per load to learn two constants would be a
  round trip per load.

  `nil` means this node does not know — no pool process, a helper this node has no binary for,
  a helper too old to report a target — and `form/4` reads that as "use the source form", which
  is the answer that always works. Never an exception and never a guess: a node that guessed
  its own build would be a node deserializing machine code on a hunch.

  ## `connect:` — whether asking may start the helper

  Default `true`, because the caller on the load path is about to issue a `load` anyway and a
  pool that has not connected yet has no report to read: without this the *first* load on every
  node would fall back to the source form for no reason but ordering. The handshake keeps the
  report, so at most one extra `doctor` is spent per helper lifetime.

  `connect: false` is for a reader. `wasm.list` is a `:read` verb and W5's rule is that it never
  starts a helper to answer, so it asks with `false` and renders `nil` — "this node does not
  know" — where a load would have connected and found out.
  """
  @spec helper_build(GenServer.server(), keyword()) :: %{String.t() => String.t()} | nil
  def helper_build(server \\ __MODULE__, opts \\ []) do
    case status(server) do
      # A handshake has happened, so *this* is the report — whether or not it names a target.
      # A helper too old to report one is asked once and never again: re-asking would spend a
      # round trip per load to be told the same thing, on the sequential wire every capability
      # and every hook on this node shares.
      %{doctor: report} when is_map(report) ->
        build_of(report)

      _no_report ->
        if Keyword.get(opts, :connect, true) do
          case doctor(server) do
            {:ok, report} -> build_of(report)
            {:error, _unavailable} -> nil
          end
        end
    end
  end

  defp build_of(%{"wasmtime" => wasmtime, "target" => target})
       when is_binary(wasmtime) and wasmtime != "" and is_binary(target) and target != "",
       do: %{"wasmtime" => wasmtime, "target" => target}

  defp build_of(_absent), do: nil

  @doc "Describes the helper this node owns: phase, os pid, the accepted doctor report."
  @spec status(GenServer.server()) :: status()
  def status(server \\ __MODULE__) do
    GenServer.call(server, :status)
  catch
    :exit, reason ->
      %{
        phase: :broken,
        helper_path: "",
        os_pid: nil,
        doctor: nil,
        instances: 0,
        owned: 0,
        pending_drops: 0,
        hook_components: 0,
        # No process answered, so nothing is known about what it would have spawned. `:refused`
        # is the honest reading of "there is no helper and there will not be one from here".
        sandbox: %{
          posture: :refused,
          backend: "unknown",
          reason: :pool_unavailable,
          readable: []
        },
        broken_reason: {:pool_unavailable, reason}
      }
  end

  # Never raises and never exits the caller. A missing binary, a dead helper, a full queue,
  # and a helper that does not answer are all error tuples. The deadline is named rather
  # than passed: which one a method gets is the pool's decision, made against the settings
  # that pool was started with and, for `call`, against what it knows of the instance.
  defp request(server, method, params, deadline, owner \\ nil, lane \\ :capability)
       when deadline in [:fixed, :derived] do
    GenServer.call(server, {:request, method, params, deadline, owner, lane}, @client_ceiling_ms)
  catch
    :exit, reason -> {:error, {:pool_unavailable, reason}}
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    # A soft heap ceiling: `kill: false` so a decode blow-up on a hostile frame is logged
    # rather than crashing a pool that holds live-instance bookkeeping. See `@max_heap_words`.
    Process.flag(:max_heap_size, %{size: @max_heap_words, kill: false, error_logger: true})

    {:ok,
     %{
       helper_path: Keyword.get(opts, :helper_path) || Wasm.helper_path(),
       settings: settings(opts),
       # W16. The posture this pool was started with, or `nil` for "read the node's setting".
       # A test pins it; a node states it once, in configuration, and may change it without
       # restarting the pool because it is read at every connect.
       helper_sandbox: sandbox_option(opts),
       # W21. `true` says the helper at `helper_path` is a shell script — a `#!/bin/sh` fake
       # in this repository's own suites — which needs its interpreter exec'd and `awk`
       # forked, so the policy leaves the process posture open. A test-fixture widening
       # (`Ouroboros.Wasm.SandboxFixture.scripted_pool_opts/1`) and not a setting: the real
       # helper is one binary and runs sealed, and there is no configuration key that widens
       # it.
       scripted_helper: Keyword.get(opts, :scripted_helper) == true,
       # Roots this pool names to the policy on top of the node's own. A test's component
       # directory and a test's fake helper's journal, and nothing else in this repository:
       # the node supervisor starts this pool with neither, so what production reads and
       # writes is `readable_roots/1`'s four sources and the scratch, exactly.
       readable: Keyword.get(opts, :readable, []),
       writable: Keyword.get(opts, :writable, []),
       scratch_root: Keyword.get(opts, :scratch_root),
       # What the last spawn actually did, or `nil` before there has been one — in which case
       # `status/1` answers what the next one would do.
       sandbox: nil,
       # The roots the live child was fenced to, as this pool computed them — the input to the
       # policy rather than the policy's own list, so `ensure_connected/1` compares like with
       # like. `nil` until a child exists.
       fenced: nil,
       scratch: nil,
       port: nil,
       os_pid: nil,
       buffer: <<>>,
       noise: 0,
       next_id: 1,
       phase: :idle,
       inflight: nil,
       queue: :queue.new(),
       broken_until: 0,
       broken_reason: nil,
       doctor: nil,
       deadlines: %{},
       # `instance => {seq, monitor}` for instances an owner claimed, and the names whose
       # owners have since died and whose `drop` has not gone out yet. Both are bounded by
       # `max_instances` for the reason `deadlines` is: a peer that never drops must not be
       # able to grow a map in this process without limit.
       owners: %{},
       pending_drops: [],
       # The distinct component digests the helper *accepted* under `lane: :untrusted_hook`
       # since it was spawned. Reset with every other per-child fact, because the cache it
       # bounds dies with the child that held it.
       hook_shas: MapSet.new(),
       instance_seq: 0,
       max_instances: max_instances(opts)
     }}
  end

  @impl true
  def handle_call({:request, method, params, requested, owner, lane}, from, state) do
    case admit(state, method, params, lane) do
      :ok ->
        issue_request(state, method, params, requested, owner, from, lane)

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       phase: state.phase,
       helper_path: state.helper_path,
       os_pid: state.os_pid,
       doctor: state.doctor,
       instances: map_size(state.deadlines),
       owned: map_size(state.owners),
       pending_drops: length(state.pending_drops),
       hook_components: MapSet.size(state.hook_shas),
       sandbox: sandbox_report(state),
       broken_reason: state.broken_reason
     }, state}
  end

  # Everything a request must satisfy before anything is spent on it: no frame is built, no
  # timer armed, no monitor taken, and — since this pool is lazy — no child spawned. A
  # refusal that had already touched the wire would be a smaller version of the exhaustion
  # these bounds exist to prevent.
  defp admit(state, method, params, lane) do
    with :ok <- check_lane(state, method, params, lane),
         :ok <- check_path(state, method, params) do
      check_limits(state, method, params)
    end
  end

  # W16, the pool's half of the fence. Every `load` in this repository names a file the node
  # itself put where it is: the wrapper agent, the policy engine's two and the rollout's
  # staging and boot restart all resolve theirs through `Store.path/2` or
  # `Store.precompiled_path/2`, and `Ouroboros.Provider.Native.Hooks` resolves its own inside
  # the workspace it confined it to. `readable_roots/1` is that set, and it is the same list
  # the child's policy is built from. Refusing here means the kernel is denying something the
  # pool already refused, which is the point: the rule is stated by this node and not only by
  # whatever backend the node happens to have.
  #
  # Both verbs that name a path, which is what "stated twice" has to mean: `load` and
  # `inspect`. `inspect` is the forge reading the imports of bytes it just built (D18), whose
  # directory is in the readable set for exactly that reason; `instantiate`/`call`/`drop` name
  # a component the helper already holds and no path at all.
  defp check_path(state, method, %{"path" => path})
       when method in ["load", "inspect"] and is_binary(path) do
    if under_readable?(state, path),
      do: :ok,
      else: {:error, {:refused, :path_outside_roots}}
  end

  defp check_path(_state, _method, _params), do: :ok

  # The leaf is not resolved, the directory is: a path whose parent is a symlink out of the
  # store is refused here, and a symlinked *file* inside the store is left to the kernel,
  # which evaluates what it resolves to. A directory that cannot be resolved is **refused**,
  # not compared as written: the roots carry both spellings of every directory, so a path
  # measured in its unresolved spelling would match the named root it sits under and admit
  # exactly the link out of the store this exists to refuse (`Workspace.Path.canonicalize/1`
  # answers `{:symbolic_link_cycle, "/var"}` for a link into `/var/folders` on macOS). Stated
  # in the moduledoc, because a fence with a documented asymmetry is a fence and an
  # undocumented one is a hole.
  defp under_readable?(state, path) do
    case WorkspacePath.canonicalize(Path.dirname(path)) do
      {:ok, dir} ->
        resolved = Path.join(dir, Path.basename(path))
        Enum.any?(readable_roots(state), &WorkspacePath.within?(resolved, &1))

      {:error, _unresolvable} ->
        false
    end
  end

  # The untrusted-hook budget. Only `lane: :untrusted_hook` is budgeted (F7): a repository's
  # bytes are the ones nobody signed, and one counter shared with the operator's own trusted
  # hooks let a clone spend the budget and make a trusted `deny` fail open.
  #
  # Checking and *counting* are separate steps, and counting happens on the helper's `{:ok,
  # _}` (`count_hook/3`) rather than here. Two reasons, and either is sufficient. This pool
  # is lazy, so the request that finds no child spawns one and `connect/1` empties
  # `hook_shas`; counting here would put the sha in a set the next line throws away. And a
  # `load` the helper *refuses* — a sha mismatch, bytes that are not a component, an
  # undeclared import — admitted nothing to the cache this budget bounds, so counting it let
  # sixteen refusals spend a budget that had cost the node nothing.
  #
  # Admission is **re-run** when a queued load is issued (`drain/1`). Concurrent callers all
  # pass this check while `hook_shas` is still short of the ceiling, then queue; without a
  # second look the budget would be `16 + inflight + queue`. The count still happens on
  # success, so a refused load still spends nothing.
  defp check_lane(state, "load", params, :untrusted_hook) do
    case Map.get(params, "sha256") do
      sha when is_binary(sha) ->
        if MapSet.member?(state.hook_shas, sha) or
             MapSet.size(state.hook_shas) < @hook_component_budget,
           do: :ok,
           else: {:error, :hook_component_budget}

      _absent ->
        # Malformed, and the helper's own refusal is the honest answer to it.
        :ok
    end
  end

  defp check_lane(_state, _method, _params, lane) when lane in [:capability, :hook], do: :ok

  # A lane this build does not know is a caller's typo, and a typo must never buy an
  # exemption from a budget. `load/4` refuses one before it ever reaches here; this is the
  # same answer for anything that arrives another way.
  defp check_lane(_state, _method, _params, lane), do: {:error, {:invalid_lane, lane}}

  # What the connected helper says it will accept, checked against what this request carries.
  # `wire_limits/1` has already refused anything outside this build's constants; this is the
  # narrower check that only a `doctor` report can answer, and it is done here rather than at
  # the API boundary because only the pool holds the report.
  defp check_limits(state, "instantiate", params) do
    case get_in_map(params, ["limits"]) do
      limits when is_map(limits) -> within_helper_limits(state, limits)
      _absent -> :ok
    end
  end

  defp check_limits(_state, _method, _params), do: :ok

  # Counted when the helper answers `{:ok, _}` and not before: the budget bounds the compiles
  # and the evictions a repository can cause, and a refused `load` caused neither.
  defp count_hook(state, %{method: "load", lane: :untrusted_hook, params: params}, {:ok, _result}) do
    case Map.get(params, "sha256") do
      sha when is_binary(sha) -> %{state | hook_shas: MapSet.put(state.hook_shas, sha)}
      _absent -> state
    end
  end

  defp count_hook(state, _inflight, _reply), do: state

  defp issue_request(state, method, params, requested, owner, from, lane) do
    # Mint the deadline at receipt, before reconnect or queue work, so a caller waiting
    # behind another one is not given a fresh window when its turn comes.
    item =
      request_item(
        from,
        method,
        params,
        resolve_timeout(state, method, params, requested),
        owner,
        lane
      )

    cond do
      # A ready, idle pool issues at once — unless the roots it was fenced to are no longer
      # the roots this node has (a data directory that moved between two callers), in which
      # case the request queues behind the reconnect `ensure_connected/1` performs below. The
      # load fence would have admitted the path on today's roots while the child still lived
      # inside yesterday's namespace, and answered `unreadable_component` for a file that is
      # there (the container proof found it: a forge's product, on a node whose data
      # directory had changed since the helper spawned).
      state.phase == :ready and state.inflight == nil and fence_fresh?(state) ->
        case issue_item(state, item) do
          {:ok, state} ->
            {:noreply, state}

          {:expired, state} ->
            cleanup_item(item)
            {:reply, {:error, :timeout}, state}

          {:frame_too_large, state, size} ->
            cleanup_item(item)
            {:reply, {:error, {:frame_too_large, size, state.settings.max_frame_bytes}}, state}

          {:error, reason} ->
            cleanup_item(item)
            {:reply, {:error, :broken}, go_broken(state, {:transport_closed, reason})}
        end

      queueable?(state) ->
        case ensure_connected(state) do
          {:ok, state} ->
            {:noreply, enqueue(state, item)}

          {:unavailable, state} ->
            cleanup_item(item)
            {:reply, {:error, :unavailable}, state}

          {:broken, state} ->
            cleanup_item(item)
            {:reply, {:error, :broken}, state}
        end

      state.phase == :broken ->
        cleanup_item(item)
        {:reply, {:error, :broken}, state}

      true ->
        cleanup_item(item)
        {:reply, {:error, :busy}, state}
    end
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    case Codec.decode(state.buffer <> data, state.settings.max_frame_bytes) do
      {:ok, frames, noise, rest} ->
        state = %{state | buffer: rest, noise: state.noise + noise}

        if state.noise > @max_noise do
          {:noreply, go_broken(state, {:noise_limit, state.noise})}
        else
          {:noreply, Enum.reduce(frames, state, &handle_frame/2)}
        end

      {:error, reason} ->
        {:noreply, go_broken(state, {:protocol_error, reason})}
    end
  end

  # stderr is the helper's own log and is deliberately not read here; see `open_port/1`.
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    {:noreply, go_broken(%{state | port: nil, os_pid: nil}, {:helper_exited, status})}
  end

  def handle_info({:deadline, id}, %{inflight: %{id: id, kind: :handshake}} = state) do
    {:noreply, go_broken(state, :handshake_timeout)}
  end

  def handle_info({:deadline, id}, %{inflight: %{id: id, kind: {:caller, item}}} = state) do
    # A request that outlived its own deadline plus the margin is not slow work: the helper
    # bounds every guest itself, so nothing it is doing can take longer. Answer this caller
    # honestly and treat the child as wedged.
    Process.demonitor(item.monitor, [:flush])
    GenServer.reply(item.from, {:error, :timeout})
    {:noreply, go_broken(%{state | inflight: nil}, {:request_timeout, item.method})}
  end

  # Nobody is owed this answer — an abandoned caller's request, or a reclaim `drop` this
  # pool issued itself — but a helper that does not answer either one is as wedged as one
  # that strands a caller, and it is found the same way.
  def handle_info({:deadline, id}, %{inflight: %{id: id, kind: kind}} = state)
      when kind in [:orphaned, :internal] do
    {:noreply, go_broken(state, {:request_timeout, state.inflight.method})}
  end

  def handle_info({:deadline, _stale_id}, state), do: {:noreply, state}

  def handle_info({:queued_deadline, ref}, state) do
    case remove_queued(state.queue, ref, :ref) do
      {nil, _queue} ->
        {:noreply, state}

      {item, queue} ->
        Process.demonitor(item.monitor, [:flush])
        GenServer.reply(item.from, {:error, :timeout})
        {:noreply, %{state | queue: queue}}
    end
  end

  def handle_info(
        {:DOWN, monitor, :process, _caller, _reason},
        %{inflight: %{kind: {:caller, %{monitor: monitor} = item}}} = state
      ) do
    # The answer is owed to nobody now, but the helper is still working on it and the slot
    # is still occupied. The deadline stays armed: it is the only thing that would notice a
    # helper that never answers this request, and dropping it would wedge the pool quietly.
    Process.demonitor(item.monitor, [:flush])
    {:noreply, put_in(state.inflight.kind, :orphaned)}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    case remove_queued(state.queue, monitor, :monitor) do
      # Not a caller waiting in the queue, so it may be the owner of a live instance.
      {nil, _queue} ->
        {:noreply, owner_down(state, monitor)}

      {item, queue} ->
        drop_timer(item.deadline)
        {:noreply, %{state | queue: queue}}
    end
  end

  # The port is linked to this process and, because we trap exits, its termination arrives
  # here as an `{:EXIT, port, _}` in addition to the `{:exit_status, _}` the exit-status
  # option delivers. The status message is the one that drove `go_broken`; this signal is
  # spent, and stopping on it would kill the pool every time its child does.
  def handle_info({:EXIT, port, _reason}, state) when is_port(port), do: {:noreply, state}

  # A non-port `{:EXIT, …}` is the linked starter going away (`start_link`, a test); follow
  # it down. The detached singleton (`start/1`) has no such link.
  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    _state = hard_close(state)
    :ok
  rescue
    _error -> :ok
  end

  ## Lifecycle

  # Answers whether a request may proceed, opening the child if one is needed. A missing
  # binary is `:unavailable` and leaves the pool idle rather than broken: nothing failed,
  # the operator has not opted in, and installing a helper must take effect at once.
  # A child whose fence is still the fence this node would build now. When it is not — a data
  # directory that moved, a `helper_readable` an operator corrected, a pool told different
  # roots — the child is replaced rather than kept: a running helper's policy is fixed at
  # spawn, so a stale one is a fence describing a store this node no longer uses, in both
  # directions. Replacing costs the helper's cache and its live instances, which is what
  # every other reconnect costs, and configuration does not move on a running node.
  defp fence_fresh?(%{fenced: fenced} = state) when is_list(fenced),
    do: fenced == readable_roots(state)

  defp fence_fresh?(_unfenced), do: true

  defp ensure_connected(%{phase: phase, fenced: fenced} = state)
       when phase in [:ready, :handshaking] and is_list(fenced) do
    if fence_fresh?(state) do
      {:ok, state}
    else
      case connect(state) do
        %{phase: :broken} = state -> {:broken, state}
        state -> {:ok, state}
      end
    end
  end

  defp ensure_connected(%{phase: phase} = state) when phase in [:ready, :handshaking],
    do: {:ok, state}

  defp ensure_connected(state) do
    if File.regular?(state.helper_path) do
      case connect(state) do
        %{phase: :broken} = state -> {:broken, state}
        state -> {:ok, state}
      end
    else
      {:unavailable, hard_close(state)}
    end
  end

  # (Re)opens the child and starts the doctor handshake. Failure to spawn leaves the pool
  # broken rather than crashing it, so a helper that is present but unrunnable answers every
  # request with an error instead of driving a supervision storm.
  defp connect(state) do
    state = hard_close(state)

    # `hook_shas` goes with `deadlines`: both are facts about a child that no longer exists,
    # and a fresh helper's cache is empty whatever the last one held.
    #
    # `doctor` goes with them for the same reason and one more (W8, H3): the accepted report
    # names the wasmtime and the target triple a precompiled artifact is bound to, and the
    # binary on disk can have been replaced between one child and the next. Carrying the old
    # report over a reconnect would have this node deserialize artifacts for a build it is no
    # longer running, on the strength of a reading from a process that is gone.
    case open_port(%{
           state
           | buffer: <<>>,
             noise: 0,
             inflight: nil,
             deadlines: %{},
             doctor: nil,
             hook_shas: MapSet.new()
         }) do
      {:ok, state} ->
        start_handshake(state)

      # W16, D25. A node that cannot sandbox its helper under `:required` refuses to spawn
      # one, and the reason travels as itself rather than inside `{:spawn_failed, _}`: it is
      # not a helper that failed, it is a node that will not run one, and `wasm.status` has
      # to be able to say which.
      {:error, {:helper_sandbox_unavailable, why} = reason} ->
        go_broken(%{state | sandbox: refused_sandbox(state, why)}, reason)

      {:error, reason} ->
        go_broken(state, {:spawn_failed, reason})
    end
  end

  defp start_handshake(state) do
    case issue(state, "doctor", %{}, :handshake, state.settings.handshake_timeout_ms) do
      {:ok, state} -> %{state | phase: :handshaking}
      {:error, reason} -> go_broken(state, {:transport_closed, reason})
    end
  end

  defp handle_frame(%{"id" => id} = frame, %{inflight: %{id: id, kind: kind} = inflight} = state) do
    drop_timer(inflight.deadline)
    route(kind, answer(frame), %{state | inflight: nil}, inflight)
  end

  # A frame with no matching in-flight id — a late answer to a request that already timed
  # out, or a helper-initiated message this protocol does not have — is dropped rather than
  # acted on. Correlation is by id and only by id.
  defp handle_frame(_frame, state), do: state

  # A frame that is neither a result nor an error is this helper breaking its own contract,
  # and the frame after it cannot be trusted to be better. The caller is owed an answer
  # before the child goes.
  defp route(kind, {:error, :malformed}, state, inflight) do
    case kind do
      {:caller, item} ->
        Process.demonitor(item.monitor, [:flush])
        GenServer.reply(item.from, {:error, :broken})

      _handshake_or_orphaned ->
        :ok
    end

    go_broken(state, {:malformed_frame, inflight.method})
  end

  defp route(:handshake, {:ok, report}, state, _inflight) do
    if admissible?(report) do
      drain(%{state | phase: :ready, doctor: report})
    else
      go_broken(state, {:handshake_refused, refusal_summary(report)})
    end
  end

  defp route(:handshake, {:error, reason}, state, _inflight),
    do: go_broken(state, {:handshake_failed, reason})

  # The eviction note goes out before the reply does: a caller that returns from `load/4`
  # and reads the log expects the line to be there, and a line written after the reply
  # would race it.
  defp route({:caller, item}, reply, state, inflight) do
    Process.demonitor(item.monitor, [:flush])
    note_evictions(inflight, reply)
    GenServer.reply(item.from, reply)

    state
    |> count_hook(inflight, reply)
    |> remember_instance(inflight, reply)
    |> drain()
  end

  # The caller went away, but the helper still answered and a successful `load` still
  # admitted a component to the shared cache — so it is still counted.
  defp route(:orphaned, reply, state, inflight),
    do: state |> count_hook(inflight, reply) |> drain()

  # A reclaim `drop` this pool issued for a dead owner. Nobody is waiting for the answer;
  # the bookkeeping it settles is this pool's own.
  defp route(:internal, reply, state, inflight),
    do: state |> remember_instance(inflight, reply) |> drain()

  # An eviction is the helper's decision, and a legible one: the `load` that caused it names
  # what was let go. This is the one place on this side that sees every `load` answer, so it
  # is where that fact reaches the node's log — at debug, because on a busy node evictions
  # are routine, and the helper's own `doctor` census holds the count and the recent ones for
  # anyone asking after the fact. Helper strings, so bounded and never atoms.
  defp note_evictions(%{method: "load"}, {:ok, %{"evicted" => [_ | _] = evicted}}) do
    Logger.debug(fn ->
      shas =
        evicted
        |> Enum.take(@max_evicted_logged)
        |> Enum.filter(&is_binary/1)
        |> Enum.map_join(", ", &bounded/1)

      "wasm helper evicted #{length(evicted)} component(s) to admit a load: #{shas}"
    end)
  end

  defp note_evictions(_inflight, _reply), do: :ok

  # The handshake is where a helper is admitted or not. `usable` is the helper's own probe
  # of whether an engine can be built on this host; `worlds` is what it will link against.
  defp admissible?(%{"usable" => true, "worlds" => worlds}) when is_list(worlds),
    do: Wasm.world() in worlds

  defp admissible?(_report), do: false

  # What a refused report is worth recording, and no more of it: a boolean if the helper
  # sent one, and a bounded list of its world strings. Anything else it put in those fields
  # is dropped rather than kept in a status surface's state.
  defp refusal_summary(report) when is_map(report) do
    %{
      usable: is_boolean(Map.get(report, "usable")) && Map.get(report, "usable"),
      worlds: report |> Map.get("worlds") |> bounded_worlds()
    }
  end

  # A refused report's world list is the helper's own strings. It is worth reporting and is
  # therefore bounded before it is kept anywhere a status surface can read.
  defp bounded_worlds(worlds) when is_list(worlds) do
    worlds
    |> Enum.take(8)
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&bounded/1)
  end

  defp bounded_worlds(_other), do: []

  defp answer(%{"error" => error}) when is_map(error), do: {:error, refusal(error)}
  defp answer(%{"result" => result}) when is_map(result), do: {:ok, result}
  # A frame that is neither is this helper breaking its own contract, and the next frame
  # cannot be trusted to be better.
  defp answer(_frame), do: {:error, :malformed}

  # `data.refusal` is the name peers match on (`tui/wasm/src/refusal.rs`); `message` is
  # prose for a human. Both are helper-supplied strings and stay strings — no atom is minted
  # from anything that arrived on this pipe.
  defp refusal(error) do
    %{
      code: integer_or(Map.get(error, "code"), 0),
      refusal: string_or(get_in_map(error, ["data", "refusal"]), "unspecified"),
      message: string_or(Map.get(error, "message"), "")
    }
  end

  defp get_in_map(map, [key]) when is_map(map), do: Map.get(map, key)

  defp get_in_map(map, [key | rest]) when is_map(map),
    do: map |> Map.get(key) |> get_in_map(rest)

  defp get_in_map(_other, _path), do: nil

  defp integer_or(value, _default) when is_integer(value), do: value
  defp integer_or(_value, default), do: default

  defp string_or(value, _default) when is_binary(value), do: bounded(value)
  defp string_or(_value, default), do: default

  # Helper prose is bounded before it is stored or replied with. The helper already bounds
  # its own error text; this is the bound that does not depend on it having done so. The cut
  # is by bytes and then walked back to a whole character, because a message half a
  # codepoint long is one no surface downstream can encode.
  defp bounded(text) when byte_size(text) <= @max_message_bytes, do: text

  defp bounded(text), do: valid_prefix(binary_part(text, 0, @max_message_bytes)) <> "…"

  defp valid_prefix(binary) do
    cond do
      String.valid?(binary) -> binary
      byte_size(binary) == 0 -> binary
      true -> binary |> binary_part(0, byte_size(binary) - 1) |> valid_prefix()
    end
  end

  defp issue(state, method, params, kind, timeout_ms) do
    {id, state} = take_id(state)
    frame = Codec.request(id, method, params)

    with :ok <- within_frame_cap(state, frame),
         :ok <- write(state, frame) do
      # Clamped like every other interval that reaches a timer here (F2). This path carries
      # settings rather than a caller's number, but a settings typo is still an integer
      # somebody chose, and `Process.send_after/3` raises on a large enough one.
      ref = Process.send_after(self(), {:deadline, id}, min(max(timeout_ms, 1), @max_timeout_ms))

      {:ok,
       %{
         state
         | inflight: %{
             id: id,
             kind: kind,
             method: method,
             # Carried so `remember_instance/3` can settle the bookkeeping for a request
             # this pool issued itself, exactly as it does for a caller's.
             params: params,
             owner: nil,
             # A request this pool issued for itself — the handshake, a reclaim `drop` — is
             # never a repository's, so it is never budgeted.
             lane: :capability,
             deadline: ref
           }
       }}
    end
  end

  defp issue_item(state, item) do
    cond do
      item.expires_at <= now() or not Process.alive?(item.caller) ->
        {:expired, state}

      true ->
        {id, state} = take_id(state)
        frame = Codec.request(id, item.method, item.params)

        # The outbound bound, measured before the port is touched. It is this caller's
        # request that is oversize, not the helper that is broken, so refuse only this
        # caller: touching the port here would send a frame the helper must drop (it cannot
        # correlate a reply to a request it never fully read), stalling its whole deadline
        # and taking every concurrent caller down with it when the pool then went broken.
        case within_frame_cap(state, frame) do
          {:error, {:frame_too_large, size}} ->
            {:frame_too_large, state, size}

          :ok ->
            issue_measured(state, item, id, frame)
        end
    end
  end

  defp issue_measured(state, item, id, frame) do
    case write(state, frame) do
      :ok ->
        drop_timer(item.deadline)
        ref = Process.send_after(self(), {:deadline, id}, item.expires_at - now())

        {:ok,
         %{
           state
           | inflight: %{
               id: id,
               kind: {:caller, item},
               method: item.method,
               params: item.params,
               owner: item.owner,
               lane: item.lane,
               deadline: ref
             }
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # A frame this side would refuse inbound is one it must not write outbound either: the
  # helper enforces the same read-bounded cap and would drop it unread. Measured as iodata
  # so the encoded bytes are never materialized twice.
  defp within_frame_cap(state, frame) do
    size = IO.iodata_length(frame)

    if size > state.settings.max_frame_bytes,
      do: {:error, {:frame_too_large, size}},
      else: :ok
  end

  defp take_id(state), do: {state.next_id, %{state | next_id: state.next_id + 1}}

  # Mark broken and answer whoever was waiting. The pool keeps running: a crash here would
  # only replace a process that answers honestly with one that is not there at all.
  defp go_broken(state, reason) do
    if state.inflight do
      drop_timer(state.inflight.deadline)

      case state.inflight.kind do
        {:caller, item} ->
          Process.demonitor(item.monitor, [:flush])
          GenServer.reply(item.from, {:error, :broken})

        _handshake_or_orphaned ->
          :ok
      end
    end

    Enum.each(:queue.to_list(state.queue), fn item ->
      cleanup_item(item)
      GenServer.reply(item.from, {:error, :broken})
    end)

    Logger.debug(fn -> "wasm helper broken: #{Kernel.inspect(reason, limit: 10)}" end)

    # The child is killed by `hard_close/1` and its whole instance table goes with it, so
    # there is nothing left to reclaim: every monitor is released and every scheduled drop
    # is forgotten rather than issued against a helper that has never heard of the name.
    forget_owners(state)

    %{
      hard_close(state)
      | phase: :broken,
        inflight: nil,
        queue: :queue.new(),
        buffer: <<>>,
        deadlines: %{},
        owners: %{},
        # W8, H3. The accepted report goes with the rest of the dead child's facts. It names
        # the wasmtime and the target triple a precompiled artifact is bound to, and the binary
        # on disk can have been replaced — `make wasm` while a node runs is the ordinary way.
        # Keeping it would have `wasm.list` draw a form, and a reader with `connect: false`
        # answer one, out of a reading from a process that is gone; `nil` is "this node does not
        # know", which is what it is until a fresh helper says otherwise.
        doctor: nil,
        pending_drops: [],
        hook_shas: MapSet.new(),
        broken_until: now() + state.settings.broken_ms,
        broken_reason: reason
    }
  end

  defp forget_owners(state) do
    Enum.each(state.owners, fn {_instance, {_seq, monitor}} ->
      Process.demonitor(monitor, [:flush])
    end)
  end

  ## Transport

  defp open_port(state) do
    case spawn_plan(state) do
      {:ok, plan} -> spawn_child(state, plan)
      {:error, _reason} = error -> error
    end
  end

  # What to spawn, with what argv, in what environment, and what that says about the posture.
  # One function, because "is this child sandboxed" and "what is the command line" have to be
  # the same decision: a plan that computed the argv in one place and the posture in another
  # is a status surface that can be wrong about its own child.
  defp spawn_plan(state) do
    case sandbox_setting(state) do
      :off -> {:ok, unsandboxed_plan(state)}
      :required -> sandboxed_plan(state)
    end
  end

  # The same bound this pool encodes and decodes under, named on the child so a raised
  # Elixir cap cannot send a frame the helper will drop unread. Always passed, including
  # at the 8 MiB default: one number, both sides.
  defp helper_argv(state) do
    ["serve", "--max-frame-bytes", Integer.to_string(state.settings.max_frame_bytes)]
  end

  # One line per spawn, at warning level, and not one per request: an operator who turned the
  # fence off should see it in the log of a node that restarts its helper, and should not have
  # it drown the log of a node that is working.
  defp unsandboxed_plan(state) do
    Logger.warning(
      "wasm helper spawning unsandboxed: config :ouroboros, :wasm, helper_sandbox: :off " <>
        "— the helper maps machine code a signer produced (docs/WASM.md D24, D25)"
    )

    %{
      executable: state.helper_path,
      args: helper_argv(state),
      env: filtered_env(),
      scratch: nil,
      fenced: readable_roots(state),
      sandbox: %{
        posture: :off,
        process: :off,
        backend: Sandbox.label(Sandbox.detect()),
        reason: nil,
        # What the pool *would* have fenced to, so `:off` and `:sandboxed` are read the same
        # way and the difference between them is the posture and nothing else.
        readable: effective_readable(state)
      }
    }
  end

  # The two questions asked before a scratch is created, in the order that spends the least:
  # a node with no backend and a node whose backend cannot fence reads are both refusals, and
  # neither is worth a directory. `fences_reads?/1` is the only question this module asks
  # about a backend (contract C11) — what a backend can express is that module's to know.
  defp sandboxed_plan(state) do
    detection = Sandbox.detect()

    cond do
      detection.backend == :none ->
        {:error, {:helper_sandbox_unavailable, {:no_backend, bounded(detection.notes)}}}

      not Sandbox.fences_reads?(detection) ->
        {:error, {:helper_sandbox_unavailable, {:cannot_fence_reads, detection.backend}}}

      # A backend can be present, apply every filesystem rule, and still leave the child on the
      # host's network: `bwrap` on a host that refuses `CLONE_NEWNET` records
      # `unshare_net: false` and emits no `--unshare-net`, so a policy that says `network:
      # false` is not one. For a human's shell that is a documented weaker posture; for the
      # process that holds a signer's machine code it is a wall with a hole in it.
      not Sandbox.fences_network?(detection) ->
        {:error, {:helper_sandbox_unavailable, {:cannot_fence_network, detection.backend}}}

      true ->
        wrapped_plan(state, detection)
    end
  end

  defp wrapped_plan(state, detection) do
    with {:ok, scratch} <- open_scratch(state) do
      ensure_own_roots()
      roots = readable_roots(state)

      # Canonical, all of it. A backend evaluates the path the kernel resolves, and on macOS
      # `System.tmp_dir!()` is `/var/folders/…`, which is `/private/var/folders/…` by the time
      # `open` sees it — a rule written on the un-resolved form matches nothing and the fence
      # silently becomes a wall. `readable_roots/1` already resolves; the writable roots and
      # the scratch are resolved here for the same reason.
      policy =
        Sandbox.helper_policy(
          readable: roots,
          writable: Enum.map(List.wrap(state.writable), &canonical/1),
          scratch: scratch,
          process: process_setting(state)
        )

      case Sandbox.wrap({:argv, [state.helper_path | helper_argv(state)]}, %{}, policy, detection) do
        {:ok, {executable, args}} ->
          {:ok,
           %{
             executable: executable,
             args: args,
             env: filtered_env() ++ scratch_env(policy),
             scratch: scratch,
             fenced: roots,
             sandbox: %{
               posture: :sandboxed,
               # What the backend applied, not what the policy asked: a Linux node's helper
               # runs with an open process posture and its status says so (W21).
               process: Sandbox.process_posture(policy, detection),
               backend: Sandbox.label(detection),
               reason: nil,
               readable: policy.readable
             }
           }}

        {:error, reason} ->
          _ = File.rm_rf(scratch)
          {:error, {:helper_sandbox_unavailable, reason}}
      end
    end
  end

  defp spawn_child(state, plan) do
    port =
      Port.open(
        {:spawn_executable, String.to_charlist(plan.executable)},
        [
          :binary,
          :exit_status,
          # `:use_stdio` and deliberately *not* `:stderr_to_stdout`: the helper's stderr
          # inherits this VM's stderr instead of becoming a pipe nothing here reads. That is
          # a wiring constraint, not a default. Per `tui/wasm/src/host.rs`'s module doc,
          # neither fuel nor the epoch deadline can interrupt a guest that is inside a host
          # call, so a guest calling `log` runs at the speed of the helper's stderr; the
          # helper budgets log lines per call so no single call can fill a pipe, but an
          # undrained pipe still wedges it eventually — and a wedged helper is one this pool
          # can only kill. Inheriting costs nothing and removes the failure entirely.
          :use_stdio,
          :hide,
          {:args, plan.args},
          {:env, plan.env}
        ]
      )

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _absent -> nil
      end

    {:ok,
     %{
       state
       | port: port,
         os_pid: os_pid,
         scratch: plan.scratch,
         sandbox: plan.sandbox,
         fenced: plan.fenced
     }}
  rescue
    error ->
      _ = if is_binary(plan.scratch), do: File.rm_rf(plan.scratch)
      {:error, Exception.message(error)}
  end

  # Erlang's `env` option *modifies* the inherited environment rather than replacing it —
  # there is no `:clear` for `Port.open/2` as there is for erlexec — so deny-by-default is
  # expressed by naming every variable this node holds that is not on the allow-list and
  # removing it (value `false` unsets one). The list is built from this node's own
  # environment at spawn time, so nothing that is not there cannot be removed.
  defp filtered_env do
    System.get_env()
    |> Enum.reject(fn {name, value} -> inherited?(name, value) end)
    |> Enum.map(fn {name, _value} -> {String.to_charlist(name), false} end)
  end

  defp inherited?(name, value),
    do: name in @inherited_env and not Regex.match?(@credential_value, value)

  # `Sandbox.env/1`'s three names, as `Port.open/2` wants them. They come *after* the
  # allow-list's unsets, so `TMPDIR` ends up at the scratch whatever this node's own was: a
  # child whose only writable directory is the scratch and whose `$TMPDIR` still named the
  # operator's would be one whose first `mkstemp` fails inside a sandbox that is working.
  defp scratch_env(policy) do
    Enum.map(Sandbox.env(policy), fn {name, value} ->
      {String.to_charlist(name), String.to_charlist(value)}
    end)
  end

  ## The OS sandbox (W16, D25)

  # The pool's option wins over the node's setting, and the setting is read at every connect
  # rather than at `init/1`: an operator who turns the fence off, or back on, gets it on the
  # next spawn instead of on the next restart of a supervision tree.
  defp sandbox_setting(%{helper_sandbox: posture}) when posture in [:required, :off],
    do: posture

  defp sandbox_setting(_state), do: Wasm.helper_sandbox()

  # W21. Sealed unless this pool was told its helper is a script; nothing in the node's
  # configuration can say otherwise.
  defp process_setting(%{scripted_helper: true}), do: :open
  defp process_setting(_binary), do: :sealed

  defp sandbox_option(opts) do
    case Keyword.get(opts, :helper_sandbox) do
      posture when posture in [:required, :off] -> posture
      _absent -> nil
    end
  end

  # Everything the child may read, and the fence is that there is no more. Four sources and
  # each is here for one reason:
  #
  #   * `Sandbox.platform_readable/0` — the dynamic loader and the C library the helper links,
  #     without which the process does not start at all;
  #   * the **helper binary's own directory**, because bubblewrap has to `--ro-bind` the
  #     executable into the namespace before it can `execve` it. Seatbelt does not need it —
  #     a mutation that dropped this root stayed green on macOS under W16's open
  #     `(allow process-exec)`, and the sentence that used to stand here ("`process-exec`
  #     still has to read the executable") was simply false there. It is a Linux requirement,
  #     pinned as one in `test/provider/native/sandbox_helper_policy_test.exs`. Since W21 the
  #     Seatbelt profile's one exec is a literal on the helper's **resolved** path, which
  #     `SandboxExec.wrap/4` computes from argv[0] itself; this root is still not what makes
  #     that exec work;
  #   * this node's **component store**, `Ouroboros.Wasm.Store.root/1` — the one directory
  #     every `load` in this repository resolves a path in, the hook lane included since W16's
  #     fix wave staged its bytes there. Not `<data_dir>/wasm`: that subtree also holds the
  #     upload staging area, the sign scratch, the forged bundles and the forge's cargo home,
  #     and a cargo home's `config.toml` on a builder node can hold a credential;
  #   * the forge's **build directory**, `Ouroboros.Wasm.Forge`'s own, because `inspect` on a
  #     freshly built product is the one path this node hands the helper that is not a store
  #     entry (D18). It is the node's own directory, holding a project this node validated and
  #     bytes cargo just wrote;
  #   * `helper_readable` — **vetted** (`Ouroboros.Wasm.helper_readable/0`) — for a node whose
  #     components are somewhere else, plus whatever this pool was started with.
  #
  # What is **not** here, and was in W16's first cut: the node's workspace roots. The hook lane
  # was the reason — `Ouroboros.Provider.Native.Hooks` read a `component =` hook out of the
  # repository it was configured in and handed the pool that path — and it is gone because
  # `run_component/4` now stages those bytes into the store first (docs/WASM.md D25). A fence
  # that had to name every repository an operator serves was a fence around nothing much.
  #
  # The same list is what `check_path/3` measures a `load` and an `inspect` against, so the two
  # walls cannot disagree about where a component may come from.
  defp readable_roots(state) do
    ([Path.dirname(state.helper_path)] ++
       store_root() ++
       List.wrap(Wasm.builds_root()) ++
       Wasm.helper_readable() ++ List.wrap(state.readable))
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    # Both spellings, as `Sandbox.builder_policy/1` keeps them: the canonical one is what a
    # backend that matches resolved paths needs, and the named one is what bubblewrap has to
    # bind for that name to exist in the namespace at all — the helper is executed by the path
    # this pool was configured with, through `_build/…/priv` where that is a symlink.
    |> Enum.flat_map(&[&1, canonical_root(&1)])
    |> Enum.uniq()
  end

  # The node's own roots exist before the child does. Bubblewrap binds only what is on disk
  # when it starts — a root that is not there yet is skipped, not deferred — and the store's
  # directory is created lazily by `Ouroboros.Wasm.Store` on the first publish, so a child
  # spawned on a node that has never held a component would have no store in its namespace
  # and every later load would be `unreadable_component` from inside a fence that looked
  # right from outside (the container proof found it: a forge's first deploy). Creating the
  # directory is what the store does on that publish anyway; a failure here is left to it.
  defp ensure_own_roots do
    Enum.each(store_root() ++ List.wrap(Wasm.builds_root()), fn dir -> _ = File.mkdir_p(dir) end)
  end

  defp store_root do
    case Store.root([]) do
      {:ok, dir} -> [dir]
      {:error, _no_data_dir} -> []
    end
  end

  # The path the kernel would resolve, or — when this side cannot resolve it — the path as
  # written. Used for the writable roots of the policy, where an unresolved spelling names a
  # directory the kernel never matches (the load fence, `under_readable?/2`, refuses an
  # unresolvable parent outright rather than relying on that).
  #
  # A backend evaluates the path an `open` resolves to, so a rule has to be written on the
  # resolved form: on macOS `System.tmp_dir!()` is `/var/folders/…`, which is
  # `/private/var/folders/…` by the time the kernel sees it. The roots are resolvable by the
  # time a policy is built, because `open_scratch/1` runs first and creates the lane's own
  # subtree. When a path is not resolvable the unresolved form is used, and that is the safe
  # direction on both sides: a readable root that does not resolve names a directory the
  # kernel never matches, and a `load` path that does not resolve is measured as written and
  # is therefore refused rather than admitted — which is what `Workspace.Path.canonicalize/1`
  # answering `{:symbolic_link_cycle, "/var"}` for a link into `/var/folders` would otherwise
  # have turned into an admission.
  defp canonical(path) do
    case WorkspacePath.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _unresolvable} -> Path.expand(path)
    end
  end

  # A **root**, resolved as far as it exists and appended for the rest — the opposite fallback
  # from `canonical/1`, and for the opposite reason.
  #
  # A root's job is to match: the store's own directory is created lazily by
  # `Ouroboros.Wasm.Store` on its first publish, so a pool that spawns before a node has ever
  # held a component is asked to fence a directory that is not there yet. `Path.expand/1` would
  # then leave `/var/folders/…` un-resolved where the kernel sees `/private/var/folders/…`, and
  # the rule would name a directory that never matches — the store unreadable, every load
  # `unreadable_component`, on a node that looks correctly configured. Resolving the deepest
  # ancestor that does exist keeps the two spellings the same one. A *load path* still fails
  # closed (`canonical/1`): an unresolvable path there is refused, never admitted.
  defp canonical_root(path) do
    case WorkspacePath.canonicalize(path) do
      {:ok, canonical} ->
        canonical

      {:error, _absent} ->
        parent = Path.dirname(path)

        if parent == path,
          do: Path.expand(path),
          else: Path.join(canonical_root(parent), Path.basename(path))
    end
  end

  # A directory only this child writes into, created the way `Ouroboros.Wasm.Deploy`'s sign
  # scratch is and for the same reason: `System.tmp_dir!()` is writable by every account on
  # the machine, so a root this process `mkdir_p`s there may already exist, be owned by
  # somebody else, or be a symlink into a directory they control — and it is the one place
  # this node's containment helper is allowed to write. So the root is
  # `<data_dir>/wasm/scratch/`, both it and the child's directory are created 0700 and
  # **verified** with `lstat` to be real directories rather than links, and a node with no
  # data directory does not get one — which under `:required` is a refusal to spawn.
  defp open_scratch(state) do
    with {:ok, root} <- scratch_root(state),
         {:ok, root} <- private_dir(root) do
      sweep_scratch(root)

      name = @scratch_prefix <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
      dir = Path.join(root, name)

      case private_dir(dir) do
        {:ok, dir} ->
          # Written after the directory exists and before the child does, so a sweep that runs
          # between the two sees a fresh directory and leaves it alone on age anyway.
          _ = File.write(dir <> @owner_suffix, System.pid())
          {:ok, canonical(dir)}

        {:error, _reason} = error ->
          error
      end
    end
  end

  defp private_dir(path) do
    with :ok <- File.mkdir_p(path),
         :ok <- File.chmod(path, 0o700),
         {:ok, %File.Stat{type: :directory}} <- File.lstat(path) do
      {:ok, path}
    else
      {:ok, %File.Stat{type: type}} ->
        {:error, {:helper_sandbox_unavailable, {:scratch_not_a_directory, type}}}

      {:error, reason} ->
        {:error, {:helper_sandbox_unavailable, {:scratch_unavailable, reason}}}
    end
  end

  defp scratch_root(%{scratch_root: dir}) when is_binary(dir) and dir != "", do: {:ok, dir}

  defp scratch_root(_state) do
    case Wasm.data_root() do
      dir when is_binary(dir) -> {:ok, Path.join(dir, "scratch")}
      nil -> {:error, {:helper_sandbox_unavailable, :no_data_dir}}
    end
  end

  # On the way in, because "removed when the child ends" is not always in this runtime's gift:
  # a node killed with `-9` runs no `terminate/2`. Bounded in three directions — only
  # directories this pool named, only ones old enough *and* whose owning BEAM is gone, and at
  # most `@scratch_sweep_limit` of them per spawn — so a crowded root costs a bounded amount
  # of work rather than a growing one, and a sibling node's live child is never the cost.
  defp sweep_scratch(root) do
    cutoff = System.os_time(:second) - @scratch_abandoned_after_seconds

    case File.ls(root) do
      {:ok, entries} ->
        entries
        |> Stream.filter(&String.starts_with?(&1, @scratch_prefix))
        |> Stream.reject(&String.ends_with?(&1, @owner_suffix))
        |> Stream.map(&Path.join(root, &1))
        |> Stream.filter(&abandoned_scratch?(&1, cutoff))
        |> Enum.take(@scratch_sweep_limit)
        |> Enum.each(fn dir ->
          _ = File.rm_rf(dir)
          _ = File.rm(dir <> @owner_suffix)
        end)

      {:error, _unreadable} ->
        :ok
    end

    :ok
  end

  # Old enough first, because that is a `stat` and the other is a process check: on a healthy
  # node nothing passes the first filter and nothing spends the second.
  defp abandoned_scratch?(path, cutoff) do
    old_scratch?(path, cutoff) and not owner_alive?(path <> @owner_suffix)
  end

  defp old_scratch?(path, cutoff) do
    match?(
      {:ok, %File.Stat{type: :directory, mtime: mtime}} when mtime < cutoff,
      File.stat(path, time: :posix)
    )
  end

  # A marker naming a pid this machine still has. Pid reuse can make a dead owner look alive,
  # which only postpones a reclaim; the direction that matters is the other one, and a missing,
  # unreadable or unparseable marker is "no owner" and therefore reclaimable.
  defp owner_alive?(marker) do
    with {:ok, text} <- File.read(marker),
         {pid, _rest} when pid > 0 <- Integer.parse(String.trim(text)),
         exe when is_binary(exe) <- System.find_executable("kill") do
      match?(
        {_output, 0},
        System.cmd(exe, ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
      )
    else
      _no_living_owner -> false
    end
  end

  # The read set as the **policy** states it — this pool's own roots plus the platform's — so
  # the field means the same thing whether a child exists or not. A spawned child reports the
  # policy it actually ran under; everything else reports what the policy would be, built the
  # same way and creating nothing.
  defp effective_readable(state) do
    Sandbox.helper_policy(readable: readable_roots(state), writable: []).readable
  end

  # The process posture the next spawn would get, computed the same way `wrapped_plan/2`
  # computes the one a spawn did get: the policy's ask against what the backend can express.
  defp intended_process(state, detection) do
    Sandbox.process_posture(
      Sandbox.helper_policy(readable: [], writable: [], process: process_setting(state)),
      detection
    )
  end

  defp refused_sandbox(state, why),
    do: %{
      posture: :refused,
      process: nil,
      backend: Sandbox.label(Sandbox.detect()),
      reason: why,
      readable: effective_readable(state)
    }

  # What the last spawn did, or — before there has been one — what the next one would do. The
  # second half is computed rather than assumed, including the scratch root, so a node that
  # would refuse says `:refused` while it is still idle instead of saying `:sandboxed` and
  # then refusing.
  defp sandbox_report(%{sandbox: report}) when is_map(report), do: report

  defp sandbox_report(state) do
    case sandbox_setting(state) do
      :off ->
        %{
          posture: :off,
          process: :off,
          backend: Sandbox.label(Sandbox.detect()),
          reason: nil,
          readable: effective_readable(state)
        }

      :required ->
        intended_sandbox(state, Sandbox.detect())
    end
  end

  defp intended_sandbox(state, detection) do
    label = Sandbox.label(detection)
    roots = effective_readable(state)

    cond do
      detection.backend == :none ->
        %{
          posture: :refused,
          process: nil,
          backend: label,
          reason: {:no_backend, bounded(detection.notes)},
          readable: roots
        }

      not Sandbox.fences_reads?(detection) ->
        %{
          posture: :refused,
          process: nil,
          backend: label,
          reason: {:cannot_fence_reads, detection.backend},
          readable: roots
        }

      not Sandbox.fences_network?(detection) ->
        %{
          posture: :refused,
          process: nil,
          backend: label,
          reason: {:cannot_fence_network, detection.backend},
          readable: roots
        }

      true ->
        case scratch_root(state) do
          {:ok, _root} ->
            %{
              posture: :sandboxed,
              process: intended_process(state, detection),
              backend: label,
              reason: nil,
              readable: roots
            }

          {:error, {:helper_sandbox_unavailable, why}} ->
            %{posture: :refused, process: nil, backend: label, reason: why, readable: roots}
        end
    end
  end

  defp write(%{port: nil}, _frames), do: {:error, :closed}

  # `:nosuspend`, because a compromised helper that reads a request's first bytes and then
  # stops draining stdin leaves this frame buffered; the default `Port.command/2` would then
  # *suspend this GenServer* inside the port until the pipe drains — and a suspended pool
  # cannot fire its own deadline timers, so nothing would ever kill the wedged child. A busy
  # port is instead a broken transport: `Port.command/3` returns `false`, both callers route
  # it into `go_broken({:transport_closed, _})`, and that hard-closes and kills by os pid,
  # which is the right answer to a helper that stopped reading.
  defp write(state, frames) do
    if Port.command(state.port, frames, [:nosuspend]), do: :ok, else: {:error, :port_busy}
  rescue
    ArgumentError -> {:error, :closed}
  end

  defp close_port(%{port: port} = state) when is_port(port) do
    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    %{state | port: nil}
  end

  defp close_port(state), do: state

  defp hard_close(%{os_pid: os_pid} = state) do
    # Kill while the port still names this child; closing first creates a needless PID-reuse
    # race. Closing the port would only shut the child's stdin, which a helper wedged inside
    # a host call is in no position to read. `close_port/1` then releases the BEAM resource
    # and makes old port messages stale.
    #
    # W16: under `bwrap` the os pid is bubblewrap's rather than the helper's, and the helper
    # dies with it because `Bwrap.options/3` passes `--die-with-parent`. Under `sandbox-exec`
    # the wrapper `execve`s the helper in place, so the pid *is* the helper's. Either way one
    # `kill -KILL` of this pid is the whole reap, which is why nothing here changed.
    if is_integer(os_pid) and os_pid > 0 do
      case System.find_executable("kill") do
        nil -> :ok
        exe -> System.cmd(exe, ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)
      end
    end

    state
    |> close_port()
    |> release_scratch()
    |> Map.put(:os_pid, nil)
  rescue
    _error -> state |> close_port() |> release_scratch() |> Map.put(:os_pid, nil)
  end

  # The child's private directory goes with the child. Removed after the kill, so nothing is
  # taken out from under a process that is still running in it.
  defp release_scratch(%{scratch: scratch} = state) when is_binary(scratch) do
    _ = File.rm_rf(scratch)
    %{state | scratch: nil}
  end

  defp release_scratch(state), do: state

  ## Deadlines

  # `call` runs a guest under the deadline its instance was created with, so the transport's
  # deadline has to be derived from that rather than from a constant: a wedged helper must
  # be found on the timescale of the request that wedged it. An instance this pool did not
  # create is either unknown to the helper too (refused at once) or a leftover from before a
  # reconnect, so the helper's own ceiling is the honest bound to wait.
  defp resolve_timeout(state, method, params, requested) do
    # Clamped at the one place every timeout leaves this function, so no derivation below —
    # nor any added later — can hand `Process.send_after/3` an interval it will raise on.
    # `max/2` as well as `min/2`: a non-positive interval is a timer that fires immediately
    # and answers a caller `:timeout` before the helper has read the request.
    state |> derive_timeout(method, params, requested) |> max(1) |> min(@max_timeout_ms)
  end

  defp derive_timeout(state, "instantiate", params, :derived) do
    deadline_of(params) + state.settings.call_margin_ms
  end

  defp derive_timeout(state, "call", params, :derived) do
    instance = Map.get(params, "instance")

    case Map.get(state.deadlines, instance) do
      {_seq, deadline} -> deadline + state.settings.call_margin_ms
      nil -> helper_max_deadline(state) + state.settings.call_margin_ms
    end
  end

  defp derive_timeout(state, _method, _params, _fixed), do: state.settings.request_timeout_ms

  defp deadline_of(params) do
    case get_in_map(params, ["limits", "deadline_ms"]) do
      value when is_integer(value) and value > 0 -> value
      _absent -> 0
    end
  end

  defp helper_max_deadline(state) do
    case get_in_map(state.doctor, ["limits", "max_deadline_ms"]) do
      value when is_integer(value) and value > 0 -> value
      _absent -> 60_000
    end
  end

  # The deadline an instance runs under is only knowable from the request that created it,
  # so it is recorded when the helper confirms the instance and forgotten when it goes. The
  # map is bounded oldest-first (`@max_instances`): a peer that never `drop`s a trapped
  # instance leaves a stale entry, and unbounded stale entries are the only unbounded thing
  # here. Each value carries a sequence so "oldest" is insertion order, not map iteration.
  defp remember_instance(state, %{method: "instantiate", params: params} = inflight, {:ok, _ok}) do
    case {Map.get(params, "instance"), deadline_of(params)} do
      {instance, deadline} when is_binary(instance) and deadline > 0 ->
        seq = state.instance_seq + 1

        deadlines =
          state.deadlines
          |> Map.put(instance, {seq, deadline})
          |> bound_instances(state.max_instances)

        %{state | deadlines: deadlines, instance_seq: seq}
        |> remember_owner(instance, Map.get(inflight, :owner), seq)

      _incomplete ->
        state
    end
  end

  defp remember_instance(state, %{method: "drop", params: params}, {:ok, _result}) do
    instance = Map.get(params, "instance")

    %{state | deadlines: Map.delete(state.deadlines, instance)}
    |> forget_owner(instance)
  end

  defp remember_instance(state, _inflight, _reply), do: state

  defp bound_instances(deadlines, cap) when map_size(deadlines) <= cap, do: deadlines

  defp bound_instances(deadlines, _cap) do
    {oldest, _value} = Enum.min_by(deadlines, fn {_instance, {seq, _deadline}} -> seq end)
    Map.delete(deadlines, oldest)
  end

  ## Ownership

  # An owner is monitored per *instance*, not per pid: one process may own several, each
  # goes away on its own, and a per-instance monitor makes each `:DOWN` name exactly one
  # instance without a reverse index. Re-instantiating a name this pool already tracks
  # releases the previous monitor first, so a guest that traps on every message cannot leave
  # a monitor behind per message.
  defp remember_owner(state, _instance, nil, _seq), do: state

  defp remember_owner(state, instance, owner, seq) when is_pid(owner) do
    state = forget_owner(state, instance)

    owners =
      state.owners
      |> Map.put(instance, {seq, Process.monitor(owner)})
      |> bound_owners(state.max_instances)

    %{state | owners: owners}
  end

  defp forget_owner(state, instance) do
    case Map.pop(state.owners, instance) do
      {nil, _owners} ->
        state

      {{_seq, monitor}, owners} ->
        Process.demonitor(monitor, [:flush])
        %{state | owners: owners}
    end
  end

  # Bounded exactly as `deadlines` is, and for the same reason. Evicting an entry costs the
  # reclaim for that one instance, never correctness.
  defp bound_owners(owners, cap) when map_size(owners) <= cap, do: owners

  defp bound_owners(owners, _cap) do
    {oldest, {_seq, monitor}} = Enum.min_by(owners, fn {_instance, {seq, _ref}} -> seq end)
    Process.demonitor(monitor, [:flush])
    Map.delete(owners, oldest)
  end

  # An owner died. Its instances are still standing in the helper, and nothing else will
  # ever ask for them, so a `drop` is scheduled on this pool's own wire — behind whatever
  # callers are already waiting, because a reclaim is never more urgent than work.
  defp owner_down(state, monitor) do
    case Enum.find(state.owners, fn {_instance, {_seq, ref}} -> ref == monitor end) do
      nil ->
        state

      {instance, _entry} ->
        %{state | owners: Map.delete(state.owners, instance)}
        |> schedule_drop(instance)
        |> drain()
    end
  end

  # Bounded, and oldest-first like everything else here: losing the oldest scheduled reclaim
  # is a leaked instance, while an unbounded list is a leaked node.
  defp schedule_drop(state, instance) do
    pending =
      state.pending_drops
      |> Enum.reject(&(&1 == instance))
      |> Kernel.++([instance])
      |> Enum.take(-state.max_instances)

    %{state | pending_drops: pending}
  end

  ## Queue

  defp queueable?(state) do
    :queue.len(state.queue) < @max_queue and
      (state.phase in [:idle, :ready, :handshaking] or
         (state.phase == :broken and now() >= state.broken_until))
  end

  defp request_item(from, method, params, timeout, owner, lane) do
    caller = elem(from, 0)
    ref = make_ref()

    %{
      ref: ref,
      from: from,
      caller: caller,
      monitor: Process.monitor(caller),
      method: method,
      params: params,
      owner: owner,
      lane: lane,
      expires_at: now() + timeout,
      deadline: Process.send_after(self(), {:queued_deadline, ref}, timeout)
    }
  end

  defp cleanup_item(item) do
    drop_timer(item.deadline)
    Process.demonitor(item.monitor, [:flush])
    :ok
  end

  defp enqueue(state, item), do: %{state | queue: :queue.in(item, state.queue)}

  defp drain(%{phase: :ready, inflight: nil} = state) do
    case :queue.out(state.queue) do
      # Callers first, always. A reclaim only ever rides an idle wire, so it cannot delay
      # work and cannot take the one in-flight slot from a request somebody is waiting on.
      {:empty, _queue} ->
        drain_pending_drops(state)

      {{:value, item}, rest} ->
        state = %{state | queue: rest}
        drain_item(state, item)
    end
  end

  defp drain(state), do: state

  # Re-admit before spending the wire. `handle_call` already ran `admit/4`, but that was
  # against the set as it stood on arrival; a load that waited behind another may now be
  # past the untrusted-hook budget, and a reconnect may have changed the readable roots.
  defp drain_item(state, item) do
    case admit(state, item.method, item.params, item.lane) do
      {:error, reason} ->
        if Process.alive?(item.caller), do: GenServer.reply(item.from, {:error, reason})
        cleanup_item(item)
        drain(state)

      :ok ->
        case issue_item(state, item) do
          {:ok, state} ->
            state

          {:expired, state} ->
            if Process.alive?(item.caller), do: GenServer.reply(item.from, {:error, :timeout})
            cleanup_item(item)
            drain(state)

          {:frame_too_large, state, size} ->
            if Process.alive?(item.caller) do
              GenServer.reply(
                item.from,
                {:error, {:frame_too_large, size, state.settings.max_frame_bytes}}
              )
            end

            cleanup_item(item)
            drain(state)

          {:error, reason} ->
            cleanup_item(item)
            GenServer.reply(item.from, {:error, :broken})
            go_broken(state, {:transport_closed, reason})
        end
    end
  end

  defp drain_pending_drops(%{pending_drops: []} = state), do: state

  defp drain_pending_drops(%{pending_drops: [instance | rest]} = state) do
    state = %{state | pending_drops: rest}

    case issue(
           state,
           "drop",
           %{"instance" => instance},
           :internal,
           state.settings.request_timeout_ms
         ) do
      {:ok, state} -> state
      {:error, reason} -> go_broken(state, {:transport_closed, reason})
    end
  end

  defp remove_queued(queue, value, key) do
    items = :queue.to_list(queue)

    case Enum.split_while(items, &(Map.fetch!(&1, key) != value)) do
      {before, [item | after_items]} -> {item, :queue.from_list(before ++ after_items)}
      {_all, []} -> {nil, queue}
    end
  end

  ## Settings

  defp settings(opts) do
    Map.new(
      [
        :handshake_timeout_ms,
        :request_timeout_ms,
        :call_margin_ms,
        :max_frame_bytes,
        :broken_ms
      ],
      fn key -> {key, setting(opts, key)} end
    )
  end

  # `broken_ms` is settable so a test can prove the cooldown window is honored without
  # sitting through the node's; every other value is a bound an operator may already move.
  defp setting(opts, :max_frame_bytes) do
    max = Wasm.max_frame_bytes_max()

    case Keyword.get(opts, :max_frame_bytes) do
      value when is_integer(value) and value > 0 and value <= max -> value
      _absent -> Wasm.config(:max_frame_bytes)
    end
  end

  defp setting(opts, key) do
    case Keyword.get(opts, key) do
      value when is_integer(value) and value > 0 -> value
      _absent -> Wasm.config(key)
    end
  end

  # The deadline-map cap. A module constant in production (`@max_instances`); overridable in
  # opts so a test can prove the oldest-first bound without instantiating hundreds of times.
  defp max_instances(opts) do
    case Keyword.get(opts, :max_instances) do
      value when is_integer(value) and value > 0 -> value
      _absent -> @max_instances
    end
  end

  # Every one of the three bounds is range-checked here, against the helper's own maxima, and
  # a value outside them is `{:error, {:invalid_limits, {key, value}}}` before a frame is
  # built or a timer armed (F2). Two separate things needed this. `deadline_ms` is the one
  # limit that also becomes a *transport* deadline — `resolve_timeout/4` derives one from it
  # and hands it to `Process.send_after/3` — so a caller-chosen `deadline_ms` past what a
  # timer accepts used to raise `badarg` inside `handle_call/3` and kill the pool, which is
  # remotely reachable through `Mesh.start_agent/2`'s `initial_state`. And all three are
  # bounds the helper would refuse anyway (`limits_out_of_range`), so refusing here spends no
  # frame, no compile, and — since the pool is lazy — no spawn.
  #
  # This is a refusal and not a clamp: a bound nobody stated is not one this node invents,
  # and silently running a guest under a *different* bound than the one it was deployed with
  # would be exactly that. The clamping belongs one layer up, where the declaration is
  # visible (`Ouroboros.Wasm.Capability.limits/1`).
  defp wire_limits(%{fuel: fuel, memory_bytes: memory, deadline_ms: deadline}) do
    with :ok <- in_range(:fuel, fuel, 1, @max_fuel),
         :ok <- in_range(:memory_bytes, memory, @min_memory_bytes, @max_memory_bytes),
         :ok <- in_range(:deadline_ms, deadline, 1, @max_deadline_ms) do
      {:ok, %{"fuel" => fuel, "memory_bytes" => memory, "deadline_ms" => deadline}}
    end
  end

  defp wire_limits(_other), do: :error

  defp in_range(_key, value, low, high)
       when is_integer(value) and value >= low and value <= high,
       do: :ok

  defp in_range(key, value, _low, _high), do: {:error, {:invalid_limits, {key, value}}}

  # The second, narrower check: what the *connected* helper says it accepts. The constants
  # above are this build's reading of `host.rs` and cannot be newer than the binary on disk,
  # so a helper whose `doctor.limits` are tighter has the last word. An absent or malformed
  # report leaves the constants standing rather than widening anything.
  defp within_helper_limits(state, %{"fuel" => fuel} = wire) do
    limits = get_in_map(state.doctor, ["limits"])

    with :ok <- under(:fuel, fuel, limits, "max_fuel"),
         :ok <- over(:memory_bytes, wire["memory_bytes"], limits, "min_memory_bytes"),
         :ok <- under(:memory_bytes, wire["memory_bytes"], limits, "max_memory_bytes"),
         :ok <- under(:deadline_ms, wire["deadline_ms"], limits, "max_deadline_ms") do
      :ok
    end
  end

  defp within_helper_limits(_state, _params), do: :ok

  defp under(key, value, limits, name) do
    case get_in_map(limits, [name]) do
      bound when is_integer(bound) and bound > 0 and value > bound ->
        {:error, {:invalid_limits, {key, value}}}

      _within_or_unknown ->
        :ok
    end
  end

  defp over(key, value, limits, name) do
    case get_in_map(limits, [name]) do
      bound when is_integer(bound) and bound > 0 and value < bound ->
        {:error, {:invalid_limits, {key, value}}}

      _within_or_unknown ->
        :ok
    end
  end

  defp drop_timer(ref) when is_reference(ref), do: Process.cancel_timer(ref)
  defp drop_timer(_ref), do: :ok

  defp now, do: System.monotonic_time(:millisecond)
end
