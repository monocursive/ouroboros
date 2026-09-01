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

  ## Env is filtered

  The helper is spawned with the node's environment minus anything that reads like a secret.
  It runs untrusted guest code behind a linker that imports one host function; it has no
  business holding this runtime's credentials, and a child that cannot read them cannot leak
  them to the thing it contains.
  """

  use GenServer

  require Logger

  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Codec

  # Names of environment variables the helper is never given. Deliberately the same
  # expression as `Ouroboros.Provider.Native.Desktop.Pool`'s `@secret_env` and kept in step
  # with it by hand: a shared module would tie two independent spawn seams to one list, and
  # this repo already carries a third, differently-shaped copy in
  # `Ouroboros.Provider.Native.Exec`. Stripping generously is safe because the helper needs
  # none of these to run.
  @secret_env ~r/(API_?KEY|_TOKEN|SECRET|OAUTH|PASSWORD|CREDENTIAL|GATEWAY_TOKEN)/i

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

  @typedoc "What `status/1` reports about the helper."
  @type status :: %{
          phase: :idle | :handshaking | :ready | :broken,
          helper_path: String.t(),
          os_pid: pos_integer() | nil,
          doctor: map() | nil,
          instances: non_neg_integer(),
          owned: non_neg_integer(),
          pending_drops: non_neg_integer(),
          broken_reason: term() | nil
        }

  @typedoc "A refusal frame from the helper. `refusal` is the name peers match on."
  @type refusal :: %{code: integer(), refusal: String.t(), message: String.t()}

  @typedoc "Everything a caller can be told that is not a helper result."
  @type failure ::
          refusal()
          | :unavailable
          | :broken
          | :busy
          | :timeout
          | {:frame_too_large, non_neg_integer(), pos_integer()}
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
  """
  @spec load(String.t(), String.t(), GenServer.server()) :: {:ok, map()} | {:error, failure()}
  def load(sha256, path, server \\ __MODULE__) when is_binary(sha256) and is_binary(path) do
    request(server, "load", %{"sha256" => sha256, "path" => path}, :fixed)
  end

  @doc """
  Instantiates a loaded component as `instance`, running its `init` under `limits`.

  All three limits are required and none is defaulted here. The helper refuses a request
  that omits one — "there is no unlimited default" is its sentence, not this pool's — and
  inventing a value on this side would be this node deciding, silently, how much of the
  machine a guest may have.

  ## `owner:` — who this instance belongs to

  `opts` takes one option, `owner: pid`, and it is the answer to the only unbounded thing
  this pool otherwise has: an instance nobody drops. The helper holds `MAX_INSTANCES` (256)
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
         {:ok, wire} <- wire_limits(limits) do
      request(
        server,
        "instantiate",
        %{"instance" => instance, "sha256" => sha256, "config" => config, "limits" => wire},
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
        broken_reason: {:pool_unavailable, reason}
      }
  end

  # Never raises and never exits the caller. A missing binary, a dead helper, a full queue,
  # and a helper that does not answer are all error tuples. The deadline is named rather
  # than passed: which one a method gets is the pool's decision, made against the settings
  # that pool was started with and, for `call`, against what it knows of the instance.
  defp request(server, method, params, deadline, owner \\ nil)
       when deadline in [:fixed, :derived] do
    GenServer.call(server, {:request, method, params, deadline, owner}, @client_ceiling_ms)
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
       instance_seq: 0,
       max_instances: max_instances(opts)
     }}
  end

  @impl true
  def handle_call({:request, method, params, requested, owner}, from, state) do
    # Mint the deadline at receipt, before reconnect or queue work, so a caller waiting
    # behind another one is not given a fresh window when its turn comes.
    item =
      request_item(
        from,
        method,
        params,
        resolve_timeout(state, method, params, requested),
        owner
      )

    cond do
      state.phase == :ready and state.inflight == nil ->
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
       broken_reason: state.broken_reason
     }, state}
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

    case open_port(%{state | buffer: <<>>, noise: 0, inflight: nil, deadlines: %{}}) do
      {:ok, state} -> start_handshake(state)
      {:error, reason} -> go_broken(state, {:spawn_failed, reason})
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

  defp route({:caller, item}, reply, state, inflight) do
    Process.demonitor(item.monitor, [:flush])
    GenServer.reply(item.from, reply)
    state |> remember_instance(inflight, reply) |> drain()
  end

  defp route(:orphaned, _reply, state, _inflight), do: drain(state)

  # A reclaim `drop` this pool issued for a dead owner. Nobody is waiting for the answer;
  # the bookkeeping it settles is this pool's own.
  defp route(:internal, reply, state, inflight),
    do: state |> remember_instance(inflight, reply) |> drain()

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

  defp refusal_summary(_report), do: %{usable: false, worlds: []}

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
      ref = Process.send_after(self(), {:deadline, id}, timeout_ms)

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
        pending_drops: [],
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
    port =
      Port.open(
        {:spawn_executable, String.to_charlist(state.helper_path)},
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
          {:args, [~c"serve"]},
          {:env, filtered_env()}
        ]
      )

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _absent -> nil
      end

    {:ok, %{state | port: port, os_pid: os_pid}}
  rescue
    error -> {:error, Exception.message(error)}
  end

  # Erlang's `env` option modifies the inherited environment rather than replacing it, so
  # the helper keeps PATH, HOME, and TMPDIR, and only the secret-shaped variables are unset
  # (value `false` removes one).
  defp filtered_env do
    System.get_env()
    |> Enum.filter(fn {name, _value} -> Regex.match?(@secret_env, name) end)
    |> Enum.map(fn {name, _value} -> {String.to_charlist(name), false} end)
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
    if is_integer(os_pid) and os_pid > 0 do
      case System.find_executable("kill") do
        nil -> :ok
        exe -> System.cmd(exe, ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)
      end
    end

    state
    |> close_port()
    |> Map.put(:os_pid, nil)
  rescue
    _error -> state |> close_port() |> Map.put(:os_pid, nil)
  end

  ## Deadlines

  # `call` runs a guest under the deadline its instance was created with, so the transport's
  # deadline has to be derived from that rather than from a constant: a wedged helper must
  # be found on the timescale of the request that wedged it. An instance this pool did not
  # create is either unknown to the helper too (refused at once) or a leftover from before a
  # reconnect, so the helper's own ceiling is the honest bound to wait.
  defp resolve_timeout(state, "instantiate", params, :derived) do
    deadline_of(params) + state.settings.call_margin_ms
  end

  defp resolve_timeout(state, "call", params, :derived) do
    instance = Map.get(params, "instance")

    case Map.get(state.deadlines, instance) do
      {_seq, deadline} -> deadline + state.settings.call_margin_ms
      nil -> helper_max_deadline(state) + state.settings.call_margin_ms
    end
  end

  defp resolve_timeout(state, _method, _params, _fixed), do: state.settings.request_timeout_ms

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

  defp request_item(from, method, params, timeout, owner) do
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

  defp drain(state), do: state

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

  defp wire_limits(%{fuel: fuel, memory_bytes: memory, deadline_ms: deadline})
       when is_integer(fuel) and fuel > 0 and is_integer(memory) and memory > 0 and
              is_integer(deadline) and deadline > 0 do
    {:ok, %{"fuel" => fuel, "memory_bytes" => memory, "deadline_ms" => deadline}}
  end

  defp wire_limits(_other), do: :error

  defp drop_timer(ref) when is_reference(ref), do: Process.cancel_timer(ref)
  defp drop_timer(_ref), do: :ok

  defp now, do: System.monotonic_time(:millisecond)
end
