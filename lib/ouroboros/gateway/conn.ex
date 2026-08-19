defmodule Ouroboros.Gateway.Conn do
  @moduledoc """
  One client connection: framing, the handshake, bounded dispatch, and the event stream.

  A `Conn` owns exactly one socket and nothing else. There is no state shared between
  connections, so a client that stops reading, floods, or dies stalls only itself.

  ## The handshake is the only thing that grants anything

  The first frame must be `hello`. Any other frame before it is answered `-32001` and the
  socket is closed — including a well-formed `runtime.status`, because a method table
  leaked to an unauthenticated peer is still a leak. A connection that has not completed
  `hello` within 10 seconds is closed whether or not it sent anything.

  The token is compared as `:crypto.hash_equals/2` over SHA-256 digests of both sides.
  Hashing first makes the operands equal length, so the comparison can neither raise on a
  length mismatch nor leak the length of the expected token through timing.

  A frame carrying no token, a wrong token, or an unreadable one is `-32001` and nothing
  more specific. An unauthenticated peer learns whether it is authenticated, and that is
  all: the protocol version check happens *after* the token check for the same reason.

  ## Bounded dispatch, out-of-order responses

  Each request runs in a task supervised outside this process — a handler that raises
  becomes `-32006` rather than a dead connection — under the ceiling its method declares
  in `Ouroboros.Gateway.Methods`. At most 8 run at once per connection; at most 64 more
  wait behind them, past which further requests are answered `-32004` rather than
  accumulating. That inbound bound is a fixed constant rather than a setting:
  `OUROBOROS_GATEWAY_QUEUE_LIMIT` governs the *outbound* event queue below, and one
  variable naming two different queues would be a variable an operator cannot reason
  about. Responses correlate by `id` and are written in completion order, so a slow
  `runtime.providers` never delays a fast `agents.list` behind it.

  A request that outlives its ceiling is killed and answered `-32005`. That answer is
  honest about the gateway and silent about the plane: killing the task does not cancel
  work already in flight upstream, and for the `:infinity` verbs — `teams.cancel`,
  `teams.close` — it provably cannot, so those two carry `"outcome": "unknown"` in the
  timeout's `data` and the client reconciles by reading `teams.state`.

  ## Subscriptions live in this process

  Both planes register `self()` as the subscriber and monitor it
  ([interactive/task.ex](../lib/ouroboros/interactive/task.ex)), so the four subscribe
  verbs are answered here rather than in a dispatch task — a task's `self()` is the wrong
  process and would die with the request. The cost is stated rather than hidden: those
  calls block this process for as long as the plane's own control-plane bound allows
  (30s, `:session_call_timeout`), because a `GenServer.call` this process must make itself
  is not a call it can put a gateway ceiling on.

  Two upstream behaviors are handled explicitly, because both would otherwise leave a
  client waiting for events that are never coming:

    * a terminal session answers the backlog and *silently declines* the registration, so
      the session's status is read immediately after every successful subscribe and
      `stream.ended` follows the backlog when it is terminal;
    * the coordinator holding the registration can retire or crash, taking the
      subscription with it, so it is monitored and its `:DOWN` also produces
      `stream.ended`. That monitor is the honest half of a promise this connection cannot
      otherwise keep.

  Cleanup after an abnormal death needs nothing from here: both planes monitor the
  subscriber pid and drop it on `:DOWN`. A graceful close still unsubscribes explicitly,
  under a total budget, because releasing a registration you are about to abandon is
  cheap and the budget is what keeps a wedged coordinator from delaying the exit.

  ## The outbound queue is where backpressure happens

  Frames leave through `Ouroboros.Gateway.Writer`, one process whose only job is the
  blocking `:gen_tcp.send/2` that this one must not make. What this process keeps is the
  count of frames handed over and not yet acknowledged — the queue depth — and that
  number decides two things:

    * **responses and stream control frames are never dropped.** Above a hard cap
      (`OUROBOROS_GATEWAY_QUEUE_LIMIT` plus the 72 responses that can ever be outstanding
      at once) the connection is closed after a best-effort error frame. A client that
      cannot drain its own responses is broken, not throttled.
    * **event notifications are droppable.** Above the limit they are counted per session
      and discarded; when the queue drains below half, one `stream.lagged` per lagged
      session tells the client how many and how far, and it replays from its own cursor.
      Reconciliation is exact inside the retained window and truthfully truncated outside
      it — never silently missing events.

  ## Framing

  The socket runs in `packet: :line` with `packet_size` set from
  `OUROBOROS_GATEWAY_MAX_FRAME`. That combination does not error on an over-long line —
  it delivers a chopped prefix with no newline — so this module treats *any* frame that
  does not end in a newline as a frame that never terminated inside the limit, answers
  it, and closes. Draining the remainder of an unbounded line is the thing the limit
  exists to refuse.
  """

  use GenServer

  require Logger

  alias Ouroboros.Cluster
  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Gateway.Writer
  alias Ouroboros.Interactive.Event, as: InteractiveEvent

  @protocol 1
  @max_in_flight 8

  # Requests accepted and not yet dispatched. Fixed rather than configurable: it bounds
  # what a client costs this process by sending faster than it reads, and the one setting
  # a client's behavior legitimately varies with — how far its event stream may run ahead
  # — is the outbound limit.
  @max_pending 64

  # Every response that can be outstanding at once, which is exactly the two bounds above.
  # Above the outbound limit plus this, an unread response queue is not a slow client, it
  # is a client that stopped reading, and the connection says so and closes.
  @response_headroom @max_in_flight + @max_pending

  # One terminal watches a handful of sessions. This is the ceiling on what a connection
  # can register itself with across the planes, so "bounded everything" covers the thing a
  # client can ask other processes to remember about it.
  @max_subscriptions 64

  @send_timeout 15_000

  # What a deliberate close waits for the last frame to reach the socket. A peer that is
  # not reading must not be able to hold a connection's exit open, so this is short and
  # the socket closes either way.
  @flush_timeout 1_000

  # The whole budget for releasing subscriptions on a graceful close. The planes' own
  # subscriber monitors are what make this optional; if a coordinator is wedged, the
  # supervisor's 5s shutdown kills this process and the monitor does the release.
  @unsubscribe_budget_ms 1_000

  # Read from the method table rather than restated here, because `hello`'s entry is what
  # a client is told the deadline is. One number, in the place a client can see it.
  @hello_timeout Methods.table() |> Map.fetch!("hello") |> Map.fetch!(:timeout)

  # Answered by this process instead of by a dispatch task: the four subscription verbs
  # because the plane registers `self()`, and `runtime.shutdown` because it needs the
  # listener configuration this process holds and the socket it owns.
  @conn_methods %{
    "interactive.subscribe" => {:subscribe, :interactive},
    "interactive.unsubscribe" => {:unsubscribe, :interactive},
    "coding.subscribe" => {:subscribe, :coding},
    "coding.unsubscribe" => {:unsubscribe, :coding},
    "runtime.shutdown" => {:shutdown, nil}
  }

  @doc false
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      restart: :temporary,
      type: :worker,
      shutdown: 5_000
    }
  end

  @doc """
  Starts a connection handler.

  The caller must still be the socket's controlling process: it transfers ownership and
  then sends `:socket_ready`. Until that arrives this process touches nothing.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  The JSON-RPC envelope for a successful result.

  Public because `mix ouroboros.gateway.golden` builds the cross-language fixtures through
  the same three functions the socket is written from. A fixture that came from anywhere
  else could drift from what this build actually emits, which is the one thing a contract
  file must not do.
  """
  @spec result_frame(term(), term()) :: map()
  def result_frame(id, value) do
    %{"jsonrpc" => "2.0", "id" => id, "result" => Wire.to_json(value)}
  end

  @doc "The JSON-RPC envelope for an error, with optional `Wire`-encoded `data`."
  @spec error_frame(term(), integer(), String.t()) :: map()
  def error_frame(id, code, message) do
    %{"jsonrpc" => "2.0", "id" => id, "error" => %{"code" => code, "message" => message}}
  end

  @spec error_frame(term(), integer(), String.t(), term()) :: map()
  def error_frame(id, code, message, data) do
    %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => code, "message" => message, "data" => Wire.to_json(data)}
    }
  end

  @doc "The JSON-RPC envelope for a server notification, which carries no id."
  @spec notification_frame(String.t(), term()) :: map()
  def notification_frame(method, params) do
    %{"jsonrpc" => "2.0", "method" => method, "params" => Wire.to_json(params)}
  end

  @impl true
  def init(opts) do
    config = Keyword.fetch!(opts, :config)

    state = %{
      socket: Keyword.fetch!(opts, :socket),
      config: config,
      task_supervisor: Keyword.fetch!(opts, :task_supervisor),
      peer: nil,
      client: nil,
      authenticated?: false,
      # Set when this connection has decided to end: the frame in hand is written, and
      # then it stops. A failed write and an overloaded queue both land here.
      closing?: false,
      # Set when `runtime.shutdown` was accepted. The node stops once the acknowledgement
      # has actually reached the socket, not before.
      shutdown?: false,
      writer: nil,
      # Frames handed to the writer and not yet acknowledged. This is the queue §2.6
      # bounds; it is a count rather than a list because the frames themselves are already
      # in the writer's mailbox, in order.
      outbound: 0,
      in_flight: %{},
      pending: :queue.new(),
      pending_len: 0,
      # `{plane, session_id} => %{ref, dropped, last_sequence}`. `dropped == 0` means
      # the stream is not lagging. Lag lives on this record so forget/unsubscribe cannot
      # leave drop counters behind for a session this connection no longer watches.
      subscriptions: %{},
      # The reverse index, so a `:DOWN` finds its session without scanning.
      coordinators: %{},
      # Armed before ownership transfer so that a socket that never arrives — the handoff
      # raced a dying client — still reaps this process.
      hello_timer: Process.send_after(self(), :hello_timeout, @hello_timeout)
    }

    {:ok, state}
  end

  @impl true
  def handle_info(:socket_ready, state) do
    peer =
      case :inet.peername(state.socket) do
        {:ok, peer} -> peer
        {:error, _reason} -> nil
      end

    # The writer exists before the socket is readable, so there is no window in which a
    # frame has nowhere to go.
    state = %{state | peer: peer, writer: Writer.start_link(state.socket)}

    case :inet.setopts(state.socket, socket_options(state.config)) do
      :ok -> {:noreply, state}
      {:error, _reason} -> {:stop, :normal, state}
    end
  end

  def handle_info({:tcp, socket, frame}, %{socket: socket} = state) do
    case handle_frame(frame, state) do
      {:continue, state} ->
        case :inet.setopts(socket, active: :once) do
          :ok -> maybe_stop(state)
          {:error, _reason} -> {:stop, :normal, state}
        end

      {:close, state} ->
        {:stop, :normal, state}
    end
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state), do: {:stop, :normal, state}

  def handle_info({:tcp_error, socket, _reason}, %{socket: socket} = state),
    do: {:stop, :normal, state}

  def handle_info(:hello_timeout, %{authenticated?: false} = state) do
    {:stop, :normal, state}
  end

  def handle_info(:hello_timeout, state), do: {:noreply, state}

  def handle_info({:ouroboros_interactive_event, id, %InteractiveEvent{} = event}, state) do
    state
    |> stream_event({:interactive, id}, "interactive.event", id, event)
    |> maybe_stop()
  end

  def handle_info({:ouroboros_coding_event, id, %CodingEvent{} = event}, state) do
    state
    |> stream_event({:coding, id}, "coding.event", id, event)
    |> maybe_stop()
  end

  def handle_info({:frame_written, count}, state) do
    %{state | outbound: max(state.outbound - count, 0)}
    |> flush_lagged()
    |> maybe_stop()
  end

  def handle_info({:write_failed, _reason}, state), do: {:stop, :normal, state}

  def handle_info({:request_timeout, ref}, state) when is_reference(ref) do
    case Map.pop(state.in_flight, ref) do
      {nil, _in_flight} ->
        {:noreply, state}

      {request, in_flight} ->
        Process.demonitor(ref, [:flush])
        _ = Task.Supervisor.terminate_child(state.task_supervisor, request.pid)

        %{state | in_flight: in_flight}
        |> respond(request.id, timeout_result(request))
        |> drain()
        |> maybe_stop()
    end
  end

  def handle_info({ref, result}, state) when is_reference(ref) do
    case Map.pop(state.in_flight, ref) do
      {nil, _in_flight} ->
        {:noreply, state}

      {request, in_flight} ->
        Process.demonitor(ref, [:flush])
        _ = Process.cancel_timer(request.timer)

        %{state | in_flight: in_flight}
        |> respond(request.id, result)
        |> drain()
        |> maybe_stop()
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state) when is_reference(ref) do
    case Map.pop(state.in_flight, ref) do
      {nil, _in_flight} ->
        coordinator_down(state, ref)

      {request, in_flight} ->
        _ = Process.cancel_timer(request.timer)

        Logger.warning(
          "gateway method #{request.method} failed: #{inspect(reason, limit: 10)}",
          gateway_peer: describe_peer(state.peer)
        )

        %{state | in_flight: in_flight}
        |> respond(
          request.id,
          {:error, Methods.code(:upstream_error), "the handler for #{request.method} crashed",
           reason}
        )
        |> drain()
        |> maybe_stop()
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    # Order matters: the client's last frame goes out before anything slower is attempted,
    # and the socket closes whether or not the rest of this succeeds.
    if state.writer, do: Writer.flush(state.writer, @flush_timeout)
    release_subscriptions(state)
    _ = :gen_tcp.close(state.socket)
    :ok
  end

  defp socket_options(config) do
    [
      active: :once,
      packet: :line,
      packet_size: config.max_frame,
      buffer: config.max_frame,
      nodelay: true,
      send_timeout: @send_timeout,
      send_timeout_close: true
    ]
  end

  defp handle_frame(frame, state) do
    case strip_newline(frame) do
      {:ok, payload} ->
        decode(payload, state)

      :unterminated ->
        state =
          respond_error(
            state,
            nil,
            :parse_error,
            "a frame must be one JSON object terminated by a newline within " <>
              "#{state.config.max_frame} bytes (OUROBOROS_GATEWAY_MAX_FRAME)"
          )

        {:close, state}
    end
  end

  defp strip_newline(frame) do
    case frame do
      <<>> -> :unterminated
      _other -> strip_newline(frame, byte_size(frame))
    end
  end

  defp strip_newline(frame, size) do
    case :binary.at(frame, size - 1) do
      ?\n -> {:ok, strip_carriage_return(binary_part(frame, 0, size - 1))}
      _other -> :unterminated
    end
  end

  defp strip_carriage_return(<<>>), do: <<>>

  defp strip_carriage_return(payload) do
    size = byte_size(payload)

    case :binary.at(payload, size - 1) do
      ?\r -> binary_part(payload, 0, size - 1)
      _other -> payload
    end
  end

  defp decode(payload, state) do
    case JSON.decode(payload) do
      {:ok, request} when is_map(request) ->
        dispatch(request, state)

      {:ok, _other} ->
        {:continue,
         respond_error(state, nil, :invalid_request, "a request frame must be a JSON object")}

      {:error, _reason} ->
        {:continue, respond_error(state, nil, :parse_error, "the frame is not valid JSON")}
    end
  end

  defp dispatch(request, state) do
    id = Map.get(request, "id")
    method = Map.get(request, "method")

    cond do
      not valid_id?(id) ->
        {:continue,
         respond_error(
           state,
           nil,
           :invalid_request,
           "every request must carry a string or number id; this protocol has no " <>
             "client notifications"
         )}

      not is_binary(method) ->
        {:continue, respond_error(state, id, :invalid_request, "method must be a string")}

      true ->
        case params(request) do
          {:ok, params} ->
            route(method, id, params, state)

          :error ->
            {:continue, respond_error(state, id, :invalid_params, "params must be an object")}
        end
    end
  end

  defp valid_id?(id), do: is_binary(id) or is_integer(id) or is_float(id)

  defp params(request) do
    case Map.get(request, "params") do
      nil -> {:ok, %{}}
      params when is_map(params) -> {:ok, params}
      _other -> :error
    end
  end

  defp route("hello", id, params, %{authenticated?: false} = state), do: hello(id, params, state)

  defp route("hello", id, _params, state) do
    {:continue,
     respond_error(state, id, :invalid_request, "hello has already completed on this connection")}
  end

  defp route(_method, id, _params, %{authenticated?: false} = state) do
    {:close,
     respond_error(
       state,
       id,
       :unauthenticated,
       "every frame before a successful hello is refused"
     )}
  end

  defp route(method, id, params, state) do
    case Methods.fetch(method) do
      {:ok, entry} ->
        if Methods.permits?(state.config.scope, entry) do
          {:continue, invoke(method, id, params, entry, audit(state, method, params, entry))}
        else
          {:continue,
           respond_error(
             state,
             id,
             :scope_denied,
             "#{method} mutates the runtime and this listener was started with " <>
               "OUROBOROS_GATEWAY_SCOPE=read"
           )}
        end

      :error ->
        {:continue,
         respond_error(state, id, :method_not_found, "this build does not serve #{method}")}
    end
  end

  defp invoke(method, id, params, entry, state) do
    case Map.fetch(@conn_methods, method) do
      {:ok, {:subscribe, plane}} -> subscribe(state, plane, id, params)
      {:ok, {:unsubscribe, plane}} -> unsubscribe(state, plane, id, params)
      {:ok, {:shutdown, _plane}} -> shutdown(state, id)
      :error -> accept(state, id, method, params, entry)
    end
  end

  # Every operate call leaves exactly one line, and the line names the call rather than
  # its contents: an objective, a prompt, or a workspace path in a log is a payload the
  # operator did not choose to write down. The digest is enough to correlate a log entry
  # with the request a client can reproduce.
  defp audit(state, method, params, %{scope: :operate}) do
    Logger.info(
      "gateway operate #{method} params=#{params_digest(params)} peer=#{describe_peer(state.peer)}"
    )

    state
  end

  defp audit(state, _method, _params, _entry), do: state

  defp params_digest(params) do
    :sha256
    |> :crypto.hash(params |> Wire.to_json() |> JSON.encode_to_iodata!())
    |> Base.encode16(case: :lower)
    |> binary_part(0, 16)
  end

  defp hello(id, params, state) do
    with :ok <- authenticate(params, state.config),
         :ok <- check_protocol(params) do
      _ = Process.cancel_timer(state.hello_timer)

      state = %{
        state
        | authenticated?: true,
          hello_timer: nil,
          client: client_name(params)
      }

      Logger.info(
        "gateway connection authenticated at #{state.config.scope} scope",
        gateway_peer: describe_peer(state.peer),
        gateway_client: state.client
      )

      {:continue, respond(state, id, {:ok, hello_result(state)})}
    else
      :unauthenticated ->
        {:close,
         respond_error(
           state,
           id,
           :unauthenticated,
           "hello did not present the token this listener was started with"
         )}

      {:protocol_mismatch, presented} ->
        {:close,
         respond(
           state,
           id,
           {:error, Methods.code(:protocol_mismatch),
            "this gateway speaks protocol #{@protocol}, the client asked for " <>
              inspect(presented), %{"server_protocol" => @protocol}}
         )}
    end
  end

  defp authenticate(params, config) do
    with token when is_binary(token) <- Map.get(params, "token"),
         true <-
           :crypto.hash_equals(
             :crypto.hash(:sha256, token),
             :crypto.hash(:sha256, config.token)
           ) do
      :ok
    else
      _refused -> :unauthenticated
    end
  end

  defp check_protocol(params) do
    case Map.get(params, "protocol") do
      @protocol -> :ok
      other -> {:protocol_mismatch, other}
    end
  end

  defp client_name(params) do
    case Map.get(params, "client") do
      client when is_binary(client) -> String.slice(client, 0, 120)
      _other -> nil
    end
  end

  defp hello_result(state) do
    %{
      "server" => server_version(),
      "node" => Atom.to_string(node()),
      "role" => Atom.to_string(Cluster.role()),
      "protocol" => @protocol,
      "scope" => Atom.to_string(state.config.scope),
      "methods" => Methods.names()
    }
  end

  defp server_version do
    case Application.spec(:ouroboros, :vsn) do
      nil -> "unknown"
      vsn -> List.to_string(vsn)
    end
  end

  defp subscribe(state, plane, rpc_id, params) do
    case Methods.subscription_params(params) do
      {:ok, session_id, cursor} ->
        key = {plane, session_id}

        if map_size(state.subscriptions) >= @max_subscriptions and
             not Map.has_key?(state.subscriptions, key) do
          respond_error(
            state,
            rpc_id,
            :unavailable,
            "this connection already watches #{@max_subscriptions} sessions; unsubscribe " <>
              "from one before subscribing to another"
          )
        else
          open_subscription(state, key, rpc_id, cursor)
        end

      {:invalid, message} ->
        respond_error(state, rpc_id, :invalid_params, message)
    end
  end

  defp open_subscription(state, {plane, session_id} = key, rpc_id, cursor) do
    case Methods.subscribe(plane, session_id, cursor) do
      {:ok, backlog} ->
        # Registration completed inside the plane before this returned, so any event it
        # has already sent is sitting in this process's mailbox behind the frame being
        # answered here — the backlog and the live stream cannot interleave or gap.
        state = state |> forget_subscription(key) |> respond(rpc_id, {:ok, backlog})

        case Methods.session(plane, session_id) do
          {:ok, _status, false} -> watch(state, key)
          {:ok, status, true} -> stream_ended(state, key, Atom.to_string(status))
          :error -> stream_ended(state, key, "unknown")
        end

      error ->
        respond(state, rpc_id, error)
    end
  end

  defp watch(state, {plane, session_id} = key) do
    case Methods.coordinator(plane, session_id) do
      pid when is_pid(pid) ->
        ref = Process.monitor(pid)

        %{
          state
          | subscriptions:
              Map.put(state.subscriptions, key, %{ref: ref, dropped: 0, last_sequence: 0}),
            coordinators: Map.put(state.coordinators, ref, key)
        }

      nil ->
        # The coordinator retired between answering the subscribe and this lookup. The
        # registration went with it, so the stream is over before it started.
        stream_ended(state, key, "unknown")
    end
  end

  defp unsubscribe(state, plane, rpc_id, params) do
    case Methods.session_param(params) do
      {:ok, session_id} ->
        key = {plane, session_id}

        if Map.has_key?(state.subscriptions, key) do
          _ = Methods.unsubscribe(plane, session_id)
          state |> forget_subscription(key) |> respond(rpc_id, {:ok, :ok})
        else
          # Answered without calling the plane on purpose: `unsubscribe` would *start* a
          # coordinator for a session this connection never watched, and a verb that
          # spawns the thing it was asked to stop listening to is not a read verb.
          respond(state, rpc_id, {:ok, :ok})
        end

      {:invalid, message} ->
        respond_error(state, rpc_id, :invalid_params, message)
    end
  end

  defp shutdown(state, rpc_id) do
    if state.config.allow_shutdown do
      Logger.warning(
        "gateway accepted runtime.shutdown from #{describe_peer(state.peer)}; this node is stopping"
      )

      state = respond(state, rpc_id, {:ok, %{"stopping" => true, "node" => node()}})
      %{state | shutdown?: true}
    else
      respond_error(
        state,
        rpc_id,
        :scope_denied,
        "runtime.shutdown stops this node, so it needs one permission more than " <>
          "operate scope: OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1 on the daemon"
      )
    end
  end

  defp coordinator_down(state, ref) do
    case Map.pop(state.coordinators, ref) do
      {nil, _coordinators} ->
        {:noreply, state}

      {key, _coordinators} ->
        # The registration lived in that process. Whether it retired after a terminal
        # session or crashed and was restarted without us, no further event is coming, and
        # a client that is told so resubscribes instead of waiting.
        state |> stream_ended(key, "unknown") |> maybe_stop()
    end
  end

  defp stream_ended(state, {plane, session_id} = key, status) do
    state
    |> flush_lag(key)
    |> forget_subscription(key)
    |> enqueue(
      notification_frame("stream.ended", %{
        "id" => session_id,
        "plane" => Atom.to_string(plane),
        "status" => status
      })
    )
  end

  defp forget_subscription(state, key) do
    case Map.pop(state.subscriptions, key) do
      {nil, _subscriptions} ->
        state

      {%{ref: ref}, subscriptions} ->
        Process.demonitor(ref, [:flush])

        %{
          state
          | subscriptions: subscriptions,
            coordinators: Map.delete(state.coordinators, ref)
        }
    end
  end

  defp release_subscriptions(state) do
    deadline = System.monotonic_time(:millisecond) + @unsubscribe_budget_ms

    Enum.each(state.subscriptions, fn {{plane, session_id}, _ref} ->
      if System.monotonic_time(:millisecond) < deadline do
        _ = Methods.unsubscribe(plane, session_id)
      end
    end)
  end

  defp stream_event(state, key, method, session_id, event) do
    cond do
      not Map.has_key?(state.subscriptions, key) ->
        # An event that crossed an unsubscribe. The plane stopped sending after it, and a
        # notification for a stream the client closed would misdescribe what it watches.
        state

      state.outbound >= state.config.queue_limit ->
        lag(state, key, event.sequence)

      true ->
        enqueue_event(
          state,
          notification_frame(method, %{"id" => session_id, "event" => event})
        )
    end
  end

  defp lag(state, key, sequence) do
    case Map.get(state.subscriptions, key) do
      nil ->
        state

      sub ->
        updated = %{
          sub
          | dropped: sub.dropped + 1,
            last_sequence: max(sub.last_sequence, sequence)
        }

        %{state | subscriptions: Map.put(state.subscriptions, key, updated)}
    end
  end

  # One notification per lagged session, once the queue is genuinely drained rather than
  # merely under the limit — otherwise the notification itself arrives in the middle of the
  # congestion it is reporting and is dropped or repeated.
  defp flush_lagged(state) do
    if state.outbound < low_water(state) do
      state.subscriptions
      |> Enum.filter(fn {_key, sub} -> sub.dropped > 0 end)
      |> Enum.reduce(state, fn {key, _sub}, acc -> flush_lag(acc, key) end)
    else
      state
    end
  end

  defp flush_lag(state, key) do
    case Map.get(state.subscriptions, key) do
      %{dropped: dropped, last_sequence: last_sequence} = sub when dropped > 0 ->
        {plane, session_id} = key

        %{
          state
          | subscriptions:
              Map.put(state.subscriptions, key, %{sub | dropped: 0, last_sequence: 0})
        }
        |> enqueue(
          notification_frame("stream.lagged", %{
            "id" => session_id,
            "plane" => Atom.to_string(plane),
            "dropped" => dropped,
            "last_sequence" => last_sequence
          })
        )

      _other ->
        state
    end
  end

  defp low_water(state), do: max(div(state.config.queue_limit, 2), 1)

  defp accept(state, id, method, params, entry) do
    request = {id, method, params, entry}

    cond do
      map_size(state.in_flight) < @max_in_flight ->
        start_request(state, request)

      state.pending_len >= @max_pending ->
        respond_error(
          state,
          id,
          :unavailable,
          "this connection already has #{state.pending_len} requests waiting; read your " <>
            "responses before sending more"
        )

      true ->
        %{state | pending: :queue.in(request, state.pending), pending_len: state.pending_len + 1}
    end
  end

  defp start_request(state, {id, method, params, entry}) do
    task =
      Task.Supervisor.async_nolink(state.task_supervisor, fn ->
        Methods.invoke(method, params)
      end)

    timer = Process.send_after(self(), {:request_timeout, task.ref}, entry.timeout)

    in_flight =
      Map.put(state.in_flight, task.ref, %{
        id: id,
        method: method,
        pid: task.pid,
        timer: timer,
        timeout: entry.timeout,
        outcome: Map.get(entry, :outcome)
      })

    %{state | in_flight: in_flight}
  end

  defp drain(state) do
    if map_size(state.in_flight) < @max_in_flight do
      case :queue.out(state.pending) do
        {{:value, request}, pending} ->
          %{state | pending: pending, pending_len: state.pending_len - 1}
          |> start_request(request)
          |> drain()

        {:empty, _pending} ->
          state
      end
    else
      state
    end
  end

  defp timeout_result(%{outcome: :unknown} = request) do
    {:error, Methods.code(:upstream_timeout), timeout_message(request), %{"outcome" => "unknown"}}
  end

  defp timeout_result(request) do
    {:error, Methods.code(:upstream_timeout), timeout_message(request)}
  end

  defp timeout_message(request) do
    "#{request.method} exceeded the gateway ceiling of #{request.timeout}ms; the " <>
      "runtime may still be working on it"
  end

  defp respond(state, id, {:ok, value}), do: enqueue(state, result_frame(id, value))

  defp respond(state, id, {:error, code, message}),
    do: enqueue(state, error_frame(id, code, message))

  defp respond(state, id, {:error, code, message, data}),
    do: enqueue(state, error_frame(id, code, message, data))

  # A handler that answers something the contract does not describe is a bug in this
  # build, not in the client, and it is reported as one rather than crashing the socket.
  defp respond(state, id, other) do
    Logger.error("gateway handler returned an unrecognized result: #{inspect(other, limit: 10)}")

    respond(
      state,
      id,
      {:error, Methods.code(:upstream_error), "the handler returned an unrecognized result"}
    )
  end

  defp respond_error(state, id, name, message),
    do: respond(state, id, {:error, Methods.code(name), message})

  # Responses and the two stream control notifications. Never dropped: above the hard cap
  # the connection ends rather than lies about having answered.
  defp enqueue(state, envelope) do
    if state.outbound >= state.config.queue_limit + @response_headroom do
      overloaded(state)
    else
      write(state, encode(envelope))
    end
  end

  # Session events, and the only frames this gateway will discard. The client's cursor is
  # what makes that safe: it replays what it missed after `stream.lagged`.
  defp enqueue_event(state, envelope), do: write(state, encode(envelope))

  defp encode(envelope) do
    Wire.frame!(envelope)
  rescue
    error ->
      # Encoding is the last place a payload can surprise this process. Answering with a
      # frame the client can parse beats dropping the response and leaving it waiting.
      Logger.error("gateway could not encode a frame: #{Exception.message(error)}")

      Wire.frame!(
        error_frame(
          Map.get(envelope, "id"),
          Methods.code(:upstream_error),
          "the response could not be encoded"
        )
      )
  end

  defp write(%{writer: nil} = state, _frame), do: %{state | closing?: true}

  defp write(state, frame) do
    :ok = Writer.write(state.writer, frame)
    %{state | outbound: state.outbound + 1}
  end

  defp overloaded(state) do
    Logger.warning(
      "gateway closing a connection with #{state.outbound} unwritten frames " <>
        "(OUROBOROS_GATEWAY_QUEUE_LIMIT=#{state.config.queue_limit}): the peer is not " <>
        "reading its responses",
      gateway_peer: describe_peer(state.peer)
    )

    state
    |> write(
      encode(
        error_frame(
          nil,
          Methods.code(:unavailable),
          "this connection is #{state.outbound} frames behind and is being closed; " <>
            "reconnect and resubscribe"
        )
      )
    )
    |> Map.put(:closing?, true)
  end

  defp maybe_stop(%{closing?: true} = state), do: {:stop, :normal, state}

  defp maybe_stop(%{shutdown?: true} = state) do
    # The client asked for this and is owed the acknowledgement before the node it is
    # attached to goes away, so the stop happens after the frame is on the wire. It is
    # asynchronous by nature: `System.stop/0` returns and the VM shuts down behind it.
    _ = Writer.flush(state.writer, @flush_timeout)
    stop_node()
    {:noreply, %{state | shutdown?: false}}
  end

  defp maybe_stop(state), do: {:noreply, state}

  # Indirected only so the suite can prove the acknowledgement is written before the node
  # stops without stopping the node running the suite. Nothing sets this in production.
  defp stop_node do
    {module, function, arguments} =
      Application.get_env(:ouroboros, :gateway_stop_mfa, {System, :stop, []})

    apply(module, function, arguments)
  end

  defp describe_peer(nil), do: "unknown"

  defp describe_peer({address, port}) do
    "#{address |> :inet.ntoa() |> List.to_string()}:#{port}"
  end
end
