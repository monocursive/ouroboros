defmodule Ouroboros.Gateway.Conn do
  @moduledoc """
  One client connection: framing, the handshake, and bounded dispatch.

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
  in `Ouroboros.Gateway.Methods`. At most 8 run at once per connection; the rest wait in
  a queue bounded by `OUROBOROS_GATEWAY_QUEUE_LIMIT`, past which further requests are
  answered `-32004` rather than accumulating. Responses correlate by `id` and are written
  in completion order, so a slow `runtime.providers` never delays a fast `agents.list`
  behind it.

  A request that outlives its ceiling is killed and answered `-32005`. That answer is
  honest about the gateway and silent about the plane: killing the task does not cancel
  work already in flight upstream, and for the `:infinity` verbs Slice 2 adds it
  provably cannot.

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
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Wire

  @protocol 1
  @max_in_flight 8
  @send_timeout 15_000

  # Read from the method table rather than restated here, because `hello`'s entry is what
  # a client is told the deadline is. One number, in the place a client can see it.
  @hello_timeout Methods.table() |> Map.fetch!("hello") |> Map.fetch!(:timeout)

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
      # The socket is written from this process only, so a failed write is observed here
      # and turned into a closed connection rather than a silently dropped response.
      send_failed?: false,
      in_flight: %{},
      pending: :queue.new(),
      pending_len: 0,
      # Slice 2 keeps live session subscriptions here. It is declared now so that adding
      # them does not move where connection state lives.
      subscriptions: %{},
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

    case :inet.setopts(state.socket, socket_options(state.config)) do
      :ok -> {:noreply, %{state | peer: peer}}
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

  def handle_info({:request_timeout, ref}, state) when is_reference(ref) do
    case Map.pop(state.in_flight, ref) do
      {nil, _in_flight} ->
        {:noreply, state}

      {request, in_flight} ->
        Process.demonitor(ref, [:flush])
        _ = Task.Supervisor.terminate_child(state.task_supervisor, request.pid)

        %{state | in_flight: in_flight}
        |> respond_error(request.id, :upstream_timeout, timeout_message(request))
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
        {:noreply, state}

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
           Wire.to_json(reason)}
        )
        |> drain()
        |> maybe_stop()
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
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
          {:continue, accept(state, id, method, params, entry.timeout)}
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

  defp accept(state, id, method, params, timeout) do
    request = {id, method, params, timeout}

    cond do
      map_size(state.in_flight) < @max_in_flight ->
        start_request(state, request)

      state.pending_len >= state.config.queue_limit ->
        respond_error(
          state,
          id,
          :unavailable,
          "this connection already has #{state.pending_len} requests waiting " <>
            "(OUROBOROS_GATEWAY_QUEUE_LIMIT); read your responses before sending more"
        )

      true ->
        %{state | pending: :queue.in(request, state.pending), pending_len: state.pending_len + 1}
    end
  end

  defp start_request(state, {id, method, params, timeout}) do
    task =
      Task.Supervisor.async_nolink(state.task_supervisor, fn ->
        Methods.invoke(method, params)
      end)

    timer = Process.send_after(self(), {:request_timeout, task.ref}, timeout)

    in_flight =
      Map.put(state.in_flight, task.ref, %{
        id: id,
        method: method,
        pid: task.pid,
        timer: timer,
        timeout: timeout
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

  defp timeout_message(request) do
    "#{request.method} exceeded the gateway ceiling of #{request.timeout}ms; the " <>
      "runtime may still be working on it"
  end

  defp respond(state, id, {:ok, value}) do
    send_frame(state, %{"jsonrpc" => "2.0", "id" => id, "result" => Wire.to_json(value)})
  end

  defp respond(state, id, {:error, code, message}) do
    send_frame(state, %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => code, "message" => message}
    })
  end

  defp respond(state, id, {:error, code, message, data}) do
    send_frame(state, %{
      "jsonrpc" => "2.0",
      "id" => id,
      "error" => %{"code" => code, "message" => message, "data" => data}
    })
  end

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

  defp send_frame(state, envelope) do
    case :gen_tcp.send(state.socket, Wire.frame!(envelope)) do
      :ok -> state
      {:error, _reason} -> %{state | send_failed?: true}
    end
  rescue
    error ->
      # Encoding is the last place a payload can surprise this process. Answering with a
      # frame the client can parse beats dropping the response and leaving it waiting.
      Logger.error("gateway could not encode a response: #{Exception.message(error)}")

      _ =
        :gen_tcp.send(
          state.socket,
          Wire.frame!(%{
            "jsonrpc" => "2.0",
            "id" => Map.get(envelope, "id"),
            "error" => %{
              "code" => Methods.code(:upstream_error),
              "message" => "the response could not be encoded"
            }
          })
        )

      state
  end

  defp maybe_stop(%{send_failed?: true} = state), do: {:stop, :normal, state}
  defp maybe_stop(state), do: {:noreply, state}

  defp describe_peer(nil), do: "unknown"

  defp describe_peer({address, port}) do
    "#{address |> :inet.ntoa() |> List.to_string()}:#{port}"
  end
end
