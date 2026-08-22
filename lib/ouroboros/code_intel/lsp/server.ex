defmodule Ouroboros.CodeIntel.Lsp.Server do
  @moduledoc """
  Owns exactly one language-server OS process and the JSON-RPC conversation with it.

  The child is spawned through `priv/provider-exec`, the same wrapper every provider CLI
  crosses: it resets the umask to the conventional workspace `022` and then `exec`s the
  real executable, so the language server runs as the user, in the workspace root, with
  the permissions an operator's own editor would produce. There is no interpolated
  command string — the executable and every argument stay positional.

  Nothing here is unbounded. Every request carries a deadline and answers `{:error,
  :timeout}` when it expires rather than waiting; `initialize` gets its own, larger
  deadline because ElixirLS, jdtls and Metals compile or index on first launch; the
  in-flight request table is capped and answers `{:error, :busy}` past the cap;
  notifications this client does not serve are dropped and counted rather than queued;
  and `shutdown`/`exit` are followed by a bounded grace and then `SIGKILL`.

  Server-initiated requests are answered minimally — a language server that asks for a
  progress token, a capability registration, or its configuration and never hears back
  will stall, so the ones that matter get sensible defaults and everything else gets a
  `MethodNotFound` error instead of silence.

  This process holds no durable state and checkpoints nothing. A language server is
  ephemeral by design: if it dies, the pool respawns it and the documents are re-opened
  from disk.
  """

  use GenServer

  require Logger

  alias Ouroboros.CodeIntel.Codec
  alias Ouroboros.CodeIntel.Config

  @method_not_found -32_601

  @typedoc "Everything the pool needs to describe one server in `status/0`."
  @type info :: %{
          state: :initializing | :ready | :stopping,
          os_pid: pos_integer() | nil,
          pending: non_neg_integer(),
          dropped: non_neg_integer(),
          server_info: map() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Issues a request and waits at most `timeout_ms` for the answer.

  Never raises and never exits the caller: a dead server, a full request table, and a
  server that simply does not answer are all error tuples.
  """
  @spec request(GenServer.server(), String.t(), term(), pos_integer()) ::
          {:ok, term()} | {:error, term()}
  def request(server, method, params, timeout_ms) do
    GenServer.call(server, {:request, method, params, timeout_ms}, timeout_ms + 1_000)
  catch
    :exit, reason -> {:error, {:server_unavailable, reason}}
  end

  @doc "Sends a notification. Fire-and-forget by protocol definition."
  @spec notify(GenServer.server(), String.t(), term()) :: :ok
  def notify(server, method, params), do: GenServer.cast(server, {:notify, method, params})

  @doc "Begins the bounded graceful shutdown. The process stops on its own afterwards."
  @spec stop(GenServer.server()) :: :ok
  def stop(server), do: GenServer.cast(server, :begin_shutdown)

  @spec info(GenServer.server()) :: {:ok, info()} | {:error, term()}
  def info(server) do
    GenServer.call(server, :info, 5_000)
  catch
    :exit, reason -> {:error, {:server_unavailable, reason}}
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    state = %{
      owner: Keyword.fetch!(opts, :owner),
      key: Keyword.fetch!(opts, :key),
      root: Keyword.fetch!(opts, :root),
      server_id: Keyword.fetch!(opts, :server_id),
      executable: Keyword.fetch!(opts, :executable),
      args: Keyword.get(opts, :args, []),
      env: Keyword.get(opts, :env, []),
      initialization_options: Keyword.get(opts, :initialization_options),
      max_frame_bytes: Keyword.get(opts, :max_frame_bytes, Config.get(:max_frame_bytes)),
      max_pending: Keyword.get(opts, :max_pending_requests, Config.get(:max_pending_requests)),
      initialize_timeout_ms:
        Keyword.get(opts, :initialize_timeout_ms, Config.get(:initialize_timeout_ms)),
      shutdown_grace_ms: Keyword.get(opts, :shutdown_grace_ms, Config.get(:shutdown_grace_ms)),
      port: nil,
      os_pid: nil,
      buffer: <<>>,
      next_id: 1,
      pending: %{},
      outbox: [],
      phase: :initializing,
      server_info: nil,
      capabilities: %{},
      dropped: 0,
      initialize_id: nil
    }

    case open_port(state) do
      {:ok, state} -> {:ok, state, {:continue, :initialize}}
      {:error, reason} -> {:stop, {:spawn_failed, reason}}
    end
  end

  @impl true
  def handle_continue(:initialize, state) do
    {id, state} = take_id(state)
    Process.send_after(self(), {:deadline, id}, state.initialize_timeout_ms)

    state = %{
      state
      | initialize_id: id,
        pending: Map.put(state.pending, id, %{from: nil, method: "initialize"})
    }

    case write(state, Codec.request(id, "initialize", initialize_params(state))) do
      :ok -> {:noreply, state}
      {:error, reason} -> {:stop, {:transport_closed, reason}, state}
    end
  end

  @impl true
  def handle_call({:request, _method, _params, _timeout}, _from, %{phase: :stopping} = state),
    do: {:reply, {:error, :shutting_down}, state}

  def handle_call({:request, method, params, timeout_ms}, from, state) do
    if map_size(state.pending) >= state.max_pending do
      {:reply, {:error, :busy}, state}
    else
      dispatch_request(method, params, timeout_ms, from, state)
    end
  end

  def handle_call(:info, _from, state) do
    {:reply,
     {:ok,
      %{
        state: state.phase,
        os_pid: state.os_pid,
        pending: map_size(state.pending),
        dropped: state.dropped,
        server_info: state.server_info
      }}, state}
  end

  @impl true
  def handle_cast({:notify, _method, _params}, %{phase: :stopping} = state),
    do: {:noreply, state}

  def handle_cast({:notify, method, params}, state) do
    frame = Codec.notification(method, params)

    if state.phase == :ready do
      case write(state, frame) do
        :ok -> {:noreply, state}
        {:error, reason} -> {:stop, {:transport_closed, reason}, state}
      end
    else
      {:noreply, %{state | outbox: [frame | state.outbox]}}
    end
  end

  def handle_cast(:begin_shutdown, %{phase: :stopping} = state), do: {:noreply, state}

  def handle_cast(:begin_shutdown, state) do
    state = fail_pending(state, :shutting_down)
    {id, state} = take_id(state)
    state = %{state | phase: :stopping}

    _ = write(state, Codec.request(id, "shutdown", nil))
    Process.send_after(self(), :shutdown_grace_expired, state.shutdown_grace_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    case Codec.decode(state.buffer <> data, state.max_frame_bytes) do
      {:ok, frames, rest} ->
        Enum.reduce_while(frames, {:noreply, %{state | buffer: rest}}, fn
          frame, {:noreply, acc} -> {:cont, handle_frame(frame, acc)}
          _frame, halted -> {:halt, halted}
        end)

      {:error, reason} ->
        {:stop, {:protocol_error, reason}, state}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    state = %{state | port: nil, os_pid: nil}

    if state.phase == :stopping do
      {:stop, :normal, state}
    else
      {:stop, {:server_exited, status}, fail_pending(state, {:server_exited, status})}
    end
  end

  def handle_info({:deadline, id}, state) do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        {:noreply, state}

      {%{from: nil}, pending} when id == state.initialize_id ->
        {:stop, :initialize_timeout, %{state | pending: pending}}

      {%{from: from}, pending} ->
        if from, do: GenServer.reply(from, {:error, :timeout})
        {:noreply, %{state | pending: pending}}
    end
  end

  def handle_info(:shutdown_grace_expired, state) do
    {:stop, :normal, state}
  end

  # The pool owns this process and is monitoring it; an exit from anywhere else is the
  # supervisor taking the tree down.
  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, %{state | dropped: state.dropped + 1}}

  @impl true
  def terminate(_reason, state) do
    kill(state)
    :ok
  end

  ## Frames

  # A frame naming a method is something the server asks of this client, whether or not
  # it also carries an id. Routing on the id first reads every such request as a
  # response, which completes the wrong caller or tears down the transport.
  defp handle_frame(%{"method" => method} = frame, state) when is_map_key(frame, "id") do
    {:noreply, serve(method, frame["id"], frame["params"], state)}
  end

  defp handle_frame(%{"method" => method} = frame, state) do
    {:noreply, observe(method, frame["params"], state)}
  end

  defp handle_frame(%{"id" => id} = frame, state) do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        # A late answer to a request whose deadline already expired. The caller has its
        # error; counting the frame is all that is owed.
        {:noreply, %{state | dropped: state.dropped + 1}}

      {%{from: from}, pending} ->
        state = %{state | pending: pending}
        answer = frame_result(frame)

        cond do
          id == state.initialize_id ->
            complete_initialize(answer, state)

          from == nil ->
            {:noreply, state}

          true ->
            GenServer.reply(from, answer)
            {:noreply, state}
        end
    end
  end

  defp handle_frame(_frame, state), do: {:noreply, %{state | dropped: state.dropped + 1}}

  defp frame_result(%{"error" => %{} = error}),
    do: {:error, {:lsp_error, error["code"], error["message"]}}

  defp frame_result(%{"result" => result}), do: {:ok, result}
  defp frame_result(_frame), do: {:ok, nil}

  defp complete_initialize({:ok, result}, state) do
    result = if is_map(result), do: result, else: %{}

    state = %{
      state
      | phase: :ready,
        initialize_id: nil,
        server_info: result["serverInfo"],
        capabilities: Map.get(result, "capabilities") || %{}
    }

    frames = [Codec.notification("initialized", %{}) | Enum.reverse(state.outbox)]

    case write(state, frames) do
      :ok -> {:noreply, %{state | outbox: []}}
      {:error, reason} -> {:stop, {:transport_closed, reason}, state}
    end
  end

  defp complete_initialize({:error, reason}, state),
    do: {:stop, {:initialize_refused, reason}, state}

  # Minimal but real answers. A server that asks for a progress token or a configuration
  # block and never hears back stalls, and a stalled server is indistinguishable from a
  # broken one.
  defp serve("window/workDoneProgress/create", id, _params, state),
    do: reply_frame(state, Codec.response(id, nil))

  defp serve("client/registerCapability", id, _params, state),
    do: reply_frame(state, Codec.response(id, nil))

  defp serve("client/unregisterCapability", id, _params, state),
    do: reply_frame(state, Codec.response(id, nil))

  defp serve("workspace/configuration", id, params, state) do
    items =
      case params do
        %{"items" => items} when is_list(items) -> items
        _other -> []
      end

    reply_frame(state, Codec.response(id, Enum.map(items, fn _item -> %{} end)))
  end

  defp serve("workspace/workspaceFolders", id, _params, state) do
    folder = %{"uri" => uri(state.root), "name" => Path.basename(state.root)}
    reply_frame(state, Codec.response(id, [folder]))
  end

  defp serve("window/showMessageRequest", id, _params, state),
    do: reply_frame(state, Codec.response(id, nil))

  defp serve("workspace/applyEdit", id, _params, state) do
    # This client never applies a server-driven workspace edit. Saying so is the honest
    # answer; silently accepting would claim an edit was made that was not.
    reply_frame(state, Codec.response(id, %{"applied" => false}))
  end

  defp serve(method, id, _params, state) do
    reply_frame(
      state,
      Codec.error_response(id, @method_not_found, "ouroboros does not serve #{method}")
    )
  end

  defp reply_frame(state, frame) do
    case write(state, frame) do
      :ok -> state
      {:error, _reason} -> %{state | dropped: state.dropped + 1}
    end
  end

  defp observe("textDocument/publishDiagnostics", params, state) when is_map(params) do
    send(state.owner, {:code_intel_lsp, state.key, {:diagnostics, params}})
    state
  end

  defp observe("window/logMessage", params, state) do
    Logger.debug(fn -> "#{state.server_id}: #{inspect(params)}" end)
    %{state | dropped: state.dropped + 1}
  end

  defp observe(_method, _params, state), do: %{state | dropped: state.dropped + 1}

  ## Requests

  defp dispatch_request(method, params, timeout_ms, from, state) do
    {id, state} = take_id(state)
    Process.send_after(self(), {:deadline, id}, timeout_ms)
    state = %{state | pending: Map.put(state.pending, id, %{from: from, method: method})}
    frame = Codec.request(id, method, params)

    if state.phase == :ready do
      case write(state, frame) do
        :ok -> {:noreply, state}
        {:error, reason} -> {:stop, {:transport_closed, reason}, state}
      end
    else
      {:noreply, %{state | outbox: [frame | state.outbox]}}
    end
  end

  defp fail_pending(state, reason) do
    Enum.each(state.pending, fn
      {_id, %{from: nil}} -> :ok
      {_id, %{from: from}} -> GenServer.reply(from, {:error, reason})
    end)

    %{state | pending: %{}}
  end

  defp take_id(state), do: {state.next_id, %{state | next_id: state.next_id + 1}}

  ## Transport

  defp open_port(state) do
    with {:ok, wrapper} <- wrapper_executable() do
      port =
        Port.open(
          {:spawn_executable, String.to_charlist(wrapper)},
          [
            :binary,
            :exit_status,
            :use_stdio,
            :hide,
            {:args, Enum.map([state.executable | state.args], &String.to_charlist/1)},
            {:cd, String.to_charlist(state.root)},
            {:env, Enum.map(state.env, fn {k, v} -> {to_charlist(k), to_charlist(v)} end)}
          ]
        )

      os_pid =
        case Port.info(port, :os_pid) do
          {:os_pid, pid} -> pid
          _absent -> nil
        end

      {:ok, %{state | port: port, os_pid: os_pid}}
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  # The same wrapper every provider child crosses. Reusing it keeps one answer to "what
  # umask does a program this runtime spawns into a workspace run with".
  defp wrapper_executable do
    with directory when is_list(directory) <- :code.priv_dir(:ouroboros),
         path = directory |> List.to_string() |> Path.join("provider-exec"),
         {:ok, %File.Stat{type: :regular, mode: mode}} <- File.lstat(path),
         true <- Bitwise.band(mode, 0o111) != 0 do
      {:ok, path}
    else
      failure -> {:error, {:workspace_wrapper_unavailable, failure}}
    end
  end

  # `Port.command/2` answers `true` or raises, and it raises exactly when the port is
  # already gone — the child died between two frames.
  defp write(%{port: nil}, _frames), do: {:error, :closed}

  defp write(state, frames) do
    Port.command(state.port, frames)
    :ok
  rescue
    ArgumentError -> {:error, :closed}
  end

  defp kill(%{port: port, os_pid: os_pid}) do
    if is_port(port) do
      try do
        Port.close(port)
      rescue
        ArgumentError -> :ok
      end
    end

    # Closing the port closes the pipes; it does not reap the child. A server that does
    # not exit on stdin EOF would otherwise outlive this runtime.
    if is_integer(os_pid) and os_pid > 0 do
      case System.find_executable("kill") do
        nil ->
          :ok

        executable ->
          System.cmd(executable, ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)
      end
    end

    :ok
  rescue
    _error -> :ok
  end

  ## Protocol payloads

  defp initialize_params(state) do
    root_uri = uri(state.root)

    %{
      "processId" => os_pid(),
      "clientInfo" => Config.client_info(),
      "locale" => "en",
      "rootPath" => state.root,
      "rootUri" => root_uri,
      "workspaceFolders" => [%{"uri" => root_uri, "name" => Path.basename(state.root)}],
      "initializationOptions" => state.initialization_options,
      "trace" => "off",
      "capabilities" => capabilities()
    }
  end

  # Exactly what the pool uses and nothing else. Declaring a capability this client does
  # not consume invites a server to spend memory producing it.
  defp capabilities do
    %{
      "general" => %{"positionEncodings" => ["utf-16"]},
      "window" => %{"workDoneProgress" => true},
      "workspace" => %{
        "workspaceFolders" => true,
        "configuration" => true,
        "didChangeConfiguration" => %{"dynamicRegistration" => false},
        "symbol" => %{"dynamicRegistration" => false}
      },
      "textDocument" => %{
        "synchronization" => %{
          "dynamicRegistration" => false,
          "willSave" => false,
          "willSaveWaitUntil" => false,
          "didSave" => false
        },
        "publishDiagnostics" => %{
          "relatedInformation" => true,
          "versionSupport" => true,
          "codeDescriptionSupport" => true,
          "tagSupport" => %{"valueSet" => [1, 2]}
        },
        "definition" => %{"dynamicRegistration" => false, "linkSupport" => true},
        "implementation" => %{"dynamicRegistration" => false, "linkSupport" => true},
        "references" => %{"dynamicRegistration" => false},
        "hover" => %{
          "dynamicRegistration" => false,
          "contentFormat" => ["markdown", "plaintext"]
        },
        "documentSymbol" => %{
          "dynamicRegistration" => false,
          "hierarchicalDocumentSymbolSupport" => true
        },
        "callHierarchy" => %{"dynamicRegistration" => false}
      }
    }
  end

  defp os_pid do
    case Integer.parse(System.pid()) do
      {pid, _rest} -> pid
      :error -> nil
    end
  end

  @doc false
  @spec uri(String.t()) :: String.t()
  def uri("/" <> _rest = path) do
    "file://" <> (path |> String.split("/") |> Enum.map_join("/", &encode_segment/1))
  end

  def uri(path), do: "file://" <> path

  defp encode_segment(segment), do: URI.encode(segment, &URI.char_unreserved?/1)
end
