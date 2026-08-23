defmodule Ouroboros.Provider.Native.Mcp.Server do
  @moduledoc """
  Owns exactly one MCP server's OS process and the JSON-RPC conversation with it.

  The child is spawned through `priv/provider-exec`, the same wrapper every provider CLI
  and every language server crosses: it resets the umask to the conventional workspace
  `022` and then `exec`s the declared command, so an MCP server runs as the user with
  the permissions an operator's own editor would produce. There is no interpolated
  command string — the executable and every argument stay positional, which is why an
  argument containing a shell metacharacter is a string here and not a sentence.

  ## The handshake, and its single deadline

  `initialize` → `notifications/initialized` → `tools/list` (following `nextCursor`
  until the server stops paginating) is one budget, `handshake_timeout_ms`, not three.
  A server that answers `initialize` in fourteen seconds and then paginates forever is
  exactly as broken as one that never answers at all, and a per-step deadline would let
  it through. When the budget expires this process stops with `:handshake_timeout` and
  the pool counts a restart. Nothing waits on it: **a server that never answers
  `initialize` is broken, not waited on.**

  ## Bounds

  Every request carries its own deadline and answers `{:error, :timeout}` rather than
  waiting. The in-flight table is capped and answers `{:error, :busy}` past the cap. A
  tool list is capped per server and its pagination is capped in pages, so a server
  returning a `nextCursor` forever terminates. One frame is capped in bytes. Lines the
  server writes to stdout that are not JSON are counted, and past the noise bound the
  transport is treated as broken rather than as a log to buffer.

  ## What this client declares

  No `sampling`, no `roots`, no `elicitation`. Declaring a capability we do not serve
  invites a server to ask for something we then cannot answer, and an MCP server that
  asks and is never answered stalls. Every server-initiated request therefore gets a
  `MethodNotFound` immediately, which is a legal answer and one every server handles.

  This process holds no durable state and checkpoints nothing. If it dies the pool
  respawns it and the tool list is fetched again.
  """

  use GenServer

  require Logger

  alias Ouroboros.Provider.Native.Mcp.Codec
  alias Ouroboros.Provider.Native.Mcp.Config
  alias Ouroboros.Provider.Native.Mcp.Servers

  # The revision `tui/src/mcp_serve.rs` speaks on the serving side of this same runtime.
  # Sending ours and accepting whatever the server answers is what the spec's
  # backward-compatibility rules are for; insisting on a match would fail negotiation
  # against every older server instead of talking to it.
  @protocol_version "2026-07-28"

  @method_not_found -32_601

  @typedoc "One tool as the server advertises it, after this module's bounds."
  @type tool :: %{name: String.t(), description: String.t(), input_schema: map()}

  @typedoc "Everything the pool needs to describe one server."
  @type info :: %{
          phase: :handshaking | :ready | :stopping,
          os_pid: pos_integer() | nil,
          pending: non_neg_integer(),
          noise: non_neg_integer(),
          tool_count: non_neg_integer(),
          server_info: map() | nil,
          protocol_version: String.t() | nil
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Issues one request and waits at most `timeout_ms` for the answer.

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

  @doc "Calls one tool. The raw MCP result map, or a typed error."
  @spec call_tool(GenServer.server(), String.t(), map(), pos_integer()) ::
          {:ok, map()} | {:error, term()}
  def call_tool(server, name, arguments, timeout_ms) do
    case request(server, "tools/call", %{"name" => name, "arguments" => arguments}, timeout_ms) do
      {:ok, %{} = result} -> {:ok, result}
      {:ok, other} -> {:error, {:malformed_result, inspect_bounded(other)}}
      {:error, _reason} = error -> error
    end
  end

  @doc "The tool list this server advertised, or `[]` while it is still handshaking."
  @spec tools(GenServer.server()) :: [tool()]
  def tools(server) do
    GenServer.call(server, :tools, 5_000)
  catch
    :exit, _reason -> []
  end

  @doc "Blocks until the handshake has completed, or `timeout_ms` elapses."
  @spec await_ready(GenServer.server(), pos_integer()) :: :ok | {:error, term()}
  def await_ready(server, timeout_ms) do
    GenServer.call(server, :await_ready, timeout_ms)
  catch
    :exit, reason -> {:error, {:server_unavailable, reason}}
  end

  @spec info(GenServer.server()) :: {:ok, info()} | {:error, term()}
  def info(server) do
    GenServer.call(server, :info, 5_000)
  catch
    :exit, reason -> {:error, {:server_unavailable, reason}}
  end

  @doc "Begins the bounded shutdown. The process stops on its own afterwards."
  @spec stop(GenServer.server()) :: :ok
  def stop(server), do: GenServer.cast(server, :begin_shutdown)

  @doc "The MCP revision this client sends in `initialize`."
  @spec protocol_version() :: String.t()
  def protocol_version, do: @protocol_version

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    definition = Keyword.fetch!(opts, :definition)

    state = %{
      owner: Keyword.fetch!(opts, :owner),
      key: Keyword.fetch!(opts, :key),
      definition: definition,
      cwd: Keyword.get(opts, :cwd) || definition.cwd || System.tmp_dir!(),
      max_frame_bytes: setting(opts, :max_frame_bytes),
      max_pending: setting(opts, :max_pending_requests),
      max_tools: setting(opts, :max_tools_per_server),
      max_pages: setting(opts, :max_tool_pages),
      max_noise: setting(opts, :max_noise_lines),
      max_description_bytes: setting(opts, :max_tool_description_bytes),
      handshake_timeout_ms: setting(opts, :handshake_timeout_ms),
      request_timeout_ms: setting(opts, :request_timeout_ms),
      shutdown_grace_ms: setting(opts, :shutdown_grace_ms),
      port: nil,
      os_pid: nil,
      buffer: <<>>,
      noise: 0,
      next_id: 1,
      pending: %{},
      phase: :handshaking,
      server_info: nil,
      server_protocol: nil,
      capabilities: %{},
      tools: [],
      # The in-progress `tools/list`, or `nil`. Held separately from `tools` so that a
      # refresh that fails leaves the list this server is already advertising alone,
      # and so only one listing can be in flight however often a server says its tools
      # changed.
      listing: nil,
      ready_waiters: []
    }

    case open_port(state) do
      {:ok, state} -> {:ok, state, {:continue, :handshake}}
      {:error, reason} -> {:stop, {:spawn_failed, reason}}
    end
  end

  @impl true
  def handle_continue(:handshake, state) do
    Process.send_after(self(), :handshake_deadline, state.handshake_timeout_ms)

    params = %{
      "protocolVersion" => @protocol_version,
      "capabilities" => %{},
      "clientInfo" => Config.client_info()
    }

    case issue(state, "initialize", params, :initialize, state.handshake_timeout_ms) do
      {:ok, state} -> {:noreply, state}
      {:error, reason} -> {:stop, {:transport_closed, reason}, state}
    end
  end

  @impl true
  def handle_call({:request, _method, _params, _timeout}, _from, %{phase: :stopping} = state),
    do: {:reply, {:error, :shutting_down}, state}

  def handle_call({:request, _method, _params, _timeout}, _from, %{phase: :handshaking} = state),
    do: {:reply, {:error, :not_ready}, state}

  def handle_call({:request, method, params, timeout_ms}, from, state) do
    if map_size(state.pending) >= state.max_pending do
      {:reply, {:error, :busy}, state}
    else
      case issue(state, method, params, {:caller, from}, timeout_ms) do
        {:ok, state} -> {:noreply, state}
        {:error, reason} -> {:stop, {:transport_closed, reason}, {:error, reason}, state}
      end
    end
  end

  def handle_call(:tools, _from, state), do: {:reply, state.tools, state}

  def handle_call(:await_ready, _from, %{phase: :ready} = state), do: {:reply, :ok, state}

  def handle_call(:await_ready, _from, %{phase: :stopping} = state),
    do: {:reply, {:error, :shutting_down}, state}

  def handle_call(:await_ready, from, state) do
    # The waiter list is capped like every other queue here: past the in-flight bound a
    # caller is told the server is busy rather than joining an unbounded list.
    if length(state.ready_waiters) >= state.max_pending do
      {:reply, {:error, :busy}, state}
    else
      {:noreply, %{state | ready_waiters: [from | state.ready_waiters]}}
    end
  end

  def handle_call(:info, _from, state) do
    {:reply,
     {:ok,
      %{
        phase: state.phase,
        os_pid: state.os_pid,
        pending: map_size(state.pending),
        noise: state.noise,
        tool_count: length(state.tools),
        server_info: state.server_info,
        protocol_version: state.server_protocol
      }}, state}
  end

  @impl true
  def handle_cast(:begin_shutdown, %{phase: :stopping} = state), do: {:noreply, state}

  # Closing the port closes the child's stdin, which is exactly how the MCP spec asks a
  # stdio server to exit; an Erlang port cannot half-close, so this closes stdout with
  # it and the exit status is no longer observable. That is the whole reason for the
  # grace: the child is given `shutdown_grace_ms` to notice EOF and leave, and then
  # `terminate/2` reaps whatever is left with `SIGKILL`.
  def handle_cast(:begin_shutdown, state) do
    state = state |> fail_pending(:shutting_down) |> close_port()
    Process.send_after(self(), :shutdown_grace_expired, state.shutdown_grace_ms)
    {:noreply, %{state | phase: :stopping}}
  end

  @impl true
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    case Codec.decode(state.buffer <> data, state.max_frame_bytes) do
      {:ok, frames, noise, rest} ->
        state = %{state | buffer: rest, noise: state.noise + noise}

        if state.noise > state.max_noise do
          {:stop, {:protocol_error, {:noise_limit, state.noise}}, state}
        else
          Enum.reduce_while(frames, {:noreply, state}, fn
            frame, {:noreply, acc} -> {:cont, handle_frame(frame, acc)}
            _frame, halted -> {:halt, halted}
          end)
        end

      {:error, reason} ->
        {:stop, {:protocol_error, reason}, state}
    end
  end

  # stderr is the server's own log. It is neither buffered nor forwarded: a server that
  # writes a token to its diagnostics must not be able to put one in this node's logs.
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    state = %{state | port: nil, os_pid: nil}

    if state.phase == :stopping do
      {:stop, :normal, state}
    else
      {:stop, {:server_exited, status}, fail_pending(state, {:server_exited, status})}
    end
  end

  def handle_info(:handshake_deadline, %{phase: :handshaking} = state),
    do: {:stop, :handshake_timeout, fail_pending(state, :handshake_timeout)}

  def handle_info(:handshake_deadline, state), do: {:noreply, state}

  def handle_info({:deadline, id}, state) do
    case Map.pop(state.pending, id) do
      {nil, _pending} ->
        {:noreply, state}

      {%{kind: {:caller, from}}, pending} ->
        GenServer.reply(from, {:error, :timeout})
        {:noreply, %{state | pending: pending}}

      {%{kind: _internal}, pending} ->
        # An internal request belongs to the handshake or to a tool-list refresh. During
        # the handshake its expiry *is* the handshake failing, and saying so here names
        # the step the whole-handshake deadline would have reported anonymously.
        if state.phase == :handshaking,
          do: {:stop, :handshake_timeout, %{state | pending: pending}},
          else: {:noreply, %{state | pending: pending, listing: nil}}
    end
  end

  def handle_info(:shutdown_grace_expired, state), do: {:stop, :normal, state}

  # The pool owns this process and monitors it; an exit from anywhere else is the tree
  # coming down.
  def handle_info({:EXIT, _pid, reason}, state), do: {:stop, reason, state}

  def handle_info(_message, state), do: {:noreply, state}

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
    _ = write(state, Codec.error_response(frame["id"], @method_not_found, unsupported(method)))
    {:noreply, state}
  end

  defp handle_frame(%{"method" => method}, state), do: {:noreply, observe(method, state)}

  defp handle_frame(%{"id" => id} = frame, state) do
    case Map.pop(state.pending, id) do
      {nil, _pending} -> {:noreply, state}
      {%{kind: kind}, pending} -> route(kind, answer(frame), %{state | pending: pending})
    end
  end

  defp handle_frame(_frame, state), do: {:noreply, state}

  defp answer(%{"error" => %{} = error}),
    do: {:error, {:rpc_error, Map.get(error, "code"), bounded(Map.get(error, "message"))}}

  defp answer(%{"result" => result}), do: {:ok, result}
  defp answer(_frame), do: {:error, {:malformed_result, "neither result nor error"}}

  defp route({:caller, from}, reply, state) do
    GenServer.reply(from, reply)
    {:noreply, state}
  end

  defp route(:initialize, {:ok, %{} = result}, state) do
    capabilities = Map.get(result, "capabilities")

    state = %{
      state
      | server_info: server_info(Map.get(result, "serverInfo")),
        server_protocol: bounded(Map.get(result, "protocolVersion")),
        capabilities: if(is_map(capabilities), do: capabilities, else: %{})
    }

    with :ok <- write(state, Codec.notification("notifications/initialized", %{})),
         {:ok, state} <- list_tools(state, nil) do
      {:noreply, state}
    else
      {:error, reason} -> {:stop, {:transport_closed, reason}, state}
    end
  end

  defp route(:initialize, other, state),
    do: {:stop, {:initialize_failed, describe(other)}, state}

  defp route(:tools_list, {:ok, %{} = result}, %{listing: %{} = listing} = state) do
    tools =
      Enum.take(listing.tools ++ decode_tools(Map.get(result, "tools"), state), state.max_tools)

    cursor = Map.get(result, "nextCursor")

    if is_binary(cursor) and cursor != "" and length(tools) < state.max_tools and
         listing.pages < state.max_pages do
      case list_tools(%{state | listing: %{listing | tools: tools}}, cursor) do
        {:ok, state} -> {:noreply, state}
        {:error, reason} -> {:stop, {:transport_closed, reason}, state}
      end
    else
      {:noreply, ready(%{state | tools: tools, listing: nil})}
    end
  end

  defp route(:tools_list, other, state) do
    # A server that answered `initialize` and then refused `tools/list` is a server with
    # no tools, not a crash: the pool marks it ready with whatever list it already had —
    # empty on a first listing — and `mcp.list` shows `tools: 0` rather than a restart
    # loop nobody asked for.
    Logger.debug(fn -> "mcp #{state.definition.name}: tools/list failed: #{describe(other)}" end)

    if state.phase == :handshaking,
      do: {:noreply, ready(%{state | listing: nil})},
      else: {:noreply, %{state | listing: nil}}
  end

  # The one server notification this client acts on. A refresh is bounded exactly like
  # the first listing, and only one may be in flight: a server that emits `list_changed`
  # in a loop must not be able to make this process issue requests in a loop.
  defp observe("notifications/tools/list_changed", %{phase: :ready, listing: nil} = state) do
    case list_tools(state, nil) do
      {:ok, state} -> state
      {:error, _closed} -> state
    end
  end

  defp observe(_method, state), do: state

  defp list_tools(state, cursor) do
    params = if is_binary(cursor), do: %{"cursor" => cursor}, else: %{}
    listing = state.listing || %{tools: [], pages: 0}

    timeout =
      if state.phase == :handshaking,
        do: state.handshake_timeout_ms,
        else: state.request_timeout_ms

    state = %{state | listing: %{listing | pages: listing.pages + 1}}
    issue(state, "tools/list", params, :tools_list, timeout)
  end

  # Idempotent on purpose: the handshake calls it once, and a `list_changed` refresh
  # calls it again with no waiters left to answer. The owner learns the new list either
  # way, which is the only thing that has to be true after a refresh.
  defp ready(state) do
    Enum.each(state.ready_waiters, &GenServer.reply(&1, :ok))
    send(state.owner, {:mcp_ready, state.key, self(), state.tools})
    %{state | phase: :ready, ready_waiters: []}
  end

  # Every field a tool descriptor contributes to the model's context is bounded here,
  # once, so nothing downstream has to trust a server's idea of a short description.
  defp decode_tools(tools, state) when is_list(tools) do
    tools
    |> Enum.flat_map(fn
      %{"name" => name} = tool when is_binary(name) and name != "" ->
        [
          %{
            name: bounded(name),
            description: description(tool, state),
            input_schema: input_schema(Map.get(tool, "inputSchema"))
          }
        ]

      _malformed ->
        []
    end)
    |> Enum.uniq_by(& &1.name)
  end

  defp decode_tools(_tools, _state), do: []

  defp description(tool, state) do
    case Enum.find(
           [Map.get(tool, "description"), Map.get(tool, "title")],
           &(is_binary(&1) and String.trim(&1) != "")
         ) do
      nil -> ""
      text -> text |> String.trim() |> truncate(state.max_description_bytes)
    end
  end

  defp input_schema(%{} = schema), do: schema
  defp input_schema(_absent), do: %{"type" => "object", "properties" => %{}}

  ## Requests

  defp issue(state, method, params, kind, timeout_ms) do
    {id, state} = take_id(state)

    case write(state, Codec.request(id, method, params)) do
      :ok ->
        Process.send_after(self(), {:deadline, id}, timeout_ms)
        {:ok, %{state | pending: Map.put(state.pending, id, %{kind: kind})}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp take_id(state), do: {state.next_id, %{state | next_id: state.next_id + 1}}

  defp fail_pending(state, reason) do
    Enum.each(state.ready_waiters, &GenServer.reply(&1, {:error, reason}))

    Enum.each(state.pending, fn
      {_id, %{kind: {:caller, from}}} -> GenServer.reply(from, {:error, reason})
      {_id, _internal} -> :ok
    end)

    %{state | pending: %{}, ready_waiters: []}
  end

  ## Transport

  defp open_port(state) do
    with {:ok, wrapper} <- wrapper_executable(),
         {:ok, cwd} <- directory(state.cwd) do
      port =
        Port.open(
          {:spawn_executable, String.to_charlist(wrapper)},
          [
            :binary,
            :exit_status,
            :use_stdio,
            :hide,
            {:args, Enum.map(command(state.definition), &String.to_charlist/1)},
            {:cd, String.to_charlist(cwd)},
            {:env, env(state.definition)}
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

  defp command(%Servers{command: command, args: args}), do: [command | args]

  # Erlang's `env` option *modifies* the inherited environment rather than replacing it,
  # which is what an MCP server expects: it needs `PATH` and `HOME` to run at all, and
  # the declared variables on top. The values are never logged, inspected, or reported —
  # see `Ouroboros.Provider.Native.Mcp.Servers`.
  defp env(%Servers{env: env}),
    do: Enum.map(env, fn {key, value} -> {to_charlist(key), to_charlist(value)} end)

  defp directory(path) do
    if File.dir?(path), do: {:ok, path}, else: {:error, {:missing_cwd, path}}
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

  defp close_port(%{port: port} = state) when is_port(port) do
    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    # `os_pid` is kept: it is the only handle left once the port is gone, and it is what
    # `SIGKILL` needs if the child ignores EOF.
    %{state | port: nil}
  end

  defp close_port(state), do: state

  defp kill(state) do
    %{os_pid: os_pid} = close_port(state)

    # Closing the port closes stdin, which is how the MCP spec asks a stdio server to
    # exit. It does not reap the child: a server that ignores EOF would otherwise
    # outlive this runtime.
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

  ## Bounds on what a server says

  defp setting(opts, key), do: Keyword.get(opts, key) || Config.get(key)

  defp unsupported(method) when is_binary(method),
    do: "this MCP client declares no capabilities; #{truncate(method, 64)} is unsupported"

  defp unsupported(_method), do: "this MCP client declares no capabilities"

  defp bounded(text) when is_binary(text), do: truncate(text, 512)
  defp bounded(nil), do: nil
  defp bounded(other), do: inspect_bounded(other)

  defp server_info(%{} = info) do
    info
    |> Map.take(["name", "title", "version"])
    |> Map.new(fn {key, value} -> {key, bounded(value)} end)
  end

  defp server_info(_absent), do: nil

  defp truncate(text, limit) when byte_size(text) <= limit, do: text

  # Cutting a UTF-8 binary on a byte boundary can split a codepoint, and what is cut
  # here reaches a JSON encoder, so the tail is trimmed until it is valid again.
  defp truncate(text, limit),
    do: text |> binary_part(0, limit) |> valid_prefix() |> Kernel.<>("…")

  defp valid_prefix(<<>>), do: <<>>

  defp valid_prefix(binary) do
    if String.valid?(binary),
      do: binary,
      else: binary |> binary_part(0, byte_size(binary) - 1) |> valid_prefix()
  end

  defp inspect_bounded(term),
    do: term |> inspect(limit: 20, printable_limit: 256) |> truncate(512)

  defp describe({:error, reason}), do: inspect_bounded(reason)
  defp describe(other), do: inspect_bounded(other)
end
