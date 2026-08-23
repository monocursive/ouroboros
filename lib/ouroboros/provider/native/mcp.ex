defmodule Ouroboros.Provider.Native.Mcp do
  @moduledoc """
  The Model Context Protocol *client* for the native agent (AGENT_EXPERIENCE D4).

  Ouroboros already **serves** MCP — `ouro mcp-serve` is the permission prompt a bridged
  Claude session calls ([tui/src/mcp_serve.rs](../../../../tui/src/mcp_serve.rs)). This
  is the other half: the native provider spawns somebody else's MCP server over stdio
  and puts its tools in front of the model.

  ## What the model sees

  Every tool a server advertises appears as `mcp__<server>__<tool>` — Claude Code's
  convention, unchanged, because the C1 permission rule language already matches those
  names and because a rule somebody wrote for one agent should mean the same thing here.
  A call goes through `Ouroboros.Control.Permissions` like any other tool
  (`mode: :execute`, tool name `mcp__server__tool`), produces ordinary `tool_call` and
  `tool_result` events with the server named, and is bounded on both sides.

  ## Deferred schemas — the measurement, and the decision

  R3 §6 describes agents that hide MCP tool schemas behind a lookup call because a dozen
  servers can bury a context window before the first token. So the budget was measured
  rather than assumed. Encoded `inputSchema` sizes for the servers this was built
  against: `everything` (14 tools) 2.9 kB total, `git` (13 tools) 4.6 kB, `filesystem`
  (12 tools) 5.1 kB; the largest single schema seen was 1.4 kB. Two or three ordinary
  servers therefore cost about as much as one of this runtime's own thirteen tools, and
  hiding them would buy nothing while costing a round trip on first use.

  So the decision is: **schemas are exposed directly while they fit, and deferred past a
  bound.** A tool's schema is sent to the model when it is at most
  `max_tool_schema_bytes` (4 kB) and the session's running MCP schema total is under
  `max_schema_budget_bytes` (32 kB). Past either bound the tool is *still listed* — name
  and one-line description — with an open `{"type": "object"}` schema and a sentence in
  its description saying the schema was withheld and that the server validates
  arguments. Nothing disappears silently.

  One honest note on the word "deferred": MCP has no per-tool schema request. `tools/list`
  returns every schema at once, so this client already holds them all after the
  handshake. The deferral is of what reaches the *model's context*, not of a fetch — and
  a call to a tool whose schema was withheld works exactly as well, because the server
  is the thing that validates.

  ## Where servers come from

  `Ouroboros.Provider.Native.Mcp.Servers`: node configuration, then
  `~/.config/ouroboros/mcp.json`, then `<workspace>/.ouroboros/mcp.json` — the last
  gated on the same workspace trust `Ouroboros.Provider.Native.Hooks` requires, because
  a repository that ships an `mcp.json` is a repository that runs commands on every
  machine that clones it.

  ## Honest limits

  **stdio only.** Streamable HTTP is not implemented; a `url` server is refused with
  `:unsupported_transport` and named in `mcp.list` rather than ignored. **No OAuth** —
  there is no authorization flow here at all, so a server needing one is a server this
  client cannot use. **No `resources/*` or `prompts/*`** in this slice: the transport
  would carry them, but nothing in the native loop consumes them yet and shipping an
  unreachable code path is worse than saying so. **No `ouro mcp add`** — servers are
  configured by file or by node config; the CLI is client work for a later slice.
  """

  alias Ouroboros.Provider.Native.Mcp.Config
  alias Ouroboros.Provider.Native.Mcp.Pool
  alias Ouroboros.Provider.Native.Mcp.Result
  alias Ouroboros.Provider.Native.Mcp.Server
  alias Ouroboros.Provider.Native.Mcp.Servers

  @prefix "mcp__"

  @typedoc "One tool spec as `Ouroboros.Provider.Native.Tools.specs/3` hands it to a model."
  @type spec :: %{name: String.t(), description: String.t(), parameters: map()}

  @doc "Whether this node runs MCP servers at all, and has the subtree to run them in."
  @spec enabled?(keyword()) :: boolean()
  def enabled?(opts \\ []) do
    Config.enabled?() and is_pid(pool_pid(opts))
  end

  @doc """
  The model-facing name for one server's tool.

  Public because the pool, the tool module, and the tests all have to agree about it,
  and three copies of a string concatenation is how they stop agreeing.
  """
  @spec tool_name(String.t(), String.t()) :: String.t()
  def tool_name(server, tool), do: @prefix <> server <> "__" <> tool

  @doc """
  Splits a model-facing name back into `{server, tool}`.

  Split on the *first* `__` after the prefix, which is why
  `Ouroboros.Provider.Native.Mcp.Servers` refuses a server name containing `__`: without
  that refusal this split has no single right answer.
  """
  @spec split(String.t()) :: {:ok, String.t(), String.t()} | :error
  def split(@prefix <> rest) when rest != "" do
    case String.split(rest, "__", parts: 2) do
      [server, tool] when server != "" and tool != "" -> {:ok, server, tool}
      _malformed -> :error
    end
  end

  def split(_name), do: :error

  @doc "Whether a name is shaped like an MCP tool name at all."
  @spec name?(term()) :: boolean()
  def name?(name) when is_binary(name), do: match?({:ok, _server, _tool}, split(name))
  def name?(_name), do: false

  @doc """
  Whether any live server on this node advertises `name`.

  Cheap and non-blocking, because `Ouroboros.Provider.Native.Tools.lookup/3` calls it on
  every tool dispatch and is given no workspace to narrow by.
  """
  @spec advertised?(String.t(), keyword()) :: boolean()
  def advertised?(name, opts \\ []) do
    name?(name) and enabled?(opts) and Pool.advertised?(pool(opts), name)
  end

  @doc """
  Every MCP tool spec for one session, after this module's schema budget.

  Starts any configured server that is not running and waits at most `list_wait_ms` in
  *total* for the ones still handshaking. A server that is not ready in time contributes
  nothing this turn and appears on the next one: a turn that stalls before the model
  sees a token is worse than a tool list that arrives one turn late.
  """
  @spec specs(String.t() | nil, keyword()) :: [spec()]
  def specs(workspace_root, opts \\ []) do
    if enabled?(opts) do
      loaded = Servers.load(workspace_root, opts)

      pool(opts)
      |> Pool.ensure(workspace_root, loaded.servers)
      |> await_ready(deadline(Keyword.get(opts, :list_wait_ms) || Config.get(:list_wait_ms)))

      pool(opts)
      |> Pool.tools(workspace_root)
      |> build_specs(opts)
    else
      []
    end
  end

  @doc """
  Calls one MCP tool by its model-facing name.

  Always answers a *result*, never raises: an unknown server, an unknown tool, a refusal,
  a timeout, and a server that died mid-call are all `is_error: true` outputs the model
  can read and act on, which is the whole reason tool errors are in band.

  `opts` carries `:workspace` (required to resolve the server), `:owner` (the session
  process whose death releases the claim), and `:timeout_ms`.
  """
  @spec call(String.t(), map(), keyword()) :: %{output: String.t(), is_error: boolean()}
  def call(name, arguments, opts \\ []) do
    case invoke(name, arguments, opts) do
      {:ok, result} ->
        result

      {:error, reason} ->
        %{output: "#{name} failed: #{Result.describe_error(reason)}", is_error: true}
    end
  end

  @doc """
  Describes every MCP server this node holds, for `mcp.list`.

  Shaped for a client: no pids, no atoms a wire format cannot carry back, and never an
  environment *value* — only how many variables a server was given. Configured servers
  that have never been started still appear, with `state: "disabled"` when this node has
  MCP switched off, so an operator can tell "not configured" from "configured and not
  running".
  """
  @spec status(keyword()) :: map()
  def status(opts \\ []) do
    workspaces = Keyword.get(opts, :workspaces, [])
    loaded = Enum.map(workspaces, &{&1, Servers.load(&1, opts)})

    live = if enabled?(opts), do: Pool.status(pool(opts)), else: %{node: node(), servers: []}
    running = MapSet.new(live.servers, &{&1.workspace, &1.name})

    configured =
      for {workspace, result} <- loaded,
          definition <- result.servers,
          not MapSet.member?(running, {workspace, definition.name}) do
        definition
        |> Servers.describe()
        |> Map.merge(%{
          workspace: workspace,
          state: if(Config.enabled?(), do: :configured, else: :disabled),
          tools: 0,
          tool_names: [],
          restarts: 0,
          claims: 0
        })
      end

    %{
      node: node(),
      enabled: Config.enabled?(),
      supervised: is_pid(pool_pid(opts)),
      protocol_version: Server.protocol_version(),
      transports: [:stdio],
      servers: Enum.sort_by(live.servers ++ configured, &{&1.workspace || "", &1.name}),
      refusals: Enum.flat_map(loaded, fn {workspace, result} -> refusals(workspace, result) end)
    }
  end

  ## Calling

  defp invoke(name, arguments, opts) do
    with {:ok, arguments} <- arguments(arguments),
         {:ok, server_name, tool_name} <- resolve(name),
         :ok <- available(opts),
         workspace = Keyword.get(opts, :workspace),
         {:ok, definition} <- definition(server_name, workspace, opts),
         {:ok, pid} <- checkout(definition, workspace, opts),
         :ok <- ready(pid, opts),
         :ok <- advertises(pid, server_name, tool_name) do
      timeout = Keyword.get(opts, :timeout_ms) || Config.get(:call_timeout_ms)

      case Server.call_tool(pid, tool_name, arguments, timeout) do
        {:ok, result} -> {:ok, Result.render(result, opts)}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp resolve(name) do
    case split(name) do
      {:ok, server, tool} -> {:ok, server, tool}
      :error -> {:error, {:invalid_name, name}}
    end
  end

  defp available(opts) do
    if enabled?(opts),
      do: :ok,
      else: {:error, if(Config.enabled?(), do: :pool_unavailable, else: :disabled)}
  end

  defp arguments(arguments) when is_map(arguments), do: {:ok, arguments}
  defp arguments(nil), do: {:ok, %{}}
  defp arguments(other), do: {:error, {:invalid_arguments, inspect(other, limit: 5)}}

  defp definition(server_name, workspace, opts) do
    loaded = Servers.load(workspace, opts)

    case Enum.find(loaded.servers, &(&1.name == server_name)) do
      %Servers{} = definition ->
        {:ok, definition}

      nil ->
        case Enum.find(loaded.refusals, &(&1.name == server_name)) do
          %{reason: :unsupported_transport} ->
            {:error, {:unsupported_transport, server_name}}

          _other ->
            {:error, {:unknown_server, server_name, Enum.map(loaded.servers, & &1.name)}}
        end
    end
  end

  defp checkout(definition, workspace, opts) do
    Pool.checkout(pool(opts), {workspace, definition.name}, definition, Keyword.get(opts, :owner))
  end

  defp ready(pid, opts) do
    wait = Keyword.get(opts, :handshake_timeout_ms) || Config.get(:handshake_timeout_ms)
    Server.await_ready(pid, wait)
  end

  # A tool the server does not advertise is refused before `tools/call` is sent. Not for
  # safety — the server would refuse it too — but because "this server has echo and add"
  # is a far more useful answer to a model than a JSON-RPC error code.
  defp advertises(pid, server_name, tool_name) do
    tools = Server.tools(pid)

    if Enum.any?(tools, &(&1.name == tool_name)),
      do: :ok,
      else: {:error, {:unknown_tool, server_name, tool_name, Enum.map(tools, & &1.name)}}
  end

  ## Specs

  defp build_specs(servers, opts) do
    per_tool = Keyword.get(opts, :max_tool_schema_bytes) || Config.get(:max_tool_schema_bytes)
    budget = Keyword.get(opts, :max_schema_budget_bytes) || Config.get(:max_schema_budget_bytes)

    {specs, _remaining} =
      Enum.reduce(servers, {[], budget}, fn {server, tools}, acc ->
        Enum.reduce(tools, acc, fn tool, {specs, remaining} ->
          {spec, remaining} = spec(server, tool, per_tool, remaining)
          {[spec | specs], remaining}
        end)
      end)

    Enum.reverse(specs)
  end

  defp spec(server, tool, per_tool, remaining) do
    encoded = encoded_size(tool.input_schema)

    if encoded <= per_tool and encoded <= remaining do
      {%{
         name: tool_name(server, tool.name),
         description: describe(server, tool.description),
         parameters: tool.input_schema
       }, remaining - encoded}
    else
      {%{
         name: tool_name(server, tool.name),
         description:
           describe(server, tool.description) <>
             " (This tool's argument schema was withheld to keep the request small; " <>
             "pass the arguments the server's own documentation names — it validates them.)",
         parameters: %{"type" => "object", "additionalProperties" => true}
       }, remaining}
    end
  end

  defp describe(server, ""), do: "A tool served by the MCP server `#{server}`."

  defp describe(server, description),
    do: description <> " (MCP server `#{server}`.)"

  # A schema that will not encode cannot be sent to a model at all, so it counts as
  # over every budget and the tool gets the open schema and the withheld note.
  defp encoded_size(schema) do
    schema |> JSON.encode_to_iodata!() |> IO.iodata_length()
  rescue
    _unencodable -> :infinity
  end

  ## Waiting

  # One deadline for every server that is still handshaking, not one each: five servers
  # times fifteen seconds is a turn nobody would wait for, and the bound a caller asked
  # for is the bound it should get.
  defp await_ready(placements, deadline) do
    Enum.each(placements, fn placement ->
      remaining = deadline - System.monotonic_time(:millisecond)

      if placement.state == :starting and is_pid(placement.pid) and remaining > 0 do
        Server.await_ready(placement.pid, remaining)
      end
    end)
  end

  defp deadline(wait_ms), do: System.monotonic_time(:millisecond) + wait_ms

  defp refusals(workspace, result) do
    declined =
      if result.declined > 0 do
        [
          %{
            name: nil,
            workspace: workspace,
            scope: :workspace,
            reason: :untrusted_workspace,
            detail:
              "#{result.declined} server(s) declared in #{Servers.workspace_path(workspace)} " <>
                "were not loaded: this workspace is not trusted"
          }
        ]
      else
        []
      end

    Enum.map(result.refusals, &Map.put(&1, :workspace, workspace)) ++
      declined ++
      Enum.map(result.errors, fn error ->
        %{name: nil, workspace: workspace, scope: :workspace, reason: :unreadable, detail: error}
      end)
  end

  ## Pool

  defp pool(opts), do: Keyword.get(opts, :pool) || Pool

  defp pool_pid(opts) do
    case pool(opts) do
      pid when is_pid(pid) -> pid
      name when is_atom(name) -> Process.whereis(name)
      _other -> nil
    end
  end
end
