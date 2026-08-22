defmodule Ouroboros.Provider.ClaudeAdapter do
  @moduledoc """
  Claude Code with a human in the loop, on a transport that has no room for one.

  ## What was wrong

  `claude --print` runs one process per turn and declares no approvals channel, so an
  interactive session at the plane default `approval_mode: :prompt` had every
  permission-needing tool denied by the CLI without a word: the session looked alive and
  could not work, and `Ouroboros.Provider.safety_options/3` refused the combination
  outright rather than let someone discover that by watching an agent fail (X1).

  ## What this does

  Claude Code's headless answer to "who asks the human" is `--permission-prompt-tool`
  (<https://code.claude.com/docs/en/cli-reference>): name an MCP tool and it is called
  instead of prompting. MCP tools are named `mcp__<server>__<tool>`
  (<https://code.claude.com/docs/en/mcp>), so this adapter registers one stdio MCP server
  called `ouroboros` — `ouro mcp-serve`, in the same binary the operator already
  installed — and points Claude at `mcp__ouroboros__approve`. That tool calls
  `interactive.request_approval` back into this runtime, which asks the permission engine
  and then the person, and answers `{"behavior":"allow",…}` or `{"behavior":"deny",…}`.

  The transport is therefore declared with `approvals: :native` whenever the binary is
  there, which is what lifts the X1 refusal — the capability is read from the spec, so
  nothing else has to learn about this.

  ## Where it applies, and where it deliberately does not

    * **Interactive sessions only.** The bridge is attached when the run carries an
      `ouroboros_session_id` in its metadata, which is the interactive plane's marker
      (`Ouroboros.Interactive.State.request/1`); the coding plane sets
      `ouroboros_task_id` instead and is left exactly as it was. There is no human loop
      on the coding plane — a `coding.start` is a caller handing over a whole objective —
      so a permission prompt there would block on somebody who is not watching.
    * **`approval_mode: :prompt` and `:default`.** `:auto_edit` and `:auto_approve`
      produce byte-identical argv to the pinned adapter's. `:prompt` is the mode that
      promises a person is asked, so it is the mode that gets one; `:default` is Claude's
      own default permission mode, which asks too — and under `--print` can only ask
      through this tool, so leaving it unbridged would be the silent denial again.
    * **Only when there is a binary to run.** `OUROBOROS_PROCESS_ID_HELPER` names the
      product binary when `ouro` spawned this runtime (README, "What a spawned runtime
      inherits"); `config :ouroboros, :ouro_binary` names it for a runtime that was
      started some other way. With neither, the transport declares `approvals: false` —
      today's truth — and the X1 refusal goes on protecting people from a mode that
      cannot work.

  ## MCP by reference, which is what D6 asks for

  `mcp_config` stays refused *inline* from callers on both planes
  (`Ouroboros.Coding.TaskState`): a server command inside a durable checkpoint is an
  execution vector that outlives the operator who typed it. Nothing changes about that.
  What this adapter composes is not a caller's value: it is derived at dispatch from node
  facts — this node's own binary, its own gateway address, its own token *file* path, and
  the session id — and it is never checkpointed. That is the "by reference" posture, with
  the reference being the node rather than a name in a registry that does not exist yet.

  The token never appears in argv or in the MCP definition; a path to a `0600` file does,
  which is the posture every other client already has.

  ## The honest limit on merging

  A node-level MCP configuration arriving as a *string* — a JSON blob or a file path,
  both of which `Jido.Harness.Adapters.Claude` accepts — cannot be merged with this one
  without this module parsing and rewriting somebody else's configuration. It does not:
  the bridge is not attached, a warning names the conflict, and the session behaves as it
  did before this adapter existed. A map merges cleanly and the `ouroboros` key is this
  adapter's.

  ## Coupling worth stating

  Upstream's `run/2` is a private assembly of `build_argv/2`, `Helpers.merge_env/2`,
  `Helpers.cli_path/2`, and `CLIStream.run/6`, and `--permission-prompt-tool` is not a
  flag `build_argv/2` can emit. The bridged path therefore re-performs that assembly
  around the upstream argv rather than reaching through `run/2`, and the *only* thing it
  changes is the two elements it splices in. A change to how the pinned adapter starts a
  process has to be mirrored here; the unbridged path delegates and cannot drift.
  """

  @behaviour Jido.Harness.Adapter

  import Bitwise

  require Logger

  alias Jido.Harness.Adapters.{Claude, CLIMapper, CLIStream, Helpers}
  alias Jido.Harness.{Error, RunRequest}

  # Half of the tool name Claude Code is handed, and the same string `ouro mcp-serve`
  # declares as its server name.
  @server "ouroboros"
  @prompt_tool "mcp__ouroboros__approve"
  @subcommand "mcp-serve"

  @helper_env "OUROBOROS_PROCESS_ID_HELPER"

  # Mirrors the pinned adapter's own list. It is private there and this module has to hand
  # the same set to `build_argv/2`, so it is spelled out rather than guessed at.
  @provider_options [
    :cli_path,
    :fallback_model,
    :max_budget_usd,
    :fork_session,
    :settings,
    :betas
  ]

  @impl true
  def spec do
    base = Claude.spec()
    %{base | session_transports: Enum.map(base.session_transports, &declare_approvals/1)}
  end

  @impl true
  def run(%RunRequest{} = request, context) do
    case bridge(request) do
      nil -> Claude.run(request, context)
      bridge -> bridged_run(request, context, bridge)
    end
  end

  @impl true
  defdelegate status(config), to: Claude

  @impl true
  defdelegate install(config, options), to: Claude

  @impl true
  defdelegate cancel(run_id, context), to: Claude

  @doc """
  The MCP server definition this adapter would compose for one session, or `nil`.

  Exposed so a test and an operator can read the exact thing Claude Code is given without
  starting a provider.
  """
  @spec mcp_server(String.t(), String.t() | nil) :: map() | nil
  def mcp_server(session_id, session_node \\ nil) when is_binary(session_id) do
    with {:ok, binary} <- ouro_binary(),
         {:ok, gateway} <- gateway_facts() do
      server(binary, gateway, session_id, session_node)
    else
      _unavailable -> nil
    end
  end

  @doc "The tool name Claude Code is told to call. One constant, two sides of the bridge."
  @spec prompt_tool() :: String.t()
  def prompt_tool, do: @prompt_tool

  # ---------------------------------------------------------------------------
  # Capability declaration
  # ---------------------------------------------------------------------------

  defp declare_approvals(transport) do
    %{transport | capabilities: %{transport.capabilities | approvals: approvals()}}
  end

  # The binary alone. The gateway is what the bridge *calls*, and a runtime with no
  # gateway has no client to open a modal on either — but a runtime with no `ouro` on
  # disk cannot ask under any circumstances, and that is the fact `:prompt` turns on.
  defp approvals do
    case ouro_binary() do
      {:ok, _binary} -> :native
      _absent -> false
    end
  end

  # ---------------------------------------------------------------------------
  # Dispatch
  # ---------------------------------------------------------------------------

  defp bridge(%RunRequest{approval_mode: mode} = request) when mode in [:prompt, :default] do
    case session_id(request) do
      nil -> nil
      session_id -> interactive_bridge(request, session_id)
    end
  end

  defp bridge(_request), do: nil

  defp interactive_bridge(request, session_id) do
    with {:ok, binary} <- ouro_binary(),
         {:ok, gateway} <- gateway_facts(),
         {:ok, servers} <- servers(request.mcp_config) do
      %{
        session_id: session_id,
        servers:
          Map.put(servers, @server, server(binary, gateway, session_id, node_name(request)))
      }
    else
      {:error, reason} ->
        # Falling back is falling back to silent denial, so it is said out loud once, at
        # the moment a session that asked for a human is about to not get one.
        Logger.warning(
          "claude session #{session_id} asked for approval_mode: :prompt and this node " <>
            "cannot bridge it (#{inspect(reason)}); every tool call that needs " <>
            "permission will be denied by claude --print without asking"
        )

        nil
    end
  end

  defp bridged_run(request, context, bridge) do
    options = Helpers.provider_options(request.provider_options, @provider_options)
    request = %{request | mcp_config: bridge.servers}

    with {:ok, argv} <- Claude.build_argv(request, options) do
      request = %{request | env: Helpers.merge_env(request, context.config)}

      executable =
        options[:cli_path] || Helpers.cli_path(context.config, Claude.spec().executable)

      CLIStream.run(
        :claude,
        request,
        context,
        executable,
        with_prompt_tool(argv),
        &CLIMapper.claude/1
      )
    end
  rescue
    exception ->
      {:error,
       Error.validation("invalid Claude options",
         provider: :claude,
         details: %{message: Exception.message(exception)}
       )}
  end

  # `build_argv/2` ends with `["--", prompt]`, so the flag goes in front of the separator
  # rather than after the positional it introduces. With no separator the split leaves an
  # empty tail and the pair lands at the end, which is still a flag before no positional.
  defp with_prompt_tool(argv) do
    {head, tail} = Enum.split_while(argv, &(&1 != "--"))
    head ++ ["--permission-prompt-tool", @prompt_tool] ++ tail
  end

  defp server(binary, gateway, session_id, session_node) do
    %{
      "command" => binary,
      "args" => [@subcommand],
      "env" => %{
        "OUROBOROS_GATEWAY_ADDR" => gateway.addr,
        "OUROBOROS_GATEWAY_TOKEN_FILE" => gateway.token_file,
        "OUROBOROS_SESSION_ID" => session_id,
        "OUROBOROS_SESSION_NODE" => session_node || Atom.to_string(node())
      }
    }
  end

  defp servers(nil), do: {:ok, %{}}
  defp servers(existing) when is_map(existing), do: {:ok, existing}
  defp servers(_string_or_path), do: {:error, :unmergeable_mcp_config}

  # ---------------------------------------------------------------------------
  # Node facts
  # ---------------------------------------------------------------------------

  defp session_id(%RunRequest{metadata: metadata}) when is_map(metadata) do
    case Map.get(metadata, :ouroboros_session_id) || Map.get(metadata, "ouroboros_session_id") do
      id when is_binary(id) and id != "" -> id
      _absent -> nil
    end
  end

  defp session_id(_request), do: nil

  defp node_name(%RunRequest{metadata: metadata}) when is_map(metadata) do
    case Map.get(metadata, :ouroboros_node) || Map.get(metadata, "ouroboros_node") do
      name when is_binary(name) and name != "" -> name
      _absent -> nil
    end
  end

  defp node_name(_request), do: nil

  # An absolute, executable, regular file — the same three checks
  # `Ouroboros.RuntimeOwner` makes of the same variable, and `lstat` for the same reason:
  # a symlink is not the thing it points at.
  defp ouro_binary do
    case configured_binary() do
      path when is_binary(path) ->
        path = String.trim(path)

        case File.lstat(path) do
          {:ok, %File.Stat{type: :regular, mode: mode}} when (mode &&& 0o111) != 0 ->
            if Path.type(path) == :absolute,
              do: {:ok, path},
              else: {:error, {:ouro_binary, :not_absolute}}

          _unsafe ->
            {:error, {:ouro_binary, :not_an_executable_regular_file}}
        end

      _missing ->
        {:error, {:ouro_binary, :not_configured}}
    end
  end

  defp configured_binary do
    case Application.get_env(:ouroboros, :ouro_binary) do
      path when is_binary(path) and path != "" -> path
      _unset -> System.get_env(@helper_env)
    end
  end

  # The address and credential path a client uses to reach this node, taken from the same
  # configuration the listener bound and published — never from `gateway.json`, which is a
  # file this runtime writes for other processes to read rather than a source of truth
  # about itself.
  defp gateway_facts do
    config = Ouroboros.Gateway.Config.load!()

    with {:ok, port} <- gateway_port(config),
         token_file when is_binary(token_file) and token_file != "" <- config.token_file do
      {:ok, %{addr: gateway_addr(config.bind, port), token_file: token_file}}
    else
      {:error, _reason} = error -> error
      _no_token_file -> {:error, {:gateway, :no_token_file}}
    end
  rescue
    _unconfigured -> {:error, {:gateway, :not_configured}}
  end

  # `port: 0` means the listener chose one, and only the listener knows which.
  defp gateway_port(config) do
    case safe_listener_port() do
      port when is_integer(port) and port > 0 -> {:ok, port}
      _no_listener when config.port > 0 -> {:ok, config.port}
      _no_listener -> {:error, {:gateway, :no_bound_port}}
    end
  end

  defp safe_listener_port do
    Ouroboros.Gateway.Listener.port()
  catch
    :exit, _reason -> nil
  end

  # A wildcard bind is reachable on loopback, and loopback is the address a child process
  # on this host should be given: it is the one that cannot be routed off the machine.
  defp gateway_addr({0, 0, 0, 0}, port), do: "127.0.0.1:#{port}"
  defp gateway_addr({0, 0, 0, 0, 0, 0, 0, 0}, port), do: "[::1]:#{port}"

  defp gateway_addr(address, port) when tuple_size(address) == 8,
    do: "[#{address |> :inet.ntoa() |> List.to_string()}]:#{port}"

  defp gateway_addr(address, port),
    do: "#{address |> :inet.ntoa() |> List.to_string()}:#{port}"
end
