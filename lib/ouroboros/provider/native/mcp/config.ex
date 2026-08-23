defmodule Ouroboros.Provider.Native.Mcp.Config do
  @moduledoc """
  Reads the `:mcp` application environment and answers with defaults.

  Every value here is a bound: a timeout, a cap, a byte budget, or a retention window.
  There is no `:infinity` and none is accepted — a non-positive or non-integer setting
  falls back to the shipped default rather than removing the bound, because a mistyped
  operator value must never widen what a stranger's program may consume on this node.
  This is deliberately the same posture, and nearly the same code, as
  `Ouroboros.CodeIntel.Config`: an MCP server and a language server are the same kind of
  hazard — somebody else's process, spawned by us, reading and writing a pipe.
  """

  @defaults [
    # Lazy spawn means nothing runs until a session asks; this switch exists so an
    # operator can refuse MCP servers on a host outright.
    enabled: true,
    # The handshake budget: `initialize`, `notifications/initialized`, and the first
    # `tools/list` must all land inside this. Node runtimes cold-starting an npx package
    # are the slow case the number is sized for.
    handshake_timeout_ms: 15_000,
    # One `tools/call`. Longer than a language-server request because an MCP tool is
    # often a network call somebody else is making on our behalf.
    call_timeout_ms: 60_000,
    # `tools/list` after the handshake, and any other bookkeeping request.
    request_timeout_ms: 15_000,
    # How long `Ouroboros.Provider.Native.Mcp.tools/2` will wait, in total, for servers
    # that are still handshaking when a turn asks for its tool list. Past this the turn
    # goes out without them and they appear on the next one — a turn that stalls for
    # fifteen seconds before the model sees a token is worse than a tool list that
    # arrives one turn late.
    list_wait_ms: 5_000,
    # The only reason a healthy server with no session holding it ever stops.
    idle_ms: 600_000,
    # How often the pool checks for idle servers and stale broken marks.
    sweep_ms: 5_000,
    # `notifications/cancelled` and a closed stdin are a courtesy; after this the OS
    # process is killed.
    shutdown_grace_ms: 5_000,
    max_restarts: 3,
    restart_backoff_ms: 1_000,
    # Once a key is broken every call against it answers `{:error, :broken}` for this
    # long rather than respawning a server that has already failed repeatedly.
    broken_ms: 300_000,
    # 25k tokens is Claude Code's documented cap on a single tool result; 100 KB is the
    # byte proxy this runtime already uses for the same bound in
    # `Ouroboros.Provider.Native.Tools`. Past it the result carries a visible marker.
    max_result_bytes: 100 * 1024,
    # One JSON-RPC line. MCP stdio frames are newline-delimited, so this is also the cap
    # on how much unterminated garbage a server may make this node buffer.
    max_frame_bytes: 4 * 1024 * 1024,
    # In-flight requests per server. Past this the server answers `{:error, :busy}`
    # rather than growing a mailbox.
    max_pending_requests: 32,
    # Per server, and per node. A server advertising ten thousand tools is not a tool
    # set, it is a context-window attack.
    max_tools_per_server: 200,
    max_servers: 20,
    # `tools/list` pages, so a server that returns a `nextCursor` forever terminates.
    max_tool_pages: 20,
    # What one tool's JSON Schema may contribute to the model's context, and what every
    # MCP tool on a session may contribute together. Past the budget a tool is still
    # listed by name and description, with an open schema and a note saying so. See the
    # "Deferred schemas" section of `Ouroboros.Provider.Native.Mcp`.
    max_tool_schema_bytes: 4 * 1024,
    max_schema_budget_bytes: 32 * 1024,
    # One tool description, after the server's own text is trimmed to its first line.
    max_tool_description_bytes: 400,
    # Lines a server may write to stdout that are not JSON before the transport is
    # treated as broken. The spec forbids them outright; counting a few is the
    # difference between tolerating a stray banner and buffering a log file.
    max_noise_lines: 100
  ]

  @doc "Returns one setting, falling back to the shipped default when it is unusable."
  @spec get(atom()) :: term()
  def get(key) when is_atom(key) do
    default = Keyword.fetch!(@defaults, key)
    configured = Application.get_env(:ouroboros, :mcp, [])

    value =
      if Keyword.keyword?(configured), do: Keyword.get(configured, key, default), else: default

    if valid?(default, value), do: value, else: default
  end

  @doc "Whether this node runs MCP servers at all."
  @spec enabled?() :: boolean()
  def enabled?, do: get(:enabled) == true

  @doc "Every setting and its effective value, for `mcp.list` and for tests."
  @spec all() :: keyword()
  def all, do: Enum.map(@defaults, fn {key, _default} -> {key, get(key)} end)

  @doc """
  The client identity sent in `initialize`.

  Servers key behaviour on it — a few refuse unknown clients — so it names this runtime
  rather than pretending to be an editor.
  """
  @spec client_info() :: map()
  def client_info do
    version =
      case :application.get_key(:ouroboros, :vsn) do
        {:ok, vsn} -> List.to_string(vsn)
        _undefined -> "0.0.0"
      end

    %{"name" => "ouroboros", "title" => "Ouroboros native agent", "version" => version}
  end

  defp valid?(default, value) when is_integer(default) and default > 0,
    do: is_integer(value) and value > 0

  defp valid?(default, value) when is_boolean(default), do: is_boolean(value)
  defp valid?(_default, _value), do: true
end
