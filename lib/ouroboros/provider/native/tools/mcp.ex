defmodule Ouroboros.Provider.Native.Tools.Mcp do
  @moduledoc """
  The one module that answers every `mcp__<server>__<tool>` name.

  ## Why this is not a `Jido.Action`

  Every other tool in this set is one, because every other tool has a schema known at
  compile time and `Jido.AI.ToolAdapter` turns that schema into the JSON Schema a model
  sees. An MCP tool's schema arrives from a stranger's process at run time, and there
  are as many of them as the configured servers advertise. A `Jido.Action` per MCP tool
  would mean generating modules — and therefore atoms — from a remote server's tool
  list, which is the shape of a memory leak somebody else controls.

  So `Ouroboros.Provider.Native.Tools` resolves an `mcp__…` name to `{__MODULE__, name}`
  and `Tools.execute/4` calls `run/3` with the name it resolved. That tuple is the whole
  dynamic-tools seam: the loop treats what `Tools.lookup/3` returns as opaque, so
  nothing outside `tools.ex` had to change to carry a name alongside a module.

  ## How a session's server is found, and killed

  The tool context carries `session_dir`, whose basename *is* the
  `provider_session_id` — `Ouroboros.Provider.Native.Paths.session_dir/1` builds it that
  way. Looking that id up in `Ouroboros.Provider.Native.Registry` gives the session
  process, which is handed to the pool as the claim owner. The pool monitors it, so the
  session ending releases the claim and the last claim released stops the child. No new
  field in the loop's context, and no timer standing in for a fact the runtime already
  knows.

  A session whose transport is not registered — a test driving `Tools.execute/4`
  directly, or a coding-plane run — resolves to `nil` owner, and then only the pool's
  idle clock stops the server. That is stated rather than hidden, because it is the one
  case where "killed on session end" is not literally true.
  """

  alias Ouroboros.Provider.Native.Mcp

  @registry Ouroboros.Provider.Native.Registry

  @doc "The name every MCP tool shares in classification and in errors."
  @spec name() :: String.t()
  def name, do: "mcp"

  @doc """
  Calls one MCP tool.

  Never raises: an unknown server, an unknown tool, a refusal, a timeout, and a server
  that died mid-call are all `is_error: true` results the model reads in band.
  """
  @spec run(String.t(), map(), map()) :: {:ok, %{output: String.t(), is_error: boolean()}}
  def run(tool_name, params, context) do
    opts = [
      workspace: workspace(context),
      owner: owner(context),
      timeout_ms: Map.get(context, :mcp_timeout_ms),
      pool: Map.get(context, :mcp_pool)
    ]

    {:ok, Mcp.call(tool_name, arguments(params), Enum.reject(opts, fn {_k, v} -> is_nil(v) end))}
  end

  # The model's arguments go to the server untouched. This client validates nothing
  # about them: the server owns the schema, and a second opinion here would only be able
  # to refuse calls the server would have accepted.
  defp arguments(params) when is_map(params), do: params
  defp arguments(_params), do: %{}

  defp workspace(context) do
    case context do
      %{scope: %{root: root}} when is_binary(root) -> root
      _absent -> nil
    end
  end

  # `Registry.lookup/2` rather than `Session.whereis/1`: the registry is named by an
  # atom and creates no module dependency, and `Tools` is already on the session's own
  # compile path.
  defp owner(%{session_dir: session_dir}) when is_binary(session_dir) do
    case Registry.lookup(@registry, Path.basename(session_dir)) do
      [{pid, _value} | _rest] -> pid
      _none -> nil
    end
  rescue
    ArgumentError -> nil
  end

  defp owner(_context), do: nil
end
