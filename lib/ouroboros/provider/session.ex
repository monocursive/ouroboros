defmodule Ouroboros.Provider.Session do
  @moduledoc """
  Interactive JSONL session dialects, so a new ACP (or app-server) provider cannot
  omit a feature by forgetting an optional callback.

  `Jido.Harness.SessionAdapter` is the process boundary the planes already call.
  Its optional `respond_approval` / `steer` / `configure` callbacks are exactly how
  a copy-pasted ACP transport silently drops a modal. Elixir `defprotocol` would not
  help: protocols dispatch on a struct type, and a live session is a process.

  The contract here is a **required-callback behaviour** (`Dialect`) plus one
  **JSONL runtime** that owns process lifecycle, pending RPC, method-not-found,
  and declining in-flight approvals on close. A dialect supplies only the wire
  mapping. Adding a feature means adding a callback; every listed dialect fails
  compile (or `Dialect.verify!/1`) until it answers.
  """

  alias Ouroboros.Provider.Session.Dialect

  @doc "Every JSONL dialect this runtime ships. Completeness tests walk this list."
  @spec dialects() :: [module()]
  def dialects do
    [Dialect.Codex, Dialect.ACP]
  end

  @doc "Points an upstream ACP `SessionTransportSpec` at this runtime's adapter."
  @spec upgrade_acp(Jido.Harness.AdapterSpec.t()) :: Jido.Harness.AdapterSpec.t()
  def upgrade_acp(%{session_transports: transports} = spec) do
    %{spec | session_transports: Enum.map(transports, &upgrade_transport/1)}
  end

  defp upgrade_transport(%{name: :acp} = transport),
    do: %{transport | adapter: Ouroboros.Provider.Session.ACP}

  defp upgrade_transport(transport), do: transport

  @doc """
  What a transport can actually do, once this runtime owns the code that answers it.

  `upgrade_acp/1` replaces an upstream transport's *adapter* and leaves its
  `capabilities` declaration alone, so for an upgraded transport the spec describes
  the implementation Ouroboros removed. Where a dialect drives the wire, the dialect's
  own `capabilities/0` is the truth; every other transport keeps the declaration its
  adapter shipped with.
  """
  @spec capabilities(Jido.Harness.SessionTransportSpec.t()) ::
          Jido.Harness.InteractionCapabilities.t()
  def capabilities(%{adapter: adapter, capabilities: declared}) do
    case dialect(adapter) do
      nil -> declared
      dialect -> dialect.capabilities()
    end
  end

  @doc "The dialect a session adapter runs, or `nil` for an adapter this runtime does not own."
  @spec dialect(module()) :: module() | nil
  def dialect(adapter) when is_atom(adapter) and not is_nil(adapter) do
    if Code.ensure_loaded?(adapter) and function_exported?(adapter, :__dialect__, 0),
      do: adapter.__dialect__()
  end

  def dialect(_adapter), do: nil
end
