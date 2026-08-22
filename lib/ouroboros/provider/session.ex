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
end
