defmodule Ouroboros.Provider.Session do
  @moduledoc """
  Interactive JSONL session dialects, so a new ACP provider cannot omit a feature by
  forgetting an optional callback.

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
    [Dialect.ACP]
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

  @doc """
  Asks the transport serving one harness session for a correlated round trip.

  C4. The three verbs the pinned harness has no vocabulary for — a Codex
  `thread/compact/start`, a live `model/list`, an ACP `session/set_mode` — reach the wire
  through here and nowhere else. `Jido.Harness.Session` exposes the session *worker*, and
  the worker's own `configure` path validates against a four-key `SessionRequest` before
  the transport is ever consulted, so a verb outside that vocabulary cannot travel on it.

  Two refusals, and they mean different things — the same split
  `Ouroboros.Interactive.Task`'s `native_transport/2` makes. `:unsupported` is the
  dialect saying its protocol has no such frame, which no amount of waiting changes.
  `provider_transport_unavailable` is a liveness answer: the verb exists, this session's
  transport is not up, and retrying is sensible.
  """
  @spec ask(term(), atom(), map(), timeout()) :: {:ok, term()} | {:error, term()}
  def ask(harness_session_id, verb, args \\ %{}, timeout \\ 30_000)

  def ask(harness_session_id, verb, args, timeout) when is_binary(harness_session_id) do
    case Ouroboros.Provider.Session.Jsonl.whereis(harness_session_id) do
      pid when is_pid(pid) ->
        Ouroboros.Provider.Session.Jsonl.ask(pid, verb, args, timeout)

      nil ->
        {:error, transport_unavailable(verb, :no_live_transport)}
    end
  end

  def ask(_harness_session_id, verb, _args, _timeout),
    do: {:error, transport_unavailable(verb, :not_started)}

  defp transport_unavailable(verb, reason) do
    {:provider_transport_unavailable,
     %{
       verb: verb,
       reason: reason,
       message:
         "this session has no live provider transport to ask; send a turn first, or " <>
           "reopen the session."
     }}
  end
end
