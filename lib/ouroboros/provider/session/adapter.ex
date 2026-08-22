defmodule Ouroboros.Provider.Session.Adapter do
  @moduledoc false

  alias Jido.Harness.Event
  alias Ouroboros.Provider.Session.Jsonl

  @startup_timeout 30_000

  defmacro __using__(opts) do
    dialect = Keyword.fetch!(opts, :dialect)

    quote do
      @behaviour Jido.Harness.SessionAdapter

      @doc """
      The dialect this adapter runs.

      An upstream `SessionTransportSpec` keeps its own `capabilities` when
      `Ouroboros.Provider.Session.upgrade_acp/1` repoints it here, so the declaration
      and the code that answers the wire can drift apart. This is the link that lets
      `Ouroboros.Provider.Session.capabilities/1` read the dialect instead of the
      declaration it replaced.
      """
      @spec __dialect__() :: module()
      def __dialect__, do: unquote(dialect)

      @impl true
      def open(request, context),
        do: unquote(__MODULE__).open(unquote(dialect), request, context)

      @impl true
      def send(handle, request, turn_id),
        do: Jido.Harness.SessionAdapter.call(handle, {:send, request, turn_id})

      @impl true
      def interrupt(handle, turn_id),
        do: Jido.Harness.SessionAdapter.call(handle, {:interrupt, turn_id})

      @impl true
      def respond_approval(handle, request_id, response),
        do: Jido.Harness.SessionAdapter.call(handle, {:respond_approval, {request_id, response}})

      @impl true
      def close(handle), do: Jido.Harness.SessionAdapter.call(handle, :close)
    end
  end

  @spec open(module(), Jido.Harness.SessionRequest.t(), map()) :: {:ok, pid()} | {:error, term()}
  def open(dialect, request, context) do
    case DynamicSupervisor.start_child(
           Jido.Harness.SessionTransportSupervisor,
           {Jsonl, {dialect, request, context}}
         ) do
      {:ok, pid} ->
        case Jido.Harness.SessionAdapter.call(pid, {:initialize, request}, @startup_timeout) do
          {:ok, provider_session_id} ->
            Jido.Harness.SessionAdapter.emit(
              context.owner,
              Event.new!(
                type: :provider_event,
                provider: context.provider,
                provider_session_id: provider_session_id,
                payload: %{"kind" => dialect.ready_kind()}
              )
            )

            {:ok, pid}

          {:error, _reason} = error ->
            DynamicSupervisor.terminate_child(Jido.Harness.SessionTransportSupervisor, pid)
            error
        end

      {:error, _reason} = error ->
        error
    end
  catch
    :exit, reason -> {:error, reason}
  end
end
