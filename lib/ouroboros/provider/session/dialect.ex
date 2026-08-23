defmodule Ouroboros.Provider.Session.Dialect do
  @moduledoc """
  Wire mapping for one interactive JSONL dialect.

  Every callback is required. A feature a dialect does not have still needs an
  explicit `{:error, :unsupported}` (or `:method_not_found` / `:skip`) so the next
  ACP implementation cannot leave a hole by omitting a function.
  """

  alias Jido.Harness.{
    ApprovalResponse,
    Event,
    InteractionCapabilities,
    SessionRequest,
    TurnRequest
  }

  @type runtime :: map()
  @type frame :: map()
  @type handshake_step :: {:notify, String.t(), map()} | {:open, String.t(), map()}

  @type action ::
          {:assign, map()}
          | {:emit, atom(), map(), keyword()}
          | {:emit_event, Event.t()}

  @type command ::
          {:ok, executable :: String.t(), argv :: [String.t()], env :: map()} | {:error, term()}

  @type interrupt ::
          {:request, String.t(), map()} | {:notify, String.t(), map()} | :skip | {:error, term()}

  @type approval :: {:approval, map(), map()} | :method_not_found | {:result, map()}

  # C4. The *second* inbound seam. `approval_request/2` is a provider asking permission
  # for something it will do itself; this is a provider asking Ouroboros to do the thing.
  # ACP is the one protocol here where the traffic runs both ways: an agent may call the
  # client for `fs/read_text_file`, `fs/write_text_file` and the five `terminal/*` verbs.
  # A dialect that serves none says so with `:method_not_found`, which is what the wire
  # already answers, so nothing about a one-way transport changes.
  @type service :: {:service, atom(), map()} | :method_not_found

  # C4. One correlated round trip the *runtime* starts, for the verbs that are neither a
  # turn nor an interrupt: `interactive.compact` on a Codex thread, `runtime.models` for a
  # live account, `interactive.configure`'s `mode` on ACP. `ask/3` builds the frame and
  # `answer/3` reads the result, so the wire mapping stays in the dialect and the
  # correlation stays in `Session.Jsonl` — the same split `steer/3` already uses, and for
  # the same reason: an id spent behind the session's back would be reused.
  @type verb :: :compact | :models | :set_mode
  @type ask :: {:request, String.t(), map()} | {:error, term()}

  @callback name() :: atom()
  @callback ready_kind() :: String.t()
  @callback unsupported_method_message() :: String.t()
  @callback capabilities() :: InteractionCapabilities.t()
  @callback command(SessionRequest.t(), map()) :: command()
  @callback envelope(frame()) :: frame()
  @callback initialize_params(SessionRequest.t()) :: map()
  @callback after_initialize(map(), SessionRequest.t(), runtime()) ::
              {:handshake, [handshake_step()]} | {:error, term()}
  @callback session_id(term()) :: String.t() | nil
  @callback start_turn(TurnRequest.t(), String.t(), runtime()) ::
              {:request, String.t(), map()} | {:error, term()}
  @callback interrupt(runtime()) :: interrupt()
  @callback close_signal(runtime()) :: interrupt()
  # `:ok` is a dialect that has already said everything it needs to. `{:request, …}` hands
  # the frame back to `Session.Jsonl` instead of writing it here, and that is the only
  # correct shape for a steer whose answer matters: the id comes from the session's own
  # counter and the response is correlated, where a dialect writing its own frame would
  # have to invent an id the session does not know it spent. `handle_rpc/3` then sees
  # `{:steer, request_id}`.
  @callback steer(runtime(), TurnRequest.t(), String.t()) ::
              :ok | {:request, String.t(), map()} | {:error, term()}
  @callback configure(runtime(), map()) :: :ok | {:error, term()}
  @callback ask(verb(), map(), runtime()) :: ask()
  @callback answer(verb(), map(), runtime()) :: term()
  @callback service_request(String.t(), map(), runtime()) :: service()
  @callback approval_request(String.t(), map()) :: approval()
  @callback approval_reply(ApprovalResponse.t(), map()) :: map()
  @callback deny_reply(map()) :: map()
  @callback handle_notification(String.t(), map(), frame(), runtime()) :: [action()]
  @callback handle_rpc(term(), frame(), runtime()) :: [action()]

  @callbacks [
    name: 0,
    ready_kind: 0,
    unsupported_method_message: 0,
    capabilities: 0,
    command: 2,
    envelope: 1,
    initialize_params: 1,
    after_initialize: 3,
    session_id: 1,
    start_turn: 3,
    interrupt: 1,
    close_signal: 1,
    steer: 3,
    configure: 2,
    ask: 3,
    answer: 3,
    service_request: 3,
    approval_request: 2,
    approval_reply: 2,
    deny_reply: 1,
    handle_notification: 4,
    handle_rpc: 3
  ]

  @doc "Raises unless `module` exports every dialect callback."
  @spec verify!(module()) :: :ok
  def verify!(module) when is_atom(module) do
    Code.ensure_loaded!(module)

    missing =
      Enum.reject(@callbacks, fn {name, arity} ->
        function_exported?(module, name, arity)
      end)

    if missing != [] do
      formatted = Enum.map_join(missing, ", ", fn {name, arity} -> "#{name}/#{arity}" end)

      raise ArgumentError,
            "#{inspect(module)} is not a complete session dialect; missing #{formatted}"
    end

    caps = module.capabilities()

    unless match?(%InteractionCapabilities{}, caps) do
      raise ArgumentError,
            "#{inspect(module)}.capabilities/0 must return InteractionCapabilities, got #{inspect(caps)}"
    end

    :ok
  end

  @doc "The callbacks a dialect must implement, as `{name, arity}` pairs."
  @spec callbacks() :: [{atom(), arity()}]
  def callbacks, do: @callbacks
end
