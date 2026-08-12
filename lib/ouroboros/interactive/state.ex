defmodule Ouroboros.Interactive.State do
  @moduledoc "Serializable domain state for one interactive coding session."

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.Event

  @session_options [
    :transport,
    :turn_runtime_timeout_ms,
    :turn_idle_timeout_ms,
    :session_idle_timeout_ms,
    :approval_timeout_ms
  ]

  @enforce_keys [
    :id,
    :node,
    :provider,
    :workspace,
    :workspace_mode,
    :status,
    :created_at,
    :updated_at
  ]
  defstruct @enforce_keys ++
              [
                :workspace_lease_id,
                :harness_session_id,
                :provider_session_id,
                cursor: 0,
                event_floor: 0,
                event_limit: 10_000,
                events: [],
                turns: %{},
                options: %{},
                error: nil
              ]

  @type status ::
          :starting
          | :idle
          | :running
          | :awaiting_approval
          | :closing
          | :closed
          | :failed
          | :cancelled
          | :lost

  @type turn_status ::
          :dispatching
          | :queued
          | :running
          | :finishing
          | :completed
          | :failed
          | :interrupted
          | :ambiguous

  @type turn :: %{
          required(:id) => String.t(),
          required(:mode) => :message | :follow_up,
          required(:fingerprint) => String.t(),
          required(:request) => map(),
          required(:status) => turn_status(),
          required(:created_at) => String.t(),
          required(:updated_at) => String.t(),
          optional(:harness_turn_id) => String.t() | nil,
          optional(:result) => map() | nil,
          optional(:error) => term()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          node: node(),
          provider: atom(),
          workspace: String.t(),
          workspace_mode: :shared_read | :exclusive,
          status: status(),
          created_at: String.t(),
          updated_at: String.t(),
          workspace_lease_id: String.t() | nil,
          harness_session_id: String.t() | nil,
          provider_session_id: String.t() | nil,
          cursor: non_neg_integer(),
          event_floor: non_neg_integer(),
          event_limit: pos_integer(),
          events: [Event.t()],
          turns: %{optional(String.t()) => turn()},
          options: map(),
          error: term()
        }

  @terminal_statuses [:closed, :failed, :cancelled, :lost]
  @terminal_turn_statuses [:completed, :failed, :interrupted, :ambiguous]

  @spec new(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(id, opts) when is_list(opts) do
    if Keyword.keyword?(opts) and unique_keys?(opts) do
      with :ok <- validate_session_options(opts),
           {:ok, base} <-
             TaskState.new(id, "interactive coding session", Keyword.drop(opts, @session_options)),
           :ok <- validate_serializable_options(opts) do
        now = timestamp()

        {:ok,
         %__MODULE__{
           id: id,
           node: node(),
           provider: base.provider,
           workspace: base.workspace,
           workspace_mode: base.workspace_mode,
           status: :starting,
           created_at: now,
           updated_at: now,
           event_limit: base.event_limit,
           options:
             base.options
             |> Map.merge(Map.new(Keyword.take(opts, @session_options)))
         }}
      end
    else
      {:error, :invalid_options}
    end
  end

  def new(_id, _opts), do: {:error, :invalid_options}

  @spec terminal?(t()) :: boolean()
  def terminal?(%__MODULE__{status: status}), do: status in @terminal_statuses

  @spec terminal_turn?(turn()) :: boolean()
  def terminal_turn?(%{status: status}), do: status in @terminal_turn_statuses

  @spec request(t()) :: map()
  def request(%__MODULE__{} = state) do
    state.options
    |> rename(:runtime_timeout_ms, :turn_runtime_timeout_ms)
    |> rename(:idle_timeout_ms, :turn_idle_timeout_ms)
    |> Map.drop([:attachments, :max_turns])
    |> Map.merge(%{
      cwd: state.workspace,
      metadata: %{
        ouroboros_session_id: state.id,
        ouroboros_node: Atom.to_string(state.node)
      }
    })
    |> reject_nil_values()
  end

  @spec new_turn(String.t(), :message | :follow_up, Jido.Harness.TurnRequest.t()) :: turn()
  def new_turn(id, mode, %Jido.Harness.TurnRequest{} = request) do
    request = request |> Map.from_struct() |> reject_nil_values()
    now = timestamp()

    %{
      id: id,
      mode: mode,
      fingerprint: fingerprint(mode, request),
      request: request,
      harness_turn_id: nil,
      status: :dispatching,
      result: nil,
      error: nil,
      created_at: now,
      updated_at: now
    }
  end

  @spec public(t()) :: t()
  def public(%__MODULE__{} = state) do
    options = %{
      approval_mode: Map.get(state.options, :approval_mode),
      sandbox_mode: Map.get(state.options, :sandbox_mode),
      model: Map.get(state.options, :model),
      reasoning_effort: Map.get(state.options, :reasoning_effort),
      transport: Map.get(state.options, :transport),
      has_system_prompt: present?(Map.get(state.options, :system_prompt)),
      has_provider_options: map_size(Map.get(state.options, :provider_options, %{}) || %{}) > 0
    }

    turns = Map.new(state.turns, fn {id, turn} -> {id, public_turn(turn)} end)
    %{state | options: options, turns: turns}
  end

  @spec public_turn(turn()) :: map()
  def public_turn(turn) do
    request = Map.get(turn, :request, %{})

    turn
    |> Map.drop([:fingerprint, :request])
    |> Map.put(:prompt, Map.get(request, :prompt))
    |> Jido.Harness.Redaction.redact()
  end

  @spec fingerprint(:message | :follow_up, map()) :: String.t()
  def fingerprint(mode, request) do
    :sha256
    |> :crypto.hash(:erlang.term_to_binary({mode, request}, [:deterministic]))
    |> Base.encode16(case: :lower)
  end

  @spec touch(t()) :: t()
  def touch(%__MODULE__{} = state), do: %{state | updated_at: timestamp()}

  @spec touch_turn(turn()) :: turn()
  def touch_turn(turn), do: %{turn | updated_at: timestamp()}

  @doc false
  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{} = state) do
    state.id |> valid_id?() and
      is_atom(state.node) and not is_nil(state.node) and
      is_atom(state.provider) and not is_nil(state.provider) and
      is_binary(state.workspace) and state.workspace != "" and
      state.workspace_mode in [:shared_read, :exclusive] and
      state.status in (@terminal_statuses ++
                         [:starting, :idle, :running, :awaiting_approval, :closing]) and
      is_binary(state.created_at) and is_binary(state.updated_at) and
      optional_id?(state.workspace_lease_id) and optional_id?(state.harness_session_id) and
      optional_id?(state.provider_session_id) and
      is_integer(state.cursor) and state.cursor >= 0 and
      is_integer(state.event_floor) and state.event_floor >= 0 and
      state.event_floor <= state.cursor and
      is_integer(state.event_limit) and state.event_limit > 0 and state.event_limit <= 100_000 and
      is_list(state.events) and length(state.events) <= state.event_limit and
      valid_events?(state.events, state) and valid_turns?(state.turns) and is_map(state.options) and
      serializable?(state.options) and serializable?(state.error)
  rescue
    _error -> false
  end

  def valid?(_state), do: false

  defp validate_session_options(opts) do
    accepted =
      @session_options ++
        [
          :id,
          :workspace,
          :workspace_mode,
          :provider,
          :event_limit,
          :model,
          :provider_session_id,
          :max_turns,
          :runtime_timeout_ms,
          :idle_timeout_ms,
          :system_prompt,
          :allowed_tools,
          :disallowed_tools,
          :add_dirs,
          :attachments,
          :reasoning_effort,
          :provider_options,
          :approval_mode,
          :sandbox_mode,
          :env,
          :env_mode,
          :mcp_config
        ]

    case Enum.find(Keyword.keys(opts), &(&1 not in accepted)) do
      nil -> :ok
      key -> {:error, {:unknown_option, key}}
    end
  end

  defp unique_keys?(opts) do
    keys = Keyword.keys(opts)
    Enum.uniq(keys) == keys
  end

  defp validate_serializable_options(opts) do
    if serializable?(Map.new(opts)), do: :ok, else: {:error, :non_serializable_options}
  end

  defp serializable?(value)
       when is_pid(value) or is_port(value) or is_reference(value) or is_function(value),
       do: false

  defp serializable?(value) when is_struct(value),
    do: value |> Map.from_struct() |> serializable?()

  defp serializable?(value) when is_map(value),
    do: Enum.all?(value, fn {key, nested} -> serializable?(key) and serializable?(nested) end)

  defp serializable?(value) when is_list(value), do: Enum.all?(value, &serializable?/1)

  defp serializable?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(_value), do: true

  defp valid_events?(events, state) do
    sequences = Enum.map(events, &Map.get(&1, :sequence))

    Enum.all?(events, fn
      %Event{
        id: event_id,
        session_id: id,
        sequence: sequence,
        type: type,
        timestamp: timestamp,
        payload: payload
      } = event
      when id == state.id and is_binary(event_id) and byte_size(event_id) > 0 and
             is_integer(sequence) and sequence > 0 and is_atom(type) and is_binary(timestamp) ->
        optional_id?(event.harness_session_id) and
          (is_nil(event.provider) or is_atom(event.provider)) and
          optional_id?(event.provider_session_id) and optional_id?(event.turn_id) and
          optional_id?(event.request_id) and serializable?(payload) and serializable?(event)

      _event ->
        false
    end) and sequences == Enum.sort(sequences) and Enum.uniq(sequences) == sequences and
      Enum.all?(sequences, &(&1 <= state.cursor)) and
      case sequences do
        [] -> true
        [first | _rest] -> first > state.event_floor
      end
  end

  defp valid_turns?(turns) when is_map(turns) do
    Enum.all?(turns, fn
      {id,
       %{
         id: id,
         mode: mode,
         fingerprint: fingerprint,
         request: request,
         status: status,
         created_at: created_at,
         updated_at: updated_at
       } = turn}
      when is_binary(id) and byte_size(id) > 0 and mode in [:message, :follow_up] and
             is_binary(fingerprint) and byte_size(fingerprint) > 0 and is_map(request) and
             status in [
               :dispatching,
               :queued,
               :running,
               :finishing,
               :completed,
               :failed,
               :interrupted,
               :ambiguous
             ] and is_binary(created_at) and is_binary(updated_at) ->
        optional_id?(Map.get(turn, :harness_turn_id)) and serializable?(request) and
          serializable?(Map.get(turn, :result)) and serializable?(Map.get(turn, :error))

      _turn ->
        false
    end)
  end

  defp valid_turns?(_turns), do: false

  defp valid_id?(id), do: is_binary(id) and String.trim(id) != ""
  defp optional_id?(nil), do: true
  defp optional_id?(id), do: valid_id?(id)

  defp rename(map, old, new) do
    case Map.pop(map, old) do
      {nil, map} -> map
      {value, map} -> Map.put_new(map, new, value)
    end
  end

  defp reject_nil_values(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)
  defp present?(value), do: value not in [nil, "", [], %{}]
  defp timestamp, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
