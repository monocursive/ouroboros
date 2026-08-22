defmodule Ouroboros.Interactive.State do
  @moduledoc "Serializable domain state for one interactive coding session."

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.Event
  alias Ouroboros.Prompt.Trace

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
                prompt_trace: nil,
                runtime_snapshot: nil,
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
          prompt_trace: map() | nil,
          runtime_snapshot: map() | nil,
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
             TaskState.new(
               id,
               "interactive coding session",
               Keyword.drop(opts, @session_options),
               # The transport decides which normalized options a session may carry, so
               # the capability lookup needs the one this session will select. It is a
               # session option and therefore dropped from the base's own options.
               {:interactive, Keyword.get(opts, :transport)}
             ),
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
           prompt_trace: Map.get(base, :prompt_trace),
           runtime_snapshot: Map.get(base, :runtime_snapshot),
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
    prompt_trace = Map.get(state, :prompt_trace)

    metadata =
      %{
        ouroboros_session_id: state.id,
        ouroboros_node: Atom.to_string(state.node)
      }
      |> Trace.put(prompt_trace, :ouroboros_prompt)

    state.options
    |> Map.delete(:agent_profile)
    |> Map.delete(:runtime_exposure)
    |> rename(:runtime_timeout_ms, :turn_runtime_timeout_ms)
    |> rename(:idle_timeout_ms, :turn_idle_timeout_ms)
    |> Map.drop([:attachments, :max_turns])
    |> Map.merge(%{
      cwd: state.workspace,
      metadata: metadata
    })
    |> reject_nil_values()
    |> Ouroboros.Provider.apply_runtime_provider_policy(state.provider)
    |> Ouroboros.Provider.apply_execution_directories(state.provider, :session)
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
    prompt_trace = Map.get(state, :prompt_trace)

    options =
      %{
        approval_mode: Map.get(state.options, :approval_mode),
        sandbox_mode: Map.get(state.options, :sandbox_mode),
        model: Map.get(state.options, :model),
        reasoning_effort: Map.get(state.options, :reasoning_effort),
        transport: Map.get(state.options, :transport),
        has_system_prompt:
          projected(
            state.options,
            :has_system_prompt,
            present?(Map.get(state.options, :system_prompt))
          ),
        has_provider_options:
          projected(
            state.options,
            :has_provider_options,
            map_size(Map.get(state.options, :provider_options, %{}) || %{}) > 0
          ),
        provider_execution:
          projected(
            state.options,
            :provider_execution,
            Ouroboros.Provider.public_execution_policy(
              state.provider,
              Map.get(state.options, :provider_options),
              surface: :interactive,
              transport: Map.get(state.options, :transport)
            )
          ),
        # Derived from the provider spec at projection time rather than stored, so a
        # session listed after a restart declares what its transport can do without a
        # coordinator being up to ask. `nil` where the provider or transport does not
        # resolve — an absent claim rather than a false one.
        capabilities:
          projected(
            state.options,
            :capabilities,
            Ouroboros.Provider.session_capabilities(
              state.provider,
              Map.get(state.options, :transport)
            )
          )
      }
      |> Trace.put(prompt_trace)

    turns = Map.new(state.turns, fn {id, turn} -> {id, public_turn(turn)} end)

    state
    |> Map.put(:runtime_snapshot, nil)
    |> Map.put(:options, options)
    |> Map.put(:turns, turns)
  end

  @spec public_turn(turn()) :: map()
  def public_turn(turn) do
    case Map.fetch(turn, :request) do
      {:ok, request} ->
        turn
        |> Map.drop([:fingerprint, :request])
        |> Map.put(:prompt, Map.get(request, :prompt))
        |> Jido.Harness.Redaction.redact()

      :error ->
        Jido.Harness.Redaction.redact(turn)
    end
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
  def valid?(state), do: loadable?(state) and requestable?(state)

  @doc """
  Returns why a reconstructed session cannot build a Harness request, or `nil`.

  Separate from `valid?/1` so a session whose durable prompt this build cannot honour
  fails as itself, at the moment it would be handed to the provider, rather than
  condemning every session that shares its checkpoint.
  """
  @spec unrequestable_reason(term()) :: term() | nil
  def unrequestable_reason(%__MODULE__{options: options} = state) when is_map(options) do
    system_prompt = Map.get(options, :system_prompt)

    cond do
      Map.has_key?(options, :agent_profile) ->
        :agent_profile_in_durable_options

      not valid_system_prompt?(system_prompt) ->
        :invalid_system_prompt

      not valid_runtime_snapshot?(state) ->
        :invalid_runtime_snapshot

      true ->
        case Trace.validate(Map.get(state, :prompt_trace), system_prompt) do
          :ok -> nil
          {:error, reason} -> reason
        end
    end
  rescue
    error -> {:invalid_session_state, error.__struct__}
  catch
    kind, _reason -> {:invalid_session_state, kind}
  end

  def unrequestable_reason(_state), do: :invalid_session_state

  @doc "Returns whether a reconstructed session can safely build a Harness request."
  @spec requestable?(term()) :: boolean()
  def requestable?(state), do: unrequestable_reason(state) == nil

  # A terminal session never builds another request, and refusing to write one would
  # leave a session that stopped satisfying `requestable?/1` mid-run with no way to
  # record its own honest ending.
  @doc "Returns whether a session may be written to durable storage."
  @spec storable?(term()) :: boolean()
  def storable?(%__MODULE__{} = state),
    do: loadable?(state) and (terminal?(state) or requestable?(state))

  def storable?(_state), do: false

  @doc """
  Returns whether a checkpointed session is sound enough to be loaded.

  This is shape and serializability: identifiers, statuses, event and turn structure,
  no runtime authority smuggled into durable state. It deliberately says nothing about
  whether the session's prompt can be reproduced — that question belongs to
  `requestable?/1`, and answering it at load would let one session veto the boot of
  every other session in the same checkpoint.
  """
  @spec loadable?(term()) :: boolean()
  def loadable?(%__MODULE__{} = state) do
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
      serializable?(state.options) and serializable?(Map.get(state, :runtime_snapshot)) and
      serializable?(state.error)
  rescue
    _error -> false
  end

  def loadable?(_state), do: false

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
          :agent_profile,
          :allowed_tools,
          :disallowed_tools,
          :add_dirs,
          :attachments,
          :reasoning_effort,
          :provider_options,
          :approval_mode,
          :sandbox_mode,
          :runtime_exposure,
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

  @doc """
  Returns a term safe to checkpoint, with runtime authority rendered as text.

  Redaction removes secrets but keeps pids: a harness call exit reason carries the
  process it was calling. A session that checkpointed one was refused by the store on
  every attempt, forever, over an error term that was only ever meant to be read.
  """
  @spec durable_term(term()) :: term()
  def durable_term(term)
      when is_pid(term) or is_port(term) or is_reference(term) or is_function(term),
      do: inspect(term)

  def durable_term(%module{} = term) do
    term |> Map.from_struct() |> Map.new(&durable_pair/1) |> then(&struct(module, &1))
  end

  def durable_term(term) when is_map(term), do: Map.new(term, &durable_pair/1)
  def durable_term(term) when is_list(term), do: Enum.map(term, &durable_term/1)

  def durable_term(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.map(&durable_term/1) |> List.to_tuple()

  def durable_term(term), do: term

  defp durable_pair({key, value}), do: {durable_term(key), durable_term(value)}

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

  defp projected(options, key, fallback) do
    if Map.has_key?(options, key), do: Map.get(options, key), else: fallback
  end

  defp timestamp, do: DateTime.utc_now() |> DateTime.to_iso8601()

  defp valid_system_prompt?(prompt),
    do: is_nil(prompt) or (is_binary(prompt) and String.valid?(prompt))

  defp valid_runtime_snapshot?(%__MODULE__{options: options} = state) do
    case Map.get(options, :runtime_exposure, true) do
      true -> Ouroboros.Runtime.Exposure.valid_capture?(Map.get(state, :runtime_snapshot))
      false -> is_nil(Map.get(state, :runtime_snapshot))
    end
  end
end
