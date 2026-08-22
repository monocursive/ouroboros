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
                # D7. Mirrors `Ouroboros.Coding.TaskState`: the request, then the record.
                worktree_requested: false,
                worktree: nil,
                cursor: 0,
                sequence_offset: 0,
                resumes: 0,
                event_floor: 0,
                event_limit: 10_000,
                events: [],
                turns: %{},
                prompt_trace: nil,
                runtime_snapshot: nil,
                usage: nil,
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
          worktree_requested: boolean(),
          worktree: map() | nil,
          harness_session_id: String.t() | nil,
          provider_session_id: String.t() | nil,
          cursor: non_neg_integer(),
          sequence_offset: non_neg_integer(),
          resumes: non_neg_integer(),
          event_floor: non_neg_integer(),
          event_limit: pos_integer(),
          events: [Event.t()],
          turns: %{optional(String.t()) => turn()},
          prompt_trace: map() | nil,
          runtime_snapshot: map() | nil,
          usage: usage() | nil,
          options: map(),
          error: term()
        }

  @typedoc """
  What the provider said this session has spent. Numbers only, and only numbers a
  provider actually reported: a counter no `:usage` event carried stays `0`, and
  `cost_usd` stays `nil` rather than becoming a zero that reads like "free".
  """
  @type usage :: %{
          required(:input_tokens) => non_neg_integer(),
          required(:output_tokens) => non_neg_integer(),
          required(:cache_read_tokens) => non_neg_integer(),
          required(:cache_creation_tokens) => non_neg_integer(),
          required(:total_tokens) => non_neg_integer(),
          required(:cost_usd) => number() | nil,
          required(:turns_with_usage) => non_neg_integer(),
          required(:last) => map()
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
           worktree_requested: Map.get(base, :worktree_requested, false),
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
    |> put_provider_session_id(state.provider_session_id)
    |> reject_nil_values()
    |> Ouroboros.Provider.apply_runtime_provider_policy(state.provider)
    |> Ouroboros.Provider.apply_execution_directories(state.provider, :session)
  end

  # The provider session id a session learned from its own events is the one that can
  # resume it, and it lives on the struct rather than in the start options. A request
  # rebuilt to resume therefore has to carry it explicitly; a session that never learned
  # one keeps whatever the caller stated at start, which is nothing in the normal case.
  defp put_provider_session_id(request, id) when is_binary(id) and id != "",
    do: Map.put(request, :provider_session_id, id)

  defp put_provider_session_id(request, _id), do: request

  @doc """
  Returns the durable offset between this session's event sequence and its Harness one.

  Ouroboros event sequences are strictly monotonic for the life of a session, and a
  resumed session's Harness log starts counting from one again. The offset is what keeps
  those two number spaces reconcilable: `ouroboros = harness + offset`. Zero until the
  first resume, and read defensively so a checkpoint written before this field existed
  loads as the session it was.
  """
  @spec sequence_offset(t()) :: non_neg_integer()
  def sequence_offset(%__MODULE__{} = state), do: Map.get(state, :sequence_offset, 0) || 0

  @doc "Returns how many times this session has been resumed onto a new Harness session."
  @spec resumes(t()) :: non_neg_integer()
  def resumes(%__MODULE__{} = state), do: Map.get(state, :resumes, 0) || 0

  @doc """
  Returns whether this session could be resumed onto a new Harness session, or why not.

  Two facts have to hold: the session knows the provider's own session id, and the
  transport this session will select can carry it. The second is asked of the transport
  rather than the adapter because that is the list the Harness session manager validates
  a start request against — a transport that does not declare `:provider_session_id`
  refuses the request, and refusing here first keeps `:lost` reasons honest instead of
  turning every unsupported transport into a start failure.

  This deliberately does not promise that the *provider* still has the session: only the
  provider can answer that, and it answers by accepting or refusing the resume.
  """
  @spec resume_support(t()) :: :ok | {:error, term()}
  def resume_support(%__MODULE__{provider_session_id: id}) when not is_binary(id),
    do: {:error, :no_provider_session_id}

  def resume_support(%__MODULE__{} = state) do
    with {:ok, spec} <- Jido.Harness.Registry.spec(state.provider),
         true <- spec.capabilities.resume? || {:error, :provider_does_not_resume},
         {:ok, options} <- session_options(spec, Map.get(state.options, :transport)) do
      if :provider_session_id in options,
        do: :ok,
        else: {:error, :transport_cannot_carry_provider_session_id}
    else
      {:error, _reason} = error -> error
      :error -> {:error, :unknown_session_transport}
    end
  end

  def resume_support(_state), do: {:error, :invalid_session_state}

  # Mirrors the transport resolution `Ouroboros.Provider` performs for safety options.
  # It is asked here for a different question — can this transport carry a resume id —
  # and answering it there would make one private helper serve two unrelated refusals.
  defp session_options(spec, transport) do
    selected = transport || spec.default_session_transport || first_transport(spec)

    case Enum.find(spec.session_transports, &(&1.name == selected)) do
      %{session_options: :adapter} -> {:ok, spec.normalized_options}
      %{session_options: options} when is_list(options) -> {:ok, options}
      nil when selected == :managed -> {:ok, spec.normalized_options}
      _unresolvable -> :error
    end
  end

  defp first_transport(spec) do
    case spec.session_transports do
      [transport | _rest] -> transport.name
      [] -> :managed
    end
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

  @doc """
  Folds what a provider reported spending into the session's durable usage account.

  Reads `:usage` events for token counters and `:run_completed` for `cost_usd`, which is
  the only event any bundled provider puts a cost on (`claude_stream.ex:61-71`). Provider
  key spellings vary — `input_tokens`, `inputTokens`, `input`, `prompt_tokens` all mean
  the same number — so each counter is looked up through a list of known variants and a
  payload that carries none of them contributes nothing at all rather than a zero.

  ## Why a turn's reports replace rather than add

  Transports disagree about what a usage event means. Claude emits one per turn holding
  that turn's totals; Codex app-server sends `thread/tokenUsage/updated` repeatedly, and
  the name says it is a value being updated rather than a delta. Adding both shapes would
  multiply the Codex numbers by however many times it happened to report. So within one
  `turn_id` each counter keeps the **largest** figure that turn reported, and only
  distinct turns are added together. This cannot inflate a total past the provider's own
  largest claim for that turn; it would under-count only a transport that reported true
  per-turn deltas, which none of the bundled ones does.

  Bounded: one map, whatever the turn count. Durable through the caller's checkpoint.
  """
  @spec fold_usage(t(), [Event.t()]) :: t()
  def fold_usage(%__MODULE__{} = state, events) when is_list(events) do
    Enum.reduce(events, state, &fold_usage_event/2)
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
      is_integer(sequence_offset(state)) and sequence_offset(state) >= 0 and
      sequence_offset(state) <= state.cursor and
      is_integer(resumes(state)) and resumes(state) >= 0 and
      is_integer(state.event_floor) and state.event_floor >= 0 and
      state.event_floor <= state.cursor and
      is_integer(state.event_limit) and state.event_limit > 0 and state.event_limit <= 100_000 and
      is_list(state.events) and length(state.events) <= state.event_limit and
      valid_events?(state.events, state) and valid_turns?(state.turns) and is_map(state.options) and
      serializable?(state.options) and serializable?(Map.get(state, :runtime_snapshot)) and
      serializable?(Map.get(state, :usage)) and serializable?(state.error) and
      valid_worktree?(state)
  rescue
    _error -> false
  end

  def loadable?(_state), do: false

  # D7's durable half, held to the same rule as everything else here: shape and
  # serializability. A worktree record is a map of strings, or it is `nil`.
  defp valid_worktree?(state) do
    is_boolean(Map.get(state, :worktree_requested, false)) and
      case Map.get(state, :worktree) do
        nil -> true
        record when is_map(record) -> serializable?(record)
        _other -> false
      end
  end

  defp validate_session_options(opts) do
    accepted =
      @session_options ++
        [
          :id,
          :workspace,
          :workspace_mode,
          :worktree,
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

  # The counters a session accounts for, each with the spellings a provider may use.
  # Claude sends `input_tokens` and `cache_read_input_tokens`; the Codex app-server and
  # ACP payloads are their server's own map passed through untouched; Harness's own
  # adapter fixtures carry `input` and `totalTokens`. So each counter is a list of keys,
  # not a key, and the first one present wins.
  @usage_counters [
    input_tokens: ~w(input_tokens inputTokens input prompt_tokens promptTokens),
    output_tokens: ~w(output_tokens outputTokens output completion_tokens completionTokens),
    cache_read_tokens:
      ~w(cache_read_tokens cache_read_input_tokens cacheReadTokens cacheReadInputTokens cached_input_tokens cachedInputTokens),
    cache_creation_tokens:
      ~w(cache_creation_tokens cache_creation_input_tokens cacheCreationTokens cacheCreationInputTokens),
    total_tokens: ~w(total_tokens totalTokens total)
  ]

  @usage_counter_fields Keyword.keys(@usage_counters)
  @usage_cost_keys ~w(cost_usd costUsd total_cost_usd totalCostUsd)

  @empty_usage %{
    input_tokens: 0,
    output_tokens: 0,
    cache_read_tokens: 0,
    cache_creation_tokens: 0,
    total_tokens: 0,
    cost_usd: nil,
    turns_with_usage: 0,
    last: %{}
  }

  # `:run_completed` is here for one field: no bundled provider puts a cost on a `:usage`
  # event, and Claude's arrives as `cost_usd` on the run's terminator. Reading only
  # `:usage` would ship a `cost_usd` that is structurally always `nil`.
  defp fold_usage_event(%Event{type: type, payload: payload, turn_id: turn_id}, state)
       when type in [:usage, :run_completed] and is_map(payload) do
    case reported_usage(payload) do
      nil -> state
      reported -> Map.put(state, :usage, account_usage(Map.get(state, :usage), reported, turn_id))
    end
  end

  defp fold_usage_event(_event, state), do: state

  defp reported_usage(payload) do
    counters =
      Enum.reduce(@usage_counters, %{}, fn {field, keys}, acc ->
        case usage_number(payload, keys) do
          nil -> acc
          value -> Map.put(acc, field, value)
        end
      end)

    cost = usage_number(payload, @usage_cost_keys)

    if counters == %{} and is_nil(cost) do
      nil
    else
      counters
      |> Map.put(:cost_usd, cost)
      |> Map.put_new_lazy(:total_tokens, fn ->
        Map.get(counters, :input_tokens, 0) + Map.get(counters, :output_tokens, 0)
      end)
    end
  end

  # A negative or non-numeric figure is not a count of anything. Skipping it leaves the
  # counter as whatever a provider did report rather than moving a total backwards.
  defp usage_number(payload, keys) do
    Enum.find_value(keys, fn key ->
      case Map.get(payload, key) do
        value when is_number(value) and value >= 0 -> value
        _absent_or_unusable -> nil
      end
    end)
  end

  defp account_usage(usage, reported, turn_id) do
    usage = usage || @empty_usage
    previous = Map.get(usage, :last) || %{}
    same_turn? = is_binary(turn_id) and turn_id != "" and Map.get(previous, :turn_id) == turn_id

    {contribution, replaced} =
      if same_turn?, do: {max_usage(previous, reported), previous}, else: {reported, %{}}

    counters =
      Map.new(@usage_counter_fields, fn field ->
        {field,
         Map.get(usage, field, 0) - Map.get(replaced, field, 0) + Map.get(contribution, field, 0)}
      end)

    usage
    |> Map.merge(counters)
    |> Map.put(
      :cost_usd,
      account_cost(
        Map.get(usage, :cost_usd),
        Map.get(replaced, :cost_usd),
        Map.get(contribution, :cost_usd)
      )
    )
    |> Map.put(
      :turns_with_usage,
      Map.get(usage, :turns_with_usage, 0) + if(same_turn?, do: 0, else: 1)
    )
    |> Map.put(:last, Map.put(contribution, :turn_id, turn_id))
  end

  defp max_usage(previous, reported) do
    Map.merge(previous, reported, fn
      :turn_id, kept, _new -> kept
      _field, kept, new when is_number(kept) and is_number(new) -> max(kept, new)
      _field, nil, new -> new
      _field, kept, nil -> kept
      _field, _kept, new -> new
    end)
  end

  # A provider that never priced the work leaves this `nil` rather than `0.0`: a zero
  # here would read as "this session was free", which is a claim no payload made.
  defp account_cost(total, _replaced, nil), do: total

  defp account_cost(total, replaced, contributed),
    do: (total || 0) - (replaced || 0) + contributed

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
