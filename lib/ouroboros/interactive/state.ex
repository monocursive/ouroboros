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
    :approval_timeout_ms,
    # B2. Plan mode is this plane's option — `request/1` folds it into `provider_options`
    # for the adapters that read it — and not a coding-task option the base would refuse.
    :plan
  ]

  # Start options that land on the struct rather than in `options`. `forked_from` and
  # `handed_off_from` are relationships between two sessions, not something the provider
  # is ever told; putting either in `options` would send it to `State.request/1` and on to
  # a harness that never asked.
  @struct_options [:forked_from, :handed_off_from]

  # What `configure/2` may write into a session's durable options. Deliberately a literal
  # rather than a read of `Ouroboros.Provider`: this is the storage rule, and it holds
  # even if a capability check somewhere else is ever wrong.
  @configurable_options [:approval_mode, :sandbox_mode, :model, :reasoning_effort, :plan]

  # A session title is drawn into one picker row on every list, so it is bounded where it
  # is written rather than by every client that draws it. An auto-title is shorter still:
  # it is a guess from one prompt, and a guess that filled the row would crowd out the
  # workspace and machine a person actually picks by.
  @max_title_chars 120
  @auto_title_chars 60

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
                :title,
                :forked_from,
                # D9. The durable half of a handoff, held apart from `forked_from`
                # because they are different claims: a fork carries the parent's
                # conversation, a handoff carries a curated packet *about* it.
                :handed_off_from,
                title_source: nil,
                forks: 0,
                # G1. What this conversation delegated, keyed by delegation id. Bounded
                # by construction: a picker draws these, and a session that delegated
                # five hundred times is a session whose rail row must still fit.
                delegations: %{},
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

  @typedoc """
  Who named this session. `nil` until something did.

  The distinction is the whole point of storing it: an auto-title is a guess the runtime
  made from the first prompt and any later prompt could improve it, while a `:human` title
  is a decision, and nothing this runtime does may overwrite one.
  """
  @type title_source :: :auto | :human | nil

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
          title: String.t() | nil,
          title_source: title_source(),
          forked_from: String.t() | nil,
          handed_off_from: String.t() | nil,
          forks: non_neg_integer(),
          delegations: %{optional(String.t()) => delegation()},
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
          required(:context_window) => non_neg_integer() | nil,
          required(:context_used) => non_neg_integer() | nil,
          required(:last) => map()
        }

  @typedoc """
  One delegation this conversation started.

  Ids and a status, and never the objective's text: the objective is the child task's own
  durable record, and copying it here would put one plane's content in the other's
  checkpoint. `status` is a hint that follows the team's own record — `interactive.delegations`
  reads the authority, and this is what a rail row can draw without asking.
  """
  @type delegation :: %{
          required(:id) => String.t(),
          required(:team_id) => String.t(),
          required(:task_id) => String.t(),
          required(:task_node) => node(),
          required(:objective_digest) => String.t(),
          required(:status) => atom(),
          required(:created_at) => String.t(),
          required(:updated_at) => String.t(),
          optional(:result_digest) => String.t() | nil
        }

  # One conversation's delegations, bounded where they are written. A session that
  # delegated past this is refused a new one rather than silently forgetting an old one:
  # dropping the oldest would lose the link to a child task that is still running.
  @max_delegations 100

  @terminal_statuses [:closed, :failed, :cancelled, :lost]
  @terminal_turn_statuses [:completed, :failed, :interrupted, :ambiguous]

  @spec new(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(id, opts) when is_list(opts) do
    if Keyword.keyword?(opts) and unique_keys?(opts) do
      with :ok <- validate_session_options(opts),
           :ok <- validate_parent(Keyword.get(opts, :forked_from)),
           :ok <- validate_parent(Keyword.get(opts, :handed_off_from)),
           {:ok, base} <-
             TaskState.new(
               id,
               "interactive coding session",
               Keyword.drop(opts, @session_options ++ @struct_options),
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
           # Immutable start intent, like the workspace: which session this one branched
           # from is not something a fork can be talked out of afterwards.
           forked_from: Keyword.get(opts, :forked_from),
           handed_off_from: Keyword.get(opts, :handed_off_from),
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
    |> fold_plan_option()
    |> Map.merge(%{
      cwd: state.workspace,
      metadata: metadata
    })
    |> put_provider_session_id(state.provider_session_id)
    |> reject_nil_values()
    |> Ouroboros.Provider.apply_runtime_provider_policy(state.provider)
    |> Ouroboros.Provider.apply_execution_directories(state.provider, :session)
  end

  # B2. `plan` is a session option on the wire and a provider option underneath: the
  # native session and the Claude adapter read `provider_options.plan`, and the pinned
  # Harness request has no field of its own for it (a fifth `approval_mode` is refused by
  # the dependency). A session started planning therefore carries it where the adapters
  # look; one that is not carries nothing, so the request stays byte-identical to before.
  defp fold_plan_option(%{plan: true} = request) do
    provider_options = Map.get(request, :provider_options) || %{}

    request
    |> Map.delete(:plan)
    |> Map.put(:provider_options, Map.put(provider_options, :plan, true))
  end

  defp fold_plan_option(request), do: Map.delete(request, :plan)

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

  @doc """
  Folds an accepted mid-session configuration into the session's durable options.

  Only the four fields `Ouroboros.Provider.session_configuration/3` validates are ever
  written, and they are written into the same map a start filled, so `request/1` rebuilds
  a resumed session under the options it is actually running with rather than the ones it
  was started with. Anything else in `changes` is ignored here rather than trusted: the
  authority for what may change is the provider capability check, not this merge.
  """
  @spec configure(t(), map()) :: t()
  def configure(%__MODULE__{} = state, changes) when is_map(changes) do
    accepted = Map.take(changes, @configurable_options)
    %{state | options: Map.merge(state.options, accepted)}
  end

  @doc """
  Validates a human-supplied session title, or says why it is not one.

  Bounded and sanitised at the boundary rather than at every reader: the title travels on
  every `interactive.list` row and gets drawn into a one-line picker, so an unbounded
  string or an embedded control character is a rendering problem for every client at once.
  Trimmed, control characters (including newlines and the ANSI escape a terminal would
  obey) refused rather than stripped — a title that silently became something else would
  be worse than a refusal — and capped at #{@max_title_chars} graphemes, counted in
  graphemes because that is what a terminal column budget is.
  """
  @spec validate_title(term()) :: {:ok, String.t()} | {:error, term()}
  def validate_title(title) when is_binary(title) do
    trimmed = String.trim(title)

    cond do
      not String.valid?(title) ->
        {:error, {:invalid_title, %{reason: :not_valid_utf8}}}

      trimmed == "" ->
        {:error, {:invalid_title, %{reason: :blank}}}

      String.length(trimmed) > @max_title_chars ->
        {:error,
         {:invalid_title,
          %{reason: :too_long, limit: @max_title_chars, length: String.length(trimmed)}}}

      control_characters?(trimmed) ->
        {:error, {:invalid_title, %{reason: :control_characters}}}

      true ->
        {:ok, trimmed}
    end
  end

  def validate_title(title),
    do: {:error, {:invalid_title, %{reason: :not_a_string, value: title}}}

  @doc """
  Returns a title derived from a user prompt, or `nil` when the prompt yields none.

  The first line, because a prompt's first line is what a person would have typed as a
  subject; capped at #{@auto_title_chars} graphemes with an ellipsis, because a picker row
  is not a transcript. Control characters end the line rather than being carried into it.
  Deliberately not a model call: an auto-title that cost a token would be a cost nobody
  asked for on every session, and the first line is what four of the six leading tools use.
  """
  @spec auto_title(term()) :: String.t() | nil
  def auto_title(prompt) when is_binary(prompt) do
    line =
      prompt
      |> String.split(["\r\n", "\n", "\r"], parts: 2)
      |> hd()
      |> String.trim()

    cond do
      not String.valid?(line) or line == "" ->
        nil

      String.length(line) <= @auto_title_chars ->
        strip_controls(line)

      true ->
        line |> String.slice(0, @auto_title_chars - 1) |> String.trim_trailing() |> ellipsis()
    end
  end

  def auto_title(_prompt), do: nil

  @doc """
  Names a session, recording who named it so a later guess cannot overwrite a decision.

  `:human` always wins. `:auto` writes only where nothing has named the session yet, which
  is what keeps a second prompt from renaming a conversation a person already named — and
  from renaming one the runtime titled from the first prompt, since the first prompt is
  the one that describes what the session is about.
  """
  @spec put_title(t(), String.t(), :auto | :human) :: t()
  def put_title(%__MODULE__{} = state, title, :human) when is_binary(title),
    do: %{state | title: title, title_source: :human}

  def put_title(%__MODULE__{} = state, title, :auto) when is_binary(title) do
    case title(state) do
      nil -> %{state | title: title, title_source: :auto}
      _already_named -> state
    end
  end

  @doc """
  Returns the session's title, read defensively so a pre-title checkpoint loads as itself.
  """
  @spec title(t()) :: String.t() | nil
  def title(%__MODULE__{} = state), do: Map.get(state, :title)

  @doc "Returns who named this session: `:human`, `:auto`, or `nil` for nobody."
  @spec title_source(t()) :: title_source()
  def title_source(%__MODULE__{} = state), do: Map.get(state, :title_source)

  @doc "Returns the id of the session this one was forked from, or `nil`."
  @spec forked_from(t()) :: String.t() | nil
  def forked_from(%__MODULE__{} = state), do: Map.get(state, :forked_from)

  @doc """
  Returns the session this one was handed off from, or `nil`.

  Held apart from `forked_from` because the two are different claims: a fork carries the
  parent's conversation, a handoff carries a curated packet *about* it. Read through
  `Map.get/2` so a checkpoint from a build before handoffs existed projects as an
  unrelated session rather than a missing key.
  """
  @spec handed_off_from(t()) :: String.t() | nil
  def handed_off_from(%__MODULE__{} = state), do: Map.get(state, :handed_off_from)

  @doc """
  Returns how many forks this session has successfully started.

  A count, not a list: the children are addressable by their own ids and carry
  `forked_from`, which is the durable half of the relationship. This is the hint a picker
  shows, and it is honest about being one — a fork whose parent checkpoint failed after
  the child was created leaves it low rather than inventing a child that does not exist.
  """
  @spec forks(t()) :: non_neg_integer()
  def forks(%__MODULE__{} = state), do: Map.get(state, :forks, 0) || 0

  @doc """
  Every delegation this conversation started, keyed by delegation id.

  Read through `Map.get/3` so a checkpoint written before delegations existed projects as
  a session that delegated nothing rather than a missing key.
  """
  @spec delegations(t()) :: %{optional(String.t()) => delegation()}
  def delegations(%__MODULE__{} = state), do: Map.get(state, :delegations) || %{}

  @doc "The bound on how many delegations one conversation may hold."
  @spec max_delegations() :: pos_integer()
  def max_delegations, do: @max_delegations

  @doc """
  Records or updates one delegation.

  Refused with `:delegation_limit_reached` for a *new* delegation past the bound; an
  update to one already recorded always lands, because a terminal status arriving for a
  child that is running is exactly the news this map exists to carry.
  """
  @spec put_delegation(t(), delegation()) :: {:ok, t()} | {:error, term()}
  def put_delegation(%__MODULE__{} = state, %{id: id} = delegation) when is_binary(id) do
    existing = delegations(state)

    if not Map.has_key?(existing, id) and map_size(existing) >= @max_delegations do
      {:error, {:delegation_limit_reached, @max_delegations}}
    else
      {:ok, %{state | delegations: Map.put(existing, id, delegation)}}
    end
  end

  def put_delegation(%__MODULE__{}, delegation),
    do: {:error, {:invalid_delegation, delegation}}

  @doc "The child task ids this conversation started, sorted, for a nesting client."
  @spec children(t()) :: [String.t()]
  def children(%__MODULE__{} = state) do
    state |> delegations() |> Enum.map(fn {_id, record} -> record.task_id end) |> Enum.sort()
  end

  @doc false
  @spec count_fork(t()) :: t()
  def count_fork(%__MODULE__{} = state), do: %{state | forks: forks(state) + 1}

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

  # C5. Which OS sandbox a native session's shell runs under is a fact about the node
  # that owns the session, so it is answered only where that node is this one — a row
  # projected elsewhere carries no `sandbox` key, which a client reads as unknown rather
  # than as "none". Vendor providers run their own tools behind their own boundaries and
  # say nothing here.
  defp put_sandbox_capability(capabilities, %__MODULE__{provider: :native, node: owner})
       when is_map(capabilities) do
    if owner == node() do
      Map.put(
        capabilities,
        :sandbox,
        Ouroboros.Provider.Native.Sandbox.label(Ouroboros.Provider.Native.Sandbox.detect())
      )
    else
      capabilities
    end
  end

  defp put_sandbox_capability(capabilities, _state), do: capabilities

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
        # B2. Whether the session is planning, as the record has it; a plan exit the native
        # session applied is folded into the record by the coordinator.
        plan: Map.get(state.options, :plan, false) == true,
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
          |> put_sandbox_capability(state)
      }
      |> Trace.put(prompt_trace)

    turns = Map.new(state.turns, fn {id, turn} -> {id, public_turn(turn)} end)

    state
    |> Map.put(:runtime_snapshot, nil)
    |> Map.put(:options, options)
    |> Map.put(:turns, turns)
    # Written explicitly rather than left to the struct, so a checkpoint from a build
    # before titles existed projects as an unnamed session instead of a missing key.
    |> Map.put(:title, title(state))
    |> Map.put(:title_source, title_source(state))
    |> Map.put(:forked_from, forked_from(state))
    |> Map.put(:handed_off_from, handed_off_from(state))
    |> Map.put(:forks, forks(state))
    |> Map.put(:delegations, delegations(state))
  end

  @doc """
  Projects one session as a *row*: everything a picker draws, and nothing it does not.

  `public/1` is the whole session, and `interactive.list` answered with it — which meant
  every row carried its retained event window and its whole turn ledger across the socket,
  and across an `:erpc` from every fleet node, on every list. A client that wanted one
  integer — the contiguous high-water mark, to know whether it had replayed everything —
  paid for a session's entire transcript to learn it.

  So a row is bounded by construction: the same struct, the same `_struct` tag and the same
  field names, with `events` and `turns` emptied and `usage` reduced to the two figures a
  row can show. `cursor` is on it, which is the integer that made this necessary. Anything
  a row drops is one `interactive.info` away, addressed by the id the row carries.
  """
  @spec summary(t()) :: t()
  def summary(%__MODULE__{} = state) do
    state
    |> public()
    |> Map.put(:events, [])
    |> Map.put(:turns, %{})
    |> Map.put(:usage, usage_summary(state))
    # Ids, not records: a rail row nests its children by id and fetches the rest from
    # `coding.info`, exactly as it does for everything else a row drops.
    |> Map.put(:delegations, %{})
    |> Map.put(:children, children(state))
  end

  @doc """
  Reduces a session's usage account to what a row can honestly show.

  Two numbers, and `nil` for either that no provider reported. A session nobody has
  charged keeps `cost_usd: nil` rather than a zero that reads as "this was free", exactly
  as `fold_usage/2` keeps it.
  """
  @spec usage_summary(t()) :: %{total_tokens: non_neg_integer() | nil, cost_usd: number() | nil}
  def usage_summary(%__MODULE__{} = state) do
    usage = Map.get(state, :usage) || %{}

    %{total_tokens: Map.get(usage, :total_tokens), cost_usd: Map.get(usage, :cost_usd)}
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
      optional_id?(state.provider_session_id) and valid_title?(state) and
      optional_id?(forked_from(state)) and optional_id?(handed_off_from(state)) and
      valid_delegations?(state) and
      is_integer(forks(state)) and forks(state) >= 0 and
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

  defp validate_parent(nil), do: :ok
  defp validate_parent(parent) when is_binary(parent), do: validate_forked_from(parent)
  defp validate_parent(parent), do: {:error, {:invalid_parent_session, parent}}

  defp validate_forked_from(parent) do
    if valid_id?(parent), do: :ok, else: {:error, {:invalid_parent_session, parent}}
  end

  # D7's durable half, held to the same rule as everything else here: shape and
  # serializability. A worktree record is a map of strings, or it is `nil`.
  defp valid_delegations?(state) do
    delegations = Map.get(state, :delegations)

    (is_nil(delegations) or is_map(delegations)) and
      Enum.all?(delegations || %{}, fn
        {id, %{id: id, team_id: team, task_id: task, task_node: owner, status: status}} ->
          valid_id?(id) and valid_id?(team) and valid_id?(task) and is_atom(owner) and
            not is_nil(owner) and is_atom(status)

        _other ->
          false
      end)
  end

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
        @struct_options ++
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
          :mcp_config,
          :plan
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

  # `\p{Cc}` is the Unicode control category, which covers the C0 range a terminal would
  # interpret, `\e`, and the C1 range a UTF-8 title could smuggle one in as.
  defp control_characters?(string), do: String.match?(string, ~r/\p{Cc}/u)

  defp strip_controls(string), do: String.replace(string, ~r/\p{Cc}/u, "")

  defp ellipsis(""), do: nil
  defp ellipsis(string), do: strip_controls(string) <> "…"

  # A checkpoint written before titles existed has neither key, which is read as a session
  # nobody has named. A title present without a source, or a source without a title, is a
  # record this build did not write and does not know how to read.
  defp valid_title?(state) do
    case {title(state), title_source(state)} do
      {nil, nil} -> true
      {title, source} when is_binary(title) and source in [:auto, :human] -> ok_title?(title)
      _mismatched -> false
    end
  end

  defp ok_title?(title), do: match?({:ok, ^title}, validate_title(title))

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

  # Not counters. The model's context window and the size of the last request are facts
  # about one request, so the newest report replaces the previous one rather than being
  # added to it — summing a window across turns would produce a denominator that grows
  # with the conversation. A payload that reports neither leaves both alone, which is why
  # a `:run_completed` terminator cannot blank a window a `:usage` event established.
  @usage_latest [
    context_window: ~w(context_window contextWindow),
    context_used: ~w(context_used contextUsed)
  ]

  @usage_latest_fields Keyword.keys(@usage_latest)

  @empty_usage %{
    input_tokens: 0,
    output_tokens: 0,
    cache_read_tokens: 0,
    cache_creation_tokens: 0,
    total_tokens: 0,
    cost_usd: nil,
    turns_with_usage: 0,
    context_window: nil,
    context_used: nil,
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

    latest =
      Enum.reduce(@usage_latest, %{}, fn {field, keys}, acc ->
        case usage_number(payload, keys) do
          nil -> acc
          value -> Map.put(acc, field, trunc(value))
        end
      end)

    if counters == %{} and is_nil(cost) and latest == %{} do
      nil
    else
      counters
      |> Map.merge(latest)
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
    |> Map.merge(
      Map.new(@usage_latest_fields, fn field ->
        {field, Map.get(contribution, field) || Map.get(usage, field)}
      end)
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
