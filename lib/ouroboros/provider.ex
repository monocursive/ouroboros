defmodule Ouroboros.Provider do
  @moduledoc """
  What a provider will actually accept for the two options the planes default.

  Both planes want to start under a usable posture: approvals prompted and the workspace
  writable. Four of the nine bundled providers cannot be told that. Amp declares neither
  option, OpenCode declares no `sandbox_mode`, Kimi declares both but accepts only
  `:default` for each, and Pi refuses `:prompt` approvals. `Jido.Harness` refuses any
  normalized option a provider has not declared, so injecting the pair unconditionally
  did not make those four providers safe — it made them unstartable. A read-only session
  is still available: pass `sandbox_mode: :read_only`.

  The lookup answers per plane because the harness validates the two surfaces against
  different lists. A run is checked against the adapter's own `normalized_options`
  (`Jido.Harness.Run.RequestResolver`); a session is checked against the selected
  transport's `session_options`, which inherit the adapter's list only when the
  transport declares `:adapter` (`Jido.Harness.SessionManager`). OpenCode is the case
  that makes the distinction load-bearing: its adapter accepts `approval_mode`, its ACP
  session transport does not.

  What a plane does with the answer is the plane's business, and the two differ:

    * The interactive plane omits a default the provider cannot take, which leaves the
      harness request at `:default` — the provider's own behavior, which is what "the
      caller said nothing" has always meant.
    * The coding plane refuses at creation, because its workspace-write default is a
      promise the README makes to whoever starts a task, and quietly dropping it would
      break that promise in the one direction that matters.

  Neither plane rewrites or drops an option the caller stated. A sandbox the provider
  cannot enforce has to fail loudly rather than quietly become no sandbox at all, so a
  stated value travels to the harness untouched and the harness refuses it by name.
  """

  alias Jido.Harness.InteractionCapabilities
  alias Jido.Harness.Registry
  alias Jido.Harness.SessionTransportSpec
  alias Ouroboros.Provider.Session

  @typedoc """
  Which harness surface the options are bound for. An interactive session also carries
  the transport the caller selected, or `nil` when it takes the adapter's default.
  """
  @type plane :: :coding | {:interactive, atom() | nil}

  # The default posture, in the order a refusal reports it. Read-only is opt-in.
  @plane_defaults [approval_mode: :prompt, sandbox_mode: :workspace_write]

  # The capabilities a session declares publicly. Deliberately the granular set and not
  # the whole struct: `maturity` describes the transport's own readiness rather than
  # anything a session can do, and a struct on the wire would carry `_struct` into every
  # `interactive.list` row. Each value is `:native | :managed | :process | false` and
  # crosses `Ouroboros.Gateway.Wire` as a string or `false`.
  @capability_keys [
    :transport,
    :process,
    :multi_turn,
    :follow_up,
    :interrupt,
    :approvals,
    :steer,
    :multimodal,
    :dynamic_model,
    :dynamic_configuration
  ]

  # Not `InteractionCapabilities` fields: the harness has no notion of forking a session
  # and none of folding one, so `:fork` and `:compact` are derived beside the declared set
  # — from the dialect, or from the adapter table below. Listed here so the public shape
  # stays one map with one docstring.
  @derived_capability_keys [:fork, :compact]

  # Run adapters whose `provider_options.fork_session` is a **boolean** that branches the
  # session named by `provider_session_id`, rather than something else wearing the same
  # key. Read from each adapter's own argv builder in the pinned Harness:
  #
  #   * `Adapters.Claude` — `CLIArgs.pair("--resume", request.provider_session_id)` and
  #     `CLIArgs.flag("--fork-session", options[:fork_session])` (`claude.ex:92,105`).
  #   * `Adapters.Zai` — delegates `run/2` to `Claude.run/2` with rewritten env
  #     (`zai.ex:71`) and declares the same option.
  #   * `Adapters.Grok` — `pair("--resume", …)` plus `flag("--fork-session", …)`
  #     (`grok.ex:105,115`), where `flag/2` emits the bare flag only for `true`.
  #
  # Pi is deliberately absent although it declares `:fork_session`: there the option is
  # `pair("--fork", options[:fork_session])`, a *session name* rather than a flag, and its
  # validator refuses `provider_session_id` and `fork_session` together
  # (`pi.ex:230,399-401`). Sending `true` there would produce `--fork true` and a refusal,
  # and inferring the other shape from an argv nobody has run would be a guess about a
  # user's session. Pi therefore declares `fork: false` until someone verifies it.
  #
  # This is a table because no upstream declaration distinguishes the two shapes: an
  # `AdapterSpec` lists option *names*, never their meaning. It is keyed on the module the
  # argv was read in so a provider repointed at other code loses the claim automatically.
  @adapter_fork_flags %{
    Jido.Harness.Adapters.Claude => {:fork_session, true},
    Jido.Harness.Adapters.Zai => {:fork_session, true},
    Jido.Harness.Adapters.Grok => {:fork_session, true}
  }

  # The normalized approval vocabulary `Jido.Harness.SessionRequest` validates against
  # (`deps/jido_harness/lib/jido_harness/session/request.ex:3`). A transport that
  # declares no `normalized_values.approval_mode` allowlist accepts all four, which is
  # what `evaluate/3` already assumes — so this is the list a refusal may recommend from
  # when the spec narrows nothing. `test/provider_capability_test.exs` checks it against
  # the harness schema so an upstream addition fails here rather than in a session.
  @approval_modes [:default, :prompt, :auto_edit, :auto_approve]

  # What `interactive.configure` may name. Exactly the four fields
  # `Jido.Harness.SessionRequestValidator` normalizes a configuration to
  # (`deps/jido_harness/lib/jido_harness/session/request_validator.ex:7`) and the four a
  # managed transport's own `configuration_options` default to — anything else is a start
  # option, not something an open session can be moved to.
  @configuration_fields [:approval_mode, :sandbox_mode, :model, :reasoning_effort]

  @execution_defaults %{}

  # `Jido.Harness` reads each of these as "the caller said nothing" and never checks it
  # against a provider's allowlist. `:default` is therefore always legal to send.
  @unset_values [nil, [], %{}, :default]

  @doc "Merges this node's provider execution defaults under caller options."
  @spec execution_options(atom(), map() | nil) :: map() | nil
  def execution_options(provider, options) when options in [nil, %{}] do
    defaults = provider_defaults(provider, %{})
    if defaults == %{} and is_nil(options), do: nil, else: defaults
  end

  def execution_options(provider, options) when is_map(options) do
    provider
    |> provider_defaults(%{})
    |> Map.merge(options)
  end

  def execution_options(_provider, options), do: options

  @doc "Returns non-secret execution policy safe to show in public session state."
  @spec public_execution_policy(atom(), map() | nil) :: map()
  @spec public_execution_policy(atom(), map() | nil, keyword()) :: map()
  def public_execution_policy(provider, options, opts \\ [])

  def public_execution_policy(:native, _options, opts) do
    model = Ouroboros.Provider.Native.Model.configured_model()

    %{
      runtime_ready:
        Ouroboros.Provider.Native.Model.available?() and is_binary(model) and
          Ouroboros.Provider.Native.Model.credential_ready?(model),
      runtime_error: nil,
      model: model,
      transport: :direct,
      interactive_approvals: true,
      coding_approvals: true,
      escalation_behavior: :prompt,
      surface: Keyword.get(opts, :surface)
    }
  end

  def public_execution_policy(_provider, _options, _opts), do: %{}

  @doc false
  @spec apply_runtime_provider_policy(map(), atom()) :: map()
  def apply_runtime_provider_policy(request, _provider) when is_map(request), do: request

  @doc false
  @spec apply_execution_directories(map(), atom()) :: map()
  def apply_execution_directories(request, provider),
    do: apply_execution_directories(request, provider, nil)

  @doc false
  @spec apply_execution_directories(map(), atom(), :request | :session | nil) :: map()
  def apply_execution_directories(request, _provider, _defaults_kind), do: request

  @doc false
  @spec configure_runtime_cache() :: :ok
  def configure_runtime_cache, do: :ok

  defp provider_defaults(provider, fallback) do
    case Application.get_env(:ouroboros, :provider_execution_defaults, @execution_defaults) do
      configured when is_map(configured) ->
        case Map.get(configured, provider, fallback) do
          defaults when is_map(defaults) -> defaults
          _invalid -> fallback
        end

      _invalid ->
        fallback
    end
  end

  @doc """
  Returns the `approval_mode` and `sandbox_mode` a request for `provider` may carry.

  Options the caller stated in `opts` are returned unchanged. Options the caller left
  unset take the plane's default when the provider can accept it. On the interactive
  plane an unacceptable default is omitted from the result; on the coding plane it is
  refused, and so is a stated value the provider cannot enforce.

  When the provider's spec cannot be resolved — an unregistered atom, or a session
  transport no adapter declares — the defaults are returned as they always were, so the
  harness produces its own error about the thing that is actually wrong.
  """
  @spec safety_options(term(), keyword(), plane()) :: {:ok, keyword()} | {:error, term()}
  def safety_options(provider, opts, plane) when is_list(opts) do
    capability = capability(provider, plane)

    # A refusal names every option the provider cannot take, not just the first. Amp and
    # Kimi can take neither, and answering them one at a time would send the operator
    # around the loop twice to learn one thing.
    {taken, unsupported} =
      Enum.reduce(@plane_defaults, {[], []}, fn {field, plane_default}, {taken, unsupported} ->
        stated? = Keyword.has_key?(opts, field)
        value = Keyword.get(opts, field, plane_default)

        case {plane, evaluate(capability, field, value)} do
          {{:interactive, _transport}, {:unsupported, _accepted}} when not stated? ->
            {taken, unsupported}

          {:coding, {:unsupported, accepted}} ->
            {taken, unsupported ++ [refused(field, value, stated?, accepted)]}

          _supported_or_unresolvable ->
            {taken ++ [{field, value}], unsupported}
        end
      end)

    cond do
      unsupported != [] -> {:error, refusal(provider, unsupported)}
      refused = unanswerable_prompt(provider, plane, taken, capability) -> {:error, refused}
      true -> {:ok, taken}
    end
  end

  @doc """
  Returns what the transport an interactive session will select can actually do.

  Derived from the provider spec alone. No live process is consulted, because sessions
  are listed after a restart and a capability that only a running coordinator could
  answer would be blank on exactly the rows an operator is trying to understand.

  `nil` when the provider or the transport does not resolve. An unregistered provider and
  a transport no adapter declares are the harness's to name, and inventing a capability
  map for them would be this module describing a transport it has never seen.

  `:fork` is the one key the harness has no notion of; see `session_fork_options/2` for
  where its answer comes from.
  """
  @spec session_capabilities(term(), atom() | nil) :: map() | nil
  def session_capabilities(provider, transport \\ nil) do
    with {:ok, spec} <- Registry.spec(provider),
         %{capabilities: %InteractionCapabilities{}} = declared <-
           selected_transport(spec, transport) do
      capabilities = Session.capabilities(declared)

      @capability_keys
      |> Map.new(&{&1, Map.get(capabilities, &1, false)})
      |> Map.put(:fork, fork_capability(provider, spec, declared))
      |> Map.put(:compact, compact_capability(declared))
    else
      _unresolvable -> nil
    end
  end

  @doc """
  Whether a session's conversation can be folded, and by whom.

  Three answers, and the difference between the first two is the whole point.

    * `:native` — this runtime holds the conversation, so it does the summarising and the
      report carries real token counts. `Ouroboros.Provider.Native.Session.compact/2`.
    * `:provider` — a dialect-owned transport may fold its own thread. The report says
      which side did the work and never borrows the native path's measurements.
    * `false` — the transport neither hands its conversation over nor offers a verb, and
      `interactive.compact` refuses by capability. A summary invented for a transcript
      Ouroboros never had would be a claim nothing supports.

  Derived from the dialect for the same reason `:fork` is: where this runtime owns the
  wire, only the dialect knows whether the protocol has the frame. A provider or transport
  that does not resolve is `false` — this module does not claim a verb for a transport it
  has never seen.
  """
  @spec session_compact(term(), atom() | nil) :: :native | :provider | false
  def session_compact(provider, transport \\ nil) do
    with {:ok, spec} <- Registry.spec(provider),
         declared when not is_nil(declared) <- selected_transport(spec, transport) do
      compact_capability(declared)
    else
      _unresolvable -> false
    end
  end

  defp compact_capability(declared) do
    cond do
      Session.capabilities(declared).transport == :native -> :native
      match?({:compact, _how}, dialect_compact_option(declared)) -> :provider
      true -> false
    end
  end

  defp dialect_compact_option(%{adapter: adapter}) do
    with dialect when not is_nil(dialect) <- Session.dialect(adapter),
         true <- function_exported?(dialect, :compact_option, 0) do
      dialect.compact_option()
    else
      _no_dialect_compact -> nil
    end
  end

  @doc "Every key `session_capabilities/2` answers with, declared and derived."
  @spec capability_keys() :: [atom()]
  def capability_keys, do: @capability_keys ++ @derived_capability_keys

  @doc """
  Returns the start options that make a new session a fork of an existing provider session.

  A fork is a *new* Ouroboros session that carries the parent's `provider_session_id` plus
  whatever the transport spells "branch this rather than continue it". Both halves are read
  from declarations:

    * a dialect this runtime owns may declare its own by exporting `fork_option/0`;
    * a run adapter declares its own by exporting `fork_option/0`, or — for the three
      pinned upstream modules that have nowhere to put one — appears in
      `@adapter_fork_flags`. Either way the structural half is still checked: the transport
      must be able to carry `:provider_session_id` and the adapter must declare `resume?`,
      because a branch flag with nothing to branch from is a new conversation.

  Everything else answers `{:error, {:unforkable_session, …}}`, including ACP: neither
  bundled ACP agent publishes a branch verb, and `session/load` continues a session rather
  than copying it.
  """
  @spec session_fork_options(term(), atom() | nil) :: {:ok, map()} | {:error, term()}
  def session_fork_options(provider, transport \\ nil) do
    with {:ok, spec} <- fork_spec(provider),
         {:ok, declared} <- fork_transport(spec, provider, transport) do
      case fork_option(provider, spec, declared) do
        nil ->
          {:error,
           {:unforkable_session,
            %{
              provider: spec.provider,
              transport: declared.name,
              reason: :transport_cannot_fork,
              message:
                "#{inspect(spec.provider)} reaches an interactive session over the " <>
                  "#{inspect(declared.name)} transport, which declares no way to branch one. " <>
                  "Start a new session instead; the conversation so far stays where it is."
            }}}

        {key, value} ->
          {:ok, %{key => value}}
      end
    end
  end

  defp fork_spec(provider) do
    case Registry.spec(provider) do
      {:ok, spec} ->
        {:ok, spec}

      _unresolvable ->
        {:error, {:unforkable_session, %{provider: provider, reason: :unknown_provider}}}
    end
  end

  defp fork_transport(spec, provider, transport) do
    case selected_transport(spec, transport) do
      nil ->
        {:error,
         {:unforkable_session,
          %{provider: provider, transport: transport, reason: :unknown_session_transport}}}

      declared ->
        {:ok, declared}
    end
  end

  defp fork_capability(provider, spec, declared) do
    if fork_option(provider, spec, declared), do: :native, else: false
  end

  # The dialect first, because where this runtime owns the wire it is the only thing that
  # knows whether the protocol has a branch verb. Only then the run adapter.
  defp fork_option(provider, spec, declared) do
    dialect_fork_option(declared) || adapter_fork_option(provider, spec, declared)
  end

  defp dialect_fork_option(%{adapter: adapter}) do
    with dialect when not is_nil(dialect) <- Session.dialect(adapter),
         true <- function_exported?(dialect, :fork_option, 0) do
      dialect.fork_option()
    else
      _no_dialect_fork -> nil
    end
  end

  # Keyed on the adapter *module*, not the provider name, because a node may point a
  # provider at a different adapter — this runtime already does for codex, kimi and
  # opencode — and the claim below is about argv that was read in a particular module.
  # The structural half is still asked of the spec every time: a branch flag is only a
  # fork when the request can also carry the session being branched.
  defp adapter_fork_option(provider, spec, declared) do
    with {:ok, adapter} <- Registry.lookup(provider),
         option when not is_nil(option) <- declared_fork_option(adapter),
         true <-
           :fork_session in transport_list(
             declared.session_provider_options,
             spec.provider_options
           ),
         true <-
           :provider_session_id in transport_list(
             declared.session_options,
             spec.normalized_options
           ),
         true <- spec.capabilities.resume? do
      option
    else
      _not_declared -> nil
    end
  end

  # An adapter this runtime owns says so itself, the way a dialect does. The table is the
  # fallback for the three pinned upstream modules, which have nowhere to put it.
  defp declared_fork_option(adapter) do
    if Code.ensure_loaded?(adapter) and function_exported?(adapter, :fork_option, 0),
      do: adapter.fork_option(),
      else: Map.get(@adapter_fork_flags, adapter)
  end

  defp transport_list(:adapter, adapter_list), do: adapter_list
  defp transport_list(list, _adapter_list) when is_list(list), do: list
  defp transport_list(_unresolvable, _adapter_list), do: []

  @doc """
  Whether a provider can be put into plan mode, how it is asked, and when it takes hold.

      {:ok, %{applies: :now | :next_turn,
              settable: :any_time | :at_start,
              via: :native_session | :provider_options}}
      {:error, {:unsupported_configuration, %{provider:, transport:, field: :plan,
                                              reason:, message:}}}

  ## Why plan mode is not an `interactive.configure` key

  It cannot be one on the pinned harness. `Jido.Harness.Session.RequestValidator`
  normalizes a configuration against a literal four-key list — `model`,
  `reasoning_effort`, `approval_mode`, `sandbox_mode`
  (`deps/jido_harness/lib/jido_harness/session/request_validator.ex:7`) — and refuses
  anything else *before* the transport is consulted, and `SessionRequest`'s
  `approval_mode` is a four-member `Zoi.enum` with no room for `:plan`
  (`.../session/request.ex:4`). Adding `:plan` to `@configuration_fields` here would
  advertise a key that the very next call rejects, which is the failure this module's
  whole docstring exists to prevent. So plan mode is declared here, applied through the
  channel each transport can actually carry it on, and `@configuration_fields` stays at
  four.

  ## The two transports that can carry it

    * **`:native`** — `Ouroboros.Provider.Native.Session.plan_mode/2`, which reaches a live
      session process by name the same way `compact`, `handoff` and `rewind` do. `:now`,
      any time, and durable across a resume. A start may also ask with
      `provider_options: %{plan: true}`.
    * **`:claude`** — `provider_options: %{plan: true}` on the session request or on one
      turn's, which `Ouroboros.Provider.ClaudeAdapter` turns into
      `--permission-mode plan`. `:next_turn`, because `claude --print` runs one process
      per turn: the turn already executing keeps the argv it started with.

  Everything else is refused by name rather than quietly running without plan mode.
  """
  @spec plan_mode(term(), atom() | nil) :: {:ok, map()} | {:error, term()}
  def plan_mode(provider, transport \\ nil) do
    with {:ok, spec} <- plan_spec(provider),
         {:ok, declared} <- plan_transport(spec, provider, transport) do
      case plan_support(provider) do
        nil -> {:error, unplannable(spec, declared, plan_refusal(spec.provider))}
        support -> {:ok, support}
      end
    end
  end

  # Read from this runtime's own two modules rather than from a declaration upstream: no
  # `AdapterSpec` has a field for "can this provider be told to plan", and inventing one in
  # a pinned dependency's struct is not available. Keyed on the provider a spec resolves
  # to, so a node that repoints `:claude` at a different adapter does not inherit the
  # claim — `plan_adapter?/1` checks the module too.
  defp plan_support(provider) do
    case {provider, Registry.lookup(provider)} do
      {:native, {:ok, Ouroboros.Provider.Native}} ->
        %{applies: :now, settable: :any_time, via: :native_session}

      {:claude, {:ok, Ouroboros.Provider.ClaudeAdapter}} ->
        %{applies: :next_turn, settable: :at_start, via: :provider_options}

      _other ->
        nil
    end
  end

  defp plan_refusal(provider),
    do:
      {:transport_cannot_plan,
       "#{inspect(provider)} declares no way to be told to plan. Plan mode is a " <>
         "read-only posture with an exit approval attached, and a provider that cannot " <>
         "be told about either would run the work while a client showed a planning " <>
         "label. Use `sandbox_mode: :read_only` for a session that must not write."}

  defp unplannable(spec, declared, {reason, message}) do
    {:unsupported_configuration,
     %{
       provider: spec.provider,
       transport: declared.name,
       field: :plan,
       reason: reason,
       message: message
     }}
  end

  defp plan_spec(provider) do
    case Registry.spec(provider) do
      {:ok, spec} ->
        {:ok, spec}

      _unresolvable ->
        {:error,
         {:unsupported_configuration,
          %{provider: provider, field: :plan, reason: :unknown_provider}}}
    end
  end

  defp plan_transport(spec, provider, transport) do
    case selected_transport(spec, transport) do
      nil ->
        {:error,
         {:unsupported_configuration,
          %{
            provider: provider,
            transport: transport,
            field: :plan,
            reason: :unknown_session_transport
          }}}

      declared ->
        {:ok, declared}
    end
  end

  @doc """
  Returns whether a running session can be told to change the *agent's own* mode.

  C4, and the counterpart to B1's refusal rather than a reversal of it. ACP's only
  configuration verb is `session/set_mode`, whose argument is a mode id the agent itself
  invented and published in `session/new`'s `availableModes` — "ask", "architect",
  "code", whatever that agent ships. Those are not Ouroboros's four normalized approval
  modes and no bundled agent publishes a mapping, so `approval_mode` and `sandbox_mode`
  stay refused on ACP exactly as they were: the transport declares no
  `dynamic_configuration`, and `session_configuration/3` refuses before any wire is
  touched.

  What C4 adds is a *different key*. `mode` carries the agent's own id, is validated
  against the list that agent announced, and is refused by name everywhere else. Nothing
  is guessed and nothing is mapped: a client that wants to move an ACP agent's posture
  has to name a mode the agent said it had.

  Declaration-shaped, like `session_fork_options/2`: the answer comes from the dialect
  exporting `mode_option/0`, so a transport gains this by implementing it rather than by
  being added to a table here. `applies` is `:now` because `session/set_mode` is a
  correlated round trip that has already been answered by the time this runtime replies.

  Not durable. A mode is a property of the live agent process; a resume starts a new one,
  which comes up in its own default. Reporting it as remembered would be a claim about a
  session that has not started yet.
  """
  @spec session_mode(term(), atom() | nil) :: {:ok, map()} | {:error, term()}
  def session_mode(provider, transport \\ nil) do
    with {:ok, spec} <- mode_spec(provider),
         {:ok, declared} <- mode_transport(spec, provider, transport) do
      case dialect_mode_option(declared) do
        {:mode, vocabulary} ->
          {:ok, %{applies: :now, settable: :any_time, via: :session_set_mode, ids: vocabulary}}

        _undeclared ->
          {:error,
           {:unsupported_configuration,
            %{
              provider: spec.provider,
              transport: declared.name,
              field: :mode,
              reason: :transport_has_no_modes,
              message:
                "#{inspect(spec.provider)} reaches this session over the " <>
                  "#{inspect(declared.name)} transport, which has no notion of an agent " <>
                  "mode. `mode` carries an id the agent itself published; a transport " <>
                  "that publishes none cannot be told one."
            }}}
      end
    end
  end

  defp dialect_mode_option(%{adapter: adapter}) do
    with dialect when not is_nil(dialect) <- Session.dialect(adapter),
         true <- function_exported?(dialect, :mode_option, 0) do
      dialect.mode_option()
    else
      _no_dialect_mode -> nil
    end
  end

  defp mode_spec(provider) do
    case Registry.spec(provider) do
      {:ok, spec} ->
        {:ok, spec}

      _unresolvable ->
        {:error,
         {:unsupported_configuration,
          %{provider: provider, field: :mode, reason: :unknown_provider}}}
    end
  end

  defp mode_transport(spec, provider, transport) do
    case selected_transport(spec, transport) do
      nil ->
        {:error,
         {:unsupported_configuration,
          %{
            provider: provider,
            transport: transport,
            field: :mode,
            reason: :unknown_session_transport
          }}}

      declared ->
        {:ok, declared}
    end
  end

  @doc """
  Returns the options a *running* session may still be changed to, and when it takes hold.

  Validated against exactly what `safety_options/3` validates a start against — the
  option list the selected transport declares, and the `normalized_values` allowlists the
  adapter narrows them with — plus the two questions only a mid-session change raises:
  whether the transport declares `dynamic_configuration` at all, and whether it declares
  `dynamic_model` for a change that names a model.

  The second element of a success is the honest half. `:now` is returned only for a
  transport whose `dynamic_configuration` is `:native` — one that carries the change to a
  live provider process. `:next_turn` is everything else: a managed transport re-executes
  its process per turn, so the turn already running keeps the policy it started with.
  Callers state which happened; nothing presents `:next_turn` as immediate.

  The X1 rule applies unchanged: `approval_mode: :prompt` on a transport with no approvals
  channel is refused with the same typed error a start is refused with, because a session
  configured into a mode that asks nobody is denied without a word exactly as a session
  started into it is.
  """
  @spec session_configuration(term(), map(), atom() | nil) ::
          {:ok, map(), :now | :next_turn} | {:error, term()}
  def session_configuration(provider, changes, transport \\ nil)

  def session_configuration(provider, changes, transport) when is_map(changes) do
    with :ok <- validate_configuration_fields(changes),
         {:ok, spec} <- configuration_spec(provider),
         {:ok, declared} <- configuration_transport(spec, provider, transport),
         :ok <- validate_dynamic_configuration(spec, declared, changes),
         :ok <- validate_configuration_options(spec, declared, changes),
         :ok <- validate_configuration_values(spec, declared, changes),
         :ok <- validate_configured_approval_mode(spec, declared, changes) do
      {:ok, changes, applies(declared)}
    end
  end

  def session_configuration(_provider, changes, _transport),
    do: {:error, {:invalid_configuration, %{reason: :not_a_map, changes: changes}}}

  # `:now` is a claim about a live provider process, so only `:native` earns it.
  defp applies(%{capabilities: %{dynamic_configuration: :native}}), do: :now
  defp applies(_declared), do: :next_turn

  defp validate_configuration_fields(changes) do
    cond do
      changes == %{} ->
        {:error,
         {:invalid_configuration,
          %{reason: :no_changes, fields: Enum.sort(@configuration_fields)}}}

      field = Enum.find(Map.keys(changes), &(&1 not in @configuration_fields)) ->
        {:error,
         {:invalid_configuration,
          %{reason: :unknown_field, field: field, fields: Enum.sort(@configuration_fields)}}}

      true ->
        :ok
    end
  end

  defp configuration_spec(provider) do
    case Registry.spec(provider) do
      {:ok, spec} ->
        {:ok, spec}

      _unresolvable ->
        {:error, {:unconfigurable_session, %{provider: provider, reason: :unknown_provider}}}
    end
  end

  # A start may proceed past an unresolvable transport and let the harness name it. A
  # configure may not: its whole answer includes *when* the change takes effect, and a
  # transport nobody declares cannot be asked.
  defp configuration_transport(spec, provider, transport) do
    case selected_transport(spec, transport) do
      nil ->
        {:error,
         {:unconfigurable_session,
          %{provider: provider, transport: transport, reason: :unknown_session_transport}}}

      declared ->
        {:ok, declared}
    end
  end

  defp validate_dynamic_configuration(spec, declared, changes) do
    capabilities = Session.capabilities(declared)

    cond do
      not InteractionCapabilities.supported?(capabilities, :dynamic_configuration) ->
        {:error, unconfigurable(spec, declared, :no_dynamic_configuration, changes)}

      Map.has_key?(changes, :model) and
          not InteractionCapabilities.supported?(capabilities, :dynamic_model) ->
        {:error, unconfigurable(spec, declared, :no_dynamic_model, changes)}

      true ->
        :ok
    end
  end

  # Two lists have to agree, and they answer different questions. `normalized_options`
  # is what this transport accepts *at all* — the same list a start is held to. The
  # transport's `configuration_options` is the narrower "and can still be changed once
  # the session is open". A field outside either is refused by name.
  defp validate_configuration_options(spec, declared, changes) do
    case normalized_options(spec, {:interactive, declared.name}) do
      {:ok, accepted} ->
        validate_configurable_fields(spec, declared, changes, accepted)

      # `selected_transport/2` only answers with a transport the spec declares or the
      # synthetic managed one, so this is unreachable today. It is a `case` rather than a
      # match because an unreachable `MatchError` here would crash a live coordinator.
      :error ->
        {:error,
         {:unconfigurable_session,
          %{
            provider: spec.provider,
            transport: declared.name,
            reason: :unknown_session_transport
          }}}
    end
  end

  defp validate_configurable_fields(spec, declared, changes, accepted) do
    case Enum.find(
           Map.keys(changes),
           &(&1 not in accepted or &1 not in declared.configuration_options)
         ) do
      nil ->
        :ok

      field ->
        {:error,
         {:unconfigurable_session,
          %{
            provider: spec.provider,
            transport: declared.name,
            reason: :option_not_configurable,
            field: field,
            configurable:
              Enum.sort(Enum.filter(declared.configuration_options, &(&1 in accepted))),
            message:
              "#{inspect(spec.provider)} over the #{inspect(declared.name)} transport cannot " <>
                "change #{inspect(field)} on an open session; it can change " <>
                "#{inspect(Enum.sort(Enum.filter(declared.configuration_options, &(&1 in accepted))))}"
          }}}
    end
  end

  defp validate_configuration_values(spec, declared, changes) do
    Enum.reduce_while(changes, :ok, fn {field, value}, :ok ->
      case Map.get(spec.normalized_values, field) do
        nil ->
          {:cont, :ok}

        allowed ->
          if value in allowed or value in @unset_values do
            {:cont, :ok}
          else
            {:halt,
             {:error,
              {:unconfigurable_session,
               %{
                 provider: spec.provider,
                 transport: declared.name,
                 reason: :value_not_accepted,
                 field: field,
                 value: value,
                 accepted_values: allowed
               }}}}
          end
      end
    end)
  end

  # X1, on the configure path. A mode that asks nobody is exactly as broken arrived at by
  # `interactive.configure` as it is stated at `interactive.start`, so it is refused with
  # the same tuple and the same sentence rather than a second vocabulary.
  defp validate_configured_approval_mode(spec, declared, changes) do
    with :prompt <- Map.get(changes, :approval_mode),
         %{approvals: false} = capabilities <-
           Map.new(@capability_keys, &{&1, Map.get(Session.capabilities(declared), &1, false)}) do
      {:error,
       {:unsupported_approval_mode,
        unanswerable(
          spec.provider,
          capabilities,
          capability(spec.provider, {:interactive, declared.name})
        )}}
    else
      _answerable_or_absent -> :ok
    end
  end

  defp unconfigurable(spec, declared, reason, changes) do
    {:unconfigurable_session,
     %{
       provider: spec.provider,
       transport: declared.name,
       reason: reason,
       fields: changes |> Map.keys() |> Enum.sort(),
       message: unconfigurable_message(spec.provider, declared.name, reason)
     }}
  end

  defp unconfigurable_message(provider, transport, :no_dynamic_configuration) do
    "#{inspect(provider)} reaches an interactive session over the #{inspect(transport)} " <>
      "transport, which declares no dynamic configuration: nothing about an open session " <>
      "can be changed. Start a new session with the options you want."
  end

  defp unconfigurable_message(provider, transport, :no_dynamic_model) do
    "#{inspect(provider)} over the #{inspect(transport)} transport declares no dynamic " <>
      "model, so the model an open session runs cannot be changed. Start a new session " <>
      "with the model you want."
  end

  # Mirrors `Jido.Harness.Session.Manager.resolve_transport/2`, including the synthetic
  # managed transport it substitutes for an adapter that declares none. Declaring
  # anything else here would describe a transport the session is not going to get.
  defp selected_transport(spec, transport) do
    selected = transport || spec.default_session_transport || first_transport(spec)

    declared =
      Enum.find(spec.session_transports, &(&1.name == selected)) ||
        if selected == :managed, do: SessionTransportSpec.managed()

    case declared do
      nil -> nil
      found -> specialize(found, spec)
    end
  end

  # Mirrors `Jido.Harness.Session.Manager.specialize_transport/2`. A managed transport
  # re-executes the CLI per turn, so it can only change a setting the adapter actually
  # normalizes: Amp takes no `model`, and a session that advertised `dynamic_model` for
  # it would be offering a control that cannot be wired to anything.
  defp specialize(%{adapter: Jido.Harness.SessionAdapters.Managed} = transport, spec) do
    configuration_options =
      Enum.filter(transport.configuration_options, &(&1 in spec.normalized_options))

    capabilities = %{
      transport.capabilities
      | dynamic_model:
          if(:model in configuration_options,
            do: transport.capabilities.dynamic_model,
            else: false
          ),
        dynamic_configuration:
          if(configuration_options == [],
            do: false,
            else: transport.capabilities.dynamic_configuration
          )
    }

    %{transport | capabilities: capabilities, configuration_options: configuration_options}
  end

  defp specialize(transport, _spec), do: transport

  # X1. `approval_mode: :prompt` promises that a human is asked before a tool runs. A
  # transport with no approvals channel cannot keep that promise and does not fail
  # either: `claude --print --permission-mode default` is never given a
  # `--permission-prompt-tool`
  # (`deps/jido_harness/lib/jido_harness/adapters/claude.ex:161-163`), so every tool call
  # that needs permission is denied without a word. The session looks alive and cannot
  # work. Refusing here is the only place the two spellings that do work can be named.
  #
  # Only where the spec would otherwise have *accepted* the value. A transport whose
  # `normalized_values` already exclude `:prompt` — Pi's RPC, Kimi's ACP — is refused by
  # name upstream when the caller states it, and has the default omitted when they did
  # not; neither is this clause's business.
  defp unanswerable_prompt(provider, {:interactive, transport}, taken, capability) do
    with :prompt <- Keyword.get(taken, :approval_mode),
         :supported <- evaluate(capability, :approval_mode, :prompt),
         %{approvals: false} = capabilities <- session_capabilities(provider, transport) do
      {:unsupported_approval_mode, unanswerable(provider, capabilities, capability)}
    else
      _answerable_or_unresolvable -> nil
    end
  end

  defp unanswerable_prompt(_provider, :coding, _taken, _capability), do: nil

  defp unanswerable(provider, capabilities, capability) do
    supported = answerable_modes(capability)

    %{
      plane: :interactive,
      provider: provider,
      transport: capabilities.transport,
      requested: :prompt,
      supported: supported,
      reason: :no_approval_channel,
      message: unanswerable_message(provider, capabilities.transport, supported)
    }
  end

  # Everything the transport declares it can take, minus the one value it cannot honour.
  # `:default` stays in the list rather than being filtered out: it is always legal, it
  # is frequently the only other thing a narrow provider accepts, and the message says
  # what it means so the list is not read as four equivalent policies.
  defp answerable_modes({_declared, allowlists}) do
    (Map.get(allowlists, :approval_mode) || @approval_modes) -- [:prompt]
  end

  defp answerable_modes(:unresolvable), do: @approval_modes -- [:prompt]

  defp unanswerable_message(provider, transport, supported) do
    "#{inspect(provider)} reaches an interactive session over the #{inspect(transport)} " <>
      "transport, which declares no approvals channel. #{inspect(:prompt)} is accepted " <>
      "there and then asks nobody: every tool call that needs permission is denied " <>
      "without a word, so the session looks alive and cannot work. It can honour " <>
      "approval_mode #{Enum.map_join(supported, ", ", &inspect/1)} — :default meaning " <>
      "the provider's own behavior. State one of those, or use a transport that can ask " <>
      "(Native or ACP)."
  end

  # The options this provider declares for this plane, and the value allowlists that
  # narrow them. Resolved once per call: `Registry.spec/1` re-parses the adapter's spec
  # every time it is asked.
  defp capability(provider, plane) do
    with {:ok, spec} <- Registry.spec(provider),
         {:ok, declared} <- normalized_options(spec, plane) do
      {declared, spec.normalized_values}
    else
      _unresolvable -> :unresolvable
    end
  end

  defp evaluate(:unresolvable, _field, _value), do: :unknown

  defp evaluate({declared, allowlists}, field, value) do
    allowed = Map.get(allowlists, field)

    cond do
      value in @unset_values -> :supported
      field not in declared -> {:unsupported, [:default]}
      is_nil(allowed) -> :supported
      value in allowed -> :supported
      true -> {:unsupported, allowed}
    end
  end

  # A run is validated against the adapter's own list and nothing else.
  defp normalized_options(spec, :coding), do: {:ok, spec.normalized_options}

  # A session is validated against the transport the manager will select, which inherits
  # the adapter's list only when it declares `:adapter`. A transport name no adapter
  # declares is left unresolved on purpose: the harness refuses it by name, and that is a
  # better error than anything this module could invent about sandboxes.
  defp normalized_options(spec, {:interactive, transport}) do
    selected = transport || spec.default_session_transport || first_transport(spec)

    case Enum.find(spec.session_transports, &(&1.name == selected)) do
      %{session_options: :adapter} -> {:ok, spec.normalized_options}
      %{session_options: options} -> {:ok, options}
      # The manager synthesizes a managed transport for an adapter that declares none,
      # and that synthetic transport inherits the adapter's list.
      nil when selected == :managed -> {:ok, spec.normalized_options}
      nil -> :error
    end
  end

  defp first_transport(spec) do
    case spec.session_transports do
      [transport | _rest] -> transport.name
      [] -> :managed
    end
  end

  defp refused(field, value, stated?, accepted) do
    %{
      field: field,
      value: value,
      source: if(stated?, do: :stated, else: :plane_default),
      accepted_values: accepted
    }
  end

  defp refusal(provider, unsupported) do
    override = Enum.map_join(unsupported, ", ", &"#{&1.field}: :default")

    {:unsupported_safety_options,
     %{
       plane: :coding,
       provider: provider,
       options: unsupported,
       override: override,
       message: message(provider, unsupported, override)
     }}
  end

  # The message is the whole point of refusing here rather than letting the harness say
  # "provider does not support normalized option": it names the plane that chose the
  # value, and the one spelling that accepts the provider's own behavior instead.
  defp message(provider, unsupported, override) do
    Enum.map_join(unsupported, " ", &clause(provider, &1)) <>
      " The coding plane refuses rather than silently downgrading a policy it promised," <>
      " so the downgrade has to be typed out: pass #{override} to accept " <>
      "#{inspect(provider)}'s own behavior."
  end

  defp clause(provider, %{source: :plane_default} = refused) do
    "#{inspect(provider)} cannot enforce the coding plane's default #{refused.field}: " <>
      "#{inspect(refused.value)}; it accepts #{inspect(refused.accepted_values)}."
  end

  defp clause(provider, %{source: :stated} = refused) do
    "#{inspect(provider)} cannot enforce #{refused.field}: #{inspect(refused.value)}; " <>
      "it accepts #{inspect(refused.accepted_values)}."
  end
end

defmodule Ouroboros.Provider.RuntimeCache do
  @moduledoc false

  use GenServer

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    server_options =
      case Keyword.fetch(opts, :name) do
        {:ok, nil} -> []
        {:ok, name} -> [name: name]
        :error -> [name: __MODULE__]
      end

    GenServer.start_link(__MODULE__, opts, server_options)
  end

  @impl true
  def init(opts) do
    configure = Keyword.get(opts, :configure, &Ouroboros.Provider.configure_runtime_cache/0)

    case configure.() do
      :ok -> {:ok, :configured}
      {:error, reason} -> {:stop, reason}
      other -> {:stop, {:invalid_provider_runtime_cache_result, other}}
    end
  end
end
