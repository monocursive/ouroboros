defmodule Ouroboros.Coding.TaskState do
  @moduledoc "The serializable source of truth for one coding-agent run."

  alias Ouroboros.Coding.Event
  alias Ouroboros.{AgentProfile, Prompt.Assembler, Prompt.Trace}
  alias Ouroboros.Provider

  @envelope_options [:id, :workspace, :workspace_mode, :provider, :event_limit, :origin_digest]
  @request_options [
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
    :sandbox_mode
  ]
  @rejected_inline_options [:env, :env_mode, :mcp_config]
  @accepted_options @envelope_options ++ @request_options ++ @rejected_inline_options

  # Values for these adapter options are reproducible execution policy, not
  # credentials. Rich settings, arbitrary argv, and toolbox maps belong in the
  # node's provider configuration and never in a durable task checkpoint.
  @durable_provider_options [
    :agent,
    :allowed_mcp_server_names,
    :api_timeout_ms,
    :attach,
    :base_url,
    :betas,
    :cli_path,
    :continue,
    :dangerously_allow_all,
    :debug,
    :extensions,
    :fallback_model,
    :fork,
    :fork_session,
    :log_file,
    :log_level,
    :max_budget_usd,
    :model_provider,
    :model_reasoning_summary,
    :network_access_enabled,
    :no_color,
    :no_context_files,
    :no_extensions,
    :no_ide,
    :no_jetbrains,
    :no_notifications,
    :no_session,
    :no_skills,
    :offline,
    :project_trust,
    :resume_last,
    :session_dir,
    :session_name,
    :skip_git_repo_check,
    :skills,
    :skills_dirs,
    :thinking,
    :title,
    :visibility,
    :web_search_enabled
  ]

  @public_request_options [
    :approval_mode,
    :sandbox_mode,
    :model,
    :max_turns,
    :runtime_timeout_ms,
    :idle_timeout_ms,
    :allowed_tools,
    :disallowed_tools,
    :reasoning_effort
  ]

  @enforce_keys [
    :id,
    :objective,
    :workspace,
    :provider,
    :status,
    :created_at,
    :updated_at
  ]
  defstruct @enforce_keys ++
              [
                node: nil,
                workspace_mode: :shared_read,
                origin_digest: nil,
                workspace_lease_id: nil,
                harness_run_id: nil,
                provider_session_id: nil,
                cursor: 0,
                next_sequence: 1,
                event_floor: 0,
                event_limit: 10_000,
                events: [],
                result: nil,
                error: nil,
                prompt_trace: nil,
                options: %{}
              ]

  @type status :: :starting | :running | :completed | :failed | :cancelled | :lost
  @type t :: %__MODULE__{
          id: String.t(),
          objective: String.t(),
          workspace: String.t(),
          provider: atom(),
          status: status(),
          created_at: String.t(),
          updated_at: String.t(),
          node: node(),
          workspace_mode: :shared_read | :exclusive,
          origin_digest: String.t() | nil,
          workspace_lease_id: String.t() | nil,
          harness_run_id: String.t() | nil,
          provider_session_id: String.t() | nil,
          cursor: non_neg_integer(),
          next_sequence: pos_integer(),
          event_floor: non_neg_integer(),
          event_limit: pos_integer(),
          events: [Event.t()],
          result: map() | nil,
          error: term(),
          prompt_trace: map() | nil,
          options: map()
        }

  # The interactive plane builds its own base from this struct, and the two planes differ
  # in what they may do with a safety default the provider cannot enforce, so the plane
  # travels with the call rather than being guessed from the objective.
  @doc false
  @spec new(String.t(), String.t(), keyword(), Provider.plane()) ::
          {:ok, t()} | {:error, term()}
  def new(id, objective, opts, plane \\ :coding)

  def new(id, objective, opts, plane) when is_list(opts) do
    if Keyword.keyword?(opts) and unique_keys?(opts) do
      do_new(id, objective, opts, plane)
    else
      {:error, :invalid_options}
    end
  end

  def new(_id, _objective, _opts, _plane), do: {:error, :invalid_options}

  defp do_new(id, objective, opts, plane) do
    workspace_option = Keyword.get(opts, :workspace, File.cwd!())
    provider = Keyword.get(opts, :provider, :codex)
    sandbox_mode = Keyword.get(opts, :sandbox_mode, :read_only)
    workspace_mode = Keyword.get(opts, :workspace_mode, default_workspace_mode(sandbox_mode))
    origin_digest = Keyword.get(opts, :origin_digest)
    safety = Provider.safety_options(provider, opts, plane)
    assembly = assemble_prompt_options(Map.new(opts))

    cond do
      unknown = unknown_option(opts) ->
        {:error, {:unknown_option, unknown}}

      not is_binary(id) or String.trim(id) == "" ->
        {:error, :invalid_task_id}

      not is_binary(objective) or String.trim(objective) == "" ->
        {:error, :invalid_objective}

      not is_atom(provider) or is_nil(provider) ->
        {:error, :invalid_provider}

      not is_binary(workspace_option) ->
        {:error, {:invalid_workspace, workspace_option}}

      not valid_workspace_mode?(workspace_mode) ->
        {:error, {:invalid_workspace_mode, workspace_mode}}

      not valid_origin_digest?(origin_digest) ->
        {:error, :invalid_origin_digest}

      inline_environment?(opts) ->
        {:error, :inline_environment_not_persisted}

      inline_mcp_config?(opts) ->
        {:error, :inline_mcp_config_not_persisted}

      not valid_system_prompt?(Keyword.get(opts, :system_prompt)) ->
        {:error, :invalid_system_prompt}

      not valid_agent_profile?(Keyword.get(opts, :agent_profile)) ->
        {:error, :invalid_agent_profile}

      not match?({:ok, _assembly}, assembly) ->
        {:error, :invalid_agent_profile_options}

      not valid_provider_options?(provider, Keyword.get(opts, :provider_options, %{})) ->
        {:error, {:unsafe_provider_options, provider}}

      not File.dir?(Path.expand(workspace_option)) ->
        {:error, {:invalid_workspace, Path.expand(workspace_option)}}

      not valid_event_limit?(Keyword.get(opts, :event_limit, 10_000)) ->
        {:error, :invalid_event_limit}

      match?({:error, _reason}, safety) ->
        safety

      true ->
        {:ok, safety_options} = safety
        {:ok, prompt_assembly} = assembly
        workspace = Path.expand(workspace_option)
        now = DateTime.utc_now() |> DateTime.to_iso8601()

        {:ok,
         %__MODULE__{
           id: id,
           objective: objective,
           workspace: workspace,
           provider: provider,
           status: :starting,
           created_at: now,
           updated_at: now,
           node: node(),
           workspace_mode: workspace_mode,
           origin_digest: origin_digest,
           event_limit: Keyword.get(opts, :event_limit, 10_000),
           prompt_trace: Assembler.trace(prompt_assembly),
           options: request_options(opts, safety_options, prompt_assembly)
         }}
    end
  end

  @doc false
  @spec terminal?(t()) :: boolean()
  def terminal?(%__MODULE__{status: status}),
    do: status in [:completed, :failed, :cancelled, :lost]

  @doc "Returns whether a reconstructed task can safely build a Harness request."
  @spec requestable?(term()) :: boolean()
  def requestable?(state), do: unrequestable_reason(state) == nil

  @doc """
  Returns why a reconstructed task cannot build a Harness request, or `nil`.

  A task whose durable prompt cannot be trusted — a profile option a rollback would
  hand to Harness, a prompt that is no longer a UTF-8 binary, a trace from a prompt
  format this build does not implement — fails as itself, by name. It is not grounds
  for refusing to load the checkpoint that contains it.
  """
  @spec unrequestable_reason(term()) :: term() | nil
  def unrequestable_reason(%__MODULE__{options: options} = state) when is_map(options) do
    system_prompt = Map.get(options, :system_prompt)

    cond do
      Map.has_key?(options, :agent_profile) ->
        :agent_profile_in_durable_options

      not valid_system_prompt?(system_prompt) ->
        :invalid_system_prompt

      true ->
        case Trace.validate(Map.get(state, :prompt_trace), system_prompt) do
          :ok -> nil
          {:error, reason} -> reason
        end
    end
  rescue
    error -> {:invalid_task_state, error.__struct__}
  catch
    kind, _reason -> {:invalid_task_state, kind}
  end

  def unrequestable_reason(_state), do: :invalid_task_state

  @doc false
  @spec public(t()) :: t()
  def public(%__MODULE__{} = state) do
    prompt_trace = Map.get(state, :prompt_trace)

    options =
      state.options
      |> Map.take(@public_request_options)
      |> Map.put(:has_system_prompt, present?(state.options[:system_prompt]))
      |> Map.put(:attachment_count, list_count(state.options[:attachments]))
      |> Map.put(:additional_directory_count, list_count(state.options[:add_dirs]))
      |> Map.put(:has_provider_options, map_size(state.options[:provider_options] || %{}) > 0)
      |> Trace.put(prompt_trace)

    state
    |> Map.put(:origin_digest, nil)
    |> Map.put(:options, options)
  end

  @doc false
  def request(%__MODULE__{} = state) do
    prompt_trace = Map.get(state, :prompt_trace)

    metadata =
      %{
        ouroboros_task_id: state.id,
        ouroboros_node: Atom.to_string(node())
      }
      |> Trace.put(prompt_trace, :ouroboros_prompt)

    state.options
    |> Map.delete(:agent_profile)
    |> Map.merge(%{
      prompt: state.objective,
      cwd: state.workspace,
      metadata: metadata
    })
  end

  # `Ouroboros.Provider` has already decided what the two safety options may be, stated
  # values included, so they are dropped here and merged back rather than defaulted a
  # second time. An option it omitted must be absent from the request, not present as
  # `nil`: absent is what leaves the harness request at `:default`.
  defp request_options(opts, safety_options, assembly) do
    opts
    |> Keyword.take(@request_options)
    |> Keyword.drop([:approval_mode, :sandbox_mode, :agent_profile])
    |> Keyword.merge(safety_options)
    |> Map.new()
    |> put_system_prompt(assembly.system_prompt)
  end

  defp valid_event_limit?(limit), do: is_integer(limit) and limit > 0 and limit <= 100_000

  defp unique_keys?(opts) do
    keys = Keyword.keys(opts)
    Enum.uniq(keys) == keys
  end

  defp default_workspace_mode(:read_only), do: :shared_read
  defp default_workspace_mode(_sandbox_mode), do: :exclusive

  defp valid_workspace_mode?(mode), do: mode in [:shared_read, :exclusive]

  defp valid_origin_digest?(nil), do: true

  defp valid_origin_digest?(digest) when is_binary(digest) do
    case Base.decode16(digest, case: :lower) do
      {:ok, decoded} when byte_size(decoded) == 32 -> true
      _other -> false
    end
  end

  defp valid_origin_digest?(_digest), do: false

  defp inline_environment?(opts) do
    Keyword.has_key?(opts, :env) or Keyword.has_key?(opts, :env_mode)
  end

  defp inline_mcp_config?(opts), do: Keyword.has_key?(opts, :mcp_config)

  defp unknown_option(opts) do
    opts
    |> Keyword.keys()
    |> Enum.find(&(&1 not in @accepted_options))
  end

  defp valid_provider_options?(_provider, options) when options in [nil, %{}], do: true

  defp valid_provider_options?(provider, options) when is_map(options) do
    allowed_by_adapter =
      case Jido.Harness.Registry.spec(provider) do
        {:ok, spec} -> spec.provider_options
        {:error, _reason} -> []
      end

    Enum.all?(options, fn {key, value} ->
      atom_key = normalize_provider_option_key(key, allowed_by_adapter)

      atom_key in @durable_provider_options and
        atom_key in allowed_by_adapter and
        Jido.Harness.Redaction.redact(value) == value
    end)
  end

  defp valid_provider_options?(_provider, _options), do: false

  defp valid_agent_profile?(nil), do: true
  defp valid_agent_profile?(%AgentProfile{} = profile), do: AgentProfile.valid?(profile)
  defp valid_agent_profile?(_profile), do: false

  defp valid_system_prompt?(prompt),
    do: is_nil(prompt) or (is_binary(prompt) and String.valid?(prompt))

  defp assemble_prompt_options(options) do
    Assembler.assemble(Map.get(options, :agent_profile),
      system_prompt: Map.get(options, :system_prompt),
      allowed_tools: Map.get(options, :allowed_tools),
      disallowed_tools: Map.get(options, :disallowed_tools)
    )
  end

  defp normalize_provider_option_key(key, _allowed) when is_atom(key), do: key

  defp normalize_provider_option_key(key, allowed) when is_binary(key) do
    Enum.find(allowed, &(Atom.to_string(&1) == key))
  end

  defp normalize_provider_option_key(_key, _allowed), do: nil

  defp present?(value), do: value not in [nil, "", [], %{}]
  defp list_count(value) when is_list(value), do: length(value)
  defp list_count(_value), do: 0

  defp put_system_prompt(options, nil), do: Map.delete(options, :system_prompt)

  defp put_system_prompt(options, system_prompt),
    do: Map.put(options, :system_prompt, system_prompt)
end
