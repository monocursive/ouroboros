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

  alias Jido.Harness.Registry

  require Logger

  @typedoc """
  Which harness surface the options are bound for. An interactive session also carries
  the transport the caller selected, or `nil` when it takes the adapter's default.
  """
  @type plane :: :coding | {:interactive, atom() | nil}

  # The default posture, in the order a refusal reports it. Read-only is opt-in.
  @plane_defaults [approval_mode: :prompt, sandbox_mode: :workspace_write]

  # Codex's non-interactive transport otherwise refuses an empty directory before the
  # model sees the first turn, and its workspace-write sandbox cannot fetch a dependency
  # unless network access is stated. These are execution facts of the node, not knobs a
  # terminal should have to smuggle through `provider_options`. Explicit caller values
  # still win below, including `false`.
  @execution_defaults %{
    codex: %{skip_git_repo_check: true, network_access_enabled: true}
  }

  # `Jido.Harness` reads each of these as "the caller said nothing" and never checks it
  # against a provider's allowlist. `:default` is therefore always legal to send, which
  # is what makes it the override a refusal can honestly recommend.
  @unset_values [nil, [], %{}, :default]

  @doc "Merges this node's safe provider execution defaults under caller options."
  @spec execution_options(atom(), map() | nil) :: map() | nil
  def execution_options(provider, options) when options in [nil, %{}] do
    defaults = provider |> provider_defaults(%{}) |> normalize_default_keys(provider)
    if defaults == %{} and is_nil(options), do: nil, else: defaults
  end

  def execution_options(provider, options) when is_map(options) do
    defaults = provider |> provider_defaults(%{}) |> normalize_default_keys(provider)
    Map.merge(defaults, normalize_default_keys(options, provider))
  end

  def execution_options(_provider, options), do: options

  @doc "Returns the non-secret execution policy safe to show in public session state."
  @spec public_execution_policy(atom(), map() | nil) :: map()
  def public_execution_policy(:codex, options) when is_map(options) do
    %{
      network_access_enabled: execution_value(options, :network_access_enabled) == true,
      git_repository_required: execution_value(options, :skip_git_repo_check) != true,
      managed_cargo_cache: is_binary(Application.get_env(:ouroboros, :managed_cargo_cache)),
      interactive_approvals: false,
      escalation_behavior: :deny_when_provider_cannot_prompt
    }
  end

  def public_execution_policy(_provider, _options), do: %{}

  @doc false
  @spec apply_execution_directories(map(), atom()) :: map()
  def apply_execution_directories(request, :codex) when is_map(request) do
    case Application.get_env(:ouroboros, :codex_cargo_home) do
      cargo_home when is_binary(cargo_home) and cargo_home != "" ->
        add_dirs =
          case Map.get(request, :add_dirs, []) do
            dirs when is_list(dirs) -> Enum.uniq([cargo_home | dirs])
            _invalid -> [cargo_home]
          end

        Map.put(request, :add_dirs, add_dirs)

      _unset ->
        request
    end
  end

  def apply_execution_directories(request, _provider), do: request

  @doc false
  @spec configure_runtime_cache() :: :ok
  def configure_runtime_cache do
    case Application.get_env(:ouroboros, :data_dir) do
      data_dir when is_binary(data_dir) ->
        cargo_home = Path.join([data_dir, "provider-cache", "codex", "cargo"])

        case File.mkdir_p(cargo_home) do
          :ok ->
            case configure_codex_cache(cargo_home) do
              ^cargo_home ->
                Application.put_env(:ouroboros, :managed_cargo_cache, cargo_home)
                Application.put_env(:ouroboros, :codex_cargo_home, cargo_home)

              operator_home ->
                Application.delete_env(:ouroboros, :managed_cargo_cache)
                Application.put_env(:ouroboros, :codex_cargo_home, operator_home)
            end

          {:error, reason} ->
            Application.delete_env(:ouroboros, :managed_cargo_cache)
            Application.delete_env(:ouroboros, :codex_cargo_home)

            Logger.warning(
              "Codex Cargo cache #{cargo_home} is unavailable: #{:file.format_error(reason)}; " <>
                "Rust turns may need a workspace-local CARGO_HOME"
            )
        end

      _unset ->
        :ok
    end

    :ok
  end

  defp configure_codex_cache(cargo_home) do
    providers =
      case Application.get_env(:jido_harness, :provider_config, %{}) do
        value when is_map(value) or is_list(value) -> Map.new(value)
        _invalid -> %{}
      end

    codex =
      case Map.get(providers, :codex, %{}) do
        value when is_map(value) or is_list(value) -> Map.new(value)
        _invalid -> %{}
      end

    env = codex |> config_map(:env) |> Map.put_new("CARGO_HOME", cargo_home)

    effective_cargo_home =
      case Map.get(env, "CARGO_HOME") do
        path when is_binary(path) and path != "" -> path
        _invalid -> cargo_home
      end

    env = Map.put(env, "CARGO_HOME", effective_cargo_home)

    codex =
      codex
      |> Map.delete("env")
      |> Map.put(:env, env)
      |> put_cache_default(:request_defaults, effective_cargo_home)
      |> put_cache_default(:session_defaults, effective_cargo_home)

    Application.put_env(:jido_harness, :provider_config, Map.put(providers, :codex, codex))
    effective_cargo_home
  end

  defp put_cache_default(config, field, cargo_home) do
    defaults = config_map(config, field)

    add_dirs =
      case Map.get(defaults, :add_dirs, Map.get(defaults, "add_dirs", [])) do
        dirs when is_list(dirs) -> Enum.uniq([cargo_home | dirs])
        _invalid -> [cargo_home]
      end

    defaults = defaults |> Map.delete("add_dirs") |> Map.put(:add_dirs, add_dirs)
    config |> Map.delete(Atom.to_string(field)) |> Map.put(field, defaults)
  end

  defp config_map(config, field) do
    case Map.get(config, field, Map.get(config, Atom.to_string(field), %{})) do
      value when is_map(value) or is_list(value) -> Map.new(value)
      _invalid -> %{}
    end
  end

  defp normalize_default_keys(options, :codex) do
    Map.new(options, fn
      {"skip_git_repo_check", value} -> {:skip_git_repo_check, value}
      {"network_access_enabled", value} -> {:network_access_enabled, value}
      pair -> pair
    end)
  end

  defp normalize_default_keys(options, _provider), do: options

  defp execution_value(options, key),
    do: Map.get(options, key, Map.get(options, Atom.to_string(key)))

  defp provider_defaults(provider, fallback) do
    case Application.get_env(:ouroboros, :provider_execution_defaults, @execution_defaults) do
      configured when is_map(configured) ->
        case Map.get(configured, provider, fallback) do
          defaults when is_map(defaults) -> defaults
          _invalid -> fallback
        end

      _invalid ->
        Map.get(@execution_defaults, provider, fallback)
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

    if unsupported == [],
      do: {:ok, taken},
      else: {:error, refusal(provider, unsupported)}
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
