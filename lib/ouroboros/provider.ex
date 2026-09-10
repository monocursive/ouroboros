defmodule Ouroboros.Provider do
  @moduledoc """
  The one provider, and what its session transport can be told.

  `:native` — `Ouroboros.Provider.Native`, the tool loop this VM runs — is the only
  provider. The wrapped vendor CLIs are gone, and with them the capability matrix that
  normalised nine of them into one session shape: this module used to answer, per
  provider and per transport, whether a session could be forked, folded, replayed, put
  into plan mode or reconfigured mid-flight. Every one of those questions now has one
  answer, so what is left is that answer plus the two validations that still discriminate
  — a configuration field outside the four the harness normalizes, and a value outside the
  allowlist the adapter declares.

  Nothing here is a boundary. `Jido.Harness.Registry` still carries nine bundled
  vendor-CLI adapters and merges `config :jido_harness, :providers` *over* them, so a
  provider name this build no longer serves still resolves to an upstream adapter.
  `Ouroboros.Interactive.State.new/2` is the boundary that refuses it, by name, before a
  session exists.

  The answers are read from `Ouroboros.Provider.Native.spec/0` rather than restated here,
  so a change to the adapter's declaration cannot drift from what a client is told.
  """

  alias Jido.Harness.Registry

  @provider :native

  # The default posture. Read-only is opt-in.
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

  # Not `InteractionCapabilities` fields: the harness has no notion of forking a session,
  # none of folding one, and none of replaying one. Listed here so the public shape stays
  # one map with one docstring. `:replay` is a boolean rather than a member of the
  # `:native | :managed | :process | false` vocabulary above, because replay is not a
  # thing a transport does some other way — it is a thing this runtime's own turn journal
  # either recorded or did not.
  @derived_capability_keys [:fork, :compact, :replay]

  # What `interactive.configure` may name. Exactly the four fields
  # `Jido.Harness.SessionRequestValidator` normalizes a configuration to
  # (`deps/jido_harness/lib/jido_harness/session/request_validator.ex:7`) — anything else
  # is a start option, not something an open session can be moved to.
  @configuration_fields [:approval_mode, :sandbox_mode, :model, :reasoning_effort]

  # `Jido.Harness` reads each of these as "the caller said nothing" and never checks it
  # against a provider's allowlist. `:default` is therefore always legal to send.
  @unset_values [nil, [], %{}, :default]

  @doc "The only provider this runtime serves."
  @spec provider() :: atom()
  def provider, do: @provider

  @doc """
  Returns the `approval_mode` and `sandbox_mode` a start request carries.

  Both are always present: the native transport declares both options, so neither plane
  default is ever dropped. An option the caller stated is returned unchanged — a sandbox
  the provider cannot enforce has to fail loudly rather than quietly become no sandbox at
  all, so a stated value travels to the harness untouched and the harness refuses it by
  name.
  """
  @spec safety_options(keyword()) :: {:ok, keyword()}
  def safety_options(opts) when is_list(opts) do
    {:ok,
     Enum.map(@plane_defaults, fn {field, default} ->
       {field, Keyword.get(opts, field, default)}
     end)}
  end

  @doc "Returns non-secret execution policy safe to show in public session state."
  @spec public_execution_policy(map() | keyword() | nil, keyword()) :: map()
  def public_execution_policy(options, opts \\ []) do
    model = selected_model(options) || Ouroboros.Provider.Native.Model.configured_model()

    %{
      runtime_ready:
        Ouroboros.Provider.Native.Model.available?() and is_binary(model) and
          Ouroboros.Provider.Native.Model.credential_ready?(model),
      runtime_error: nil,
      model: model,
      transport: :direct,
      interactive_approvals: true,
      escalation_behavior: :prompt,
      surface: Keyword.get(opts, :surface)
    }
  end

  defp selected_model(options) when is_map(options) do
    Map.get(options, :model) || Map.get(options, "model")
  end

  defp selected_model(options) when is_list(options), do: Keyword.get(options, :model)
  defp selected_model(_options), do: nil

  @doc """
  Returns what the native session transport can do.

  Derived from the adapter spec alone. No live process is consulted, because sessions are
  listed after a restart and a capability that only a running coordinator could answer
  would be blank on exactly the rows an operator is trying to understand.

  `nil` only when the registry cannot resolve `:native` at all, which means the adapter is
  not registered and no session can start either.
  """
  @spec session_capabilities() :: map() | nil
  def session_capabilities do
    case Registry.spec(@provider) do
      {:ok, %{session_transports: [%{capabilities: declared} | _rest]}} ->
        @capability_keys
        |> Map.new(&{&1, Map.get(declared, &1, false)})
        # This runtime holds the conversation, so it branches it, folds it with real token
        # counts, and has the turn journal to replay it. All three are the native answer
        # and there is no other transport to ask.
        |> Map.merge(%{fork: :native, compact: :native, replay: true})

      _unresolvable ->
        nil
    end
  end

  @doc "Every key `session_capabilities/0` answers with, declared and derived."
  @spec capability_keys() :: [atom()]
  def capability_keys, do: @capability_keys ++ @derived_capability_keys

  @doc """
  Returns the start options that make a new session a fork of an existing one.

  A fork is a *new* Ouroboros session that carries the parent's `provider_session_id` plus
  the option the transport spells "branch this rather than continue it". `to_turn` names a
  turn to branch *at* rather than at the tail; the native session holds the conversation,
  so it is the one that can be cut anywhere.
  """
  @spec session_fork_options(String.t() | non_neg_integer() | nil) :: {:ok, map()}
  def session_fork_options(to_turn \\ nil) do
    {key, value} = Ouroboros.Provider.Native.fork_option()
    {:ok, fork_turn_option(%{key => value}, to_turn)}
  end

  # A tail fork carries no turn option at all.
  defp fork_turn_option(options, nil), do: options
  defp fork_turn_option(options, to_turn), do: Map.put(options, :fork_to_turn, to_turn)

  @doc """
  Returns the options a *running* session may still be changed to.

  Validated against exactly what `safety_options/1` validates a start against — the option
  list the adapter declares and the `normalized_values` allowlists it narrows them with —
  plus the narrower "and can still be changed once the session is open" list the transport
  declares.

  A change always applies `:now`: the native transport carries it to a live session
  process rather than to the next re-execution of a CLI.
  """
  @spec session_configuration(map()) :: {:ok, map(), :now} | {:error, term()}
  def session_configuration(changes) when is_map(changes) do
    with {:ok, spec} <- configuration_spec(),
         [declared | _rest] <- spec.session_transports,
         :ok <- validate_configuration_fields(changes),
         :ok <- validate_configuration_options(spec, declared, changes),
         :ok <- validate_configuration_values(spec, declared, changes) do
      {:ok, changes, :now}
    end
  end

  def session_configuration(changes),
    do: {:error, {:invalid_configuration, %{reason: :not_a_map, changes: changes}}}

  defp configuration_spec do
    case Registry.spec(@provider) do
      {:ok, spec} ->
        {:ok, spec}

      # Unreachable while `config :jido_harness, :providers` names the adapter, and a
      # `case` rather than a match because an unreachable `MatchError` here would crash a
      # live coordinator.
      _unresolvable ->
        {:error, {:unconfigurable_session, %{provider: @provider, reason: :unknown_provider}}}
    end
  end

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

  # Two lists have to agree, and they answer different questions. `normalized_options` is
  # what the transport accepts *at all* — the same list a start is held to. The
  # transport's `configuration_options` is the narrower "and can still be changed once the
  # session is open". A field outside either is refused by name.
  defp validate_configuration_options(spec, declared, changes) do
    accepted = spec.normalized_options

    case Enum.find(
           Map.keys(changes),
           &(&1 not in accepted or &1 not in declared.configuration_options)
         ) do
      nil ->
        :ok

      field ->
        configurable = Enum.sort(Enum.filter(declared.configuration_options, &(&1 in accepted)))

        {:error,
         {:unconfigurable_session,
          %{
            provider: spec.provider,
            transport: declared.name,
            reason: :option_not_configurable,
            field: field,
            configurable: configurable,
            message:
              "#{inspect(spec.provider)} cannot change #{inspect(field)} on an open " <>
                "session; it can change #{inspect(configurable)}"
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
end
