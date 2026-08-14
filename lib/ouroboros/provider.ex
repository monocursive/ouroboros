defmodule Ouroboros.Provider do
  @moduledoc """
  What a provider will actually accept for the two options the planes default.

  Both planes want to start under a conservative posture: approvals prompted and the
  workspace read-only. Four of the nine bundled providers cannot be told that. Amp
  declares neither option, OpenCode declares no `sandbox_mode`, Kimi declares both but
  accepts only `:default` for each, and Pi refuses `:prompt` approvals. `Jido.Harness`
  refuses any normalized option a provider has not declared, so injecting the
  conservative pair unconditionally did not make those four providers safe — it made
  them unstartable.

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
    * The coding plane refuses at creation, because its read-only default is a promise
      the README makes to whoever starts a task, and quietly dropping it would break
      that promise in the one direction that matters.

  Neither plane rewrites or drops an option the caller stated. A sandbox the provider
  cannot enforce has to fail loudly rather than quietly become no sandbox at all, so a
  stated value travels to the harness untouched and the harness refuses it by name.
  """

  alias Jido.Harness.Registry

  @typedoc """
  Which harness surface the options are bound for. An interactive session also carries
  the transport the caller selected, or `nil` when it takes the adapter's default.
  """
  @type plane :: :coding | {:interactive, atom() | nil}

  # The conservative posture, in the order a refusal reports it.
  @plane_defaults [approval_mode: :prompt, sandbox_mode: :read_only]

  # `Jido.Harness` reads each of these as "the caller said nothing" and never checks it
  # against a provider's allowlist. `:default` is therefore always legal to send, which
  # is what makes it the override a refusal can honestly recommend.
  @unset_values [nil, [], %{}, :default]

  @doc """
  Returns the `approval_mode` and `sandbox_mode` a request for `provider` may carry.

  Options the caller stated in `opts` are returned unchanged. Options the caller left
  unset take the plane's conservative default when the provider can accept it. On the
  interactive plane an unacceptable default is omitted from the result; on the coding
  plane it is refused, and so is a stated value the provider cannot enforce.

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
