defmodule Ouroboros.Test.ManagedSessionTransport do
  @moduledoc """
  The managed session transport with an approvals channel.

  Turn mechanics delegate to `Jido.Harness.SessionAdapters.Managed`, so the one
  emit/finish controller pattern drives these sessions exactly as before. The one thing
  added is `respond_approval/3`: a session transport that declares no approvals cannot
  be started under the plane's default `approval_mode: :prompt`
  (`Ouroboros.Provider.safety_options/3`), because a managed CLI re-executed per turn
  has nobody to ask and denies silently instead. A fixture standing in for the
  approval-capable providers (Codex app-server, ACP) has to answer, not just declare.
  """

  @behaviour Jido.Harness.SessionAdapter

  @impl true
  defdelegate open(request, context), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  defdelegate send(handle, request, turn_id), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  defdelegate interrupt(handle, turn_id), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  defdelegate close(handle), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  def configure(handle, changes),
    do: Jido.Harness.SessionAdapters.Managed.configure(handle, changes)

  # A real transport would forward the decision to its provider process here. The worker
  # has already resolved the pending approval, which is the part these tests observe.
  @impl true
  def respond_approval(_handle, _request_id, _response), do: :ok
end

defmodule Ouroboros.Test.HarnessAdapter do
  @moduledoc false

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.{
    AdapterSpec,
    Capabilities,
    Event,
    InteractionCapabilities,
    ProviderStatus,
    RunRequest,
    SessionTransportSpec
  }

  @provider :ouroboros_test
  @accepted_resume_ids_key :test_harness_adapter_accepted_resume_ids

  @impl true
  def spec do
    AdapterSpec.new!(
      provider: @provider,
      name: "Ouroboros deterministic test adapter",
      executable: "in-memory",
      capabilities:
        Capabilities.new!(
          streaming?: true,
          resume?: resumes?(),
          usage?: true,
          native_cancel?: true
        ),
      default_session_transport: :managed,
      session_transports: [managed_transport(), unanswerable_transport(), frozen_transport()],
      normalized_options: [
        :provider_session_id,
        :approval_mode,
        :sandbox_mode,
        # Prompt policy is normalized, not provider-specific: a test provider that
        # rejected it could not exercise an assembled agent profile at all.
        :system_prompt,
        :allowed_tools,
        :disallowed_tools
      ],
      normalized_values: accepted_resume_values(),
      provider_options: [:fork_session]
    )
  end

  @doc """
  Declares that a start request carrying `fork_session: true` branches the resumed session.

  The same declaration `Ouroboros.Provider` reads from a dialect, made by an adapter this
  repository owns. It is what gives this provider `fork: :native` without adding a test
  module to the table in `Ouroboros.Provider` that covers the pinned upstream adapters.
  """
  @spec fork_option() :: {atom(), term()}
  def fork_option, do: {:fork_session, true}

  # Named `:managed` because that is the transport Harness would otherwise synthesize for
  # an adapter that declares none, so every existing expectation about this provider's
  # transport name still holds. `dynamic_model` is `false` rather than `:managed` because
  # this adapter normalizes no `:model` — the same narrowing
  # `Jido.Harness.Session.Manager.specialize_transport/2` applies to the synthetic one.
  defp managed_transport do
    %{
      SessionTransportSpec.managed(:managed)
      | adapter: Ouroboros.Test.ManagedSessionTransport,
        capabilities:
          InteractionCapabilities.new!(
            transport: :managed,
            process: :per_turn,
            multi_turn: :managed,
            follow_up: :managed,
            interrupt: :process,
            approvals: :native,
            dynamic_model: false,
            dynamic_configuration: :managed
          )
    }
  end

  # The managed transport as the bundled ones actually ship it: no approvals channel.
  # X1 is a rule about *this* shape, and a session cannot be started into `:prompt` here
  # — which is exactly why the same rule has to hold on `interactive.configure`, where a
  # session started into a mode that works could otherwise be moved into one that asks
  # nobody. This transport is what lets that be tested end to end.
  defp unanswerable_transport do
    %{
      SessionTransportSpec.managed(:managed_no_approvals)
      | adapter: Jido.Harness.SessionAdapters.Managed,
        capabilities:
          InteractionCapabilities.new!(
            transport: :managed_no_approvals,
            process: :per_turn,
            multi_turn: :managed,
            follow_up: :managed,
            interrupt: :process,
            dynamic_model: false,
            dynamic_configuration: :managed
          )
    }
  end

  # A transport that declares no dynamic configuration at all, as ACP does. Nothing about
  # an open session on it can be changed, and the refusal has to come from the
  # declaration rather than from a failed call.
  defp frozen_transport do
    %{
      SessionTransportSpec.managed(:managed_frozen)
      | adapter: Ouroboros.Test.ManagedSessionTransport,
        configuration_options: [],
        capabilities:
          InteractionCapabilities.new!(
            transport: :managed_frozen,
            process: :per_turn,
            multi_turn: :managed,
            follow_up: :managed,
            interrupt: :process,
            approvals: :native,
            dynamic_model: false,
            dynamic_configuration: false
          )
    }
  end

  @doc """
  Declares which provider session ids this adapter will still answer to.

  A resume is a session start that carries `provider_session_id`, so the honest way to
  make this provider refuse one is to say which ids it still knows: the Harness session
  manager validates the start request against exactly this list. `:any` — the default,
  and what `reset_resume/0` restores — accepts every id, `[]` refuses every one, and
  `:unsupported` withdraws the `resume?` capability altogether, which is a different
  answer: the provider cannot resume at all rather than refusing this particular thread.
  """
  @spec accept_resume(:any | :unsupported | [String.t()]) :: :ok
  def accept_resume(accepted) when accepted in [:any, :unsupported] or is_list(accepted),
    do: Application.put_env(:ouroboros, @accepted_resume_ids_key, accepted)

  @doc "Restores the default: every provider session id is accepted."
  @spec reset_resume() :: :ok
  def reset_resume, do: Application.delete_env(:ouroboros, @accepted_resume_ids_key)

  defp accepted_resume_ids, do: Application.get_env(:ouroboros, @accepted_resume_ids_key, :any)

  defp resumes?, do: accepted_resume_ids() != :unsupported

  # Narrowed the way Kimi and Pi narrow theirs: a normalized value the adapter cannot
  # enforce is named in `normalized_values` and refused by the harness rather than
  # silently downgraded. `:unrestricted` is the one this provider does not accept, which
  # is what gives `interactive.configure` an allowlist to be refused by.
  @accepted_sandbox_modes [:default, :read_only, :workspace_write]

  defp accepted_resume_values do
    case accepted_resume_ids() do
      ids when is_list(ids) -> %{provider_session_id: ids, sandbox_mode: @accepted_sandbox_modes}
      _every_id -> %{sandbox_mode: @accepted_sandbox_modes}
    end
  end

  @impl true
  def status(_config) do
    {:ok,
     ProviderStatus.new!(
       provider: @provider,
       installed: true,
       compatible: true,
       authenticated: true,
       smoke_ready: true,
       executable: "in-memory",
       capabilities: spec().capabilities
     )}
  end

  @impl true
  def run(%RunRequest{} = request, context) do
    with controller when is_pid(controller) <- controller(context.config) do
      adapter = self()
      provider_session_id = request.provider_session_id || "ouroboros-test-session"

      send(
        controller,
        {:ouroboros_test_adapter_started, context.run_id, request, adapter}
      )

      {:ok, controlled_stream(controller, context.run_id, provider_session_id)}
    else
      _ -> {:error, :test_controller_not_configured}
    end
  end

  @impl true
  def cancel(run_id, context) do
    case controller(context.config) do
      pid when is_pid(pid) -> send(pid, {:ouroboros_test_adapter_cancelled, run_id})
      _ -> :ok
    end

    :ok
  end

  @doc """
  Emits one event from a running turn.

  `fields` carries the event's own non-payload identities — today `:request_id`, which is
  what an `approval_requested` / `approval_resolved` pair is correlated by everywhere in
  this runtime. A fixture that could not set it could not stand in for a transport with an
  approvals channel at all.
  """
  @spec emit(pid(), Event.event_type(), map(), keyword()) :: :ok
  def emit(adapter, type, payload \\ %{}, fields \\ [])
      when is_pid(adapter) and is_atom(type) and is_map(payload) and is_list(fields) do
    send(adapter, {:ouroboros_test_emit, type, payload, fields})
    :ok
  end

  @spec finish(pid()) :: :ok
  def finish(adapter) when is_pid(adapter) do
    send(adapter, :ouroboros_test_finish)
    :ok
  end

  defp controlled_stream(controller, run_id, provider_session_id) do
    Stream.resource(
      fn -> provider_session_id end,
      fn provider_session_id ->
        receive do
          {:ouroboros_test_emit, type, payload, fields} ->
            event =
              Event.new!(
                [
                  provider: @provider,
                  type: type,
                  provider_session_id: provider_session_id,
                  payload: payload
                ] ++ Keyword.take(fields, [:request_id, :turn_id])
              )

            {[event], provider_session_id}

          :ouroboros_test_finish ->
            {:halt, provider_session_id}
        end
      end,
      fn _provider_session_id ->
        send(controller, {:ouroboros_test_adapter_closed, run_id})
      end
    )
  end

  defp controller(config) do
    Map.get(config, :test_pid) || Map.get(config, "test_pid")
  end
end
