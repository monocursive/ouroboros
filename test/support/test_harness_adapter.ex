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

  # Registered *as* `:native` by the tests that use it, because
  # `Ouroboros.Interactive.State.new/2` refuses every other provider name at the boundary
  # and `Jido.Harness.Registry.spec/1` refuses a spec whose `provider` disagrees with the
  # key it was looked up under. What this adapter stands in for is the native transport
  # with the model taken out: the session mechanics are real, the turns are scripted.
  @provider :native
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
      default_session_transport: :native,
      session_transports: [native_transport()],
      normalized_options: [
        :provider_session_id,
        :approval_mode,
        :sandbox_mode,
        :model,
        # Prompt policy is normalized, not provider-specific: a test provider that
        # rejected it could not exercise an assembled agent profile at all.
        :system_prompt,
        :allowed_tools,
        :disallowed_tools
      ],
      normalized_values: accepted_resume_values(),
      provider_options: [:fork_session, :fork_to_turn]
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

  # Named `:native` because that is the only provider, and this fixture is registered as
  # it. What it declares is what it can actually do: the controller underneath re-executes
  # per turn, so `process`, `multi_turn` and `interrupt` say so rather than borrowing the
  # live loop's answers. `approvals: :native` is the one thing it must declare, because a
  # transport with no approvals channel cannot be started under the plane's default
  # `approval_mode: :prompt`, and `steer: :managed` for the same reason: a transport that
  # declares no steering cannot be steered, and the seam under test is downstream of that.
  defp native_transport do
    %{
      SessionTransportSpec.managed(:native)
      | adapter: Ouroboros.Test.SessionTransport,
        configuration_options: [:model, :reasoning_effort, :approval_mode, :sandbox_mode],
        capabilities:
          InteractionCapabilities.new!(
            transport: :native,
            maturity: :stable,
            process: :per_turn,
            multi_turn: :managed,
            follow_up: :managed,
            interrupt: :process,
            approvals: :native,
            steer: :managed,
            dynamic_model: :managed,
            dynamic_configuration: :managed
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
