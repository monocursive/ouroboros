defmodule Ouroboros.Test.SessionTransport do
  @moduledoc """
  Deterministic interactive session transport that declares steering support.

  The shared `Ouroboros.Test.HarnessAdapter` is a run adapter only, so Harness
  synthesizes its managed session transport for it — and that transport declares no
  `steer` capability and its adapter module has no `steer/3`, which is why no live
  steer test could exist before this module. Sessions started on `:test_rpc` accept a
  steer without any provider process: the session worker itself appends the
  synchronous `input_accepted` event, so everything downstream of acceptance is real.

  Turn mechanics delegate to the managed transport, so one controller pattern drives
  both providers (`test_pid` receives the started adapter exactly as elsewhere).
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

  # A real provider transport would forward the steered text to its process here. The
  # worker has already recorded acceptance, which is the part these tests observe.
  @impl true
  def steer(_handle, _request, _request_id), do: :ok
end

defmodule Ouroboros.Test.SessionHarnessAdapter do
  @moduledoc """
  Run-adapter twin of `#{Ouroboros.Test.HarnessAdapter}` whose sessions can steer.

  Register as `:ouroboros_test_session` beside the base adapter when a test needs an
  interactive session whose transport declares `steer`. Runs behave identically to the
  base adapter, so the same emit/finish controller pattern works unchanged.
  """

  @behaviour Jido.Harness.Adapter

  @provider :ouroboros_test_session

  @impl true
  def spec do
    base = Ouroboros.Test.HarnessAdapter.spec()

    Jido.Harness.AdapterSpec.new!(
      base
      |> Map.from_struct()
      |> Map.merge(%{
        provider: @provider,
        default_session_transport: :test_rpc,
        session_transports: [
          Jido.Harness.SessionTransportSpec.new!(
            name: :test_rpc,
            adapter: Ouroboros.Test.SessionTransport,
            capabilities:
              Jido.Harness.InteractionCapabilities.new!(
                transport: :test_rpc,
                multi_turn: :managed,
                follow_up: :managed,
                steer: :managed,
                interrupt: :process
              ),
            session_options: :adapter,
            session_provider_options: :adapter,
            turn_options: :adapter,
            turn_provider_options: :adapter,
            configuration_options: [:model, :reasoning_effort, :approval_mode, :sandbox_mode]
          )
        ]
      })
    )
  end

  @impl true
  def status(_config) do
    {:ok,
     Jido.Harness.ProviderStatus.new!(
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
  defdelegate run(request, context), to: Ouroboros.Test.HarnessAdapter
  @impl true
  defdelegate cancel(run_id, context), to: Ouroboros.Test.HarnessAdapter
end
