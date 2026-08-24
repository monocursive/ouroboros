defmodule Ouroboros.Provider.RemovedCodex do
  @moduledoc false

  @behaviour Jido.Harness.Adapter
  alias Jido.Harness.AdapterSpec
  alias Jido.Harness.Capabilities
  alias Jido.Harness.Error
  alias Jido.Harness.ProviderStatus

  @message "the Codex CLI transport was removed; start provider :native with an openai: or openai_codex: model"

  @impl true
  def spec do
    AdapterSpec.new!(
      provider: :codex,
      name: "Codex CLI (removed)",
      executable: "removed",
      capabilities: Capabilities.new!(streaming?: false),
      default_session_transport: nil,
      session_transports: []
    )
  end

  @impl true
  def status(_config) do
    {:ok,
     ProviderStatus.new!(
       provider: :codex,
       installed: false,
       compatible: false,
       authenticated: false,
       smoke_ready: false,
       executable: "removed",
       capabilities: spec().capabilities,
       session_transports: [],
       details: %{"removed" => true, "message" => @message}
     )}
  end

  @impl true
  def run(_request, _context),
    do: {:error, Error.new(:configuration, @message, provider: :codex)}

  @impl true
  def install(_config, _options),
    do: {:error, Error.new(:configuration, @message, provider: :codex)}

  @impl true
  def cancel(_run_id, _context), do: :ok
end
