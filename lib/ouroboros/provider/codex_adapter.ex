defmodule Ouroboros.Provider.CodexAdapter do
  @moduledoc false

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.Adapters.{Codex, Helpers}
  alias Jido.Harness.SessionTransportSpec
  alias Jido.Harness.Redaction
  alias Ouroboros.HarnessEventProjection
  alias Ouroboros.Provider.CodexSession

  @impl true
  def spec do
    # Coding `run/2` stays on `codex exec --json`. Interactive sessions default to
    # app-server so a sandbox escalation can complete `respond_approval` instead of
    # being denied inside a one-way JSONL stream. The exec transport remains a named
    # fallback (`transport: :exec_jsonl_resume`), not the default.
    base = Codex.spec()
    exec_jsonl = Enum.filter(base.session_transports, &(&1.name == :exec_jsonl_resume))

    %{
      base
      | default_session_transport: :app_server,
        session_transports: [app_server_transport() | exec_jsonl]
    }
  end

  defp app_server_transport do
    SessionTransportSpec.new!(
      name: :app_server,
      adapter: CodexSession,
      capabilities: Ouroboros.Provider.Session.Dialect.Codex.capabilities(),
      session_options: :adapter,
      session_provider_options: :adapter,
      turn_options: :adapter,
      turn_provider_options: :adapter,
      configuration_options: [:model, :reasoning_effort, :approval_mode, :sandbox_mode]
    )
  end

  @impl true
  defdelegate status(config), to: Codex

  @impl true
  def run(request, context) do
    # The upstream adapter applies provider-config env before dispatch. Derive the
    # journal redaction set from that exact effective environment as well, otherwise a
    # credential configured at the provider boundary could survive in command/output
    # payloads even though it was never present on the caller's request.
    secrets = request |> Helpers.merge_env(context.config) |> Redaction.secrets_from_env()

    case Codex.run(request, context) do
      {:ok, events} ->
        {:ok, Stream.map(events, &before_journal(&1, secrets))}

      other ->
        other
    end
  end

  @impl true
  defdelegate install(config, options), to: Codex

  @impl true
  defdelegate cancel(run_id, context), to: Codex

  defp before_journal(event, secrets) do
    event = HarnessEventProjection.before_journal(event, secrets)

    # EventStore strips raw data only after adapter events cross this boundary. Redact
    # both fields here so live consumers and every mapped Codex event (including command
    # completion/tool output) receive the same provider-config secret protection.
    %{
      event
      | payload: Redaction.redact(event.payload, secrets),
        raw: Redaction.redact(event.raw, secrets)
    }
  end
end
