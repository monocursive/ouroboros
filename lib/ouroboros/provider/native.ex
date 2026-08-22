defmodule Ouroboros.Provider.Native do
  @moduledoc """
  The tenth provider: a tool loop Ouroboros owns, in this VM.

  Every other provider drives a vendor CLI. Ouroboros hands it a request, polls its
  events, and is never in the loop where a tool actually runs — so it cannot ask before
  a command executes, append a diagnostic to an edit, or veto anything
  (`docs/AGENT_EXPERIENCE.md` §3.3 F1/F2/F5). This adapter is the one place that is not
  true: the model call, the tool dispatch, and the file writes all happen here, which is
  why it is the only honest home for permission rules, LSP, MCP, hooks, compaction and
  checkpoints (§4.3, D1).

  It registers like the three adapters this runtime already overrides — through
  `config :jido_harness, :providers` — and emits the same normalized event kinds into
  the same journals, gateway stream, and TUI cells. Nothing about a vendor session
  changes because this exists.

  ## What is enforced, and what is not

    * **Path containment is enforced.** Every tool path is canonicalized with
      `Ouroboros.Workspace.Path` and refused outside the session workspace or its
      declared `add_dirs`.
    * **`sandbox_mode: :read_only` is enforced** by refusing `write`, `edit`, and *any*
      `bash` command. There is no OS sandbox yet (§7 Track C5), so a shell cannot be
      made read-only by containing it; the only honest read-only shell is no shell.
    * **`:unrestricted` is not offered.** Declaring a sandbox mode this runtime cannot
      enforce would be a promise no code keeps, so `normalized_values.sandbox_mode`
      lists only `:default`, `:read_only`, and `:workspace_write`.
    * **There is no OS sandbox.** `workspace_write` is the tools' own path checks, not
      Seatbelt or bubblewrap. A `bash` command can still reach the network and can still
      write outside the workspace through a program this runtime does not inspect.
      Approvals, rules, and the ledger are the containment until C5 lands.
    * **No LSP, MCP, hooks, or compaction yet.** Those are D3–D5 and E2; this slice is
      the loop, its tools, its approvals, and its checkpoint.
  """

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.AdapterSpec
  alias Jido.Harness.Capabilities
  alias Jido.Harness.InteractionCapabilities
  alias Jido.Harness.ProviderStatus
  alias Jido.Harness.RunRequest
  alias Jido.Harness.SessionTransportSpec
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Session

  @provider :native

  @doc "The registry key this adapter is registered under."
  @spec provider() :: atom()
  def provider, do: @provider

  @impl true
  def spec do
    AdapterSpec.new!(
      provider: @provider,
      name: "Ouroboros native agent",
      # Not a program on PATH. `ProviderStatus.executable` is a free-form string that
      # every consumer renders; naming the truth beats naming a binary that never exists.
      executable: "in-process",
      capabilities:
        Capabilities.new!(
          streaming?: true,
          tool_calls?: true,
          tool_results?: true,
          thinking?: true,
          resume?: true,
          usage?: true,
          file_changes?: true,
          native_cancel?: true
        ),
      default_session_transport: :native,
      session_transports: [native_transport()],
      normalized_options: [
        :model,
        :system_prompt,
        :max_turns,
        :approval_mode,
        :sandbox_mode,
        :reasoning_effort,
        :attachments,
        :provider_session_id,
        :allowed_tools,
        :disallowed_tools,
        :add_dirs
      ],
      normalized_values: %{
        approval_mode: [:default, :prompt, :auto_edit, :auto_approve],
        # No `:unrestricted`. See the moduledoc: there is no OS sandbox to relax.
        sandbox_mode: [:default, :read_only, :workspace_write]
      },
      provider_options: [:max_iterations, :tool_timeout_ms, :event_limit]
    )
  end

  # One transport, and it is a process this runtime supervises. `steer: :native` is the
  # capability eight of the nine vendor providers cannot declare: the loop is here, so a
  # steered message can be injected between two tool calls of a running turn.
  defp native_transport do
    SessionTransportSpec.new!(
      name: :native,
      adapter: Session,
      capabilities:
        InteractionCapabilities.new!(
          transport: :native,
          maturity: :experimental,
          process: :persistent,
          multi_turn: :native,
          follow_up: :managed,
          interrupt: :native,
          approvals: :native,
          steer: :native,
          # `:attachments` is a normalized option so the coding plane accepts the name,
          # but no tool reads an image yet. Declaring multimodal would let an interactive
          # turn carry an attachment this loop silently drops.
          multimodal: false,
          dynamic_model: :native,
          dynamic_configuration: :native
        ),
      session_options: :adapter,
      session_provider_options: :adapter,
      turn_options: :adapter,
      turn_provider_options: :adapter,
      configuration_options: [:model, :reasoning_effort, :approval_mode, :sandbox_mode]
    )
  end

  @doc """
  Reports which model credentials this node can see, never what they are.

  `installed` is whether the loop's dependencies are loadable; `authenticated` is
  whether at least one ReqLLM provider's key is readable from the environment. The
  detail map carries environment variable *names* and a boolean, which is the whole
  point: a status probe that echoed a key would put it in every `runtime.providers`
  reply, and those cross the gateway.
  """
  @impl true
  def status(_config) do
    credentials = Model.credential_report()
    authenticated? = Enum.any?(credentials, & &1.present)
    available? = Model.available?()

    {:ok,
     ProviderStatus.new!(
       provider: @provider,
       installed: available?,
       compatible: available?,
       authenticated: authenticated?,
       smoke_ready: available? and authenticated? and not is_nil(Model.configured_model()),
       executable: "in-process",
       version: version(),
       capabilities: spec().capabilities,
       session_transports: spec().session_transports,
       details: %{
         "model_env" => Model.model_env(),
         "model" => Model.configured_model(),
         "credentials" => Enum.map(credentials, &Map.new(&1, fn {k, v} -> {to_string(k), v} end)),
         "sandbox" => "none",
         "enforced" => "workspace path containment; read_only refuses write/edit/bash"
       }
     )}
  end

  @doc """
  Runs one finite coding-plane turn to completion and returns its event stream.

  The run worker owns `run_started`/`run_completed`/`run_failed`; everything between
  them is this loop's. The loop runs in a task and the returned stream is that task's
  output, so a consumer that stops reading tears the task down with it.
  """
  @impl true
  def run(%RunRequest{} = request, context) do
    Loop.run_stream(request, context)
  end

  defp version do
    case Application.spec(:ouroboros, :vsn) do
      nil -> nil
      vsn -> to_string(vsn)
    end
  end
end
