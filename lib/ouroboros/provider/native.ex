defmodule Ouroboros.Provider.Native do
  @moduledoc """
  Native execution declarations and configuration owned by Ouroboros.

  The model call, permission decisions, tool dispatch, compaction, and conversation
  checkpoints run in this VM. Session scheduling and delivery are owned by
  `Ouroboros.Provider.Native.Session`; this module describes its public capabilities.

  `:unrestricted` disables the shell OS sandbox only. Structured file tools retain
  workspace path containment, and approvals, rules, plan posture, and the effect ledger
  remain authoritative. Without an OS sandbox backend, read-only and workspace-write
  shell commands refuse unless the existing explicit unsandboxed policy permits them.
  """

  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Session

  @provider :native

  @doc "Reads native runtime settings directly from the Ouroboros application."
  @spec config() :: map()
  def config, do: :ouroboros |> Application.get_env(:native_provider, %{}) |> Map.new()

  @doc "The one provider supported by this runtime."
  @spec provider() :: atom()
  def provider, do: @provider

  def spec do
    Map.new(
      provider: @provider,
      install: nil,
      docs_url: nil,
      request_defaults: %{},
      name: "Ouroboros native agent",
      # Not a program on PATH. `ProviderStatus.executable` is a free-form string that
      # every consumer renders; naming the truth beats naming a binary that never exists.
      executable: "in-process",
      capabilities:
        Map.new(
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
        :plan,
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
        reasoning_effort: Ouroboros.ReasoningEffort.atoms_or_nil(),
        # `:unrestricted` is the shell's OS sandbox turned off, and nothing else. See the
        # moduledoc for what it does not relax.
        sandbox_mode: [:default, :read_only, :workspace_write, :unrestricted]
      },
      # These are runtime-specific bounds and fork/child settings. Plan posture is an
      # explicit Request field, independent of the provider options map.
      provider_options: [
        :max_iterations,
        :tool_timeout_ms,
        :event_limit,
        :subagent_model,
        :fork_session,
        :fork_to_turn,
        :subagent_deadline_ms
      ]
    )
  end

  @doc false
  def fork_option, do: {:fork_session, true}

  # One transport, and it is a process this runtime supervises. `steer: :native` is the
  # capability eight of the nine vendor providers cannot declare: the loop is here, so a
  # steered message can be injected between two tool calls of a running turn.
  defp native_transport do
    Map.new(
      name: :native,
      minimum_version: nil,
      adapter: Session,
      capabilities:
        Map.new(
          transport: :native,
          maturity: :stable,
          process: :persistent,
          multi_turn: :native,
          follow_up: :managed,
          interrupt: :native,
          approvals: :native,
          steer: :native,
          # Authorized images are copied into the session's private attachment store and
          # sent as ReqLLM image content parts; other files are named for the read tool.
          structured_output: false,
          multimodal: :native,
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
  whether the configured model's provider has a usable key or OAuth credential. Detail
  rows expose names and booleans only.
  """
  def status(_config) do
    credentials = Model.credential_report()
    model = Model.configured_model()
    authenticated? = Model.credential_ready?(model)
    available? = Model.available?()
    sandbox = Sandbox.detect()

    {:ok,
     Map.new(
       provider: @provider,
       error: nil,
       installed: available?,
       compatible: available?,
       authenticated: authenticated?,
       smoke_ready: available? and authenticated? and is_binary(model),
       executable: "in-process",
       version: version(),
       capabilities: spec().capabilities,
       session_transports: spec().session_transports,
       details: %{
         "model_env" => Model.model_env(),
         "model" => model,
         "credentials" => Enum.map(credentials, &Map.new(&1, fn {k, v} -> {to_string(k), v} end)),
         # The one capability a client needs to stop guessing: the footer may say "no OS
         # sandbox" for a native session only when this says `none`. A string naming the
         # backend, never a boolean — "sandboxed" is not a fact, "sandbox-exec" is.
         "sandbox" => Sandbox.label(sandbox),
         "sandbox_notes" => sandbox.notes,
         "enforced" => enforced(sandbox)
       }
     )}
  end

  defp enforced(%{backend: :none}),
    do:
      "workspace path containment; read_only refuses write/edit/bash; no OS sandbox on " <>
        "this node, so workspace_write refuses bash too unless " <>
        "OUROBOROS_ALLOW_UNSANDBOXED_BASH=1; unrestricted is an unsandboxed shell, " <>
        "asked for by name"

  defp enforced(sandbox),
    do:
      "workspace path containment; read_only refuses write/edit and runs bash under " <>
        Sandbox.label(sandbox) <>
        "; workspace_write runs bash under " <>
        Sandbox.label(sandbox) <>
        " with the workspace and declared roots writable, .git/.ouroboros/data dir/user " <>
        "config read-only, and the network denied; unrestricted runs bash with no OS " <>
        "sandbox at all, and leaves the file tools' path containment in place"

  defp version do
    case Application.spec(:ouroboros, :vsn) do
      nil -> nil
      vsn -> to_string(vsn)
    end
  end
end
