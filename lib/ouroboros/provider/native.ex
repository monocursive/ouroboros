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
    * **`sandbox_mode: :read_only` is enforced** by refusing `write` and `edit`, and —
      since C5 — by running `bash` inside the node's OS sandbox. Where the node has no
      sandbox backend `bash` is still refused outright, because a shell that cannot be
      made read-only under a read-only label is a lie about the label.
    * **`:unrestricted` is not offered.** `normalized_values.sandbox_mode` lists only
      `:default`, `:read_only`, and `:workspace_write`. C5 gave this provider a sandbox
      to relax, not a reason to offer a mode that turns everything off;
      `Ouroboros.Provider.Native.Sandbox` understands `:unrestricted` so nothing breaks
      if the vocabulary widens, but until someone decides that on purpose the answer to
      "let it out" is a human, not a flag.
    * **The OS sandbox is what the node has.** `Ouroboros.Provider.Native.Sandbox`
      detects macOS `sandbox-exec` or Linux `bwrap`; `ProviderStatus.details["sandbox"]`
      names which, or `none`. On `none`, `workspace_write` is still only the tools' own
      path checks: a `bash` command can reach the network and write outside the
      workspace through a program this runtime does not inspect, and approvals, rules
      and the ledger are the containment. There is no seccomp filter and no domain
      allowlist on any backend.
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
  alias Ouroboros.Provider.Native.Sandbox
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
      # `plan` (B2) is here rather than in `normalized_options` because
      # `Jido.Harness.SessionRequest` has no field for it and its `approval_mode` enum has
      # no fifth member; `provider_options` is the one channel a start can carry it on.
      # Mid-session it moves through `Native.Session.plan_mode/2`, which is a live process
      # call rather than a request field. `Ouroboros.Provider.plan_mode/2` declares both.
      #
      # G3's two are here for the same reason and are deliberately the *only* two a caller
      # may set: `subagent_model` points children at a cheaper model than the parent's, and
      # `subagent_deadline_ms` bounds how long one may run. The rest of a child's shape —
      # its depth, its parent, its task id — is set by this runtime when it opens the child
      # and would be a way to forge a lineage if a request could name it.
      provider_options: [
        :max_iterations,
        :tool_timeout_ms,
        :event_limit,
        :plan,
        :subagent_model,
        :subagent_deadline_ms
      ]
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
          # Not a quality claim. `Jido.Harness.Session.Manager` refuses to *default* to
          # an `:experimental` transport
          # (`deps/jido_harness/lib/jido_harness/session/manager.ex:128`), and this is
          # the provider's only transport — so `:experimental` would mean every caller
          # had to pass `transport: :native` by hand or watch the session refuse to
          # start, including `ouro new --provider native`. Choosing this provider *is*
          # the explicit selection the flag exists to require. How new the loop is, and
          # what it does not yet enforce, is stated in the README and the moduledoc,
          # where it can be read rather than inferred from an enum.
          maturity: :stable,
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
    sandbox = Sandbox.detect()

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
         # The one capability a client needs to stop guessing: the footer may say "no OS
         # sandbox" for a native session only when this says `none`. A string naming the
         # backend, never a boolean — "sandboxed" is not a fact, "sandbox-exec" is.
         "sandbox" => Sandbox.label(sandbox),
         "sandbox_notes" => sandbox.notes,
         "enforced" => enforced(sandbox)
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

  defp enforced(%{backend: :none}),
    do:
      "workspace path containment; read_only refuses write/edit/bash; no OS sandbox on " <>
        "this node, so a bash command is bounded by approvals and rules alone"

  defp enforced(sandbox),
    do:
      "workspace path containment; read_only refuses write/edit and runs bash under " <>
        Sandbox.label(sandbox) <>
        "; workspace_write runs bash under " <>
        Sandbox.label(sandbox) <>
        " with the workspace and declared roots writable, .git/.ouroboros/data dir/user " <>
        "config read-only, and the network denied"

  defp version do
    case Application.spec(:ouroboros, :vsn) do
      nil -> nil
      vsn -> to_string(vsn)
    end
  end
end
