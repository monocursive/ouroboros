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
    * **`:unrestricted` is offered, deliberately.** `normalized_values.sandbox_mode`
      lists `:default`, `:read_only`, `:workspace_write`, and `:unrestricted`, valid at
      start and through `interactive.configure`. C5 said the answer to "let it out" was
      a human rather than a flag; the human has since decided, so the flag exists and
      says what it does. What it means is narrow and worth stating exactly:

        * It is about **the shell**. `bash` runs with no OS sandbox — the
          `{:unsandboxed, :unrestricted}` branch of `Ouroboros.Provider.Native.Sandbox`,
          which logs a warning naming the session every time a command takes it. The
          `sandbox` marker on the `bash` tool call reads `none`, so a client footer says
          "no OS sandbox" from a fact rather than a guess.
        * It is **not** about the structured file tools. `write`, `edit`, `apply_patch`
          and every path-taking tool keep their `Ouroboros.Workspace.Path` containment
          inside the workspace and its declared `add_dirs`. Widening those is a separate
          decision nobody has made, and quietly folding it into this one would mean the
          mode did two things under one name.
        * It is **not** about who is asked. `approval_mode`, the C1 permission engine,
          the hooks and the effect ledger are untouched: full access answers "what can
          be written", never "who is asked".
        * Plan mode still outranks it. Entering plan mode forces `:read_only` and
          remembers what it displaced, `:unrestricted` included, and leaving restores it.
    * **The OS sandbox is what the node has.** `Ouroboros.Provider.Native.Sandbox`
      detects macOS `sandbox-exec` or Linux `bwrap`; `ProviderStatus.details["sandbox"]`
      names which, or `none`. On `none`, `workspace_write` is still only the tools' own
      path checks: a `bash` command can reach the network and write outside the
      workspace through a program this runtime does not inspect, and approvals, rules
      and the ledger are the containment. There is no seccomp filter and no domain
      allowlist on any backend.
    * **LSP, MCP, hooks, compaction, and checkpoints live in this adapter.** They are
      the reason this provider exists in-process rather than as another CLI: the loop
      can ask before a tool runs, append a diagnostic to an edit, fold a conversation it
      actually holds, and refuse a compaction whose archive cannot be written. Vendor
      transports still own whatever of those they implement themselves; this module does
      not invent a second copy for a transcript it never had.
  """

  @behaviour Jido.Harness.Adapter

  alias Jido.Harness.AdapterSpec
  alias Jido.Harness.Capabilities
  alias Jido.Harness.InteractionCapabilities
  alias Jido.Harness.ProviderStatus
  alias Jido.Harness.RunRequest
  alias Jido.Harness.SessionTransportSpec
  alias Ouroboros.Provider.Native.Run
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
        reasoning_effort: Ouroboros.ReasoningEffort.atoms_or_nil(),
        # `:unrestricted` is the shell's OS sandbox turned off, and nothing else. See the
        # moduledoc for what it does not relax.
        sandbox_mode: [:default, :read_only, :workspace_write, :unrestricted]
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
      # R3's `fork_to_turn` rides beside `fork_session` for the same reason: a fork's
      # branch point is start intent that only exists at open, and this is the one channel
      # a start carries it on. It is meaningless without `fork_session`, and the session
      # ignores it when that is absent — a resume is not a branch.
      provider_options: [
        :max_iterations,
        :tool_timeout_ms,
        :event_limit,
        :plan,
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
          # Authorized images are copied into the session's private attachment store and
          # sent as ReqLLM image content parts; other files are named for the read tool.
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
  @impl true
  def status(_config) do
    credentials = Model.credential_report()
    model = Model.configured_model()
    authenticated? = Model.credential_ready?(model)
    available? = Model.available?()
    sandbox = Sandbox.detect()

    {:ok,
     ProviderStatus.new!(
       provider: @provider,
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

  @doc """
  Runs one finite coding-plane turn to completion and returns its event stream.

  The run worker owns `run_started`/`run_completed`/`run_failed`; everything between
  them is the session-backed bridge's stream. Coding and interactive turns therefore
  restore and checkpoint the same conversation instead of maintaining two implementations.
  """
  @impl true
  def run(%RunRequest{} = request, context) do
    with {:ok, pid, _provider_session_id} <- Run.start(request, context) do
      {:ok, Run.stream(pid)}
    end
  end

  defp enforced(%{backend: :none}),
    do:
      "workspace path containment; read_only refuses write/edit/bash; no OS sandbox on " <>
        "this node, so a bash command is bounded by approvals and rules alone; " <>
        "unrestricted is the same posture, asked for by name"

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
