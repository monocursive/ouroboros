defmodule Ouroboros.Provider.Native.Hooks do
  @moduledoc """
  Lifecycle hooks for the native agent, on the contract Claude Code, Codex, Gemini and
  Factory all already speak.

  Four vendors converged on the same JSON shape (R3 §4.2), which means a hook script
  somebody already wrote for one of them works here unchanged. That compatibility is the
  whole point; inventing a fifth contract would make this feature worth less than not
  having it.

  ## Where hooks are declared

      config :ouroboros, :hooks          node scope — operator configuration, runs first
      ~/.config/ouroboros/hooks.toml     user scope — always honoured
      <workspace>/ouroboros.toml         project scope — shell hooks require workspace trust

      [[hooks]]
      event = "PreToolUse"
      matcher = "Bash|Edit|Write"
      command = "./scripts/vet.sh"
      timeout_ms = 10000

      [[hooks]]
      event = "PreToolUse"
      component = "./hooks/vet.wasm"
      config = "{\\"strict\\":true}"

      [checks]
      typecheck = "mix compile --warnings-as-errors"
      lint = { component = "./hooks/lint.wasm" }

  `matcher` is a regular expression over the tool name, anchored; absent or empty means
  every tool. `event` is one of #{inspect(~w(SessionStart SessionEnd UserPromptSubmit PreToolUse PostToolUse PostToolUseFailure Stop PreCompact Notification FileChanged))}.

  An entry declares **exactly one** of `command` and `component`; both, or neither, is an
  error line and no hook. The chain runs node, then user, then project: an operator's own
  hook should see a tool call before a repository's does, and node configuration is the
  last word on this machine — the same precedence `Ouroboros.Provider.Native.Mcp.Servers`
  gives an operator's servers, and the repair of the asymmetry docs/WASM.md records as
  W-F3. A node hook has no configuration directory to run in, so it runs in the session's
  workspace; a user hook runs beside its own file, as it always has.

  ## Component hooks, and the world they are

  `component = "<path>"` routes a hook through `Ouroboros.Wasm.Pool` instead of `/bin/sh`.
  The payload is the same JSON object on the way in, the answer is the same stdout contract
  on the way back, and `invoke/3` is the only function that knows which it was — the fold,
  deny-is-final, ask-outranks-auto-approve, silence-is-not-consent and the `updatedInput`
  re-evaluation all live above this seam and are untouched by it (docs/WASM.md §8.1).

  **v1 hook components are capability-world components.** The helper speaks two worlds —
  `ouroboros:capability@0.1.0` and `ouroboros:policy@0.1.0` (W15, D21) — and a hook is
  admitted to the capability one: a strict subset of a capability — one string in, one
  string out, log-only — so the hook payload goes in through `handle-message`, the stdout
  contract comes back as its reply, `init` receives the hook's declared `config` (or
  `"{}"`), and `describe` is unused. Containment is identical, because containment is the
  linker: it defines `log` and nothing else. The dedicated `ouroboros:hook` world §8.1
  sketches is deferred until a third world is a signing-policy event rather than a
  convenience; policy already took the second.

  Each invocation stands up its **own instance and always drops it**. Nothing carries
  between hook runs: no guest state, and therefore no earlier payload able to influence a
  later verdict. The component's bytes are read under a 16 MiB cap and hashed here, and the
  helper recomputes that digest from the bytes *it* reads and refuses `sha_mismatch` before
  compiling anything, which closes the window between the two reads. A component hook's
  deadline is the smaller of its own `timeout_ms` and the helper's 60-second ceiling: it
  cannot ask for the ten minutes a shell hook can, because a wasm guest that has not
  answered in a minute is not working.

  A component hook that fails to run — the guest's own `err`, a trap, a refusal, a helper
  that was never built, a broken pipe, a deadline, a reply past the output cap — is
  **ignored loudly**, exactly as a shell hook that crashed is. It is not consent and it is
  not a denial.

  ## Trust, and why the project file needs it

  A repository that ships its own hooks is a repository that runs commands on every
  machine that clones it. Claude Code gates project settings on workspace trust, Kiro
  keeps workspace rules outside the repository entirely, and both do it because the
  alternative is remote code execution by `git clone` (R3 §8d). `ouroboros.toml` is
  therefore read only when `config :ouroboros, :trusted_workspaces` names the canonical
  workspace root.

  Trust cannot come from a file inside the workspace. The native shell may run without an
  OS sandbox on a node that has no backend, and repository contents are writable by
  definition under `workspace_write`; either fact makes an in-repository trust marker
  self-authorizing. Operator configuration lives outside both authorities.

  Untrusted is not silent: `load/2` reports `trusted?: false` together with how many
  hooks it declined to load, so a session can say why the repository's hooks did nothing.

  ## Containment replaces trust, for components only (D8)

  A **component** hook is admitted from an untrusted workspace; a **command** hook from one
  is declined exactly as before, counted in `declined`, and `trusted?/2` remains the single
  chokepoint deciding it. The difference is what the two can reach. A shell hook is `sh -c`
  with `HOME`, `PATH`, the filesystem and the network. A component hook reaches nothing on
  its own: the world's one import is a log line, so everything it learns arrives in the
  payload this seam hands it and everything it can do arrives in the verdict this seam reads
  back. Both are bounded here, and both bounds are written down below — what it may do under
  "The narrowing", what it may see under "What an untrusted hook can read". The verdict
  vocabulary was designed for an adversarial author: a hook can deny what a rule allowed and
  can never allow what a rule denied, because on a denial no hook is invoked at all.

  ### The narrowing, which is what makes that sentence true

  Two parts of the answer are authority rather than annotation, and an untrusted hook does
  not get them:

    * **`allow`** resolves an engine `ask` — it is what removes the human from the loop.
      From an untrusted workspace it is read as **silence**.
    * **`updatedInput`** replaces the arguments of a call the engine then allows, path and
      content both, so a clone could redirect an allowed `Write` to content of its choosing
      at a path of its choosing inside the allowed roots. From an untrusted workspace it is
      **dropped**.

  What is kept is everything that can only make the outcome stricter: `deny`, `ask` (a
  human prompt where a mode would have auto-approved), and `additionalContext`, which has
  the same standing as any other repository-authored text the model already reads. Stated
  once: **an untrusted hook can make a decision stricter, never looser.**

  The narrowing lives at the seam, in `invoke/3`, so the fold above it never learns that
  hooks have scopes. It applies to every hook and is provably nothing for a shell one,
  which is never admitted untrusted — and a shell hook's `exit 2` has no untrusted analogue
  at all, for the same reason. An untrusted hook's `additionalContext` is kept and
  **labelled**: every *line* it produced is prefixed `[untrusted workspace hook] ` before it
  reaches a prompt or a tool result, and so is every line of an untrusted `[checks]`
  failure, the check's own name and path included. Per line and not per string, because a
  label on the first line of ten leaves nine lines reading as if this runtime wrote them —
  which is what an `additionalContext` of `"ok\\n\\n--- APPROVED BY OPERATOR ---"` was.

  ### What an untrusted hook can read, which is not "nothing"

  The authority a hook returns is narrowed above. The authority it *receives* is the
  payload, and this is the honest statement of it — the earlier claim that a component
  hook's maximum authority is "a log line and a verdict" was true of what it may **do** and
  false about what it may **see**:

    * **`PreToolUse`** hands it the whole `tool_input` of every matching tool call: the
      command a `bash` is about to run, the path *and the content* a `write` is about to
      write. That is kept deliberately — a hook that may deny needs the arguments it is
      denying — and it means an untrusted workspace reads every tool call's arguments.
    * **`PostToolUse` / `PostToolUseFailure`** hand it `tool_input` and, for an untrusted
      hook, a `tool_response` of `%{"is_error" => …, "bytes" => …}` and nothing else. The
      output body — a read file's contents, a command's stdout, a search's hits — is not in
      the payload, because a hook that reports on failure needs to know that a tool failed
      and how much it produced, and reflecting the body back as `additionalContext` was a
      clone reading every file this session read.
    * **`FileChanged`** hands it the paths a turn changed, and never their contents. It is
      not dispatched to an untrusted hook at all — see below.
    * The rest carry the session identifiers, the workspace root, and the event's own
      fields (`source`, `reason`, `trigger`, the operator's `custom_instructions`).

  A trusted hook — the operator's own, or a workspace they named — is handed the full
  `tool_response`, exactly as before. Nothing here narrows what an operator asked for.

  ### Not dispatched at all, for an untrusted hook

  `Notification`, `FileChanged` and `SessionEnd` are the three events whose answer nothing
  above this seam reads: the turn loop discards what they return and `session_end/2` says so
  in its own contract. Running one from an untrusted workspace would hand a clone's guest
  the tool name it is being asked to approve and the paths a turn changed, in exchange for a
  verdict this runtime then throws away — authority with no purpose, which is the one kind
  worth deleting outright. So they are not dispatched to an untrusted hook. A trusted hook
  still runs on them: it may be a shell script whose whole point is the side effect.

  ### Counted, as well as narrowed

  Containment bounds what one component may do and says nothing about how many a clone may
  ship, so an untrusted workspace is admitted at most eight components across `[[hooks]]`
  and `[checks]` together; the rest are declined and counted like shell hooks. Separately,
  `Ouroboros.Wasm.Pool` budgets the *shared* helper cache: at most sixteen distinct
  **untrusted** hook shas per helper lifetime. The helper's 64-slot table evicts at its
  ceiling — least recently used, never a component with a live instance — so a clone can no
  longer fill it and leave every later `load` on the node (the capability lane's rollouts,
  the operator's own earlier-loaded hooks) failing `too_many_components`, which was an
  untrusted workspace making an outcome *looser* by deleting somebody else's `deny`. What
  the budget bounds now is churn: every distinct sha a repository ships is a compile, and
  past the ceiling an eviction somebody else pays to compile again.

  Untrusted only, and that is the repair of a bound that used to be its own bypass: one
  counter shared by both scopes meant a clone could spend it and leave the *operator's own*
  component hook unable to load — a `deny` disarmed by an untrusted workspace, through the
  mechanism meant to stop exactly that. So each entry, hook and check alike, carries the
  `trusted` its scope decided, and that field chooses the lane: `:hook` for an operator's,
  `:untrusted_hook` for a repository's, and only the second is counted. A count is taken when
  the helper answers `{:ok, _}`, so a refused `load` — a sha mismatch, bytes that are not a
  component, a shape the helper will not compile — spends nothing, having cost the node
  nothing. `Pool.status/1`'s `hook_components` is that count, and therefore means budgeted
  untrusted shas rather than every hook component the helper holds.

  ### Accepted residuals

  Written down because they are real and in-slice mitigation would cost more than it buys:

    * An untrusted clone's `PreCompact` component hook can deny every compaction. That is
      strictly stricter and therefore inside D8, but it is a new availability lever: a
      session in such a repository keeps its whole conversation and says why, forever.
    * Compilation is bounded by *shape* and not by time. The helper refuses
      `component_too_complex` on a structural walk before `Component::new` runs, which is
      what makes a compile bomb cheap to reject; cranelift itself is still not interruptible,
      so the bound is "no admissible component compiles slowly" rather than "no compile
      outlasts a deadline".
    * A `matcher` that exhausts its backtracking budget reads as **no match**, silently. That
      is the only safe direction — a hook that did not run cannot loosen anything, since
      `deny` needs a hook to have run — but it means a pathological pattern stops matching
      rather than saying so, and the operator who wrote it sees a hook that never fires. The
      length bound and the isolated compile are what make that reachable only by writing a
      genuinely catastrophic pattern.

  ## The contract, exactly

  One JSON object on stdin:

      {"session_id": …, "cwd": …, "hook_event_name": "PreToolUse",
       "tool_name": "bash", "tool_input": {…}, "tool_response": {…}}

  `tool_response` is the tool's own answer for a trusted hook and `{"is_error": …, "bytes":
  …}` for an untrusted one — see "What an untrusted hook can read". That is the one place
  this contract differs from the four it is compatible with, and it differs only for a hook
  no other implementation would have admitted at all.

  And on the way back, any of:

    * **exit 2** — blocked. stderr is the reason, and it is what the model is told.
    * **exit 0 with JSON on stdout** — `hookSpecificOutput.permissionDecision` of
      `allow`/`deny`/`ask` with `permissionDecisionReason`, `updatedInput` replacing the
      tool's arguments, and `additionalContext` appended to the tool result or the next
      prompt. The older top-level `decision: "block"` / `reason` shape is accepted too,
      because Factory and Claude Code both still emit it.
    * **exit 0 with anything else** — nothing happened. Non-JSON stdout is not an error;
      it is a script that printed something.
    * **any other exit code** — logged and ignored. A hook that is broken must not be
      able to stop work; only one that says `deny` may.

  ## The three lifecycle events

  `SessionStart`, `SessionEnd` and `PreCompact` are dispatched by
  `Ouroboros.Provider.Native.Session` rather than by the turn loop, because none of them
  happens inside a turn:

    * **`SessionStart`** runs once, when the transport initialises — including on a
      resume, which it names in `source` (`"startup"` / `"resume"`, Claude Code's own
      vocabulary). Its `additionalContext` is appended to the *first turn's prompt*, not
      to the system prompt: an instruction in the prefix would change the prefix
      fingerprint and cost the cache on every turn after it.
    * **`SessionEnd`** runs on close or on the transport terminating, with `reason`. It is
      fire-and-forget and detached onto a task supervisor: a session that is going away
      has nowhere to put an answer, and a hook that blocked here would hold a terminating
      process open.
    * **`PreCompact`** runs before the conversation is folded, with `trigger`
      (`"manual"` / `"automatic"`) and the operator's `custom_instructions`. It is the
      second event in this contract that can **stop** something: `exit 2` refuses the
      compaction and its stderr becomes the reason, exactly as `PreToolUse`'s does. The
      session keeps its whole conversation and says why.

  All three are bounded at ten seconds per hook on top of whatever the hook declared,
  because each of them runs while something else is waiting.

  ## Ordering against the permission engine

  `PreToolUse` hooks run **after** `Ouroboros.Control.Permissions`. A rule that denied is
  final and no hook is even invoked, so **a hook can never allow what a rule denied**. A
  hook may deny what a rule allowed, and may resolve a rule's `ask` in either direction —
  which is the useful case, and is exactly as trusted as the operator who installed the
  hook. `updatedInput` is re-evaluated by the engine before it is used, so a hook cannot
  launder a denied command through a rewrite.
  """

  require Logger

  alias Ouroboros.Provider.Native.Exec
  alias Ouroboros.Wasm

  @project_file "ouroboros.toml"
  @user_file "hooks.toml"

  @default_timeout_ms 60_000
  @max_timeout_ms 600_000
  # The three lifecycle events run while something else is waiting — a session opening, a
  # session closing, a compaction about to start — so they get a ceiling of their own on
  # top of whatever the hook declared. A minute is the right default for a `PreToolUse`
  # vet script; it is not the right default for the time between `interactive.start` and a
  # usable session.
  @lifecycle_timeout_ms 10_000
  @max_output_bytes 256 * 1024
  @max_context_bytes 8 * 1024
  @max_hooks 50

  # `[checks]` was uncapped while `[[hooks]]` was not, which made the cheaper of the two
  # tables the way to declare four hundred programs: 16 KiB of TOML is 400 component checks,
  # each a file read, a hash and a compile. Same posture as `@max_hooks` — take the first
  # and drop the rest — because a repository with twenty checks is already unusual.
  @max_checks 20

  # The most components an **untrusted** workspace may have admitted at once, hooks and
  # checks together. Containment bounds what one component can do and says nothing about how
  # many a clone may ship, and every one of them costs a compile and a slot in a cache this
  # node shares with the capability lane. Eight is far above any honest repository and far
  # below anything worth calling a corpus.
  #
  # Trusted workspaces and the operator's own scopes are not capped here: they can already
  # run shell, so a count limit would be theatre. The pool's own per-helper lane budget is
  # what bounds the shared resource for every scope.
  @max_untrusted_components 8

  @max_config_bytes 256 * 1024

  # How much of a helper refusal name may reach a model. The names are a closed vocabulary
  # (`tui/wasm/src/refusal.rs`) but they arrive as somebody else's string, and a bound that
  # does not depend on the helper having kept its own is the only bound worth having.
  @max_refusal_name_bytes 64

  # What an untrusted workspace's `additionalContext` is labelled with before it is appended
  # to a tool result or a prompt. The reviewer's judgement was that this is not a materially
  # new injection surface — it is repository-authored text the model already reads — but it
  # arrives at a moment of the repository's choosing and inside a runtime-authored sentence,
  # and text that came from a clone should say so.
  @untrusted_context_prefix "[untrusted workspace hook] "

  # How much of a `[checks]` key and its target may reach a model. Both come from
  # `ouroboros.toml`, both are interpolated into a sentence injected into a turn, and a
  # four-kilobyte key is a repository writing most of a model's next message rather than
  # naming a check.
  @max_check_name_bytes 200

  # `matcher` is a repository-authored regular expression run against a tool name the model
  # chose, which is the pairing that makes catastrophic backtracking reachable: `(a+)+$`
  # against a 41-character subject took 90 ms here, per tool call, per hook. Three bounds,
  # because no one of them is enough on its own — a length the pattern may not exceed, a
  # backtracking budget `matches?/2` runs it under, and the isolated compile in `matcher/1`
  # that stops a `)` from closing the group the anchoring opened.
  @max_matcher_bytes 200
  @matcher_match_limit 10_000

  # A component's bytes, read here and hashed before the helper is told about them. The
  # helper's own ceiling is 64 MiB; this is the 16 MiB the signing lane already uses for an
  # artifact (`Ouroboros.Upgrade.Signing.Policy`), because a hook is not the place to
  # discover that a repository shipped sixty megabytes of guest.
  @max_component_bytes 16 * 1024 * 1024

  # The string handed to a component's `init`, verbatim. Bounded because it is repository
  # text that crosses into a guest's memory, and because a config is a switch, not a corpus.
  @max_hook_config_bytes 16 * 1024

  # `tui/wasm/src/host.rs`'s `MAX_DEADLINE_MS`. A component hook's deadline is the smaller
  # of its declared `timeout_ms` and this, so a `timeout_ms = 600000` a shell hook may ask
  # for arrives on the wire as sixty seconds rather than as a refused `instantiate`.
  @component_deadline_ceiling_ms 60_000

  # Every instance this seam stands up is named under one prefix and a unique integer, so a
  # hook's instance is never a name any other lane could derive, and two invocations of the
  # same hook are never the same instance.
  @component_prefix "hook/"

  @events %{
    "sessionstart" => :session_start,
    "sessionend" => :session_end,
    "userpromptsubmit" => :user_prompt_submit,
    "pretooluse" => :pre_tool_use,
    "posttooluse" => :post_tool_use,
    "posttoolusefailure" => :post_tool_use_failure,
    "stop" => :stop,
    "precompact" => :pre_compact,
    "notification" => :notification,
    "filechanged" => :file_changed
  }

  # The events whose answer nothing above this seam reads: the turn loop discards what a
  # `Notification` and a `FileChanged` hook return, and `session_end/2` discards a
  # `SessionEnd` hook's by contract. An untrusted hook is not dispatched on them — see the
  # moduledoc: it would be a read of this session's tool names and changed paths bought with
  # a verdict this runtime throws away.
  @discarded_events [:notification, :file_changed, :session_end]

  @event_names %{
    session_start: "SessionStart",
    session_end: "SessionEnd",
    user_prompt_submit: "UserPromptSubmit",
    pre_tool_use: "PreToolUse",
    post_tool_use: "PostToolUse",
    post_tool_use_failure: "PostToolUseFailure",
    stop: "Stop",
    pre_compact: "PreCompact",
    notification: "Notification",
    file_changed: "FileChanged"
  }

  defstruct hooks: [],
            checks: [],
            trusted?: false,
            declined: 0,
            workspace: nil,
            errors: [],
            pool: Ouroboros.Wasm.Pool

  @typedoc "Where a hook was declared. Node scope comes only from application configuration."
  @type scope :: :node | :user | :workspace

  @typedoc """
  One hook.

  `kind` says which of `command` and `component` is populated; the other is `nil`.
  `confine_to` is the canonical root a workspace component may never resolve outside of,
  and `nil` for the scopes that have no such root. `trusted` is the narrowing switch: false
  only for an untrusted workspace's component hook.
  """
  @type hook :: %{
          event: atom(),
          matcher: Regex.t() | nil,
          kind: :command | :component,
          command: String.t() | nil,
          component: String.t() | nil,
          confine_to: String.t() | nil,
          config: String.t(),
          timeout_ms: pos_integer(),
          scope: scope(),
          trusted: boolean(),
          cwd: String.t() | nil,
          pool: GenServer.server()
        }

  @typedoc """
  One `[checks]` entry. Same command/component split as a hook, without a verdict.

  `trusted` is the same field a hook carries and decides the same two things: whether the
  failure text is labelled before it is injected, and which of the pool's two hook lanes the
  component loads under — only the untrusted one is budgeted.
  """
  @type check :: %{
          name: String.t(),
          kind: :command | :component,
          command: String.t() | nil,
          component: String.t() | nil,
          confine_to: String.t() | nil,
          config: String.t(),
          timeout_ms: pos_integer(),
          trusted: boolean()
        }

  @type t :: %__MODULE__{
          hooks: [hook()],
          checks: [check()],
          trusted?: boolean(),
          declined: non_neg_integer(),
          workspace: String.t() | nil,
          errors: [String.t()],
          pool: GenServer.server()
        }

  @doc "Every event name this runtime dispatches."
  @spec events() :: [atom()]
  def events, do: Map.values(@events)

  @doc """
  Loads the hook configuration for one workspace.

  Never raises and never returns an error: an unparseable file contributes an entry in
  `errors` and no hooks. A session must be able to start in a repository whose
  `ouroboros.toml` has a typo in it.

  `opts` accepts `:user_hooks_path`, `:trusted_workspaces` and `:pool` — the last so a test
  can point a component hook at a pool of its own without touching anything global. The
  loop calls `load/1` and gets the node's singleton, which is the only pool production ever
  uses.
  """
  @spec load(String.t() | nil, keyword()) :: t()
  def load(workspace_root, opts \\ []) do
    trusted? = trusted?(workspace_root, opts)
    pool = pool(opts)

    {project_hooks, project_checks, project_errors, declined} =
      load_project(workspace_root, trusted?)

    {user_hooks, user_errors} = load_user(opts)
    {node_hooks, node_errors} = load_node(workspace_root)

    %__MODULE__{
      # Node scope first, then user, then project: an operator's own hook should see a tool
      # call before a repository's does, and a `deny` from any of them is final either way.
      hooks:
        (node_hooks ++ user_hooks ++ project_hooks)
        |> Enum.take(@max_hooks)
        |> Enum.map(&Map.put(&1, :pool, pool)),
      checks: project_checks,
      trusted?: trusted?,
      declined: declined,
      workspace: workspace_root,
      errors: node_errors ++ user_errors ++ project_errors,
      pool: pool
    }
  end

  # A pool is a server name or pid, never validated further here: the pool itself answers
  # `{:error, {:pool_unavailable, _}}` for one that is not there, and that is a refusal this
  # seam already ignores loudly.
  defp pool(opts) do
    case Keyword.get(opts, :pool) do
      nil -> Wasm.Pool
      pool -> pool
    end
  end

  @doc "Whether any hook is declared for an event and tool name."
  @spec any?(t(), atom(), String.t() | nil) :: boolean()
  def any?(%__MODULE__{} = config, event, tool_name \\ nil),
    do: matching(config, event, tool_name) != []

  @doc """
  Runs every `PreToolUse` hook for a tool and folds their answers into one verdict.

      {:deny, reason}
      {:ask, reason, input, context, rewritten?} a hook asked for confirmation
      {:allow, input, context, rewritten?}       a hook allowed it
      {:none, input, context, rewritten?}        no hook expressed a decision

  `input` is the hook-visible arguments after any `updatedInput`; `rewritten?` distinguishes
  an explicit rewrite from a no-op whose input was privacy-redacted before the hook ran;
  `context` is the list of `additionalContext` strings to append to the tool result. The
  verdicts are distinct
  because the caller has to tell "a hook said allow" from "no hook said anything": only
  the first resolves an engine `ask`, and treating silence as consent would make every
  installed hook an approval bypass.

  The fold is narrowest-wins for denial: the first `deny` stops everything, and the last
  hook to state `allow` or `ask` carries the verdict — so a chain ordered
  user-then-project ends on the repository's opinion, which is what an operator who
  trusted the repository asked for.
  """
  @spec pre_tool_use(t(), String.t(), map(), map()) ::
          {:allow, map(), [String.t()], boolean()}
          | {:none, map(), [String.t()], boolean()}
          | {:ask, String.t(), map(), [String.t()], boolean()}
          | {:deny, String.t()}
  def pre_tool_use(%__MODULE__{} = config, tool_name, input, base) do
    config
    |> matching(:pre_tool_use, tool_name)
    |> Enum.reduce_while({:none, input, [], false}, fn hook,
                                                       {verdict, input, context, rewritten?} ->
      payload =
        Map.merge(base, %{
          "hook_event_name" => @event_names.pre_tool_use,
          "tool_name" => tool_name,
          "tool_input" => input
        })

      case invoke(hook, payload) do
        {:deny, reason} ->
          {:halt, {:deny, reason}}

        {:ok, %{decision: :deny} = answer} ->
          {:halt, {:deny, denial_reason(answer, context, hook)}}

        {:ok, answer} ->
          {input, rewritten?} =
            case answer.updated_input do
              %{} = updated -> {updated, true}
              nil -> {input, rewritten?}
            end

          {:cont, {answer.decision || verdict, input, context ++ answer.context, rewritten?}}
      end
    end)
    |> case do
      {:deny, reason} ->
        {:deny, reason}

      {:ask, input, context, rewritten?} ->
        {:ask, ask_reason(context), input, context, rewritten?}

      {:allow, input, context, rewritten?} ->
        {:allow, input, context, rewritten?}

      {:none, input, context, rewritten?} ->
        {:none, input, context, rewritten?}
    end
  end

  defp denial_reason(%{context: [reason | _rest]}, _earlier, _hook), do: reason

  defp denial_reason(_answer, [reason | _rest], _hook), do: reason

  # `label/1` rather than `hook.command`: a component hook's denial reaches the seam as
  # `{:deny, _}` and never lands here, but a `nil` interpolated into an operator-facing
  # sentence is the kind of thing that only stays impossible while somebody remembers why.
  defp denial_reason(_answer, [], hook),
    do:
      "a PreToolUse hook (#{clip(label(hook), @max_check_name_bytes)}) denied this without saying why"

  defp ask_reason([reason | _rest]), do: "a PreToolUse hook asked for confirmation: #{reason}"
  defp ask_reason([]), do: "a PreToolUse hook asked for confirmation"

  @doc """
  Runs the `PostToolUse` (or `PostToolUseFailure`) hooks and returns their
  `additionalContext`.

  A post hook cannot block: the tool has already run. `exit 2` from one is recorded as
  context text so the model still sees what it said, which is what Claude Code does.

  An **untrusted** hook is handed a `tool_response` of `%{"is_error" => …, "bytes" => …}`
  rather than the response itself: the output body is what every tool this session ran
  produced — a file it read, a command's stdout — and a hook that can put text into the next
  prompt is a way back out for it. What survives is what a "did that fail" hook needs.
  """
  @spec post_tool_use(t(), String.t(), map(), map(), map()) :: [String.t()]
  def post_tool_use(%__MODULE__{} = config, tool_name, input, response, base) do
    event = if response["is_error"] == true, do: :post_tool_use_failure, else: :post_tool_use

    config
    |> matching(event, tool_name)
    |> Enum.flat_map(fn hook ->
      payload =
        Map.merge(base, %{
          "hook_event_name" => @event_names[event],
          "tool_name" => tool_name,
          "tool_input" => input,
          "tool_response" => tool_response(response, hook)
        })

      case invoke(hook, payload) do
        {:deny, reason} -> ["A #{@event_names[event]} hook reported: #{reason}"]
        {:ok, answer} -> answer.context
      end
    end)
  end

  # The trusted case is the response itself — an operator's hook sees what an operator's
  # session did. The untrusted one is the shape of the answer without the answer: whether it
  # errored, and how big it was.
  defp tool_response(response, %{trusted: true}), do: response

  defp tool_response(response, _untrusted) when is_map(response) do
    %{"is_error" => response["is_error"] == true, "bytes" => output_bytes(response["output"])}
  end

  defp tool_response(_response, _untrusted), do: %{"is_error" => false, "bytes" => 0}

  defp output_bytes(output) when is_binary(output), do: byte_size(output)
  defp output_bytes(_absent), do: 0

  @doc """
  Runs the hooks for an event that carries no tool and collects their
  `additionalContext`.

  `UserPromptSubmit`, `Stop`, `SessionStart`, `SessionEnd`, `PreCompact`,
  `Notification`, `FileChanged`. A `deny` from one of these is recorded as context, not
  as a block: only `PreToolUse` and `PreCompact` have something to stop, and `PreCompact`
  has `pre_compact/2` for it.

  `opts` may carry `:timeout_ms`, a ceiling applied to every hook in the chain *in
  addition to* its own declared timeout. The lifecycle events use it: a session must not
  wait a minute to open because somebody wrote a slow `SessionStart` hook, and the
  operator's own `timeout_ms` is still honoured when it is the smaller of the two.
  """
  @spec notify(t(), atom(), map(), keyword()) :: [String.t()]
  def notify(config, event, base, opts \\ [])

  def notify(%__MODULE__{} = config, event, base, opts) do
    ceiling = Keyword.get(opts, :timeout_ms)

    config
    |> matching(event, nil)
    |> Enum.flat_map(fn hook ->
      payload = Map.put(base, "hook_event_name", @event_names[event] || to_string(event))

      case invoke(hook, payload, ceiling) do
        {:deny, reason} -> ["A #{@event_names[event]} hook reported: #{reason}"]
        {:ok, answer} -> answer.context
      end
    end)
  end

  @doc """
  Runs the `SessionStart` hooks and returns the context they want the session to open
  with.

  `source` is Claude Code's own vocabulary for why the session started — `"startup"` for
  a fresh one, `"resume"` for one restored from a checkpoint — so a hook written for
  Claude Code reads the field it already reads. The strings come back bounded exactly as
  every other hook's `additionalContext` is, and the caller decides where they land; the
  native session appends them to the first turn's prompt, which is the only place a
  session-scoped instruction can reach a model without changing the cached prefix.

  Bounded at ten seconds per hook, because this runs while a session is
  opening and an operator waiting on `interactive.start` is not waiting on their own
  script.
  """
  @spec session_start(t(), map()) :: [String.t()]
  def session_start(%__MODULE__{} = config, base),
    do: notify(config, :session_start, base, timeout_ms: @lifecycle_timeout_ms)

  @doc """
  Runs the `SessionEnd` hooks and discards whatever they say.

  Fire-and-forget by contract: the session is going away, so there is nothing left for
  `additionalContext` to be appended to, and a hook that blocked here would hold a
  terminating process open. The return value is `:ok` in every case — including the case
  where a hook failed, which is logged by `invoke/3` and nothing else.

  The caller is expected to detach this onto a task supervisor. `run/2` on the way out of
  `terminate/2` would make a slow script into a slow shutdown.
  """
  @spec session_end(t(), map()) :: :ok
  def session_end(%__MODULE__{} = config, base) do
    _ = notify(config, :session_end, base, timeout_ms: @lifecycle_timeout_ms)
    :ok
  end

  @doc """
  Runs the `PreCompact` hooks and returns whether the compaction may proceed.

      :ok                     nothing objected; `context` is empty or advisory
      {:deny, reason}         a hook exited 2, and `reason` is its stderr

  This is the `PreToolUse` contract applied to the one other thing in this provider worth
  stopping. A compaction is not undoable — the conversation it folds is summarised and the
  originals go to an archive — so a repository that wants to say "not while a migration is
  half-written" needs the same `exit 2` it already uses for a tool.

  The first denial stops the chain, exactly as `pre_tool_use/4`'s does. Anything a hook
  printed on a non-denying run is returned as context so the session can put it in the
  event that names the compaction.
  """
  @spec pre_compact(t(), map()) :: {:ok, [String.t()]} | {:deny, String.t()}
  def pre_compact(%__MODULE__{} = config, base) do
    payload = Map.put(base, "hook_event_name", @event_names.pre_compact)

    config
    |> matching(:pre_compact, nil)
    |> Enum.reduce_while({:ok, []}, fn hook, {:ok, context} ->
      case invoke(hook, payload, @lifecycle_timeout_ms) do
        {:deny, reason} -> {:halt, {:deny, reason}}
        {:ok, answer} -> {:cont, {:ok, context ++ answer.context}}
      end
    end)
  end

  @doc """
  Runs the `[checks]` commands and returns the tail of whatever failed.

  A **command** check needs a trusted workspace: it is a repository-supplied command line
  and there is no difference in kind between one of them and a `[[hooks]]` command. A
  **component** check runs from an untrusted workspace too, under D8 and for D8's reason —
  it reaches nothing, and it has no verdict at all, only text.

  Only text, but text is not nothing here: a failure is injected into the turn as a **user
  message**, which is a stronger position than a hook's `additionalContext` gets. So an
  untrusted workspace's failure is labelled exactly as its hook's context is — every line,
  the check's own name and path included, both of which come from `ouroboros.toml` and are
  clipped before they reach a model.

  The component contract: an empty reply is a pass, any other reply is the failure text
  (tail-clipped exactly as a command's output is), and a guest error, a trap or any other
  refusal is a failure line naming the reason. A check that could not run is not a check
  that passed, which is the same sentence the timeout branch has always made.

  `[]` when everything passed, when nothing is configured, or when every configured check
  is a command one in an untrusted workspace. Each check is bounded and a check that times
  out counts as a failure with that said — a typecheck this runtime gave up on is not a
  typecheck that passed.
  """
  @spec run_checks(t(), keyword()) :: [String.t()]
  def run_checks(config, opts \\ [])

  def run_checks(%__MODULE__{checks: []}, _opts), do: []

  def run_checks(%__MODULE__{} = config, opts) do
    tail_lines = Keyword.get(opts, :tail_lines, 40)
    Enum.flat_map(config.checks, &run_check(&1, config, tail_lines))
  end

  # Belt and braces, and both braces are asked. `load_project/2` already declines an
  # untrusted workspace's command checks; this refuses one that reached the struct any other
  # way, and it asks the **entry** as well as the configuration it arrived in. The entry
  # carries its own `trusted` for the same reason a hook does — it is what chooses the pool
  # lane and the label — so a check whose own answer is "repository-authored" must not run
  # `sh -c` on this machine because the struct around it happened to say otherwise. An entry
  # with no `trusted` key at all is read as untrusted, the conservative default every reader
  # of this field takes.
  defp run_check(%{kind: :command} = check, %__MODULE__{} = config, tail_lines) do
    if config.trusted? and Map.get(check, :trusted, false),
      do: run_command_check(check, config, tail_lines),
      else: []
  end

  defp run_check(%{kind: :component} = check, %__MODULE__{pool: pool}, tail_lines) do
    payload = encode(%{"event" => "check", "name" => check.name})

    case run_component(check, pool, payload, nil) do
      {:ok, reply} ->
        case String.trim(reply) do
          "" ->
            []

          failure ->
            [check_text(check, "#{subject(check)} failed:\n" <> tail(failure, tail_lines))]
        end

      # The refusal *name*, and never the helper's prose: this line is injected into a turn,
      # and the prose can carry a digest of whatever was at the path. `report/2` puts the
      # whole sentence in this node's log, where no model reads it.
      {:ignored, note} ->
        report(check.component, note)
        [check_text(check, "#{subject(check)} could not run: #{note.name}")]
    end
  end

  defp run_command_check(check, %__MODULE__{workspace: workspace}, tail_lines) do
    case Exec.run_shell(check.command,
           cd: workspace,
           timeout_ms: check.timeout_ms,
           max_bytes: @max_output_bytes
         ) do
      {:ok, %{status: 0, timed_out?: false}} ->
        []

      {:ok, %{timed_out?: true}} ->
        ["#{subject(check)} did not finish within #{check.timeout_ms} ms."]

      {:ok, result} ->
        [
          "#{subject(check)} exited #{result.status}:\n" <>
            tail(result.output <> result.stderr, tail_lines)
        ]

      {:error, reason} ->
        ["#{subject(check)} could not run: #{inspect(reason)}"]
    end
  end

  # What a `[checks]` failure calls itself, clipped on both halves. Name and target alike
  # come from `ouroboros.toml`, and this sentence becomes a user message in the next model
  # step — a 4000-byte key was a repository writing that message rather than naming a check.
  defp subject(check),
    do:
      "`#{clip(check.name, @max_check_name_bytes)}` " <>
        "(#{clip(check.component || check.command, @max_check_name_bytes)})"

  # An untrusted workspace's check failure is labelled the same way its hook's
  # `additionalContext` is, and for the stronger reason: this text is injected as a *user
  # message* rather than appended to a tool result, so unlabelled it is indistinguishable
  # from something the operator said. Every line, header included — the check's own name and
  # path are as repository-authored as the guest's reply is.
  #
  # Read off the **check**, which is also what chooses the pool lane, so one entry has one
  # answer to "is this repository-authored" rather than two that can drift. An entry with no
  # `trusted` key at all — a caller assembling its own configuration — is read as untrusted,
  # the same conservative default `run_component/4` gives the lane.
  defp check_text(%{trusted: true}, text), do: text
  defp check_text(_untrusted, text), do: labelled(text)

  @doc "Whether operator configuration trusts a workspace for repository commands."
  @spec trusted?(String.t() | nil, keyword()) :: boolean()
  def trusted?(workspace_root, opts \\ [])
  def trusted?(nil, _opts), do: false

  def trusted?(root, opts) when is_binary(root) do
    canonical =
      case Ouroboros.Workspace.Path.canonicalize(root) do
        {:ok, path} -> path
        {:error, _reason} -> Path.expand(root)
      end

    opts
    |> Keyword.get(
      :trusted_workspaces,
      Application.get_env(:ouroboros, :trusted_workspaces, [])
    )
    |> List.wrap()
    |> Enum.filter(&is_binary/1)
    |> Enum.any?(fn configured ->
      case Ouroboros.Workspace.Path.canonicalize(configured) do
        {:ok, path} -> path == canonical
        {:error, _reason} -> Path.expand(configured) == canonical
      end
    end)
  end

  def trusted?(_root, _opts), do: false

  # ---------------------------------------------------------------- invoking

  # The one dispatch point in this lane. Which runtime a hook is depends on `kind` and on
  # nothing else, and both branches answer in the same two shapes — so every caller above
  # this function, and every invariant they encode, is untouched by the existence of the
  # second one.
  defp invoke(hook, payload, ceiling \\ nil)

  defp invoke(%{kind: :component} = hook, payload, ceiling) do
    case run_component(hook, hook.pool, encode(payload), ceiling) do
      {:ok, reply} ->
        case narrow(parse_output(reply), hook) do
          # A component has no exit code, so `permissionDecision: "deny"` is its `exit 2`.
          # Answering in the same shape is what gives `pre_compact/2` and the post hooks
          # the same behaviour they have for a shell hook that blocked.
          %{decision: :deny} = answer -> {:deny, component_denial(answer, hook)}
          answer -> {:ok, answer}
        end

      # A hook that failed to run is not consent and not a denial — the same posture a
      # crashed shell hook gets, for the same reason.
      {:ignored, note} ->
        report(label(hook), note)
        {:ok, empty()}
    end
  end

  defp invoke(hook, payload, ceiling) do
    stdin = encode(payload)

    case Exec.run_shell(hook.command,
           cd: hook.cwd,
           stdin: stdin,
           timeout_ms: bounded(hook.timeout_ms, ceiling),
           max_bytes: @max_output_bytes
         ) do
      {:ok, %{timed_out?: true}} ->
        Logger.warning("native hook timed out and was ignored: #{hook.command}")
        {:ok, empty()}

      # The one exit code with a meaning. stderr is the reason, because that is where
      # every one of the four compatible implementations puts it.
      {:ok, %{status: 2} = result} ->
        {:deny, reason_text(result.stderr, result.output, hook.command)}

      {:ok, %{status: 0} = result} ->
        # `narrow/2` is identity here and always will be: a shell hook is never admitted
        # from an untrusted workspace, so `trusted` is true for every one of them. It is
        # applied anyway, because a seam that narrows on one path and not the other is one
        # sentence away from being wrong.
        {:ok, narrow(parse_output(result.output), hook)}

      {:ok, result} ->
        Logger.warning(
          "native hook exited #{result.status} and was ignored: #{hook.command}" <>
            reason_suffix(result.stderr)
        )

        {:ok, empty()}

      {:error, reason} ->
        Logger.warning("native hook could not run: #{hook.command}: #{inspect(reason)}")
        {:ok, empty()}
    end
  end

  # ------------------------------------------------------- the untrusted narrowing (D8)

  # An untrusted workspace's component hook may make a decision *stricter* and never looser.
  # `deny` and `ask` stand — both only ever add a refusal or a human — and so does
  # `additionalContext`, which is repository-authored text with the same standing as the
  # repository's own files. The two that are authority rather than annotation are removed:
  # `allow`, which resolves an engine `ask` and is therefore what takes the human out of the
  # loop, and `updatedInput`, which replaces the path *and* the content of a call the engine
  # then allows.
  #
  # Here, and not in the fold: `loop.ex` never learns that a hook has a scope.
  defp narrow(answer, %{trusted: true}), do: answer

  defp narrow(answer, hook),
    do: answer |> drop_allow(hook) |> drop_updated_input(hook) |> label_context()

  # Every context line an untrusted hook produced says where it came from — including the
  # one that becomes a denial's reason, which is the line a human is most likely to read.
  defp label_context(%{context: []} = answer), do: answer

  defp label_context(%{context: context} = answer),
    do: %{answer | context: Enum.map(context, &labelled/1)}

  # Per **line**, and that is the whole point rather than a detail. One `additionalContext`
  # is one string, and a string may carry newlines — so prefixing the string labelled line
  # one and left every line after it reading as text this runtime wrote. That is how
  # `"ok\n\n--- APPROVED BY OPERATOR ---"` reached a model carrying a label that pointed at
  # the wrong line.
  #
  # All three line endings, normalised to `\n` on the way out: a lone `\r` is a line break to
  # every reader of this text and a way to redraw over one in a terminal, so a label that
  # only understood `\n` would be a label with a gap in it.
  #
  # Clipped after labelling rather than before: the prefix costs bytes, and the bound on how
  # much text one hook can put in front of a model has to hold *after* this runtime has
  # added its own. A cut lands after the prefix of whatever line it lands in, so every line
  # that survives — whole or truncated — still carries one.
  defp labelled(text) do
    text
    |> String.split(["\r\n", "\n", "\r"])
    |> Enum.map_join("\n", &(@untrusted_context_prefix <> &1))
    |> clip(@max_context_bytes)
  end

  defp drop_allow(%{decision: :allow} = answer, hook) do
    Logger.warning(
      "native component hook from an untrusted workspace may not allow; its `allow` was " <>
        "read as silence: #{clip(label(hook), 500)}"
    )

    %{answer | decision: nil}
  end

  defp drop_allow(answer, _hook), do: answer

  defp drop_updated_input(%{updated_input: updated} = answer, hook) when is_map(updated) do
    Logger.warning(
      "native component hook from an untrusted workspace may not rewrite a call; its " <>
        "`updatedInput` was dropped: #{clip(label(hook), 500)}"
    )

    %{answer | updated_input: nil}
  end

  defp drop_updated_input(answer, _hook), do: answer

  # ------------------------------------------------------------------ the component path

  # One instance, one message, always dropped.
  #
  # A fresh instance per invocation is the whole state story: no guest memory carries from
  # one hook run to the next, so no earlier payload can influence a later verdict and a
  # guest that trapped cannot poison the call after it. The `after` is unconditional
  # because the helper never evicts an *instance* — one stands until somebody drops it —
  # and the pool's owner monitor is the backstop, not the plan. Dropping it is also what
  # lets the helper evict the *component* once nothing holds it.
  @spec run_component(map(), GenServer.server(), String.t(), pos_integer() | nil) ::
          {:ok, String.t()} | {:ignored, note()}
  defp run_component(hook, pool, payload, ceiling) do
    with {:ok, _path, bytes} <- read_component(hook),
         # Hashed from the bytes this side read; the helper recomputes the digest from the
         # bytes it reads and refuses `sha_mismatch` if they differ, so a file swapped
         # between the two reads is a refusal rather than a substituted component.
         sha = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower),
         {:ok, staged} <- stage_component(bytes, sha) do
      # `lane: :hook` is what subjects a repository's components to the pool's shared-cache
      # budget. The helper evicts at its ceiling, so a clone can no longer fill its table
      # and silence the operator's own `deny`; what the budget bounds is how many compiles,
      # and how many of somebody else's evictions, a repository can cause per helper life.
      # This `load` is also how an evicted sha comes back: the helper forgets a component
      # nothing holds, and loading it again — a cache hit whenever it is still held — is
      # what makes the `instantiate` after it safe to issue.
      case Wasm.Pool.load(sha, staged, pool,
             lane: if(Map.get(hook, :trusted, false), do: :hook, else: :untrusted_hook)
           ) do
        {:ok, _report} -> stand_and_call(hook, pool, sha, payload, ceiling)
        {:error, reason} -> {:ignored, note(reason, "load")}
      end
    else
      {:error, note} -> {:ignored, note}
    end
  end

  # W16, D25. The path the helper is given is a **store** path, never the workspace one.
  #
  # This lane used to hand `Ouroboros.Wasm.Pool` the file inside the repository the hook was
  # configured in, and it was the only `load` in this runtime that did. The cost was not the
  # path, it was the fence: the helper's sandbox had to make every workspace root readable for
  # component hooks to work at all, so a compromised precompiled artifact (D24) reached the
  # operator's repositories. Nothing here needed that — the bytes are already in hand and their
  # digest is already computed — so they are published into the node's own content-addressed
  # store first, and the helper reads only from there.
  #
  # `Ouroboros.Wasm.Store.put/3` is content-addressed and publish-once, so re-running the same
  # hook costs one `File.stat`; it is bounded by `store_budget_bytes` and pruned like every
  # other component, and a repository's hook is unreferenced by any rollout so a prune may
  # evict it — after which the next run publishes it again. **A store that will not take the
  # bytes is a hook that does not run**, named `component_not_staged`: a node with no data
  # directory has no store, and a store over budget that cannot prune is a store that fails
  # closed (`Wasm.Store`'s posture), so the honest answer is a refused hook rather than a
  # component loaded from somewhere the fence does not cover.
  defp stage_component(bytes, sha) do
    case Wasm.Store.put(bytes, sha, []) do
      {:ok, %{path: path}} ->
        {:ok, path}

      {:error, reason} ->
        {:error,
         note(
           "component_not_staged",
           "component_not_staged: the component could not be published into this node's " <>
             "store: " <> Kernel.inspect(reason, limit: 10)
         )}
    end
  end

  defp stand_and_call(hook, pool, sha, payload, ceiling) do
    instance = @component_prefix <> Integer.to_string(System.unique_integer([:positive]))

    try do
      case Wasm.Pool.instantiate(instance, sha, hook.config, limits(hook, ceiling), pool,
             owner: self()
           ) do
        {:ok, _result} -> component_reply(pool, instance, payload)
        {:error, reason} -> {:ignored, note(reason, "instantiate")}
      end
    after
      _ = Wasm.Pool.drop(instance, pool)
    end
  end

  defp component_reply(pool, instance, payload) do
    case Wasm.Pool.call(instance, "handle-message", payload, pool) do
      {:ok, %{"payload" => reply}} when is_binary(reply) ->
        # The same cap a shell hook's stdout gets, applied before anything parses it. An
        # oversize reply is ignored loudly exactly as oversize stdout would be.
        if byte_size(reply) > @max_output_bytes do
          {:ignored,
           note("oversize_reply", "replied #{byte_size(reply)} bytes; cap #{@max_output_bytes}")}
        else
          {:ok, reply}
        end

      {:ok, _malformed} ->
        {:ignored, note("malformed_result", "the helper answered with no payload")}

      {:error, reason} ->
        {:ignored, note(reason, "call")}
    end
  end

  # The node's capability bounds, with the one bound a hook declares for itself substituted
  # in. There is no second limits block: fuel and memory are `config :ouroboros, :wasm`'s,
  # where an operator can already see and move them.
  #
  # Always in 1..#{@component_deadline_ceiling_ms}: `timeout/1` floors a declared value at
  # one and defaults an absent one, and `bounded/2` falls through to the declared value for
  # a ceiling that is not a positive integer — so this can never send the zero the helper
  # (and `Pool.wire_limits/1` before it) would refuse.
  defp limits(hook, ceiling) do
    Map.put(
      Wasm.capability_limits(),
      :deadline_ms,
      min(bounded(hook.timeout_ms, ceiling), @component_deadline_ceiling_ms)
    )
  end

  # Statted and read fresh at every invocation, so a file that has grown past the cap or
  # gone away since the session opened is caught here rather than assumed away.
  #
  # For a **workspace** component the canonical path and its confinement are recomputed too,
  # because a repository is writable under `workspace_write` and replacing the file with a
  # symlink out of the tree is exactly the escape the load-time check exists to stop. For
  # node and user scope there is no root to confine to and the load-time path stands: it is
  # the operator's own file, and re-resolving it would answer a question nobody asked.
  defp read_component(hook) do
    case confined_path(hook) do
      {:ok, path} -> read_bounded(path)
      {:error, note} -> {:error, note}
    end
  end

  defp confined_path(%{component: path, confine_to: nil}), do: {:ok, path}

  # One refusal for both ways this can fail, exactly as `canonical_component/2`'s load-time
  # check has one message: a `[checks]` refusal *name* is injected into a turn, so two names
  # that differ on whether the target exists is the same existence oracle, published to a
  # model instead of to `errors`. The detail — which of the two it was, and why — goes to
  # this node's log, where `report/2` puts it and no model reads it.
  defp confined_path(%{component: path, confine_to: root}) do
    case Ouroboros.Workspace.Path.canonicalize_file(path) do
      {:ok, canonical} ->
        if Ouroboros.Workspace.Path.within?(canonical, root),
          do: {:ok, canonical},
          else:
            {:error,
             note("component_outside_workspace", "the component resolves outside the workspace")}

      {:error, reason} ->
        {:error,
         note(
           "component_outside_workspace",
           "the component could not be resolved: #{Kernel.inspect(reason, limit: 10)}"
         )}
    end
  end

  defp read_bounded(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_component_bytes ->
        case File.read(path) do
          {:ok, bytes} ->
            {:ok, path, bytes}

          {:error, reason} ->
            {:error, note("unreadable_component", "could not be read: #{format_error(reason)}")}
        end

      {:ok, %File.Stat{type: :regular, size: size}} ->
        {:error,
         note("oversize_component", "is #{size} bytes; the limit is #{@max_component_bytes}")}

      {:ok, %File.Stat{type: type}} ->
        {:error, note("not_a_regular_file", "the component is a #{type}, not a regular file")}

      {:error, reason} ->
        {:error, note("unreadable_component", "could not be read: #{format_error(reason)}")}
    end
  end

  defp format_error(reason) when is_atom(reason), do: :file.format_error(reason)

  # Every component failure carries two forms, and which one a reader gets is not a
  # convenience.
  #
  #   * `name` — a short slug or the helper's own refusal name, and the **only** part that
  #     may reach a model. `[checks]` failures are injected into a turn, so a line that
  #     repeated the helper's prose would be a repository-driven oracle: `sha_mismatch`'s
  #     message names the digest of whatever was actually at the path, and a check pointed
  #     at a file it is not allowed to read would hand the model that file's sha256.
  #   * `detail` — the whole sentence, prose included, for this node's log only.
  #
  # Nothing here mints an atom: helper refusal names are already strings, and the atoms
  # turned into strings are ones this codebase wrote.
  @typep note :: %{name: String.t(), detail: String.t()}

  defp note(%{refusal: refusal, message: message} = _reason, stage)
       when is_binary(refusal) and is_binary(message) do
    detail = if message == "", do: refusal, else: refusal <> " (" <> message <> ")"
    %{name: clip(refusal, @max_refusal_name_bytes), detail: stage <> ": " <> detail}
  end

  defp note(reason, stage) when is_atom(reason) or is_tuple(reason) do
    %{
      name: clip(refusal_name(reason), @max_refusal_name_bytes),
      detail: stage <> ": " <> Kernel.inspect(reason, limit: 10)
    }
  end

  defp note(name, detail) when is_binary(name) and is_binary(detail),
    do: %{name: name, detail: detail}

  defp refusal_name(reason) when is_atom(reason), do: Atom.to_string(reason)

  defp refusal_name(reason) when is_tuple(reason) and tuple_size(reason) > 0,
    do: Atom.to_string(elem(reason, 0))

  defp refusal_name(_reason), do: "helper_error"

  # How loud a failure is. Everything a hook itself can cause is a warning about that hook;
  # the lane budget is the one refusal that is not about this hook at all — it says this
  # node's hook-lane budget for the shared component cache is spent on somebody else's
  # bytes, and every later *new* hook component on this node will fail the same way until
  # the helper is respawned (the helper itself evicts and has room; the pool's per-lifetime
  # count is what refused). That is operator-actionable, so it is an error with the action
  # in it.
  #
  # A session-visible status event for the same fact belongs to W5, the surface slice; there
  # is no event vocabulary for it here yet.
  defp report(subject, %{name: "hook_component_budget", detail: detail}) do
    Logger.error(
      "native component hook could not be loaded: #{clip(subject, 500)}: #{clip(detail, 500)}. " <>
        "This node's wasm helper will admit no new hook components until it is respawned " <>
        "(restart the ouro-wasm helper, or the node); a workspace shipping many components " <>
        "is the usual cause."
    )
  end

  defp report(subject, %{detail: detail}) do
    Logger.warning(
      "native component hook was ignored: #{clip(subject, 500)}: #{clip(detail, 500)}"
    )
  end

  defp component_denial(%{context: [reason | _rest]}, _hook), do: reason

  # `label/1` is a repository-authored path for a workspace hook, and this sentence is the
  # one a human reads when a call is refused — so it is clipped like every other piece of
  # repository text that reaches a reader.
  defp component_denial(_answer, hook),
    do: "a hook (#{clip(label(hook), @max_check_name_bytes)}) blocked this without saying why"

  # What to call a hook in a message. Never `nil`: a component hook has no command line.
  defp label(%{kind: :component, component: component}), do: component
  defp label(%{command: command}) when is_binary(command), do: command
  defp label(_hook), do: "a hook"

  # The smaller of what the operator declared and what the caller can wait for. Never the
  # larger: a ceiling that a hook's own `timeout_ms` could raise would not be one.
  defp bounded(declared, nil), do: declared

  defp bounded(declared, ceiling) when is_integer(ceiling) and ceiling > 0,
    do: min(declared, ceiling)

  defp bounded(declared, _unusable), do: declared

  defp empty, do: %{decision: nil, updated_input: nil, context: []}

  # A payload a hook cannot be handed is an empty object rather than a crashed turn: a
  # tool input holding something no encoder accepts must not be able to stop the tool.
  defp encode(payload) do
    JSON.encode!(payload)
  rescue
    _error -> "{}"
  end

  defp parse_output(output) do
    with trimmed when trimmed != "" <- String.trim(output),
         {:ok, decoded} when is_map(decoded) <- decode(trimmed) do
      specific = map_or_empty(decoded["hookSpecificOutput"])

      %{
        decision: decision(specific["permissionDecision"] || decoded["decision"]),
        updated_input: updated_input(specific["updatedInput"] || decoded["updatedInput"]),
        context:
          [
            specific["permissionDecisionReason"],
            specific["additionalContext"],
            decoded["additionalContext"],
            decoded["systemMessage"]
          ]
          |> Enum.flat_map(&context_line/1)
      }
    else
      _not_json -> empty()
    end
  end

  defp decode(json) do
    {:ok, JSON.decode!(json)}
  rescue
    _error -> :error
  end

  defp decision("allow"), do: :allow
  defp decision("deny"), do: :deny
  defp decision("ask"), do: :ask
  # Claude Code's and Factory's older shape.
  defp decision("block"), do: :deny
  defp decision(_other), do: nil

  defp updated_input(value) when is_map(value), do: value
  defp updated_input(_other), do: nil

  defp context_line(value) when is_binary(value) do
    case String.trim(value) do
      "" -> []
      text -> [clip(text, @max_context_bytes)]
    end
  end

  defp context_line(_other), do: []

  defp map_or_empty(value) when is_map(value), do: value
  defp map_or_empty(_other), do: %{}

  defp reason_text(stderr, stdout, command) do
    cond do
      String.trim(stderr) != "" -> clip(String.trim(stderr), @max_context_bytes)
      String.trim(stdout) != "" -> clip(String.trim(stdout), @max_context_bytes)
      true -> "a hook (#{command}) blocked this without saying why"
    end
  end

  defp reason_suffix(stderr) do
    case String.trim(stderr) do
      "" -> ""
      text -> ": " <> clip(text, 500)
    end
  end

  defp matching(%__MODULE__{hooks: hooks}, event, tool_name) do
    Enum.filter(hooks, fn hook ->
      hook.event == event and dispatchable?(hook, event) and matches?(hook.matcher, tool_name)
    end)
  end

  # An untrusted hook is not dispatched on an event whose answer is discarded. Here rather
  # than in each caller, so `any?/3` agrees with `notify/4` about what will run — a surface
  # that said a hook was there and a dispatch that skipped it would be two answers to one
  # question.
  defp dispatchable?(%{trusted: false}, event) when event in @discarded_events, do: false
  defp dispatchable?(_hook, _event), do: true

  defp matches?(nil, _tool_name), do: true
  defp matches?(_matcher, nil), do: true

  # `:re.run/3` rather than `Regex.match?/2`, for the one option `Regex` does not pass
  # through: a backtracking budget. The pattern is repository-authored and the subject is a
  # tool name the *model* chose, which is the pairing catastrophic backtracking needs —
  # `(a+)+$` against 41 characters is 90 ms of this node, on every tool call, for every hook
  # that declared it. Under the limit the same match is 94 µs and answers `:nomatch`.
  #
  # A budget exceeded reading as "no match" is the safe direction and the only one available:
  # it means the hook does not run, and a hook that does not run cannot loosen anything —
  # `deny` is the verdict that needs a hook to have run. Ten thousand steps is three orders
  # of magnitude above what an honest matcher against a tool name spends.
  defp matches?(regex, tool_name) do
    :re.run(tool_name, Regex.re_pattern(regex), [
      {:capture, :none},
      {:match_limit, @matcher_match_limit}
    ]) ==
      :match
  end

  # ---------------------------------------------------------------- loading

  defp load_project(nil, _trusted?), do: {[], [], [], 0}

  defp load_project(root, trusted?) do
    path = Path.join(root, @project_file)

    case read_config(path) do
      {:ok, %{} = document} ->
        {hooks, hook_errors} = hooks_from(document, :workspace, root, trusted?)
        {checks, check_errors} = checks_from(document, :workspace, root, trusted?)
        errors = hook_errors ++ check_errors

        if trusted? do
          {hooks, checks, errors, 0}
        else
          # D8. A component's whole authority is a log line and a verdict this seam then
          # narrows, so a clone's component hooks run; its shell hooks are `sh -c` on this
          # machine and are declined and counted exactly as they always were.
          {admitted_hooks, declined_hooks} = Enum.split_with(hooks, &(&1.kind == :component))

          {admitted_checks, declined_checks} =
            Enum.split_with(checks, &(&1.kind == :component))

          {capped_hooks, capped_checks, over} = cap_untrusted(admitted_hooks, admitted_checks)

          {capped_hooks, capped_checks, errors ++ cap_error(over),
           length(declined_hooks) + length(declined_checks) + over}
        end

      :absent ->
        {[], [], [], 0}

      {:error, message} ->
        {[], [], ["#{path}: #{message}"], 0}
    end
  end

  # One budget across both tables, spent in document order — hooks first, then checks — so a
  # repository cannot double it by moving half its components into `[checks]`. What is
  # dropped is declined and counted like a shell hook, and says so in `errors`: a cap that
  # silently ate the ninth component would be indistinguishable from one that ran it.
  defp cap_untrusted(hooks, checks) do
    kept_hooks = Enum.take(hooks, @max_untrusted_components)
    kept_checks = Enum.take(checks, @max_untrusted_components - length(kept_hooks))
    over = length(hooks) - length(kept_hooks) + (length(checks) - length(kept_checks))

    {kept_hooks, kept_checks, over}
  end

  defp cap_error(0), do: []

  defp cap_error(over) do
    [
      "#{@project_file}: an untrusted workspace may run #{@max_untrusted_components} " <>
        "components; #{over} beyond that were declined"
    ]
  end

  defp load_user(opts) do
    case user_path(opts) do
      nil ->
        {[], []}

      path ->
        case read_config(path) do
          {:ok, %{} = document} ->
            hooks_from(document, :user, Path.dirname(path), true)

          :absent ->
            {[], []}

          {:error, message} ->
            {[], ["#{path}: #{message}"]}
        end
    end
  end

  # `config :ouroboros, :hooks` — the node scope docs/WASM.md files as W-F3. Entries have
  # the same keys a `[[hooks]]` table has, with string or atom keys, and are parsed by the
  # same `build/4`, so there is one grammar and not two. Node scope is reachable *only*
  # from application configuration: nothing a workspace or a user file can write chooses a
  # scope, because scope is a parameter here and never a field of an entry.
  defp load_node(workspace_root) do
    :ouroboros
    |> Application.get_env(:hooks, [])
    |> List.wrap()
    |> Enum.with_index(1)
    |> Enum.reduce({[], []}, fn {entry, index}, {hooks, errors} ->
      # A node hook has no configuration directory of its own, so it runs where the session
      # is working. `nil` when there is no workspace, exactly as a node MCP server's is.
      case entry |> normalize_entry() |> build(:node, workspace_root, true) do
        {:ok, hook} ->
          {hooks ++ [hook], errors}

        {:error, message} ->
          {hooks, errors ++ ["config :ouroboros, :hooks ##{index}: #{message}"]}
      end
    end)
  end

  # Atom keys and string keys both, normalized once so `build/4` reads one shape. The
  # direction is atom to string and never the reverse: nothing here mints an atom.
  defp normalize_entry(entry) when is_map(entry), do: Map.new(entry, &normalize_pair/1)

  defp normalize_entry(entry) when is_list(entry) do
    if Keyword.keyword?(entry), do: Map.new(entry, &normalize_pair/1), else: entry
  end

  defp normalize_entry(entry), do: entry

  defp normalize_pair({key, value}) when is_atom(key), do: {Atom.to_string(key), value}
  defp normalize_pair({key, value}) when is_binary(key), do: {key, value}
  defp normalize_pair({key, value}), do: {Kernel.inspect(key), value}

  @doc """
  Where the user-scope hook file lives on this node.

  `config :ouroboros, :native_user_hooks_path` moves it, for the same reason
  `:native_data_dir` moves the session directory: an operator running several runtimes on
  one account needs the option, and it is what the tests point at a temporary file so
  they never read — or run — the machine's real hooks.
  """
  @spec user_path(keyword()) :: String.t() | nil
  def user_path(opts \\ []) do
    configured =
      Keyword.get(opts, :user_hooks_path) ||
        Application.get_env(:ouroboros, :native_user_hooks_path) ||
        :default

    case configured do
      :default ->
        case System.user_home() do
          home when is_binary(home) and home != "" ->
            Path.join([home, ".config", "ouroboros", @user_file])

          _unknown ->
            nil
        end

      path when is_binary(path) ->
        path

      _disabled ->
        nil
    end
  end

  defp read_config(path) do
    with {:ok, %File.Stat{type: :regular, size: size}} when size <= @max_config_bytes <-
           File.stat(path),
         {:ok, content} <- File.read(path) do
      case Toml.decode(content) do
        {:ok, document} -> {:ok, document}
        {:error, reason} -> {:error, "not valid TOML: #{inspect(reason)}"}
      end
    else
      {:ok, %File.Stat{size: size}} ->
        {:error, "is #{size} bytes; the limit is #{@max_config_bytes}"}

      {:error, :enoent} ->
        :absent

      {:error, reason} ->
        {:error, :file.format_error(reason)}
    end
  end

  defp hooks_from(document, scope, cwd, trusted?) do
    document
    |> Map.get("hooks", [])
    |> List.wrap()
    |> Enum.with_index(1)
    |> Enum.reduce({[], []}, fn {entry, index}, {hooks, errors} ->
      case build(entry, scope, cwd, trusted?) do
        {:ok, hook} -> {hooks ++ [hook], errors}
        {:error, message} -> {hooks, errors ++ ["[[hooks]] ##{index}: #{message}"]}
      end
    end)
  end

  defp build(entry, scope, cwd, trusted?) when is_map(entry) do
    with {:ok, event} <- event(Map.get(entry, "event")),
         {:ok, target} <- target(entry, scope, cwd),
         {:ok, config} <- hook_config(entry, target.kind),
         {:ok, matcher} <- matcher(Map.get(entry, "matcher")) do
      {:ok,
       Map.merge(target, %{
         event: event,
         matcher: matcher,
         config: config,
         timeout_ms: timeout(Map.get(entry, "timeout_ms")),
         scope: scope,
         trusted: entry_trusted?(scope, trusted?),
         cwd: cwd,
         pool: Wasm.Pool
       })}
    end
  end

  defp build(_entry, _scope, _cwd, _trusted?), do: {:error, "is not a table"}

  # Exactly one of `command` and `component`. Both is ambiguous and neither is empty, and
  # neither is a raise: a repository with a typo in its hooks must still open a session.
  defp target(entry, scope, cwd) do
    case {Map.get(entry, "command"), Map.get(entry, "component")} do
      {nil, nil} ->
        {:error, "has no `command` and no `component`"}

      {_command, nil} ->
        with {:ok, command} <- command(Map.get(entry, "command")) do
          {:ok, %{kind: :command, command: command, component: nil, confine_to: nil}}
        end

      {nil, _component} ->
        with {:ok, path, confine_to} <-
               component_path(Map.get(entry, "component"), scope, cwd) do
          {:ok, %{kind: :component, command: nil, component: path, confine_to: confine_to}}
        end

      {_both, _of_them} ->
        {:error, "declares both `command` and `component`; a hook is one or the other"}
    end
  end

  # The path confinement, in one place for hooks and `[checks]` alike.
  #
  #   * **workspace** — relative to the workspace root and canonically inside it. An
  #     absolute path is refused rather than resolved, `..` cannot climb out, and a symlink
  #     pointing out is followed and then refused, because `Ouroboros.Workspace.Path`
  #     resolves links before it processes `..` rather than expanding lexically first.
  #   * **user** — absolute, or relative to the directory of the file that declared it.
  #   * **node** — absolute, because there is no directory a node hook is relative to.
  #
  # `canonicalize_file/1` is used rather than `canonicalize/1`: the latter requires a
  # directory, and this is a file.
  defp component_path(value, scope, cwd) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, "has an empty `component`"}
      path -> resolve_component(path, scope, cwd)
    end
  end

  defp component_path(_value, _scope, _cwd), do: {:error, "`component` must be a string"}

  defp resolve_component(path, :node, _cwd) do
    if Path.type(path) == :absolute do
      canonical_component(path, nil)
    else
      {:error, "a node-scope `component` must be an absolute path, got `#{path}`"}
    end
  end

  defp resolve_component(path, :user, cwd) do
    if Path.type(path) == :absolute do
      canonical_component(path, nil)
    else
      canonical_component(Path.join(cwd || ".", path), nil)
    end
  end

  defp resolve_component(path, :workspace, root) do
    if Path.type(path) == :absolute do
      {:error, "a workspace `component` must be relative to the workspace root"}
    else
      case Ouroboros.Workspace.Path.canonicalize(root) do
        {:ok, canonical_root} ->
          canonical_component(Path.join(canonical_root, path), canonical_root)

        {:error, reason} ->
          {:error, "the workspace root could not be resolved: #{Kernel.inspect(reason)}"}
      end
    end
  end

  # Node and user scope: the operator's own path, so the reason it failed is theirs to read.
  defp canonical_component(path, nil) do
    case Ouroboros.Workspace.Path.canonicalize_file(path) do
      {:ok, canonical} ->
        {:ok, canonical, nil}

      {:error, reason} ->
        {:error, "`component` is not a readable regular file: #{Kernel.inspect(reason)}"}
    end
  end

  # Workspace scope: **one** message for every way a path can fail to be an admissible
  # component here. Two messages — "resolves outside the workspace" for a symlink that
  # resolved and "is not a readable regular file" for one that did not — differ exactly on
  # whether the target exists, and a repository can plant a symlink per guess and read the
  # answer out of `errors`, which a session reports once per turn. That is an existence
  # oracle for paths this workspace may not read, built out of the error text. The distinction
  # is worth nothing to the author of an honest `ouroboros.toml`, whose component is inside
  # the tree either way, and the whole sentence stays in this node's log for the operator.
  defp canonical_component(path, confine_to) do
    with {:ok, canonical} <- Ouroboros.Workspace.Path.canonicalize_file(path),
         true <- Ouroboros.Workspace.Path.within?(canonical, confine_to) do
      {:ok, canonical, confine_to}
    else
      _outside_or_unreadable ->
        {:error, "`component` is not a readable regular file inside the workspace"}
    end
  end

  # The string a component's `init` is handed, verbatim. A command hook has no `init`, so
  # `config` on one is a mistake worth a line rather than a value silently ignored.
  defp hook_config(entry, :component) do
    case Map.get(entry, "config", "{}") do
      value when is_binary(value) and byte_size(value) <= @max_hook_config_bytes ->
        {:ok, value}

      value when is_binary(value) ->
        {:error, "`config` is #{byte_size(value)} bytes; the limit is #{@max_hook_config_bytes}"}

      _other ->
        {:error, "`config` must be a string"}
    end
  end

  defp hook_config(entry, :command) do
    case Map.get(entry, "config") do
      nil -> {:ok, "{}"}
      _present -> {:error, "`config` is only meaningful for a `component` hook"}
    end
  end

  defp event(name) when is_binary(name) do
    case Map.fetch(@events, name |> String.trim() |> String.downcase()) do
      {:ok, event} -> {:ok, event}
      :error -> {:error, "`#{name}` is not a hook event"}
    end
  end

  defp event(_name), do: {:error, "has no `event`"}

  defp command(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, "has an empty `command`"}
      command -> {:ok, command}
    end
  end

  defp command(_value), do: {:error, "has no `command`"}

  defp matcher(nil), do: {:ok, nil}

  defp matcher(value) when is_binary(value) do
    case String.trim(value) do
      "" ->
        {:ok, nil}

      pattern when byte_size(pattern) > @max_matcher_bytes ->
        {:error, "`matcher` is #{byte_size(pattern)} bytes; the limit is #{@max_matcher_bytes}"}

      pattern ->
        compile_matcher(pattern)
    end
  end

  defp matcher(_value), do: {:error, "`matcher` must be a string"}

  # The pattern is compiled **alone** before it is compiled inside the anchoring group, and
  # the bare compile is not a nicety: `\A(?:` … `)\z` is string concatenation, so a pattern
  # carrying its own parenthesis closes the group early. `a)|(x` anchors to
  # `\A(?:a)|(x)\z` — an alternation of "starts with a" and "ends with x" — which compiles,
  # matches `anything x`, and is not anchored at all. A pattern that compiles on its own has
  # balanced parentheses, so the group this adds is the group this closes.
  defp compile_matcher(pattern) do
    with {:ok, _alone} <- Regex.compile(pattern),
         {:ok, regex} <- Regex.compile("\\A(?:" <> pattern <> ")\\z") do
      {:ok, regex}
    else
      {:error, reason} -> {:error, "`matcher` is not a regular expression: #{inspect(reason)}"}
    end
  end

  defp timeout(value) when is_integer(value) and value > 0, do: min(value, @max_timeout_ms)
  defp timeout(_value), do: @default_timeout_ms

  defp checks_from(document, scope, cwd, trusted?) do
    document
    |> Map.get("checks", %{})
    |> case do
      table when is_map(table) ->
        # Capped like `[[hooks]]` is, and silently for the same reason: the take is a bound
        # on this runtime's work, not a judgement about the entries beyond it.
        table
        |> Enum.sort()
        |> Enum.take(@max_checks)
        |> Enum.reduce({[], []}, fn {name, value}, {checks, errors} ->
          case check(name, value, scope, cwd, trusted?) do
            {:ok, check} -> {checks ++ [check], errors}
            {:error, message} -> {checks, errors ++ ["[checks] #{name}: #{message}"]}
          end
        end)

      _not_a_table ->
        {[], ["[checks] must be a table"]}
    end
  end

  defp check(name, command, scope, _cwd, trusted?) when is_binary(command) and command != "" do
    {:ok,
     %{
       name: name,
       kind: :command,
       command: String.trim(command),
       component: nil,
       confine_to: nil,
       config: "{}",
       timeout_ms: @default_timeout_ms,
       trusted: entry_trusted?(scope, trusted?)
     }}
  end

  defp check(name, table, scope, cwd, trusted?) when is_map(table) do
    with {:ok, path, confine_to} <- component_path(Map.get(table, "component"), scope, cwd),
         {:ok, config} <- hook_config(table, :component) do
      {:ok,
       %{
         name: name,
         kind: :component,
         command: nil,
         component: path,
         confine_to: confine_to,
         config: config,
         timeout_ms: @default_timeout_ms,
         trusted: entry_trusted?(scope, trusted?)
       }}
    end
  end

  defp check(_name, _other, _scope, _cwd, _trusted?),
    do: {:error, "must be a command string or a `{ component = \"…\" }` table"}

  # The one rule, shared by `[[hooks]]` and `[checks]`: only a workspace can be untrusted. A
  # node or user entry is the operator's own, which is the authority a rule answers to.
  defp entry_trusted?(scope, trusted?), do: scope != :workspace or trusted?

  # ---------------------------------------------------------------- text

  defp tail(text, lines) do
    text
    |> String.split("\n")
    |> Enum.reject(&(String.trim(&1) == ""))
    |> Enum.take(-lines)
    |> Enum.join("\n")
    |> clip(@max_context_bytes)
  end

  # Cut on a **character** boundary, not on a byte.
  #
  # `binary_part/3` cuts wherever the number lands, and a repository chooses the text: eight
  # kilobytes of `additionalContext` ending in an accented letter puts the cut inside a
  # two-byte codepoint, and the result is a binary that is not valid UTF-8. Everything
  # downstream then has to survive it — `JSON.encode!` does not, it raises — so a clone could
  # stop a turn with one long context line. Found by W10's review, which reached it through
  # `ouro wasm hook` on a component whose reply ended in `é`.
  #
  # Walking back is bounded by construction: UTF-8 is at most four bytes, so the loop runs at
  # most three times before `String.valid?/1` is true. The Rust half of this rule
  # (`tui/src/wasm_cli.rs`'s `clip`) cuts at the character boundary at or below the same limit,
  # so the two now agree byte for byte, and `test/support/wasm_golden/hook_narrowing.json` pins
  # a case that lands mid-codepoint to keep them that way.
  defp clip(text, limit) when byte_size(text) <= limit, do: text

  defp clip(text, limit),
    do: binary_part(text, 0, character_boundary(text, limit)) <> "\n… (truncated)"

  defp character_boundary(_text, 0), do: 0

  defp character_boundary(text, at) do
    if String.valid?(binary_part(text, 0, at)),
      do: at,
      else: character_boundary(text, at - 1)
  end
end
