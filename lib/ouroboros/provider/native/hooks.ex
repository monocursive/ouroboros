defmodule Ouroboros.Provider.Native.Hooks do
  @moduledoc """
  Lifecycle hooks for the native agent, on the contract Claude Code, Codex, Gemini and
  Factory all already speak.

  Four vendors converged on the same JSON shape (R3 §4.2), which means a hook script
  somebody already wrote for one of them works here unchanged. That compatibility is the
  whole point; inventing a fifth contract would make this feature worth less than not
  having it.

  ## Where hooks are declared

      <workspace>/ouroboros.toml        project scope — requires workspace trust
      ~/.config/ouroboros/hooks.toml    user scope — always honoured

      [[hooks]]
      event = "PreToolUse"
      matcher = "Bash|Edit|Write"
      command = "./scripts/vet.sh"
      timeout_ms = 10000

      [checks]
      typecheck = "mix compile --warnings-as-errors"
      lint = "mix credo --strict"

  `matcher` is a regular expression over the tool name, anchored; absent or empty means
  every tool. `event` is one of #{inspect(~w(SessionStart SessionEnd UserPromptSubmit PreToolUse PostToolUse PostToolUseFailure Stop PreCompact Notification FileChanged))}.

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

  ## The contract, exactly

  One JSON object on stdin:

      {"session_id": …, "cwd": …, "hook_event_name": "PreToolUse",
       "tool_name": "bash", "tool_input": {…}, "tool_response": {…}}

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
  @max_config_bytes 256 * 1024

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

  defstruct hooks: [], checks: [], trusted?: false, declined: 0, workspace: nil, errors: []

  @type hook :: %{
          event: atom(),
          matcher: Regex.t() | nil,
          command: String.t(),
          timeout_ms: pos_integer(),
          scope: :workspace | :user,
          cwd: String.t() | nil
        }

  @type t :: %__MODULE__{
          hooks: [hook()],
          checks: [%{name: String.t(), command: String.t(), timeout_ms: pos_integer()}],
          trusted?: boolean(),
          declined: non_neg_integer(),
          workspace: String.t() | nil,
          errors: [String.t()]
        }

  @doc "Every event name this runtime dispatches."
  @spec events() :: [atom()]
  def events, do: Map.values(@events)

  @doc """
  Loads the hook configuration for one workspace.

  Never raises and never returns an error: an unparseable file contributes an entry in
  `errors` and no hooks. A session must be able to start in a repository whose
  `ouroboros.toml` has a typo in it.
  """
  @spec load(String.t() | nil, keyword()) :: t()
  def load(workspace_root, opts \\ []) do
    trusted? = trusted?(workspace_root, opts)

    {project_hooks, project_checks, project_errors, declined} =
      load_project(workspace_root, trusted?)

    {user_hooks, _user_checks, user_errors, _declined} = load_user(opts)

    %__MODULE__{
      # User scope first: an operator's own hook should see a tool call before a
      # repository's does, and a `deny` from either is final either way.
      hooks: Enum.take(user_hooks ++ project_hooks, @max_hooks),
      checks: project_checks,
      trusted?: trusted?,
      declined: declined,
      workspace: workspace_root,
      errors: user_errors ++ project_errors
    }
  end

  @doc "Whether any hook is declared for an event and tool name."
  @spec any?(t(), atom(), String.t() | nil) :: boolean()
  def any?(%__MODULE__{} = config, event, tool_name \\ nil),
    do: matching(config, event, tool_name) != []

  @doc """
  Runs every `PreToolUse` hook for a tool and folds their answers into one verdict.

      {:deny, reason}
      {:ask, reason, input, context}     a hook asked for confirmation
      {:allow, input, context}           a hook allowed it
      {:none, input, context}            no hook expressed a decision

  `input` is the tool's arguments after any `updatedInput`; `context` is the list of
  `additionalContext` strings to append to the tool result. The four are distinct
  because the caller has to tell "a hook said allow" from "no hook said anything": only
  the first resolves an engine `ask`, and treating silence as consent would make every
  installed hook an approval bypass.

  The fold is narrowest-wins for denial: the first `deny` stops everything, and the last
  hook to state `allow` or `ask` carries the verdict — so a chain ordered
  user-then-project ends on the repository's opinion, which is what an operator who
  trusted the repository asked for.
  """
  @spec pre_tool_use(t(), String.t(), map(), map()) ::
          {:allow, map(), [String.t()]}
          | {:none, map(), [String.t()]}
          | {:ask, String.t(), map(), [String.t()]}
          | {:deny, String.t()}
  def pre_tool_use(%__MODULE__{} = config, tool_name, input, base) do
    config
    |> matching(:pre_tool_use, tool_name)
    |> Enum.reduce_while({:none, input, []}, fn hook, {verdict, input, context} ->
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
          {:cont,
           {answer.decision || verdict, answer.updated_input || input, context ++ answer.context}}
      end
    end)
    |> case do
      {:deny, reason} -> {:deny, reason}
      {:ask, input, context} -> {:ask, ask_reason(context), input, context}
      {:allow, input, context} -> {:allow, input, context}
      {:none, input, context} -> {:none, input, context}
    end
  end

  defp denial_reason(%{context: [reason | _rest]}, _earlier, _hook), do: reason

  defp denial_reason(_answer, [reason | _rest], _hook), do: reason

  defp denial_reason(_answer, [], hook),
    do: "a PreToolUse hook (#{hook.command}) denied this without saying why"

  defp ask_reason([reason | _rest]), do: "a PreToolUse hook asked for confirmation: #{reason}"
  defp ask_reason([]), do: "a PreToolUse hook asked for confirmation"

  @doc """
  Runs the `PostToolUse` (or `PostToolUseFailure`) hooks and returns their
  `additionalContext`.

  A post hook cannot block: the tool has already run. `exit 2` from one is recorded as
  context text so the model still sees what it said, which is what Claude Code does.
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
          "tool_response" => response
        })

      case invoke(hook, payload) do
        {:deny, reason} -> ["A #{@event_names[event]} hook reported: #{reason}"]
        {:ok, answer} -> answer.context
      end
    end)
  end

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

  Only for a trusted workspace: these are repository-supplied command lines and there is
  no difference in kind between one of them and a `[[hooks]]` command.

  `[]` when everything passed, when nothing is configured, or when the workspace is not
  trusted. Each check is bounded and a check that times out counts as a failure with
  that said — a typecheck this runtime gave up on is not a typecheck that passed.
  """
  @spec run_checks(t(), keyword()) :: [String.t()]
  def run_checks(config, opts \\ [])

  def run_checks(%__MODULE__{checks: []}, _opts), do: []
  def run_checks(%__MODULE__{trusted?: false}, _opts), do: []

  def run_checks(%__MODULE__{checks: checks, workspace: workspace}, opts) do
    tail_lines = Keyword.get(opts, :tail_lines, 40)

    Enum.flat_map(checks, fn check ->
      case Exec.run_shell(check.command,
             cd: workspace,
             timeout_ms: check.timeout_ms,
             max_bytes: @max_output_bytes
           ) do
        {:ok, %{status: 0, timed_out?: false}} ->
          []

        {:ok, %{timed_out?: true}} ->
          ["`#{check.name}` (#{check.command}) did not finish within #{check.timeout_ms} ms."]

        {:ok, result} ->
          [
            "`#{check.name}` (#{check.command}) exited #{result.status}:\n" <>
              tail(result.output <> result.stderr, tail_lines)
          ]

        {:error, reason} ->
          ["`#{check.name}` (#{check.command}) could not run: #{inspect(reason)}"]
      end
    end)
  end

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

  defp invoke(hook, payload, ceiling \\ nil) do
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
        {:ok, parse_output(result.output)}

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
      hook.event == event and matches?(hook.matcher, tool_name)
    end)
  end

  defp matches?(nil, _tool_name), do: true
  defp matches?(_matcher, nil), do: true
  defp matches?(regex, tool_name), do: Regex.match?(regex, tool_name)

  # ---------------------------------------------------------------- loading

  defp load_project(nil, _trusted?), do: {[], [], [], 0}

  defp load_project(root, trusted?) do
    path = Path.join(root, @project_file)

    case read_config(path) do
      {:ok, %{} = document} ->
        {hooks, hook_errors} = hooks_from(document, :workspace, root)
        {checks, check_errors} = checks_from(document)

        if trusted? do
          {hooks, checks, hook_errors ++ check_errors, 0}
        else
          {[], [], hook_errors ++ check_errors, length(hooks) + length(checks)}
        end

      :absent ->
        {[], [], [], 0}

      {:error, message} ->
        {[], [], ["#{path}: #{message}"], 0}
    end
  end

  defp load_user(opts) do
    case user_path(opts) do
      nil ->
        {[], [], [], 0}

      path ->
        case read_config(path) do
          {:ok, %{} = document} ->
            {hooks, errors} = hooks_from(document, :user, Path.dirname(path))
            {hooks, [], errors, 0}

          :absent ->
            {[], [], [], 0}

          {:error, message} ->
            {[], [], ["#{path}: #{message}"], 0}
        end
    end
  end

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

  defp hooks_from(document, scope, cwd) do
    document
    |> Map.get("hooks", [])
    |> List.wrap()
    |> Enum.with_index(1)
    |> Enum.reduce({[], []}, fn {entry, index}, {hooks, errors} ->
      case build(entry, scope, cwd) do
        {:ok, hook} -> {hooks ++ [hook], errors}
        {:error, message} -> {hooks, errors ++ ["[[hooks]] ##{index}: #{message}"]}
      end
    end)
  end

  defp build(entry, scope, cwd) when is_map(entry) do
    with {:ok, event} <- event(Map.get(entry, "event")),
         {:ok, command} <- command(Map.get(entry, "command")),
         {:ok, matcher} <- matcher(Map.get(entry, "matcher")) do
      {:ok,
       %{
         event: event,
         matcher: matcher,
         command: command,
         timeout_ms: timeout(Map.get(entry, "timeout_ms")),
         scope: scope,
         cwd: cwd
       }}
    end
  end

  defp build(_entry, _scope, _cwd), do: {:error, "is not a table"}

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

      pattern ->
        case Regex.compile("\\A(?:" <> pattern <> ")\\z") do
          {:ok, regex} ->
            {:ok, regex}

          {:error, reason} ->
            {:error, "`matcher` is not a regular expression: #{inspect(reason)}"}
        end
    end
  end

  defp matcher(_value), do: {:error, "`matcher` must be a string"}

  defp timeout(value) when is_integer(value) and value > 0, do: min(value, @max_timeout_ms)
  defp timeout(_value), do: @default_timeout_ms

  defp checks_from(document) do
    document
    |> Map.get("checks", %{})
    |> case do
      table when is_map(table) ->
        Enum.reduce(Enum.sort(table), {[], []}, fn {name, value}, {checks, errors} ->
          case value do
            command when is_binary(command) and command != "" ->
              {checks ++
                 [%{name: name, command: String.trim(command), timeout_ms: @default_timeout_ms}],
               errors}

            _other ->
              {checks, errors ++ ["[checks] #{name}: must be a command string"]}
          end
        end)

      _not_a_table ->
        {[], ["[checks] must be a table"]}
    end
  end

  # ---------------------------------------------------------------- text

  defp tail(text, lines) do
    text
    |> String.split("\n")
    |> Enum.reject(&(String.trim(&1) == ""))
    |> Enum.take(-lines)
    |> Enum.join("\n")
    |> clip(@max_context_bytes)
  end

  defp clip(text, limit) when byte_size(text) <= limit, do: text
  defp clip(text, limit), do: binary_part(text, 0, limit) <> "\n… (truncated)"
end
