defmodule Ouroboros.Provider.Native.Prompt do
  @moduledoc """
  The system prompt for a native session, and the discipline around the caller's.

  Short on purpose. Pi's prompt is under a thousand tokens and Claude Code's own memory
  guidance says an instruction file past roughly two hundred lines "reduce[s]
  adherence"; a prompt that lists every rule the author could think of is how a model
  learns to skim rules. This one states who the agent is, what its tools are, where it
  may work, and the four things it must actually do.

  The honesty invariant is a prompt rule, not a doc rule: the agent is told to say what
  it verified and to name what it did not. That is the sentence the rest of this
  runtime's honesty claims rest on, so it lives in the prompt where the model reads it.

  One block is conditional: a session in plan mode (B2) gets a `## Plan mode` section that
  states the task — explore, record the plan with the `plan` tool, stop — because a model
  handed a read-only posture and no instruction discovers it one refused tool at a time.
  It is part of the cached prefix like everything else here, which is why leaving plan
  mode rebuilds the prefix: the session is a different session to the model afterwards.

  ## The envelope

  A caller's `system_prompt` is not concatenated raw. It goes through
  `Ouroboros.Prompt.Assembler`, the same path the interactive plane uses, which refuses
  text containing an `<ouroboros-agent-profile>`, `<ouroboros-session-instructions>`, or
  `<ouroboros-runtime>` delimiter rather than escaping it — a prompt this runtime
  rewrote would no longer be the prompt whose digest it reports. The base prompt below
  is held to the same rule by `Ouroboros.AgentProfile.reserved_delimiter?/1`, so the
  provider's own text cannot forge a block either. `test/provider/native/prompt_test.exs`
  asserts it.
  """

  alias Ouroboros.AgentProfile
  alias Ouroboros.Prompt.Assembler
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Sandbox

  @doc """
  Builds the system prompt for one session.

  Returns `{:error, {:reserved_prompt_delimiter, :system_prompt}}` when the caller's
  prompt would forge a runtime block, which is the assembler's refusal, unchanged.

  `:instructions` carries the rendered project instruction files from
  `Ouroboros.Provider.Native.Context.Instructions`. They sit between the provider's own
  text and the operator's, and are held to the same delimiter rule: a repository that
  could forge an `<ouroboros-runtime>` block would be writing runtime identity into a
  session opened on it.
  """
  @spec build(keyword()) :: {:ok, String.t()} | {:error, term()}
  def build(opts) do
    caller = Keyword.get(opts, :system_prompt)
    instructions = Keyword.get(opts, :instructions)

    with {:ok, assembly} <- Assembler.assemble(nil, system_prompt: caller),
         :ok <- verify(assembly.system_prompt, :system_prompt),
         :ok <- verify(instructions, :instruction_files),
         base = base(opts),
         :ok <- verify(base, :native_base_prompt) do
      base
      |> with_instructions(instructions)
      |> join(assembly.system_prompt)
      |> then(&{:ok, &1})
    end
  end

  @doc "The provider's own prompt text, without the caller's."
  @spec base(keyword()) :: String.t()
  def base(opts) do
    cwd = Keyword.get(opts, :cwd, "the workspace")
    add_dirs = Keyword.get(opts, :add_dirs) || []
    sandbox_mode = Keyword.get(opts, :sandbox_mode, :default)
    approval_mode = Keyword.get(opts, :approval_mode, :default)
    tools = Keyword.get(opts, :tools) || Tools.specs(nil, nil)

    sandbox = Keyword.get(opts, :sandbox, Sandbox.detect())
    scope = %{root: cwd, roots: [cwd | add_dirs], sandbox_mode: sandbox_mode}
    sandbox_decision = Sandbox.decision(scope, sandbox)

    """
    You are the Ouroboros native agent: a coding agent whose tool loop runs inside the
    Ouroboros runtime itself, on the operator's own machine. You are talking to an
    experienced engineer through a terminal. Be concise. Prefer doing the work over
    describing it.

    ## Tools

    #{tool_lines(tools)}

    #{tool_guidance(tools)}
    Call tools to find things out. Do not guess a file's contents, and do not describe
    an edit you have not made. Every tool input must match its advertised schema and
    include every required argument. After an invalid-arguments result, correct the
    input; never repeat the unchanged call.

    ## Workspace

    Your working directory is #{cwd}.#{extra_dirs(add_dirs)}

    Every path you pass to a tool is canonicalised and refused if it lands outside those
    directories, symlinks included. Relative paths are resolved against the working
    directory. A path containing `..` is refused outright — give the absolute path.

    #{posture(sandbox_decision, approval_mode)}
    #{plan_section(approval_mode)}
    ## Rules

    1. **Read before you edit.** `edit` refuses a file this session has not read, and
       refuses again if the file changed after that read. Read it, then edit it.
    2. **Make `old_string` unique.** Include enough surrounding lines that it matches
       once. If a match needed whitespace tolerance, the result says so — check it.
    3. **Run the project's own checks.** Use the test, lint, and type commands this
       repository already has, the way its own documentation runs them. Do not invent a
       command, and do not claim a check you did not run.
    4. **Report what you verified.** Say which checks you ran and what they returned.
       Name anything you changed but did not verify, and anything you could not do. An
       unverified claim is worse than an admitted gap: the operator can act on a gap.

    ## Ouroboros sources

    When the task is about Ouroboros itself and this workspace contains its source, read
    `README.md` and the relevant document before answering from memory:
    `docs/ARCHITECTURE.md` for runtime boundaries, `docs/PROTOCOL.md` for the gateway
    contract, `docs/TUI.md` for the terminal client, and `docs/FLEET.md` for distributed
    operation. Follow their cross-references before changing behavior.

    ## Style

    Answer in plain prose, no preamble and no summary of what you are about to do.
    Reference code as `path:line`. When you are finished, say what changed and what you
    checked, in a few lines. If a task turns out to be the wrong thing to do, say so
    instead of doing it well.
    """
    |> String.trim()
  end

  defp tool_lines(tools) do
    Enum.map_join(tools, "\n", fn tool ->
      "- `#{tool.name}` — #{first_sentence(tool.description)}"
    end)
  end

  defp first_sentence(description) do
    description
    |> String.split(". ", parts: 2)
    |> List.first()
    |> String.trim_trailing(".")
    |> Kernel.<>(".")
  end

  defp tool_guidance(tools) do
    names = Enum.map(tools, & &1.name)
    search_tools = Enum.filter(~w(grep glob ls), &(&1 in names))

    guidelines =
      [
        if("read" in names, do: "Use `read`, not `bash`, to inspect file contents."),
        if(search_tools != [],
          do: "Use #{tool_names(search_tools)} for discovery instead of shell pipelines."
        ),
        if("code_intel" in names,
          do: "Use `code_intel` for symbol-aware navigation, references, and diagnostics."
        ),
        if("edit" in names,
          do: "Use `edit` for one exact, uniquely matched replacement in a file."
        ),
        if("apply_patch" in names,
          do: "Use `apply_patch` for coordinated structural or multi-file changes."
        ),
        if("write" in names,
          do: "Use `write` only for a new file or an intentional whole-file replacement."
        )
      ]
      |> Enum.reject(&is_nil/1)

    case guidelines do
      [] ->
        ""

      rows ->
        "Use the most specific available tool:\n" <> Enum.map_join(rows, "\n", &("- " <> &1))
    end
  end

  defp tool_names(names), do: Enum.map_join(names, ", ", &"`#{&1}`")

  defp extra_dirs([]), do: ""

  defp extra_dirs(dirs),
    do: " You may also work in: " <> Enum.join(dirs, ", ") <> "."

  defp posture(_decision, :plan) do
    """
    This session is **read-only for planning**. The `## Plan mode` section below names
    every operation that is refused.#{approvals(:plan)}
    """
    |> String.trim()
  end

  defp posture({:sandboxed, label, %{mode: :read_only} = policy}, approval_mode) do
    """
    This session is **read-only**. `write`, `edit`, `apply_patch`, and writing
    `code_intel` operations are refused. `bash` runs inside the #{label} OS sandbox; it
    may write only to a private scratch directory, and #{network_posture(policy)}
    Investigate and report; if the task needs a change, say what change you would
    make.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp posture({:sandboxed, label, %{mode: :workspace_write} = policy}, approval_mode) do
    """
    `bash` runs inside the #{label} OS sandbox. The workspace and declared roots are
    writable; `.git`, `.ouroboros`, the runtime data directory, and the user's Ouroboros
    configuration stay read-only. #{String.capitalize(network_posture(policy))}
    A sandbox denial names the constraint it hit; do not retry it under a weaker
    posture.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp posture({:refused, {:read_only_without_backend, _detection}}, approval_mode) do
    """
    This session is **read-only**. `write`, `edit`, `apply_patch`, and `bash` are refused:
    this node has no OS sandbox that can make a shell read-only. Investigate and report;
    if the task needs a change, say what change you would make.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp posture({:unsandboxed, {:no_backend, _detection}}, approval_mode) do
    """
    This node has **no OS sandbox available**. `bash` runs with the operator's own
    privileges and can write outside the workspace or reach the network. Path checks
    still contain the file tools, and permission rules and approvals still gate the
    command. Treat destructive commands accordingly.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp posture({:unsandboxed, :unrestricted}, approval_mode) do
    """
    This session is explicitly **unrestricted**. `bash` has no OS sandbox and runs with
    the operator's own filesystem and network access. Permission rules and approvals
    still apply. Treat destructive commands accordingly.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp posture({:refused, reason}, approval_mode) do
    """
    `bash` is refused because the session has no sandbox policy for
    `#{inspect(reason)}`. File tools remain bounded by the workspace path checks
    above.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp network_posture(%{network: true}), do: "network access is enabled by node policy."
  defp network_posture(_policy), do: "network access is denied."

  # B2. The instruction block that makes plan mode a *task* rather than a series of
  # refusals. Without it a model in a read-only session spends the turn discovering, one
  # denied tool at a time, that it cannot work — which is the behaviour every vendor's
  # plan mode had before it grew a prompt.
  #
  # It is deliberately short and ends with "stop": the exit approval is what turns the
  # plan into work, and a model that kept going would be answering a question the operator
  # has not been asked yet.
  defp plan_section(:plan) do
    """

    ## Plan mode

    This session is **planning**. Investigate as much as you need, then produce a plan and
    stop. Do not try to make the change.

    1. Read the code the task touches. A plan written from memory is a guess with numbered
       steps, and this session exists so that it is not one.
    2. Record the plan with the `plan` tool — every step, in order, replacing the whole
       plan each time. That is the form the operator reviews.
    3. Say in a few lines what you found, what the plan assumes, and what you are unsure
       about. Name the alternative you rejected and why, if there was one.
    4. Then stop. Do not ask for permission to start; the operator is asked automatically
       when your turn ends, and they choose whether the work runs with edits auto-accepted,
       with each change approved by hand, or not yet.

    `write`, `edit`, `apply_patch`, `bash` and the writing `code_intel` operations are
    refused for the whole of this mode, whatever a permission rule says. If the task turns
    out to need no change, say that instead of planning one.
    """
    |> String.trim_trailing()
    |> Kernel.<>("\n")
  end

  defp plan_section(_other), do: ""

  defp approvals(:plan),
    do:
      " Nothing runs that would change anything: this session is read-only until the " <>
        "operator answers the plan-exit question at the end of the turn."

  defp approvals(:auto_approve),
    do: " Tools run without asking; the operator sees every call in the transcript."

  defp approvals(:auto_edit),
    do:
      " Edits and writes inside the workspace run without asking. Commands are put to " <>
        "the operator, who may take a moment to answer."

  defp approvals(_prompt),
    do:
      " A tool call may be put to the operator for approval before it runs. That is " <>
        "normal; wait for the answer rather than trying a different tool."

  # `Assembler.assemble(nil, …)` returns a caller's prompt byte-for-byte and only
  # rejects invalid UTF-8: with no profile there is no block for the caller's text to
  # break out of, so the assembler has nothing to defend. This module composes — its own
  # sections wrap the caller's text — so the delimiter check that the profile path
  # applies has to be applied here too, with the same refusal shape.
  defp verify(nil, _field), do: :ok

  defp verify(text, field) do
    if AgentProfile.reserved_delimiter?(text),
      do: {:error, {:reserved_prompt_delimiter, field}},
      else: :ok
  end

  # Project instructions go *before* the operator's session prompt and after the
  # runtime's rules, which is the precedence the text itself states: the runtime's rules
  # are not negotiable, the repository's instructions are how this repository works, and
  # the operator's instructions for this session outrank the repository's.
  defp with_instructions(base, nil), do: base
  defp with_instructions(base, ""), do: base
  defp with_instructions(base, instructions), do: base <> "\n\n" <> instructions

  defp join(base, nil), do: base
  defp join(base, ""), do: base

  defp join(base, caller) do
    base <>
      "\n\n## Session instructions\n\nThe operator configured this session with the " <>
      "following instructions. They take precedence over the style guidance above, " <>
      "never over the rules.\n\n" <> caller
  end
end
