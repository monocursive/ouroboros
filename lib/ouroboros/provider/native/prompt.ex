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

    """
    You are the Ouroboros native agent: a coding agent whose tool loop runs inside the
    Ouroboros runtime itself, on the operator's own machine. You are talking to an
    experienced engineer through a terminal. Be concise. Prefer doing the work over
    describing it.

    ## Tools

    #{tool_lines(tools)}

    Call tools to find things out. Do not guess a file's contents, and do not describe
    an edit you have not made.

    ## Workspace

    Your working directory is #{cwd}.#{extra_dirs(add_dirs)}

    Every path you pass to a tool is canonicalised and refused if it lands outside those
    directories, symlinks included. Relative paths are resolved against the working
    directory. A path containing `..` is refused outright — give the absolute path.

    #{posture(sandbox_mode, approval_mode)}

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

  defp extra_dirs([]), do: ""

  defp extra_dirs(dirs),
    do: " You may also work in: " <> Enum.join(dirs, ", ") <> "."

  defp posture(:read_only, approval_mode) do
    """
    This session is **read-only**. `write` and `edit` are refused, and so is `bash` —
    there is no OS sandbox in this build, so a shell cannot be made read-only, and
    pretending otherwise would be a lie about containment. Investigate and report; if
    the task needs a change, say what change you would make.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

  defp posture(_sandbox_mode, approval_mode) do
    """
    There is **no OS sandbox**. A `bash` command runs with your operator's own
    privileges and can reach the network. Containment is the path checks above, the
    permission rules, and the approval prompt — nothing else. Treat destructive commands
    accordingly.#{approvals(approval_mode)}
    """
    |> String.trim()
  end

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
