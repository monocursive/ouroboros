defmodule Ouroboros.Provider.Native.Tools.Skill do
  @moduledoc """
  Load one Agent Skill's instructions into the turn.

  Discovery, the budget, and the frontmatter rules all live in
  `Ouroboros.Provider.Native.Skills`; this is the call. The tool's *description* carries
  the catalogue — the names and one-line descriptions of every skill this session can
  see, bounded — which is why the description is built per session rather than baked in
  by `Jido.Action`. That is the whole Agent Skills trick: names in the prompt, bodies on
  demand.

  A skill's body arrives as a tool result, so it reads to the model exactly like a file
  it opened. It grants nothing.
  """

  use Jido.Action,
    name: "skill",
    description:
      "Load one skill's instructions. Skills are project- or user-authored guides for " <>
        "specific tasks. Call this only for a skill named in this description.",
    schema: [
      name: [type: :string, required: true, doc: "The skill's name, exactly as listed."]
    ]

  alias Ouroboros.Provider.Native.Skills

  @doc """
  The description the model sees for this session, with the skill catalogue in it.

  `Ouroboros.Provider.Native.Tools.specs/3` calls this when it is given a scope. With no
  scope — the coding plane's prompt preview, for instance — the static description above
  stands.
  """
  @spec description(keyword()) :: String.t()
  def description(opts) do
    root = Keyword.get(opts, :workspace)
    skills = Skills.discover(root)

    case Skills.catalogue(skills, opts) do
      "" ->
        "Load one skill's instructions. No skills are installed for this workspace " <>
          "(none found under `.agents/skills/` or `~/.config/ouroboros/skills/`), so " <>
          "there is nothing to load."

      catalogue ->
        "Load one skill's instructions by name. Skills available in this session:\n" <>
          catalogue <>
          "\nCall this when a skill's description matches the task. Do not guess a name " <>
          "that is not listed."
    end
  end

  @impl true
  def run(params, context) do
    root = context[:scope][:root]

    case Skills.load(params.name, root) do
      {:ok, skill} ->
        {:ok,
         %{
           output:
             "Skill `#{skill.name}` (#{skill.scope} scope, #{Path.relative_to(skill.path, root || "/")}):\n\n" <>
               skill.body,
           is_error: false
         }}

      {:error, reason} ->
        {:ok, %{output: "skill failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp describe({:unknown_skill, name, []}),
    do: "there is no skill named `#{name}`, and no skills are installed for this workspace"

  defp describe({:unknown_skill, name, available}),
    do: "there is no skill named `#{name}`. Available: #{Enum.join(available, ", ")}."

  defp describe({:unreadable_skill, path, reason}),
    do: "#{path}: #{:file.format_error(reason)}"
end
