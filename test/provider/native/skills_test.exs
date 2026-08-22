defmodule Ouroboros.Provider.Native.SkillsTest do
  @moduledoc """
  Agent Skills: discovery, the budget, and the load.

  The user scope is redirected at a temporary directory through
  `config :ouroboros, :native_user_skills_dir`, so nothing here reads or depends on the
  machine's real `~/.config/ouroboros/skills`. Not `async` for that reason.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Skills
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Skill

  setup do
    root = Path.join(System.tmp_dir!(), "native-skills-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    home = Path.join(root, "home")
    File.mkdir_p!(workspace)
    File.mkdir_p!(Path.join(home, ".config/ouroboros/skills"))

    previous = Application.get_env(:ouroboros, :native_user_skills_dir)

    Application.put_env(
      :ouroboros,
      :native_user_skills_dir,
      Path.join([home, ".config", "ouroboros", "skills"])
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :native_user_skills_dir, previous),
        else: Application.delete_env(:ouroboros, :native_user_skills_dir)

      File.rm_rf(root)
    end)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)

    %{
      root: root,
      home: home,
      workspace: scope.root,
      scope: scope,
      context: %{scope: scope, session_dir: root, reads: %{}}
    }
  end

  defp project_skill(workspace, name, frontmatter, body \\ "Do the thing.") do
    directory = Path.join([workspace, ".agents", "skills", name])
    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "SKILL.md"), "---\n" <> frontmatter <> "---\n" <> body)
  end

  defp user_skill(home, name, frontmatter, body \\ "User body.") do
    directory = Path.join([home, ".config", "ouroboros", "skills", name])
    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "SKILL.md"), "---\n" <> frontmatter <> "---\n" <> body)
  end

  describe "discovery" do
    test "finds project and user skills, project first on a name collision", %{
      workspace: workspace,
      home: home
    } do
      project_skill(workspace, "deploy", "name: deploy\ndescription: Ship it.\n", "Project body.")
      user_skill(home, "deploy", "name: deploy\ndescription: The user's.\n", "User body.")
      user_skill(home, "review", "name: review\ndescription: Read it.\n")

      skills = Skills.discover(workspace)

      assert Enum.map(skills, & &1.name) == ["deploy", "review"]
      assert Enum.find(skills, &(&1.name == "deploy")).scope == :project
      assert Enum.find(skills, &(&1.name == "deploy")).description == "Ship it."
      assert Enum.find(skills, &(&1.name == "review")).scope == :user
    end

    test "a directory with no SKILL.md is not a skill", %{workspace: workspace} do
      File.mkdir_p!(Path.join([workspace, ".agents", "skills", "empty"]))
      assert Skills.discover(workspace) == []
    end

    test "falls back to the directory name when the frontmatter names none", %{
      workspace: workspace
    } do
      project_skill(workspace, "fallback", "description: No name key.\n")
      assert [%{name: "fallback"}] = Skills.discover(workspace)
    end

    test "a name that is not the documented shape is skipped rather than sanitised", %{
      workspace: workspace
    } do
      directory = Path.join([workspace, ".agents", "skills", "Bad Name!"])
      File.mkdir_p!(directory)
      File.write!(Path.join(directory, "SKILL.md"), "---\nname: ../../escape\n---\nbody")

      assert Skills.discover(workspace) == []
    end

    test "no workspace and no directories is an empty list, never an error" do
      assert Skills.discover(nil) == []
      assert Skills.discover("/nonexistent-#{System.unique_integer([:positive])}") == []
    end

    test "a long description is clipped", %{workspace: workspace} do
      project_skill(workspace, "verbose", "description: #{String.duplicate("x", 5_000)}\n")

      [skill] = Skills.discover(workspace)
      assert byte_size(skill.description) <= 1_030
      assert String.ends_with?(skill.description, "…")
    end
  end

  describe "the catalogue budget" do
    test "lists names and descriptions" do
      catalogue =
        Skills.catalogue([
          %{name: "a", description: "First.", path: "x", scope: :project},
          %{name: "b", description: "Second.", path: "y", scope: :user}
        ])

      assert catalogue =~ "a — First."
      assert catalogue =~ "b — Second."
    end

    test "stops at the budget and says how many it dropped" do
      skills =
        for index <- 1..200 do
          %{
            name: "skill#{index}",
            description: String.duplicate("d", 200),
            path: "x",
            scope: :project
          }
        end

      catalogue = Skills.catalogue(skills)

      assert byte_size(catalogue) <= 8_200
      assert catalogue =~ "more not listed"
      assert catalogue =~ "the budget is 8000 characters"
    end

    test "2% of the context window wins when it is smaller than 8k characters" do
      skills =
        for index <- 1..50 do
          %{
            name: "s#{index}",
            description: String.duplicate("d", 100),
            path: "x",
            scope: :project
          }
        end

      narrow = Skills.catalogue(skills, context_window: 8_000)
      wide = Skills.catalogue(skills, context_window: 1_000_000)

      assert byte_size(narrow) < byte_size(wide)
      assert narrow =~ "the budget is 640 characters"
    end

    test "no skills is an empty catalogue, not an empty list rendered" do
      assert Skills.catalogue([]) == ""
    end
  end

  describe "load" do
    test "returns the body with the frontmatter stripped", %{workspace: workspace} do
      project_skill(
        workspace,
        "deploy",
        "name: deploy\ndescription: Ship it.\n",
        "# Steps\n\n1. Go"
      )

      assert {:ok, skill} = Skills.load("deploy", workspace)
      assert skill.body == "# Steps\n\n1. Go"
      refute skill.body =~ "description:"
    end

    test "an unknown name answers with the names that exist", %{workspace: workspace} do
      project_skill(workspace, "deploy", "description: Ship it.\n")

      assert {:error, {:unknown_skill, "release", ["deploy"]}} = Skills.load("release", workspace)
    end
  end

  describe "the `skill` tool" do
    test "its description carries the catalogue for this workspace", %{workspace: workspace} do
      project_skill(workspace, "deploy", "description: Ship it.\n")

      description = Skill.description(workspace: workspace)
      assert description =~ "Skills available in this session"
      assert description =~ "deploy — Ship it."
    end

    test "says so when there are none", %{workspace: workspace} do
      description = Skill.description(workspace: workspace)
      assert description =~ "No skills are installed for this workspace"
    end

    test "the session's tool spec picks the catalogue up", %{workspace: workspace} do
      project_skill(workspace, "deploy", "description: Ship it.\n")

      spec = Tools.specs(nil, nil, workspace: workspace) |> Enum.find(&(&1.name == "skill"))
      assert spec.description =~ "deploy — Ship it."

      # With no workspace the static description stands rather than a stale catalogue.
      bare = Tools.specs(nil, nil) |> Enum.find(&(&1.name == "skill"))
      refute bare.description =~ "deploy"
    end

    test "loading one returns its body as a tool result", %{
      workspace: workspace,
      context: context
    } do
      project_skill(workspace, "deploy", "description: Ship it.\n", "Run the pipeline.")

      result = Tools.execute(Skill, %{"name" => "deploy"}, context, 10_000)

      refute result.is_error
      assert result.output =~ "Skill `deploy` (project scope"
      assert result.output =~ "Run the pipeline."
    end

    test "an unknown name is an in-band error naming what exists", %{
      workspace: workspace,
      context: context
    } do
      project_skill(workspace, "deploy", "description: Ship it.\n")

      result = Tools.execute(Skill, %{"name" => "nope"}, context, 10_000)

      assert result.is_error
      assert result.output =~ "there is no skill named `nope`"
      assert result.output =~ "Available: deploy"
    end
  end

  describe "frontmatter parsing" do
    test "reads only name and description, and unquotes" do
      front =
        Skills.frontmatter(~s(---\nname: "a"\ndescription: 'b'\nallowed-tools: rm\n---\nbody))

      assert front == %{"name" => "a", "description" => "b"}
    end

    test "a file with no frontmatter yields nothing rather than guessing" do
      assert Skills.frontmatter("# Just a heading\n") == %{}
    end
  end
end
