defmodule Ouroboros.WorkspaceAccessTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Workspace.{Access, Git, Worktree}
  alias Ouroboros.Provider.Native.{Paths, Sandbox, Tools}
  alias Ouroboros.Provider.Native.Tools.{Bash, Write}
  alias Ouroboros.Control.Permissions.{Request, Rule, Rules}

  setup do
    {:ok, root} = Git.temp_directory()
    data = Path.join(root, "data")

    saved =
      Map.new([:data_dir, :workspace_allowed_roots], &{&1, Application.get_env(:ouroboros, &1)})

    Application.put_env(:ouroboros, :data_dir, data)
    Application.put_env(:ouroboros, :workspace_allowed_roots, [root])
    id = String.duplicate("a", 64)
    repo = Path.join([data, "mirrors", id])
    source = Path.join(root, "source")
    File.mkdir_p!(source)
    git!(source, ["init", "-q"])
    git!(source, ["config", "user.name", "Test"])
    git!(source, ["config", "user.email", "test@example.invalid"])
    File.write!(Path.join(source, "base"), "base")
    git!(source, ["add", "base"])
    git!(source, ["commit", "-qm", "base"])
    File.mkdir_p!(Path.dirname(repo))
    git!(source, ["clone", "--bare", "-q", source, repo])
    commit = git!(source, ["rev-parse", "HEAD"])
    {:ok, tree} = Worktree.create_detached(repo, commit, "access-child", repo_id: id)
    {:ok, sibling} = Worktree.create_detached(repo, commit, "access-sibling", repo_id: id)
    File.mkdir_p!(Path.join(tree.root, ".ouroboros/deliver"))
    {:ok, scope} = Paths.scope(tree.root, [], :workspace_write)
    session = Path.join(root, "session")
    File.mkdir_p!(session)

    on_exit(fn ->
      Enum.each(saved, fn {key, value} ->
        if is_nil(value),
          do: Application.delete_env(:ouroboros, key),
          else: Application.put_env(:ouroboros, key, value)
      end)

      File.rm_rf(root)
    end)

    %{
      root: root,
      repo: tree.repository,
      tree: tree,
      sibling: sibling,
      scope: scope,
      context: %{scope: scope, session_dir: session, reads: %{}}
    }
  end

  test "ordinary native write permission reaches only verified delivery content", c do
    input = %{"path" => ".ouroboros/deliver/report.txt", "content" => "report"}

    request =
      Tools.classify("write", input, c.scope)
      |> Map.put(:principal, %{session_id: "access-child"})
      |> Request.new()

    {:ok, rule} =
      Rule.new(
        scope: :session,
        session_id: "access-child",
        decision: :allow,
        pattern: "Write(#{c.tree.root}/**)"
      )

    assert {:allow, _} = Rules.decide(request, [rule])
    assert %{is_error: false} = Tools.execute(Write, input, c.context, 30_000)
    assert File.read!(Path.join(c.tree.root, input["path"])) == "report"

    for suffix <- [
          ".git/HEAD",
          ".ouroboros/state",
          ".ouroboros/deliver/.git/config",
          ".ouroboros/deliver/deep/.OuRoBoRoS/state"
        ] do
      assert Rules.protected_write?(Path.join(c.tree.root, suffix))
    end

    File.ln_s!(c.repo, Path.join(c.tree.root, ".ouroboros/deliver/escape"))
    refute Access.delivery_write?(Path.join(c.tree.root, ".ouroboros/deliver/escape/config"))

    File.rename!(
      Path.join(c.tree.root, ".ouroboros/deliver"),
      Path.join(c.tree.root, "delivery-moved")
    )

    File.ln_s!(
      Path.join(c.tree.root, "delivery-moved"),
      Path.join(c.tree.root, ".ouroboros/deliver")
    )

    assert is_nil(Access.grants(c.tree.root))
  end

  test "registry authority and additive backend protocol", c do
    %{delivery: delivery, git: git} = Access.grants(c.tree.root)
    assert git == [c.tree.git_dir, Path.join(c.repo, "objects")]
    existing = Path.join(delivery, ".GIT")
    File.write!(existing, "protected")
    ordinary = Sandbox.policy(c.scope, :workspace_write)
    assert ordinary.write_exceptions == [delivery]
    binds = Sandbox.Bwrap.options(c.scope, Sandbox.with_scratch(ordinary, c.root), false)
    assert ["--ro-bind", existing, existing] in Enum.chunk_every(binds, 3, 1, :discard)
    escalated = Sandbox.policy(c.scope, :workspace_write_escalated)
    assert escalated.write_exceptions == [delivery | git]
    assert escalated.protected_segments == [".git", ".ouroboros"]
    refute Map.has_key?(Sandbox.policy(c.scope, :read_only), :write_exceptions)
    assert Sandbox.Helper.request(escalated, c.scope)["write_exceptions"] == [delivery | git]
    File.write!(Path.join(c.tree.git_dir, "gitdir"), Path.join(c.sibling.root, ".git"))
    assert is_nil(Access.grants(c.tree.root))
    invalid = Sandbox.policy(c.scope, :workspace_write_escalated)
    assert invalid.protected_segments == [".git", ".ouroboros"]
    refute Map.has_key?(invalid, :write_exceptions)
    assert Rules.protected_write?(delivery <> "/report")
  end

  test "real bash delivery and approved detached Git commit preserve neighboring fences", c do
    unless Sandbox.detect().backend in [:sandbox_exec, :ouro_sandbox, :bwrap],
      do: flunk("OS sandbox required")

    assert %{is_error: false} =
             Tools.execute(
               Bash,
               %{"command" => "printf 'log\\n' > .ouroboros/deliver/test.log"},
               c.context,
               30_000
             )

    assert File.read!(Path.join(c.tree.root, ".ouroboros/deliver/test.log")) == "log\n"
    File.write!(Path.join(c.tree.root, "changed"), "change")

    command =
      "git -c user.name=Test -c user.email=test@example.invalid add changed && git -c user.name=Test -c user.email=test@example.invalid commit -qm child"

    denied = Tools.execute(Bash, %{"command" => command}, c.context, 30_000)
    assert denied.is_error
    policy = Sandbox.policy(c.scope, :workspace_write)

    assert Sandbox.escalatable?(
             %{
               constraint: :filesystem,
               evidence:
                 "fatal: cannot create '#{c.tree.git_dir}/index.lock': Operation not permitted"
             },
             policy,
             command
           )

    refute Sandbox.escalatable?(
             %{constraint: :filesystem, evidence: "#{c.repo}/config: Operation not permitted"},
             policy,
             command
           )

    approved = Map.put(c.context, :scope, Sandbox.escalated_scope(c.scope))
    result = Tools.execute(Bash, %{"command" => command}, approved, 30_000)
    refute result.is_error, inspect(result)
    assert git!(c.tree.root, ["log", "-1", "--format=%s"]) == "child"

    for target <- [
          Path.join(c.tree.root, ".git"),
          Path.join(c.repo, "config"),
          Path.join(c.repo, "hooks/bad"),
          Path.join(c.repo, "refs/bad"),
          Path.join(c.sibling.git_dir, "HEAD"),
          Path.join(c.sibling.root, "bad"),
          Path.join(c.tree.root, ".ouroboros/state"),
          Path.join(c.tree.root, ".ouroboros/deliver/.git/config")
        ] do
      result = Tools.execute(Bash, %{"command" => "printf bad > '#{target}'"}, approved, 30_000)
      assert result.is_error, "unexpected write to #{target}"
    end

    nested =
      Tools.execute(Bash, %{"command" => "mkdir .ouroboros/deliver/.GIT"}, approved, 30_000)

    assert nested.is_error
  end

  defp git!(cwd, args) do
    {out, 0} = System.cmd("git", args, cd: cwd, stderr_to_stdout: true)
    String.trim(out)
  end
end
