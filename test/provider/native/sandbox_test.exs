defmodule Ouroboros.Provider.Native.SandboxTest do
  # Not async: the `:none` backend cases put `:ouroboros, :native_sandbox` on the
  # application environment, which every other native session on this node reads.
  use ExUnit.Case, async: false

  alias Ouroboros.Control.Permissions.Rules
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.SandboxExec
  alias Ouroboros.Provider.Native.Tools.Bash

  @backend Sandbox.detect().backend

  # The live escape tests need the real binary. Where it is absent they are skipped with
  # the reason printed rather than silently passing, so a green Linux CI run is honest
  # about what it did not check.
  @needs_sandbox_exec (case @backend do
                         :sandbox_exec ->
                           []

                         other ->
                           [
                             skip:
                               "no sandbox-exec on this node (detected backend: #{inspect(other)}); " <>
                                 "the live escape tests need macOS"
                           ]
                       end)

  @none %{
    backend: :none,
    executable: nil,
    version: nil,
    notes: "no OS sandbox on this node: neither sandbox-exec nor bwrap is available"
  }

  setup do
    root = Path.join(System.tmp_dir!(), "native-sandbox-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/.git"))
    File.mkdir_p!(Path.join(root, "extra"))
    on_exit(fn -> File.rm_rf(root) end)

    workspace = Path.join(root, "workspace")
    {:ok, scope} = Paths.scope(workspace, [Path.join(root, "extra")], :workspace_write)
    {:ok, read_only} = Paths.scope(workspace, [], :read_only)
    session_dir = Path.join(root, "session")
    File.mkdir_p!(session_dir)

    %{
      root: root,
      workspace: scope.root,
      scope: scope,
      read_only: read_only,
      session_dir: session_dir,
      context: %{scope: scope, session_dir: session_dir, reads: %{}},
      read_only_context: %{scope: read_only, session_dir: session_dir, reads: %{}}
    }
  end

  defp fixed_policy(mode, network \\ false) do
    %{
      mode: mode,
      writable: if(mode == :read_only, do: ["/scratch"], else: ["/scratch", "/ws", "/ws-extra"]),
      protected: ["/srv/ouroboros/data", "/home/agent/.config/ouroboros"],
      protected_segments: [".git", ".ouroboros"],
      scratch: "/scratch",
      network: network
    }
  end

  defp run(module, input, context, timeout \\ 30_000),
    do: Ouroboros.Provider.Native.Tools.execute(module, input, context, timeout)

  describe "the macOS Seatbelt profile" do
    test "denies everything, opens reads, and makes only the scratch directory writable under read_only" do
      assert SandboxExec.profile(fixed_policy(:read_only)) == """
             (version 1)
             ; Ouroboros native agent, sandbox_mode: read_only.
             ; Shape after Codex CLI's Seatbelt base policy: closed by default, reads open,
             ; writes only where a parameter names them. Paths arrive as -D parameters.
             (deny default)
             (allow file-read*)
             (allow process-exec)
             (allow process-fork)
             (allow signal (target self))
             (allow sysctl-read)
             (allow mach-lookup)
             (allow file-write-data (require-all (path "/dev/null") (vnode-type CHARACTER-DEVICE)))
             (allow file-write* (subpath (param "OURO_WRITABLE_0")))
             (deny file-write* (subpath (param "OURO_PROTECTED_0")))
             (deny file-write* (subpath (param "OURO_PROTECTED_1")))
             (deny file-write* (regex #"/\\.git($|/)"))
             (deny file-write* (regex #"/\\.ouroboros($|/)"))
             (deny network*)
             """
    end

    test "opens every writable root under workspace_write and denies the protected ones after them" do
      assert SandboxExec.profile(fixed_policy(:workspace_write)) == """
             (version 1)
             ; Ouroboros native agent, sandbox_mode: workspace_write.
             ; Shape after Codex CLI's Seatbelt base policy: closed by default, reads open,
             ; writes only where a parameter names them. Paths arrive as -D parameters.
             (deny default)
             (allow file-read*)
             (allow process-exec)
             (allow process-fork)
             (allow signal (target self))
             (allow sysctl-read)
             (allow mach-lookup)
             (allow file-write-data (require-all (path "/dev/null") (vnode-type CHARACTER-DEVICE)))
             (allow file-write* (subpath (param "OURO_WRITABLE_0")))
             (allow file-write* (subpath (param "OURO_WRITABLE_1")))
             (allow file-write* (subpath (param "OURO_WRITABLE_2")))
             (deny file-write* (subpath (param "OURO_PROTECTED_0")))
             (deny file-write* (subpath (param "OURO_PROTECTED_1")))
             (deny file-write* (regex #"/\\.git($|/)"))
             (deny file-write* (regex #"/\\.ouroboros($|/)"))
             (deny network*)
             """
    end

    test "denies the network unless the policy allows it, and never by omission" do
      assert SandboxExec.profile(fixed_policy(:workspace_write)) =~ "(deny network*)"
      assert SandboxExec.profile(fixed_policy(:workspace_write, true)) =~ "(allow network*)"
      refute SandboxExec.profile(fixed_policy(:workspace_write, true)) =~ "(deny network*)"
    end

    test "carries every path as a -D parameter, so a workspace name cannot become policy" do
      policy = fixed_policy(:workspace_write)

      assert SandboxExec.parameters(policy) == [
               "-D",
               "OURO_WRITABLE_0=/scratch",
               "-D",
               "OURO_WRITABLE_1=/ws",
               "-D",
               "OURO_WRITABLE_2=/ws-extra",
               "-D",
               "OURO_PROTECTED_0=/srv/ouroboros/data",
               "-D",
               "OURO_PROTECTED_1=/home/agent/.config/ouroboros"
             ]

      for path <- policy.writable ++ policy.protected do
        refute SandboxExec.profile(policy) =~ path
      end
    end

    test "wraps a shell line as sandbox-exec's own argv, with the shell last" do
      policy = fixed_policy(:read_only)

      assert {:ok, {"/usr/bin/sandbox-exec", args}} =
               SandboxExec.wrap(
                 {:shell, "echo hi"},
                 %{root: "/ws"},
                 policy,
                 "/usr/bin/sandbox-exec"
               )

      assert ["-p", profile | rest] = args
      assert profile == SandboxExec.profile(policy)
      assert List.last(rest, nil) == "echo hi"
      assert Enum.take(rest, -3) == ["/bin/sh", "-c", "echo hi"]
    end
  end

  describe "the Linux bubblewrap argv" do
    test "binds the whole filesystem read-only and gives read_only nothing but a tmpfs scratch" do
      assert Bwrap.options(%{root: "/ws"}, fixed_policy(:read_only)) == [
               "--die-with-parent",
               "--ro-bind",
               "/",
               "/",
               "--dev",
               "/dev",
               "--proc",
               "/proc",
               "--tmpfs",
               "/scratch",
               "--unshare-net",
               "--chdir",
               "/ws"
             ]
    end

    test "binds each writable root read-write and re-binds its .git read-only on top", %{
      root: root,
      workspace: workspace
    } do
      scratch = Path.join(root, "scratch")

      policy = %{
        fixed_policy(:workspace_write)
        | writable: [scratch, workspace],
          protected: [],
          scratch: scratch
      }

      assert Bwrap.options(%{root: workspace}, policy) == [
               "--die-with-parent",
               "--ro-bind",
               "/",
               "/",
               "--dev",
               "/dev",
               "--proc",
               "/proc",
               "--bind",
               workspace,
               workspace,
               "--ro-bind",
               Path.join(workspace, ".git"),
               Path.join(workspace, ".git"),
               "--tmpfs",
               scratch,
               "--unshare-net",
               "--chdir",
               workspace
             ]
    end

    test "leaves the network namespace shared only when the policy allows the network" do
      refute "--unshare-net" in Bwrap.options(%{root: "/ws"}, fixed_policy(:read_only, true))
      assert "--unshare-net" in Bwrap.options(%{root: "/ws"}, fixed_policy(:read_only, false))
    end

    test "puts the program after a -- so an argv entry can never be read as an option" do
      assert {:ok, {"/usr/bin/bwrap", args}} =
               Bwrap.wrap(
                 {:shell, "echo hi"},
                 %{root: "/ws"},
                 fixed_policy(:read_only),
                 "/usr/bin/bwrap"
               )

      assert Enum.take(args, -4) == ["--", "/bin/sh", "-c", "echo hi"]
    end
  end

  describe "the decision" do
    test "refuses a read_only shell on a node with no backend, rather than weakening it", %{
      read_only: read_only
    } do
      assert {:refused, {:read_only_without_backend, _detection}} =
               Sandbox.decide(read_only, @none)
    end

    test "runs a workspace_write shell unsandboxed on a node with no backend, and says which", %{
      scope: scope
    } do
      assert {:unsandboxed, {:no_backend, _detection}} = Sandbox.decide(scope, @none)
    end

    test "refuses a sandbox_mode it has no policy for instead of rounding it to a near one", %{
      workspace: workspace
    } do
      {:ok, scope} = Paths.scope(workspace, [], :something_nobody_wrote)

      assert {:refused, {:unknown_sandbox_mode, :something_nobody_wrote}} =
               Sandbox.decide(scope, @none)
    end

    test "reads :default and nil as workspace_write, the way the loop already does", %{
      workspace: workspace
    } do
      for mode <- [:default, nil] do
        {:ok, scope} = Paths.scope(workspace, [], mode)
        assert {:unsandboxed, {:no_backend, _}} = Sandbox.decide(scope, @none)
      end
    end

    test "reads Codex's :danger_full_access as the harness's :unrestricted: no sandbox at all", %{
      workspace: workspace
    } do
      for mode <- [:unrestricted, :danger_full_access] do
        {:ok, scope} = Paths.scope(workspace, [], mode)
        assert {:unsandboxed, :unrestricted} = Sandbox.decide(scope, Sandbox.detect())
      end
    end

    test "makes only the scratch directory writable under read_only", %{read_only: read_only} do
      policy = read_only |> Sandbox.policy(:read_only) |> Sandbox.with_scratch("/scratch")
      assert policy.writable == ["/scratch"]
    end

    test "makes every declared root writable under workspace_write, scratch first", %{
      scope: scope,
      root: root
    } do
      policy = scope |> Sandbox.policy(:workspace_write) |> Sandbox.with_scratch("/scratch")

      assert hd(policy.writable) == "/scratch"
      assert scope.root in policy.writable
      assert Enum.any?(policy.writable, &String.ends_with?(&1, "extra"))
      assert length(policy.writable) == 3
      refute root in policy.writable
    end
  end

  describe "detection" do
    test "probes once and answers from the cache afterwards" do
      Sandbox.forget()
      first = Sandbox.detect()
      assert :persistent_term.get({Sandbox, :detection}) == first
      assert Sandbox.detect() == first
      assert first.backend in [:sandbox_exec, :bwrap, :none]
    end

    test "lets configuration turn the sandbox off ahead of the cache, without a restart" do
      Sandbox.detect()
      Application.put_env(:ouroboros, :native_sandbox, :none)
      on_exit(fn -> Application.delete_env(:ouroboros, :native_sandbox) end)

      detection = Sandbox.detect()
      assert detection.backend == :none
      assert detection.notes =~ "disabled by"
      assert Sandbox.label(detection) == "none"
    end

    test "names each backend the way a client shows it" do
      assert Sandbox.label(:sandbox_exec) == "sandbox-exec"
      assert Sandbox.label(:bwrap) == "bwrap"
      assert Sandbox.label(:none) == "none"
    end
  end

  describe "the tool call marker" do
    test "names the backend a bash call will actually run under, and marks no other tool", %{
      scope: scope
    } do
      assert Sandbox.tool_call_marker("bash", scope, @none) == %{"sandbox" => "none"}

      assert Sandbox.tool_call_marker("bash", scope, Sandbox.detect()) == %{
               "sandbox" => Sandbox.label(Sandbox.detect())
             }

      assert Sandbox.tool_call_marker("read", scope, Sandbox.detect()) == %{}
      assert Sandbox.tool_call_marker("write", scope, @none) == %{}
    end
  end

  describe "attributing a failure" do
    test "reads an EPERM line as a denial and names the constraint and the escalation" do
      policy = fixed_policy(:read_only)
      output = "/bin/sh: notes.txt: Operation not permitted\n"

      assert %{constraint: :filesystem, evidence: evidence} =
               violation = Sandbox.violation(policy, output, 1)

      assert evidence == "/bin/sh: notes.txt: Operation not permitted"

      escalation = Sandbox.escalation(violation, policy, "sandbox-exec")
      assert escalation =~ "sandbox_mode: read_only"
      assert escalation =~ "no writes at all outside $TMPDIR"
      assert escalation =~ "sandbox_mode: workspace_write"
      assert escalation =~ "ask_user"
      assert escalation =~ "Do not retry the same command"
    end

    test "reads a denied connection as the network constraint, not a filesystem one" do
      policy = fixed_policy(:workspace_write)
      output = "nc: connectx to 127.0.0.1 port 9 (tcp) failed: Operation not permitted\n"

      assert %{constraint: :network} = violation = Sandbox.violation(policy, output, 1)
      assert Sandbox.escalation(violation, policy, "sandbox-exec") =~ "denies all network access"
      assert Sandbox.escalation(violation, policy, "sandbox-exec") =~ "native_sandbox_network"
    end

    test "reads bubblewrap's own denials, which are EROFS and ENETUNREACH rather than EPERM" do
      policy = fixed_policy(:workspace_write)

      assert %{constraint: :filesystem} =
               Sandbox.violation(policy, "touch: /etc/x: Read-only file system\n", 1)

      assert %{constraint: :network} =
               Sandbox.violation(policy, "curl: (7) ... Network is unreachable\n", 1)
    end

    test "does not read a plain Permission denied as a sandbox denial: EACCES is a file mode" do
      policy = fixed_policy(:read_only)
      assert Sandbox.violation(policy, "cat: /etc/shadow: Permission denied\n", 1) == nil
    end

    test "says nothing about a command that succeeded" do
      assert Sandbox.violation(fixed_policy(:read_only), "Operation not permitted\n", 0) == nil
    end

    test "tells a backend that could not apply its policy apart from the command's own failure" do
      assert Sandbox.backend_failure(
               "sandbox-exec",
               "sandbox-exec: syntax error: expecting ')'\n",
               65
             ) == "sandbox-exec: syntax error: expecting ')'"

      assert Sandbox.backend_failure("sandbox-exec", "make: *** [all] Error 1\n", 2) == nil
      assert Sandbox.backend_failure("sandbox-exec", "sandbox-exec: whatever\n", 0) == nil
    end
  end

  describe "the protected set" do
    test "protects exactly the paths the permission rules already protect", %{scope: scope} do
      policy = Sandbox.policy(scope, :workspace_write)
      declared = Rules.protected_paths()

      for segment <- policy.protected_segments do
        assert "**/#{segment}/**" in declared
      end

      for root <- policy.protected do
        assert "#{root}/**" in declared
      end
    end
  end

  describe "bash on a node with no backend" do
    setup do
      Application.put_env(:ouroboros, :native_sandbox, :none)
      on_exit(fn -> Application.delete_env(:ouroboros, :native_sandbox) end)
      :ok
    end

    test "keeps the read_only refusal, and names what was missing", %{
      read_only_context: context
    } do
      result = run(Bash, %{"command" => "echo hi"}, context)

      assert result.is_error
      assert result.output =~ "read_only"
      assert result.output =~ "no OS sandbox backend"
      assert result.output =~ "disabled by"
      assert result.output =~ "sandbox_mode: workspace_write"
    end

    test "still runs a workspace_write command, unsandboxed, exactly as it did before C5", %{
      context: context,
      workspace: workspace
    } do
      result = run(Bash, %{"command" => "echo out > unsandboxed.txt && echo ok"}, context)

      refute result.is_error
      assert result.output =~ "ok"
      assert File.read!(Path.join(workspace, "unsandboxed.txt")) == "out\n"
    end
  end

  describe "the sandbox-exec backend, live on this node" do
    @describetag :sandbox_exec
    @describetag @needs_sandbox_exec

    test "runs a read_only command that used to be refused outright", %{
      read_only_context: context
    } do
      result = run(Bash, %{"command" => "echo hi && pwd"}, context)

      refute result.is_error
      assert result.output =~ "hi"
      assert result.output =~ context.scope.root
    end

    test "denies a write into the workspace under read_only and names the constraint", %{
      read_only_context: context,
      workspace: workspace
    } do
      result = run(Bash, %{"command" => "echo nope > denied.txt"}, context)

      assert result.is_error
      assert result.output =~ "Operation not permitted"
      assert result.output =~ "sandbox-exec, sandbox_mode: read_only"
      assert result.output =~ "no writes at all outside $TMPDIR"
      assert result.output =~ "sandbox_mode: workspace_write"
      refute File.exists?(Path.join(workspace, "denied.txt"))
    end

    test "writes inside the workspace under workspace_write", %{
      context: context,
      workspace: workspace
    } do
      result = run(Bash, %{"command" => "echo inside > inside.txt"}, context)

      refute result.is_error
      assert File.read!(Path.join(workspace, "inside.txt")) == "inside\n"
    end

    test "denies a write to the home directory under workspace_write" do
      escape =
        Path.join(System.user_home!(), "ouroboros-escape-#{System.unique_integer([:positive])}")

      on_exit(fn -> File.rm(escape) end)

      root = Path.join(System.tmp_dir!(), "native-escape-#{System.unique_integer([:positive])}")
      File.mkdir_p!(root)
      on_exit(fn -> File.rm_rf(root) end)
      {:ok, scope} = Paths.scope(root, [], :workspace_write)

      result =
        run(
          Bash,
          %{"command" => "echo escaped > #{escape}"},
          %{scope: scope, session_dir: root, reads: %{}}
        )

      assert result.is_error
      assert result.output =~ "Operation not permitted"
      assert result.output =~ "add the directory this needs to the session's `add_dirs`"
      refute File.exists?(escape)
    end

    test "denies a write into .git, which is why a commit needs a human", %{
      context: context,
      workspace: workspace
    } do
      result = run(Bash, %{"command" => "echo tampered > .git/HEAD"}, context)

      assert result.is_error
      assert result.output =~ "Operation not permitted"
      assert result.output =~ "never into a `.git` or `.ouroboros` directory"
      refute File.exists?(Path.join(workspace, ".git/HEAD"))
    end

    test "stops a real git commit, because a commit writes into .git", %{root: root} do
      repo = Path.join(root, "repo")
      File.mkdir_p!(repo)
      File.write!(Path.join(repo, "README.md"), "one\n")
      git = fn args -> System.cmd("git", args, cd: repo, stderr_to_stdout: true) end
      git.(["init", "-q"])
      git.(["-c", "user.email=a@b", "-c", "user.name=a", "add", "-A"])
      git.(["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "base"])

      {:ok, scope} = Paths.scope(repo, [], :workspace_write)

      result =
        run(
          Bash,
          %{
            "command" =>
              "echo two >> README.md && " <>
                "git -c user.email=a@b -c user.name=a commit -qam second"
          },
          %{scope: scope, session_dir: root, reads: %{}}
        )

      assert result.is_error
      assert result.output =~ "index.lock"
      assert result.output =~ "Operation not permitted"
      assert result.output =~ "never into a `.git` or `.ouroboros` directory"

      # The workspace edit landed; the history did not.
      assert File.read!(Path.join(repo, "README.md")) == "one\ntwo\n"
      {log, 0} = git.(["log", "--oneline"])
      assert String.trim(log) |> String.split("\n") |> length() == 1
    end

    test "denies a connection by policy, which reads differently from a port refusing it", %{
      context: context
    } do
      sandboxed = run(Bash, %{"command" => "nc -vz 127.0.0.1 9 2>&1"}, context)

      assert sandboxed.is_error
      # EPERM from Seatbelt, not ECONNREFUSED from a closed port: the port is closed
      # either way, so the text is the only thing that says which one stopped it.
      assert sandboxed.output =~ "Operation not permitted"
      refute sandboxed.output =~ "Connection refused"
      assert sandboxed.output =~ "denies all network access"

      {plain, 1} = System.cmd("/usr/bin/nc", ["-vz", "127.0.0.1", "9"], stderr_to_stdout: true)
      assert plain =~ "Connection refused"
      refute plain =~ "Operation not permitted"
    end

    test "gives the command a writable $TMPDIR in both modes, so a build with a temp file runs",
         %{context: context, read_only_context: read_only_context} do
      for one <- [context, read_only_context] do
        result =
          run(
            Bash,
            %{"command" => ~s|f=$(mktemp "$TMPDIR/x.XXXXXX") && echo scratch > "$f" && cat "$f"|},
            one
          )

        refute result.is_error
        assert result.output =~ "scratch"
      end
    end

    test "does not reach the Darwin per-user temp directory that a bare mktemp still uses", %{
      context: context
    } do
      # A real limit, found by running it: macOS `mktemp` with no template asks libc for
      # `_CS_DARWIN_USER_TEMP_DIR` rather than reading `$TMPDIR`, so it lands outside the
      # scratch directory and is denied. A tool that reads the variable is fine; one that
      # asks the OS is not. Stated here, and in the README, rather than discovered later.
      result = run(Bash, %{"command" => "mktemp"}, context)

      assert result.is_error
      assert result.output =~ "Operation not permitted"
    end

    test "leaves no scratch directory behind once the command has ended", %{context: context} do
      result = run(Bash, %{"command" => "echo $TMPDIR"}, context)

      refute result.is_error
      scratch = result.output |> String.trim() |> String.split("\n") |> List.last()
      assert scratch =~ "ouroboros-sandbox-"
      refute File.exists?(scratch)
    end
  end
end
