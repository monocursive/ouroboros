defmodule Ouroboros.Provider.Native.SandboxTest do
  # Not async: the `:none` backend cases put `:ouroboros, :native_sandbox` on the
  # application environment, which every other native session on this node reads.
  use ExUnit.Case, async: false

  alias Ouroboros.Control.Permissions.Rules
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.Helper
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

  # Same honesty for bubblewrap: installing the binary is not sufficient. Detection runs
  # a representative filesystem probe (and a separate network-namespace probe), so a Linux
  # host whose container policy blocks mounts skips these live tests with the detected
  # backend printed instead of failing every unrelated command before it starts.
  @needs_bwrap (case @backend do
                  :bwrap ->
                    []

                  other ->
                    [
                      skip:
                        "no bwrap on this node (detected backend: #{inspect(other)}); " <>
                          "the live bubblewrap tests need Linux"
                    ]
                end)

  @none %{
    backend: :none,
    executable: nil,
    version: nil,
    notes: "no OS sandbox on this node: none of ouro-sandbox, sandbox-exec, or bwrap is available"
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

  # `/bin` is a symlink to `usr/bin` on Debian-family Linux, and `builder_policy/1`
  # canonicalises every root it names (a root that is a link is the thing it points at, to
  # Landlock and to Seatbelt alike). So the assertion is that each platform root is covered,
  # in whichever spelling names that directory.
  defp canonical_root(path) do
    case Ouroboros.Workspace.Path.canonicalize(path) do
      {:ok, canonical} -> canonical
      {:error, _absent} -> path
    end
  end

  # The same, for a *file*: `canonicalize/1` insists on a directory, so a credential's path
  # is resolved through its parent — which is also what `Sandbox.hidden_files/0` does, and
  # for the same reason (the file may not exist yet).
  # Exactly what `Ouroboros.Provider.Native.Tools.Bash.plan/2` does with a wrapped command,
  # which is what the reviewers' exploits reproduced: the policy, the argv, `System.cmd`.
  defp sandboxed(scope, policy, detection, command) do
    {:ok, {executable, args}} = Sandbox.wrap({:shell, command}, scope, policy, detection)

    {output, status} =
      System.cmd(executable, args, env: Sandbox.env(policy), stderr_to_stdout: true)

    {String.trim(output), status}
  end

  defp canonical_file(path),
    do: path |> Path.dirname() |> canonical_root() |> Path.join(Path.basename(path))

  defp run(module, input, context, timeout \\ 30_000),
    do: Ouroboros.Provider.Native.Tools.execute(module, input, context, timeout)

  # Whether `needle` appears in `list` as consecutive elements — which is what an argv
  # assertion about a bind actually means: the three words together, in that order.
  defp subsequence_of?(needle, list) do
    length = length(needle)

    list
    |> Enum.chunk_every(length, 1, :discard)
    |> Enum.any?(&(&1 == needle))
  end

  defp index_of(list, value), do: Enum.find_index(list, &(&1 == value))

  defp restore_app_env(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_app_env(key, value), do: Application.put_env(:ouroboros, key, value)

  defp restore_sys_env(name, nil), do: System.delete_env(name)
  defp restore_sys_env(name, value), do: System.put_env(name, value)

  defp env_value(["--setenv", key, value | _rest], key), do: value
  defp env_value([_head | rest], key), do: env_value(rest, key)
  defp env_value([], _key), do: nil

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
             (allow network-bind (local ip "localhost:*"))
             (allow network-inbound (local ip "localhost:*"))
             (allow network-outbound (remote ip "localhost:*"))
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
             (allow network-bind (local ip "localhost:*"))
             (allow network-inbound (local ip "localhost:*"))
             (allow network-outbound (remote ip "localhost:*"))
             """
    end

    test "denies external network while retaining loopback unless policy opens everything" do
      denied = SandboxExec.profile(fixed_policy(:workspace_write))
      assert denied =~ "(deny network*)"
      assert denied =~ "(allow network-bind (local ip \"localhost:*\"))"
      assert denied =~ "(allow network-inbound (local ip \"localhost:*\"))"
      assert denied =~ "(allow network-outbound (remote ip \"localhost:*\"))"

      assert SandboxExec.profile(fixed_policy(:workspace_write, true)) =~ "(allow network*)"
      refute SandboxExec.profile(fixed_policy(:workspace_write, true)) =~ "(deny network*)"
      refute SandboxExec.profile(fixed_policy(:workspace_write, true)) =~ "localhost:*"
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

    test "allows a worktree inside the protected data directory again after the denies" do
      policy = %{
        fixed_policy(:workspace_write)
        | writable: ["/scratch", "/srv/ouroboros/data/worktrees/repo/s1"],
          protected: ["/srv/ouroboros/data", "/home/agent/.config/ouroboros"]
      }

      lines = String.split(SandboxExec.profile(policy), "\n")
      deny = "(deny file-write* (subpath (param \"OURO_PROTECTED_0\")))"
      reallow = "(allow file-write* (subpath (param \"OURO_WRITABLE_1\")))"
      git = "(deny file-write* (regex #\"/\\.git($|/)\"))"

      indexes = fn line -> for {l, i} <- Enum.with_index(lines), l == line, do: i end
      [deny_at] = indexes.(deny)
      [_first_allow, reallow_at] = indexes.(reallow)
      [git_at] = indexes.(git)
      # Last match wins: the worktree is allowed again after the data directory is denied,
      # and its `.git` is denied after that. The scratch root, outside every protected
      # root, is allowed once and never repeated.
      assert deny_at < reallow_at and reallow_at < git_at
      assert [_once] = indexes.("(allow file-write* (subpath (param \"OURO_WRITABLE_0\")))")
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

    test "binds a protected root read-only before a worktree inside it is bound writable", %{
      root: root
    } do
      data = Path.join(root, "data")
      worktree = Path.join(data, "worktrees/s1")
      File.mkdir_p!(worktree)
      scratch = Path.join(root, "scratch")

      policy = %{
        fixed_policy(:workspace_write)
        | writable: [scratch, worktree],
          protected: [data],
          scratch: scratch
      }

      options = Bwrap.options(%{root: worktree}, policy)
      triples = Enum.chunk_every(options, 3, 1)
      ro = Enum.find_index(triples, &(&1 == ["--ro-bind", data, data]))
      bind = Enum.find_index(triples, &(&1 == ["--bind", worktree, worktree]))
      assert is_integer(ro) and is_integer(bind)
      # The later bind overlays the earlier read-only one: the worktree is writable, the
      # rest of the data directory is not.
      assert ro < bind
    end

    test "re-binds existing and absent protected segments read-only over writable roots", %{
      root: root,
      workspace: workspace
    } do
      scratch = Path.join(root, "scratch")
      # A vendored dependency's `.git` is as much a repository as the workspace's own, and
      # bubblewrap has no path regex to cover both: it needs a bind per directory.
      nested = Path.join(workspace, "deps/foo/.git")
      File.mkdir_p!(nested)

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
               "--ro-bind",
               scratch,
               Path.join(workspace, ".ouroboros"),
               "--ro-bind",
               nested,
               nested,
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

    test "injects the name-based create filter when the library is on disk" do
      path = Application.app_dir(:ouroboros, "priv/native/libouro_fs_filter.so")

      assert {:ok, {"/usr/bin/bwrap", args}} =
               Bwrap.wrap(
                 {:shell, "echo hi"},
                 %{root: "/ws"},
                 fixed_policy(:workspace_write),
                 "/usr/bin/bwrap"
               )

      assert Enum.take(args, -4) == ["--", "/bin/sh", "-c", "echo hi"]

      if File.regular?(path) do
        assert env_value(args, "LD_PRELOAD") == path
        assert env_value(args, "OUROBOROS_FS_DENY") == ".git:.ouroboros"
      else
        refute "LD_PRELOAD" in args
      end
    end
  end

  # The helper's argv is one flag and a JSON document, so what is pinned here is the
  # *decoded* request rather than a byte string: a map comparison is exactly as strict and
  # does not make the suite depend on the key order a JSON encoder happens to emit.
  describe "the ouro-sandbox request" do
    test "carries the same policy the bubblewrap argv expresses" do
      request = Helper.request(fixed_policy(:workspace_write), %{root: "/ws"})

      assert request["version"] == 1
      assert request["mode"] == "workspace_write"
      assert request["cwd"] == "/ws"
      assert request["scratch"] == "/scratch"
      # Scratch is mounted by the helper itself and must not appear twice.
      assert request["writable"] == ["/ws", "/ws-extra"]
      assert request["protected"] == ["/srv/ouroboros/data", "/home/agent/.config/ouroboros"]
      assert request["denied_names"] == [".git", ".ouroboros"]
      assert request["network"] == false
    end

    test "a read_only policy grants no writable root at all" do
      request = Helper.request(fixed_policy(:read_only), %{root: "/ws"})

      assert request["mode"] == "read_only"
      assert request["writable"] == []
      assert request["scratch"] == "/scratch"
    end

    test "an escalated policy carries only the fence the operator did not lift" do
      policy = %{fixed_policy(:workspace_write) | mode: :workspace_write_escalated}
      policy = %{policy | protected_segments: [".ouroboros"]}

      request = Helper.request(policy, %{root: "/ws"})

      assert request["mode"] == "workspace_write_escalated"
      assert request["denied_names"] == [".ouroboros"]
    end

    test "the network posture is the policy's, and nothing else moves with it" do
      denied = Helper.request(fixed_policy(:workspace_write, false), %{root: "/ws"})
      allowed = Helper.request(fixed_policy(:workspace_write, true), %{root: "/ws"})

      assert denied["network"] == false
      assert allowed["network"] == true
      assert Map.delete(denied, "network") == Map.delete(allowed, "network")
    end

    test "a session with no root sends no cwd rather than an empty one" do
      refute Map.has_key?(Helper.request(fixed_policy(:read_only), %{}), "cwd")
    end

    test "wraps a shell line as exec --request <json> -- /bin/sh -c" do
      assert {:ok, {"/opt/ouro-sandbox", args}} =
               Helper.wrap(
                 {:shell, "echo hi"},
                 %{root: "/ws"},
                 fixed_policy(:workspace_write),
                 "/opt/ouro-sandbox"
               )

      assert ["exec", "--request", encoded | rest] = args
      assert rest == ["--", "/bin/sh", "-c", "echo hi"]
      assert {:ok, decoded} = JSON.decode(encoded)
      assert decoded == Helper.request(fixed_policy(:workspace_write), %{root: "/ws"})
    end

    test "wraps an explicit argv without a shell in front of it" do
      assert {:ok, {_executable, args}} =
               Helper.wrap(
                 {:argv, ["git", "status"]},
                 %{root: "/ws"},
                 fixed_policy(:read_only),
                 "/opt/ouro-sandbox"
               )

      assert Enum.take(args, -3) == ["--", "git", "status"]
    end

    test "refuses a command it cannot interpret rather than guessing" do
      assert {:error, {:uninterpretable_command, :nonsense}} =
               Helper.wrap(
                 :nonsense,
                 %{root: "/ws"},
                 fixed_policy(:read_only),
                 "/opt/ouro-sandbox"
               )
    end

    test "a shell request is exactly these keys and no others" do
      # L5, and the reason it is a whole-map comparison rather than a field-by-field one:
      # W17 added a key to this request and the pinned tests all still passed, because every
      # one of them asserted on the keys it knew about. A future field that leaks into a
      # shell policy has to redden something, and this is the something.
      expected = %{
        "version" => 1,
        "mode" => "workspace_write",
        "cwd" => "/ws",
        "scratch" => "/scratch",
        "writable" => ["/ws", "/ws-extra"],
        "protected" => ["/srv/ouroboros/data", "/home/agent/.config/ouroboros"],
        "denied_names" => [".git", ".ouroboros"],
        "network" => false
      }

      # The one conditional key: present exactly when this build has the `.so` on disk.
      library = Application.app_dir(:ouroboros, "priv/native/libouro_fs_filter.so")

      expected =
        if File.regular?(library),
          do: Map.put(expected, "fs_filter_library", library),
          else: expected

      assert Helper.request(fixed_policy(:workspace_write), %{root: "/ws"}) == expected
    end

    test "a builder policy carries its read allow-set, and no other mode carries one" do
      # C10 on the wire. Red without `Helper.request/2`'s `readable` clause: a builder
      # request with no allow-set is one the helper fences to its writable roots alone, so
      # the omission would not be a wider build — it would be a build that cannot read its
      # own toolchain, which is a failure nobody would read as a policy bug.
      policy =
        Sandbox.builder_policy(writable: ["/build"], readable: ["/toolchain"])
        |> Sandbox.with_scratch("/scratch")

      request = Helper.request(policy, %{root: "/build"})

      assert request["mode"] == "builder"
      assert request["writable"] == ["/build"]
      assert "/toolchain" in request["readable"]
      # Every platform root the builder policy starts from travels too.
      for root <- Sandbox.platform_readable(),
          do: assert(canonical_root(root) in request["readable"])

      # A builder has no name fence and no protected roots: the read allow-set is the
      # fence, and the helper refuses a builder request that carries `denied_names`.
      assert request["denied_names"] == []
      assert request["network"] == false

      # And no preload library. It rode along on every builder request until a review
      # noticed the helper was silently discarding it while §14 said it was refused; the
      # helper refuses the field under `builder` now, so sending it would be a backend
      # failure rather than a courtesy. Red without `filter_library/1`'s builder clause.
      refute Map.has_key?(request, "fs_filter_library")

      # And the field belongs to that mode alone. A shell's read set is `/`, so a
      # `readable` in one of these would be a fence the helper refuses outright.
      for mode <- [:read_only, :workspace_write, :workspace_write_escalated] do
        refute Map.has_key?(Helper.request(fixed_policy(mode), %{root: "/ws"}), "readable"),
               "mode #{mode} must not carry a read allow-set"
      end
    end

    test "carries the fs_filter library when this build has one, because Landlock cannot" do
      # The documented gap: denying the *creation* of a `.git` that does not exist yet is
      # not expressible in Landlock, so the helper is handed the same LD_PRELOAD shim the
      # bubblewrap backend uses. When no `.so` was built the key is absent, not empty —
      # an empty LD_PRELOAD would make every exec inside the sandbox fail.
      path = Application.app_dir(:ouroboros, "priv/native/libouro_fs_filter.so")
      request = Helper.request(fixed_policy(:workspace_write), %{root: "/ws"})

      if File.regular?(path) do
        assert request["fs_filter_library"] == path
      else
        refute Map.has_key?(request, "fs_filter_library")
      end
    end
  end

  describe "detecting the ouro-sandbox helper" do
    test "an override pointing at nothing is not a helper" do
      # Restored, not deleted: the variable is how a host that has an `ouro-sandbox` on disk
      # says "not this one" (the bubblewrap proof in a container sets it), and a test that
      # deleted it handed every later detection in the run the helper it had been told to
      # ignore.
      previous = System.get_env("OUROBOROS_SANDBOX_HELPER")
      System.put_env("OUROBOROS_SANDBOX_HELPER", Path.join(System.tmp_dir!(), "absent-helper"))

      on_exit(fn ->
        case previous do
          nil -> System.delete_env("OUROBOROS_SANDBOX_HELPER")
          value -> System.put_env("OUROBOROS_SANDBOX_HELPER", value)
        end
      end)

      assert Helper.executable() == nil
    end

    test "a binary that cannot answer `doctor` is not selected", %{root: root} do
      # The detection contract: `probe/1` returns nil for anything that is not a working
      # helper, so `probe_linux` falls through to bubblewrap instead of choosing a backend
      # that would refuse every command.
      fake = Path.join(root, "not-a-helper")
      File.write!(fake, "#!/bin/sh\nexit 1\n")
      File.chmod!(fake, 0o755)

      assert Helper.probe(fake) == nil
    end

    test "a helper reporting itself unusable is not selected", %{root: root} do
      # Exactly what a kernel older than 5.13 produces: the binary runs, answers, and says
      # it cannot enforce.
      fake = Path.join(root, "unusable-helper")
      File.write!(fake, ~s(#!/bin/sh\necho '{"usable":false,"notes":"no landlock"}'\n))
      File.chmod!(fake, 0o755)

      assert Helper.probe(fake) == nil
    end

    test "a helper reporting itself usable is selected, with its version", %{root: root} do
      fake = Path.join(root, "usable-helper")

      File.write!(
        fake,
        ~s(#!/bin/sh\necho '{"usable":true,"version":"0.1.0","notes":"ok","landlock":{"abi":8}}'\n)
      )

      File.chmod!(fake, 0o755)

      assert %{version: "0.1.0 (landlock abi 8)", notes: "ok"} = Helper.probe(fake)
    end

    test "a readable root that is a symlink is the thing it points at, by name", %{root: root} do
      # L4. Landlock opens a rule's path with `O_PATH` and Seatbelt's `subpath` resolves the
      # same way, so a policy naming a link grants its target under a name that does not say
      # so — a `readable` of `/opt/toolchain` that happens to point at `/home/me/secrets`
      # would have been a fence with the secret inside it. Red without `canonical_root/1`.
      # Built under the *canonical* temp root, because `Workspace.Path.canonicalize/1` has a
      # defect of its own on this platform (see the report): its symlink-cycle guard is one
      # set for the whole resolution, so an absolute link target that re-traverses macOS's
      # `/var` link is reported as a cycle. That is why the helper refuses a symlinked
      # `readable` as well — this half is the daemon naming what it grants, and it is not
      # the only half.
      {:ok, base} = Ouroboros.Workspace.Path.canonicalize(root)
      target = Path.join(base, "real-toolchain")
      link = Path.join(base, "toolchain-link")
      File.mkdir_p!(target)
      File.ln_s!(target, link)

      policy = Sandbox.builder_policy(writable: [], readable: [link])

      # The policy names both: the target under its own name, and the link because bubblewrap
      # binds by name and a namespace with no `/bin` in it runs no `#!/bin/sh` (the hosted CI
      # job found exactly that on a merged-`/usr` Ubuntu). What reaches *this* helper is the
      # target alone — it refuses a symlinked root by design, and Landlock's rule attaches to
      # the inode the target already names.
      assert target in policy.readable
      assert link in policy.readable

      request = Helper.request(Sandbox.with_scratch(policy, Path.join(base, "scratch")), %{})
      assert target in request["readable"]
      refute link in request["readable"]

      # A root that does not exist yet cannot be canonicalised and is carried through
      # unchanged, because dropping it would narrow the policy without saying so — and the
      # helper is what refuses it, out loud, if it turns out to be a link.
      absent = Path.join(base, "not-created-yet")
      assert absent in Sandbox.builder_policy(writable: [], readable: [absent]).readable
    end

    test "the read fence is claimed by the helper's own report, never by its name", %{root: root} do
      # C11. Delete the `read_fence:` key from `probe/1` and the second half goes red; make
      # it a constant `true` and the first half does. A helper installed before the read
      # allow-set existed reports no feature, and a node that inferred the fence from the
      # backend's name would run a build under one it does not have.
      stale = Path.join(root, "stale-helper")
      File.write!(stale, ~s(#!/bin/sh\necho '{"usable":true,"version":"0.1.0","notes":"ok"}'\n))
      File.chmod!(stale, 0o755)

      assert %{read_fence: false} = Helper.probe(stale)

      current = Path.join(root, "current-helper")

      File.write!(
        current,
        ~s(#!/bin/sh\necho '{"usable":true,"version":"0.1.0","notes":"ok","features":{"read_allow_set":true}}'\n)
      )

      File.chmod!(current, 0o755)

      assert %{read_fence: true} = Helper.probe(current)

      # A `features` that is not an object is a helper that claims nothing, not an
      # exception on the detection path every `bash` call crosses.
      odd = Path.join(root, "odd-helper")

      File.write!(
        odd,
        ~s(#!/bin/sh\necho '{"usable":true,"version":"0.1.0","notes":"ok","features":"yes"}'\n)
      )

      File.chmod!(odd, 0o755)

      assert %{read_fence: false} = Helper.probe(odd)
    end
  end

  describe "detecting bubblewrap" do
    test "rejects a binary whose version works but whose filesystem namespace is forbidden", %{
      root: root
    } do
      fake = Path.join(root, "blocked-bwrap")

      File.write!(
        fake,
        """
        #!/bin/sh
        if [ "${1:-}" = "--version" ]; then
          echo 'bubblewrap 0.test'
          exit 0
        fi
        echo 'bwrap: Can't mount tmpfs on /newroot: Operation not permitted' >&2
        exit 1
        """
      )

      File.chmod!(fake, 0o755)

      assert Bwrap.probe(fake) == {:error, :filesystem_namespace_refused}
    end

    test "keeps the backend when only the network namespace is forbidden", %{root: root} do
      fake = Path.join(root, "fs-only-bwrap")

      File.write!(
        fake,
        """
        #!/bin/sh
        if [ "${1:-}" = "--version" ]; then
          echo 'bubblewrap 0.test'
          exit 0
        fi
        for arg in "$@"; do
          if [ "$arg" = "--unshare-net" ]; then
            echo 'bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted' >&2
            exit 1
          fi
        done
        exit 0
        """
      )

      File.chmod!(fake, 0o755)

      assert {:ok, %{version: "bubblewrap 0.test", unshare_net: false, notes: notes}} =
               Bwrap.probe(fake)

      assert notes =~ "filesystem capability probe passed"
      assert notes =~ "network namespace unavailable"
      refute "--unshare-net" in Bwrap.options(%{root: "/ws"}, fixed_policy(:read_only), false)
    end

    test "selects a binary only after the representative filesystem command succeeds", %{
      root: root
    } do
      fake = Path.join(root, "working-bwrap")

      File.write!(
        fake,
        """
        #!/bin/sh
        if [ "${1:-}" = "--version" ]; then
          echo 'bubblewrap 0.test'
        fi
        exit 0
        """
      )

      File.chmod!(fake, 0o755)

      assert {:ok, %{version: "bubblewrap 0.test", unshare_net: true, notes: notes}} =
               Bwrap.probe(fake)

      assert notes =~ "capability probes passed"
    end
  end

  describe "the decision" do
    # An operator who exported OUROBOROS_ALLOW_UNSANDBOXED_BASH=1 in the environment
    # that launched mix test would otherwise turn the fail-closed assertions green in
    # the wrong direction. These cases observe the default: both gates shut.
    setup do
      previous_app = Application.get_env(:ouroboros, :allow_unsandboxed_bash)
      previous_env = System.get_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH")
      Application.put_env(:ouroboros, :allow_unsandboxed_bash, false)
      System.delete_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH")

      on_exit(fn ->
        restore_app_env(:allow_unsandboxed_bash, previous_app)
        restore_sys_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH", previous_env)
      end)

      :ok
    end

    test "refuses a read_only shell on a node with no backend, rather than weakening it", %{
      read_only: read_only
    } do
      assert {:refused, {:read_only_without_backend, _detection}} =
               Sandbox.decide(read_only, @none)
    end

    test "refuses a workspace_write shell on a node with no backend, rather than weakening it", %{
      scope: scope
    } do
      assert {:refused, {:workspace_write_without_backend, detection}} =
               Sandbox.decide(scope, @none)

      assert detection.backend == :none

      message = Sandbox.workspace_write_without_backend_refusal(detection)
      assert message =~ "OUROBOROS_ALLOW_UNSANDBOXED_BASH=1"
      assert message =~ "ouro-sandbox"
      assert message =~ "sandbox-exec"
      assert message =~ "bwrap"
    end

    test "runs a workspace_write shell unsandboxed when the operator opts in", %{scope: scope} do
      Application.put_env(:ouroboros, :allow_unsandboxed_bash, true)
      System.delete_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH")

      assert {:unsandboxed, {:no_backend, _detection}} = Sandbox.decide(scope, @none)

      Application.put_env(:ouroboros, :allow_unsandboxed_bash, false)
      System.put_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH", "1")

      assert {:unsandboxed, {:no_backend, _detection}} = Sandbox.decide(scope, @none)
    end

    test "the unsandboxed opt-in does not lift a read_only session without a backend", %{
      read_only: read_only
    } do
      Application.put_env(:ouroboros, :allow_unsandboxed_bash, true)
      System.put_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH", "1")

      assert {:refused, {:read_only_without_backend, _detection}} =
               Sandbox.decide(read_only, @none)
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

        assert {:refused, {:workspace_write_without_backend, _}} =
                 Sandbox.decide(scope, @none)
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

    # The mode the provider now offers by name. It answers the same on every backend,
    # which is the whole claim: "no OS sandbox" is not a property of the node here, it is
    # what the session asked for.
    test "answers :unrestricted the same whatever this node can sandbox with", %{
      workspace: workspace
    } do
      {:ok, scope} = Paths.scope(workspace, [], :unrestricted)

      for detection <- [@none, Sandbox.detect()] do
        assert Sandbox.decision(scope, detection) == {:unsandboxed, :unrestricted}
      end
    end

    test "an approved escalation stays sandboxed and only lifts the .git segment", %{
      workspace: workspace
    } do
      {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
      escalated = Sandbox.escalated_scope(scope)

      assert {:refused, {:escalation_without_backend, _}} = Sandbox.decision(escalated, @none)

      case Sandbox.detect() do
        %{backend: :none} ->
          :ok

        detection ->
          assert {:sandboxed, _label, policy} = Sandbox.decision(escalated, detection)
          assert policy.mode == :workspace_write_escalated
          assert ".ouroboros" in policy.protected_segments
          refute ".git" in policy.protected_segments
          assert policy.protected == Sandbox.protected_roots()
      end
    end

    # `writable/2` has clauses for sandboxed modes only. `decision/2` answers
    # `:unrestricted` before any policy is built — pinned here so a future edit that
    # reordered those two cannot land quietly.
    test "never builds a policy for :unrestricted, so `writable/2` never sees it", %{
      workspace: workspace
    } do
      {:ok, scope} = Paths.scope(workspace, [], :unrestricted)

      refute match?({:sandboxed, _label, _policy}, Sandbox.decision(scope, Sandbox.detect()))

      # Through `apply/3` on purpose: the call is deliberately outside `policy/2`'s
      # declared domain, and going through the compiler's type checker to say so would
      # only produce a warning about a call this test exists to make.
      assert_raise FunctionClauseError, fn -> apply(Sandbox, :policy, [scope, :unrestricted]) end
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
      assert first.backend in [:sandbox_exec, :ouro_sandbox, :bwrap, :none]
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

    test "sweeps a scratch directory a killed tool task could not remove, and spares a live one" do
      abandoned = Path.join(System.tmp_dir!(), "ouroboros-sandbox-abandoned-probe")
      File.mkdir_p!(abandoned)
      on_exit(fn -> File.rm_rf(abandoned) end)
      # Seven hours old: past the six-hour cutoff, which no live command can reach.
      old = System.os_time(:second) - 7 * 60 * 60
      File.touch!(abandoned, old)

      {:ok, live} = Sandbox.scratch()

      assert File.exists?(live)
      refute File.exists?(abandoned)

      Sandbox.sweep()
      assert File.exists?(live)

      Sandbox.release(live)
      refute File.exists?(live)
    end

    test "names each backend the way a client shows it" do
      assert Sandbox.label(:sandbox_exec) == "sandbox-exec"
      assert Sandbox.label(:ouro_sandbox) == "ouro-sandbox"
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

    # The one line a client footer reads to say "no OS sandbox" for a native session. An
    # unrestricted session must say `none` on a node that *has* a backend, because the
    # session declined it — a marker that named the backend there would be a lie by
    # omission.
    test "says none for an unrestricted session even where this node has a backend", %{
      workspace: workspace
    } do
      {:ok, scope} = Paths.scope(workspace, [], :unrestricted)

      assert Sandbox.tool_call_marker("bash", scope, Sandbox.detect()) == %{"sandbox" => "none"}
      assert Sandbox.tool_call_marker("bash", scope, @none) == %{"sandbox" => "none"}
    end
  end

  describe "which denials an operator may lift" do
    test "offers a filesystem denial under workspace_write" do
      policy = fixed_policy(:workspace_write)
      violation = Sandbox.violation(policy, "/bin/sh: x: Operation not permitted\n", 1)

      assert Sandbox.escalatable?(violation, policy, "git commit -am wip")
    end

    test "never offers a network denial: that is a node setting, not one command's answer" do
      policy = fixed_policy(:workspace_write)
      violation = Sandbox.violation(policy, "nc: connectx: Operation not permitted\n", 1)

      assert violation.constraint == :network
      refute Sandbox.escalatable?(violation, policy, "nc example.com 9")
    end

    test "never offers one under read_only: a label a shell can step out of is not a label" do
      policy = fixed_policy(:read_only)
      violation = Sandbox.violation(policy, "/bin/sh: x: Operation not permitted\n", 1)

      refute Sandbox.escalatable?(violation, policy, "touch x")
    end

    test "never offers one that names a protected root or an .ouroboros directory" do
      policy = fixed_policy(:workspace_write)
      violation = Sandbox.violation(policy, "/bin/sh: x: Operation not permitted\n", 1)

      for root <- Sandbox.protected_roots() do
        refute Sandbox.escalatable?(violation, policy, "rm -rf #{root}/store")
      end

      refute Sandbox.escalatable?(violation, policy, "rm -rf .ouroboros/state")
      refute Sandbox.escalatable?(violation, policy, "rm -rf /tmp/ws/.ouroboros/state")

      denial = %{constraint: :filesystem, evidence: "rm: .ouroboros/x: Operation not permitted"}
      refute Sandbox.escalatable?(denial, policy, nil)
    end

    test "does offer a `.git` write, because a commit is the case this exists for" do
      policy = fixed_policy(:workspace_write)

      violation = %{
        constraint: :filesystem,
        evidence: "error: cannot lock ref: .git/index.lock: Operation not permitted"
      }

      assert Sandbox.escalatable?(violation, policy, "git commit -am wip")
    end

    # The bug this pins: on macOS a data directory an operator configures as
    # `/var/folders/…` canonicalizes to `/private/var/folders/…`, and a command names
    # whichever one the person typed. Matching only the canonical form offered an
    # escalation straight into the runtime's own store.
    test "matches a protected root in the form it was configured, not only canonicalized" do
      raw =
        Path.join(System.tmp_dir!(), "ouroboros-protected-#{System.unique_integer([:positive])}")

      File.mkdir_p!(raw)
      on_exit(fn -> File.rm_rf(raw) end)

      previous = Application.get_env(:ouroboros, :native_data_dir)
      Application.put_env(:ouroboros, :native_data_dir, raw)

      on_exit(fn ->
        case previous do
          nil -> Application.delete_env(:ouroboros, :native_data_dir)
          value -> Application.put_env(:ouroboros, :native_data_dir, value)
        end
      end)

      names = Sandbox.protected_names()
      assert raw in names
      assert Enum.all?(Sandbox.protected_roots(), &(&1 in names))

      policy = fixed_policy(:workspace_write)
      violation = Sandbox.violation(policy, "/bin/sh: x: Operation not permitted\n", 1)

      refute Sandbox.escalatable?(violation, policy, "echo x > #{raw}/ledger.db")

      for canonical <- Sandbox.protected_roots() do
        refute Sandbox.escalatable?(violation, policy, "echo x > #{canonical}/ledger.db")
      end
    end

    test "says nothing at all when there was no violation" do
      refute Sandbox.escalatable?(nil, fixed_policy(:workspace_write), "true")
      refute Sandbox.escalatable?(%{constraint: :filesystem}, nil, "true")
    end

    test "the reason an approval carries names what was stopped and which constraint" do
      policy = fixed_policy(:workspace_write)
      violation = Sandbox.violation(policy, "/bin/sh: x: Operation not permitted\n", 1)
      reason = Sandbox.escalation_reason(violation, policy, "sandbox-exec")

      assert reason =~ "sandbox-exec sandbox (sandbox_mode: workspace_write) stopped"
      assert reason =~ "Operation not permitted"
      assert reason =~ "allows writes only under"
      refute reason =~ "ask_user"
    end

    test "the guidance changes when an escalation is actually on offer" do
      policy = fixed_policy(:workspace_write)
      violation = Sandbox.violation(policy, "/bin/sh: x: Operation not permitted\n", 1)

      plain = Sandbox.escalation(violation, policy, "sandbox-exec")
      offered = Sandbox.escalation(violation, policy, "sandbox-exec", offered: true)

      assert plain =~ "ask_user"
      assert offered =~ "re-runs the command once inside a fenced profile"
      assert offered =~ "no escalation was granted"
      assert offered =~ "still protects runtime data"

      # The sentence C5 shipped is now false, and is gone from both.
      refute plain =~ "does not offer a full-access mode"
      refute offered =~ "does not offer a full-access mode"
      refute plain =~ "sandbox_mode: unrestricted"
      refute offered =~ "sandbox_mode: unrestricted"
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

    test "reads a denied external connection as the network constraint, not a filesystem one" do
      policy = fixed_policy(:workspace_write)
      output = "nc: connectx to 192.0.2.1 port 9 (tcp) failed: Operation not permitted\n"

      assert %{constraint: :network} = violation = Sandbox.violation(policy, output, 1)

      assert Sandbox.escalation(violation, policy, "sandbox-exec") =~
               "denies external network access"

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

    # The reason the helper's Landlock layer is kept congruent with its mount layer rather
    # than made stricter: a Landlock denial is EACCES, which the clause above correctly
    # refuses to treat as a sandbox signal. Keeping the two layers in agreement means the
    # read-only mount always decides first, and the denial a command can actually provoke
    # is the EROFS this asserts. Observed on Linux by
    # `tui/sandbox/tests/linux_enforcement.rs`; asserted here as the contract.
    test "reads an ouro-sandbox denial, which is the same EROFS bubblewrap produces" do
      policy = fixed_policy(:workspace_write)
      output = "/bin/sh: 1: cannot create .git/HEAD: Read-only file system\n"

      assert %{constraint: :filesystem, evidence: evidence} =
               violation = Sandbox.violation(policy, output, 2)

      assert evidence == "/bin/sh: 1: cannot create .git/HEAD: Read-only file system"
      assert Sandbox.escalatable?(violation, policy, "echo x > .git/HEAD")

      escalation = Sandbox.escalation(violation, policy, "ouro-sandbox")
      assert escalation =~ "ouro-sandbox, sandbox_mode: workspace_write"
      assert escalation =~ "ask_user"
      assert escalation =~ "Do not retry the same command"
    end

    test "tells an ouro-sandbox backend failure apart from the command's own failure" do
      # The helper prefixes every policy-application failure with its own label and exits
      # 125, which is what makes this distinguishable at all.
      assert Sandbox.backend_failure(
               "ouro-sandbox",
               "ouro-sandbox: unshare(CLONE_NEWUSER|CLONE_NEWNS): Operation not permitted\n",
               125
             ) ==
               "ouro-sandbox: unshare(CLONE_NEWUSER|CLONE_NEWNS): Operation not permitted"

      # A command that merely mentions the helper is not a backend failure.
      assert Sandbox.backend_failure("ouro-sandbox", "built ouro-sandbox ok\n", 1) == nil
      # Nor is a denial, which is the command's own exit status and must stay one.
      assert Sandbox.backend_failure(
               "ouro-sandbox",
               "/bin/sh: 1: cannot create x: Read-only file system\n",
               2
             ) == nil
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

    # S1/HIGH-1. The engine refuses a *write* to `ouroboros.toml`, but the engine only sees
    # the paths a call declares and a shell declares none. So the file is in the policy as a
    # path, one per writable root, and both lists say the same thing.
    test "names each writable root's own hook manifest as a protected file", %{scope: scope} do
      policy = Sandbox.policy(scope, :workspace_write)

      assert policy.protected_files ==
               scope.roots
               |> Kernel.++([scope.root])
               |> Enum.map(&Path.join(&1, "ouroboros.toml"))
               |> Enum.uniq()
               |> Enum.sort()

      assert Path.join(scope.root, "ouroboros.toml") in policy.protected_files

      for file <- policy.protected_files do
        assert ("**/" <> Path.basename(file)) in Rules.protected_paths()
        assert Rules.protected_write?(file)
      end
    end

    test "read_only has none, because nothing there is writable to protect one in", %{
      read_only: scope
    } do
      assert Sandbox.policy(scope, :read_only).protected_files == []
    end

    test "a build has none: it has no workspace and therefore no hook manifest" do
      assert Sandbox.builder_policy(writable: ["/tmp"]).protected_files == []
    end

    # The honest answer, per backend, and the one `Hooks.trusted?/2` reads.
    test "protects_files? is true only where the backend can deny a path that need not exist" do
      assert Sandbox.protects_files?(:sandbox_exec)
      assert Sandbox.protects_files?(:bwrap)
      refute Sandbox.protects_files?(:ouro_sandbox)
      refute Sandbox.protects_files?(:none)

      # A detection map answers by its backend, and a bare `%{}` answers no.
      assert Sandbox.protects_files?(%{backend: :sandbox_exec, read_fence: true})
      refute Sandbox.protects_files?(%{backend: :ouro_sandbox, read_fence: true})
      refute Sandbox.protects_files?(%{})
    end

    test "Seatbelt writes one literal deny per protected file, after the segment denies" do
      policy = Map.put(fixed_policy(:workspace_write), :protected_files, ["/ws/ouroboros.toml"])
      profile = SandboxExec.profile(policy)

      assert profile =~ ~s{(deny file-write* (literal (param "OURO_PROTECTED_FILE_0")))}
      assert "-D" in SandboxExec.parameters(policy)
      assert "OURO_PROTECTED_FILE_0=/ws/ouroboros.toml" in SandboxExec.parameters(policy)

      # SBPL is last-match-wins, so the deny has to come after the allow that opened the
      # root it sits in.
      allow = :binary.match(profile, ~s{(allow file-write* (subpath (param "OURO_WRITABLE_1")))})

      deny =
        :binary.match(profile, ~s{(deny file-write* (literal (param "OURO_PROTECTED_FILE_0")))})

      assert elem(allow, 0) < elem(deny, 0)
    end

    test "bubblewrap binds the file over itself when it is there and the scratch directory when it is not",
         %{root: root, scope: scope} do
      present = Path.join(root, "workspace/ouroboros.toml")
      File.write!(present, "[[hooks]]\n")
      absent = Path.join(root, "extra/ouroboros.toml")

      policy =
        Sandbox.policy(scope, :workspace_write)
        |> Map.put(:protected_files, [absent, present])
        |> Sandbox.with_scratch(Path.join(root, "scratch"))

      argv = Bwrap.options(scope, policy)

      # An empty directory, never `/dev/null`: a character device at that path made `git add
      # -A` refuse a whole tree in CI, and git ignores an empty directory by design.
      assert ["--ro-bind", policy.scratch, absent] |> subsequence_of?(argv)
      refute ["--ro-bind", "/dev/null", absent] |> subsequence_of?(argv)
      assert ["--ro-bind", present, present] |> subsequence_of?(argv)

      # And the manifest's name joins the create filter's list, where this build has the
      # library — that is what refuses a create beneath a writable root, which no root-level
      # bind reaches.
      assert {:ok, {_bwrap, wrapped}} =
               Bwrap.wrap({:shell, "echo hi"}, scope, policy, "/usr/bin/bwrap")

      if File.regular?(Application.app_dir(:ouroboros, "priv/native/libouro_fs_filter.so")) do
        assert env_value(wrapped, "OUROBOROS_FS_DENY") == ".git:.ouroboros:ouroboros.toml"
      else
        refute "OUROBOROS_FS_DENY" in wrapped
      end

      # After the writable bind that would otherwise have made it writable.
      assert index_of(argv, scope.root) < index_of(argv, present)
    end
  end

  # S4 fix wave, HIGH-1 and HIGH-1b. The write fence above is not a read fence, and the two
  # exploits that proved it were the same shape: a sandboxed `bash` read this node's signing
  # seed (and derived the keypair with `:crypto`), and a sandboxed `bash` read this node's
  # gateway token and drove `policy.demote`/`policy.clear` against its own runtime.
  describe "the node's own credentials are hidden from a read" do
    setup do
      saved =
        Map.new(
          [:data_dir, :signer_key_path, :gateway, :web],
          &{&1, Application.get_env(:ouroboros, &1)}
        )

      on_exit(fn -> Enum.each(saved, fn {key, value} -> restore_app_env(key, value) end) end)
      :ok
    end

    test "hidden_files names the seed, the two tokens and the cookie secret", %{root: root} do
      data_dir = Path.join(root, "data")
      File.mkdir_p!(data_dir)
      key = Path.join(root, "keys/signer.key")
      File.mkdir_p!(Path.dirname(key))

      Application.put_env(:ouroboros, :data_dir, data_dir)
      Application.put_env(:ouroboros, :signer_key_path, key)
      Application.put_env(:ouroboros, :gateway, token_file: Path.join(data_dir, "named.token"))

      Application.put_env(:ouroboros, :web,
        token_file: Path.join(data_dir, "named.token"),
        secret_file: Path.join(data_dir, "named.secret")
      )

      hidden = Sandbox.hidden_files()

      for path <- [
            key,
            Path.join(data_dir, "named.token"),
            Path.join(data_dir, "named.secret"),
            # The names `ouro` and the daemon agree on with nobody configuring them.
            Path.join(data_dir, "gateway.token"),
            Path.join(data_dir, "web.secret")
          ] do
        assert path in hidden or canonical_file(path) in hidden,
               "#{path} is not fenced: #{inspect(hidden)}"
      end
    end

    # The conventional names are re-derived in `Sandbox` rather than imported, for
    # `protected_roots/0`'s reason. This is the check that the two agree.
    test "the conventional names are the ones the gateway and the web surface use", %{
      root: root
    } do
      data_dir = Path.join(root, "data")
      File.mkdir_p!(data_dir)
      Application.put_env(:ouroboros, :data_dir, data_dir)
      Application.delete_env(:ouroboros, :gateway)
      Application.delete_env(:ouroboros, :web)

      hidden = Sandbox.hidden_files()

      assert Ouroboros.Web.Config.default_token_file(data_dir) in hidden
      assert Ouroboros.Web.Config.default_secret_file(data_dir) in hidden
    end

    # Seatbelt resolves the path the kernel opens, and on macOS `/var/folders/…` is
    # `/private/var/folders/…` by then. A rule on the spelling alone renders perfectly and
    # denies nothing — which is what the first cut of this fix did.
    test "each path is listed as written and as the kernel resolves it", %{root: root} do
      data_dir = Path.join(root, "data")
      File.mkdir_p!(data_dir)
      Application.put_env(:ouroboros, :data_dir, data_dir)

      hidden = Sandbox.hidden_files()
      token = Path.join(data_dir, "gateway.token")

      assert token in hidden
      assert canonical_file(token) in hidden
    end

    test "a surface configured with a literal token contributes no path", %{root: root} do
      Application.put_env(:ouroboros, :data_dir, Path.join(root, "data"))
      Application.put_env(:ouroboros, :gateway, token: "a-literal-token")
      Application.delete_env(:ouroboros, :web)
      Application.delete_env(:ouroboros, :signer_key_path)

      refute "a-literal-token" in Sandbox.hidden_files()
    end

    test "every session policy carries them, in every mode", %{
      scope: scope,
      read_only: read_only,
      root: root
    } do
      data_dir = Path.join(root, "data")
      File.mkdir_p!(data_dir)
      Application.put_env(:ouroboros, :data_dir, data_dir)
      token = Path.join(data_dir, "gateway.token")

      for {mode, one} <- [
            {:read_only, read_only},
            {:workspace_write, scope},
            {:workspace_write_escalated, scope}
          ] do
        assert token in Sandbox.policy(one, mode).hidden_files,
               "#{mode} does not hide the gateway token"
      end
    end

    test "a build has none: a policy closed on reads has already hidden them" do
      assert Sandbox.builder_policy(writable: ["/tmp"]).hidden_files == []
    end

    test "hides_files? is true only where the backend can deny one named path a read" do
      assert Sandbox.hides_files?(:sandbox_exec)
      assert Sandbox.hides_files?(:bwrap)
      refute Sandbox.hides_files?(:ouro_sandbox)
      refute Sandbox.hides_files?(:none)

      assert Sandbox.hides_files?(%{backend: :sandbox_exec, read_fence: true})
      refute Sandbox.hides_files?(%{backend: :ouro_sandbox, read_fence: true})
      refute Sandbox.hides_files?(%{})
    end

    test "Seatbelt denies read and write, last of all the file rules" do
      policy =
        fixed_policy(:workspace_write)
        |> Map.put(:write_exceptions, ["/ws/delivery"])
        |> Map.put(:hidden_files, ["/srv/ouroboros/data/gateway.token"])

      profile = SandboxExec.profile(policy)

      assert profile =~ ~s{(deny file-read* (literal (param "OURO_HIDDEN_FILE_0")))}
      assert profile =~ ~s{(deny file-write* (literal (param "OURO_HIDDEN_FILE_0")))}

      assert "OURO_HIDDEN_FILE_0=/srv/ouroboros/data/gateway.token" in SandboxExec.parameters(
               policy
             )

      # Last-match-wins: after the blanket `(allow file-read*)` this profile opens with, and
      # after the delivery re-allow, which is the only rule that reopens a denied subtree.
      read_allow = :binary.match(profile, "(allow file-read*)")

      exception =
        :binary.match(profile, ~s{(allow file-write* (subpath (param "OURO_EXCEPTION_0")))})

      deny = :binary.match(profile, ~s{(deny file-read* (literal (param "OURO_HIDDEN_FILE_0")))})

      assert elem(read_allow, 0) < elem(deny, 0)
      assert elem(exception, 0) < elem(deny, 0)
    end

    # The loopback exception is what the S2b exploit reached the gateway over, and it stays:
    # `mix` and `cargo` coordinate concurrent compilers over it. The credential is the fence.
    test "and the loopback exception is untouched" do
      profile =
        fixed_policy(:workspace_write)
        |> Map.put(:hidden_files, ["/srv/ouroboros/data/gateway.token"])
        |> SandboxExec.profile()

      assert profile =~ ~s{(allow network-outbound (remote ip "localhost:*"))}
    end

    test "bubblewrap masks the path with /dev/null, and only where the file is there", %{
      root: root,
      scope: scope
    } do
      present = Path.join(root, "data/gateway.token")
      File.mkdir_p!(Path.dirname(present))
      File.write!(present, "a-token")
      absent = Path.join(root, "data/web.secret")
      directory = Path.join(root, "data/a-directory")
      File.mkdir_p!(directory)

      policy =
        Sandbox.policy(scope, :workspace_write)
        |> Map.put(:hidden_files, [present, absent, directory])
        |> Sandbox.with_scratch(Path.join(root, "scratch"))

      argv = Bwrap.options(scope, policy)

      # The source is `/dev/null` — unlike `protected_files`, which binds the file over
      # itself and would leave the bytes there to `cat`.
      assert ["--ro-bind", "/dev/null", present] |> subsequence_of?(argv)
      refute ["--ro-bind", present, present] |> subsequence_of?(argv)

      # And a path that is not a regular file is left out entirely. Measured with bubblewrap
      # 0.8.0 in a privileged container: `--ro-bind /dev/null <absent>` under a read-only
      # bind is "Can't create file … Read-only file system" and `bwrap` runs *nothing* — so
      # emitting it would take every command on a Linux node down with it.
      refute ["--ro-bind", "/dev/null", absent] |> subsequence_of?(argv)
      refute ["--ro-bind", "/dev/null", directory] |> subsequence_of?(argv)
    end

    # The helper's wire format has a read *allow*-set and no per-path deny, so it sends
    # nothing and says so through `hides_files?/1`.
    test "the ouro-sandbox request carries no hidden_files field", %{scope: scope, root: root} do
      policy =
        Sandbox.policy(scope, :workspace_write)
        |> Map.put(:hidden_files, [Path.join(root, "data/gateway.token")])
        |> Sandbox.with_scratch(Path.join(root, "scratch"))

      request = Helper.request(policy, scope)

      refute Map.has_key?(request, "hidden_files")
      refute request |> JSON.encode!() |> String.contains?("gateway.token")
    end
  end

  describe "bash on a node with no backend" do
    setup do
      previous_app = Application.get_env(:ouroboros, :allow_unsandboxed_bash)
      previous_env = System.get_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH")
      Application.put_env(:ouroboros, :native_sandbox, :none)
      Application.put_env(:ouroboros, :allow_unsandboxed_bash, false)
      System.delete_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH")

      on_exit(fn ->
        Application.delete_env(:ouroboros, :native_sandbox)
        restore_app_env(:allow_unsandboxed_bash, previous_app)
        restore_sys_env("OUROBOROS_ALLOW_UNSANDBOXED_BASH", previous_env)
      end)

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
      assert result.output =~ "workspace_write"
      assert result.output =~ "OUROBOROS_ALLOW_UNSANDBOXED_BASH=1"
    end

    test "refuses a workspace_write command, and names the allow flag", %{
      context: context,
      workspace: workspace
    } do
      result = run(Bash, %{"command" => "echo out > unsandboxed.txt && echo ok"}, context)

      assert result.is_error
      assert result.output =~ "workspace_write"
      assert result.output =~ "no OS sandbox backend"
      assert result.output =~ "OUROBOROS_ALLOW_UNSANDBOXED_BASH=1"
      assert result.output =~ "ouro-sandbox"
      assert result.output =~ "sandbox-exec"
      assert result.output =~ "bwrap"
      refute File.exists?(Path.join(workspace, "unsandboxed.txt"))
    end

    test "runs a workspace_write command unsandboxed when the operator opts in", %{
      context: context,
      workspace: workspace
    } do
      Application.put_env(:ouroboros, :allow_unsandboxed_bash, true)

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

    # S1/HIGH-1, the reviewer's exploit_c adopted as a regression. The permission engine
    # refuses a *write* to `ouroboros.toml`, but a shell declares only its redirect targets,
    # so `cp`, `mv`, `tee`, `sed -i`, `dd` and a Python one-liner all reached the file with
    # that rule in place. This is the kernel's answer, and `.git/pwned` is the control: the
    # same shell, the same policy, a fence that was always there.
    test "no shell reaches the hook manifest, by any of the ways that used to", %{
      context: context,
      workspace: workspace
    } do
      manifest = Path.join(workspace, "ouroboros.toml")
      File.write!(Path.join(workspace, "template"), "[[hooks]]\nevent = \"PreToolUse\"\n")

      # The control: `.git` is fenced by a segment rule, and has been since the beginning.
      control = run(Bash, %{"command" => "cp template .git/pwned"}, context)
      assert control.is_error
      refute File.exists?(Path.join([workspace, ".git", "pwned"]))

      for command <- [
            "cp template ouroboros.toml",
            "mv template ouroboros.toml",
            "cat template | tee ouroboros.toml",
            "printf '[[hooks]]' | dd of=ouroboros.toml",
            "echo x > ouroboros.toml",
            "python3 -c \"open('ouroboros.toml','w').write('x')\"",
            "touch ouroboros.toml"
          ] do
        result = run(Bash, %{"command" => command}, context)

        assert result.is_error, "#{command} was allowed: #{result.output}"
        refute File.exists?(manifest), "#{command} created the hook manifest"
      end
    end

    # S4/HIGH-1 and HIGH-1b, the two reviewers' exploits adopted as one regression.
    #
    # `rv-s4/exploit-1-key-readable.exs` planted an Ed25519 seed where docs/SELF.md tells the
    # operator to put it, ran the exact pipeline `Tools.Bash.plan/2` runs — detect, decide,
    # scratch, with_scratch, wrap, `System.cmd` — and `cat`ed the seed out through a
    # `workspace_write` shell, then derived the keypair and signed arbitrary bytes with it.
    # `rv-s2b/live_sandbox_to_gateway.sh` did the same to `gateway.token` and drove
    # `policy.demote` and `policy.clear` against the node's own gateway with it.
    #
    # This is the kernel's answer to both. The seed is planted in both places the exploit
    # used — under the data directory and in a directory of the daemon user's own — because
    # the fence is on the configured path and not on the data directory.
    test "no shell reads this node's signing seed or its gateway token", %{
      root: root,
      scope: scope
    } do
      saved =
        Map.new([:data_dir, :signer_key_path], &{&1, Application.get_env(:ouroboros, &1)})

      on_exit(fn -> Enum.each(saved, fn {key, value} -> restore_app_env(key, value) end) end)

      data_dir = Path.join(root, "credentials")
      elsewhere = Path.join(root, "home-keys")
      File.mkdir_p!(data_dir)
      File.mkdir_p!(elsewhere)

      seed = :crypto.strong_rand_bytes(32)
      encoded = Base.encode64(seed)
      token = Path.join(data_dir, "gateway.token")
      secret = Path.join(data_dir, "web.secret")
      File.write!(token, "a-real-looking-operator-token")
      File.write!(secret, "a-real-looking-cookie-secret")

      for {label, key} <- [
            {"under the data directory", Path.join(data_dir, "signer.key")},
            {"anywhere the daemon user can read", Path.join(elsewhere, "signer.key")}
          ] do
        File.write!(key, encoded)
        File.chmod!(key, 0o600)

        Application.put_env(:ouroboros, :data_dir, data_dir)
        Application.put_env(:ouroboros, :signer_key_path, key)

        detection = Sandbox.detect()
        assert Sandbox.hides_files?(detection), "this backend cannot hide a file"

        {:sandboxed, _label, policy} = Sandbox.decide(scope, detection)
        {:ok, scratch} = Sandbox.scratch()
        policy = Sandbox.with_scratch(policy, scratch)

        try do
          for {what, path} <- [
                {"the seed #{label}", key},
                {"the gateway token", token},
                {"the cookie secret", secret}
              ] do
            {output, status} = sandboxed(scope, policy, detection, "cat #{path}")

            assert status != 0, "#{what} was readable: #{output}"
            refute output =~ encoded, "#{what} leaked the seed"
            refute output =~ "operator-token", "#{what} leaked the token"
            refute output =~ "cookie-secret", "#{what} leaked the secret"
            assert output =~ "Operation not permitted"
          end

          # A key a session may not read is a key it may not replace either.
          {_output, status} = sandboxed(scope, policy, detection, "echo overwritten > #{key}")
          assert status != 0
          assert File.read!(key) == encoded

          # The control: the same shell, the same policy, an ordinary file beside them. The
          # fence is these paths, not the directory and not reads in general.
          plain = Path.join(data_dir, "notes.txt")
          File.write!(plain, "ordinary")
          {output, 0} = sandboxed(scope, policy, detection, "cat #{plain}")
          assert output =~ "ordinary"
        after
          Sandbox.release(scratch)
        end
      end
    end

    test "and an existing hook manifest cannot be rewritten or removed", %{
      context: context,
      workspace: workspace
    } do
      manifest = Path.join(workspace, "ouroboros.toml")
      File.write!(manifest, "[[hooks]]\nevent = \"PreToolUse\"\n")

      for command <- [
            "echo pwned > ouroboros.toml",
            "sed -i '' 's/PreToolUse/SessionStart/' ouroboros.toml",
            "rm -f ouroboros.toml",
            "mv ouroboros.toml elsewhere.toml"
          ] do
        result = run(Bash, %{"command" => command}, context)
        assert result.is_error, "#{command} was allowed: #{result.output}"
      end

      # Unchanged, and still readable: a fence on writing is not a fence on reading.
      assert File.read!(manifest) == "[[hooks]]\nevent = \"PreToolUse\"\n"

      assert %{is_error: false, output: shown} =
               run(Bash, %{"command" => "cat ouroboros.toml"}, context)

      assert shown =~ "PreToolUse"
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

    test "permits loopback IPC while continuing to deny external connections", %{
      context: context
    } do
      bind =
        run(
          Bash,
          %{
            "command" =>
              "/usr/bin/python3 -c \"import socket; s=socket.socket(); " <>
                "s.bind(('127.0.0.1', 0)); print(s.getsockname()[0]); s.close()\""
          },
          context
        )

      refute bind.is_error
      assert bind.output =~ "127.0.0.1"

      loopback = run(Bash, %{"command" => "nc -vz 127.0.0.1 9 2>&1"}, context)
      assert loopback.is_error
      assert loopback.output =~ "Connection refused"
      refute loopback.output =~ "Operation not permitted"

      external = run(Bash, %{"command" => "nc -vz 192.0.2.1 9 2>&1"}, context)

      assert external.is_error
      assert external.output =~ "Operation not permitted"
      assert external.output =~ "denies external network access"
    end

    test "runs Mix compilation with its loopback coordination intact", %{
      context: context,
      workspace: workspace
    } do
      File.write!(
        Path.join(workspace, "mix.exs"),
        """
        defmodule SandboxFixture.MixProject do
          use Mix.Project

          def project do
            [app: :sandbox_fixture, version: "0.1.0", elixir: "~> 1.14"]
          end
        end
        """
      )

      File.mkdir_p!(Path.join(workspace, "lib"))

      File.write!(
        Path.join(workspace, "lib/sandbox_fixture.ex"),
        "defmodule SandboxFixture do\n  def ok?, do: true\nend\n"
      )

      # `MIX_ENV=dev` is pinned because the test runner's own environment leaks into the
      # sandboxed command: a shell (or CI) that exported MIX_ENV=test would steer this
      # compile into _build/test and fail the _build/dev assertion below.
      result =
        run(Bash, %{"command" => "MIX_ENV=dev mix compile --warnings-as-errors"}, context)

      refute result.is_error, result.output
      refute result.output =~ "failed to acquire filesystem lock using TCP"
      refute result.output =~ "failed to subscribe to Mix events using TCP"

      assert File.exists?(
               Path.join(
                 workspace,
                 "_build/dev/lib/sandbox_fixture/ebin/Elixir.SandboxFixture.beam"
               )
             )
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

  # S1's Linux half, measured after CI: bubblewrap creates the mount point for an absent
  # protected path *inside the host's own directory* and never unlinks it, so `--ro-bind
  # /dev/null <ws>/ouroboros.toml` leaves a zero-byte read-only file behind and `--ro-bind
  # <scratch> <ws>/.git` leaves an empty directory. `Bwrap.mount_point_stubs/1` names them
  # from the same `File.exists?` the argv reads, and the bash tool clears them afterwards.
  # This half is pure filesystem and runs on every platform; the bubblewrap half is below.
  describe "the mount-point stubs bubblewrap leaves behind" do
    setup do
      root = Path.join(System.tmp_dir!(), "native-stubs-#{System.unique_integer([:positive])}")
      on_exit(fn -> File.rm_rf(root) end)
      workspace = Path.join(root, "workspace")
      scratch = Path.join(root, "scratch")
      File.mkdir_p!(workspace)
      File.mkdir_p!(scratch)
      {:ok, scope} = Paths.scope(workspace, [], :workspace_write)
      policy = scope |> Sandbox.policy(:workspace_write) |> Sandbox.with_scratch(scratch)
      %{workspace: scope.root, policy: policy, scratch: scratch}
    end

    test "names the absent manifest and the absent segment directories, and nothing that exists",
         %{workspace: workspace, policy: policy} do
      stubs = Bwrap.mount_point_stubs(policy)

      assert Path.join(workspace, "ouroboros.toml") in stubs
      assert Path.join(workspace, ".git") in stubs
      assert Path.join(workspace, ".ouroboros") in stubs

      File.write!(Path.join(workspace, "ouroboros.toml"), "[[hooks]]\n")
      File.mkdir_p!(Path.join(workspace, ".git"))

      stubs = Bwrap.mount_point_stubs(policy)
      refute Path.join(workspace, "ouroboros.toml") in stubs
      refute Path.join(workspace, ".git") in stubs
      assert Path.join(workspace, ".ouroboros") in stubs
    end

    test "the sandbox seam answers them for bubblewrap and nothing for the others", %{
      policy: policy,
      workspace: workspace
    } do
      assert Path.join(workspace, "ouroboros.toml") in Sandbox.stubs(policy, %{
               backend: :bwrap,
               executable: "/usr/bin/bwrap"
             })

      for backend <- [:sandbox_exec, :ouro_sandbox, :none] do
        assert Sandbox.stubs(policy, %{backend: backend, executable: nil}) == []
      end
    end

    test "clearing removes only what is still a stub", %{workspace: workspace} do
      # The manifest stub is an empty directory (the scratch bind's shape); a zero-byte file
      # is what the first cut left, and clearing knows both.
      stub_file = Path.join(workspace, "ouroboros.toml.first-cut")
      stub_dir = Path.join(workspace, ".git")
      stub_manifest = Path.join(workspace, "ouroboros.toml")
      real_file = Path.join(workspace, "kept.toml")
      real_dir = Path.join(workspace, ".ouroboros")
      missing = Path.join(workspace, "never-there")

      File.write!(stub_file, "")
      File.mkdir_p!(stub_dir)
      File.mkdir_p!(stub_manifest)
      File.write!(real_file, "[[hooks]]\n")
      File.mkdir_p!(Path.join(real_dir, "sessions"))

      assert :ok =
               Bwrap.clear_mount_point_stubs([
                 stub_file,
                 stub_dir,
                 stub_manifest,
                 real_file,
                 real_dir,
                 missing
               ])

      refute File.exists?(stub_file)
      refute File.exists?(stub_dir)
      refute File.exists?(stub_manifest)
      assert File.read!(real_file) == "[[hooks]]\n"
      assert File.dir?(Path.join(real_dir, "sessions"))
      refute File.exists?(missing)

      # Total, in both spellings the bash tool can hand it.
      assert :ok = Sandbox.clear_stubs([])
      assert :ok = Sandbox.clear_stubs(nil)
    end
  end

  describe "the bwrap backend, live on this node" do
    @describetag :bwrap
    @describetag @needs_bwrap

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
      assert result.output =~ "Read-only file system"
      assert result.output =~ "bwrap, sandbox_mode: read_only"
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

    # S1/HIGH-1's Linux half. Same claim as the sandbox-exec case above, by a different
    # mechanism: an existing manifest is bound read-only over itself and an absent one has
    # the empty scratch directory bound onto it, so a create fails `EROFS` or `EISDIR` and a
    # rename or an unlink over the mount point fails `EBUSY`. Runs where the live bubblewrap
    # suite runs — Linux CI's ubuntu-24.04 job and `scripts/wasm-linux-test.sh` — and is
    # skipped, loudly, on a Mac.
    test "no shell reaches the hook manifest, present or absent", %{
      context: context,
      workspace: workspace
    } do
      manifest = Path.join(workspace, "ouroboros.toml")
      File.write!(Path.join(workspace, "template"), "[[hooks]]\n")

      for command <- [
            "cp template ouroboros.toml",
            "mv template ouroboros.toml",
            "cat template | tee ouroboros.toml",
            "echo x > ouroboros.toml"
          ] do
        result = run(Bash, %{"command" => command}, context)
        assert result.is_error, "#{command} was allowed: #{result.output}"
        refute File.exists?(manifest), "#{command} created the hook manifest"
      end
    end

    # The residue the first run of the test above found in CI: the mask is a mount point,
    # and bubblewrap's teardown leaves it on the host. After the command the bash tool
    # clears what it named beforehand, so a workspace that had no manifest and no `.git`
    # still has neither — the pre-existing `.git`/`.ouroboros` scratch binds had been
    # leaving an empty directory behind on every Linux command for the same reason.
    test "leaves no mount-point stub behind once the command has ended", %{
      context: context,
      workspace: workspace
    } do
      absent_before =
        ["ouroboros.toml", ".git", ".ouroboros"]
        |> Enum.map(&Path.join(workspace, &1))
        |> Enum.reject(&File.exists?/1)

      assert Path.join(workspace, "ouroboros.toml") in absent_before

      assert %{is_error: false, output: output} = run(Bash, %{"command" => "echo hi"}, context)
      assert output =~ "hi"

      for path <- absent_before do
        refute File.exists?(path), "#{path} was left behind by the sandbox"
      end
    end

    # The shape of the mask, from inside: a directory, which git ignores and nothing writes
    # into — not a device, which made `git add -A` refuse a whole tree in CI.
    test "an absent hook manifest is masked as an empty directory inside the namespace", %{
      context: context,
      workspace: workspace
    } do
      refute File.exists?(Path.join(workspace, "ouroboros.toml"))

      assert %{is_error: false, output: output} =
               run(
                 Bash,
                 %{"command" => "ls -ld ouroboros.toml && find . -name ouroboros.toml -type f"},
                 context
               )

      assert output =~ ~r/^d/m
      refute output =~ ~r/^\.\/ouroboros\.toml$/m
    end

    test "and an existing hook manifest stays readable and unwritable", %{
      context: context,
      workspace: workspace
    } do
      manifest = Path.join(workspace, "ouroboros.toml")
      File.write!(manifest, "[[hooks]]\nevent = \"PreToolUse\"\n")

      for command <- ["echo pwned > ouroboros.toml", "rm -f ouroboros.toml"] do
        result = run(Bash, %{"command" => command}, context)
        assert result.is_error, "#{command} was allowed: #{result.output}"
      end

      assert File.read!(manifest) == "[[hooks]]\nevent = \"PreToolUse\"\n"

      assert %{is_error: false, output: shown} =
               run(Bash, %{"command" => "cat ouroboros.toml"}, context)

      assert shown =~ "PreToolUse"
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
      assert result.output =~ "Read-only file system"
      assert result.output =~ "add the directory this needs to the session's `add_dirs`"
      refute File.exists?(escape)
    end

    test "denies a write into .git, which is why a commit needs a human", %{
      context: context,
      workspace: workspace
    } do
      result = run(Bash, %{"command" => "echo tampered > .git/HEAD"}, context)

      assert result.is_error
      assert result.output =~ "Read-only file system"
      assert result.output =~ "never into a `.git` or `.ouroboros` directory"
      refute File.exists?(Path.join(workspace, ".git/HEAD"))
    end

    test "denies a write into a nested .git, not only the workspace's own", %{
      context: context,
      workspace: workspace
    } do
      nested = Path.join(workspace, "deps/foo/.git")
      File.mkdir_p!(nested)

      result = run(Bash, %{"command" => "echo tampered > deps/foo/.git/HEAD"}, context)

      assert result.is_error
      assert result.output =~ "Read-only file system"
      refute File.exists?(Path.join(nested, "HEAD"))
    end

    test "denies creating a .git that did not exist when the command started", %{
      context: context,
      workspace: workspace
    } do
      result =
        run(
          Bash,
          %{"command" => "mkdir -p deps/bar/.git && echo x > deps/bar/.git/HEAD"},
          context
        )

      assert result.is_error
      assert result.output =~ "Read-only file system"
      refute File.dir?(Path.join(workspace, "deps/bar/.git"))
      refute File.exists?(Path.join(workspace, "deps/bar/.git/HEAD"))
    end
  end
end
