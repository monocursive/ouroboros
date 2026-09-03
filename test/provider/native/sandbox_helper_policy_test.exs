defmodule Ouroboros.Provider.Native.SandboxHelperPolicyTest do
  @moduledoc """
  `Sandbox.helper_policy/1`: the closed, **sealed** policy the `ouro-wasm` helper runs under
  (W16, W21, D25).

  Contract C10 says this is `builder_policy/1`'s shape with the scratch attached, and that it
  adds **no backend arm** — `:builder` is this module's vocabulary for "closed by default on
  reads" and all three backends already implement it. What W21 added is a *field*, `process`,
  the way W16 added `loopback`: the Seatbelt profile is a function of the policy's fields, so
  sealing the helper's process cost no fourth profile. So what is pinned here is the shape and
  the mode, the sealed profile's whole text beside the builder's, and then — where a claim is
  a kernel claim — what `sandbox-exec` actually does under the real `helper_policy/1`, with
  the builder policy as the other half of every pair so that a denial is a fence and not a
  broken command.

  The kernel tests are Seatbelt's and skip elsewhere with the reason: the two Linux backends
  render a sealed policy exactly as they render an open one, which is pinned below as a
  property of the pure functions, and what proves the Linux read fence is CI's ubuntu job.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.Helper
  alias Ouroboros.Provider.Native.Sandbox.SandboxExec

  # Seatbelt is the one backend that seals a process, so the kernel-level claims about the
  # seal can only be measured where it is. Decided by the operating system rather than by the
  # detection cache, because a suite that planted another backend into that cache would
  # otherwise turn these into skips nobody asked for.
  @seatbelt (case :os.type() do
               {:unix, :darwin} -> []
               _other -> [skip: "Seatbelt only: the Linux backends do not seal a process"]
             end)

  # The real helper, for the one claim that needs it: that a sealed profile starts it by
  # either spelling of its path.
  @needs_helper Ouroboros.Wasm.LiveFixture.tag()

  describe "the shape" do
    test "is the builder's, with the scratch attached, the network off and the process sealed" do
      policy =
        Sandbox.helper_policy(
          readable: ["/opt/store"],
          writable: [],
          scratch: "/opt/scratch"
        )

      # `:builder` and not a fourth mode: the profile is a function of the fields, and the
      # helper's difference from a build is two of them — `loopback` and `process`.
      assert policy.mode == :builder
      assert policy.network == false
      assert policy.loopback == false
      assert policy.process == :sealed
      assert policy.protected == []
      assert policy.protected_segments == []

      # The platform's own roots come for free — a process that cannot read the dynamic
      # loader does not start — and the caller's roots are added to them.
      assert "/opt/store" in policy.readable
      assert Enum.all?(Sandbox.platform_readable(), &(&1 in policy.readable))

      # The scratch is writable, and it is the *only* writable root when the caller names
      # none. That is the helper's case: it reads components and writes nothing.
      assert policy.scratch == "/opt/scratch"
      assert policy.writable == ["/opt/scratch"]
    end

    test "`process: :open` is the one opt-out, and anything else is sealed (W21)" do
      assert Sandbox.helper_policy(process: :open).process == :open
      # A typo is the narrower posture, because the wider one has to be asked for by name.
      assert Sandbox.helper_policy(process: :scripted).process == :sealed
      assert Sandbox.helper_policy(process: true).process == :sealed
      assert Sandbox.helper_policy([]).process == :sealed

      # And a forge is a process tree — cargo forks and execs rustc — so the builder's own
      # policy is open, by construction and not by omission.
      assert Sandbox.builder_policy(writable: ["/opt/build"]).process == :open
    end

    test "the caller's writable roots are kept, and the scratch joins them" do
      policy = Sandbox.helper_policy(writable: ["/opt/sign"], scratch: "/opt/sign/tmp-x")

      assert Enum.sort(policy.writable) == ["/opt/sign", "/opt/sign/tmp-x"]

      # Writable implies readable at both backends, which is why the sign scratch is not also
      # named in `readable`: a compiler that could write its artifact and not read it back
      # would not be a compiler.
      refute "/opt/sign" in policy.readable
    end

    test "no scratch is a policy `wrap/4` refuses, rather than one that runs unfenced" do
      policy = Sandbox.helper_policy(readable: ["/opt/store"])

      assert policy.scratch == nil

      assert {:error, :no_scratch_directory} =
               Sandbox.wrap({:argv, ["/bin/true"]}, %{}, policy, Sandbox.detect())
    end

    test "a sealed policy refuses a shell and a relative argv[0], by name, on every backend" do
      sealed = Sandbox.helper_policy(readable: [], writable: [], scratch: "/opt/scratch")
      detection = Sandbox.detect()

      # A shell is exec and fork; wrapping one sealed would be a child that fails for reasons
      # the profile cannot name.
      assert {:error, :shell_under_sealed_policy} =
               Sandbox.wrap({:shell, "/usr/bin/true"}, %{}, sealed, detection)

      # The one exec the profile allows is a literal path, and a name resolved through `$PATH`
      # is not one.
      assert {:error, {:relative_exec_under_sealed_policy, "ouro-wasm"}} =
               Sandbox.wrap({:argv, ["ouro-wasm", "serve"]}, %{}, sealed, detection)

      assert {:error, {:relative_exec_under_sealed_policy, ""}} =
               Sandbox.wrap({:argv, [""]}, %{}, sealed, detection)

      # The builder policy still wraps both, because a build is a shell's worth of processes.
      # Only where there is a backend to wrap with: `:none` answers its own refusal.
      if detection.backend != :none do
        builder =
          Sandbox.builder_policy(readable: [], writable: [])
          |> Sandbox.with_scratch("/opt/scratch")

        assert {:ok, _wrapped} = Sandbox.wrap({:shell, "/usr/bin/true"}, %{}, builder, detection)
        assert {:ok, _wrapped} = Sandbox.wrap({:argv, ["true"]}, %{}, builder, detection)
      end
    end
  end

  describe "which backend seals a process (W21)" do
    test "Seatbelt does; the Linux backends do not, and neither does no backend" do
      assert Sandbox.seals_process?(:sandbox_exec)
      refute Sandbox.seals_process?(:bwrap)
      refute Sandbox.seals_process?(:ouro_sandbox)
      refute Sandbox.seals_process?(:none)

      # Answered by backend, off a detection map exactly as `fences_reads?/1` is.
      assert Sandbox.seals_process?(%{
               backend: :sandbox_exec,
               executable: "/usr/bin/sandbox-exec"
             })

      refute Sandbox.seals_process?(%{backend: :bwrap, executable: "/usr/bin/bwrap"})
    end

    test "the posture a policy actually gets is the policy's ask against the backend" do
      sealed = Sandbox.helper_policy(scratch: "/opt/scratch")
      open = Sandbox.helper_policy(scratch: "/opt/scratch", process: :open)

      assert Sandbox.process_posture(sealed, :sandbox_exec) == :sealed
      assert Sandbox.process_posture(sealed, :bwrap) == :open
      assert Sandbox.process_posture(sealed, :ouro_sandbox) == :open
      assert Sandbox.process_posture(open, :sandbox_exec) == :open
      assert Sandbox.process_posture(Sandbox.builder_policy([]), :sandbox_exec) == :open
    end
  end

  describe "what each backend makes of it" do
    setup do
      %{
        policy:
          Sandbox.helper_policy(
            readable: ["/opt/store", "/opt/helper"],
            writable: [],
            scratch: "/opt/scratch"
          )
      }
    end

    test "Seatbelt denies the network with no loopback exception (W16 HIGH-1)", %{
      policy: policy
    } do
      profile = SandboxExec.profile(policy)

      assert profile =~ "(deny network*)"

      # The three lines that used to follow the deny, and the reason they are gone: SBPL is
      # last-match-wins, so they re-allowed every `localhost` bind, inbound and outbound after
      # the deny. A review connected to a loopback listener under this exact policy — which is
      # every service on the machine, this node's own gateway included.
      refute profile =~ "network-bind"
      refute profile =~ "network-inbound"
      refute profile =~ "network-outbound"

      # And the exception is still there for the one caller that needs it: `mix` and `cargo`
      # coordinate concurrent compilers over loopback, and a build without it fails `:eperm`.
      builder = SandboxExec.profile(Sandbox.builder_policy(writable: ["/opt/build"]))
      assert builder =~ "(deny network*)"
      assert builder =~ ~s[(allow network-outbound (remote ip "localhost:*"))]
    end

    @tag :tmp_dir
    test "and the kernel agrees: a loopback listener is unreachable", %{tmp_dir: tmp} do
      detection = Sandbox.detect()

      # A listener this test owns, on a port the OS chose, so nothing here depends on what
      # else happens to be running.
      {:ok, socket} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
      {:ok, port} = :inet.port(socket)
      on_exit(fn -> :gen_tcp.close(socket) end)

      scratch = Path.join(tmp, "scratch")
      File.mkdir_p!(scratch)
      File.chmod!(scratch, 0o700)

      # `nc` **as the target**, not behind a shell (W21): a sealed policy refuses a shell, and
      # a shell that could not fork `nc` would be an exec denial dressed as a network one. As
      # the target it is the one exec the profile allows, and what it then reports is the
      # connect — non-zero on `EPERM`, zero on a listener it reached.
      reach = fn policy ->
        {:ok, {exe, args}} =
          Sandbox.wrap(
            {:argv, ["/usr/bin/nc", "-w", "2", "-z", "127.0.0.1", Integer.to_string(port)]},
            %{},
            policy,
            detection
          )

        {_output, status} =
          System.cmd(exe, args, stderr_to_stdout: true, env: Sandbox.env(policy), cd: "/")

        status == 0
      end

      helper = Sandbox.helper_policy(readable: [tmp], writable: [], scratch: scratch)

      refute reach.(helper), "the helper policy let a child open a loopback socket"

      # The other half, and what makes the first half a fence rather than a broken `nc`: the
      # builder policy — the same shape, two fields different — reaches the same listener.
      # Only on Seatbelt: the Linux backends unshare the network namespace for *both*, so
      # there is no loopback in either child to compare.
      if detection.backend == :sandbox_exec do
        builder =
          Sandbox.builder_policy(readable: [tmp], writable: [])
          |> Sandbox.with_scratch(scratch)

        assert reach.(builder), "the builder policy lost the loopback exception cargo needs"
      end
    end

    test "Seatbelt closes on reads and names the roots as parameters", %{policy: policy} do
      profile = SandboxExec.profile(policy)

      assert profile =~ "(deny default)"
      # The one line that separates this from every other policy this module makes: there is
      # no bare `(allow file-read*)`.
      refute profile =~ "\n(allow file-read*)"
      # W21: metadata on the root directory itself and nowhere else — `file-read*` on a root
      # already implies it there, and a `stat` everywhere is an existence oracle.
      assert profile =~ ~s[(allow file-read-metadata (literal "/"))]
      refute profile =~ ~s[(allow file-read-metadata (subpath "/"))]
      assert profile =~ ~s[(allow file-read* (subpath (param "OURO_READABLE_0")))]
      assert profile =~ ~s[(allow file-write* (subpath (param "OURO_WRITABLE_0")))]
      assert profile =~ "(deny network*)"

      # Paths reach the profile only as `-D` parameters, so a directory name can never be
      # part of the policy's source.
      parameters = SandboxExec.parameters(policy)
      assert "OURO_WRITABLE_0=/opt/scratch" in parameters
      assert Enum.any?(parameters, &String.ends_with?(&1, "=/opt/helper"))
      assert Enum.any?(parameters, &String.ends_with?(&1, "=/opt/store"))
      refute profile =~ "/opt/store"
    end

    test "the sealed Seatbelt profile, whole (W21)" do
      # Built by hand rather than through `helper_policy/1`, so the count of readable roots —
      # and with it the text — does not depend on which platform's roots are in the set.
      assert SandboxExec.profile(fixed(:sealed)) == """
             (version 1)
             ; Ouroboros wasm helper (docs/WASM.md 7.3a, D25). Closed by default on reads as well
             ; as on writes, and sealed as a process: it may exec only the binary it was spawned
             ; as, may not fork, and reaches no mach service. Paths arrive as -D parameters.
             (deny default)
             (allow process-exec (literal (param "OURO_EXEC")))
             (allow signal (target self))
             (allow sysctl-read (sysctl-name-prefix "hw."))
             (allow file-read-metadata (literal "/"))
             (allow file-read* (literal "/"))
             (allow file-write-data (require-all (path "/dev/null") (vnode-type CHARACTER-DEVICE)))
             (allow file-read* (subpath (param "OURO_READABLE_0")))
             (allow file-read* (subpath (param "OURO_READABLE_1")))
             (allow file-read* (subpath (param "OURO_WRITABLE_0")))
             (allow file-write* (subpath (param "OURO_WRITABLE_0")))
             (deny network*)
             """

      # No `process-fork`, no `mach-lookup`, no bare `sysctl-read`, no metadata over `/`: each
      # is a line the helper never used and a compromised one could.
      sealed = SandboxExec.profile(fixed(:sealed))
      refute sealed =~ "process-fork"
      refute sealed =~ "mach-lookup"
      refute sealed =~ "(allow sysctl-read)"
      refute sealed =~ "(allow process-exec)\n"
    end

    test "and the builder's profile is what it was: a forge keeps the open process rules" do
      # `test/wasm/forge_test.exs` asserts this profile line by line; the whole text is here so
      # that sealing the helper cannot have touched a forge's rules by accident.
      assert SandboxExec.profile(fixed(:open)) == """
             (version 1)
             ; Ouroboros forge builder (docs/WASM.md D18). Closed by default on reads as well as
             ; on writes: a build may read the toolchain roots it was given and nothing else, so
             ; what a compiler can carry into its output is bounded. Paths arrive as -D parameters.
             (deny default)
             (allow process-exec)
             (allow process-fork)
             (allow signal (target self))
             (allow sysctl-read)
             (allow mach-lookup)
             (allow file-read-metadata (subpath "/"))
             (allow file-read* (literal "/"))
             (allow file-write-data (require-all (path "/dev/null") (vnode-type CHARACTER-DEVICE)))
             (allow file-read* (subpath (param "OURO_READABLE_0")))
             (allow file-read* (subpath (param "OURO_READABLE_1")))
             (allow file-read* (subpath (param "OURO_WRITABLE_0")))
             (allow file-write* (subpath (param "OURO_WRITABLE_0")))
             (deny network*)
             """

      # And a builder policy that says nothing about its process is that same open profile:
      # the field defaults open where it is absent, so no caller of `builder_policy/1` moved.
      assert SandboxExec.profile(Map.delete(fixed(:open), :process)) ==
               SandboxExec.profile(fixed(:open))
    end

    @tag @seatbelt
    @tag :tmp_dir
    test "the sealed wrap names the exec as one resolved parameter and spawns by that path",
         %{tmp_dir: tmp} do
      %{backend: :sandbox_exec, executable: sandbox_exec} = detection = Sandbox.detect()

      # A binary reached through a symlinked directory, the way `_build/test/lib/…/priv` reaches
      # `priv/wasm/ouro-wasm` on a development machine.
      real = Path.join(tmp, "real")
      File.mkdir_p!(real)
      binary = Path.join(real, "fake-helper")
      File.write!(binary, "#!/bin/sh\n")
      File.chmod!(binary, 0o755)
      File.ln_s!(real, Path.join(tmp, "link"))
      spelled = Path.join([tmp, "link", "fake-helper"])
      {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize_file(binary)

      policy = Sandbox.helper_policy(readable: [tmp], writable: [], scratch: tmp)

      assert {:ok, {^sandbox_exec, args}} =
               Sandbox.wrap({:argv, [spelled, "serve"]}, %{}, policy, detection)

      # Seatbelt matches the exec literal against the path the kernel resolves and needs
      # metadata on every symlink along a spelled path to resolve it, which a sealed profile
      # does not grant; so the one parameter is the resolved path and argv[0] is the same.
      assert ["-D", "OURO_EXEC=" <> canonical] ==
               Enum.chunk_every(args, 2, 1, :discard)
               |> Enum.find(&match?(["-D", "OURO_EXEC=" <> _], &1))

      assert Enum.take(args, -2) == [canonical, "serve"]
      refute spelled in args

      # A target that does not resolve is passed as spelled: its exec fails as it would have,
      # and rewriting it to a guess would be a fence with a hole.
      absent = Path.join(tmp, "never-built")

      assert {:ok, {_exe, args}} =
               Sandbox.wrap({:argv, [absent, "serve"]}, %{}, policy, detection)

      assert ("OURO_EXEC=" <> absent) in args
      assert Enum.take(args, -2) == [absent, "serve"]

      # And the builder's wrap names no exec at all — the profile has no literal to feed.
      builder = Sandbox.builder_policy(readable: [tmp], writable: []) |> Sandbox.with_scratch(tmp)

      assert {:ok, {_exe, open_args}} =
               Sandbox.wrap({:argv, [spelled, "serve"]}, %{}, builder, detection)

      refute Enum.any?(open_args, &String.starts_with?(&1, "OURO_EXEC="))
      assert Enum.take(open_args, -2) == [spelled, "serve"]
    end

    @tag :tmp_dir
    test "a root reached through a symlink names the link, and only the link (W21)", %{
      tmp_dir: tmp
    } do
      # `/var/folders/…` is the ordinary shape of a temporary directory on macOS and `/var`
      # is a link; a store under such a root was unreadable to the sealed child until the link
      # itself could be read. The link is named as one literal; the directories beside it are
      # not, and a root with no link on its way names nothing.
      real = Path.join(tmp, "real")
      File.mkdir_p!(real)
      File.ln_s!(real, Path.join(tmp, "link"))
      spelled = Path.join([tmp, "link", "store"])
      File.mkdir_p!(spelled)

      policy = Sandbox.helper_policy(readable: [spelled], writable: [], scratch: "/opt/scratch")

      # `helper_policy/1` keeps the canonical spelling too; only the spelled one has a link.
      links = SandboxExec.links(policy)
      assert Path.join(tmp, "link") in links
      refute real in links
      refute spelled in links

      profile = SandboxExec.profile(policy)
      parameters = SandboxExec.parameters(policy)
      index = Enum.find_index(links, &(&1 == Path.join(tmp, "link")))
      assert profile =~ ~s[(allow file-read-metadata (literal (param "OURO_LINK_#{index}")))]
      assert "OURO_LINK_#{index}=#{Path.join(tmp, "link")}" in parameters
      refute profile =~ ~s[(allow file-read-metadata (subpath]

      # A root that is spelled canonically adds no line of its own. The platform roots may:
      # on a merged-`/usr` Linux `/bin`, `/lib`, `/lib64` and `/sbin` are themselves symlinks
      # into `/usr` (the shape lesson W16 learned for bubblewrap), so the comparison is against
      # what the platform alone contributes, not against nothing.
      platform = Sandbox.helper_policy(readable: [], writable: [], scratch: "/opt/scratch")
      plain = Sandbox.helper_policy(readable: [real], writable: [], scratch: "/opt/scratch")
      assert SandboxExec.links(plain) == SandboxExec.links(platform)
      refute Path.join(tmp, "link") in SandboxExec.links(plain)

      assert Enum.count(SandboxExec.links(platform), &String.starts_with?(&1, tmp)) == 0
    end

    test "bubblewrap binds only the named roots and never `/`", %{policy: policy} do
      options = Bwrap.options(%{}, policy, true)

      refute Enum.chunk_every(options, 3, 1, :discard)
             |> Enum.any?(&(&1 == ["--ro-bind", "/", "/"]))

      assert "--die-with-parent" in options
      assert "--unshare-net" in options
      assert "--tmpfs" in options
    end

    test "and it ro-binds the helper's own directory, which is why that root is in the set" do
      # W16 MEDIUM-8. A mutation dropping the helper binary's directory from
      # `Ouroboros.Wasm.Pool`'s readable roots stayed green on macOS: Seatbelt's
      # `(allow process-exec)` does not need the file readable to `execve` it, so the comment
      # that used to justify the root ("`process-exec` still has to read the executable") was
      # false there. It is a **Linux** requirement — bubblewrap builds a namespace, and a
      # binary that is not bound into it is not there to run — so this is where it is pinned.
      #
      # `Bwrap.options/3` filters the readable list to what is on disk, so the root used here
      # is one that exists on every machine this suite runs on.
      here = Path.dirname(__ENV__.file)

      binds =
        Sandbox.helper_policy(readable: [here], writable: [], scratch: "/opt/scratch")
        |> then(&Bwrap.options(%{}, &1, true))
        |> Enum.chunk_every(3, 1, :discard)

      assert ["--ro-bind", here, here] in binds,
             "the helper's own directory is not bound into the namespace"

      refute ["--bind", here, here] in binds, "a readable root must not be writable"
    end

    test "the two Linux backends render a sealed policy exactly as an open one (W21)", %{
      policy: sealed
    } do
      # Neither can express the seal: bubblewrap's namespace has `/usr/bin` readable and
      # executable, and Landlock fences neither `execve` nor `stat`. So the honest rendering is
      # the builder's, byte for byte, and the pool's status is what says `open` on such a
      # node rather than a profile that claimed otherwise.
      open = %{sealed | process: :open}
      assert sealed.process == :sealed

      assert Bwrap.options(%{}, sealed, true) == Bwrap.options(%{}, open, true)
      assert Bwrap.options(%{}, sealed, false) == Bwrap.options(%{}, open, false)
      assert Helper.request(sealed, %{}) == Helper.request(open, %{})

      # And the request carries no field the helper would refuse as unknown.
      refute Map.has_key?(Helper.request(sealed, %{}), "process")
    end
  end

  describe "and the kernel agrees, on Seatbelt (W21)" do
    # Every test here runs the same command twice: sealed, under the real
    # `Sandbox.helper_policy/1`, and open, under `Sandbox.builder_policy/1` with the same
    # roots and scratch. The pair is the proof; one half alone is a broken `bash`.
    setup %{tmp_dir: tmp} do
      scratch = Path.join(tmp, "scratch")
      File.mkdir_p!(scratch)
      File.chmod!(scratch, 0o700)

      sealed = Sandbox.helper_policy(readable: [], writable: [], scratch: scratch)

      open =
        Sandbox.builder_policy(readable: [], writable: [])
        |> Sandbox.with_scratch(scratch)

      %{scratch: scratch, sealed: sealed, open: open}
    end

    @tag @seatbelt
    @tag :tmp_dir
    test "exec of another binary is denied, and so is a fork", context do
      # `exec` is bash's builtin that replaces the process without forking, so what this
      # measures is the exec literal and nothing in front of it.
      {sealed, 1} = run(context.sealed, ["/bin/bash", "-c", "exec /usr/bin/id"])
      assert sealed =~ "Operation not permitted"
      refute sealed =~ "uid="

      {open, 0} = run(context.open, ["/bin/bash", "-c", "exec /usr/bin/id"])
      assert open =~ "uid="

      # A `$(…)` is a fork before it is anything else, and the profile has no `process-fork`.
      {forked, _status} =
        run(context.sealed, ["/bin/bash", "-c", "x=$(/usr/bin/id); echo got=$x"])

      assert forked =~ "fork: Operation not permitted"
      refute forked =~ "got=uid="

      {unforked, 0} = run(context.open, ["/bin/bash", "-c", "x=$(/usr/bin/id); echo got=$x"])
      assert unforked =~ "got=uid="
    end

    @tag @seatbelt
    @tag :tmp_dir
    test "`osascript`'s `do shell script` cannot leave the sandbox, even as the target itself",
         context do
      # The exact escape D25 named while the process was open: `do shell script` runs its
      # command *outside* the sandbox. As the sealed target, `osascript` runs — it is the one
      # allowed exec — but the scripting addition that implements `do shell script` is a
      # mach service and a fork away, and the script fails to compile.
      script = ~s(do shell script "id")
      {sealed, status} = run(context.sealed, ["/usr/bin/osascript", "-e", script])
      assert status != 0
      refute sealed =~ "uid="

      {open, 0} = run(context.open, ["/usr/bin/osascript", "-e", script])
      assert open =~ "uid="
    end

    @tag @seatbelt
    @tag :tmp_dir
    test "the pasteboard is out of reach: no `mach-lookup`", context do
      # `pbpaste` is the pasteboard over mach, which is the reach D25 named. Chosen over
      # `launchctl list` because that one exits non-zero under the *open* profile too on this
      # macOS and so proves nothing; `pbpaste` answers 0 wherever a pasteboard server runs —
      # a logged-in session, which a hosted macOS runner is — and 1 where it cannot look one
      # up, which is the sealed half and is deterministic anywhere.
      {_sealed, status} = run(context.sealed, ["/usr/bin/pbpaste"])
      assert status != 0

      {_open, 0} = run(context.open, ["/usr/bin/pbpaste"])
    end

    @tag @seatbelt
    @tag :tmp_dir
    test "no existence oracle: a file outside the roots is absent, not denied",
         %{tmp_dir: tmp} = context do
      # Outside every readable root and outside the scratch: `tmp` itself is neither.
      planted = Path.join(tmp, "planted")
      File.write!(planted, "here")

      # Quoted: ExUnit's `tmp_dir` carries the test's name, parentheses included.
      probe = ["/bin/bash", "-c", "test -e '#{planted}'; echo rc=$?"]

      {sealed, 0} = run(context.sealed, probe)
      assert sealed =~ "rc=1", "a sealed child could stat a path it may not read"

      {open, 0} = run(context.open, probe)
      assert open =~ "rc=0"

      # And inside a readable root `stat` still works, because `file-read*` implies it there:
      # the seal took the oracle away, not the reads.
      {inside, 0} = run(context.sealed, ["/bin/bash", "-c", "test -e /usr/bin/id; echo rc=$?"])
      assert inside =~ "rc=0"
    end

    @tag @seatbelt
    @tag :tmp_dir
    test "a root reached through a symlink is readable by that spelling, and the link is no oracle",
         %{tmp_dir: tmp, scratch: scratch} do
      # The shape every wasm suite's store has on this machine — `/var/folders/…` — made
      # local: a root spelled through a link this test made.
      real = Path.join(tmp, "real")
      File.mkdir_p!(real)
      File.ln_s!(real, Path.join(tmp, "link"))
      spelled = Path.join([tmp, "link", "store"])
      File.mkdir_p!(spelled)
      File.write!(Path.join(spelled, "component.wasm"), "bytes")
      File.write!(Path.join(tmp, "beside"), "beside the link, outside the roots")

      policy = Sandbox.helper_policy(readable: [spelled], writable: [], scratch: scratch)

      # Readable under the spelling the caller used — which is the one the pool hands the
      # helper — and under the kernel's.
      {output, 0} = run(policy, ["/bin/cat", Path.join(spelled, "component.wasm")])
      assert output == "bytes"
      {output, 0} = run(policy, ["/bin/cat", Path.join([real, "store", "component.wasm"])])
      assert output == "bytes"

      # Mutation: without the link's literal — `links/1` returning `[]` — the spelled read is
      # `Operation not permitted` (measured). And the literal is the link and nothing beside it:
      # a file next to the link, outside every root, is still absent.
      {beside, 0} =
        run(policy, ["/bin/bash", "-c", "test -e '#{Path.join(tmp, "beside")}'; echo rc=$?"])

      assert beside =~ "rc=1"
    end

    @tag @seatbelt
    @tag @needs_helper
    @tag :tmp_dir
    test "the real helper answers `doctor` by its canonical path and through a symlink",
         %{tmp_dir: tmp} do
      helper = Ouroboros.Wasm.helper_path()
      {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize_file(helper)

      # A spelling that goes through a symlinked directory this test made, whatever
      # `helper_path/0` itself is on this machine.
      File.ln_s!(Path.dirname(canonical), Path.join(tmp, "link"))
      spelled = Path.join([tmp, "link", Path.basename(canonical)])

      scratch = Path.join(tmp, "scratch")
      File.mkdir_p!(scratch)
      File.chmod!(scratch, 0o700)

      policy =
        Sandbox.helper_policy(
          readable: [Path.dirname(canonical)],
          writable: [],
          scratch: scratch
        )

      # Mutation: drop the resolution in `SandboxExec.wrap/4` and the spelled half is red —
      # `execvp() … failed: Operation not permitted`, measured — while the canonical one
      # stays green.
      for target <- [canonical, spelled] do
        {output, status} = run(policy, [target, "doctor"])
        assert status == 0, "`doctor` failed under the sealed profile via #{target}: #{output}"
        assert {:ok, %{"usable" => true}} = JSON.decode(output)
      end
    end

    # The command under a policy, with the scratch as `$TMPDIR` and `/` as the working
    # directory — the one directory both profiles can read, so `bash` does not spend its
    # first line on a `getcwd` it is not allowed.
    defp run(policy, argv) do
      {:ok, {exe, args}} = Sandbox.wrap({:argv, argv}, %{}, policy, Sandbox.detect())
      System.cmd(exe, args, stderr_to_stdout: true, env: Sandbox.env(policy), cd: "/")
    end
  end

  # A policy with a fixed root count, so a profile golden is one text on every platform.
  defp fixed(process) do
    %{
      mode: :builder,
      process: process,
      readable: ["/opt/helper", "/opt/store"],
      writable: ["/opt/scratch"],
      protected: [],
      protected_segments: [],
      scratch: "/opt/scratch",
      network: false,
      loopback: false
    }
  end
end
