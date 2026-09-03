defmodule Ouroboros.Provider.Native.SandboxHelperPolicyTest do
  @moduledoc """
  `Sandbox.helper_policy/1`: the closed policy the `ouro-wasm` helper runs under (W16, D25).

  Contract C10 says this is `builder_policy/1`'s shape with the scratch attached, and that it
  adds **no backend arm** — `:builder` is this module's vocabulary for "closed by default on
  reads" and all three backends already implement it. So what is pinned here is the shape and
  the mode, and then that each backend renders it as the thing it already renders a build as.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Sandbox.Bwrap
  alias Ouroboros.Provider.Native.Sandbox.SandboxExec

  describe "the shape" do
    test "is the builder's, with the scratch attached and the network off" do
      policy =
        Sandbox.helper_policy(
          readable: ["/opt/store"],
          writable: [],
          scratch: "/opt/scratch"
        )

      # `:builder` and not a fourth mode. A helper arm would be a fourth profile to keep in
      # step with three others, for a rule that is the same rule.
      assert policy.mode == :builder
      assert policy.network == false
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

      reach = fn policy ->
        {:ok, {exe, args}} =
          Sandbox.wrap(
            {:shell, "/usr/bin/nc -w 2 -z 127.0.0.1 #{port}; echo rc=$?"},
            %{},
            policy,
            detection
          )

        {output, _status} =
          System.cmd(exe, args, stderr_to_stdout: true, env: Sandbox.env(policy))

        String.contains?(output, "rc=0")
      end

      helper = Sandbox.helper_policy(readable: [tmp], writable: [], scratch: scratch)

      refute reach.(helper), "the helper policy let a child open a loopback socket"

      # The other half, and what makes the first half a fence rather than a broken `nc`: the
      # builder policy — the same shape, one field different — reaches the same listener.
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
      assert profile =~ ~s[(allow file-read-metadata (subpath "/"))]
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
  end
end
