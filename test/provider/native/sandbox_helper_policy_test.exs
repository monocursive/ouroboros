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
  end
end
