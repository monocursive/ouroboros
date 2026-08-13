defmodule Ouroboros.Upgrade.ForgeBuildPeerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Beam
  alias Ouroboros.Upgrade.Forge.BuildPeer

  @module Ouroboros.Capability.PeerBuilt

  setup do
    on_exit(fn -> unload(@module) end)
    :ok
  end

  test "compiles a capability in a peer that never loads it into this VM" do
    assert {:ok, build} = BuildPeer.build(@module, capability_source(), capability_test_source())

    assert build.module == @module
    assert is_binary(build.binary)
    assert build.test_report.failures == 0
    assert build.test_report.total == 1
    assert build.test_report.ran

    # The binary is real: it inspects as the declared module and is a legal introduction.
    assert {:ok, %{module: @module}} = Beam.inspect_binary(build.binary)
    assert {:ok, beam} = Beam.introduce(@module, build.binary)
    assert beam.disposition == :introduce
    assert beam.sha256 == Beam.sha256(build.binary)

    # ...and it is still only a binary here. Compiling happened in another OS process, so
    # this VM has never heard the name.
    assert :code.which(@module) == :non_existing
    assert :code.get_object_code(@module) == :error
    refute Code.ensure_loaded?(@module)
  end

  test "the peer is not distributed and shares this VM's runtime" do
    assert {:ok, observed} =
             BuildPeer.with_peer(fn peer ->
               {:ok,
                %{
                  node: BuildPeer.call(peer, :erlang, :node, []),
                  alive: BuildPeer.call(peer, :erlang, :is_alive, []),
                  visible: BuildPeer.call(peer, Node, :list, []),
                  otp_release: BuildPeer.call(peer, :erlang, :system_info, [:otp_release]),
                  elixir: BuildPeer.call(peer, System, :version, []),
                  architecture:
                    BuildPeer.call(peer, :erlang, :system_info, [:system_architecture])
                }}
             end)

    # No node name, no distribution, no visible peers: generated code has nothing to
    # :erpc the production cluster with even if it tries.
    assert observed.node == :nonode@nohost
    assert observed.alive == false
    assert observed.visible == []

    # An artifact is verified against the loading node's exact runtime, so a peer that
    # did not match this one would produce binaries no node would accept.
    assert to_string(observed.otp_release) == to_string(:erlang.system_info(:otp_release))
    assert observed.elixir == System.version()

    assert to_string(observed.architecture) ==
             to_string(:erlang.system_info(:system_architecture))
  end

  test "a failing capability test is a named failure, not a binary" do
    failing = """
    defmodule Ouroboros.Capability.PeerBuiltTest do
      use ExUnit.Case, async: false

      test "insists on the wrong answer" do
        assert Ouroboros.Capability.PeerBuilt.double(2) == 5
      end
    end
    """

    assert {:error, {:capability_tests_failed, summary}} =
             BuildPeer.build(@module, capability_source(), failing)

    assert summary.total == 1
    assert summary.failures == 1
    assert summary.output =~ "insists on the wrong answer"

    assert :code.which(@module) == :non_existing
  end

  test "a compile error is a named failure and the peer does not survive it" do
    parent = self()

    result =
      BuildPeer.with_peer(fn peer ->
        send(parent, {:peer, peer})

        BuildPeer.call(peer, Ouroboros.Upgrade.Forge.Sandbox, :compile_and_test, [
          @module,
          "defmodule #{inspect(@module)} do\n  def broken, do: undefined_thing\nend\n",
          nil
        ])
      end)

    assert {:error, {:compile_failed, diagnostics}} = result
    assert diagnostics.message =~ "cannot compile module"
    assert Enum.any?(diagnostics.diagnostics, &(&1.severity == :error))
    assert Enum.any?(diagnostics.diagnostics, &(&1.message =~ "undefined_thing"))

    assert_received {:peer, peer}
    wait_until_dead!(peer)
    assert :code.which(@module) == :non_existing
  end

  test "an unexpected extra module is refused: a capability is exactly one BEAM" do
    nested = """
    defmodule #{inspect(@module)} do
      @vsn 1
      def double(n), do: n * 2

      defmodule Helper do
        def help, do: :ok
      end
    end
    """

    assert {:error, {:unexpected_modules, modules}} = BuildPeer.build(@module, nested, nil)
    assert Ouroboros.Capability.PeerBuilt.Helper in modules
    unload(Ouroboros.Capability.PeerBuilt.Helper)
  end

  test "the build deadline kills the callback and stops the peer anyway" do
    parent = self()

    result =
      BuildPeer.with_peer(
        fn peer ->
          send(parent, {:peer, peer})
          BuildPeer.call(peer, :timer, :sleep, [30_000], 30_000)
        end,
        timeout: 1_500
      )

    assert {:error, {:build_timeout, _remaining}} = result

    assert_received {:peer, peer}
    wait_until_dead!(peer)
  end

  test "a peer that cannot boot is reported rather than raised" do
    assert {:error, {:build_peer_start_failed, _reason}} =
             BuildPeer.with_peer(fn _peer -> :never end, boot_timeout: 1, timeout: 1_000)
  end

  defp capability_source do
    """
    defmodule #{inspect(@module)} do
      @vsn 1

      def double(n) when is_integer(n), do: n * 2
    end
    """
  end

  defp capability_test_source do
    """
    defmodule Ouroboros.Capability.PeerBuiltTest do
      use ExUnit.Case, async: false

      test "doubles" do
        assert Ouroboros.Capability.PeerBuilt.double(21) == 42
      end
    end
    """
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp wait_until_dead!(pid) do
    reference = Process.monitor(pid)
    assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, 5_000
    :ok
  end
end
