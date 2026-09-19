defmodule Ouroboros.ClusterEpmdTest do
  @moduledoc """
  What `-epmd_module Elixir.Ouroboros.Cluster.Epmd` answers, callback by callback.

  `inet_tcp_dist` calls these from `net_kernel`, where a wrong answer is a node that
  cannot listen, cannot dial, or silently dials the wrong port. They are pure functions
  of two environment variables, so each answer is pinned here directly; the two-node
  proof in `Ouroboros.ClusterDistTlsTest` is the other half, and shows a real mesh formed
  through them with no port mapper anywhere.
  """
  # Both variables are process-global, so this module owns them for its duration rather
  # than sharing them with a concurrently running one.
  use ExUnit.Case, async: false

  alias Ouroboros.Cluster.Epmd

  @variables ["OUROBOROS_DIST_PORT", "OUROBOROS_DIST_PORTS"]

  setup do
    previous = Map.new(@variables, &{&1, System.get_env(&1)})
    Enum.each(@variables, &System.delete_env/1)

    on_exit(fn ->
      Enum.each(previous, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)

    :ok
  end

  describe "start_link/0 and register_node/2,3" do
    test "there is nothing to supervise and nothing to register" do
      assert Epmd.start_link() == :ignore

      # A creation distinguishes one incarnation of a node name from the last, which is
      # the only thing EPMD's registration ever gave this runtime.
      for answer <- [
            Epmd.register_node(~c"ouro-a", 13_700),
            Epmd.register_node(~c"ouro-a", 13_700, :inet),
            Epmd.register_node("ouro-a", 13_700, :inet6)
          ] do
        assert {:ok, creation} = answer
        assert creation in 1..3
      end

      # Registering twice is not a collision, because nothing was recorded: two nodes
      # that share a name fail at the distribution handshake, as they always did, not
      # here.
      assert {:ok, _creation} = Epmd.register_node(~c"ouro-a", 13_700)
      assert {:ok, _creation} = Epmd.register_node(~c"ouro-a", 13_701)
    end
  end

  describe "listen_port_please/2" do
    test "pins the listener to OUROBOROS_DIST_PORT" do
      System.put_env("OUROBOROS_DIST_PORT", "13700")
      assert Epmd.listen_port_please(~c"ouro-a", ~c"100.64.0.1") == {:ok, 13_700}
    end

    test "asks for nothing without it, which leaves the kernel's own range in charge" do
      assert Epmd.listen_port_please(~c"ouro-a", ~c"100.64.0.1") == {:ok, 0}

      # A value that is not a port is the same answer as no value: `inet_tcp_dist` would
      # otherwise crash `net_kernel` with a badarg on a typo in one environment variable.
      for invalid <- ["", "   ", "0", "65536", "-1", "thirteen", "13700,13701", "13700x"] do
        System.put_env("OUROBOROS_DIST_PORT", invalid)

        assert Epmd.listen_port_please(~c"ouro-a", ~c"100.64.0.1") == {:ok, 0},
               "#{inspect(invalid)} was accepted as a listen port"
      end

      # Surrounding whitespace is trimmed rather than refused, because an environment
      # written by a shell line is where it comes from.
      System.put_env("OUROBOROS_DIST_PORT", " 13700 ")
      assert Epmd.listen_port_please(~c"ouro-a", ~c"100.64.0.1") == {:ok, 13_700}
    end
  end

  describe "port_please/2,3" do
    test "reads the member's port out of the OUROBOROS_DIST_PORTS map" do
      System.put_env(
        "OUROBOROS_DIST_PORTS",
        "100.64.0.1=13700,100.64.0.2=13701,pi.internal=13702"
      )

      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == {:port, 13_701, 5}
      assert Epmd.port_please(~c"ouro-a", ~c"pi.internal") == {:port, 13_702, 5}

      # The timeout arity is the one `inet_tcp_dist` reaches for when it has one, and it
      # costs this lookup nothing.
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2", 5_000) == {:port, 13_701, 5}
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2", :infinity) == {:port, 13_701, 5}
    end

    test "the host may be a charlist, a binary or an IPv4 tuple" do
      System.put_env("OUROBOROS_DIST_PORTS", "100.64.0.2=13701")

      # Not the dial path — `address_please/3` answers the port there, before a host has
      # been resolved to an address. This callback still takes whatever shape a hand call
      # or another caller hands it, and folds all three to one key.
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == {:port, 13_701, 5}
      assert Epmd.port_please(~c"ouro-a", "100.64.0.2") == {:port, 13_701, 5}
      assert Epmd.port_please(~c"ouro-a", {100, 64, 0, 2}) == {:port, 13_701, 5}

      # And the name is accepted in either spelling, because nothing else about the
      # answer depends on it.
      assert Epmd.port_please("ouro-a", {100, 64, 0, 2}) == {:port, 13_701, 5}

      # An address that is not in the map is not this fleet's member.
      refute Epmd.port_please(~c"ouro-a", {100, 64, 0, 9}) == {:port, 13_701, 5}
    end

    test "falls back to OUROBOROS_DIST_PORT, which is the one-port-per-fleet case" do
      System.put_env("OUROBOROS_DIST_PORT", "13700")

      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == {:port, 13_700, 5}

      # The map wins where it has an answer, and the fallback covers the rest.
      System.put_env("OUROBOROS_DIST_PORTS", "100.64.0.2=13701")
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == {:port, 13_701, 5}
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.3") == {:port, 13_700, 5}
    end

    test "answers :noport when neither variable says anything" do
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == :noport
      assert Epmd.port_please(~c"ouro-a", {100, 64, 0, 2}, 5_000) == :noport

      # An empty map is not an answer either, and neither is one whose every entry is
      # unusable: a node with no way to dial says so rather than guessing a port.
      System.put_env("OUROBOROS_DIST_PORTS", "")
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == :noport

      System.put_env("OUROBOROS_DIST_PORTS", "garbage,,=13700,100.64.0.2=")
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.2") == :noport
    end

    test "a malformed entry is ignored and costs no other member its answer" do
      System.put_env(
        "OUROBOROS_DIST_PORTS",
        "100.64.0.1=13700,garbage,100.64.0.2=nope,=13701,100.64.0.3=0," <>
          "100.64.0.4=65536,100.64.0.5=13702=13703,100.64.0.6=13704"
      )

      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.1") == {:port, 13_700, 5}
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.6") == {:port, 13_704, 5}

      for unusable <- ["garbage", "100.64.0.2", "100.64.0.3", "100.64.0.4", "100.64.0.5"] do
        assert Epmd.port_please(~c"ouro-a", String.to_charlist(unusable)) == :noport,
               "#{unusable} was read out of a malformed entry"
      end

      # Whitespace around either half is the shell's, not the operator's.
      System.put_env("OUROBOROS_DIST_PORTS", " 100.64.0.7 = 13705 ")
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.7") == {:port, 13_705, 5}
    end

    test "two nodes on one host are told apart by a whole node name" do
      # The launcher writes one `name@host=port` entry per member, including this one. A
      # bare `host=port` entry is read too, as a fallback for a hand-written map, and a
      # node-name entry wins wherever the two disagree — which is what lets a lab, and
      # this suite, put two nodes on 127.0.0.1.
      System.put_env(
        "OUROBOROS_DIST_PORTS",
        "ouro-a@127.0.0.1=13710,ouro-b@127.0.0.1=13711,127.0.0.1=13712"
      )

      assert Epmd.port_please(~c"ouro-a", ~c"127.0.0.1") == {:port, 13_710, 5}
      assert Epmd.port_please(~c"ouro-b", {127, 0, 0, 1}) == {:port, 13_711, 5}

      # A node the map does not name reads the host's entry.
      assert Epmd.port_please(~c"ouro-c", ~c"127.0.0.1") == {:port, 13_712, 5}
    end

    test "the node-name entry wins whichever order the two are written in" do
      # The map is built before anything is looked up, so where an entry sits in the
      # string cannot decide which of two different keys answers.
      for map <- [
            "127.0.0.1=13712,ouro-a@127.0.0.1=13710",
            "ouro-a@127.0.0.1=13710,127.0.0.1=13712"
          ] do
        System.put_env("OUROBOROS_DIST_PORTS", map)

        assert Epmd.port_please(~c"ouro-a", ~c"127.0.0.1") == {:port, 13_710, 5},
               "the bare host key won in #{inspect(map)}"
      end
    end

    test "a trailing dot folds onto the same key, from either side" do
      # A node name may carry a fully qualified host while the profile's `host` may not,
      # and `valid_profile_host?/1` admits either, so the fold is applied to the map's own
      # keys as well as to the host being looked up.
      for {map, host} <- [
            {"ouro-a@pi.internal=13701", ~c"pi.internal."},
            {"ouro-a@pi.internal.=13701", ~c"pi.internal"},
            {"pi.internal.=13701", "pi.internal"},
            {"pi.internal=13701", "pi.internal."}
          ] do
        System.put_env("OUROBOROS_DIST_PORTS", map)

        assert Epmd.port_please(~c"ouro-a", host) == {:port, 13_701, 5},
               "#{inspect(host)} did not fold onto #{inspect(map)}"
      end
    end

    test "the first entry for a key is the answer a later duplicate cannot change" do
      System.put_env("OUROBOROS_DIST_PORTS", "100.64.0.1=13700,100.64.0.1=13799")
      assert Epmd.port_please(~c"ouro-a", ~c"100.64.0.1") == {:port, 13_700, 5}
    end
  end

  describe "address_please/3" do
    test "resolves the host, which is the one thing the port mapper never did" do
      assert Epmd.address_please(~c"ouro-a", ~c"127.0.0.1", :inet) == {:ok, {127, 0, 0, 1}}
      assert Epmd.address_please(~c"ouro-a", "127.0.0.1", :inet) == {:ok, {127, 0, 0, 1}}
      assert Epmd.address_please(~c"ouro-a", {127, 0, 0, 1}, :inet) == {:ok, {127, 0, 0, 1}}
      assert Epmd.address_please(~c"ouro-a", ~c"localhost", :inet) == {:ok, {127, 0, 0, 1}}

      # A name that does not resolve is an error tuple, never a raise: `inet_tcp_dist`
      # turns it into a refused connection and the dialer retries.
      assert {:error, _reason} =
               Epmd.address_please(
                 ~c"ouro-a",
                 ~c"ouroboros-no-such-host.invalid",
                 :inet
               )
    end

    test "answers the port too, because it is the last place that holds the host's text" do
      # This is the dial path. `inet_tcp_dist:fam_setup/4` calls this first and, unless it
      # answers a port, calls `port_please/2` with the address it just resolved — by which
      # point a member named by a private DNS name can no longer be found in a map keyed
      # by what the operator wrote. The four-tuple is what skips that step.
      System.put_env("OUROBOROS_DIST_PORTS", "ouro-a@127.0.0.1=13700,ouro-b@localhost=13701")

      assert Epmd.address_please(~c"ouro-a", ~c"127.0.0.1", :inet) ==
               {:ok, {127, 0, 0, 1}, 13_700, 5}

      # Two members that resolve to the same address are still two members, because the
      # lookup happens before the resolution collapses them.
      assert Epmd.address_please(~c"ouro-b", ~c"localhost", :inet) ==
               {:ok, {127, 0, 0, 1}, 13_701, 5}

      # A node the map does not name resolves without a port, which sends `inet_tcp_dist`
      # on to `port_please/2` and its `OUROBOROS_DIST_PORT` fallback — §4's chain, intact.
      assert Epmd.address_please(~c"ouro-c", ~c"127.0.0.1", :inet) == {:ok, {127, 0, 0, 1}}

      # And a host that does not resolve is an error even when the map names it: there is
      # no address to carry the port on.
      System.put_env("OUROBOROS_DIST_PORTS", "ouro-a@ouroboros-no-such-host.invalid=13700")

      assert {:error, _reason} =
               Epmd.address_please(~c"ouro-a", ~c"ouroboros-no-such-host.invalid", :inet)
    end
  end

  describe "names/1" do
    test "there is no registry to enumerate" do
      # The same answer `erl_epmd` gives for a host with no port mapper listening, so a
      # caller that already handles an absent EPMD handles this unchanged.
      assert Epmd.names(~c"127.0.0.1") == {:error, :address}
      assert Epmd.names({127, 0, 0, 1}) == {:error, :address}
      assert Epmd.names("localhost") == {:error, :address}
    end
  end
end
