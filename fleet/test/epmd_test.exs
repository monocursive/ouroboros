defmodule OuroFleet.EpmdTest do
  use ExUnit.Case, async: false
  alias OuroFleet.Epmd

  @repository Path.expand("../..", __DIR__)

  setup do
    saved = Map.new(["OUROBOROS_DIST_PORTS", "OUROBOROS_DIST_PORT"], &{&1, System.get_env(&1)})

    on_exit(fn ->
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)
  end

  test "every launcher names this module, and it exports what distribution calls" do
    # The node service (README) and the `ouro` client launcher spell the flag apart.
    for source <- ["docs/specs/fleet-v1/README.md", "crates/ouro/src/main.rs"] do
      text = File.read!(Path.join(@repository, source))
      assert [_, module] = Regex.run(~r/-epmd_module (\S+)/, text), source
      assert String.to_atom(module) == Epmd, "#{source} passes -epmd_module #{module}"
    end

    assert {:module, Epmd} = Code.ensure_loaded(Epmd)

    for {function, arity} <- [
          start_link: 0,
          register_node: 3,
          listen_port_please: 2,
          address_please: 3,
          port_please: 2,
          names: 1
        ] do
      assert function_exported?(Epmd, function, arity)
    end
  end

  test "each registration draws a full-width creation, so a restart is told apart" do
    creations = for _ <- 1..64, do: elem(Epmd.register_node(~c"ouro-a", 4370, :inet), 1)
    # 0..3 are never drawn, and 64 draws from four billion values collide with odds
    # below one in a million.
    assert Enum.all?(creations, &(&1 in 4..0xFFFFFFFF))
    assert length(Enum.uniq(creations)) == 64
  end

  test "a member's port is keyed by its node name, and an unnamed node falls back" do
    System.put_env(
      "OUROBOROS_DIST_PORTS",
      "ouro-a@127.0.0.1=4370,ouro-b@localhost.=4371,127.0.0.1=4999,bad,ouro-a@127.0.0.1=1"
    )

    System.put_env("OUROBOROS_DIST_PORT", "4380")

    assert {:ok, {127, 0, 0, 1}, 4370, 5} = Epmd.address_please(~c"ouro-a", ~c"127.0.0.1", :inet)
    assert {:ok, {127, 0, 0, 1}, 4999, 5} = Epmd.address_please("ouro-z", "127.0.0.1", :inet)
    assert {:ok, {127, 0, 0, 1}, 4371, 5} = Epmd.address_please(~c"ouro-b", ~c"localhost", :inet)
    assert {:port, 4370, 5} = Epmd.port_please(~c"ouro-a", {127, 0, 0, 1})
    assert {:ok, {127, 0, 0, 1}} = Epmd.address_please(~c"ouro-c", ~c"localhost", :inet)
    assert {:port, 4380, 5} = Epmd.port_please(~c"ouro-c", ~c"localhost")
    assert {:ok, 4380} = Epmd.listen_port_please(~c"ouro-a", ~c"127.0.0.1")
    System.delete_env("OUROBOROS_DIST_PORT")
    assert :noport = Epmd.port_please(~c"ouro-c", ~c"localhost")
    assert {:ok, 0} = Epmd.listen_port_please(~c"ouro-c", ~c"localhost")
  end
end
