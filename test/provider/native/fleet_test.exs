defmodule Ouroboros.Provider.Native.FleetTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Cluster.Facts
  alias Ouroboros.Provider.Native.{Prompt, Tools}
  alias Ouroboros.Provider.Native.Tools.Fleet
  alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool

  test "facts are rolling safe and presence-only" do
    facts = Facts.local()
    assert is_binary(facts.os) and is_binary(facts.arch) and is_binary(facts.hostname)
    assert is_boolean(facts.provisionable)
    assert Enum.all?(facts.toolchains, &System.find_executable/1)
    posture = Ouroboros.Cluster.local_fleet_posture() |> Map.delete(:facts)
    assert Ouroboros.Cluster.valid_fleet_posture?(node(), posture)
    assert Facts.tags(%{}) == []
  end

  test "invalid tags produce an explicit error, including null and oversized lists" do
    assert Facts.validate_tags(["xcode", "ios-sim", "xcode"]) == %{tags: ["xcode", "ios-sim"]}

    for tags <- [
          [nil],
          ["BAD"],
          ["bad tag"],
          ["x\n"],
          [String.duplicate("x", 65)],
          List.duplicate("x", 33),
          nil
        ] do
      assert %{tags: [], tags_error: error} = Facts.validate_tags(tags)
      assert is_binary(error)
    end
  end

  test "live renderer keeps unknown facts and offline time explicit and caps machines" do
    old = %{
      machine: "old",
      node: :old@host,
      state: :offline,
      last_down_at: "2026-09-07",
      role: :core
    }

    machine = %{
      machine: "studio",
      node: :studio@host,
      state: :connected,
      role: :core,
      compatibility: :compatible,
      facts: %{
        os: "macos",
        arch: "aarch64",
        tags: ["xcode"],
        toolchains: ["git", "xcodebuild"],
        provisionable: true
      }
    }

    output = Fleet.render([old, machine])
    assert output =~ "offline since 2026-09-07 unknown/unknown"
    assert output =~ "tags: xcode toolchains: git xcodebuild provisionable: true"
    assert output =~ "workspace: PATH"
    assert output =~ "sync: true"

    refute Fleet.render(List.duplicate(machine, 64) ++ [%{old | machine: "beyond-cap"}]) =~
             "beyond-cap"
  end

  test "fleet executes as a read-only tool without input" do
    assert %{output: output, is_error: false} = Tools.execute(Fleet, %{}, %{}, 5_000)
    assert output =~ "Place work with agent"
    assert Tools.classify("fleet", %{}, %{root: System.tmp_dir!()}).mode == :read
  end

  test "prompt snapshot is optional and fleet schema follows distribution" do
    refute Prompt.base([]) =~ "## Fleet"

    assert Prompt.base(fleet: []) =~
             "as of when this session opened — call `fleet` for the live list"

    assert Prompt.base(fleet: []) =~ "Ignored files do not travel"
    refute Enum.any?(Tools.specs(nil, nil, distributed: false), &(&1.name == "fleet"))
    assert Enum.any?(Tools.specs(nil, nil, distributed: true), &(&1.name == "fleet"))
  end

  test "tag selection resolves only concrete connected nodes and explains ambiguity" do
    one = %{machine: "studio", node: :studio@host, state: :connected, facts: %{tags: ["xcode"]}}
    two = %{one | node: :other@host, machine: "other"}
    assert {:ok, :studio@host} = Facts.resolve("tag:xcode", [one])

    assert {:error, {:ambiguous_machine, [:other@host, :studio@host]}} =
             Facts.resolve("tag:xcode", [one, two])

    assert {:error, :unknown_machine} = Facts.resolve("tag:absent", [one])
    assert {:error, :unknown_machine} = Facts.resolve("tag:xcode", [%{one | state: :offline}])
    assert {:error, refusal} = AgentTool.resolve_machine("tag:absent", [node()])
    assert refusal =~ "Connected machines and tags"
  end
end
