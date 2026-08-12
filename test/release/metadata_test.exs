defmodule Ouroboros.Release.MetadataTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Release.Metadata

  test "builds deterministic rel, appup, and relup terms without writing anything" do
    assert {:ok, rel} =
             Metadata.rel("ouroboros", "0.2.0", [
               {:kernel, "11.0.2"},
               {:stdlib, "7.0.1"},
               {:sasl, "4.4"},
               {:ouroboros, "0.2.0"}
             ])

    assert {:ok, %{name: "ouroboros", version: "0.2.0"}} = Metadata.validate_rel(rel)

    transitions = [{"0.1.0", "upgrade", [{:load_module, Ouroboros}]}]
    assert {:ok, appup} = Metadata.appup("0.2.0", transitions, [])
    assert {:ok, %{version: "0.2.0"}} = Metadata.validate_appup(appup)

    relup_transitions = [{"0.1.0", "upgrade", [:point_of_no_return]}]
    assert {:ok, relup} = Metadata.relup("0.2.0", relup_transitions, [])
    assert {:ok, %{version: "0.2.0"}} = Metadata.validate_relup(relup)
    assert Metadata.encode(relup) == Metadata.encode(relup)
  end

  test "transition summaries expose approval-relevant dangerous operations" do
    assert {:ok, summary} =
             Metadata.validate_relup(
               {~c"0.2.0",
                [
                  {~c"0.1.0", ~c"upgrade",
                   [
                     {:load, {Ouroboros, :brutal_purge, :soft_purge}},
                     {:apply, {Application, :put_env, [:ouroboros, :mode, :upgraded]}},
                     :point_of_no_return,
                     :restart_emulator
                   ]}
                ], []}
             )

    [transition] = summary.upgrades
    assert transition.brutal_purge?
    assert transition.point_of_no_return?
    assert transition.restart?
    assert transition.applies == [%{module: Application, function: :put_env, arity: 3}]
  end

  test "rejects duplicate applications, transition versions, and unknown instructions" do
    assert {:error, :duplicate_applications} =
             Metadata.rel("ouroboros", "0.2.0", [
               {:kernel, "11.0.2"},
               {:kernel, "11.0.3"}
             ])

    assert {:error, :duplicate_transition_versions} =
             Metadata.appup(
               "0.2.0",
               [
                 {"0.1.0", "one", [{:load_module, Ouroboros}]},
                 {"0.1.0", "two", [{:load_module, Ouroboros}]}
               ],
               []
             )

    assert {:error, {:invalid_appup_instruction, {:run_shell, "echo nope"}}} =
             Metadata.appup("0.2.0", [{"0.1.0", "bad", [{:run_shell, "echo nope"}]}], [])
  end
end
