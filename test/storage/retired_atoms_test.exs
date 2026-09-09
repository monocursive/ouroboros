defmodule Ouroboros.Storage.RetiredAtomsTest do
  # A node upgraded onto the core reduction reads checkpoints an older build wrote.
  # `Ouroboros.Storage.DurableFile` decodes them with `[:safe]`, which refuses to create an
  # atom, so a file naming an atom this build deleted fails to decode *entirely* — and
  # both stores below are supervised children, so the node then does not boot.
  # `Ouroboros.Storage.RetiredAtoms` keeps those names interned; these tests are the proof
  # that it does, against bytes written before the reduction rather than against terms a
  # test built for itself (see `test/support/retired_atoms/README.md`).
  #
  # Nothing here writes a retired atom as a literal. That is the point: this file must not
  # be the reason the names exist.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.{Matcher, Request, Rule}
  alias Ouroboros.Storage.{DurableFile, RetiredAtoms}

  @fixtures Path.expand("../support/retired_atoms", __DIR__)

  # What the two committed checkpoints carry that this build would otherwise not have.
  # Strings, so reading this file does not create them.
  @fixture_names ~w(computer_use observe act desktop_action window_id)

  describe "a permission checkpoint written before the reduction" do
    setup do
      {:ok, engine: start_permissions!()}
    end

    test "loads with the surviving rules intact", %{engine: engine} do
      assert {:ok, rules} = Permissions.list([scope: :user], engine)

      assert rules |> Enum.map(& &1.pattern) |> Enum.sort() == [
               "Bash(ls *)",
               "ComputerUse(act)",
               "ComputerUse(app:com.apple.Calculator)",
               "ComputerUse(observe)"
             ]
    end

    test "still answers with the live rule beside the retired ones", %{engine: engine} do
      assert {:allow, %{pattern: "Bash(ls *)", scope: :user}} =
               Permissions.evaluate(%{tool: "bash", command: "ls -la"}, engine)
    end

    test "matches nothing with a rule whose kind this build retired", %{engine: engine} do
      assert {:ok, rules} = Permissions.list([scope: :user], engine)
      retired = Enum.reject(rules, &(&1.pattern == "Bash(ls *)"))
      assert length(retired) == 3

      # The request the three rules were written about: the desktop tool this build no
      # longer has, with the app the node used to resolve.
      request =
        Request.new(%{
          tool: "desktop_act",
          context: %{"app" => "com.apple.Calculator", "desktop_action" => "click"}
        })

      for rule <- retired, quantifier <- [:any, :all] do
        pattern = stored_pattern!(engine, rule.id)

        refute Matcher.matches?(pattern, request, quantifier),
               "#{rule.pattern} still decides something under #{quantifier}"
      end
    end

    test "keeps a retired rule listable and removable rather than quarantining it", %{
      engine: engine
    } do
      assert {:ok, rules} = Permissions.list([scope: :user], engine)
      assert [rule] = Enum.filter(rules, &(&1.pattern == "ComputerUse(act)"))

      assert rule.decision == :deny
      assert Atom.to_string(rule.kind) == "computer_use"

      assert :ok = Permissions.remove(:user, rule.id, engine)
      assert {:ok, remaining} = Permissions.list([scope: :user], engine)
      refute "ComputerUse(act)" in Enum.map(remaining, & &1.pattern)
    end
  end

  describe "an effect-ledger checkpoint written before the reduction" do
    test "loads and lists the entry with its retired subject keys" do
      ledger = start_ledger!()

      assert {:ok, [entry]} = EffectLedger.list([], ledger)
      assert entry.effect == :tool_call
      assert entry.status == :ok
      assert entry.attempt.tool == "desktop_act"

      keys = entry.attempt.subject |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort()
      assert keys == ["app", "desktop_action", "window_id"]

      assert %{retained: 1, next_sequence: 2} = EffectLedger.status(ledger)
    end
  end

  describe "the list itself" do
    test "holds every atom the committed fixtures need" do
      retired = MapSet.new(RetiredAtoms.all(), &Atom.to_string/1)

      assert MapSet.subset?(MapSet.new(@fixture_names), retired),
             "Ouroboros.Storage.RetiredAtoms no longer covers " <>
               inspect(Enum.reject(@fixture_names, &MapSet.member?(retired, &1)))
    end

    test "is exercised by them, so a thinner fixture cannot pass for a proof" do
      retired = MapSet.new(RetiredAtoms.all(), &Atom.to_string/1)

      in_fixtures =
        [permissions_fixture(), ledger_fixture()]
        |> Enum.flat_map(&(&1 |> File.read!() |> :erlang.binary_to_term([:safe]) |> atoms()))
        |> MapSet.new(&Atom.to_string/1)
        |> MapSet.intersection(retired)

      assert MapSet.equal?(in_fixtures, MapSet.new(@fixture_names))
    end

    test "is compiled into the adapter that decodes, not only into its own module" do
      assert DurableFile.retired_atoms() == RetiredAtoms.all()
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────────────────

  defp start_permissions!, do: start!(Permissions, "permissions")
  defp start_ledger!, do: start!(EffectLedger, "effect-ledger")

  # A copy, because a store that boots may checkpoint, and the fixture is a record of what
  # an older node wrote rather than a file this suite owns.
  defp start!(module, directory) do
    name = :"retired_atoms_#{directory}_#{System.unique_integer([:positive])}"
    path = Path.join(System.tmp_dir!(), "ouroboros-#{name}")
    File.mkdir_p!(path)
    File.cp_r!(Path.join(@fixtures, directory), path)
    on_exit(fn -> File.rm_rf(path) end)

    start_supervised!({module, name: name, storage: {DurableFile, path: path}}, id: name)
    name
  end

  defp permissions_fixture, do: fixture!("permissions")
  defp ledger_fixture, do: fixture!("effect-ledger")

  defp fixture!(directory) do
    [path] = Path.wildcard(Path.join([@fixtures, directory, "checkpoints", "*.term"]))
    path
  end

  # `Permissions.list/2` answers the wire projection, which renders a pattern as its text.
  # The parsed pattern the matcher is asked about comes from the server's own state.
  defp stored_pattern!(engine, id) do
    assert {:ok, rules} = GenServer.call(engine, :rules)
    assert %Rule{pattern: pattern} = Enum.find(rules, &(&1.id == id))
    pattern
  end

  defp atoms(term) when is_atom(term), do: [term]
  defp atoms(term) when is_list(term), do: Enum.flat_map(term, &atoms/1)
  defp atoms(term) when is_tuple(term), do: term |> Tuple.to_list() |> atoms()

  defp atoms(%module{} = term), do: [module | term |> Map.from_struct() |> atoms()]

  defp atoms(term) when is_map(term),
    do: Enum.flat_map(term, fn {key, value} -> atoms(key) ++ atoms(value) end)

  defp atoms(_term), do: []
end
