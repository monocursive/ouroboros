defmodule Ouroboros.Storage.RetiredAtomsTest do
  # A node upgraded onto the core reduction reads checkpoints an older build wrote.
  # `Ouroboros.Storage.DurableFile` decodes them with `[:safe]`, which refuses to create an
  # atom, so a file naming an atom this build deleted fails to decode *entirely*. The
  # permission store, the effect ledger and the grant store are each a single file and each
  # a supervised child, so the node then does not boot; the interactive store quarantines
  # the one record instead and loses the session. `Ouroboros.Storage.RetiredAtoms` keeps
  # those names interned, and these tests are the proof, against bytes written before the
  # reduction rather than against terms a test built for itself (see the READMEs under
  # `test/support/retired_atoms/`).
  #
  # Nothing here writes a retired atom as a literal. That is the point: this file must not
  # be the reason the names exist.
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Grants
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Control.Permissions.{Matcher, Request, Rule}
  alias Ouroboros.EventPresentation
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Storage.{DurableFile, RetiredAtoms}

  @fixtures Path.expand("../support/retired_atoms", __DIR__)

  # What the four committed checkpoints carry that this build would otherwise not have.
  # Strings, so reading this file does not create them.
  @permissions_names ~w(computer_use observe act)
  @desktop_ledger_names ~w(desktop_action window_id)
  @ledger_names ~w(effect_denied unidentified_principal effect_failed delegation_setup_failed
                   coding_start coding_task_owner_conflict delivered delivering
                   Elixir.Ouroboros.Agent.Worker Elixir.Ouroboros.Agent.Coordinator)
  @grants_names ~w(Elixir.Ouroboros.Agent.Worker Elixir.Ouroboros.Agent.Coordinator)

  # Every name a committed `DurableFile` fixture holds. The session record below is base64
  # rather than a store, so it is guarded separately.
  @fixture_names @permissions_names ++ @desktop_ledger_names ++ @ledger_names ++ @grants_names

  # An interactive session's own `delegations` field, captured as base64 rather than as a
  # `DurableFile` directory because what matters about it is the nine names, not the store.
  # Its `Storage.Records` reader quarantines the record instead of failing the file, which
  # is a quieter loss than the ledger's, not a smaller one.
  @session_record "g3QAAAAJdwtkZWxlZ2F0aW9uc3cLZGVsZWdhdGlvbnN3CmRlbGVnYXRpb253CmRlbGVnYXRpb253B3RlYW1faWR3B3RlYW1faWR3CXRhc2tfbm9kZXcJdGFza19ub2RldxBvYmplY3RpdmVfZGlnZXN0dxBvYmplY3RpdmVfZGlnZXN0dw1yZXN1bHRfZGlnZXN0dw1yZXN1bHRfZGlnZXN0dwpkZWxpdmVyaW5ndwpkZWxpdmVyaW5ndwlkZWxpdmVyZWR3CWRlbGl2ZXJlZHcGY29kaW5ndwZjb2Rpbmc="
  @session_names ~w(delegations delegation team_id task_node objective_digest result_digest
                    delivering delivered coding)

  describe "a permission checkpoint written before the reduction" do
    setup do
      {:ok, engine: start!(Permissions, "permissions")}
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

  describe "an effect-ledger checkpoint a deleted desktop tool wrote" do
    test "loads and lists the entry with its retired subject keys" do
      ledger = start!(EffectLedger, "effect-ledger")

      assert {:ok, [entry]} = EffectLedger.list([], ledger)
      assert entry.effect == :tool_call
      assert entry.status == :ok
      assert entry.attempt.tool == "desktop_act"

      keys = entry.attempt.subject |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort()
      assert keys == ["app", "desktop_action", "window_id"]

      assert %{retained: 1, next_sequence: 2} = EffectLedger.status(ledger)
    end

    test "exports through the hash chain, with the retired keys as ordinary strings" do
      ledger = start!(EffectLedger, "effect-ledger")
      assert {:ok, entries} = EffectLedger.list([], ledger)

      # What `ledger.export` answers: `Present.ledger_export/2` is this over the same list.
      assert %{count: 1, lines: [%{line: line, hash: hash}]} = Methods.chain(entries)
      assert line =~ ~s("desktop_action":"click")
      assert line =~ ~s("window_id":"42")
      assert String.match?(hash, ~r/\A[0-9a-f]{64}\z/)
    end
  end

  describe "an interactive session record written before the reduction" do
    test "still decodes, with every name it carries on the list" do
      decoded = @session_record |> Base.decode64!() |> :erlang.binary_to_term([:safe])

      names = decoded |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort()

      assert names == Enum.sort(@session_names)
      assert MapSet.subset?(MapSet.new(names), retired_names())
    end

    test "the transcript type it carries presents as a named note rather than raising" do
      [type] = Enum.filter(RetiredAtoms.all(), &(Atom.to_string(&1) == "delegation"))

      assert %EventPresentation.ProviderNote{kind: "delegation"} =
               EventPresentation.from_event(%{type: type, payload: %{}})
    end
  end

  describe "an effect-ledger checkpoint the deleted agent-effect runner wrote" do
    setup do
      {:ok, ledger: start!(EffectLedger, "agent-effects")}
    end

    test "boots and lists every entry the deleted runner wrote", %{ledger: ledger} do
      assert {:ok, entries} = EffectLedger.list([], ledger)
      assert length(entries) == 5
      assert %{retained: 5, next_sequence: 6} = EffectLedger.status(ledger)
    end

    test "keeps the refusal's classification readable", %{ledger: ledger} do
      assert {:ok, [entry | _rest]} = EffectLedger.list([status: :denied], ledger)

      assert {denied, delegate, principal} = entry.error.classification

      assert Enum.map([denied, delegate, principal], &Atom.to_string/1) ==
               ["effect_denied", "delegate", "unidentified_principal"]
    end

    test "keeps a deleted module readable in an attempt, a result and an allow-list", %{
      ledger: ledger
    } do
      assert {:ok, [entry]} = EffectLedger.list([effect: :start_agent], ledger)

      assert Atom.to_string(entry.attempt.module) == "Elixir.Ouroboros.Agent.Worker"
      assert Atom.to_string(entry.result.module) == "Elixir.Ouroboros.Agent.Worker"

      assert entry.authority.constraints.modules |> Enum.map(&Atom.to_string/1) ==
               ["Elixir.Ouroboros.Agent.Worker", "Elixir.Ouroboros.Agent.Coordinator"]
    end

    test "keeps both retired values of a settled delegation's delivery", %{ledger: ledger} do
      assert {:ok, entries} = EffectLedger.list([effect: :delegate, status: :ok], ledger)

      assert entries
             |> Enum.map(&Atom.to_string(&1.result.delivery))
             |> Enum.sort() == ["delivered", "delivering"]
    end

    test "keeps a nested work failure readable three atoms deep", %{ledger: ledger} do
      assert {:ok, [entry]} = EffectLedger.list([effect: :delegate, status: :failed], ledger)

      assert {failed, delegate, {setup, stage, {conflict, _text}}} = entry.error.classification

      assert Enum.map([failed, delegate, setup, stage, conflict], &Atom.to_string/1) ==
               [
                 "effect_failed",
                 "delegate",
                 "delegation_setup_failed",
                 "coding_start",
                 "coding_task_owner_conflict"
               ]
    end
  end

  describe "a grant checkpoint written before the reduction" do
    test "loads, and the allow-list naming deleted modules is still an allow-list" do
      grants = start!(Grants, "grants")

      assert [start_agent] =
               "agent-alpha" |> Grants.list(grants) |> Enum.filter(&(&1.effect == :start_agent))

      assert start_agent.constraints.modules |> Enum.map(&Atom.to_string/1) |> Enum.sort() ==
               ["Elixir.Ouroboros.Agent.Coordinator", "Elixir.Ouroboros.Agent.Worker"]

      # A module that no longer exists still narrows: the allow-list admits it and nothing
      # else, so a stale grant is not a wider grant.
      [worker | _rest] = start_agent.constraints.modules
      assert Grants.granted?("agent-alpha", :start_agent, %{module: worker}, grants)
      refute Grants.granted?("agent-alpha", :start_agent, %{module: Ouroboros.Mesh}, grants)
    end
  end

  describe "the list itself" do
    test "holds every atom the committed fixtures need" do
      retired = retired_names()
      needed = @fixture_names ++ @session_names

      assert MapSet.subset?(MapSet.new(needed), retired),
             "Ouroboros.Storage.RetiredAtoms no longer covers " <>
               inspect(Enum.reject(needed, &MapSet.member?(retired, &1)))
    end

    test "is exercised by them, so a thinner fixture cannot pass for a proof" do
      in_fixtures =
        ["permissions", "effect-ledger", "agent-effects", "grants"]
        |> Enum.map(&fixture!/1)
        |> Enum.flat_map(&(&1 |> File.read!() |> :erlang.binary_to_term([:safe]) |> atoms()))
        |> MapSet.new(&Atom.to_string/1)
        |> MapSet.intersection(retired_names())

      assert MapSet.equal?(in_fixtures, MapSet.new(@fixture_names))
    end

    test "is compiled into the adapter that decodes, not only into its own module" do
      assert DurableFile.retired_atoms() == RetiredAtoms.all()
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────────────────

  defp retired_names, do: MapSet.new(RetiredAtoms.all(), &Atom.to_string/1)

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
