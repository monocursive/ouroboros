defmodule Ouroboros.Gateway.LedgerTest do
  use ExUnit.Case, async: false

  @moduledoc """
  `ledger.list`, `ledger.get`, and `ledger.export` through `Methods.invoke/2`, including
  the two-node fan-out I3 is about.

  Every entry these tests write carries a principal unique to the test, so the assertions
  are about this test's rows rather than about whatever the rest of the suite left in the
  node's ledger. That matters: the ledger is one node-global process by design, and a test
  that asserted on its total would be asserting about the seed ExUnit happened to pick.
  """

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Cluster
  alias Ouroboros.Gateway.Methods

  @moduletag :capture_log

  setup do
    {:ok, principal: "ledger-test-#{System.unique_integer([:positive])}"}
  end

  defp record!(principal, id, overrides \\ %{}, target \\ nil) do
    attrs =
      Map.merge(
        %{
          id: id,
          effect: :permission,
          principal: principal,
          attempt: %{tool: "Bash", mode: :prompt, provider: :claude_code},
          authority: %{decision: :allow},
          cause: %{signal_id: id},
          result: %{decision: :allow, scope: :once, actor: :human}
        },
        overrides
      )

    case target do
      nil ->
        {:ok, entry, _created} = EffectLedger.record_settled(attrs)
        entry

      node ->
        {:ok, entry, _created} =
          :erpc.call(node, EffectLedger, :record_settled, [attrs, EffectLedger])

        entry
    end
  end

  test "the three verbs are read scope: reading history changes nothing" do
    for name <- ["ledger.list", "ledger.get", "ledger.export"] do
      assert name in Methods.names()
      assert {:ok, %{scope: :read}} = Methods.fetch(name)
    end
  end

  test "list answers entries beside the nodes that were asked", context do
    entry = record!(context.principal, "effect-#{context.principal}-1")

    assert {:ok, answer} =
             Methods.invoke("ledger.list", %{"principal" => context.principal})

    assert Enum.map(answer.entries, & &1.id) == [entry.id]
    assert answer.nodes == [%{node: node(), status: :ok}]
  end

  test "the filters a client sends are the ledger's own", context do
    record!(context.principal, "effect-#{context.principal}-a")

    denied =
      record!(
        context.principal,
        "effect-#{context.principal}-b",
        %{result: nil, error: :refused}
      )

    assert {:ok, %{entries: [entry]}} =
             Methods.invoke("ledger.list", %{
               "principal" => context.principal,
               "effect" => "permission",
               "limit" => 1
             })

    # Newest first by default, and `denied` was written second.
    assert entry.id == denied.id

    assert {:ok, %{entries: entries}} =
             Methods.invoke("ledger.list", %{
               "principal" => context.principal,
               "order" => "asc"
             })

    assert Enum.map(entries, & &1.id) == [
             "effect-#{context.principal}-a",
             "effect-#{context.principal}-b"
           ]

    assert {:ok, %{entries: [^entry]}} =
             Methods.invoke("ledger.list", %{
               "principal" => context.principal,
               "since_sequence" => entry.sequence - 1
             })
  end

  test "an effect or status this build does not record is a parameter error" do
    assert {:error, -32_602, message} =
             Methods.invoke("ledger.list", %{"effect" => "rm_minus_rf"})

    assert message =~ "params.effect must be one of"
    assert message =~ "permission"

    assert {:error, -32_602, status_message} =
             Methods.invoke("ledger.list", %{"status" => "probably"})

    assert status_message =~ "params.status must be one of"
    # Matched against terms that already exist rather than converted into one.
    refute :rm_minus_rf in EffectLedger.effects()
  end

  test "the limit is the ledger's own bound, not a second one" do
    limits = EffectLedger.query_limits()

    assert {:error, -32_602, message} =
             Methods.invoke("ledger.list", %{"limit" => limits.max + 1})

    assert message =~ "between 1 and #{limits.max}"
    assert {:ok, %{entries: _entries}} = Methods.invoke("ledger.list", %{"limit" => limits.max})
  end

  test "get resolves one stable id and says so when there is none", context do
    entry = record!(context.principal, "effect-#{context.principal}-get")

    assert {:ok, found} = Methods.invoke("ledger.get", %{"id" => entry.id})
    assert found.id == entry.id
    assert found.effect == :permission

    assert {:error, -32_007, _message} =
             Methods.invoke("ledger.get", %{"id" => "effect-that-was-never-written"})
  end

  test "export chains every line to the one before it, verifiably", context do
    record!(context.principal, "effect-#{context.principal}-x1")
    record!(context.principal, "effect-#{context.principal}-x2")

    assert {:ok, export} = Methods.invoke("ledger.export", %{})

    assert export.format == "jsonl"
    assert export.algorithm == "sha256"
    assert export.node == node()
    assert export.seed == String.duplicate("0", 64)
    assert export.count == length(export.lines)

    # The verification a client performs, performed here: hash the bytes you were handed,
    # in order, and compare. Nothing about how the runtime encodes an entry is needed.
    head =
      Enum.reduce(export.lines, export.seed, fn line, previous ->
        assert line.previous == previous

        expected =
          :sha256 |> :crypto.hash([previous, line.line]) |> Base.encode16(case: :lower)

        assert line.hash == expected
        # Every line is a decodable JSON object naming the entry it exports.
        assert JSON.decode!(line.line)["id"] == line.id

        expected
      end)

    assert export.head == head

    # A tampered line breaks the chain from that point on, which is the whole claim.
    [first | _rest] = export.lines
    tampered = String.replace(first.line, "\"status\":\"ok\"", "\"status\":\"denied\"")

    refute :sha256 |> :crypto.hash([export.seed, tampered]) |> Base.encode16(case: :lower) ==
             first.hash
  end

  test "export pages forward from a sequence", context do
    first = record!(context.principal, "effect-#{context.principal}-p1")

    assert {:ok, later} = Methods.invoke("ledger.export", %{"since" => first.sequence})
    refute Enum.any?(later.lines, &(&1.id == first.id))
    assert later.since == first.sequence
  end

  @tag :cluster
  test "fleet: true asks every connected core node and names the ones that did not answer",
       context do
    peer = start_app_peer!()

    local = record!(context.principal, "effect-#{context.principal}-local")
    remote = record!(context.principal, "effect-#{context.principal}-remote", %{}, peer)

    # The directory has to have seen the peer before the fan-out can target it.
    await(fn ->
      Enum.any?(Cluster.fleet_status().machines, &(&1.node == peer and &1.state == :connected))
    end)

    assert {:ok, answer} =
             Methods.invoke("ledger.list", %{
               "principal" => context.principal,
               "fleet" => true
             })

    assert Enum.sort(Enum.map(answer.nodes, & &1.node)) == Enum.sort([node(), peer])
    assert Enum.all?(answer.nodes, &(&1.status == :ok))

    # Sequences are minted per node, so what makes an entry addressable across the fleet is
    # the pair: every row carries the node it was written on.
    assert Enum.sort(Enum.map(answer.entries, &{&1.origin_node, &1.id})) ==
             Enum.sort([{node(), local.id}, {peer, remote.id}])

    # A machine that stops answering is a row saying so, never a shorter list that looks
    # complete. The directory still knows the peer, so the verb still targets it.
    :ok = :erpc.call(peer, Application, :stop, [:ouroboros])

    assert {:ok, %{entries: [], nodes: [%{node: ^peer, status: :unavailable} = row]}} =
             Methods.invoke("ledger.list", %{
               "principal" => context.principal,
               "node" => Atom.to_string(peer)
             })

    assert row.reason != nil
  end

  ## Peer plumbing, the same shape `Ouroboros.ClusterTest` uses.

  defp await(condition, attempts \\ 100) do
    Enum.reduce_while(1..attempts, false, fn _attempt, _accumulator ->
      if condition.(), do: {:halt, true}, else: Process.sleep(50) && {:cont, false}
    end)
    |> then(&assert(&1, "the fleet directory never reached the expected state"))
  end

  defp start_app_peer! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_ledger_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end

    name = String.to_atom("ouroboros_ledger_peer_#{System.unique_integer([:positive])}")

    {:ok, peer, peer_node} =
      :peer.start(%{
        name: name,
        args: Enum.flat_map(:code.get_path(), &[~c"-pa", &1]),
        wait_boot: 30_000
      })

    on_exit(fn -> stop_peer(peer) end)

    table = peer_node |> Atom.to_string() |> String.replace(~r/[^a-zA-Z0-9]/, "_")

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: String.to_atom(table)}
      ])

    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    _kind, _reason -> :ok
  end
end
