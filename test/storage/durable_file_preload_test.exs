defmodule Ouroboros.Storage.DurableFilePreloadTest do
  @moduledoc """
  A checkpoint's readability is a property of the build, not of the reading VM's boot order.

  `Ouroboros.Storage.DurableFile` decodes with `:erlang.binary_to_term(binary, [:safe])`,
  which refuses to *create* an atom, so a checkpoint decodes only if every atom in it is
  already interned in the reading VM. Under Elixir's default `:interactive` code loading —
  `mix run`, `make dev`, every test that boots a data directory — modules load on demand,
  so which atoms exist when a store first reads depends on which modules happened to load
  first. The integration fixture measured between 36 and 117 `Ouroboros.*` modules loaded
  at the effect ledger's first read, run to run, against identical bytes.

  `Ouroboros.Agent.EffectLedger` is `Ouroboros.Application`'s child at `application.ex:150`
  and the atoms it stores in a refusal — `:unidentified_principal`,
  `:missing_effect_state`, `:missing_agent_state` — are spelled in exactly one module of
  this build, `Ouroboros.Agent.Effects.Runner`, which nothing loads before the ledger
  reads. The ledger quarantines a checkpoint it cannot decode and starts empty, so the
  cost is not a crash: it is the whole ledger, silently.

  Each boot below is a `:peer` node — a VM that has never interned those names — with
  `:ouroboros` loaded and not started, which is the state `mix run --no-start` and a
  release boot both leave the application controller in. Ten of them, each against its own
  copy of the same bytes, because a boot that fails quarantines the file and would
  otherwise poison the boots after it.

  Nothing here spells the three atoms as literals: they are read out of the module that
  owns them. If a later slice deletes `Runner`, this test fails at `Code.ensure_loaded!/1`
  rather than quietly becoming their only speller, which is what
  `Ouroboros.Storage.RetiredAtoms` exists to decide.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Storage.DurableFile

  @boots 10
  @speller Ouroboros.Agent.Effects.Runner
  @refusals ~w(unidentified_principal missing_effect_state missing_agent_state)

  @tag timeout: 600_000
  test "the effect ledger loads intact on ten fresh boots that have never interned its atoms" do
    ensure_distributed!()
    source = written_ledger!()
    expected = Enum.map(@refusals, &{:effect_denied, :delegate, String.to_existing_atom(&1)})

    outcomes =
      for boot <- 1..@boots do
        directory = copy_of!(source, boot)
        {peer, node} = start_peer!(boot)

        # The condition the whole test is about: on this VM the three names do not exist.
        for name <- @refusals, do: refute(peer_knows?(node, name), "peer already knows #{name}")

        outcome = {boot, load_ledger(node, directory), quarantined(directory)}

        # Stopped here rather than at exit: ten live peers would mesh through `:global`,
        # and this test is ten independent boots, not a cluster.
        :peer.stop(peer)
        outcome
      end

    intact =
      for {boot, {:ok, classifications}, []} <- outcomes, classifications == expected, do: boot

    assert length(intact) == @boots,
           "#{@boots - length(intact)} of #{@boots} boots lost the effect ledger.\n\n" <>
             Enum.map_join(outcomes, "\n", &describe/1)
  end

  defp describe({boot, loaded, quarantines}) do
    moved =
      case quarantines do
        [] -> ""
        files -> ", quarantined #{inspect(Enum.map(files, &Path.basename/1))}"
      end

    "  boot #{boot}: #{inspect(loaded)}#{moved}"
  end

  # The three refusal reasons, taken from the module that spells them rather than written
  # here. `Code.ensure_loaded!/1` is what makes `to_existing_atom/1` answerable in a test
  # VM that may not have loaded the runner yet — the same interning this fix is about.
  defp refusal_reasons do
    Code.ensure_loaded!(@speller)
    Enum.map(@refusals, &String.to_existing_atom/1)
  end

  # One ledger with three refused attempts, written by the ledger itself through
  # `DurableFile`, so the bytes are the ones a node would have written.
  defp written_ledger! do
    directory = tmp_dir!("source")
    name = :"preload_source_#{System.unique_integer([:positive])}"

    {:ok, ledger} =
      EffectLedger.start_link(name: name, storage: {DurableFile, path: directory})

    for {reason, index} <- Enum.with_index(refusal_reasons(), 1) do
      {:ok, _entry, :created} = EffectLedger.record_denied(refused(index, reason), name)
    end

    :ok = GenServer.stop(ledger)
    directory
  end

  defp refused(index, reason) do
    %{
      id: "preload-denied-#{index}",
      effect: :delegate,
      principal: "session:preload",
      claimed_from: "session:preload",
      attempt: %{team: "preload"},
      authority: %{
        decision: :denied,
        reason: :not_granted,
        constraints: %{},
        granted_at: "2026-09-09T00:00:00Z"
      },
      cause: %{signal_id: "signal-preload-#{index}", signal_type: "effect.delegate"},
      error: {:effect_denied, :delegate, reason}
    }
  end

  # Boots the ledger on the peer and answers with the refusal classifications it recovered,
  # oldest first. An unreadable checkpoint is quarantined by `Agent.EffectLedger`'s reader,
  # so the ledger starts — empty — rather than refusing to boot.
  defp load_ledger(peer, directory) do
    server = :preload_probe

    case :erpc.call(peer, GenServer, :start, [
           EffectLedger,
           [storage: {DurableFile, path: directory}],
           [name: server]
         ]) do
      {:ok, pid} ->
        {:ok, entries} =
          :erpc.call(peer, EffectLedger, :list, [[limit: 100, order: :asc], server])

        :ok = :erpc.call(peer, GenServer, :stop, [pid])
        {:ok, Enum.map(entries, & &1.error.classification)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp quarantined(directory) do
    directory |> Path.join("checkpoints/*.quarantined-*.term") |> Path.wildcard()
  end

  defp copy_of!(source, boot) do
    destination = tmp_dir!("boot-#{boot}")
    File.rm_rf!(destination)
    {:ok, _copied} = File.cp_r(source, destination)
    destination
  end

  defp start_peer!(boot) do
    name = :"ouro-preload-#{boot}-#{System.unique_integer([:positive])}"

    {:ok, peer, node} =
      :peer.start(%{
        name: name,
        args: Enum.flat_map(:code.get_path(), &[~c"-pa", &1]),
        wait_boot: 60_000
      })

    on_exit(fn ->
      try do
        :peer.stop(peer)
      catch
        _kind, _reason -> :ok
      end
    end)

    # What `mix run --no-start` and a release boot both leave behind: the application
    # controller has the application's spec, and none of its code is running. Loading the
    # `.app` interns the module *names*; the atoms inside those modules are the question.
    case :erpc.call(node, Application, :load, [:ouroboros]) do
      :ok -> :ok
      {:error, {:already_loaded, :ouroboros}} -> :ok
    end

    {peer, node}
  end

  # Asked with a binary on purpose: sending the atom would intern it on the peer and
  # destroy the only condition this test is about.
  defp peer_knows?(peer, name) do
    :erpc.call(peer, String, :to_existing_atom, [name])
    true
  rescue
    _error -> false
  catch
    _kind, _reason -> false
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      root = :"ouroboros_preload_root_#{System.unique_integer([:positive])}"
      {:ok, _pid} = :net_kernel.start([root, :shortnames])
    end

    :ok
  end

  defp tmp_dir!(suffix) do
    directory =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-preload-#{suffix}-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end
end
