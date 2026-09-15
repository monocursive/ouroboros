defmodule Ouroboros.Web.Live.DeckMachineLabelsTest do
  @moduledoc """
  Two machines nobody named, from the cluster's own directory to the deck's rows.

  `Ouroboros.Web.Presentation.node_label/2` prefers the roster's label to its own string
  split, which is right — a fleet that knows what a machine is called knows better — and
  is exactly why the roster was where two computers became one word: the runtime used to
  label `ouro@alpha` and `ouro@beta` both `ouro`, the release half they share. The pure
  proofs in `presentation_labels_test.exs` and `layouts_test.exs` hand the deck a roster;
  this one lets the real monitor build it, and asserts across that seam that two rows get
  two words.

  Not async: the roster comes from the cluster's environment, which is process-global.
  """

  use ExUnit.Case, async: false

  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Layouts
  alias Ouroboros.Web.Live.DeckLive

  @alpha :ouro@alpha
  @beta :ouro@beta

  setup do
    previous =
      Map.new(
        ~w(OUROBOROS_CLUSTER_STRATEGY OUROBOROS_CLUSTER_HOSTS OUROBOROS_MACHINE_NAME),
        &{&1, System.get_env(&1)}
      )

    System.put_env("OUROBOROS_CLUSTER_STRATEGY", "epmd")
    System.put_env("OUROBOROS_CLUSTER_HOSTS", "ouro@alpha,ouro@beta")
    System.delete_env("OUROBOROS_MACHINE_NAME")

    on_exit(fn ->
      Enum.each(previous, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)

      # Leave the monitor's directory as this test found it, so a later test that counts
      # or names machines is not reading these fixtures.
      case Process.whereis(Ouroboros.Cluster.Monitor) do
        monitor when is_pid(monitor) ->
          :sys.replace_state(monitor, fn state ->
            %{state | machines: Map.drop(state.machines, [@alpha, @beta])}
          end)

        _absent ->
          :ok
      end
    end)

    :ok
  end

  test "two machines nobody named are two rows with two words" do
    # The same snapshot `runtime.status` answers the deck with, roster and all.
    rows = DeckLive.machines(Ouroboros.status())

    fixture = Enum.filter(rows, &(&1.name in ["ouro@alpha", "ouro@beta"]))
    assert Enum.map(fixture, & &1.label) == ["alpha", "beta"]
    refute Enum.any?(fixture, & &1.connected?)

    # And the bar draws the two words it was handed, never "ouro" twice.
    html = render_component(&Layouts.topbar/1, %{machines: rows})

    hidden =
      ~r/class="ouro-visually-hidden">([^<]*)</
      |> Regex.scan(html, capture: :all_but_first)
      |> List.flatten()
      |> Enum.map(&String.trim/1)

    assert "alpha" in hidden
    assert "beta" in hidden
    refute "ouro" in hidden
  end
end
