defmodule Ouroboros.Web.CommandsTest do
  @moduledoc """
  The catalogue, where it is pure.

  Every assertion here is about the *list*: that it is grouped the way the parity plan
  fixes, that a row is offered only where the runtime serves the method and the session
  is in a state that allows it, and that "nobody said" is not read as "no". The deck's own
  test proves the wiring; this proves the arithmetic behind what a palette is allowed to
  draw, which is where the honesty invariant actually lives.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Web.Commands
  alias Ouroboros.Web.Live.Rail
  alias Ouroboros.Web.Transcript.Cell

  @running %{running?: true, spoke?: true, failed?: false, turn_id: "t1", queued: 0}
  @idle %{running?: false, spoke?: true, failed?: false, turn_id: nil, queued: 0}

  defp assigns(overrides \\ %{}) do
    Map.merge(
      %{
        scope: :operate,
        open: {:interactive, "s1"},
        rows: [%Rail.Row{plane: :interactive, id: "s1", status: :running}],
        info: %{status: :running, options: %{}},
        turn: @idle,
        draft: "",
        approvals: [],
        truncated: 0,
        cells: %{}
      },
      overrides
    )
  end

  defp ids(assigns), do: assigns |> Commands.available() |> Enum.map(& &1.id)

  describe "the catalogue" do
    test "is the parity plan's five groups, in the parity plan's order" do
      assert Commands.groups() == [:session, :turn, :conversation, :runtime, :client]

      seen = Commands.all() |> Enum.map(& &1.group) |> Enum.uniq()

      assert seen == Commands.groups(),
             "every group appears, once, in order — a palette drawing a heading twice is #{inspect(seen)}"
    end

    test "every row carries the six fields a palette and a shortcut sheet read" do
      for command <- Commands.all() do
        assert %{id: id, label: label, group: group, slash: slash, gate: gate} = command
        assert is_binary(id) and id != ""
        assert is_binary(label) and label != ""
        assert group in Commands.groups()
        assert is_binary(slash) and String.starts_with?(slash, "/")
        assert is_function(gate, 1)
        assert Map.has_key?(command, :shortcut)
      end
    end

    test "ids are unique, because the run handler looks a row up by one" do
      ids = Enum.map(Commands.all(), & &1.id)
      assert ids == Enum.uniq(ids)
    end

    test "names the verbs the five groups promise" do
      by_group =
        Commands.all() |> Enum.group_by(& &1.group, &String.replace(&1.id, ~r/^[a-z]+\./, ""))

      assert "new" in by_group[:session]
      assert "switch" in by_group[:session]
      assert "rename" in by_group[:session]

      for verb <- ~w(send queue steer interrupt retry effort model plan sandbox approval) do
        assert verb in by_group[:turn], "the Turn group is missing #{verb}"
      end

      assert "copy" in by_group[:conversation]
      assert "copy_source" in by_group[:conversation]
      assert "status" in by_group[:runtime]
      assert "theme" in by_group[:client]
      assert "shortcuts" in by_group[:client]
    end
  end

  describe "the gates" do
    test "a read-scope endpoint is offered no verb that mutates anything" do
      offered = ids(assigns(%{scope: :read, draft: "go", turn: @running}))

      for id <- ~w(session.new session.rename turn.send turn.steer turn.interrupt turn.plan) do
        refute id in offered, "#{id} is drawn at read scope"
      end

      # What a reader can still do is still offered: nothing here is a mutation.
      assert "runtime.status" in offered
      assert "client.theme" in offered
    end

    test "interrupt appears only while a turn is running, and steer with it" do
      idle = ids(assigns(%{turn: @idle, info: %{status: :idle, options: %{}}, draft: "go"}))
      running = ids(assigns(%{turn: @running, draft: "go"}))

      refute "turn.interrupt" in idle
      refute "turn.steer" in idle
      assert "turn.interrupt" in running
      assert "turn.steer" in running
    end

    test "steer is hidden only by a declared false, never by silence" do
      silent = assigns(%{turn: @running, draft: "go", info: %{status: :running, options: %{}}})

      declared_no =
        assigns(%{
          turn: @running,
          draft: "go",
          info: %{status: :running, options: %{capabilities: %{steer: false}}}
        })

      declared_yes =
        assigns(%{
          turn: @running,
          draft: "go",
          info: %{status: :running, options: %{capabilities: %{steer: :native}}}
        })

      # An older gateway that never spoke about the key keeps the control: hiding a
      # working verb on silence would be this surface inventing a ceiling.
      assert "turn.steer" in ids(silent)
      assert "turn.steer" in ids(declared_yes)
      refute "turn.steer" in ids(declared_no)
    end

    test "send and queue are the same key at two different times, and never both" do
      idle = ids(assigns(%{turn: @idle, info: %{status: :idle, options: %{}}, draft: "go"}))
      running = ids(assigns(%{turn: @running, draft: "go"}))

      assert "turn.send" in idle
      refute "turn.queue" in idle
      assert "turn.queue" in running
      refute "turn.send" in running
    end

    test "nothing that sends the draft is offered when there is no draft" do
      empty = ids(assigns(%{turn: @running, draft: "   "}))

      refute "turn.send" in empty
      refute "turn.queue" in empty
      refute "turn.steer" in empty
    end

    test "ending and deleting are the two halves of a session's status, never both" do
      live = ids(assigns(%{info: %{status: :running, options: %{}}}))

      closed =
        ids(
          assigns(%{
            info: %{status: :closed, options: %{}},
            rows: [%Rail.Row{plane: :interactive, id: "s1", status: :closed}]
          })
        )

      assert "session.end" in live
      refute "session.delete" in live
      assert "session.delete" in closed
      refute "session.end" in closed
    end

    test "the conversation's copy rows need a message to copy" do
      refute "conversation.copy" in ids(assigns())

      with_message =
        assigns(%{
          cells: %{
            "event-1-0" => %{
              id: "event-1-0",
              index: 0,
              cell: %Cell.Message{speaker: :agent, text: "the answer"}
            }
          }
        })

      assert "conversation.copy" in ids(with_message)
      assert "conversation.copy_source" in ids(with_message)
    end

    test "a closed session offers nothing that would speak into it" do
      offered =
        ids(
          assigns(%{
            draft: "go",
            info: %{status: :closed, options: %{}},
            turn: @idle,
            rows: [%Rail.Row{plane: :interactive, id: "s1", status: :closed}]
          })
        )

      refute "turn.send" in offered
      refute "turn.steer" in offered
    end

    test "a gate that meets an assigns shape it does not know answers no, and does not raise" do
      # A palette that crashed the deck to draw a menu would turn a bug into an outage.
      assert Commands.available(%{}) |> Enum.map(& &1.id) |> Enum.sort() ==
               ~w(client.notifications client.shortcuts client.theme runtime.settings
                  session.switch)
    end
  end

  describe "search/2 and grouped/1" do
    test "an empty query is every row, unreordered" do
      rows = Commands.all()

      assert Commands.search(rows, "") == rows
      assert Commands.search(rows, nil) == rows
      assert Commands.search(rows, "   ") == rows
    end

    test "matches the label, the slash spelling and the group's own heading" do
      rows = Commands.all()

      assert Enum.any?(Commands.search(rows, "interrupt"), &(&1.id == "turn.interrupt"))
      assert Enum.any?(Commands.search(rows, "/audit"), &(&1.id == "runtime.audit"))

      # A query equal to a group name filters to that group, as the TUI palette does.
      assert Commands.search(rows, "conversation") |> Enum.map(& &1.group) |> Enum.uniq() ==
               [:conversation]
    end

    test "keeps catalogue order, which is what makes the selection index the screen row" do
      filtered = Commands.search(Commands.all(), "s")

      assert filtered == Enum.filter(Commands.all(), &(&1 in filtered))
    end

    test "groups in order, with an empty group drawn not at all" do
      grouped = Commands.grouped(Commands.search(Commands.all(), "/theme"))

      assert [{:client, [%{id: "client.theme"}]}] = grouped
    end
  end

  describe "last_agent_message/1" do
    test "is the newest agent message, with the dom id and the Markdown apart" do
      assigns =
        assigns(%{
          cells: %{
            "a" => %{id: "a", index: 0, cell: %Cell.Message{speaker: :agent, text: "first"}},
            "b" => %{id: "b", index: 1, cell: %Cell.Message{speaker: :you, text: "mine"}},
            "c" => %{id: "c", index: 2, cell: %Cell.Message{speaker: :agent, text: "# last"}}
          }
        })

      assert Commands.last_agent_message(assigns) == {"cells-c", "# last"}
    end

    test "is nothing where the drawn window holds no agent message" do
      assert Commands.last_agent_message(assigns()) == nil

      only_mine =
        assigns(%{cells: %{"a" => %{id: "a", index: 0, cell: %Cell.Message{speaker: :you}}}})

      assert Commands.last_agent_message(only_mine) == nil
    end
  end
end
