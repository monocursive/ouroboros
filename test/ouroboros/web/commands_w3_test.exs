defmodule Ouroboros.Web.CommandsW3Test do
  @moduledoc """
  W3.12. The ten rows this slice adds, and the two questions each of their gates asks.

  Every test here deletes one half of one gate and expects the row to vanish or stand —
  which is the mutation a reviewer will run. The deck's own test proves the wiring; this
  proves the arithmetic behind what a palette is *allowed* to draw, because that is where
  the honesty invariant lives: a verb this runtime cannot serve is not listed, and a verb
  it can is not hidden on silence.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Web.Commands
  alias Ouroboros.Web.Live.Rail
  alias Ouroboros.Web.Watch

  @idle %{running?: false, spoke?: true, failed?: false, turn_id: nil, queued: 0}

  # The rows W3 adds, by the group the parity plan puts them in.
  @w3_rows %{
    session: ~w(session.fork session.handoff),
    turn: ~w(turn.shell),
    conversation:
      ~w(conversation.details conversation.export conversation.backtrack conversation.rewind
         conversation.compact conversation.context),
    runtime: ~w(runtime.mcp)
  }

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

  defp all_w3, do: @w3_rows |> Map.values() |> List.flatten()

  # ------------------------------------------------------------------------------------
  # The rows exist, in the groups the plan fixes
  # ------------------------------------------------------------------------------------

  describe "the catalogue gained the remaining verbs" do
    test "each new row sits in the group the parity plan names" do
      by_id = Map.new(Commands.all(), &{&1.id, &1})

      for {group, rows} <- @w3_rows, id <- rows do
        row = Map.get(by_id, id)
        assert row, "the catalogue has no #{id}"

        assert row.group == group,
               "#{id} is in #{row.group}, and the parity plan puts it in #{group}"
      end
    end

    test "and every one of them can actually run on a live native session" do
      offered = ids(assigns())

      for id <- all_w3() do
        assert id in offered, "#{id} is not offered on an open, running native session"
      end
    end

    test "the palette still draws each group heading once, in order" do
      seen = Commands.all() |> Enum.map(& &1.group) |> Enum.uniq()
      assert seen == Commands.groups()
    end
  end

  # ------------------------------------------------------------------------------------
  # Half one: served at this scope
  # ------------------------------------------------------------------------------------

  describe "the served-at-this-scope half" do
    test "read scope is offered no verb that mutates the runtime" do
      offered = ids(assigns(%{scope: :read}))

      for id <- ~w(session.fork session.handoff turn.shell conversation.compact
                   conversation.rewind) do
        refute id in offered, "#{id} is drawn at read scope, and its method is operate-scope"
      end
    end

    test "and is still offered the three that only read" do
      offered = ids(assigns(%{scope: :read}))

      for id <- ~w(conversation.details conversation.export conversation.context runtime.mcp) do
        assert id in offered,
               "#{id} is withheld at read scope, and `Ouroboros.Web.Call` says it may run"
      end
    end

    test "a scope this build does not recognise offers nothing at all" do
      offered = ids(assigns(%{scope: :something_else}))

      for id <- all_w3(), do: refute(id in offered, "#{id} survived an unknown scope")
    end
  end

  # ------------------------------------------------------------------------------------
  # Half two: the session's own state
  # ------------------------------------------------------------------------------------

  describe "the session-state half" do
    test "nothing session-shaped is offered with no session open" do
      offered = ids(assigns(%{open: nil}))

      for id <- all_w3() -- ["runtime.mcp"] do
        refute id in offered, "#{id} is drawn with no session open"
      end
    end

    test "MCP is the one row that needs no session, because the verb has none to ask about" do
      assert "runtime.mcp" in ids(assigns(%{open: nil}))
    end

    test "an ended session takes no compaction, no handoff, no rewind and no command" do
      ended =
        assigns(%{
          rows: [%Rail.Row{plane: :interactive, id: "s1", status: :closed}],
          info: %{status: :closed, options: %{}}
        })

      offered = ids(ended)

      for id <- ~w(conversation.compact session.handoff conversation.rewind turn.shell) do
        refute id in offered, "#{id} is offered on a session that has ended"
      end
    end

    test "but its ledger can still be read, exported and forked" do
      ended =
        assigns(%{
          rows: [%Rail.Row{plane: :interactive, id: "s1", status: :closed}],
          info: %{status: :closed, options: %{}}
        })

      offered = ids(ended)

      for id <- ~w(conversation.details conversation.export conversation.context session.fork) do
        assert id in offered, "#{id} is withheld from a finished conversation it can still read"
      end
    end

    test "the watch's own `session_closed` ends it three seconds before the poll does" do
      watch = Watch.new() |> Watch.ended("closed")
      offered = ids(assigns(%{watch: watch}))

      refute "conversation.compact" in offered
      refute "turn.shell" in offered
    end
  end

  # ------------------------------------------------------------------------------------
  # The transport label, which is not a yes/no
  # ------------------------------------------------------------------------------------

  describe "native_transport?/1" do
    test "silence is offerable, because a gateway that never spoke set no ceiling" do
      assert Commands.native_transport?(assigns())
      assert Commands.native_transport?(assigns(%{info: %{options: %{capabilities: %{}}}}))
    end

    test "`native` is the one label that can, in either spelling" do
      for declared <- [:native, "native"] do
        assert Commands.native_transport?(
                 assigns(%{
                   info: %{status: :running, options: %{capabilities: %{transport: declared}}}
                 })
               )
      end
    end

    test "any other label cannot, and the four native verbs go with it" do
      managed =
        assigns(%{
          info: %{status: :running, options: %{capabilities: %{transport: "managed"}}}
        })

      refute Commands.native_transport?(managed)
      offered = ids(managed)

      for id <- ~w(conversation.compact conversation.rewind session.handoff) do
        refute id in offered, "#{id} is drawn on a transport that cannot honour it"
      end
    end

    test "and `context` is not one of them: every transport answers it" do
      managed =
        assigns(%{
          info: %{status: :running, options: %{capabilities: %{transport: "managed"}}}
        })

      assert "conversation.context" in ids(managed)
      assert "conversation.details" in ids(managed)
    end

    test "a capabilities map this build cannot read is silence, not a refusal" do
      assert Commands.native_transport?(assigns(%{info: %{options: %{capabilities: "?"}}}))
    end
  end

  # ------------------------------------------------------------------------------------
  # Fork, and the backtrack row that leads to it
  # ------------------------------------------------------------------------------------

  describe "forkable?/1" do
    test "a declared `fork: false` is the only value that withholds it" do
      refused =
        assigns(%{info: %{status: :running, options: %{capabilities: %{fork: false}}}})

      refute Commands.forkable?(refused)
      refute "session.fork" in ids(refused)
    end

    test "a mechanism name is a declaration that it can, including the word \"false\"" do
      for declared <- [:native, "native", "managed", "false"] do
        offered =
          assigns(%{info: %{status: :running, options: %{capabilities: %{fork: declared}}}})

        assert Commands.forkable?(offered), "fork: #{inspect(declared)} was read as a refusal"
      end
    end

    test "the backtrack row stands where either of its two verbs can run" do
      # Fork refused, but the conversation can still be spoken into: "edit and resend"
      # remains, and the dialog is worth opening for it.
      no_fork = assigns(%{info: %{status: :running, options: %{capabilities: %{fork: false}}}})
      assert "conversation.backtrack" in ids(no_fork)

      # Ended and fork refused: neither verb can run, so the row is not drawn.
      neither =
        assigns(%{
          rows: [%Rail.Row{plane: :interactive, id: "s1", status: :closed}],
          info: %{status: :closed, options: %{capabilities: %{fork: false}}}
        })

      refute "conversation.backtrack" in ids(neither)
    end

    test "read scope keeps neither half, so the row goes with them" do
      refute "conversation.backtrack" in ids(assigns(%{scope: :read}))
    end
  end

  # ------------------------------------------------------------------------------------
  # `!`
  # ------------------------------------------------------------------------------------

  describe "shell_offered?/1" do
    test "is the method and the session state, and nothing about the session's posture" do
      # `auto_approve` is deliberately not asked: a rule may permit the command and only
      # the permission engine knows that (`tui/src/ui/app/native.rs:96-101`).
      assert Commands.shell_offered?(assigns(%{info: %{options: %{approval_mode: "prompt"}}}))
    end

    test "and never at read scope, because `workspace.exec` is operate-scope" do
      refute Commands.shell_offered?(assigns(%{scope: :read}))
    end
  end

  # ------------------------------------------------------------------------------------
  # The slash column
  # ------------------------------------------------------------------------------------

  describe "the slash spellings" do
    test "match the terminal client's, and `!` is the one that is not a slash verb" do
      by_id = Map.new(Commands.all(), &{&1.id, &1.slash})

      assert by_id["conversation.details"] == "/details"
      assert by_id["conversation.export"] == "/export"
      assert by_id["conversation.rewind"] == "/rewind"
      assert by_id["conversation.compact"] == "/compact"
      assert by_id["conversation.context"] == "/context"
      assert by_id["session.fork"] == "/fork"
      assert by_id["session.handoff"] == "/handoff"
      assert by_id["runtime.mcp"] == "/mcp"
      assert by_id["turn.shell"] == "!"
    end

    test "no new key is claimed: the shortcut sheet is untouched by this slice" do
      for id <- all_w3() do
        row = Enum.find(Commands.all(), &(&1.id == id))
        assert is_nil(row.shortcut), "#{id} claims the key #{inspect(row.shortcut)}"
      end
    end
  end
end
