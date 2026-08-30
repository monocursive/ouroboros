defmodule Ouroboros.Web.Live.RailTest do
  @moduledoc """
  The attention stack: which group a session lands in, in what order, and how it draws.

  The triage rules are a port of `SessionInfo::triage` (`tui/src/model.rs:237`) and
  `SessionsTab::triaged` (`tui/src/ui/app/session.rs:380`), and the reason they are tested
  this hard is that the whole page is an argument about ordering. If a session that needs a
  person can be pushed below eleven finished ones, the rail is worse than a flat list —
  because a flat list does not promise otherwise.

  Rows are built from plain maps rather than the planes' structs on purpose: what is under
  test is the rule, not the checkpoint format, and a test that had to construct a valid
  `%Ouroboros.Interactive.State{}` to assert a heading would break on every field added to
  a checkpoint.
  """

  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Live.DeckLive
  alias Ouroboros.Web.Live.Rail

  defp interactive(id, fields) do
    Rail.from_interactive(
      Enum.into(fields, %{
        id: id,
        node: :core@one,
        status: :idle,
        updated_at: "2026-08-29T12:00:00Z",
        provider: :claude_code,
        workspace: "/w",
        title: nil,
        options: %{},
        usage: %{},
        children: []
      })
    )
  end

  defp coding(id, fields \\ []) do
    Rail.from_coding(
      Enum.into(fields, %{
        id: id,
        node: :core@one,
        status: :running,
        updated_at: "2026-08-29T12:00:00Z",
        provider: :claude_code,
        workspace: "/w",
        objective: "do the thing",
        options: %{},
        parent: nil
      })
    )
  end

  defp groups(rows, pending \\ %{}) do
    rows |> Rail.triaged(pending) |> Enum.map(&{&1.group, &1.row.id, &1.depth})
  end

  # ------------------------------------------------------------------------------------

  describe "triage" do
    test "an unanswered approval outranks everything, including a terminal status" do
      row = interactive("a", status: :completed)

      assert Rail.triage_of(row, 0) == :settled
      assert Rail.triage_of(row, 1) == :needs_you
    end

    test "an approval the robot already answered is not a reason to interrupt anyone" do
      # The count is of *unanswered* approvals. A view holding an answered one and still
      # triaging its row to the top would make the top of the list mean nothing.
      assert Rail.triage_of(interactive("a", status: :running), 0) == :at_work
    end

    test "awaiting_approval needs a person whether or not this view holds the request" do
      assert Rail.triage_of(interactive("a", status: :awaiting_approval), 0) == :needs_you
    end

    test "an idle session settles, on either plane, and is never NEEDS YOU" do
      # A deliberate divergence from `tui/src/model.rs:249-254`, which routes
      # interactive+idle to NeedsInput. On a rail a person scans for work that rule fills
      # the top group with every conversation anyone has ever finished reading. See the
      # `triage_of/2` docs; the green eye is for a real ask and nothing else.
      assert Rail.triage_of(interactive("a", status: :idle), 0) == :settled
      assert Rail.triage_of(coding("t", status: :idle), 0) == :settled
    end

    test "but an idle session holding an unanswered approval still needs a person" do
      # Idle settles because nobody is blocked, not because the row is uninteresting. An
      # ask outranks it, through the same door every other ask uses.
      assert Rail.triage_of(interactive("a", status: :idle), 1) == :needs_you
    end

    test "NEEDS YOU has exactly two doors" do
      # Enumerated rather than sampled: this is the group the whole page is arranged
      # around, and anything that can enter it without an ask devalues all of it.
      statuses = [
        :awaiting_approval,
        :idle,
        :running,
        :starting,
        :closing,
        :closed,
        :completed,
        :failed,
        :cancelled,
        :lost,
        :something_new
      ]

      for status <- statuses, plane <- [:interactive, :coding] do
        row =
          if plane == :interactive,
            do: interactive("a", status: status),
            else: coding("a", status: status)

        if status == :awaiting_approval do
          assert Rail.triage_of(row, 0) == :needs_you
        else
          refute Rail.triage_of(row, 0) == :needs_you,
                 "#{plane} #{status} reached NEEDS YOU without an ask"
        end

        assert Rail.triage_of(row, 1) == :needs_you,
               "#{plane} #{status} ignored an unanswered approval"
      end
    end

    test "every terminal status settles" do
      for status <- [:closed, :completed, :failed, :cancelled, :lost] do
        assert Rail.triage_of(interactive("a", status: status), 0) == :settled,
               "#{status} did not settle"
      end
    end

    test "busy statuses are at work" do
      for status <- [:running, :starting, :closing] do
        assert Rail.triage_of(interactive("a", status: status), 0) == :at_work
      end
    end

    test "a status this build does not know is never terminal" do
      # Guessing wrong here stops a live session rendering, which is the expensive
      # direction to be wrong in.
      row = interactive("a", status: :negotiating_with_the_future)

      refute Rail.terminal?(row.status)
      assert Rail.triage_of(row, 0) == :at_work
    end
  end

  describe "ordering" do
    test "group first, and nothing reorders across it" do
      rows = [
        interactive("settled", status: :completed, updated_at: "2026-08-29T23:00:00Z"),
        interactive("working", status: :running, updated_at: "2026-08-29T22:00:00Z"),
        interactive("needs", status: :awaiting_approval, updated_at: "2026-08-29T01:00:00Z")
      ]

      # The needs-you row is the oldest by a day and is still first.
      assert groups(rows) == [
               {:needs_you, "needs", 0},
               {:at_work, "working", 0},
               {:settled, "settled", 0}
             ]
    end

    test "newest activity next" do
      rows = [
        interactive("old", status: :running, updated_at: "2026-08-29T01:00:00Z"),
        interactive("new", status: :running, updated_at: "2026-08-29T23:00:00Z"),
        interactive("mid", status: :running, updated_at: "2026-08-29T12:00:00Z")
      ]

      assert Enum.map(groups(rows), &elem(&1, 1)) == ["new", "mid", "old"]
    end

    test "then plane, then id — so the list does not reshuffle under a reader's cursor" do
      at = "2026-08-29T12:00:00Z"

      rows = [
        coding("b", status: :running, updated_at: at),
        interactive("b", status: :running, updated_at: at),
        coding("a", status: :running, updated_at: at),
        interactive("a", status: :running, updated_at: at)
      ]

      assert Enum.map(groups(rows), &{elem(&1, 0), elem(&1, 1)}) == [
               {:at_work, "a"},
               {:at_work, "b"},
               {:at_work, "a"},
               {:at_work, "b"}
             ]

      # Interactive before coding, and the same order every time it is asked.
      assert Rail.triaged(rows) |> Enum.map(& &1.row.plane) ==
               [:interactive, :interactive, :coding, :coding]

      assert Rail.triaged(rows) == Rail.triaged(Enum.shuffle(rows))
    end

    test "a row with no updated_at sorts last rather than first" do
      rows = [
        interactive("nameless", status: :running, updated_at: nil),
        interactive("dated", status: :running, updated_at: "2020-01-01T00:00:00Z")
      ]

      assert Enum.map(groups(rows), &elem(&1, 1)) == ["dated", "nameless"]
    end
  end

  describe "dedupe" do
    test "one row per addressable stream" do
      rows = [
        interactive("a", status: :running, updated_at: "2026-08-29T12:00:00Z"),
        interactive("a", status: :running, updated_at: "2026-08-29T11:00:00Z")
      ]

      assert length(Rail.triaged(rows)) == 1
    end

    test "the same id on two planes is two rows, because they are two streams" do
      rows = [interactive("x", status: :running), coding("x", status: :running)]

      assert length(Rail.triaged(rows)) == 2
    end
  end

  describe "nesting" do
    test "a delegated task is drawn under the conversation that started it" do
      rows = [
        interactive("parent", status: :running, children: ["child"]),
        coding("child", status: :running, parent: %{plane: :interactive, id: "parent"})
      ]

      assert groups(rows) == [{:at_work, "parent", 0}, {:at_work, "child", 1}]
    end

    test "but only within a group — a child that needs a person is never buried" do
      rows = [
        interactive("parent", status: :running, children: ["child"]),
        coding("child", status: :awaiting_approval, parent: %{plane: :interactive, id: "parent"})
      ]

      # The child keeps its own place at depth zero, above its parent, because the two
      # orderings disagree and "what needs me" wins.
      assert groups(rows) == [{:needs_you, "child", 0}, {:at_work, "parent", 0}]
    end

    test "a child claimed only by its own parent pointer still nests" do
      rows = [
        # The parent's delegation list is stale; the child names the parent anyway.
        interactive("parent", status: :running, children: ["someone-else"]),
        coding("child", status: :running, parent: %{plane: :interactive, id: "parent"})
      ]

      assert groups(rows) == [{:at_work, "parent", 0}, {:at_work, "child", 1}]
    end

    test "a parent with no children nests nothing, whatever else is in the list" do
      rows = [interactive("a", status: :running), coding("b", status: :running)]

      assert Enum.all?(Rail.triaged(rows), &(&1.depth == 0))
    end
  end

  describe "counts and words" do
    test "counts what each group holds" do
      rows = [
        interactive("n", status: :awaiting_approval),
        interactive("w", status: :running),
        interactive("d", status: :completed),
        interactive("d2", status: :failed)
      ]

      assert Rail.counts(Rail.triaged(rows)) == %{needs_you: 1, at_work: 1, settled: 2}
    end

    test "a title is never blank" do
      assert Rail.title(interactive("abc", title: nil)) == "abc"
      assert Rail.title(interactive("abc", title: "   ")) == "abc"
      assert Rail.title(interactive("abc", title: " Named ")) == "Named"
      assert Rail.title(coding("t1")) == "do the thing"
    end

    test "an outcome word is read off the status and never invented" do
      assert Rail.outcome(interactive("a", status: :completed)) == "completed"
      assert Rail.outcome(interactive("a", status: :failed)) == "failed"
      assert Rail.outcome(interactive("a", status: :something_new)) == "settled"
    end

    test "only failure and loss take the danger tone" do
      assert Rail.failed?(interactive("a", status: :failed))
      assert Rail.failed?(interactive("a", status: :lost))
      refute Rail.failed?(interactive("a", status: :cancelled))
      refute Rail.failed?(interactive("a", status: :completed))
    end
  end

  # ------------------------------------------------------------------------------------
  # Rendering
  # ------------------------------------------------------------------------------------

  describe "the rail as drawn" do
    test "draws all three headings, always, so an empty group is a fact and not a gap" do
      html = render_rail([])

      assert html =~ "NEEDS YOU"
      assert html =~ "AT WORK"
      assert html =~ "SETTLED"
      assert html =~ "nothing here"
    end

    test "puts the count beside the only heading that earns one" do
      rows = [
        interactive("n1", status: :awaiting_approval),
        interactive("n2", status: :awaiting_approval),
        interactive("d", status: :completed)
      ]

      html = render_rail(rows)

      assert [count] = Regex.run(~r/ouro-count">\s*(\d+)\s*</, html, capture: :all_but_first)
      assert count == "2"

      # And nowhere else: a count beside AT WORK or SETTLED would be a number nobody is
      # being asked to act on.
      assert Regex.scan(~r/ouro-count/, html) |> length() == 1
    end

    test "a needs-you row is a card carrying the ask, and the only green on the page" do
      html = render_rail([interactive("n", status: :awaiting_approval, title: "Ship it")])

      assert html =~ "ouro-row-needs_you"
      assert html =~ "Ship it"
      assert html =~ "waiting on your answer"

      # The eye, and nothing else, spends the attention tone.
      assert html =~ "var(--attention-green)"
      assert Regex.scan(~r/--attention-green/, html) |> length() == 1
    end

    test "an at-work row says provider and machine when nothing is watching it" do
      html = render_rail([interactive("w", status: :running)])

      assert html =~ "claude_code · core@one"
      assert html =~ "ouro-glyph-work"
    end

    test "an at-work row says what the watched session is doing when one is" do
      rows = [interactive("w", status: :running)]

      html =
        render_component(&DeckLive.rail/1,
          triaged: Rail.triaged(rows),
          open: {:interactive, "w"},
          error: nil,
          activity: %{{:interactive, "w"} => "Read lib/thing.ex"}
        )

      assert html =~ "Read lib/thing.ex"
      refute html =~ "claude_code · core@one"
    end

    test "an idle session is drawn in the third group, reading 'idle · <age>'" do
      html = render_rail([interactive("i", status: :idle, title: "The refactor thread")])

      assert html =~ "The refactor thread"
      assert html =~ ~r/idle · \d+[mhd]|idle · now/

      # In SETTLED, dimmed, with the closed ring — not a card, and not the eye.
      assert html =~ "ouro-row-settled"
      assert html =~ "ouro-glyph-settled"
      refute html =~ "ouro-row-needs_you"
      refute html =~ "var(--attention-green)"
    end

    test "and its age is printed once, not once in the line and again in the column" do
      html = render_rail([interactive("i", status: :idle)])

      refute html =~ "ouro-row-age"
      assert length(Regex.scan(~r/idle · /, html)) == 1
    end

    test "an idle session with an unanswered ask is a card again, with the eye" do
      rows = [interactive("i", status: :idle)]

      html =
        render_component(&DeckLive.rail/1,
          triaged: Rail.triaged(rows, %{{:interactive, "i"} => 1}),
          open: nil,
          error: nil,
          activity: %{}
        )

      assert html =~ "ouro-row-needs_you"
      assert html =~ "var(--attention-green)"
      refute html =~ "idle · "
    end

    test "a settled row is dimmed and says its outcome" do
      html = render_rail([interactive("d", status: :completed)])

      assert html =~ "ouro-row-settled"
      assert html =~ "ouro-glyph-settled"
      assert html =~ "completed"
    end

    test "a failed row takes the danger tone on the ring and the word" do
      html = render_rail([interactive("d", status: :failed)])

      assert html =~ "ouro-row-failed"
      assert html =~ "ouro-glyph-failed"
      assert html =~ "failed"
    end

    test "a nested child is drawn as one" do
      rows = [
        interactive("parent", status: :running, children: ["child"]),
        coding("child", status: :running, parent: %{plane: :interactive, id: "parent"})
      ]

      assert render_rail(rows) =~ "ouro-row-nested"
    end

    test "every row is a link to its own session" do
      html = render_rail([interactive("abc", status: :running)])

      assert html =~ ~s(href="/s/interactive/abc")
    end

    test "operate scope exposes rename and terminal-only delete controls" do
      active =
        render_component(&DeckLive.rail/1,
          triaged: Rail.triaged([interactive("active", status: :running)]),
          open: nil,
          error: nil,
          activity: %{},
          scope: :operate
        )

      assert active =~ ~s(phx-value-action="rename")
      refute active =~ ~s(phx-value-action="delete")

      terminal =
        render_component(&DeckLive.rail/1,
          triaged: Rail.triaged([interactive("done", status: :completed)]),
          open: nil,
          error: nil,
          activity: %{},
          scope: :operate
        )

      assert terminal =~ ~s(phx-value-action="rename")
      assert terminal =~ ~s(phx-value-action="delete")
    end

    test "a refused list says so instead of drawing an empty rail as if it were empty" do
      html =
        render_component(&DeckLive.rail/1,
          triaged: [],
          open: nil,
          error: "core@two is unreachable",
          activity: %{}
        )

      assert html =~ "ouro-refusal"
      assert html =~ "core@two is unreachable"
    end
  end

  defp render_rail(rows) do
    render_component(&DeckLive.rail/1,
      triaged: Rail.triaged(rows),
      open: nil,
      error: nil,
      activity: %{}
    )
  end
end
