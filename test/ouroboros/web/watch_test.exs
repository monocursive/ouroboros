defmodule Ouroboros.Web.WatchTest do
  @moduledoc """
  The cursor arithmetic, tested as arithmetic.

  `Ouroboros.Web.Watch` is pure on purpose, so every property this suite asserts is a
  function call rather than a process, a socket, or a sleep. What is being defended here
  is one claim: **the number a repair resubscribes from never steps over a hole**. Each
  test below is a way that could go wrong — an out-of-order batch, a replayed backlog, a
  prune the runtime announced, a prune it did not, a window that filled up — and the
  cursor is checked afterwards.

  A transcript that looks complete and is not is the worst outcome this surface has, and
  the cursor is the only thing standing between a reader and it.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Transcript.Entry
  alias Ouroboros.Web.Watch

  defp event(sequence, type \\ :output_text_delta, payload \\ %{"text" => "x"}) do
    %Event{
      id: "e#{sequence}",
      session_id: "s1",
      sequence: sequence,
      type: type,
      timestamp: "2026-08-29T12:00:00Z",
      payload: payload
    }
  end

  defp events(range), do: Enum.map(range, &event/1)

  describe "the cursor" do
    test "starts at zero and follows a contiguous run" do
      watch = Watch.new()
      assert Watch.cursor(watch) == 0

      watch = Watch.absorb(watch, events(1..5))

      assert Watch.cursor(watch) == 5
      refute Watch.has_gap?(watch)
    end

    test "stops at the first hole, whatever sits above it" do
      watch = Watch.absorb(Watch.new(), events(1..3) ++ events(7..9))

      # Not 9. Resuming from the newest sequence would step over 4, 5 and 6 and leave a
      # transcript that looks complete and is not — the whole reason this is not `newest`.
      assert Watch.cursor(watch) == 3
      assert Watch.newest(watch) == 9
      assert Watch.has_gap?(watch)
    end

    test "advances the moment the hole is filled" do
      watch =
        Watch.new()
        |> Watch.absorb(events(1..3) ++ events(7..9))
        |> Watch.absorb(events(4..6))

      assert Watch.cursor(watch) == 9
      refute Watch.has_gap?(watch)
    end

    test "does not care what order a batch arrives in" do
      shuffled = 1..9 |> Enum.shuffle() |> Enum.map(&event/1)

      assert Watch.cursor(Watch.absorb(Watch.new(), shuffled)) == 9
    end

    test "never moves backwards when a hole opens above it" do
      watch = Watch.absorb(Watch.new(), events(1..5))
      assert Watch.cursor(watch) == 5

      watch = Watch.absorb(watch, [event(20)])

      assert Watch.cursor(watch) == 5
      assert Watch.has_gap?(watch)
    end
  end

  describe "absorbing the same events twice" do
    test "changes nothing at all" do
      once = Watch.absorb(Watch.new(), events(1..20))
      twice = Watch.absorb(once, events(1..20))

      assert Watch.cursor(twice) == Watch.cursor(once)
      assert Watch.size(twice) == Watch.size(once)
      assert Watch.entries(twice) == Watch.entries(once)
    end

    test "which is what makes the overlap every resync produces free" do
      watch =
        Watch.new()
        |> Watch.absorb(events(1..10))
        # A resync from cursor 4 answers 5..12: the overlap is deliberate and idempotent.
        |> Watch.backlog(4, events(5..12))

      assert Watch.cursor(watch) == 12
      assert Watch.size(watch) == 12
    end

    test "and is idempotent by sequence, not by identity" do
      # Two different structs at the same sequence: the later one wins, and the ledger does
      # not grow. A durable event is immutable upstream, so this can only happen when a
      # replay re-encodes one — and it must not double the row.
      watch =
        Watch.new()
        |> Watch.absorb([event(1, :output_text_delta, %{"text" => "a"})])
        |> Watch.absorb([event(1, :output_text_delta, %{"text" => "b"})])

      assert Watch.size(watch) == 1
      assert Watch.cursor(watch) == 1
    end
  end

  describe "an announced prune" do
    test "raises the floor and takes the cursor with it" do
      watch = Watch.raise_floor(Watch.new(), 40)

      assert Watch.floor(watch) == 40
      assert Watch.cursor(watch) == 40

      watch = Watch.absorb(watch, events(41..45))
      assert Watch.cursor(watch) == 45
    end

    test "keeps every event this view already held" do
      # A prune is a fact about what the *runtime* retains. Events obtained before it are
      # real history, and discarding them would delete a transcript somebody is reading.
      watch =
        Watch.new()
        |> Watch.absorb(events(1..10))
        |> Watch.raise_floor(7)

      assert Watch.size(watch) == 10
      assert Watch.floor(watch) == 7
      assert Watch.cursor(watch) == 10
    end

    test "cannot be lowered by a stale refusal answering late" do
      watch = Watch.new() |> Watch.raise_floor(50) |> Watch.raise_floor(20)

      assert Watch.floor(watch) == 50
    end

    test "puts the divider where the hole is, not at the top" do
      entries =
        Watch.new()
        |> Watch.absorb(events(1..4))
        |> Watch.raise_floor(2)
        |> Watch.entries()

      # 1 and 2 are still drawn; the marker sits between them and 3.
      assert [
               %Entry.Event{},
               %Entry.Event{},
               %Entry.Floor{sequence: 2},
               %Entry.Event{},
               %Entry.Event{}
             ] = entries
    end
  end

  describe "a silent prune" do
    test "is inferred from a backlog that starts above the cursor" do
      # Both verbs answer "the retained events after this cursor, in order". A first entry
      # at 30 for a cursor of 4 therefore proves 5..29 are gone.
      watch = Watch.backlog(Watch.new(), 4, events(30..32))

      assert Watch.floor(watch) == 29
      assert Watch.cursor(watch) == 32
      refute Watch.has_gap?(watch)
    end

    test "is not inferred from a batch that starts exactly where it was asked to" do
      # Asked from the cursor it actually holds, which is what every repair does.
      watch = Watch.new() |> Watch.absorb(events(1..4)) |> Watch.backlog(4, events(5..8))

      assert Watch.floor(watch) == 0
      assert Watch.cursor(watch) == 8
    end

    test "is not inferred from an empty answer" do
      watch = Watch.new() |> Watch.absorb(events(1..3)) |> Watch.backlog(3, [])

      assert Watch.floor(watch) == 0
      assert Watch.cursor(watch) == 3
    end

    test "leaves the gap visible when the hole is above the batch's own start" do
      # Asked from 4, answered 5..6 and then 10..11 in one batch: the first entry proves
      # nothing was pruned, and 7..9 are a hole a further replay can still fill.
      watch =
        Watch.new()
        |> Watch.absorb(events(1..4))
        |> Watch.backlog(4, events(5..6) ++ events(10..11))

      assert Watch.floor(watch) == 0
      assert Watch.cursor(watch) == 6
      assert Watch.has_gap?(watch)
    end
  end

  describe "the window" do
    test "drops the oldest events and raises the floor by exactly as much" do
      window = Watch.window()
      watch = Watch.absorb(Watch.new(), events(1..(window + 10)))

      assert Watch.size(watch) == window
      assert Watch.floor(watch) == 10
      assert Watch.cursor(watch) == window + 10
    end

    test "produces the same divider a runtime prune produces" do
      window = Watch.window()

      entries =
        Watch.new()
        |> Watch.absorb(events(1..(window + 3)))
        |> Watch.entries()

      # One marker, saying the one thing: history before here is gone. A reader is not
      # told, and does not need to know, which side let go of it.
      assert Enum.count(entries, &match?(%Entry.Floor{}, &1)) == 1
      assert %Entry.Floor{sequence: 3} = Enum.find(entries, &match?(%Entry.Floor{}, &1))
    end
  end

  describe "notes" do
    test "anchor at the newest sequence known, which is where the jump is" do
      watch =
        Watch.new()
        |> Watch.absorb(events(1..5))
        |> Watch.note(:reconnected)

      # `entries/2` emits a note anchored at N immediately *before* the event at N, which
      # is what `tui/src/ui/transcript.rs:1290` does with the same anchor. The position is
      # the TUI's, not a choice made here — and it is asserted rather than assumed, because
      # a note that drifted a row would be the first sign these two had come apart.
      assert [_, _, _, _, %Entry.Note{note: :reconnected}, %Entry.Event{}] = Watch.entries(watch)
    end

    test "are forgotten once the floor rises past them" do
      watch =
        Watch.new()
        |> Watch.absorb(events(1..5))
        |> Watch.note(:reconnected)
        |> Watch.raise_floor(9)

      refute Enum.any?(Watch.entries(watch), &match?(%Entry.Note{}, &1))
    end

    test "are bounded, so a session that reconnected all night is still readable" do
      watch =
        Enum.reduce(1..200, Watch.absorb(Watch.new(), events(1..5)), fn _n, watch ->
          Watch.note(watch, :reconnected)
        end)

      # They all anchor at the same sequence, so the map holds one — the bound is not
      # under test here so much as the fact that notes cannot grow without limit.
      assert Enum.count(Watch.entries(watch), &match?(%Entry.Note{}, &1)) <= 64
    end
  end

  describe "the end of the stream" do
    test "is recorded rather than inferred" do
      watch = Watch.new() |> Watch.absorb(events(1..2)) |> Watch.ended("completed")

      assert Watch.ended?(watch)
      assert %Entry.Ended{status: "completed"} = List.last(Watch.entries(watch))
    end

    test "is absent until something says so" do
      refute Watch.ended?(Watch.absorb(Watch.new(), events(1..2)))
    end
  end

  describe "an event with no sequence" do
    test "is counted, not guessed at a position for" do
      watch = Watch.absorb(Watch.new(), [%{type: :usage, payload: %{}}])

      assert Watch.size(watch) == 0
      assert watch.undecodable == 1
      assert Watch.cursor(watch) == 0
    end
  end

  describe "a seeded floor" do
    test "starts the cursor there, so a remount after a prune does not ask for the gone" do
      watch = Watch.new(floor: 120)

      assert Watch.cursor(watch) == 120
      assert Watch.floor(watch) == 120
    end
  end

  describe "mailbox lag" do
    test "is the watch window, because a longer queue is already a hole" do
      refute Watch.mailbox_lagged?(0)
      refute Watch.mailbox_lagged?(Watch.window() - 1)
      assert Watch.mailbox_lagged?(Watch.window())
      assert Watch.mailbox_lagged?(Watch.window() + 1)
      assert Watch.window() == 2_000
    end
  end
end
