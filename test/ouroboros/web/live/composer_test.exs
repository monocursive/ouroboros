defmodule Ouroboros.Web.Live.ComposerTest do
  @moduledoc """
  The composer's two readings of the held ledger, tested where they are pure.

  `turn_state/1` decides which verb a send uses and whether an interrupt is on screen, and
  it decides both from the events this view is holding rather than from a status poll three
  seconds behind. The deck's own test proves the wiring; this one proves the arithmetic,
  including the case that matters most and is hardest to stage end to end — a ledger that
  has never mentioned a turn at all.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Live.Composer
  alias Ouroboros.Web.Transcript.Entry

  defp entries(events) do
    Enum.map(events, &%Entry.Event{event: &1})
  end

  defp event(sequence, type, payload \\ %{}, turn_id \\ "t1") do
    %Event{
      id: "e#{sequence}",
      session_id: "s",
      sequence: sequence,
      type: type,
      timestamp: "2026-08-29T12:00:00Z",
      payload: payload,
      turn_id: turn_id
    }
  end

  describe "turn_state/1" do
    test "says nothing when the ledger has said nothing" do
      state = Composer.turn_state([])

      refute state.spoke?
      refute state.running?
      refute state.failed?
      assert state.queued == 0
    end

    test "a started turn is running, and names itself" do
      state = Composer.turn_state(entries([event(1, :turn_started)]))

      assert state.spoke?
      assert state.running?
      assert state.turn_id == "t1"
    end

    for outcome <- [:turn_completed, :turn_failed, :turn_interrupted] do
      test "#{outcome} ends it, however it ended" do
        state =
          Composer.turn_state(entries([event(1, :turn_started), event(2, unquote(outcome))]))

        assert state.spoke?
        refute state.running?
        assert is_nil(state.turn_id)
        assert state.failed? == (unquote(outcome) == :turn_failed)
      end
    end

    test "an idle status after a failed turn keeps the retry evidence" do
      state =
        Composer.turn_state(
          entries([
            event(1, :turn_started),
            event(2, :turn_failed),
            event(3, :session_idle)
          ])
        )

      assert state.failed?
      refute state.running?
    end

    test "the queue depth is the newest one the runtime published" do
      state =
        Composer.turn_state(
          entries([
            event(1, :queue_changed, %{"queued_turns" => 3}),
            event(2, :queue_changed, %{"queued_turns" => 1})
          ])
        )

      assert state.queued == 1
    end

    test "a queue_changed that named no number reports nothing rather than guessing" do
      state = Composer.turn_state(entries([event(1, :queue_changed, %{})]))

      assert state.queued == 0
    end

    test "dividers are not events and do not move the state" do
      mixed = [
        %Entry.Floor{sequence: 4},
        %Entry.Event{event: event(5, :turn_started)},
        %Entry.Gap{from: 6, to: 7},
        %Entry.Ended{status: "closed"}
      ]

      assert Composer.turn_state(mixed).running?
    end
  end

  describe "verb/2" do
    test "a ledger that spoke is the authority, whatever the polled status says" do
      running = Composer.turn_state(entries([event(1, :turn_started)]))
      settled = Composer.turn_state(entries([event(1, :turn_started), event(2, :turn_completed)]))

      assert Composer.verb(running, :idle) == "interactive.follow_up"
      assert Composer.verb(settled, :running) == "interactive.send_message"
    end

    test "a silent ledger falls back to the status, which is the only other evidence" do
      silent = Composer.turn_state([])

      assert Composer.verb(silent, :idle) == "interactive.send_message"
      assert Composer.verb(silent, nil) == "interactive.send_message"
      assert Composer.verb(silent, :running) == "interactive.follow_up"
      assert Composer.verb(silent, :awaiting_approval) == "interactive.follow_up"
    end
  end

  describe "working?/2" do
    test "follows the ledger where it spoke and the status where it did not" do
      running = Composer.turn_state(entries([event(1, :turn_started)]))
      silent = Composer.turn_state([])

      assert Composer.working?(running, :idle)
      refute Composer.working?(silent, :idle)
      assert Composer.working?(silent, :running)
      # A session blocked on an approval is a session with a turn in it.
      assert Composer.working?(silent, :awaiting_approval)
      refute Composer.working?(silent, :closed)
    end
  end

  describe "the sendable values" do
    test "are exactly what interactive.configure accepts, and no more" do
      # `default` is a word for having been told nothing, not a value to send: the
      # envelope's `reasoning_effort` is `high | low | medium`
      # (`lib/ouroboros/gateway/methods.ex:409`).
      assert Composer.efforts() == ["low", "medium", "high"]
      refute "default" in Composer.efforts()

      assert Composer.sandbox_modes() == [
               "default",
               "read_only",
               "workspace_write",
               "unrestricted"
             ]
    end

    test "postures use human-facing file-access language" do
      assert Composer.word(nil) == "Session default"
      assert Composer.word("workspace_write") == "Project files"
      assert Composer.word("unrestricted") == "Full computer access"
    end
  end
end
