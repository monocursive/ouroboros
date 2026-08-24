defmodule Ouroboros.InteractiveUsageTest do
  @moduledoc """
  What a session spent, folded from the `:usage` events providers actually emit.

  The payloads here are the shapes the bundled mappers produce — Claude's result
  `usage` block (`claude_stream.ex:122-128`), the Codex exec mapper's
  (`cli_mapper/codex.ex:145-149`), the Codex app-server `thread/tokenUsage/updated`
  notification (`dialect/codex.ex:164-178`), and ACP's `usage_update`
  (`dialect/acp.ex:197`) — plus the `input`/`totalTokens` spelling Harness's own adapter
  fixtures carry, because a counter that only reads one spelling silently reports zero.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.{Event, State}

  describe "folding provider usage" do
    test "a session with nothing reported claims nothing" do
      assert session().usage == nil
      assert State.fold_usage(session(), []).usage == nil
    end

    test "Claude's result usage block, cache keys and all" do
      usage =
        fold([
          usage_event("turn-1", %{
            "input_tokens" => 12,
            "output_tokens" => 34,
            "cache_read_input_tokens" => 100,
            "cache_creation_input_tokens" => 7,
            "total_tokens" => 46
          })
        ])

      assert usage.input_tokens == 12
      assert usage.output_tokens == 34
      assert usage.cache_read_tokens == 100
      assert usage.cache_creation_tokens == 7
      assert usage.total_tokens == 46
      assert usage.turns_with_usage == 1
      assert usage.cost_usd == nil
    end

    test "the camelCase and bare spellings other transports send" do
      usage =
        fold([
          usage_event("turn-1", %{"input" => 10, "output" => 2, "totalTokens" => 12}),
          usage_event("turn-2", %{
            "inputTokens" => 1,
            "outputTokens" => 2,
            "cacheReadInputTokens" => 3,
            "cacheCreationTokens" => 4
          })
        ])

      assert usage.input_tokens == 11
      assert usage.output_tokens == 4
      assert usage.cache_read_tokens == 3
      assert usage.cache_creation_tokens == 4
      assert usage.turns_with_usage == 2
      # The second payload named no total, so the parts stand in for it.
      assert usage.total_tokens == 12 + 3
    end

    test "distinct turns add up" do
      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 5, "output_tokens" => 1, "total_tokens" => 6}),
          usage_event("turn-2", %{"input_tokens" => 7, "output_tokens" => 2, "total_tokens" => 9}),
          usage_event("turn-3", %{"input_tokens" => 1, "output_tokens" => 1, "total_tokens" => 2})
        ])

      assert usage.input_tokens == 13
      assert usage.output_tokens == 4
      assert usage.total_tokens == 17
      assert usage.turns_with_usage == 3
    end

    test "a turn that reports repeatedly is a running total, not three turns" do
      # `thread/tokenUsage/updated` is a value being updated. Adding each notification
      # would multiply a Codex session's tokens by however often it reported.
      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 10, "total_tokens" => 10}),
          usage_event("turn-1", %{"input_tokens" => 25, "total_tokens" => 30}),
          usage_event("turn-1", %{"input_tokens" => 40, "total_tokens" => 55})
        ])

      assert usage.input_tokens == 40
      assert usage.total_tokens == 55
      assert usage.turns_with_usage == 1
      assert usage.last.turn_id == "turn-1"
    end

    test "a running total that is followed by a new turn keeps both" do
      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 10, "total_tokens" => 10}),
          usage_event("turn-1", %{"input_tokens" => 40, "total_tokens" => 55}),
          usage_event("turn-2", %{"input_tokens" => 5, "total_tokens" => 6})
        ])

      assert usage.input_tokens == 45
      assert usage.total_tokens == 61
      assert usage.turns_with_usage == 2
    end

    test "a re-report can never inflate a total past the largest figure the turn claimed" do
      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 40, "total_tokens" => 55}),
          usage_event("turn-1", %{"input_tokens" => 10, "total_tokens" => 10})
        ])

      assert usage.input_tokens == 40
      assert usage.total_tokens == 55
    end

    test "cost arrives on the run terminator and is nil until a provider prices the work" do
      # Claude puts `cost_usd` on `run_completed`, never on the `usage` event.
      assert fold([usage_event("turn-1", %{"input_tokens" => 3})]).cost_usd == nil

      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 3, "output_tokens" => 1}),
          run_completed("turn-1", %{"cost_usd" => 0.25, "num_turns" => 1, "duration_ms" => 900}),
          usage_event("turn-2", %{"input_tokens" => 4, "output_tokens" => 1}),
          run_completed("turn-2", %{"cost_usd" => 0.5})
        ])

      assert usage.cost_usd == 0.75
      assert usage.input_tokens == 7
      assert usage.turns_with_usage == 2
    end

    test "a run terminator that priced nothing changes nothing" do
      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 3}),
          run_completed("turn-1", %{"cost_usd" => nil, "num_turns" => 1})
        ])

      assert usage.cost_usd == nil
      assert usage.input_tokens == 3
      assert usage.turns_with_usage == 1
    end

    test "a payload with no number in it is not usage" do
      for payload <- [
            %{},
            %{"sessionUpdate" => "usage_update"},
            %{"input_tokens" => "many"},
            %{"input_tokens" => -5},
            %{"model" => "sonnet"}
          ] do
        assert fold([usage_event("turn-1", payload)]) == nil,
               "#{inspect(payload)} was accounted for as usage"
      end
    end

    test "an event of any other type is ignored" do
      assert fold([
               %Event{
                 id: "e",
                 session_id: "s",
                 sequence: 1,
                 type: :output_text_final,
                 timestamp: "t",
                 turn_id: "turn-1",
                 payload: %{"input_tokens" => 999}
               }
             ]) == nil
    end

    test "usage with no turn id is counted rather than dropped" do
      usage =
        fold([
          usage_event(nil, %{"input_tokens" => 2, "total_tokens" => 2}),
          usage_event(nil, %{"input_tokens" => 3, "total_tokens" => 3})
        ])

      assert usage.input_tokens == 5
      assert usage.turns_with_usage == 2
    end

    test "the account is one bounded map however many turns report" do
      events = for index <- 1..500, do: usage_event("turn-#{index}", %{"input_tokens" => 1})
      usage = fold(events)

      assert usage.input_tokens == 500
      assert usage.turns_with_usage == 500
      assert map_size(usage) == 10
      assert Enum.sort(Map.keys(usage)) == Enum.sort(usage_keys())
    end

    # D9. The window and the last request's size are not counters: the footer divides one
    # by the other, and a denominator that grew with the conversation would draw a
    # percentage that falls as the context fills.
    test "the context meter is carried through, latest wins, never summed" do
      usage =
        fold([
          usage_event("turn-1", %{
            "input_tokens" => 100,
            "context_used" => 100,
            "context_window" => 200_000
          }),
          usage_event("turn-2", %{
            "input_tokens" => 150,
            "context_used" => 250,
            "context_window" => 200_000
          })
        ])

      assert usage.input_tokens == 250
      assert usage.context_window == 200_000
      assert usage.context_used == 250
    end

    test "an unknown window stays nil rather than becoming a zero the footer would divide by" do
      usage = fold([usage_event("turn-1", %{"input_tokens" => 10, "context_used" => 10})])

      assert usage.context_used == 10
      assert usage.context_window == nil
    end

    test "a later payload without the meter does not blank a window already reported" do
      usage =
        fold([
          usage_event("turn-1", %{"input_tokens" => 10, "context_window" => 128_000}),
          run_completed("turn-1", %{"cost_usd" => 0.02})
        ])

      assert usage.context_window == 128_000
      assert usage.cost_usd == 0.02
    end

    test "the account is serializable, so it survives the checkpoint it rides on" do
      state = State.fold_usage(session(), [usage_event("turn-1", %{"input_tokens" => 3})])

      assert State.loadable?(state)
      assert state |> :erlang.term_to_binary() |> :erlang.binary_to_term() == state
    end

    test "public state carries the account and re-projects to itself" do
      state = State.fold_usage(session(), [usage_event("turn-1", %{"input_tokens" => 3})])
      public = State.public(state)

      assert public.usage == state.usage
      assert State.public(public) == public
    end

    test "a checkpoint written before this field existed folds from scratch" do
      # An older durable session deserializes without the key at all.
      legacy = session() |> Map.from_struct() |> Map.delete(:usage)
      legacy = struct(State, legacy)

      folded = State.fold_usage(legacy, [usage_event("turn-1", %{"input_tokens" => 3})])
      assert folded.usage.input_tokens == 3
    end
  end

  defp fold(events), do: State.fold_usage(session(), events).usage

  defp session do
    assert {:ok, state} =
             State.new("usage-#{System.unique_integer([:positive])}", provider: :native)

    state
  end

  defp usage_event(turn_id, payload), do: event(:usage, turn_id, payload)
  defp run_completed(turn_id, payload), do: event(:run_completed, turn_id, payload)

  defp event(type, turn_id, payload) do
    %Event{
      id: "event-#{System.unique_integer([:positive])}",
      session_id: "usage",
      sequence: System.unique_integer([:positive]),
      type: type,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      turn_id: turn_id,
      payload: payload
    }
  end

  defp usage_keys do
    [
      :input_tokens,
      :output_tokens,
      :cache_read_tokens,
      :cache_creation_tokens,
      :total_tokens,
      :cost_usd,
      :turns_with_usage,
      :context_window,
      :context_used,
      :last
    ]
  end
end
