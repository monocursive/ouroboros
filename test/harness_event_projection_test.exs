defmodule Ouroboros.HarnessEventProjectionTest do
  use ExUnit.Case, async: true

  alias Jido.Harness.Event, as: HarnessEvent
  alias Ouroboros.Coding.Event, as: CodingEvent
  alias Ouroboros.Interactive.Event, as: InteractiveEvent

  test "normalized direct events retain canonical type and payload in both planes" do
    harness_event =
      HarnessEvent.new!(
        provider: :native,
        type: :tool_call,
        session_id: "harness-session",
        sequence: 7,
        payload: %{
          "call_id" => "item-42",
          "name" => "bash",
          "input" => %{"command" => "mix test"}
        }
      )

    interactive = InteractiveEvent.from_harness("interactive-session", harness_event)
    coding = CodingEvent.from_harness("coding-task", 11, harness_event)

    assert interactive.type == :tool_call
    assert interactive.payload == harness_event.payload
    assert interactive.sequence == 7
    assert coding.type == :tool_call
    assert coding.payload == harness_event.payload
    assert coding.sequence == 11
    assert coding.harness_sequence == 7
  end

  test "raw provider records are never persisted" do
    harness_event =
      HarnessEvent.new!(
        provider: :native,
        type: :provider_event,
        sequence: 3,
        payload: %{"kind" => "status"},
        raw: %{"authorization" => "Bearer must-not-persist"}
      )

    interactive = InteractiveEvent.from_harness("interactive-session", harness_event)
    coding = CodingEvent.from_harness("coding-task", 5, harness_event)

    refute Map.has_key?(Map.from_struct(interactive), :raw)
    refute Map.has_key?(Map.from_struct(coding), :raw)
    refute inspect(interactive) =~ "must-not-persist"
    refute inspect(coding) =~ "must-not-persist"
  end
end
