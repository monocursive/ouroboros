defmodule Ouroboros.HarnessEventProjectionTest do
  use ExUnit.Case, async: true

  alias Jido.Harness.Event, as: HarnessEvent
  alias Ouroboros.Interactive.Event, as: InteractiveEvent

  test "normalized direct events retain canonical type and payload" do
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

    assert interactive.type == :tool_call
    assert interactive.payload == harness_event.payload
    assert interactive.sequence == 7
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

    refute Map.has_key?(Map.from_struct(interactive), :raw)
    refute inspect(interactive) =~ "must-not-persist"
  end
end
