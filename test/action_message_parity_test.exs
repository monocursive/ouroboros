defmodule Ouroboros.ActionMessageParityTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Test.ActionMessageBaseline

  @fixture Path.expand("support/fixtures/action_message_baseline.exs", __DIR__)

  test "direct action inputs and message wire envelopes match the frozen pre-J3 observations" do
    {fixture, _} = Code.eval_file(@fixture)
    previous = Application.fetch_env(:ouroboros, :audit)
    Application.put_env(:ouroboros, :audit, mode: :standard)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:ouroboros, :audit, value)
        :error -> Application.delete_env(:ouroboros, :audit)
      end
    end)

    assert ActionMessageBaseline.capture() == fixture.observations
  end

  test "message validation refuses an unowned envelope or wrong type" do
    alias Ouroboros.Signals.AgentMessage
    message = AgentMessage.new!(%{from: "sender", body: nil, correlation_id: "correlation"})
    assert {:ok, ^message} = AgentMessage.validate(message)

    assert {:error, :unsupported_message_contract} =
             AgentMessage.validate(Map.from_struct(message))

    assert {:error, :unsupported_message_contract} =
             AgentMessage.validate(%{message | type: "other"})

    assert {:error, _} = AgentMessage.validate(%{message | data: %{}})
  end

  test "an unsupported schema type or option fails visibly before model dispatch" do
    alias Ouroboros.Action.Schema

    assert_raise ArgumentError, ~r/unsupported action schema type/, fn ->
      Schema.to_json_schema(value: [type: :pid])
    end

    assert_raise ArgumentError, ~r/unsupported action schema options/, fn ->
      Schema.to_json_schema(value: [type: :string, future_constraint: true])
    end
  end

  test "action validation leaves nested remote keys opaque and never creates their atoms" do
    alias Ouroboros.Test.NativeToolBehaviorBaseline.Probe
    key = "remote-action-#{System.unique_integer([:positive])}"
    assert_raise ArgumentError, fn -> String.to_existing_atom(key) end

    assert {:ok, %{payload: %{^key => 1}}} =
             Probe.validate_params(%{title: "fixture", payload: %{key => 1}})

    assert_raise ArgumentError, fn -> String.to_existing_atom(key) end
  end
end
