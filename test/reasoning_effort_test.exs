defmodule Ouroboros.ReasoningEffortTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Session.Request, as: SessionRequest
  alias Ouroboros.Session.TurnRequest
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Provider.Native
  alias Ouroboros.ReasoningEffort

  test "the gateway, native adapter, and request contract share the six-level vocabulary" do
    atoms = [:none, :low, :medium, :high, :xhigh, :max]
    names = Enum.map(atoms, &Atom.to_string/1)

    assert ReasoningEffort.atoms() == atoms
    assert ReasoningEffort.names() == names
    assert Native.spec().normalized_values.reasoning_effort == atoms ++ [nil]

    assert {:ok, contract} = Methods.params("interactive.start")
    descriptor = Enum.find(contract.params, &(&1.name == "reasoning_effort"))
    assert descriptor.type == {:enum, Map.new(Enum.zip(names, atoms))}
  end

  test "session and turn requests retain values the native runtime supports" do
    for effort <- [:none, :xhigh, :max] do
      assert {:ok, %SessionRequest{reasoning_effort: ^effort}} =
               ReasoningEffort.session_request(%{cwd: File.cwd!(), reasoning_effort: effort})

      assert {:ok, %TurnRequest{reasoning_effort: ^effort}} =
               ReasoningEffort.turn_request(%{prompt: "think", reasoning_effort: effort})
    end
  end

  test "the owned vocabulary remains closed to unknown values" do
    assert {:error, :invalid_reasoning_effort} =
             ReasoningEffort.session_request(%{
               cwd: File.cwd!(),
               reasoning_effort: :unbounded
             })

    assert {:error, :invalid_reasoning_effort} =
             ReasoningEffort.turn_request(%{prompt: "think", reasoning_effort: "unbounded"})

    valid_request = ReasoningEffort.turn_request!("think")

    assert {:error, :invalid_reasoning_effort} =
             ReasoningEffort.turn_request(%{valid_request | reasoning_effort: :unbounded})
  end
end
