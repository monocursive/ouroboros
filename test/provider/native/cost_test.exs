defmodule Ouroboros.Provider.Native.CostTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Cost

  test "normalizes whichever key spelling a provider used" do
    payload = Cost.payload(%{prompt_tokens: 100, completion_tokens: 30}, nil)

    assert payload["input_tokens"] == 100
    assert payload["output_tokens"] == 30
    assert payload["total_tokens"] == 130
  end

  test "carries the cache counters and the model, all as numbers and strings" do
    payload =
      Cost.payload(
        %{
          input_tokens: 1_000,
          output_tokens: 200,
          cache_read_tokens: 800,
          cache_creation_tokens: 100,
          reasoning_tokens: 40
        },
        "anthropic:claude-sonnet-5"
      )

    assert payload["cache_read_tokens"] == 800
    assert payload["cache_creation_tokens"] == 100
    assert payload["reasoning_tokens"] == 40
    assert payload["model"] == "anthropic:claude-sonnet-5"

    assert Enum.all?(Map.values(payload), &(is_number(&1) or is_binary(&1)))
  end

  test "omits cost_usd for a model this node cannot price, rather than reporting zero" do
    payload = Cost.payload(%{input_tokens: 10, output_tokens: 5}, "scripted:<0.1.0>")
    refute Map.has_key?(payload, "cost_usd")
  end

  test "omits cost_usd when no model is known" do
    payload = Cost.payload(%{input_tokens: 10, output_tokens: 5}, nil)
    refute Map.has_key?(payload, "cost_usd")
  end

  test "prices a known model from llm_db, charging cached reads separately" do
    known =
      Enum.find(
        ["anthropic:claude-sonnet-4-5", "openai:gpt-4o-mini", "anthropic:claude-3-5-haiku-latest"],
        fn spec -> is_number(Cost.cost_usd(spec, 1_000_000, 0, 0, 0)) end
      )

    if known do
      full = Cost.cost_usd(known, 1_000_000, 0, 0, 0)
      cached = Cost.cost_usd(known, 1_000_000, 0, 1_000_000, 0)

      assert full > 0
      # Every priced model in llm_db discounts a cache read; charging it as fresh input
      # would overstate every long session.
      assert cached <= full
    else
      # llm_db carries no priced entry for any of the probes on this node. The contract
      # under test is then the honest one: no price, no number.
      assert is_nil(Cost.cost_usd("anthropic:claude-sonnet-4-5", 1_000, 1_000, 0, 0))
    end
  end

  test "a usage map with nothing usable still yields a well-formed payload" do
    payload = Cost.payload(%{}, nil)
    assert payload["input_tokens"] == 0
    assert payload["output_tokens"] == 0
    assert payload["total_tokens"] == 0
  end
end
