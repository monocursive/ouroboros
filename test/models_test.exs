defmodule Ouroboros.ModelsTest do
  @moduledoc """
  What the runtime can vouch for about a model: the window, the price, and which
  provider's catalogue it came from.

  These read the packaged `llm_db` snapshot the build ships with, so a snapshot bump that
  changed a shape — a missing `limits.context`, a pricing component that stopped being
  per-million — fails here rather than in a footer that quietly shows nothing.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Models

  describe "the catalogue" do
    test "every provider this node serves gets a row, bounded and deterministic" do
      catalogue = Models.list()

      assert catalogue.source == "llm_db"
      assert is_integer(catalogue.epoch)
      assert catalogue.limit == 40

      served = Enum.map(Ouroboros.providers(), & &1.provider) |> Enum.sort()
      assert catalogue.providers |> Enum.map(& &1.provider) |> Enum.sort() == served

      for row <- catalogue.providers do
        assert length(row.models) <= catalogue.limit
        assert row.total >= length(row.models)
        assert is_boolean(row.model_option)
      end

      # Deterministic: the same snapshot answers the same way twice, which is what makes
      # a client's cache and a golden fixture possible at all.
      assert Models.list() == catalogue
    end

    test "a model carries the two numbers a context meter needs" do
      row = provider_row(:claude)

      assert row.catalog == :anthropic
      assert row.total > 0

      for model <- row.models do
        assert is_binary(model.id) and model.id != ""
        assert is_integer(model.context_window) and model.context_window > 0
        assert is_integer(model.max_output_tokens) and model.max_output_tokens > 0
      end
    end

    test "pricing is normalised to one million tokens, in the currency it was stated in" do
      row = provider_row(:claude)
      model = Enum.find(row.models, &(&1.pricing != nil))

      assert model, "the packaged snapshot priced no Anthropic model"
      assert model.pricing.currency == "USD"
      assert is_number(model.pricing.input_per_mtok) and model.pricing.input_per_mtok > 0
      assert is_number(model.pricing.output_per_mtok) and model.pricing.output_per_mtok > 0

      # Output costs more than input everywhere the snapshot prices both; a normalisation
      # that divided by the wrong unit would invert this on some rows and not others.
      assert model.pricing.output_per_mtok > model.pricing.input_per_mtok

      # Per-call tool pricing is deliberately absent: it cannot be derived from a token
      # count, and a footer that summed it would be showing a number nobody owes.
      refute Map.has_key?(model.pricing, :web_search)
    end

    test "a provider with no catalogue says so rather than guessing one" do
      # Amp normalizes no model at all, and Pi routes to whatever `model_provider` names.
      assert %{catalog: nil, models: [], total: 0, model_option: false} = provider_row(:amp)
      assert %{catalog: nil, models: [], total: 0} = provider_row(:pi)
    end

    test "the catalogue mapping is a default a node can correct" do
      assert Models.catalog(:claude) == :anthropic
      assert Models.catalog(:codex) == :openai
      assert Models.catalog(:gemini) == :google
      assert Models.catalog(:grok) == :xai
      assert Models.catalog(:kimi) == :moonshotai

      # A provider whose atom is itself an llm_db provider id needs no entry.
      assert Models.catalog(:zai) == :zai
      assert Models.catalog(:opencode) == :opencode
      assert Models.catalog(:amp) == nil

      previous = Application.get_env(:ouroboros, :model_catalogs)
      Application.put_env(:ouroboros, :model_catalogs, %{amp: :anthropic})

      try do
        assert Models.catalog(:amp) == :anthropic
        assert provider_row(:amp).catalog == :anthropic
        assert provider_row(:amp).total > 0
      after
        restore(:model_catalogs, previous)
      end
    end

    test "the default model is the one the node configured, not one chosen here" do
      assert Models.default_model(:claude) == nil

      previous = Application.get_env(:jido_harness, :provider_config)

      Application.put_env(
        :jido_harness,
        :provider_config,
        Map.put(Map.new(previous || %{}), :claude, %{session_defaults: %{model: "claude-opus-5"}})
      )

      try do
        assert Models.default_model(:claude) == "claude-opus-5"
        assert provider_row(:claude).default == "claude-opus-5"
      after
        restore_harness(:provider_config, previous)
      end
    end

    test "a coding-only node's request default is read too, with session first" do
      previous = Application.get_env(:jido_harness, :provider_config)

      Application.put_env(
        :jido_harness,
        :provider_config,
        Map.put(Map.new(previous || %{}), :claude, %{request_defaults: %{model: "from-coding"}})
      )

      try do
        assert Models.default_model(:claude) == "from-coding"
      after
        restore_harness(:provider_config, previous)
      end

      Application.put_env(
        :jido_harness,
        :provider_config,
        Map.put(Map.new(previous || %{}), :claude, %{
          request_defaults: %{model: "from-coding"},
          session_defaults: %{model: "from-sessions"}
        })
      )

      try do
        assert Models.default_model(:claude) == "from-sessions"
      after
        restore_harness(:provider_config, previous)
      end
    end

    test "the whole answer crosses the wire and stays bounded" do
      encoded = Models.list() |> Wire.to_json() |> JSON.encode!()

      assert is_binary(encoded)
      # Bounded by construction, and small enough that a client may poll it. The figure is
      # a ceiling with room, not a measurement to chase.
      assert byte_size(encoded) < 256 * 1024
    end
  end

  defp provider_row(provider) do
    Models.list().providers |> Enum.find(&(&1.provider == provider))
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp restore_harness(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_harness(key, value), do: Application.put_env(:jido_harness, key, value)
end
