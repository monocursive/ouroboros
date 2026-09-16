defmodule Ouroboros.ModelsTest do
  @moduledoc """
  What the runtime can vouch for about a model: the window, the price, and which model
  provider's catalogue it came from.

  One row, because `:native` is the only provider — but three catalogues under it, one per
  model lane the in-process transport can reach.

  These read the packaged `llm_db` snapshot the build ships with, so a snapshot bump that
  changed a shape — a missing `limits.context`, a pricing component that stopped being
  per-million — fails here rather than in a footer that quietly shows nothing.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Models

  @moduletag :tmp_dir
  setup %{tmp_dir: dir} do
    Ouroboros.Test.FirstUseIsolation.setup(dir)
  end

  test "missing configured exact model is pinned without fabricated metadata" do
    id = "openai_codex:fixture-astra"
    Application.put_env(:ouroboros, :native_model, id)
    row = provider_row(:native)
    assert [%{id: ^id, configured: true, metadata: :unavailable} = model | _] = row.models
    assert model.context_window == nil
    assert model.max_output_tokens == nil
    assert model.pricing == nil
    assert model.release_date == nil
    assert "xhigh" in model.reasoning_efforts
    assert length(row.models) == 40
    assert Enum.count(row.models, &(&1.id == id)) == 1
    assert Models.list() == Models.list()
  end

  test "older configured catalogue model survives the cap, retains metadata and is deduplicated" do
    known =
      LLMDB.models(:openai)
      |> Enum.filter(
        &(is_binary(&1.release_date) and &1.retired != true and &1.deprecated != true and
            &1.catalog_only != true)
      )
      |> Enum.min_by(&{&1.release_date, &1.id})

    id = "openai_codex:" <> known.id
    Application.put_env(:ouroboros, :native_model, id)
    row = provider_row(:native)
    assert hd(row.models).id == id
    assert hd(row.models).release_date == known.release_date
    assert Enum.count(row.models, &(&1.id == id)) == 1
    total = row.total
    Application.put_env(:ouroboros, :native_model, "openai_codex:fixture-absent")
    assert provider_row(:native).total == total + 1
  end

  describe "the catalogue" do
    test "lookup resolves every lane's prefix, and nothing it cannot vouch for" do
      codex = Models.lookup("openai_codex:gpt-5.6-sol")
      assert is_map(codex)
      assert is_integer(get_in(codex, [Access.key(:limits), :context]))
      assert is_map(Map.get(codex, :cost))

      assert Models.lookup("grok:grok-4.3") == Models.lookup("xai:grok-4.3")
      assert is_map(Models.lookup("xai:grok-4.3"))
      assert is_map(Models.lookup("anthropic:claude-opus-5"))

      assert is_nil(Models.lookup("not-a-provider:not-a-model"))
      assert is_nil(Models.lookup(""))
      assert is_nil(Models.lookup(nil))
    end

    test "Astra is discoverable with metadata without being configured as the default" do
      native = provider_row(:native)
      id = "openai_codex:gpt-6-astra"

      refute native.default == id
      model = Enum.find(native.models, &(&1.id == id))

      assert model,
             "the packaged OpenAI catalogue must include GPT-6 Astra within the picker limit"

      assert model.name == "GPT-6 Astra"
      assert model.context_window == 1_050_000
      assert model.max_output_tokens == 128_000
      assert model.reasoning_efforts == ["low", "medium", "high", "xhigh", "max"]
      assert Models.reasoning_efforts(id) == model.reasoning_efforts
    end

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

    # Asked of the Anthropic lane, which is where the claim was asked before the native row
    # absorbed every catalogue: the packaged xAI snapshot carries image and quality models
    # that state no output ceiling, and this is a claim about the snapshot's shape for the
    # models a context meter is drawn for.
    test "a model carries the two numbers a context meter needs" do
      row = provider_row(:native)
      anthropic = Enum.filter(row.models, &String.starts_with?(&1.id, "anthropic:"))

      assert row.total > 0
      assert anthropic != []

      for model <- anthropic do
        assert is_binary(model.id) and model.id != ""
        assert is_integer(model.context_window) and model.context_window > 0
        assert is_integer(model.max_output_tokens) and model.max_output_tokens > 0
      end
    end

    test "reasoning levels are model-specific and limited to what the runtime accepts" do
      model =
        provider_row(:native).models
        |> Enum.find(&(&1.id == "openai_codex:gpt-5.6-sol"))

      assert model, "the packaged OpenAI catalogue no longer carries gpt-5.6-sol"
      assert model.reasoning_efforts == ["none", "low", "medium", "high", "xhigh", "max"]

      for row <- Models.list().providers, model <- row.models do
        assert Enum.all?(model.reasoning_efforts, &(&1 in Ouroboros.ReasoningEffort.names()))
      end

      assert Models.reasoning_efforts("anthropic:claude-opus-5") == [
               "low",
               "medium",
               "high",
               "xhigh",
               "max"
             ]
    end

    test "pricing is normalised to one million tokens, in the currency it was stated in" do
      row = provider_row(:native)
      model = Enum.find(row.models, &(&1.pricing != nil))

      assert model, "the packaged snapshot priced no model in any native lane"
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

    # `@catalogs` — the per-provider table that said which vendor's models each CLI ran,
    # and the `config :ouroboros, model_catalogs` override beside it — went with the
    # wrapped vendor CLIs. A lane is a model prefix now, not a CLI, and the mapping it
    # needs is the two-line one below.
    test "the native row carries one catalogue per model lane it can reach" do
      assert Models.catalog(:native) == :openai

      native = provider_row(:native)
      assert native.catalogs == [:openai, :anthropic, :xai]
      assert Enum.any?(native.models, &String.starts_with?(&1.id, "openai_codex:"))
      assert Enum.any?(native.models, &String.starts_with?(&1.id, "anthropic:"))
      assert Enum.any?(native.models, &String.starts_with?(&1.id, "xai:"))
    end

    test "the default model is the one the node configured, not one chosen here" do
      previous = Application.get_env(:ouroboros, :native_model)
      Application.delete_env(:ouroboros, :native_model)

      try do
        assert Models.default_model(:native) ==
                 Ouroboros.Provider.Native.Model.configured_model()
      after
        restore(:native_model, previous)
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
end
