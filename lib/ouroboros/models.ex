defmodule Ouroboros.Models do
  @moduledoc """
  The model catalogue this node can vouch for, per configured provider.

  A context meter needs two numbers a session cannot produce on its own: the window the
  model was given and what it costs. `usage` events carry the tokens spent; everything
  else comes from `llm_db`, a packaged snapshot of provider metadata that loads lazily
  and needs no network (`deps/llm_db`). This module is the seam between the two — it
  answers what `llm_db` knows about the models each *configured* provider draws from,
  and nothing about models nobody here can reach.

  ## What this is not

  Not a claim that a listed model will work. Ouroboros drives a vendor CLI; whether that
  CLI accepts a given model id depends on the account behind it, and only the CLI can
  answer. A provider whose adapter does not normalize `:model` at all says so
  (`model_option: false`) rather than offering a list nothing can select from.

  Not pricing this runtime charges or verifies. The rates are `llm_db`'s snapshot of the
  vendor's public list price, stated with the epoch they came from so a stale figure can
  be recognised as one. Cache and tool pricing beyond the four token rates is deliberately
  dropped: a footer shows a cost estimate, not an invoice.

  ## Which catalogue a provider draws from

  There is no declaration for this anywhere — an adapter spec names a CLI, not the vendor
  whose models it runs — so `@catalogs` is Ouroboros's own reading, listed provider by
  provider and overridable per node with

      config :ouroboros, model_catalogs: %{amp: :anthropic}

  A provider whose atom is itself an `llm_db` provider id needs no entry. A provider that
  resolves to nothing answers with an empty list and a `nil` catalogue rather than a guess:
  Amp normalizes no model at all, and Pi routes to whatever its `model_provider` names.
  """

  # Ouroboros provider => the `llm_db` provider whose catalogue that CLI draws from.
  # Each is a statement about which vendor's models the CLI runs, not about the CLI.
  @catalogs %{
    claude: :anthropic,
    codex: :openai,
    gemini: :google,
    grok: :xai,
    kimi: :moonshotai
  }

  # One provider's list is drawn into a picker, so it is bounded here rather than by the
  # client. Newest first, because that is the order a person scans for the model they
  # meant; the count that did not fit travels beside it so the bound is visible rather
  # than mistaken for the whole catalogue.
  @max_models 40

  # The four token rates a context meter and a cost line actually use. Everything else
  # `llm_db` prices — web search, file search, code-interpreter sessions — is per-call
  # and cannot be derived from a token count, so listing it would invite a wrong sum.
  @token_rates %{
    "token.input" => :input_per_mtok,
    "token.output" => :output_per_mtok,
    "token.cache_read" => :cache_read_per_mtok,
    "token.cache_write" => :cache_write_per_mtok
  }

  @doc """
  Returns the catalogue for every provider this node serves.

  Bounded per provider and deterministic: the same snapshot answers the same way on every
  node. `epoch` is `llm_db`'s own snapshot counter, carried so a client can tell two
  answers apart without diffing them.
  """
  @spec list() :: map()
  def list do
    # The snapshot loads on first query, so the epoch is read *after* the catalogue has
    # been asked for anything; reading it first reports the zero of an unloaded store.
    providers = Enum.map(providers(), &provider_models/1)

    %{source: "llm_db", epoch: epoch(), limit: @max_models, providers: providers}
  end

  @doc "Returns the `llm_db` provider a given Ouroboros provider draws its models from."
  @spec catalog(atom()) :: atom() | nil
  def catalog(provider) when is_atom(provider) do
    case Map.fetch(configured_catalogs(), provider) do
      {:ok, catalog} -> catalog
      :error -> if known_catalog?(provider), do: provider
    end
  end

  @doc """
  Returns the model this node configures for `provider`, or `nil`.

  Read from the Harness provider configuration a node actually starts sessions with —
  `session_defaults` first, because that is what an interactive session inherits, then
  `request_defaults` for a node that only configured the coding plane. Not a preference
  this module holds: a default nobody configured is `nil`, not a model picked here.
  """
  @spec default_model(atom()) :: String.t() | nil
  def default_model(provider) when is_atom(provider) do
    config = provider_config(provider)

    default_from(config, :session_defaults) || default_from(config, :request_defaults)
  end

  defp providers do
    Enum.map(Ouroboros.providers(), & &1.provider)
  rescue
    _unavailable -> []
  end

  defp provider_models(provider) do
    catalog = catalog(provider)
    models = catalog_models(catalog)

    %{
      provider: provider,
      catalog: catalog,
      default: default_model(provider),
      # Whether a model can be selected at all is the adapter's declaration, exactly as
      # every other capability is. A client that greys the picker reads this.
      model_option: model_option?(provider),
      total: length(models),
      models: models |> Enum.take(@max_models) |> Enum.map(&model/1)
    }
  end

  defp catalog_models(nil), do: []

  defp catalog_models(catalog) do
    catalog
    |> LLMDB.models()
    |> Enum.reject(&retired?/1)
    |> Enum.sort_by(&{Map.get(&1, :release_date) || "", &1.id}, :desc)
  rescue
    _unavailable -> []
  end

  # A model the snapshot marks as gone, or one it carries for reference without an
  # execution lane, is not something a session can be pointed at.
  defp retired?(model) do
    Map.get(model, :retired) == true or Map.get(model, :deprecated) == true or
      Map.get(model, :catalog_only) == true
  end

  defp model(model) do
    limits = Map.get(model, :limits) || %{}

    %{
      id: model.id,
      name: Map.get(model, :name),
      # The two numbers a context meter needs: how much fits, and how much can come back.
      context_window: number(Map.get(limits, :context)),
      max_output_tokens: number(Map.get(limits, :output)),
      release_date: Map.get(model, :release_date),
      pricing: pricing(Map.get(model, :pricing))
    }
  end

  defp pricing(%{components: components} = pricing) when is_list(components) do
    rates =
      Enum.reduce(components, %{}, fn component, rates ->
        case Map.fetch(@token_rates, Map.get(component, :id)) do
          {:ok, field} -> put_rate(rates, field, component)
          :error -> rates
        end
      end)

    if rates == %{},
      do: nil,
      else: Map.put(rates, :currency, Map.get(pricing, :currency) || "USD")
  end

  defp pricing(_absent), do: nil

  # `llm_db` states a rate against a unit count (`rate` per `per` tokens). Normalised to
  # one million here so every figure on the wire is comparable without carrying the
  # divisor; a component with a nonsense `per` is dropped rather than divided by zero.
  defp put_rate(rates, field, %{rate: rate, per: per})
       when is_number(rate) and is_number(per) and per > 0 do
    Map.put(rates, field, rate * 1_000_000 / per)
  end

  defp put_rate(rates, _field, _component), do: rates

  defp number(value) when is_integer(value) and value > 0, do: value
  defp number(_value), do: nil

  defp model_option?(provider) do
    case Jido.Harness.Registry.spec(provider) do
      {:ok, spec} -> :model in spec.normalized_options
      _unresolvable -> false
    end
  end

  defp known_catalog?(provider) do
    match?({:ok, _provider}, LLMDB.provider(provider))
  rescue
    _unavailable -> false
  end

  defp configured_catalogs do
    case Application.get_env(:ouroboros, :model_catalogs) do
      overrides when is_map(overrides) or is_list(overrides) ->
        Map.merge(@catalogs, Map.new(overrides))

      _unset ->
        @catalogs
    end
  end

  defp provider_config(provider) do
    case Application.get_env(:jido_harness, :provider_config, %{}) do
      config when is_map(config) or is_list(config) ->
        config |> Map.new() |> Map.get(provider, %{}) |> normalize_map()

      _invalid ->
        %{}
    end
  end

  defp default_from(config, key) do
    case config |> Map.get(key, %{}) |> normalize_map() |> Map.get(:model) do
      model when is_binary(model) and model != "" -> model
      _absent -> nil
    end
  end

  defp normalize_map(value) when is_map(value) or is_list(value) do
    value
    |> Map.new()
    |> Map.new(fn
      {key, nested} when is_binary(key) -> {safe_atom(key), nested}
      pair -> pair
    end)
  end

  defp normalize_map(_value), do: %{}

  # Configuration keys arrive from a node's own config file, so a string spelling of a
  # key this module knows is honoured and anything else is left as the string it was
  # rather than minting an atom that is never collected.
  defp safe_atom(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> key
  end

  defp epoch do
    LLMDB.epoch()
  rescue
    _unavailable -> nil
  end
end
