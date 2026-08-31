defmodule Ouroboros.Models do
  @moduledoc """
  The model catalogue this node can vouch for, per configured provider.

  A context meter needs two numbers a session cannot produce on its own: the window the
  model was given and what it costs. `usage` events carry the tokens spent; everything
  else comes from `llm_db`, a packaged snapshot of provider metadata that loads lazily
  and needs no network (`deps/llm_db`). This module is the seam between the two — it
  answers what `llm_db` knows about the models each *configured* provider draws from,
  and nothing about models nobody here can reach. Native is the deliberate exception to
  the one-catalogue-per-provider shape: its in-process transport can reach both the
  ChatGPT-backed OpenAI lane and Anthropic's API-key lane, so its row combines those
  catalogues and prefixes every id with the transport ReqLLM must use.

  ## What this is not

  Not a claim that a listed model will work. Ouroboros drives a vendor CLI or, for Native,
  a direct API; whether that account accepts a given model id is known only when it is
  called. A provider whose adapter does not normalize `:model` at all says so
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
    gemini: :google,
    grok: :xai,
    kimi: :moonshotai
  }

  # These are model transports inside `:native`, not Harness providers. The configured
  # native model is inserted first below and wins when it draws from the same catalogue
  # (for example an `openai:` API-key default replacing the packaged `openai_codex:` lane).
  @native_catalogs [openai_codex: :openai, anthropic: :anthropic]

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

  # Model metadata is intersected with the selected transport's vocabulary. Native owns
  # the whole request path and accepts the six OpenAI levels; vendor transports stay on
  # the three values their pinned Harness request schemas validate.

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
  def catalog(:native), do: native_catalog(native_model_provider())

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
  def default_model(:native), do: Ouroboros.Provider.Native.Model.configured_model()

  def default_model(provider) when is_atom(provider) do
    config = provider_config(provider)

    default_from(config, :session_defaults) || default_from(config, :request_defaults)
  end

  @doc "Reasoning levels advertised by one selected model and accepted by its transport."
  @spec reasoning_efforts(atom() | String.t() | nil, String.t() | nil) :: [String.t()]
  def reasoning_efforts(provider, model_id) do
    accepted = Ouroboros.ReasoningEffort.names_for_provider(provider)

    with provider when is_atom(provider) <- provider_atom(provider),
         model_id when is_binary(model_id) and model_id != "" <- model_id,
         model when not is_nil(model) <- find_model(provider, model_id) do
      model_reasoning_efforts(model, provider)
    else
      _unknown -> accepted
    end
  end

  defp provider_atom(provider) when is_atom(provider), do: provider

  defp provider_atom(provider) when is_binary(provider) do
    providers()
    |> Enum.find(&(Atom.to_string(&1) == provider))
  end

  defp providers do
    Enum.map(Ouroboros.providers(), & &1.provider)
  rescue
    _unavailable -> []
  end

  defp provider_models(:native) do
    lanes = native_catalogs()

    models =
      lanes
      |> Enum.flat_map(fn {prefix, catalog} ->
        Enum.map(catalog_models(catalog), &{prefix, catalog, &1})
      end)
      |> Enum.sort_by(
        fn {prefix, _catalog, model} ->
          {Map.get(model, :release_date) || "", model.id, Atom.to_string(prefix)}
        end,
        :desc
      )

    %{
      provider: :native,
      # Kept for older clients that know only the singular field. `catalogs` states the
      # complete truth for clients that understand Native's multi-transport row.
      catalog: catalog(:native),
      catalogs: Enum.map(lanes, &elem(&1, 1)),
      default: default_model(:native),
      model_option: model_option?(:native),
      total: length(models),
      models:
        models
        |> Enum.take(@max_models)
        |> Enum.map(fn {prefix, _catalog, model} ->
          model(model, Atom.to_string(prefix), :native)
        end)
    }
  end

  defp provider_models(provider) do
    catalog = catalog(provider)
    models = catalog_models(catalog)
    prefix = model_prefix(provider)

    %{
      provider: provider,
      catalog: catalog,
      default: default_model(provider),
      # Whether a model can be selected at all is the adapter's declaration, exactly as
      # every other capability is. A client that greys the picker reads this.
      model_option: model_option?(provider),
      total: length(models),
      models: models |> Enum.take(@max_models) |> Enum.map(&model(&1, prefix, provider))
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

  defp model(model, prefix, provider) do
    limits = Map.get(model, :limits) || %{}

    %{
      id: model_id(prefix, model.id),
      name: Map.get(model, :name),
      # The two numbers a context meter needs: how much fits, and how much can come back.
      context_window: number(Map.get(limits, :context)),
      max_output_tokens: number(Map.get(limits, :output)),
      release_date: Map.get(model, :release_date),
      reasoning_efforts: model_reasoning_efforts(model, provider),
      pricing: pricing(Map.get(model, :pricing))
    }
  end

  defp model_reasoning_efforts(model, provider) do
    accepted = Ouroboros.ReasoningEffort.names_for_provider(provider)

    model
    |> declared_reasoning_efforts()
    |> Enum.map(&reasoning_effort_name/1)
    |> Enum.filter(&(&1 in accepted))
    |> Enum.uniq()
    |> Enum.sort_by(&Enum.find_index(accepted, fn known -> known == &1 end))
  end

  # Prefer llm_db's canonical capability shape. The packaged snapshot predates that
  # enrichment for some models, so retain the opaque `extra.reasoning_options` fallback
  # that holds the same vendor declaration in those rows.
  defp declared_reasoning_efforts(%{capabilities: capabilities, extra: extra}) do
    case get_in(capabilities || %{}, [:reasoning, :effort]) do
      %{supported: true, values: values} when is_list(values) and values != [] -> values
      _absent -> extra_reasoning_efforts(extra)
    end
  end

  defp declared_reasoning_efforts(_model), do: []

  defp extra_reasoning_efforts(extra) when is_map(extra) do
    options = Map.get(extra, "reasoning_options") || Map.get(extra, :reasoning_options) || []

    Enum.flat_map(options, fn
      option when is_map(option) ->
        type = Map.get(option, "type") || Map.get(option, :type)
        values = Map.get(option, "values") || Map.get(option, :values)
        if reasoning_effort_name(type) == "effort" and is_list(values), do: values, else: []

      _other ->
        []
    end)
  end

  defp extra_reasoning_efforts(_extra), do: []
  defp reasoning_effort_name(value) when is_atom(value), do: Atom.to_string(value)
  defp reasoning_effort_name(value) when is_binary(value), do: value
  defp reasoning_effort_name(_value), do: ""

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

  defp find_model(:native, model_id) do
    Enum.find_value(native_catalogs(), fn {prefix, catalog} ->
      prefix = Atom.to_string(prefix)
      Enum.find(catalog_models(catalog), &(model_id(prefix, &1.id) == model_id))
    end)
  end

  defp find_model(provider, model_id) do
    catalog = catalog(provider)
    prefix = model_prefix(provider)

    if catalog do
      Enum.find(catalog_models(catalog), &(model_id(prefix, &1.id) == model_id))
    end
  end

  defp native_catalogs do
    configured =
      case native_model_provider() do
        nil ->
          []

        provider ->
          catalog = native_catalog(provider)
          if is_nil(catalog), do: [], else: [{provider, catalog}]
      end

    (configured ++ @native_catalogs)
    |> Enum.filter(fn {_prefix, catalog} -> known_catalog?(catalog) end)
    |> Enum.uniq_by(&elem(&1, 1))
  end

  defp native_catalog(:openai_codex), do: :openai

  defp native_catalog(provider) when is_atom(provider) and not is_nil(provider) do
    if known_catalog?(provider), do: provider
  end

  defp native_catalog(_unknown), do: nil

  defp model_prefix(_provider), do: nil
  defp model_id(nil, id), do: id
  defp model_id(prefix, id), do: prefix <> ":" <> id

  defp native_model_provider do
    case Ouroboros.Provider.Native.Model.configured_model() do
      model when is_binary(model) ->
        case String.split(model, ":", parts: 2) do
          [provider, _id] -> existing_provider(provider)
          _bare -> nil
        end

      _unset ->
        nil
    end
  end

  defp existing_provider(provider) do
    String.to_existing_atom(provider)
  rescue
    ArgumentError -> nil
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
