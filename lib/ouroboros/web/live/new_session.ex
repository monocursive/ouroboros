defmodule Ouroboros.Web.Live.NewSession do
  @moduledoc """
  Everything the new-session form decides, with no LiveView in it.

  `Ouroboros.Web.Live.NewSessionLive` draws this and owns the calls; this module owns the
  answers — which provider rows exist, what the model control can honestly be, what the
  request will carry, and the sentence that says so. Split for the reason
  `Ouroboros.Web.Live.Rail` is split from the deck: a rule that can be asserted without a
  socket is a rule that stays asserted.

  ## The one property this module exists to hold

  **The hint line and the request are built by the same function.** `model_intent/3`
  returns both `:send` (the `model` option, or `nil` for none at all) and `:hint` (the
  sentence under the field), and `start_params/2` reads the same `:send`. A surface that
  computed the sentence separately from the value could tell an operator it was sending
  one thing while sending another, which is the exact failure the desktop's model picker
  was rebuilt to prevent (`tui/src/desktop.rs`, the note on `ModelIntent`).

  ## Absent, not defaulted

  The three optional postures — `model`, `sandbox_mode`, `reasoning_effort` — are omitted
  from the request when the operator did not state them. Omission is not the same as
  sending `"default"`: it leaves the choice with the plane, which is the only party that
  knows what the selected transport can actually normalize.

  ## What a stored default is, and what it is not

  `new/1` seeds this struct from `Ouroboros.Web.Prefs`, and the semantics are the
  **desktop's**, which `docs/DESKTOP.md` states in one sentence: "What the file supplies is
  where the control *starts*; an explicit pick is what gets sent, and an untouched panel
  with no stored default states no posture at all, leaving the plane to decide."

  Read carefully, that sentence says a stored default **is** sendable — only the *absence*
  of one leaves the field off the request — and the desktop implements exactly that:
  `let sandbox = self.new_sandbox.or(configured_sandbox)` under the comment "What the form
  will actually send: the operator's pick, else the stored default, else nothing"
  (`tui/src/desktop.rs:2264-2269`). So a seeded control here is a *stated* control on all
  five keys, and "absent, not defaulted" continues to mean what it always meant: nothing
  the operator has never chosen — this time or on a previous session — ever reaches the
  plane. The alternative, a file that is displayed but not sent, would show an operator one
  posture and request another, which is the exact failure `model_intent/3` exists to
  prevent.

  A field with no stored value and no pick is still absent, and `start_params/2` is
  unchanged: it reads the struct, not the file, and cannot tell where a value came from.
  """

  alias Ouroboros.Gateway.Methods.Browse

  @sandbox_modes ["read_only", "workspace_write", "unrestricted"]
  @efforts ["none", "low", "medium", "high", "xhigh", "max"]

  @typedoc "Which model row a choice stands for. Not the row's label — the label is drawn."
  @type model_choice :: :runtime_default | :custom | {:catalog, String.t()}

  @typedoc """
  What the model control can honestly be for the selected provider.

  `:unsupported` is the adapter declaring it normalizes no `model` option at all;
  `{:text, hint}` is every path with no catalogue to filter, which is the field this form
  had before `runtime.models` existed; `{:rows, rows, total}` is the catalogue.
  """
  @type model_field ::
          :unsupported
          | {:text, String.t() | nil}
          | {:rows, [map()], non_neg_integer()}

  @enforce_keys []
  defstruct id: nil,
            provider: nil,
            model_choice: :runtime_default,
            model_text: "",
            model_search: "",
            workspace: "",
            sandbox: nil,
            effort: nil

  @type t :: %__MODULE__{
          id: String.t() | nil,
          provider: String.t() | nil,
          model_choice: model_choice(),
          model_text: String.t(),
          model_search: String.t(),
          workspace: String.t(),
          sandbox: String.t() | nil,
          effort: String.t() | nil
        }

  @doc """
  A fresh form, carrying the caller-owned session id it will start under.

  The id is minted here rather than left to the runtime because `interactive.start`'s
  table entry admits `outcome: :unknown` — a ceiling breach cannot say whether the session
  was created. A caller-owned id makes the retry adopt the same immutable intent instead
  of starting a second session (`docs/PROTOCOL.md`, `interactive.start`'s `id`), and it
  survives a re-render, so the same form retried twice is one session either way.

  Given a map from `Ouroboros.Web.Prefs.read/1`, the form starts where the operator's last
  successful start left it. Every value in that map has already been checked against the
  vocabulary its parameter admits, so nothing here re-validates and nothing here can be
  seeded with something `start_params/2` would then decline to send — the seed and the
  request would disagree, and this module exists so they cannot.

  The stored model is seeded as a **custom** choice carrying the spec verbatim. That is the
  one seed that is correct under every model field: `{:text, _}` reads the typed value,
  `{:rows, _, _}` offers a custom row unconditionally (`rows/1` appends one), and
  `:unsupported` sends nothing whatever is typed. `promote/2` upgrades it to the catalogue
  row once a catalogue has actually arrived and turns out to list it — a change to how the
  form *draws*, never to what it sends.
  """
  @spec new(map()) :: t()
  def new(prefs \\ %{}) when is_map(prefs) do
    %__MODULE__{
      id: mint_id(),
      provider: Map.get(prefs, "provider"),
      model_choice: if(Map.has_key?(prefs, "model"), do: :custom, else: :runtime_default),
      model_text: Map.get(prefs, "model", ""),
      workspace: Map.get(prefs, "workspace", ""),
      sandbox: Map.get(prefs, "sandbox_mode", "workspace_write"),
      effort: Map.get(prefs, "reasoning_effort")
    }
  end

  @doc """
  Draw a seeded custom model as its catalogue row, when the catalogue turns out to have one.

  Called once, after `runtime.models` answers. `model_option/3` returns the same string for
  `{:catalog, id}` and for `:custom` carrying that id, so this cannot change the request —
  it only stops a remembered catalogue model from being shown in the "custom" box as though
  this runtime had never heard of it.
  """
  @spec promote(t(), model_field()) :: t()
  def promote(%__MODULE__{model_choice: :custom} = form, field) do
    case trimmed(form.model_text) do
      nil ->
        form

      id ->
        if offers?(field, {:catalog, id}), do: %{form | model_choice: {:catalog, id}}, else: form
    end
  end

  def promote(%__MODULE__{} = form, _field), do: form

  @doc "The three sandbox postures the form offers, least power first."
  @spec sandbox_modes() :: [String.t()]
  def sandbox_modes, do: @sandbox_modes

  @doc "The reasoning levels the gateway's vocabulary names."
  @spec efforts() :: [String.t()]
  def efforts, do: @efforts

  @doc "The levels offered for the selected model, or the provider vocabulary if unknown."
  @spec efforts(t(), model_field()) :: [String.t()]
  def efforts(%__MODULE__{} = form, {:rows, rows, _total}) do
    case Enum.find(rows, &(&1.choice == form.model_choice)) do
      %{reasoning_efforts: efforts} when is_list(efforts) -> efforts
      _unknown -> Ouroboros.ReasoningEffort.names_for_provider(form.provider)
    end
  end

  def efforts(%__MODULE__{}, :unsupported), do: []

  def efforts(%__MODULE__{} = form, _field),
    do: Ouroboros.ReasoningEffort.names_for_provider(form.provider)

  # ------------------------------------------------------------------------------------
  # Provider rows
  # ------------------------------------------------------------------------------------

  @doc """
  One row per provider `runtime.providers` reported, in the order it reported them.

  A row whose probe found nothing is retained so the page can explain why it is
  unavailable, but the browser disables it. Starting a provider that this runtime already
  proved it cannot drive turns a deterministic setup problem into a late refusal.
  """
  @spec provider_rows(term()) :: [map()]
  def provider_rows(entries) when is_list(entries) do
    Enum.flat_map(entries, &provider_row/1)
  end

  def provider_rows(_other), do: []

  defp provider_row(%{provider: provider} = entry) do
    status = Map.get(entry, :status)

    [
      %{
        name: to_string(provider),
        detected?: detected?(status),
        note: probe_note(status, Map.get(entry, :error)),
        # Native reports credential names and booleans only. Keeping that non-secret
        # projection lets the form stop an Anthropic request before it becomes a failed
        # turn, without ever reading or transporting the key itself.
        credentials: credential_rows(status)
      }
    ]
  end

  defp provider_row(_other), do: []

  defp credential_rows(%{details: details}) when is_map(details) do
    details
    |> value(:credentials)
    |> List.wrap()
    |> Enum.flat_map(fn
      row when is_map(row) ->
        provider = identifier(value(row, :provider))
        env = trimmed(value(row, :env))
        present = value(row, :present)
        source = identifier(value(row, :source))
        workspace_env = trimmed(value(row, :workspace_env))
        workspace_configured = value(row, :workspace_configured) == true

        if provider && env && is_boolean(present),
          do: [
            %{
              provider: provider,
              env: env,
              present: present,
              source: source,
              workspace_env: workspace_env,
              workspace_configured?: workspace_configured
            }
          ],
          else: []

      _other ->
        []
    end)
  end

  defp credential_rows(_status), do: []

  defp detected?(%{installed: true, compatible: true}), do: true
  defp detected?(_status), do: false

  # Only what the probe actually reported. "no executable found" is the probe's finding
  # when it ran; a probe that did not run says so instead of borrowing that sentence.
  defp probe_note(nil, nil), do: "the probe did not answer"
  defp probe_note(nil, error), do: "the probe did not answer: #{describe(error)}"
  defp probe_note(%{installed: false}, _error), do: "no executable found"

  defp probe_note(%{compatible: false} = status, _error) do
    case Map.get(status, :version) do
      version when is_binary(version) and version != "" ->
        "version #{version} is not one this build can drive"

      _unstated ->
        "the version this node found is not one this build can drive"
    end
  end

  defp probe_note(_status, _error), do: nil

  @doc """
  The footnote drawn once under the picker when any row is unavailable, or `nil`.
  """
  @spec provider_footnote([map()]) :: String.t() | nil
  def provider_footnote(rows) when is_list(rows) do
    if Enum.any?(rows, &(not &1.detected?)) do
      "Unavailable providers stay listed so you can see what this computer is missing."
    end
  end

  # ------------------------------------------------------------------------------------
  # The model control
  # ------------------------------------------------------------------------------------

  @doc """
  What the model control becomes for `provider`, given whatever `runtime.models` answered.

  Every path that cannot offer a list falls back to the text input rather than to an empty
  picker, because an empty picker claims this runtime knows of no models and none of these
  paths know that. Ported from `model_field` in `tui/src/desktop.rs`.
  """
  @spec model_field(term(), String.t() | nil) :: model_field()
  def model_field(catalogue, provider) do
    provider = trimmed(provider)

    cond do
      not is_map(catalogue) -> {:text, nil}
      provider == nil -> {:text, "choose a provider to see its models"}
      true -> provider_field(catalogue, provider)
    end
  end

  defp provider_field(catalogue, provider) do
    case Enum.find(List.wrap(catalogue[:providers]), &(to_string(&1[:provider]) == provider)) do
      nil ->
        {:text, "this runtime's model list does not mention #{provider}"}

      %{model_option: false} ->
        :unsupported

      row ->
        {:rows, rows(row), row[:total] || 0}
    end
  end

  defp rows(row) do
    default = trimmed(row[:default])

    catalogue =
      row
      |> Map.get(:models)
      |> List.wrap()
      |> Enum.filter(&agent_model?(&1, default))
      |> Enum.map(fn model ->
        id = to_string(model[:id])

        %{
          choice: {:catalog, id},
          model: id,
          label: trimmed(model[:name]) || short_model_id(id),
          detail: model_detail(model, id),
          reasoning_efforts: List.wrap(model[:reasoning_efforts])
        }
      end)

    [default_row(row)] ++ catalogue ++ [custom_row()]
  end

  defp default_row(row) do
    default = trimmed(row[:default])

    label =
      case default do
        nil ->
          "Recommended"

        default ->
          name =
            row
            |> Map.get(:models)
            |> List.wrap()
            |> Enum.find(&(to_string(&1[:id]) == default))
            |> then(fn
              nil -> short_model_id(default)
              model -> trimmed(model[:name]) || short_model_id(default)
            end)

          "Recommended · #{name}"
      end

    efforts =
      case default do
        nil ->
          nil

        default ->
          row
          |> Map.get(:models)
          |> List.wrap()
          |> Enum.find(&(to_string(&1[:id]) == default))
          |> then(fn
            nil -> nil
            model -> List.wrap(model[:reasoning_efforts])
          end)
      end

    %{
      choice: :runtime_default,
      model: default,
      label: label,
      detail: "Let Ouroboros choose the best model",
      reasoning_efforts: efforts
    }
  end

  defp custom_row do
    %{
      choice: :custom,
      model: nil,
      label: "Custom model…",
      detail: "For advanced provider configurations",
      reasoning_efforts: nil
    }
  end

  @doc """
  Catalogue rows grouped by the execution path the form actually selected.

  Native rows are grouped by the company that provides the model and explicitly marked as
  direct, no-CLI calls. A CLI-backed provider gets one group bearing that CLI's name. The
  runtime's ranking stays authoritative inside every group. The form-owned Recommended
  and Custom rows are deliberately absent; they frame the groups separately in the
  control.

  Transport namespaces that reach the same model provider share one heading — notably
  `openai:` API models and `openai_codex:` ChatGPT-backed models both belong to OpenAI.
  Their exact transport remains visible in each row's detail.
  """
  @spec model_groups([map()], String.t() | nil) :: [%{label: String.t(), rows: [map()]}]
  def model_groups(rows, provider \\ nil)

  def model_groups(rows, provider) when is_list(rows) do
    rows
    |> Enum.filter(&catalogue?/1)
    |> Enum.reduce(%{}, fn row, groups ->
      label = model_group_label(row.model, provider)
      Map.update(groups, label, [row], &[row | &1])
    end)
    |> Enum.map(fn {label, rows} -> %{label: label, rows: Enum.reverse(rows)} end)
    |> Enum.sort_by(&String.downcase(&1.label))
  end

  def model_groups(_rows, _provider), do: []

  defp model_group_label(model, "native"),
    do: "#{model_provider_label(model)} · direct via Ouroboros (no CLI)"

  defp model_group_label(_model, provider) when is_binary(provider),
    do: provider_route(provider).group

  defp model_group_label(model, _provider), do: model_provider_label(model)

  defp model_provider_label(model) when is_binary(model) do
    model
    |> String.split(":", parts: 2)
    |> List.first()
    |> case do
      "anthropic" -> "Anthropic"
      "google" -> "Google"
      "google_vertex" -> "Google"
      "ollama" -> "Ollama"
      "openai" -> "OpenAI"
      "openai_codex" -> "OpenAI"
      "openrouter" -> "OpenRouter"
      "xai" -> "xAI"
      namespace when namespace == model -> "Other"
      namespace -> namespace |> String.replace("_", " ") |> String.capitalize()
    end
  end

  defp model_provider_label(_model), do: "Other"

  @doc "Human-readable execution path for one provider choice."
  @spec provider_route(String.t() | nil) :: %{
          name: String.t(),
          short: String.t(),
          badge: String.t(),
          title: String.t(),
          detail: String.t(),
          group: String.t()
        }
  def provider_route("native") do
    %{
      name: "Ouroboros AI",
      short: "direct model APIs, no CLI",
      badge: "Direct · no CLI",
      title: "Ouroboros runs this model directly.",
      detail: "Its built-in agent loop calls the model API; no model CLI is launched.",
      group: "Direct via Ouroboros (no CLI)"
    }
  end

  def provider_route("claude"),
    do: cli_route("Claude", "Claude Code CLI", "Claude Code CLI")

  def provider_route("gemini"), do: cli_route("Gemini", "Gemini CLI", "Gemini CLI")

  def provider_route("grok") do
    cli_route(
      "Grok",
      "Grok Build CLI",
      "Grok Build CLI",
      "The CLI owns the model session and can use a SpaceXAI subscription or xAI API key."
    )
  end

  def provider_route("kimi"), do: cli_route("Kimi", "Kimi Code CLI", "Kimi Code CLI")

  def provider_route("opencode"),
    do: cli_route("OpenCode", "OpenCode CLI", "OpenCode CLI")

  def provider_route("pi"), do: cli_route("Pi", "Pi CLI", "Pi CLI")
  def provider_route("amp"), do: cli_route("Amp", "Amp CLI", "Amp CLI")

  def provider_route("zai") do
    cli_route(
      "Z.ai",
      "Claude CLI configured for Z.ai",
      "Claude CLI for Z.ai",
      "Claude CLI owns the model session and is configured to use Z.ai's GLM models."
    )
  end

  def provider_route(nil) do
    %{
      name: "finding provider",
      short: "execution path unknown",
      badge: "Not selected",
      title: "Choose an AI provider.",
      detail: "Its execution path will be shown here before you select a model.",
      group: "Provider not selected"
    }
  end

  def provider_route(provider) when is_binary(provider) do
    %{
      name: provider,
      short: "external provider adapter",
      badge: "Provider adapter",
      title: "Runs through the #{provider} provider adapter.",
      detail: "This adapter does not declare a more specific execution path to the form.",
      group: "#{provider} provider adapter"
    }
  end

  defp cli_route(name, short, group, detail \\ nil) do
    %{
      name: name,
      short: short,
      badge: "CLI-backed",
      title: "Runs through #{short}.",
      detail:
        detail ||
          "The CLI owns the model session and tools; Ouroboros supervises and normalizes it.",
      group: group
    }
  end

  # The readable name is the option label. Detail keeps the exact id available to an
  # advanced reader without forcing everybody else to parse a provider namespace first.
  defp model_detail(model, id) do
    case window(model[:context_window]) do
      nil -> id
      window -> "#{id} · #{window}"
    end
  end

  defp short_model_id(id) do
    id
    |> String.split(":", parts: 2)
    |> List.last()
    |> String.replace("-", " ")
  end

  # The shared catalogue also contains embedding, image, audio, moderation and realtime
  # lanes. They cannot run an interactive coding turn, so offering them here creates a
  # choice whose only outcome is a provider refusal.
  defp agent_model?(model, default) do
    id = model |> Map.get(:id) |> to_string()

    id == default or
      not Regex.match?(
        ~r/(?:^|[-_:])(embedding|image|moderation|omni|realtime|transcrib|tts|whisper|audio)(?:$|[-_:])/i,
        id
      )
  end

  defp window(tokens) when is_integer(tokens) and tokens >= 1_000 and tokens < 1_000_000,
    do: "#{div(tokens, 1_000)}K context"

  defp window(tokens) when is_integer(tokens) and tokens >= 1_000_000,
    do: "#{:erlang.float_to_binary(tokens / 1_000_000, decimals: 1)}M context"

  defp window(_tokens), do: nil

  @doc """
  The rows a search term leaves, with the two framing rows and the current choice kept.

  The filter runs **here**, over the rows this process holds, and the choice the socket
  holds is what the request reads — so there is no client-side widget list that could
  resolve a label against a different set of rows than the one the operator picked from.
  That indirection is the whole reason the desktop's picker needed a separate
  authoritative hint line (`tui/src/desktop.rs`, the note on `DesktopView::model_choice`);
  LiveView state removes it, and the hint stays anyway because it is worth saying.

  Two rows are never filtered out. "Runtime default" and "Custom…" are this form's own
  rather than the catalogue's — a person whose search matches nothing still needs the row
  that lets them type an id. And **the chosen row always survives its own search**: a
  `<select>` whose selected value is not among its options draws some other row, which is
  precisely the disagreement between widget and state this design exists to make
  impossible.
  """
  @spec search(model_field(), String.t(), model_choice()) :: model_field()
  def search({:rows, rows, total}, term, choice) do
    case trimmed(term) do
      nil ->
        {:rows, rows, total}

      term ->
        needle = String.downcase(term)

        kept =
          Enum.filter(rows, fn row ->
            row.choice == choice or not catalogue?(row) or matches?(row, needle)
          end)

        {:rows, kept, total}
    end
  end

  def search(field, _term, _choice), do: field

  defp catalogue?(row), do: match?({:catalog, _id}, row.choice)

  defp matches?(row, needle) do
    String.contains?(String.downcase("#{row.label} #{row.detail}"), needle)
  end

  @doc "How many catalogue rows a field carries, ignoring this form's two framing rows."
  @spec listed(model_field()) :: non_neg_integer()
  def listed({:rows, rows, _total}), do: Enum.count(rows, &catalogue?/1)
  def listed(_field), do: 0

  @doc """
  Whether `choice` is something this field can actually offer.

  Asked whenever the provider changes: a model picked under the previous provider is not
  necessarily a row under the new one, and a choice with no row would leave the form
  claiming a model the control cannot show.
  """
  @spec offers?(model_field(), model_choice()) :: boolean()
  def offers?({:rows, rows, _total}, choice), do: Enum.any?(rows, &(&1.choice == choice))
  def offers?(_field, choice), do: choice == :runtime_default

  @doc """
  What the form will send for `model`, and the sentence that says so.

  Returns `%{send: String.t() | nil, hint: String.t()}`. `start_params/2` reads `:send`
  and the form draws `:hint`, so the two cannot disagree.
  """
  @spec model_intent(model_field(), model_choice(), String.t()) :: %{
          send: String.t() | nil,
          hint: String.t()
        }
  def model_intent(field, choice, typed) do
    send = model_option(field, choice, typed)

    hint =
      case {field, send} do
        {:unsupported, _send} -> "This provider chooses its own model"
        {_field, nil} -> "Ouroboros will choose the recommended model"
        {_field, model} -> "Using #{model}"
      end

    %{send: send, hint: hint}
  end

  @doc "The model intent for a whole form, so a caller never has to thread the three parts."
  @spec model_intent(t(), model_field()) :: %{send: String.t() | nil, hint: String.t()}
  def model_intent(%__MODULE__{} = form, field),
    do: model_intent(field, form.model_choice, form.model_text)

  # The adapter normalizes no model option, so naming one would name something nothing
  # downstream reads.
  defp model_option(:unsupported, _choice, _typed), do: nil
  defp model_option({:text, _hint}, _choice, typed), do: trimmed(typed)
  defp model_option({:rows, _rows, _total}, :custom, typed), do: trimmed(typed)
  defp model_option({:rows, _rows, _total}, {:catalog, id}, _typed), do: trimmed(id)
  defp model_option(_field, _choice, _typed), do: nil

  @doc """
  Whether the effective model needs a connected ChatGPT subscription.

  The prefix is the whole test: `runtime.models` already stamps `openai_codex:` onto the
  ids that resolve through subscription OAuth, and an official `openai:` API-key model
  does not consult the account surface at all.
  """
  @spec requires_chatgpt?(t(), model_field()) :: boolean()
  def requires_chatgpt?(%__MODULE__{} = form, field) do
    case model_intent(form, field).send do
      model when is_binary(model) -> String.starts_with?(model, "openai_codex:")
      nil -> false
    end
  end

  @doc "Whether the selected managed provider runs through the first-party Grok CLI."
  @spec requires_grok?(t()) :: boolean()
  def requires_grok?(%__MODULE__{provider: "grok"}), do: true
  def requires_grok?(%__MODULE__{}), do: false

  @doc "API-key readiness for a selected direct Anthropic/xAI model or managed Grok."
  @spec api_key_card(t(), model_field(), term()) :: map() | nil
  def api_key_card(%__MODULE__{} = form, field, provider_rows) do
    case effective_model(form, field) do
      "anthropic:" <> _model ->
        api_key_card(
          provider_rows,
          form.provider,
          "anthropic",
          "Anthropic",
          "ANTHROPIC_API_KEY",
          managed?: false,
          workspace_env: "ANTHROPIC_WORKSPACE_ID"
        )

      "xai:" <> _model ->
        api_key_card(
          provider_rows,
          form.provider,
          "xai",
          "xAI",
          "XAI_API_KEY",
          managed?: false
        )

      _other when form.provider == "grok" ->
        api_key_card(
          provider_rows,
          form.provider,
          "xai",
          "xAI",
          "XAI_API_KEY",
          managed?: true
        )

      _other ->
        nil
    end
  end

  defp api_key_card(rows, selected_provider, model_provider, label, env, opts)
       when is_list(rows) and is_list(opts) do
    credential =
      rows
      |> Enum.find(&(trimmed(&1[:name]) == trimmed(selected_provider)))
      |> case do
        %{credentials: credentials} when is_list(credentials) ->
          Enum.find(credentials, &(trimmed(&1[:provider]) == model_provider and &1[:env] == env))

        _unknown ->
          nil
      end

    state =
      case credential do
        %{present: true} -> :available
        %{present: false} -> :required
        _not_reported -> :checking
      end

    %{
      provider: label,
      key: model_provider,
      env: env,
      managed?: Keyword.get(opts, :managed?, false),
      workspace_env: (credential && credential[:workspace_env]) || opts[:workspace_env],
      workspace_configured?: credential != nil and credential[:workspace_configured?] == true,
      state: state,
      source: credential && credential[:source],
      usable?: state == :available
    }
  end

  defp api_key_card(_rows, _selected_provider, model_provider, label, env, opts),
    do: %{
      provider: label,
      key: model_provider,
      env: env,
      managed?: Keyword.get(opts, :managed?, false),
      workspace_env: opts[:workspace_env],
      workspace_configured?: false,
      state: :checking,
      source: nil,
      usable?: false
    }

  @doc "Non-secret SpaceXAI subscription readiness and pending device login."
  @spec grok_account_card(term(), term()) :: map()
  def grok_account_card(read, login) do
    pending? = grok_pending_login?(read) or is_map(login)

    state =
      cond do
        not is_map(read) and not pending? -> :checking
        grok_usable?(read) -> :connected
        pending? -> :waiting
        true -> :required
      end

    %{
      state: state,
      usable?: grok_usable?(read),
      identity: grok_identity(read),
      code: login && login[:code],
      url: login && login[:url],
      login_id: login && login[:login_id],
      error: grok_login_error(read)
    }
  end

  @doc "Whether the first-party CLI reports a usable subscription credential."
  @spec grok_usable?(term()) :: boolean()
  def grok_usable?(%{"account" => %{"type" => "grok_subscription"}}), do: true
  def grok_usable?(%{"requiresGrokAuth" => false}), do: true
  def grok_usable?(_read), do: false

  defp grok_pending_login?(%{"login" => %{"status" => status}})
       when status in ["starting", "pending"],
       do: true

  defp grok_pending_login?(_read), do: false

  defp grok_login_error(%{"login" => %{"error" => error}})
       when is_binary(error) and error != "",
       do: error

  defp grok_login_error(_read), do: nil

  defp grok_identity(%{"account" => account}) when is_map(account),
    do: trimmed(account["label"]) || "SpaceXAI subscription"

  defp grok_identity(_read), do: nil

  defp effective_model(%__MODULE__{} = form, field) do
    model_intent(form, field).send || selected_default_model(field, form.model_choice)
  end

  defp selected_default_model({:rows, rows, _total}, :runtime_default) do
    case Enum.find(rows, &(&1.choice == :runtime_default)) do
      %{model: model} -> trimmed(model)
      _unknown -> nil
    end
  end

  defp selected_default_model(_field, _choice), do: nil

  @doc "The `<option>` value one choice travels to the browser as."
  @spec choice_value(model_choice()) :: String.t()
  def choice_value(:runtime_default), do: "runtime_default"
  def choice_value(:custom), do: "custom"
  def choice_value({:catalog, id}), do: "catalog:" <> id

  @doc """
  The choice one `<option>` value decodes back to.

  Anything this does not recognise is "runtime default", which is the one answer that
  sends nothing — an unreadable pick must never be resolved into a model.
  """
  @spec choice(term()) :: model_choice()
  def choice("custom"), do: :custom

  def choice("catalog:" <> id) when byte_size(id) > 0, do: {:catalog, id}

  def choice(_other), do: :runtime_default

  # ------------------------------------------------------------------------------------
  # The ChatGPT account card
  # ------------------------------------------------------------------------------------

  @doc """
  Non-secret ChatGPT readiness, folded from `account.read` and whatever login is in flight.

  `read` is the method's answer (or `nil` while it has not answered), `login` is the
  `account.login.start` reply this view is holding. Nothing here can carry a credential:
  the account surface projects an identity, a boolean, and a login status, and the token
  itself never leaves the runtime's private file.

  Four states, and they are different facts rather than degrees of the same one:

    * `:checking` — nothing has answered yet, so nothing is claimed.
    * `:connected` — the runtime says the subscription model can run now.
    * `:waiting` — a login is pending; the code and the verification link belong here.
    * `:required` — resolved, and the answer was no.
  """
  @spec account_card(term(), term()) :: map()
  def account_card(read, login) do
    pending? = pending_login?(read) or is_map(login)

    state =
      cond do
        not is_map(read) and not pending? -> :checking
        usable?(read) -> :connected
        pending? -> :waiting
        true -> :required
      end

    %{
      state: state,
      usable?: usable?(read),
      identity: identity(read),
      code: login && login[:code],
      url: login && login[:url],
      login_id: login && login[:login_id],
      error: login_error(read)
    }
  end

  @doc "Whether the runtime says an `openai_codex:` model can run right now."
  @spec usable?(term()) :: boolean()
  def usable?(%{"account" => %{"type" => "chatgpt"}}), do: true
  def usable?(%{"requiresOpenaiAuth" => false}), do: true
  def usable?(_read), do: false

  @doc """
  Whether a URL may be offered as a link.

  HTTPS only, and the same rule the desktop's sign-in card holds: a sign-in URL that
  arrived over anything else is shown as text and never made clickable, because the one
  thing this card hands a person is a place to type their password into.
  """
  @spec https?(term()) :: boolean()
  def https?(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: "https", host: host}} when is_binary(host) and host != "" -> true
      _otherwise -> false
    end
  end

  def https?(_url), do: false

  @doc "Builds a credential update without retaining raw keys in form or socket state."
  def credential_params(form) do
    params =
      case Map.get(form, "anthropic_api_key") do
        value when is_binary(value) ->
          case String.trim(value) do
            "" -> %{}
            key -> %{"api_key" => key}
          end

        _ ->
          %{}
      end

    put_workspace_param(params, form)
  end

  @doc """
  Adds a workspace id to a credential payload, or an empty string that the gateway
  treats as a clear.

  A typed workspace id wins. The clear checkbox is the only way to send an empty
  `workspace_id` without a new value, so a blank field still means "keep" when the key
  is not also being replaced.
  """
  @spec put_workspace_param(map(), map()) :: map()
  def put_workspace_param(params, form) when is_map(params) and is_map(form) do
    workspace = form["anthropic_workspace_id"]
    clear? = form["clear_anthropic_workspace"] in ["true", "on"]

    cond do
      is_binary(workspace) and String.trim(workspace) != "" ->
        Map.put(params, "workspace_id", String.trim(workspace))

      clear? ->
        Map.put(params, "workspace_id", "")

      true ->
        params
    end
  end

  defp pending_login?(%{"login" => %{"status" => "pending"}}), do: true
  defp pending_login?(_read), do: false

  defp login_error(%{"login" => %{"error" => error}}) when is_binary(error) and error != "",
    do: error

  defp login_error(_read), do: nil

  defp identity(%{"account" => account}) when is_map(account) do
    trimmed(account["email"]) || plan(account["planType"]) || "ChatGPT subscription"
  end

  defp identity(_read), do: nil

  defp plan(value) do
    case trimmed(value) do
      nil -> nil
      plan -> String.capitalize(plan)
    end
  end

  # ------------------------------------------------------------------------------------
  # The request
  # ------------------------------------------------------------------------------------

  @doc """
  The exact `interactive.start` params, or the reason there are none.

  The envelope is closed, so every key here is one the method's table entry names, and a
  key is present **only** when the operator stated it:

    * `id` — always. Caller-owned idempotency, minted with the form (see `new/0`).
    * `provider` — always, and the form refuses to start without one.
    * `model` — whatever `model_intent/2` says it is sending, absent when that is nothing.
    * `workspace` — the trimmed path, absent when the field is empty.
    * `sandbox_mode` — the operator's card, absent when no card was chosen.
    * `reasoning_effort` — the operator's level, absent when the picker was left alone.

  There is no `title`: `interactive.start` has no such parameter, and a session's durable
  name is `interactive.rename`'s to write after one exists.
  """
  @spec start_params(t(), model_field()) :: {:ok, map()} | {:error, String.t()}
  def start_params(%__MODULE__{} = form, field) do
    case trimmed(form.provider) do
      nil ->
        {:error, "choose a provider before starting a session"}

      provider ->
        {:ok,
         %{"id" => form.id || mint_id(), "provider" => provider}
         |> put_stated("model", model_intent(form, field).send)
         |> put_stated("workspace", trimmed(form.workspace))
         |> put_stated("sandbox_mode", stated(form.sandbox, @sandbox_modes))
         |> put_stated("reasoning_effort", stated(form.effort, efforts(form, field)))}
    end
  end

  defp put_stated(params, _key, nil), do: params
  defp put_stated(params, key, value), do: Map.put(params, key, value)

  defp stated(value, allowed) when is_binary(value), do: if(value in allowed, do: value)
  defp stated(_value, _allowed), do: nil

  @doc """
  The session `interactive.start` answered with, whichever shape it answered in.

  A ready session comes back as `%Ouroboros.Interactive.Ref{}`; one the runtime created
  but could not bring up answers the `outcome: "created"` map instead. Both name the
  session, and the form opens either — a session that exists is a session an operator
  should be looking at, whatever its readiness.
  """
  @spec started(term()) :: {:ok, String.t()} | :error
  def started(%{id: id}) when is_binary(id), do: {:ok, id}
  def started(%{"id" => id}) when is_binary(id), do: {:ok, id}
  def started(_other), do: :error

  @doc "Where the deck is asked to open the session this form just started."
  @spec deck_path(String.t()) :: String.t()
  def deck_path(id) when is_binary(id), do: Ouroboros.Web.Route.session(:interactive, id)

  # ------------------------------------------------------------------------------------
  # Refusals
  # ------------------------------------------------------------------------------------

  @doc """
  What a refused call says, in the runtime's own words.

  The gateway's sentence first, and then — where the plane typed its refusal — the plane's
  own `message` out of `data`. `unsupported_safety_options` and
  `unsupported_approval_mode` both carry one, and it is the only text that names which
  option was refused and what the provider would accept instead; dropping it would leave
  an operator reading "the runtime refused the call" with no way to act.
  """
  @spec refusal(term()) :: %{message: String.t(), detail: String.t() | nil} | nil
  def refusal({:error, _code, message}) when is_binary(message),
    do: %{message: message, detail: nil}

  def refusal({:error, _code, message, data}) when is_binary(message),
    do: %{message: message, detail: refusal_detail(data)}

  def refusal(_other), do: nil

  defp refusal_detail(%{"message" => message}) when is_binary(message) and message != "",
    do: message

  defp refusal_detail(%{"error" => error}), do: refusal_detail(error)
  defp refusal_detail(_data), do: nil

  @doc """
  The roots a refusal named, so a browse refusal can say where this node *does* look.

  `outside_roots` is the one refusal that carries them, and it carries them precisely
  because the message deliberately says nothing else about the path.
  """
  @spec refusal_roots(term()) :: [String.t()]
  def refusal_roots({:error, _code, _message, %{"roots" => roots}}) when is_list(roots),
    do: Enum.map(roots, &to_string/1)

  def refusal_roots(_other), do: []

  @doc "The bound one `workspace.browse` listing is cut at, read from the method itself."
  @spec browse_limit() :: pos_integer()
  def browse_limit, do: Browse.limit()

  # ------------------------------------------------------------------------------------

  # `ouro-` rather than the terminal client's `ouro-session-`: the id is opaque to the
  # runtime, and a surface's prefix is the one thing about it worth being able to read in
  # a log.
  defp mint_id,
    do: "ouro-web-" <> (12 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower))

  defp trimmed(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp trimmed(_value), do: nil

  defp identifier(nil), do: nil
  defp identifier(value) when is_atom(value), do: Atom.to_string(value)
  defp identifier(value), do: trimmed(value)

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason) when is_atom(reason), do: to_string(reason)
  defp describe(reason), do: inspect(reason, limit: 5)

  defp value(map, key) when is_map(map),
    do: Map.get(map, key, Map.get(map, Atom.to_string(key)))
end
