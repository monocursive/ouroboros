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
  knows what the selected transport can actually normalize. The web surface has no stored
  form defaults at all (`docs/WEB.md` §4, D10 — `web.prefs.json` is a later slice), so an
  untouched control here is always an absent field.
  """

  alias Ouroboros.Gateway.Methods.Browse

  @sandbox_modes ["read_only", "workspace_write", "unrestricted"]
  @efforts ["low", "medium", "high"]

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
  """
  @spec new() :: t()
  def new, do: %__MODULE__{id: mint_id()}

  @doc "The three sandbox postures the form offers, least power first."
  @spec sandbox_modes() :: [String.t()]
  def sandbox_modes, do: @sandbox_modes

  @doc "The three reasoning levels the gateway's vocabulary names."
  @spec efforts() :: [String.t()]
  def efforts, do: @efforts

  # ------------------------------------------------------------------------------------
  # Provider rows
  # ------------------------------------------------------------------------------------

  @doc """
  One row per provider `runtime.providers` reported, in the order it reported them.

  A row whose probe found nothing is `detected?: false` and carries the probe's own reason,
  and it is **still offered**. The probe knows whether an executable is on this node's
  PATH; it does not know whether a session can start, and a picker that hid a provider on
  that evidence would be making a claim the runtime never made.
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
        note: probe_note(status, Map.get(entry, :error))
      }
    ]
  end

  defp provider_row(_other), do: []

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
  The footnote drawn once under the picker when any row is dimmed, or `nil`.

  Said once rather than beside each row, and said as what it is: a report about a probe,
  not a verdict on whether a session can start.
  """
  @spec provider_footnote([map()]) :: String.t() | nil
  def provider_footnote(rows) when is_list(rows) do
    if Enum.any?(rows, &(not &1.detected?)) do
      "Dimmed entries are ones whose probe found no executable. " <>
        "The runtime decides whether a session starts."
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
    catalogue =
      row
      |> Map.get(:models)
      |> List.wrap()
      |> Enum.map(fn model ->
        id = to_string(model[:id])
        %{choice: {:catalog, id}, label: id, detail: detail(model)}
      end)

    [default_row(row)] ++ catalogue ++ [custom_row()]
  end

  defp default_row(row) do
    label =
      case trimmed(row[:default]) do
        nil -> "Runtime default"
        default -> "Runtime default · #{default}"
      end

    %{choice: :runtime_default, label: label, detail: "Send no model and let the runtime choose"}
  end

  defp custom_row do
    %{choice: :custom, label: "Custom…", detail: "Type a model id this list does not carry"}
  end

  # The vendor's name and the window, whichever the snapshot actually stated. `nil` when it
  # stated neither: a row showing only the id is honest, an empty second line is not.
  defp detail(model) do
    case {trimmed(model[:name]), window(model[:context_window])} do
      {nil, nil} -> nil
      {name, nil} -> name
      {nil, window} -> window
      {name, window} -> "#{name} · #{window}"
    end
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
        {:unsupported, _send} -> "Sends no model option — this provider does not accept one"
        {_field, nil} -> "Sends no model option (runtime default)"
        {_field, model} -> "Sends #{model}"
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
  Whether the model this form would send needs a connected ChatGPT subscription.

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
         |> put_stated("reasoning_effort", stated(form.effort, @efforts))}
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

  @doc """
  Where the deck is asked to open the session this form just started.

  A query parameter rather than `/s/interactive/:id` because this is a navigation and not
  a patch — the form is a different LiveView, so the deck mounts fresh either way — and
  because the deck's `handle_params` is the one place that decides what "open" means. The
  two ends of that contract are `Ouroboros.Web.Live.DeckLive.handle_params/3` and this
  function, and they are tested against each other rather than against a literal typed
  twice.
  """
  @spec deck_path(String.t()) :: String.t()
  def deck_path(id) when is_binary(id), do: "/?open=interactive:" <> id

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

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason) when is_atom(reason), do: to_string(reason)
  defp describe(reason), do: inspect(reason, limit: 5)
end
