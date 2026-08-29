defmodule Ouroboros.Web.Live.NewSessionLive do
  @moduledoc """
  The form that starts a session, at `/new`.

  Its parity target is the GPUI desktop's new-session panel (`docs/DESKTOP.md`), and what
  is ported is the *semantics*: which controls exist, what each of them may honestly
  claim, and — above all — which fields end up in the request. The pixels are the deck's
  own tokens. Every rule the panel holds is in `Ouroboros.Web.Live.NewSession`, which has
  no socket in it; this module fetches, draws, and sends.

  ## Providers and models are read once

  `runtime.providers` and `runtime.models` are fetched on the connected mount and never
  again — the TUI's rule (`mod.rs:107`), and not a cadence this page invents. A probe walks
  the PATH for every configured adapter; running that every three seconds while somebody
  fills in a path would be a page that costs more than the session it starts. The one
  thing here that *does* poll is the ChatGPT card, at one second, and only while a login is
  actually pending.

  ## Browse is a gateway call, not a file dialog

  `workspace.browse` is the only way this surface reads a directory, and everything about
  what it may read lives in `Ouroboros.Gateway.Methods.Browse`. The panel draws exactly
  what the method answered — its roots, its entries, its `truncated` flag, and its refusals
  in its own words — and invents nothing when it is refused. A native file dialog would
  have browsed the *browser's* machine, which is only ever the right filesystem when the
  daemon happens to be on it.

  ## Absent, not defaulted

  The sandbox cards and the thinking picker send nothing until an operator picks. The web
  has no stored form defaults (`docs/WEB.md` §4, D10), so "untouched" here is always an
  absent field rather than a guessed one, and the caption says so.

  ## What this page cannot do

  Everything it draws is gated on `Ouroboros.Web.Call.available?/2`. On a `read`-scope
  endpoint `interactive.start` and `workspace.browse` do not exist, and the controls that
  would have called them are disabled and labelled with the reason rather than hidden — a
  form that silently dropped its Browse button would read as broken rather than restricted.
  """

  use Phoenix.LiveView

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Layouts
  alias Ouroboros.Web.Live.NewSession
  alias Ouroboros.Web.Prefs

  # Only while a login is pending, and only because a device-code flow completes on another
  # device: there is nothing for the runtime to push, so the page asks.
  @account_poll 1_000

  @impl true
  def mount(_params, _session, socket) do
    config = Config.for_endpoint(socket.endpoint)

    socket =
      socket
      |> assign(:scope, config.scope)
      |> assign(:data_dir, config.data_dir)
      # Where the operator's last successful start left this form. `read/1` is total, so a
      # corrupt file is a form with no defaults rather than a page that will not mount.
      |> assign(:form, NewSession.new(Prefs.read(config.data_dir)))
      |> assign(:providers, nil)
      |> assign(:providers_error, nil)
      |> assign(:catalogue, nil)
      |> assign(:catalogue_error, nil)
      |> assign(:loaded?, false)
      |> assign(:browse_open?, false)
      |> assign(:browse, nil)
      |> assign(:browse_refusal, nil)
      |> assign(:account, nil)
      |> assign(:login, nil)
      |> assign(:polling_account?, false)
      |> assign(:starting?, false)
      |> assign(:refusal, nil)

    # The lists are read on the connected mount alone. The static first paint says it is
    # reading rather than showing an empty picker, which would be a claim that this node
    # serves no providers.
    {:ok, if(connected?(socket), do: load(socket), else: socket)}
  end

  # ------------------------------------------------------------------------------------
  # The form
  # ------------------------------------------------------------------------------------

  # One `phx-change` for the whole form, so every re-render is drawn from one consistent
  # reading of it. A control absent from the DOM — the model text input outside its two
  # modes — is absent from the params too, and keeps whatever it last held rather than
  # being cleared by a change to some other field.
  @impl true
  def handle_event("change", params, socket) do
    form = socket.assigns.form

    form = %{
      form
      | provider: params["provider"] || form.provider,
        workspace: params["workspace"] || form.workspace,
        model_text: params["model_text"] || form.model_text,
        model_search: params["model_search"] || form.model_search,
        model_choice: model_choice(params, form),
        effort: blank_to_nil(params["effort"])
    }

    {:noreply, socket |> assign(:form, reconcile(form, socket)) |> assign(:refusal, nil)}
  end

  # A card, not a radio group: three postures with their consequences written under them,
  # which is the shape the desktop settled on and the reason it is not a `<select>`.
  def handle_event("pick-sandbox", %{"mode" => mode}, socket) do
    form = %{socket.assigns.form | sandbox: mode}
    {:noreply, socket |> assign(:form, form) |> assign(:refusal, nil)}
  end

  # ------------------------------------------------------------------------------------
  # Browse
  # ------------------------------------------------------------------------------------

  def handle_event("browse-open", _params, socket) do
    # No path: the method's own first root, which is the only default this page is
    # entitled to assume.
    {:noreply, socket |> assign(:browse_open?, true) |> browse(nil)}
  end

  def handle_event("browse-close", _params, socket) do
    {:noreply, assign(socket, :browse_open?, false)}
  end

  def handle_event("browse-to", %{"path" => path}, socket) do
    {:noreply, browse(socket, path)}
  end

  def handle_event("browse-use", %{"path" => path}, socket) do
    form = %{socket.assigns.form | workspace: path}

    {:noreply,
     socket
     |> assign(:form, form)
     |> assign(:browse_open?, false)
     |> assign(:refusal, nil)}
  end

  # ------------------------------------------------------------------------------------
  # ChatGPT
  # ------------------------------------------------------------------------------------

  # Device code, not the browser flow. The browser flow's callback is a loopback listener
  # on the *daemon's* 127.0.0.1, and this page may well be open on another machine over a
  # tailnet; a device code is the one flow that is correct either way.
  def handle_event("connect-chatgpt", _params, socket) do
    case call(socket, "account.login.start", %{"flow" => "device_code"}) do
      {:ok, reply} when is_map(reply) ->
        login = %{
          login_id: reply["loginId"],
          url: reply["verificationUrl"] || reply["authUrl"],
          code: reply["userCode"]
        }

        {:noreply,
         socket |> assign(:login, login) |> assign(:refusal, nil) |> maybe_poll_account()}

      refused ->
        {:noreply, assign(socket, :refusal, NewSession.refusal(refused))}
    end
  end

  def handle_event("cancel-chatgpt", _params, socket) do
    socket =
      case socket.assigns.login do
        %{login_id: id} when is_binary(id) ->
          _ = call(socket, "account.login.cancel", %{"login_id" => id})
          socket

        _none ->
          socket
      end

    {:noreply, socket |> assign(:login, nil) |> read_account()}
  end

  # ------------------------------------------------------------------------------------
  # Start
  # ------------------------------------------------------------------------------------

  def handle_event("start", _params, socket) do
    case NewSession.start_params(socket.assigns.form, field(socket)) do
      {:error, message} ->
        {:noreply, assign(socket, :refusal, %{message: message, detail: nil})}

      {:ok, params} ->
        {:noreply, start(socket, params)}
    end
  end

  @impl true
  def handle_info(:poll_account, socket) do
    socket = socket |> assign(:polling_account?, false) |> read_account()

    # The login is finished the moment the runtime stops calling it pending; holding the
    # code on screen after that would be showing a credential that no longer opens
    # anything.
    socket = if settled?(socket.assigns.account), do: assign(socket, :login, nil), else: socket

    {:noreply, maybe_poll_account(socket)}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # Calls
  # ------------------------------------------------------------------------------------

  defp load(socket) do
    socket
    |> load_providers()
    |> load_models()
    |> promote_seed()
    |> assign(:loaded?, true)
    |> read_account()
    # A login this runtime already has in flight — started from the TUI, or from another
    # browser — is one this page should follow rather than ignore.
    |> maybe_poll_account()
  end

  defp load_providers(socket) do
    case call(socket, "runtime.providers", %{}) do
      {:ok, entries} when is_list(entries) ->
        assign(socket, :providers, NewSession.provider_rows(entries))

      refused ->
        assign(socket, :providers_error, message(refused))
    end
  end

  defp load_models(socket) do
    case call(socket, "runtime.models", %{}) do
      {:ok, catalogue} when is_map(catalogue) ->
        assign(socket, :catalogue, catalogue)

      refused ->
        assign(socket, :catalogue_error, message(refused))
    end
  end

  # A model seeded out of `web.prefs.json` arrives as a custom choice, because at mount
  # there is no catalogue to check it against. Once there is one, a remembered model this
  # runtime actually lists is drawn as its own row rather than sitting in the custom box
  # looking like something nobody has heard of. It sends the same string either way.
  defp promote_seed(socket),
    do: assign(socket, :form, NewSession.promote(socket.assigns.form, field(socket)))

  # Read whenever the card is on screen, which is what makes "checking" a state that
  # resolves rather than a spinner.
  defp read_account(socket) do
    case call(socket, "account.read", %{}) do
      {:ok, read} when is_map(read) -> assign(socket, :account, read)
      _refused -> socket
    end
  end

  # Only while a login is actually waiting. Every other state of this card is answered by
  # the read the page already did, and a timer that kept running past it would be a poll
  # nobody asked for.
  defp maybe_poll_account(socket) do
    card = NewSession.account_card(socket.assigns.account, socket.assigns.login)
    if card.state == :waiting, do: poll_account(socket), else: socket
  end

  defp poll_account(%{assigns: %{polling_account?: true}} = socket), do: socket

  defp poll_account(socket) do
    Process.send_after(self(), :poll_account, @account_poll)
    assign(socket, :polling_account?, true)
  end

  defp settled?(read) when is_map(read),
    do: not match?(%{"login" => %{"status" => "pending"}}, read)

  defp settled?(_read), do: false

  defp browse(socket, path) do
    params = if is_binary(path), do: %{"path" => path}, else: %{}

    case call(socket, "workspace.browse", params) do
      {:ok, listing} when is_map(listing) ->
        socket |> assign(:browse, listing) |> assign(:browse_refusal, nil)

      refused ->
        # The listing that was already there stays: a refused step into one directory does
        # not un-answer the one the operator is standing in.
        assign(socket, :browse_refusal, %{
          words: NewSession.refusal(refused),
          roots: NewSession.refusal_roots(refused)
        })
    end
  end

  defp start(socket, params) do
    socket = assign(socket, :starting?, true)

    case call(socket, "interactive.start", params) do
      {:ok, answer} ->
        case NewSession.started(answer) do
          {:ok, id} ->
            # Only on a start that actually happened, and only the keys the request
            # carried. A refused start is not evidence about how the operator likes to
            # work, and `id` is dropped because idempotency is the whole reason it exists:
            # a remembered one would adopt a session that is already running.
            _ = Prefs.write(socket.assigns.data_dir, Map.delete(params, "id"))

            push_navigate(socket, to: NewSession.deck_path(id))

          :error ->
            socket
            |> assign(:starting?, false)
            |> assign(:refusal, %{
              message: "interactive.start answered something this build cannot read",
              detail: nil
            })
        end

      refused ->
        # The form is left exactly as it was. A refusal is information about the request,
        # and a page that cleared the fields would make the operator retype what the
        # runtime just told them to change.
        socket |> assign(:starting?, false) |> assign(:refusal, NewSession.refusal(refused))
    end
  end

  defp call(socket, method, params) do
    Call.call(socket.assigns.scope, method, params, session: socket.assigns[:web_session])
  end

  defp message(refused) do
    case NewSession.refusal(refused) do
      %{message: message} -> message
      nil -> nil
    end
  end

  # ------------------------------------------------------------------------------------
  # Derived state
  # ------------------------------------------------------------------------------------

  # A model chosen under the previous provider is not necessarily a row under the new one,
  # so the choice is re-checked against the field the change produced rather than carried.
  defp reconcile(form, socket) do
    field = NewSession.model_field(socket.assigns.catalogue, form.provider)

    if NewSession.offers?(field, form.model_choice),
      do: form,
      else: %{form | model_choice: :runtime_default}
  end

  defp field(socket),
    do: NewSession.model_field(socket.assigns.catalogue, socket.assigns.form.provider)

  defp model_choice(%{"model_choice" => value}, _form), do: NewSession.choice(value)
  defp model_choice(_params, form), do: form.model_choice

  defp blank_to_nil(value) when is_binary(value), do: if(String.trim(value) != "", do: value)
  defp blank_to_nil(_value), do: nil

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    field = NewSession.model_field(assigns.catalogue, assigns.form.provider)
    account = NewSession.account_card(assigns.account, assigns.login)
    gated? = NewSession.requires_chatgpt?(assigns.form, field)

    assigns =
      assigns
      |> assign(:field, field)
      |> assign(
        :visible,
        NewSession.search(field, assigns.form.model_search, assigns.form.model_choice)
      )
      |> assign(:intent, NewSession.model_intent(assigns.form, field))
      |> assign(:account_card, account)
      |> assign(:gated?, gated?)
      |> assign(:can_start?, Call.available?(assigns.scope, "interactive.start"))
      |> assign(:can_browse?, Call.available?(assigns.scope, "workspace.browse"))

    ~H"""
    <div class="ouro-new">
      <header class="ouro-new-top">
        <div class="ouro-top-row">
          <a class="ouro-new-back" href="/">← Deck</a>
          <Layouts.theme_toggle />
        </div>
        <h1 class="ouro-new-title">New session</h1>
        <p class="ouro-new-sub">Choose where and how this agent works</p>
      </header>

      <form id="new-session" class="ouro-new-form" phx-change="change" phx-submit="start">
        <.provider_field
          rows={@providers}
          error={@providers_error}
          loaded={@loaded?}
          chosen={@form.provider}
        />

        <.model_field
          field={@field}
          visible={@visible}
          form={@form}
          intent={@intent}
          error={@catalogue_error}
        />

        <.workspace_field
          workspace={@form.workspace}
          can_browse={@can_browse?}
          open={@browse_open?}
          listing={@browse}
          refusal={@browse_refusal}
        />

        <.thinking_field effort={@form.effort} />

        <.sandbox_field sandbox={@form.sandbox} />

        <.account_card :if={@gated?} card={@account_card} scope={@scope} />

        <p :if={@refusal} class="ouro-refusal ouro-new-refusal">
          {@refusal.message}
          <span :if={@refusal.detail} class="ouro-new-refusal-detail">{@refusal.detail}</span>
        </p>

        <footer class="ouro-new-foot">
          <a class="ouro-new-cancel" href="/">Cancel</a>
          <button
            type="submit"
            class="ouro-button"
            disabled={not @can_start? or @starting? or (@gated? and not @account_card.usable?)}
          >
            {start_label(@can_start?, @starting?, @gated?, @account_card)}
          </button>
        </footer>

        <p :if={not @can_start?} class="ouro-new-note">
          This endpoint was started with <code>OUROBOROS_WEB_SCOPE=read</code>, which does not
          serve <code>interactive.start</code>.
        </p>
      </form>
    </div>
    """
  end

  defp start_label(false, _starting?, _gated?, _card), do: "Start session"
  defp start_label(_can?, true, _gated?, _card), do: "Starting…"

  defp start_label(_can?, _starting?, true, %{usable?: false}), do: "Connect ChatGPT first"
  defp start_label(_can?, _starting?, _gated?, _card), do: "Start session"

  # ------------------------------------------------------------------------------------
  # Provider
  # ------------------------------------------------------------------------------------

  attr :rows, :any, required: true
  attr :error, :any, required: true
  attr :loaded, :boolean, required: true
  attr :chosen, :any, required: true

  def provider_field(assigns) do
    assigns = assign(assigns, :footnote, NewSession.provider_footnote(assigns.rows || []))

    ~H"""
    <section class="ouro-new-field" aria-labelledby="provider-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="provider-label">Provider</span>
        <span class="ouro-new-aside">Required</span>
      </div>

      <select class="ouro-new-select" name="provider" aria-labelledby="provider-label">
        <option value="" selected={is_nil(@chosen) or @chosen == ""}>Choose a provider</option>
        <option
          :for={row <- @rows || []}
          value={row.name}
          selected={@chosen == row.name}
          class={if not row.detected?, do: "ouro-new-dim"}
        >
          {row.name}{if row.note, do: " — #{row.note}"}
        </option>
      </select>

      <p :if={@error} class="ouro-refusal">the provider list could not be read: {@error}</p>
      <p :if={not @loaded and is_nil(@error)} class="ouro-new-hint">reading the provider list…</p>
      <p :if={@footnote} class="ouro-new-hint">{@footnote}</p>
    </section>
    """
  end

  # ------------------------------------------------------------------------------------
  # Model
  # ------------------------------------------------------------------------------------

  attr :field, :any, required: true
  attr :visible, :any, required: true
  attr :form, :any, required: true
  attr :intent, :map, required: true
  attr :error, :any, required: true

  def model_field(assigns) do
    ~H"""
    <section class="ouro-new-field" aria-labelledby="model-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="model-label">Model</span>
        <span class="ouro-new-aside">{model_aside(@field)}</span>
      </div>

      <.model_control field={@field} visible={@visible} form={@form} />

      <p :if={@error} class="ouro-refusal">the model list could not be read: {@error}</p>

      <%!-- The field's authoritative reading: the same function that builds the request
            builds this sentence, so a picker and a payload cannot disagree. --%>
      <p class="ouro-new-intent">{@intent.hint}</p>
    </section>
    """
  end

  attr :field, :any, required: true
  attr :visible, :any, required: true
  attr :form, :any, required: true

  def model_control(%{field: :unsupported} = assigns) do
    ~H"""
    <select class="ouro-new-select" name="model_disabled" disabled aria-label="model">
      <option>No model option</option>
    </select>
    """
  end

  def model_control(%{field: {:text, _hint}} = assigns) do
    assigns = assign(assigns, :hint, elem(assigns.field, 1))

    ~H"""
    <input
      type="text"
      class="ouro-new-input"
      name="model_text"
      value={@form.model_text}
      placeholder="Model id (optional)"
      aria-label="model"
      autocomplete="off"
    />
    <p :if={@hint} class="ouro-new-hint">{@hint}</p>
    """
  end

  def model_control(%{field: {:rows, _rows, _total}} = assigns) do
    {:rows, rows, _total} = assigns.visible

    assigns =
      assigns
      |> assign(:rows, rows)
      |> assign(:matched, NewSession.listed(assigns.visible))
      |> assign(:custom?, assigns.form.model_choice == :custom)

    ~H"""
    <input
      type="search"
      class="ouro-new-input ouro-new-search"
      name="model_search"
      value={@form.model_search}
      placeholder="Search models…"
      aria-label="search models"
      autocomplete="off"
    />

    <%!-- The search filters this list here, in the process that also holds the choice.
          There is no client-side widget cache to distrust, so the label on screen and the
          value in the request are read from one place. --%>
    <select class="ouro-new-select ouro-new-list" name="model_choice" size="8" aria-label="model">
      <option
        :for={row <- @rows}
        value={NewSession.choice_value(row.choice)}
        selected={row.choice == @form.model_choice}
      >
        <%!-- An em dash, not the middot the detail itself uses to join a name to a
              context window: one option is one line here, and the two separators keep the
              row's id readable apart from what the snapshot says about it. --%>
        {row.label}{if row.detail, do: " — #{row.detail}"}
      </option>
    </select>

    <p :if={@form.model_search != ""} class="ouro-new-hint">
      {@matched} {if @matched == 1, do: "model", else: "models"} match
    </p>

    <input
      :if={@custom?}
      type="text"
      class="ouro-new-input"
      name="model_text"
      value={@form.model_text}
      placeholder="Model id"
      aria-label="custom model id"
      autocomplete="off"
    />
    """
  end

  defp model_aside(:unsupported), do: "Not accepted"

  defp model_aside({:rows, _rows, total} = field) do
    listed = NewSession.listed(field)
    if total > listed, do: "#{listed} of #{total}", else: "Optional"
  end

  defp model_aside(_field), do: "Optional"

  # ------------------------------------------------------------------------------------
  # Workspace
  # ------------------------------------------------------------------------------------

  attr :workspace, :string, required: true
  attr :can_browse, :boolean, required: true
  attr :open, :boolean, required: true
  attr :listing, :any, required: true
  attr :refusal, :any, required: true

  def workspace_field(assigns) do
    ~H"""
    <section class="ouro-new-field" aria-labelledby="workspace-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="workspace-label">Workspace</span>
        <span class="ouro-new-aside">Absolute path</span>
      </div>

      <div class="ouro-new-row">
        <input
          type="text"
          class="ouro-new-input"
          name="workspace"
          value={@workspace}
          placeholder="/absolute/path"
          aria-labelledby="workspace-label"
          autocomplete="off"
        />
        <button
          type="button"
          class="ouro-new-secondary"
          phx-click="browse-open"
          disabled={not @can_browse}
          title={not @can_browse && "this endpoint does not serve workspace.browse"}
        >
          Browse…
        </button>
      </div>

      <.browse_panel :if={@open} listing={@listing} refusal={@refusal} />
    </section>
    """
  end

  attr :listing, :any, required: true
  attr :refusal, :any, required: true

  def browse_panel(assigns) do
    listing = assigns.listing || %{}

    assigns =
      assigns
      |> assign(:path, listing["path"])
      |> assign(:parent, listing["parent"])
      |> assign(:roots, List.wrap(listing["roots"]))
      |> assign(:entries, List.wrap(listing["entries"]))
      |> assign(:truncated?, listing["truncated"] == true)
      |> assign(:limit, NewSession.browse_limit())

    ~H"""
    <div class="ouro-browse" role="group" aria-label="browse directories">
      <div class="ouro-browse-head">
        <span class="ouro-browse-path ouro-mono">{@path || "—"}</span>
        <button type="button" class="ouro-new-secondary" phx-click="browse-close">Close</button>
      </div>

      <div class="ouro-browse-roots">
        <button
          :for={root <- @roots}
          type="button"
          class="ouro-browse-root ouro-mono"
          phx-click="browse-to"
          phx-value-path={root}
        >
          {root}
        </button>
      </div>

      <%!-- Rendered verbatim. A refusal from this method is deliberately narrow — it says
            a path is outside every root and nothing about whether it exists — and
            rewording it here would be this page claiming to know more. --%>
      <p :if={@refusal && @refusal.words} class="ouro-refusal">
        {@refusal.words.message}
        <span :if={@refusal.words.detail}>{@refusal.words.detail}</span>
      </p>
      <p :if={@refusal && @refusal.roots != []} class="ouro-new-hint ouro-mono">
        this node browses: {Enum.join(@refusal.roots, ", ")}
      </p>

      <ul class="ouro-browse-list">
        <li :if={@parent} class="ouro-browse-entry">
          <button
            type="button"
            class="ouro-browse-open"
            phx-click="browse-to"
            phx-value-path={@parent}
          >
            ..
          </button>
        </li>

        <li :for={entry <- @entries} class="ouro-browse-entry">
          <button
            type="button"
            class="ouro-browse-open"
            phx-click="browse-to"
            phx-value-path={Path.join(@path || "", entry["name"])}
          >
            {entry["name"]}
          </button>
          <button
            type="button"
            class="ouro-browse-use"
            phx-click="browse-use"
            phx-value-path={Path.join(@path || "", entry["name"])}
          >
            use
          </button>
        </li>
      </ul>

      <p :if={@truncated?} class="ouro-new-hint">
        {@limit} of more shown — this directory holds more than one listing carries.
      </p>

      <div class="ouro-browse-foot">
        <button
          :if={@path}
          type="button"
          class="ouro-new-secondary"
          phx-click="browse-use"
          phx-value-path={@path}
        >
          Use this directory
        </button>
      </div>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Thinking
  # ------------------------------------------------------------------------------------

  attr :effort, :any, required: true

  def thinking_field(assigns) do
    ~H"""
    <section class="ouro-new-field" aria-labelledby="effort-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="effort-label">Thinking</span>
        <span class="ouro-new-aside">{if @effort, do: "Your choice", else: "Not stated"}</span>
      </div>

      <select class="ouro-new-select" name="effort" aria-labelledby="effort-label">
        <option value="" selected={is_nil(@effort)}>Runtime default</option>
        <option :for={level <- NewSession.efforts()} value={level} selected={@effort == level}>
          {String.capitalize(level)}
        </option>
      </select>

      <p class="ouro-new-intent">
        {if @effort,
          do: "Sends reasoning_effort #{@effort}",
          else: "Sends no reasoning_effort — the runtime decides"}
      </p>
    </section>
    """
  end

  # ------------------------------------------------------------------------------------
  # Sandbox
  # ------------------------------------------------------------------------------------

  attr :sandbox, :any, required: true

  def sandbox_field(assigns) do
    ~H"""
    <section class="ouro-new-field" aria-labelledby="sandbox-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="sandbox-label">File access</span>
        <span class="ouro-new-aside">{if @sandbox, do: "Your choice", else: "Not stated"}</span>
      </div>

      <div class="ouro-cards" role="group" aria-labelledby="sandbox-label">
        <%!-- Two separate signals. The full-access row's *title* wears the warning tone
              always, because that is a standing property of the posture; the card's own
              chosen state is the accent every other control uses — except on that row,
              where it stays warning, so picking it never reads as an action highlight. --%>
        <button
          :for={mode <- NewSession.sandbox_modes()}
          type="button"
          class={[
            "ouro-card",
            @sandbox == mode && "ouro-card-on",
            warns?(mode) && "ouro-card-warn"
          ]}
          phx-click="pick-sandbox"
          phx-value-mode={mode}
          aria-pressed={to_string(@sandbox == mode)}
        >
          <span class="ouro-card-title">{sandbox_title(mode)}</span>
          <span class="ouro-card-line">{sandbox_describe(mode)}</span>
        </button>
      </div>

      <p class="ouro-new-intent">
        {if @sandbox,
          do: "Sends sandbox_mode #{@sandbox}",
          else: "Sends no sandbox_mode — the plane decides"}
      </p>
    </section>
    """
  end

  # `unrestricted` is the wire's word and it stays on the wire; every surface a person
  # reads says full access, because "unrestricted" names the parameter rather than what
  # the agent is being allowed to do.
  defp sandbox_title("read_only"), do: "Read only"
  defp sandbox_title("workspace_write"), do: "Workspace write"
  defp sandbox_title("unrestricted"), do: "Full access — no sandbox"

  defp sandbox_describe("read_only"), do: "cannot create or edit files"
  defp sandbox_describe("workspace_write"), do: "can edit files in the workspace"
  defp sandbox_describe("unrestricted"), do: "shell runs with no OS sandbox"

  defp warns?(mode), do: mode == "unrestricted"

  # ------------------------------------------------------------------------------------
  # ChatGPT
  # ------------------------------------------------------------------------------------

  attr :card, :map, required: true
  attr :scope, :atom, required: true

  def account_card(assigns) do
    assigns = assign(assigns, :can_login?, Call.available?(assigns.scope, "account.login.start"))

    ~H"""
    <section class="ouro-new-field ouro-account" aria-labelledby="account-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="account-label">ChatGPT</span>
        <span class="ouro-new-aside">{account_aside(@card.state)}</span>
      </div>

      <p :if={@card.state == :checking} class="ouro-new-hint">reading account readiness…</p>

      <p :if={@card.state == :connected} class="ouro-new-hint">
        Connected{if @card.identity, do: " as #{@card.identity}"}.
      </p>

      <p :if={@card.state == :required} class="ouro-new-hint">
        This model runs on a ChatGPT subscription, and the runtime has no usable credential
        for one. Tokens stay in the runtime; this page never sees them.
      </p>

      <div :if={@card.state == :waiting} class="ouro-account-wait">
        <p class="ouro-new-hint">Open the link, enter the code, then come back here.</p>
        <p :if={@card.code} class="ouro-account-code ouro-mono">{@card.code}</p>
        <p :if={@card.url}>
          <a
            :if={NewSession.https?(@card.url)}
            href={@card.url}
            rel="noreferrer noopener"
            target="_blank"
          >
            {@card.url}
          </a>
          <span :if={not NewSession.https?(@card.url)} class="ouro-mono">
            {@card.url} — shown but not linked: it is not https.
          </span>
        </p>
      </div>

      <p :if={@card.error} class="ouro-refusal">{@card.error}</p>

      <div class="ouro-new-row">
        <button
          :if={@card.state in [:required, :checking]}
          type="button"
          class="ouro-new-secondary"
          phx-click="connect-chatgpt"
          disabled={not @can_login?}
        >
          Connect
        </button>
        <button
          :if={@card.state == :waiting}
          type="button"
          class="ouro-new-secondary"
          phx-click="cancel-chatgpt"
        >
          Cancel
        </button>
      </div>
    </section>
    """
  end

  defp account_aside(:checking), do: "Checking"
  defp account_aside(:connected), do: "Connected"
  defp account_aside(:waiting), do: "Waiting"
  defp account_aside(:required), do: "Required"
end
