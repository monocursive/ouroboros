defmodule Ouroboros.Web.Live.NewSessionLive do
  @moduledoc """
  The form that starts a session, at `/new`.

  Its parity target was the GPUI desktop's new-session panel; that client was removed in
  W9 and this page is now the only surface with the form, so the parity map in
  `docs/WEB.md` §4 is the record of what was ported. What was ported is the *semantics*:
  which controls exist, what each of them may honestly claim, and — above all — which
  fields end up in the request. In particular the defaulting rule, which `docs/DESKTOP.md`
  keeps as the one rule that outlived that client: what the config file supplies is where
  a control *starts*, never what gets sent — a stored default is sendable, and only the
  absence of one leaves the field off the request. The pixels are the deck's own tokens.
  Every rule the panel holds is in `Ouroboros.Web.Live.NewSession`, which has no socket in
  it; this module fetches, draws, and sends.

  ## Providers and models are read once

  `runtime.providers` and `runtime.models` are fetched on the connected mount and never
  again — a cadence this page does not invent. (The TUI set the precedent for
  `runtime.providers`; it no longer asks for `runtime.models` at all, since it offers no
  model picker to read the catalogue.) A probe walks
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
      |> assign(:page_title, "New session")
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
      |> assign(:grok_account, nil)
      |> assign(:grok_login, nil)
      |> assign(:polling_grok_account?, false)
      |> assign(:api_key_dialog?, false)
      |> assign(:api_key_error, nil)
      |> assign(:starting?, false)
      |> assign(:refusal, nil)
      |> assign(:provider_invalid?, false)
      |> assign(:initial_message, "")
      |> assign(:started_id, nil)

    # The lists are read on the connected mount alone. The static first paint says it is
    # reading rather than showing an empty picker, which would be a claim that this node
    # serves no providers.
    {:ok, if(connected?(socket), do: load(socket), else: socket)}
  end

  # ------------------------------------------------------------------------------------
  # The form
  # ------------------------------------------------------------------------------------

  # One `phx-change` for the whole form, so every re-render is drawn from one consistent
  # reading of it. The submit handler reads the browser payload through the same function;
  # rendered controls and the request can therefore never disagree.
  @impl true
  def handle_event("change", params, socket) do
    form = params |> read_form(socket.assigns.form) |> reconcile(socket)

    provider_invalid? =
      socket.assigns.provider_invalid? and blank?(form.provider)

    {:noreply,
     socket
     |> assign(:form, form)
     |> assign(:initial_message, params["initial_message"] || socket.assigns.initial_message)
     |> assign(:provider_invalid?, provider_invalid?)
     |> assign(:refusal, nil)}
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
  # Grok subscription
  # ------------------------------------------------------------------------------------

  # The first-party CLI owns this device-code flow and its token file. The page receives
  # only the verification URL and short code that the CLI prints for a human.
  def handle_event("connect-grok", _params, socket) do
    case call(socket, "grok.account.login.start", %{}) do
      {:ok, reply} when is_map(reply) ->
        login = %{
          login_id: reply["loginId"],
          url: reply["verificationUrl"],
          code: reply["userCode"]
        }

        {:noreply,
         socket
         |> assign(:grok_login, login)
         |> assign(:refusal, nil)
         |> maybe_poll_grok_account()}

      refused ->
        {:noreply, assign(socket, :refusal, NewSession.refusal(refused))}
    end
  end

  def handle_event("cancel-grok", _params, socket) do
    socket =
      case socket.assigns.grok_login do
        %{login_id: id} when is_binary(id) ->
          _ = call(socket, "grok.account.login.cancel", %{"login_id" => id})
          socket

        _none ->
          socket
      end

    {:noreply, socket |> assign(:grok_login, nil) |> read_grok_account()}
  end

  # ------------------------------------------------------------------------------------
  # Anthropic API key
  # ------------------------------------------------------------------------------------

  def handle_event("open-anthropic-key", _params, socket) do
    if Call.available?(socket.assigns.scope, "credentials.anthropic.set") do
      {:noreply,
       socket
       |> assign(:api_key_dialog?, true)
       |> assign(:api_key_error, nil)
       |> assign(:refusal, nil)}
    else
      {:noreply,
       assign(socket, :refusal, %{
         message: "This link cannot change provider credentials.",
         detail: "Open the operate-scope Ouroboros web surface to add an Anthropic API key."
       })}
    end
  end

  def handle_event("cancel-anthropic-key", _params, socket) do
    {:noreply, socket |> assign(:api_key_dialog?, false) |> assign(:api_key_error, nil)}
  end

  # The raw key exists only in this callback's parameters and the gateway task that
  # atomically stores it. It is never assigned to the socket, echoed in a refusal, or put
  # into the session form. Phoenix filters the `api_key` parameter name before logging.
  # A blank key is deliberately omitted so an operator can add a workspace id to the
  # already-stored key that Anthropic will not show them again.
  def handle_event("save-anthropic-key", params, socket) when is_map(params) do
    credential_params =
      %{}
      |> put_credential_param("api_key", params["anthropic_api_key"])
      |> put_credential_param("workspace_id", params["anthropic_workspace_id"])

    case credential_params do
      empty when map_size(empty) == 0 ->
        {:noreply,
         assign(socket, :api_key_error, "Enter a new API key or an Anthropic workspace ID.")}

      credential_params ->
        save_anthropic_credentials(socket, credential_params)
    end
  end

  def handle_event("open-xai-key", _params, socket) do
    if Call.available?(socket.assigns.scope, "credentials.xai.set") do
      {:noreply,
       socket
       |> assign(:api_key_dialog?, true)
       |> assign(:api_key_error, nil)
       |> assign(:refusal, nil)}
    else
      {:noreply,
       assign(socket, :refusal, %{
         message: "This link cannot change provider credentials.",
         detail: "Open the operate-scope Ouroboros web surface to add an xAI API key."
       })}
    end
  end

  def handle_event("cancel-xai-key", _params, socket) do
    {:noreply, socket |> assign(:api_key_dialog?, false) |> assign(:api_key_error, nil)}
  end

  def handle_event("save-xai-key", %{"xai_api_key" => api_key}, socket) do
    case String.trim(api_key) do
      "" ->
        {:noreply, assign(socket, :api_key_error, "Enter an xAI API key.")}

      api_key ->
        save_xai_key(socket, api_key)
    end
  end

  # ------------------------------------------------------------------------------------
  # Start
  # ------------------------------------------------------------------------------------

  def handle_event("start", params, socket) do
    form = params |> read_form(socket.assigns.form) |> reconcile(socket)

    socket =
      socket
      |> assign(:form, form)
      |> assign(:initial_message, params["initial_message"] || socket.assigns.initial_message)

    api_key = NewSession.api_key_card(form, field(socket), socket.assigns.providers)

    grok_account =
      NewSession.grok_account_card(socket.assigns.grok_account, socket.assigns.grok_login)

    grok_required? = NewSession.requires_grok?(form)

    cond do
      not socket.assigns.loaded? ->
        {:noreply,
         assign(socket, :refusal, %{
           message: "Settings are still loading.",
           detail: "Wait a moment, then start the session."
         })}

      blank?(form.provider) ->
        {:noreply,
         socket
         |> assign(:provider_invalid?, true)
         |> assign(:refusal, nil)
         |> push_event("focus-invalid", %{selector: "#provider"})}

      not available_provider?(socket.assigns.providers, form.provider) ->
        {:noreply,
         assign(socket, :refusal, %{
           message: "That AI provider is not available on this computer.",
           detail: "Choose one marked available under Advanced settings."
         })}

      grok_required? and not grok_account.usable? and not (api_key && api_key.usable?) ->
        {:noreply,
         assign(socket, :refusal, %{
           message: "Grok needs a SpaceXAI subscription or an xAI API key.",
           detail: "Connect the first-party Grok CLI, or add an API key under Advanced settings."
         })}

      match?(%{managed?: false, usable?: false}, api_key) ->
        {:noreply,
         assign(socket, :refusal, %{
           message: "A #{api_key.provider} API key is not available to the Ouroboros service.",
           detail:
             "Add it under #{api_key.provider} API, or set #{api_key.env} in the service environment."
         })}

      is_binary(socket.assigns.started_id) ->
        {:noreply, send_initial(socket, socket.assigns.started_id)}

      true ->
        case NewSession.start_params(form, field(socket)) do
          {:error, message} ->
            {:noreply, assign(socket, :refusal, %{message: message, detail: nil})}

          {:ok, params} ->
            {:noreply, start(socket, params)}
        end
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

  def handle_info(:poll_grok_account, socket) do
    socket = socket |> assign(:polling_grok_account?, false) |> read_grok_account()

    socket =
      if grok_settled?(socket.assigns.grok_account),
        do: assign(socket, :grok_login, nil),
        else: socket

    {:noreply, maybe_poll_grok_account(socket)}
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
    |> read_grok_account()
    |> maybe_poll_grok_account()
  end

  defp load_providers(socket) do
    case call(socket, "runtime.providers", %{}) do
      {:ok, entries} when is_list(entries) ->
        rows = NewSession.provider_rows(entries)

        socket
        |> assign(:providers, rows)
        |> assign(:form, choose_provider(socket.assigns.form, rows))

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

  defp read_grok_account(socket) do
    case call(socket, "grok.account.read", %{}) do
      {:ok, read} when is_map(read) -> assign(socket, :grok_account, read)
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

  defp maybe_poll_grok_account(socket) do
    card = NewSession.grok_account_card(socket.assigns.grok_account, socket.assigns.grok_login)
    if card.state == :waiting, do: poll_grok_account(socket), else: socket
  end

  defp poll_grok_account(%{assigns: %{polling_grok_account?: true}} = socket), do: socket

  defp poll_grok_account(socket) do
    Process.send_after(self(), :poll_grok_account, @account_poll)
    assign(socket, :polling_grok_account?, true)
  end

  defp settled?(read) when is_map(read),
    do: not match?(%{"login" => %{"status" => "pending"}}, read)

  defp settled?(_read), do: false

  defp grok_settled?(%{"login" => %{"status" => status}})
       when status in ["starting", "pending"],
       do: false

  defp grok_settled?(read), do: is_map(read)

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

            socket
            |> assign(:started_id, id)
            |> send_initial(id)

          :error ->
            socket
            |> assign(:starting?, false)
            |> assign(:refusal, %{
              message: "The session started, but this build could not open it.",
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

  defp send_initial(socket, id) do
    message = String.trim(socket.assigns.initial_message)

    if message == "" do
      push_navigate(socket, to: NewSession.deck_path(id))
    else
      digest =
        :crypto.hash(:sha256, id <> <<0>> <> message)
        |> Base.encode16(case: :lower)
        |> binary_part(0, 24)

      params = %{
        "id" => id,
        "input" => message,
        "turn_id" => "web-" <> digest
      }

      case call(socket, "interactive.send_message", params) do
        {:ok, _turn} ->
          push_navigate(socket, to: NewSession.deck_path(id))

        refused ->
          detail =
            case NewSession.refusal(refused) do
              %{message: message} -> message
              _other -> "the runtime refused the first message"
            end

          socket
          |> assign(:starting?, false)
          |> assign(:refusal, %{
            message: "The session started, but its first message was not sent.",
            detail: detail
          })
      end
    end
  end

  defp save_anthropic_credentials(socket, credential_params) do
    case call(socket, "credentials.anthropic.set", credential_params) do
      {:ok, _status} ->
        {:noreply,
         socket
         |> assign(:api_key_dialog?, false)
         |> assign(:api_key_error, nil)
         |> assign(:refusal, nil)
         |> load_providers()}

      refused ->
        words = NewSession.refusal(refused)

        {:noreply,
         assign(
           socket,
           :api_key_error,
           (words && words.message) || "The Anthropic credentials could not be stored."
         )}
    end
  end

  defp save_xai_key(socket, api_key) do
    case call(socket, "credentials.xai.set", %{"api_key" => api_key}) do
      {:ok, _status} ->
        {:noreply,
         socket
         |> assign(:api_key_dialog?, false)
         |> assign(:api_key_error, nil)
         |> assign(:refusal, nil)
         |> load_providers()}

      refused ->
        words = NewSession.refusal(refused)

        {:noreply,
         assign(
           socket,
           :api_key_error,
           (words && words.message) || "The xAI API key could not be stored."
         )}
    end
  end

  defp put_credential_param(params, _key, value) when not is_binary(value), do: params

  defp put_credential_param(params, key, value) do
    case String.trim(value) do
      "" -> params
      value -> Map.put(params, key, value)
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
  defp read_form(params, form) do
    %{
      form
      | provider: Map.get(params, "provider", form.provider),
        workspace: Map.get(params, "workspace", form.workspace),
        model_text: Map.get(params, "model_text", form.model_text),
        model_search: Map.get(params, "model_search", form.model_search),
        model_choice: model_choice(params, form),
        effort: blank_to_nil(Map.get(params, "effort", form.effort))
    }
  end

  defp choose_provider(form, rows) do
    available = Enum.filter(rows, & &1.detected?)

    provider =
      cond do
        Enum.any?(available, &(&1.name == form.provider)) -> form.provider
        Enum.any?(available, &(&1.name == "native")) -> "native"
        available != [] -> hd(available).name
        true -> nil
      end

    %{form | provider: provider}
  end

  defp available_provider?(rows, provider) when is_list(rows) do
    Enum.any?(rows, &(&1.name == provider and &1.detected?))
  end

  defp available_provider?(_rows, _provider), do: false

  # A model chosen under the previous provider is not necessarily a row under the new one,
  # so the choice is re-checked against the field the change produced rather than carried.
  defp reconcile(form, socket) do
    field = NewSession.model_field(socket.assigns.catalogue, form.provider)

    form =
      if NewSession.offers?(field, form.model_choice),
        do: form,
        else: %{form | model_choice: :runtime_default}

    if is_nil(form.effort) or form.effort in NewSession.efforts(form, field),
      do: form,
      else: %{form | effort: nil}
  end

  defp field(socket),
    do: NewSession.model_field(socket.assigns.catalogue, socket.assigns.form.provider)

  defp model_choice(%{"model_choice" => value}, _form), do: NewSession.choice(value)
  defp model_choice(_params, form), do: form.model_choice

  defp blank_to_nil(value) when is_binary(value), do: if(String.trim(value) != "", do: value)
  defp blank_to_nil(_value), do: nil

  defp blank?(value), do: not is_binary(value) or String.trim(value) == ""

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    field = NewSession.model_field(assigns.catalogue, assigns.form.provider)
    account = NewSession.account_card(assigns.account, assigns.login)
    gated? = NewSession.requires_chatgpt?(assigns.form, field)
    grok_account = NewSession.grok_account_card(assigns.grok_account, assigns.grok_login)
    grok_gated? = NewSession.requires_grok?(assigns.form)
    api_key = NewSession.api_key_card(assigns.form, field, assigns.providers)
    chatgpt_ready? = not gated? or account.usable?
    grok_ready? = not grok_gated? or grok_account.usable? or (api_key && api_key.usable?)
    api_key_required? = match?(%{managed?: false, usable?: false}, api_key)

    can_start? = Call.available?(assigns.scope, "interactive.start")

    provider_ready? =
      assigns.loaded? and available_provider?(assigns.providers, assigns.form.provider)

    assigns =
      assigns
      |> assign(:field, field)
      |> assign(:efforts, NewSession.efforts(assigns.form, field))
      |> assign(
        :visible,
        NewSession.search(field, assigns.form.model_search, assigns.form.model_choice)
      )
      |> assign(:intent, NewSession.model_intent(assigns.form, field))
      |> assign(:account_card, account)
      |> assign(:gated?, gated?)
      |> assign(:chatgpt_ready?, chatgpt_ready?)
      |> assign(:grok_account_card, grok_account)
      |> assign(:grok_gated?, grok_gated?)
      |> assign(:grok_ready?, grok_ready?)
      |> assign(:api_key_card, api_key)
      |> assign(:api_key_required?, api_key_required?)
      |> assign(
        :can_set_api_key?,
        Call.available?(assigns.scope, credential_method(api_key))
      )
      |> assign(:can_start?, can_start?)
      |> assign(:provider_ready?, provider_ready?)
      |> assign(:can_browse?, Call.available?(assigns.scope, "workspace.browse"))
      |> assign(:provider_label, provider_label(assigns.form.provider))

    ~H"""
    <div class="ouro-new">
      <header class="ouro-new-top">
        <div class="ouro-top-row">
          <a class="ouro-new-back" href="/">← Sessions</a>
          <Layouts.theme_toggle />
        </div>
        <h1 class="ouro-new-title">New session</h1>
        <p class="ouro-new-sub">Choose a project and describe what you want done</p>
      </header>

      <form id="new-session" class="ouro-new-form" phx-change="change" phx-submit="start">
        <.workspace_field
          workspace={@form.workspace}
          can_browse={@can_browse?}
          open={@browse_open?}
          listing={@browse}
          refusal={@browse_refusal}
        />

        <section class="ouro-new-field" aria-labelledby="initial-message-label">
          <div class="ouro-new-label-row">
            <label class="ouro-new-label" id="initial-message-label" for="initial-message">
              What should the agent do?
            </label>
            <span class="ouro-new-aside">Optional</span>
          </div>
          <textarea
            id="initial-message"
            class="ouro-new-input ouro-new-message"
            name="initial_message"
            rows="5"
            placeholder="Describe the result you want. You can add more instructions later."
          >{@initial_message}</textarea>
          <p class="ouro-new-hint">This becomes the first message in the session.</p>
        </section>

        <details
          class="ouro-new-advanced"
          open={
            @provider_invalid? or not @chatgpt_ready? or not @grok_ready? or
              @api_key_required?
          }
        >
          <summary>
            <span>Advanced settings</span>
            <span class="ouro-new-advanced-summary">
              {@provider_label} · recommended model · {sandbox_title(@form.sandbox)}
            </span>
          </summary>

          <.provider_field
            rows={@providers}
            error={@providers_error}
            invalid={@provider_invalid?}
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

          <.thinking_field effort={@form.effort} choices={@efforts} />
          <.sandbox_field sandbox={@form.sandbox} />
          <.account_card :if={@gated?} card={@account_card} scope={@scope} />
          <.grok_account_card
            :if={@grok_gated?}
            card={@grok_account_card}
            scope={@scope}
            api_key={@api_key_card}
          />
          <.api_key_card
            :if={is_map(@api_key_card)}
            card={@api_key_card}
            can_set={@can_set_api_key?}
          />
        </details>

        <p :if={@refusal} class="ouro-refusal ouro-new-refusal" role="alert">
          {@refusal.message}
          <span :if={@refusal.detail} class="ouro-new-refusal-detail">{@refusal.detail}</span>
        </p>

        <footer class="ouro-new-foot">
          <a class="ouro-new-cancel" href="/">Cancel</a>
          <button
            type="submit"
            class="ouro-button"
            disabled={
              not @can_start? or not @provider_ready? or @starting? or
                not @chatgpt_ready? or not @grok_ready? or @api_key_required?
            }
          >
            {start_label(
              @can_start?,
              @starting?,
              @chatgpt_ready?,
              @grok_ready?,
              @api_key_required?,
              @api_key_card
            )}
          </button>
        </footer>

        <p :if={not @loaded? and is_nil(@providers_error)} class="ouro-new-note" role="status">
          Finding the available AI provider…
        </p>
        <p :if={@loaded? and not @provider_ready?} class="ouro-new-note" role="alert">
          No supported AI provider is available on this computer.
        </p>
        <p :if={not @can_start?} class="ouro-new-note">
          This link is view-only. Ask the person who set up Ouroboros for permission to start
          sessions.
        </p>
      </form>

      <.anthropic_key_dialog
        :if={(@api_key_dialog? and @api_key_card) && @api_key_card.key == "anthropic"}
        error={@api_key_error}
        card={@api_key_card}
      />
      <.xai_key_dialog
        :if={(@api_key_dialog? and @api_key_card) && @api_key_card.key == "xai"}
        error={@api_key_error}
      />
    </div>
    """
  end

  defp start_label(false, _starting?, _chatgpt?, _grok?, _key?, _card), do: "Start session"
  defp start_label(_can?, true, _chatgpt?, _grok?, _key?, _card), do: "Starting…"
  defp start_label(_can?, _starting?, false, _grok?, _key?, _card), do: "Connect ChatGPT first"

  defp start_label(_can?, _starting?, _chatgpt?, false, _key?, _card),
    do: "Connect Grok or add API key first"

  defp start_label(_can?, _starting?, _chatgpt?, _grok?, true, card),
    do: "Add #{card.provider} API key first"

  defp start_label(_can?, _starting?, _chatgpt?, _grok?, _key?, _card),
    do: "Start session"

  defp credential_method(%{key: "anthropic"}), do: "credentials.anthropic.set"
  defp credential_method(%{key: "xai"}), do: "credentials.xai.set"
  defp credential_method(_card), do: "credentials.anthropic.set"
  defp provider_label(provider), do: NewSession.provider_route(provider).name

  defp provider_option_label(provider) do
    route = NewSession.provider_route(provider)
    "#{route.name} — #{route.short}"
  end

  # ------------------------------------------------------------------------------------
  # Provider
  # ------------------------------------------------------------------------------------

  attr :rows, :any, required: true
  attr :error, :any, required: true
  attr :invalid, :boolean, required: true
  attr :loaded, :boolean, required: true
  attr :chosen, :any, required: true

  def provider_field(assigns) do
    assigns = assign(assigns, :footnote, NewSession.provider_footnote(assigns.rows || []))

    ~H"""
    <section class="ouro-new-field" aria-labelledby="provider-label">
      <div class="ouro-new-label-row">
        <label class="ouro-new-label" id="provider-label" for="provider">AI provider</label>
        <span class="ouro-new-aside">Automatically selected</span>
      </div>

      <select
        id="provider"
        class="ouro-new-select"
        phx-hook="FocusInvalid"
        name="provider"
        required
        disabled={not @loaded}
        aria-invalid={to_string(@invalid)}
        aria-describedby={if @invalid, do: "provider-error", else: nil}
      >
        <option value="" selected={is_nil(@chosen) or @chosen == ""}>No provider available</option>
        <option
          :for={row <- @rows || []}
          value={row.name}
          selected={@chosen == row.name}
          disabled={not row.detected?}
          class={if not row.detected?, do: "ouro-new-dim"}
        >
          {provider_option_label(row.name)}{if row.name == "native" and row.detected?,
            do: " — recommended"}{if row.note, do: " — unavailable: #{row.note}"}
        </option>
      </select>

      <p :if={@invalid} id="provider-error" class="ouro-refusal" role="alert">
        choose an available AI provider before starting
      </p>
      <p :if={@error} class="ouro-refusal">The provider list could not be loaded: {@error}</p>
      <p :if={not @loaded and is_nil(@error)} class="ouro-new-hint">Finding providers…</p>
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
    assigns = assign(assigns, :route, NewSession.provider_route(assigns.form.provider))

    ~H"""
    <section class="ouro-new-field" aria-labelledby="model-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="model-label">Model</span>
        <span class="ouro-new-aside">{model_aside(@field)}</span>
      </div>

      <div class="ouro-model-route" aria-label="Model execution path">
        <span class="ouro-model-route-badge">{@route.badge}</span>
        <span class="ouro-model-route-copy">
          <strong>{@route.title}</strong>
          <span>{@route.detail}</span>
        </span>
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
      |> assign(:recommended_rows, Enum.filter(rows, &(&1.choice == :runtime_default)))
      |> assign(:model_groups, NewSession.model_groups(rows, assigns.form.provider))
      |> assign(:custom_rows, Enum.filter(rows, &(&1.choice == :custom)))
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
      <.model_option :for={row <- @recommended_rows} row={row} chosen={@form.model_choice} />

      <optgroup :for={group <- @model_groups} label={group.label}>
        <.model_option :for={row <- group.rows} row={row} chosen={@form.model_choice} />
      </optgroup>

      <.model_option :for={row <- @custom_rows} row={row} chosen={@form.model_choice} />
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

  attr :row, :map, required: true
  attr :chosen, :any, required: true

  defp model_option(assigns) do
    ~H"""
    <option
      value={NewSession.choice_value(@row.choice)}
      selected={@row.choice == @chosen}
    >
      <%!-- An em dash, not the middot the detail itself uses to join a name to a
            context window: one option is one line here, and the two separators keep the
            row's id readable apart from what the snapshot says about it. --%>
      {@row.label}{if @row.detail, do: " — #{@row.detail}"}
    </option>
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
        <label class="ouro-new-label" id="workspace-label" for="workspace">Project folder</label>
        <span class="ouro-new-aside">Optional</span>
      </div>

      <div class="ouro-new-row">
        <input
          id="workspace"
          type="text"
          class="ouro-new-input"
          name="workspace"
          value={@workspace}
          placeholder="Choose a project folder"
          autocomplete="off"
        />
        <button
          type="button"
          class="ouro-new-secondary"
          phx-click="browse-open"
          disabled={not @can_browse}
          title={not @can_browse && "Folder browsing is unavailable from this link"}
        >
          Browse…
        </button>
      </div>
      <p class="ouro-new-hint">Leave blank to use the default project folder.</p>

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
  attr :choices, :list, required: true

  def thinking_field(assigns) do
    ~H"""
    <section class="ouro-new-field" aria-labelledby="effort-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="effort-label">Thinking</span>
        <span class="ouro-new-aside">{if @effort, do: "Selected", else: "Recommended"}</span>
      </div>

      <select
        class="ouro-new-select"
        name="effort"
        aria-labelledby="effort-label"
        disabled={@choices == []}
      >
        <option value="" selected={is_nil(@effort)}>Recommended</option>
        <option :for={level <- @choices} value={level} selected={@effort == level}>
          {String.capitalize(level)}
        </option>
      </select>

      <p class="ouro-new-intent">
        {thinking_intent(@effort, @choices)}
      </p>
    </section>
    """
  end

  defp thinking_intent(_effort, []),
    do: "The selected model does not advertise an adjustable thinking level."

  defp thinking_intent(effort, _choices) when is_binary(effort),
    do: "Thinking level: #{String.capitalize(effort)}"

  defp thinking_intent(_effort, _choices),
    do: "Ouroboros will choose the recommended thinking level."

  # ------------------------------------------------------------------------------------
  # Sandbox
  # ------------------------------------------------------------------------------------

  attr :sandbox, :any, required: true

  def sandbox_field(assigns) do
    ~H"""
    <section class="ouro-new-field" aria-labelledby="sandbox-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="sandbox-label">File access</span>
        <span class="ouro-new-aside">
          {if @sandbox == "workspace_write", do: "Recommended", else: "Selected"}
        </span>
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

      <p class="ouro-new-intent">{sandbox_intent(@sandbox)}</p>
    </section>
    """
  end

  # `unrestricted` is the wire's word and it stays on the wire; every surface a person
  # reads says full access, because "unrestricted" names the parameter rather than what
  # the agent is being allowed to do.
  defp sandbox_title("read_only"), do: "Read only"
  defp sandbox_title("workspace_write"), do: "Project files"
  defp sandbox_title("unrestricted"), do: "Full computer access"

  defp sandbox_describe("read_only"), do: "cannot create or edit files"
  defp sandbox_describe("workspace_write"), do: "can edit files in the project folder"

  defp sandbox_describe("unrestricted"),
    do: "can change files outside the project and run system commands"

  defp sandbox_intent("read_only"),
    do: "The agent can inspect the project without changing files."

  defp sandbox_intent("workspace_write"), do: "The agent can edit files in the project folder."

  defp sandbox_intent("unrestricted"),
    do: "The agent can access files outside the project folder."

  defp sandbox_intent(_mode), do: "Ouroboros will use the recommended file access."

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

  # ------------------------------------------------------------------------------------
  # Grok subscription
  # ------------------------------------------------------------------------------------

  attr :card, :map, required: true
  attr :scope, :atom, required: true
  attr :api_key, :any, required: true

  def grok_account_card(assigns) do
    assigns =
      assign(
        assigns,
        :can_login?,
        Call.available?(assigns.scope, "grok.account.login.start")
      )

    ~H"""
    <section class="ouro-new-field ouro-account" aria-labelledby="grok-account-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="grok-account-label">SpaceXAI subscription</span>
        <span class="ouro-new-aside">
          {grok_account_aside(@card.state, @api_key)}
        </span>
      </div>

      <p :if={@card.state == :checking} class="ouro-new-hint">
        Reading Grok CLI account readiness…
      </p>

      <p :if={@card.state == :connected} class="ouro-new-hint">
        The first-party Grok Build CLI is connected{if @card.identity,
          do: " as #{@card.identity}"}. It owns and refreshes the subscription tokens;
        Ouroboros never reads them.
      </p>

      <p :if={@card.state == :required} class="ouro-new-hint">
        Connect an eligible SpaceXAI subscription through the first-party Grok Build CLI.
        You can use an xAI API key instead; API usage is billed separately from a subscription.
      </p>

      <div :if={@card.state == :waiting} class="ouro-account-wait">
        <p class="ouro-new-hint">
          Open the link, confirm that the code matches, then come back here.
        </p>
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
          phx-click="connect-grok"
          disabled={not @can_login?}
        >
          Connect subscription
        </button>
        <button
          :if={@card.state == :waiting}
          type="button"
          class="ouro-new-secondary"
          phx-click="cancel-grok"
        >
          Cancel
        </button>
      </div>
    </section>
    """
  end

  defp grok_account_aside(:checking, _api_key), do: "Checking"
  defp grok_account_aside(:connected, _api_key), do: "Connected"
  defp grok_account_aside(:waiting, _api_key), do: "Waiting"
  defp grok_account_aside(:required, %{usable?: true}), do: "Optional"
  defp grok_account_aside(:required, _api_key), do: "One option required"

  # ------------------------------------------------------------------------------------
  # Direct API key
  # ------------------------------------------------------------------------------------

  attr :card, :map, required: true
  attr :can_set, :boolean, required: true

  def api_key_card(assigns) do
    ~H"""
    <section class="ouro-new-field ouro-account" aria-labelledby="api-key-label">
      <div class="ouro-new-label-row">
        <span class="ouro-new-label" id="api-key-label">{@card.provider} API</span>
        <span class="ouro-new-aside">{api_key_aside(@card.state)}</span>
      </div>

      <p :if={@card.state == :checking} class="ouro-new-hint">
        Reading API-key readiness…
      </p>

      <p :if={@card.state == :available and @card.source == "stored"} class="ouro-new-hint">
        A private {@card.provider} API key is stored by Ouroboros. Its value never reaches
        this page.
        <span :if={@card.key == "anthropic" and @card.workspace_configured?}>
          A workspace ID is configured for identity-linked requests.
        </span>
        <span :if={@card.key == "anthropic" and not @card.workspace_configured?}>
          Identity-linked keys also need their <code>wrkspc_…</code> workspace ID.
        </span>
      </p>

      <p :if={@card.state == :available and @card.source != "stored"} class="ouro-new-hint">
        {@card.env} is available from the service environment. Its value never reaches this page.
        <span :if={@card.key == "anthropic"}>
          Set <code>{@card.workspace_env}</code> too when the key is identity-linked.
        </span>
      </p>

      <p :if={@card.state == :required and @card.key == "anthropic"} class="ouro-new-hint">
        Claude models use direct Anthropic API calls only. Add a key here, or set
        <code>{@card.env}</code>
        in the Ouroboros service environment. OAuth and Claude
        subscription login are not used.
      </p>

      <p
        :if={@card.state == :required and @card.key == "xai" and not @card.managed?}
        class="ouro-new-hint"
      >
        Direct Grok models use the xAI API. Add a key here, or set <code>{@card.env}</code>
        in the Ouroboros service environment. SpaceXAI subscription
        login is available through the managed Grok provider instead.
      </p>

      <p
        :if={@card.state == :required and @card.key == "xai" and @card.managed?}
        class="ouro-new-hint"
      >
        Add an xAI API key as an alternative to subscription login. The first-party CLI uses
        a connected subscription first and this key as its fallback.
      </p>

      <div :if={@can_set and @card.source != "environment"} class="ouro-new-row">
        <button
          type="button"
          class="ouro-new-secondary"
          phx-click={open_api_key_event(@card.key)}
        >
          {api_key_button_label(@card)}
        </button>
      </div>

      <p :if={not @can_set and @card.state == :required} class="ouro-new-hint">
        This link is view-only, so it cannot store provider credentials.
      </p>
    </section>
    """
  end

  defp api_key_aside(:checking), do: "Checking"
  defp api_key_aside(:available), do: "Available"
  defp api_key_aside(:required), do: "Required"

  defp open_api_key_event("anthropic"), do: "open-anthropic-key"
  defp open_api_key_event("xai"), do: "open-xai-key"

  defp api_key_button_label(%{key: "anthropic", state: :available}),
    do: "Manage Anthropic credentials"

  defp api_key_button_label(%{state: :available} = card),
    do: "Replace #{card.provider} API key"

  defp api_key_button_label(_card), do: "Add API key"

  attr :error, :any, required: true
  attr :card, :map, required: true

  def anthropic_key_dialog(assigns) do
    ~H"""
    <dialog
      id="anthropic-key-dialog"
      class="ouro-session-dialog"
      aria-modal="true"
      aria-labelledby="anthropic-key-title"
      phx-hook="Modal"
      data-cancel-event="cancel-anthropic-key"
    >
      <form
        id="anthropic-key-form"
        phx-submit="save-anthropic-key"
        class="ouro-session-dialog-form"
        autocomplete="off"
      >
        <h2 id="anthropic-key-title">Anthropic credentials</h2>
        <p>
          The key and optional workspace ID are stored in one private mode-0600 file on this
          runtime host. They are sent only to Anthropic when a Claude model runs and are never
          shown again.
        </p>
        <label for="anthropic-api-key">
          API key{if @card.state == :available, do: " (optional)", else: ""}
        </label>
        <input
          id="anthropic-api-key"
          name="anthropic_api_key"
          type="password"
          class="ouro-new-input ouro-mono"
          placeholder="sk-ant-…"
          autocomplete="new-password"
          autocapitalize="none"
          spellcheck="false"
          maxlength="8192"
          required={@card.state != :available}
          autofocus
        />
        <p :if={@card.state == :available} class="ouro-new-hint">
          Leave this blank to keep the saved key.
        </p>
        <label for="anthropic-workspace-id">Workspace ID (identity-linked keys)</label>
        <input
          id="anthropic-workspace-id"
          name="anthropic_workspace_id"
          type="text"
          class="ouro-new-input ouro-mono"
          placeholder="wrkspc_…"
          autocomplete="off"
          autocapitalize="none"
          spellcheck="false"
          maxlength="256"
          pattern="wrkspc_[A-Za-z0-9]+"
        />
        <p class="ouro-new-hint">
          Personal or service-account keys that can access multiple workspaces require this
          value on every request. Find it in Anthropic Console → Settings → Workspaces.
          <span :if={@card.workspace_configured?}>
            Leave this blank to keep the saved workspace ID.
          </span>
        </p>
        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>
        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="cancel-anthropic-key">
            Cancel
          </button>
          <button type="submit" class="ouro-button" phx-disable-with="Saving…">
            Save credentials
          </button>
        </div>
      </form>
    </dialog>
    """
  end

  attr :error, :any, required: true

  def xai_key_dialog(assigns) do
    ~H"""
    <dialog
      id="xai-key-dialog"
      class="ouro-session-dialog"
      aria-modal="true"
      aria-labelledby="xai-key-title"
      phx-hook="Modal"
      data-cancel-event="cancel-xai-key"
    >
      <form
        id="xai-key-form"
        phx-submit="save-xai-key"
        class="ouro-session-dialog-form"
        autocomplete="off"
      >
        <h2 id="xai-key-title">xAI API key</h2>
        <p>
          The key is stored in a private mode-0600 file on this runtime host. It is passed
          only to direct xAI requests and the first-party Grok CLI, and is never shown again.
        </p>
        <label for="xai-api-key">API key</label>
        <input
          id="xai-api-key"
          name="xai_api_key"
          type="password"
          class="ouro-new-input ouro-mono"
          placeholder="xai-…"
          autocomplete="new-password"
          autocapitalize="none"
          spellcheck="false"
          maxlength="8192"
          required
          autofocus
        />
        <p class="ouro-new-hint">
          Create API keys in the xAI Console. API usage and SpaceXAI subscriptions are
          separate billing paths.
        </p>
        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>
        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="cancel-xai-key">
            Cancel
          </button>
          <button type="submit" class="ouro-button" phx-disable-with="Saving…">
            Save API key
          </button>
        </div>
      </form>
    </dialog>
    """
  end
end
