defmodule Ouroboros.Web.Live.SettingsLive do
  @moduledoc """
  The web surface's settings index.

  This page separates three kinds of configuration that have different owners:

    * session defaults are operator preferences and can be changed here;
    * provider connections are runtime credentials and are changed only through the
      gateway methods that already own their storage and authorization;
    * runtime and web-endpoint facts are boot configuration, so they are shown as
      read-only rather than dressed up as controls that cannot take effect.

  Secret values never enter the socket. Provider probes report only presence and source,
  account methods project only readiness and identity, and the two key forms hand their
  password fields directly to the existing credential methods.
  """

  use Phoenix.LiveView

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Layouts
  alias Ouroboros.Web.Live.NewSession
  alias Ouroboros.Web.Live.NewSessionLive
  alias Ouroboros.Web.Prefs
  alias Ouroboros.Web.Presentation

  @account_poll 1_000

  @impl true
  def mount(_params, _session, socket) do
    config = Config.for_endpoint(socket.endpoint)

    socket =
      socket
      |> assign(:page_title, "Settings")
      |> assign(:scope, config.scope)
      |> assign(:data_dir, config.data_dir)
      |> assign(:web_config, config)
      |> assign(:form, NewSession.new(Prefs.read(config.data_dir)))
      |> assign(:providers, nil)
      |> assign(:providers_error, nil)
      |> assign(:catalogue, nil)
      |> assign(:catalogue_error, nil)
      |> assign(:runtime, nil)
      |> assign(:runtime_error, nil)
      |> assign(:loaded?, false)
      |> assign(:browse_open?, false)
      |> assign(:browse, nil)
      |> assign(:browse_refusal, nil)
      |> assign(:account, nil)
      |> assign(:login, nil)
      |> assign(:polling_account?, false)
      |> assign(:credential_dialog, nil)
      |> assign(:credential_error, nil)
      |> assign(:notice, nil)
      |> assign(:refusal, nil)

    {:ok, if(connected?(socket), do: load(socket), else: socket)}
  end

  # ------------------------------------------------------------------------------------
  # Session defaults
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_event("change-defaults", params, socket) do
    form = params |> read_form(socket.assigns.form) |> reconcile(socket)
    {:noreply, socket |> assign(:form, form) |> clear_feedback()}
  end

  def handle_event("pick-sandbox", %{"mode" => mode}, socket) do
    {:noreply,
     socket
     |> assign(:form, %{socket.assigns.form | sandbox: mode})
     |> clear_feedback()}
  end

  def handle_event("save-defaults", params, socket) do
    form = params |> read_form(socket.assigns.form) |> reconcile(socket)
    socket = assign(socket, :form, form)

    cond do
      not Call.available?(socket.assigns.scope, "interactive.start") ->
        {:noreply,
         refuse(socket, "This link is view-only.",
           detail: "Open the operate-scope Ouroboros web surface to change session defaults."
         )}

      true ->
        stated = NewSession.start_params(form, field(socket))

        case Prefs.write(socket.assigns.data_dir, Map.delete(stated, "id")) do
          :ok ->
            {:noreply,
             socket
             |> assign(:notice, "Session defaults saved for this Ouroboros runtime.")
             |> assign(:refusal, nil)}

          {:error, _reason} ->
            {:noreply,
             refuse(socket, "The defaults could not be stored.",
               detail: "The runtime log has the filesystem reason."
             )}
        end
    end
  end

  def handle_event("browse-open", _params, socket),
    do: {:noreply, socket |> assign(:browse_open?, true) |> browse(nil)}

  def handle_event("browse-close", _params, socket),
    do: {:noreply, assign(socket, :browse_open?, false)}

  def handle_event("browse-to", %{"path" => path}, socket),
    do: {:noreply, browse(socket, path)}

  def handle_event("browse-use", %{"path" => path}, socket) do
    {:noreply,
     socket
     |> assign(:form, %{socket.assigns.form | workspace: path})
     |> assign(:browse_open?, false)
     |> clear_feedback()}
  end

  # ------------------------------------------------------------------------------------
  # Subscription connections
  # ------------------------------------------------------------------------------------

  def handle_event("refresh-connections", _params, socket) do
    {:noreply, socket |> load_providers() |> read_account() |> maybe_poll_account()}
  end

  def handle_event("connect-chatgpt", _params, socket) do
    case Ouroboros.Web.Live.AccountConnection.connect(socket, &call/3, @account_poll) do
      {:ok, updated} -> {:noreply, clear_feedback(updated)}
      {:error, updated} -> {:noreply, updated}
    end
  end

  def handle_event("cancel-chatgpt", _params, socket),
    do: {:noreply, Ouroboros.Web.Live.AccountConnection.cancel(socket, &call/3)}

  def handle_event("open-anthropic-key", _params, socket),
    do: open_credential(socket, :anthropic, "credentials.anthropic.set")

  def handle_event("cancel-anthropic-key", _params, socket),
    do: {:noreply, socket |> assign(:credential_dialog, nil) |> assign(:credential_error, nil)}

  def handle_event("save-anthropic-key", params, socket) when is_map(params) do
    credential_params =
      NewSession.credential_params(params)

    if env_backed_credential?(socket, :anthropic) do
      {:noreply,
       assign(
         socket,
         :credential_error,
         "This runtime is using ANTHROPIC_API_KEY from the environment. Unset that variable to store a private key instead."
       )}
    else
      if map_size(credential_params) == 0 do
        {:noreply,
         assign(socket, :credential_error, "Enter a new API key or an Anthropic workspace ID.")}
      else
        save_credential(socket, "credentials.anthropic.set", credential_params)
      end
    end
  end

  def handle_event("open-xai-key", _params, socket),
    do: open_credential(socket, :xai, "credentials.xai.set")

  def handle_event("cancel-xai-key", _params, socket),
    do: {:noreply, socket |> assign(:credential_dialog, nil) |> assign(:credential_error, nil)}

  def handle_event("save-xai-key", %{"xai_api_key" => key}, socket) do
    cond do
      env_backed_credential?(socket, :xai) ->
        {:noreply,
         assign(
           socket,
           :credential_error,
           "This runtime is using XAI_API_KEY from the environment. Unset that variable to store a private key instead."
         )}

      String.trim(key) == "" ->
        {:noreply, assign(socket, :credential_error, "Enter an xAI API key.")}

      true ->
        save_credential(socket, "credentials.xai.set", %{"api_key" => String.trim(key)})
    end
  end

  @impl true
  def handle_info(:poll_account, socket),
    do: {:noreply, Ouroboros.Web.Live.AccountConnection.poll(socket, &call/3, @account_poll)}

  def handle_info(_message, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # Loading and gateway calls
  # ------------------------------------------------------------------------------------

  defp load(socket) do
    socket
    |> load_providers()
    |> load_models()
    |> load_runtime()
    |> promote_seed()
    |> assign(:loaded?, true)
    |> read_account()
    |> maybe_poll_account()
  end

  defp load_providers(socket) do
    case call(socket, "runtime.providers", %{}) do
      {:ok, entries} when is_list(entries) ->
        rows = NewSession.provider_rows(entries)

        if Enum.any?(rows, &(&1.credentials != [])) do
          socket
          |> assign(:providers, rows)
          |> assign(:providers_error, nil)
        else
          unavailable_providers(
            assign(socket, :providers, rows),
            "This runtime did not report credential status. Refresh or update the runtime."
          )
        end

      refused ->
        unavailable_providers(
          socket,
          refusal_message(refused) || "The credential report could not be read."
        )
    end
  end

  defp unavailable_providers(socket, message) do
    rows =
      Enum.map(socket.assigns.providers || [], fn row ->
        %{
          row
          | credentials:
              Enum.map(
                row.credentials,
                &Map.merge(&1, %{present: false, credential_state: "unavailable"})
              )
        }
      end)

    socket |> assign(:providers, rows) |> assign(:providers_error, message)
  end

  defp load_models(socket) do
    case call(socket, "runtime.models", %{}) do
      {:ok, catalogue} when is_map(catalogue) -> assign(socket, :catalogue, catalogue)
      refused -> assign(socket, :catalogue_error, refusal_message(refused))
    end
  end

  defp load_runtime(socket) do
    case call(socket, "runtime.status", %{}) do
      {:ok, runtime} when is_map(runtime) -> assign(socket, :runtime, runtime)
      refused -> assign(socket, :runtime_error, refusal_message(refused))
    end
  end

  defp promote_seed(socket),
    do: assign(socket, :form, NewSession.promote(socket.assigns.form, field(socket)))

  defp read_account(socket),
    do: Ouroboros.Web.Live.AccountConnection.read(socket, &call/3)

  defp maybe_poll_account(socket),
    do: Ouroboros.Web.Live.AccountConnection.maybe_poll(socket, @account_poll)

  defp browse(socket, path) do
    params = if is_binary(path), do: %{"path" => path}, else: %{}

    case call(socket, "workspace.browse", params) do
      {:ok, listing} when is_map(listing) ->
        socket |> assign(:browse, listing) |> assign(:browse_refusal, nil)

      refused ->
        assign(socket, :browse_refusal, %{
          words: NewSession.refusal(refused),
          roots: NewSession.refusal_roots(refused)
        })
    end
  end

  defp open_credential(socket, credential, method) do
    cond do
      not Call.available?(socket.assigns.scope, method) ->
        {:noreply,
         refuse(socket, "This link cannot change provider credentials.",
           detail: "Open the operate-scope Ouroboros web surface to add an API key."
         )}

      env_backed_credential?(socket, credential) ->
        {:noreply,
         refuse(socket, "This runtime is using an environment credential.",
           detail: "Unset the environment variable to store a private key instead."
         )}

      true ->
        {:noreply,
         socket
         |> assign(:credential_dialog, credential)
         |> assign(:credential_error, nil)
         |> clear_feedback()}
    end
  end

  defp save_credential(socket, method, params) do
    case call(socket, method, params) do
      {:ok, _status} ->
        {:noreply,
         socket
         |> assign(:credential_dialog, nil)
         |> assign(:credential_error, nil)
         |> assign(:notice, "Provider credentials saved on this runtime host.")
         |> assign(:refusal, nil)
         |> load_providers()}

      refused ->
        {:noreply,
         assign(
           socket,
           :credential_error,
           refusal_message(refused) || "The credentials could not be stored."
         )}
    end
  end

  defp call(socket, method, params),
    do: Call.call(socket.assigns.scope, method, params, session: socket.assigns[:web_session])

  defp refusal_message(refused) do
    case NewSession.refusal(refused) do
      %{message: message} -> message
      nil -> nil
    end
  end

  # ------------------------------------------------------------------------------------
  # Form and projections
  # ------------------------------------------------------------------------------------

  defp read_form(params, form) do
    %{
      form
      | workspace: Map.get(params, "workspace", form.workspace),
        model_text: Map.get(params, "model_text", form.model_text),
        model_search: Map.get(params, "model_search", form.model_search),
        model_choice: model_choice(params, form),
        effort: blank_to_nil(Map.get(params, "effort", form.effort))
    }
  end

  # A model chosen before the catalogue arrived — or remembered in `web.prefs.json` from a
  # snapshot that no longer lists it — is not necessarily a row in the current one, so the
  # field is built *with the form* (`model_field/2`) and keeps the current choice as a row
  # of its own. Reconciling against `model_field/1` is what reset a remembered model to the
  # runtime default the moment any other field was touched (review §3.5); `/new` has always
  # used `/2` and these two pages share the form, the control and the writer.
  defp reconcile(form, socket) do
    field = NewSession.model_field(socket.assigns.catalogue, form)

    form =
      if NewSession.offers?(field, form.model_choice),
        do: form,
        else: %{form | model_choice: :runtime_default}

    if is_nil(form.effort) or form.effort in NewSession.efforts(form, field),
      do: form,
      else: %{form | effort: nil}
  end

  defp model_choice(%{"model_choice" => value}, _form), do: NewSession.choice(value)
  defp model_choice(_params, form), do: form.model_choice

  defp field(socket),
    do: NewSession.model_field(socket.assigns.catalogue, socket.assigns.form)

  defp credential(rows, provider, env) when is_list(rows) do
    rows
    |> Enum.flat_map(&List.wrap(&1.credentials))
    |> Enum.filter(&(&1.provider == provider and &1.env == env))
    |> Enum.sort_by(&if(&1.present, do: 0, else: 1))
    |> List.first()
    |> case do
      nil ->
        %{
          provider: provider,
          env: env,
          present: false,
          source: nil,
          credential_state: "unavailable",
          workspace_configured?: false
        }

      credential ->
        credential
    end
  end

  defp credential(_rows, _provider, _env), do: nil

  defp env_backed_credential?(socket, :anthropic),
    do:
      match?(
        %{source: "environment"},
        credential(socket.assigns.providers, "anthropic", "ANTHROPIC_API_KEY")
      )

  defp env_backed_credential?(socket, :xai),
    do:
      match?(
        %{source: "environment"},
        credential(socket.assigns.providers, "xai", "XAI_API_KEY")
      )

  defp stored_credential_managed?(_can_set?, %{source: "environment"}), do: false
  defp stored_credential_managed?(can_set?, _credential), do: can_set?

  defp credential_state(%{credential_state: "invalid"}), do: :invalid
  defp credential_state(%{credential_state: "unavailable"}), do: :unavailable
  defp credential_state(%{present: true}), do: :available
  defp credential_state(%{present: false}), do: :missing
  defp credential_state(_credential), do: :checking

  defp provider_summaries(rows, catalogue) do
    model_rows = if is_map(catalogue), do: List.wrap(catalogue[:providers]), else: []

    Enum.map(rows || [], fn row ->
      models = Enum.find(model_rows, &(to_string(&1[:provider]) == row.name))

      %{
        name: NewSession.provider_route().name,
        key: row.name,
        available?: row.detected?,
        note: row.note,
        models: models && (models[:total] || length(List.wrap(models[:models]))),
        default: models && models[:default]
      }
    end)
  end

  defp blank_to_nil(value) when is_binary(value), do: if(String.trim(value) != "", do: value)
  defp blank_to_nil(_value), do: nil

  defp clear_feedback(socket), do: socket |> assign(:notice, nil) |> assign(:refusal, nil)

  defp refuse(socket, message, opts) do
    socket
    |> assign(:notice, nil)
    |> assign(:refusal, %{message: message, detail: opts[:detail]})
  end

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    field = NewSession.model_field(assigns.catalogue, assigns.form)

    assigns =
      assigns
      |> assign(:field, field)
      |> assign(:efforts, NewSession.efforts(assigns.form, field))
      |> assign(
        :visible,
        NewSession.search(field, assigns.form.model_search, assigns.form.model_choice)
      )
      |> assign(:intent, NewSession.model_intent(assigns.form, field))
      |> assign(:account_card, NewSession.account_card(assigns.account, assigns.login))
      |> assign(:anthropic, credential(assigns.providers, "anthropic", "ANTHROPIC_API_KEY"))
      |> assign(:openai, credential(assigns.providers, "openai", "OPENAI_API_KEY"))
      |> assign(:xai, credential(assigns.providers, "xai", "XAI_API_KEY"))
      |> assign(:grok, credential(assigns.providers, "grok", "OUROBOROS_GROK_AUTH_FILE"))
      |> assign(
        :additional_credentials,
        Enum.filter(other_credentials(assigns.providers), &credential_visible?/1)
      )
      |> assign(
        :other_credentials,
        Enum.reject(other_credentials(assigns.providers), &credential_visible?/1)
      )
      |> assign(:provider_summaries, provider_summaries(assigns.providers, assigns.catalogue))
      |> assign(:can_save?, Call.available?(assigns.scope, "interactive.start"))
      |> assign(:can_browse?, Call.available?(assigns.scope, "workspace.browse"))
      |> assign(:can_set_anthropic?, Call.available?(assigns.scope, "credentials.anthropic.set"))
      |> assign(:can_set_xai?, Call.available?(assigns.scope, "credentials.xai.set"))

    ~H"""
    <div>
      <Layouts.topbar current={:settings} />

      <main class="ouro-settings">
        <header class="ouro-settings-head">
          <div class="ouro-top-row">
            <a class="ouro-new-back" href="/">← Sessions</a>
          </div>
          <p class="ouro-settings-eyebrow">Ouroboros preferences</p>
          <h1>Settings</h1>
          <p>Your models, connected accounts, and preferences. All in one place.</p>
        </header>

        <div class="ouro-settings-shell">
          <nav class="ouro-settings-nav" aria-label="Settings sections">
            <a href="#connections">AI connections</a>
            <a href="#defaults">Session defaults</a>
            <a href="#providers">Providers & models</a>
            <a href="#runtime">Runtime & security</a>
          </nav>

          <div class="ouro-settings-content">
            <section
              id="connections"
              class="ouro-settings-section"
              aria-labelledby="connections-title"
            >
              <.section_head
                eyebrow="Accounts & billing"
                title="AI connections"
                id="connections-title"
                copy="Choose a subscription or use your own API keys. Secrets stay on the runtime; their values are never shown here."
              />

              <div class="ouro-settings-connections-summary" aria-live="polite">
                <p :if={@providers_error}>Connection status unavailable</p>
                <p :if={is_nil(@providers) and is_nil(@providers_error)}>
                  Reading connection status…
                </p>
                <p :if={not is_nil(@providers) and is_nil(@providers_error)}>
                  <strong>{connection_count(@account_card, @providers)}</strong>
                  {if connection_count(@account_card, @providers) == 1,
                    do: "connection",
                    else: "connections"} configured on this runtime
                </p>
                <button
                  type="button"
                  class="ouro-new-secondary"
                  phx-click="refresh-connections"
                  phx-disable-with="Refreshing…"
                >Refresh status</button>
              </div>
              <p :if={@providers_error} class="ouro-refusal" role="alert">
                Connection status could not be refreshed. {@providers_error}
              </p>
              <p class="ouro-settings-verification-note">
                Status reflects local credentials. Provider acceptance and model access are not verified.
              </p>

              <div class="ouro-settings-group">
                <div class="ouro-settings-group-head">
                  <h3>Subscriptions</h3>
                  <p>First-party account connections for eligible models.</p>
                </div>
                <div class="ouro-settings-connection-grid">
                  <.subscription_card
                    service="ChatGPT"
                    detail="OpenAI Codex models"
                    card={@account_card}
                    connect="connect-chatgpt"
                    cancel="cancel-chatgpt"
                    can_connect={Call.available?(@scope, "account.login.start")}
                  />
                  <.grok_subscription_card credential={@grok} />
                </div>
              </div>

              <div class="ouro-settings-group">
                <div class="ouro-settings-group-head">
                  <h3>API credentials</h3>
                  <p>
                    Direct usage billed by each provider. Stored keys can be replaced, never revealed.
                  </p>
                </div>
                <div class="ouro-settings-connection-list">
                  <.credential_card
                    provider="OpenAI"
                    logo="openai"
                    env="OPENAI_API_KEY"
                    credential={@openai}
                    managed={false}
                    read_only={@scope == :read}
                  />
                  <.credential_card
                    provider="Anthropic"
                    logo="anthropic"
                    env="ANTHROPIC_API_KEY"
                    credential={@anthropic}
                    managed={stored_credential_managed?(@can_set_anthropic?, @anthropic)}
                    event="open-anthropic-key"
                    read_only={@scope == :read}
                    workspace
                  />
                  <.credential_card
                    provider="xAI"
                    logo="xai"
                    env="XAI_API_KEY"
                    credential={@xai}
                    managed={stored_credential_managed?(@can_set_xai?, @xai)}
                    event="open-xai-key"
                    read_only={@scope == :read}
                  />
                  <.credential_card
                    :for={credential <- @additional_credentials}
                    provider={provider_name(credential.provider)}
                    env={credential.env}
                    credential={credential}
                    managed={false}
                    read_only={@scope == :read}
                  />
                </div>
              </div>
              <details
                :if={@other_credentials != []}
                class="ouro-settings-other"
                data-ouro-disclosure
                id="other-provider-credentials"
              >
                <summary>
                  Other API providers <span>{length(@other_credentials)} available to configure</span>
                </summary>
                <div class="ouro-settings-connection-list">
                  <.credential_card
                    :for={credential <- @other_credentials}
                    provider={provider_name(credential.provider)}
                    env={credential.env}
                    credential={credential}
                    managed={false}
                    read_only={@scope == :read}
                  />
                </div>
              </details>
            </section>

            <section id="defaults" class="ouro-settings-section" aria-labelledby="defaults-title">
              <.section_head
                eyebrow="Everyday"
                title="Session defaults"
                id="defaults-title"
                copy="These choices prefill every new session. You can still change them before starting."
              />

              <form
                id="session-defaults"
                class="ouro-settings-card ouro-settings-form"
                phx-change="change-defaults"
                phx-submit="save-defaults"
              >
                <NewSessionLive.model_field
                  field={@field}
                  visible={@visible}
                  form={@form}
                  intent={@intent}
                  error={@catalogue_error}
                />
                <NewSessionLive.thinking_field effort={@form.effort} choices={@efforts} />
                <NewSessionLive.sandbox_field sandbox={@form.sandbox} />
                <NewSessionLive.workspace_field
                  workspace={@form.workspace}
                  can_browse={@can_browse?}
                  open={@browse_open?}
                  listing={@browse}
                  refusal={@browse_refusal}
                />

                <div class="ouro-settings-form-foot">
                  <p>Stored privately on this runtime host.</p>
                  <button class="ouro-button" type="submit" disabled={not @can_save?}>
                    Save defaults
                  </button>
                </div>
              </form>
            </section>

            <section id="providers" class="ouro-settings-section" aria-labelledby="providers-title">
              <.section_head
                eyebrow="Model catalogue"
                title="Providers & models"
                id="providers-title"
                copy="What this computer can run right now. Unavailable adapters remain visible so setup gaps are inspectable."
              />

              <div class="ouro-settings-card ouro-settings-provider-list">
                <div :for={provider <- @provider_summaries} class="ouro-settings-provider-row">
                  <span
                    class={["ouro-settings-status", provider.available? && "is-ready"]}
                    aria-hidden="true"
                  ></span>
                  <div>
                    <strong>{provider.name}</strong>
                    <p :if={provider.available?}>
                      {model_count(provider.models)}{if provider.default,
                        do: " · default #{provider.default}"}
                    </p>
                    <p :if={not provider.available?}>
                      {provider.note || "Unavailable on this computer"}
                    </p>
                  </div>
                  <span class="ouro-settings-state">
                    {if provider.available?, do: "Available", else: "Unavailable"}
                  </span>
                </div>
                <p :if={@provider_summaries == []} class="ouro-settings-empty">
                  {if @providers_error, do: @providers_error, else: "Finding providers…"}
                </p>
              </div>
            </section>

            <section id="runtime" class="ouro-settings-section" aria-labelledby="runtime-title">
              <.section_head
                eyebrow="This installation"
                title="Runtime & security"
                id="runtime-title"
                copy="Boot-owned values are shown for diagnosis. Change them in the service environment, then restart Ouroboros."
              />

              <dl class="ouro-settings-card ouro-settings-facts">
                <.fact term="Runtime node" value={runtime_node(@runtime)} />
                <.fact term="Web access" value={scope_label(@scope)} />
                <.fact term="Listening on" value={endpoint_label(@web_config)} mono />
                <.fact term="Data directory" value={@data_dir} mono />
                <.fact term="Model catalogue" value={catalogue_label(@catalogue)} />
              </dl>
              <%!-- Node role, connected machines and the live session count are the same
                  runtime asked the same question a second later, so they are named once,
                  on the page whose whole job is to answer it. --%>
              <p class="ouro-settings-section-foot">
                <a href="/status">Runtime status — role, connected machines, live sessions →</a>
              </p>
              <p :if={@runtime_error} class="ouro-refusal ouro-settings-inline-error">
                Runtime details could not be loaded: {@runtime_error}
              </p>
            </section>

            <p :if={@notice} class="ouro-settings-toast" role="status">{@notice}</p>
            <p :if={@refusal} class="ouro-refusal ouro-settings-toast" role="alert">
              {@refusal.message}
              <span :if={@refusal.detail}>{@refusal.detail}</span>
            </p>
          </div>
        </div>

        <NewSessionLive.anthropic_key_dialog
          :if={@credential_dialog == :anthropic}
          error={@credential_error}
          card={anthropic_dialog_card(@anthropic)}
        />
        <NewSessionLive.xai_key_dialog
          :if={@credential_dialog == :xai}
          error={@credential_error}
        />
      </main>
    </div>
    """
  end

  attr :eyebrow, :string, required: true
  attr :title, :string, required: true
  attr :id, :string, required: true
  attr :copy, :string, required: true

  def section_head(assigns) do
    ~H"""
    <header class="ouro-settings-section-head">
      <p>{@eyebrow}</p>
      <h2 id={@id}>{@title}</h2>
      <span>{@copy}</span>
    </header>
    """
  end

  attr :service, :string, required: true
  attr :detail, :string, required: true
  attr :card, :map, required: true
  attr :connect, :string, required: true
  attr :cancel, :string, required: true
  attr :can_connect, :boolean, required: true

  def subscription_card(assigns) do
    ~H"""
    <article class="ouro-settings-connection-card" id="connection-chatgpt">
      <div class="ouro-settings-connection-title">
        <.provider_logo name="openai" />
        <div>
          <h4>{@service}</h4>
          <p>{@detail}</p>
        </div>
        <span class={["ouro-settings-state", @card.state == :connected && "is-ready"]}>{account_state(
          @card.state
        )}</span>
      </div>

      <p :if={@card.state == :connected} class="ouro-settings-connection-copy">
        Local account{if @card.identity, do: " — #{@card.identity}"}. Sign-in stays on the runtime computer.
      </p>
      <p :if={@card.state == :checking} class="ouro-settings-connection-copy">
        Reading account readiness…
      </p>
      <p :if={@card.state != :connected} class="ouro-settings-connection-copy">
        {@card.credential_note}
      </p>

      <div :if={@card.state == :waiting} class="ouro-account-wait">
        <p>Open the verification link, confirm the code, then return here.</p>
        <p :if={@card.code} class="ouro-account-code ouro-mono">{@card.code}</p>
        <p :if={@card.url}>
          <a
            :if={NewSession.https?(@card.url)}
            href={@card.url}
            target="_blank"
            rel="noreferrer noopener"
          >
            Open verification
          </a>
          <span :if={not NewSession.https?(@card.url)} class="ouro-mono">{@card.url}</span>
        </p>
      </div>

      <p :if={@card.error} class="ouro-refusal">{@card.error}</p>
      <div class="ouro-settings-card-actions">
        <button
          :if={@card.state in [:required, :checking, :unavailable]}
          type="button"
          class="ouro-new-secondary"
          phx-click={@connect}
          disabled={not @can_connect}
        >
          Connect ChatGPT
        </button>
        <button
          :if={@card.state == :waiting}
          type="button"
          class="ouro-new-secondary"
          phx-click={@cancel}
        >
          Cancel
        </button>
      </div>
    </article>
    """
  end

  attr :provider, :string, required: true
  attr :logo, :string, default: nil
  attr :read_only, :boolean, default: false
  attr :env, :string, required: true
  attr :credential, :any, required: true
  attr :managed, :boolean, required: true
  attr :event, :string, default: nil
  attr :workspace, :boolean, default: false

  def credential_card(assigns) do
    state = credential_state(assigns.credential)
    source = assigns.credential && assigns.credential.source

    assigns = assigns |> assign(:state, state) |> assign(:source, source)

    ~H"""
    <article
      class="ouro-settings-credential-row"
      id={"credential-" <> String.replace(@provider, " ", "-") <> "-" <> @env}
    >
      <.provider_logo :if={@logo} name={@logo} />
      <div class="ouro-settings-credential-body">
        <div class="ouro-settings-credential-name">
          <strong>{@provider}</strong>
          <span class={[
            "ouro-settings-state",
            @state == :available && "is-ready",
            @state == :invalid && "is-warning"
          ]}>{credential_label(@state, @source)}</span>
        </div>
        <p>
          <code>{@env}</code>{credential_copy(@state, @source)}
          <span :if={(@workspace and @credential) && @credential.workspace_configured?}>
            Workspace ID configured.
          </span>
          <span :if={(@workspace and @credential) && not @credential.workspace_configured?}>
            Identity-linked keys also need <code>ANTHROPIC_WORKSPACE_ID</code>.
          </span>
        </p>
      </div>
      <button
        :if={@managed and @event}
        type="button"
        class="ouro-new-secondary"
        phx-click={@event}
        aria-label={
          if @state == :available, do: "Manage #{@provider} API key", else: "Add #{@provider} API key"
        }
      >
        {if @state == :available, do: "Manage key", else: "Add key"}
      </button>
      <details
        :if={not @managed}
        class="ouro-settings-key-help"
        id={"setup-" <> String.replace(@provider, " ", "-") <> "-" <> @env}
        data-ouro-disclosure
      >
        <summary>{if @read_only, do: "View setup", else: "How to set up"}</summary>
        <p :if={@read_only}>This link is view-only. Use an operate link to manage stored keys.</p>
        <p :if={@source != "stored"}>
          <strong>Environment only.</strong>
          Set <code>{@env}</code>
          in the environment that starts Ouroboros on the runtime computer, then restart it and refresh this page.
        </p>
      </details>
    </article>
    """
  end

  attr :name, :string, required: true

  def provider_logo(assigns) do
    ~H"""
    <span class={["ouro-provider-logo", "ouro-provider-logo-" <> @name]} aria-hidden="true">
      <img src={"/web/providers/" <> @name <> ".svg"} alt="" width="28" height="28" />
    </span>
    """
  end

  attr :credential, :any, required: true

  def grok_subscription_card(assigns) do
    assigns = assign(assigns, :state, credential_state(assigns.credential))

    ~H"""
    <article class="ouro-settings-connection-card" id="connection-grok">
      <div class="ouro-settings-connection-title">
        <.provider_logo name="grok" />
        <div>
          <h4>Grok</h4><p>Grok subscription models</p>
        </div>
        <span class={[
          "ouro-settings-state",
          @state == :available && "is-ready",
          @state == :invalid && "is-warning"
        ]}>
          {grok_state(@state)}
        </span>
      </div>
      <p class="ouro-settings-connection-copy">{grok_copy(@state)}</p>
      <p class="ouro-settings-connection-copy">
        On the runtime computer, run <code>grok login</code>, then choose <strong>Refresh status</strong>.
      </p>
      <details
        class="ouro-settings-grok-setup"
        id="grok-setup"
        data-ouro-disclosure
      >
        <summary>Sign-in details</summary>
        <p>
          Uses your Grok subscription; the xAI API key is separate. Ouroboros reads the local sign-in; it does not copy or renew it.
        </p>
        <p class="ouro-settings-credential-path">
          Default: <code>~/.grok/auth.json</code>. A custom location can be set with <code>OUROBOROS_GROK_AUTH_FILE</code>.
        </p>
      </details>
    </article>
    """
  end

  defp grok_state(:available), do: "Connected locally"
  defp grok_state(:missing), do: "Not connected"
  defp grok_state(:invalid), do: "Sign in again"
  defp grok_state(:unavailable), do: "Status unavailable"
  defp grok_state(_), do: "Checking"
  defp grok_copy(:available), do: "A current Grok credential was found on this runtime."
  defp grok_copy(:missing), do: "Connect your Grok subscription to use its models here."

  defp grok_copy(:invalid),
    do: "The local sign-in has expired or is invalid. Sign in again with Grok."

  defp grok_copy(:unavailable),
    do:
      "The local sign-in could not be read. Check file access on the runtime computer, then refresh."

  defp grok_copy(_), do: "Waiting for this runtime to report its Grok sign-in status."

  defp credential_visible?(credential),
    do: credential.present or credential.credential_state == "invalid"

  defp other_credentials(rows) do
    (rows || [])
    |> Enum.flat_map(& &1.credentials)
    |> Enum.reject(&(&1.provider in ["openai", "openai_codex", "anthropic", "xai", "grok"]))
    |> Enum.uniq_by(& &1.env)
    |> Enum.sort_by(&{not &1.present, &1.provider})
  end

  defp provider_name(name),
    do:
      name
      |> String.replace("_", " ")
      |> String.split()
      |> Enum.map_join(" ", &String.capitalize/1)

  defp connection_count(account, rows) do
    if is_nil(rows),
      do: "Checking",
      else:
        Enum.count(
          Enum.uniq_by(Enum.flat_map(rows, & &1.credentials), & &1.env),
          &(&1.present and &1.provider != "openai_codex")
        ) + if(account.state == :connected, do: 1, else: 0)
  end

  attr :term, :string, required: true
  attr :value, :string, required: true
  attr :mono, :boolean, default: false

  def fact(assigns) do
    ~H"""
    <div>
      <dt>{@term}</dt>
      <dd class={@mono && "ouro-mono"}>{@value}</dd>
    </div>
    """
  end

  defp anthropic_dialog_card(credential) do
    %{
      state: if(credential_state(credential) == :available, do: :available, else: :required),
      workspace_configured?: credential != nil and credential.workspace_configured? == true
    }
  end

  defp account_state(:connected), do: "Connected locally"
  defp account_state(:unavailable), do: "Status unavailable"
  defp account_state(:waiting), do: "Waiting"
  defp account_state(:required), do: "Not connected"
  defp account_state(:checking), do: "Checking"

  defp credential_label(:invalid, _source), do: "Needs attention"
  defp credential_label(:unavailable, _source), do: "Status unavailable"
  defp credential_label(:available, "stored"), do: "Key stored"
  defp credential_label(:available, "environment"), do: "Environment key"
  defp credential_label(:available, _source), do: "Key configured"
  defp credential_label(:missing, _source), do: "Not configured"
  defp credential_label(:checking, _source), do: "Checking"

  defp credential_copy(:available, "stored"), do: " is stored by Ouroboros. The value is hidden. "

  defp credential_copy(:available, _source),
    do: " is available to the service. The value is hidden. "

  defp credential_copy(:invalid, _source),
    do: " could not be used. Check or replace the local credential. "

  defp credential_copy(:unavailable, _source),
    do: " status could not be read. Check access on the runtime computer, then refresh. "

  defp credential_copy(:missing, _source), do: " is not available to the service. "
  defp credential_copy(:checking, _source), do: " readiness has not been reported yet. "

  defp model_count(nil), do: "Model list unavailable"
  defp model_count(1), do: "1 model"
  defp model_count(count) when is_integer(count), do: "#{count} models"

  # The node, as a label rather than as the BEAM's own name for it. Node *role*, connected
  # machines and the live session count moved to `/status` with W1.5 rather than being
  # asked for twice.
  defp runtime_node(runtime) when is_map(runtime),
    do: Presentation.node_label(Map.get(runtime, :node))

  defp runtime_node(_runtime), do: "Loading…"

  defp scope_label(:operate), do: "Operate · settings and sessions enabled"
  defp scope_label(:read), do: "Read only · changes disabled"

  defp endpoint_label(config) do
    "#{Config.bind_to_string(config.bind)}:#{config.port}"
  end

  defp catalogue_label(catalogue) when is_map(catalogue) do
    source = catalogue[:source] || "runtime"
    epoch = catalogue[:epoch]
    if epoch, do: "#{source} · epoch #{epoch}", else: to_string(source)
  end

  defp catalogue_label(_catalogue), do: "Loading…"
end
