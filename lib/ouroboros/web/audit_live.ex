defmodule Ouroboros.Web.AuditLive do
  @moduledoc "Read-only investigation of canonical evidence with explicit coverage."
  use Phoenix.LiveView
  alias Ouroboros.Web.{Call, Config}

  @impl true
  def mount(_, _, socket) do
    {:ok,
     assign(socket,
       page_title: "Audit",
       error: nil,
       status: nil,
       events: [],
       detail: nil,
       filters: %{},
       next_offset: nil,
       stream: nil,
       artifact: nil,
       bundle: nil
     )}
  end

  @impl true
  def handle_params(params, _, socket) do
    socket = assign(socket, stream: params["stream"], detail: nil, bundle: nil)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("search", params, socket) do
    filters =
      Map.take(params, ~w(session_id actor_id kind tool model since until))
      |> Map.reject(fn {_, v} -> v == "" end)

    {:noreply, socket |> assign(filters: filters, detail: nil, stream: nil) |> load()}
  end

  def handle_event("refresh", _, socket), do: {:noreply, load(socket)}

  def handle_event("more", _, socket) do
    params = Map.put(socket.assigns.filters, "offset", socket.assigns.next_offset || 0)

    case call(socket, "audit.search", params) do
      {:ok, result} ->
        {:noreply,
         assign(socket,
           events: socket.assigns.events ++ result.events,
           next_offset: result.next_offset
         )}

      error ->
        {:noreply, failure(socket, error)}
    end
  end

  def handle_event("next", _, socket) do
    since = socket.assigns.detail.next_seq || 0

    case call(socket, "audit.show", %{
           "stream_id" => socket.assigns.stream,
           "since_seq" => since,
           "limit" => 50
         }) do
      {:ok, detail} -> {:noreply, assign(socket, detail: detail)}
      error -> {:noreply, failure(socket, error)}
    end
  end

  def handle_event("artifact", %{"blob" => blob}, socket) do
    case call(socket, "audit.artifact", %{"stream_id" => socket.assigns.stream, "blob" => blob}) do
      {:ok, artifact} -> {:noreply, assign(socket, artifact: artifact)}
      error -> {:noreply, failure(socket, error)}
    end
  end

  def handle_event("export", _, socket) do
    params = if socket.assigns.stream, do: %{"stream_id" => socket.assigns.stream}, else: %{}

    case call(socket, "audit.export", params) do
      {:ok, bundle} -> {:noreply, assign(socket, bundle: bundle)}
      error -> {:noreply, failure(socket, error)}
    end
  end

  defp load(socket) do
    socket = assign(socket, error: nil)

    socket =
      case call(socket, "audit.status", %{}) do
        {:ok, status} -> assign(socket, status: status)
        error -> failure(socket, error)
      end

    if socket.assigns.stream do
      case call(socket, "audit.show", %{"stream_id" => socket.assigns.stream, "limit" => 50}) do
        {:ok, detail} -> assign(socket, detail: detail)
        error -> failure(socket, error)
      end
    else
      case call(socket, "audit.search", socket.assigns.filters) do
        {:ok, result} -> assign(socket, events: result.events, next_offset: result.next_offset)
        error -> failure(socket, error)
      end
    end
  end

  defp call(socket, method, params),
    do:
      Call.call(Config.for_endpoint(socket.endpoint).scope, method, params,
        session: socket.assigns[:web_session]
      )

  defp failure(socket, error) do
    message =
      case error do
        {:error, _, message} -> message
        {:error, _, message, _} -> message
      end

    assign(socket, error: message)
  end

  defp pretty(value), do: Jason.encode!(value, pretty: true)
  defp durability("file_and_directory_sync"), do: "Files and directories synced"
  defp durability(value), do: String.replace(value, "_", " ")

  @impl true
  def render(assigns) do
    ~H"""
    <main class="ouro-page ouro-audit">
      <header class="ouro-header">
        <p class="ouro-subhead"><a href="/">Sessions</a> · <a href="/audit">Audit</a></p>
        <h1>Investigate execution</h1>
        <p>Follow model requests, tool actions, approvals and their recorded outcomes.</p>
      </header>
      <p :if={@error} role="alert" class="ouro-refusal">{@error}</p>
      <section :if={@status} class="ouro-panel" aria-label="Recording status">
        <div class="ouro-panel-head">
          <h2>Recording status</h2><button class="ouro-button" phx-click="refresh">Refresh</button>
        </div>
        <dl class="ouro-facts">
          <div class="ouro-fact">
            <dt>Mode</dt><dd>{to_string(@status.storage.policy.mode)}</dd>
          </div>
          <div class="ouro-fact">
            <dt>Content policy</dt><dd>{to_string(@status.storage.policy.capture)}</dd>
          </div>
          <div class="ouro-fact">
            <dt>Durability</dt><dd>{durability(@status.storage.durability)}</dd>
          </div>
          <div class="ouro-fact">
            <dt>Stored bytes / capacity</dt><dd>
              {@status.storage.bytes} / {@status.storage.capacity_bytes}
            </dd>
          </div>
        </dl>
        <p>
          Local hash chains detect changes within retained evidence. Independent trust anchors are required to verify completeness against an earlier observation.
        </p>
        <details>
          <summary>Coverage and storage details</summary><pre>{pretty(@status)}</pre>
        </details>
      </section>
      <section :if={!@stream} class="ouro-panel">
        <h2>Find events</h2>
        <form phx-submit="search" class="ouro-audit-filters">
          <label :for={
            {key, label} <- [
              {"session_id", "Session"},
              {"actor_id", "Actor"},
              {"kind", "Event kind"},
              {"tool", "Tool"},
              {"model", "Model"},
              {"since", "From (ISO 8601)"},
              {"until", "Until (ISO 8601)"}
            ]
          }>
            {label}<input type="text" name={key} value={@filters[key]} autocomplete="off" />
          </label>
          <button class="ouro-button" type="submit">Search</button>
        </form>
        <p :if={@events == []}>No matching retained events.</p>
        <div class="ouro-audit-scroll">
          <table :if={@events != []} class="ouro-audit-table">
            <thead>
              <tr>
                <th>Time</th><th>Event</th><th>Actor / session</th><th>Model / tool</th><th>
                  Evidence
                </th>
              </tr>
            </thead>
            <tbody>
              <tr :for={event <- @events}>
                <td>{event["at"]}</td><td>{event["kind"]}</td><td>
                  {event["actor_id"] || "Unattributed"}<br />{event["session_id"]}
                </td>
                <td>{event["model"] || event["tool"]}</td><td>
                  <.link navigate={"/audit/" <> event["stream_id"]}>Open stream · {event["seq"]}</.link>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <button :if={@next_offset} class="ouro-button" phx-click="more">Load more events</button>
      </section>
      <section :if={@detail} class="ouro-panel">
        <h2>Evidence stream</h2><p class="ouro-mono">{@stream}</p>
        <p>
          Verified through sequence {@detail.verified_through}. {@detail.coverage.unknown_outcomes} calls have no recorded terminal outcome.
        </p>
        <details>
          <summary>Coverage</summary><pre>{pretty(@detail.coverage)}</pre>
        </details>
        <h3 :if={@detail.calls != []}>Call outcomes</h3>
        <div :if={@detail.calls != []} class="ouro-audit-table">
          <table>
            <thead>
              <tr>
                <th>Call</th><th>Recorded outcome</th><th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={call <- @detail.calls}>
                <td>{call.name}</td><td>{call.outcome}</td>
                <td><a href={"#event-#{call.start_seq}"}>Start · {call.start_seq}</a></td>
              </tr>
            </tbody>
          </table>
        </div>
        <article
          :for={record <- @detail.records}
          id={"event-#{record["seq"]}"}
          class="ouro-audit-event"
        >
          <h3>{record["seq"]} · {record["kind"]}</h3><p>{record["at"]}</p>
          <details>
            <summary>Inspect recorded fields</summary><pre>{pretty(record)}</pre>
          </details>
          <button
            :for={blob <- Ouroboros.Audit.Bundle.blob_ids(record) |> Enum.uniq()}
            class="ouro-button"
            phx-click="artifact"
            phx-value-blob={blob}
          >Read retained artifact</button>
        </article>
        <button
          :if={@detail.next_seq && @detail.next_seq < @detail.verified_through}
          class="ouro-button"
          phx-click="next"
        >Next records</button>
      </section>
      <section :if={assigns[:artifact]} class="ouro-panel" aria-label="Retained artifact">
        <h2>Retained artifact</h2><pre>{pretty(@artifact)}</pre>
      </section>
      <section class="ouro-panel">
        <h2>Portable evidence</h2><p>
          Export a snapshot for independent review. Verification never reruns tools or models.
        </p>
        <button class="ouro-button" phx-click="export" phx-disable-with="Preparing…">Prepare export</button>
        <div :if={@bundle}>
          <p><a href={"/audit-bundle/" <> @bundle.bundle_id}>Download evidence bundle</a></p>
          <p>Manifest SHA-256: <code>{@bundle.manifest_sha256}</code></p>
          <p>
            Keep this digest through a separate trusted channel. After extraction, verify with <code>ouro audit verify DIRECTORY --expected-digest DIGEST</code>.
          </p>
        </div>
      </section>
    </main>
    """
  end
end
