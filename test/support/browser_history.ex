defmodule Ouroboros.Test.BrowserHistory do
  @moduledoc "Synthetic retained history for browser pagination checks; no model calls."

  alias Ouroboros.Interactive.{Event, State, Store}

  def seed do
    id = "browser-history"

    messages =
      for n <- 1..125 do
        Event.from_runtime(id, n, :output_text_final, %{
          "text" =>
            "History message #{n}.\n\nA complete earlier reply, kept in chronological order."
        })
      end

    deltas =
      for n <- 1..2_100 do
        Event.from_runtime(
          id,
          125 + n,
          :output_text_delta,
          %{"text" => "Review section #{n}.\n\n"},
          turn_id: "long-review"
        )
      end

    events =
      messages ++
        deltas ++
        [
          Event.from_runtime(id, 2_226, :output_text_final, %{"text" => ""},
            turn_id: "long-review"
          )
        ]

    now = DateTime.utc_now() |> DateTime.to_iso8601()

    state = %State{
      id: id,
      node: node(),
      provider: :native,
      title: "History pagination proof",
      title_source: :human,
      workspace: File.cwd!(),
      workspace_mode: :shared_read,
      status: :closed,
      options: %{runtime_exposure: false},
      created_at: now,
      updated_at: now,
      events: events,
      cursor: 2_226
    }

    :ok = Store.put(state)
  end
end

defmodule Ouroboros.Test.BrowserHistoryReplay do
  @moduledoc "A scripted live ledger that fills a gap on request, without model calls."
  use GenServer

  alias Ouroboros.Interactive.{Event, State, Store}

  def start(id), do: GenServer.start(__MODULE__, id)

  @impl true
  def init(id) do
    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    session = %State{
      id: id,
      node: node(),
      provider: :native,
      workspace: File.cwd!(),
      workspace_mode: :shared_read,
      status: :idle,
      options: %{runtime_exposure: false},
      created_at: now,
      updated_at: now
    }

    :ok = Store.put(session)

    events =
      for n <- 1..100 do
        Event.from_runtime(id, n, :output_text_final, %{
          "text" => "Replay message #{n}.\n\nA retained reply with a stable reading position."
        })
      end

    {:ok, %{session: session, events: events, subscribers: [], repaired: false}}
  end

  @impl true
  def handle_call(:info, _from, state), do: {:reply, {:ok, state.session}, state}

  def handle_call({:subscribe, subscriber, cursor}, _from, state) do
    events =
      Enum.filter(state.events, fn event ->
        event.sequence > (cursor || 0) and (state.repaired or event.sequence not in 21..30)
      end)

    {:reply, {:ok, events}, %{state | subscribers: Enum.uniq([subscriber | state.subscribers])}}
  end

  def handle_call({:unsubscribe, subscriber}, _from, state),
    do: {:reply, :ok, %{state | subscribers: state.subscribers -- [subscriber]}}

  def handle_call({:send_turn, :message, turn_id, "repair history", _opts}, _from, state) do
    for event <- state.events, event.sequence in 21..30, subscriber <- state.subscribers do
      send(subscriber, {:ouroboros_interactive_event, state.session.id, event})
    end

    {:reply, {:ok, %{turn_id: turn_id}}, %{state | repaired: true}}
  end
end
