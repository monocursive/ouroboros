defmodule Ouroboros.Audit.Index do
  @moduledoc "Optional, rebuildable SQLite metadata index; never an execution authority."
  use GenServer
  alias Exqlite.Sqlite3, as: SQL
  alias Ouroboros.Audit.{Config, Query, Store, Record}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal

  @filters ~w(stream_id session_id provider_session_id turn_id call_id ledger_effect_id actor_id model tool kind status)

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def status(server \\ __MODULE__), do: GenServer.call(server, :status)
  def reindex(server \\ __MODULE__), do: GenServer.call(server, :reindex, 60_000)
  def search(params, server \\ __MODULE__), do: GenServer.call(server, {:search, params}, 30_000)
  @impl true
  def init(opts) do
    config = Keyword.get(opts, :config, Config.current())
    if Config.enabled?(config) and config.index, do: send(self(), :refresh)
    {:ok, %{config: config, db: nil, updated_at: nil, error: nil, count: 0}}
  end

  @impl true
  def handle_info(:refresh, state) do
    next = refresh(state)
    Process.send_after(self(), :refresh, 5_000)
    {:noreply, next}
  end

  @impl true
  def handle_call(:status, _, state),
    do:
      {:reply,
       Map.take(state, [:updated_at, :error, :count]) |> Map.put(:enabled, state.config.index),
       state}

  def handle_call(:reindex, _, state) do
    if state.db, do: SQL.close(state.db)
    path = Path.join(state.config.root || "", "index.sqlite3")

    if state.config.index do
      # Disposable files only, never follow a symlink and never touch the journal.
      for suffix <- ["", "-wal", "-shm"], do: File.rm(path <> suffix)
    end

    next = refresh(%{state | db: nil, updated_at: nil})

    {:reply,
     if(next.error,
       do: {:error, next.error},
       else: {:ok, %{count: next.count, updated_at: next.updated_at}}
     ), next}
  end

  def handle_call({:search, params}, _, state) do
    params = Query.normalize_times(params)
    {conditions, values} = filters(params)
    where = if conditions == [], do: "", else: " WHERE " <> Enum.join(conditions, " AND ")
    limit = params["limit"] || 100
    offset = params["offset"] || 0

    result =
      with :ok <- Query.validate(params),
           true <- state.db != nil and state.error == nil,
           {:ok, [[total]]} <- query(state.db, "SELECT COUNT(*) FROM events" <> where, values),
           {:ok, rows} <-
             query(
               state.db,
               "SELECT projection FROM events" <>
                 where <> " ORDER BY at DESC, stream_id DESC, seq DESC LIMIT ? OFFSET ?",
               values ++ [limit, offset]
             ) do
        events = Enum.map(rows, fn [json] -> JSON.decode!(json) end)

        {:ok,
         %{
           events: events,
           total: total,
           next_offset: if(offset + length(events) < total, do: offset + length(events)),
           source: "sqlite",
           indexed_through: state.updated_at
         }}
      else
        _ -> {:error, :audit_index_unavailable}
      end

    {:reply, result, state}
  end

  @impl true
  def terminate(_, %{db: nil}), do: :ok
  def terminate(_, %{db: db}), do: SQL.close(db)

  defp filters(params) do
    Enum.reduce(@filters ++ ["since", "until"], {[], []}, fn key, {sql, values} ->
      case params[key] do
        nil ->
          {sql, values}

        value ->
          expression =
            case key do
              "since" -> "at >= ?"
              "until" -> "at <= ?"
              key when key in ["stream_id", "kind"] -> key <> " = ?"
              key -> "json_extract(projection, '$." <> key <> "') = ?"
            end

          {sql ++ [expression], values ++ [value]}
      end
    end)
  end

  defp refresh(%{config: %{index: false}} = state), do: %{state | error: :audit_index_disabled}

  defp refresh(state) do
    with {:ok, db} <- connect(state) do
      result =
        with :ok <- SQL.execute(db, "BEGIN IMMEDIATE"),
             :ok <- ingest(db, state.config.root),
             :ok <- SQL.execute(db, "COMMIT"),
             {:ok, [[count]]} <- query(db, "SELECT COUNT(*) FROM events", []) do
          {:ok, count}
        end

      case result do
        {:ok, count} ->
          %{
            state
            | db: db,
              count: count,
              error: nil,
              updated_at: DateTime.to_iso8601(DateTime.utc_now())
          }

        _ ->
          SQL.execute(db, "ROLLBACK")
          %{state | db: db, error: :audit_index_unavailable}
      end
    else
      _ -> %{state | error: :audit_index_unavailable}
    end
  rescue
    _ -> %{state | error: :audit_index_unavailable}
  end

  defp connect(%{db: db}) when db != nil, do: {:ok, db}

  defp connect(state) do
    path = Path.join(state.config.root, "index.sqlite3")

    with :ok <- Durable.no_symlinks(state.config.root),
         true <-
           Enum.all?(["", "-wal", "-shm"], fn suffix ->
             case File.lstat(path <> suffix) do
               {:error, :enoent} -> true
               {:ok, %{type: :regular}} -> true
               _ -> false
             end
           end),
         {:ok, db} <- SQL.open(path) do
      result =
        with :ok <- File.chmod(path, 0o600),
             :ok <-
               SQL.execute(
                 db,
                 "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000; CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL, projection TEXT NOT NULL); CREATE INDEX IF NOT EXISTS events_stream ON events(stream_id, seq); CREATE INDEX IF NOT EXISTS events_time ON events(at, stream_id, seq); CREATE INDEX IF NOT EXISTS events_kind ON events(kind, at); CREATE TABLE IF NOT EXISTS progress (stream_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL, context TEXT NOT NULL);"
               ) do
          for suffix <- ["-wal", "-shm"], do: File.chmod(path <> suffix, 0o600)
          :ok
        end

      if result == :ok,
        do: {:ok, db},
        else:
          (
            SQL.close(db)
            result
          )
    end
  end

  defp ingest(db, root) do
    streams = Store.streams(root)
    {:ok, known} = query(db, "SELECT stream_id FROM progress", [])

    for [id] <- known, id not in streams do
      :ok = execute(db, "DELETE FROM events WHERE stream_id = ?", [id])
      :ok = execute(db, "DELETE FROM progress WHERE stream_id = ?", [id])
    end

    Enum.reduce_while(streams, :ok, fn stream, :ok ->
      case ingest_stream(db, root, stream) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp ingest_stream(db, root, stream) do
    {:ok, progress} =
      query(db, "SELECT seq, hash, context FROM progress WHERE stream_id = ?", [stream])

    {seq, hash, context} =
      case progress do
        [[seq, hash, context]] -> {seq, hash, JSON.decode!(context)}
        [] -> {0, Journal.seed(), %{}}
      end

    paths = Store.segments(Store.stream_path(root, stream))
    # Closed segments before the watermark were already verified. Read only the current
    # segment and any newer segments, bounded by the configured segment size.
    paths =
      case Enum.find_index(paths, &(segment_seq(&1) > seq)) do
        nil -> Enum.take(paths, -1)
        0 -> paths
        index -> Enum.drop(paths, index - 1)
      end

    result =
      Enum.reduce_while(paths, {:ok, {seq, hash, context}}, fn path, {:ok, cursor} ->
        with {:ok, bytes} <- Durable.read(path), true <- String.ends_with?(bytes, "\n") do
          result =
            bytes
            |> String.split("\n", trim: true)
            |> Enum.reduce_while({:ok, cursor}, fn line, {:ok, {through, head, context}} ->
              record = JSON.decode!(line)

              cond do
                record["seq"] <= seq ->
                  {:cont, {:ok, {through, head, context}}}

                Record.valid?(record, through + 1, head) and record["stream_id"] == stream ->
                  [event] = Query.project([Map.merge(context, record)])

                  next_context =
                    Map.take(
                      event,
                      ~w(session_id provider_session_id parent_session_id parent_task_id workspace actor_id)
                    )

                  case insert(db, event) do
                    :ok -> {:cont, {:ok, {record["seq"], record["hash"], next_context}}}
                    error -> {:halt, error}
                  end

                true ->
                  {:halt, {:error, :chain_broken}}
              end
            end)

          case result do
            {:ok, _} -> {:cont, result}
            error -> {:halt, error}
          end
        else
          _ -> {:halt, {:error, :partial_segment}}
        end
      end)

    with {:ok, {through, head, context}} <- result do
      execute(
        db,
        "INSERT INTO progress VALUES (?, ?, ?, ?) ON CONFLICT(stream_id) DO UPDATE SET seq=excluded.seq, hash=excluded.hash, context=excluded.context",
        [stream, through, head, JSON.encode!(context)]
      )
    end
  end

  defp segment_seq(path), do: path |> Path.basename(".ndjson") |> String.to_integer()

  defp insert(db, event),
    do:
      execute(db, "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?)", [
        event["event_id"],
        event["stream_id"],
        event["seq"],
        event["at"],
        event["kind"],
        JSON.encode!(event)
      ])

  defp execute(db, sql, values) do
    with {:ok, statement} <- SQL.prepare(db, sql) do
      try do
        with :ok <- SQL.bind(statement, values), :done <- SQL.step(db, statement), do: :ok
      after
        SQL.release(db, statement)
      end
    end
  end

  defp query(db, sql, values) do
    with {:ok, statement} <- SQL.prepare(db, sql) do
      try do
        with :ok <- SQL.bind(statement, values), do: SQL.fetch_all(db, statement)
      after
        SQL.release(db, statement)
      end
    end
  end
end
