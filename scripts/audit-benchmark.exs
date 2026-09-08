# Synthetic local measurement; no model, network, user state or provider credentials.
# mix run --no-start scripts/audit-benchmark.exs [event-count]
alias Ouroboros.Audit.{Config, Store, Index}
alias Ouroboros.Provider.Native.Journal
{:ok, _} = Application.ensure_all_started(:exqlite)
{:ok, temporary} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
count = case System.argv() do
  [n] -> String.to_integer(n)
  [] -> 1000
end
if count not in 1..100_000, do: raise("event count must be 1..100000")
root = Path.join(temporary, "ouro-audit-benchmark-#{System.unique_integer([:positive])}")
try do
  results = for capture <- [:metadata, :redacted, :full] do
    config = Config.new!(mode: :local, capture: capture, root: Path.join(root, to_string(capture)), index: true,
      encryption_key_id: if(capture == :full, do: "benchmark"), encryption_keys: %{"benchmark" => :binary.copy(<<1>>, 32)})
    {:ok, store} = Store.start_link(name: nil, config: config)
    stream = Journal.digest("synthetic-session")
    times = for n <- 1..count do
      {us, {:ok, _}} = :timer.tc(fn -> Store.append(stream, "model_chunk", %{iteration: n, chunk: ["text", String.duplicate("synthetic output ", 128)]}, store) end)
      us
    end |> Enum.sort()
    {:ok, index} = Index.start_link(name: __MODULE__.BenchmarkIndex, config: config)
    {index_us, {:ok, _}} = :timer.tc(fn -> Index.reindex(index) end)
    {search_us, {:ok, result}} = :timer.tc(fn -> Index.search(%{"kind" => "model_chunk", "limit" => 20}, index) end)
    {:ok, scan} = Store.read(Store.stream_path(config.root, stream))
    if scan.verified_through != count or result.total != count, do: raise("benchmark verification failed")
    bytes = Store.status(store).bytes
    GenServer.stop(index)
    GenServer.stop(store)
    %{capture: capture, events: count, append_p50_us: Enum.at(times, div(count, 2)), append_p95_us: Enum.at(times, min(count - 1, div(count * 95, 100))), append_total_ms: div(Enum.sum(times), 1000), index_rebuild_ms: div(index_us, 1000), search_us: search_us, total_disk_bytes_including_index: bytes}
  end
  IO.puts(JSON.encode!(%{elixir: System.version(), otp: to_string(:erlang.system_info(:otp_release)), os: inspect(:os.type()), results: results}))
after
  File.rm_rf!(root)
end
