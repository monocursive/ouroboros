defmodule Ouroboros.CodeIntel.DocumentsTest do
  use ExUnit.Case, async: false

  alias Ouroboros.CodeIntel.LspPool

  @moduletag :capture_log

  @script Path.expand("../support/fake_language_server.exs", __DIR__)

  setup context do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-lsp-docs-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    pool_name = :"code_intel_docs_#{System.unique_integer([:positive])}"

    opts =
      Keyword.merge(
        [
          name: :"code_intel_docs_sup_#{System.unique_integer([:positive])}",
          pool_name: pool_name,
          idle_ms: 60_000,
          sweep_ms: 60_000,
          memory_poll_ms: 60_000,
          max_restarts: 3,
          restart_backoff_ms: 20,
          initialize_timeout_ms: 20_000,
          shutdown_grace_ms: 500,
          diagnostics_debounce_ms: 30
        ],
        Map.get(context, :pool_opts, [])
      )

    start_supervised!({Ouroboros.CodeIntel.Supervisor, opts})
    {:ok, root: root, pool: pool_name}
  end

  defp spec(context, extra_args \\ []) do
    %{
      root: context.root,
      server_id: "fake",
      executable: System.find_executable("elixir"),
      args: [@script] ++ extra_args,
      path: Path.join(context.root, "thing.ex"),
      language_id: "elixir"
    }
  end

  defp write(context, contents) do
    path = Path.join(context.root, "thing.ex")
    File.write!(path, contents)
    path
  end

  defp await(fun, timeout \\ 20_000) do
    do_await(fun, System.monotonic_time(:millisecond) + timeout)
  end

  defp do_await(fun, deadline) do
    case fun.() do
      {:ok, value} ->
        value

      other ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("condition never held; last saw #{inspect(other)}")
        else
          Process.sleep(20)
          do_await(fun, deadline)
        end
    end
  end

  defp await_ready(context, spec) do
    assert {:ok, _pid} = LspPool.checkout(context.pool, spec, wait_ready_ms: 20_000)
  end

  ## Document synchronisation

  test "versions increase monotonically across open and change", context do
    write(context, "first")
    spec = spec(context)

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    write(context, "second")
    assert {:ok, 2} = LspPool.touch(context.pool, spec, :changed)
    write(context, "third")
    assert {:ok, 3} = LspPool.touch(context.pool, spec, :changed)

    assert [%{documents: [%{path: path, version: 3, language_id: "elixir"}]}] =
             LspPool.status(context.pool).servers

    assert path == Path.join(context.root, "thing.ex")
  end

  test "the server receives the file's content from disk, never from the caller", context do
    record = Path.join(context.root, "frames.jsonl")
    write(context, "on disk, version one")
    spec = spec(context, ["--record", record])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)

    did_open =
      await(fn ->
        case recorded(record) |> Enum.find(&(&1["method"] == "textDocument/didOpen")) do
          nil -> :pending
          frame -> {:ok, frame}
        end
      end)

    document = did_open["params"]["textDocument"]
    assert document["text"] == "on disk, version one"
    assert document["version"] == 1
    assert document["languageId"] == "elixir"
    assert document["uri"] == "file://" <> Path.join(context.root, "thing.ex")

    write(context, "on disk, version two")
    assert {:ok, 2} = LspPool.touch(context.pool, spec, :changed)

    did_change =
      await(fn ->
        case recorded(record) |> Enum.find(&(&1["method"] == "textDocument/didChange")) do
          nil -> :pending
          frame -> {:ok, frame}
        end
      end)

    assert did_change["params"]["textDocument"]["version"] == 2
    assert [%{"text" => "on disk, version two"}] = did_change["params"]["contentChanges"]
  end

  test "closing a document drops it and its cached diagnostics", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, %{version: 1}} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :closed)
    assert [%{documents: []}] = LspPool.status(context.pool).servers
    assert {:error, :document_not_open} = LspPool.diagnostics(context.pool, spec, wait_ms: 50)
  end

  test "a file that does not exist is not synchronised", context do
    spec = spec(context)

    assert {:error, {:document_unreadable, _path, :enoent}} =
             LspPool.touch(context.pool, spec, :open)

    assert [%{documents: []}] = LspPool.status(context.pool).servers
  end

  @tag pool_opts: [max_document_bytes: 16]
  test "a file past the size cap is refused rather than read", context do
    write(context, String.duplicate("x", 4_096))
    spec = spec(context)
    assert {:error, {:document_too_large, 4_096, 16}} = LspPool.touch(context.pool, spec, :open)
  end

  @tag pool_opts: [max_documents: 1]
  test "the open-document cap is a refusal, not a queue", context do
    write(context, "code")
    other = Path.join(context.root, "other.ex")
    File.write!(other, "more code")

    assert {:ok, 1} = LspPool.touch(context.pool, spec(context), :open)

    assert {:error, :too_many_documents} =
             LspPool.touch(context.pool, %{spec(context) | path: other}, :open)
  end

  ## Diagnostics freshness

  test "diagnostics are served once their version matches the document", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)

    assert {:ok, snapshot} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)
    assert snapshot.version == 1
    assert snapshot.source == :reported
    assert [%{severity: :error, code: "E001", message: "undefined variable"}] = snapshot.items
    assert snapshot.counts.error == 1
    assert snapshot.truncated == 0
  end

  test "a stale-version push is never served, and never overwrites a newer one", context do
    write(context, "code")
    # This server always publishes version 1, whatever the document's real version is.
    spec = spec(context, ["--publish-on-change", "--publish-version", "1"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, %{version: 1}} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)

    write(context, "different code")
    assert {:ok, 2} = LspPool.touch(context.pool, spec, :changed)

    # The push for version 2 says "1". It describes text that no longer exists, so the
    # gate holds and the caller is told to expect nothing rather than shown the old file's
    # errors.
    assert {:pending, 2} = LspPool.diagnostics(context.pool, spec, wait_ms: 400)

    # And the cache was not rolled back to the stale push either.
    assert {:ok, %{version: 1, fresh?: false, document_version: 2}} =
             LspPool.baseline(context.pool, spec)
  end

  test "a server that reports no version has its push attributed, and says so", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change", "--publish-unversioned"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, snapshot} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)

    # `:inferred` is the honest label: the version was assigned on arrival, not reported,
    # so the freshness guarantee is weaker and a caller can see that it is.
    assert snapshot.source == :inferred
    assert snapshot.version == 1
  end

  test "a document with no push waits the budget and then answers pending", context do
    write(context, "code")
    spec = spec(context)

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    await_ready(context, spec)

    started = System.monotonic_time(:millisecond)
    assert {:pending, 1} = LspPool.diagnostics(context.pool, spec, wait_ms: 300)
    elapsed = System.monotonic_time(:millisecond) - started

    assert elapsed >= 250
    assert elapsed < 5_000
  end

  test "a waiter is answered as soon as the matching push lands", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change"])
    await_ready(context, spec)

    task =
      Task.async(fn ->
        Process.sleep(50)
        LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)
      end)

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, %{version: 1}} = Task.await(task, 15_000)
  end

  test "duplicate diagnostics collapse on code, severity, message, and range", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change", "--publish-duplicates"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, snapshot} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)

    # The fake server publishes the same error twice plus one distinct warning.
    assert length(snapshot.items) == 2
    assert snapshot.counts == %{error: 1, warning: 1, information: 0, hint: 0, unknown: 0}
  end

  @tag pool_opts: [max_diagnostics_per_document: 1]
  test "diagnostics past the cap are counted rather than kept", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change", "--publish-duplicates"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, snapshot} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)

    assert length(snapshot.items) == 1
    assert snapshot.truncated == 1
  end

  ## Baseline

  test "a baseline with nothing cached is honest about having nothing", context do
    write(context, "code")
    spec = spec(context)

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)

    assert {:ok, %{version: nil, document_version: 1, fresh?: false, items: []}} =
             LspPool.baseline(context.pool, spec)
  end

  test "a baseline is the snapshot a caller can diff new diagnostics against", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, _fresh} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)

    assert {:ok, baseline} = LspPool.baseline(context.pool, spec)
    assert baseline.fresh?
    assert baseline.version == 1
    assert baseline.path == Path.join(context.root, "thing.ex")
    assert baseline.root == context.root
    assert [%{code: "E001"}] = baseline.items
  end

  ## Subscribers

  test "subscribers are told which file changed, with counts and not items", context do
    write(context, "code")
    spec = spec(context, ["--publish-on-change"])

    assert :ok = LspPool.subscribe(context.pool, self())
    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)

    path = Path.join(context.root, "thing.ex")
    root = context.root

    assert_receive {:code_intel, :diagnostics_changed,
                    %{
                      node: _node,
                      root: ^root,
                      server_id: "fake",
                      path: ^path,
                      version: 1,
                      source: :reported,
                      counts: %{error: 1}
                    }},
                   20_000

    assert :ok = LspPool.unsubscribe(context.pool, self())
    write(context, "more code")
    assert {:ok, 2} = LspPool.touch(context.pool, spec, :changed)
    refute_receive {:code_intel, :diagnostics_changed, _payload}, 500
  end

  test "a dead subscriber is dropped without anyone unsubscribing", context do
    subscriber = spawn(fn -> Process.sleep(60_000) end)
    assert :ok = LspPool.subscribe(context.pool, subscriber)
    Process.exit(subscriber, :kill)

    write(context, "code")
    spec = spec(context, ["--publish-on-change"])
    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)

    # Nothing to assert but liveness: the pool must still answer after fanning out to a
    # subscriber that no longer exists.
    assert {:ok, %{version: 1}} = LspPool.diagnostics(context.pool, spec, wait_ms: 10_000)
  end

  ## Restart

  test "documents are re-opened from disk when a replacement server comes up", context do
    record = Path.join(context.root, "frames.jsonl")
    write(context, "code")
    spec = spec(context, ["--record", record, "--crash-on", "textDocument/hover"])

    assert {:ok, 1} = LspPool.touch(context.pool, spec, :open)
    assert {:ok, pid} = LspPool.checkout(context.pool, spec, wait_ready_ms: 20_000)

    Ouroboros.CodeIntel.Lsp.Server.notify(pid, "textDocument/hover", %{})

    # The replacement re-opens the document at a fresh version rather than assuming the
    # new process knows about a file the old one was told about.
    assert %{documents: [%{version: 2}]} =
             await(fn ->
               case LspPool.status(context.pool).servers do
                 [%{state: state, documents: [%{version: 2}]} = server]
                 when state in [:starting, :ready] ->
                   {:ok, server}

                 other ->
                   other
               end
             end)

    # The record file is written by the replacement's own OS process as frames reach it,
    # so it lags the pool's status — the status above can flip while the replacement is
    # still `:starting` with the didOpen queued, and under CPU load an `elixir` script
    # takes seconds to boot. Await the evidence, then hold the exact count: one re-open,
    # never a re-opening loop.
    opens =
      await(fn ->
        case Enum.count(recorded(record), &(&1["method"] == "textDocument/didOpen")) do
          count when count >= 2 -> {:ok, count}
          count -> {:recorded_opens, count}
        end
      end)

    assert opens == 2
  end

  defp recorded(record) do
    case File.read(record) do
      {:ok, contents} ->
        contents
        |> String.split("\n", trim: true)
        |> Enum.flat_map(fn line ->
          case JSON.decode(line) do
            {:ok, frame} -> [frame]
            _other -> []
          end
        end)

      _other ->
        []
    end
  end
end
