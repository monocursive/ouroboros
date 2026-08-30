defmodule Ouroboros.Provider.Native.ReplayTest do
  @moduledoc """
  R2 — the verify engine, against journals a real turn wrote.

  Every turn under test here was recorded by `Loop.run_turn/2` itself rather than by a
  hand-written fixture, because the claim verified replay makes is about *this* loop
  re-deriving *its own* record. A scripted journal would only prove the engine agrees with
  whoever wrote the script.

  What each block pins:

    * the verdict — a session whose record is intact verifies, across more than one turn,
      and the engine writes nothing anywhere while deciding so;
    * divergence — a flipped conversation digest, a flipped request digest and a deleted
      record are each refused **by name**, never continued past;
    * the chain — one flipped byte is `{:chain_broken, seq}` before any turn is re-run;
    * boundaries — a gap, a truncation, an unsettled turn, an ambiguous inference, a
      resumed conversation and a compaction each bound verification at their own sequence
      and leave the prefix verified.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Replay
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-replay-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "workspace/lib"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(root, "workspace/lib/a.ex"), "defmodule A do\nend\n")
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(Path.join(root, "workspace"), [], :workspace_write)

    %{
      root: root,
      scope: scope,
      session_dir: Path.join(root, "session"),
      session_id: "replay-sess-#{System.unique_integer([:positive, :monotonic])}"
    }
  end

  describe "the verdict" do
    test "a session whose record is intact verifies, turn by turn", context do
      live(context, "turn-1", [[{:text, "first"}, {:finish, :stop}]])
      live(context, "turn-2", [[{:text, "second"}, {:finish, :stop}]], prompt: "and again")

      assert {:ok, verdict} = verify(context)
      assert verdict.verified
      assert verdict.turns == 2
      assert verdict.divergence == nil
      assert verdict.records == records(context) |> length()
      assert byte_size(verdict.head) == 64
    end

    test "replay writes nothing: no journal record, no checkpoint, no ledger entry", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])

      before = File.ls!(context.session_dir) |> Enum.sort()
      journal_before = File.read!(Journal.path(context.session_dir))

      # The live turn accounted for its one model call, and that entry is the record replay
      # is verifying: a second one written by the replay would corrupt it, and dedup rules
      # are the wrong place to close that — `tool_source` closes it at the source.
      assert [_live] = inferences(context)

      assert {:ok, %{verified: true}} = verify(context)

      assert File.ls!(context.session_dir) |> Enum.sort() == before
      assert File.read!(Journal.path(context.session_dir)) == journal_before
      assert [_still_one] = inferences(context)
      assert {:ok, []} = EffectLedger.list(principal: principal(context), effect: :tool_call)
    end

    test "the events come back carrying the recorded instants, not this one's", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])

      assert {:ok, verdict} = verify(context)
      recorded = records(context) |> Map.new(&{&1["kind"], &1["at"]})

      started = Enum.find(verdict.events, &(&1.type == :turn_started))
      completed = Enum.find(verdict.events, &(&1.type == :turn_completed))

      assert started.at == recorded["turn_started"]
      assert completed.at == recorded["turn_settled"]

      # And every event carries one, which is the whole of D9: no event is left to read a
      # clock the replay would have moved.
      assert Enum.all?(verdict.events, &is_binary(&1.at))
    end

    test "a session with no journal is refused by name", context do
      assert Replay.verify(context.session_dir, engine_opts(context)) == {:error, :no_journal}
    end
  end

  describe "divergence is a named refusal" do
    test "a flipped conversation digest names the field and the record", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])

      flipped = String.duplicate("a", 64)

      settled =
        rewrite(context, fn record ->
          tamper(record, "turn_settled", "conversation_digest", flipped)
        end)

      assert {:ok, verdict} = verify(context)
      refute verdict.verified
      assert {:replay_diverged, divergence} = verdict.divergence
      assert divergence.field == "conversation_digest"
      assert divergence.turn_id == "turn-1"
      assert divergence.seq == settled["seq"]
      assert divergence.expected_sha256 == flipped
      assert byte_size(divergence.got_sha256) == 64
      assert divergence.got_sha256 != flipped
    end

    test "a flipped request digest is caught where the request is, not at settle", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])

      flipped = String.duplicate("b", 64)

      call =
        rewrite(context, fn record -> tamper(record, "model_call", "request_sha256", flipped) end)

      assert {:ok, verdict} = verify(context)
      assert {:replay_diverged, divergence} = verdict.divergence
      assert divergence.field == "request_sha256"
      assert divergence.seq == call["seq"]
      assert divergence.expected_sha256 == flipped
    end

    test "a deleted record diverges rather than replaying a shorter conversation", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])

      # The model's answer, removed and the survivors rechained: the file still verifies as
      # a chain, and the conversation it describes is no longer the one that happened.
      drop(context, fn record -> record["kind"] == "model_result" end)

      assert {:ok, verdict} = verify(context)
      refute verdict.verified
      assert {:replay_boundary, :ambiguous_inference, _seq} = verdict.divergence
    end

    test "a prompt removed leaves a turn the engine refuses to invent", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])
      drop(context, fn record -> record["kind"] == "prompt" end)

      assert {:ok, %{divergence: {:replay_boundary, :no_prompt, _seq}}} = verify(context)
    end
  end

  describe "the chain bounds everything above it" do
    test "one flipped byte is a chain break, named by sequence", context do
      live(context, "turn-1", [[{:text, "hi"}, {:finish, :stop}]])

      path = Journal.path(context.session_dir)
      [first | rest] = path |> File.read!() |> String.split("\n", trim: true)
      broken = JSON.decode!(first) |> Map.put("at", "1999-01-01T00:00:00.000000Z")
      File.write!(path, Enum.join([JSON.encode!(broken) | rest], "\n") <> "\n")

      assert {:error, {:chain_broken, 1}} =
               Replay.verify(context.session_dir, engine_opts(context))
    end
  end

  describe "honest boundaries" do
    test "a gap bounds verification at the gap, and the prefix still verifies", context do
      live(context, "turn-1", [[{:text, "one"}, {:finish, :stop}]])
      gap = append(context, "gap", %{"reason" => "eacces", "dropped_kinds" => ["tool_result"]})
      live(context, "turn-2", [[{:text, "two"}, {:finish, :stop}]], prompt: "again")

      assert {:ok, verdict} = verify(context)
      refute verdict.verified
      assert verdict.turns == 1
      assert verdict.divergence == {:replay_boundary, :gap, gap["seq"]}
    end

    test "a truncation bounds verification at its own record", context do
      live(context, "turn-1", [[{:text, "one"}, {:finish, :stop}]])

      truncated =
        append(context, "truncated", %{"dropped_through_seq" => 0, "prior_head" => Journal.seed()})

      assert {:ok, %{divergence: {:replay_boundary, :truncated, seq}}} = verify(context)
      assert seq == truncated["seq"]
    end

    test "a turn that never settled is the crash case, named", context do
      live(context, "turn-1", [[{:text, "one"}, {:finish, :stop}]])
      drop(context, fn record -> record["kind"] == "turn_settled" end)

      assert {:ok, %{divergence: {:replay_boundary, :unsettled_turn, _seq}, turns: 0}} =
               verify(context)
    end

    test "a conversation that predates the journal is refused, not retrofitted", context do
      append(context, "session_opened", %{
        "provider_session_id" => "p",
        "resumed" => true,
        "journal_version" => Journal.version()
      })

      live(context, "turn-1", [[{:text, "one"}, {:finish, :stop}]])

      assert {:ok, %{divergence: {:replay_boundary, :resumed_conversation, 1}, turns: 0}} =
               verify(context)
    end

    test "a compaction bounds verification: the fold is not re-decided", context do
      live(context, "turn-1", [[{:text, "one"}, {:finish, :stop}]])

      compaction =
        append(context, "compaction", %{
          "trigger" => "auto",
          "summariser_turn_id" => "compact_1",
          "elided_count" => 2,
          "archive_id" => "a1",
          "pre_digest" => String.duplicate("1", 64),
          "post_digest" => String.duplicate("2", 64)
        })

      assert {:ok, verdict} = verify(context)
      assert verdict.turns == 1
      assert verdict.divergence == {:replay_boundary, :compaction, compaction["seq"]}
    end

    test "an injection this engine cannot reproduce is named rather than dropped", context do
      live(context, "turn-1", [[{:text, "one"}, {:finish, :stop}]],
        after_run: fn journal ->
          Journal.append(journal, "injected", %{
            "turn_id" => "turn-1",
            "origin" => "stop_hook",
            "content" => "a hook said so"
          })
        end
      )

      assert {:ok,
              %{divergence: {:replay_boundary, {:unreproducible_injection, "stop_hook"}, _seq}}} =
               verify(context)
    end
  end

  describe "the wire shape of a refusal" do
    test "both kinds carry a sequence, and are told apart by kind" do
      diverged =
        Replay.describe(
          {:replay_diverged,
           %{
             seq: 8,
             turn_id: "turn-1",
             field: "conversation_digest",
             expected_sha256: String.duplicate("a", 64),
             got_sha256: String.duplicate("b", 64)
           }}
        )

      assert diverged["kind"] == "diverged"
      assert diverged["seq"] == 8
      assert diverged["field"] == "conversation_digest"

      assert Replay.describe({:replay_boundary, :gap, 4}) == %{
               "kind" => "boundary",
               "reason" => "gap",
               "detail" => nil,
               "seq" => 4
             }

      # A boundary whose reason carries a subject keeps the subject, because "an injection
      # this engine cannot reproduce" is only actionable once you know which one.
      assert Replay.describe({:replay_boundary, {:unreproducible_injection, "stop_hook"}, 9}) ==
               %{
                 "kind" => "boundary",
                 "reason" => "unreproducible_injection",
                 "detail" => "stop_hook",
                 "seq" => 9
               }

      assert Replay.describe(nil) == nil
    end
  end

  # ------------------------------------------------------------------ helpers

  # One real turn through the real loop, recorded into this session's journal.
  defp live(context, turn_id, script, opts \\ []) do
    {model_spec, _agent} = NativeModelScript.start(script)
    {:ok, prefix} = prefix(context, model_spec)
    test = self()

    loop = %Loop{
      emit: fn event -> send(test, {:event, event}) end,
      model_module: NativeModelScript,
      model_spec: model_spec,
      system: prefix.system,
      context_window: prefix.context_window,
      prefix_fingerprint: prefix.fingerprint,
      scope: context.scope,
      session_dir: context.session_dir,
      session_id: context.session_id,
      provider_session_id: "native-replay-test",
      turn_id: turn_id,
      approval_mode: :auto_approve,
      approval_timeout_ms: 2_000,
      messages: Keyword.get(opts, :messages, previous_messages(context)),
      journal: Journal.open(context.session_dir),
      checkpoint: fn snapshot -> {:ok, Checkpoint.digest_of(snapshot.messages)} end
    }

    parent = self()

    spawn_link(fn ->
      send(parent, {:finished, Loop.run_turn(loop, Keyword.get(opts, :prompt, "do the thing"))})
    end)

    {events, %Loop{} = final} = collect()
    Process.put({__MODULE__, :messages}, final.messages)

    case Keyword.get(opts, :after_run) do
      nil -> :ok
      fun -> fun.(Journal.open(context.session_dir))
    end

    events
  end

  defp previous_messages(_context), do: Process.get({__MODULE__, :messages}, [])

  defp prefix(context, model_spec) do
    window = Window.resolve(model_spec)

    Context.build(
      system_prompt: nil,
      cwd: context.scope.root,
      add_dirs: [],
      sandbox_mode: context.scope.sandbox_mode,
      approval_mode: :auto_approve,
      tools:
        Tools.specs(nil, nil,
          workspace: context.scope.root,
          context_window: window,
          subagent_depth: 0
        ),
      model_module: NativeModelScript,
      model_spec: model_spec,
      context_window: window,
      reasoning_effort: nil,
      compactions: 0
    )
  end

  defp engine_opts(context) do
    [
      workspace: context.scope.root,
      add_dirs: [],
      session_id: context.session_id,
      provider_session_id: "native-replay-test",
      model_module: NativeModelScript
    ]
  end

  defp verify(context), do: Replay.verify(context.session_dir, engine_opts(context))

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        # The loop writes `turn_settled` after the terminal event's `persist`, so wait for
        # the process to finish rather than racing its last append.
        final =
          receive do
            {:finished, {:ok, state}} -> state
          after
            20_000 -> flunk("the loop did not return")
          end

        {Enum.reverse([event | acc]), final}

      {:event, event} ->
        collect([event | acc])
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp records(context) do
    {:ok, %{records: records}} = Journal.window(Journal.path(context.session_dir), limit: 500)
    records
  end

  defp principal(context), do: "session:" <> context.session_id

  defp inferences(context) do
    {:ok, entries} = EffectLedger.list(principal: principal(context), effect: :inference)
    entries
  end

  defp append(context, kind, fields) do
    journal = context.session_dir |> Journal.open() |> Journal.append(kind, fields)
    Enum.find(records(context), &(&1["seq"] == journal.seq))
  end

  # Rewrites the journal with one record changed and the survivors rechained, so the file
  # still verifies as a chain — which is the only way to test what the *engine* does about a
  # record that lies rather than what the chain does about one that was edited.
  defp tamper(record, kind, key, value) do
    if record["kind"] == kind, do: Map.put(record, key, value), else: record
  end

  defp rewrite(context, transform) do
    original = records(context)
    changed = Enum.map(original, transform)
    rechain(context, changed)

    original
    |> Enum.zip(changed)
    |> Enum.find_value(fn {before, altered} -> if before != altered, do: altered end)
  end

  defp drop(context, predicate) do
    kept = context |> records() |> Enum.reject(predicate)
    rechain(context, kept)
  end

  defp rechain(context, records) do
    {lines, _prev} =
      Enum.map_reduce(records, Journal.seed(), fn record, prev ->
        body = Map.drop(record, ["prev", "hash"])

        hash =
          :sha256
          |> :crypto.hash([prev, Journal.canonical_json(body)])
          |> Base.encode16(case: :lower)

        sealed = body |> Map.put("prev", prev) |> Map.put("hash", hash)
        {Journal.canonical_json(sealed), hash}
      end)

    File.write!(Journal.path(context.session_dir), Enum.join(lines, "\n") <> "\n")
  end
end
