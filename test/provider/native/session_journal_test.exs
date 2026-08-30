defmodule Ouroboros.Provider.Native.SessionJournalTest do
  @moduledoc """
  R1 — what the *session* writes down, between the turns the loop writes.

  The session process is the journal's other writer: it opens the record, notes every
  applied `configure`, records a compaction with the digests either side of the fold, and
  records a rewind. The two writers share one file and never overlap, so what these tests
  pin is that the chain survives handing off between them — and that the compaction
  summariser, which is a real model call on the operator's key, is gated and recorded like
  any other.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root =
      Path.join(System.tmp_dir!(), "native-sess-journal-#{System.unique_integer([:positive])}")

    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)

    on_exit(fn ->
      if previous_dir,
        do: Application.put_env(:ouroboros, :native_data_dir, previous_dir),
        else: Application.delete_env(:ouroboros, :native_data_dir)

      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace}
  end

  test "the session opens the record, and the loop continues the same chain", context do
    {handle, _agent} = open(context, [[{:text, "hi"}, {:finish, :stop}]])

    assert [opened] = records(handle)
    assert opened["kind"] == "session_opened"
    assert opened["seq"] == 1
    assert opened["prev"] == Journal.seed()
    assert opened["turn_id"] == nil
    assert opened["resumed"] == false
    assert opened["forked_from_provider_session_id"] == nil
    assert opened["journal_version"] == Journal.version()

    assert :ok = Session.send(handle, TurnRequest.new!("hello"), "turn-1")
    await_terminal()

    kinds = handle |> records() |> Enum.map(& &1["kind"])
    assert kinds == ~w(session_opened turn_started prompt model_call model_result turn_settled)

    # One chain across two writing processes, which is the property the sync exists for.
    assert {:ok, %{verified_through: 6}} = Journal.verify(path(handle))
  end

  test "every applied configure is recorded, and a refused one is not", context do
    {handle, _agent} = open(context, [[{:text, "hi"}, {:finish, :stop}]])

    assert :ok = Session.configure(handle, %{model: "script:other", reasoning_effort: :high})
    assert {:error, _reason} = Session.configure(handle, %{nonsense: true})

    configures = records_of(handle, "configure")

    assert Enum.map(configures, & &1["key"]) == ["model", "reasoning_effort"]
    assert Enum.map(configures, & &1["value"]) == ["script:other", "high"]
    refute Enum.any?(configures, &(&1["key"] == "nonsense"))
    assert Enum.all?(configures, &(&1["turn_id"] == nil))
  end

  test "a compaction records the fold, and its summariser is a gated model call", context do
    {handle, _agent} =
      open(
        context,
        [
          [
            {:text, "reading"},
            {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
          ],
          [{:text, "done"}, {:usage, %{input_tokens: 11, output_tokens: 4}}, {:finish, :stop}],
          [{:text, "## Goal\n\nship it"}, {:finish, :stop}]
        ],
        # Keep almost nothing verbatim, so the fold is a real one and the digests either
        # side of it actually differ. A compaction with nothing to fold is a no-op, and a
        # test that asserted against one would be asserting nothing.
        %{"keep_recent_tokens" => 1}
      )

    assert :ok = Session.send(handle, TurnRequest.new!("look at lib/a.ex"), "turn-1")
    await_terminal()

    assert {:ok, _report} = Session.compact(handle)

    assert [compaction] = records_of(handle, "compaction")
    assert compaction["trigger"] == "manual"
    assert compaction["turn_id"] == "compact_2"
    assert is_integer(compaction["elided_count"])
    assert byte_size(compaction["pre_digest"]) == 64
    assert byte_size(compaction["post_digest"]) == 64
    assert compaction["pre_digest"] != compaction["post_digest"]

    # Asserted rather than branched on: `keep_recent_tokens: 1` above is what makes the
    # fold summarise, and a conditional here would let the whole gate go unverified the day
    # that stopped being true.
    assert compaction["summarised"] == true
    assert compaction["summariser_turn_id"] == "compact_2"

    # The summariser's own call is a top-level pair under its own turn id — not inlined
    # here — so a replay engine feeds it back through the same path as any other model
    # call rather than reaching inside a compaction record for it.
    summariser_calls =
      handle |> records_of("model_call") |> Enum.filter(&(&1["turn_id"] == "compact_2"))

    assert [call] = summariser_calls
    assert call["tools_sha256"] == Journal.digest([])
    assert String.starts_with?(call["ledger_effect_id"], "inference-")

    assert [_result] =
             handle |> records_of("model_result") |> Enum.filter(&(&1["turn_id"] == "compact_2"))

    # And it is accounted for: a summary is spent on the operator's key like any turn.
    assert {:ok, entry} = EffectLedger.get(call["ledger_effect_id"])
    assert entry.effect == :inference
    assert entry.attempt.turn_id == "compact_2"
    assert entry.cause.signal_type == "native.compaction.inference"
    assert entry.status == :ok

    assert {:ok, %{verified_through: through}} = Journal.verify(path(handle))
    assert through == length(records(handle))
  end

  test "a rewind is recorded with what the conversation was cut to", context do
    {handle, _agent} =
      open(context, [
        [
          {:text, "writing"},
          {:tool_call,
           %{
             id: "c1",
             name: "write",
             input: %{"path" => "lib/b.ex", "content" => "defmodule B do\nend\n"}
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ])

    assert :ok = Session.send(handle, TurnRequest.new!("write lib/b.ex"), "turn-1")
    await_terminal()

    assert {:ok, _outcome} = Session.rewind(handle, 0, :conversation)

    assert [rewind] = records_of(handle, "rewind")
    assert rewind["to_turn"] == 0
    assert rewind["message_count"] == 0
    assert byte_size(rewind["conversation_digest"]) == 64

    assert {:ok, %{verified_through: through}} = Journal.verify(path(handle))
    assert through == length(records(handle))
  end

  # ------------------------------------------------------------------ helpers

  defp open(context, script, provider_options \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      if previous_model,
        do: Application.put_env(:ouroboros, :native_model_module, previous_model),
        else: Application.delete_env(:ouroboros, :native_model_module)
    end)

    request =
      SessionRequest.new!(%{
        provider: :native,
        cwd: context.workspace,
        model: model_spec,
        approval_mode: :auto_approve,
        approval_timeout_ms: :infinity,
        provider_options: provider_options
      })

    session_context = %{
      session_id: "sess-#{System.unique_integer([:positive])}",
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    assert {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)

    {handle, agent}
  end

  defp await_terminal do
    receive do
      {:session_adapter_event, %{type: type}}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        :ok

      {:session_adapter_event, _other} ->
        await_terminal()
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp path(handle) do
    {:ok, info} = Session.info(handle)
    {:ok, dir, _durable?} = Ouroboros.Provider.Native.Paths.session_dir(info.provider_session_id)
    Journal.path(dir)
  end

  defp records(handle) do
    {:ok, %{records: records}} = Journal.window(path(handle), limit: 500)
    records
  end

  defp records_of(handle, kind), do: handle |> records() |> Enum.filter(&(&1["kind"] == kind))
end
