defmodule Ouroboros.NativeCheckpointImportMatrixTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Interactive.State

  defmodule CaptureModel do
    @behaviour Ouroboros.Provider.Native.Model

    def available?, do: true
    def credential_report, do: []

    def stream(request, _opts) do
      send(
        Ouroboros.Provider.Native.config().test_pid,
        {:imported_model_context, request.messages}
      )

      {:ok, [{:finish, :stop}]}
    end
  end

  defmodule RefusingStoreStorage do
    def put_checkpoint(_key, _value, _opts), do: {:error, :disk_full}
  end

  defmodule SwitchableLedgerStorage do
    def get_checkpoint(key, opts), do: Ouroboros.Storage.ETS.get_checkpoint(key, opts)

    def put_checkpoint(key, value, opts) do
      gate = Keyword.fetch!(opts, :gate)

      attempt = Agent.get_and_update(gate, &{&1, &1 + 1})

      if attempt == 1,
        do: {:error, :disk_full},
        else: Ouroboros.Storage.ETS.put_checkpoint(key, value, opts)
    end
  end

  setup do
    root =
      Path.join(System.tmp_dir!(), "native-import-matrix-#{System.unique_integer([:positive])}")

    data = Path.join(root, "data")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)

    previous = %{
      native_data_dir: Application.get_env(:ouroboros, :native_data_dir),
      native_provider: Application.get_env(:ouroboros, :native_provider),
      native_model_module: Application.get_env(:ouroboros, :native_model_module),
      native_model: Application.get_env(:ouroboros, :native_model)
    }

    Application.put_env(:ouroboros, :native_data_dir, Path.join(data, "native"))
    Application.put_env(:ouroboros, :native_provider, %{test_pid: self()})
    Application.put_env(:ouroboros, :native_model_module, CaptureModel)
    Application.put_env(:ouroboros, :native_model, "scripted:checkpoint-import")

    on_exit(fn ->
      Enum.each(previous, fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)

      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, native: Path.join(data, "native")}
  end

  test "version, corrupt payload, embedded digest mismatch, and caller digest mismatch are inert",
       ctx do
    cases = [
      {"future version", fn payload -> %{payload | "version" => 999} end,
       {:checkpoint_version, 999}},
      {"missing version", &Map.delete(&1, "version"), :checkpoint_corrupt},
      {"invalid JSON", fn _ -> "{not-json" end, :checkpoint_corrupt},
      {"embedded digest", fn payload -> %{payload | "digest" => String.duplicate("f", 64)} end,
       :checkpoint_digest_mismatch}
    ]

    Enum.each(cases, fn {label, mutate, reason} ->
      {source, path, digest} = source_checkpoint()
      payload = path |> File.read!() |> JSON.decode!()
      changed = mutate.(payload)
      File.write!(path, if(is_binary(changed), do: changed, else: JSON.encode!(changed)))
      before = native_tree(ctx.native)

      assert {:error, ^reason} = InteractiveSession.preview_native(source), label
      assert {:error, ^reason} = import(source, digest, ctx, id: id(label)), label
      assert native_tree(ctx.native) == before, label
    end)

    {source, _path, _digest} = source_checkpoint()
    before = native_tree(ctx.native)
    assert {:error, :checkpoint_digest_changed} = import(source, String.duplicate("0", 64), ctx)
    assert native_tree(ctx.native) == before
  end

  test "untrusted IDs, traversal, and a symlinked session directory cannot escape", ctx do
    for candidate <- [
          nil,
          "",
          "native-a",
          "../conversation.json",
          "native-a-b/../../x",
          "/native-a-b"
        ] do
      before = native_tree(ctx.native)

      assert {:error, {:invalid_provider_session_id, _}} =
               InteractiveSession.preview_native(candidate)

      assert native_tree(ctx.native) == before
    end

    outside = Path.join(ctx.root, "outside")
    File.mkdir_p!(outside)
    escape = "native-valid-escape"
    File.mkdir_p!(ctx.native)
    File.ln_s!(outside, Path.join(ctx.native, escape))
    before = native_tree(ctx.native)
    assert {:error, :session_path_escape} = InteractiveSession.preview_native(escape)
    assert native_tree(ctx.native) == before
    assert File.ls!(outside) == []
  end

  test "offset requires explicit acknowledgement and all source sibling bytes survive failure and success",
       ctx do
    {source, path, digest} = source_checkpoint(offset: 13, siblings: true)
    source_dir = Path.dirname(path)
    source_before = byte_tree(source_dir)
    all_before = native_tree(ctx.native)

    assert {:ok, %{offset: 13, rewind_floor: 13}} = InteractiveSession.preview_native(source)
    assert {:error, :partial_tail_acknowledgement_required} = import(source, digest, ctx)
    assert native_tree(ctx.native) == all_before

    assert {:ok, imported} =
             import(source, digest, ctx, acknowledge_partial_tail: true, id: id("offset"))

    assert byte_tree(source_dir) == source_before
    assert {:ok, target_path, _} = Checkpoint.locate(imported.provider_session_id)
    assert {:ok, target} = Checkpoint.load(target_path)
    assert target.offset == 13 and target.rewind_floor == 13

    assert Enum.map(target.messages, & &1.content) == [
             "remember matrix sentinel",
             "source answer"
           ]

    target_files = byte_tree(Path.dirname(target_path)) |> Map.keys()
    assert "conversation.json" in target_files

    assert Enum.sort(target_files) ==
             Enum.sort(["conversation.json", "journal.ndjson", "posture.json"])
  end

  test "exact retry converges, changed fingerprint conflicts, and a direct owner blocks import",
       ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    source_before = byte_tree(Path.dirname(path))
    logical = id("idempotent")
    opts = [id: logical, workspace: ctx.workspace, sandbox_mode: :read_only]

    assert {:ok, first} = InteractiveSession.import_native(source, digest, opts)
    assert {:ok, second} = InteractiveSession.import_native(source, digest, opts)
    assert second.idempotent
    assert second.provider_session_id == first.provider_session_id
    assert {:ok, %{owned_by: ^logical}} = InteractiveSession.preview_native(source)

    direct = id("direct-after-import")

    assert {:error, {:native_checkpoint_owned, ^logical}} =
             InteractiveSession.start(
               id: direct,
               workspace: ctx.workspace,
               sandbox_mode: :read_only,
               provider_session_id: source
             )

    assert {:error, {:session_id_conflict, ^logical}} =
             InteractiveSession.import_native(
               source,
               digest,
               Keyword.put(opts, :model, "changed:model")
             )

    {owned_source, owned_path, owned_digest} = source_checkpoint(siblings: true)
    owner = id("direct-owner")

    assert {:ok, _} =
             InteractiveSession.start(
               id: owner,
               workspace: ctx.workspace,
               sandbox_mode: :read_only,
               provider_session_id: owned_source
             )

    assert {:ok, %{owned_by: ^owner}} = InteractiveSession.preview_native(owned_source)

    assert {:error, {:native_checkpoint_owned, ^owner}} =
             import(owned_source, owned_digest, ctx, id: id("blocked"))

    assert byte_tree(Path.dirname(path)) == source_before
    assert File.regular?(owned_path)
  end

  test "competing concurrent imports admit exactly one logical owner and leave no losing seed",
       ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    source_before = byte_tree(Path.dirname(path))
    gate = make_ref()
    parent = self()

    tasks =
      for contender <- [id("race-a"), id("race-b")] do
        Task.async(fn ->
          send(parent, {:ready, self()})
          receive do: ({:go, ^gate} -> :ok)
          {contender, import(source, digest, ctx, id: contender)}
        end)
      end

    pids = for _ <- tasks, do: receive(do: ({:ready, pid} -> pid))
    Enum.each(pids, &send(&1, {:go, gate}))
    results = Enum.map(tasks, &Task.await(&1, 5_000))

    assert [{winner, {:ok, imported}}] = Enum.filter(results, &match?({_, {:ok, _}}, &1))

    assert [{loser, {:error, {:native_checkpoint_owned, ^winner}}}] =
             Enum.filter(results, &match?({_, {:error, _}}, &1))

    refute loser == winner
    assert {:ok, %State{id: ^winner}} = InteractiveSession.info(winner)
    assert {:error, :not_found} = InteractiveSession.info(loser)
    assert byte_tree(Path.dirname(path)) == source_before

    dirs = File.ls!(ctx.native) |> Enum.filter(&(&1 != source))
    assert imported.provider_session_id in dirs
    assert length(dirs) == 1

    assert {:ok, effects} = EffectLedger.list(effect: :native_import, limit: 100)
    race_effects = Enum.filter(effects, &(&1.attempt.source_provider_session_id == source))
    assert Enum.sort(Enum.map(race_effects, & &1.status)) == [:failed, :ok]
  end

  test "success creates context-only state under fresh identities and retained context reaches a controlled model",
       ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    before = byte_tree(Path.dirname(path))
    logical = id("fresh")

    assert {:ok, imported} = import(source, digest, ctx, id: logical)
    refute imported.provider_session_id == source
    assert byte_tree(Path.dirname(path)) == before

    assert {:ok, state} = InteractiveSession.info(logical)
    assert state.id == logical
    assert state.provider_session_id == imported.provider_session_id
    assert state.forked_from == nil and state.handed_off_from == nil
    assert state.turns == %{} and state.last_turn == nil and state.usage == nil
    assert state.error == nil and state.cursor >= 1 and state.sequence_offset >= 1
    assert [%{type: :native_checkpoint_imported, sequence: 1} = marker | _] = state.events

    assert marker.payload["not_restored"] == [
             "public events",
             "approvals and grants",
             "effects",
             "cursor and outcome",
             "ancestry and timestamps"
           ]

    turn = id("context-turn")
    assert {:ok, _} = InteractiveSession.send_message(logical, "continue after import", id: turn)
    assert_receive {:imported_model_context, messages}, 2_000
    contents = Enum.map(messages, & &1.content)
    assert "remember matrix sentinel" in contents
    assert "source answer" in contents
    assert Enum.any?(contents, &String.ends_with?(&1, "continue after import"))
  end

  test "invalid workspace refuses before any target checkpoint or visible logical session", ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    before = native_tree(ctx.native)
    logical = id("bad-workspace")
    missing = Path.join(ctx.root, "missing")

    assert {:error, {:invalid_workspace, ^missing}} =
             import(source, digest, ctx, id: logical, workspace: missing)

    assert {:error, :not_found} = InteractiveSession.info(logical)
    assert native_tree(ctx.native) == before
    assert File.regular?(path)
  end

  test "ledger admission failure creates neither logical visibility nor target residue", ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    before = native_tree(ctx.native)
    logical = id("ledger-refused")
    Application.put_env(:ouroboros, :native_import_ledger, :missing_native_import_ledger)
    on_exit(fn -> Application.delete_env(:ouroboros, :native_import_ledger) end)

    assert {:error, {:import_unrecordable, {:effect_ledger_unavailable, _}}} =
             import(source, digest, ctx, id: logical)

    assert {:error, :not_found} = InteractiveSession.info(logical)
    assert native_tree(ctx.native) == before
    assert File.regular?(path)
  end

  test "workspace lease conflict is durably visible without touching the source", ctx do
    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots)
    Application.put_env(:ouroboros, :workspace_allowed_roots, [ctx.workspace])
    on_exit(fn -> restore_env(:workspace_allowed_roots, previous_roots) end)

    start_supervised!(
      {Ouroboros.Workspace,
       allowed_roots: [ctx.workspace],
       name: Ouroboros.Workspace.Manager,
       recover_reservations: false,
       id: {:native_import_workspace, System.unique_integer([:positive])}}
    )

    assert {:ok, lease, _} =
             Ouroboros.Workspace.acquire(ctx.workspace, "blocker",
               server: Ouroboros.Workspace.Manager,
               mode: :exclusive
             )

    {source, path, digest} = source_checkpoint(siblings: true)
    before = byte_tree(Path.dirname(path))
    logical = id("lease-conflict")

    assert {:ok, imported} = import(source, digest, ctx, id: logical)
    refute imported.ready
    assert match?({:workspace_admission_failed, {:workspace_conflict, _}}, imported.error)

    assert {:ok, %State{status: :failed, provider_session_id: target}} =
             InteractiveSession.info(logical)

    assert {:ok, target_path, _} = Checkpoint.locate(target)
    assert {:ok, %{messages: [_ | _]}} = Checkpoint.snapshot(target_path)
    assert {:ok, effects} = EffectLedger.list(effect: :native_import, limit: 100)

    assert [%{status: :ok, result: %{ready: false, provider_session_id: ^target}}] =
             Enum.filter(effects, &(&1.attempt.session_id == logical))

    assert {:ok, retried} = import(source, digest, ctx, id: logical)
    assert retried.idempotent and not retried.ready
    assert retried.provider_session_id == target

    assert :ok = Ouroboros.Workspace.release(lease, server: Ouroboros.Workspace.Manager)
    assert {:ok, replayed} = import(source, digest, ctx, id: logical)
    refute replayed.ready
    assert replayed.error == inspect(imported.error)
    assert replayed.provider_session_id == target

    assert :ok = InteractiveSession.delete(logical)
    assert {:ok, recovered} = import(source, digest, ctx, id: id("lease-recovered"))
    assert recovered.ready and recovered.provider_session_id != target
    assert byte_tree(Path.dirname(path)) == before
  end

  test "interactive store failure removes the new seed and settles the import failed", ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    source_before = byte_tree(Path.dirname(path))
    logical = id("store-refused")
    original = :sys.get_state(Ouroboros.Interactive.Store)

    :sys.replace_state(Ouroboros.Interactive.Store, fn state ->
      %{state | repo: %{state.repo | adapter: RefusingStoreStorage, opts: []}}
    end)

    on_exit(fn -> :sys.replace_state(Ouroboros.Interactive.Store, fn _ -> original end) end)

    assert {:error, :disk_full} = import(source, digest, ctx, id: logical)

    assert {:error, :not_found} = InteractiveSession.info(logical)
    assert byte_tree(Path.dirname(path)) == source_before
    assert File.ls!(ctx.native) == [source]
    assert {:ok, effects} = EffectLedger.list(effect: :native_import, limit: 100)

    assert [%{status: :failed}] =
             Enum.filter(effects, &(&1.attempt.session_id == logical))

    :sys.replace_state(Ouroboros.Interactive.Store, fn _ -> original end)
    assert {:error, {:import_previously_failed, _}} = import(source, digest, ctx, id: logical)
    assert {:error, :not_found} = InteractiveSession.info(logical)
    assert File.ls!(ctx.native) == [source]
  end

  test "success-settlement persistence failure retries the same committed target", ctx do
    {source, _path, digest} = source_checkpoint(siblings: true)
    logical = id("settlement-retry")
    gate = start_supervised!({Agent, fn -> 0 end})
    ledger = String.to_atom("import_ledger_#{System.unique_integer([:positive])}")
    table = String.to_atom("import_ledger_storage_#{System.unique_integer([:positive])}")

    start_supervised!(
      {EffectLedger, name: ledger, storage: {SwitchableLedgerStorage, table: table, gate: gate}}
    )

    Application.put_env(:ouroboros, :native_import_ledger, ledger)
    on_exit(fn -> Application.delete_env(:ouroboros, :native_import_ledger) end)
    opts = [id: logical, workspace: ctx.workspace, sandbox_mode: :read_only]

    # Ledger write 0 admits the attempt; write 1 is success settlement and fails.
    assert {:error, {:import_settlement_failed, {:effect_ledger_checkpoint_failed, :disk_full}}} =
             InteractiveSession.import_native(source, digest, opts)

    assert {:ok, %State{provider_session_id: target}} = InteractiveSession.info(logical)
    assert {:ok, target_path, _} = Checkpoint.locate(target)
    assert {:ok, %{messages: [_ | _]}} = Checkpoint.snapshot(target_path)

    assert {:ok, retried} = InteractiveSession.import_native(source, digest, opts)
    assert retried.idempotent and retried.provider_session_id == target

    assert {:ok, [%{status: :ok, result: %{provider_session_id: ^target}}]} =
             EffectLedger.list([effect: :native_import], ledger)
  end

  test "failed-settlement persistence remains retryable after a precommit store failure", ctx do
    {source, _path, digest} = source_checkpoint()
    logical = id("failed-settlement-retry")
    gate = start_supervised!({Agent, fn -> 0 end})
    ledger = String.to_atom("failed_import_ledger_#{System.unique_integer([:positive])}")
    table = String.to_atom("failed_import_storage_#{System.unique_integer([:positive])}")

    start_supervised!(
      {EffectLedger, name: ledger, storage: {SwitchableLedgerStorage, table: table, gate: gate}}
    )

    Application.put_env(:ouroboros, :native_import_ledger, ledger)
    original = :sys.get_state(Ouroboros.Interactive.Store)

    :sys.replace_state(Ouroboros.Interactive.Store, fn state ->
      %{state | repo: %{state.repo | adapter: RefusingStoreStorage, opts: []}}
    end)

    on_exit(fn ->
      Application.delete_env(:ouroboros, :native_import_ledger)
      :sys.replace_state(Ouroboros.Interactive.Store, fn _ -> original end)
    end)

    assert {:error, {:import_failed_unsettled, :disk_full, _}} =
             import(source, digest, ctx, id: logical)

    assert {:error, :not_found} = InteractiveSession.info(logical)

    :sys.replace_state(Ouroboros.Interactive.Store, fn _ -> original end)
    assert {:ok, recovered} = import(source, digest, ctx, id: logical)
    assert recovered.ready
    assert {:ok, [%{status: :ok}]} = EffectLedger.list([effect: :native_import], ledger)
  end

  test "cleanup refusal is reported and retains only generated target residue", ctx do
    {source, path, digest} = source_checkpoint(siblings: true)
    source_before = byte_tree(Path.dirname(path))
    original = :sys.get_state(Ouroboros.Interactive.Store)

    :sys.replace_state(Ouroboros.Interactive.Store, fn state ->
      %{state | repo: %{state.repo | adapter: RefusingStoreStorage, opts: []}}
    end)

    Application.put_env(:ouroboros, :native_import_cleanup, fn _ -> {:error, :unlink_denied} end)

    on_exit(fn ->
      Application.delete_env(:ouroboros, :native_import_cleanup)
      :sys.replace_state(Ouroboros.Interactive.Store, fn _ -> original end)
    end)

    assert {:error, {:import_cleanup_failed, :disk_full, {:error, :unlink_denied}}} =
             import(source, digest, ctx, id: id("cleanup-refused"))

    assert byte_tree(Path.dirname(path)) == source_before
    assert length(File.ls!(ctx.native)) == 2
  end

  test "digest binding remains safe under source replacement (TOCTOU stress)", ctx do
    Enum.each(1..20, fn _ ->
      {source, path, digest} = source_checkpoint()
      parent = self()

      mutator =
        spawn(fn ->
          receive do
            :go -> Checkpoint.write(path, [%{role: :user, content: "replacement"}])
          end

          send(parent, {:mutated, self()})
        end)

      send(mutator, :go)

      result =
        Checkpoint.import(source, "native-target-#{System.unique_integer([:positive])}", digest)

      assert_receive {:mutated, ^mutator}, 1_000

      case result do
        {:error, :checkpoint_digest_changed} ->
          :ok

        {:ok, %{digest: imported_digest}} ->
          target =
            ctx.native
            |> File.ls!()
            |> Enum.find(&String.starts_with?(&1, "native-target-"))

          {:ok, target_path, _} = Checkpoint.locate(target)
          assert {:ok, %{digest: ^imported_digest}} = Checkpoint.snapshot(target_path)
          assert imported_digest == digest
          File.rm_rf!(Path.dirname(target_path))
      end
    end)
  end

  test "import preserves the digest-bound work-item plan", ctx do
    source = "native-plan-#{System.unique_integer([:positive])}"
    target = "native-plan-target-#{System.unique_integer([:positive])}"
    {:ok, source_path, true} = Checkpoint.locate(source)

    plan = %{
      "plan" => [
        %{
          "id" => "P0",
          "step" => "Preserve accepted evidence",
          "status" => "accepted",
          "acceptance" => %{"basis" => "model_judgment", "deterministic" => false}
        }
      ]
    }

    {:ok, digest} = Checkpoint.write(source_path, [%{role: :user, content: "source"}], plan: plan)
    assert {:ok, _result} = Checkpoint.import(source, target, digest)
    {:ok, target_path, true} = Checkpoint.locate(target)
    assert {:ok, %{plan: ^plan}} = Checkpoint.load(target_path)

    File.rm_rf!(Path.dirname(target_path))
    File.rm_rf!(Path.dirname(source_path))
    assert File.dir?(ctx.native)
  end

  defp import(source, digest, ctx, extra \\ []) do
    defaults = [id: id("import"), workspace: ctx.workspace, sandbox_mode: :read_only]
    InteractiveSession.import_native(source, digest, Keyword.merge(defaults, extra))
  end

  defp restore_env(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_env(key, value), do: Application.put_env(:ouroboros, key, value)

  defp source_checkpoint(opts \\ []) do
    source = "native-matrix-#{System.unique_integer([:positive])}"
    {:ok, path, true} = Checkpoint.locate(source)

    messages = [
      %{role: :user, content: "remember matrix sentinel"},
      %{role: :assistant, content: "source answer", tool_calls: []}
    ]

    {:ok, digest} = Checkpoint.write(path, messages, offset: Keyword.get(opts, :offset, 0))

    if Keyword.get(opts, :siblings, false) do
      dir = Path.dirname(path)
      File.mkdir_p!(Path.join(dir, "blobs"))
      File.write!(Path.join(dir, "blobs/deadbeef"), <<0, 1, 2, 255>>)
      File.write!(Path.join(dir, "manifest.json"), "manifest-byte-sentinel\n")
      File.write!(Path.join(dir, "journal.jsonl"), "journal-byte-sentinel\n")
    end

    {source, path, digest}
  end

  defp id(prefix),
    do: "#{String.replace(prefix, ~r/[^a-zA-Z0-9_-]/, "-")}-#{System.unique_integer([:positive])}"

  defp native_tree(root), do: if(File.dir?(root), do: byte_tree(root), else: %{})

  defp byte_tree(root) do
    root
    |> Path.join("**/*")
    |> Path.wildcard(match_dot: true)
    |> Enum.filter(&File.regular?/1)
    |> Map.new(&{Path.relative_to(&1, root), File.read!(&1)})
  end
end
