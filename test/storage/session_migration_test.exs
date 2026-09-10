defmodule Ouroboros.Storage.SessionMigrationTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Interactive.{State, Store}
  alias Ouroboros.Storage.{DurableFile, SessionMigration}

  @fixture Path.expand("../support/j2_fixture/data", __DIR__)

  test "pre-J2 records retain identities, public history, offsets and nested data without a write" do
    root = Path.join(System.tmp_dir!(), "j2-reader-#{System.unique_integer([:positive])}")
    File.cp_r!(@fixture, root)
    on_exit(fn -> File.rm_rf!(root) end)
    files = Path.wildcard(Path.join(root, "**/*.term"))
    before = Map.new(files, &{&1, File.read!(&1)})

    store =
      start_supervised!(
        {Store, name: nil, storage: {DurableFile, path: Path.join(root, "interactive")}}
      )

    assert length(Store.list(store)) == 8
    assert {:ok, resumed} = Store.get("j2-fixture-resumed", store)
    assert resumed.runtime_id == "legacy-runtime-resumed"
    assert resumed.provider_session_id == "native-conversation-resumed"
    assert resumed.runtime_cursor == 1
    assert resumed.runtime_generation == nil
    assert resumed.cursor == 41
    assert resumed.sequence_offset == 40
    assert resumed.resumes == 1
    assert resumed.usage.total_tokens == 10

    assert {:ok, queued} = Store.get("j2-fixture-queued", store)

    assert Enum.sort(Enum.map(queued.turns, fn {_, turn} -> turn.status end)) == [
             :queued,
             :running
           ]

    assert Enum.all?(queued.turns, fn {_, turn} ->
             turn.runtime_turn_id == turn.harness_turn_id
           end)

    nested = hd(queued.events).payload["legacy"]
    refute is_struct(nested.request)
    refute is_struct(nested.event)
    refute is_struct(nested.approval)
    assert nested.approval.decision == :deny
    assert nested.event.session_id == "legacy-runtime-queued"

    assert {:ok, removed} = Store.get("j2-fixture-removed_provider", store)
    assert State.removed_provider(removed) == :claude
    assert {:legacy_transport_unavailable, :claude} = State.unrequestable_reason(removed)
    assert Enum.find(Store.list_recoverable(store), &(&1.id == removed.id)).removed_provider?
    assert before == Map.new(files, &{&1, File.read!(&1)})
  end

  test "known retired tags normalize through nested tuples without calling a module" do
    tag = SessionMigration.legacy_structs() |> List.first()
    value = %{__struct__: tag, metadata: %{nested: [{:error, %{__struct__: tag, cwd: "/old"}}]}}
    assert SessionMigration.normalize(value) == %{metadata: %{nested: [{:error, %{cwd: "/old"}}]}}
    # An arbitrary tag remains data; it is neither loaded nor used as a constructor.
    assert SessionMigration.normalize(%{__struct__: :j2_unknown_module}) == %{
             __struct__: :j2_unknown_module
           }
  end

  test "future record versions are refused instead of silently dropping fields" do
    {:ok, session} = State.new("j2-future", workspace: File.cwd!(), runtime_exposure: false)
    assert :error == SessionMigration.decode(session.id, %{session | format_version: 3})
  end

  test "malformed new runtime fields never become loadable durable authority" do
    {:ok, session} =
      State.new("j2-invalid-fields", workspace: File.cwd!(), runtime_exposure: false)

    for changes <- [
          %{runtime_generation: ""},
          %{runtime_generation: make_ref()},
          %{runtime_cursor: -1},
          %{runtime_cursor: 1},
          %{runtime_cursor: 1.0},
          %{close_intent: :resume},
          %{format_version: 0},
          %{format_version: "2"}
        ] do
      malformed = Map.merge(session, changes)
      refute State.loadable?(malformed)
      assert :error == SessionMigration.decode(session.id, malformed)
    end

    for intent <- [nil, :close, :kill] do
      valid = %{session | close_intent: intent}
      assert State.loadable?(valid)
      assert {:ok, ^valid} = SessionMigration.decode(session.id, valid)
    end
  end

  test "legacy native planning becomes an explicit setting while an existing explicit setting wins" do
    id = "j2-fixture-idle"
    key = {{:ouroboros, :interactive_sessions, 1}, :session, 2, id}

    {:ok, %{^id => legacy}} =
      DurableFile.get_checkpoint(key, path: Path.join(@fixture, "interactive"))

    for key <- [:plan, "plan"] do
      old = %{
        legacy
        | workspace: File.cwd!(),
          options: %{runtime_exposure: false, provider_options: %{key => true}}
      }

      assert {:ok, migrated} = SessionMigration.decode(id, old)
      assert migrated.options.plan == true
      assert migrated.options.provider_options == %{}
      assert {:ok, request} = migrated |> State.request() |> Ouroboros.Session.Request.new()
      assert request.plan == true

      assert {:ok, explicit} =
               SessionMigration.decode(id, %{old | options: Map.put(old.options, :plan, false)})

      assert explicit.options.plan == false
      assert explicit.options.provider_options == %{}
    end

    tag =
      Enum.find(
        SessionMigration.legacy_structs(),
        &(Atom.to_string(&1) == "Elixir.Jido.Harness.SessionRequest")
      )

    assert %{plan: true, provider_options: %{}} =
             SessionMigration.normalize(%{__struct__: tag, provider_options: %{"plan" => true}})
  end

  test "unknown serialized atom input is refused and does not intern its name" do
    root = Path.join(System.tmp_dir!(), "j2-unknown-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(root) end)
    key = {:j2_test, 1}
    hash = :crypto.hash(:sha256, :erlang.term_to_binary(key)) |> Base.url_encode64(padding: false)
    path = Path.join([root, "checkpoints", hash <> ".term"])
    File.mkdir_p!(Path.dirname(path))
    name = "j2_never_intern_#{System.unique_integer([:positive])}"
    File.write!(path, <<131, 119, byte_size(name), name::binary>>)
    assert {:error, :invalid_term} = DurableFile.get_checkpoint(key, path: root)
    assert_raise ArgumentError, fn -> String.to_existing_atom(name) end
  end
end
