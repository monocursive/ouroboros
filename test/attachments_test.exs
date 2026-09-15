defmodule Ouroboros.AttachmentsTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Attachments

  defmodule Decoder do
    def normalize(paths, _root) do
      bytes =
        Enum.map_join(paths, fn path ->
          {:ok, bytes} = Ouroboros.Audit.Content.read(path)
          bytes
        end)

      {:ok, %{content: bytes, thumbnail: bytes, width: 2, height: 1}}
    end
  end

  setup do
    root = Path.join(System.tmp_dir!(), "attachments-test-#{System.unique_integer([:positive])}")
    server = start_supervised!({Attachments, name: nil, data_dir: root, normalizer: Decoder})
    on_exit(fn -> File.rm_rf(root) end)
    %{root: root, server: server}
  end

  defp call(context, op, params, actor \\ "owner"),
    do: Attachments.operation(op, params, actor, context.server)

  defp begin(context, bytes, overrides \\ %{}) do
    call(
      context,
      "begin",
      Map.merge(
        %{
          "client_id" => "client",
          "draft_id" => "draft",
          "client_attachment_id" => "entry",
          "attempt_id" => "attempt",
          "byte_size" => byte_size(bytes),
          "session_id" => "session",
          "display_name" => "screen.png"
        },
        overrides
      )
    )
  end

  defp upload(context, bytes, overrides \\ %{}) do
    {:ok, %{"upload_id" => id}} = begin(context, bytes, overrides)

    {:ok, _} =
      call(context, "append", %{"upload_id" => id, "offset" => 0, "data" => Base.encode64(bytes)})

    {:ok, _} = call(context, "finish", %{"upload_id" => id, "sha256" => hash(bytes)})
    await_ready(context, id)
  end

  defp await_ready(context, id, remaining \\ 1000)
  defp await_ready(_context, _id, 0), do: flunk("upload did not finish")

  defp await_ready(context, id, remaining) do
    case call(context, "status", %{"upload_id" => id}) do
      {:ok, %{"state" => "ready"} = record} ->
        record

      {:ok, %{"state" => "failed"} = record} ->
        flunk(inspect(record))

      _ ->
        receive do
        after
          1 -> await_ready(context, id, remaining - 1)
        end
    end
  end

  defp hash(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  test "recovery namespaces survive token rotation and restart, but isolate principals and stores",
       context do
    alias Ouroboros.Audit.Identity
    {:ok, first_subject} = Identity.authenticate("old-token", "old-token")
    {:ok, rotated_subject} = Identity.authenticate("new-token", "new-token")

    namespace =
      Identity.with_subject(first_subject, fn ->
        Attachments.recovery_namespace(Identity.actor(), context.server)
      end)

    assert namespace ==
             Identity.with_subject(rotated_subject, fn ->
               Attachments.recovery_namespace(Identity.actor(), context.server)
             end)

    refute namespace == Attachments.recovery_namespace("another-principal", context.server)
    {:ok, stat} = File.stat(Path.join(context.root, "attachments/.recovery-id"))
    assert Bitwise.band(stat.mode, 0o777) == 0o600
    stop_supervised!(Attachments)

    restarted =
      start_supervised!({Attachments, name: nil, data_dir: context.root, normalizer: Decoder})

    assert namespace == Attachments.recovery_namespace("local-owner", restarted)

    other =
      start_supervised!(
        {Attachments, name: nil, data_dir: context.root <> "-other", normalizer: Decoder},
        id: :other
      )

    on_exit(fn -> File.rm_rf(context.root <> "-other") end)
    refute namespace == Attachments.recovery_namespace("local-owner", other)
  end

  test "a fresh initial draft binds independently of retained images from the previous session",
       context do
    first = upload(context, "pixels", %{"session_id" => nil, "draft_id" => "first-draft"})

    assert {:ok, _} =
             call(context, "bind_draft", %{"draft_id" => "first-draft", "session_id" => "one"})

    assert {:ok, _} =
             Attachments.reserve("one", "turn-one", [%{"id" => first["id"]}], 0, context.server)

    second = upload(context, "second", %{"session_id" => nil, "draft_id" => "next-draft"})

    assert {:ok, _} =
             call(context, "bind_draft", %{"draft_id" => "next-draft", "session_id" => "two"})

    assert {:ok, _} =
             Attachments.reserve("two", "turn-two", [%{"id" => second["id"]}], 0, context.server)

    assert {:error, :attachment_not_ready} =
             Attachments.reserve("two", "wrong-turn", [%{"id" => first["id"]}], 0, context.server)
  end

  test "chunks and finish are idempotent; a conflicting append does not mutate content",
       context do
    {:ok, first} = begin(context, "pixels")
    assert {:ok, ^first} = begin(context, "pixels")
    id = first["upload_id"]
    chunk = %{"upload_id" => id, "offset" => 0, "data" => Base.encode64("pixels")}
    assert {:ok, receipt} = call(context, "append", chunk)
    assert {:ok, ^receipt} = call(context, "append", chunk)

    assert {:error, :attachment_upload_conflict} =
             call(context, "append", %{chunk | "data" => Base.encode64("others")})

    finish = %{"upload_id" => id, "sha256" => hash("pixels")}
    assert {:ok, _} = call(context, "finish", finish)
    record = await_ready(context, id)
    assert {:ok, ^record} = call(context, "finish", finish)

    assert {:error, :attachment_upload_conflict} =
             call(context, "finish", %{finish | "sha256" => hash("others")})
  end

  test "draft content is private and cannot be rebound to another session", context do
    record = upload(context, "pixels")
    ref = %{"id" => record["id"]}

    assert {:error, :attachment_not_authorized} =
             call(context, "status", %{"attachment_id" => record["id"]}, "stranger")

    assert {:error, :attachment_not_ready} =
             Attachments.reserve("other", "turn", [ref], 0, context.server)

    assert {:error, :attachment_not_authorized} =
             call(context, "bind_draft", %{"draft_id" => "draft", "session_id" => "other"})

    assert {:ok, [manifest]} = Attachments.reserve("session", "turn", [ref], 0, context.server)
    assert manifest["sha256"] == hash("pixels")

    assert {:ok, _} =
             call(
               context,
               "status",
               %{"attachment_id" => record["id"], "session_id" => "session"},
               "reader"
             )
  end

  test "accepted images survive removal from a draft and restart", context do
    record = upload(context, "pixels")
    refs = [%{"id" => record["id"]}]
    assert {:ok, _} = Attachments.reserve("session", "turn", refs, 0, context.server)
    assert {:ok, %{retained: true}} = call(context, "discard", %{"attachment_id" => record["id"]})
    stop_supervised!(Attachments)
    {:ok, server} = Attachments.start_link(name: nil, data_dir: context.root, normalizer: Decoder)
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    assert {:ok, [part]} = Attachments.content("session", refs, server)
    assert {:ok, "pixels"} = Ouroboros.Audit.Content.read(part.path)
    assert part.sha256 == hash("pixels")
  end

  test "removal and missing or corrupt content never become a partial input", context do
    record = upload(context, "pixels")
    refs = [%{"id" => record["id"]}]

    assert {:error, :attachment_duplicate} =
             Attachments.reserve("session", "turn", refs ++ refs, 0, context.server)

    assert {:error, :attachment_count_exceeded} =
             Attachments.reserve("session", "turn", refs, 32, context.server)

    File.write!(Path.join([context.root, "attachments", record["id"], "content"]), "changed")

    assert {:error, :attachment_integrity_failed} =
             Attachments.content("session", refs, context.server)

    assert {:ok, _} = call(context, "discard", %{"attachment_id" => record["id"]})

    assert {:error, :attachment_not_ready} =
             Attachments.reserve("session", "turn", refs, 0, context.server)
  end

  test "an image-only turn validates without a fabricated prompt and old fingerprints stay stable" do
    assert {:ok, request} =
             Ouroboros.Session.TurnRequest.new(%{
               prompt: "",
               image_attachments: [%{"id" => "att_test"}]
             })

    assert Ouroboros.Session.TurnRequest.text(request) == ""
    assert {:error, _} = Ouroboros.Session.TurnRequest.new(%{prompt: "", image_attachments: []})
    plain = Ouroboros.Session.TurnRequest.new!("hello")
    old = Map.delete(plain, :image_attachments)

    old_hash =
      :crypto.hash(:sha256, :erlang.term_to_binary({:message, old}, [:deterministic]))
      |> Base.encode16(case: :lower)

    assert Ouroboros.Interactive.State.fingerprint(:message, plain) == old_hash
  end

  test "ready drafts expire but turn reservations and inherited sessions keep their images",
       context do
    record = upload(context, "durable pixels")
    refs = [%{"id" => record["id"]}]
    assert {:ok, _} = Attachments.reserve("session", "turn-1", refs, 0, context.server)
    assert :ok = Attachments.inherit("session", "child", context.server)
    assert {:ok, _} = Attachments.reserve("child", "turn-2", refs, 0, context.server)
    future = System.system_time(:second) + 86_401
    :sys.replace_state(context.server, &Map.put(&1, :clock, fn -> future end))

    assert {:ok, %{data: encoded}} =
             call(
               context,
               "read",
               %{
                 "attachment_id" => record["id"],
                 "session_id" => "child",
                 "variant" => "content"
               },
               "another reader"
             )

    assert Base.decode64!(encoded) == "durable pixels"

    assert {:error, :attachment_not_authorized} =
             call(
               context,
               "read",
               %{
                 "attachment_id" => record["id"],
                 "session_id" => "other",
                 "variant" => "content"
               },
               "another reader"
             )
  end

  test "unreserved drafts expire and corrupt content refuses model dispatch", context do
    record = upload(context, "pixels")
    File.write!(Path.join([context.root, "attachments", record["id"], "content"]), "tampered")

    assert {:error, :attachment_integrity_failed} =
             Attachments.content("session", [%{"id" => record["id"]}], context.server)

    future = System.system_time(:second) + 86_401
    :sys.replace_state(context.server, &Map.put(&1, :clock, fn -> future end))

    assert {:error, :attachment_not_authorized} =
             call(context, "status", %{"attachment_id" => record["id"]})

    refute File.exists?(Path.join([context.root, "attachments", record["id"]]))
  end

  test "attachment persistence honors configured operational encryption", context do
    old = Application.get_env(:ouroboros, :audit)

    on_exit(fn ->
      if old,
        do: Application.put_env(:ouroboros, :audit, old),
        else: Application.delete_env(:ouroboros, :audit)
    end)

    config = %{
      Ouroboros.Audit.Config.current()
      | encryption_key_id: "attachments",
        encryption_keys: %{"attachments" => :binary.copy(<<4>>, 32)}
    }

    Application.put_env(:ouroboros, :audit, config)
    record = upload(context, "private image pixels")

    for file <- ["manifest", "content", "thumbnail"] do
      bytes = File.read!(Path.join([context.root, "attachments", record["id"], file]))
      assert Ouroboros.Audit.Content.encrypted?(bytes)
      refute bytes =~ "private image pixels"
    end

    assert Attachments.limits().client_draft_persistence == "ephemeral"
    assert {:ok, _} = Attachments.content("session", [%{"id" => record["id"]}], context.server)
  end

  test "restart refuses an unreadable manifest rather than losing the image record", context do
    record = upload(context, "pixels")
    stop_supervised!(Attachments)

    File.write!(
      Path.join([context.root, "attachments", record["id"], "manifest"]),
      "corrupt manifest"
    )

    assert {:error, _} =
             start_supervised(
               {Attachments, name: nil, data_dir: context.root, normalizer: Decoder}
             )
  end

  test "malformed chunks cannot kill the attachment owner", context do
    {:ok, record} = begin(context, "pixels")

    for invalid <- [nil, -1, "0", [], %{}] do
      assert {:error, _} =
               call(context, "append", %{
                 "upload_id" => record["id"],
                 "offset" => invalid,
                 "data" => "!!!!"
               })
    end

    assert Process.alive?(context.server)
  end
end
