defmodule Ouroboros.Audit.TestTransport do
  def deliver(payload, archive),
    do: Ouroboros.Audit.Collector.accept(payload, archive.token, archive.collector)

  def inventory(nonce, archive),
    do: Ouroboros.Audit.Collector.inventory(nonce, archive.token, archive.collector)
end

defmodule Ouroboros.Audit.SystemTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log
  alias Ouroboros.Audit.{
    Archive,
    Bundle,
    Collector,
    Config,
    Content,
    Identity,
    Index,
    Lifecycle,
    OTLP,
    Record,
    Store
  }

  alias Ouroboros.Provider.Native.Journal

  setup do
    {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(tmp, "ouro-audit-system-#{System.unique_integer([:positive])}")

    config =
      Config.new!(
        mode: :local,
        capture: :full,
        root: Path.join(root, "evidence"),
        writer_id: "test-node",
        index: true
      )

    previous = Application.get_env(:ouroboros, :audit)
    Application.put_env(:ouroboros, :audit, config)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :audit, previous),
        else: Application.delete_env(:ouroboros, :audit)

      File.rm_rf(root)
    end)

    %{root: root, config: config, stream: Journal.digest("test-session")}
  end

  test "SQLite catches up incrementally, filters in SQL and rebuilds from evidence", ctx do
    store = start_supervised!({Store, name: nil, config: ctx.config})

    {:ok, _} =
      Store.append(
        ctx.stream,
        "session_opened",
        %{"session_id" => "session-1", "actor_id" => "alice"},
        store
      )

    {:ok, _} =
      Store.append(
        ctx.stream,
        "model_call",
        %{"model" => "model-1", "request" => "private prompt"},
        store
      )

    index = start_supervised!({Index, name: __MODULE__.Index, config: ctx.config})
    assert {:ok, %{count: 2}} = Index.reindex(index)

    assert {:ok, %{events: [event], total: 1}} =
             Index.search(%{"actor_id" => "alice", "kind" => "model_call"}, index)

    refute Map.has_key?(event, "request")
    {:ok, _} = Store.append(ctx.stream, "model_result", %{"model" => "model-1"}, store)
    send(index, :refresh)
    _ = Index.status(index)
    assert {:ok, %{total: 3, events: [last]}} = Index.search(%{"limit" => 1}, index)
    assert last["seq"] == 3
    assert {:ok, %{total: 0}} = Index.search(%{"actor_id" => "alice' OR 1=1 --"}, index)
    assert {:ok, %{count: 3}} = Index.reindex(index)
  end

  test "independent custody rejects conflict and forged receipts and detects whole-stream deletion",
       ctx do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    token = "test-custody-credential"

    collector =
      start_supervised!(
        {Collector,
         name: __MODULE__.Collector,
         root: Path.join(ctx.root, "custodian"),
         organization: "local",
         writer_id: "test-node",
         token_sha256: sha(token),
         key_id: "test-key",
         private_key: private}
      )

    archive = %{
      transport: Ouroboros.Audit.TestTransport,
      collector: collector,
      token: token,
      key_id: "test-key",
      public_key: public
    }

    config = %{ctx.config | archive: archive, archive_required: true}
    store = start_supervised!({Store, name: nil, config: config})
    assert {:ok, first} = Store.append(ctx.stream, "model_call", %{"request" => "private"}, store)
    assert :ok = Archive.deliver(first, config)
    assert {:ok, envelope} = Archive.inventory(config)
    assert :ok = Archive.verify_local_inventory(envelope["receipt"]["streams"], config)

    assert {:error, :conflicting_evidence} =
             Collector.accept(
               %{
                 "version" => 1,
                 "record" => Map.put(first, "request", "changed"),
                 "blobs" => %{}
               },
               token,
               collector
             )

    assert {:error, :unauthenticated} = Collector.accept(%{}, "wrong", collector)
    receipt_path = Path.join([ctx.config.root, "receipts", first["hash"] <> ".json"])
    receipt = File.read!(receipt_path) |> JSON.decode!()

    assert {:error, :invalid_archive_receipt} =
             Archive.verify_receipt(put_in(receipt, ["receipt", "seq"], 4), first, config)

    File.rm_rf!(Store.stream_path(config.root, ctx.stream))
    assert {:error, :anchored_evidence_missing_or_changed} = Archive.reconcile(config)
  end

  test "a receipt failure after append is retryable without duplicate records", ctx do
    {_public, private} = :crypto.generate_key(:eddsa, :ed25519)
    root = Path.join(ctx.root, "custodian")
    token = "test-custody-credential"

    collector =
      start_supervised!(
        {Collector,
         name: __MODULE__.Collector,
         root: root,
         organization: "local",
         writer_id: "test-node",
         token_sha256: sha(token),
         key_id: "test-key",
         private_key: private}
      )

    store = start_supervised!({Store, name: nil, config: ctx.config})
    {:ok, record} = Store.append(ctx.stream, "model_call", %{}, store)
    payload = %{"version" => 1, "record" => record, "blobs" => %{}}
    receipt = Path.join([root, "receipts", record["hash"] <> ".json"])
    File.mkdir!(receipt)
    assert {:error, _} = Collector.accept(payload, token, collector)
    File.rmdir!(receipt)
    assert {:ok, envelope} = Collector.accept(payload, token, collector)
    assert {:ok, ^envelope} = Collector.accept(payload, token, collector)

    assert {:ok, %{records: [^record], verified_through: 1}} =
             Store.read(Store.stream_path(root, ctx.stream))

    {:ok, next} = Store.append(ctx.stream, "model_result", %{}, store)
    assert {:ok, _} = Collector.accept(%{payload | "record" => next}, token, collector)

    assert {:ok, %{records: [^record, ^next], verified_through: 2}} =
             Store.read(Store.stream_path(root, ctx.stream))
  end

  test "operational image copies and large shell output are encrypted and inventoried", ctx do
    config = %{
      ctx.config
      | encryption_key_id: "images",
        encryption_keys: %{"images" => :binary.copy(<<4>>, 32)}
    }

    Application.put_env(:ouroboros, :audit, config)
    session = Path.join(ctx.root, "native/images")
    workspace = Path.join(ctx.root, "workspace")
    File.mkdir_p!(workspace)
    source = Path.join(workspace, "image.png")
    bytes = <<137, 80, 78, 71, 13, 10, 26, 10>> <> "private image pixels"
    File.write!(source, bytes)

    assert {:ok, %{content: [_, image]}} =
             Ouroboros.Provider.Native.Attachments.message("look", [source], session)

    assert Content.encrypted?(File.read!(image.path))
    assert {:ok, ^bytes} = Content.read(image.path)
    assert File.read!(source) == bytes
    assert {:ok, _} = Ouroboros.Provider.Native.Attachments.message("again", [source], session)
    assert Content.inventory(ctx.root).encrypted == 1

    # Local audit permits unrestricted shell execution; output storage still encrypts.
    {:ok, scope} = Ouroboros.Provider.Native.Paths.scope(workspace, [], :unrestricted)

    assert {:ok, %{is_error: false}} =
             Ouroboros.Provider.Native.Tools.Bash.run(
               %{command: "head -c 40000 /dev/zero | tr '\\000' x", timeout_ms: 5000},
               %{scope: scope, session_dir: session}
             )

    [output] = Path.wildcard(Path.join(session, "output/*"))
    assert Content.encrypted?(File.read!(output))
    assert {:ok, clear} = Content.read(output)
    assert byte_size(clear) == 40000
    assert Content.inventory(ctx.root).encrypted == 2
    assert Content.inventory(ctx.root).plaintext == []
  end

  test "encrypted operational state survives key rotation and refuses missing keys", ctx do
    key = :binary.copy(<<7>>, 32)
    config = %{ctx.config | encryption_key_id: "old", encryption_keys: %{"old" => key}}
    bytes = Content.encode("confidential conversation", config)
    refute bytes =~ "confidential conversation"
    assert {:ok, "confidential conversation"} = Content.decode(bytes, config)

    rotated = %{
      config
      | encryption_key_id: "new",
        encryption_keys: Map.put(config.encryption_keys, "new", :binary.copy(<<8>>, 32))
    }

    assert {:ok, "confidential conversation"} = Content.decode(bytes, rotated)

    assert {:error, :operational_content_key_or_integrity_failure} =
             Content.decode(bytes, %{rotated | encryption_keys: %{}})

    Application.put_env(:ouroboros, :audit, config)
    path = Path.join(ctx.root, "working")
    opts = [path: path]

    assert :ok =
             Ouroboros.Storage.DurableFile.put_checkpoint(
               :test,
               %{content: "confidential conversation"},
               opts
             )

    [file] = Path.wildcard(Path.join([path, "checkpoints", "*.term"]))
    refute File.read!(file) =~ "confidential conversation"

    assert {:ok, %{content: "confidential conversation"}} =
             Ouroboros.Storage.DurableFile.get_checkpoint(:test, opts)
  end

  test "roles and expired or revoked credentials are enforced on every request", ctx do
    identity = %{"id" => "auditor", "roles" => ["auditor"], "token_sha256" => sha("audit-token")}
    config = %{ctx.config | identities: [identity]}
    Application.put_env(:ouroboros, :audit, config)
    assert {:ok, subject} = Identity.authenticate("audit-token", "local-token")
    assert Identity.permits?(subject, "audit.search", :read)
    refute Identity.permits?(subject, "audit.purge", :operate)
    refute Identity.permits?(subject, "interactive.start", :operate)
    Application.put_env(:ouroboros, :audit, %{config | identities: []})
    refute Identity.permits?(subject, "audit.search", :read)

    Application.put_env(:ouroboros, :audit, %{
      config
      | identities: [Map.put(identity, "expires_at", "2000-01-01T00:00:00Z")]
    })

    assert {:error, :unauthenticated} = Identity.authenticate("audit-token", "local-token")
  end

  test "holds and retention survive restart and prevent deletion of active evidence", ctx do
    store = start_supervised!({Store, name: nil, config: ctx.config})
    {:ok, _} = Store.append(ctx.stream, "session_opened", %{}, store)

    assert {:error, :stream_held_active_or_not_expired} =
             Store.purge(ctx.stream, "case closed", "admin", store)

    {:ok, _} = Store.append(ctx.stream, "session_closed", %{}, store)
    future = DateTime.add(DateTime.utc_now(), 100 * 86_400, :second)
    assert {:ok, _} = Lifecycle.eligible(ctx.config, ctx.stream, future)
    assert {:ok, %{held: true}} = Store.hold(ctx.stream, true, "investigation", "admin", store)

    assert {:error, :stream_held_active_or_not_expired} =
             Lifecycle.eligible(ctx.config, ctx.stream, future)

    assert {:ok, %{held: false}} = Store.hold(ctx.stream, false, "case complete", "admin", store)
    assert {:ok, _} = Lifecycle.eligible(ctx.config, ctx.stream, future)

    assert {:error, :stream_held_active_or_not_expired} =
             Store.purge(ctx.stream, "not expired", "admin", store)
  end

  test "expired evidence purge retains a tombstone and cannot silently reuse its stream", ctx do
    fixture = Path.expand("../support/audit_bundle", __DIR__)
    manifest = File.read!(Path.join(fixture, "manifest.json")) |> JSON.decode!()
    [stream] = manifest["streams"]
    id = stream["stream_id"]
    source = Store.stream_path(fixture, id)
    target = Store.stream_path(ctx.config.root, id)
    File.mkdir_p!(Path.dirname(target))
    File.cp_r!(source, target)

    for path <- [ctx.config.root, Path.join(ctx.config.root, "streams"), target],
        do: File.chmod!(path, 0o700)

    for file <- Store.segments(target), do: File.chmod!(file, 0o600)
    store = start_supervised!({Store, name: nil, config: ctx.config})
    assert {:ok, exported} = Store.export([id], store)

    assert {:ok, %{scope: "retained_audit_and_server_exports"}} =
             Store.purge(id, "expired case", "admin", store)

    refute File.exists?(target)
    refute File.exists?(Path.join([ctx.config.root, "exports", exported.bundle_id]))
    assert {:ok, governance} = Lifecycle.state(ctx.config)
    assert governance.purges[id]["removed_head"] == stream["head"]
    assert {:error, :evidence_stream_retired} = Store.append(id, "model_call", %{}, store)
    assert :ok = Lifecycle.recover(ctx.config)
  end

  test "missing custody authorization never permits destructive purge recovery", ctx do
    store = start_supervised!({Store, name: nil, config: ctx.config})
    {:ok, record} = Store.append(ctx.stream, "session_closed", %{}, store)

    {:ok, _} =
      Store.append(
        Lifecycle.stream(),
        "purge_authorized",
        %{
          "target_stream" => ctx.stream,
          "removed_head" => record["hash"],
          "removed_through" => 1
        },
        store
      )

    {public, _} = :crypto.generate_key(:eddsa, :ed25519)

    required = %{
      ctx.config
      | archive_required: true,
        archive: %{key_id: "missing", public_key: public}
    }

    refute Lifecycle.authorized?(required, ctx.stream, record["hash"], 1)
    assert {:error, :purge_receipt_unavailable} = Lifecycle.recover(required)

    assert {:ok, %{records: [^record]}} =
             Store.read(Store.stream_path(ctx.config.root, ctx.stream))
  end

  test "privacy inventory distinguishes legacy content, encrypted state and workspace files",
       ctx do
    key = :binary.copy(<<9>>, 32)

    config = %{
      ctx.config
      | encryption_key_id: "inventory",
        encryption_keys: %{"inventory" => key}
    }

    old = Path.join(ctx.root, "native/example/conversation.json")
    encrypted = Path.join(ctx.root, "coding/checkpoints/example.term")
    workspace = Path.join(ctx.root, "worktrees/example/conversation.json")
    for path <- [old, encrypted, workspace], do: File.mkdir_p!(Path.dirname(path))
    File.write!(old, "legacy conversation")
    File.write!(encrypted, Content.encode("encrypted checkpoint", config))
    File.write!(workspace, "workspace source")

    legacy =
      for family <- ["attachments", "output"] do
        relative = "native/example/#{family}/legacy.bin"
        path = Path.join(ctx.root, relative)
        File.mkdir_p!(Path.dirname(path))
        File.write!(path, "legacy sensitive content")
        relative
      end

    inventory = Content.inventory(ctx.root, config)

    assert Enum.sort(inventory.plaintext) ==
             Enum.sort(["native/example/conversation.json" | legacy])

    assert inventory.encrypted == 1
    assert inventory.unreadable == []

    assert Content.inventory(ctx.root, %{config | encryption_keys: %{}}).unreadable == [
             "coding/checkpoints/example.term"
           ]
  end

  test "offline migration and rotation include legacy images and output", ctx do
    config = %{
      ctx.config
      | encryption_key_id: "old",
        encryption_keys: %{"old" => :binary.copy(<<2>>, 32)}
    }

    files =
      for family <- ["attachments", "output"] do
        file = Path.join(ctx.root, "native/legacy/#{family}/content.bin")
        File.mkdir_p!(Path.dirname(file))
        File.write!(file, <<0, 255, 1>> <> "private #{family}")
        {file, File.read!(file)}
      end

    assert length(Content.inventory(ctx.root, config).plaintext) == 2

    assert {:error, :migration_requires_stopped_runtime_and_key} =
             Content.migrate(ctx.root, config)

    migrate_offline(ctx.root, config, 3)
    assert Content.inventory(ctx.root, config).encrypted == 3

    rotated = %{
      config
      | encryption_key_id: "new",
        encryption_keys: Map.put(config.encryption_keys, "new", :binary.copy(<<3>>, 32))
    }

    migrate_offline(ctx.root, rotated, 3)
    new_only = %{rotated | encryption_keys: Map.take(rotated.encryption_keys, ["new"])}

    for {file, bytes} <- files do
      encoded = File.read!(file)
      assert Content.encrypted?(encoded)
      assert {:ok, ^bytes} = Content.decode(encoded, new_only)
      assert {:error, _} = Content.decode(encoded, config)
    end
  end

  defp migrate_offline(root, config, count) do
    encoded = {root, config} |> :erlang.term_to_binary() |> Base.encode64()

    script = """
    {root, config} = :erlang.binary_to_term(Base.decode64!(#{inspect(encoded)}))
    {:ok, #{count}} = Ouroboros.Audit.Content.migrate(root, config)
    """

    paths = Enum.map(:code.get_path(), &List.to_string/1)

    {output, status} =
      System.cmd(
        System.find_executable("elixir"),
        ["--erl", "+S 2"] ++ Enum.flat_map(paths, &["-pa", &1]) ++ ["-e", script],
        stderr_to_stdout: true
      )

    assert status == 0, output
  end

  test "private environment policy is optional and required mode validates identity and keys",
       ctx do
    assert Config.from_environment!(ctx.root, %{}).mode == :standard
    policy = Path.join(ctx.root, "policy.json")
    File.mkdir_p!(ctx.root)
    File.write!(policy, JSON.encode!(%{"mode" => "required", "root" => ctx.config.root}))
    File.chmod!(policy, 0o600)

    assert_raise ArgumentError, ~r/required_mode_needs_encryption/, fn ->
      Config.from_environment!(ctx.root, %{"OUROBOROS_AUDIT_CONFIG" => policy})
    end

    document = %{
      "mode" => "required",
      "root" => ctx.config.root,
      "encryption_key_id" => "test",
      "encryption_keys" => %{"test" => Base.encode64(:binary.copy(<<0>>, 32))},
      "identities" => [
        %{"id" => "alice", "token_sha256" => sha("test-identity"), "roles" => ["operator"]}
      ]
    }

    File.write!(policy, JSON.encode!(document))
    config = Config.from_environment!(ctx.root, %{"OUROBOROS_AUDIT_CONFIG" => policy})
    assert config.mode == :required
    refute inspect(Config.public(config)) =~ sha("test-identity")
    refute Config.revision(config) == Config.revision(%{config | identities: []})
    File.chmod!(policy, 0o644)

    assert_raise ArgumentError, ~r/private_policy_file/, fn ->
      Config.from_environment!(ctx.root, %{"OUROBOROS_AUDIT_CONFIG" => policy})
    end
  end

  test "time filters normalize offsets and fractional seconds" do
    rows = [%{"at" => "2026-09-07T10:00:00.123456Z", "stream_id" => "test", "seq" => 1}]
    params = %{"since" => "2026-09-07T12:00:00+02:00", "until" => "2026-09-07T10:00:01Z"}
    assert :ok = Ouroboros.Audit.Query.validate(params)
    assert Ouroboros.Audit.Query.select(rows, params).total == 1

    assert {:error, :invalid_audit_query} =
             Ouroboros.Audit.Query.validate(%{"since" => "yesterday"})
  end

  test "metadata policy withholds unknown fields; telemetry contains no prompt or output", ctx do
    assert Ouroboros.Audit.Record.capture(
             %{"encoding" => "base64", "data" => Base.encode64("sensitive binary content")},
             :redacted
           ) == %{"withheld" => "binary_redaction_not_supported"}

    record =
      Record.build(
        %{
          "unrecognized" => "secret phrase",
          "request" => %{"prompt" => "secret phrase"},
          "tool" => "write",
          "arguments" => %{"content" => "secret phrase"}
        },
        "tool_dispatch",
        ctx.stream,
        1,
        Journal.seed(),
        %{ctx.config | capture: :metadata}
      )

    refute JSON.encode!(record) =~ "secret phrase"
    assert record["tool"] == "write"

    full =
      Record.build(
        %{"request" => "secret phrase", "model" => "test-model"},
        "model_call",
        ctx.stream,
        1,
        Journal.seed(),
        ctx.config
      )

    encoded = OTLP.payload([full], ctx.config) |> JSON.encode!()
    refute encoded =~ "secret phrase"
    assert encoded =~ "test-model"
  end

  test "offline bundles reject duplicates, unlisted files and path traversal", ctx do
    store = start_supervised!({Store, name: nil, config: ctx.config})
    {:ok, _} = Store.append(ctx.stream, "model_call", %{"request" => "hello"}, store)
    assert {:ok, snapshot} = Store.snapshot([], store)
    destination = Path.join(ctx.root, "bundle")
    {:ok, _} = Bundle.write(snapshot, destination)
    assert {:ok, _} = Bundle.verify(destination)
    File.write!(Path.join(destination, "unlisted"), "hidden")
    assert {:error, :audit_bundle_verification_failed} = Bundle.verify(destination)
    File.rm!(Path.join(destination, "unlisted"))
    modified = Map.update!(snapshot.manifest, "files", &(&1 ++ &1))
    File.write!(Path.join(destination, "manifest.json"), Journal.canonical_json(modified))
    assert {:error, :audit_bundle_verification_failed} = Bundle.verify(destination)

    modified =
      put_in(snapshot.manifest, ["files"], [
        %{"path" => "../secret", "bytes" => 0, "sha256" => sha("")}
      ])

    File.write!(Path.join(destination, "manifest.json"), Journal.canonical_json(modified))
    assert {:error, :audit_bundle_verification_failed} = Bundle.verify(destination)
  end

  defp sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end
