# Fresh production-only VM, direct read-only historical-data smoke. No application starts.
# MIX_BUILD_PATH=_build/j3-prod-clean MIX_ENV=prod mix run --no-start --no-compile \
#   scripts/fixture/j3_production_check.exs
# Add --preload-modules for the independent fully preloaded VM. The build path must
# contain a clean production build; neither fixture strings nor test modules seed atoms.

fixture = Path.expand("../../test/support/j3_fixture", __DIR__)
canonical = Path.join(fixture, "data")

root =
  Path.join(
    System.tmp_dir!(),
    "ouro-j3-production-#{System.pid()}-#{System.unique_integer([:positive])}"
  )

manifest = fixture |> Path.join("SHA256.json") |> File.read!() |> JSON.decode!()

try do
  File.cp_r!(canonical, root)

  unless Mix.env() == :prod, do: raise("production Mix environment required")

  for path <- :code.get_path() do
    path = to_string(path)
    if String.contains?(path, "/test/"), do: raise("test code path present: #{path}")

    for beam <- Path.wildcard(Path.join(path, "*Jido*.beam")),
        do: raise("retired executable on code path: #{beam}")
  end

  started_before = Application.started_applications() |> Enum.map(&elem(&1, 0)) |> Enum.sort()

  closure = fn recurse, app, seen ->
    if MapSet.member?(seen, app) do
      seen
    else
      case Application.load(app) do
        :ok -> :ok
        {:error, {:already_loaded, ^app}} -> :ok
        other -> raise("application metadata unavailable: #{inspect({app, other})}")
      end

      optional = Application.spec(app, :optional_applications) || []

      Enum.reduce(
        Application.spec(app, :applications) || [],
        MapSet.put(seen, app),
        fn dependency, acc ->
          absent = :code.where_is_file(Atom.to_charlist(dependency) ++ ~c".app") == :non_existing
          if dependency in optional and absent, do: acc, else: recurse.(recurse, dependency, acc)
        end
      )
    end
  end

  applications = closure.(closure, :ouroboros, MapSet.new())

  for app <- applications do
    if Atom.to_string(app) in ~w(jido jido_action jido_signal jido_ai jido_harness),
      do: raise("retired package in production graph: #{app}")
  end

  hashes = fn data_root ->
    Map.new(Path.wildcard(Path.join(data_root, "**/*.term")), fn path ->
      {Path.relative_to(path, data_root),
       Base.encode16(:crypto.hash(:sha256, File.read!(path)), case: :lower)}
    end)
  end

  unless hashes.(root) == manifest, do: raise("fixture bytes do not match the frozen manifest")
  unless hashes.(canonical) == manifest, do: raise("canonical fixture bytes changed")
  files_before = Path.wildcard(Path.join(root, "**/*"), match_dot: true)

  # Keys are the current checkpoint contracts, independent of fixture atom text.
  index_key = {:ouroboros, :interactive_sessions, 1}

  keys = [
    {"interactive", index_key},
    {"effect-ledger", {:ouroboros, :agent_effect_ledger, 1}},
    {"grants", {:ouroboros, :agent_grants, 1}},
    {"permissions", {:ouroboros, :control_permissions, 1}},
    {"policy-promotion", {:ouroboros, :policy_promotion, 1}},
    {"capabilities", {:ouroboros, :capability_rollouts, 1}},
    {"forge-epochs", {:ouroboros, :forge_epoch, 1}},
    {"signing-journal", {:ouroboros, :signing_journal, 1}}
  ]

  read = fn leaf, key ->
    case Ouroboros.Storage.DurableFile.get_checkpoint(key, path: Path.join(root, leaf)) do
      {:ok, value} -> value
      other -> raise("production checkpoint decode failed for #{leaf}: #{inspect(other)}")
    end
  end

  # The first decode exercises DurableFile's own preload from a lazy VM. There is no
  # preceding read of atoms.txt and no module choice derived from checkpoint contents.
  records = Map.new(keys, fn {leaf, key} -> {leaf, read.(leaf, key)} end)
  field = fn value, name -> Map.fetch!(value, String.to_existing_atom(name)) end
  index = Map.fetch!(records, "interactive")
  unless field.(index, "version") == 2, do: raise("unexpected interactive index version")
  ids = field.(index, "ids")
  unless length(ids) == 8, do: raise("session index count changed")

  sessions =
    Enum.map(ids, fn id ->
      read.("interactive", {index_key, :session, 2, id}) |> Map.fetch!(id)
    end)

  unless map_size(records) + length(sessions) == 16, do: raise("checkpoint count changed")

  # This read is intentionally after production decoding. It can find missing names,
  # never create them. The tested build must supply its own finite retired vocabulary.
  atom_names = fixture |> Path.join("atoms.txt") |> File.read!() |> String.split("\n", trim: true)

  missing =
    Enum.filter(atom_names, fn name ->
      try do
        String.to_existing_atom(name)
        false
      rescue
        ArgumentError -> true
      end
    end)

  unless missing == [], do: raise("production-only missing atoms: #{inspect(missing)}")

  for name <- atom_names, String.starts_with?(name, "Elixir.Jido.") do
    atom = String.to_existing_atom(name)

    unless :code.which(atom) == :non_existing and :code.is_loaded(atom) == false,
      do: raise("retired module is executable: #{name}")
  end

  for stored <- sessions do
    id = field.(stored, "id")
    {:ok, session} = Ouroboros.Storage.SessionMigration.decode(id, stored)
    [event] = field.(session, "events")
    legacy = field.(event, "payload")["j3"]
    signed = legacy["signed_manifest"]
    wire = legacy["signed_manifest_wire"]

    unless Ouroboros.Upgrade.Wire.load(wire) === signed,
      do: raise("old signed Wire representation changed: #{id}")

    unless Ouroboros.Upgrade.Wire.load(Ouroboros.Upgrade.Wire.dump(signed)) === signed,
      do: raise("signed manifest round-trip changed: #{id}")

    signature = field.(field.(signed, "signature"), "value")

    unless :crypto.verify(
             :eddsa,
             :none,
             Ouroboros.Wasm.Artifact.signing_payload(signed, "j3-fixture-signer"),
             signature,
             [legacy["public_key"], :ed25519]
           ),
           do: raise("historical signed manifest signature failed: #{id}")

    history = legacy["keyed_history"]

    unless map_size(history) == 2 and Enum.sort(Map.values(history)) == ["plain", "retired"],
      do: raise("historical map key identities collided: #{id}")
  end

  # Inspect trusted loaded modules' compile metadata only after the lazy decode.
  # A test support module can accidentally supply atoms even with no /test/ ebin path.
  production_modules = Application.spec(:ouroboros, :modules) || []

  for {module, _path} <- :code.all_loaded(),
      module in production_modules,
      function_exported?(module, :module_info, 1) do
    source = module.module_info(:compile) |> Keyword.get(:source, ~c"") |> to_string()

    if String.contains?(source, "/test/"),
      do: raise("test module loaded: #{module} from #{source}")
  end

  started_after = Application.started_applications() |> Enum.map(&elem(&1, 0)) |> Enum.sort()
  unless started_after == started_before, do: raise("historical reads started applications")
  unless Process.whereis(Ouroboros.Supervisor) == nil, do: raise("runtime services were started")
  unless hashes.(root) == manifest, do: raise("history read changed fixture bytes")
  unless hashes.(canonical) == manifest, do: raise("canonical fixture bytes changed")

  unless Path.wildcard(Path.join(root, "**/*"), match_dot: true) == files_before,
    do: raise("history read added, renamed or quarantined fixture files")

  IO.puts(
    "J3 PRODUCTION: 16 checkpoints, #{length(atom_names)} known atoms, 8 historical signatures valid, no repository test/Jido BEAMs, no services started, no fixture writes"
  )
after
  File.rm_rf!(root)
end
