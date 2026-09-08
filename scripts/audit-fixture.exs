# Run with: mix run --no-start scripts/audit-fixture.exs
# Cross-language evidence fixture. Contains invented data and no credentials.
alias Ouroboros.Provider.Native.Journal
alias Ouroboros.Audit.{Bundle, Config, Record}
destination = Path.expand("../test/support/audit_bundle", __DIR__)
stream = Journal.digest("cross-language-audit-fixture")
config = Config.new!(mode: :local, capture: :full, root: "/fixture-only", writer_id: "fixture-node", organization: "example")
{records, _} = Enum.map_reduce([
  {"session_opened", %{"session_id" => "example-session", "actor_id" => "example-operator"}},
  {"model_call", %{"ledger_effect_id" => "example-model", "turn_id" => "example-turn", "model" => "example:model", "request" => %{"temperature" => 1.0e-4, "messages" => [%{"role" => "user", "content" => "Write 42 to answer.txt"}]}}},
  {"model_result", %{"ledger_effect_id" => "example-model", "turn_id" => "example-turn", "chunks" => [["text", "42"]], "usage" => %{"input_tokens" => 5, "output_tokens" => 1}}},
  {"session_closed", %{"status" => "closed"}}
] |> Enum.with_index(1), Journal.seed(), fn {{kind, fields}, seq}, previous ->
  record = Record.build(fields, kind, stream, seq, previous, config)
  body = record |> Map.drop(["hash", "prev"]) |> Map.merge(%{"at" => "2020-01-01T00:00:00.000000Z", "node" => "fixture@offline", "runtime_version" => "fixture", "elixir_version" => "fixture"})
  record = Record.seal(body, previous)
  {record, record["hash"]}
end)
bytes = Enum.map_join(records, &(Journal.canonical_json(&1) <> "\n"))
path = "streams/#{stream}/00000000000000000001.ndjson"
manifest = %{"version" => 1, "organization" => "example", "created_at" => "2020-01-01T00:00:00Z", "scope" => "selected_streams", "streams" => [%{"stream_id" => stream, "through" => length(records), "head" => List.last(records)["hash"]}], "files" => [%{"path" => path, "bytes" => byte_size(bytes), "sha256" => :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)}], "integrity" => "self_contained_requires_external_trust_anchor"}
# Public test-only signing seed. Never use this fixture key for custody.
{public, private} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<42>>, 32))
receipts = Map.new(records, fn record ->
  receipt = Map.take(record, ~w(organization stream_id seq hash)) |> Map.merge(%{"version" => 1, "key_id" => "fixture-key", "accepted_at" => "2020-01-01T00:00:01Z", "retain_until" => "2030-01-01T00:00:00Z"})
  envelope = %{"receipt" => receipt, "signature" => :crypto.sign(:eddsa, :none, Journal.canonical_json(receipt), [private, :ed25519]) |> Base.encode64()}
  {"receipts/#{record["hash"]}.json", Journal.canonical_json(envelope)}
end)
files = Map.put(receipts, path, bytes)
manifest = Map.put(manifest, "files", Enum.map(files, fn {path, bytes} -> %{"path" => path, "bytes" => byte_size(bytes), "sha256" => :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)} end) |> Enum.sort_by(& &1["path"]))
if File.exists?(destination), do: File.rm_rf!(destination)
{:ok, result} = Bundle.write(%{manifest: manifest, files: files}, destination)
File.write!(Path.expand("../test/support/audit-trusted-keys.json", __DIR__), Journal.canonical_json(%{"fixture-key" => Base.encode64(public)}))
IO.puts(result.manifest_sha256)
