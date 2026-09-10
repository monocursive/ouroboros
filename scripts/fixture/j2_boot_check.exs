# Full application boot against a FRESH COPY of the pre-J2 synthetic data directory.
# Use the companion gate script so the writer node is never adopted on the reader.
root = System.fetch_env!("J2_FIXTURE_COPY")

manifest =
  Path.expand("../../test/support/j2_fixture/SHA256.json", __DIR__)
  |> File.read!()
  |> JSON.decode!()

for {relative, expected} <- manifest do
  actual = :crypto.hash(:sha256, File.read!(Path.join(root, relative))) |> Base.encode16(case: :lower)
  unless actual == expected, do: raise("captured baseline checksum differs: #{relative}")
end

originals =
  Path.wildcard(Path.join(root, "**/*.term"))
  |> Map.new(fn path -> {path, :crypto.hash(:sha256, File.read!(path))} end)

for {key, leaf} <- [interactive_storage: "interactive", effect_ledger_storage: "effect-ledger"] do
  Application.put_env(
    :ouroboros,
    key,
    {Ouroboros.Storage.DurableFile, path: Path.join(root, leaf)}
  )
end

{:ok, _} = Application.ensure_all_started(:ouroboros)

if Enum.any?(Application.started_applications(), fn {app, _, _} -> app == :jido_harness end),
  do: raise("retired session dependency is still running")

for tag <- Ouroboros.Storage.SessionMigration.legacy_structs() do
  unless :code.which(tag) == :non_existing, do: raise("retired module is still on code path: #{tag}")
end

sessions = Ouroboros.Interactive.Store.list()
expected = ~w(idle running queued awaiting_approval terminal resumed forked removed_provider)

unless Enum.sort(Enum.map(sessions, & &1.id)) ==
         Enum.sort(Enum.map(expected, &("j2-fixture-" <> &1))),
       do: raise("J2 corpus session loss")

for session <- sessions do
  kind = String.replace_prefix(session.id, "j2-fixture-", "")
  unless session.runtime_id == "legacy-runtime-#{kind}", do: raise("runtime identity changed")

  unless session.provider_session_id == "native-conversation-#{kind}",
    do: raise("conversation identity changed")

  unless session.runtime_cursor == 1 and session.runtime_generation == nil,
    do: raise("legacy cursor changed")

  unless session.usage.total_tokens == 10, do: raise("usage changed")
  [event] = session.events

  unless event.payload["legacy"].request.cwd != nil and
           not is_struct(event.payload["legacy"].request),
         do: raise("legacy request was not normalized")

  unless event.payload["legacy"].event.type == :session_started, do: raise("nested event lost")
  unless event.payload["legacy"].approval.decision == :deny, do: raise("nested approval lost")

  for {_id, turn} <- session.turns do
    unless turn.runtime_turn_id == turn.harness_turn_id,
      do: raise("historical turn identity lost")
  end
end

resumed = Enum.find(sessions, &(&1.id == "j2-fixture-resumed"))

unless resumed.cursor == 41 and resumed.sequence_offset == 40 and resumed.resumes == 1,
  do: raise("resumed public offset lost")

removed = Enum.find(sessions, &(&1.id == "j2-fixture-removed_provider"))

unless Ouroboros.Interactive.State.removed_provider(removed) == :claude,
  do: raise("removed provider no longer readable")

{:ok, entries} = Ouroboros.Agent.EffectLedger.list(limit: 500)
unless length(entries) == 1, do: raise("J2 corpus ledger loss")
[entry] = entries

unless entry.error.classification |> elem(1) |> Map.get(:category) == :validation,
  do: raise("nested ledger error changed")

for {path, hash} <- originals do
  unless :crypto.hash(:sha256, File.read!(path)) == hash,
    do: raise("history read rewrote #{path}")
end

unless Path.wildcard(Path.join(root, "**/*quarantined*")) == [],
  do: raise("valid corpus quarantined")

IO.puts("J2 BOOT: 8 sessions, 1 ledger error, no rewrite, no quarantine")
:ok = Application.stop(:ouroboros)
