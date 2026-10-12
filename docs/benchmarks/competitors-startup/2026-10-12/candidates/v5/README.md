# Candidate v5: unguarded regular-file hints superseded

Directory timestamps may coalesce very recent type changes. The final v6 code uses regular-file hints only on known local ext-family/tmpfs directories whose change second predates the current coarse-clock second; recent directories, unknown filesystems and failed clock/filesystem readbacks retain the original stat path. A new regression covers this decision. All v5 Ouro timing/client data remains retained and excluded from the final Ouro selection.

Competitor/direct client calls execute no Ouro code and are reused unchanged with explicit source/hash selection. New timing matrices still rerun every interleaved arm. The guarded Ouro client rerun executes the Ouro positions from the unchanged full seeded schedule, retaining every task, model, limit and check.
