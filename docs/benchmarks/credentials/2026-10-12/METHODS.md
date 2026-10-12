# Credential workflow follow-up

This is a supplement to the sealed startup benchmark committed at `cf98e6a1`.
Its existing results and archive bytes remain unchanged. The follow-up uses
the same final Ouro runtime binaries on the provisioned VPS and Pi. There
are no runtime, isolation, observer, host-kernel, filesystem, or budget changes.
The native Mac lane was unavailable in that benchmark and remains outside this
credential experiment.

## Frozen online work

The copied native harness, task fixtures, independent checks, workflow fixture,
and exporter are byte-identical to the saved startup versions. The protocol
manifest binds their hashes and the implementation commit. Each Linux host
runs all three small tasks twice for Claude Code, OpenCode, and Codex, then
one inventory workflow per client: 21 calls per host, 42 total. The original
seeded full schedule is generated and filtered to Ouro, retaining original
sequence numbers. Every failure is retained; successful pilots do not count
as scored runs, and scored failures are not selectively retried.

Client versions, models, prompts, model flags, turn limits, 240-second wall
budget, fresh repositories/state, and hidden checks match the saved benchmark.
Read-only grants cover the same installed client/library objects. The new
benchmark bin directory uses direct links to those objects, avoiding an
unmounted intermediate directory encountered in the first pilot.

The credential transport is the intentional change. Claude/OpenCode map
`OURO_VAULT_API` to `ANTHROPIC_API_KEY` inside the contained shell. The
supervisor reads the existing operator key from a separate private file and
substitutes only `x-api-key` at `https://api.anthropic.com`. Codex uses the
existing authorized login's access token as a vault source, restricted to
`https://chatgpt.com`, with `authorization` and `Bearer ` placement. It receives
an external-token auth file containing an access placeholder, non-secret
identity template, routing account metadata, and an empty refresh token. The
template and `chatgptAuthTokens` mode match the already exercised OpenShell
adapter. An earlier pilot using empty identity fields in ordinary `chatgpt`
mode failed authentication and is retained as an adapter diagnostic.

The real ID/refresh tokens are neither staged nor passed to Codex. Ouro has
no OAuth refresh worker; this experiment establishes current access-token
compatibility, not future refresh reliability. The historical OpenShell
expired-token/401/recovery diagnostic remains relevant and is not recast as
reliable long-term refresh.

The frozen Codex transport is left unchanged. WebSocket retries and any HTTPS
fallback remain visible in the diagnostic counts and descriptive elapsed time;
the vault lane does not get a special flag to hide unsupported transports.

## Independent exposure checks

Each scored client run records a contained check that the credential source
is unreadable and the generated value is a placeholder. A supervisor-side
watcher samples descendant readable process environments/argv and regular
files in the workspace/vendor state every 100 ms. It compares against the
real operator key and current OAuth access/ID/refresh tokens without storing
their values. Raw stdout/stderr are checked before redaction. Reports retain
sample counts, unreadable environment counts, and hit categories.

These are bounded samples, not inspection of arbitrary process memory,
every instant, every file, or encrypted wire bytes. Unreadable process
environments are counted rather than called clean. Files over 1 MiB and
symlinks are skipped. An allowed upstream can reflect a secret in a response;
vaulting cannot prevent that. The normal observer records its declared
syscall coverage, not arbitrary application payloads.

All scored receipts and referenced journals are checked for enforced
containment, strict evidence, attached `linux-closed-v1` observation, active
coverage classes, empty-tree settlement, cleanup, vault `never_staged` rows,
and the TLS credential injection declaration. These checks include failed
coding calls rather than only successful tasks. Exported files exclude
private config/state/auth homes, credential sources and CA private material,
and undergo exact-value and credential-pattern scans.

## Live boundary and startup fixtures

Each host runs eight synthetic-token boundary checks: successful approved
origin substitution, wrong origin port, wrong header, prior-attempt
placeholder, plaintext without opt-in, missing source, hidden child source,
and source rotation for the next attempt. The fixture servers record token
equality booleans rather than token values. Local HTTP is explicitly allowed
only for these fake-token fixtures; real provider runs use HTTPS with normal
upstream certificate validation.

A separate synchronized lifecycle fixture rotates then deletes the source
while one attempt remains alive. It records which token the approved server
actually receives, followed by a missing-source refusal and a new attempt
using the replaced source. It also tests another URL path on the same allowed
origin. These are behavior observations, including limitations, rather than
claims that static snapshot semantics provide live revocation or path binding.

A separate no-op experiment uses the `agent` profile with the same fixture
network destinations and fresh launch/state preparation, comparing a raw
environment credential with a vault credential. Three warmups per arm are
retained, followed by 30 pairs in randomized order, seed 20261012. Every
attempt has a receipt and journal; failures would remain recorded and would
withhold the corresponding pair. Paired median differences and a seeded
bootstrap 95% interval are descriptive for this host/session. They do not
replace the earlier tool-profile no-op benchmark or establish a universal
startup ranking.

The exposure watcher runs only during client tasks, not these offline startup
trials. Online elapsed time includes provider variability, client actions,
and independent sampling overhead. Historical environment/staged calls are
used for compatibility comparison, not a contemporaneous causal latency test.
Competitor credential results are reused with their source hashes; competitors
do not receive an unperformed exposure-test pass.

## Preservation

Pilot folders remain in the export with explicit exclusion from scored work.
Both host exports contain original/sanitized file hashes and exact installed
harness snapshots. Archived evidence, final manifests, source/binary bindings,
and a deterministic offline analysis script make the results reusable. This
follow-up does not establish new reference-host conformance or release freeze.
