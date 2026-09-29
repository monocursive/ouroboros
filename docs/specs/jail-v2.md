# Jail v2: adoption, parity and closeout specification

Status: implementation specification, revised 2026-09-29.
Implementation status and measured evidence are tracked in
[the execution report](../benchmarks/jail/README.md); this specification
alone makes no completion claim. This revision records the plan
of record for the six milestones J6–J11, derived from the fifth security
audit ([security-audit-2026-09-27-2.md](../security-audit-2026-09-27-2.md),
findings C1–C11), the same-host benchmark against greywall 0.3.7
([benchmark-2026-09-28-greywall.md](../benchmark-2026-09-28-greywall.md))
and [the gap analysis](../greywall-gap-analysis-2026-09-28.md) it fed.

Parent: [North star](../../north-star.md) and
[Jail v1](jail-v1.md) (revision 23). Jail v1 remains the governing
specification for everything it specifies; this document extends it with
new milestones and amends it only where a section below says so
explicitly. Nothing here weakens a v1 invariant: the threat model (v1
§2), the closed set (v1 §11.2), the evidence semantics of the milestone-1 wire records and
the honest-evidence rules (v1 §13) all survive unchanged. There is one implementation, one set of current schemas, and no legacy
compatibility branch. This is pre-release software: update the existing
records, consumers, fixtures and validators together. Version numbers in
historical evidence identify what actually ran; they are not an obligation
to retain an obsolete implementation.

Normative words: **must** is a release gate, **initial** is a tunable
default that must be recorded, and **candidate** is unproved until the
named evaluation passes. Greywall is not integrated, vendored or
depended on anywhere in this plan; D8 already evaluated it as a backend
and disqualified it by named failures
([backend-evaluation.md](jail-v1/backend-evaluation.md)). Comparisons inform measurements, not the security contract.

## 1. Outcome and scope

Jail v2 ships, in dependency order:

- **J6 — security closeout**: every fifth-audit finding fixed and
  verified live on the reference host, before any marketing surface
  points at the comparison.
- **J7 — distribution and profiles**: signed release artifacts, a
  non-interactive installer, a Homebrew tap, and bundled launch
  profiles for the common agents and toolchains, validated by recorded
  compatibility rows.
- **J8 — `ouro-jail learn`**: a least-privilege policy generator whose
  every proposal cites the receipt of the run that observed the need.
- **J9 — network parity**: a SOCKS5 listener in the bridge, origin-bound
  allowlists for both listeners (closing C1's class), and credential
  vaulting without staging real secrets in child files or environment.
  An authorized upstream can still reflect a secret; vaulting cannot
  promise that the child will never learn it.
- **J10 — live supervision**: `ouro-jail tail`, and opt-in command
  deny-rules enforced at the exec gate.
- **J11 — the macOS execution lane**: Seatbelt containment with the
  same bridge, receipts and profiles, with every unsupported mechanism
  named honestly in the receipt.

Excluded: agent protocols, ledger/fleet features (governed by
[Managed teams v1](managed-teams-v1.md)), PTY allocation, a web
dashboard (J10 is a terminal and JSON view; a dashboard is a consumer of
the same stream, not a v2 deliverable), TUN-based transparent proxying
(v1 §10's userspace bridge is the design; TUN is a J9 non-goal), and any
content-based control claimed as containment (§7.2).

Success metrics, recorded in `docs/benchmarks/` at each milestone and
re-measured with the vendored scripts (§13): time-to-first-sandboxed
agent under ten minutes from install; the jail's own overhead on the
reference host within 2x of J5's phase budgets, defined by K17 below (the
2026-09-28 whole-invocation baseline of 124–147 ms is informational); every profiled agent with a
recorded A-row; zero open High/Medium audit findings at release.

## 2. Milestones and order

| Milestone | Delivers | Why in this position |
|---|---|---|
| J6 | Fifth-audit fixes C1–C4 (+ C5–C10 hygiene) | Close demonstrated failures first; audit fix directions still require review and adversarial regression tests. |
| J7 | Release pipeline, installer, tap, bundled profiles, compatibility rows | Unblocks adoption measurement for every later milestone; pure tooling plus data. |
| J8 | `ouro-jail learn` | Reuses only J5 machinery (observer, receipts); no dependency on J9–J11. |
| J9 | SOCKS5, origin binding, credential vaulting | Add transports and optional vaulting after the shared destination checks ship in J6. |
| J10 | `ouro-jail tail`, command deny-rules | Presentation plus one exec-gate hook; lands after the event stream is final (J9). |
| J11 | macOS execution | Largest surface; benefits from J7 distribution and J8–J10 parity existing on Linux first. |

Each milestone must leave a buildable tree, a green CI run (`contracts`,
`rust`, `conformance`), and its acceptance rows (§11) computed from the
suite's own output the way J5's acceptance map does.

## 3. J6 — security closeout (amends v1 §§6.2, 9.1, 9.2, 10, 11.2)

Every item below carries its detailed statement and fix direction in the
fifth audit; this section makes them normative.

### 3.1 C1 groundwork: network rules

The allowlist grammar gains nothing; its **meaning** is tightened (the
breaking change is deliberate and must be called out in the release
notes):

1. A host-only allow entry admits **only port 443**. Ports 80 and all
   others require an explicit `host:port` entry. Existing host-only
   entries resolve to port 443. The program cannot infer whether an old
   configuration intended port 80. An attempted port 80 connection is
   denied; documentation and diagnostics say to add an explicit port.
2. **Origin binding** (mechanism in §6.2): for every CONNECT tunnel on
   either listener, the bridge holds the upstream connection closed
   until the client's first flight identifies the origin, and the
   identified origin must match the authorized target under the shared
   normalization (v1 network-rules.md). No match, no origin, or a
   timeout (initial 5 s, recorded) closes the tunnel with a `proxy.deny`
   event whose reason is `origin_mismatch`, `origin_unverified` or
   `origin_timeout`.
3. Network evidence names the actual verification: `http_host`,
   `tls_sni`, `mitm_http_host` or `explicit_ip`. It must not collapse
   these into an unqualified application-origin enforcement claim.
   Each allowed result records its verified target; numeric grants
   assert an address and port, not an observed DNS origin.

### 3.2 C2 — `none` and the trusted layers

`check_config_isolation` (v1 §6.2, as added by the fourth audit) models
child visibility from the policy's declared roots, which is wrong for
`none`. Under `--profile none`, a run refuses with `unsafe_config_path`
at resolving when `<config>/config.toml` or any
`<config>/launch/*.toml` exists, naming each file found and remediation
"move the trusted configuration aside, or run contained". The
supervisor-held config snapshot (read once, identity-pinned, live file
never re-read) is the recorded future alternative and is **not** v2.

Security 2026-09-29 (sixth audit, F1, as corrected by its review): that
refusal cannot see files that do not exist yet, and an uncontained child
shares the operator's uid and the whole filesystem — the creation
variant planted a `config.toml` from a `none` run on a fresh
configuration directory and every later contained run loaded it as
trusted widening. Markers close that direction for the files the child
writes directly. They are written to the data directory **and** the
configuration directory, because `OURO_DATA_DIR` and `OURO_CONFIG_DIR`
are chosen independently and a run sharing either must see them:

- Before its target is released, an uncontained run writes a live marker
  `uncontained.<attempt id>.live` into both; a run that cannot write them
  refuses before release (`state_write_failed`).
- While any live marker exists — a `none` run in progress, or one that
  ended without settling — every run refuses each trusted file that
  exists (`config.toml`, a launch profile, a `--profile FILE` policy),
  however new: no trusted file can be dated while the child can still
  write (`unsafe_config_path`; the remediation names the marker and how
  to clear it once no such run is active).
- After the run's tree is gone the supervisor writes the settled marker
  `uncontained.epoch` (durable replacement through an exclusive,
  unpredictable temporary), first clearing what the child could have put
  in its way — a directory at the marker's path, the operator's own
  directory made unwritable — then removes its live marker. A settle that
  still fails keeps the live marker, so the failure fails closed, and is
  reported on stderr.
- Every later run refuses a trusted file whose ctime does not postdate
  the newest settled marker (`unsafe_config_path`, remediation "re-save
  it or remove it"); a settled marker that is not a regular file refuses
  the run (`unsafe_state_path`). Nothing of the run can order its writes
  after its own settled marker, and a contained run cannot reach the
  configuration directory or the state root, so it cannot re-save a
  planted file into trust.

Residual, documented — each is the same `none` opt-out that says the
child is the operator for the run's duration: a supervisor killed
outright during a `none` run leaves its live markers (fail closed) but a
child that also deleted them and left the settle unwritable (a full
disk) leaves no marker at all; a descendant that outlives the run's
teardown can still write; the child can forge or delete markers while
the run is live, so the concurrent-run refusal holds against accidents,
not against a hostile child; and anything the child left behind that
re-saves a trusted file later — a line in a shell rc file, a crontab
entry, a `systemd --user` timer — dates that file after the marker. The
markers bound what the child wrote directly, not what it arranged to
have written.

### 3.3 C3 — the binaries the supervisor executes

A new guard, `check_binary_isolation`, runs on every contained run
beside the other three: it refuses (`unsafe_state_path` semantics, key
`binaries`) any child-writable root that contains `current_exe()` or the
resolved backend (`resolved_bwrap`, v1 §6.2) — containment is
component-wise on the canonicalized binary paths, and the refusal names
both the binary and the root. The backend is additionally opened once at
resolution (`O_PATH`, no-follow, identity recorded as `(dev, ino, uid,
mode)`) and executed through that descriptor (`fexecve`); a
spawn-time identity mismatch refuses with `internal_error` at preparing
and never falls back to the pathname. `watch.rs`'s bootstrap execs the
same pinned descriptor. The receipt's platform record gains
`lifetime.native.details.backend_exec_by: "descriptor"`.

### 3.4 C4 — compat-ABI `clone3`

The narrowing filter refuses nr 435 with `ENOSYS` **before** the
architecture branch (the number is `clone3` on every ABI this build can
see; the native refusal's rationale — flags live in memory a filter
cannot read — applies unchanged to the compat spellings). `compat_special`
additionally classifies any foreign-arch `clone3` that still reaches a
successful exit as the open-ended `untraced_descendant` gap, never a
bounded `foreign_abi` interval. The i386 PoC from the fifth audit
(`int 0x80`, eax=435, `CLONE_UNTRACED`) becomes a conformance fixture:
with observation on it returns `ENOSYS` with no child on each profile;
the contained baseline with observation off returns `EPERM`.

### 3.5 Hygiene (C5–C10)

- **C5**: the resolv.conf sanitizer fails closed: a host file that
  cannot be read or parsed ships an empty nameserver file and records
  `resolv_sanitization: "failed_closed"` in the platform record — never
  the host file verbatim.
- **C6**: `refuse_pseudo_fs_grants` (v1 §9.1) runs over the workspace
  and explicit scratch sources exactly as over grants. The scan's
  accidental fail-closed on unreadable trees stays (it is correct), but
  the guard no longer depends on it; `--workspace /dev/shm` refuses
  `policy_widening`.
- **C7**: `alias_conflict` extends to submounts of a guarded tree on
  other devices, the walk `alias_identities` already performs. Translate
  child roots through their containing mounts too: a grant below an
  ancestor bind is still an alias. Receipt-copy destinations use containment
  in one direction; a parent shared with the workspace is not inside it.
- **C8**: `--profile FILE` is read through the hardened operator reader
  (no-follow, regular-file, bounded 256 KiB, identity on the
  descriptor).
- **C9**: after the protected-segment scan and before spawn, each
  scanned directory is re-stat'd; an mtime change re-runs the scan once,
  and a second change refuses with `missing_capability` (the
  `existing_and_root` claim must not cover a directory that changed
  under the scan).
- **C10**: `settimeofday` (164), `open_tree_attr` (467), `listns`
  (470) and `file_getattr`/`file_setattr` (468/469) join `DENY_EPERM`
  with the fifth audit's live results recorded in the evidence tables;
  the xattrat family (463–466) joins them (they reached the kernel in
  the audit's probe).

The scan is not an atomic filesystem snapshot. Directory metadata is
checked after scanning and again before spawn, including after the jail
creates its own placeholders. A concurrent external writer after the
last check remains outside this snapshot claim; do not describe the
check as eliminating every scan-to-mount race.

### 3.6 J6 exit criteria

Every item's live PoC from the fifth audit re-run against the fixed
tree and inverted (it now fails closed or refuses); the audit's
artifacts (`~/a5ws` scripts) are vendored as conformance fixtures; the
evidence tables and `milestone-1-freeze.toml` are regenerated
(`cargo xtask freeze`); a sixth audit pass over the fix code is recorded
before J7 ships.

## 4. J7 — distribution and bundled profiles

Publication is deferred by the operator: the release repository, Homebrew
tap and signing identity are undecided. Local packaging and installer
verification are in scope now. Never generate a production key or infer
a repository name to make a publication gate appear complete.

### 4.1 Release artifacts

A `release` CI workflow (cargo-dist or equivalent) produces, per tag:

- Tarballs for `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin` (the darwin targets execute only after J11;
  before that they support inspection and refuse execution as v1
  specifies).
- `SHA256SUMS` and a minisign signature over the manifest; once publication is configured, the public
  key is committed and pinned in the installer. Until then the local
  installer requires an explicit public key and artifact directory or
  HTTPS release base URL.
- Provenance: the workflow records the git revision, rustc version and
  build-inputs digest into the artifacts' `version` output, so
  `ouro-jail version` on an installed binary names exactly what ran.

### 4.2 The installer

`install.sh` is fetched from the release (and vendored in the repo):

- Non-interactive by default: `--yes`/`--prefix` flags; **it must never
  require a TTY** (the fifth audit's environment recorded greywall's
  installer failing exactly there). Confirmation is required only when
  overwriting an existing binary, and `--upgrade` makes it
  non-interactive after verifying the existing binary's version record.
- Verifies checksum and signature before install; on failure removes
  partial files and exits non-zero with a message naming the mismatched
  artifact.
- Installs to `~/.local/bin` by default, prints the PATH hint, and ends
  by running `ouro-jail version` as the install proof.
- Does not install, configure or ask for a backend, privileged helper,
  sysctl or service (v1's no-host-configuration rule applies to the
  installer too).

### 4.3 Homebrew tap

A future operator-selected tap with an `ouro-jail` formula built from the release
tarball and checksum. The formula installs no dependencies beyond
`bubblewrap` on Linux (v1 §6.2's backend resolution rule stands; the
formula does not vendor a backend).

### 4.4 Bundled launch profiles (amends v1 §12)

The bundled example files stop being dead examples and become **embedded
profiles** the binary resolves:

- `ouro-jail run --launch NAME` resolves NAME first as an operator file
  at `<config>/launch/NAME.toml` (which wins, with a receipt note that
  the operator file shadowed the bundled one), then as an embedded
  profile. Bundled profiles are compiled into the binary
  (`include_str!`), so no filesystem trust question exists for them.
- The initial set: `opencode`, `claude`, `codex`, `cursor`, `aider`,
  `goose`, `gemini`, `amp`, `cline`, `copilot`, `kilo`, `auggie`,
  `droid`, `pi`, plus toolchain fragments `node`, `python`, `go`,
  `rust`, `java`, `ruby`, `scm`, `containers`.
- A launch profile gains a `bundles = ["node", …]` key: each named
  fragment contributes filesystem grants, environment mappings and
  allowed hosts; fragments are data-only (no `jail`, no `profile`, no
  credentials), conflicts between fragments refuse at load, and the
  receipt lists every fragment that applied.
- Every bundled profile remains `experimental` (v1 §14.1) until an
  A-row records a real run of that agent at that version (§13,
  compatibility table). The
  historical OpenCode A01 row proves only its named build; re-run it
  before extending that support claim to the current build.
- `doctor --launch NAME` validates bundled profiles without any
  operator file present, and the doctor report names the resolution
  (`bundled` vs `operator file`).

### 4.5 J7 exit criteria

A clean VM (no rust toolchain) reaches a sandboxed `true` and then a
sandboxed `opencode` A01 run in under ten minutes using only the
installer and `--launch opencode`; signature verification failure is
tested by a corrupted-artifact fixture; every bundled profile has a
`doctor --launch` green path on the reference host and an A-row
(recorded) or an explicit `experimental, unrecorded` status in the
compatibility table.

## 5. J8 — `ouro-jail learn`

### 5.1 Command and semantics

```
ouro-jail learn [--launch NAME] [--profile NAME] [--workspace PATH]
  [--out FILE] [--adopt] [--min-hits N] [-- PROGRAM [ARG]...]
```

`learn` executes one ordinary contained run (the named profile, default
`tool`; observation forced on; strict evidence) and then derives a
**candidate policy** from the attempt's own records:

- **Reads**: each complete `open`/`openat` argument snapshot whose
  read-only operation failed outside workspace and scratch in the
  closed view (`ENOENT`/`EACCES`/`EPERM` inside the sandbox) is a candidate only when the native path is absolute, untruncated and
  unambiguously resolved, and a bounded no-follow host lookup confirms
  the exact object exists and the contained backend permits such a grant.
  Pseudo-filesystem paths and aliases remain unresolved, never proposed.
  Propose that object, never its parent tree;
  missing/noncanonical/ambiguous paths are reported without grants, de-duplicated, `--min-hits`
  (initial 1) filtering noise.
  `openat2` memory-sourced flags and missing interpreter inference do
  not produce grants. A host lookup confirms existence at that time;
  it does not establish which inode a previous failed syscall needed.
- **Network**: every proxy-source denial event with reason `host_not_allowed`
  contributes its normalized destination as an `allow` proposal. Denied
  destinations of other reasons are never proposed; they stay in the run's
  own trace journal.
- **Execs**: copy the observed exec fields into the proposal's notes,
  including explicit unavailable digests. Do not infer interpreter,
  library, environment or filesystem grants from an executable name.
  A closed-set coverage summary is not a complete inventory of reads;
  successful reads and memory-sourced `openat2` flags are not learning inputs.
- **Writes**: denied writes outside the workspace are **reported as a
  denied-writes list and never proposed as grants**. Include read-only
  filesystem refusals (`EROFS`), which the audit contract records under the
  original filesystem operation rather than `fs.deny`. Preserve that evidence
  meaning; a failed lookup (`ENOENT`) alone is not proof of a policy denial.
  The dangerous direction is never auto-widened.

The output is a proposal document, schema `ouro.jail.learned-policy/1`
(§10), containing the proposals, the denied-writes report, and mandatory
provenance: attempt id, receipt digest, event counts per class, the
coverage summary of the learning run, and the ouro-jail revision. It is
written `0600`, operator-owned, to `<config>/learned/<attempt>.toml` (or
`--out`).

### 5.2 Adoption

Learned files are never loaded implicitly. `--adopt` appends the
proposals to `<config>/config.toml` atomically (temp file,
fsync, rename — the receipt-persistence discipline), each proposal under
a marker comment `# adopted from attempt <id> (receipt <digest>)`,
after printing the exact replacement configuration and requiring interactive confirmation on
a TTY (refusing without one). The next run reads them as ordinary
operator configuration — which is to say: adopted grants are trusted
because the operator adopted them, and every later receipt carries them
like any operator grant.

### 5.3 Honesty rules

A learned policy describes **one observed run**, not the program's
needs; the output says so and the provenance digest makes the claim
checkable. Proposals are grants (widening): `learn` never writes to
anything the operator did not name, and the `--adopt` replacement is the
operator's review. Learning runs under a contained profile only — never
`none`.

### 5.4 J8 exit criteria

For three fixture programs with known needs (a missing read-only
file, a tool reading a data directory, an HTTP client to two hosts),
`learn` proposes exactly the known grant set, cites the right receipt
digest, refuses to propose denied writes, and `--adopt` produces a
config that runs the program successfully; an opencode run records only the subset its events justify. K-rows: K08–K11.

## 6. J9 — network parity (extends v1 §10)

### 6.1 The SOCKS5 listener

The bridge process (v1 §10) opens a second listener on
`127.0.0.1:3129` in the attempt's network namespace, speaking RFC 1928
with this profile:

- Method `NO AUTHENTICATION` only (the listener exists solely inside
  the netns; loopback-only by construction).
- `CONNECT` with `ATYP` `DOMAINNAME` (the `socks5h` form): the bridge
  resolves the name itself — the child never resolves — through the same
  resolver policy, normalization and allowlist as HTTP CONNECT (v1
  network-rules.md), then connects and relays.
- `CONNECT` with IPv4/IPv6 literals: allowed only if the literal is
  itself authorized (numeric exceptions are explicit entries, as v1
  already requires).
- `UDP ASSOCIATE` answers `REP=0x07` (command not supported); `BIND`
  answers `REP=0x02`. There is no UDP egress in v2 and the receipt says
  so when a `socks5` transport is active.
- Agent-profile environments gain `ALL_PROXY=socks5h://127.0.0.1:3129`
  beside the existing HTTP proxy variables; the CONNECT listener on
  3128 is unchanged.

### 6.2 Destination binding and its application-origin limit

For every tunnel either listener opens, the bridge buffers the client's
first flight (bounded: 8 KiB or 5 s, whichever first) before connecting
upstream:

- **TLS**: the bridge parses the ClientHello's SNI (reading, not
  terminating) and requires it to normalize-equal the authorized
  target. A ClientHello without SNI is `origin_unverified` unless the
  entry is an IP literal.
- **Plaintext HTTP** (only reachable through explicit `host:port`
  entries after §3.1): the first request's `Host` must equal the
  target under the shared normalization; the strict request-head
  parser (v1 §10) already applies.
- **HTTP/2 over the tunnel**: the connection preface's first HEADERS
  block is refused in plaintext. Do not add an HPACK/HTTP2 stack merely to
inspect a first header block. HTTP/2 inside TLS remains opaque unless
vault TLS termination is active.
- Anything else — unparseable first bytes, timeout, a second CONNECT —
  is `origin_unverified` and the tunnel never opens.

The residual is recorded in the spec and the receipt: after the first
flight, the tunnel is opaque; mid-connection Host changes on keep-alive
connections are the CDN-co-tenancy limit of any non-terminating proxy,
and is **not** bounded to one application origin by SNI. A matching
SNI can still carry an encrypted Host for a different CDN tenant. Full
HTTP-origin enforcement requires TLS termination and validation of every
request; do not claim the TLS Host-swap PoC closed through SNI alone.
Plaintext tunneled HTTP uses the existing one-request framed relay and
closes afterward, so a second request cannot change Host. TLS ECH,
missing/duplicate SNI, malformed or oversized ClientHello and unsupported
protocols refuse for named destinations. Explicit IP grants authorize that
address and port, not a DNS or application identity.
`proxy.net` results record the transport (`http` or `socks5`) and the
observed origin.

### 6.3 Credential vaulting (staged)

New credential mode, `[credentials.<id>] mode = "vault"`, with the same
source isolation rules as `copy_rw` (operator-owned, single-link, outside every
child-visible grant, budgeted). The stages:

- **J9b — vault over plaintext HTTP**: no bytes are staged. The
  supervisor reads the secret at prepare, holds it in memory, injects
  `OURO_VAULT_<ID>=vault:<attempt>:<id>` into the environment, and the
  bridge substitutes the real value into `Authorization` headers of plaintext requests whose destination
  is in the credential's `hosts` list. Substitution is exact-value: the
  placeholder must be the whole header value. Credential bytes never
  appear in diagnostics, receipts or request captures. Reject CR, LF, NUL
  and oversized values. Never forward Proxy-Authorization upstream; it is
  a hop-by-hop proxy credential, not an origin credential. Host grants bind
  scheme, exact normalized host and port. Redirects require fresh policy
  validation. Plaintext vaulting requires an explicit operator opt-in
  because the secret crosses the network without TLS.
- **J9c — vault over TLS**: the bridge generates a per-attempt CA (the
  private key lives only in supervisor memory, never in the sandbox),
  terminates all TLS tunnels in an attempt with vaulted credentials
  (so an unauthorized destination cannot receive a placeholder),
  substitutes only for the credential's exact authorized origins,
  and re-originates TLS upstream with normal certificate-chain and hostname
  validation. Validate every decrypted request's authority; disable ALPN
  h2 until an actual HTTP/2 implementation is present. The initial
  TLS lane handles one HTTP/1.1 request per connection, requires a
  content length for request bodies, and refuses chunked uploads and
  Expect. It has a 32 KiB decrypted-header bound, a 10 s header
  deadline, 30 s upstream I/O deadlines and a 300 s client deadline.
  TLS record state is bounded separately from relay buffers; the
  relay buffer budget is not a total process-memory limit. Never forward a
  placeholder to an unauthorized host: reject it without exposing bytes. The child's trust stores are extended via
  the conventional file variables (`SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`); `SSL_CERT_DIR` is a
  directory with hashed certificates, not a PEM filename pointing at the attempt's
  CA bundle, and the receipt records `credential_injection: "mitm_ca"`.
  Certificate pinning by the child fails loudly; that is documented
  behavior, not a gap to fix.

The receipt's credential rows gain `mode: "vault"` with
`never_staged: true` and no digest (the v1 rule — no credential digest
in receipts — is unchanged). Cleanup destroys the CA; the private key
never touches disk. Non-HTTP protocols are out of scope for vaulting
and the launch profile validation says so when a vaulted credential has
no HTTP(S) hosts.

### 6.4 J9 exit criteria

The fifth audit's plaintext Host-swap and a CONNECT/SNI mismatch
refuse; encrypted HTTP Host mismatch refuses only in the vault TLS
lane. The non-terminating lane retains the explicitly recorded residual; a `socks5h` client reaches exactly the allowlisted
hosts and its `proxy.net` evidence records transport and origin; a
vaulted credential reaches an HTTPS host end-to-end with the child's
environment containing only the placeholder (verified by an in-sandbox
fixture printing its environment); the CA is absent after cleanup.
K-rows: K12–K18.

## 7. J10 — live supervision and command rules

### 7.1 `ouro-jail tail`

```
ouro-jail tail [--attempt ID] [--follow] [--json] [--since TIME]
```

Reads an attempt's bounded trace journal (v1 §13.3) and prints events:
human table by default (`time class operation path → result`), one JSON
event per line with `--json` (the recorded envelope, unmodified — tail
never rewrites evidence). `--follow` polls the journal at 100 ms (the
journal is append-only, so polling is exact; inotify is an
optimization, not a correctness dependency). Tail works on any attempt
the operator can read, including live ones, and on macOS once J11
lands. It grants no authority: read-only, no control channel.

### 7.2 Command deny-rules (opt-in, not containment)

Operator configuration:

```toml
[jail.commands]
deny = ["rm -rf /*", "git push --force"]
forbid = ["dangerous-tool **"]
```

- A rule is a positional glob list: element 0 matches `argv[0]` (by
  basename and by the sandbox-visible absolute path), later elements
  match arguments positionally, and a final `**` matches any
  remaining arguments. Rules are tokenized without a shell, matched bytewise with `*` and `?`
  within each argument, and terminal `**` matches remaining arguments.
  Shell pipelines are different processes and cannot be matched as one
  argv. The root exec is checked as well as descendants. Truncated argv
  refuses when rules are active, and an `execve` with an empty argv matches
  element 0 against the exec path alone. There is no shell expansion, and
  the rule set is capped (initial 64 rules, recorded).
- `deny`: at the exec entry stop (the closed set already stops every
  `execve`/`execveat`), the supervisor matches the snapshot argv; a
  match rewrites the exec to return `EPERM`, records a
  `command_denied` event (pattern, argv digest, pid) and the run
  continues.
- `forbid`: the same match stops the tree with error code
  `command_forbidden` (new, remediation `configuration`), the receipt
  recording the pattern.
- Exec-time re-check (sixth audit F5, as corrected by its review): the
  entry-stop argv is tracee memory a sibling thread can rewrite before
  the kernel copies it, so at the exec event the rules are matched again
  against the kernel's own copy (`/proc/<tid>/cmdline`, empty arguments
  kept in place) and image (`/proc/<tid>/exe`) — never the interpreter's
  argv of a `#!` script or `binfmt_misc` handler, whose script and
  arguments are judged as the entry check judged them. A hit there kills
  the process before its image runs and records a `command_rule` note
  (`enforcement: killed_at_exec`, `signal: SIGKILL`, no `errno`); a
  `forbid` hit also stops the tree as above, a `deny` or unreadable-argv
  hit does not.
- **This is an accident filter, not a boundary.** The receipt records
  `command_rules: {deny: n, forbid: m}` and the spec says plainly what
  the operator must not conclude: a child can achieve the same effect
  through unmatched argv; containment is the profiles, not the rules.
  On the macOS lane (J11) there is no exec observation in v2, so
  command rules are refused at resolution there (`invalid_config`,
  key `jail.commands`).

### 7.3 J10 exit criteria

`tail --follow` shows a live run's events with bounded lag and never
misses a settled event (the journal is the source of truth, so the test
compares tail output against the settled trace journal); each deny/forbid fixture
exercises matching, positional globs, `EPERM` injection, the event, and
the refusal; a `sh -c` re-spelling of a denied command still runs
(the documented non-boundary, tested as such). K-rows: K19–K22.

## 8. J11 — the macOS execution lane

**Design gate remains open.** Native research on this Mac disproved ordinary
process-group cleanup, launchd job cleanup, and blocking only the `setsid` and
`setpgid` syscalls. A stronger candidate exists in macOS 27's descendant-scoped
Endpoint Security API, but the live capability probe requires an entitlement
the test executable does not have. Its ability to support termination,
including death of the custodian, remains unproved. See the
[native investigation](../benchmarks/jail/macos-native-mechanisms.md) and
[raw results](../benchmarks/jail/results/macos-native-mechanisms.json).
The current jail keeps the contained-execution refusal. The candidate below
is not an implemented backend, and the lifecycle contract is not weakened.

### 8.1 Backend

The enforcement backend on macOS is Seatbelt via `sandbox-exec`,
composed from the resolved policy snapshot:

- **Filesystem**: a default-deny profile
  (`(deny default)` plus tested, explicit allowances) with explicit allowances: read-write subpaths for workspace,
  scratch and vendor state; read-only subpaths for the admitted system
  roots and grants; write-denials for protected segments (`.git`,
  `.ouroboros`) over their writable parents. There is no mount
  namespace on macOS, so "closed view" means the profile's denial of
  everything unnamed — the receipt's containment record for macOS names
  the mechanism (`seatbelt_profile`) and does not claim a namespace
  boundary.
- **Network**: the profile denies all network egress and allows
  loopback to the bridge's two ports only. The bridge (the same Rust
  userspace, compiled for darwin) runs outside the profile, attached to
  loopback; allowlist, origin binding, SOCKS5 and vaulting are the
  J9 mechanisms, unchanged — the bridge is the network design on both
  platforms.
- **In-child paths**: the attempt's private trees mount by mapping, not
  by tmpfs: vendor state, scratch and the proxy directory live in separate private execution directories outside receipt and
  trusted configuration state; names are not an isolation mechanism, and the child
  sees them at the conventional logical paths via `HOME`/`XDG_*` and
  profile variables exactly as on Linux.
- **Limits**: the wall ceiling needs a proved native lifetime mechanism. Linux's
  pidfd/cgroup watcher is not portable. Process-group killing alone cannot
  claim tree death because setsid/double-fork descendants can escape.
  Test parent death, daemonization, helper death and PID reuse before
  advertising macOS tree containment; refuse guarantees not established. `pids`, `mem` and `cpu` cannot be enforced unprivileged on
  macOS: an explicit request refuses at resolving
  (`unsupported_platform`, key `limits.*`), and preferred limits are
  recorded as not applied, exactly as v1 records a missing controller.
- **Observation**: there is no proved closed-set observer on macOS —
  `ptrace` there is not the Linux observer. macOS 27's
  `es_new_descendants_client` removes root and TCC requirements but retains
  Apple's Endpoint Security client entitlement. It is a research candidate,
  gated the way v1 §5 gates every observer choice; the current executable's
  capability probe returns `ERR_NOT_ENTITLED`. Receipts
  mark every audit class `unsupported`, `--observe on` refuses with `unsupported_platform`; execution requires
  explicit `--observe off`, and receipts report no closed-set coverage, and command rules are refused (§7.2).
- **Lifecycle**: preparation, gate, receipts, gc and launch
  profiles reuse the shared supervisor. `learn` refuses on macOS until
  a real observer exists; unsupported audit classes cannot justify grants.
  Inherited descriptors, Mach services, Unix sockets, process inspection
  and signals to the supervisor need adversarial tests as well as paths.
  Host-wide loopback ports are not private to an attempt: use dynamically
  allocated ports with per-attempt authentication, or refuse proxy mode
  until cross-attempt access is prevented. `doctor` on macOS
  gains real probes: profile compilation (`sandbox-exec -p` dry-run),
  bridge loopback reachability, wall-limit enforcement, and the
  refusal probes for limits and command rules.

#### Native lifetime proof required before enabling execution

Investigate Seatbelt plus a descendant-scoped ES custodian, with the client
created and subscribed before workload release, audit-token identities for
signalling, and explicit detection of event loss. The macOS 27 API is an
entitled option to prove, not an implicit platform requirement or fallback.
On a normally protected Mac, the next live probe requires an approved
entitlement and matching signature/profile; an entitlement plist alone is
insufficient. Apple also permits development testing before approval with
SIP temporarily disabled. Use that exception only inside a disposable macOS
27 VM, record the guest security configuration and mark the run as development
testing. It can exercise the real ES API, but does not prove operation on a
normally protected customer Mac. Repeat the gates with SIP enabled and an
approved signature/profile before enabling the production backend.
The [prepared prototype](../benchmarks/jail/macos_es.py) builds an app-wrapped
helper with an embedded approved provisioning profile. Local ad-hoc and
Developer ID builds have only proved pre-exec entitlement refusal; the
operator submitted the [entitlement request](../benchmarks/jail/endpoint-security-request.md)
on 2026-09-29 (`S9YJTLLH28`), and Apple approval is pending. The
[development VM trials](../benchmarks/jail/macos-development.md) now exercise
the real client with an ad-hoc signature and SIP disabled. After correcting an
invalid signal-zero probe, all 30 trials with a surviving custodian observed
the known fixture processes exit and independently found them gone. All ten
custodian-death trials left five workload processes alive beyond two seconds,
including detached and double-fork descendants. Thus this prototype does not
meet the lifetime contract. SIP-enabled, Apple-approved trials remain pending;
entitlement approval alone will not resolve the demonstrated custody failure.

The following are not sufficient evidence of tree containment:

- Denying `setsid` and `setpgid`: `posix_spawn` group/session attributes bypass
  those syscall filters. Denying all `posix_spawn` breaks ordinary Node child
  execution and does not satisfy the agent workload contract.
- A launchd job or coalition ID: detached children retain coalition membership
  but survive job-root death and removal. `coalition_terminate` requests an
  empty notification rather than killing members; ordinary callers cannot
  manage coalitions directly. A private-ABI membership scan is not an atomic
  kill-and-empty operation.
- An ES sync callback or fail-closed authorization timeout: neither is a
  documented kill-all-on-custodian-death mechanism. Fork notification alone
  does not block concurrent forks.

Before opening the execution gate, prove detached and double-fork descendants,
spawn attributes, concurrent forks during teardown, supervisor death,
custodian death, PID reuse, and event loss against an actually entitled
executable. Verify bounded teardown and a complete final drain before
`tree_empty=true`; loss or uncertainty retains private state. A custodian
whose own death leaves execution running does not meet the contract.
Then run real Node/shell/Git/OpenCode compatibility and benchmark launch and
termination. Do not select a weaker native guarantee merely because these
proofs need more work.

### 8.2 J11 exit criteria

The macOS lane runs the §1.1-equivalent slice (write an allowed file,
fail a protected access, exceed the wall) plus an opencode A01 row on
macOS; every v1 M-row that asserted refusal now asserts either
execution or a named refusal per this section; the macOS receipts
validate against the current schemas with macOS backend fields. K-rows:
K23–K26 and K29; the A-row is recorded in agent-compatibility.md.

## 9. What J6–J11 must not change

- The threat model, the trust boundaries and the honest-evidence rules.
- The meaning of historical evidence; current schemas are updated in place.
- The no-host-configuration rule (the installer, the tap, the bridge,
  the CA and the macOS backend all live and die by it).
- The Linux mechanisms' v1 semantics; J9 amends network *policy*, and
  every amendment is a refusal or a recorded fact, never a silent
  behavior change.

## 10. Records and schemas

Change existing Rust records and `docs/specs/jail-v1/` schemas, validators
and fixtures together. Do not introduce a second producer, `/2` reader
branch, feature-version switch, or parallel backend implementation.
New evidence belongs in the existing extensible detail maps when that
preserves its meaning; add typed fields when consumers need them.

Every run records the actual network verification mechanism and its
limits, backend execution identity, resolver sanitization result, and any
active command rules. Vault rows have `never_staged: true` and no digest.
Learning output is a separate proposal document with exact evidence
references, receipt digest, revision, coverage and denied writes. It is
never silently interpreted as operator configuration. `command_forbidden`
is a configuration error with an explicit receipt cause.

Update the current freeze manifest only from a tested tree. Keep the raw
test output and host manifest; a regenerated digest is not test evidence.

## 11. Acceptance matrix (v2 rows)

Fixtures follow v1 §15's rules (explicit modes, private control
channel, no sleep-based synchronization, isolated state). The v1 rows
keep their evidence meaning; expectations affected by explicitly amended
policy semantics are updated in place; these rows are additive.

| ID | Test and required result |
|---|---|
| K01 | C1: two-stage plaintext Host swap and CONNECT/SNI mismatch each close the tunnel with `proxy.deny` (`origin_mismatch`); a matching first flight relays end-to-end; host-only entries admit :443 only and the refusal names the entry. |
| K02 | C1: absent SNI, unparseable first bytes and first-flight timeout each yield `origin_unverified`/`origin_timeout` and no upstream connection. |
| K03 | C2: `--profile none` with a `config.toml` or any launch profile present refuses `unsafe_config_path` naming the files; without them it runs. Sixth audit F1: while a `none` run's live marker exists (in the data or the configuration directory) every existing trusted file refuses; after it settles, a trusted file that predates the settled `uncontained.epoch` marker refuses until re-saved; a `none` run that cannot write its live markers refuses before release; a directory planted at the settled marker's path refuses reads and is cleared by the settle. |
| K04 | C3: a child-writable root over the supervisor binary's or backend's directory refuses; the backend is exec'd by pinned descriptor and an identity swap between resolution and spawn refuses at preparing. |
| K05 | C4: i386 and x32 `clone3` return `ENOSYS` under `none` and create no child; any foreign-arch `clone3` success classifies `untraced_descendant`. |
| K06 | C5–C7: unreadable/unparseable resolv.conf ships an empty file and records it; `--workspace /dev/shm` and a cross-device alias beneath a guarded tree both refuse. |
| K07 | C8–C10: `--profile` of a fifo / `/dev/zero` symlink / oversized file refuses bounded; a mid-scan directory change re-scans once and refuses on the second; the new deny rows match the regenerated evidence tables. |
| K08 | `learn` on a denied-read fixture proposes exactly the existing file as a read-only grant, never its parent tree, cites the receipt digest, and proposes nothing for its denied writes. |
| K09 | `learn` on the HTTP fixture proposes exactly the two observed hosts; a denied non-allowlist reason proposes nothing. |
| K10 | `learn --adopt` writes the marked fragment atomically after a TTY confirmation, refuses without one, and the next run applies the grants as ordinary operator config. |
| K11 | `learn` of opencode proposes only the observed, justified subset, with incomplete coverage stated. |
| K12 | SOCKS5: `socks5h` CONNECT relays to allowlisted hosts; the child never resolves (a resolver-less fixture works); `UDP ASSOCIATE`/`BIND` are refused; literals require explicit entries. |
| K13 | SOCKS5 results and HTTP CONNECT results share one allowlist, one normalization and one origin-binding path; receipts record transport and origin for both. |
| K14 | Vault (HTTP): the child's environment holds only placeholders; the bridge substitutes on authorized hosts only; a placeholder on a non-authorized host is denied without recording secret material. |
| K15 | Vault (TLS): per-attempt CA substitutes end-to-end; the key is absent from the sandbox and from disk; cleanup removes the CA bundle. |
| K16 | Credential rows record `never_staged: true`, no digest, and launch validation refuses a vaulted credential with no HTTP(S) hosts. |
| K17 | J6–J9 regression: on `tool`, observation off versus direct execution, p95 added warm startup is under 500 ms for every workload and median post-start overhead on the fixed file workload is at most 100%. These are twice J5's retained 250 ms startup and adjusted 50% post-start ceilings (v1 §5). Both plain and delegated-scope sessions must pass, with at least 30 valid samples per arm, no excluded samples, complete raw records and a predeclared quiet-host threshold. Use `xtask perf`'s no-op, 200-child and 5,000-round file fixtures; report observation-on costs separately. Whole-command timings cannot substitute for these phase measurements. |
| K18 | The bridge's first-flight buffer is bounded: oversized ClientHello, slow drip and pipelined junk cannot wedge a worker or the run. |
| K19 | `tail` on a settled attempt replays exactly the journal; `--follow` on a live attempt shows events with bounded lag and its output equals the journal at settlement. |
| K20 | `tail --json` emits the recorded envelopes byte-identically (tail never rewrites evidence). |
| K21 | Deny-rules: positional glob matching, basename and path forms, `EPERM` injection with `command_denied` event, `forbid` stopping with `command_forbidden`, and the documented non-boundary (unmatched re-spelling runs) all behave as specified. |
| K22 | Command rules refuse at resolution on macOS-lane builds and when the rule cap is exceeded. |
| K23 | macOS: the §1.1-equivalent slice (allowed write, protected denial, wall expiry) passes; explicit pids/mem/cpu refuse `unsupported_platform`. |
| K24 | macOS: network egress is deny-all except the bridge loopback ports; the bridge enforces the same allowlist and origin binding; a SOCKS5 client works unchanged. |
| K25 | macOS: receipts validate with macOS backend fields, audit classes `unsupported`, and `exec_unconfirmed` semantics as specified. |
| K26 | macOS: opencode A01 row recorded (revision, vendor version, profile, receipt). |
| K27 | Install: a clean VM reaches sandboxed `true` and the opencode A01 run in under ten minutes; corrupted artifacts fail signature verification and install nothing; the installer never requires a TTY. |
| K28 | Bundled profiles: `--launch` resolution precedence (operator file wins, noted), fragment conflicts refuse, every bundle has a green `doctor --launch` and a recorded A-row or an explicit unrecorded status. |
| K29 | macOS native lifetime: setsid/double-fork/spawn-attribute descendants and concurrent forks cannot evade termination after wall expiry, supervisor death or custodian death; identity reuse, event loss and failed final drains never produce a false `tree_empty=true`. Missing required entitlement refuses before workload release. |
| K30 | Sixth audit F4: a successful open-class call whose `/proc/<tid>/fd/<ret>` link does not corroborate the snapshot (absolute: every component; relative, bare names included: the tail; `O_TMPFILE`: the directory) delivers its event with an incomplete path, counts `path_claims_unverified` in `lifetime.native.details` and records a bookkeeping `path_claim_unverified` gap that degrades no class and never stops a strict run; agreement records none of these. |
| K31 | Sixth audit F5: an exec whose entry argv passed the rules but whose kernel copy (argv or image) hits one kills the process, records a `killed_at_exec` `command_rule` note, and for a `forbid` surfaces `command_forbidden` through the exec event, with no `entry_abandoned` gap for the killed exec; an entry-time hit still denies before the image loads; a `#!` script, an empty argument and an `execve` with no argv are judged as at the entry stop. |
| K32 | Sixth audit F6: bytes the client pipelines after the one request of a vault MITM connection are counted in `discarded_bytes`, bounded by the one-second drain. |

## 12. Implementation order and exit criteria

| Step | Deliverable | Exit criterion |
|---|---|---|
| J6: closeout | §3 complete, fixtures vendored, tables regenerated. | K01–K07 pass on the reference host with the fifth audit's PoCs inverted; a sixth audit pass recorded. |
| J7: distribution | §4 complete. | K27–K28 pass; the compatibility table carries the first twelve A-rows or explicit statuses. |
| J8: learn | §5 complete. | K08–K11 pass; the A01 learning output contains only evidence-supported proposals. |
| J9: network parity | §6 complete in stages (J9a SOCKS5 + origin binding, J9b vault HTTP, J9c vault TLS). | K12–K18 pass at each stage; K17 measured and recorded. |
| J10: live supervision | §7 complete. | K19–K22 pass. |
| J11: macOS lane | §8 complete. | K23–K26 and K29 pass on the named macOS host; v1 M-rows re-evaluated per §8. |

## 13. Publication and evidence

- **Benchmarks**: the hyperfine suite and probe scripts from
  2026-09-28 are vendored under `docs/benchmarks/` with the raw JSON, exact build digest, warmup/sample count and failures;
  every comparison claim in any document links a script in the repo.
  Re-run K17 at every milestone; publish the trend.
- **Compatibility table**: agent-compatibility.md remains the only
  place a support claim lives, one A-row per agent version and profile,
  each naming its receipt. No marketing surface may claim an agent
  without a row.
- **Audit cadence**: a security audit pass (self-directed initially,
  external when the project can fund it) is a release gate for every
  minor version from v2 on; open High/Medium findings block the release,
  and the audit reports stay in the repo — they are as much a product
  feature as the receipts.
- **Claims discipline**: every public comparison names its host, its
  versions and its scripts, and quotes the competitor's own threat
  model rather than characterizing it. We win on measured facts and
  published evidence; that is the whole strategy.

## 14. Implementation and evidence discipline

K rows are release gates, not declarations of completion. Record each row
as passed, failed, unsupported or not run, with a command and artifact.
A unit parser test is not a live containment test; a macOS refusal is not
a macOS execution result. Report medians and p95 with raw timing samples
on this Mac and `ubuntu@37.59.114.70`. Keep startup and observed workload
cost separate, and compare identical observation/profile settings.

Signing and publishing require real release keys and repository ownership.
Never invent a public key, support row, CI result or clean-VM install
measurement. Build and test distribution locally before publication.
Keep one small synchronous proxy and shared policy evaluator; add no
framework or implementation version solely for these milestones.
