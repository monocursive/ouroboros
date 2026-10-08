# Jail v1 canonical bytes

Normative companion to [§6.3](../jail-v1.md#63-policy-shape-and-narrowing).
These are contract fixtures, not an implementation of the policy resolver.

## Native strings

On Linux and macOS, paths and argv are Unix byte strings. Valid UTF-8 bytes
encode as a JSON string without Unicode normalization. Otherwise encode exactly
`{"encoding":"base64","data":"<RFC 4648 standard padded base64>"}`.
Reject noncanonical base64, unpaired JSON surrogates, and byte objects whose
decoded bytes are valid UTF-8 (they must use the string form). Native values
cannot contain NUL. Arguments may be empty; filesystem paths may not, except
the empty relative suffix of a root reference below. The codec is shared by
receipt grant values, mount paths and private snapshot path/argument values.
The byte encoding does not bypass redaction: trace paths still obey §11.3.

## Policy input

The complete hash input is the `ouro.jail.policy-snapshot/1` object validated
by [policy-snapshot.schema.json](policy-snapshot.schema.json). The schema's
`required` list and `additionalProperties: false` govern presence: every field
the schema requires is present, optional values use null or empty arrays, and
three kinds of value are omitted rather than emitted as null or false —
`commands` when both filter lists are empty, `limits.swap`, `limits.storage`
and `limits.inodes` when unset, and `observation.learning` when false. No
other fields are accepted. Resolve configuration, expand the built-in profile and
apply project narrowing before constructing it:

| Field | Canonical meaning |
|---|---|
| schema | `ouro.jail.policy-snapshot/1` |
| profile | Base `agent`, `tool`, `build`, or `none`; custom display/file names excluded |
| profile_version | `1`, the built-in semantic contract version |
| platform | `linux` or `macos`; never kernel/build/probe results |
| roots | Absolute resolved workspace; scratch as managed or explicit host path; vendor_state as managed or null |
| filesystem | Effective read_write/read_only/deny_read path-reference sets, protected_segments set, protected_coverage |
| network | Mode, normalized allow-rule set, ruleset identifier and configured translation-prefix set |
| limits | Seven ceilings: wall (ms), pids (count), mem (bytes) and cpu (percent, 100 = one core) always present, each null or `{value, required}`; swap (bytes), storage (aggregate writable bytes) and inodes (aggregate writable inode count) present only when set, each `{value, required}`. `value` is a decimal string; swap may be `0` (zero disables swap), every other ceiling is positive |
| observation | mode on/off, evidence strict/best-effort, and the learning flag; `learning` is omitted when false |
| commands | optional operator argv accident filters: `{deny, forbid}` pattern arrays, present only when either list is non-empty; both arrays are always present inside the object, possibly empty |
| environment | inherit_host boolean and explicit effective bindings `{name,value}`; value is a native string or managed path reference |
| launch | null, or resolved state_var, home_is_state, state_subdirs, credential declarations |

Path references are exactly `{root, path}`. Root is `host`, `workspace`,
`scratch` or `vendor_state`; host paths are absolute, other paths are relative
suffixes (empty means that root). No `.`/`..` or empty interior components.
Represent paths beneath a managed root using its token, not its attempt-specific
host location. Resolve overlapping roots in order vendor_state, scratch,
workspace, host, preferring the first containing root. Root identities are
checked separately at preparation; inode/birth identities are not hash input.
An explicit scratch path remains in roots even when its references are tokenized.

The environment bindings include the profile's resolved baseline and launch
overrides; generated state paths use references. Names are unique. The private
snapshot may contain configured environment values, but never copied credential
contents. Receipt/trace output includes names only. `none` sets inherit_host=true
and records only explicit overrides; the inherited ambient environment is not
a consistency guarantee. Launch credentials are `{id, source, dest, mode}`:
source is an absolute native path and dest is a relative native path under
vendor state. Modes are copy_rw, bind_ro and vault; a vault credential
additionally carries `vault: {hosts, allow_plaintext}` — `hosts` is one to 64
host names the credential may be sent to, `allow_plaintext` a boolean. The
`vault` member is present only for mode vault. Ids are unique. Launch name,
vendor version and the input file's identity are provenance, not semantic
values.

For network=proxy, ruleset is `ouro.jail.network/1`; for none/host it is null
and allow/translation_prefixes are empty. Non-proxy policy changes cannot
smuggle unused grants into the digest. Contained filesystem grants include
resolved baseline runtime paths as well as operator grants. A fixture baseline
does not authorize a production backend to omit or add runtime mounts.
Capability requirements are derived from these semantics by §6.4 and the
profile contract; the mutable probe results and chosen backend are separate.

All arrays here are sets except three: environment bindings and credentials,
which are keyed collections, and `commands.deny`/`commands.forbid`, whose
operator-declared order is preserved and is part of the digest. Reject
duplicate keys in the keyed collections. Deduplicate set elements by their
canonical bytes, then sort every set array lexicographically by each element's
RFC 8785 UTF-8 bytes; the set arrays are `filesystem.read_write`,
`filesystem.read_only`, `filesystem.deny_read`, `filesystem.protected_segments`,
`network.allow`, `network.translation_prefixes` and `launch.state_subdirs`.
Keyed collections are sorted the same way, by their elements' canonical bytes
and not by key, and are never deduplicated (a duplicate key is refused where
the collection is built); a credential's canonical bytes begin with `dest`
(member names sort `dest`, `id`, `mode`, `source`, `vault`). The commands
arrays are neither sorted nor deduplicated. No other array in a policy
snapshot encodes ordering; argv ordering is handled separately below. Decimal
strings have no sign or leading zeroes, and positive values are bounded by
unsigned 64-bit (a swap ceiling may be exactly `0`).

The private `policy.json` envelope is
`{schema:"ouro.jail.policy-file/1", snapshot, policy_digest, provenance}`.
Provenance carries file/CLI source and resolution diagnostics. Hash **only**
snapshot: never this envelope, source filenames, timestamps, attempt ids,
process identities, capability measurements, chosen backends, credential
content digests or the digest itself. Environment values remain private.

## Hash algorithms

Let `J` be the RFC 8785 canonical UTF-8 encoding of snapshot, without BOM or
trailing newline. The policy preimage is these exact bytes:

```text
ASCII("ouro.jail.policy/1") || 0x00 || J
```

`policy_digest = "sha256:" || lowercase_hex(SHA256(preimage))`.

The argv preimage is:

```text
ASCII("ouro.jail.argv/1") || 0x00 || U64BE(argc)
  || U64BE(len(argv[0])) || argv[0]
  || ...
  || U64BE(len(argv[argc-1])) || argv[argc-1]
```

Lengths count native bytes, not characters. There are no NUL terminators,
padding or newline. Hash all literal arguments including PROGRAM before PATH
lookup; do not replace argv[0] with the resolved executable. The public digest
uses the same sha256 prefix. Credential content hashes are ordinary SHA-256 of
the copied bytes, not policy/argv hashes. Digests of guesses remain guessable.

The canonical encoding `J` (and of any receipt) is RFC 8785 restricted to the
value kinds a snapshot or receipt uses: null, true/false, integers within
i64/u64, strings, arrays and objects. Integers are encoded as their shortest
decimal form (an ASCII minus sign and no leading zeroes for negatives);
floating-point numbers do not occur and must be rejected, not invented.
Strings are escaped exactly as ECMAScript `JSON.stringify` escapes: `\"`,
`\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other control characters below U+0020 as
`\u00xx` lowercase hex, every other code point as its literal UTF-8 bytes,
with no Unicode normalization and no BOM. Object member names are sorted by
their UTF-16 code units and each is serialized with the same string rules.
Arrays serialize as `[` followed by comma-separated elements and `]`; objects
as `{` followed by comma-separated `"name":value` members and `}`. There is no
whitespace between tokens and no trailing newline.

A receipt digest, as a `jail.receipt` trace note carries it, is `sha256:` over
the receipt's RFC 8785 canonical bytes, with no domain prefix: the receipt
already names its schema. A consumer recomputes it from `jail.json` (which is
written pretty-printed) by parsing the document and canonicalizing it; the
file's own bytes are not the preimage. No receipt field is a floating-point
number, so the integer-only encoding above covers every receipt.

## Golden inputs and expected results

[canonical-input.toml](fixtures/canonical-input.toml) and
[canonical-equivalent.toml](fixtures/canonical-equivalent.toml) resolve to
[policy-snapshot.json](fixtures/policy-snapshot.json) under the explicit
synthetic host/default context in [canonical-context.json](fixtures/canonical-context.json).
The expected RFC 8785 bytes are [policy.jcs](fixtures/policy.jcs), with no final
newline. [digests.json](fixtures/digests.json) pins both hashes, the argv values,
and the complete argv preimage as hex. A byte-valued path is supplied by the
fixture's CLI arguments because TOML itself is UTF-8.

P01 must compare resolver output to the snapshot, canonical bytes to policy.jcs,
and both computed digests to the checked-in values. Reordering sets/keys or
changing provenance must preserve the hash; changing a limit, grant, environment
value or argv order must change the appropriate digest. The documentation
validator checks fixture coherence and hashes; only the future runtime suite
can prove the real resolver matches these expected outputs on both platforms.
