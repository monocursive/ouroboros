# Generated self-development status

`scripts/self-development-status.py` is a bounded, read-only P5 projection over explicit files. It selects the unique newest P0 checkpoint by its RFC3339 `updated_at`, neutrally lists older supplied inputs without claiming lineage or supersession, and emits JSON or Markdown. It does not search for evidence or rewrite reports.

## Inputs and trust

- P0 checkpoint version 3: verifies the SHA-256 message and plan digests exactly as the checkpoint format supports. These are integrity checks, not authentication. Output schema version 3 preserves checkpoint `work_state` and `child_settlement` only as nested `declared` values; each has `establishment: not_established`, `observed: null`, and an explicit reason unless a future typed runtime authority supplies an observation. The current renderer has no such authority. Thus arbitrary digest-consistent declarations—including `checking`, `completed`, or `unsettled` with no owner—are never presented as runtime facts. A syntactically accepted item is rendered `unknown` until authoritative parent replay verifies its acceptance; a declared `child_settlement: completed` alone remains pending.
- P2 campaign receipt version 2: each `--receipt` requires a corresponding `--manifest` and `--key`. The projection delegates contract validation and adjudication to the authoritative P2 implementation, including manifest/source binding, signer/nonce, freshness at `--as-of`, and local HMAC checks. This proves possession of the supplied local key, not independent execution, review, current source identity, or whole-program truth. With live source verification deliberately disabled for historical rendering, it does not prove current workspace source. It does recheck supplied artifact/executable bytes where the P2 adjudicator supports that check.
- No receipt means validation is `unknown`; non-passing or incomplete constituents remain pending/blocked. No load-controller receipt format currently exists, so load status cannot be established and is not presented as complete.
- An optional `--program` declaration must contain exactly P0–P5 and X1–X4, concrete reasons, existing bounded evidence references, and explicit unknowns. It cannot declare any item passed: only a typed authoritative validator can establish that state. JSON and Markdown both render the complete inventory, its conservative overall state, and every explicit unknown.

All paths must be explicit absolute normalized regular files. Inputs, bytes, item counts, and constituent counts are bounded. Duplicate JSON keys, duplicate IDs/paths, malformed input, non-finite numbers, digest/HMAC tampering, stale receipts, missing files, and an ambiguous latest timestamp are refused.

```sh
scripts/self-development-status.py \
  --checkpoint /absolute/conversation.json \
  --receipt /absolute/receipt.json \
  --manifest /absolute/manifest.json \
  --key /absolute/private-key \
  --format markdown
```

The generated projection is a handoff aid only. Human-authored reports remain authoritative analysis, and omitted inputs remain unknown rather than evidence of completion.
