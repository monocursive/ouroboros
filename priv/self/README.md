# `priv/self` — what this runtime learned about itself

This directory is how one installation of Ouroboros hands the next one what it learned.
`make self-export` writes it out of a running node's durable state; `Ouroboros.Self.Boot`
reads it back on a fresh install under `OUROBOROS_POSTURE=self`. See
[docs/SELF.md](../../docs/SELF.md) §S4.

Empty in this checkout except for this file, which is also what keeps the directory in git —
there is no `.gitkeep`, because a directory with a README explaining what belongs in it does
not need a second file explaining that it should exist. A checkout with nothing else here
boots exactly as it always did: `Ouroboros.Self.Boot` finds no bundle, applies no promotion,
and logs nothing.

## The three files an export writes

| File | What it is |
|---|---|
| `<name>.ouro-wasm` | The signed bundle for the policy component the promotion record is bound to — the manifest, its signature, the precompiled artifact when the manifest declares one, and the component bytes. Byte for byte what `ouro wasm sign` produced. |
| `promotions.json` | The policy name, its component sha256, and the tools that component had **currently** earned the right to resolve, each with the replay numbers that earned it. |
| `signers.txt` | `signer_id:base64_public_key` — the exact line `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` takes, and the one `ouro wasm keygen` printed when the key was minted. |

Exactly three, and exactly one bundle: an export replaces those files with one atomic rename
each and **removes every other `*.ouro-wasm`** it finds here, naming them in its output. A
policy renamed between two exports would otherwise leave both, and the boot task globs this
directory — so the next installation would deploy a policy nobody promoted beside the one
somebody did. This README is left alone; it belongs to the repository, not to an export.

## What committing these does, and what it does not

It does **not** grant anything. A bundle here is a file in a repository, and the boot task
runs it through the ordinary rollout: `Ouroboros.Wasm.Rollout.deploy/4` verifies the
manifest against the receiving node's own trust policy before it writes a byte. A node whose
operator has not put the key from `signers.txt` into `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`
skips every bundle here by name, with the reason in its log, and boots with the rules it
shipped with.

Only a **policy** is deployed. A bundle here whose manifest says any other kind — a
capability, say — is skipped with `{:not_a_policy, kind}` before anything else is asked about
it: what runs on a fresh install should be what somebody promoted, not what somebody's file
was sitting next to.

`promotions.json` is applied only over an **empty** `Ouroboros.Control.PolicyPromotion`
record, and only for a component sha that is live on the receiving node under the name the
file gives. A node that has promoted anything of its own keeps its own record. Each shipped
promotion lands in the effect ledger under the actor `shipped:<sha256 of promotions.json>`,
which is the honest answer to who promoted it: not a person, and traceable to these exact
bytes.

## Nothing here is a secret

A public key, a component that already travelled as a signed bundle, and counts of
decisions. The corpus those counts came from — `Ouroboros.Control.PolicyEvidence`, which
holds the actual requests humans answered — is node-local and is not exported by this or by
anything else.
