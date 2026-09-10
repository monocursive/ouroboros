# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting instead: the **Security** tab of this repository → **Report a
vulnerability**. You will get a response there, and the report stays private until a
fix is released.

## Releases

There is no published release channel, no signed download and no self-update: the signing
key, the release workflow and `ouro update` were deleted by
[proposals/core.md](docs/proposals/core.md) §3 D4. `make ouro` builds the client on the
machine that will run it, and an operator copies that binary where it is needed. If a
release channel comes back, this section says how to verify it.

Only the latest revision is supported with fixes.
