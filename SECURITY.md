# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting instead: the **Security** tab of this repository → **Report a
vulnerability**. You will get a response there, and the report stays private until a
fix is released.

## Verifying releases

Release binaries are published with a `SHA256SUMS` file signed by minisign. The public
key of record is `dist/release.pub` in this repository — the same bytes compiled into
the `ouro` binary — not anything downloaded from the release itself. Verify with:

```sh
minisign -V -p dist/release.pub -x SHA256SUMS.minisig -m SHA256SUMS
```

Only the latest release is supported with fixes.
