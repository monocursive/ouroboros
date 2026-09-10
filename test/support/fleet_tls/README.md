# Two throwaway fleets, for `test/cluster_dist_tls_test.exs`

These are **test-only keys and they mean nothing.** They protect no machine, they are in a
public repository, and no runtime reads them: nothing outside that one test file opens this
directory, and no code path here ever consults a fleet directory that is not
`<data dir>/fleet/`. Do not copy them anywhere.

`fleet_a/` and `fleet_b/` are the certificate halves of two *independent* fleets, each with
its own self-signed CA. They were produced by the code under test:

```sh
ouro fleet create --machine fleet-a --host 127.0.0.1   # into a throwaway OUROBOROS_DATA_DIR
ouro fleet create --machine fleet-b --host 127.0.0.1   # into another one
```

and then `ca-cert.pem`, `node-cert.pem` and `node-key.pem` were copied out of each
`<data dir>/fleet/`. The cookies, CA keys and profiles were not copied; the test needs none
of them.

`ssl_dist.conf.template` is `fleet_a`'s generated `ssl_dist.conf` verbatim, with that
machine's fleet directory replaced by `@FLEET_DIR@`. The test substitutes a fixture
directory into it and hands the result to `:file.consult/1`, so what it drives `:ssl` with
is the policy `ouro fleet create` writes, not a hand-written approximation of it.
`generated_policy_matches_the_committed_ssl_dist_template` in `tui/src/fleet.rs` is the
other half: it fails if `generated_runtime_files` ever stops emitting exactly this string,
which is what keeps the fixture honest.

## When these expire

`ouro fleet create` gives a node certificate five years and a CA eleven, both anchored to
the year it ran. These were minted in 2026, so the leaves stop being valid on
**2031-01-01** and the CAs on **2036-01-01**; the test fails loudly rather than silently
passing. Regenerate them with the two commands above, copy the six PEM files back, and
rebuild the template from the new `ssl_dist.conf`.
