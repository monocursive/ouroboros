# Historical gateway compatibility

These fixtures preserve historical bytes and are not regenerated. Current wire
examples belong in `test/support/gateway_golden/` and must match the generator.

`hello_before_safe_status.json` is the original `hello_result.json` from commit
`0654a1fe09bde2de20d8f33e8347317e89c13605`, before current discovery was refreshed
to include `interactive.safe_status`. `Ouroboros.Gateway.GoldenTest` checks that
the current hello differs from this baseline only by that additive method.
