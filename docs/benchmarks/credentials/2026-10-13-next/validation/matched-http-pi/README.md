# Retained HTTP fixture cohorts

`all-04/` is the completed common four-arm persistent-client fixture. Use its
metadata, controller, actor, per-mode records and resource oracle together.
The analysis is `../../analysis/matched-http-pi.json`. Synthetic v1/v2 strings
are deliberate fixture inputs; no real provider credential is used.

Earlier pilots are retained and excluded from the completed cohort:

- `ouro-01/`: successful Ouro pilot with a shorter SSE timeout/wrapper wall.
- `lease-failed-02/`: a literal executable-path guard rejected a resolved-path
  comparison before stopping the original proxy or executing any fixture.
- `pilot-others-03/`: Greywall requests/rotation succeeded, but the SSE first
  event did not arrive within the actor's original ten-second read timeout.
  MXC failed configuration because `/lib64` does not exist on this ARM host.
  Its completed observation window was therefore not verified. An early harness
  field asserting `live_stream_oracle_observation_completed: true` is not proof;
  failure records and raw events control the interpretation. The final harness
  computes this flag from actual readiness and completed observation.

All final arms received the same longer deadlines and the same actor/resource
payload. Only existing read-only runtime paths are passed to MXC. The lease
restoration reports are retained; private environment snapshots and raw restore
logs are not exported.
