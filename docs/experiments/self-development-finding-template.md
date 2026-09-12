# Self-development finding record

This is a validation template, not evidence that a live model will use it correctly. The
repeat live benchmark measures that behavior.

## Finding

- **ID:** stable `SD-NN`
- **Severity:** high / medium / low
- **Classification:** confirmed defect / reproduction needed / intended behavior / fixed regression / retracted
- **Expected:**
- **Observed:**
- **Command:** exact bounded command
- **Environment:** application start mode, data-directory class, OS, outer sandbox, host-only prerequisites
- **Evidence:** exact failure, totals, and preserved artifact; no credential contents
- **Contradictory evidence:** none, or an explicit result
- **Disposition:** smallest supported change, retraction, or exact blocker and next action
- **Regression:** test that fails before the correction and passes after it

## Investigation budget

- Search narrowly before broad reading.
- Retry an environmental failure once only when one named variable changes.
- After the same normalized failure twice, stop and classify it.
- Record subagent ownership; shared dirty-tree edits remain serial.

## Repeat-benchmark metrics

- benchmark start/end and wall time
- supervisor steering prompts, approval changes, interrupts, and restarts
- tool calls; failures by normalized reason; unchanged retries; repeated commands
- files read and broad reads; subagent ownership
- questions asked, actual answers, declines/timeouts, and declared fallbacks
- unique usage events and input/cached-input/output tokens
- compactions, handoffs, context-window utilization, and restart result
- tests with exact pass/fail/excluded totals and host-only status

Compare these only with the original bounded benchmark performing the same exercise. Do not
score a larger implementation program against the bounded exercise's call target.