# Fix wave

This is your own session, with your own change still in front of you. A reviewer read it and
wrote the review below. Answer it.

## What to do with each finding

- **PROVED.** Reproduce it first — run the command the review gives. If it does what the
  review says, turn the reproduction into a regression test that goes **red** on your
  current code, then fix it and watch it go green. The exploit becomes the test; a fix with
  no test is a fix that comes back.
- **PLAUSIBLE.** Settle it. Run the thing the reviewer said would settle it. Then either fix
  it with a test, or write down what you ran and why the finding does not hold. "I read it
  again and it looks fine" is not settling it.
- **A survivor in the mutation table.** An enforcement point with no test defending it is
  the review's most important finding, whatever label sits beside it. Write the test that
  goes red when that check is deleted. Delete the check, watch it go red, put the check
  back.

Re-run **every** mutation the review listed, not only the survivors: a mutation that went
red before your fix must still go red after it.

## What not to do

- Do not widen the change. The review is a list of things to answer, not an invitation to
  refactor. A file you open for the review and change for another reason costs the next
  reviewer a full read.
- Do not delete or weaken a test to make something pass.
- Do not argue with a finding in a comment in the code. Arguments go in your report.
- Do not touch `lib/ouroboros/control/`, `lib/ouroboros/upgrade/` or
  `lib/ouroboros/storage/` unless a finding is there. Every hunk in those namespaces goes to
  a human by name.

## Before you finish

- `mix format --check-formatted`, `mix compile --warnings-as-errors`, and the suites you
  touched — including every test the review pointed at, not only the ones you wrote.
- `mix test` output carries NUL bytes: redirect and `grep -a 'Result:\|Failed:'`.

## Your report

Three lists, one line each, no prose in between:

1. **Fixed** — the finding, the test that now covers it, and the mutation you re-ran.
2. **Settled without a change** — the finding, what you ran, and why it does not hold.
3. **Not fixed** — the finding, and why: out of scope, wrong, or real but bigger than this
   change. Say which. This list going to a human is the point of it existing; an empty one
   you had to make empty is worse than an honest one with two entries.
