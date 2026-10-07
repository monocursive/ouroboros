# Foreground control descriptor — 2026-10-07

Implementation: `ae8ec49c48872df11f46e5f2df513430060d8879`.
Native validation includes the test-only import correction
`8a88137569631087caa45b71f96645b64d2fe5fa`.
[source.json](source.json) identifies that Git archive and
[source.sha256](source.sha256) binds its 430 runtime, test and contract inputs.
Only changed content was copied into the existing native test checkouts; the
full suites verify input hashes before and after execution.

## Behavior and proof

`run --control-fd N` sends one final compact JSON run record followed by a
newline to the supplied descriptor. It implies JSON, with no duplicate result
or summary on stdout/stderr. Child streams retain foreground behavior, including
capture teeing. Diagnostics remain on stderr. The control channel reports the
same metadata and outcome as the ordinary run projection; it adds no execution
or custody claim. This is a final response, not a lifecycle notification feed.

The CLI validates the exclusively handed-over descriptor before preparing a
run. It accepts writable regular files, pipes and connected Unix stream sockets;
invalid types, closed/read-only descriptors, stdio aliases and already-disconnected
consumers refuse. Close-on-exec prevents inheritance by the on-demand writer,
Jail and child. Shared open-file flags remain unchanged. Requests record only
`io.control: separate_fd`, so descriptor numbers can change on replay.
Detached use refuses; foreground JSON without a separate descriptor still refuses.

Result frames are bounded to 1 MiB. The CLI waits at most two seconds for its
delivery worker, with blocking writes outside the launch path and retries for
nonblocking backpressure. A delivery
failure exits 1 and names the existing run/request. It preserves the durable
outcome; the operator can inspect or replay the same request rather than launch
a replacement. Partial frames must be discarded. Successful delivery preserves
the child exit code or signal mapping.

Five added portable unit tests cover exact file/socket frames, close-on-exec,
unchanged status flags, descriptor rejection, post-validation disconnect,
frame bounds, stalled delivery and nonblocking retry. Two portable CLI tests
exercise rejection before any store is created, including stdio/file aliases,
unsupported endpoints and detached conflicts.

Three new native tests launch real Jail children. Both `tool` and `none` use
file, pipe and socket control channels with captured foreground output. The
child cannot see the control fd, exact binary stdout/stderr survive, exit 7 is
preserved, and the new on-demand writer does not keep the result channel open.
Disconnected, blocked and nonblocking-blocked pipes fail delivery within the
bound while the canonical result stays settled. Retrying returns that result
without a second execution. Foreground control without `--json` and batch
control each send the record only to the selected descriptor. Existing argv,
signed bundle, transcript, pending-journal and lifecycle tests run in full.

The separate [production CLI probe](probe-cli.py) supplies stdin, observes exact
binary child output and exit 7, and replays through a different descriptor.
It saves the actual run response, canonical events and child-stream bytes.
[validate-cli.py](validate-cli.py) checks the response against the run schema and
the events against their schemas and canonical encoding. All probe contents are
deliberate test data. Each probe uses a private fixture and stops only its writer.

## Validation

The native [validation script](../2026-10-06-writer-outage/validate-native.sh)
uses Rust 1.98.1, `OURO_CONFORMANCE=1`, `RUST_TEST_NOCAPTURE=1` and a delegated
user scope. [verify-results.py](verify-results.py) checks exit statuses, counts,
all 72 pending-owner fault cases, 66 lifecycle cases, control/argv/transcript
and vendor-cleanup markers, binary hashes and absence of test instrumentation
from the production binary. Source checks must pass before and after.

- VPS: **213 passed**, zero failed, ignored or skipped.
  [Summary](linux/summary.json), [full log](linux/ledger.log),
  [actual control response](linux/control-cli.json).
- Raspberry Pi: **213 passed**, zero failed, ignored or skipped.
  [Summary](pi/summary.json), [full log](pi/ledger.log),
  [actual control response](pi/control-cli.json).
- Local macOS: **175 passed**, zero failed or ignored.
  [Summary](local/summary.json), [full log](local/ledger.log).
  Linux launch tests are compiled out on macOS.

The first native attempts stopped at Clippy because the Linux-only test module
redundantly imported a trait already supplied by its parent. Those diagnostics
are retained for [VPS](initial-linux-clippy.log) and [Pi](initial-pi-clippy.log),
with [original source identity](initial-source.json) and
[original hashes](initial-source.sha256). The correction removes only that test
import; production code is unchanged. Local macOS results bind the implementation
revision because that Linux-only test module is compiled out there.

Formatting, Clippy, contracts, links, I02 and the unchanged Jail freeze pass.
The following evidence commit adds proof and documentation, without changing
runtime, test or schema inputs. Installed commands and kernel settings are
unchanged; this work does not publish a production release.

## Scope

These are scripted-child and native filesystem/process results. They do not
establish physical power-loss safety, external custody, real-agent/provider
compatibility or managed readiness. Structured redaction before append remains
the next milestone-2 CLI/privacy implementation slice.
