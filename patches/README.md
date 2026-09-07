# erlexec 2.3.4: macOS process-group setup

The pinned Hex package's child and parent both call `setpgid` before `exec`. On
macOS 26.6.2, concurrent calls occasionally return `EPERM` even when the other
call establishes the requested group. A minimal fork-only reproducer failed
10/5,000 times; ordering either call first passed 2,000/2,000. This happens before
the requested executable runs, independently of Git or the Erlang runtime.

The patch keeps both group-setup calls. On macOS only, the child makes at most four
attempts, with three 1 ms pauses after `EPERM`; an error is accepted only when its
actual process group is already the requested group. All other errors remain
fatal. No command is retried and process-group termination remains enabled.

The patched port passed 10,000 concurrent harmless command launches, recovering
15 observed races. A nonexistent requested group still prevented execution, and
a timed-out shell's background child was reaped. This is local macOS evidence;
the conditional leaves Linux's existing setup behavior unchanged.

`mix deps.get` applies the patch after download; `deps.precompile` also covers
implicit dependency compilation. Normal `mix compile` asks Rebar/make to check
erlexec's native build even when Mix restored a cached application. The patcher
accepts only the original or patched source's exact SHA-256, is idempotent, and
fails clearly on an unfamiliar dependency revision. `test/erlexec_patch_test.exs`
checks reproducibility and refusal without modifying the real dependency.

When upgrading erlexec, review upstream's implementation and remove this patch if
the race is fixed there. Do not update the accepted hash without reviewing the
new source and replaying the group-setup and containment checks.
