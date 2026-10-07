# Raspberry Pi Unix diagnostics and live proxy — 2026-10-07

The running `6.18.50+rpt-rpi-v8` kernel has `CONFIG_UNIX_DIAG` disabled,
but its exported symbols support the upstream diagnostics module. The exact
Raspberry Pi source tag `stable_20260911`, commit
`cff533aec2fa601846766b32ff57204e0a61bed7`, built `net/unix/diag.c` and its local
`af_unix.h` against the installed matching headers and `Module.symvers`.
No kernel image, boot configuration, enforcement policy or reboot was needed.

The native Kbuild used `obj-m += unix_diag.o` and `unix_diag-y := diag.o`.
The module was first loaded temporarily, then installed at
`/lib/modules/6.18.50+rpt-rpi-v8/updates/ouro/unix_diag.ko` after the live probe
passed. `depmod` registered it; `/etc/modules-load.d/ouro-unix-diag.conf`
contains `unix_diag`. [Host and source/module hashes](host.txt) bind this to the
installed kernel. A later kernel needs its own matching module or built-in
support; this does not make arbitrary Pi kernels supported.

The [production CLI probe](proof/proxy-status.json) now reports
`proxy_redaction_verified`: an actual proxy denial preserves its decision and
byte counters while removing the destination. Path minimization, unchanged
explicit captures and one-execution replay also passed. The saved responses and
canonical streams pass the ledger schema/canonical validator.

The full native ledger suite passed **220 tests, zero failed or ignored** with
`OURO_CONFORMANCE=1`, including the live proxy branch. The
[summary](validation/summary.json) also checks 72 owner-journal fault cases,
66 lifecycle cases, 44 journal I/O failures and 44 actual journal SIGKILLs.
[Source hashes](validation/source-precheck.log) and [binary hashes](validation/binaries.sha256)
bind the run to the previously validated ledger inputs at `15b77b4f`.
This record predates the subsequent fleet bridge changes.

Memory cgroups remain disabled by the existing boot argument and Landlock
remains absent. Required guarantees still refuse; loading Unix diagnostics
does not change either limitation. This is scripted proxy evidence, not a
real-agent/provider compatibility result.

Rollback: after all proxy attempts have stopped, remove this task's module-load
file, unload `unix_diag`, remove the exact installed module above, and run
`depmod -a 6.18.50+rpt-rpi-v8`. Retain the source and proof directory. Do not
unload the module underneath active attempts.

Sources: [pinned Raspberry Pi source](https://github.com/raspberrypi/linux/tree/cff533aec2fa601846766b32ff57204e0a61bed7/net/unix)
and [Linux external-module build contract](https://docs.kernel.org/kbuild/modules.html).
