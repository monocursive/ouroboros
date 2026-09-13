#!/bin/sh
# Kernel-level Seatbelt gate. A nested invocation is inconclusive, never silently green.
set -eu

[ "$(uname -s)" = Darwin ] && [ -x /usr/bin/sandbox-exec ] || {
    printf 'sandbox-host-test: macOS Seatbelt unavailable\n' >&2
    exit 77
}

probe="$(/usr/bin/sandbox-exec -p '(version 1) (allow default)' /usr/bin/true 2>&1)" || {
    printf 'sandbox-host-test: nested or unavailable Seatbelt is inconclusive: %s\n' "$probe" >&2
    printf 'sandbox-host-test: launch Ouroboros with --sandbox-mode unrestricted and run make sandbox-host-test\n' >&2
    exit 77
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec scripts/test-isolated.sh mix test test/provider/native/sandbox_helper_policy_test.exs --include sandbox_exec