#!/bin/sh
# Disposable Linux audit/SQLite/containment integration. Host checkout stays read-only.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=${OURO_AUDIT_TEST_IMAGE:-hexpm/elixir:1.20.2-erlang-29.0.5-ubuntu-noble-20260730.1}
docker run --rm --privileged \
  -v "$root:/source:ro" -v ouro-audit-linux-cache:/cache -w /work "$image" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq build-essential bubblewrap libsctp1 git ca-certificates >/dev/null
    sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 || true
    tar -C /source --exclude=.git --exclude=_build --exclude=deps --exclude=target --exclude=node_modules -cf - . | tar -C /work -xf -
    export MIX_ENV=test MIX_BUILD_PATH=/cache/test MIX_DEPS_PATH=/cache/deps
    if [ ! -d /cache/deps ]; then
      cp -R /source/deps /cache/deps
      # Native objects copied from macOS must be rebuilt for Linux.
      find /cache/deps -type f \( -name "*.o" -o -name "*.so" -o -name "*.dylib" \) -delete
    fi
    ln -s /cache/deps /work/deps
    mix local.hex --force
    mix local.rebar --force
    mix deps.get
    mix deps.compile
    useradd -m auditcheck
    cp -R /root/.mix /cache/mix
    chown -R auditcheck:auditcheck /work /cache
    runuser -u auditcheck -- bwrap --ro-bind / / --dev /dev --proc /proc -- /bin/true
    runuser -u auditcheck -- env MIX_HOME=/cache/mix MIX_ENV=test MIX_BUILD_PATH=/cache/test MIX_DEPS_PATH=/cache/deps mix test test/audit
  '
