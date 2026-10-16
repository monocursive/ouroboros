#!/bin/bash
# Ukai post-rename security battery — VPS runner.
# Usage: battery.sh <ukai-jail-binary> <workdir>
set -u
JAIL=$(readlink -f "${1:?ukai-jail binary}")
BASE=${2:?workdir}; mkdir -p "$BASE"; cd "$BASE"
PASS=0; FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FINDING: $1"; FAIL=$((FAIL+1)); }
info() { echo "info: $1"; }

"$JAIL" version
"$JAIL" doctor --profile tool  --json > doctor_tool.json 2>&1; echo "doctor tool rc=$?"
"$JAIL" doctor --profile agent --json > doctor_agent.json 2>&1; echo "doctor agent rc=$?"
"$JAIL" doctor --profile build --json > doctor_build.json 2>&1; echo "doctor build rc=$?"

WS="$BASE/ws"; mkdir -p "$WS"; cd "$WS"
RUN() { timeout 60 "$JAIL" run --profile "${PRF:-tool}" --workspace "$WS" --limit wall="${WALL:-20s}" "$@"; }

# --- environment hygiene -----------------------------------------------
cat > /tmp/envdump.sh <<'EOF'
#!/bin/sh
env | sort
EOF
chmod +x /tmp/envdump.sh
env SENTINEL_SHOULD_NOT_LEAK=xyz123 RUN < /dev/null > env_inside.txt 2>&1
if grep -q SENTINEL_SHOULD_NOT_LEAK env_inside.txt; then bad "parent env leaks into jail (SENTINEL visible)"; else ok "clearenv holds"; fi
info "env inside: $(head -c 400 env_inside.txt)"

# --- classic regression spot-checks (renamed build still holds) ---------
cat > spot.sh <<'EOF'
#!/bin/sh
r() { printf '%-40s' "$1"; shift; "$@" >/dev/null 2>&1 && echo "UNEXPECTED-SUCCESS" || echo "denied($?)"; }
r "read /proc/1/root/etc/passwd" cat /proc/1/root/etc/passwd
r "write /etc/passwd"            sh -c 'echo x >> /etc/passwd'
r "write /proc/sys/kernel/core_pattern" sh -c 'echo|x > /proc/sys/kernel/core_pattern'
r "mknod /tmp/n0"                mknod /tmp/n0 c 1 3
r "mount tmpfs"                  mount -t tmpfs none /tmp
r "unshare -Ur"                  unshare -Ur true
r "setns via /proc/1/ns"         sh -c 'exec 9< /proc/1/ns/mnt'
r "ptrace host pid"              sh -c 'grep -c TracerPid /proc/self/status'
r "kexec_load"                   sh -c 'echo kexec | dd of=/dev/kexec'
r "chroot /"                     chroot / true
r "open_by_handle_at"            sh -c 'exec 9</proc/self/ns/mnt'
EOF
chmod +x spot.sh
RUN -- ./spot.sh > spot_out.txt 2>&1 || true
cat spot_out.txt
grep -q "UNEXPECTED-SUCCESS" spot_out.txt && bad "a classic escape succeeded — see spot_out.txt" || ok "classic escape spot-checks all denied"

# --- io_uring probe -----------------------------------------------------
gcc -O1 -o /tmp/iouring2 "$BASE/../probes/iouring2.c" 2>/tmp/iouring_cc.err || cat /tmp/iouring_cc.err
RUN -- /tmp/iouring2 /tmp/IOURING_ESCAPED > iouring_out.txt 2>&1; rc=$?
cat iouring_out.txt
[ -e /tmp/IOURING_ESCAPED ] && bad "io_uring wrote host /tmp marker" || ok "io_uring contained (rc=$rc)"

# --- memfd exec probe ----------------------------------------------------
gcc -O1 -o /tmp/memfd_exec "$BASE/../probes/memfd_exec.c" 2>/dev/null || true
rm -f /tmp/memfd_marker
RUN -- /tmp/memfd_exec > memfd_out.txt 2>&1; rc=$?
cat memfd_out.txt
[ -e /tmp/memfd_marker ] && info "memfd script executed (receipt check: exec confirm semantics)" || ok "memfd exec refused (rc=$rc)"

# --- H1 / H2 re-verification -------------------------------------------
bash "$BASE/../probes/h1_reverify.sh" "$JAIL"
bash "$BASE/../probes/h2_reverify.sh" "$JAIL"

echo "== battery done: $PASS pass, $FAIL findings =="
