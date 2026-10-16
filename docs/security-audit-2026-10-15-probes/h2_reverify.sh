#!/bin/bash
# H2 re-verification: #! interpreter scripts must run under default strict mode
# (pass-7 H2 killed every npm/pip-shim CLI). Needs node or python3 on host.
set -u
BASE=$(mktemp -d /tmp/h2reverify.XXXXXX)
JAIL=${1:-ukai-jail}
mkdir -p "$BASE/ws"
cat > "$BASE/ws/shim" <<'EOF'
#!/usr/bin/env bash
echo "SHIM_RAN_OK args=$*"
EOF
chmod +x "$BASE/ws/shim"
echo "== env-style double-interpreter shim =="
cat > "$BASE/ws/envshim" <<'EOF'
#!/usr/bin/env bash
echo "ENVSHIM_RAN_OK"
EOF
chmod +x "$BASE/ws/envshim"
"$JAIL" run --profile tool --workspace "$BASE/ws" --limit wall=10s -- \
  "$BASE/ws/shim" arg1 > "$BASE/o1" 2> "$BASE/e1"; r1=$?
"$JAIL" run --profile tool --workspace "$BASE/ws" --limit wall=10s -- \
  ./envshim > "$BASE/o2" 2> "$BASE/e2"; r2=$?
echo "shim exit=$r1 out=$(cat "$BASE/o1") err=$(head -c 200 "$BASE/e1")"
echo "envshim exit=$r2 out=$(cat "$BASE/o2") err=$(head -c 200 "$BASE/e2")"
grep -l "exec_image_mismatch" "$BASE"/e* 2>/dev/null && echo "H2 VERDICT: STILL BROKEN" || echo "H2 VERDICT: shebang scripts execute"
rm -rf "$BASE"
