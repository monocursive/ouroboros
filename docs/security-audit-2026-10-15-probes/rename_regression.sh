#!/bin/bash
# Rename-regression probe: does the renamed ukai-jail still trust legacy
# ouro-era paths/env/config in a way an attacker can plant?
# Runs OUTSIDE any jail, as operator. Usage: rename_regression.sh <ukai-jail> <tmpbase>
set -u
JAIL=$(readlink -f "${1:?ukai-jail path}")
BASE=${2:?tmpbase}
mkdir -p "$BASE"
cd "$BASE"

echo "== binary identity =="
"$JAIL" version || true

echo "== legacy env vars honored? =="
for v in OURO_CONFIG_DIR UKAI_CONFIG_DIR OURO_DATA_DIR UKAI_DATA_DIR; do
  out=$(env "$v=$BASE/planted_$v" "$JAIL" explain --profile tool --workspace "$BASE/ws" --limit wall=5s --json 2>&1 || true)
  if echo "$out" | grep -q "planted_$v"; then
    echo "$v: HONORED (planted path appears in explain output)"
  else
    echo "$v: not honored"
  fi
done

echo "== legacy config dir trusted? =="
mkdir -p ~/.config/ouro
cat > ~/.config/ouro/config.toml <<'EOF'
[network]
allow = ["attacker.example.com:443"]
EOF
out=$("$JAIL" explain --profile tool --workspace "$BASE/ws" --limit wall=5s --json 2>&1 || true)
if echo "$out" | grep -q "attacker.example.com"; then
  echo "LEGACY ~/.config/ouro/config.toml STILL TRUSTED — widening vector"
else
  echo "~/.config/ouro ignored"
fi
rm -f ~/.config/ouro/config.toml

echo "== new config dir =="
mkdir -p ~/.config/ukai
out=$("$JAIL" explain --profile tool --workspace "$BASE/ws" --limit wall=5s --json 2>&1 || true)
if echo "$out" | grep -q "attacker.example.com"; then
  echo "unexpected: new dir trusts old content"
else
  echo "~/.config/ukai starts clean"
fi

echo "== legacy /run/ouro vs /run/ukai =="
ls -la /run/user/$(id -u)/ 2>/dev/null | grep -E "ouro|ukai" || true
