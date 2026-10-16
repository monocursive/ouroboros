#!/bin/sh
# usage: run.sh N [extra claude args]  -- one A01-fixture run under the setup-token profile
set -u
export UKAI_CONFIG_DIR=$HOME/spike-oauth/config UKAI_DATA_DIR=$HOME/spike-oauth/data
J=$HOME/spike-oauth/bin/ukai-jail
n=$1; shift
ws=$HOME/spike-oauth/ws$n; rd=$HOME/spike-oauth/runs/r$n
rm -rf "$ws" "$rd"; mkdir -p "$ws" "$rd"; cd "$ws" && git init -q
s=$(date +%s.%N)
$J run --launch claude-oauth --workspace "$ws" --limit wall=240s --receipt "$rd/jail.json" -- \
  /bin/sh -c "export CLAUDE_CODE_OAUTH_TOKEN=\"\$UKAI_VAULT_CLAUDE_OAUTH\"; exec /usr/bin/claude \"\$@\"" claude-wrap \
  -p "Create a file named greeting.txt containing the single word hello." \
  --model sonnet --max-turns 15 --dangerously-skip-permissions --output-format json "$@" \
  >"$rd/stdout" 2>"$rd/stderr"
echo "exit=$? wall=$(echo "$(date +%s.%N) - $s" | bc)" > "$rd/exit"
cat "$rd/exit"
