#!/bin/bash
set -eu
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
B=/Users/monocursive/bench-ouro-rerun
export HOME=$B XDG_CONFIG_HOME=$B/openshell/config XDG_STATE_HOME=$B/openshell/state OPENSHELL_LOCAL_TLS_DIR=$B/openshell/tls
export PATH="/Users/monocursive/bench-ouro/bin-0.1.4:$PATH"
export PYTHONPATH="$B/harness"
python3 "$B/harness/container_limits_probe.py" --out "$B/results/mac-container-limits" > "$B/results/mac-container-limits.log" 2>&1
python3 "$B/harness/container_filesystem_probe.py" --out "$B/results/mac-container-fs" > "$B/results/mac-container-fs.log" 2>&1
echo MAC-PROBES-DONE
