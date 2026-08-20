#!/usr/bin/env bash
# Hermetic packaged-release exercise for the secure three-node fleet path.
#
# This intentionally uses three loopback identities on one host. It exercises the same
# TLS BEAM distribution, membership, monitoring, and reconnection code as separate
# private-network machines without installing services or changing a host firewall.

set -Eeuo pipefail

log() {
  printf '\n==> %s\n' "$*"
}

die() {
  printf 'fleet e2e: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

for dependency in awk cksum dirname find grep mkdir mktemp python3 rm sleep stat tee tr wc; do
  require_command "$dependency"
done

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OURO_BIN=${OURO_E2E_BIN:-"$REPO_ROOT/tui/target/release/ouro"}

case "$OURO_BIN" in
  /*) ;;
  *) OURO_BIN="$PWD/$OURO_BIN" ;;
esac

[[ -x "$OURO_BIN" ]] || die "packaged binary is missing or not executable: $OURO_BIN (run make ouro)"

VERSION_OUTPUT=$("$OURO_BIN" version)
printf '%s\n' "$VERSION_OUTPUT"
grep -Fq 'release   none embedded' <<<"$VERSION_OUTPUT" &&
  die "$OURO_BIN has no embedded release; this test must exercise the packaged engine"
grep -Fq 'release   ' <<<"$VERSION_OUTPUT" ||
  die "$OURO_BIN did not report an embedded release"

ORIGINAL_HOME=${HOME:?HOME must name the caller whose default runtime must remain untouched}
ORIGINAL_XDG_DATA_HOME=${XDG_DATA_HOME:-"$ORIGINAL_HOME/.local/share"}
ORIGINAL_DEFAULT_DATA="$ORIGINAL_XDG_DATA_HOME/ouroboros"
ORIGINAL_GATEWAY="$ORIGINAL_DEFAULT_DATA/gateway.json"
ORIGINAL_OWNER="$ORIGINAL_DEFAULT_DATA/runtime.owner"

file_snapshot() {
  local path=$1

  if [[ -f "$path" ]]; then
    printf 'present:%s' "$(cksum <"$path")"
  elif [[ -e "$path" || -L "$path" ]]; then
    printf 'non-regular'
  else
    printf 'absent'
  fi
}

json_integer() {
  local path=$1
  local field=$2

  python3 - "$path" "$field" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))[sys.argv[2]]
if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
    raise SystemExit(f"{sys.argv[1]} field {sys.argv[2]} is not a positive integer")
print(value)
PY
}

json_process_identity() {
  local path=$1

  python3 - "$path" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
pid = value.get("pid")
birth = value.get("birth")
if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
    raise SystemExit(f"{path} field pid is not a positive integer")
if (
    not isinstance(birth, str)
    or not 1 <= len(birth) <= 256
    or any(not (character.isascii() and (character.isalnum() or character in ':_-')) for character in birth)
):
    raise SystemExit(f"{path} field birth is not a bounded process identity")
print(f"{pid}\t{birth}")
PY
}

file_sha256() {
  local path=$1

  python3 - "$path" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
print(hashlib.sha256(path.read_bytes()).hexdigest())
PY
}

ORIGINAL_GATEWAY_SNAPSHOT=$(file_snapshot "$ORIGINAL_GATEWAY")
ORIGINAL_OWNER_SNAPSHOT=$(file_snapshot "$ORIGINAL_OWNER")
ORIGINAL_DEFAULT_PID=""
if [[ "$ORIGINAL_GATEWAY_SNAPSHOT" == present:* ]]; then
  ORIGINAL_DEFAULT_PID=$(json_integer "$ORIGINAL_GATEWAY" pid 2>/dev/null || true)
elif [[ "$ORIGINAL_OWNER_SNAPSHOT" == present:* ]]; then
  ORIGINAL_DEFAULT_PID=$(json_integer "$ORIGINAL_OWNER" pid 2>/dev/null || true)
fi

TMP_BASE=${TMPDIR:-/tmp}
TMP_BASE=${TMP_BASE%/}
LAB_ROOT=$(mktemp -d "$TMP_BASE/ouro-fleet-e2e.XXXXXX")
case "$LAB_ROOT" in
  "$TMP_BASE"/ouro-fleet-e2e.*) ;;
  *) die "mktemp returned an unexpected lab path: $LAB_ROOT" ;;
esac

CORE_DATA="$LAB_ROOT/core"
ALPHA_DATA="$LAB_ROOT/alpha"
BRAVO_DATA="$LAB_ROOT/bravo"
LOG_DIR="$LAB_ROOT/logs"
LAB_PIDS="$LAB_ROOT/lab-pids.tsv"
SERVICE_ATTEMPTS="$LAB_ROOT/bravo-service-attempts"
SERVICE_STATUSES="$LAB_ROOT/bravo-service-statuses"
SERVICE_RUN_ID_FILE="$LAB_ROOT/bravo-service-run.identity"
SERVICE_STOP_FILE="$LAB_ROOT/bravo-service-stop"
BRAVO_SERVICE_MANAGER_PID=""
BRAVO_SERVICE_MANAGER_BIRTH=""
FLEET_EPMD_PORT=""
LAB_OWNS_EPMD=0
LAB_EPMD_CLEANED=0
LAB_EPMD_OWNER_SHA=""
LAB_EPMD_PID=""
LAB_EPMD_BIRTH=""
# These are runtime authority roots, not ordinary fixture folders. Create every leaf at
# the same private mode production requires before any create/join command can inspect it.
mkdir -m 700 "$CORE_DATA" "$ALPHA_DATA" "$BRAVO_DATA" "$LOG_DIR"
: >"$LAB_PIDS"
: >"$SERVICE_ATTEMPTS"
: >"$SERVICE_STATUSES"

# Even a missed OUROBOROS_DATA_DIR override is caught: every command also runs under a
# fresh HOME/XDG tree whose ordinary default contains a checksum-protected test sentinel.
export HOME="$LAB_ROOT/home"
export XDG_CONFIG_HOME="$LAB_ROOT/xdg/config"
export XDG_CACHE_HOME="$LAB_ROOT/xdg/cache"
export XDG_DATA_HOME="$LAB_ROOT/xdg/data"
ISOLATED_DEFAULT="$XDG_DATA_HOME/ouroboros"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$ISOLATED_DEFAULT"
printf 'fleet-e2e-default-must-remain-unused\n' >"$ISOLATED_DEFAULT/sentinel"
ISOLATED_DEFAULT_SNAPSHOT=$(cksum <"$ISOLATED_DEFAULT/sentinel")

node_cmd() {
  local data_dir=$1
  shift
  OUROBOROS_DATA_DIR="$data_dir" "$OURO_BIN" "$@"
}

lab_current_identity() {
  local data_dir=$1

  if [[ -f "$data_dir/gateway.json" ]]; then
    json_process_identity "$data_dir/gateway.json"
    return
  fi
  if [[ -f "$data_dir/runtime.owner" ]]; then
    json_process_identity "$data_dir/runtime.owner"
    return
  fi
  return 1
}

pid_is_alive() {
  kill -0 "$1" 2>/dev/null
}

valid_birth() {
  local birth=$1

  [[ -n "$birth" && ${#birth} -le 256 ]] || return 1
  case "$birth" in
    *[!A-Za-z0-9:_-]*) return 1 ;;
  esac
}

current_process_birth() {
  local pid=$1
  local birth

  birth=$("$OURO_BIN" process-birth --pid "$pid" 2>/dev/null) || return 1
  valid_birth "$birth" || return 1
  printf '%s' "$birth"
}

# Reports whether a PID still denotes the exact kernel process incarnation recorded by
# the marker. A live PID with a different/unreadable birth is never equivalent to gone:
# callers preserve it and surface an unsafe cleanup failure.
process_identity_state() {
  local pid=$1
  local expected_birth=$2
  local actual_birth

  valid_birth "$expected_birth" || {
    printf 'invalid'
    return 0
  }
  if actual_birth=$(current_process_birth "$pid"); then
    if [[ "$actual_birth" == "$expected_birth" ]]; then
      printf 'matching'
    else
      printf 'mismatch'
    fi
  elif pid_is_alive "$pid"; then
    printf 'unverifiable'
  else
    printf 'gone'
  fi
}

runtime_marker_identity() {
  local data_dir=$1
  local publication owner
  local publication_pid publication_birth owner_pid owner_birth

  publication=$(json_process_identity "$data_dir/gateway.json") || return 1
  owner=$(json_process_identity "$data_dir/runtime.owner") || return 1
  IFS=$'\t' read -r publication_pid publication_birth <<<"$publication"
  IFS=$'\t' read -r owner_pid owner_birth <<<"$owner"
  [[ "$publication_pid" == "$owner_pid" && "$publication_birth" == "$owner_birth" ]] ||
    return 1
  [[ $(process_identity_state "$publication_pid" "$publication_birth") == matching ]] ||
    return 1
  printf '%s\t%s' "$publication_pid" "$publication_birth"
}

signal_exact_process() {
  local signal=$1
  local pid=$2
  local birth=$3
  local label=$4
  local state

  state=$(process_identity_state "$pid" "$birth")
  [[ "$state" == matching ]] || {
    printf 'fleet e2e: preserving %s pid %s: recorded birth is %s (%s now)\n' \
      "$label" "$pid" "$birth" "$state" >&2
    return 1
  }
  kill -"$signal" "$pid" 2>/dev/null
}

# Speak the documented EPMD NAMES protocol rather than treating an arbitrary TCP
# listener as EPMD. The first four response bytes must repeat the daemon's port.
epmd_probe_state() {
  local port=$1

  python3 - "$port" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
try:
    with socket.create_connection(("127.0.0.1", port), timeout=0.5) as stream:
        stream.settimeout(0.5)
        stream.sendall(b"\x00\x01n")
        response = b""
        while len(response) < 4:
            chunk = stream.recv(4 - len(response))
            if not chunk:
                break
            response += chunk
except OSError:
    print("absent")
    raise SystemExit(0)

if len(response) == 4 and struct.unpack(">I", response)[0] == port:
    print("compatible")
else:
    print("incompatible")
PY
}

epmd_name_count() {
  local port=$1

  python3 - "$port" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=0.5) as stream:
    stream.settimeout(0.5)
    stream.sendall(b"\x00\x01n")
    response = b""
    while True:
        try:
            chunk = stream.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        response += chunk

if len(response) < 4 or struct.unpack(">I", response[:4])[0] != port:
    raise SystemExit("listener did not answer the EPMD NAMES protocol")
names = [line for line in response[4:].splitlines() if line.startswith(b"name ")]
print(len(names))
PY
}

capture_lab_epmd_ownership() {
  local marker="$BRAVO_DATA/fleet/epmd-owner.json"
  local before after pid port birth

  before=$(file_sha256 "$marker") || return 1
  pid=$(json_integer "$marker" pid) || return 1
  port=$(json_integer "$marker" port) || return 1
  [[ "$port" == "$FLEET_EPMD_PORT" ]] || return 1
  birth=$(current_process_birth "$pid") || return 1
  after=$(file_sha256 "$marker") || return 1
  [[ "$before" == "$after" ]] || return 1

  LAB_EPMD_OWNER_SHA=$after
  LAB_EPMD_PID=$pid
  LAB_EPMD_BIRTH=$birth
  printf 'captured Ouro-owned EPMD pid %s with verified birth %s\n' "$pid" "$birth"
}

# Initial port absence is only a reason to expect that Ouroboros may create EPMD; it is
# never durable signal authority. Cleanup requires the exact marker bytes and process
# incarnation captured while the lab was healthy, then delegates lock/inode/listener
# proof and retirement to the packaged `fleet leave` implementation. Any missing or
# changed evidence preserves the listener and retains the lab for inspection.
cleanup_lab_epmd() {
  local marker="$BRAVO_DATA/fleet/epmd-owner.json"
  local current_sha current_pid current_port name_count state identity_state

  [[ "$LAB_EPMD_CLEANED" == 0 ]] || return 0
  [[ "$LAB_OWNS_EPMD" == 1 && "$FLEET_EPMD_PORT" =~ ^[0-9]+$ ]] || {
    LAB_EPMD_CLEANED=1
    return 0
  }

  state=$(epmd_probe_state "$FLEET_EPMD_PORT") || return 1
  if [[ "$state" == absent ]]; then
    LAB_EPMD_CLEANED=1
    return 0
  fi
  [[ "$state" == compatible ]] || {
    printf 'fleet e2e: lab EPMD port %s now has an incompatible listener; refusing to signal it\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }

  [[ -n "$LAB_EPMD_OWNER_SHA" && "$LAB_EPMD_PID" =~ ^[0-9]+$ ]] &&
    valid_birth "$LAB_EPMD_BIRTH" || {
    printf 'fleet e2e: live EPMD port %s has no captured exact ownership identity; preserving it\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }
  current_sha=$(file_sha256 "$marker" 2>/dev/null) || {
    printf 'fleet e2e: EPMD ownership marker is missing or unreadable; preserving port %s\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }
  current_pid=$(json_integer "$marker" pid 2>/dev/null) || return 1
  current_port=$(json_integer "$marker" port 2>/dev/null) || return 1
  [[ "$current_sha" == "$LAB_EPMD_OWNER_SHA" && "$current_pid" == "$LAB_EPMD_PID" &&
    "$current_port" == "$FLEET_EPMD_PORT" ]] || {
    printf 'fleet e2e: EPMD ownership marker changed after capture; preserving port %s\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }
  identity_state=$(process_identity_state "$LAB_EPMD_PID" "$LAB_EPMD_BIRTH")
  [[ "$identity_state" == matching ]] || {
    printf 'fleet e2e: EPMD pid %s no longer matches captured birth (%s); preserving port %s\n' \
      "$LAB_EPMD_PID" "$identity_state" "$FLEET_EPMD_PORT" >&2
    return 1
  }
  [[ $(file_sha256 "$marker" 2>/dev/null) == "$LAB_EPMD_OWNER_SHA" ]] || {
    printf 'fleet e2e: EPMD ownership marker changed during validation; preserving port %s\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }
  name_count=$(epmd_name_count "$FLEET_EPMD_PORT") || return 1
  [[ "$name_count" == 0 ]] || {
    printf 'fleet e2e: lab EPMD port %s still advertises %s name(s); refusing to stop it\n' \
      "$FLEET_EPMD_PORT" "$name_count" >&2
    return 1
  }
  node_cmd "$BRAVO_DATA" fleet leave >"$LOG_DIR/cleanup-leave-bravo.log" 2>&1 || {
    printf 'fleet e2e: packaged fleet leave could not prove the exact EPMD lock/identity; preserving port %s\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }
  [[ $(epmd_probe_state "$FLEET_EPMD_PORT") == absent ]] || {
    printf 'fleet e2e: lab-owned EPMD port %s remained reachable after packaged fleet leave\n' \
      "$FLEET_EPMD_PORT" >&2
    return 1
  }
  LAB_EPMD_CLEANED=1
}

wait_identity_gone() {
  local pid=$1
  local birth=$2
  local label=$3
  local deadline=$((SECONDS + 30))
  local state

  while :; do
    state=$(process_identity_state "$pid" "$birth")
    case "$state" in
      gone) return 0 ;;
      matching | unverifiable)
        ((SECONDS < deadline)) || die "$label pid $pid did not stop within 30 seconds"
        sleep 0.1
        ;;
      mismatch | invalid)
        die "$label pid $pid changed incarnation while waiting for shutdown ($state); it was preserved"
        ;;
    esac
  done
}

record_lab_pid() {
  local data_dir=$1
  local label=$2
  local identity pid birth
  identity=$(runtime_marker_identity "$data_dir") ||
    die "$label publication/owner did not match the actual live BEAM process identity"
  IFS=$'\t' read -r pid birth <<<"$identity"

  [[ "$pid" != "$ORIGINAL_DEFAULT_PID" ]] ||
    die "$label unexpectedly reused the caller's default runtime pid $pid"
  printf '%s\t%s\t%s\n' "$pid" "$birth" "$data_dir" >>"$LAB_PIDS"
  printf '%s started as pid %s with verified birth %s\n' "$label" "$pid" "$birth"
}

# Cleanup may only signal an exact process incarnation. The identity is checked once
# before TERM and again before a KILL fallback so PID reuse during the grace window is
# preserved rather than becoming authority over an unrelated process.
terminate_exact_process() {
  local pid=$1
  local birth=$2
  local label=$3
  local state deadline

  state=$(process_identity_state "$pid" "$birth")
  case "$state" in
    gone) return 0 ;;
    matching) ;;
    *)
      printf 'fleet e2e: preserving %s pid %s during cleanup: identity is %s\n' \
        "$label" "$pid" "$state" >&2
      return 1
      ;;
  esac

  signal_exact_process TERM "$pid" "$birth" "$label" || return 1
  deadline=$((SECONDS + 10))
  while ((SECONDS < deadline)); do
    state=$(process_identity_state "$pid" "$birth")
    case "$state" in
      gone) return 0 ;;
      matching) sleep 0.1 ;;
      *)
        printf 'fleet e2e: preserving %s pid %s after TERM: identity is now %s\n' \
          "$label" "$pid" "$state" >&2
        return 1
        ;;
    esac
  done

  signal_exact_process KILL "$pid" "$birth" "$label" || return 1
  deadline=$((SECONDS + 10))
  while ((SECONDS < deadline)); do
    state=$(process_identity_state "$pid" "$birth")
    case "$state" in
      gone) return 0 ;;
      matching) sleep 0.1 ;;
      *)
        printf 'fleet e2e: %s pid %s changed incarnation after KILL (%s); preserving it\n' \
          "$label" "$pid" "$state" >&2
        return 1
        ;;
    esac
  done
  printf 'fleet e2e: exact %s pid %s remained alive after KILL\n' "$label" "$pid" >&2
  return 1
}

CLEANED=0
CLEANUP_UNSAFE=0
cleanup() {
  local status=$?
  local data_dir identity pid birth deadline
  set +e

  if [[ "$CLEANED" == 0 ]]; then
    CLEANED=1
    : >"$SERVICE_STOP_FILE"
    # Stop through each lab's authenticated local gateway first. Never issue a broad
    # process-name signal and never address the caller's ordinary data directory.
    for data_dir in "$CORE_DATA" "$ALPHA_DATA" "$BRAVO_DATA"; do
      node_cmd "$data_dir" stop >/dev/null 2>&1 || true
    done

    # A failure may have happened between publication and a normal stop. A marker is
    # eligible for fallback only when its validated birth still matches the live kernel
    # process. A recycled PID is preserved and turns cleanup into a visible failure.
    for data_dir in "$CORE_DATA" "$ALPHA_DATA" "$BRAVO_DATA"; do
      case "$data_dir" in
        "$LAB_ROOT"/*) ;;
        *) continue ;;
      esac
      if identity=$(lab_current_identity "$data_dir" 2>/dev/null); then
        IFS=$'\t' read -r pid birth <<<"$identity"
        if [[ "$pid" == "$ORIGINAL_DEFAULT_PID" ]]; then
          printf 'fleet e2e: refusing cleanup marker that names caller runtime pid %s\n' "$pid" >&2
          status=1
          CLEANUP_UNSAFE=1
        elif ! terminate_exact_process "$pid" "$birth" "${data_dir##*/} runtime"; then
          status=1
          CLEANUP_UNSAFE=1
        fi
      elif [[ -e "$data_dir/gateway.json" || -e "$data_dir/runtime.owner" ]]; then
        printf 'fleet e2e: malformed or legacy runtime marker under %s; no marker PID was signalled\n' \
          "$data_dir" >&2
        status=1
        CLEANUP_UNSAFE=1
      fi
    done

    if [[ "$BRAVO_SERVICE_MANAGER_PID" =~ ^[0-9]+$ ]] && pid_is_alive "$BRAVO_SERVICE_MANAGER_PID"; then
      deadline=$((SECONDS + 10))
      while pid_is_alive "$BRAVO_SERVICE_MANAGER_PID" && ((SECONDS < deadline)); do sleep 0.1; done
      if pid_is_alive "$BRAVO_SERVICE_MANAGER_PID"; then
        if ! terminate_exact_process \
          "$BRAVO_SERVICE_MANAGER_PID" "$BRAVO_SERVICE_MANAGER_BIRTH" "bravo service manager"; then
          status=1
          CLEANUP_UNSAFE=1
        fi
      fi
    fi
    if [[ -f "$SERVICE_RUN_ID_FILE" ]]; then
      identity=$(<"$SERVICE_RUN_ID_FILE")
      IFS=$'\t' read -r pid birth <<<"$identity"
      if [[ "$pid" =~ ^[0-9]+$ ]] && valid_birth "$birth"; then
        if ! terminate_exact_process "$pid" "$birth" "bravo service-run child"; then
          status=1
          CLEANUP_UNSAFE=1
        fi
      else
        printf 'fleet e2e: malformed retained bravo service-run identity; no PID was signalled\n' >&2
        status=1
        CLEANUP_UNSAFE=1
      fi
    fi

    # The normal path already did this with a hard assertion. On an earlier failure,
    # retain a failing exit status if a lab-owned empty EPMD cannot be retired safely.
    if ! cleanup_lab_epmd; then
      status=1
      CLEANUP_UNSAFE=1
    fi

    if [[ ${OURO_E2E_KEEP:-0} == 1 || "$CLEANUP_UNSAFE" == 1 ]]; then
      printf 'fleet e2e: retained lab at %s\n' "$LAB_ROOT" >&2
    else
      case "$LAB_ROOT" in
        "$TMP_BASE"/ouro-fleet-e2e.*) rm -rf -- "$LAB_ROOT" ;;
      esac
    fi
  fi

  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

read -r CORE_GATEWAY CORE_DIST ALPHA_GATEWAY ALPHA_DIST BRAVO_GATEWAY BRAVO_DIST < <(
  python3 <<'PY'
import socket

sockets = []
ports = []
for _ in range(6):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
PY
)

RUN_ID=$(printf '%s' "$LAB_ROOT" | cksum | awk '{print $1}')
CORE_MACHINE="e2e-core-$RUN_ID"
ALPHA_MACHINE="e2e-alpha-$RUN_ID"
BRAVO_MACHINE="e2e-bravo-$RUN_ID"
BRAVO_INVITE="$LAB_ROOT/bravo.ouro"
ALPHA_INVITE="$LAB_ROOT/alpha.ouro"

log "Isolation contract"
printf 'caller default data  %s\n' "$ORIGINAL_DEFAULT_DATA"
if [[ -n "$ORIGINAL_DEFAULT_PID" ]]; then
  printf 'caller default pid   %s (must remain alive)\n' "$ORIGINAL_DEFAULT_PID"
else
  printf 'caller default pid   none published\n'
fi
printf 'lab root             %s\n' "$LAB_ROOT"
printf 'lab identities       %s, %s, %s\n' "$CORE_MACHINE" "$ALPHA_MACHINE" "$BRAVO_MACHINE"
printf 'lab gateway ports    %s, %s, %s\n' "$CORE_GATEWAY" "$ALPHA_GATEWAY" "$BRAVO_GATEWAY"
printf 'lab dist ports       %s, %s, %s\n' "$CORE_DIST" "$ALPHA_DIST" "$BRAVO_DIST"

file_mode() {
  local mode
  mode=$(stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1")
  printf '%s' "$mode"
}

assert_private_file() {
  local path=$1
  [[ -f "$path" ]] || die "expected private file is missing: $path"
  [[ $(file_mode "$path") == 600 ]] || die "$path is not mode 0600"
}

wait_status() {
  local data_dir=$1
  local label=$2
  local known=$3
  local connected=$4
  local offline=$5
  local deadline=$((SECONDS + 45))
  local output needle
  needle="formation    known $known · connected $connected · offline $offline"

  while ((SECONDS < deadline)); do
    output=$(node_cmd "$data_dir" fleet status 2>&1 || true)
    printf '%s\n' "$output" >"$LOG_DIR/status-$label.latest.log"
    if grep -Fq "$needle" <<<"$output" && grep -Fq 'transport    TLS verified' <<<"$output"; then
      printf '%s\n' "$output"
      return 0
    fi
    # Leave a visible offline window so the E2E can prove the surviving peers observed
    # the crash before the manager heals it.
    sleep 1
  done

  printf '%s\n' "$output" >&2
  die "$label did not reach: $needle with TLS verified"
}

wait_gateway_pid() {
  local data_dir=$1
  local rejected_pid=$2
  local label=$3
  local deadline=$((SECONDS + 45))
  local identity pid birth

  while ((SECONDS < deadline)); do
    identity=$(json_process_identity "$data_dir/gateway.json" 2>/dev/null || true)
    IFS=$'\t' read -r pid birth <<<"$identity"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [[ "$pid" != "$rejected_pid" ]] &&
      [[ $(process_identity_state "$pid" "$birth") == matching ]]; then
      printf '%s' "$pid"
      return 0
    fi
    sleep 0.1
  done

  die "$label did not publish one live replacement pid within 45 seconds"
}

# A bounded, hermetic stand-in for launchd KeepAlive/systemd Restart=always. The
# production unit runs this same foreground `service-run` command and restarts it after
# either a crash or a clean exit until the unit is explicitly deactivated. Attempt one
# must fail when its BEAM child is SIGKILLed; attempt two then observes an EPMD crash and
# exits so attempt three can rebuild distribution. The test deactivates immediately
# before attempt three's graceful stop.
bravo_service_manager() (
  local attempt service_pid service_birth status

  for attempt in 1 2 3; do
    printf '%s\n' "$attempt" >>"$SERVICE_ATTEMPTS"
    node_cmd "$BRAVO_DATA" service-run >>"$LOG_DIR/service-bravo.log" 2>&1 &
    service_pid=$!
    service_birth=$(current_process_birth "$service_pid") ||
      die "could not retain the exact process identity for service-run pid $service_pid"
    printf '%s\t%s\n' "$service_pid" "$service_birth" >"$SERVICE_RUN_ID_FILE"

    if wait "$service_pid"; then
      status=0
    else
      status=$?
    fi
    printf '%s:%s\n' "$attempt" "$status" >>"$SERVICE_STATUSES"

    [[ ! -e "$SERVICE_STOP_FILE" ]] || exit "$status"
    ((attempt < 3)) || die "service manager exhausted its bounded restart allowance"
    sleep 0.25
  done
)

start_managed_bravo() {
  local pid
  bravo_service_manager &
  BRAVO_SERVICE_MANAGER_PID=$!
  BRAVO_SERVICE_MANAGER_BIRTH=$(current_process_birth "$BRAVO_SERVICE_MANAGER_PID") ||
    die "could not retain the exact bravo service manager process identity"
  pid=$(wait_gateway_pid "$BRAVO_DATA" "" "managed bravo")
  record_lab_pid "$BRAVO_DATA" "bravo (service-run)"
  printf 'bravo service wrapper is pid %s; supervised BEAM is pid %s\n' \
    "$BRAVO_SERVICE_MANAGER_PID" "$pid"
}

start_node() {
  local data_dir=$1
  local label=$2
  node_cmd "$data_dir" daemon | tee "$LOG_DIR/start-$label.log"
  record_lab_pid "$data_dir" "$label"
}

stop_node() {
  local data_dir=$1
  local label=$2
  local identity pid birth
  identity=$(runtime_marker_identity "$data_dir") ||
    die "$label does not have matching publication, owner, and live process identities"
  IFS=$'\t' read -r pid birth <<<"$identity"
  node_cmd "$data_dir" stop | tee "$LOG_DIR/stop-$label.log"
  wait_identity_gone "$pid" "$birth" "$label"
  printf '%s stopped cleanly\n' "$label"
}

doctor_node() {
  local data_dir=$1
  local label=$2
  local output
  output=$(node_cmd "$data_dir" fleet doctor)
  printf '%s\n' "$output" | tee "$LOG_DIR/doctor-$label.log"
  grep -Fq 'live runtime: BEAM distribution is protected with TLS' <<<"$output" ||
    die "$label doctor did not verify TLS distribution"
  grep -Fq 'scope        live runtime + local profile, host, and service checks' <<<"$output" ||
    die "$label doctor fell back to local-only checks"
  ! grep -Fq '  [fix] ' <<<"$output" || die "$label doctor reported a required fix"
}

log "Create one owner and two private per-machine invitations"
node_cmd "$CORE_DATA" fleet create \
  --name "Hermetic Fleet $RUN_ID" \
  --machine "$CORE_MACHINE" \
  --host 127.0.0.1 \
  --gateway-port "$CORE_GATEWAY" \
  --dist-port "$CORE_DIST" | tee "$LOG_DIR/create.log"

FLEET_EPMD_PORT=$(json_integer "$CORE_DATA/fleet/profile.json" epmd_port)
case $(epmd_probe_state "$FLEET_EPMD_PORT") in
  absent)
    LAB_OWNS_EPMD=1
    printf 'lab EPMD port       %s (absent before boot; this lab will retire it)\n' \
      "$FLEET_EPMD_PORT"
    ;;
  compatible)
    printf 'lab EPMD port       %s (compatible daemon predated lab; it will be preserved)\n' \
      "$FLEET_EPMD_PORT"
    ;;
  *)
    die "fleet EPMD port $FLEET_EPMD_PORT became incompatible after profile creation"
    ;;
esac

# Invite bravo first on purpose. Its saved seed list initially lacks alpha, so the test
# later proves a connected BEAM peer can teach it about the late member.
node_cmd "$CORE_DATA" fleet invite \
  --machine "$BRAVO_MACHINE" \
  --host 127.0.0.1 \
  --gateway-port "$BRAVO_GATEWAY" \
  --dist-port "$BRAVO_DIST" \
  --out "$BRAVO_INVITE" | tee "$LOG_DIR/invite-bravo.log"
node_cmd "$CORE_DATA" fleet invite \
  --machine "$ALPHA_MACHINE" \
  --host 127.0.0.1 \
  --gateway-port "$ALPHA_GATEWAY" \
  --dist-port "$ALPHA_DIST" \
  --out "$ALPHA_INVITE" | tee "$LOG_DIR/invite-alpha.log"

assert_private_file "$BRAVO_INVITE"
assert_private_file "$ALPHA_INVITE"

log "Join both new machines without exposing invitation contents"
node_cmd "$BRAVO_DATA" fleet join "$BRAVO_INVITE" | tee "$LOG_DIR/join-bravo.log"
node_cmd "$ALPHA_DATA" fleet join "$ALPHA_INVITE" | tee "$LOG_DIR/join-alpha.log"

[[ -f "$CORE_DATA/fleet/ca-key.pem" ]] || die "the owner lost its fleet signing key"
[[ ! -e "$ALPHA_DATA/fleet/ca-key.pem" && ! -e "$BRAVO_DATA/fleet/ca-key.pem" ]] ||
  die "a joined machine received the owner's fleet signing key"

for material in cookie ca-cert.pem node-cert.pem node-key.pem ssl_dist.conf vm.args; do
  assert_private_file "$CORE_DATA/fleet/$material"
  assert_private_file "$ALPHA_DATA/fleet/$material"
  assert_private_file "$BRAVO_DATA/fleet/$material"
done
assert_private_file "$CORE_DATA/fleet/ca-key.pem"

log "Reverse boot: oldest invitation first, owner last"
start_managed_bravo
wait_status "$BRAVO_DATA" bravo-isolated 2 1 1
if [[ "$LAB_OWNS_EPMD" == 1 ]]; then
  assert_private_file "$BRAVO_DATA/fleet/epmd-owner.json"
  assert_private_file "$BRAVO_DATA/fleet/epmd-owner.lock"
  capture_lab_epmd_ownership ||
    die "could not capture the exact Ouro-owned EPMD marker and process incarnation"
else
  [[ ! -e "$BRAVO_DATA/fleet/epmd-owner.json" ]] ||
    die "a compatible EPMD that predated the lab was incorrectly claimed as Ouro-owned"
fi

start_node "$ALPHA_DATA" alpha
wait_status "$ALPHA_DATA" alpha-partial 3 2 1
wait_status "$BRAVO_DATA" bravo-learned-alpha 3 2 1

start_node "$CORE_DATA" core
wait_status "$CORE_DATA" core-full 3 3 0
wait_status "$ALPHA_DATA" alpha-full 3 3 0
wait_status "$BRAVO_DATA" bravo-full 3 3 0

log "Verify the authenticated three-node mesh and mutual TLS from every machine"
doctor_node "$CORE_DATA" core-full
doctor_node "$ALPHA_DATA" alpha-full
doctor_node "$BRAVO_DATA" bravo-full

log "Remove the original hub gracefully; the two leaves remain connected"
stop_node "$CORE_DATA" core
wait_status "$ALPHA_DATA" alpha-without-hub 3 2 1
wait_status "$BRAVO_DATA" bravo-without-hub 3 2 1

log "Restart the hub and let supervised BEAM formation heal the mesh"
start_node "$CORE_DATA" core-restarted
wait_status "$CORE_DATA" core-recovered 3 3 0
wait_status "$ALPHA_DATA" alpha-after-hub-return 3 3 0
wait_status "$BRAVO_DATA" bravo-after-hub-return 3 3 0

log "Crash the service-owned leaf; the bounded manager restarts it automatically"
BRAVO_CRASH_IDENTITY=$(runtime_marker_identity "$BRAVO_DATA") ||
  die "bravo crash target did not have matching publication, owner, and process identities"
IFS=$'\t' read -r BRAVO_CRASH_PID BRAVO_CRASH_BIRTH <<<"$BRAVO_CRASH_IDENTITY"
signal_exact_process KILL "$BRAVO_CRASH_PID" "$BRAVO_CRASH_BIRTH" "bravo crash target" ||
  die "bravo crash target changed process incarnation; it was preserved"
wait_identity_gone "$BRAVO_CRASH_PID" "$BRAVO_CRASH_BIRTH" bravo-crash
wait_status "$CORE_DATA" core-sees-bravo-offline 3 2 1
wait_status "$ALPHA_DATA" alpha-sees-bravo-offline 3 2 1

BRAVO_RESTART_PID=$(wait_gateway_pid "$BRAVO_DATA" "$BRAVO_CRASH_PID" "service-managed bravo")
record_lab_pid "$BRAVO_DATA" "bravo (automatic replacement)"
[[ "$BRAVO_RESTART_PID" != "$BRAVO_CRASH_PID" ]] || die "bravo restart reused its crashed pid"
grep -Eq '^1:[1-9][0-9]*$' "$SERVICE_STATUSES" ||
  die "service-run did not report the crashed BEAM as a nonzero first attempt"
[[ $(wc -l <"$SERVICE_ATTEMPTS" | tr -d ' ') == 2 ]] ||
  die "the bounded service wrapper did not start exactly one replacement"
wait_status "$CORE_DATA" core-after-crash 3 3 0
wait_status "$ALPHA_DATA" alpha-after-crash 3 3 0
wait_status "$BRAVO_DATA" bravo-after-crash 3 3 0
doctor_node "$BRAVO_DATA" bravo-after-crash

# Give the manager more than one restart delay, then prove the stable publication and
# owner both still name the one replacement rather than a duplicate third runtime.
sleep 2
BRAVO_STABLE_IDENTITY=$(runtime_marker_identity "$BRAVO_DATA") ||
  die "the service replacement publication/owner birth does not match its live BEAM"
IFS=$'\t' read -r BRAVO_STABLE_PID _ <<<"$BRAVO_STABLE_IDENTITY"
[[ "$BRAVO_STABLE_PID" == "$BRAVO_RESTART_PID" ]] ||
  die "the service wrapper published more than one replacement runtime"

log "Crash the owned EPMD; its runtime-health watch triggers one clean service replacement"
BRAVO_EPMD_CRASH_PID=$(json_integer "$BRAVO_DATA/fleet/epmd-owner.json" pid)
BRAVO_EPMD_CRASH_BIRTH=$(current_process_birth "$BRAVO_EPMD_CRASH_PID") ||
  die "owned EPMD pid $BRAVO_EPMD_CRASH_PID disappeared before its birth could be retained"
BRAVO_BEFORE_EPMD_CRASH_IDENTITY=$(runtime_marker_identity "$BRAVO_DATA") ||
  die "bravo EPMD recovery target did not have a verified live runtime identity"
IFS=$'\t' read -r BRAVO_BEFORE_EPMD_CRASH_PID _ <<<"$BRAVO_BEFORE_EPMD_CRASH_IDENTITY"
signal_exact_process KILL "$BRAVO_EPMD_CRASH_PID" "$BRAVO_EPMD_CRASH_BIRTH" \
  "owned EPMD crash target" || die "the EPMD crash target changed incarnation; it was preserved"
BRAVO_EPMD_RECOVERY_PID=$(
  wait_gateway_pid "$BRAVO_DATA" "$BRAVO_BEFORE_EPMD_CRASH_PID" "EPMD-recovered bravo"
)
record_lab_pid "$BRAVO_DATA" "bravo (EPMD health replacement)"
[[ $(wc -l <"$SERVICE_ATTEMPTS" | tr -d ' ') == 3 ]] ||
  die "EPMD loss did not cause exactly one additional service attempt"
BRAVO_REPLACEMENT_EPMD_PID=$(json_integer "$BRAVO_DATA/fleet/epmd-owner.json" pid)
[[ "$BRAVO_REPLACEMENT_EPMD_PID" != "$BRAVO_EPMD_CRASH_PID" ]] ||
  die "EPMD recovery retained the crashed daemon identity"
pid_is_alive "$BRAVO_REPLACEMENT_EPMD_PID" ||
  die "replacement EPMD pid $BRAVO_REPLACEMENT_EPMD_PID is not alive"
[[ $(epmd_probe_state "$FLEET_EPMD_PORT") == compatible ]] ||
  die "replacement EPMD does not answer the NAMES protocol"
capture_lab_epmd_ownership ||
  die "could not capture the replacement EPMD marker and process incarnation"
wait_status "$CORE_DATA" core-after-epmd-crash 3 3 0
wait_status "$ALPHA_DATA" alpha-after-epmd-crash 3 3 0
wait_status "$BRAVO_DATA" bravo-after-epmd-crash 3 3 0
doctor_node "$BRAVO_DATA" bravo-after-epmd-crash
sleep 2
BRAVO_EPMD_STABLE_IDENTITY=$(runtime_marker_identity "$BRAVO_DATA") ||
  die "the EPMD replacement publication/owner birth does not match its live BEAM"
IFS=$'\t' read -r BRAVO_EPMD_STABLE_PID _ <<<"$BRAVO_EPMD_STABLE_IDENTITY"
[[ "$BRAVO_EPMD_STABLE_PID" == "$BRAVO_EPMD_RECOVERY_PID" ]] ||
  die "EPMD recovery started more than one replacement runtime"

log "Deactivate the recovery unit, then stop exactly the three lab runtimes"
: >"$SERVICE_STOP_FILE"
stop_node "$BRAVO_DATA" bravo
if ! wait "$BRAVO_SERVICE_MANAGER_PID"; then
  die "the deactivated service wrapper did not exit cleanly after a graceful runtime stop"
fi
grep -Fqx '3:0' "$SERVICE_STATUSES" ||
  die "the final replacement service-run did not distinguish graceful shutdown from a crash"
[[ $(wc -l <"$SERVICE_ATTEMPTS" | tr -d ' ') == 3 ]] ||
  die "the deactivated recovery unit unexpectedly started a fourth service attempt"
stop_node "$ALPHA_DATA" alpha
stop_node "$CORE_DATA" core

while IFS=$'\t' read -r pid birth data_dir; do
  [[ "$data_dir" == "$CORE_DATA" || "$data_dir" == "$ALPHA_DATA" || "$data_dir" == "$BRAVO_DATA" ]] ||
    die "recorded pid $pid did not come from a lab data directory"
  state=$(process_identity_state "$pid" "$birth")
  case "$state" in
    gone) ;;
    matching) die "lab pid $pid with recorded birth $birth remains alive after cleanup" ;;
    *) die "recorded lab pid $pid was reused or became unverifiable ($state); it was preserved" ;;
  esac
done <"$LAB_PIDS"

log "Exercise production fleet leave against the stopped fleet-specific EPMD"
if [[ "$LAB_OWNS_EPMD" == 1 ]]; then
  node_cmd "$BRAVO_DATA" fleet leave | tee "$LOG_DIR/leave-bravo.log"
  [[ ! -e "$BRAVO_DATA/fleet" ]] ||
    die "fleet leave acknowledged success but retained bravo credentials"
  [[ $(epmd_probe_state "$FLEET_EPMD_PORT") == absent ]] ||
    die "fleet leave did not retire its positively owned empty EPMD port $FLEET_EPMD_PORT"
  LAB_EPMD_CLEANED=1
  printf 'production leave retired Ouro-owned EPMD port %s\n' "$FLEET_EPMD_PORT"
else
  set +e
  node_cmd "$BRAVO_DATA" fleet leave >"$LOG_DIR/leave-bravo-unowned.log" 2>&1
  LEAVE_STATUS=$?
  set -e
  [[ "$LEAVE_STATUS" != 0 ]] ||
    die "fleet leave removed a profile backed by a pre-existing unowned EPMD"
  grep -Fq 'no positive Ouroboros ownership lease' "$LOG_DIR/leave-bravo-unowned.log" ||
    die "fleet leave did not explain why the unowned EPMD was preserved"
  [[ -f "$BRAVO_DATA/fleet/profile.json" ]] ||
    die "fleet leave removed credentials while preserving an unowned EPMD"
  [[ $(epmd_probe_state "$FLEET_EPMD_PORT") == compatible ]] ||
    die "pre-existing EPMD port $FLEET_EPMD_PORT changed while the lab was running"
  printf 'production leave failed closed and preserved pre-existing EPMD port %s\n' \
    "$FLEET_EPMD_PORT"
fi
cleanup_lab_epmd || die "could not safely finish EPMD cleanup for port $FLEET_EPMD_PORT"

log "Prove both ordinary default data directories were untouched"
[[ $(file_snapshot "$ORIGINAL_GATEWAY") == "$ORIGINAL_GATEWAY_SNAPSHOT" ]] ||
  die "the caller's default gateway publication changed"
[[ $(file_snapshot "$ORIGINAL_OWNER") == "$ORIGINAL_OWNER_SNAPSHOT" ]] ||
  die "the caller's default runtime owner changed"
if [[ -n "$ORIGINAL_DEFAULT_PID" ]]; then
  pid_is_alive "$ORIGINAL_DEFAULT_PID" || die "the caller's default runtime pid $ORIGINAL_DEFAULT_PID stopped"
fi
[[ $(cksum <"$ISOLATED_DEFAULT/sentinel") == "$ISOLATED_DEFAULT_SNAPSHOT" ]] ||
  die "a lab command touched its ordinary default data sentinel"
[[ $(find "$ISOLATED_DEFAULT" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ') == 1 ]] ||
  die "a lab command wrote unexpected files to its ordinary default data directory"

printf '\nPASS: packaged three-node fleet created, joined, formed in reverse order, survived hub loss, and automatically recovered a service-owned SIGKILL over TLS.\n'
printf 'PASS: stopped only lab runtimes; caller default pid/data stayed untouched.\n'
