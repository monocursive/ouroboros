#!/bin/sh
# Development lifecycle for the checkout's three artifacts: the dev daemon (a BEAM
# runtime started from this checkout), the terminal client, and the macOS desktop app.
#
# `ouro --dev` already owns the hard parts — the isolated `ouroboros-dev` data
# directory, the spawn lock, stale-publication recovery, and clean shutdown. This script
# is the operator layer around it: say what is running, refuse to restart onto code that
# does not compile, notice when a running daemon predates the code on disk, and find the
# stray daemons that accumulate when none of that exists (three of them did, on the day
# this file was written).
#
# Verbs: status | daemon | daemon-stop | daemon-restart | gui | gui-stop | stop-all | logs
# Honour OUROBOROS_DATA_DIR when the caller sets one (ouro --dev does the same, with a
# warning), so a scratch cycle never touches the real dev runtime.

set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${OUROBOROS_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/ouroboros-dev}"
GATEWAY="$DATA_DIR/gateway.json"
OURO="$REPO/tui/target/debug/ouro"
APP="$REPO/tui/target/debug/Ouroboros.app"

say() { printf '%s\n' "$*"; }

# One numeric field out of gateway.json. The file is flat JSON on one line; a dependency
# on jq for two integers would be a dependency nothing else here needs. Emitted through
# `say`, because the file carries no trailing newline and BSD sed preserves that — two
# raw extractions in a row would read as one glued number.
json_pid_of() {
    value="$(sed -n 's/.*"'"$2"'":\([0-9][0-9]*\).*/\1/p' "$1" | head -1)"
    [ -n "$value" ] && say "$value"
    return 0
}

gateway_field() {
    [ -f "$GATEWAY" ] || return 0
    json_pid_of "$GATEWAY" "$1"
}

alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

# The published daemon pid, but only while that process is actually alive — a gateway
# file whose writer is gone is a stale publication, not a daemon.
daemon_pid() {
    pid="$(gateway_field pid)"
    if alive "$pid"; then say "$pid"; fi
}

# Seconds since a process started, from `ps -o etime=` — portable across BSD and GNU,
# unlike parsing `lstart` locale strings. Formats: mm:ss, hh:mm:ss, dd-hh:mm:ss.
proc_age() {
    ps -p "$1" -o etime= 2>/dev/null | awk -F'[-:]' '{
        n = NF; s = $(n); m = (n >= 2) ? $(n-1) : 0
        h = (n >= 3) ? $(n-2) : 0; d = (n >= 4) ? $(n-3) : 0
        print ((d * 24 + h) * 60 + m) * 60 + s
    }'
}

# When the runtime's source last changed, as seconds-ago: the newer of the last commit
# and the newest working-tree edit under the Elixir half. Used only to *say* a daemon is
# stale, never to restart one behind the operator's back.
source_age() {
    now="$(date +%s)"
    committed="$(git -C "$REPO" log -1 --format=%ct -- lib config mix.exs 2>/dev/null || say "$now")"
    newest_file="$( (find "$REPO/lib" "$REPO/config" "$REPO/mix.exs" -type f -name '*.ex*' \
        -exec stat -f %m {} + 2>/dev/null || \
        find "$REPO/lib" "$REPO/config" "$REPO/mix.exs" -type f -name '*.ex*' \
        -exec stat -c %Y {} + 2>/dev/null) | sort -n | tail -1)"
    newest="$committed"
    [ -n "$newest_file" ] && [ "$newest_file" -gt "$newest" ] && newest="$newest_file"
    say $((now - newest))
}

# Every `mix run --no-halt` BEAM whose environment names this checkout: the daemons this
# repository started, whoever started them and however long ago.
repo_daemons() {
    ps -axww -o pid=,command= | awk '/mix run --no-halt/ {print $1}' | while read -r pid; do
        if ps -p "$pid" -wwE -o command= 2>/dev/null | grep -qF "$REPO"; then
            say "$pid"
        fi
    done
}

# The pids that are *published* — by this run's gateway and by the default dev one.
# Everything else `repo_daemons` finds is a stray. The default dir is always consulted so
# that a scratch OUROBOROS_DATA_DIR cycle can never read the real dev daemon as a stray
# and stop it.
published_pids() {
    gateway_field pid
    default_gateway="${XDG_DATA_HOME:-$HOME/.local/share}/ouroboros-dev/gateway.json"
    if [ "$default_gateway" != "$GATEWAY" ] && [ -f "$default_gateway" ]; then
        json_pid_of "$default_gateway" pid
    fi
}

is_published() {
    for known in $(published_pids); do
        [ "$1" = "$known" ] && return 0
    done
    return 1
}

ensure_ouro() {
    if [ ! -x "$OURO" ]; then
        say "==> building ouro (debug)"
        (cd "$REPO/tui" && cargo build --bin ouro)
    fi
}

ensure_app() {
    if [ ! -x "$APP/Contents/MacOS/ouro-desktop" ]; then
        (cd "$REPO" && make desktop-dev)
    fi
}

# Matched by bundle-relative suffix, not absolute path: the app is launched both ways
# (`open` uses the absolute bundle, a shell often uses `./tui/target/...`), and a
# lifecycle that only sees one spelling restarts nothing while claiming it did.
gui_pid() { pgrep -f "Ouroboros.app/Contents/MacOS/ouro-desktop" 2>/dev/null | head -1 || true; }

daemon_start() {
    ensure_ouro
    pid="$(daemon_pid)"
    if [ -n "$pid" ]; then
        say "dev daemon already running: pid $pid, port $(gateway_field port) ($DATA_DIR)"
        return 0
    fi
    (cd "$REPO" && "$OURO" --dev daemon)
}

daemon_stop() {
    pid="$(daemon_pid)"
    if [ -z "$pid" ]; then
        say "no dev daemon is running ($DATA_DIR)"
        return 0
    fi
    say "==> stopping dev daemon (pid $pid)"
    (cd "$REPO" && "$OURO" --dev stop) || kill -TERM "$pid" 2>/dev/null || true
    i=0
    while alive "$pid" && [ "$i" -lt 20 ]; do sleep 0.5; i=$((i + 1)); done
    if alive "$pid"; then
        say "daemon pid $pid did not stop; inspect it before using kill -9" >&2
        exit 1
    fi
    say "stopped"
}

# Compile *before* stopping anything: code that does not build must never cost the
# operator their running daemon.
daemon_restart() {
    say "==> compiling this checkout first, so a broken tree cannot take the daemon down"
    (cd "$REPO" && mix compile)
    daemon_stop
    daemon_start
}

gui_start() {
    ensure_app
    pid="$(gui_pid)"
    if [ -n "$pid" ]; then
        say "==> desktop app already running (pid $pid); restarting it onto this build"
        gui_stop
    fi
    say "==> launching $APP"
    open "$APP" --args --dev
}

gui_stop() {
    pid="$(gui_pid)"
    if [ -z "$pid" ]; then
        say "desktop app is not running"
        return 0
    fi
    osascript -e 'quit app "Ouroboros"' 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    i=0
    while alive "$pid" && [ "$i" -lt 10 ]; do sleep 0.5; i=$((i + 1)); done
    if alive "$pid"; then kill -TERM "$pid" 2>/dev/null || true; fi
    say "desktop app stopped"
}

status() {
    say "checkout   $REPO @ $(git -C "$REPO" log -1 --format='%h %s' 2>/dev/null)"
    say "data dir   $DATA_DIR"

    pid="$(daemon_pid)"
    if [ -n "$pid" ]; then
        port="$(gateway_field port)"
        say "daemon     up: pid $pid, 127.0.0.1:$port"
        # Older than the last source change means it booted code that has since moved.
        if [ "$(proc_age "$pid")" -gt "$(source_age)" ]; then
            say "           STALE: the runtime source changed after this daemon started."
            say "           make daemon-restart to pick the changes up"
        fi
    elif [ -f "$GATEWAY" ]; then
        say "daemon     down (stale gateway.json from pid $(gateway_field pid))"
    else
        say "daemon     down"
    fi

    gpid="$(gui_pid)"
    if [ -n "$gpid" ]; then say "desktop    up: pid $gpid"; else say "desktop    down"; fi

    found=""
    for spid in $(repo_daemons); do
        is_published "$spid" && continue
        found=1
        say "stray      pid $spid, started $(($(proc_age "$spid") / 3600))h ago — make stop stops it"
    done
    if [ -z "$found" ]; then say "strays     none"; fi
}

# A fresh runtime: the daemon stopped, then the data directory emptied — except
# oauth.json, because "start over" should not also mean "sign in to ChatGPT again";
# delete it yourself when that is what you mean. The desktop app is left alone: it only
# shows disconnected once its daemon is gone, and `make gui` is the verb that brings it
# back. The directory itself survives, so its 0700 permissions do. The guard on the name
# is for a mis-set OUROBOROS_DATA_DIR: this verb must never be able to empty a directory
# that is not an ouroboros data dir.
reset() {
    case "$(basename "$DATA_DIR")" in
    *ouro*) ;;
    *)
        say "refusing to reset $DATA_DIR: its name does not look like an ouroboros data dir" >&2
        exit 64
        ;;
    esac
    if [ "$DATA_DIR" = "/" ] || [ "$DATA_DIR" = "$HOME" ] || [ "$DATA_DIR" = "$REPO" ]; then
        say "refusing to reset $DATA_DIR" >&2
        exit 64
    fi

    daemon_stop

    if [ ! -d "$DATA_DIR" ]; then
        say "nothing to reset: $DATA_DIR does not exist"
        return 0
    fi

    say "==> emptying $DATA_DIR (oauth.json kept)"
    find "$DATA_DIR" -mindepth 1 -maxdepth 1 ! -name oauth.json -exec rm -rf {} +
    say "reset. make daemon or make gui starts a fresh runtime"
}

# Everything down: the window, the published daemon, and any stray this checkout leaks.
stop_all() {
    gui_stop
    daemon_stop
    for spid in $(repo_daemons); do
        is_published "$spid" && continue
        say "==> stopping stray daemon pid $spid"
        kill -TERM "$spid" 2>/dev/null || true
    done
}

logs() { exec tail -f "$DATA_DIR/runtime.log"; }

case "${1:-status}" in
status) status ;;
daemon) daemon_start ;;
daemon-stop) daemon_stop ;;
daemon-restart) daemon_restart ;;
gui) gui_start ;;
gui-stop) gui_stop ;;
stop-all) stop_all ;;
reset) reset ;;
logs) logs ;;
*)
    say "usage: dev.sh status|daemon|daemon-stop|daemon-restart|gui|gui-stop|stop-all|reset|logs" >&2
    exit 64
    ;;
esac
