#!/bin/sh
# A fake `ouro` that speaks the frames front end of docs/proposals/fleet-kiss.md §8.
#
# The broker runs it as `ouro fleet <kind> … --frames --operation <id>` and talks NDJSON to
# its stdin and stdout. Everything it does is scripted by a file named in
# OUROBOROS_FAKE_SCENARIO, one directive per line, so a test states the deployment it wants
# — a host-key question, three password attempts, a plan, a failure — instead of a fake
# module growing a flag per case.
#
# It also answers `fleet devices --json` from OUROBOROS_FAKE_DEVICES, because the same
# executable is the one the broker resolves through OUROBOROS_PROCESS_ID_HELPER for both.
#
# Environment:
#   OUROBOROS_DATA_DIR        where the journal and the log go, as the real `ouro` reads it
#   OUROBOROS_FAKE_SCENARIO   the directive file for a frames run
#   OUROBOROS_FAKE_DEVICES    the JSON `fleet devices --json` prints
#   OUROBOROS_FAKE_ARGV       every argument of the last run, one per line
#   OUROBOROS_FAKE_RESPONSES  every line read from stdin, appended verbatim
#
# Directives:
#   state <running|waiting|completed|failed|cancelled>
#   step <name> <ok|failed|skipped|attempted> <detail|->
#   log <text…>                  a `log` frame
#   stderr <text…>               a line in <id>.log, which is not a frame
#   plan <line…>                 one line of the plan the review challenge carries
#   challenge <id> <kind> <metadata-json>
#   await <id>                   block on stdin until that challenge is answered or cancelled
#   done <state> <summary…>
#   raw <text…>                  written to stdout as it is, which is how a line that is not
#                                a frame gets there
#   bigline                      one line past the 1 MiB frame cap
#   error <reason> <detail…>     the journal's last_error from here on
#   sleep <seconds>
#   drain                        read stdin to EOF and keep going
#   exit <status>

set -u

fake_argv="${OUROBOROS_FAKE_ARGV:-}"
if [ -n "$fake_argv" ]; then
  : > "$fake_argv"
  for arg in "$@"; do printf '%s\n' "$arg" >> "$fake_argv"; done
fi

if [ "${1:-}" = "fleet" ] && [ "${2:-}" = "devices" ]; then
  cat "${OUROBOROS_FAKE_DEVICES:-/dev/null}"
  exit 0
fi

kind="${2:-}"
operation=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--operation" ]; then operation="$arg"; fi
  previous="$arg"
done

if [ -z "$operation" ]; then
  echo "fake ouro: no --operation on $*" >&2
  exit 64
fi

deploy="${OUROBOROS_DATA_DIR:-}/deploy"
mkdir -p "$deploy"
chmod 700 "$deploy"
journal="$deploy/$operation.json"
log="$deploy/$operation.log"

# §8: stderr goes to <data dir>/deploy/<id>.log, not to whatever this was started from.
: >> "$log"
chmod 600 "$log"
exec 2>> "$log"

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
steps=""
plan=""
state="running"
last_error="null"
eof=0
cancelled=0

write_journal() {
  printf '{"schema":2,"operation":"%s","kind":"%s","state":"%s","created_at":"%s","updated_at":"%s","target":{"machine":"%s","address":"%s","ssh_user":"%s","port":%s},"paths":{},"plan":[%s],"steps":[%s],"residue":[],"last_error":%s}\n' \
    "$operation" "$kind" "$state" "$now" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${OUROBOROS_FAKE_MACHINE:-fixture-target}" "${OUROBOROS_FAKE_ADDRESS:-100.100.7.1}" \
    "${OUROBOROS_FAKE_USER:-deploy}" "${OUROBOROS_FAKE_PORT:-22}" \
    "$plan" "$steps" "$last_error" > "$journal.tmp"
  chmod 600 "$journal.tmp"
  mv "$journal.tmp" "$journal"
}

# Nothing is written to stdout once stdin has closed: §8's program finishes the operation,
# keeps writing its journal, and stops writing frames nobody is reading.
emit() {
  if [ "$eof" -eq 0 ]; then printf '%s\n' "$1"; fi
}

await() {
  want="$1"
  while IFS= read -r incoming; do
    if [ -n "${OUROBOROS_FAKE_RESPONSES:-}" ]; then
      printf '%s\n' "$incoming" >> "${OUROBOROS_FAKE_RESPONSES}"
    fi
    case "$incoming" in
      *'"op":"cancel"'*)
        cancelled=1
        return 0
        ;;
      *"\"challenge\":\"$want\""*)
        return 0
        ;;
    esac
  done
  eof=1
}

finish_cancelled() {
  state="cancelled"
  write_journal
  emit '{"event":"state","state":"cancelled"}'
  emit '{"event":"done","state":"cancelled","summary":"stopped at a safe boundary"}'
  exit 0
}

write_journal

# OUROBOROS_FAKE_SCENARIO is either one directive file, or a directory of them — in which
# case the run picks `<kind>-<machine>`, then `<kind>`, then `default`. A fixture that has to
# script four different deployments against one runtime needs the second shape; a test that
# scripts one needs the first, and rewrites it between cases.
scenario="${OUROBOROS_FAKE_SCENARIO:-/dev/null}"

if [ -d "$scenario" ]; then
  machine=""
  previous=""
  for arg in "$@"; do
    if [ "$previous" = "--machine" ]; then machine="$arg"; fi
    previous="$arg"
  done

  for candidate in "$kind-$machine" "$kind" "default"; do
    if [ -f "$scenario/$candidate" ]; then
      scenario="$scenario/$candidate"
      break
    fi
  done
fi

exec 3< "$scenario"

while IFS= read -r line <&3; do
  case "$line" in
    ''|'#'*) continue ;;
  esac

  directive=${line%% *}
  rest=${line#"$directive"}
  rest=${rest# }

  case "$directive" in
    state)
      state="$rest"
      write_journal
      emit "{\"event\":\"state\",\"state\":\"$rest\"}"
      ;;
    step)
      name=${rest%% *}
      tail_of=${rest#"$name"}
      tail_of=${tail_of# }
      outcome=${tail_of%% *}
      detail=${tail_of#"$outcome"}
      detail=${detail# }

      if [ "$detail" = "-" ] || [ -z "$detail" ]; then
        detail_json=null
      else
        detail_json="\"$detail\""
      fi

      entry="{\"step\":\"$name\",\"state\":\"$outcome\",\"at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"detail\":$detail_json}"
      if [ -z "$steps" ]; then steps="$entry"; else steps="$steps,$entry"; fi
      write_journal
      emit "{\"event\":\"step\",\"step\":\"$name\",\"state\":\"$outcome\",\"detail\":$detail_json}"
      ;;
    plan)
      if [ -z "$plan" ]; then plan="\"$rest\""; else plan="$plan,\"$rest\""; fi
      write_journal
      ;;
    log)
      emit "{\"event\":\"log\",\"line\":\"$rest\"}"
      ;;
    stderr)
      printf '%s\n' "$rest" >> "$log"
      chmod 600 "$log"
      ;;
    challenge)
      id=${rest%% *}
      tail_of=${rest#"$id"}
      tail_of=${tail_of# }
      ckind=${tail_of%% *}
      meta=${tail_of#"$ckind"}
      meta=${meta# }
      if [ -z "$meta" ]; then meta="{}"; fi

      if [ "$ckind" = "review" ] && [ "$meta" = "{}" ]; then
        meta="{\"plan\":[$plan]}"
      fi

      emit "{\"event\":\"challenge\",\"challenge\":\"$id\",\"kind\":\"$ckind\",\"expires_at\":\"${OUROBOROS_FAKE_EXPIRES:-2099-01-01T00:00:00Z}\",\"metadata\":$meta}"
      ;;
    await)
      await "$rest"
      if [ "$cancelled" -eq 1 ]; then finish_cancelled; fi
      ;;
    done)
      dstate=${rest%% *}
      summary=${rest#"$dstate"}
      summary=${summary# }
      state="$dstate"
      write_journal
      emit "{\"event\":\"done\",\"state\":\"$dstate\",\"summary\":\"$summary\"}"
      ;;
    raw)
      emit "$rest"
      ;;
    bigline)
      if [ "$eof" -eq 0 ]; then
        awk 'BEGIN { for (i = 0; i < 1048640; i++) printf "x"; printf "\n" }'
      fi
      ;;
    error)
      reason=${rest%% *}
      detail=${rest#"$reason"}
      detail=${detail# }
      last_error="{\"reason\":\"$reason\",\"detail\":\"$detail\"}"
      write_journal
      ;;
    sleep)
      sleep "$rest"
      ;;
    drain)
      while IFS= read -r incoming; do
        if [ -n "${OUROBOROS_FAKE_RESPONSES:-}" ]; then
          printf '%s\n' "$incoming" >> "${OUROBOROS_FAKE_RESPONSES}"
        fi
      done
      eof=1
      ;;
    exit)
      exit "$rest"
      ;;
    *)
      echo "fake ouro: unknown directive $directive" >&2
      exit 65
      ;;
  esac
done

exit 0
