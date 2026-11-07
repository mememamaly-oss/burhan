#!/usr/bin/env bash
# READY-WAIT helper (R17-6) — bounded, configurable, backoff-polled.
#
# Why this exists: run_integration_tests.sh inlined a 60 x 1s loop and
# declared FATAL at ~60s. On a loaded Windows host the dev server
# legitimately needed 126s to boot (measured live, Round 17 audit) —
# the runner called a genuinely-starting server dead. A readiness gate
# must bound TOTAL WAIT TIME, not iteration count.
#
# Contract:
#   wait_ready.sh URL [TIMEOUT_SECONDS]
#     - URL                polled with curl -sf -m 2 until HTTP 200
#     - TIMEOUT_SECONDS   default ${BURHAN_READY_TIMEOUT:-180}
#                          (the observed slow start was 126s; 180 gives
#                          ~43% headroom without letting a dead server
#                          stall CI for long — a dead server must still
#                          fail LOUDLY within the bound, which the
#                          tests pin in both directions)
#     - poll interval: 0.5s doubling to a 5s cap (a fast server is
#                          detected fast; a loaded one is not hammered)
#   exit 0  ready   (stdout: "READY after <n>s")
#   exit 1  timeout (stdout: "NOT-READY after <n>s")
set -u
URL="${1:?wait_ready.sh: URL required}"
TIMEOUT="${2:-${BURHAN_READY_TIMEOUT:-180}}"

DEADLINE=$(( $(date +%s) + TIMEOUT ))
START=$(date +%s)
DELAY=5   # tenths of a second: 0.5 -> 1 -> 2 -> 4 -> 5 (cap)
while :; do
  if curl -sf -m 2 "${URL}" >/dev/null 2>&1; then
    echo "READY after $(( $(date +%s) - START ))s"
    exit 0
  fi
  if [ "$(date +%s)" -ge "${DEADLINE}" ]; then
    echo "NOT-READY after $(( $(date +%s) - START ))s"
    exit 1
  fi
  sleep "0.${DELAY}"
  DELAY=$(( DELAY * 2 ))
  [ "${DELAY}" -gt 50 ] && DELAY=50
done
