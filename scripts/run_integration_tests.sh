#!/usr/bin/env bash
# INTEGRATION TEST RUNNER (audit 2026-10-23) — the supported path.
#
# Why a bash runner: the integration suite needs the real Next.js dev
# server. Spawning the server from inside `bun test` proved unreliable in
# sandboxed environments (child-process trees can observe stale file
# content); a bash-managed server + attached test suite is deterministic.
#
# P2-D (2026-10-31): the platform DB is PostgreSQL. Two supported modes:
#   1. DATABASE_URL already provided (CI service container) — used verbatim.
#   2. local dev — scripts/pg_dev_start.sh --reset provisions a FRESH local
#      cluster + database (drop + create) on 127.0.0.1:55432.
# The schema is built with `prisma migrate deploy` (the REAL migration
# files — every integration run re-validates them end to end).
#
# Steps: fresh PG database -> migrate deploy -> boot dev server -> wait
# ready -> run bun test against it -> always kill server -> exit with the
# test's exit code.
set -uo pipefail
cd "$(dirname "$0")/.."

PORT="${INTEGRATION_PORT:-3177}"
LOG="tests/integration-server.log"
URL="http://127.0.0.1:${PORT}"

# P2-D: the platform DB is PostgreSQL. The runner accepts a ready owner URL
# (protocol-checked — CI provides a postgres service container) and provisions
# the local dev cluster for anything else (unset, sqlite leftovers, garbage —
# dev sandboxes re-inject stale env between commands, so the check is by
# PROTOCOL, never by mere presence).
#
# PRIVILEGE SEPARATION (owner order 2026-10-31, items 1.2+2.3): TWO database
# identities.
#   MIGRATION_DATABASE_URL — the owner: `prisma migrate deploy` + role
#                            provisioning (scripts/db_app_role.sh).
#   DATABASE_URL           — the APP: the limited burhan_app role. The dev
#                            server and EVERY suite run with it, so a
#                            privilege regression turns CI red
#                            (tests/privsplit.integration.test.ts asserts
#                            current_user IS the limited role).
case "${MIGRATION_DATABASE_URL:-}" in
  postgresql://*|postgres://*) : ;;  # explicit owner URL (CI)
  *)
    case "${DATABASE_URL:-}" in
      postgresql://*|postgres://*) MIGRATION_DATABASE_URL="${DATABASE_URL}" ;;
      *)  MIGRATION_DATABASE_URL="$(bash scripts/pg_dev_start.sh --reset)" || {
            echo "FATAL: pg_dev_start.sh failed"; exit 1;
          } ;;
    esac
    ;;
esac
export MIGRATION_DATABASE_URL
export NEXTAUTH_SECRET="${NEXTAUTH_SECRET:-integration-test-secret}"
export BURHAN_DATA_DIR="${BURHAN_DATA_DIR:-/tmp/burhan-test-data}"
# item 1.4 (2026-10-31): the proxy-secret gate proof needs the server AND
# the test process to share the secret (positive controls send it as a
# header; forgery tests omit it / send a wrong one)
export TRUSTED_PROXY_SECRET="${TRUSTED_PROXY_SECRET:-integration-proxy-secret}"

# --- clean state -------------------------------------------------------------
pkill -f "next dev -p ${PORT}" 2>/dev/null && sleep 1
rm -f "${LOG}"
mkdir -p "${BURHAN_DATA_DIR}"

# --- schema: the real migration files (never ad-hoc db push) ------------------
# migrations run as the OWNER; the app never gets DDL rights.
if ! DATABASE_URL="${MIGRATION_DATABASE_URL}" bunx prisma migrate deploy >>"${LOG}" 2>&1; then
  echo "FATAL: prisma migrate deploy failed"; cat "${LOG}"; exit 1
fi

# --- provision + switch to the limited app role ---------------------------------
DATABASE_URL="$(bash scripts/db_app_role.sh)" || {
  echo "FATAL: db_app_role.sh failed (owner URL: MIGRATION_DATABASE_URL)"; exit 1;
}
export DATABASE_URL
echo "integration identity: burhan_app (privilege-separated; owner kept for migrations only)"

# --- boot the dev server -------------------------------------------------------
bunx next dev -p "${PORT}" >>"${LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null; pkill -f "next dev -p ${PORT}" 2>/dev/null' EXIT

# R17-6: the READY gate bounds TOTAL WAIT TIME (default 180s, env
# BURHAN_READY_TIMEOUT), not an iteration count — the old 60x1s loop
# called a genuinely-starting server dead on a loaded host (measured:
# 126s boot). A dead server still fails LOUDLY inside the bound; the
# helper's contract is pinned by tests/test_r17_wait_ready.py.
if ! bash scripts/wait_ready.sh "${URL}/api/bootstrap"; then
  echo "FATAL: integration server failed to start"; tail -30 "${LOG}"; exit 1
fi

# --- warm the public routes BEFORE the suite -----------------------------------
# `next dev` compiles routes on first hit; on a cold shared CI runner the
# landing page alone can exceed bun's 5s default test timeout (observed on
# run 41149783779: '/' timed out at exactly 5000ms while every warmed route
# passed). The runner's contract is a READY server — ready means the routes
# the suite hits are compiled, not just the process listening. One shared
# deadline (240s) bounds the whole phase; a route that cannot compile at
# all surfaces fast through the suite instead of hanging here.
WARM_DEADLINE=$(( $(date +%s) + 240 ))
for p in / /login /docs /docs/compliance /docs/ci /docs/deployment /docs/security /demo; do
  while ! curl -sf -m 15 "${URL}${p}" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "${WARM_DEADLINE}" ]; then
      echo "WARN: warmup deadline hit before ${p} answered (suite will surface it)"
      break
    fi
    sleep 1
  done
done
echo "public routes warmed"

# --- run the attached suites ---------------------------------------------------
# Each test file runs in its OWN sequential bun invocation: bun test
# parallelizes FILES within one invocation, and the suites share one
# database + one server (a parallel beforeAll races the bootstrap). Exit
# codes aggregate — any red file fails the run.
RC=0
for F in tests/privsplit.integration.test.ts tests/ratelimit.integration.test.ts tests/api.integration.test.ts tests/bola.integration.test.ts tests/ssrf.integration.test.ts tests/auditlog.integration.test.ts tests/demo.integration.test.ts tests/proxygate.integration.test.ts; do
  echo "--- bun test ${F} ---"
  INTEGRATION_SERVER_URL="${URL}" INTEGRATION_PORT="${PORT}" \
    bun test --timeout 60000 "${F}" || RC=1
done

echo "--- integration runner done (rc=${RC}) ---"
exit "${RC}"
