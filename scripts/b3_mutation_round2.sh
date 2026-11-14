#!/usr/bin/env bash
# B3 MUTATION PROOF — ROUND 2 (owner order 2026-11-14, item 1): re-run the
# four mutations (A/B/C/D, originally 2026-11-11) against the MODIFIED test
# setup — the api suite now asserts both terminal paths, and the NEW
# cancel-live.deterministic suite pins the «actually cancelled» branch on
# every run (frozen SIGSTOP engine — nothing can complete it).
#
# The owner's concern: an api test that accepts both outcomes might no
# longer kill the mutations. Each pass runs BOTH layers:
#   (a) the two deterministic suites (engine/DB level, direct DB access)
#   (b) the full api integration suite over HTTP (canonical bash runner)
# A mutation counts as KILLED when rc!=0 in either layer.
#
# Discipline (unchanged): every mutation REVERSED after its pass
# (git checkout --), diff printed from git, numbers from source.
set -uo pipefail
cd /tmp/wt8 || exit 9
export INTEGRATION_PORT=3179

run_suites () {  # $1 = label
  local log="/tmp/b3r2-$1.log"
  : >"$log"
  # (a) engine-level deterministic suites (direct DB, no HTTP)
  DATABASE_URL="postgresql://postgres@127.0.0.1:55432/burhan" \
  BURHAN_DATA_DIR="/tmp/burhan-test-data" \
  bun test --timeout 30000 \
    tests/cancel-race.deterministic.test.ts \
    tests/cancel-live.deterministic.test.ts >>"$log" 2>&1
  local rc_det=$?
  # (b) HTTP layer: full api suite via the canonical runner (bash-managed
  # server + fresh PG) — kills the route-level mutations (B, D).
  # The throwaway owner-gate store must be REMOVED first: a stale store
  # from an earlier round makes the runner skip BURHAN_OWNER_PASSWORD
  # export (file exists) → the new server has a gate but no password →
  # every engine spawn dies on getpass EOF (demo suite). One round = one
  # fresh gate with its inherited password.
  rm -f /tmp/burhan-integration-gate.json
  env -u DATABASE_URL -u MIGRATION_DATABASE_URL \
    bash scripts/run_integration_tests.sh >>"$log" 2>&1
  local rc_api=$?
  local rc=$(( rc_det | rc_api ))
  echo "== $1: rc=$rc (det=$rc_det api=$rc_api) | $(grep -cE '\(pass\)' "$log") pass | $(grep -cE '\(fail\)' "$log") fail"
  grep -E "\(fail\)" "$log" | grep -v "^$" | head -8
}

echo "=== PASS 0 — GREEN baseline (pristine merged main 6115fc0c) ==="
run_suites green

echo; echo "=== PASS 1 — MUT-A: cancel skips the status transition (wrong status literal) ==="
python3 - <<'PY'
import pathlib
p = pathlib.Path("/tmp/wt8/src/lib/engine.ts")
t = p.read_text()
old = '''  // state advance + audit in ONE transaction (item 1.3, fail-closed)
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scanId },
      data: { status: "CANCELLED", finishedAt: new Date(), error: "أُلغي الفحص بواسطة المستخدم" },
    });'''
new = '''  // MUTATION A (proof run): the kill happens but the row never advances
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scanId },
      data: { status: "CANCELLED-MUTATION-NOT-A-REAL-STATUS" },
    });'''
assert old in t, "MUT-A anchor not found"
p.write_text(t.replace(old, new))
print("MUT-A applied: status update corrupted (wrong status literal)")
PY
git diff --stat | grep -v run_integration
run_suites mutA
git checkout -- src/lib/engine.ts && echo "MUT-A reversed"

echo; echo "=== PASS 2 — MUT-B: DELETE route lies (ok:true, no cancel work) ==="
python3 - <<'PY'
import pathlib
p = pathlib.Path("/tmp/wt8/src/app/api/scans/[id]/route.ts")
t = p.read_text()
old = '''    await reconcileScan(scan.id).catch(() => null);
    const result = await engineCancelScanDetailed(scan.id);'''
new = '''    await reconcileScan(scan.id).catch(() => null);
    // MUTATION B (proof run): report success without doing the work
    return NextResponse.json({ ok: true, cancelled: true, reason: "cancelled" });'''
assert old in t, "MUT-B anchor not found"
p.write_text(t.replace(old, new))
print("MUT-B applied: DELETE returns ok without cancelling")
PY
git diff --stat | grep -v run_integration
run_suites mutB
git checkout -- "src/app/api/scans/[id]/route.ts" && echo "MUT-B reversed"

echo; echo "=== PASS 3 — MUT-C: transaction drops the audit write ==="
python3 - <<'PY'
import pathlib
p = pathlib.Path("/tmp/wt8/src/lib/engine.ts")
t = p.read_text()
old = '''  // state advance + audit in ONE transaction (item 1.3, fail-closed)
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scanId },
      data: { status: "CANCELLED", finishedAt: new Date(), error: "أُلغي الفحص بواسطة المستخدم" },
    });
    await audit("scan.cancelled", { orgId: scan.orgId, userId: scan.createdById, detail: { scanId } }, tx);
  });
}'''
new = '''  // MUTATION C (proof run): the status advances but the audit write is
  // silently dropped — the exact regression the audit assertion exists for.
  await db.scan.update({
    where: { id: scanId },
    data: { status: "CANCELLED", finishedAt: new Date(), error: "أُلغي الفحص بواسطة المستخدم" },
  });
}'''
assert old in t, "MUT-C anchor not found"
p.write_text(t.replace(old, new))
print("MUT-C applied: cancel no longer writes scan.cancelled")
PY
git diff --stat | grep -v run_integration
run_suites mutC
git checkout -- src/lib/engine.ts && echo "MUT-C reversed"

echo; echo "=== PASS 4 — MUT-D: DELETE returns a different response shape ==="
python3 - <<'PY'
import pathlib
p = pathlib.Path("/tmp/wt8/src/app/api/scans/[id]/route.ts")
t = p.read_text()
old = '''    if (result.outcome === "already_completed") {
      return NextResponse.json({
        ok: false,
        cancelled: false,
        reason: "already_completed",
        finalStatus: result.finalStatus,
      });
    }
    if (result.outcome === "not_found") {
      return NextResponse.json({ ok: false, cancelled: false, reason: "not_found" }, { status: 404 });
    }
    return NextResponse.json({ ok: true, cancelled: true, reason: "cancelled" });'''
new = '''    // MUTATION D (proof run): same work, different response shape — the
    // client contract (UI + API consumers) silently breaks.
    return NextResponse.json({ success: result.outcome === "cancelled" });'''
assert old in t, "MUT-D anchor not found"
p.write_text(t.replace(old, new))
print("MUT-D applied: DELETE now returns {success} instead of {ok,cancelled,reason}")
PY
git diff --stat | grep -v run_integration
run_suites mutD
git checkout -- "src/app/api/scans/[id]/route.ts" && echo "MUT-D reversed"
git diff --stat | grep -v run_integration && echo "(clean — only the runner-file addition remains)"
echo "=== ROUND 2 PROOF COMPLETE ==="
