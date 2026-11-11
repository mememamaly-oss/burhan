#!/usr/bin/env bash
# B3 MUTATION PROOF — PART 2 (owner order 2026-11-11, after A/B):
# MUT-C: engine.ts drops the scan.cancelled audit write      -> audit hit fails
# MUT-D: route.ts returns a DIFFERENT response shape          -> body.ok/.cancelled fail
# Same discipline as part 1: every mutation reversed after its pass, diff
# printed from git (numbers from source), only the api suite is targeted.
set -uo pipefail
WT=/home/z/my-project/burhan-mut2
cd "$WT" || exit 9
export INTEGRATION_PORT=3178

run_api_suite () {  # $1 = label
  rm -f /tmp/burhan-integration-gate.json
  mkdir -p saas-data
  local log="/tmp/b3mut2-$1.log" rc
  env -u DATABASE_URL -u MIGRATION_DATABASE_URL \
    bash scripts/run_integration_tests.sh >"$log" 2>&1
  rc=$?
  local member
  member=$(grep -E "MEMBER can start a scan on their OWN target" "$log" | head -1)
  local fails
  fails=$(grep -cE "\(fail\)" "$log")
  echo "== $1: rc=$rc | $member | suite fails: $fails"
  grep -B1 -A6 "error: expect" "$log" | head -14
}

echo "=== PASS 0 — GREEN baseline (pristine merged main 87575117da) ==="
run_api_suite green

echo; echo "=== PASS 1 — MUT-C: transaction drops the audit write ==="
python3 - <<'PY'
import pathlib
p = pathlib.Path("/home/z/my-project/burhan-mut2/src/lib/engine.ts")
t = p.read_text()
old = '''  // state advance + audit in ONE transaction (item 1.3, fail-closed)
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scanId },
      data: { status: "CANCELLED", finishedAt: new Date(), error: "أُلغي الفحص بواسطة المستخدم" },
    });
    await audit("scan.cancelled", { orgId: scan.orgId, userId: scan.createdById, detail: { scanId } }, tx);
  });
  return true;'''
new = '''  // MUTATION C (proof run): the status advances but the audit write is
  // silently dropped — the exact regression the audit assertion exists for.
  await db.scan.update({
    where: { id: scanId },
    data: { status: "CANCELLED", finishedAt: new Date(), error: "أُلغي الفحص بواسطة المستخدم" },
  });
  return true;'''
assert old in t, "MUT-C anchor not found"
p.write_text(t.replace(old, new))
print("MUT-C applied: cancel transaction no longer writes scan.cancelled")
PY
git diff --stat
run_api_suite mutC
git checkout -- src/lib/engine.ts && echo "MUT-C reversed"
git diff --stat && echo "(clean)"

echo; echo "=== PASS 2 — MUT-D: DELETE returns a different response shape ==="
python3 - <<'PY'
import pathlib
p = pathlib.Path("/home/z/my-project/burhan-mut2/src/app/api/scans/[id]/route.ts")
t = p.read_text()
old = '''    await reconcileScan(scan.id).catch(() => null);
    const ok = await engineCancelScan(scan.id);
    return NextResponse.json({ ok, cancelled: ok });'''
new = '''    await reconcileScan(scan.id).catch(() => null);
    const ok = await engineCancelScan(scan.id);
    // MUTATION D (proof run): same work, different response shape — the
    // client contract (UI + API consumers) silently breaks.
    return NextResponse.json({ success: ok });'''
assert old in t, "MUT-D anchor not found"
p.write_text(t.replace(old, new))
print("MUT-D applied: DELETE now returns {success} instead of {ok,cancelled}")
PY
git diff --stat
run_api_suite mutD
git checkout -- "src/app/api/scans/[id]/route.ts" && echo "MUT-D reversed"
git diff --stat && echo "(clean)"
echo; echo "=== PART 2 PROOF COMPLETE ==="
