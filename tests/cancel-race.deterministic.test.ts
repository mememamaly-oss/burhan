/**
 * DETERMINISTIC reproduction of the #105 CI failure (owner order 2026-11-13,
 * decision 2): DELETE /api/scans/:id returned {ok:false} in CI run 43381208733.
 *
 * Root cause hypothesis under test (sequence, no sleep-race needed):
 *   the engine finishes FAST against an unreachable target (writes
 *   result.json in ~1s), exit-reconcile imports it and flips the row to
 *   COMPLETED; engineCancelScan then reads status=COMPLETED and returns
 *   false — the DELETE contract surfaces {ok:false} even though nothing
 *   failed: the scan had simply ENDED before the cancel arrived.
 *
 * This test forces each step in order against a real PostgreSQL database
 * (no HTTP, no timing luck): a RUNNING row + a completed result.json on
 * disk -> reconcileScan() -> engineCancelScan() must return false, and the
 * row must be COMPLETED with its findings imported. That is the exact
 * state the CI failure was in when the endpoint answered ok:false.
 *
 * If this test PASSES, the CI failure is a product-contract gap (canceling
 * an already-finished scan reports failure), not an engine or DB defect.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { db } from "@/lib/db";
import { engineCancelScan, engineCancelScanDetailed, reconcileScan, scanDirFor } from "@/lib/engine";
import fs from "fs";
import path from "path";

let orgId: string, targetId: string, scanId: string, userId: string;

beforeAll(async () => {
  if (!process.env.DATABASE_URL) throw new Error("requires DATABASE_URL (PostgreSQL)");
  // minimal graph: user + org + target + a RUNNING scan row
  const user = await db.user.create({ data: { email: `race-probe-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@test.local`, name: "Race Probe", passwordHash: "x" } });
  userId = user.id;
  const org = await db.organization.create({ data: { name: "race-org", slug: `race-org-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` } });
  orgId = org.id;
  await db.membership.create({ data: { orgId, userId, role: "OWNER" } });
  const target = await db.target.create({ data: { orgId, createdById: userId, name: "race-target", url: "https://member-example.com/" } });
  targetId = target.id;
  const scan = await db.scan.create({
    data: {
      orgId, targetId, createdById: userId,
      status: "RUNNING",
      optionsJson: JSON.stringify({ maxPages: 3, timeout: 5 }),
      startedAt: new Date(),
    },
  });
  scanId = scan.id;
  // a COMPLETE engine result on disk — exactly what the engine leaves after
  // failing fast against an unreachable host (measured locally: 0.53s, 0
  // findings; CI's member-example.com is equally unreachable)
  const dir = scanDirFor(scanId);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "result.json"),
    JSON.stringify({ run_id: "race-run", scanner: "probe", stats: { duration: 0.53, requests: 0 }, findings: [] })
  );
  await db.scan.update({ where: { id: scanId }, data: { resultPath: path.join(dir, "result.json") } });
});

afterAll(async () => {
  // scoped cleanup — no shared state leaks into other suites
  await db.scan.deleteMany({ where: { id: scanId } }).catch(() => null);
  await db.target.deleteMany({ where: { id: targetId } }).catch(() => null);
  await db.membership.deleteMany({ where: { orgId } }).catch(() => null);
  await db.membership.deleteMany({ where: { orgId } }).catch(() => null);
  await db.organization.deleteMany({ where: { id: orgId } }).catch(() => null);
  await db.user.deleteMany({ where: { id: userId } }).catch(() => null);
});

describe("deterministic cancel-after-completion sequence (#105 CI failure)", () => {
  test("STEP 1: reconcileScan imports the finished result and flips the row to COMPLETED", async () => {
    await reconcileScan(scanId);
    const row = await db.scan.findUnique({ where: { id: scanId } });
    expect(row?.status).toBe("COMPLETED");
    expect(row?.finishedAt).toBeTruthy();
  });

  test("STEP 2: cancel on the now-COMPLETED row reports already_completed (the FIX for the #105 CI failure)", async () => {
    const result = await engineCancelScanDetailed(scanId);
    expect(result.ok).toBe(false); // no cancel happened — the scan ended on its own
    expect(result.outcome).toBe("already_completed"); // ← and NOW the caller can tell why
    expect(result.finalStatus).toBe("COMPLETED");
    const row = await db.scan.findUnique({ where: { id: scanId } });
    expect(row?.status).toBe("COMPLETED"); // the row is NOT cancelled — it ended on its own
  });

  test("STEP 3 (legacy boolean preserved): engineCancelScan keeps returning the boolean for old callers", async () => {
    const ok = await engineCancelScan(scanId);
    expect(ok).toBe(false);
  });
});
