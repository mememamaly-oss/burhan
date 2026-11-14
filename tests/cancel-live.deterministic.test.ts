/**
 * DETERMINISTIC "actually cancelled" path (owner order 2026-11-14, item 1).
 *
 * The api-suite cancel test asserts BOTH terminal outcomes (the race is
 * environmental), which means the «actually cancelled» branch may pass a
 * whole CI round via the already_completed branch alone. This suite pins
 * the cancel branch with ZERO timing luck, every single run:
 *
 *   1. a RUNNING scan row is created with a LIVE-but-suspended engine
 *      process (SIGSTOP — the process exists, owns no result.json, and
 *      cannot finish because it is frozen);
 *   2. reconcileScan() runs first (exactly as the DELETE endpoint does)
 *      and CANNOT complete the scan: no result.json + pidAlive → the row
 *      stays RUNNING (this is the step the old flaky test raced through);
 *   3. engineCancelScanDetailed() must then take the «actually cancelled»
 *      branch: SIGTERM to the process group, row → CANCELLED, and the
 *      scan.cancelled audit pair lands (fail-closed item 1.3).
 *
 * The engine process is a real `python3 -c` sleeper under SIGSTOP — the
 * same kill path as a real scan (process group, pidAlive), but with no
 * network and no I/O, so nothing can race the assertion sequence.
 *
 * HTTP-level: the DELETE endpoint itself is exercised over the wire in
 * the api suite (both branches); this suite pins the engine-level state
 * machine deterministically. Together the two cover the contract fully.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { db } from "@/lib/db";
import { engineCancelScanDetailed, reconcileScan, scanDirFor } from "@/lib/engine";

let orgId: string, targetId: string, scanId: string, userId: string;
let frozenPid: number | null = null;

beforeAll(async () => {
  if (!process.env.DATABASE_URL) throw new Error("requires DATABASE_URL (PostgreSQL)");
  // minimal graph: user + org + target + a RUNNING scan row
  const user = await db.user.create({
    data: {
      email: `cancel-live-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@test.local`,
      name: "Cancel Live", passwordHash: "x",
    },
  });
  userId = user.id;
  const org = await db.organization.create({
    data: { name: "cancel-live-org", slug: `cancel-live-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` },
  });
  orgId = org.id;
  await db.membership.create({ data: { orgId, userId, role: "OWNER" } });
  const target = await db.target.create({
    data: { orgId, createdById: userId, name: "cancel-live-target", url: "https://suspended-engine.test/" },
  });
  targetId = target.id;

  // A REAL, LIVE, FROZEN engine process: spawned detached (own process
  // group, exactly like engineStartScan), then SIGSTOPped so it can never
  // write result.json. pidAlive() sees it; reconcileScan() sees it; the
  // cancel path SIGTERMs it for real.
  const child = spawn("python3", ["-c", "import time; time.sleep(600)"], {
    stdio: "ignore", detached: true,
  });
  child.unref();
  frozenPid = child.pid ?? null;
  if (!frozenPid) throw new Error("failed to spawn the frozen engine process");
  process.kill(frozenPid, "SIGSTOP");
  // wait until the process is really alive (spawn pid reuse guard)
  await new Promise((r) => setTimeout(r, 300));

  const dir = scanDirFor(`live-${frozenPid}`);
  fs.mkdirSync(dir, { recursive: true });

  const scan = await db.scan.create({
    data: {
      orgId, targetId, createdById: userId,
      status: "RUNNING",
      enginePid: frozenPid,
      optionsJson: JSON.stringify({ maxPages: 1, timeout: 5 }),
      startedAt: new Date(),
      resultPath: path.join(dir, "result.json"), // deliberately NOT written
      logPath: path.join(dir, "log.txt"),
    },
  });
  scanId = scan.id;
});

afterAll(async () => {
  // scoped cleanup — no shared state leaks into other suites
  if (frozenPid) {
    try { process.kill(frozenPid, "SIGCONT"); } catch { /* gone */ }
    try { process.kill(frozenPid, "SIGTERM"); } catch { /* gone */ }
  }
  await db.scan.deleteMany({ where: { id: scanId } }).catch(() => null);
  await db.target.deleteMany({ where: { id: targetId } }).catch(() => null);
  await db.membership.deleteMany({ where: { orgId } }).catch(() => null);
  await db.organization.deleteMany({ where: { id: orgId } }).catch(() => null);
  await db.user.deleteMany({ where: { id: userId } }).catch(() => null);
});

describe("deterministic actually-cancelled sequence (owner order 2026-11-14, item 1)", () => {
  test("STEP 1: reconcileScan on a live frozen engine leaves the row RUNNING (the anti-race pin)", async () => {
    await reconcileScan(scanId);
    const row = await db.scan.findUnique({ where: { id: scanId } });
    expect(row?.status).toBe("RUNNING"); // live pid + no result → nothing to import
    expect(row?.finishedAt).toBeFalsy();
  });

  test("STEP 2: the cancel takes the «actually cancelled» branch — EVERY run, no luck", async () => {
    const result = await engineCancelScanDetailed(scanId);
    expect(result.outcome).toBe("cancelled");
    expect(result.ok).toBe(true);
    const row = await db.scan.findUnique({ where: { id: scanId } });
    expect(row?.status).toBe("CANCELLED");
    expect(row?.finishedAt).toBeTruthy();
    expect(row?.error).toContain("أُلغي الفحص");
  });

  test("STEP 3: the audit pair landed (fail-closed item 1.3 — MUT-C's target)", async () => {
    const auditRows = await db.auditLog.findMany({
      where: { action: "scan.cancelled", orgId },
      orderBy: { createdAt: "desc" },
      take: 5,
    });
    const hit = auditRows.some(
      (r) =>
        (r.detail ?? "").includes(`"scanId":"${scanId}"`) ||
        (r.detail ?? "").includes(`"scanId": "${scanId}"`)
    );
    expect(hit).toBe(true);
  });

  test("STEP 4: the frozen engine process is really dead (the kill actually happened)", async () => {
    expect(frozenPid).toBeTruthy();
    // SIGTERM to a SIGSTOPped process stays pending until SIGCONT — so
    // continue it and observe the pending termination land.
    try { process.kill(frozenPid!, "SIGCONT"); } catch { /* gone */ }
    let alive = true;
    const t0 = Date.now();
    while (Date.now() - t0 < 3000) {
      try { process.kill(frozenPid!, 0); await new Promise((r) => setTimeout(r, 100)); }
      catch { alive = false; break; }
    }
    expect(alive).toBe(false);
  });

  test("STEP 5: a second cancel now reports already_completed (terminal, honest)", async () => {
    const result = await engineCancelScanDetailed(scanId);
    expect(result.outcome).toBe("already_completed");
    expect(result.finalStatus).toBe("CANCELLED");
    expect(result.ok).toBe(false);
  });
});
