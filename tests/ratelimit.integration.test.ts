/**
 * SHARED-STORE RATE LIMITER (owner order 2026-10-31, part 2.9).
 *
 * RED before the fix (proven): the limiter kept its buckets in a
 * process-local Map — two processes each owned an independent counter, so
 * the login limit (and the demo limit) was NOT enforced across processes:
 * N processes = N x the budget. The deployment is single-process today,
 * but phase3 plans hosted deployments, and the phase3 hosted-tier doc
 * itself leans on the "documented single-process assumption".
 *
 * GREEN after: the buckets live in the EXISTING PostgreSQL (new
 * RateLimitBucket table — no new dependency), every decision runs inside
 * a transaction holding a PG advisory lock on the key (atomic under
 * concurrency), so the limit is enforced GLOBALLY regardless of how many
 * app processes exist.
 */
import { describe, test, expect, beforeAll } from "bun:test";
import { spawn, type ChildProcess } from "child_process";
import { db } from "@/lib/db";
import { rateLimit, resetRateLimits } from "@/lib/rate-limit";

const PG = (process.env.DATABASE_URL || "").startsWith("postgres");
if (!PG) throw new Error("this suite requires a PostgreSQL DATABASE_URL");

const CHILD = "scripts/final-2026-10-31/ratelimit_child.ts";

function runChild(key: string, hits: number, max: number): Promise<{ allowedCount: number; deniedCount: number }> {
  return new Promise((resolve, reject) => {
    const p: ChildProcess = spawn(
      "bun", ["--preload", "./tests/setup.ts", CHILD, key, String(hits), String(max)],
      { cwd: process.cwd(), env: process.env, stdio: ["ignore", "pipe", "pipe"] }
    );
    let out = "";
    p.stdout!.on("data", (d) => (out += d));
    p.stderr!.on("data", (d) => (out += d));
    p.on("close", (code) => {
      try {
        const line = out.split("\n").find((l) => l.trim().startsWith("{"));
        resolve(JSON.parse(line));
      } catch (e) {
        reject(new Error(`child failed (code ${code}): ${out.slice(0, 400)}`));
      }
    });
  });
}

beforeAll(async () => {
  await resetRateLimits();
});

describe("the login rate limit is enforced ACROSS PROCESSES (shared PG store)", () => {
  test("THE 2.9 REGRESSION: process A exhausts the budget; process B is denied on the very first hit", async () => {
    const key = `2p-${Date.now()}`;
    const a = await runChild(key, 10, 10);
    expect(a.allowedCount).toBe(10); // A consumes the full budget alone
    const b = await runChild(key, 5, 10);
    // Before the fix B owned a fresh in-process counter and all 5 were
    // allowed (the vulnerability). Now the shared store denies every one.
    expect(b.allowedCount).toBe(0);
    expect(b.deniedCount).toBe(5);
  });

  test("a fresh key works from both processes (no cross-contamination)", async () => {
    const key = `2p-clean-${Date.now()}`;
    const a = await runChild(key, 5, 10);
    expect(a.allowedCount).toBe(5);
    const b = await runChild(key, 5, 10);
    expect(b.allowedCount).toBe(5); // 5 + 5 = exactly the budget
    const c = await runChild(key, 1, 10);
    expect(c.allowedCount).toBe(0);
  });

  test("in-process: 30 CONCURRENT attempts on a 10-budget key admit at most 10 (advisory-lock atomicity)", async () => {
    await resetRateLimits();
    const key = `conc-${Date.now()}`;
    const verdicts = await Promise.all(
      Array.from({ length: 30 }, () => rateLimit(key, 10, 60_000))
    );
    const allowed = verdicts.filter((v) => v.allowed).length;
    expect(allowed).toBeLessThanOrEqual(10);
    expect(allowed).toBeGreaterThanOrEqual(9); // sanity: not a total outage
  });

  // Window sizing (main-build flake, 2026-11-10, run 42925172174): the
  // original 120ms window assumed 4 sequential PG transactions complete
  // inside 120ms. On a loaded CI runner the 4th call's `now` can land
  // past hits[0]+120ms, the sliding window legitimately forgets the
  // oldest hit, and the 4th hit is ALLOWED — a race in the TEST's clock
  // budget, not in the limiter. 1500ms gives the same semantics ~12x the
  // headroom while keeping every assertion's strength unchanged (block
  // at 4th hit, retryAfter > 0, recovery after the window passes).
  test("sliding window + blockedUntil semantics survive the move to PG", async () => {
    await resetRateLimits();
    const key = `slide-${Date.now()}`;
    for (let i = 0; i < 3; i++) {
      const v = await rateLimit(key, 3, 1_500);
      expect(v.allowed).toBe(true);
    }
    const blocked = await rateLimit(key, 3, 1_500);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
    await new Promise((r) => setTimeout(r, 1_600));
    const later = await rateLimit(key, 3, 1_500);
    expect(later.allowed).toBe(true);
  });

  test("the store really is the database (the table exists and holds the bucket)", async () => {
    const key = `dbproof-${Date.now()}`;
    await rateLimit(key, 1, 60_000);
    const row = await db.rateLimitBucket.findUnique({ where: { key } });
    expect(row).not.toBeNull();
    expect(JSON.parse(row!.hitsJson).length).toBe(1);
  });
});
