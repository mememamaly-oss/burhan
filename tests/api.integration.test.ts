/**
 * HTTP-LEVEL INTEGRATION TESTS (audit 2026-10-23).
 *
 * Boots (or attaches to) the real Next.js dev server on a scratch sqlite
 * database and verifies, over the wire:
 *   1. bootstrap atomicity — 10 concurrent bootstrap POSTs, exactly ONE wins
 *   2. authentication — csrf + credentials login, session cookie flows
 *   3. SSRF chain break — private-network target creation rejected (400)
 *   4. RBAC matrix — VIEWER cannot create; MEMBER cannot scan another
 *      member's target (the write-level fix); cross-org access is 404
 *   5. login rate limiting — the 11th bad attempt is refused
 *
 * Server management: when INTEGRATION_SERVER_URL is set (the canonical
 * path — see scripts/run_integration_tests.sh), the suite attaches to that
 * externally-managed server. Otherwise it self-spawns one (convenience for
 * local iteration; NOTE: in some sandboxed environments a self-spawned
 * server is unreliable — the bash runner is the supported path).
 *
 * Nothing here touches external systems: every request targets 127.0.0.1.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { spawn, type ChildProcess } from "child_process";
import fs from "fs";
import path from "path";
import { db } from "@/lib/db";

const PORT = Number(process.env.INTEGRATION_PORT || 3177);
const BASE = process.env.INTEGRATION_SERVER_URL || `http://127.0.0.1:${PORT}`;
const EXTERNAL = Boolean(process.env.INTEGRATION_SERVER_URL);
const DB_FILE = path.resolve("tests/integration.db");
const SERVER_LOG = path.resolve("tests/integration-server.log");

let server: ChildProcess | null = null;

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitUntil(fn: () => Promise<boolean>, timeoutMs: number, what: string) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await fn()) return;
    await delay(500);
  }
  throw new Error(`timeout waiting for ${what}`);
}

// --- cookie jar (minimal) ---------------------------------------------------

class Jar {
  cookies = new Map<string, string>();
  absorb(res: Response) {
    const raw = res.headers.getSetCookie?.() ?? [];
    for (const c of raw) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  header(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

async function login(jar: Jar, email: string, password: string): Promise<Response> {
  const csrfRes = await fetch(`${BASE}/api/auth/csrf`);
  jar.absorb(csrfRes);
  const { csrfToken } = (await csrfRes.json()) as { csrfToken: string };
  const res = await fetch(`${BASE}/api/auth/callback/credentials`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: jar.header(),
    },
    body: new URLSearchParams({ csrfToken, email, password, json: "true" }),
    redirect: "manual",
  });
  jar.absorb(res);
  return res;
}

async function api(jar: Jar, method: string, p: string, body?: unknown): Promise<Response> {
  return fetch(`${BASE}${p}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Cookie: jar.header(),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// --- lifecycle ---------------------------------------------------------------

beforeAll(async () => {
  if (EXTERNAL) {
    // externally-managed server (bash runner): verify readiness only
    await waitUntil(
      async () => {
        try {
          const r = await fetch(`${BASE}/api/bootstrap`, { signal: AbortSignal.timeout(2000) });
          return r.ok;
        } catch {
          return false;
        }
      },
      30_000,
      "external integration server ready"
    );
    return;
  }
  // P2-D: the platform DB is PostgreSQL. The self-spawn path REQUIRES
  // DATABASE_URL from the environment (the supported path — the bash runner —
  // either receives it, e.g. a CI service container, or provisions the local
  // dev cluster via scripts/pg_dev_start.sh). The schema is applied by
  // `prisma migrate deploy` — never ad-hoc db push — before this suite runs.
  if (!process.env.DATABASE_URL) {
    throw new Error(
      "self-spawn mode requires DATABASE_URL (PostgreSQL) — use scripts/run_integration_tests.sh"
    );
  }
  const env = {
    ...process.env,
    NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET ?? "integration-test-secret",
    BURHAN_DATA_DIR: process.env.BURHAN_DATA_DIR ?? "/tmp/burhan-test-data",
  };

  // boot the dev server
  const logFd = fs.openSync(SERVER_LOG, "a");
  server = spawn("bunx", ["next", "dev", "-p", String(PORT)], {
    env,
    stdio: ["ignore", logFd, logFd],
  });
  await waitUntil(
    async () => {
      try {
        const r = await fetch(`${BASE}/api/bootstrap`, { signal: AbortSignal.timeout(2000) });
        return r.ok;
      } catch {
        return false;
      }
    },
    120_000,
    "dev server ready"
  );
}, 240_000);

afterAll(() => {
  if (server && server.pid && !EXTERNAL) {
    try { process.kill(-server.pid, "SIGTERM"); } catch { /* ignore */ }
    try { process.kill(server.pid, "SIGTERM"); } catch { /* ignore */ }
  }
});

// --- the tests ---------------------------------------------------------------

describe("bootstrap atomicity + auth + RBAC over the wire", () => {
  const adminJar = new Jar();
  let orgId = "";

  test("fresh instance reports needsBootstrap=true", async () => {
    const r = await fetch(`${BASE}/api/bootstrap`);
    expect(r.status).toBe(200);
    expect(((await r.json()) as { needsBootstrap: boolean }).needsBootstrap).toBe(true);
  });

  // --- RACE AUDIT 2026-10-31: deterministic regressions for the two
  // reclaim-path behaviors. The stampede test below can only reach the
  // reclaim interleaving by scheduler luck; these two FORCE it by seeding
  // the PlatformLock row directly (Prisma, same database), so the
  // stale-vs-in-flight discrimination is pinned forever.

  test("stale lock (crashed attempt, 60s old) is reclaimed — bootstrap succeeds", async () => {
    expect(await db.user.count()).toBe(0);
    await db.platformLock.create({
      data: { key: "bootstrap", createdAt: new Date(Date.now() - 60_000) },
    });
    const r = await fetch(`${BASE}/api/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "stale-reclaim@integration.test",
        password: "Stale-Passw0rd!",
        name: "Stale Reclaimer",
        orgName: "Reclaimed Org",
      }),
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { userId?: string; orgId?: string };
    expect(body.userId).toBeTruthy();
    expect(body.orgId).toBeTruthy();
    expect(await db.user.count()).toBe(1);
    // restore pristine fresh-instance state for the stampede test below
    // (this suite is order-dependent by design). AuditLog rows are
    // APPEND-ONLY since 2026-10-31 (DB trigger) — they stay; they do not
    // affect any count assertion below.
    await db.user.delete({ where: { id: body.userId! } });
    await db.organization.delete({ where: { id: body.orgId! } });
    await db.platformLock.deleteMany({});
    expect(await db.user.count()).toBe(0);
    expect(await db.platformLock.count()).toBe(0);
  });

  test("FRESH lock (attempt in flight) is NOT reclaimed — 409, no user created", async () => {
    expect(await db.user.count()).toBe(0);
    // createdAt = now: an attempt is in flight RIGHT NOW — the pre-fix code
    // deleted exactly this row and let a second platform admin through
    await db.platformLock.create({ data: { key: "bootstrap" } });
    const r = await fetch(`${BASE}/api/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "inflight@integration.test",
        password: "Inflight-Passw0rd!",
        name: "In Flight",
        orgName: "Inflight Org",
      }),
    });
    expect(r.status).toBe(409);
    // the invariant that matters: an in-flight attempt's lock is untouchable
    expect(await db.user.count()).toBe(0);
    await db.platformLock.deleteMany({});
    expect(await db.platformLock.count()).toBe(0);
  });

  test("RACE: 10 concurrent bootstrap POSTs — exactly ONE wins", async () => {
    const emails = Array.from({ length: 10 }, (_, i) => `racer${i}@integration.test`);
    const results = await Promise.all(
      emails.map((email) =>
        fetch(`${BASE}/api/bootstrap`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password: "Racer-Passw0rd!", name: `Racer`, orgName: "Race Org" }),
        }).then(async (r) => ({ status: r.status, body: (await r.json()) as { orgId?: string } }))
      )
    );
    const wins = results.filter((r) => r.status === 200);
    const losses = results.filter((r) => r.status !== 200);
    expect(wins.length).toBe(1);
    expect(losses.length).toBe(9);
    for (const l of losses) expect(l.status).toBe(409);
    orgId = wins[0].body.orgId!;
    expect(orgId).toBeTruthy();
  });

  test("unauthenticated /api/me is 401", async () => {
    const r = await fetch(`${BASE}/api/me`);
    expect(r.status).toBe(401);
  });

  test("the winning account can log in and see OWNER org", async () => {
    // figure out which racer won by trying logins until one works
    let ok = false;
    for (let i = 0; i < 10 && !ok; i++) {
      adminJar.cookies.clear();
      const res = await login(adminJar, `racer${i}@integration.test`, "Racer-Passw0rd!");
      if (res.status === 200 || res.status === 302) {
        const me = await api(adminJar, "GET", "/api/me");
        if (me.status === 200) {
          const body = (await me.json()) as { orgs: { role: string }[] };
          if (body.orgs?.some((o) => o.role === "OWNER")) {
            ok = true;
            const meBody = body as unknown as { orgs: { id: string }[] };
            orgId = meBody.orgs[0].id;
          }
        }
      }
    }
    expect(ok).toBe(true);
  });

  test("SSRF chain: private-network target creation is rejected", async () => {
    for (const bad of [
      "http://127.0.0.1:8080",
      "http://localhost:3000",
      "http://10.0.0.5:8080",
      "http://169.254.169.254/latest/meta-data/",
      "http://192.168.1.1/admin",
      "http://127.0.0.1.nip.io:8080/",
    ]) {
      const r = await api(adminJar, "POST", "/api/targets", { orgId, name: "evil", url: bad });
      expect(r.status).toBe(400);
    }
  });

  test("public target creation succeeds; URL with credentials is rejected", async () => {
    const ok = await api(adminJar, "POST", "/api/targets", {
      orgId, name: "Example", url: "https://example.com/",
    });
    expect(ok.status).toBe(200);
    const cred = await api(adminJar, "POST", "/api/targets", {
      orgId, name: "Cred", url: "https://user:pass@example.com/",
    });
    expect(cred.status).toBe(400);
  });

  let memberJar = new Jar();
  let viewerJar = new Jar();
  let memberTargetId = "";

  test("OWNER adds a MEMBER and a VIEWER", async () => {
    const m = await api(adminJar, "POST", `/api/orgs/${orgId}/members`, {
      email: "member@integration.test", password: "Member-Passw0rd!", role: "MEMBER",
    });
    expect(m.status).toBe(200);
    const v = await api(adminJar, "POST", `/api/orgs/${orgId}/members`, {
      email: "viewer@integration.test", password: "Viewer-Passw0rd!", role: "VIEWER",
    });
    expect(v.status).toBe(200);
  });

  test("MEMBER logs in, creates own target, but CANNOT scan the OWNER's target (write-level fix)", async () => {
    memberJar = new Jar();
    await login(memberJar, "member@integration.test", "Member-Passw0rd!");
    const me = await api(memberJar, "GET", "/api/me");
    expect(me.status).toBe(200);

    // own target: allowed
    const t = await api(memberJar, "POST", "/api/targets", {
      orgId, name: "Member Target", url: "https://member-example.com/",
    });
    expect(t.status).toBe(200);
    memberTargetId = ((await t.json()) as { id: string }).id;

    // list targets to find the owner's target id
    const list = await api(memberJar, "GET", `/api/targets?orgId=${orgId}`);
    const { targets } = (await list.json()) as { targets: { id: string; ownerId: string }[] };
    const ownerTarget = targets.find((x) => x.id !== memberTargetId)!;
    expect(ownerTarget).toBeTruthy();

    // THE RBAC REGRESSION: read is fine, scan (write-level) must be 403
    const scan = await api(memberJar, "POST", "/api/scans", {
      orgId, targetId: ownerTarget.id, options: { allowPrivate: true },
    });
    expect(scan.status).toBe(403);
  });

  test("MEMBER can start a scan on their OWN target (policy still functional)", async () => {
    const scan = await api(memberJar, "POST", "/api/scans", { orgId, targetId: memberTargetId });
    // 200 = scan started (engine subprocess against a public URL will fail
    // or be blocked — that's the engine's business; authorization is what we test)
    expect([200, 409].includes(scan.status)).toBe(true);
    if (scan.status === 200) {
      const { id } = (await scan.json()) as { id: string };
      // cancel it immediately to not leave a zombie engine process —
      // AND assert the cancel contract (B3, 2026-11-11: this call was
      // previously a silent cleanup with zero assertions — the DELETE
      // endpoint's own contract was never tested anywhere; COVERAGE
      // REPORT §3.3 gap). The contract under test: an ADMIN cancels a
      // RUNNING/QUEUED scan -> response {ok: true, cancelled: true},
      // the DB row transitions to CANCELLED, and the action lands in
      // the audit log (item 1.3 fail-closed pair).
      //
      // 2026-11-14 (owner order, flakiness policy §9.3 — NO rerun-until-
      // green): the engine fails fast (~1s) against this suite's
      // unreachable public target, so the scan can COMPLETE before the
      // DELETE arrives (observed 1/11 locally, again in CI run
      // 132552308417 on the UNRELATED #109 docs branch). The endpoint's
      // FIXED contract (PR #106) reports that honestly as
      // {ok:false, reason:"already_completed", finalStatus:"COMPLETED"}.
      // Both terminal paths are now asserted — this is the deterministic
      // state machine, not luck: each branch pins response shape + DB
      // row + (for the cancel path) the audit pair.
      const del = await api(adminJar, "DELETE", `/api/scans/${id}?orgId=${orgId}`);
      expect(del.status).toBe(200);
      const body = (await del.json()) as {
        ok?: boolean; cancelled?: boolean; reason?: string; finalStatus?: string;
      };
      const row = await db.scan.findUnique({ where: { id } });
      expect(row?.finishedAt).toBeTruthy();
      if (body.reason === "already_completed") {
        // the engine finished before the cancel arrived — the honest race path
        expect(body.ok).toBe(false);
        expect(body.cancelled).toBe(false);
        expect(body.finalStatus).toBe("COMPLETED");
        expect(row?.status).toBe("COMPLETED"); // ended on its own, NOT cancelled
      } else {
        // the cancel won the race
        expect(body.ok).toBe(true);
        expect(body.cancelled).toBe(true);
        expect(body.reason).toBe("cancelled");
        expect(row?.status).toBe("CANCELLED");
        const auditRows = await db.auditLog.findMany({
          where: { action: "scan.cancelled", orgId },
          orderBy: { createdAt: "desc" },
          take: 5,
        });
        const hit = auditRows.some(
          (r) => (r.detail ?? "").includes(`"scanId":"${id}"`) || (r.detail ?? "").includes(`"scanId": "${id}"`)
        );
        expect(hit).toBe(true);
      }
    }
  });

  test("VIEWER can read but cannot create targets (RBAC matrix)", async () => {
    viewerJar = new Jar();
    await login(viewerJar, "viewer@integration.test", "Viewer-Passw0rd!");
    const read = await api(viewerJar, "GET", `/api/targets?orgId=${orgId}`);
    expect(read.status).toBe(200);
    const create = await api(viewerJar, "POST", "/api/targets", {
      orgId, name: "nope", url: "https://example.org/",
    });
    expect(create.status).toBe(403);
  });

  test("cross-org isolation: MEMBER of org A gets 404 for a foreign org id", async () => {
    // member creates their own org (orgs POST) — then admin's org is foreign to them? No:
    // admin is member of own org only. Use the member's NEW org vs admin probing it.
    const newOrg = await api(memberJar, "POST", "/api/orgs", { name: "Member Private Org" });
    expect(newOrg.status).toBe(200);
    const { id: foreignOrg } = (await newOrg.json()) as { id: string };
    // VIEWER (not a member of the new org) probing it => 404
    const probe = await api(viewerJar, "GET", `/api/orgs/${foreignOrg}`);
    expect(probe.status).toBe(404);
  });

  test("login rate limiting: 11th bad attempt on a fresh email is refused", async () => {
    const jar = new Jar();
    // exhaust the per-email bucket (10 attempts allowed)
    for (let i = 0; i < 10; i++) {
      const res = await login(jar, "brute@integration.test", "wrong-password-" + i);
      expect([200, 302, 401].includes(res.status)).toBe(true);
    }
    // 11th: authorize() throws RATE_LIMITED — NextAuth responds 401 (fail closed)
    const blocked = await login(jar, "brute@integration.test", "wrong-password-11");
    expect(blocked.status).toBe(401);
  });
  // ------------------- 19-axis audit regressions (2026-10-23, G8/G11) --------

    test("G8 RACE: 3 concurrent scan starts on ONE target — exactly ONE accepted", async () => {
      // Before the fix, the active-scan guard was check-then-act: three
      // concurrent POSTs all passed it and spawned THREE engine processes
      // on one target (proven live: 3 RUNNING scan rows + 3 engine scan
      // dirs). Earliest-wins compensation must accept exactly one and 409
      // the rest. The race target uses the reserved .invalid TLD so the
      // winner's engine fails fast without touching any external system.
      const t = await api(adminJar, "POST", "/api/targets", {
        orgId, name: "Scan Race Target", url: "https://scan-race-test.invalid/",
      });
      expect(t.status).toBe(200);
      const raceTargetId = ((await t.json()) as { id: string }).id;

      const results = await Promise.all(
        [0, 1, 2].map(() =>
          api(adminJar, "POST", "/api/scans", { orgId, targetId: raceTargetId }).then((r) => r.status)
        )
      );
      const wins = results.filter((s) => s === 200).length;
      const refused = results.filter((s) => s === 409).length;
      expect(wins).toBe(1);
      expect(refused).toBe(2);

      // cleanup: cancel the winner so no engine process lingers
      const list = await api(adminJar, "GET", `/api/scans?orgId=${orgId}&targetId=${raceTargetId}`);
      const { scans } = (await list.json()) as { scans: { id: string; status: string }[] };
      for (const s of scans.filter((x) => x.status === "RUNNING" || x.status === "QUEUED")) {
        await api(adminJar, "DELETE", `/api/scans/${s.id}?orgId=${orgId}`);
      }
    });

    test("G11: malformed JSON body is 400, not 500 (jsonError classification)", async () => {
      // Before the fix this returned HTTP 500 (proven live in the gap probe).
      const r = await fetch(`${BASE}/api/targets`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: adminJar.header() },
        body: "{not-json",
      });
      expect(r.status).toBe(400);
    });
});

// ------------------- P2-E/P2-B: the public surface (2026-10-31) ----------------
// Landing + docs + demo are public; the platform itself moved behind the
// server-side (app) layout guard. These tests pin both directions.

describe("public surface (P2-E) + server-side session guard (P2-B)", () => {
  test("landing / renders publicly (no session) with the brand", async () => {
    const r = await fetch(`${BASE}/`, { redirect: "manual" });
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).toContain("Burhan");
  });

  test("/login renders publicly", async () => {
    const r = await fetch(`${BASE}/login`, { redirect: "manual" });
    expect(r.status).toBe(200);
  });

  for (const p of ["/docs", "/docs/compliance", "/docs/ci", "/docs/deployment", "/docs/security", "/demo"]) {
    test(`public page ${p} renders`, async () => {
      const r = await fetch(`${BASE}${p}`, { redirect: "manual" });
      expect(r.status).toBe(200);
      const html = await r.text();
      expect(html.length).toBeGreaterThan(500);
    });
  }

  test("/docs/compliance carries the registry table (CWE rows present)", async () => {
    const r = await fetch(`${BASE}/docs/compliance`);
    const html = await r.text();
    expect(html).toContain("CWE-89");
    expect(html).toContain("A05:2025");
    expect(html).toContain("6.4.2");
  });

  test("server guard: unauthenticated /overview redirects to /login (P2-B)", async () => {
    const r = await fetch(`${BASE}/overview`, { redirect: "manual" });
    expect([302, 307]).toContain(r.status);
    expect(r.headers.get("location") ?? "").toContain("/login");
  });

  test("demo API: GET without id is 400; unknown id is 404", async () => {
    const noId = await fetch(`${BASE}/api/demo/scan`);
    expect(noId.status).toBe(400);
    const unknown = await fetch(`${BASE}/api/demo/scan?id=does-not-exist`);
    expect(unknown.status).toBe(404);
  });

  // P2-C end to end: engine result.json (with compliance) -> reconcileScan
  // import -> complianceJson column -> finding-detail API payload. The
  // platform must carry the engine's mapping VERBATIM, never re-derive it.
  test("compliance import path: reconcileScan -> column -> API (verbatim)", async () => {
    const { db } = await import("@/lib/db");
    const { reconcileScan, SCANS_DIR } = await import("@/lib/engine");
    const pathMod = await import("path");

    // self-contained session: find the winning racer (the bootstrap race left
    // exactly one account; which one won is discovered, not assumed)
    const jar = new Jar();
    let authed = false;
    for (let i = 0; i < 10 && !authed; i++) {
      jar.cookies.clear();
      const res = await login(jar, `racer${i}@integration.test`, "Racer-Passw0rd!");
      if (res.status === 200 || res.status === 302) {
        const me = await api(jar, "GET", "/api/me");
        if (me.status === 200) authed = true;
      }
    }
    expect(authed).toBe(true);

    const newOrg = await api(jar, "POST", "/api/orgs", { name: "Compliance Import Org" });
    expect(newOrg.status).toBe(200);
    const orgId2 = ((await newOrg.json()) as { id: string }).id;

    const org = await db.organization.findUniqueOrThrow({ where: { id: orgId2 } });
    const user = await db.user.create({
      data: { email: `comp-${Date.now()}@integration.test`, passwordHash: "scrypt-x", name: "comp" },
    });
    const target = await db.target.create({
      data: { orgId: org.id, createdById: user.id, name: "comp target", url: "https://comp.invalid/" },
    });
    const scan = await db.scan.create({
      data: { orgId: org.id, targetId: target.id, createdById: user.id, status: "QUEUED", optionsJson: "{}" },
    });

    // engine-shaped result.json with a compliance block on the finding
    const resultPath = pathMod.join(SCANS_DIR, scan.id, "result.json");
    fs.mkdirSync(pathMod.dirname(resultPath), { recursive: true });
    fs.writeFileSync(
      resultPath,
      JSON.stringify({
        run_id: "run-comp-test",
        scanner: "burhan-core/4.4.0",
        stats: { duration: 1.25, proofs: [] },
        findings: [
          {
            id: "F-comp000001",
            type: "sql_injection",
            severity: "critical",
            status: "verified",
            confidence: 0.98,
            risk: 92,
            method: "POST",
            url: "https://comp.invalid/search",
            parameter: "q",
            evidence: [{ kind: "reflection", detail: "sql error" }],
            verification: { method: "replay", passed: true },
            compliance: {
              type: "sql_injection", mapped: true, cwe: "CWE-89",
              cwe_label: "SQL Injection",
              owasp_2021: "A03:2021", owasp_2021_title: "Injection", owasp_2021_src: "official",
              owasp_2025: "A05:2025", owasp_2025_title: "Injection", owasp_2025_src: "official",
              pci_dss: "6.4.2",
            },
          },
        ],
      })
    );
    await db.scan.update({ where: { id: scan.id }, data: { resultPath } });

    await reconcileScan(scan.id);

    const row = await db.finding.findUnique({ where: { scanId_engineId: { scanId: scan.id, engineId: "F-comp000001" } } });
    expect(row).not.toBeNull();
    const complianceStored = JSON.parse(row!.complianceJson ?? "null") as { cwe?: string; pci_dss?: string };
    expect(complianceStored?.cwe).toBe("CWE-89");
    expect(complianceStored?.pci_dss).toBe("6.4.2");

    // the finding-detail API returns it verbatim to the UI
    const detail = await api(jar, "GET", `/api/findings/${row!.id}?orgId=${org.id}`);
    expect(detail.status).toBe(200);
    const body = (await detail.json()) as { compliance: { cwe?: string; owasp_2025?: string; pci_dss?: string } | null };
    expect(body.compliance?.cwe).toBe("CWE-89");
    expect(body.compliance?.owasp_2025).toBe("A05:2025");
    expect(body.compliance?.pci_dss).toBe("6.4.2");

    // cleanup: the org stays (append-only audit); remove the probe rows
    await db.finding.delete({ where: { id: row!.id } });
    await db.scan.delete({ where: { id: scan.id } });
    await db.target.delete({ where: { id: target.id } });
    await db.user.delete({ where: { id: user.id } });
  });
});
