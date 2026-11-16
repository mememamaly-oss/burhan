import { env } from "@/lib/env";
import { NextRequest, NextResponse } from "next/server";
import { spawn, type ChildProcess } from "child_process";
import fs from "fs";
import path from "path";
import { ENGINE_DIR, SCANS_DIR } from "@/lib/engine";
import { DEMO_TARGET_URL, ensureDemoTarget } from "@/lib/demo-target";
import { rateLimit } from "@/lib/rate-limit";
import { trustedForwardedIp } from "@/lib/forwarded";

// P2-E (2026-10-31): the PUBLIC live demo — ONE real engine scan against the
// platform-managed fixture (vulnapp on 127.0.0.1:8777). No sign-up.
//
// SECURITY contract (this is an unauthenticated endpoint, so it is minimal
// by construction):
//   * The target is HARDCODED (DEMO_TARGET_URL) — request bodies are ignored
//     entirely; there is no client-controlled input anywhere in the spawn.
//   * Rate limits: per-IP sliding window (3/hour) + ONE concurrent job
//     globally (a free demo is single-lane by design).
//   * Output is capped (top 30 findings by risk) and carries no secrets —
//     same fields the platform UI shows.
//   * Nothing is written to the tenant DB — the demo is stateless for the
//     platform; artifacts live under saas-data/demo-scans/<job>/.

const DEMO_DIR = path.join(path.dirname(SCANS_DIR), "demo-scans");
const DEMO_MAX_FINDINGS = 30;
const DEMO_HITS = 3;
const DEMO_WINDOW_MS = 60 * 60 * 1000;
// 2.7 (2026-10-31): the GET polling side had NO limit — an unauthenticated
// flood of polls was unbounded request processing on the public surface
// (proven red: 160 consecutive polls, zero refusals). Legitimate polling of
// a 1-2 minute scan at 2s intervals needs ~60 requests; 120/hour/IP leaves
// headroom for two demo runs while cutting floods off hard.
const DEMO_POLL_HITS = 120;
const DEMO_POLL_WINDOW_MS = 60 * 60 * 1000;

type DemoFinding = {
  id: string;
  type: string;
  severity: string;
  risk: number;
  confidence: number;
  url: string;
  parameter: string | null;
  compliance: Record<string, unknown> | null;
};

type DemoState = {
  id: string;
  status: "running" | "done" | "error";
  startedAt: number;
  finishedAt?: number;
  runId?: string;
  scanner?: string;
  durationSec?: number;
  findings?: DemoFinding[];
  bySeverity?: Record<string, number>;
  compliance?: {
    owasp_2021: Record<string, number>;
    owasp_2025: Record<string, number>;
    cwe: Record<string, number>;
    pci: Record<string, number>;
  };
  error?: string;
};

const g = globalThis as unknown as {
  __burhanDemoScans?: Map<string, DemoState>;
  __burhanDemoProcs?: Map<string, ChildProcess>;
};
g.__burhanDemoScans = g.__burhanDemoScans || new Map();
g.__burhanDemoProcs = g.__burhanDemoProcs || new Map();
const jobs = g.__burhanDemoScans;
const procs = g.__burhanDemoProcs;

function clientIp(req: NextRequest): string {
  // SECRET-GATED (item 1.4, 2026-10-31): forwarded headers only count when
  // the request proves it came through the proxy (x-proxy-secret); forged
  // XFF from a direct client must NOT buy a fresh rate-limit bucket
  // (proven red: 130 distinct forged XFF values, zero refusals).
  return trustedForwardedIp((n) => req.headers.get(n)) ?? "local";
}

function rollupCompliance(findings: DemoFinding[]): DemoState["compliance"] {
  const owasp_2021: Record<string, number> = {};
  const owasp_2025: Record<string, number> = {};
  const cwe: Record<string, number> = {};
  const pci: Record<string, number> = {};
  for (const f of findings) {
    const c = f.compliance as { mapped?: boolean; cwe?: string | null; owasp_2021?: string | null; owasp_2025?: string | null; pci_dss?: string | null } | null;
    if (!c || c.mapped === false) continue;
    if (c.owasp_2021) owasp_2021[c.owasp_2021] = (owasp_2021[c.owasp_2021] ?? 0) + 1;
    if (c.owasp_2025) owasp_2025[c.owasp_2025] = (owasp_2025[c.owasp_2025] ?? 0) + 1;
    if (c.cwe) cwe[c.cwe] = (cwe[c.cwe] ?? 0) + 1;
    if (c.pci_dss) pci[c.pci_dss] = (pci[c.pci_dss] ?? 0) + 1;
  }
  return { owasp_2021, owasp_2025, cwe, pci };
}

export async function POST(req: NextRequest) {
  // rate limit FIRST (per-IP, fail-closed)
  const ip = clientIp(req);
  // 2.9 (2026-10-31): shared PostgreSQL store — the demo budget is global
  // across app processes too.
  const verdict = await rateLimit(`demo:ip:${ip}`, DEMO_HITS, DEMO_WINDOW_MS);
  if (!verdict.allowed) {
    return NextResponse.json({ error: "RATE_LIMITED" }, { status: 429 });
  }
  // one lane globally — a free demo never runs concurrent engine scans
  for (const s of jobs.values()) {
    if (s.status === "running") {
      return NextResponse.json({ error: "BUSY" }, { status: 429 });
    }
  }

  const health = await ensureDemoTarget();
  if (!health.ok) {
    return NextResponse.json({ error: "DEMO_TARGET_DOWN", detail: health.detail }, { status: 503 });
  }

  const id = `demo-${Date.now().toString(36)}`;
  const dir = path.join(DEMO_DIR, id);
  fs.mkdirSync(dir, { recursive: true });
  const resultPath = path.join(dir, "result.json");
  const logPath = path.join(dir, "log.txt");

  const state: DemoState = { id, status: "running", startedAt: Date.now() };
  jobs.set(id, state);

  const out = fs.openSync(logPath, "a");
  const child = spawn(
    env("PYTHON") ?? "python3",
    [
      "-m", "burhan.cli", "scan", DEMO_TARGET_URL,
      "--out", resultPath,
      "--db", path.join(dir, "store.db"),
      "--max-pages", "25",
      "--timeout", "10",
      "--allow-private",
      // r19-2.5: the ownership gate refuses the loopback demo fixture
      // without the EXPLICIT laboratory mode — same server-side decision
      // as engine.ts (the demo target is platform-managed and local);
      // the spawned CLI needs the flag so the gate passes and the demo
      // report records stats.lab_mode.
      "--lab",
    ],
    { cwd: ENGINE_DIR, env: { ...process.env, PYTHONUNBUFFERED: "1" }, stdio: ["ignore", out, out], detached: true }
  );
  fs.closeSync(out);
  procs.set(id, child);

  child.on("exit", () => {
    procs.delete(id);
    try {
      const parsed = JSON.parse(fs.readFileSync(resultPath, "utf8")) as {
        run_id?: string;
        scanner?: string;
        stats?: { duration?: number };
        findings?: Array<Record<string, unknown>>;
      };
      const all = (parsed.findings ?? []).map((f) => ({
        id: String(f.id ?? ""),
        type: String(f.type ?? "unknown"),
        severity: String(f.severity ?? "info").toLowerCase(),
        risk: Number(f.risk ?? 0),
        confidence: Number(f.confidence ?? 0),
        url: String(f.url ?? ""),
        parameter: f.parameter ? String(f.parameter) : null,
        compliance: (f.compliance as Record<string, unknown> | null) ?? null,
      }));
      const bySeverity: Record<string, number> = {};
      for (const f of all) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      state.status = "done";
      state.finishedAt = Date.now();
      state.runId = parsed.run_id;
      state.scanner = parsed.scanner;
      state.durationSec = Number(parsed.stats?.duration ?? 0);
      state.bySeverity = bySeverity;
      state.compliance = rollupCompliance(all);
      state.findings = all.sort((a, b) => b.risk - a.risk).slice(0, DEMO_MAX_FINDINGS);
    } catch (e) {
      state.status = "error";
      state.finishedAt = Date.now();
      state.error = String(e).slice(0, 300);
    }
  });

  return NextResponse.json({ id, status: "running" }, { status: 202 });
}

export async function GET(req: NextRequest) {
  // 2.7 (2026-10-31): per-IP poll budget BEFORE any work (fail-closed).
  const pollVerdict = await rateLimit(
    `demo-poll:ip:${clientIp(req)}`,
    DEMO_POLL_HITS,
    DEMO_POLL_WINDOW_MS
  );
  if (!pollVerdict.allowed) {
    return NextResponse.json({ error: "RATE_LIMITED" }, { status: 429 });
  }
  const id = req.nextUrl.searchParams.get("id");
  if (!id) {
    return NextResponse.json({ error: "id required" }, { status: 400 });
  }
  const job = jobs.get(id);
  if (!job) {
    return NextResponse.json({ error: "unknown demo job" }, { status: 404 });
  }
  return NextResponse.json({
    ...job,
    elapsedSec: Math.round((Date.now() - job.startedAt) / 1000),
  });
}
