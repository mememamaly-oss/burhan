import { env } from "@/lib/env";
import { spawn, spawnSync, type ChildProcess } from "child_process";
import fs from "fs";
import path from "path";
import { db } from "@/lib/db";
import { audit } from "@/lib/rbac";

// ─────────────────────────────────────────────────────────────────────────────
// ENGINE BRIDGE — the ONLY module that talks to the Burhan engine.
//
// The engine (burhan/ at repo root — final build v4.4.0, axes 1-18) is NEVER modified, NEVER imported, and
// NEVER re-implemented. It is invoked as a black-box CLI subprocess:
//
//   scan       python -m burhan.cli scan <url> --out <result.json> --db <store.db> [opts]
//   reproduce  python -m burhan.cli reproduce --db <store.db> --finding F-xxx
//   report     python -m burhan.cli report  --db <store.db> --run-id <run> --format X --out <file>
//
// Data layout (platform-owned, outside the engine tree):
//   saas-data/scans/<scanId>/result.json   engine output
//   saas-data/scans/<scanId>/log.txt       engine stdout+stderr
//   saas-data/stores/<targetId>.db         engine SQLite store (recurring/delta across scans)
//   saas-data/reports/<reportId>.<ext>     generated reports
// ─────────────────────────────────────────────────────────────────────────────

// SECURITY/QA (audit 2026-10-23, standalone fix): the Next.js standalone
// production server chdir()s into .next/standalone at boot, so process.cwd()
// points INSIDE the build output — spawning the engine (burhan/) or the
// demo fixture (fixtures/vulnapp.py) from there failed with
// "can't open file .../.next/standalone/fixtures/vulnapp.py" (503 on demo
// target creation, FAILED scans). Resolve the real repo root by walking up
// from cwd until the engine tree is found; explicit env overrides still win.
function resolveProjectRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    // Skip directories inside .next — the standalone build TRACES a partial
    // engine copy (.next/standalone/burhan/cli.py ONLY, no fixtures/, no
    // package tree) which must never win over the real repo root.
    if (dir.split(path.sep).includes(".next")) {
      dir = path.dirname(dir);
      continue;
    }
    if (fs.existsSync(path.join(dir, "burhan", "cli.py"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd(); // fallback: current behavior (engine missing → loud error)
}
const PROJECT_ROOT = resolveProjectRoot();
export const ENGINE_DIR = env("ENGINE_DIR") ?? PROJECT_ROOT;
const PYTHON = env("PYTHON") ?? "python3";
// Absolute override keeps artifacts OUTSIDE .next/standalone (which is wiped on
// every rebuild) when running the production standalone server. The default
// now uses the RESOLVED root (not the standalone chdir cwd).
const DATA_DIR = env("DATA_DIR")
  ? path.resolve(env("DATA_DIR") as string)
  : path.join(PROJECT_ROOT, "saas-data");
export const SCANS_DIR = path.join(DATA_DIR, "scans");
export const STORES_DIR = path.join(DATA_DIR, "stores");
export const REPORTS_DIR = path.join(DATA_DIR, "reports");

for (const d of [SCANS_DIR, STORES_DIR, REPORTS_DIR]) {
  fs.mkdirSync(d, { recursive: true });
}

// in-memory handles (best-effort; reconcileScan survives restarts via pid + files)
const g = globalThis as unknown as { __burhanScans?: Map<string, ChildProcess> };
g.__burhanScans = g.__burhanScans || new Map();
const scanProcesses = g.__burhanScans;

export type ScanOptions = {
  allowPrivate: boolean;
  maxPages: number;
  timeout: number;
  noBrowser: boolean;
};

/**
 * LAB MODE (audit 2026-10-23, SSRF remediation):
 * When BURHAN_ALLOW_PRIVATE_TARGETS=1 the operator explicitly opts the
 * deployment into "lab mode" — private-network targets are accepted for
 * non-demo targets too. Default OFF. This is a server-side deployment
 * decision, NEVER a per-request client decision.
 */
export function labModeEnabled(): boolean {
  return env("ALLOW_PRIVATE_TARGETS") === "1";
}

/**
 * Heuristic pre-filter for "does this URL point at an internal network?".
 * This is NOT the security boundary — the engine (burhan/http_engine.py +
 * core.is_private_ip) re-validates EVERY connection (DNS answers included,
 * redirect hops included) and fails closed. This function only decides
 * whether the *scan policy* may even consider private egress.
 * Hostname-based detection is deliberately conservative: anything that
 * looks internal (loopback names, RFC1918/CGNAT literals, IPv6 ULA/
 * link-local/loopback literals, .local/.internal/.localhost suffixes,
 * *.nip.io/*.sslip.io style wildcards) counts as local.
 */
export function isLocalUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (
      h === "localhost" ||
      h.endsWith(".localhost") ||
      h.endsWith(".local") ||
      h.endsWith(".internal") ||
      h.endsWith(".nip.io") ||
      h.endsWith(".sslip.io") ||
      h.endsWith(".localtest.me")
    ) {
      return true;
    }
    // IPv4 literals (incl. exotic forms) and IPv6 literals
    const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      const [a, b] = [Number(v4[1]), Number(v4[2])];
      if (a === 127 || a === 0 || a === 10) return true;
      if (a === 192 && b === 168) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 169 && b === 254) return true; // link-local / cloud metadata
      if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
      return false;
    }
    if (h.includes(":")) {
      // IPv6 literal
      if (h === "::1" || h === "::") return true;
      if (/^f[cd][0-9a-f]{2}:/.test(h)) return true; // fc00::/7 ULA
      if (/^fe[89ab][0-9a-f]:/.test(h)) return true; // fe80::/10 link-local
      // IPv4-mapped IPv6 — the URL parser normalizes [::ffff:10.0.0.1] to
      // the hex form "::ffff:a00:1", so handle BOTH spellings.
      const dotted = h.match(/^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      const hexed = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      let a: number | null = null, b: number | null = null;
      if (dotted) { a = Number(dotted[1]); b = Number(dotted[2]); }
      else if (hexed) {
        const v4 = (parseInt(hexed[1], 16) << 16) | parseInt(hexed[2], 16);
        a = (v4 >>> 24) & 0xff; b = (v4 >>> 16) & 0xff;
      }
      if (a !== null && b !== null) {
        if (a === 127 || a === 0 || a === 10) return true;
        if (a === 192 && b === 168) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 169 && b === 254) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
      }
      return false;
    }
    // exotic IPv4 forms (hex "0x7f.0.0.1", octal "0177.0.0.1", int "2130706433")
    // — parse like inet_aton does and re-check the ranges
    if (/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$/.test(h)) {
      const parts = h.split(".").map((p) => (p.startsWith("0x") ? parseInt(p, 16) : parseInt(p, 10)));
      if (parts.length <= 4 && parts.every((p) => Number.isFinite(p) && p >= 0 && p < 256)) {
        const [a, b = 0] = [parts[0] ?? 0, parts[1] ?? 0];
        if (a === 127 || a === 0 || a === 10) return true;
        if (a === 192 && b === 168) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 169 && b === 254) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * SERVER-SIDE scan network policy (audit 2026-10-23).
 *
 * Before the fix, `allowPrivate` came from the request body — any MEMBER
 * could set allowPrivate:true and drive the server to scan internal
 * networks (SSRF). Now the policy is computed exclusively on the server:
 *
 *   private egress allowed  ⟺  target.isDemo (the platform-managed local
 *                               fixture), OR the deployment is in explicit
 *                               lab mode (BURHAN_ALLOW_PRIVATE_TARGETS=1,
 *                               an operator decision) AND the URL actually
 *                               points at an internal network.
 *
 * Client-supplied `allowPrivate` is intentionally IGNORED (any value).
 */
export function normalizeScanOptions(
  input: Partial<ScanOptions> | undefined,
  target: { url: string; isDemo: boolean }
): ScanOptions {
  const local = isLocalUrl(target.url);
  const allowPrivate = target.isDemo || (labModeEnabled() && local);
  return {
    allowPrivate,
    maxPages: Math.min(Math.max(Number(input?.maxPages) || 25, 1), 200),
    timeout: Math.min(Math.max(Number(input?.timeout) || 10, 3), 60),
    noBrowser: Boolean(input?.noBrowser),
  };
}

function storePathFor(targetId: string): string {
  return path.join(STORES_DIR, `${targetId}.db`);
}

export function scanDirFor(scanId: string): string {
  return path.join(SCANS_DIR, scanId);
}

function pidAlive(pid?: number | null): boolean {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: unknown) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** CPU seconds of a pid from /proc (best-effort). */
function pidCpuSec(pid: number): number | null {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const parts = stat.trim().split(" ");
    // after the comm field (in parens, may contain spaces): fields 14/15 = utime/stime
    const close = stat.lastIndexOf(")");
    const rest = stat.slice(close + 2).split(" ");
    const utime = parseInt(rest[11] || "0", 10);
    const stime = parseInt(rest[12] || "0", 10);
    if (!Number.isFinite(utime)) return null;
    return (utime + stime) / 100; // CLOCK_TICKS=100
  } catch {
    return null;
  }
}

/** Count ESTABLISHED TCP sockets owned by pid (live engine activity proof). */
function pidConnections(pid: number): number {
  try {
    const fdDir = `/proc/${pid}/fd`;
    const inodes = new Set<string>();
    for (const fd of fs.readdirSync(fdDir)) {
      try {
        const link = fs.readlinkSync(path.join(fdDir, fd));
        const m = link.match(/^socket:\[(\d+)\]$/);
        if (m) inodes.add(m[1]);
      } catch {
        /* fd closed racing us — ignore */
      }
    }
    let count = 0;
    for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
      let text: string;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch {
        continue;
      }
      for (const line of text.split("\n").slice(1)) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 10) continue;
        if (cols[3] !== "01") continue; // ESTABLISHED
        if (inodes.has(cols[9])) count++;
      }
    }
    return count;
  } catch {
    return 0;
  }
}

function readLogTail(logPath: string, maxBytes = 16000): string {
  // fd-pinned (CodeQL js/file-system-race, 2026-10-31): open ONCE, fstat
  // THAT descriptor, read from the same descriptor — the path is never
  // resolved twice (same doctrine as the vault key-file fix)
  let fd: number;
  try {
    fd = fs.openSync(logPath, "r");
  } catch {
    return "";
  }
  try {
    const size = fs.fstatSync(fd).size;
    const start = Math.max(0, size - maxBytes);
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    return buf.toString("utf8");
  } catch {
    return "";
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      /* already closed */
    }
  }
}

// ── START ────────────────────────────────────────────────────────────────────

export async function engineStartScan(scanId: string, target: { id: string; url: string }): Promise<number> {
  const dir = scanDirFor(scanId);
  fs.mkdirSync(dir, { recursive: true });
  const resultPath = path.join(dir, "result.json");
  const logPath = path.join(dir, "log.txt");

  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (!scan) throw new Error("scan row missing");
  const opts: ScanOptions = JSON.parse(scan.optionsJson);

  const args = [
    "-m", "burhan.cli", "scan", target.url,
    "--out", resultPath,
    "--db", storePathFor(target.id),
    "--max-pages", String(opts.maxPages),
    "--timeout", String(opts.timeout),
  ];
  if (opts.allowPrivate) args.push("--allow-private");
  if (opts.noBrowser) args.push("--no-browser");

  const out = fs.openSync(logPath, "a");
  const child = spawn(PYTHON, args, {
    cwd: ENGINE_DIR,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    stdio: ["ignore", out, out],
    detached: true, // own process group → survives dev-server reloads, cancellable via -pgid
  });
  child.unref();
  fs.closeSync(out);

  scanProcesses.set(scanId, child);
  const pid = child.pid ?? null;

  await db.scan.update({
    where: { id: scanId },
    data: { status: "RUNNING", enginePid: pid, startedAt: scan.startedAt ?? new Date(), resultPath, logPath },
  });

  child.on("exit", () => {
    scanProcesses.delete(scanId);
    // reconcile in the background once the engine exits
    setTimeout(() => {
      reconcileScan(scanId).catch((e) => console.error("[engine] exit-reconcile failed", scanId, e));
    }, 250);
  });

  return pid ?? 0;
}

// ── RECONCILE (self-healing import; idempotent) ─────────────────────────────

type EngineFinding = {
  id: string;
  type: string;
  severity: string;
  status: string;
  confidence: number;
  method?: string;
  url: string;
  parameter?: string;
  evidence?: unknown[];
  verification?: unknown;
  scanner?: string;
  run_id?: string;
  risk?: number;
  impact?: unknown;
  // P2-C: engine compliance mapping imported verbatim from result.json
  compliance?: Record<string, unknown> | null;
};

/** Read engine store.db → engineId → fingerprint (for recurring analysis).
 *
 * SECURITY (audit 2026-10-23): the previous version embedded the store path
 * into a `python -c` code string. The path is platform-controlled (not
 * client input), but the pattern is a code-injection class hazard — the
 * path now travels through argv, never through code text.
 */
function readFingerprintsSync(storePath: string): Record<string, string> {
  try {
    const r = spawnSync(
      PYTHON,
      [
        "-c",
        "import sys, sqlite3, json\n" +
          "db = sqlite3.connect(sys.argv[1])\n" +
          "print(json.dumps({r[0]: r[1] for r in db.execute('SELECT id, fingerprint FROM findings').fetchall()}))",
        "--",
        storePath,
      ],
      { cwd: ENGINE_DIR, timeout: 15000 }
    );
    if (r.status !== 0 || !r.stdout) return {};
    return JSON.parse(r.stdout.toString());
  } catch {
    return {};
  }
}

export async function reconcileScan(scanId: string): Promise<void> {
  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (!scan) return;
  if (scan.status !== "QUEUED" && scan.status !== "RUNNING") return;

  const resultPath = scan.resultPath || path.join(scanDirFor(scanId), "result.json");

  if (fs.existsSync(resultPath)) {
    // engine finished — import exactly once (unique constraint scanId+engineId)
    let parsed: { run_id?: string; scanner?: string; stats?: Record<string, unknown>; findings?: EngineFinding[] };
    const raw = (() => {
      try {
        return fs.readFileSync(resultPath, "utf8");
      } catch {
        return null;
      }
    })();
    try {
      parsed = JSON.parse(raw ?? "");
    } catch {
      // RACE GUARD: the engine writes result.json progressively — a parse
      // failure with a LIVE process means "still writing", NOT "failed".
      if (pidAlive(scan.enginePid) || scanProcesses.has(scanId)) return;
      // process is gone — give the filesystem a moment then retry once
      await new Promise((r) => setTimeout(r, 1500));
      try {
        parsed = JSON.parse(fs.readFileSync(resultPath, "utf8"));
      } catch (e) {
        await db.scan.update({
          where: { id: scanId },
          data: { status: "FAILED", error: `تعذر تحليل مخرجات المحرك: ${String(e).slice(0, 300)}`, finishedAt: new Date() },
        });
        return;
      }
    }

    const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
    const stats = (parsed.stats ?? {}) as Record<string, unknown>;
    const fingerprints = readFingerprintsSync(storePathFor(scan.targetId));

    // Evidence-OS proofs (reproduction recipes) ride in stats.proofs —
    // the engine emits one proof per verified capability (not per finding row);
    // capture them at import so the platform needs no runtime coupling for recipes.
    const proofs = Array.isArray(stats.proofs) ? (stats.proofs as Array<Record<string, unknown>>) : [];
    const proofsByFinding = new Map<string, string>();
    for (const p of proofs) {
      const fid = p.finding_id as string | undefined;
      if (fid) proofsByFinding.set(fid, JSON.stringify(p));
    }

    const created = await Promise.all(
      findings.map((f) =>
        db.finding.upsert({
          where: { scanId_engineId: { scanId, engineId: f.id } },
          update: {},
          create: {
            orgId: scan.orgId,
            scanId,
            targetId: scan.targetId,
            engineId: f.id,
            fingerprint: fingerprints[f.id] ?? null,
            type: f.type,
            severity: (f.severity || "info").toLowerCase(),
            status: f.status || "verified",
            confidence: Number(f.confidence) || 0,
            risk: Number(f.risk) || 0,
            method: f.method ?? null,
            url: f.url,
            parameter: f.parameter ?? null,
            evidenceJson: JSON.stringify(f.evidence ?? []),
            verificationJson: JSON.stringify(f.verification ?? {}),
            impactJson: JSON.stringify(f.impact ?? {}),
            proofJson: proofsByFinding.get(f.id) ?? null,
            complianceJson: f.compliance ? JSON.stringify(f.compliance) : null,
          },
        }).catch(() => null)
      )
    );
    const imported = created.filter(Boolean).length;

    const duration = Number(stats.duration) || null;
    // state advance + audit in ONE transaction (item 1.3, fail-closed): a
    // scan never reaches COMPLETED without its evidence row; on audit
    // failure the status stays un-advanced and the poller retries (the
    // result file on disk is the durable input).
    await db.$transaction(async (tx) => {
      await tx.scan.update({
        where: { id: scanId },
        data: {
          status: "COMPLETED",
          runId: parsed.run_id ?? null,
          scanner: parsed.scanner ?? null,
          statsJson: JSON.stringify(stats),
          durationSec: duration,
          finishedAt: new Date(),
          error: null,
        },
      });
      await audit(
        "scan.completed",
        {
          orgId: scan.orgId,
          userId: scan.createdById,
          detail: { scanId, runId: parsed.run_id, findings: imported, scanner: parsed.scanner },
        },
        tx
      );
    });
    return;
  }

  // no result yet — is the engine still alive?
  const alive = pidAlive(scan.enginePid) || scanProcesses.has(scanId);
  if (alive) {
    if (scan.status === "QUEUED") {
      await db.scan.update({ where: { id: scanId }, data: { status: "RUNNING" } });
    }
    return;
  }

  // process gone without output → failed (guard: give spawn a moment)
  const startedAt = scan.startedAt ? scan.startedAt.getTime() : Date.now();
  if (Date.now() - startedAt < 8000) return;
  const tail = readLogTail(scan.logPath || path.join(scanDirFor(scanId), "log.txt"), 3000);
  // state advance + audit in ONE transaction (item 1.3, fail-closed)
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scanId },
      data: {
        status: "FAILED",
        error: (tail || "انتهت عملية المحرك دون مخرجات").slice(-1500),
        finishedAt: new Date(),
      },
    });
    await audit("scan.failed", { orgId: scan.orgId, userId: scan.createdById, detail: { scanId } }, tx);
  });
}

// ── PROGRESS ─────────────────────────────────────────────────────────────────

export type ScanProgress = {
  elapsedSec: number;
  pidAlive: boolean;
  cpuSec: number | null;
  connections: number;
  etaSec: number | null;
  logTail: string;
};

export async function getScanProgress(scanId: string): Promise<ScanProgress> {
  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (!scan) throw new Error("scan not found");
  await reconcileScan(scanId);

  const started = scan.startedAt ?? scan.createdAt;
  const elapsedSec = Math.max(0, (Date.now() - started.getTime()) / 1000);
  const alive = pidAlive(scan.enginePid);
  let etaSec: number | null = null;
  if (scan.status === "RUNNING" || scan.status === "QUEUED") {
    const priors = await db.scan.findMany({
      where: { targetId: scan.targetId, status: "COMPLETED" },
      select: { durationSec: true },
    });
    const ds = priors.map((p) => p.durationSec).filter((d): d is number => d !== null && d > 0);
    if (ds.length > 0) {
      ds.sort((a, b) => a - b);
      etaSec = Math.max(0, ds[Math.floor(ds.length / 2)] - elapsedSec);
    }
  }
  return {
    elapsedSec: Math.round(elapsedSec),
    pidAlive: alive,
    cpuSec: alive && scan.enginePid ? pidCpuSec(scan.enginePid) : null,
    connections: alive && scan.enginePid ? pidConnections(scan.enginePid) : 0,
    etaSec: etaSec === null ? null : Math.round(etaSec),
    logTail: readLogTail(scan.logPath || path.join(scanDirFor(scanId), "log.txt")),
  };
}

// ── CANCEL ───────────────────────────────────────────────────────────────────

export type CancelOutcome =
  | { outcome: "cancelled"; ok: true }
  | { outcome: "already_completed"; ok: false; finalStatus: string }
  | { outcome: "not_found"; ok: false };

// Cancel a scan. The return value distinguishes WHY a cancel did not
// happen: the scan had already finished on its own (engine raced the
// operator — fast-fail scans against unreachable targets complete in
// ~1s, owner order 2026-11-13 decision 2) versus the scan not existing.
// Callers that only need the boolean keep using .ok.
export async function engineCancelScanDetailed(scanId: string): Promise<CancelOutcome> {
  const scan = await db.scan.findUnique({ where: { id: scanId } });
  if (!scan) return { outcome: "not_found", ok: false };
  if (scan.status !== "RUNNING" && scan.status !== "QUEUED") {
    return { outcome: "already_completed", ok: false, finalStatus: scan.status };
  }
  await cancelRunningScan(scanId, scan);
  return { outcome: "cancelled", ok: true };
}

async function cancelRunningScan(scanId: string, scan: { enginePid: number | null; orgId: string; createdById: string }): Promise<void> {
  const pid = scan.enginePid;
  if (pid && pidAlive(pid)) {
    try {
      process.kill(-pid, "SIGTERM"); // process group
    } catch {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        /* already gone */
      }
    }
    setTimeout(() => {
      try {
        if (pidAlive(pid)) process.kill(-pid, "SIGKILL");
      } catch {
        /* gone */
      }
    }, 3000).unref();
  }
  // state advance + audit in ONE transaction (item 1.3, fail-closed)
  await db.$transaction(async (tx) => {
    await tx.scan.update({
      where: { id: scanId },
      data: { status: "CANCELLED", finishedAt: new Date(), error: "أُلغي الفحص بواسطة المستخدم" },
    });
    await audit("scan.cancelled", { orgId: scan.orgId, userId: scan.createdById, detail: { scanId } }, tx);
  });
}

export async function engineCancelScan(scanId: string): Promise<boolean> {
  return (await engineCancelScanDetailed(scanId)).ok;
}

// ── REPRODUCE (Evidence OS — engine recipe for one finding) ──────────────────

export async function engineReproduceFinding(
  targetId: string,
  engineId: string
): Promise<Record<string, unknown> | null> {
  const r = spawnSync(
    PYTHON,
    ["-m", "burhan.cli", "reproduce", "--db", storePathFor(targetId), "--finding", engineId],
    { cwd: ENGINE_DIR, timeout: 30000, maxBuffer: 10 * 1024 * 1024 }
  );
  if (r.status !== 0 || !r.stdout) {
    console.error("[engine] reproduce failed", engineId, String(r.stderr || "").slice(0, 400));
    return null;
  }
  try {
    return JSON.parse(r.stdout.toString());
  } catch {
    return null;
  }
}

// ── REPORT GENERATION ────────────────────────────────────────────────────────

export const FORMAT_TO_EXT: Record<string, string> = {
  HTML: "html",
  JSON: "json",
  SARIF: "sarif",
  EXECUTIVE: "json", // engine executive format emits an executive-summary JSON
  GLASS: "html",
};

export async function engineGenerateReport(
  scan: { id: string; runId: string | null; targetId: string },
  format: string
): Promise<{ filePath: string; sizeBytes: number } | null> {
  if (!scan.runId) throw new Error("لا يمكن إنشاء تقرير قبل اكتمال الفحص");
  const ext = FORMAT_TO_EXT[format] ?? "html";
  const outPath = path.join(REPORTS_DIR, `${scan.id}-${Date.now().toString(36)}.${ext}`);
  const r = spawnSync(
    PYTHON,
    [
      "-m", "burhan.cli", "report",
      "--db", storePathFor(scan.targetId),
      "--run-id", scan.runId,
      "--format", format.toLowerCase(),
      "--out", outPath,
    ],
    { cwd: ENGINE_DIR, timeout: 60000, maxBuffer: 20 * 1024 * 1024 }
  );
  if (r.status !== 0 || !fs.existsSync(outPath)) {
    console.error("[engine] report failed", String(r.stderr || r.stdout || "").slice(0, 400));
    throw new Error("فشل توليد التقرير من المحرك");
  }
  const size = fs.statSync(outPath).size;
  return { filePath: outPath, sizeBytes: size };
}
