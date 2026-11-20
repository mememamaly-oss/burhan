import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireTargetAccess, jsonError, ApiError, audit } from "@/lib/rbac";
import { engineStartScan, normalizeScanOptions, reconcileScan } from "@/lib/engine";
import { ensureDemoTarget } from "@/lib/demo-target";

// GET /api/scans?orgId=&targetId=&limit= — scan history (org-scoped)
export async function GET(req: NextRequest) {
  try {
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const targetId = req.nextUrl.searchParams.get("targetId");
    const limit = Math.min(Number(req.nextUrl.searchParams.get("limit")) || 50, 200);
    const access = await requireOrgAccess(user, orgId);

    // opportunistic reconcile of any active scan (self-healing status)
    const active = await db.scan.findMany({
      where: { orgId: access.orgId, status: { in: ["QUEUED", "RUNNING"] } },
      select: { id: true },
    });
    await Promise.all(active.map((s) => reconcileScan(s.id).catch(() => null)));

    const scans = await db.scan.findMany({
      where: { orgId: access.orgId, ...(targetId ? { targetId } : {}) },
      include: {
        target: { select: { id: true, name: true, url: true } },
        createdBy: { select: { name: true, email: true } },
        _count: { select: { findings: true, reports: true } },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return NextResponse.json({
      scans: scans.map((s) => ({
        id: s.id,
        status: s.status,
        target: s.target,
        createdBy: s.createdBy.name || s.createdBy.email,
        runId: s.runId,
        scanner: s.scanner,
        durationSec: s.durationSec,
        findingsCount: s._count.findings,
        reportsCount: s._count.reports,
        error: s.error,
        createdAt: s.createdAt,
        startedAt: s.startedAt,
        finishedAt: s.finishedAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

// POST /api/scans — start a scan {orgId, targetId, options?}
//
// SECURITY (audit 2026-10-23):
//   1. Scan start is a WRITE-level action on the target (it consumes org
//      resources, writes findings/reports, and drives network egress from
//      the server) — previously it only required "read", which let any
//      MEMBER scan targets created by other members.
//   2. options.allowPrivate from the client is IGNORED by
//      normalizeScanOptions — the private-egress policy is computed
//      exclusively on the server (demo target / explicit lab mode).
export async function POST(req: NextRequest) {
  try {
    const user = await requireUser();
    const body = await req.json();
    const orgId = String(body.orgId || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");
    const target = await requireTargetAccess(access, String(body.targetId || ""), "write");

    const active = await db.scan.findFirst({
      where: { targetId: target.id, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (active) {
      throw new ApiError(409, "يوجد فحص نشط على هذا الهدف بالفعل — انتظر انتهاءه أو ألغِه أولًا (تسلسل الفحوصات لكل هدف)");
    }

    // r19-2.17 (owner order 2026-11-20 PR-ب/P2-2): a non-boolean
    // options.noBrowser is a CLIENT error (same strict-boolean contract as
    // the targets route's isDemo guard) — 400, never a 500.
    let options;
    try {
      options = normalizeScanOptions(body.options, { url: target.url, isDemo: target.isDemo });
    } catch (e) {
      if (e instanceof Error && e.message.startsWith("options.noBrowser")) {
        throw new ApiError(400, e.message);
      }
      throw e;
    }

    // self-healing demo target: restart the managed fixture if it is down
    if (target.isDemo) {
      const demo = await ensureDemoTarget();
      if (!demo.ok) throw new ApiError(503, demo.detail);
    }

    // SECURITY (19-axis audit 2026-10-23, G8 — scan-start TOCTOU; re-serialized
    // 2026-10-31): the active-scan check above is check-then-act. The original
    // earliest-wins compensation relied on each participant's scan row being
    // VISIBLE before the next participant's re-read — the item-1.3 change
    // (scan + audit in ONE transaction) delayed row visibility to COMMIT and
    // the race re-opened (CI-proven on this branch: 3 concurrent starts,
    // TWO accepted as winners). The per-target advisory transaction lock now
    // SERIALIZES scan starts: a concurrent starter waits for the first's
    // COMMIT, re-reads, sees the QUEUED row and is refused — exactly one
    // engine per target regardless of interleaving. Scan-create + audit
    // remain ONE atomic unit (item 1.3, fail-closed).
    const scan = await db.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`scan-start:${target.id}`}))`;
      const active = await tx.scan.findFirst({
        where: { targetId: target.id, status: { in: ["QUEUED", "RUNNING"] } },
      });
      if (active) {
        throw new ApiError(409, "يوجد فحص نشط على هذا الهدف بالفعل — انتظر انتهاءه أو ألغِه أولًا (تسلسل الفحوصات لكل هدف)");
      }
      const created = await tx.scan.create({
        data: {
          orgId: access.orgId,
          targetId: target.id,
          createdById: user.id,
          status: "QUEUED",
          optionsJson: JSON.stringify(options),
        },
      });
      await audit(
        "scan.started",
        {
          orgId: access.orgId,
          userId: user.id,
          detail: { scanId: created.id, targetId: target.id, url: target.url, options },
        },
        tx
      );
      return created;
    });

    try {
      await engineStartScan(scan.id, { id: target.id, url: target.url });
    } catch (e) {
      await db.scan.update({
        where: { id: scan.id },
        data: { status: "FAILED", error: `فشل تشغيل المحرك: ${String(e).slice(0, 300)}`, finishedAt: new Date() },
      });
      throw new ApiError(500, "فشل تشغيل محرك الفحص");
    }

    return NextResponse.json({ id: scan.id, status: "RUNNING" });
  } catch (e) {
    return jsonError(e);
  }
}
