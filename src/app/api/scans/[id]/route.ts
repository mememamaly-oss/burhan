import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, requireScanAccess, jsonError, parseJsonSafe, roleAtLeast } from "@/lib/rbac";
import { getScanProgress, engineCancelScanDetailed, reconcileScan } from "@/lib/engine";

// GET /api/scans/:id?orgId= — scan meta + live progress (reconciles state)
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, id);

    const progress = await getScanProgress(scan.id); // includes reconcile
    const fresh = await db.scan.findUnique({
      where: { id: scan.id },
      include: {
        target: { select: { id: true, name: true, url: true } },
        createdBy: { select: { name: true, email: true } },
        _count: { select: { findings: true, reports: true } },
      },
    });

    const stats = parseJsonSafe<Record<string, unknown>>(fresh!.statsJson, {});
    const bySeverity =
      fresh!.status === "COMPLETED"
        ? await db.finding.groupBy({ by: ["severity"], where: { scanId: scan.id }, _count: { _all: true } })
        : [];

    return NextResponse.json({
      scan: {
        id: fresh!.id,
        status: fresh!.status,
        target: fresh!.target,
        createdBy: fresh!.createdBy.name || fresh!.createdBy.email,
        options: parseJsonSafe<Record<string, unknown>>(fresh!.optionsJson, {}),
        runId: fresh!.runId,
        scanner: fresh!.scanner,
        durationSec: fresh!.durationSec,
        error: fresh!.error,
        enginePid: fresh!.enginePid,
        createdAt: fresh!.createdAt,
        startedAt: fresh!.startedAt,
        finishedAt: fresh!.finishedAt,
        findingsCount: fresh!._count.findings,
        reportsCount: fresh!._count.reports,
        bySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity, r._count._all])),
        stats:
          fresh!.status === "COMPLETED"
            ? {
                requests: stats.requests ?? null,
                endpoints: stats.endpoints ?? null,
                candidates: stats.candidates ?? null,
                verified: stats.verified ?? null,
                rejected: stats.rejected ?? null,
                duration: stats.duration ?? null,
                authenticated: stats.authenticated ?? null,
              }
            : null,
      },
      progress,
    });
  } catch (e) {
    return jsonError(e);
  }
}

// DELETE /api/scans/:id?orgId= — cancel an active scan (ADMIN+ or the scan creator)
export async function DELETE(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const scan = await requireScanAccess(access, id);
    const mayCancel = roleAtLeast(access.role, "ADMIN") || scan.createdById === user.id;
    if (!mayCancel) {
      return NextResponse.json({ error: "فقط منشئ الفحص أو ADMIN يمكنه الإلغاء" }, { status: 403 });
    }
    await reconcileScan(scan.id).catch(() => null);
    const result = await engineCancelScanDetailed(scan.id);
    // Contract (owner order 2026-11-13, decision 2): a cancel that arrives
    // AFTER the scan finished on its own is NOT a failure — the response
    // must say so instead of a bare ok:false. ok/cancelled keep their
    // legacy meaning (a cancel really happened); reason + finalStatus are
    // the honest detail. 409 would break existing clients, so the response
    // stays 200 with the distinction in the body.
    if (result.outcome === "already_completed") {
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
    return NextResponse.json({ ok: true, cancelled: true, reason: "cancelled" });
  } catch (e) {
    return jsonError(e);
  }
}
