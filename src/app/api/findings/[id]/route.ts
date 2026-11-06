import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, ApiError, parseJsonSafe } from "@/lib/rbac";
import { remediationFor } from "@/lib/remediation";
import { complianceFromJson, complianceFor } from "@/lib/compliance";

// GET /api/findings/:id?orgId= — full finding detail:
//   engine evidence + verification + impact + reproduction recipe (Evidence OS)
//   + platform remediation guidance (clearly labeled, NOT engine output)
//
// L0 (Phase 02) tenant isolation: the orgId query parameter is NEVER trusted
// as an authorization grant. The chain is:
//   authentication (requireUser)
//     -> organization authorization (requireOrgAccess: session membership,
//        non-members get 404 + audit record — indistinguishable from a
//        nonexistent org, the platform-wide convention)
//     -> the Finding must belong to that membership-authorized organization
//        (findFirst scoped to access.orgId; otherwise 404 — indistinguishable
//        from a nonexistent finding, so cross-tenant existence is not leaked)
export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    if (!orgId) throw new ApiError(400, "orgId مطلوب");

    const access = await requireOrgAccess(user, orgId);

    const finding = await db.finding.findFirst({
      where: { id, orgId: access.orgId },
      include: {
        scan: { select: { id: true, runId: true, status: true, targetId: true, createdAt: true } },
        target: { select: { id: true, name: true, url: true } },
      },
    });
    if (!finding) throw new ApiError(404, "الثغرة غير موجودة");

    const evidence = parseJsonSafe<Array<{ kind?: string; detail?: string }>>(finding.evidenceJson, []);
    const verification = parseJsonSafe<Record<string, unknown>>(finding.verificationJson, {});
    const impact = parseJsonSafe<Record<string, unknown>>(finding.impactJson, {});
    // Evidence-OS proof (reproduction recipe) — captured at scan import from
    // the engine's stats.proofs (same data source as the engine's reproduce CLI).
    const reproduction = parseJsonSafe<Record<string, unknown> | null>(finding.proofJson, null);
    // P2-C: engine compliance mapping (OWASP/CWE/PCI) — imported verbatim from
    // result.json at scan time. Parsed through the DEDICATED complianceFromJson
    // (round-12 class-(d) fix): one parser per column — it normalizes partial/
    // legacy rows through the UNMAPPED shape instead of returning raw
    // JSON.parse output, so the UI contract is stable. Rows imported before the
    // complianceJson column existed fall back to complianceFor(finding.type) —
    // the same lookup-by-type the engine itself performs, unknown types get the
    // honest unmapped shape (never a guess; identical contract both sides).
    const compliance =
      complianceFromJson(finding.complianceJson) ?? complianceFor(finding.type);

    return NextResponse.json({
      finding: {
        id: finding.id,
        engineId: finding.engineId,
        fingerprint: finding.fingerprint,
        type: finding.type,
        severity: finding.severity,
        status: finding.status,
        confidence: finding.confidence,
        risk: finding.risk,
        method: finding.method,
        url: finding.url,
        parameter: finding.parameter,
        createdAt: finding.createdAt,
      },
      scan: finding.scan,
      target: finding.target,
      evidence,
      verification,
      impact,
      reproduction,
      compliance,
      remediation: remediationFor(finding.type), // platform guidance
    });
  } catch (e) {
    return jsonError(e);
  }
}
