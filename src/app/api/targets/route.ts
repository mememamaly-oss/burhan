import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireUser, requireOrgAccess, jsonError, ApiError, audit } from "@/lib/rbac";
import { ensureDemoTarget, DEMO_TARGET_URL, DEMO_TARGET_NAME } from "@/lib/demo-target";
import { isLocalUrl, labModeEnabled, strictBooleanField } from "@/lib/engine";

// GET /api/targets?orgId=... — org-scoped list with scan stats
export async function GET(req: NextRequest) {
  try {
    const user = await requireUser();
    const orgId = String(req.nextUrl.searchParams.get("orgId") || "");
    const access = await requireOrgAccess(user, orgId);
    const targets = await db.target.findMany({
      where: { orgId: access.orgId },
      include: {
        createdBy: { select: { name: true, email: true } },
        _count: { select: { scans: true, findings: true } },
        scans: {
          orderBy: { createdAt: "desc" },
          take: 1,
          select: { status: true, createdAt: true, finishedAt: true, scanner: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });
    return NextResponse.json({
      targets: targets.map((t) => ({
        id: t.id,
        name: t.name,
        url: t.url,
        description: t.description,
        isDemo: t.isDemo,
        owner: t.createdBy.name || t.createdBy.email,
        ownerId: t.createdById,
        scansCount: t._count.scans,
        findingsCount: t._count.findings,
        lastScan: t.scans[0] ?? null,
        createdAt: t.createdAt,
      })),
    });
  } catch (e) {
    return jsonError(e);
  }
}

function validHttpUrl(raw: string): URL | null {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

// POST /api/targets — create target {orgId, name, url, description?, isDemo?}
//
// SECURITY (audit 2026-10-23, SSRF chain break): a non-demo target pointing
// at an internal network (loopback/RFC1918/CGNAT/link-local/metadata/IPv6
// ULA…) is REJECTED unless the deployment is in explicit lab mode
// (BURHAN_ALLOW_PRIVATE_TARGETS=1) — previously any MEMBER could register
// http://10.0.0.5:8080 and the scan layer would auto-enable private egress.
// The engine re-validates every hop independently (fail-closed), so this is
// defense in depth, not the only barrier.
export async function POST(req: NextRequest) {
  try {
    const user = await requireUser();
    const body = await req.json();
    const orgId = String(body.orgId || "");
    const access = await requireOrgAccess(user, orgId, "MEMBER");

    let url = String(body.url || "").trim();
    let name = String(body.name || "").trim();
    const description = body.description ? String(body.description).slice(0, 500) : null;
    // r19-2.17 (owner order 2026-11-20 PR-ب/P2-1): isDemo is a REAL boolean
    // or absent — never coerced (Boolean("false") === true used to ARM the
    // demo path: forced url + allowPrivate later). The shared helper
    // throws a plain Error; mapped here to a 400 naming the field.
    let isDemo: boolean;
    try {
      isDemo = strictBooleanField(body.isDemo, "isDemo");
    } catch (e) {
      if (e instanceof Error && e.message.startsWith("isDemo")) {
        throw new ApiError(400, `isDemo يجب أن يكون قيمة منطقية (true/false) أو غائبًا`);
      }
      throw e;
    }

    if (isDemo) {
      const demo = await ensureDemoTarget();
      if (!demo.ok) throw new ApiError(503, demo.detail);
      url = DEMO_TARGET_URL;
      if (!name) name = DEMO_TARGET_NAME;
    } else {
      if (!url) throw new ApiError(400, "URL مطلوب");
      const u = validHttpUrl(url);
      if (!u) throw new ApiError(400, "URL غير صالح — يجب أن يبدأ بـ http:// أو https://");
      if (u.username || u.password) throw new ApiError(400, "URL يتضمن بيانات اعتماد — غير مسموح");
      if (isLocalUrl(url) && !labModeEnabled()) {
        throw new ApiError(
          400,
          "عناوين الشبكة الداخلية/المحلية غير مسموحة للأهداف — وضع المختبر (BURHAN_ALLOW_PRIVATE_TARGETS=1) مطلوب من مسؤول النشر"
        );
      }
      url = u.toString();
      if (!name) name = u.hostname;
    }

    const dup = await db.target.findFirst({ where: { orgId: access.orgId, url } });
    if (dup) throw new ApiError(409, "هذا الهدف مسجل بالفعل في المنظمة");

    // target + audit row in ONE transaction (item 1.3, fail-closed)
    const target = await db.$transaction(async (tx) => {
      const created = await tx.target.create({
        data: {
          orgId: access.orgId,
          createdById: user.id, // target ownership
          name,
          url,
          description,
          isDemo,
        },
      });
      await audit(
        "target.created",
        {
          orgId: access.orgId,
          userId: user.id,
          detail: { targetId: created.id, url, isDemo },
        },
        tx
      );
      return created;
    });
    return NextResponse.json({ id: target.id, name: target.name, url: target.url, isDemo: target.isDemo });
  } catch (e) {
    return jsonError(e);
  }
}
