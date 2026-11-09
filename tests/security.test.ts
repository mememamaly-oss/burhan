/**
 * SECURITY REGRESSION TESTS — SaaS platform policy layer (audit 2026-10-23).
 *
 * Pure-unit tests for the SSRF policy, rate limiter, password hashing and
 * slug generation. The HTTP-level integration suite (bootstrap race, RBAC
 * matrix, private-target rejection) lives in api.integration.test.ts.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import {
  normalizeScanOptions,
  isLocalUrl,
  labModeEnabled,
} from "@/lib/engine";
import { rateLimit, resetRateLimits } from "@/lib/rate-limit";
import { hashPassword, verifyPassword } from "@/lib/passwords";
import { slugify, roleAtLeast } from "@/lib/rbac";
import { execSync } from "child_process";
import { readFileSync } from "fs";

// ---------------------------------------------------------------- SSRF policy

describe("SSRF policy: normalizeScanOptions (audit 2026-10-23)", () => {
  const ORIG_LAB = process.env.BURHAN_ALLOW_PRIVATE_TARGETS;

  afterEach(() => {
    if (ORIG_LAB === undefined) delete process.env.BURHAN_ALLOW_PRIVATE_TARGETS;
    else process.env.BURHAN_ALLOW_PRIVATE_TARGETS = ORIG_LAB;
  });

  test("THE REGRESSION: client-supplied allowPrivate:true is IGNORED for non-demo public targets", () => {
    // Before the fix, this exact input produced allowPrivate:true and the
    // engine scanned internal networks. Must be false — always.
    const opts = normalizeScanOptions(
      { allowPrivate: true } as never,
      { url: "https://public-example.com/app", isDemo: false }
    );
    expect(opts.allowPrivate).toBe(false);
  });

  test("client allowPrivate:false on the demo target still allows private (server policy wins both ways)", () => {
    const opts = normalizeScanOptions(
      { allowPrivate: false } as never,
      { url: "http://127.0.0.1:8777", isDemo: true }
    );
    expect(opts.allowPrivate).toBe(true);
  });

  test("demo target => private egress allowed (platform-managed fixture)", () => {
    expect(
      normalizeScanOptions(undefined, { url: "http://127.0.0.1:8777", isDemo: true }).allowPrivate
    ).toBe(true);
  });

  test("non-demo local URL is denied without explicit lab mode", () => {
    delete process.env.BURHAN_ALLOW_PRIVATE_TARGETS;
    expect(
      normalizeScanOptions(undefined, { url: "http://10.0.0.5:8080", isDemo: false }).allowPrivate
    ).toBe(false);
  });

  test("non-demo local URL is allowed ONLY in explicit lab mode", () => {
    process.env.BURHAN_ALLOW_PRIVATE_TARGETS = "1";
    expect(labModeEnabled()).toBe(true);
    expect(
      normalizeScanOptions(undefined, { url: "http://10.0.0.5:8080", isDemo: false }).allowPrivate
    ).toBe(true);
    delete process.env.BURHAN_ALLOW_PRIVATE_TARGETS;
    expect(
      normalizeScanOptions(undefined, { url: "http://10.0.0.5:8080", isDemo: false }).allowPrivate
    ).toBe(false);
  });

  test("2.8 guard: ONLY the exact string '1' enables lab mode — every other value stays OFF", () => {
    const prev = process.env.BURHAN_ALLOW_PRIVATE_TARGETS;
    try {
      for (const v of ["0", "false", "true", "yes", "", "2", "on", " 1", "1 "]) {
        process.env.BURHAN_ALLOW_PRIVATE_TARGETS = v;
        expect(labModeEnabled()).toBe(false);
      }
      process.env.BURHAN_ALLOW_PRIVATE_TARGETS = "1";
      expect(labModeEnabled()).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.BURHAN_ALLOW_PRIVATE_TARGETS;
      else process.env.BURHAN_ALLOW_PRIVATE_TARGETS = prev;
    }
  });

  test("numeric option clamping survives (regression guard)", () => {
    const opts = normalizeScanOptions(
      { maxPages: 99999, timeout: 999, noBrowser: true } as never,
      { url: "https://x.com", isDemo: false }
    );
    expect(opts.maxPages).toBe(200);
    expect(opts.timeout).toBe(60);
    expect(opts.noBrowser).toBe(true);
  });
});

describe("isLocalUrl heuristic", () => {
  test("loopback + RFC1918 + CGNAT + link-local literals are local", () => {
    for (const u of [
      "http://localhost:3000/",
      "http://127.0.0.1/",
      "http://127.8.8.8/",               // any 127/8
      "http://0.0.0.0/",
      "http://10.1.2.3/",
      "http://172.16.0.1/",
      "http://172.31.255.254/",
      "http://192.168.1.1/",
      "http://169.254.169.254/latest/meta-data/",
      "http://100.64.0.1/",
      "http://[::1]:3000/",
      "http://[fe80::1]/",
      "http://[fc00::1]/",
    ]) {
      expect(isLocalUrl(u)).toBe(true);
    }
  });

  test("wildcard DNS conventions count as local", () => {
    expect(isLocalUrl("http://127.0.0.1.nip.io:8080/")).toBe(true);
    expect(isLocalUrl("http://10.0.0.5.sslip.io/")).toBe(true);
    expect(isLocalUrl("http://foo.localtest.me/")).toBe(true);
    expect(isLocalUrl("http://service.internal:8080/")).toBe(true);
    expect(isLocalUrl("http://db.local/")).toBe(true);
  });

  test("public hosts are not local", () => {
    for (const u of [
      "https://example.com/",
      "http://8.8.8.8/",
      "http://172.32.0.1/",   // just outside RFC1918
      "http://100.128.0.1/",  // just outside CGNAT
      "https://2606:4700::1111/",
    ]) {
      expect(isLocalUrl(u)).toBe(false);
    }
  });

  test("IPv4-mapped IPv6 and exotic v4 forms are local", () => {
    expect(isLocalUrl("http://[::ffff:127.0.0.1]/")).toBe(true);
    expect(isLocalUrl("http://[::ffff:10.0.0.1]/")).toBe(true);
    expect(isLocalUrl("http://[::ffff:169.254.169.254]/")).toBe(true);
    expect(isLocalUrl("http://[::ffff:8.8.8.8]/")).toBe(false);
    expect(isLocalUrl("http://0x7f.0.0.1/")).toBe(true);
    expect(isLocalUrl("http://0177.0.0.1/")).toBe(true);
  });

  test("garbage is not local (engine still fail-closes downstream)", () => {
    expect(isLocalUrl("not a url")).toBe(false);
    expect(isLocalUrl("")).toBe(false);
  });
});

// ------------------------------------------------------------- rate limiter

// 2.9 (2026-10-31): the limiter is now a SHARED-STORE (PostgreSQL)
// async API. These unit checks require a postgres DATABASE_URL (CI's web
// job provides the service container); without one they skip — the
// authoritative proofs, including the two-process red/green, live in
// tests/ratelimit.integration.test.ts.
describe("login rate limiter (audit 2026-10-23; shared store 2026-10-31)", () => {
  const PG = (process.env.DATABASE_URL || "").startsWith("postgres");
  beforeEach(async () => {
    if (PG) await resetRateLimits();
  });

  test.skipIf(!PG)("allows up to N hits then blocks, with retryAfter", async () => {
    for (let i = 0; i < 10; i++) {
      const v = await rateLimit("k1", 10, 60_000);
      expect(v.allowed).toBe(true);
    }
    const blocked = await rateLimit("k1", 10, 60_000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
    expect(blocked.retryAfterSec).toBeLessThanOrEqual(60);
  });

  test.skipIf(!PG)("keys are isolated", async () => {
    for (let i = 0; i < 10; i++) await rateLimit("a", 10, 60_000);
    expect((await rateLimit("a", 10, 60_000)).allowed).toBe(false);
    expect((await rateLimit("b", 10, 60_000)).allowed).toBe(true);
  });

  test.skipIf(!PG)("window slides (expired hits free the key)", async () => {
    // 3 hits / 2s window: the 4th is blocked, but after the window
    // passes the bucket frees itself (no permanent lockout). The
    // window is 2s, not 80ms: the blocking assertion needs all four
    // PG round-trips inside one window, and a loaded CI runner (this
    // suite runs beside two Engine suites) can stretch a round-trip
    // past 50ms — an 80ms window expired the early hits before the
    // 4th call and flaked the test (observed 2026-11-09, the adjacent
    // test ran 11 calls in 199ms). 2s keeps ~10x margin over that
    // degradation; the sleep must exceed the window measured from the
    // LAST hit, hence 2.1s.
    for (let i = 0; i < 3; i++) await rateLimit("slide", 3, 2_000);
    expect((await rateLimit("slide", 3, 2_000)).allowed).toBe(false);
    await new Promise((r) => setTimeout(r, 2_100));
    const later = await rateLimit("slide", 3, 2_000);
    expect(later.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------- passwords

describe("password hashing", () => {
  test("round-trip verify", () => {
    const h = hashPassword("Correct-Horse-9!");
    expect(h.startsWith("scrypt$")).toBe(true);
    expect(verifyPassword("Correct-Horse-9!", h)).toBe(true);
    expect(verifyPassword("wrong", h)).toBe(false);
  });

  test("unique salts: same password, different hashes", () => {
    const a = hashPassword("same-password-1");
    const b = hashPassword("same-password-1");
    expect(a).not.toBe(b);
  });

  test("malformed stored hash fails closed", () => {
    expect(verifyPassword("x", "")).toBe(false);
    expect(verifyPassword("x", "plaintext")).toBe(false);
    expect(verifyPassword("x", "md5$abc$def")).toBe(false);
  });
});

// ---------------------------------------------------------------- rbac utils

describe("RBAC helpers", () => {
  test("role ranking is total and correct", () => {
    expect(roleAtLeast("OWNER", "ADMIN")).toBe(true);
    expect(roleAtLeast("ADMIN", "ADMIN")).toBe(true);
    expect(roleAtLeast("MEMBER", "ADMIN")).toBe(false);
    expect(roleAtLeast("VIEWER", "MEMBER")).toBe(false);
  });

  test("slugify: ascii, arabic, fallback", () => {
    expect(slugify("Acme Corp")).toBe("acme-corp");
    expect(slugify("شركة الأمن")).toBe("شركة-الأمن");
    expect(slugify("!!!")).toMatch(/^org-/);
  });
});

// ------------------------------------------- QA regression (2026-10-23 gate)

describe("production standalone fixes (QA gate 2026-10-23)", () => {
  test("ENGINE_DIR resolves to the real engine tree (standalone chdir regression)", async () => {
    // Before the fix, the standalone server chdir()s into .next/standalone,
    // making cwd-based ENGINE_DIR point at the build output — demo target
    // 503'd and every scan FAILED. The resolver must find burhan/cli.py.
    const { ENGINE_DIR } = await import("@/lib/engine");
    const fs = await import("fs");
    const path = await import("path");
    expect(fs.existsSync(path.join(ENGINE_DIR, "burhan", "cli.py"))).toBe(true);
    expect(ENGINE_DIR.endsWith(".next/standalone")).toBe(false);
  });

  test("security headers are configured for every route (headers regression)", async () => {
    const nextConfig = (await import("../next.config")).default;
    const result = await nextConfig.headers!();
    const all = result.find((r) => r.source === "/:path*");
    expect(all).toBeDefined();
    const keys = all!.headers.map((h) => h.key);
    expect(keys).toContain("X-Content-Type-Options");
    expect(keys).toContain("X-Frame-Options");
    expect(keys).toContain("Referrer-Policy");
    expect(keys).toContain("Content-Security-Policy");
    const csp = all!.headers.find((h) => h.key === "Content-Security-Policy")!.value;
    expect(csp).toContain("frame-ancestors 'none'");
  });
});

// ---------------------------- 19-axis audit regressions (2026-10-23)

describe("19-axis audit fixes (2026-10-23)", () => {
  test("G11: malformed JSON body (SyntaxError) maps to 400, not 500", async () => {
    // Before the fix, POSTing "{not-json" returned HTTP 500 (proven live in
    // the gap probe). req.json() throws SyntaxError — jsonError must
    // classify it as a client error.
    const { jsonError } = await import("@/lib/rbac");
    const res = jsonError(new SyntaxError("Unexpected token n in JSON at position 1"));
    expect(res.status).toBe(400);
    const body = (res as unknown as { bodyUsed?: boolean }) && res;
    // ApiError path unchanged (still propagates its own status)
    const { ApiError } = await import("@/lib/rbac");
    const apiRes = jsonError(new ApiError(409, "conflict"));
    expect(apiRes.status).toBe(409);
    // Unknown errors remain 500 (the 500 channel stays for real faults)
    const errRes = jsonError(new Error("boom"));
    expect(errRes.status).toBe(500);
    void body;
  });
});

// --------------------------------------------------- 2.3/2.4 guards (2026-10-31)

describe("report viewer + findings XSS posture (owner order 2026-10-31, 2.3/2.4)", () => {
  // Source-contract tripwire: the report viewer MUST render engine HTML in
  // an iframe with sandbox="" (opaque origin, scripts disabled). A refactor
  // that drops the attribute or adds allow-scripts/allow-same-origin must
  // fail HERE, not in a pentest. (Full DOM-level proof: the Playwright run
  // scripts/final-2026-10-31/xss_iframe_browser_proof.py against a
  // production build — 9/9 checks, evidence in download/.)
  test("report viewer iframe keeps sandbox exactly empty (no allow-scripts / allow-same-origin)", () => {
    const src = readFileSync("src/app/(app)/reports/[id]/page.tsx", "utf8");
    // strip comment lines first — the historical audit note mentions the OLD
    // (pre-fix) value sandbox="allow-same-origin" inside a comment
    const code = src.replace(/^\s*\/\/.*$/gm, "");
    if (!/sandbox=""/.test(code)) {
      throw new Error('sandbox="" missing from the report viewer iframe');
    }
    if (/sandbox="[^"]*(allow-scripts|allow-same-origin)/.test(code)) {
      throw new Error("report viewer sandbox must never include allow-scripts or allow-same-origin");
    }
  });

  test("no dangerouslySetInnerHTML on any app page (React auto-escape stays the only HTML path)", () => {
    const hits = execSync(
      "grep -rn dangerouslySetInnerHTML src/app src/components/shell src/components/saas 2>/dev/null || true",
      { encoding: "utf8" }
    ).trim();
    if (hits) {
      throw new Error("dangerouslySetInnerHTML appeared in app code:\n" + hits);
    }
  });
});
