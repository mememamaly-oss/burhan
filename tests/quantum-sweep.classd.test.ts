// Round-12 class-(d) regression pin — the compliance column parser routing.
//
// RED (before the fix): GET /api/findings/:id parsed complianceJson with the
//   GENERIC parseJsonSafe, so a truncated/legacy complianceJson row returned
//   whatever raw JSON.parse produced (e.g. {"cwe": "CWE-89"} alone — missing
//   mapped/type/pci_dss keys, unstable UI contract), and the dedicated
//   complianceFromJson parser existed ONLY in tests (exported, tested,
//   unrouted — the exact --gated bug shape in TypeScript).
// BLUE (after the fix): the route parses through complianceFromJson; partial
//   rows are normalized through the UNMAPPED shape (mapped=false, typed keys
//   present), full rows pass through unchanged.
//
// This test pins the ROUTING (the route calls the dedicated parser), not the
// parser's own unit behavior (tests/compliance.test.ts already covers that).
import { describe, expect, test } from "bun:test";
import { complianceFromJson, complianceFor } from "@/lib/compliance";

describe("round-12 class-(d): findings route parses complianceJson via the dedicated parser", () => {
  test("source routing: the route file imports complianceFromJson (not parseJsonSafe for the compliance column)", async () => {
    const src = await Bun.file("src/app/api/findings/[id]/route.ts").text();
    expect(src).toContain('import { complianceFromJson, complianceFor } from "@/lib/compliance"');
    expect(src).toMatch(
      /complianceFromJson\(finding\.complianceJson\) \?\? complianceFor\(finding\.type\)/,
    );
    // and the OLD generic-parse line is gone
    expect(src).not.toMatch(
      /parseJsonSafe<[^>]*>\(finding\.complianceJson/,
    );
  });

  test("fallback contract: pre-column legacy rows resolve compliance by type", () => {
    // complianceJson == null on a typed finding -> the route serves the
    // engine's lookup-by-type shape; unknown types stay honestly unmapped
    expect(complianceFor("sql_injection").cwe).toBe("CWE-89");
    const unmapped = complianceFor("legacy_unknown_type");
    expect(unmapped.mapped).toBe(false);
    expect(unmapped.cwe).toBeNull();
  });

  test("shape contract: a partial/legacy complianceJson row normalizes through UNMAPPED", () => {
    const out = complianceFromJson('{"cwe":"CWE-89"}');
    expect(out).not.toBeNull();
    expect(out!.cwe).toBe("CWE-89");
    expect(out!.mapped).toBe(false);          // UNMAPPED default fills the gap
    expect(out!.pci_dss).toBeNull();
    expect(out!.type).toBe("");
  });

  test("shape contract: a full engine row passes through verbatim", () => {
    const row = {
      type: "sql_injection", mapped: true, cwe: "CWE-89",
      cwe_label: "SQL Injection", owasp_2021: "A03:2021",
      owasp_2021_title: "Injection", owasp_2021_src: "s",
      owasp_2025: "A03:2025", owasp_2025_title: "Injection", owasp_2025_src: "s",
      pci_dss: "6.4.2",
    };
    const out = complianceFromJson(JSON.stringify(row));
    expect(out).toEqual(row);
  });

  test("shape contract: null/invalid rows return null, never a throw", () => {
    expect(complianceFromJson(null)).toBeNull();
    expect(complianceFromJson("")).toBeNull();
    expect(complianceFromJson("{not json")).toBeNull();
  });
});
