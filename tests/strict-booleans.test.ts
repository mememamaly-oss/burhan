/**
 * r19-2.17 (owner order 2026-11-20, PR-ب): strict booleans on the SaaS
 * boundary — isDemo (targets route) and options.noBrowser (engine).
 *
 * The coercion table (live-verified before the fix, node/bun identical):
 *   Boolean("false") === true   ← the killer: a client sending "false"
 *                                  (meaning OFF) ARMED the demo path
 *   Boolean("true")  === true
 *   Boolean(1)       === true
 *   Boolean(0)       === false  ← silently-off mask
 *   Boolean(null)    === false
 *
 * GREEN (under test):
 *   - engine.normalizeScanOptions: a non-boolean noBrowser (string /
 *     number / null-with-key-present) THROWS naming the field and the
 *     received type; absent and real booleans pass through; true stays
 *     true, false/absent stay false (the CLI flag --no-browser is only
 *     appended for === true).
 *   - targets route isDemo: guarded by the same contract — see the
 *     exported helper `strictBooleanField` (engine.ts) that the route
 *     now uses; the route-level 400 mapping is covered by the
 *     integration suite's runner, the unit here pins the helper's
 *     semantics both ways.
 *
 * Mutation kills: flipping any `=== true` back to Boolean(), or removing
 * the typeof guard, flips at least one assertion below (each direction
 * is asserted: refuse the bad types, pass the good ones).
 */
import { describe, test, expect } from "bun:test";
import { normalizeScanOptions, strictBooleanField } from "@/lib/engine";

const TARGET_LOCAL = { url: "http://127.0.0.1:8777", isDemo: false };

describe("strict booleans: normalizeScanOptions.noBrowser (r19-2.17)", () => {
  test("real booleans pass through unchanged", () => {
    const on = normalizeScanOptions({ noBrowser: true }, TARGET_LOCAL);
    const off = normalizeScanOptions({ noBrowser: false }, TARGET_LOCAL);
    expect(on.noBrowser).toBe(true);
    expect(off.noBrowser).toBe(false);
  });

  test("absent noBrowser defaults to false (browser half enabled)", () => {
    const a = normalizeScanOptions(undefined, TARGET_LOCAL);
    const b = normalizeScanOptions({}, TARGET_LOCAL);
    expect(a.noBrowser).toBe(false);
    expect(b.noBrowser).toBe(false);
  });

  test("string 'false' is REFUSED (the killer case: Boolean('false')===true)", () => {
    expect(() => normalizeScanOptions({ noBrowser: "false" }, TARGET_LOCAL)).toThrow(
      /noBrowser.*boolean.*string/i,
    );
  });

  test("string 'true' is REFUSED (not silently accepted)", () => {
    expect(() => normalizeScanOptions({ noBrowser: "true" }, TARGET_LOCAL)).toThrow(
      /noBrowser.*boolean.*string/i,
    );
  });

  test("numbers are REFUSED (0 and 1 — the silently-off masks)", () => {
    expect(() => normalizeScanOptions({ noBrowser: 0 }, TARGET_LOCAL)).toThrow(
      /noBrowser.*boolean.*number/i,
    );
    expect(() => normalizeScanOptions({ noBrowser: 1 }, TARGET_LOCAL)).toThrow(
      /noBrowser.*boolean.*number/i,
    );
  });

  test("explicit null is REFUSED (ambiguous intent must be explicit)", () => {
    expect(() => normalizeScanOptions({ noBrowser: null }, TARGET_LOCAL)).toThrow(
      /noBrowser.*boolean.*null/i,
    );
  });

  test("the other knobs keep their clamping behavior", () => {
    const o = normalizeScanOptions(
      { maxPages: 9999, timeout: 999 },
      TARGET_LOCAL,
    );
    expect(o.maxPages).toBe(200);
    expect(o.timeout).toBe(60);
  });
});

describe("strict booleans: strictBooleanField helper (targets route isDemo, r19-2.17)", () => {
  test("undefined (absent) -> false, the documented default", () => {
    expect(strictBooleanField(undefined, "isDemo")).toBe(false);
  });

  test("real booleans pass through", () => {
    expect(strictBooleanField(true, "isDemo")).toBe(true);
    expect(strictBooleanField(false, "isDemo")).toBe(false);
  });

  test("string 'false' THROWS (Boolean('false')===true used to arm the demo path)", () => {
    expect(() => strictBooleanField("false", "isDemo")).toThrow(/isDemo.*boolean.*string/i);
  });

  test("string 'true', numbers, null all THROW", () => {
    expect(() => strictBooleanField("true", "isDemo")).toThrow(/isDemo/i);
    expect(() => strictBooleanField(0, "isDemo")).toThrow(/isDemo.*number/i);
    expect(() => strictBooleanField(1, "isDemo")).toThrow(/isDemo.*number/i);
    expect(() => strictBooleanField(null, "isDemo")).toThrow(/isDemo.*null/i);
  });
});
