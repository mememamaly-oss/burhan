#!/usr/bin/env python3
"""P2 (2026-10-31): REAL-target CI scan — OWASP Juice Shop in a container.

The bundled fixture (vulnapp) is our OWN ground truth; this harness is the
honest external check: a real-world OWASP training application the engine
has never seen, running in a container started by the CI job, scanned
UNAUTHENTICATED (the engine's AuthProfile is form-based; Juice Shop
authenticates via a JSON REST endpoint — an honest, documented limitation
of this baseline, not a hidden gap).

Baseline discipline (same honesty contract as every registry here):
  * first run = BASELINE: gate only on (a) scan completed, (b) >= 1
    verified finding, (c) every verified finding carries a compliance
    mapping. The observed numbers are then committed as the floor file
    and every later run must reproduce them (--floor).
  * the scan is seeded and deterministic in its axis configuration: no
    race/symbolic batteries in this baseline (time-boxed first external
    validation); enable them in a later floor revision.

Usage:
  python3 scripts/ci_real_target_scan.py --base http://127.0.0.1:3000 \
      --out-dir /tmp/real [--floor evidence/real-targets/juice-shop/floor.json]

Exit codes: 0 ok / 2 target unreachable / 3 gate failure.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="target base URL")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--floor", default="",
                    help="committed baseline floor JSON (tightened gate)")
    ap.add_argument("--max-requests", type=int, default=2500)
    ap.add_argument("--max-pages", type=int, default=60)
    args = ap.parse_args()

    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # ---- authorization gate (round 8, part 2): BEFORE the liveness probe —
    # the probe is itself a request, so the gate goes first. The registry
    # (authorized-targets.json, repo root) is the ONLY source of truth; an
    # unlisted/unverified target is refused loudly with exit 2.
    from burhan.authorized_targets import require_authorized
    require_authorized(args.base)

    # 0. target must answer before we scan
    import urllib.error
    import urllib.request
    try:
        # A 302 at the root is a LIVE answer, not an outage: WebGoat (dev-set
        # calibration run 43329704514, 2026-11-12) answers GET /WebGoat/ with
        # a session-creating 302 loop when the probe carries no cookie jar.
        # Accept any < 400 as proof of life; the engine's own fetcher (with
        # cookie handling) does the real crawling afterwards. Fails closed
        # on >= 400, network errors and timeouts exactly as before.
        req = urllib.request.Request(args.base + "/", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                probe = resp.status
        except urllib.error.HTTPError as http_err:
            probe = http_err.code
        assert probe < 400, probe
    except Exception as e:  # noqa: BLE001
        print(f"REAL-TARGET FAILURE: {args.base} unreachable: {e}")
        return 2
    print(f"target up: {args.base} (probe status {probe})")

    # 1. the scan — unauthenticated, seeded, core axes
    from burhan.compliance import compliance_for, compliance_summary
    from burhan.oast import OastServer
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.store import Store

    oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=args.max_pages,
                         timeout=15.0, seed="real430" * 8, oast=oast,
                         workflow=True, logic_active=True,
                         max_requests=args.max_requests)
        sc = BurhanScanner(args.base, cfg)
        rep = sc.run()
    finally:
        oast.stop()
    wall = time.time() - t0

    (out / "scan.json").write_text(
        json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
    Store(str(out / "store.db")).save_run(rep)
    findings = rep["findings"]
    verified = [f for f in findings if f.get("status") == "verified"]
    distinct = sorted({f["type"] for f in verified})

    summary = {
        "target": args.base,
        "mode": "unauthenticated",
        "seed": "real430" * 8,
        "axes": {"workflow": True, "logic_active": True,
                 "race": False, "symbolic": False},
        "wall_seconds": round(wall, 1),
        "requests": rep["stats"]["requests"],
        "findings_total": len(findings),
        "findings_verified": len(verified),
        "distinct_verified_types": distinct,
        "compliance": compliance_summary(findings),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"scan done in {wall:.1f}s: requests={rep['stats']['requests']} "
          f"findings={len(findings)} verified={len(verified)} "
          f"distinct_types={len(distinct)}")
    for t in distinct:
        print(f"  - {t}")

    # 2. reports from the store (json + sarif for the artifacts)
    run_id = rep["run_id"]
    import subprocess
    for fmt in ("json", "sarif"):
        r = subprocess.run(
            [sys.executable, "-m", "burhan.cli", "report",
             "--db", str(out / "store.db"), "--run-id", str(run_id),
             "--format", fmt, "--out", str(out / f"report.{fmt}")],
            cwd=str(ROOT), capture_output=True, text=True)
        if r.returncode != 0:
            print(f"REPORT EXPORT FAILURE ({fmt}): {r.stderr[-500:]}")
            return 3
    (out / "compliance.json").write_text(
        json.dumps({t: compliance_for(t) for t in distinct}, indent=1,
                   ensure_ascii=False), encoding="utf-8")

    # 3. gates
    ok = True
    if len(verified) < 1:
        print("GATE FAIL: no verified findings on a real target"); ok = False
    unmapped = [t for t in distinct
                if not compliance_for(t).get("mapped")]
    if unmapped:
        print(f"GATE FAIL: unmapped verified types: {unmapped}"); ok = False

    if args.floor:
        floor = json.loads((ROOT / args.floor).read_text(encoding="utf-8"))
        if len(verified) < floor["findings_verified"]:
            print(f"GATE FAIL: verified {len(verified)} < floor "
                  f"{floor['findings_verified']}"); ok = False
        if len(distinct) < floor["distinct_types"]:
            print(f"GATE FAIL: distinct types {len(distinct)} < floor "
                  f"{floor['distinct_types']}"); ok = False
        # owner order 2026-11-13 (decision 5): surface the TYPE BALANCE next to
        # the counts — a green floor that is 100% passive hygiene must say so
        # in the log line itself, not only in the committed JSON.
        passive = ("missing_security_headers", "server_banner_disclosure",
                   "tech_banner_disclosure", "vulnerable_js_dependency")
        n_passive = sum(1 for fd in verified if fd.get("type") in passive)
        n_active = len(verified) - n_passive
        print(f"floor check: verified>={floor['findings_verified']}, "
              f"types>={floor['distinct_types']} "
              f"(floor: {floor.get('source', 'committed')}) | "
              f"type-balance: {n_passive} passive-hygiene / {n_active} active-attack | "
              f"CAVEAT: unauthenticated-only, does not reflect vulnerabilities behind login")

    if not ok:
        return 3
    print("REAL-TARGET GATES OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
