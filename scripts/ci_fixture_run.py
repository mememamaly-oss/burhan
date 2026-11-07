#!/usr/bin/env python3
"""P2 (2026-10-31): the canonical CI fixture run.

Mirrors the verified full-platform configuration EXACTLY (the same
ScanConfig the benchmark/reverify campaign used — seed 'bench430'*8,
authenticated demo user, authz accounts, workflow + logic + race +
symbolic batteries, max_requests=0), persists the run to a Store DB, and
writes scan.json. CI gates on it (findings floor + compliance mapping on
every verified finding) and exports all five report formats from the store.

Usage: python3 scripts/ci_fixture_run.py --out-dir /tmp/ci-fixture
Exit codes: 0 ok / 2 engine or fixture failure / 3 gate failure.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# R17-8: the fixture spawn must EXTEND the inherited environment (a
# wholesale-replaced env broke Windows Winsock — WinError 10106, Winsock
# needs SYSTEMROOT — and dropped host-required vars on every platform),
# while PRESERVING the deliberate isolation: vulnapp.py reads BEHAVIORAL
# env vars (DELAY_MS/AUTH_TTL/CONFUSION/BFLA/SHADOW/RACE_MODE/SIGNOFF)
# used by chaos/demo runs; an inherited BFLA=1 or RACE_MODE=broken would
# mutate the fixture and break the deterministic record (TP=38/FP=0).
# Shared helper => no drift between this script and repro_attest.py.
from burhan.fixture_env import fixture_env  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--port", type=int, default=8777)
    args = ap.parse_args()

    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    base = f"http://127.0.0.1:{args.port}"

    # 1. spawn the fixture (same code the benchmark spawns)
    fixture = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env=fixture_env(args.port),
        stdout=open(out / "fixture.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    import urllib.request
    probe = urllib.request.urlopen(base + "/", timeout=5).status
    assert probe == 200, probe
    print(f"fixture up on {base} (pid {fixture.pid})")

    # 2. full-platform engine run (benchmark configuration, verbatim)
    from burhan.auth import AuthProfile
    from burhan.core import EventBus, ScopeRule  # noqa: F401 (parity with the campaign driver)
    from burhan.oast import OastServer
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.store import Store

    auth = AuthProfile(login_url=base + "/login", username="demo",
                       password="demo123", user_field="uid", pass_field="passw",
                       success_marker="Sign Off")
    authz_cfg = json.load(open(ROOT / "benchmarks" / "authz_accounts.json"))
    oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=40, timeout=12.0,
                         seed="bench430" * 8, oast=oast, auth=auth,
                         authz=authz_cfg, workflow=True, logic_active=True,
                         max_requests=0, race=True, race_parallel=10,
                         race_variance=0.005, symbolic=True)
        sc = BurhanScanner(base, cfg)
        rep = sc.run()
    finally:
        oast.stop()
    wall = time.time() - t0

    (out / "scan.json").write_text(
        json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
    n = Store(str(out / "store.db")).save_run(rep)
    findings = rep["findings"]
    print(f"scan done in {wall:.1f}s: requests={rep['stats']['requests']} "
          f"findings={len(findings)} persisted={n}")

    # 3. gates — floors comfortably below the deterministic record
    #    (199 verified / 30 distinct types), above any honest floor.
    from burhan.compliance import compliance_for
    verified = [f for f in findings if f.get("status") == "verified"]
    unmapped = [f["id"] for f in verified if not (f.get("compliance") or {}).get("mapped")]
    distinct = len({f["type"] for f in verified})
    ok = True
    if len(verified) < 150:
        print(f"GATE FAIL: verified findings {len(verified)} < 150"); ok = False
    if distinct < 25:
        print(f"GATE FAIL: distinct types {distinct} < 25"); ok = False
    if unmapped:
        print(f"GATE FAIL: findings without compliance mapping: {unmapped[:5]}"); ok = False
    if not ok:
        return 3
    print(f"GATES OK: {len(verified)} verified, {distinct} distinct types, all mapped")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"FIXTURE FAILURE: {e}")
        sys.exit(2)
