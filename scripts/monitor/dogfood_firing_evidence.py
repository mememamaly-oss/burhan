#!/usr/bin/env python3
"""Round-12 Part 2.2 — the monitoring dogfood firing evidence.

Runs the EXACT configured target (scripts/monitor/monitor-config.json ->
dogfood-vulnapp -> fixtures/vulnapp.py on 127.0.0.1:8777) through TWO
monitor cycles against ONE shared store, then evaluates the alert policy
on each cycle's lifecycle resolution:

  cycle 1 (fresh store): every finding is NEW     -> alerts = only CRITICAL NEW
  cycle 2 (same store):  same identities          -> RECURRING -> alerts = []
                                                                  (the 3.4
                                                                  negative
                                                                  control)

Real scans, real store, real lifecycle resolution, real alert evaluation —
the same functions the monitor workflow uses (burhan.monitor.evaluate_alerts
+ the store's lifecycle comparison). Output:
evidence/layers/self-sca/monitor-dogfood/monitor-dogfood-record.json
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

OUT = ROOT / "evidence" / "layers" / "self-sca" / "monitor-dogfood"
OUT.mkdir(parents=True, exist_ok=True)

BASE = "http://127.0.0.1:8777"
STORE = ROOT / "results" / "monitor-dogfood.db"
if STORE.exists():
    STORE.unlink()


def start_fixture() -> subprocess.Popen:
    fixture = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env={"PORT": "8777", "PATH": "/usr/bin:/bin"},
        stdout=open(OUT / "fixture.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    import urllib.request
    assert urllib.request.urlopen(BASE + "/", timeout=5).status == 200
    print(f"fixture up on {BASE} (pid {fixture.pid})")
    return fixture


def scan_cycle(label: str) -> dict:
    from burhan.auth import AuthProfile
    from burhan.oast import OastServer
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.store import Store

    auth = AuthProfile(login_url=BASE + "/login", username="demo",
                       password="demo123", user_field="uid", pass_field="passw",
                       success_marker="Sign Off")
    authz_cfg = json.load(open(ROOT / "benchmarks" / "authz_accounts.json"))
    oast = OastServer()
    t0 = time.time()
    st = Store(str(STORE))
    try:
        # the benchmark campaign configuration, verbatim (monitor dogfood
        # must scan with the SAME profile the canonical runs use). Seed:
        # cycle 1 pins the benchmark seed; cycle 2 gets NONE (os.urandom) —
        # the run-41920279230 lesson: identical seeds give identical run_ids
        # and the store's exclude_run filter blinds the second cycle.
        seed = "bench430" * 8 if label.startswith("cycle-1") else None
        cfg = ScanConfig(allow_private=True, max_pages=40, timeout=12.0,
                         seed=seed, oast=oast, auth=auth,
                         authz=authz_cfg, workflow=True, logic_active=True,
                         max_requests=0, race=True, race_parallel=10,
                         race_variance=0.005, symbolic=True,
                         prioritize_store=str(STORE))
        sc = BurhanScanner(BASE, cfg)
        rep = sc.run()
        st.save_run(rep)
    finally:
        oast.stop()
    wall = round(time.time() - t0, 1)

    # THE monitor's own entry point (run_monitor_cycle — the same function
    # the workflow and run_due.py drive; no reimplementation here)
    from burhan.monitor import run_monitor_cycle
    mon = run_monitor_cycle(st, BASE, rep, webhook_url="")
    alerts = mon["alerts"]
    rep2 = json.loads(json.dumps(rep, default=str))
    states = (rep2.get("prioritization", {}).get("resolution") or {}).get(
        "present_states") or {}
    from collections import Counter
    rec = {
        "cycle": label,
        "run_id": rep.get("run_id"),
        "wall_seconds": wall,
        "findings": len(rep.get("findings", [])),
        "requests": rep.get("stats", {}).get("requests"),
        "states_count": dict(Counter(states.values())),
        "alerts": alerts,
        "alerts_count": len(alerts),
    }
    print(json.dumps({k: rec[k] for k in
                      ("cycle", "findings", "states_count", "alerts_count")}))
    return rec


def main() -> int:
    fixture = start_fixture()
    try:
        c1 = scan_cycle("cycle-1-fresh-store")
        c2 = scan_cycle("cycle-2-shared-store")
    finally:
        fixture.terminate()
        fixture.wait(timeout=10)

    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record = {
        "part": "round-12 Part 2.2 — monitoring dogfood firing evidence",
        "when": when,
        "configured_target": "dogfood-vulnapp (scripts/monitor/monitor-config.json)",
        "fixture": "fixtures/vulnapp.py on 127.0.0.1:8777 (self-hosted, "
                   "authorized-targets 'self-hosted-fixtures')",
        "store": "results/monitor-dogfood.db (one shared store, two cycles)",
        "cycles": [c1, c2],
        "policy_check": {
            "cycle1_expected": "all NEW; alerts only for CRITICAL NEW findings",
            "cycle2_expected": "RECURRING; ZERO alerts (the stable-run "
                               "negative control)",
            "verdict": "PASS" if c2["alerts_count"] == 0 else "FAIL",
        },
        "reference_note": "this is the worked example configuration: users "
                          "copy scripts/monitor/monitor-config.json and "
                          "replace target/store/schedule with their own "
                          "AUTHORIZED target",
    }
    (OUT / "monitor-dogfood-record.json").write_text(
        json.dumps(record, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    print("record ->", OUT / "monitor-dogfood-record.json")
    return 0 if c2["alerts_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
