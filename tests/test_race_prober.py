"""3F — the generic limited-resource race prober: RED/BLUE with the REAL
distribution across repeated concurrent runs (order 2.5: not a single
lucky/unlucky run; at least 10 runs, real numbers reported).

The fixture surface (fixtures/vulnapp.py, RACE_MODE selects the twin):
  POST /api/coupon/redeem {"code": X} — a single-use code; the invariant
  allows at most ONE winner per code.
  RED   RACE_MODE=broken — check-then-set with a deliberate 40ms window:
        a concurrent burst passes the check together and wins together.
  BLUE  RACE_MODE=locked — the SAME handler under a mutex: exactly one
        winner, every run.

Also proven here: the prober is NEVER blind (a scan without
race_candidates records NOT_DISCOVERED with the constraint verbatim),
and VR-37 re-verifies via a fresh burst on the operator-declared second
sample (verify_params) — a single-use resource would otherwise be
consumed by the first burst.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.core import EventBus, ScopeRule                # noqa: E402
from burhan.http_engine import RequestEngine              # noqa: E402
from burhan.modernsec2 import run_modern_battery_v2       # noqa: E402
from burhan.orchestrator import BurhanScanner, ScanConfig  # noqa: E402

N_RUNS = 10
BURST = 6


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(mode: str):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env={**os.environ, "PORT": str(port), "RACE_MODE": mode},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        if proc.poll() is not None:
            pytest.fail("vulnapp fixture died during startup")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.fail("vulnapp never became reachable")
    return port, proc


def _burst(engine, base, code):
    """One battery run against one fresh single-use code -> (fired, winners)."""
    mres = run_modern_battery_v2(
        engine, [], seed="race-dist",
        race_candidates=[{"url": f"{base}/api/coupon/redeem",
                          "method": "POST", "params": {"code": code},
                          "quota": 1, "concurrent": BURST}])
    fam = [f for f in mres.findings if f.type == "race_condition"]
    if fam:
        m = re.search(r"winners (\d+)", fam[0].evidence[0].detail)
        return True, int(m.group(1))
    neg = [b for b in mres.boundaries
           if b["family"] == "race_condition" and b["kind"] == "TESTED_NEGATIVE"]
    assert neg, mres.boundaries
    m = re.search(r"(\d+) winner", neg[0]["detail"])
    return False, int(m.group(1))


def test_red_broken_twin_real_distribution():
    """10 real concurrent bursts, a fresh single-use code each: every burst
    must violate the invariant (more than one winner)."""
    port, proc = _spawn("broken")
    try:
        engine = RequestEngine(ScopeRule(allow_private=True,
                                         allowed_hosts=["127.0.0.1"]),
                               EventBus("race-red"), timeout=10.0)
        dist = [_burst(engine, f"http://127.0.0.1:{port}", f"RED-{i}")
                for i in range(N_RUNS)]
    finally:
        proc.terminate()
    fired = [d for d, _ in dist]
    winners = [w for _, w in dist]
    print(f"\nRED distribution over {N_RUNS} real concurrent bursts: "
          f"winners={winners}")
    assert all(fired), f"race did not fire in every run: {dist}"
    assert all(w > 1 for w in winners), winners
    assert sum(1 for w in winners if w == BURST) >= N_RUNS - 1, winners


def test_blue_locked_twin_real_distribution():
    """The SAME concurrency, same sample size, against the atomic twin:
    zero violations — exactly one winner, every run."""
    port, proc = _spawn("locked")
    try:
        engine = RequestEngine(ScopeRule(allow_private=True,
                                         allowed_hosts=["127.0.0.1"]),
                               EventBus("race-blue"), timeout=10.0)
        dist = [_burst(engine, f"http://127.0.0.1:{port}", f"BLUE-{i}")
                for i in range(N_RUNS)]
    finally:
        proc.terminate()
    fired = [d for d, _ in dist]
    winners = [w for _, w in dist]
    print(f"\nBLUE distribution over {N_RUNS} real concurrent bursts: "
          f"winners={winners}")
    assert not any(fired), dist
    assert all(w == 1 for w in winners), winners


def test_full_scan_wiring_and_vr37():
    """The orchestrator wiring: cfg.race_candidates reaches the battery, the
    finding fires, and VR-37 re-verifies on the operator-declared SECOND
    sample (verify_params) — the first burst consumed the first code."""
    port, proc = _spawn("broken")
    base = f"http://127.0.0.1:{port}"
    try:
        cfg = ScanConfig(
            allow_private=True, max_pages=3, timeout=8.0, browser=False,
            modern_v2=True, max_requests=6000,
            race_candidates=[{"url": f"{base}/api/coupon/redeem",
                              "method": "POST",
                              "params": {"code": "SCAN-1"},
                              "verify_params": {"code": "SCAN-2"},
                              "quota": 1, "concurrent": BURST}])
        data = BurhanScanner(base, cfg).run()
    finally:
        proc.terminate()
    fam = [f for f in data["findings"] if f["type"] == "race_condition"]
    # 2026-11-14 (owner flakiness policy §9.3): a CI run (132557089776) failed
    # this assertion with NO race_condition among the types — 120 local runs
    # (100 plain + 20 under 4-core CPU load) could not reproduce it. On any
    # future failure the burst diagnostics below make the cause decidable
    # from the log alone: whether the battery fired (sent==BURST) and what
    # statuses came back, instead of a bare type list.
    assert fam, {
        "types": sorted({f["type"] for f in data["findings"]}),
        "race_probe_counts": (data["stats"].get("modern_v2") or {})
                             .get("probe_counts", {}).get("race_condition"),
        "boundary": [b for b in (data["stats"].get("boundary") or [])
                     if isinstance(b, dict) and "race" in str(b).lower()][:4],
    }
    assert str(fam[0]["status"]).lower() == "verified", fam[0]["status"]
    m2 = data["stats"].get("modern_v2") or {}
    assert m2["probe_counts"]["race_condition"]["sent"] == BURST, \
        m2["probe_counts"]["race_condition"]


def test_never_blind_boundary():
    """A scan with NO candidate list never fires concurrent load — the
    honest NOT_DISCOVERED record carries the constraint verbatim."""
    port, proc = _spawn("broken")
    base = f"http://127.0.0.1:{port}"
    try:
        cfg = ScanConfig(allow_private=True, max_pages=3, timeout=8.0,
                         browser=False, modern_v2=True, max_requests=4000)
        data = BurhanScanner(base, cfg).run()
    finally:
        proc.terminate()
    assert not [f for f in data["findings"] if f["type"] == "race_condition"]
    m2 = data["stats"].get("modern_v2") or {}
    fam_b = [b for b in m2.get("boundaries", [])
             if b["family"] == "race_condition"]
    assert fam_b and fam_b[0]["kind"] == "NOT_DISCOVERED", fam_b
    assert "never" in fam_b[0]["detail"].lower() or "operator" in \
        fam_b[0]["detail"].lower(), fam_b[0]["detail"]
    assert m2["probe_counts"]["race_condition"]["sent"] == 0
