"""3G — Shadow / Zombie API detection: RED/BLUE against a spec that
mismatches reality in EXACTLY the two documented ways vs a twin spec
that matches it exactly.

Fixture surface (fixtures/vulnapp.py, env SHADOW=1):
  /api/v2/internal/telemetry — LIVE, JSON, deliberately absent from the
                              RED spec (the SHADOW).
  /api/v1/users              — the deprecated version kept alive; the RED
                              spec declares it deprecated:true.
  /api/v2/ghost              — declared in the RED spec, never existed
                              (404 live — the dead ZOMBIE).
Both specs declare /api/filter (the live endpoint the crawl also finds)
so the diff is clean.

RED  = shadow fires on telemetry + zombie fires twice (ghost dead,
       v1/users deprecated-but-alive), all surviving VR-38.
BLUE = the matched twin: zero findings, an honest TESTED_NEGATIVE.
NOSPEC = a scan without cfg.openapi_spec never runs the diff
       (NOT_DISCOVERED, zero probes).
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.orchestrator import BurhanScanner, ScanConfig         # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def shadow_base():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env={**os.environ, "PORT": str(port), "SHADOW": "1"},
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
    yield f"http://127.0.0.1:{port}"
    proc.terminate()


def _spec(base, *, red: bool):
    paths = {
        "/api/filter": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/api/v1/users": {"get": {
            "responses": {"200": {"description": "ok"}},
            **({"deprecated": True} if red else {})}},
    }
    if red:
        paths["/api/v2/ghost"] = {"get": {
            "responses": {"200": {"description": "ok"}}}}
    else:
        paths["/api/v2/internal/telemetry"] = {"get": {
            "responses": {"200": {"description": "ok"}}}}
    return {"openapi": "3.0.0",
            "info": {"title": "shadow-zombie-fixture", "version": "1.0.0"},
            "servers": [{"url": base}],
            "paths": paths}


def _scan(base, spec):
    cfg = ScanConfig(allow_private=True, max_pages=8, timeout=8.0,
                     browser=False, modern_v2=True, max_requests=6000,
                     openapi_spec=spec)
    return BurhanScanner(base, cfg).run()


def test_red_spec_mismatches_isolated_and_verified(shadow_base):
    data = _scan(shadow_base, _spec(shadow_base, red=True))
    shadows = [f for f in data["findings"] if f["type"] == "shadow_api_endpoint"]
    zombies = [f for f in data["findings"] if f["type"] == "zombie_api_endpoint"]
    assert shadows, sorted({f["type"] for f in data["findings"]})
    assert {f["url"].split("://", 1)[1].split("/", 1)[1]
            for f in shadows} == {"api/v2/internal/telemetry"}, \
        [f["url"] for f in shadows]
    assert str(shadows[0]["status"]).lower() == "verified", shadows[0]["status"]
    zpaths = sorted(f["url"].split("://", 1)[1].split("/", 1)[1]
                    for f in zombies)
    assert zpaths == ["api/v1/users", "api/v2/ghost"], zpaths
    assert all(str(f["status"]).lower() == "verified" for f in zombies), \
        [(f["url"], f["status"]) for f in zombies]
    m2 = data["stats"].get("modern_v2") or {}
    assert m2["probe_counts"]["shadow_api"]["sent"] >= 3, \
        m2["probe_counts"]["shadow_api"]


def test_blue_matched_spec_zero_findings(shadow_base):
    data = _scan(shadow_base, _spec(shadow_base, red=False))
    assert not [f for f in data["findings"]
                if f["type"] in ("shadow_api_endpoint", "zombie_api_endpoint")], \
        [f["type"] for f in data["findings"]]
    m2 = data["stats"].get("modern_v2") or {}
    fam_b = [b for b in m2.get("boundaries", []) if b["family"] == "shadow_api"]
    assert any(b["kind"] == "TESTED_NEGATIVE" for b in fam_b), fam_b


def test_no_spec_no_diff(shadow_base):
    data = _scan(shadow_base, None)
    assert not [f for f in data["findings"]
                if f["type"] in ("shadow_api_endpoint", "zombie_api_endpoint")]
    m2 = data["stats"].get("modern_v2") or {}
    fam_b = [b for b in m2.get("boundaries", []) if b["family"] == "shadow_api"]
    assert fam_b and fam_b[0]["kind"] == "NOT_DISCOVERED", fam_b
    assert m2["probe_counts"]["shadow_api"]["sent"] == 0, \
        m2["probe_counts"]["shadow_api"]
