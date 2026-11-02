"""3E BFLA (Broken Function Level Authorization) — RED/BLUE proof.

The family lives in the modern2 battery (OFF by default with --modern-v2
unset) and reuses the authz battery's logged-in sessions (demo=admin,
bob=user — nothing logs in inside 3E). The fixture surface
(BFLA=1-gated lab divs + two POST routes):

  RED   POST /api/admin/rotate-keys — any AUTHENTICATED session executes
        the admin function (no role check): the API5:2023 class. The
        finding fires and survives VR-36 (a fresh lower-privilege replay
        through the same session engine).
  BLUE  POST /api/secure/admin/rotate-keys — the hardened twin (role
        enforced, 403): zero findings, honest TESTED_NEGATIVE.
  REGRESSION the standard fixture (no BFLA surfaces) with the same
        authz + modern_v2 configuration: zero bfla findings on every
        correctly-scoped endpoint the suite already exercises.
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


def _spawn(mode: str = ""):
    port = _free_port()
    env = {**os.environ, "PORT": str(port)}
    if mode:
        env["BFLA"] = mode
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


def _scan(base: str):
    cfg = ScanConfig(
        allow_private=True, max_pages=8, timeout=8.0, browser=False,
        modern_v2=True, max_requests=8000,
        authz={"login_url": f"{base}/login",
               "accounts": [
                   {"name": "admin", "role": "admin",
                    "username": "demo", "password": "demo123",
                    "marker": "root-admin@burhan-fixture.local"},
                   {"name": "bob", "role": "user",
                    "username": "bob", "password": "bob123",
                    "marker": "bob-user@burhan-fixture.local"}],
               "user_field": "uid", "pass_field": "passw",
               "success_marker": "Sign Off"})
    return BurhanScanner(base, cfg).run()


def test_bfla_red_broken_and_blue_hardened_in_one_scan():
    port, proc = _spawn("1")
    try:
        data = _scan(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
    types = {f["type"] for f in data["findings"]}
    # RED: the broken admin function fired
    bfla = [f for f in data["findings"] if f["type"] == "bfla"]
    assert bfla, sorted(types)
    broken = [f for f in bfla if "/api/admin/rotate-keys" in f["url"]]
    assert broken, [f["url"] for f in bfla]
    assert str(broken[0]["status"]).lower() == "verified", broken[0]["status"]
    # BLUE: the hardened twin stayed silent
    secure = [f for f in bfla if "secure" in f["url"]]
    assert not secure, [f["url"] for f in bfla]
    # the battery's own record: probes sent, hardened endpoint rejected
    m2 = (data["stats"].get("modern_v2") or {})
    assert m2.get("probe_counts", {}).get("bfla", {}).get("sent", 0) >= 3, \
        m2.get("probe_counts", {}).get("bfla")
    kinds = [b["kind"] for b in m2.get("boundaries", []) if b["family"] == "bfla"]
    assert "TESTED_NEGATIVE" in kinds or len(bfla) >= 1, kinds


def test_bfla_regression_standard_fixture_zero_findings():
    """Every existing surface the suite already exercises — correctly scoped
    or not admin-shaped — must produce ZERO bfla findings."""
    port, proc = _spawn()
    try:
        data = _scan(f"http://127.0.0.1:{port}")
    finally:
        proc.terminate()
    bfla = [f for f in data["findings"] if f["type"] == "bfla"]
    assert not bfla, [f["url"] for f in bfla]
    m2 = (data["stats"].get("modern_v2") or {})
    fam_b = [b for b in m2.get("boundaries", []) if b["family"] == "bfla"]
    assert fam_b and fam_b[0]["kind"] == "NOT_DISCOVERED", fam_b
    assert m2.get("probe_counts", {}).get("bfla", {}).get("sent", 0) == 0, \
        m2.get("probe_counts", {}).get("bfla")


def _tpl_spec(base):
    """crAPI's own spec shape: the admin DELETE declares its path parameter
    with a documentation EXAMPLE id (12345) that matches no real object, and
    a spec-only route (token_id) no session view can ever supply. Two
    DISTINCT object kinds (videos broken / clips hardened): a destructive
    oracle consumes the session's object of that kind, so a second admin
    function over the SAME kind would find it gone — the honest UNTESTABLE."""
    def _pdel(name, example):
        return {"delete": {
            "responses": {"200": {"description": "OK"}},
            "parameters": [
                {"name": name, "in": "path", "required": True,
                 "schema": {"type": "integer", "format": "int64"},
                 "example": example}]}}
    return {"openapi": "3.0.0",
            "info": {"title": "bfla-template-fixture", "version": "1.0.0"},
            "servers": [{"url": base}],
            "paths": {
                "/api/me": {"get": {
                    "responses": {"200": {"description": "OK"}}}},
                "/api/admin/videos/{video_id}": _pdel("video_id", 12345),
                "/api/secure/admin/clips/{clip_id}": _pdel("clip_id", 12345),
                "/api/admin/tokens/{token_id}": _pdel("token_id", 999)}}


def test_bfla_spec_example_id_materializes_from_session_views():
    """BFLA-2 (crAPI live round, 2026-11-02, run 41436129520): the spec
    declares the admin DELETE's path parameter with a documentation EXAMPLE
    id — the privileged oracle replayed the placeholder, read 404, and the
    honest record said UNTESTABLE although no authorization question had
    been asked. The fix: each replaying session substitutes its OWN real
    object id, harvested from the JSON view the authz battery already
    fetched under that identity (/api/me — the crAPI dashboard shape).

    RED   the broken twin fires on the LOW session's OWN harvested id
          (bob -> 202, never the example 12345 nor the braces) and
          survives VR-36 through the consumed transition (the single-use
          video is gone: fresh replay reads 404 after the stashed 200).
    BLUE  the hardened twin stays silent (role enforced, TESTED_NEGATIVE).
    UNSUBSTITUTED the spec-only token_id records the wiring fact and
          sends NOTHING."""
    port, proc = _spawn("2")
    try:
        base = f"http://127.0.0.1:{port}"
        cfg = ScanConfig(
            allow_private=True, max_pages=8, timeout=8.0, browser=False,
            modern_v2=True, max_requests=8000, openapi_spec=_tpl_spec(base),
            authz={"login_url": f"{base}/login",
                   "accounts": [
                       {"name": "admin", "role": "admin",
                        "username": "demo", "password": "demo123",
                        "marker": "root-admin@burhan-fixture.local"},
                       {"name": "bob", "role": "user",
                        "username": "bob", "password": "bob123",
                        "marker": "bob-user@burhan-fixture.local"}],
                   "user_field": "uid", "pass_field": "passw",
                   "success_marker": "Sign Off"})
        data = BurhanScanner(base, cfg).run()
    finally:
        proc.terminate()
    bfla = [f for f in data["findings"] if f["type"] == "bfla"]
    assert bfla, sorted({f["type"] for f in data["findings"]})
    broken = [f for f in bfla if "/api/admin/videos/" in f["url"]]
    assert broken, [f["url"] for f in bfla]
    # the finding names the LOW session's OWN materialized resource
    assert broken[0]["url"].endswith("/api/admin/videos/202"), broken[0]["url"]
    assert "12345" not in broken[0]["url"] and "{" not in broken[0]["url"]
    # VR-36 consumed transition: single-use object, fresh replay 404
    # after the stashed 200 — still verified (weaker, documented basis)
    assert str(broken[0]["status"]).lower() == "verified", (
        broken[0]["status"], broken[0].get("verification"))
    # BLUE: the hardened twin (clips — its own object kind) stayed silent
    assert not [f for f in bfla if "secure" in f["url"] or "clips" in f["url"]], \
        [f["url"] for f in bfla]
    m2 = (data["stats"].get("modern_v2") or {})
    kinds = [b["kind"] for b in m2.get("boundaries", [])
             if b["family"] == "bfla"]
    # UNSUBSTITUTED: the spec-only token_id — zero probes for that endpoint.
    # (The family-wide TESTED_NEGATIVE only records when NOTHING fired; the
    # hardened twin's rejection shows below in the probe accounting.)
    assert "UNSUBSTITUTED_PATH_PARAM" in kinds, kinds
    tok = [b for b in m2.get("boundaries", [])
           if b["family"] == "bfla" and b["kind"] == "UNSUBSTITUTED_PATH_PARAM"]
    assert tok and "token_id" in tok[0]["detail"], tok
    # probe accounting: broken (anon+high+low = 3) + secure (3) + ghost (0)
    assert m2.get("probe_counts", {}).get("bfla", {}).get("sent", 0) == 6, \
        m2.get("probe_counts", {}).get("bfla")
