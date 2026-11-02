"""Evidence generator for PART 3 — 3G: Shadow / Zombie API detection.

RED (a spec that mismatches reality in exactly the two documented
ways) vs BLUE (a twin spec that matches it exactly), full scanner runs.
"""
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.orchestrator import BurhanScanner, ScanConfig         # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env={**os.environ, "PORT": str(port), "SHADOW": "1"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return port, proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("fixture never became reachable")


def _spec(base, red):
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
            "servers": [{"url": base}], "paths": paths}


def _record(data, label, spec_desc):
    m2 = data["stats"].get("modern_v2") or {}
    fam = [f for f in data["findings"]
           if f["type"] in ("shadow_api_endpoint", "zombie_api_endpoint")]
    return {
        "layer": "shadow-api",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": "fixtures/vulnapp.py (env SHADOW=1) — full BurhanScanner scan",
        "label": label,
        "spec": spec_desc,
        "probe_counts": m2.get("probe_counts", {}).get("shadow_api"),
        "boundaries": [b for b in m2.get("boundaries", [])
                       if b["family"] == "shadow_api"],
        "findings": [{"type": f["type"],
                      "url": f["url"].split("://", 1)[1].split("/", 1)[1],
                      "status": str(f["status"]),
                      "evidence": [{"kind": e.get("kind"), "detail": e.get("detail")}
                                   for e in (f.get("evidence") or [])]}
                     for f in fam],
    }


port, proc = _spawn()
base = f"http://127.0.0.1:{port}"
try:
    red = _record(
        BurhanScanner(base, ScanConfig(
            allow_private=True, max_pages=8, timeout=8.0, browser=False,
            modern_v2=True, max_requests=6000,
            openapi_spec=_spec(base, red=True))).run(),
        "RED — the spec mismatches reality in EXACTLY the two documented ways",
        "declares: /api/filter (live), /api/v1/users (deprecated:true, live), "
        "/api/v2/ghost (never existed); MISSING /api/v2/internal/telemetry "
        "(live JSON)")
    blue = _record(
        BurhanScanner(base, ScanConfig(
            allow_private=True, max_pages=8, timeout=8.0, browser=False,
            modern_v2=True, max_requests=6000,
            openapi_spec=_spec(base, red=False))).run(),
        "BLUE — the twin spec matches live reality exactly",
        "declares: /api/filter (live), /api/v1/users (live, not deprecated), "
        "/api/v2/internal/telemetry (live) — nothing dead, nothing missing")
finally:
    proc.terminate()

out = os.path.join(ROOT, "evidence", "layers", "shadow-api")
os.makedirs(out, exist_ok=True)

assert {f["url"] for f in red["findings"] if f["type"] == "shadow_api_endpoint"} \
    == {"api/v2/internal/telemetry"}, red["findings"]
z = sorted(f["url"] for f in red["findings"]
           if f["type"] == "zombie_api_endpoint")
assert z == ["api/v1/users", "api/v2/ghost"], z
assert all(f["status"].lower() == "verified" for f in red["findings"]), red
assert not blue["findings"], blue["findings"]
assert any(b["kind"] == "TESTED_NEGATIVE" for b in blue["boundaries"]), blue

for name, doc in (("RED.json", red), ("BLUE.json", blue)):
    with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)

print(f"RED  findings: {len(red['findings'])} "
      f"({[f['type'] for f in red['findings']]}) — details in RED.json")
print(f"BLUE findings: {len(blue['findings'])} — details in BLUE.json")
print("ALL EVIDENCE ASSERTIONS PASS")
