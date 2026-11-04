"""R10 Part 2 exploration: ONE scan of vulnapp (SIGNOFF=1 + BFLA=1 +
authz accounts + modern_v2) — which of the chain-rule candidate pairs
actually fire together, with what authz_contexts? Facts before rules."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/z/my-project"
sys.path.insert(0, ROOT)


def main() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "PORT": str(port), "SIGNOFF": "1", "BFLA": "1"}
    proc = subprocess.Popen(
        [sys.executable, f"{ROOT}/fixtures/vulnapp.py"], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/", timeout=2)
                break
            except Exception:
                time.sleep(0.25)
        from burhan.orchestrator import ScanConfig, BurhanScanner
        cfg = ScanConfig(
            allow_private=True, max_pages=8, timeout=8.0, browser=False,
            modern_v2=True, max_requests=8000,
            authz={"login_url": f"{base}/login",
                   "accounts": [
                       {"name": "admin", "role": "admin",
                        "username": "demo", "password": "demo123",
                        "marker": "root-admin@burhan-fixture.local",
                        "object_id": "1001"},
                       {"name": "bob", "role": "user",
                        "username": "bob", "password": "bob123",
                        "marker": "bob-user@burhan-fixture.local",
                        "object_id": "2002"},
                       {"name": "carol", "role": "user",
                        "username": "carol", "password": "carol123",
                        "marker": "carol-user@burhan-fixture.local",
                        "object_id": "3003"}],
                   "user_field": "uid", "pass_field": "passw",
                   "success_marker": "Sign Off"})
        rep = BurhanScanner(base, cfg).run()
        interesting = ("bfla", "idor_bola", "jwt_signature_not_enforced",
                       "vertical_privilege_escalation", "shadow_api_endpoint",
                       "zombie_api_endpoint")
        out = []
        for f in rep["findings"]:
            if f["type"] in interesting or \
                    f["type"].startswith("xss") and "/account" in f["url"]:
                out.append({"type": f["type"], "url": f["url"],
                            "param": f.get("parameter"),
                            "authz_context": f.get("authz_context", ""),
                            "ev0": (f.get("evidence") or [{}])[0]
                                   .get("detail", "")[:180]})
        print(json.dumps({"types": sorted({f["type"] for f in rep["findings"]}),
                          "interesting": out}, indent=1)[:4000])
        return 0
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
