"""R10 exploration: does a LIGHT engine run on fixtures/vulnapp.py still
verify xss_reflected on /vuln/xss.php, and how long does it take?
This decides the Part-1 three-scan test configuration."""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = "/home/z/my-project"
sys.path.insert(0, ROOT)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> int:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [sys.executable, f"{ROOT}/fixtures/vulnapp.py"],
        env={"PORT": str(port), "PATH": "/usr/bin:/bin"},
        stdout=open("/tmp/render/scan-fixture.log", "w"),
        stderr=subprocess.STDOUT)
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen(base + "/", timeout=2)
                break
            except Exception:
                time.sleep(0.25)
        from burhan.core import ScopeRule  # noqa: F401
        from burhan.orchestrator import ScanConfig, BurhanScanner
        t0 = time.time()
        cfg = ScanConfig(allow_private=True, max_pages=25, timeout=8.0,
                         seed="r10light" * 8, max_requests=1500,
                         browser=False, workflow=False, logic_active=False,
                         race=False, symbolic=False, websocket=False,
                         graphql=False, modern=False)
        rep = BurhanScanner(base, cfg).run()
        wall = time.time() - t0
        types = {}
        for f in rep["findings"]:
            types[f["type"]] = types.get(f["type"], 0) + 1
        xss = [f for f in rep["findings"] if f["type"] == "xss_reflected"]
        print(json.dumps({
            "wall_s": round(wall, 1),
            "requests": rep["stats"]["requests"],
            "verified": len(rep["findings"]),
            "distinct_types": len(types),
            "xss_reflected": len(xss),
            "xss_urls": [f["url"] for f in xss],
            "journal_entries": len(rep["stats"].get("request_journal") or {}),
        }, indent=1))
        return 0
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
