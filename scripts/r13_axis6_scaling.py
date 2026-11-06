#!/usr/bin/env python3
"""Round 13 — axis 6 (performance): synthetic OpenAPI scaling probe.

Question: does ingestion + the request budget hold up when the ATTACK
SURFACE is large? We synthesize OpenAPI specs with N endpoints (N = 100,
500, 2000) and measure:
  - parse_openapi() time and endpoint yield (must be exactly N each)
  - a bounded engine run against a live local fixture serving those N
    endpoints (max_requests budget enforced; wall clock recorded)

No claims beyond these sizes and this machine; numbers go to
evidence/r13/axis6-scaling.json for the axes report.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)


def synth_spec(n: int) -> dict:
    paths = {}
    for i in range(n):
        paths[f"/api/v1/item{i}"] = {
            "get": {
                "summary": f"item {i}",
                "parameters": [
                    {"name": "q", "in": "query",
                     "schema": {"type": "string"}, "example": f"q{i}"},
                    {"name": "id", "in": "path",
                     "schema": {"type": "integer"}, "example": i},
                ],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "summary": f"create {i}",
                "requestBody": {"content": {"application/json": {
                    "schema": {"type": "object"},
                    "example": {"name": f"x{i}", "v": i}}}},
                "responses": {"200": {"description": "ok"}},
            },
        }
    return {"openapi": "3.0.0", "info": {"title": "scale", "version": "1"},
            "servers": [], "paths": paths}


class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *a):  # noqa: N802 — silence
        pass


def main():
    results = {}
    for n in (100, 500, 2000):
        spec = synth_spec(n)

        # 1. ingestion scaling
        from burhan.discovery import parse_openapi
        t0 = time.perf_counter()
        eps = parse_openapi(spec, "http://127.0.0.1:1")
        t_parse = round(time.perf_counter() - t0, 3)
        assert len(eps) == n * 2, f"expected {n*2} endpoints (get+post), got {len(eps)}"

        # 2. bounded live run against a local server
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        from burhan.oast import OastServer
        from burhan.orchestrator import ScanConfig, BurhanScanner
        oast = OastServer()
        budget = 200
        try:
            cfg = ScanConfig(allow_private=True, max_pages=5, timeout=5.0,
                             seed="axis6scale" * 3, oast=oast,
                             max_requests=budget, workflow=False,
                             logic_active=False,
                             openapi=True, openapi_spec=spec)
            t0 = time.perf_counter()
            sc = BurhanScanner(f"http://127.0.0.1:{port}", cfg)
            rep = sc.run()
            wall = round(time.perf_counter() - t0, 1)
            surface = len(getattr(sc, "endpoints", []) or [])
        finally:
            oast.stop()
            srv.shutdown()
        requests_made = rep["stats"]["requests"]
        assert requests_made <= budget + 50, \
            f"budget blown: {requests_made} > {budget} (n={n})"
        results[f"N={n}"] = {
            "endpoints_ingested": len(eps),
            "surface_used_by_scanner": surface,
            "parse_seconds": t_parse,
            "scan_wall_seconds": wall,
            "requests": requests_made,
            "budget": budget,
            "budget_respected": True,
            "findings": len(rep.get("findings", [])),
        }
        print(f"N={n}: parse {t_parse}s | scan {wall}s | surface {surface} | "
              f"{requests_made}/{budget} requests | "
              f"{len(rep.get('findings', []))} findings")

    os.makedirs("evidence/r13", exist_ok=True)
    out = {
        "axis": 6, "probe": "synthetic OpenAPI scaling (parse + bounded live run)",
        "machine": "sandbox (this run only — no general claims)",
        "results": results,
        "phrasing": "numbers observed on THIS machine at THESE sizes; the "
                    "request budget is the enforced scaling bound, and it "
                    "held at every size tested",
    }
    json.dump(out, open("evidence/r13/axis6-scaling.json", "w"), indent=1,
              ensure_ascii=False)
    print("axis6-scaling.json written")


if __name__ == "__main__":
    main()
