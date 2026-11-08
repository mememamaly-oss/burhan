#!/usr/bin/env python3
"""Owner order part 3: modern-battery-v2 RED/BLUE fixture (vulnerable + safe twins).

vuln mode (the RED target):
  /login      issues an HS256 JWT signed with the common secret "secret"  (3A)
  /graphql    executes every alias carried by a single request            (3C)
  /api/users  returns password_hash + is_internal fields                 (3D)

safe mode (the BLUE twin — same app, hardened):
  /login      signs with a 48-char non-wordlist secret
  /graphql    enforces a query-complexity limit (max 5 aliases)
  /api/users  returns the clean response shape

Run:
  python3 fixtures/modern2_fixture.py --mode vuln --port 18701
  python3 fixtures/modern2_fixture.py --mode safe --port 18702
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAFE_SECRET = "b7f3d9" * 8       # 48 chars — not in any common-secret wordlist
VULN_SECRET = "secret"           # the 3A RED anchor: a guessable HMAC secret


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def hs256(secret: str, claims: dict) -> str:
    h = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"},
                         separators=(",", ":")).encode())
    p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64u(hmac.new(secret.encode(), f"{h}.{p}".encode(),
                         hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


class _Handler(BaseHTTPRequestHandler):
    mode = "vuln"

    def log_message(self, *a):        # noqa: N802 — silence test servers
        pass

    def _send(self, code, doc, cookies=None):
        body = json.dumps(doc).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookies:
            self.send_header("Set-Cookie", cookies)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                 # noqa: N802
        if self.path.startswith("/login"):
            secret = VULN_SECRET if self.mode == "vuln" else SAFE_SECRET
            tok = hs256(secret, {"sub": "u1", "role": "user"})
            return self._send(200, {"ok": True, "token": tok},
                              cookies=f"sid={tok}; Path=/")
        if self.path.startswith("/api/users"):
            if self.mode == "vuln":
                return self._send(200, [
                    {"id": 1, "email": "a@ex.test",
                     "password_hash": "$2b$12$fixtureNotARealHashValue000000",
                     "is_internal": True}])
            return self._send(200, [{"id": 1, "email": "a@ex.test"}])
        if self.path.startswith("/graphql"):
            return self._send(200, {"data": None,
                                    "errors": [{"message": "POST required"}]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):                # noqa: N802
        if self.path.startswith("/graphql"):
            n = int(self.headers.get("Content-Length", "0"))
            try:
                doc = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._send(400, {"errors": [{"message": "bad json"}]})
            q = str(doc.get("query", ""))
            found = re.findall(r"\ba(\d+)\s*:", q)
            if self.mode == "safe" and len(found) > 5:
                return self._send(200, {"errors": [{
                    "message": "query complexity limit: max 5 aliases"}]})
            data = {f"a{i}": "__Typename__" for i in found}
            return self._send(200, {"data": data})
        return self._send(404, {"error": "not found"})


def serve(mode: str, port: int):
    handler = type(f"Handler_{mode}", (_Handler,), {"mode": mode})
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    # the actual bound port, for --port 0; flush matters: the parent reads
    # this line to learn where we landed (r18-8.5)
    print(f"modern2-{mode} listening on 127.0.0.1:{srv.server_address[1]}",
          flush=True)
    srv.serve_forever()


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["vuln", "safe"], required=True)
    ap.add_argument("--port", type=int, default=0)
    a = ap.parse_args()
    serve(a.mode, a.port or _free_port())
