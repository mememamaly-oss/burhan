"""Burhan chainapp — the round-10 PART 2 fixture target (attack-path
chaining RED/BLUE twins).

A self-contained deliberately-vulnerable app, separate from
fixtures/vulnapp.py on purpose: vulnapp's behavior is PINNED by the
committed benchmark ground truth (the deterministic 38/38 record, the
F1=1.0 gate) and must not change; chainapp carries its own surface so the
chain rules get a real target that disturbs nothing.

Surface (identical in both twins):
  GET  /                       HTML index (crawl seed; links the surfaces)
  POST /auth/api/login         JSON login {email,password} -> Bearer token
                               (the AUTH-06 surface the engine's json_login
                               harvest replays)
  GET  /api/account/dashboard  Bearer-protected; parses the token, NEVER
                               verifies the signature (the SIGNOFF class,
                               CWE-347) -> jwt_signature_not_enforced
  POST /api/admin/rotate-keys  executes for ANY authenticated session with
                               NO role check (the BFLA class, CWE-285)

THE TWO TWINS (CHAIN_TWIN env var):

  RED (unset or "red") — the escalation path is REAL: rotate-keys returns
      the freshly-rotated ADMIN token, so finding A's output is literally
      the credential that feeds finding B. The combined proof: login as
      the low-privilege user -> execute the admin function -> take the
      admin token it returns -> corrupt its signature (finding B's own
      mechanism) -> present it to the dashboard -> ACCEPTED AS ADMIN.

  BLUE ("blue") — the same two vulnerability CLASSES fire independently
      but the escalation path is broken at exactly the chain's link:
      rotate-keys still executes for the low-privilege session (BFLA
      fires) and returns NO credential material; the dashboard still
      accepts corrupted signatures (the JWT finding fires). Two highs,
      no shared path — the chain layer must report nothing.
"""
from __future__ import annotations

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TWIN = os.environ.get("CHAIN_TWIN", "red")

ACCOUNTS = {
    "bob@chainapp.test": {"password": "bob-pass-123", "role": "user"},
    "root-admin@chainapp.test": {"password": "admin-pass-123", "role": "admin"},
}

# the "rotated" admin token finding A hands out in the RED twin — a
# token-shaped artifact whose payload carries role=admin
ADMIN_TOKEN_MATERIAL = ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
                        "eyJzdWIiOiJyb290LWFkbWluQGNoYWluYXBwLnRlc3Qi"
                        "LCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NjIyNTkyMDB9."
                        "UkVELXNpZ25FZC1tYXRlcmlhbC1yb3RhdGVkLWJ5LXRo"
                        "ZS1hZG1pbi1mdW5jdGlvbi1ub3QtdmVyaWZpZWQ")

INDEX = """<!doctype html><html><head><title>chainapp</title></head>
<body><h1>chainapp — burhan r10 part-2 fixture</h1>
<p>twin: __TWIN__</p>
<div id="nl-bfla" class="form" data-method="post"
     data-action="/api/admin/rotate-keys">
<input required type="text" name="reason" value="monthly-rotation">
<button type="submit">Rotate keys (admin)</button></div>
<a href="/api/account/dashboard">dashboard</a>
</body></html>"""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def issue_token(email: str) -> str:
    hdr = _b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = {"sub": email, "role": ACCOUNTS[email]["role"]}
    pl = _b64u(json.dumps(claims).encode())
    sig = _b64u(("fixture-signature-" + email.split("@")[0]).encode())
    return f"{hdr}.{pl}.{sig}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _bearer_claims(self):
        auth = self.headers.get("Authorization") or ""
        tok = auth[7:] if auth[:7].lower() == "bearer " else ""
        parts = tok.split(".")
        if len(parts) != 3:
            return None
        try:
            pad = "=" * (-len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        except Exception:
            return None

    def do_GET(self):
        if self.path == "/":
            return self._html(INDEX.replace("__TWIN__", TWIN))
        if self.path == "/api/account/dashboard":
            claims = self._bearer_claims()
            # the SIGNOFF class: claims are READ, the signature is NEVER
            # verified — any token-shaped Bearer with a parseable payload
            # is accepted with whatever role it claims (CWE-347)
            if not claims:
                return self._json(401, {"error": "malformed token"})
            return self._json(200, {
                "account": claims.get("sub", ""),
                "role": claims.get("role", ""),
                "admin_data": claims.get("role") == "admin",
            })
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/auth/api/login":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._json(400, {"error": "bad request"})
            acc = ACCOUNTS.get(str(body.get("email", "")))
            if not acc or body.get("password") != acc["password"]:
                return self._json(401, {"error": "invalid credentials"})
            return self._json(200, {"token": issue_token(str(body.get("email"))),
                                    "role": acc["role"],
                                    "status": "authenticated"})
        if self.path == "/api/admin/rotate-keys":
            claims = self._bearer_claims()
            if not claims:
                return self._json(401, {"error": "authentication required"})
            # the BFLA class: ANY authenticated session executes the
            # admin-only function — no role check anywhere (CWE-285)
            if TWIN == "blue":
                # the broken link: the function executes (BFLA still
                # fires) but returns NO credential material — finding
                # A's output cannot feed finding B
                return self._json(200, {"status": "rotated",
                                        "role_used": claims.get("role", "")})
            # RED: the function's response IS the escalation path —
            # the freshly rotated ADMIN token, handed to the caller
            return self._json(200, {"status": "rotated",
                                    "role_used": claims.get("role", ""),
                                    "admin_token": ADMIN_TOKEN_MATERIAL})
        return self._json(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8790"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
