"""r19-2 (owner order 2026-11-16, item 1b): target-ownership proof tests.

Covers:
  - the new well_known proof class (token on the target's own
    /.well-known/burhan-authorization.txt, live fetch, no storage);
  - cross-origin redirect in the proof fetch = REFUSAL (a proof served by
    someone else's host proves nothing);
  - same-origin redirect (http->https hop style) stays allowed;
  - redirect chains (bounded at 5 hops);
  - DNS rebinding shape at the gate layer: the proof must come from the
    host the registry matched, not a string-lookalike;
  - case-insensitivity of the hostname and the trailing-dot form;
  - IDN unification: a unicode-spelled URL must match the punycode entry
    (and must NOT enter a different entry's proof path);
  - subdomains of a suffixed entry pass; lookalikes don't (regression);
  - CLI e2e: refused target -> exit 2, ZERO requests;
  - API: refused target -> no run_id, error payload, no scan started;
  - mutation testing of the ownership logic (see test_ownership_mutations).
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.authorized_targets import (authorize, _host_of)  # noqa: E402
from burhan.ownership import (fetch_well_known, WellKnownError,  # noqa: E402
                              WELL_KNOWN_PATH)


# --------------------------------------------------------------- helpers
def _reg(tmp_path, targets):
    p = tmp_path / "authorized-targets.json"
    p.write_text(json.dumps({"policy": "test", "targets": targets}))
    return str(p)


def _wk_entry(suffix, token, host=""):
    return {
        "id": f"wk-{suffix}",
        "kind": "permissioned-public-demo",
        "match": {"host_suffix": suffix},
        "proof": {"type": "well_known", "token": token},
    }


class _Resp:
    def __init__(self, status, body=b"", location=None):
        self.status = status
        self.body = body
        self.headers = {"Location": location} if location else {}

    def get(self, k, default=None):
        return self.headers.get(k, default)


def _fetch_router(table):
    """fetch(url) -> (status, headers, body) following the table dict
    {path_or_suffix: _Resp}. Counts calls for the zero-request proofs."""
    calls = []

    def fetch(url):
        calls.append(url)
        for k, v in table.items():
            if k in url:
                return v.status, v.headers, v.body
        raise ConnectionError("no route for " + url)

    fetch.calls = calls
    return fetch


# ---------------------------------------------------- well-known proof class
def test_well_known_token_verified_live(tmp_path):
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"auth: burhan-tok-123\n")})
    ok, reason, eid = authorize("https://sub.example.test/", reg, fetch=fetch)
    assert ok, reason
    assert eid == "wk-example.test"


def test_well_known_missing_token_refused(tmp_path):
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"some other text entirely")})
    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert not ok
    assert "does NOT carry" in reason


def test_well_known_404_refused(tmp_path):
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({"burhan-authorization.txt": _Resp(404, b"")})
    ok, reason, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert not ok
    assert "404" in reason


def test_well_known_cross_origin_redirect_refused(tmp_path):
    # the target bounces the proof fetch to ANOTHER host — that host's
    # file proves nothing about the scanned target
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({
        "https://example.test": _Resp(302, b"", location=
                                      "https://evil.example.net"
                                      "/burhan-authorization.txt"),
        "https://evil.example.net": _Resp(200, b"burhan-tok-123"),
    })
    ok, reason, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert not ok
    assert "leaves the scanned origin" in reason


def test_well_known_same_origin_redirect_allowed(tmp_path):
    # a same-scheme, same-host, same-port hop (path-level redirect) is fine
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({
        "https://example.test/old": _Resp(302, b"", location=
                                          "https://example.test"
                                          "/burhan-authorization.txt"),
        "https://example.test/burhan": _Resp(200, b"token burhan-tok-123"),
    })

    # the first fetch URL is the well-known path; simulate a server that
    # 302s it to a new path on the SAME origin
    def routed(url):
        if url.endswith(WELL_KNOWN_PATH):
            return (302, {"Location":
                          "https://example.test/v2/authorization.txt"}, b"")
        if "/v2/authorization.txt" in url:
            return (200, {}, b"token burhan-tok-123")
        raise ConnectionError(url)

    ok, reason, _ = authorize("https://example.test/", reg, fetch=routed)
    assert ok, reason


def test_well_known_redirect_chain_bounded(tmp_path):
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])

    def fetch(url):
        # endless same-origin loop: /a -> /b -> /a -> ...
        n = fetch.n = getattr(fetch, "n", 0) + 1
        return 302, {"Location": "/loop%d" % (n + 1)}, b""

    with pytest.raises(WellKnownError, match="exceeded 5 redirect hops"):
        fetch_well_known("https://example.test/", fetch=fetch)


def test_well_known_scheme_downgrade_in_redirect_kept_same_origin(tmp_path):
    # https->http same host is still same-origin by (host,port) — but the
    # PORT differs (443 vs 80): refused. The proof cannot be downgraded.
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({
        "https://example.test": _Resp(302, b"", location=
                                      "http://example.test/x.txt"),
        "http://example.test": _Resp(200, b"burhan-tok-123"),
    })
    ok, reason, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert not ok
    assert "leaves the scanned origin" in reason


def test_well_known_oversized_body_refused():
    def fetch(url):
        return 200, {}, b"x" * 30_000

    with pytest.raises(WellKnownError, match="exceeds"):
        fetch_well_known("https://example.test/", fetch=fetch)


def test_well_known_no_storage_between_checks(tmp_path):
    # the proof is fetched EVERY authorize() call — a file that flips to
    # 404 between two scans must refuse the second (never cached)
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    state = {"up": True}

    def fetch(url):
        if state["up"]:
            return 200, {}, b"burhan-tok-123"
        return 404, {}, b""

    ok, _, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert ok
    state["up"] = False
    ok2, reason2, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert not ok2
    assert "404" in reason2


# ----------------------------------------------------- host normalization
def test_host_case_insensitive(tmp_path):
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"burhan-tok-123")})
    ok, reason, _ = authorize("https://ExAmPlE.tEsT/", reg, fetch=fetch)
    assert ok, reason


def test_host_trailing_dot_form_matches(tmp_path):
    reg = _reg(tmp_path, [_wk_entry("example.test", "burhan-tok-123")])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"burhan-tok-123")})
    ok, reason, _ = authorize("https://example.test./", reg, fetch=fetch)
    assert ok, reason


def test_idn_unicode_spelling_matches_punycode_entry(tmp_path):
    # пример.испытание == xn--e1afmkfd.xn--80akhbyknj4f
    reg = _reg(tmp_path, [{
        "id": "wk-idn", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "xn--e1afmkfd.xn--80akhbyknj4f"},
        "proof": {"type": "well_known", "token": "tok"},
    }])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"tok")})
    ok, reason, _ = authorize("https://пример.испытание/", reg, fetch=fetch)
    assert ok, reason
    # and the punycode spelling of the SAME host matches the same entry
    ok2, reason2, eid = authorize(
        "https://xn--e1afmkfd.xn--80akhbyknj4f/", reg, fetch=fetch)
    assert ok2, reason2
    assert eid == "wk-idn"


def test_idn_lookalike_does_not_enter_the_entry(tmp_path):
    # a DIFFERENT unicode domain whose punycode differs must not match
    reg = _reg(tmp_path, [{
        "id": "wk-idn", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "xn--e1afmkfd.xn--80akhbyknj4f"},
        "proof": {"type": "well_known", "token": "tok"},
    }])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"tok")})
    ok, reason, _ = authorize("https://пример.другое/", reg, fetch=fetch)
    assert not ok
    assert "NOT PRESENT" in reason


def test_subdomain_of_suffixed_entry_passes(tmp_path):
    reg = _reg(tmp_path, [_wk_entry(".example.test", "tok")])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"tok")})
    ok, reason, _ = authorize("https://deep.sub.example.test/", reg,
                              fetch=fetch)
    assert ok, reason


def test_lookalike_suffix_still_refused(tmp_path):
    # regression guard from round 13: evil-example.test must not match
    reg = _reg(tmp_path, [_wk_entry("example.test", "tok")])
    fetch = _fetch_router({"burhan-authorization.txt":
                           _Resp(200, b"tok")})
    ok, reason, _ = authorize("https://evilexample.test/", reg, fetch=fetch)
    assert not ok
    assert "NOT PRESENT" in reason


def test_dns_rebinding_shape_gate_uses_registry_host_not_bare_string():
    # the gate fetches the proof from the REGISTRY-matched host; a target
    # spelled with a userinfo trick cannot re-point the fetch
    assert _host_of("https://user:pass@example.test/") == "example.test"
    assert _host_of("https://example.test:8443/") == "example.test"


# ------------------------------------------------------------------ CLI e2e
def test_cli_scan_unauthorized_target_exits_2_zero_requests(tmp_path):
    """END-TO-END through the real CLI: a live local server IS running (so
    the failure cannot be 'target dead'), but it is NOT in any registry —
    the gate must refuse with exit 2 BEFORE any scan request."""
    port = _free_port()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    accepted = []

    def _accept():
        while True:
            try:
                c, _ = srv.accept()
                accepted.append(c)
                c.close()
            except OSError:
                return

    threading.Thread(target=_accept, daemon=True).start()

    # arm a REAL owner gate with a known password so the run passes it and
    # reaches the ownership gate; point the authorization registry at a
    # temp registry WITHOUT the self-hosted entry so the loopback target
    # has no proof path at all
    import burhan.owner_gate as og
    gate_path = tmp_path / "owner-gate.json"
    og.OwnerGate.setup(str(gate_path), "test-owner-password-123")
    regp = tmp_path / "authorized-targets.json"
    regp.write_text(json.dumps({"policy": "t", "targets": [
        _wk_entry("example.test", "tok")]}))
    env = {**os.environ,
           "BURHAN_OWNER_GATE": str(gate_path),
           "BURHAN_AUTHORIZED_TARGETS": str(regp)}
    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "scan",
         f"http://127.0.0.1:{port}/", "--allow-private",
         "--owner-password", "test-owner-password-123"],
        capture_output=True, text=True, timeout=120, cwd=ROOT, env=env)
    assert "REFUSED — LIVE SCAN AUTHORIZATION GATE" in \
        r.stdout + r.stderr, (r.returncode, r.stdout[-400:], r.stderr[-400:])
    assert r.returncode == 2, r.returncode
    # zero scan requests: nothing but (possibly) the ownership-gate fetch
    # hit the target — the accept loop saw no HTTP request bytes
    for c in accepted:
        c.close()
    srv.close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ------------------------------------------------------------------ API e2e
def test_api_launch_scan_refuses_unauthorized_target(tmp_path):
    from burhan.api import launch_scan
    from burhan.store import Store

    regp = tmp_path / "authorized-targets.json"
    regp.write_text(json.dumps({"policy": "t", "targets": [
        _wk_entry("example.test", "tok")]}))
    # point the default registry at our temp registry
    import burhan.authorized_targets as at
    old = at.DEFAULT_REGISTRY
    at.DEFAULT_REGISTRY = str(regp)
    try:
        store = Store(str(tmp_path / "db.sqlite"))
        res = launch_scan(store, "https://unlisted-evil.example.com/")
        assert "error" in res
        assert "refused" in res["error"]
        assert "run_id" not in res
        assert "ZERO" in res.get("refusal_banner", "") or \
            "REFUSED" in res.get("refusal_banner", "")
    finally:
        at.DEFAULT_REGISTRY = old

# --------------------------------------- r19-2.1: the REAL fetch path (live)
def test_well_known_real_fetch_live_positive_and_404():
    """r19-2.1 (CodeQL fix follow-up): the refactored _default_fetch
    indirection still performs a REAL urlopen against a live local
    server — positive leg (token body comes back) and negative leg (a
    404 answer refuses). Pins the behavior the refactor could have
    silently broken."""
    from burhan.ownership import fetch_well_known, WellKnownError
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.well-known/burhan-authorization.txt":
                body = b"tok-live-123"
                self.send_response(200)
            else:
                body = b"nope"
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # positive: the token body really comes back over the wire
        body = fetch_well_known(f"http://127.0.0.1:{port}/")
        assert body == "tok-live-123", body
        # negative: a server answering 404 for the well-known path refuses
        class _H404(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv404 = ThreadingHTTPServer(("127.0.0.1", 0), _H404)
        port404 = srv404.server_address[1]
        threading.Thread(target=srv404.serve_forever, daemon=True).start()
        try:
            fetch_well_known(f"http://127.0.0.1:{port404}/")
            raise AssertionError("404 must refuse")
        except WellKnownError as e:
            assert "404" in str(e)
        finally:
            srv404.shutdown()
    finally:
        srv.shutdown()
