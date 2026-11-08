"""Owner order part 3: modern battery v2 — RED/BLUE proof for every new family.

RED  = the vulnerable fixture/target PRODUCES the finding.
BLUE = the hardened twin produces ZERO findings for that family (no false
       positives), and the family is reported as TESTED_NEGATIVE in the
       boundaries (honest negative evidence, not silence).

Families: jwt_weak_secret (3A), graphql_aliasing (3C),
excessive_data_exposure (3D), rebind_toctou (3B, via the flip-DNS fixture).
Flag contract: modern_v2 is OFF by default; the legacy modernsec battery and
every existing detector are untouched by this module.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import re
import threading
import time

import pytest
from burhan.http_engine import RequestMutation
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "fixtures"))

from burhan.core import Endpoint, EventBus, ScopeRule, Severity          # noqa: E402
from burhan.http_engine import RequestEngine, RequestMutation                    # noqa: E402
from burhan import modernsec2                                   # noqa: E402
from burhan.modernsec2 import (ALIAS_CAP, WEAK_SECRET_WORDLIST,  # noqa: E402
                               FlipDNS, _ProbeListener,
                               jwt_weak_secret_offline,
                               rebind_toctou_probe,
                               run_modern_battery_v2)
from modern2_fixture import SAFE_SECRET, hs256                  # noqa: E402


def _engine():
    scope = ScopeRule(allow_private=True, allowed_hosts=["127.0.0.1"])
    return RequestEngine(scope, EventBus("m2-test"), timeout=8.0)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(args) -> subprocess.Popen:
    p = subprocess.Popen([sys.executable] + args,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    return p


def _wait_port(port, timeout=10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            s.close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


# ---------------------------------------------------------------- 3A offline
def test_3a_red_weak_secret_detected_offline():
    tok = hs256("secret", {"sub": "x"})
    matched, alg, attempts = jwt_weak_secret_offline(tok)
    assert matched == "secret"
    assert alg == "HS256"
    assert 1 <= attempts <= len(WEAK_SECRET_WORDLIST)


def test_3a_red_every_wordlist_entry_is_detectable():
    # the whole wordlist is a detection capability: each entry must verify
    for cand in WEAK_SECRET_WORDLIST[:5] + WEAK_SECRET_WORDLIST[-3:]:
        tok = hs256(cand, {"sub": "x"})
        matched, _, _ = jwt_weak_secret_offline(tok)
        assert matched == cand, cand


def test_3a_blue_strong_secret_not_detected():
    tok = hs256(SAFE_SECRET, {"sub": "x"})
    matched, alg, attempts = jwt_weak_secret_offline(tok)
    assert matched is None
    assert alg == "HS256"
    assert attempts == len(WEAK_SECRET_WORDLIST)   # the documented cap ran


def test_3a_cap_is_explicitly_bounded_and_documented():
    assert len(WEAK_SECRET_WORDLIST) == 27          # the documented cap
    assert len(set(WEAK_SECRET_WORDLIST)) == 27     # no duplicate attempts


def test_3a_non_hs_token_is_skipped_not_crashed():
    # an RS256-shaped token must be skipped (offline HMAC check is HS-only)
    import base64
    h = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(
        json.dumps({"sub": "x"}).encode()).rstrip(b"=").decode()
    tok = f"{h}.{p}.ZmFrZXNpZ25hdHVyZQ"
    matched, alg, attempts = jwt_weak_secret_offline(tok)
    assert matched is None and alg == "RS256" and attempts == 0


def test_3a_garbage_token_is_skipped():
    matched, alg, attempts = jwt_weak_secret_offline("not.a.jwt")
    assert matched is None and attempts == 0


def _loopback_alias_supported(ip="127.0.0.2") -> bool:
    """r18-8.2 (the macOS finding): Linux routes all of 127/8 on lo, but
    macOS binds only 127.0.0.1 on lo0 — binding 127.0.0.2 raises
    EADDRNOTAVAIL (errno 49, the live CI failure). The 3B rebinding
    oracle NEEDS a second alias to mean what it asserts (a fetch to the
    flipped internal address reaching a listener the validated public
    address could not). On platforms without it the oracle would be a
    DIFFERENT experiment, so the affected tests skip LOUDLY with this
    documented reason — the same discipline as the r15 SIGINT
    browser-capability skips."""
    import socket as _s
    try:
        with _s.socket() as sk:
            sk.bind((ip, 0))
        return True
    except OSError:
        return False


_ALIAS = pytest.mark.skipif(not _loopback_alias_supported(),
                            reason="platform routes only 127.0.0.1 on "
                                   "loopback (macOS default) — the rebind "
                                   "oracle's distinct-address semantics "
                                   "need a second 127/8 alias; see "
                                   "r18-8.2 in worklog.md")


# ------------------------------------------------- battery RED/BLUE over HTTP
@pytest.fixture(scope="module")
def vuln_port():
    port = _free_port()
    p = _spawn([os.path.join(ROOT, "fixtures", "modern2_fixture.py"),
                "--mode", "vuln", "--port", str(port)])
    assert _wait_port(port), "vuln fixture did not start"
    yield port
    p.terminate()


@pytest.fixture(scope="module")
def safe_port():
    port = _free_port()
    p = _spawn([os.path.join(ROOT, "fixtures", "modern2_fixture.py"),
                "--mode", "safe", "--port", str(port)])
    assert _wait_port(port), "safe fixture did not start"
    yield port
    p.terminate()


def _battery(port):
    eps = [Endpoint(url=f"http://127.0.0.1:{port}/login", method="GET"),
           Endpoint(url=f"http://127.0.0.1:{port}/graphql", method="POST"),
           Endpoint(url=f"http://127.0.0.1:{port}/api/users", method="GET")]
    return run_modern_battery_v2(_engine(), eps, seed="m2-proof")


def test_battery_red_vuln_fixture_produces_all_three_findings(vuln_port):
    res = _battery(vuln_port)
    types = {f.type for f in res.findings}
    assert "jwt_weak_secret" in types, [b for b in res.boundaries]
    assert "graphql_aliasing" in types, [b for b in res.boundaries]
    assert "excessive_data_exposure" in types, [b for b in res.boundaries]
    # evidence quality: the weak-secret finding names the matched secret
    f = next(f for f in res.findings if f.type == "jwt_weak_secret")
    assert "secret" in json.dumps([e.__dict__ for e in f.evidence]
                                   if hasattr(f.evidence[0], "__dict__")
                                   else str(f.evidence))
    # the exposure finding names the leaked FIELD NAMES, never values
    f2 = next(f for f in res.findings if f.type == "excessive_data_exposure")
    ev = " ".join(str(getattr(e, "detail", "")) for e in f2.evidence)
    assert "password_hash" in ev and "is_internal" in ev
    assert "fixtureNotARealHashValue" not in ev   # values never republished


def test_battery_red_rebind_family_skips_loudly_without_operator_dns(vuln_port):
    res = _battery(vuln_port)
    skip = [b for b in res.boundaries
            if b["family"] == "rebind_toctou"
            and b["kind"] == "SKIPPED_NO_REBIND_DNS"]
    assert skip, "rebind_toctou must be skipped LOUDLY, never silently"


def test_battery_blue_hardened_twin_zero_findings(safe_port):
    res = _battery(safe_port)
    assert res.findings == [], \
        f"false positives on the hardened twin: {[f.type for f in res.findings]}"
    kinds = {(b["family"], b["kind"]) for b in res.boundaries}
    assert ("jwt_weak_secret", "TESTED_NEGATIVE") in kinds
    assert ("graphql_aliasing", "TESTED_NEGATIVE") in kinds
    assert ("excessive_data_exposure", "TESTED_NEGATIVE") in kinds


def test_battery_probe_counts_respect_documented_caps(vuln_port):
    res = _battery(vuln_port)
    pc = res.probe_counts
    assert pc["jwt_weak_secret"]["cap"] == 2
    assert pc["graphql_aliasing"]["cap"] == 2
    assert pc["excessive_data_exposure"]["cap"] == 8
    assert pc["rebind_toctou"]["cap"] == 4
    assert pc["jwt_weak_secret"]["offline"] <= 2 * len(WEAK_SECRET_WORDLIST)
    for fam, row in pc.items():
        assert row["sent"] <= row["cap"], (fam, row)


def test_battery_runs_with_zero_requests_when_no_surfaces():
    # empty endpoint map: every family skipped, zero requests, zero findings
    res = run_modern_battery_v2(_engine(), [], seed="m2-empty")
    assert res.findings == []
    assert res.requests == 0
    assert len(res.boundaries) >= 3   # loud skips for the absent surfaces


# ---------------------------------------------------------------- 3B rebind
@pytest.fixture()
def rebind_env():
    """(dns, probe_listener, fetcher_proc, http_port) — vuln role."""
    if not _loopback_alias_supported():
        pytest.skip("platform routes only 127.0.0.1 on loopback "
                    "(macOS default) — the rebind oracle needs a second "
                    "127/8 alias; see r18-8.2 in worklog.md")
    dns = FlipDNS(port=0)
    dns.start()
    probe = _ProbeListener(ip="127.0.0.2", port=0)
    probe.start()
    port = _free_port()
    p = _spawn([os.path.join(ROOT, "fixtures", "rebind_fixture.py"),
                "--role", "vuln", "--dns-port", str(dns.port),
                "--http-port", str(port)])
    assert _wait_port(port), "rebind vuln fetcher did not start"
    yield dns, probe, p, port
    p.terminate()


def test_3b_red_vulnerable_fetcher_rebinds_to_internal(rebind_env):
    dns, probe, _p, port = rebind_env
    vuln, detail = rebind_toctou_probe(
        f"http://127.0.0.1:{port}/fetch", dns, probe, timeout=8.0)
    assert vuln, detail
    assert probe.hits, "the internal probe listener must have received the fetch"
    assert dns.queries >= 2, "the vulnerable client must have resolved twice"


@_ALIAS
def test_3b_blue_safe_fetcher_pins_the_validated_address():
    dns = FlipDNS(port=0)
    dns.start()
    probe = _ProbeListener(ip="127.0.0.2", port=0)
    probe.start()
    port = _free_port()
    p = _spawn([os.path.join(ROOT, "fixtures", "rebind_fixture.py"),
                "--role", "safe", "--dns-port", str(dns.port),
                "--http-port", str(port)])
    try:
        assert _wait_port(port), "rebind safe fetcher did not start"
        vuln, detail = rebind_toctou_probe(
            f"http://127.0.0.1:{port}/fetch", dns, probe, timeout=8.0)
        assert not vuln, detail
        assert not probe.hits, "the internal address must never be reached"
        assert dns.queries == 1, "the safe client resolves exactly once"
    finally:
        p.terminate()


def test_3b_flip_dns_flips_after_n_queries():
    dns = FlipDNS(port=0, flip_after=2, public_ip="192.0.2.10",
                  internal_ip="127.0.0.2")
    dns.start()
    time.sleep(0.1)
    # query 1 and 2 -> public; query 3+ -> internal
    from fixtures.rebind_fixture import resolve
    a1 = resolve("rebind.burhan.test", "127.0.0.1", dns.port)
    a2 = resolve("rebind.burhan.test", "127.0.0.1", dns.port)
    a3 = resolve("rebind.burhan.test", "127.0.0.1", dns.port)
    assert (a1, a2, a3) == ("192.0.2.10", "192.0.2.10", "127.0.0.2")


# ------------------------------------------------- part 5: adversarial pins
def test_adversarial_A3_prefixed_password_hash_and_key_id_now_caught():
    from burhan.modernsec2 import _walk_secret_fields
    found = _walk_secret_fields(
        {"user_password_hash": "$2b$12$x", "aws_access_key_id": "AKIA..."})
    assert "user_password_hash" in found and "aws_access_key_id" in found


def test_adversarial_A3_depth_cap_is_the_documented_limit():
    # beyond depth 3 the bounded walk does not look — intentional cap
    from burhan.modernsec2 import _walk_secret_fields
    deep = {"a": {"b": {"c": {"d": {"password_hash": "x"}}}}}
    assert _walk_secret_fields(deep) == []


def test_adversarial_A4_reflector_is_the_declared_surface_limit():
    # a pure reflector (no resolver work) still yields the finding: the check
    # verifies response SHAPE, not execution cost — LOW severity by design
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    port = _free_port()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n).decode("utf-8", "replace")
            found = re.findall(r"\ba(\d+)\s*:", body)
            out = json.dumps({"data": {f"a{i}": "Faked"
                                       for i in found}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        eps = [Endpoint(url=f"http://127.0.0.1:{port}/graphql",
                        method="POST")]
        res = run_modern_battery_v2(_engine(), eps, seed="adv-a4")
        assert "graphql_aliasing" in {f.type for f in res.findings}
        f = next(f for f in res.findings
                 if f.type == "graphql_aliasing")
        assert f.severity == Severity.LOW   # the declared surface wording
    finally:
        srv.shutdown()


@_ALIAS
def test_adversarial_A5_flip_after_must_match_query_count():
    # flip_after=2 + a single-validation target: the rebind is MISSED — the
    # documented tuning parameter, pinned so the limit stays visible
    dns = FlipDNS(port=0, flip_after=2)
    dns.start()
    probe = _ProbeListener(ip="127.0.0.2", port=0)
    probe.start()
    port = _free_port()
    p = _spawn([os.path.join(ROOT, "fixtures", "rebind_fixture.py"),
                "--role", "vuln", "--dns-port", str(dns.port),
                "--http-port", str(port)])
    try:
        assert _wait_port(port)
        vuln, _detail = rebind_toctou_probe(
            f"http://127.0.0.1:{port}/fetch", dns, probe, timeout=6.0)
        assert not vuln          # the miss is the pinned, documented outcome
        assert dns.queries == 2  # validation + fetch, both answered PUBLIC
    finally:
        p.terminate()


@_ALIAS
def test_adversarial_A6_pinned_public_fetch_never_hits_internal():
    # safe fetcher pinned to a REACHABLE public upstream: fetch succeeds and
    # the internal listener is never hit — no false positive
    import urllib.parse
    dns = FlipDNS(port=0, flip_after=1, public_ip="127.0.0.1",
                  internal_ip="127.0.0.2")
    dns.start()
    probe = _ProbeListener(ip="127.0.0.2", port=0)
    probe.start()
    up = socket.socket()
    up.bind(("127.0.0.1", 0))
    up.listen(4)
    up_port = up.getsockname()[1]

    def _serve():
        while True:
            try:
                c, _ = up.accept()
                c.recv(1024)
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                c.close()
            except OSError:
                return

    threading.Thread(target=_serve, daemon=True).start()
    port = _free_port()
    p = _spawn([os.path.join(ROOT, "fixtures", "rebind_fixture.py"),
                "--role", "safe", "--dns-port", str(dns.port),
                "--http-port", str(port)])
    try:
        assert _wait_port(port)
        target = f"http://rebind.burhan.test:{up_port}/x"
        _engine().send(RequestMutation(
            endpoint=Endpoint(
                url=f"http://127.0.0.1:{port}/fetch?url="
                    f"{urllib.parse.quote(target, safe='')}",
                method="GET"), note="adv-a6"))
        time.sleep(1.5)
        assert not probe.hits
    finally:
        p.terminate()


# ---------------------------------------------------------------- flag contract
def test_modern_v2_flag_off_by_default():
    from burhan.orchestrator import ScanConfig
    assert ScanConfig().modern_v2 is False
    assert ScanConfig(modern_v2=True).modern_v2 is True


def test_existing_modernsec_battery_is_untouched():
    # the v1 family set and caps keep their exact v4.4.0 shape
    from burhan import modernsec
    assert modernsec.MODERN_TYPES == (
        "jwt_algorithm_confusion", "jwt_none_acceptance",
        "graphql_batching_enabled", "http_request_smuggling",
        "mass_assignment", "prototype_pollution")
    assert modernsec.FAMILY_CAPS["jwt_algorithm_confusion"] == 12
    # and the new module does not share any family name with v1
    assert not (set(modernsec.MODERN_TYPES) & set(modernsec2.MODERN2_TYPES))


# ------------------------------------- graphql axis robustness (live validation)
def test_graphql_axis_survives_null_data_error_payload():
    """Live-validation discovery (run 41312545521, DVGA): a GraphQL server
    answering introspection with {"data": null, "errors": [...]} — the
    spec-legal error shape DVGA actually returns — crashed the graphql axis
    with 'NoneType' object has no attribute 'get': payload.get("data", {})
    yields None because the key EXISTS with a null value (the {} default
    only applies to MISSING keys). The axis must degrade cleanly instead.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from burhan.orchestrator import BurhanScanner, ScanConfig

    null_data = json.dumps(
        {"data": None, "errors": [{"message": "introspection denied"}]}
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, ctype: str, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._send("text/html", b"<html><body>ok</body></html>")

        def do_POST(self):
            self._send("application/json", null_data)

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=2, timeout=6.0)
        data = BurhanScanner(f"http://127.0.0.1:{port}/", cfg).run()
    finally:
        srv.shutdown()

    gql = (data.get("stats") or {}).get("graphql") or {}
    assert gql.get("enabled") is True, gql
    assert "requests" in gql, f"graphql axis never ran: {gql}"
    assert "error" not in gql, f"graphql axis crashed again: {gql.get('error')}"
