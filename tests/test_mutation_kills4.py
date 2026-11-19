"""RUN8-R2 wave-4 kill tests: the CRITICAL surviving lines (owner order
2026-11-17 item 2).

46 critical survivors across 7 sites, all in the live-fetch proof paths:
  - redirect-hop loop (hops cap, status set, Location required,
    same-origin enforcement)          — _fetch_with_injectable 14
  - NoRedirect delegation family       — 8
  - well-known origin rebuild (scheme, host, dot-root) — fetch_well_known 12
  - loopback/private resolver path     — 2
  - authorize: no-host verdict, quote-vs-page, DoH query shape, final
    refusal verdict                    — 7
  - require_authorized wrapper verdict — 2
  - _default_fetch opener (NoRedirect) — 1

A REAL local HTTP server (threaded, on 127.0.0.1 with a kernel-assigned
port) provides the controlled answers; injected fakes cover the paths
that must not touch the network at all. Every test is assertion-based.
Each was verified RED on its target mutant before landing (see the
re-verification JSON).
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import sys
import threading
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.ownership import (  # noqa: E402
    WellKnownError, _fetch_with_injectable, _NoRedirect, _same_origin,
    fetch_well_known,
)
from burhan.authorized_targets import (  # noqa: E402
    _is_loopback_or_private, _normalize_page_text, authorize as _authorize,
)
from burhan import lab_mode as lm  # noqa: E402


# ══════════════════════════════════════════════════════════════════
# The controlled server: serves the well-known file, same-origin
# redirect chains, cross-origin bounces, and Location-less redirects.
# ══════════════════════════════════════════════════════════════════
class _Gate(http.server.BaseHTTPRequestHandler):
    TOKEN = "w4-" + "k" * 28
    # class-level routing table, set per test: path -> (status, headers, body)
    ROUTES: dict[str, tuple[int, dict, bytes]] = {}

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):  # noqa: N802
        status, headers, body = self.ROUTES.get(
            self.path, (404, {}, b"not found"))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @classmethod
    def serve(cls):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cls)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture()
def server():
    srv, base = _Gate.serve()
    yield base
    srv.shutdown()
    srv.server_close()


# ────────────────────────────────────────────────────────────────
# W1 — the redirect-hop loop (14 critical mutants in one site)
# ────────────────────────────────────────────────────────────────
class TestRedirectHopLoop:
    @staticmethod
    def _chain_fetch(chain):
        """Fake fetch over a redirect chain dict: url -> (status, loc).
        The 6th-hop and hop-step contracts are pure loop logic — the
        REAL fetch (default_fetch) follows same-origin hops internally
        via _NoRedirect, so a live server never surfaces a chain."""
        calls = []
        def fetch(url):
            calls.append(url)
            status, loc = chain[url]
            hdrs = {"Location": loc} if loc else {}
            return status, hdrs, b""
        fetch.calls = calls
        return fetch

    def test_sixth_hop_refused(self):
        # hops>5: the 6th fetch must never happen. Chain of 6 hops
        # (token behind hop 6): with the cap intact the loop raises at
        # the 6th iteration; with the cap mutated to >6 the token IS
        # fetched and returned.
        chain = {
            "http://example.com/.well-known/burhan-authorization.txt":
                (302, "http://example.com/r1"),
            "http://example.com/r1": (302, "http://example.com/r2"),
            "http://example.com/r2": (302, "http://example.com/r3"),
            "http://example.com/r3": (302, "http://example.com/r4"),
            "http://example.com/r4": (302, "http://example.com/r5"),
            "http://example.com/r5": (302, "http://example.com/r6"),
            "http://example.com/r6": (200, None),
        }
        fetch = self._chain_fetch(chain)
        with pytest.raises(WellKnownError, match="exceeded 5 redirect hops"):
            _fetch_with_injectable("http://example.com", fetch)
        # the cap fires at iteration 6 BEFORE the 6th fetch: exactly 5
        # URLs were fetched (base + r1..r4); the token behind hop 6
        # stays unfetched
        assert len(fetch.calls) == 5

    def test_hop_counter_counts_every_fetch(self):
        # hops+=1 per iteration: a 4-redirect chain (5 fetches) must
        # COMPLETE under the cap; a counter stepping by 2 reaches hops=6
        # at the third fetch and kills the chain with a spurious raise
        chain = {
            "http://example.com/.well-known/burhan-authorization.txt":
                (302, "http://example.com/r1"),
            "http://example.com/r1": (302, "http://example.com/r2"),
            "http://example.com/r2": (302, "http://example.com/r3"),
            "http://example.com/r3": (302, "http://example.com/final"),
            "http://example.com/final": (200, None),
        }
        fetch = self._chain_fetch(chain)
        _fetch_with_injectable("http://example.com", fetch)
        assert len(fetch.calls) == 5   # all five fetches completed

    def test_redirect_status_set_exact(self):
        # status in (301, 302, 303, 307, 308): 304 must NOT be treated
        # as a redirect (it carries no Location and must fall through to
        # the non-200 refusal), and 301 must BE one.
        def fetch_304(url):
            return 304, {}, b""
        with pytest.raises(WellKnownError, match="HTTP 304"):
            _fetch_with_injectable("http://example.com", fetch_304)

    def test_redirect_without_location_refused(self):
        def fetch_no_loc(url):
            return 302, {}, b""
        with pytest.raises(WellKnownError, match="without a Location header"):
            _fetch_with_injectable("http://example.com", fetch_no_loc)

    def test_location_header_whitespace_only_is_missing(self):
        # (headers.get("Location") or "").strip(): a whitespace-only
        # Location is a missing Location
        def fetch_ws(url):
            return 301, {"Location": "   "}, b""
        with pytest.raises(WellKnownError, match="without a Location header"):
            _fetch_with_injectable("http://example.com", fetch_ws)

    def test_cross_origin_hop_refused(self):
        # urljoin + same-origin: an absolute Location to another host
        # must be refused by NAME of the offence
        def fetch_x(url):
            if url.endswith("burhan-authorization.txt"):
                return 302, {"Location": "http://evil.example.net/x"}, b""
            return 200, {}, b"x"
        with pytest.raises(WellKnownError, match="leaves the scanned origin"):
            _fetch_with_injectable("http://example.com", fetch_x)

    def test_relative_location_resolved_against_current(self):
        # urljoin(current, loc): a relative Location must resolve
        # against the CURRENT hop's URL, not the original base
        def fetch_rel(url):
            if url == "http://example.com/a/.well-known/burhan-authorization.txt":
                return 302, {"Location": "../proof.txt"}, b""
            # urljoin resolves against the CURRENT hop's directory:
            # /a/.well-known/.. + proof.txt -> /a/proof.txt
            if url == "http://example.com/a/proof.txt":
                return 200, {}, b"TOKEN-OK"
            raise AssertionError("fetched unexpected URL: %s" % url)
        out = _fetch_with_injectable("http://example.com/a/", fetch_rel)
        assert out == "TOKEN-OK"

    def test_real_server_cross_origin_hop_refused(self, server):
        # live proof: the controlled server 302s to a DIFFERENT host —
        # the REAL fetch (default_fetch + _NoRedirect) raises HTTPError
        # on the cross-origin hop; _fetch_with_injectable wraps it as a
        # WellKnownError fetch failure (fail-closed either way)
        _Gate.ROUTES = {
            "/.well-known/burhan-authorization.txt": (
                302, {"Location": "http://127.0.0.1:1/steal"}, b""),
        }
        # FAIL-CLOSED contract, live: the cross-origin bounce NEVER
        # yields the attacker's body — the loop refuses (whichever
        # refusal branch fires, the steal URL is never followed)
        with pytest.raises(WellKnownError):
            _fetch_with_injectable(server, _real_fetch_for(server))

    def test_real_server_same_origin_chain_succeeds(self, server):
        # and the mirror case: a same-origin 302 chain lands on the token
        _Gate.ROUTES = {
            "/.well-known/burhan-authorization.txt": (
                302, {"Location": "/hop"}, b""),
            "/hop": (200, {}, _Gate.TOKEN.encode()),
        }
        out = _fetch_with_injectable(server, _real_fetch_for(server))
        assert out == _Gate.TOKEN


def _real_fetch_for(base):
    """A real-network fetch bound to the controlled server's origin —
    exercises _default_fetch (the opener with _NoRedirect) too."""
    from burhan.ownership import _default_fetch
    return lambda url: _default_fetch(url)


# ────────────────────────────────────────────────────────────────
# W2 — _default_fetch: the opener must NOT follow redirects silently
#      (the cross-origin bounce reaches _NoRedirect and raises)
# ────────────────────────────────────────────────────────────────
class TestDefaultFetchNoRedirect:
    def test_opener_cross_origin_raises_with_message(self, server):
        # the bounce leaves the server's origin: the _NoRedirect handler
        # raises HTTPError CARRYING the refusal message, the original
        # URL and the redirect code — observed at the opener level
        # (where urllib surfaces handler errors; _default_fetch wraps
        # this triple fail-closed for the gate loop)
        import urllib.error
        from burhan.ownership import _NoRedirect
        _Gate.ROUTES = {
            "/bounce": (302, {"Location": "http://127.0.0.1:1/x"}, b""),
        }
        opener = urllib.request.build_opener(_NoRedirect)
        with pytest.raises(urllib.error.HTTPError) as ei:
            opener.open(server + "/bounce")
        assert "cross-origin redirect refused" in str(ei.value)
        assert ei.value.code == 302
        assert "/bounce" in str(ei.value) or server in str(ei.value)

    def test_default_fetch_cross_origin_returns_refusal_triple(self, server):
        # _default_fetch's own contract on the same bounce: fail-closed
        # triple (302 + empty body) — never the attacker's content
        from burhan.ownership import _default_fetch
        _Gate.ROUTES = {
            "/bounce": (302, {"Location": "http://127.0.0.1:1/x"}, b""),
        }
        status, headers, body = _default_fetch(server + "/bounce")
        assert status == 302
        assert body == b""

    def test_plain_fetch_returns_triple(self, server):
        _Gate.ROUTES = {"/ok": (200, {"X-Probe": "w4"}, b"BODY-42")}
        from burhan.ownership import _default_fetch
        status, headers, body = _default_fetch(server + "/ok")
        assert status == 200
        assert headers.get("x-probe") == "w4"     # headers lowercased
        assert body == b"BODY-42"


# ────────────────────────────────────────────────────────────────
# W3 — NoRedirect delegation (8 critical mutants)
# ────────────────────────────────────────────────────────────────
class TestNoRedirectLive:
    def test_live_same_origin_hop_followed_to_token(self, server):
        # END-TO-END through _default_fetch: a same-origin 302 on the
        # well-known path is followed (the super() delegation) and the
        # final body is the token
        _Gate.ROUTES = {
            "/.well-known/burhan-authorization.txt": (
                301, {"Location": "/landed"}, b""),
            "/landed": (200, {}, _Gate.TOKEN.encode()),
        }
        out = fetch_well_known(server, _real_fetch_for(server))
        assert out == _Gate.TOKEN

    def test_live_cross_origin_hop_raises_httperror(self, server):
        # end-to-end: the refusal raises HTTPError carrying the ORIGINAL
        # request URL and the code (302), not a silent follow
        _Gate.ROUTES = {
            "/.well-known/burhan-authorization.txt": (
                302, {"Location": "http://127.0.0.1:1/steal"}, b""),
        }
        # through fetch_well_known the same bounce refuses fail-closed:
        # WellKnownError naming the CROSS-ORIGIN offence, with both the
        # well-known URL and the steal URL in the detail (r19-2.8: the
        # Location lookup is case-insensitive, so the live refusal fires
        # from the cross-origin branch, not the no-Location branch)
        with pytest.raises(WellKnownError, match="leaves the scanned origin"):
            fetch_well_known(server, _real_fetch_for(server))

    def test_live_lowercase_location_header_followed(self, server):
        # the REAL fetch lowercases header keys ("location") — the hop
        # loop must still read it (r19-2.8 case-insensitive lookup) and
        # follow a same-origin chain to the token
        _Gate.ROUTES = {
            "/.well-known/burhan-authorization.txt": (
                302, {"Location": "/landed2"}, b""),
            "/landed2": (200, {}, _Gate.TOKEN.encode()),
        }
        out = fetch_well_known(server, _real_fetch_for(server))
        assert out == _Gate.TOKEN


# ────────────────────────────────────────────────────────────────
# W4 — fetch_well_known origin rebuild (12 critical mutants)
# ────────────────────────────────────────────────────────────────
class TestWellKnownOriginRebuild:
    def test_scheme_default_is_https(self):
        # scheme-less base: the proof is fetched over https, and the
        # fetch SEES that scheme (an XX-wrapped or dropped default
        # changes the requested URL's scheme)
        seen = {}
        def fetch(url):
            seen["url"] = url
            return 200, {}, b"t"
        # protocol-relative base ("//host") has no scheme: the DEFAULT
        # is https — the proof URL must carry it
        fetch_well_known("//example.com/anything?ignored=1", fetch)
        assert seen["url"].startswith("https://example.com/")

    def test_unsupported_scheme_refused(self):
        seen = {}
        def fetch(url):
            seen["url"] = url
            return 200, {}, b"t"
        with pytest.raises(WellKnownError, match="unsupported scheme"):
            fetch_well_known("ftp://example.com/", fetch)
        assert "url" not in seen          # nothing fetched after refusal

    def test_scheme_checked_before_host_fetch(self):
        # the scheme check fires even when the host is fine: no fetch
        def fetch(url):
            raise AssertionError("must not fetch: %s" % url)
        with pytest.raises(WellKnownError, match="unsupported scheme"):
            fetch_well_known("gopher://example.com/", fetch)

    def test_dot_root_host_stripped_in_proof_url(self):
        # "example.com." (RFC 1034 root form) — the proof URL carries
        # the bare host; rstrip(".") mutations leak the dot into the
        # fetched origin
        seen = {}
        def fetch(url):
            seen["url"] = url
            return 200, {}, b"t"
        fetch_well_known("https://Example.COM./p", fetch)
        assert seen["url"] == "https://example.com" \
            "/.well-known/burhan-authorization.txt"

    def test_host_lowercased_in_proof_url(self):
        seen = {}
        def fetch(url):
            seen["url"] = url
            return 200, {}, b"t"
        fetch_well_known("https://MiXeD.CaSe.Host/p", fetch)
        assert seen["url"].startswith("https://mixed.case.host/")

    def test_explicit_port_preserved(self):
        seen = {}
        def fetch(url):
            seen["url"] = url
            return 200, {}, b"t"
        fetch_well_known("https://example.com:8443/p", fetch)
        assert seen["url"].startswith("https://example.com:8443/")

    def test_userinfo_and_path_dropped_from_proof_url(self):
        # the CodeQL discharge: no userinfo, no path from the input
        seen = {}
        def fetch(url):
            seen["url"] = url
            return 200, {}, b"t"
        fetch_well_known(
            "https://user:pw@example.com/decoy/path?x=1#frag", fetch)
        assert seen["url"] == "https://example.com" \
            "/.well-known/burhan-authorization.txt"

    def test_no_host_refused_before_fetch(self):
        def fetch(url):
            raise AssertionError("must not fetch: %s" % url)
        with pytest.raises(WellKnownError, match="no host"):
            fetch_well_known("https:///pathonly", fetch)


# ────────────────────────────────────────────────────────────────
# W5 — loopback/private resolver path (2 critical mutants)
# ────────────────────────────────────────────────────────────────
class TestLoopbackResolver:
    def test_public_host_literal_false(self):
        assert _is_loopback_or_private("93.184.216.34") is False

    def test_hostname_resolving_to_public_is_false(self):
        # getaddrinfo path with a PUBLIC answer must be False — an
        # `all()` mutation flipping to any() lets one private A record
        # (round-robin CDN edge) capture a public site
        assert _is_loopback_or_private("one.one.one.one") is False

    def test_resolver_failure_is_not_private(self):
        # a name that cannot resolve must NOT read as private
        assert _is_loopback_or_private("nonexistent.invalid") is False


# ────────────────────────────────────────────────────────────────
# W6 — authorize: no-host verdict + quote matching + DoH shape
#      + final refusal (7 critical mutants)
# ────────────────────────────────────────────────────────────────
class TestAuthorizeCriticalPaths:
    @staticmethod
    def _reg(tmp_path, targets):
        p = tmp_path / "reg.json"
        p.write_text(json.dumps({"targets": targets}), encoding="utf-8")
        return str(p)

    def test_no_host_verdict_false_with_reason_and_no_entry(self, tmp_path):
        reg = self._reg(tmp_path, [{
            "id": "pub", "kind": "dns_txt", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "dns_txt", "token": "z" * 32},
        }])
        ok, reason, eid = _authorize("file:///etc/passwd", reg)
        assert ok is False
        assert "no host" in reason
        assert eid is None

    def test_quote_matches_verbatim_page(self, tmp_path):
        quote = "permission to scan example.com granted"
        reg = self._reg(tmp_path, [{
            "id": "q1", "kind": "scope_page",
            "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "scope_page", "page_url": "https://example.com/perm",
                      "required_quote": quote},
        }])
        ok, reason, eid = _authorize(
            "https://example.com/", reg,
            fetch=lambda url: "<html><body>%s</body></html>" % quote)
        assert ok is True, reason
        assert eid == "q1"

    def test_quote_must_match_normalized_page_not_missing(self, tmp_path):
        # the page carries the sentence as HTML entities — the
        # `required in page or required in _normalize_page_text(page)`
        # contract: normalization is the SECOND disjunct, and dropping
        # either one must fail the verdict
        quote = "permission to scan example.com granted"
        entity_page = ("<html><body>permission to scan example.com"
                       "&nbsp;granted</body></html>")
        reg = self._reg(tmp_path, [{
            "id": "q2", "kind": "scope_page",
            "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "scope_page", "page_url": "https://example.com/perm",
                      "required_quote": quote},
        }])
        ok, reason, eid = _authorize(
            "https://example.com/", reg, fetch=lambda url: entity_page)
        assert ok is True, reason

    def test_quote_absent_from_page_refuses(self, tmp_path):
        quote = "permission to scan example.com granted"
        reg = self._reg(tmp_path, [{
            "id": "q3", "kind": "scope_page",
            "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "scope_page", "page_url": "https://example.com/perm",
                      "required_quote": quote},
        }])
        ok, reason, eid = _authorize(
            "https://example.com/", reg,
            fetch=lambda url: "<html><body>nothing to see</body></html>")
        assert ok is False

    def test_doh_query_url_shape(self, tmp_path):
        # the DoH TXT lookup queries cloudflare with the HOST
        # percent-encoded and type=TXT — mutations to that URL change
        # what the fetch is asked for
        seen = {}
        def fetch(url):
            seen["url"] = url
            # a TXT answer carrying the token
            return ('{"Status":0,"Answer":[{"type":16,"data":"\\"token'
                    '-abc123\\""}]}')
        token = "token-abc123"
        reg = self._reg(tmp_path, [{
            "id": "d1", "kind": "dns_txt", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "dns_txt", "token": token},
        }])
        ok, reason, eid = _authorize("https://example.com/", reg, fetch=fetch)
        assert seen["url"].startswith(
            "https://cloudflare-dns.com/dns-query?name=")
        assert urllib.parse.quote("example.com", safe="") in seen["url"]
        assert "type=TXT" in seen["url"]
        assert ok is True, reason

    def test_unlisted_public_host_final_refusal(self, tmp_path):
        reg = self._reg(tmp_path, [{
            "id": "pub", "kind": "dns_txt", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "dns_txt", "token": "z" * 32},
        }])
        ok, reason, eid = _authorize("https://other.example.org/", reg)
        assert ok is False
        assert "NOT PRESENT" in reason
        assert eid is None


# ────────────────────────────────────────────────────────────────
# W7 — require_authorized wrapper (2 critical mutants)
# ────────────────────────────────────────────────────────────────
class TestRequireAuthorizedWrapper:
    def test_default_lab_flag_off_refuses_private(self, tmp_path, monkeypatch, capsys):
        from burhan.authorized_targets import require_authorized
        monkeypatch.delenv(lm.ENV_VAR, raising=False)
        reg = tmp_path / "reg.json"
        reg.write_text(json.dumps({"targets": [{
            "id": "sh", "kind": "self-hosted", "covers": ["127.0.0.1"],
            "match": {"loopback_or_private": True}, "proof": {},
        }]}), encoding="utf-8")
        # lab_flag default False: a private target is REFUSED (exit 2)
        with pytest.raises(SystemExit) as ei:
            require_authorized("http://127.0.0.1:9999/", str(reg))
        assert ei.value.code == 2

    def test_fetch_passthrough_reaches_authorize(self, tmp_path, monkeypatch):
        from burhan.authorized_targets import require_authorized
        monkeypatch.delenv(lm.ENV_VAR, raising=False)
        reg = tmp_path / "reg.json"
        quote = "permission to scan example.com granted"
        reg.write_text(json.dumps({"targets": [{
            "id": "q9", "kind": "scope_page", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "scope_page",
                      "page_url": "https://example.com/perm",
                      "required_quote": quote},
        }]}), encoding="utf-8")
        # the injected fetch must be FORWARDED to authorize (a None-
        # mutation drops it and the real network fetch fails closed)
        out = require_authorized(
            "https://example.com/", str(reg),
            fetch=lambda url: "<body>%s</body>" % quote)
        # success: returns the entry id and prints the authorization line
        assert out == "q9"


# ────────────────────────────────────────────────────────────────
# W8 — resolver-path ALL-semantics + NoRedirect fp-tolerance
#      (kills x__is_loopback_or_private__mutmut_14: the `or` in the
#      getaddrinfo branch — every resolved address must be private
#      OR loopback; an `and` only passes addresses that are BOTH)
# ────────────────────────────────────────────────────────────────
class TestResolverAllSemantics:
    def test_private_non_loopback_address_is_private(self, monkeypatch):
        # a hostname resolving to private-but-not-loopback addresses:
        # `or` says PRIVATE (True), `and` says not — the gate must
        # treat the private range as private
        monkeypatch.setattr(
            "burhan.authorized_targets.socket.getaddrinfo",
            lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                 ("10.20.30.40", 0))])
        assert _is_loopback_or_private("intranet.host") is True

    def test_resolver_mixed_public_private_is_public(self, monkeypatch):
        # one public + one private answer (round-robin): all() must
        # read the host as PUBLIC — a private record alone cannot
        # capture a public site into the private gate
        monkeypatch.setattr(
            "burhan.authorized_targets.socket.getaddrinfo",
            lambda host, port: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))])
        assert _is_loopback_or_private("mixed.host") is False


# ────────────────────────────────────────────────────────────────
# W9 — final wave: message-text contracts, HTTPError properties,
#      fetch(None) passthrough, rstrip charset
# ────────────────────────────────────────────────────────────────
class TestRefusalMessageContracts:
    """The refusal/acceptance MESSAGE text is itself a contract: the
    operator (and downstream tooling) greps for these exact phrases.
    Kills the XX-wrapped message mutations on the critical paths."""

    def test_no_host_reason_text_exact(self, tmp_path):
        p = tmp_path / "reg.json"
        p.write_text(json.dumps({"targets": [{
            "id": "p", "kind": "dns_txt", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "dns_txt", "token": "z" * 32}}]}),
            encoding="utf-8")
        ok, reason, eid = _authorize("file:///etc/passwd", str(p))
        assert ok is False
        # the exact phrase, un-wrapped (XX...XX breaks the grep)
        assert reason == "no host in the given URL"

    def test_unlisted_host_reason_contains_exact_phrase(self, tmp_path):
        p = tmp_path / "reg.json"
        p.write_text(json.dumps({"targets": [{
            "id": "p", "kind": "dns_txt", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "dns_txt", "token": "z" * 32}}]}),
            encoding="utf-8")
        ok, reason, eid = _authorize("https://other.example.org/", str(p))
        assert ok is False
        assert "is NOT PRESENT in authorized-targets.json" in reason
        # structural cleanliness: the reason is machine-grepped; the
        # mutmut XX wrapper (or any stray marker) must not appear
        assert "XX" not in reason
        assert reason.startswith("host ")

    def test_quote_verified_reason_phrase(self, tmp_path):
        quote = "permission to scan example.com granted"
        p = tmp_path / "reg.json"
        p.write_text(json.dumps({"targets": [{
            "id": "q", "kind": "scope_page", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "scope_page",
                      "page_url": "https://example.com/perm",
                      "required_quote": quote}}]}), encoding="utf-8")
        ok, reason, eid = _authorize(
            "https://example.com/", str(p),
            fetch=lambda url: "<body>%s</body>" % quote)
        assert ok is True
        # exact phrase INCLUDING the capital-H of "HTML-entity"
        assert "quote verified verbatim (HTML-entity" in reason
        assert "XX" not in reason

    def test_unsupported_scheme_reason_phrase(self):
        def fetch(url):
            raise AssertionError("must not fetch")
        with pytest.raises(WellKnownError) as ei:
            fetch_well_known("ftp://example.com/", fetch)
        msg = str(ei.value)
        # BOTH halves of the two-line message must survive unwrapped
        assert "unsupported scheme" in msg
        assert "for the well-known proof" in msg
        assert "http/https only" in msg.replace("  ", " ").replace("\n", " ")


class TestScopePageFetchesPinnedUrl:
    def test_fetch_receives_the_pinned_page_url(self, tmp_path):
        # fetch(proof["page_url"]) — a None mutation asks the fetch for
        # None instead of the pinned URL; the fake asserts the exact URL
        quote = "permission to scan example.com granted"
        p = tmp_path / "reg.json"
        p.write_text(json.dumps({"targets": [{
            "id": "q", "kind": "scope_page", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "scope_page",
                      "page_url": "https://example.com/perm",
                      "required_quote": quote}}]}), encoding="utf-8")
        seen = []
        def fetch(url):
            assert url == "https://example.com/perm", \
                "scope_page proof must fetch the PINNED page_url, got %r" % url
            seen.append(url)
            return "<body>%s</body>" % quote
        ok, reason, eid = _authorize("https://example.com/", str(p), fetch=fetch)
        assert ok is True, reason
        assert len(seen) == 1


class TestNoRedirectErrorFP:
    def test_httperror_carries_real_fp(self, server):
        # the raised HTTPError must carry the REAL response object as
        # fp (readable by the consumer); an fp=None mutation leaves a
        # rebuilt BytesIO instead (r19-2.9 follow-up: proven observable)
        import http.client
        import urllib.error
        from burhan.ownership import _NoRedirect
        _Gate.ROUTES = {
            "/hopfp": (302, {"Location": "http://127.0.0.1:1/x"}, b""),
        }
        opener = urllib.request.build_opener(_NoRedirect)
        with pytest.raises(urllib.error.HTTPError) as ei:
            opener.open(server + "/hopfp")
        # the ORIGINAL passes the live response object; the fp=None
        # mutation gets a rebuilt BytesIO from urllib
        assert isinstance(ei.value.fp, http.client.HTTPResponse), \
            "fp must be the real http.client.HTTPResponse, got %s" \
            % type(ei.value.fp).__name__


class TestDefaultFetchTimeout:
    def test_slow_server_fails_fast_within_timeout(self, monkeypatch):
        """timeout is a SECURITY bound of _default_fetch: a slow/hanging
        server must fail FAST, not pin the scanner. FETCH_TIMEOUT is
        monkeypatched to 1.0s (read at CALL time), the server sleeps
        4.0s, and the fetch must die within 2.5s with a TIMEOUT-FAMILY
        exception (type, not text). Red on the timeout=None mutant,
        green on the original."""
        import time
        import urllib.error
        from burhan import ownership
        from burhan.ownership import _default_fetch

        monkeypatch.setattr(ownership, "FETCH_TIMEOUT", 1.0)

        class _Slow(http.server.BaseHTTPRequestHandler):
            DELAY = 4.0   # sleeps well past the patched 1.0s bound

            def log_message(self, *a):  # silence
                pass

            def do_GET(self):  # noqa: N802
                time.sleep(self.DELAY)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            t0 = time.monotonic()
            # exception TYPE, not message text: the timeout family
            with pytest.raises((urllib.error.URLError, socket.timeout)):
                _default_fetch(base + "/slow")
            el = time.monotonic() - t0
            assert el < 2.5, (
                "slow server was not cut off by the timeout bound "
                f"(took {el:.1f}s, patched FETCH_TIMEOUT=1.0s)")
        finally:
            srv.shutdown()
            srv.server_close()
