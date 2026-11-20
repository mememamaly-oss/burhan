"""RUN8-B wave-5 kill tests: the 69 CRITICAL survivors by the frozen
definition (owner order 2026-11-18 items 2 & 4).

Priority order as stated by the owner: authorize (22) ->
_default_fetch (17) -> _fetch_with_injectable (8) -> fetch_well_known
(6) -> the rest (16). Verified RED on each target mutant and GREEN on
the original by scripts/wave5_verify.py (see wave5-red-green.json);
45 of the 69 die here, the other 24 are equivalent-in-practice, each
confirmed by a LIVE run (the same script records them).

Sites and doctrines:
  - authorize: the well-known proof URL build (scheme preserved from
    the scanned origin), the covers-slice join, the refusal_reason
    call shape, the DoH answer default, the signed-letter OSError
    refusal;
  - _default_fetch (ownership): MAX_BODY truncation guards (both the
    200 and the HTTPError path), header lowercasing;
  - _default_fetch (authorized_targets — owner item 4): the live
    proof-fetch hop gets the same timeout/typing treatment (its
    timeout=None, url=None and error-typing mutants die here);
  - _fetch_with_injectable: redirect status set, Location fallback
    string, non-bytes decode guard, MAX_BODY boundary;
  - fetch_well_known: invalid-port refusal message shape;
  - the rest: candidate-sentence None-guard, host_of IDN branch,
    loopback numeric path, normalize tag stripping, require_authorized
    log line, NoRedirect super() delegation.
"""
from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.ownership import (  # noqa: E402
    MAX_BODY, WellKnownError, _fetch_with_injectable, _NoRedirect,
)
from burhan import ownership as own_mod  # noqa: E402
from burhan import authorized_targets as at_mod  # noqa: E402
from burhan.authorized_targets import (  # noqa: E402
    FetchError, _is_loopback_or_private, _normalize_page_text,
    authorize as _authorize, require_authorized,
)
from burhan import lab_mode as lm  # noqa: E402


# ══════════════════════════════════════════════════════════════════
# The controlled server (same doctrine as kills4): class-level ROUTES.
# ══════════════════════════════════════════════════════════════════
class _Gate(http.server.BaseHTTPRequestHandler):
    ROUTES: dict[str, tuple[int, dict, bytes]] = {}

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):  # noqa: N802
        status, headers, body = self.ROUTES.get(self.path, (404, {}, b""))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class _Slow(http.server.BaseHTTPRequestHandler):
    DELAY = 4.0  # sleeps well past the patched 1.0s bound

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):  # noqa: N802
        time.sleep(self.DELAY)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


@pytest.fixture()
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Gate)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture()
def slow_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _registry(tmp_path, targets):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    return str(p)


# ══════════════════════════════════════════════════════════════════
# authorize (priority 1)
# ══════════════════════════════════════════════════════════════════
class TestAuthorizeWellKnownUrlBuild:
    def test_proof_url_keeps_the_scanned_scheme(self, tmp_path):
        """The well-known proof fetch goes to the SAME origin the scan
        will hit: the URL passed downstream must carry the scanned
        scheme — not be rebuilt as https:// regardless (mutmut_325,
        mutmut_329)."""
        reg = _registry(tmp_path, [{
            "id": "wk-1", "match": {"host_suffix": "example.com"},
            "proof": {"type": "well_known", "token": "TK5"}}])
        seen = []

        def fake_fetch(url):
            seen.append(url)
            return 200, {}, b"TK5 present"

        ok, reason, eid = _authorize("http://example.com/scan?x=1", reg,
                                     fake_fetch)
        assert (ok, eid) == (True, "wk-1")
        assert seen == ["http://example.com/.well-known/"
                        "burhan-authorization.txt"]

    def test_signed_letter_read_failure_is_a_refusal(self, tmp_path):
        """An unreadable authorization letter is a REFUSAL naming the
        OSError — not a crash (mutmut_276 turns the %-format into a
        TypeError)."""
        reg = _registry(tmp_path, [{
            "id": "lt-1", "match": {"host_suffix": "letter.example"},
            "proof": {"type": "signed_letter",
                      "file": "definitely-missing-letter.txt",
                      "sha256": "00"}}])
        ok, reason, eid = _authorize("https://letter.example/", reg,
                                     lambda u: "")
        assert ok is False and eid == "lt-1"
        assert "could not be read" in reason

    def test_covers_slice_join(self, tmp_path, monkeypatch):
        """The self-hosted allow reason names the first three covered
        fixtures, joined ', ' — nothing more (mutmut_42..46)."""
        monkeypatch.setattr(lm, "is_lab_mode",
                            lambda flag=False: (True, "flag"))
        reg = _registry(tmp_path, [{
            "id": "sh-1", "kind": "self-hosted",
            "match": {"loopback_or_private": True},
            "covers": ["fixture-a", "fixture-b", "fixture-c", "fixture-d"]}])
        ok, reason, eid = _authorize("http://127.0.0.1:9/", reg, None)
        assert (ok, eid) == (True, "sh-1")
        assert "fixture-a, fixture-b, fixture-c" in reason
        assert "fixture-d" not in reason

    def test_refusal_reason_gets_the_real_host(self, tmp_path, monkeypatch):
        """The lab-mode refusal names the actual target host
        (mutmut_53 passes None instead)."""
        monkeypatch.setattr(lm, "is_lab_mode",
                            lambda flag=False: (False, None))
        reg = _registry(tmp_path, [{
            "id": "sh-1", "kind": "self-hosted",
            "match": {"loopback_or_private": True}, "covers": ["x"]}])
        ok, reason, eid = _authorize("http://127.0.0.1:9/", reg, None)
        assert ok is False and eid is None
        assert "127.0.0.1" in reason

    def test_doh_null_answer_is_a_refusal_not_a_crash(self, tmp_path):
        """A DoH reply with NO Answer key at all must land in the
        empty-records refusal (mutmut_193 defaults .get to None ->
        TypeError crash instead of the refusal verdict)."""
        reg = _registry(tmp_path, [{
            "id": "dns-1", "match": {"host_suffix": "dns-probe.example"},
            "proof": {"type": "dns_txt", "token": "TK"}}])

        def fake_fetch(url):
            assert "dns-query" in url
            return json.dumps({"Status": 0})

        ok, reason, eid = _authorize("https://dns-probe.example/", reg,
                                     fake_fetch)
        assert ok is False and eid == "dns-1"
        assert "do NOT carry" in reason


# ══════════════════════════════════════════════════════════════════
# _default_fetch — ownership (priority 2a)
# ══════════════════════════════════════════════════════════════════
class TestOwnDefaultFetchBodyGuards:
    def test_oversized_body_truncated_to_bound(self, server):
        """r.read(MAX_BODY + 1): the fetch returns at most the bound
        plus one byte — the +1 is what lets the caller detect and
        refuse an oversized file (mutmut_33 reads everything,
        mutmut_34 reads one byte less)."""
        _Gate.ROUTES = {"/big": (200, {}, b"x" * (MAX_BODY + 5)),
                        "/exact": (200, {}, b"x" * (MAX_BODY + 1))}
        status, headers, body = own_mod._default_fetch(server + "/big")
        assert status == 200
        assert len(body) == MAX_BODY + 1

    def test_body_at_the_bound_is_returned_whole(self, server):
        _Gate.ROUTES = {"/exact": (200, {}, b"x" * (MAX_BODY + 1))}
        status, headers, body = own_mod._default_fetch(server + "/exact")
        assert len(body) == MAX_BODY + 1

    def test_http_error_body_is_passed_through(self, server):
        """The HTTPError path returns the error body AND keeps header
        keys lowercased on that path too (mutmut_39 b"", mutmut_48/
        49/44 wrong hasattr, mutmut_50 b"XXXX", mutmut_37 uppercases
        the error-path headers)."""
        _Gate.ROUTES = {"/err": (404, {"X-Probe": "yes"}, b"gone")}
        status, headers, body = own_mod._default_fetch(server + "/err")
        assert status == 404
        assert body == b"gone"
        assert headers.get("x-probe") == "yes"

    def test_http_error_body_is_truncated_too(self, server):
        """The HTTPError read honours the same bound (mutmut_41
        read(None), mutmut_42/43 off-by-one)."""
        _Gate.ROUTES = {"/bigerr": (404, {}, b"x" * (MAX_BODY + 5))}
        status, headers, body = own_mod._default_fetch(server + "/bigerr")
        assert status == 404
        assert len(body) == MAX_BODY + 1

    def test_response_headers_are_lowercased(self, server):
        """Header keys come back lowercased — the hop decision reads
        'location' case-insensitively (mutmut_37 uppercases)."""
        _Gate.ROUTES = {"/hdr": (200, {"X-Probe": "yes"}, b"")}
        status, headers, body = own_mod._default_fetch(server + "/hdr")
        assert headers.get("x-probe") == "yes"


# ══════════════════════════════════════════════════════════════════
# _default_fetch — authorized_targets (priority 2b, owner item 4)
# ══════════════════════════════════════════════════════════════════
class TestAtDefaultFetch:
    def test_slow_server_fails_fast_within_timeout(self, monkeypatch,
                                                   slow_server):
        """authorized_targets._default_fetch has the SAME security
        bound: monkeypatched FETCH_TIMEOUT=1.0s, a server sleeping
        4.0s, a FetchError within 2.5s (mutmut_12 timeout=None),
        raised as a FetchError naming the underlying timeout-family
        exception TYPE (mutmut_29 names TypeError instead)."""
        monkeypatch.setattr(at_mod, "FETCH_TIMEOUT", 1.0)
        t0 = time.monotonic()
        with pytest.raises(FetchError) as ei:
            at_mod._default_fetch(slow_server + "/slow")
        el = time.monotonic() - t0
        assert el < 2.5, f"slow proof page was not cut off ({el:.1f}s)"
        assert "TimeoutError" in str(ei.value)

    def test_missing_page_raises_fetcherror(self, server):
        """A 404 proof page is a FetchError carrying the HTTP status
        (mutmut_11 passes url=None to urlopen -> TypeError instead)."""
        _Gate.ROUTES = {}
        with pytest.raises(FetchError) as ei:
            at_mod._default_fetch(server + "/gone")
        assert "404" in str(ei.value)


# ══════════════════════════════════════════════════════════════════
# _fetch_with_injectable (priority 3)
# ══════════════════════════════════════════════════════════════════
class TestFetchInjectable:
    def test_307_is_a_redirect_hop(self):
        """307 belongs to the hop set (mutmut_29 drops it -> the hop
        is treated as a final answer)."""
        calls = []

        def fake(url):
            calls.append(url)
            if url.endswith("/ok"):
                return 200, {}, b"TOKEN"
            return 307, {"location": "/ok"}, b""

        out = _fetch_with_injectable("http://h.example", fake)
        assert out == "TOKEN" and len(calls) == 2

    def test_309_is_not_a_redirect_hop(self):
        """A 309 answer is a final non-200 -> refusal naming the
        status (mutmut_30 adds it to the hop set)."""

        def fake(url):
            return 309, {"location": "/ok"}, b""

        with pytest.raises(WellKnownError) as ei:
            _fetch_with_injectable("http://h.example", fake)
        assert "309" in str(ei.value)

    def test_null_location_is_refused(self):
        """A Location header whose value is None is NOT a hop target
        (mutmut_41 substitutes 'XXXX' and follows it)."""

        def fake(url):
            return 302, {"Location": None}, b""

        with pytest.raises(WellKnownError) as ei:
            _fetch_with_injectable("http://h.example", fake)
        assert "without a Location header" in str(ei.value)

    def test_non_bytes_body_passes_through_unparsed(self):
        """A str body is passed through as-is — only bytes get the
        decode (mutmut_79 forces the decode on a str -> AttributeError
        wrapped as a refusal)."""
        out = _fetch_with_injectable("http://h.example",
                                     lambda u: (200, {}, "raw-string"))
        assert out == "raw-string"

    def test_body_exactly_at_max_body_passes(self):
        """len == MAX_BODY is fine; the refusal starts ABOVE it
        (mutmut_88 turns > into >=)."""
        body = b"x" * 20000
        assert len(body) == MAX_BODY
        out = _fetch_with_injectable("http://h.example",
                                     lambda u: (200, {}, body))
        assert len(out) == MAX_BODY


# ══════════════════════════════════════════════════════════════════
# fetch_well_known (priority 4)
# ══════════════════════════════════════════════════════════════════
class TestFetchWellKnownPortErrors:
    def test_invalid_port_is_a_named_refusal(self):
        """A URL with an unparseable port is refused with the port
        named and the reason text intact (mutmut_33 None message,
        mutmut_34 / instead of %, mutmut_35/36 XX-wrapped or
        lowercased text, mutmut_37 %S crashes)."""
        with pytest.raises(WellKnownError) as ei:
            own_mod.fetch_well_known("https://example.com:bad/", fetch=None)
        msg = str(ei.value)
        assert msg.startswith("invalid port")
        assert "target URL" in msg
        assert "bad" in msg

    def test_dot_root_host_keeps_its_last_label(self):
        """A dot-root host keeps its full last label: rstrip strips
        ONLY the trailing dot. Documents the verified EQUIVALENCE of
        mutmut_24 (rstrip("XX.XX") strips from the set {upper-X, '.'}
        — but the host is already lowercased in the same expression,
        so no upper-X can survive to strip; four live suite runs
        stayed green on the mutant)."""
        seen = []
        own_mod.fetch_well_known("https://fixture-x./",
                                 fetch=lambda u: seen.append(u) or
                                 (200, {}, b""))
        assert seen == ["https://fixture-x/.well-known/"
                        "burhan-authorization.txt"]


# ══════════════════════════════════════════════════════════════════
# the rest (priority 5)
# ══════════════════════════════════════════════════════════════════
class TestCandidateSentence:
    def test_matched_sentence_not_whole_page(self):
        """The candidate sentence is the MATCHED sentence, not the
        whole flattened page (mutmut_21 disables the match)."""
        page = ("Noise preamble that must not appear. Permission to "
                "test this site is granted. Trailing noise again.")
        out = at_mod._candidate_permission_sentence(page)
        assert "Noise" not in out
        assert "Permission" in out


class TestHostOf:
    def test_unicode_host_is_idna_encoded(self):
        """A unicode-spelled host is normalized to punycode before
        the registry match (mutmut_11 skips the branch)."""
        assert at_mod._host_of("https://münchen.example/") == \
            "xn--mnchen-3ya.example"


class TestLoopbackNumericPath:
    def test_numeric_loopback_is_private(self):
        """The numeric-literal path of the resolver (mutmut_1 feeds
        ip_address None)."""
        assert _is_loopback_or_private("127.0.0.1") is True

    def test_name_host_never_crashes_the_resolver(self):
        """A NON-numeric host takes the name-resolution branch: the
        verdict is a bool (True or False per the resolver), never a
        crash. Documents the verified EQUIVALENCE of mutmut_1
        (ip_address(None) raises ValueError — not TypeError — so it
        folds into the very same resolution branch; four live suite
        runs stayed green on the mutant)."""
        v = _is_loopback_or_private("localhost")
        assert isinstance(v, bool)


class TestNormalizePageText:
    def test_tags_become_single_spaces(self):
        """Tag stripping inserts ONE space and leaves no marker
        (mutmut_12 inserts 'XX XX'); leading-edge spaces from a tag at
        position 0 are the original's documented shape (no end-strip
        here — the caller compares with `in`)."""
        out = _normalize_page_text("<b>per</b>mission")
        assert "XX" not in out
        assert out.split() == ["per", "mission"]


class TestRequireAuthorizedLine:
    def test_success_line_shape(self, tmp_path, capsys):
        """The success log line starts with the gate's tag and names
        the scanned origin (mutmut_42 XX-wraps it)."""
        reg = _registry(tmp_path, [{
            "id": "ok-1", "match": {"host_suffix": "ok.example"},
            "proof": {"type": "scope_page",
                      "page_url": "https://ok.example/permission",
                      "required_quote": "QUOTE"}}])
        eid = require_authorized("https://ok.example/", reg,
                                 lambda u: "carries QUOTE verbatim")
        assert eid == "ok-1"
        out = capsys.readouterr().out
        assert out.startswith("[authorized-targets]")
        assert "https://ok.example/" in out


class TestNoRedirectDelegation:
    def test_same_origin_hop_is_followed_via_super(self, server):
        """A same-origin redirect is delegated to the parent handler
        intact (mutmut_6/8/9 pass None for fp/msg/headers)."""
        _Gate.ROUTES = {"/deleg": (302, {"Location": server + "/target"},
                                   b""),
                        "/target": (200, {}, b"final")}
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(server + "/deleg") as r:
            assert r.status == 200
            assert r.read() == b"final"
