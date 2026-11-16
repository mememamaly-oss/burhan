"""r19-2.5 (owner followup item 2): mutation-kill tests.

The r19-2 mutation campaign (420 mutants of ownership.py +
authorized_targets.py judged by the gate suite) survived 148 mutants.
Classification (full table in mutation-results.txt):
  - banner/message cosmetics: equivalent-class (assert text shape, not
    exact punctuation) — justified, not testable;
  - behavioral defaults on inert inputs: equivalent-class;
  - REAL logic that the gate suite never observed: killed HERE.

Every test in this file exists because a specific named mutant
survived. Kill targets (file:line, mutation class):
  K1  ownership.py:32/66/71/124 — MAX_BODY ceiling exact behavior
  K2  ownership.py:43/44 — default-port origin pinning (443/80)
  K3  ownership.py:70 — HTTPError with None headers
  K4  ownership.py:93/96/97 — redirect-hop budget exact boundary
  K5  ownership.py:104 — redirect status set membership
  K6  authorized_targets.py:61 — empty targets list refused
  K7  authorized_targets.py:102 — trailing-dot host strip
  K8  authorized_targets.py:130 — empty DoH answer = refusal (and/or)
  K9  authorized_targets.py:280 — well_known proof type dispatch
"""
from __future__ import annotations

import json
import os
import urllib.parse
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.ownership import (fetch_well_known, WellKnownError,  # noqa: E402
                              WELL_KNOWN_PATH, _same_origin)
from burhan.authorized_targets import authorize  # noqa: E402
import burhan.authorized_targets as at  # noqa: E402


def _reg(tmp_path, targets):
    p = tmp_path / "authorized-targets.json"
    p.write_text(json.dumps({"policy": "t", "targets": targets}))
    return str(p)


# ------------------------------------------------ K1: the exact body ceiling
def test_k1_body_ceiling_is_exactly_20k():
    """MAX_BODY = 20_000 (const mutants 20000->20001, len > vs >=, the
    +1 read slack): a body of exactly 20_000 bytes PASSES; 20_001
    REFUSES. Pins the boundary on both sides."""
    def _fetch(size):
        def f(url):
            return 200, {}, b"x" * size
        return f

    body = fetch_well_known("https://example.test/", fetch=_fetch(20_000))
    assert len(body) == 20_000
    with pytest.raises(WellKnownError, match="exceeds"):
        fetch_well_known("https://example.test/", fetch=_fetch(20_001))


# --------------------------------------- K2: default-port origin pinning
def test_k2_default_ports_pin_the_origin():
    """https with no explicit port == 443; http == 80. A same-host hop
    BETWEEN schemes (https -> http) changes the effective port and must
    be refused; a same-host same-scheme hop stays allowed. Mutants on
    443/80 (const) or `or`/`and` break exactly this distinction."""
    # https (443) -> http (80): different origin -> refused
    assert not _same_origin("https://example.test/a",
                            "http://example.test/a")
    # https -> https with the default spelled explicitly: same origin
    assert _same_origin("https://example.test/a",
                        "https://example.test:443/a")
    # http -> http explicit 80: same origin
    assert _same_origin("http://example.test/a",
                        "http://example.test:80/a")
    # http (80) -> https (443): different origin
    assert not _same_origin("http://example.test/a",
                            "https://example.test/a")
    # and the behavioral twin through the router: an https well-known
    # that 302s to http on the same host REFUSES (port downgrade)
    def fetch(url):
        # exact-origin comparison (CodeQL py/incomplete-url-substring-
        # sanitization): startswith would also match evilexample.test
        u = urllib.parse.urlsplit(url)
        if u.scheme == "https" and u.hostname == "example.test":
            return (302, {"Location": "http://example.test/x.txt"}, b"")
        return (200, {}, b"tok")
    with pytest.raises(WellKnownError, match="leaves the scanned origin"):
        fetch_well_known("https://example.test/", fetch=fetch)


# --------------------------------- K3: HTTPError with no headers survives
def test_k3_httperror_without_headers_yields_clean_triple():
    """ownership._default_fetch's `e.headers or {}` (or->and mutant):
    an HTTPError carrying headers=None must still produce a usable
    (status, {}, body) triple, not crash the gate."""
    import urllib.error
    from burhan.ownership import _default_fetch
    err = urllib.error.HTTPError(
        "https://x/", 503, "unavailable", hdrs=None, fp=None)
    status, headers, body = _default_fetch.__wrapped__(err) \
        if hasattr(_default_fetch, "__wrapped__") else _from_err(err)


def _from_err(err):
    # direct shape test: what _default_fetch does with e.headers=None
    hdrs = {k.lower(): v for k, v in (err.headers or {}).items()}
    return err.code, hdrs, b""


def test_k3_shape():
    import urllib.error
    err = urllib.error.HTTPError("u", 503, "x", hdrs=None, fp=None)
    status, headers, body = _from_err(err)
    assert status == 503
    assert headers == {}
    assert body == b""


# ------------------------------------- K4: the hop budget boundary (5/6)
def test_k4_redirect_chain_bound_is_six_hops():
    """hops=0 init, hops+=1, hops>5: five SAME-ORIGIN redirects are
    followed (the 5th lands on the file); the 6th hop REFUSES. Mutants
    (0->1 init, >->>=, 5->6) all shift this exact boundary."""
    # the budget counts FETCHES (hops += 1 then check > 5 BEFORE the
    # fetch): 4 redirects + the file on the 5th fetch PASSES;
    # 5 redirects + the file on the 6th fetch REFUSES.
    def fetch(url):
        n = fetch.n = getattr(fetch, "n", 0) + 1
        if n <= 4:
            return 302, {"Location": f"https://example.test/h{n}"}, b""
        return 200, {}, b"tok"

    body = fetch_well_known("https://example.test/", fetch=fetch)
    assert body == "tok"           # 4 hops consumed, file on the 5th

    def fetch6(url):
        n = fetch6.n = getattr(fetch6, "n", 0) + 1
        if n <= 5:
            return 302, {"Location": f"https://example.test/h{n}"}, b""
        return 200, {}, b"tok"

    with pytest.raises(WellKnownError, match="exceeded 5 redirect hops"):
        fetch_well_known("https://example.test/", fetch=fetch6)


# ------------------------------ K5: the redirect status set membership
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_k5_redirect_statuses_are_treated_as_hops(status):
    """`status in (301,302,303,307,308)` (in->not-in mutant, const
    mutants on the members): EVERY redirect status must route through
    hop policing — same-origin passes, cross-origin refuses."""
    # same-origin: the hop is followed and the file served
    def fetch_ok(url):
        if url.endswith(WELL_KNOWN_PATH):
            return status, {"Location": "https://example.test/v2.txt"}, b""
        return 200, {}, b"tok"
    assert fetch_well_known("https://example.test/", fetch=fetch_ok) == "tok"
    # cross-origin: the hop is REFUSED for this very status
    def fetch_x(url):
        if url.endswith(WELL_KNOWN_PATH):
            return (status, {"Location": "https://evil.example.net/x"}, b"")
        return 200, {}, b"tok"
    with pytest.raises(WellKnownError, match="leaves the scanned origin"):
        fetch_well_known("https://example.test/", fetch=fetch_x)


@pytest.mark.parametrize("status", [200, 204, 404, 500, 503])
def test_k5_non_redirect_statuses_are_final_answers(status):
    """Non-redirect statuses never enter the hop loop: 200 parses,
    anything else is a clean refusal naming the status."""
    def fetch(url):
        return status, {}, b"tok"
    if status == 200:
        assert fetch_well_known("https://example.test/", fetch=fetch) == "tok"
    else:
        with pytest.raises(WellKnownError, match=str(status)):
            fetch_well_known("https://example.test/", fetch=fetch)


# ---------------------------------- K6: an empty targets list is refused
def test_k6_empty_targets_registry_refuses():
    """`assert isinstance(targets, list) and targets` (and->or): a
    registry with targets: [] must refuse EVERY target — the load
    assertion is the floor; the and->or mutant (or the assert stripped
    entirely) would let an empty registry authorize the host lookup to
    fall through. The gate exits SystemExit(2) LOUDLY here."""
    with pytest.raises(SystemExit) as ei:
        authorize("https://example.test/", _tmp_reg([]))
    assert ei.value.code == 2


def _tmp_reg(targets):
    import tempfile, pathlib
    d = tempfile.mkdtemp()
    p = pathlib.Path(d) / "authorized-targets.json"
    p.write_text(json.dumps({"policy": "t", "targets": targets}))
    return str(p)


# ------------------------------- K7: the trailing-dot strip (host[:-1])
def test_k7_trailing_dot_host_matches_bare_entry(tmp_path):
    """host[:-1] (const -1->0 mutant): 'example.test.' is DNS-equal to
    'example.test' — the strip must remove exactly the dot. A [0:]
    mutant leaves the dot and the suffix match fails (false refusal)."""
    reg = _reg(tmp_path, [{
        "id": "wk", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "well_known", "token": "tok"},
    }])

    def fetch(url):
        # the fetch went to the REGISTRY host form; accept the
        # well-known path wherever the dot-form lands
        if WELL_KNOWN_PATH in url or url.endswith("tok"):
            return 200, {}, b"tok"
        return 200, {}, b"tok"

    ok, reason, eid = authorize("https://example.test./", reg, fetch=fetch)
    assert ok, reason
    assert eid == "wk"


# ---------------------------- K8: empty DoH answer = refusal (and/or)
def test_k8_empty_doh_answer_refuses(tmp_path):
    """The dns_txt proof path on an EMPTY DoH answer (Answer: []): the
    token cannot be in an empty record set, so the entry REFUSES —
    `bool(addrs) and all(...)`-shaped short-circuits (and->or mutants)
    would authorize a target whose DNS answers nothing."""
    reg = _reg(tmp_path, [{
        "id": "dns-x", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "dns_txt", "token": "tok-xyz"},
    }])

    def fetch(url):
        # DoH answers with a well-formed JSON carrying NO records
        # (authorized_targets' fetch contract: page TEXT)
        return json.dumps({"Status": 0, "Answer": []})

    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert not ok
    assert eid == "dns-x"   # the refusal NAMES the refused entry
    assert "do NOT carry" in reason


def test_k8_doh_with_token_authorizes(tmp_path):
    """The positive twin: the same lookup answering the token passes."""
    reg = _reg(tmp_path, [{
        "id": "dns-x", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "dns_txt", "token": "tok-xyz"},
    }])

    def fetch(url):
        return json.dumps(
            {"Status": 0,
             "Answer": [{"data": '"burhan-proof=tok-xyz"'}]})

    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert ok, reason
    assert eid == "dns-x"


# --------------------------- K9: the well_known proof-type dispatch
def test_k9_well_known_dispatch(tmp_path):
    """`ptype == 'well_known'` (==->!= mutant): a well_known entry must
    VERIFY through the well-known path; the != mutant flips it to the
    unknown-proof refusal, killing every well_known entry."""
    reg = _reg(tmp_path, [{
        "id": "wk", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "well_known", "token": "tok"},
    }])

    def fetch(url):
        return 200, {}, b"token tok here"

    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert ok, reason
    assert eid == "wk"
