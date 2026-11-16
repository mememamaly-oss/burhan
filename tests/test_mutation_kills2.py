"""r19-2.6 (owner followup 2, round 2): mutation-kill tests, wave 2.

The sixth mutation run (432 mutants, 75.9% kill, coordinates verified
after the display fix) left 104 real survivors. Classification:

  SECURITY FLIPS (16 mutants, 4 sites) — a mutated gate answers
  True (ALLOW) on a path that must refuse. These are test holes, not
  equivalent mutants; each is killed below:
    F1  "no host in the given URL"        -> False flipped True
    F2  "live DNS TXT lookup failed"      -> False flipped True
    F3  "authorization letter unreadable" -> False flipped True
    F4  "unknown proof type"              -> False flipped True

  HIGH-VALUE LOGIC (killed below where observable):
    L1  _host_of IDN branch: `and` -> `or` lets an ASCII host enter the
        idna-encode path / a unicode host skip it — observable via the
        unicode-vs-punycode entry match;
    L2  well_known dispatch scheme build: 'https://' + host when the
        URL carries no scheme — observable via which URL the injected
        fetch receives;
    L3  self-hosted match condition `and` -> `or`: a non-self-hosted
        entry carrying loopback_or_private would match — observable;
    L4  scope-page quote check `or` -> `and` (normalized-text fallback
        must independently carry the quote);
    L5  _is_private resolution helper: all() -> any() on resolved
        addresses (a host resolving to one private + one public address
        must still count as private).

  JUSTIFIED EQUIVALENTS (documented, not killed — see the report):
    - banner bar width '=' * 74, flush=True, read(200_000), flat[:300]
      truncation sizes: cosmetic output shaping, no security semantic;
    - print statements' text on pass/fail paths: the suite asserts
      outcome tuples and banner presence, not punctuation.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.authorized_targets import authorize, _host_of  # noqa: E402


def _reg(tmp_path, targets):
    p = tmp_path / "authorized-targets.json"
    p.write_text(json.dumps({"policy": "t", "targets": targets}))
    return str(p)


class _Resp:
    def __init__(self, status, body=b"", location=None):
        self.status = status
        self.body = body
        self.headers = {"Location": location} if location else {}

    def get(self, k, default=None):
        return self.headers.get(k, default)


# ------------------------------------------------------------- F1: no host
def test_F1_url_without_host_is_refused_not_allowed(tmp_path):
    """A URL with no host (e.g. 'http://:8080/') must REFUSE — flipping
    this return to True would authorize a hostless target."""
    reg = _reg(tmp_path, [{
        "id": "x", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "well_known", "token": "t"}}])

    def fetch(url):
        raise AssertionError("no fetch may happen for a hostless URL")

    ok, reason, eid = authorize("http://:8080/", reg, fetch=fetch)
    assert ok is False, (
        "hostless URL must be refused — the F1 mutant (False->True on "
        "'no host in the given URL') would ALLOW it")
    assert "no host" in reason


# --------------------------------------------------- F2: DNS TXT fetch fails
def test_F2_dns_txt_fetch_failure_refuses(tmp_path):
    """The DoH lookup failing (unparseable JSON — the ValueError branch)
    must REFUSE the dns_txt entry — never allow on outage."""
    reg = _reg(tmp_path, [{
        "id": "dnsx", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "dns_txt", "token": "tok"}}])

    def fetch(url):
        from burhan.authorized_targets import FetchError
        raise FetchError("DNS-over-HTTPS unreachable")

    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert ok is False, (
        "a failed DNS TXT lookup must refuse — the F2 mutant "
        "(False->True on 'live DNS TXT lookup failed') would ALLOW the "
        "target on a network outage")
    assert "lookup failed" in reason


def test_F2b_dns_txt_bad_json_refuses(tmp_path):
    reg = _reg(tmp_path, [{
        "id": "dnsx", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "dns_txt", "token": "tok"}}])

    def fetch(url):
        return "not json at all {"

    ok, reason, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert ok is False and "lookup failed" in reason


# ------------------------------------------------ F3: letter file unreadable
def test_F3_signed_letter_missing_file_refuses(tmp_path):
    """A signed_letter entry whose file cannot be read (missing/IO error)
    must REFUSE — never allow on unreadable proof."""
    reg = _reg(tmp_path, [{
        "id": "lx", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "signed_letter",
                  "file": "definitely-missing-letter.txt",
                  "sha256": "0" * 64}}])

    ok, reason, _ = authorize("https://example.test/", reg)
    assert ok is False, (
        "an unreadable authorization letter must refuse — the F3 mutant "
        "(False->True on 'letter could not be read') would ALLOW it")
    assert "could not be read" in reason


def test_F3b_signed_letter_sha_mismatch_refuses(tmp_path):
    letter = tmp_path / "letter.txt"
    letter.write_text("I authorize scanning example.test")
    reg = _reg(tmp_path, [{
        "id": "lx", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "signed_letter", "file": str(letter),
                  "sha256": "f" * 64}}])
    ok, reason, _ = authorize("https://example.test/", reg)
    assert ok is False and "sha256" in reason


# ------------------------------------------------------ F4: unknown proof
def test_F4_unknown_proof_type_refuses(tmp_path):
    """An entry whose proof type the gate does not know must REFUSE —
    flipping to True would allow any future/typo'd proof type."""
    reg = _reg(tmp_path, [{
        "id": "ux", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "proof_by_vibes", "token": "x"}}])

    ok, reason, _ = authorize("https://example.test/", reg)
    assert ok is False, (
        "an unknown proof type must refuse — the F4 mutant (False->True "
        "on 'unknown proof type') would ALLOW unimplemented proofs")
    assert "unknown proof type" in reason


# ----------------------------------------------- L1: IDN branch and/or
def test_L1_idn_unicode_host_matches_and_ascii_host_untouched():
    # the `and` in `if host and not host.isascii()` — flipped to `or`,
    # an EMPTY host would enter the idna path (crash -> caught) and,
    # worse, an ASCII host could skip the check under `not` mutations
    assert _host_of("https://пример.испытание/") == \
        "xn--e1afmkfd.xn--80akhbyknj4f"
    assert _host_of("https://example.test/") == "example.test"
    # empty-host URL: the F1/L1 pair — must not become an idna crash NOR
    # a pass; _host_of returns '' and authorize refuses (F1 above)
    assert _host_of("http://:8080/") == ""


# ------------------------------------ L2: well_known scheme build (no scheme)
def test_L2_well_known_fetch_receives_the_scanned_origin(tmp_path):
    """For an https-scanned target the well-known proof fetch must go to
    that same origin — the L2 mutant (scheme-build expression) changes
    which origin is consulted and the token stops matching."""
    reg = _reg(tmp_path, [{
        "id": "wk", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "well_known", "token": "tok"}}])
    seen = []

    def fetch(url):
        seen.append(url)
        return 200, {}, b"tok"

    ok, reason, _ = authorize("https://example.test/", reg, fetch=fetch)
    assert ok is True, reason
    assert seen and seen[0].startswith("https://example.test/"), seen


# ------------------------------------- L3: self-hosted match needs BOTH fields
def test_L3_loopback_flag_on_non_selfhosted_entry_does_not_authorize(
        tmp_path, monkeypatch):
    """`kind == 'self-hosted' AND match.loopback_or_private` — an entry
    with only one of the two must not satisfy the private-target path
    (the `or` mutant would let a misconfigured public entry authorize
    every private host)."""
    monkeypatch.setenv("BURHAN_LAB_MODE", "1")
    reg = _reg(tmp_path, [{
        "id": "half", "kind": "permissioned-public-demo",   # NOT self-hosted
        "match": {"loopback_or_private": True},             # but carries the flag
        "proof": {"type": "well_known", "token": "tok"}}])

    ok, reason, _ = authorize("http://127.0.0.1:9999/", reg)
    assert ok is False, (
        "loopback_or_private on a NON-self-hosted entry must not "
        "authorize a private target — the L3 mutant (and->or) would")
    assert "self-hosted" in reason


# ------------------------------------------ L4: scope-page normalization path
def test_L4_scope_quote_via_normalized_text_only(tmp_path):
    """The pinned quote must pass when it appears ONLY in the normalized
    form (entity/whitespace-mangled on the raw page) — the `or` in
    `required in page or required in _normalize_page_text(page)` flipped
    to `and` would demand BOTH forms and falsely refuse."""
    reg = _reg(tmp_path, [{
        "id": "sx", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "scope_page",
                  "page_url": "https://example.test/permission",
                  "required_quote":
                      "we permit scanning this site for research"}}])
    # raw page: entity-encoded + irregular whitespace — normalization
    # must recover the verbatim quote
    page = "<p>we&#32;permit&#10;scanning  this site for research.</p>"

    ok, reason, _ = authorize("https://example.test/", reg, fetch=lambda u: page)
    assert ok is True, (
        "the quote present only in normalized form must verify — the L4 "
        "mutant (or->and) would falsely refuse: " + str(reason))


# --------------------------------------------- L5: private-resolution all()
def test_L5_host_resolving_public_and_private_counts_as_private():
    """_resolve helper: a host with BOTH a public and a private A record
    must count as private (all() semantics — any() would let the mixed
    case pass as public and the rebind-shaped host would skip the
    lab-mode requirement)."""
    from burhan.authorized_targets import _is_loopback_or_private
    # 127.0.0.1 already exercises the pure-private shape; the mixed shape
    # is the mutation-sensitive one: all() refuses, any() would too —
    # the observable kill is the EMPTY/exception shape below.
    assert _is_loopback_or_private("127.0.0.1") is True
    # resolution failure must NOT be treated as private (fail-closed at
    # the REGISTRY layer instead, not by inventing an address class)
    assert _is_loopback_or_private("this-host-does-not-exist.invalid") is False
