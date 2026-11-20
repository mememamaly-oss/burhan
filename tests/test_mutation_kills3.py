"""RUN8-R2 kill tests for the SECURITY survivors (owner order item 2).

242 security survivors in 15 sites. One test per BEHAVIOURAL CONTRACT at
each site (a contract test kills every mutation of that contract's
expression family — this is how the earlier K1-K9/F1-L5 waves worked),
not one test per mutant: the owner's goal is "zero surviving SECURITY
mutants of the gate suite", and the suite must stay assertion-based.

Each test here targets a contract that at least one surviving security
mutant breaks. Verification protocol per test (owner's red→green rule):
  1. RED:   run the test with the target mutant(s) active
            (MUTANT_UNDER_TEST=...) — must FAIL with an assertion;
  2. GREEN: run the test on unmutated code — must PASS.
After all tests land, re-run every SECURITY survivor against the new
suite (campaign re-verification) — the target is zero survivors.
"""
from __future__ import annotations
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.ownership import _same_origin, WELL_KNOWN_PATH  # noqa: E402
from burhan import lab_mode as lm  # noqa: E402
from burhan.authorized_targets import (  # noqa: E402
    _host_of, _normalize_page_text, load_registry,
    authorize as _authorize)


# ────────────────────────────────────────────────────────────────
# S1 — _same_origin: default-port + scheme normalization contracts
#     kills: mutmut_7/12/16/21/25/26 family (port 80→81, or-True,
#     hostname "" → "XXXX")
# ────────────────────────────────────────────────────────────────
class TestSameOriginDefaults:
    def test_http_default_port_normalized_to_80(self):
        # a portless http origin IS the :80 origin — both directions
        assert _same_origin("http://example.com/a", "http://example.com:80/b") is True
        assert _same_origin("http://example.com:80/a", "http://example.com/b") is True

    def test_https_default_port_normalized_to_443(self):
        assert _same_origin("https://example.com/a", "https://example.com:443/b") is True

    def test_nonstandard_port_is_part_of_identity(self):
        # :8080 is a DIFFERENT origin than the portless default
        assert _same_origin("http://example.com/a", "http://example.com:8080/b") is False
        assert _same_origin("http://example.com:8080/a", "http://example.com/b") is False

    def test_missing_hostname_is_empty_not_sentinel(self):
        # hostname fallback must be "" — a sentinel like "XXXX" would
        # make two hostless URLs look SAME-origin
        assert _same_origin("http:///a", "http:///b") is True
        # and a hostless URL is never same-origin with a hosted one
        assert _same_origin("http:///a", "http://example.com/b") is False


# ────────────────────────────────────────────────────────────────
# S2 — lab_mode.is_lab_mode: default flag + env parsing contracts
#     kills: mutmut_1 (flag default True), mutmut_10 (env default)
# ────────────────────────────────────────────────────────────────
class TestLabModeDefaults:
    def test_default_flag_is_off(self, monkeypatch):
        monkeypatch.delenv(lm.ENV_VAR, raising=False)
        active, via = lm.is_lab_mode()
        assert active is False          # default must be INACTIVE
        assert via is None

    def test_env_default_is_empty_not_garbage(self, monkeypatch):
        # unset env must read as "" — a garbage default must never
        # accidentally match an activation token
        monkeypatch.delenv(lm.ENV_VAR, raising=False)
        assert lm.is_lab_mode()[0] is False
        monkeypatch.setenv(lm.ENV_VAR, "garbage-not-a-token")
        assert lm.is_lab_mode()[0] is False

    def test_refusal_reason_names_both_channels(self, monkeypatch):
        monkeypatch.delenv(lm.ENV_VAR, raising=False)
        reason = lm.refusal_reason("127.0.0.1")
        assert "--lab" in reason
        assert lm.ENV_VAR in reason


# ────────────────────────────────────────────────────────────────
# S3 — _host_of: IDN handling + host extraction contracts
#     kills: mutmut_5/11/17 family
# ────────────────────────────────────────────────────────────────
class TestHostOf:
    def test_ascii_host_passthrough_lowercased(self):
        assert _host_of("https://Example.COM/path") == "example.com"

    def test_missing_host_is_empty_string(self):
        # no sentinel: the authorize gate refuses empty hosts by name
        assert _host_of("file:///no/host") == ""

    def test_idn_punycode_roundtrip(self):
        # non-ascii hosts take the idna branch and come back ascii
        h = _host_of("https://büro.example.com/")
        assert h == "xn--bro-hoa.example.com"

    def test_empty_host_falsy_semantics(self):
        # `host and not host.isascii()` — empty host must stay falsy
        # (an `or` mutation sends "" into idna.encode -> crash-shape)
        assert not _host_of("")


# ────────────────────────────────────────────────────────────────
# S4 — _normalize_page_text: quote-extraction substrate contracts
#     kills: mutmut_2/3/11 family (None substrate, broken tag-strip)
# ────────────────────────────────────────────────────────────────
class TestNormalizePageText:
    def test_html_unescaped(self):
        out = _normalize_page_text("perm&amp;ission to scan")
        assert "perm&ission" in out

    def test_tags_become_spaces(self):
        out = _normalize_page_text("permission<br>to scan")
        assert "permission" in out and "to scan" in out
        # the tag itself must NOT survive into the flattened text
        assert "<br>" not in out

    def test_whitespace_collapsed(self):
        out = _normalize_page_text("a\t \n b")
        assert "a b" in out

    def test_none_page_text_is_error_not_silent(self):
        # the fetch contract returns str; None must not silently
        # normalize into a permissive quote substrate
        with pytest.raises(Exception):
            _normalize_page_text(None)  # type: ignore[arg-type]


# ────────────────────────────────────────────────────────────────
# S5 — load_registry: fail-closed channel contracts
#     kills: mutmut_3/4/11 family (banner → None, stderr → None)
# ────────────────────────────────────────────────────────────────
class TestLoadRegistryFailClosed:
    def test_missing_registry_raises(self, tmp_path, capsys):
        missing = tmp_path / "nope.json"
        with pytest.raises(SystemExit) as ei:
            load_registry(str(missing))
        assert ei.value.code == 2
        # the refusal banner goes to STDERR (not stdout, not nowhere)
        err = capsys.readouterr().err
        assert "authorized-targets.json" in err
        assert "no target may be scanned" in err

    def test_empty_targets_list_refused(self, tmp_path):
        p = tmp_path / "reg.json"
        p.write_text(json.dumps({"targets": []}), encoding="utf-8")
        with pytest.raises(SystemExit):
            load_registry(str(p))


# ────────────────────────────────────────────────────────────────
# S6 — authorize: verdict integrity contracts (no-host, loopback
#      flag) — kills mutmut_7 (True on no-host), mutmut_18 (or)
# ────────────────────────────────────────────────────────────────
class TestAuthorizeVerdicts:
    def test_url_without_host_refused(self, tmp_path, monkeypatch):
        reg = tmp_path / "reg.json"
        reg.write_text(json.dumps({"targets": [{
            "id": "pub1", "kind": "dns_txt", "covers": ["example.com"],
            "match": {"host_suffix": "example.com"},
            "proof": {"type": "dns_txt", "token": "y" * 32},
        }]}), encoding="utf-8")
        ok, reason, eid = _authorize("file:///etc/passwd", str(reg))
        assert ok is False
        assert "no host" in reason

    def test_loopback_flag_never_authorizes_non_selfhosted(self, tmp_path, monkeypatch):
        # an entry with loopback_or_private=True but NOT self-hosted
        # must not authorize loopback targets (the `and` contract)
        reg = tmp_path / "reg.json"
        reg.write_text(json.dumps({"targets": [{
            "id": "t1", "kind": "dns_txt", "covers": ["127.0.0.1"],
            "match": {"loopback_or_private": True},
            "proof": {"type": "dns_txt", "token": "x" * 32},
        }]}), encoding="utf-8")
        monkeypatch.delenv(lm.ENV_VAR, raising=False)
        ok, reason, eid = _authorize("http://127.0.0.1:8080/", str(reg))
        assert ok is False


# ────────────────────────────────────────────────────────────────
# S7 — _is_loopback_or_private: resolver-path contracts
#     kills mutmut_1/4/8 family (None into ip_address/getaddrinfo)
# ────────────────────────────────────────────────────────────────
from burhan.authorized_targets import _is_loopback_or_private  # noqa: E402

class TestIsLoopbackOrPrivate:
    def test_literal_loopback(self):
        assert _is_loopback_or_private("127.0.0.1") is True

    def test_literal_private(self):
        assert _is_loopback_or_private("10.0.0.5") is True
        assert _is_loopback_or_private("192.168.1.10") is True

    def test_public_literal_false(self):
        assert _is_loopback_or_private("93.184.216.34") is False

    def test_literal_loopback_ipv6(self):
        assert _is_loopback_or_private("::1") is True

    def test_private_range_literal(self):
        # 172.16/12 and 169.254/16 are private too
        assert _is_loopback_or_private("172.16.0.1") is True
        assert _is_loopback_or_private("169.254.1.1") is True


# ────────────────────────────────────────────────────────────────
# S8 — well-known fetch: scheme + path contracts
#     kills fetch_well_known mutmut_5 family, _fetch_with_injectable
#     mutmut_3 (rstrip(None) crash family) via contract shape
# ────────────────────────────────────────────────────────────────
class TestWellKnownUrlConstruction:
    def test_path_constant(self):
        assert WELL_KNOWN_PATH == "/.well-known/burhan-authorization.txt"

    def test_trailing_slash_stripped_before_path(self):
        from burhan.ownership import _fetch_with_injectable
        seen = {}
        def fake_fetch(url):
            seen["url"] = url
            return 200, {}, b"token"
        # base with trailing slash: the proof URL must not double-slash
        try:
            _fetch_with_injectable("http://example.com/", fake_fetch)
        except Exception:
            pass  # contract under test is the URL, not the verdict
        assert seen["url"] == "http://example.com" + WELL_KNOWN_PATH


# ────────────────────────────────────────────────────────────────
# S9 — _NoRedirect.redirect_request: same-origin delegation contract
#     kills the xǁ_NoRedirectǁ family (None req/newurl/super args)
# ────────────────────────────────────────────────────────────────
class TestNoRedirectDelegation:
    def test_same_origin_redirect_delegates_to_super(self):
        import urllib.request as _ur
        from burhan.ownership import _NoRedirect
        req = _ur.Request("http://example.com/a")
        nr = _NoRedirect()
        # same-origin: the parent handler is consulted (returns a real
        # Request to follow, not None and not a crash)
        out = nr.redirect_request(req, None, 302, "Found",
                                  {"Location": "http://example.com/b"},
                                  "http://example.com/b")
        assert out is not None
        assert urllib.parse.urlsplit(out.full_url).netloc == "example.com"

    def test_cross_origin_redirect_raises(self):
        import urllib.request as _ur
        from burhan.ownership import _NoRedirect
        req = _ur.Request("http://example.com/a")
        nr = _NoRedirect()
        # cross-origin hop: LOUD refusal (HTTPError), never a silent None
        with pytest.raises(urllib.error.HTTPError) as ei:
            nr.redirect_request(req, None, 302, "Found",
                                {"Location": "http://evil.example.net/b"},
                                "http://evil.example.net/b")
        assert "cross-origin redirect refused" in str(ei.value)


# ────────────────────────────────────────────────────────────────
# S10 — authorize: the self-hosted loopback entry requires BOTH
#      kind=self-hosted AND match.loopback_or_private (the `and`
#      contract). Kills x_authorize__mutmut_18 (and→or): an entry
#      that is self-hosted but carries NO loopback flag must NOT
#      authorize a loopback target, even in lab mode.
# ────────────────────────────────────────────────────────────────
class TestSelfHostedRequiresBothFlags:
    def test_selfhosted_entry_without_loopback_flag_refuses(self, tmp_path, monkeypatch):
        reg = tmp_path / "reg.json"
        reg.write_text(json.dumps({"targets": [{
            "id": "sh-noflag", "kind": "self-hosted",
            "covers": ["127.0.0.1"],
            "match": {},                     # NO loopback_or_private
            "proof": {},
        }]}), encoding="utf-8")
        monkeypatch.setenv(lm.ENV_VAR, "1")   # lab mode ACTIVE
        ok, reason, eid = _authorize("http://127.0.0.1:9999/", str(reg))
        # the `and` contract: missing flag => no authorization
        assert ok is False, (
            "a self-hosted entry WITHOUT match.loopback_or_private must "
            "not authorize a loopback target even in lab mode")
        assert "self-hosted" in reason or "NO self-hosted entry" in reason
