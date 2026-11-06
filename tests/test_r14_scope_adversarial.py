"""Round 14 — Phase C2: adversarial transport-scope matrix (permanent).

The scope gate (_scope_ok) runs BEFORE every request and AFTER every
redirect hop. This matrix pins its adversarial behavior so the r13/r14
findings can never silently regress:

  - scheme allow-list (http/https only; ftp/file/gopher refused)
  - host allow-list: exact + dot-bounded domain suffix; lookalikes refused
  - private/loopback refusal in ALL spellings the resolver understands:
    127.0.0.1, short/hex/octal/decimal liberal IPv4 forms, IPv6 loopback,
    IPv4-mapped IPv6, link-local cloud metadata
  - fail-closed: an unresolvable host is REFUSED when allow_private is off
  - cross-host redirects: the engine must not follow (follow_cross_host
    defaults False) and must re-check scope per hop

Driven against the REAL RequestEngine scope gate — no mocks of the gate.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from burhan.core import EventBus, ScopeRule          # noqa: E402
from burhan.http_engine import RequestEngine         # noqa: E402


def _engine(**scope_kwargs):
    kw = dict(allowed_hosts=["target.example.com"],
              allowed_domains=["target.example.com"],
              allow_private=False)
    kw.update(scope_kwargs)
    return RequestEngine(ScopeRule(**kw), EventBus("run-c2-matrix"))


@pytest.mark.parametrize("url", [
    "ftp://target.example.com/",
    "file:///etc/passwd",
    "gopher://target.example.com/",
    "javascript:alert(1)",
])
def test_non_http_schemes_refused(url):
    ok, why = _engine()._scope_ok(url)
    assert not ok, url
    assert "scheme" in why


@pytest.mark.parametrize("url", [
    "http://evil.example.com/",
    "http://target.example.com.evil.com/",
    "http://eviltarget.example.com/",
    "http://not-target.example.com/",
])
def test_hosts_outside_the_allowlist_refused(url):
    ok, _ = _engine()._scope_ok(url)
    assert not ok, url


@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.1", "0x7f.0.0.1", "0x7f000001", "2130706433",
    "0177.0.0.1", "017700000001",
    "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1",
    "10.0.0.1", "192.168.1.1", "172.16.0.1",
    "169.254.169.254",
])
def test_private_and_loopback_spellings_refused_without_allow_private(host):
    ok, _ = _engine()._scope_ok(f"http://{host}/")
    assert not ok, host


def test_unresolvable_host_fails_closed_without_allow_private():
    """Ambiguity = refusal: an unresolvable host in a no-allow_private
    scope must never pass the gate (DNS failure is not a pass)."""
    ok, why = _engine()._scope_ok("http://target.example.com/")
    assert not ok and "private" in why


def test_allowed_host_with_allow_private_passes():
    ok, _ = _engine(allow_private=True)._scope_ok("http://target.example.com/")
    assert ok


def test_redirect_hop_matrix_blocked_targets():
    """The same gate re-runs per redirect hop: a Location pointing at a
    private spelling, a foreign host, or a forbidden scheme must be
    refused — exactly the URLs a malicious target would emit."""
    eng = _engine(allow_private=True)  # even permissive on private-ness
    for loc in ["http://evil.example.com/",
                "http://target.example.com.evil.com/",
                "ftp://target.example.com/"]:
        ok, why = eng._scope_ok(loc)
        assert not ok, (loc, why)


def test_cross_host_redirect_following_defaults_off():
    assert ScopeRule().follow_cross_host is False
