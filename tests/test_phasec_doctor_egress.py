#!/usr/bin/env python3
"""phaseC (owner order 2026-11-12, task 5): doctor's network_egress check
must not hold CI hostage to one third-party host.

The contract under test (mirrors the OAST providers' WARN contract):
  * all probe hosts unreachable  -> status WARN (degraded egress), NOT
    FAIL — the engine's core loop needs no outbound internet, so doctor
    must stay exit-0 green (cli fails ONLY on a FAIL check, R17-2).
  * any probe host reachable     -> PASS with the working host named.

Observed live: scanme.nmap.org (45.33.32.156) went dark world-wide for
~5.5h (08:50-14:30Z, 2026-11-12) and reddened every Engine job (Linux +
macOS) on docs-only PRs. The check now probes scanme.nmap.org:443,
scanme.nmap.org:80, then github.com:443, and downgrades total failure
to WARN.
"""
import socket

from burhan.orchestrator import doctor


def _check(report, name):
    for c in report["checks"]:
        if c["check"] == name:
            return c
    raise AssertionError(f"doctor report has no {name!r} check")


def test_network_egress_all_unreachable_is_warn_not_fail(monkeypatch):
    """Every probe target unreachable -> WARN, so doctor exit stays 0."""
    def dead_create_connection(addr, timeout=None):
        raise OSError(101, "Network is unreachable")

    monkeypatch.setattr(socket, "create_connection", dead_create_connection)
    report = doctor()
    c = _check(report, "network_egress")
    assert c["status"] == "WARN", (
        f"expected WARN (degraded egress, not engine failure), got "
        f"{c['status']!r} — a dead third-party host must not FAIL the "
        f"doctor gate (phaseC 2026-11-12 scanme outage lesson)"
    )
    assert c["detail"].startswith("warn:"), c["detail"]
    # the whole report must contain zero FAILs so the R17-2 exit stays 0
    fails = [x for x in report["checks"] if x["status"] == "FAIL"]
    assert not fails, f"unexpected FAILs with dead egress: {[x['check'] for x in fails]}"


def test_network_egress_first_host_reachable_is_pass_with_host_named(monkeypatch):
    """scanme.nmap.org:443 reachable -> PASS naming that host:port."""
    def alive_first(addr, timeout=None):
        raise OSError(101, "Network is unreachable")

    # unreachable scanme (both ports), reachable github.com:443
    def selective(addr, timeout=None):
        host, port = addr
        if host == "github.com" and port == 443:
            class _S:  # minimal stand-in for a closed socket
                def close(self):
                    pass
            return _S()
        raise OSError(101, "Network is unreachable")

    monkeypatch.setattr(socket, "create_connection", selective)
    report = doctor()
    c = _check(report, "network_egress")
    assert c["status"] == "PASS", c
    assert "github.com:443" in c["detail"], c["detail"]
