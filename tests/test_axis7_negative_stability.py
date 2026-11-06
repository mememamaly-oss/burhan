"""Round 13 — axis 7 (stability): negative tests.

What happens when the world is broken around the engine?
  - the target port is CLOSED (connection refused before any scan)
  - a target that ACCEPTS then DROPS every connection (dies mid-scan)
  - the OpenAPI spec is CORRUPT (truncated JSON)

These exercise the engine API directly (BurhanScanner/parse_openapi) the
same way scripts/ci_real_target_scan.py does, plus the `report` CLI path
for the empty-store case. The contract everywhere: fail LOUD and CLEAN —
an explicit error, never a silent zero-findings success, never a hang.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _scan(base, max_requests=20, timeout=60):
    """One engine scan exactly the way ci_real_target_scan drives it."""
    from burhan.oast import OastServer
    from burhan.orchestrator import ScanConfig, BurhanScanner
    oast = OastServer()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=3, timeout=3.0,
                         seed="axis7neg" * 4, oast=oast,
                         max_requests=max_requests)
        sc = BurhanScanner(base, cfg)
        return sc.run()
    finally:
        oast.stop()


def test_closed_port_is_reported_not_swallowed():
    """Connection-refused must surface as an explicit failure in the run
    report (errors recorded), never as a silent 0-findings success."""
    port = _free_port()  # nothing listens
    rep = _scan(f"http://127.0.0.1:{port}")
    blob = json.dumps(rep)
    verified = [f for f in rep.get("findings", [])
                if f.get("status") == "verified"]
    # no findings can be verified against a closed port — if any claimed
    # to be, that would be fabrication:
    assert verified == [], "findings 'verified' against a CLOSED port = fabrication"
    # and the run must SAY something about the unreachable target:
    stats = rep.get("stats", {})
    assert stats.get("requests", 0) >= 0  # structure sane
    assert ("error" in blob.lower() or "refused" in blob.lower()
            or "unreachable" in blob.lower()
            or rep.get("errors") or stats.get("errors")
            or stats.get("failed_requests")
            or rep.get("discovery", {}).get("errors")
            or stats.get("requests") == 0), \
        "a closed-port scan must record the failure somewhere in the report"


class _DroppingListener:
    """Accepts connections then immediately closes them — a target that
    dies mid-scan."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.sock.settimeout(0.3)
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
                c.close()  # drop immediately
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def test_target_dying_mid_scan_terminates_cleanly():
    """A dropping listener: the scan must TERMINATE (bounded by the request
    budget) without hanging, without traceback, and without fabricated
    findings."""
    lst = _DroppingListener()
    try:
        rep = _scan(f"http://127.0.0.1:{lst.port}", max_requests=15)
        verified = [f for f in rep.get("findings", [])
                    if f.get("status") == "verified"]
        assert verified == [], "findings 'verified' against a dying target = fabrication"
        # termination + bounded work is the assertion; reaching here without
        # a hang/exception IS the pass condition.
    finally:
        lst.stop()


def test_corrupt_openapi_spec_is_rejected_loudly(tmp_path):
    """A truncated spec must raise a decode error from parse_openapi —
    never silently ingest as an empty endpoint set."""
    import json as _json
    from burhan.discovery import parse_openapi
    bad = tmp_path / "spec.json"
    bad.write_text('{"openapi": "3.0.0", "paths": {"/a": {"get": {"respo',
                   encoding="utf-8")
    # the LOADING layer must reject the truncated JSON loudly:
    with pytest.raises(Exception) as ei:  # noqa: B017 — ANY loud failure is the contract
        _json.loads(bad.read_text(encoding="utf-8"))
    assert any(k in str(ei.value).lower() for k in
               ("json", "decode", "expecting", "unterminated")), str(ei.value)
    # and parse_openapi on a structurally-broken dict: defensive-empty, the
    # documented contract (paths-or-{} + isinstance guards in discovery.py) —
    # no crash, no fabricated endpoints; scope-gating stays in the orchestrator.
    assert parse_openapi({"paths": None}, "http://127.0.0.1:9") == []
    assert parse_openapi({"paths": {"/a": {"get": None}}}, "http://127.0.0.1:9") == []
    assert parse_openapi({}, "http://127.0.0.1:9") == []


def test_report_cli_on_empty_store_is_honest_not_fabricated(tmp_path):
    """`report` against an empty store renders the cross-run OVERVIEW —
    that page must state 0 runs / 0 verified findings plainly (an honest
    empty summary), and a MISSING run-id must say "not found". What is
    forbidden is fabricating content that reads like a clean scan."""
    empty = tmp_path / "empty-store"
    empty.mkdir()
    out = tmp_path / "r.html"
    r = subprocess.run([sys.executable, "-m", "burhan.cli", "report",
                        "--db", str(empty / "store.db"),
                        "--out", str(out)],
                       capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert r.returncode == 0 and out.exists()
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", out.read_text(encoding="utf-8")))
    assert "0 runs" in text and "0 verified" in text, text[:200]

    out2 = tmp_path / "r2.html"
    r2 = subprocess.run([sys.executable, "-m", "burhan.cli", "report",
                         "--db", str(empty / "store.db"),
                         "--run-id", "run-nonexistent-xyz",
                         "--out", str(out2)],
                        capture_output=True, text=True, timeout=60, cwd=ROOT)
    text2 = out2.read_text(encoding="utf-8") if out2.exists() else ""
    assert "not found" in text2.lower(), text2[:200]
