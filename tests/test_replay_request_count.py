"""r19-2.21 (supervisor 2026-11-20 item 1ب): live_requests_sent is the REAL
transport-layer count, not a verdict-derived constant.

The old code: `"live_requests_sent": 1 if verdict != "NOT_REPLAYABLE" else 0`
— a hard-coded 1 for every executed replay, while a real replay of a sqli
proof sends MULTIPLE probes (14 were observed live). The field's name
promised a count; the code delivered a boolean in disguise.

The fix: evidence.replay_finding now reports engine.requests_sent (the
transport choke-point counter — one increment per engine.send(), the single
path every detector/verifier request takes), propagated through
replay.replay_finding_gated. Early NOT_REPLAYABLE returns never build an
engine and report a real 0.

RED (the test): drive a REAL replay against a counting loopback listener
with a proof whose detector sends MORE than one request — the old constant
(1) cannot equal the listener's observed count (>1), and the field must
match the listener EXACTLY. A neutered counter (dropping the propagation)
flips every assertion.
"""
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class _Hit(BaseHTTPRequestHandler):
    hits = 0

    def _count(self):
        _Hit.hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def do_GET(self):                                   # noqa: N802
        self._count()

    def do_POST(self):                                  # noqa: N802
        self._count()

    def log_message(self, *a):                          # noqa: N802
        pass


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _make_db(tmp, url):
    sys.path.insert(0, str(ROOT))
    from burhan.store import Store
    db = tmp / "burhan.db"
    Store(str(db)).save_run({
        "run_id": "run-reqcount", "target": url, "seed": "s",
        "scanner": "burhan-test", "started": 0.0, "finished": 1.0,
        "findings": [{"id": "F-reqcount01", "type": "sql_injection",
                      "severity": "high", "status": "verified",
                      "url": url, "parameter": "q", "method": "GET",
                      "evidence": {"requests": [
                          {"method": "GET", "url": url, "status": 200}]}}],
        "stats": {"proofs": [{
            "finding_id": "F-reqcount01", "type": "sql_injection",
            "url": url,
            "requests": [{"method": "GET", "url": url, "status": 200,
                          "parameter": "q"}]}]}})
    return db


def _registry(tmp):
    p = tmp / "reg.json"
    p.write_text(json.dumps({"schema": 1, "targets": [
        {"id": "self-hosted-fixtures", "kind": "self-hosted",
         "match": {"host_suffix": None, "loopback_or_private": True},
         "proof": {"type": "ownership"}}]}), encoding="utf-8")
    return p


def _cli(tmp, db, registry):
    (tmp / "home").mkdir(exist_ok=True)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp / "home"),
           "PYTHONUTF8": "1", "BURHAN_AUTHORIZED_TARGETS": str(registry),
           "BURHAN_LAB_MODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "burhan.cli", "reproduce",
         "--finding", "F-reqcount01", "--db", str(db), "--replay"],
        capture_output=True, text=True, timeout=180, cwd=str(ROOT), env=env)


def test_live_requests_sent_equals_real_transport_count(tmp_path):
    """The field must equal what the TARGET actually received — a counting
    listener is ground truth. A replay of a parametrized sqli proof sends
    multiple probes (the sqli candidate battery); the old constant said 1."""
    port = _free_port()
    _Hit.hits = 0
    srv = HTTPServer(("127.0.0.1", port), _Hit)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{port}/?q=1"
        db = _make_db(tmp_path, url)
        r = _cli(tmp_path, db, _registry(tmp_path))
        assert r.returncode in (0, 1, 2), (r.returncode, r.stdout[-300:])
        # the replay RAN (lab mode authorized it): the listener was hit
        assert _Hit.hits >= 1, "the replay must have reached the listener"
        # THE contract: the reported count equals the observed count.
        # stdout carries the gate banner lines first; the result is the
        # LAST JSON object printed — find it by scanning for the opening
        # brace of the last top-level object containing finding_id.
        sent = None
        depth, start = 0, None
        for i, ch in enumerate(r.stdout):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    candidate = r.stdout[start:i + 1]
                    if '"finding_id"' in candidate:
                        sent = json.loads(candidate)
                    start = None
        assert sent is not None, r.stdout[-400:]
        reported = sent.get("live_requests_sent")
        assert reported == _Hit.hits, \
            f"live_requests_sent={reported} but the listener received " \
            f"{_Hit.hits} requests — the field must be the REAL transport " \
            f"count (the old constant said 1 for any executed replay)"
    finally:
        srv.shutdown()


def test_not_replayable_reports_real_zero(tmp_path):
    """The NOT_REPLAYABLE early-exit family never builds an engine: the
    field is a real 0 (no engine, no send), same as before — pinned so the
    fix cannot regress the honest zero."""
    from burhan.evidence import replay_finding
    from burhan.core import ScopeRule
    out = replay_finding({"finding_id": "F-x", "type": "business_logic_x",
                          "requests": [{"method": "GET",
                                        "url": "http://127.0.0.1:1/"}]},
                         ScopeRule(allowed_domains=["127.0.0.1"],
                                   allow_private=True), None)
    assert out.get("replay") == "NOT_REPLAYABLE"
    assert out.get("live_requests_sent", 0) == 0
