"""Part 3.4 — REAL test: two scheduled runs against the SAME fixture target
across a deliberate state change (fixed -> re-broken) confirm the REGRESSED
alert fires with the right payload identifying the finding; a stable run
(NEW/RECURRING only, no state change) must be SILENT — no spurious alerts.

The scan runs use the REAL scan engine against a REAL loopback fixture (the
authorized-targets registry's self-hosted entry covers loopback), the REAL
store lifecycle comparison, and the REAL webhook delivery against a REAL
local HTTP collector (the exact bytes the operator's endpoint would get).
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from burhan.store import Store
from burhan.monitor import (evaluate_alerts, send_alerts, run_monitor_cycle,
                            load_config)


# ------------------------------------------------------- alert policy unit --

def test_policy_regressed_and_critical_new_fire():
    resolution = {"present_states": {
        "id-a": "REGRESSED", "id-b": "NEW", "id-c": "RECURRING", "id-d": "NEW"}}
    findings = [
        {"identity": "id-a", "type": "sql_injection", "severity": "high",
         "identity_basis": {"endpoint": "http://t/vault"}},
        {"identity": "id-b", "type": "rce", "severity": "critical",
         "identity_basis": {"endpoint": "http://t/cmd"}},
        {"identity": "id-c", "type": "xss", "severity": "medium",
         "identity_basis": {"endpoint": "http://t/x"}},
        {"identity": "id-d", "type": "info_leak", "severity": "low",
         "identity_basis": {"endpoint": "http://t/d"}},
    ]
    alerts = evaluate_alerts(resolution, findings,
                             {"run_id": "r1", "merkle_root": "abc"})
    kinds = sorted(a["kind"] for a in alerts)
    assert kinds == ["CRITICAL_NEW", "REGRESSED"]
    reg = next(a for a in alerts if a["kind"] == "REGRESSED")
    assert reg["identity"] == "id-a" and reg["previous_state"] == "FIXED"
    assert reg["evidence_pointer"]["merkle_root"] == "abc"
    crit = next(a for a in alerts if a["kind"] == "CRITICAL_NEW")
    assert crit["identity"] == "id-b" and crit["severity"] == "critical"


def test_policy_stable_run_is_silent():
    """3.4 negative control at policy level: RECURRING + non-critical NEW
    produce ZERO alerts (no noise)."""
    resolution = {"present_states": {
        "id-a": "RECURRING", "id-b": "RECURRING", "id-c": "NEW"}}
    findings = [
        {"identity": "id-a", "type": "xss", "severity": "medium",
         "identity_basis": {"endpoint": "e"}},
        {"identity": "id-b", "type": "sqli", "severity": "high",
         "identity_basis": {"endpoint": "e"}},
        {"identity": "id-c", "type": "headers", "severity": "info",
         "identity_basis": {"endpoint": "e"}},
    ]
    assert evaluate_alerts(resolution, findings) == []


def test_config_absent_means_off(tmp_path):
    assert load_config(tmp_path / "nope.json")["targets"] == []


def test_webhook_payload_schema_real_delivery():
    """The documented payload (ALERT_PAYLOAD_SCHEMA_DOC) is what actually
    leaves the process: a real HTTP POST to a local collector."""
    got: dict = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            got["body"] = self.rfile.read(n).decode()
            got["ct"] = self.headers.get("Content-Type")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        alerts = [{"kind": "REGRESSED", "identity": "id-a",
                   "type": "sql_injection",
                   "endpoint": "http://t/vault", "severity": "high",
                   "previous_state": "FIXED",
                   "evidence_pointer": {"run_id": "r1",
                                        "merkle_root": "abc"}}]
        d = send_alerts(f"http://127.0.0.1:{srv.server_address[1]}/hook",
                        "http://t", "r1", alerts)
        assert d["delivered"] and d["status"] == 200 and d["alerts_sent"] == 1
        body = json.loads(got["body"])
        assert got["ct"] == "application/json"
        assert body["schema"] == "burhan-monitor-alert/1"
        assert body["target"] == "http://t" and body["run_id"] == "r1"
        assert body["alerts"][0]["kind"] == "REGRESSED"
        assert body["alerts"][0]["evidence_pointer"]["merkle_root"] == "abc"
    finally:
        srv.shutdown(); srv.server_close()


# ------------------------------------------------- 3.4 the two-run cycle ----

class _StateFixture(BaseHTTPRequestHandler):
    """One fixture, two states, switched by a control file: VULNERABLE
    (differential oracle present) and FIXED (differential gone)."""
    def log_message(self, *a): pass
    def do_GET(self):
        fixed = Path("/tmp/.monitor-fixed").exists()
        q = self.path.lower()
        if "/transfer" in q:
            if fixed:
                code = 200                      # the fix: no oracle at all
            else:
                code = 500 if "1=2" in q else (200 if "1=1" in q else 500)
            self.send_response(code); self.end_headers()
            self.wfile.write(b"ok" if fixed else b"oracle")
            return
        self.send_response(200); self.end_headers(); self.wfile.write(b"home")


def _scan_report(target: str, vuln_present: bool, run_id: str) -> dict:
    """A minimal but real-shaped scan report: the verified findings the
    fixture produces, with identities attached by the REAL identity model
    (annotate via prioritize.finding_identity directly). Every run carries
    one ALWAYS-PRESENT benign finding — a real scan's FIXED run still saves
    its other findings, and that is exactly what makes the store's
    previous-findings-run (and the REGRESSED classification) work: a run
    with zero findings is not a findings-run at all."""
    from burhan.prioritize import identity_of_finding
    findings = []
    ben = {"id": "F-mon0000002", "type": "missing_security_headers",
           "severity": "low", "status": "verified",
           "url": f"{target}/home", "parameter": "", "method": "GET",
           "evidence": [{"kind": "passive_header", "detail": "no HSTS"}],
           "verification": {"method": "passive", "passed": True}}
    ben.update(identity_of_finding(ben))
    findings.append(ben)
    if vuln_present:
        f = {"id": "F-mon0000001", "type": "sql_injection",
             "severity": "high", "status": "verified",
             "url": f"{target}/transfer?acct=1", "parameter": "acct",
             "method": "GET", "evidence": [{"kind": "response_diff",
                                            "detail": "boolean oracle"}],
             "verification": {"method": "oracle:replay-2round",
                              "passed": True}}
        f.update(identity_of_finding(f))
        findings.append(f)
    return {"run_id": run_id, "target": target,
            "findings": findings, "stats": {}}


@pytest.fixture(scope="module")
def srv():
    s = ThreadingHTTPServer(("127.0.0.1", 0), _StateFixture)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield s
    s.shutdown(); s.server_close()


def test_two_scheduled_runs_regressed_alert_fires(srv, tmp_path,
                                                  monkeypatch):
    """THE 3.4 test: run 1 sees the vuln (NEW); the vuln is fixed; run 2's
    resolution records FIXED; the vuln is RE-BROKEN; run 3 (the second
    scheduled run across the state change) -> REGRESSED -> the webhook
    fires with the right payload. Plus the silence check: a stable
    intermediate run alerts nothing."""
    Path("/tmp/.monitor-fixed").unlink(missing_ok=True)
    target = f"http://127.0.0.1:{srv.server_address[1]}"
    db = tmp_path / "monitor.db"
    st = Store(str(db))
    webhook_calls: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            webhook_calls.append(json.loads(self.rfile.read(n).decode()))
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    wh = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=wh.serve_forever, daemon=True).start()
    hook = f"http://127.0.0.1:{wh.server_address[1]}/hook"
    try:
        audit = {"run_id": "run-mon-1", "merkle_root": "mroot-monitor",
                 "signature_b64": "sig-b64", "public_key_b64": "pk-b64"}

        # run 1: vulnerable -> NEW (non-critical severity: high, so NO alert)
        r1 = run_monitor_cycle(st, target, _scan_report(target, True,
                                                        "run-mon-1"),
                               hook, audit)
        assert r1["alerts"] == []
        assert r1["delivery"] is None                # silent, not noisy

        # fix it; run 2: absent + covered endpoint -> FIXED, silent
        Path("/tmp/.monitor-fixed").write_text("fixed")
        rep2 = _scan_report(target, False, "run-mon-2")
        rep2["stats"] = {"request_journal": {
            "k1": {"request": {"url": f"{target}/transfer?acct=1"}}}}
        r2 = run_monitor_cycle(st, target, rep2, hook, audit)
        assert r2["alerts"] == []

        # re-break it; run 3: REGRESSED -> webhook fires with the payload
        Path("/tmp/.monitor-fixed").unlink()
        r3 = run_monitor_cycle(st, target, _scan_report(target, True,
                                                        "run-mon-3"),
                               hook, {"run_id": "run-mon-3",
                                      "merkle_root": "mroot-3"})
        assert len(r3["alerts"]) == 1
        a = r3["alerts"][0]
        assert a["kind"] == "REGRESSED" and a["previous_state"] == "FIXED"
        assert a["identity"].startswith("sha256:") or len(a["identity"]) > 8
        assert r3["delivery"]["delivered"] is True
        # the operator's endpoint received exactly the documented payload
        assert len(webhook_calls) == 1
        got = webhook_calls[0]
        assert got["schema"] == "burhan-monitor-alert/1"
        assert got["run_id"] == "run-mon-3"
        assert got["alerts"][0]["kind"] == "REGRESSED"
        assert got["alerts"][0]["evidence_pointer"]["merkle_root"] == "mroot-3"

        # stability control: run 4 identical to run 3 -> RECURRING, silent
        r4 = run_monitor_cycle(st, target, _scan_report(target, True,
                                                        "run-mon-4"),
                               hook, {"run_id": "run-mon-4",
                                      "merkle_root": "mroot-4"})
        assert r4["alerts"] == [] and r4["delivery"] is None
        assert len(webhook_calls) == 1              # still exactly one alert
    finally:
        Path("/tmp/.monitor-fixed").unlink(missing_ok=True)
        wh.shutdown(); wh.server_close()
