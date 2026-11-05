"""Part 2.5 — replay gate tests (loopback fixture; the third leg uses a
non-authorized host so ZERO live requests are sent)."""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from burhan.replay import (replay_finding_gated, ReplayRateLimited,
                           REPLAY_MIN_INTERVAL_SECONDS)


class _VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        # "vulnerable": boolean oracle — probe values carrying the TRUE-ish
        # marker answer 200, everything else 500 (the replay engine's
        # two-round differential needs a difference). "Fixed": always 200.
        fixed = Path("/tmp/.replay-fixed").exists()
        import urllib.parse as _up
        q = _up.unquote_plus(self.path).lower()
        # TRUE-assertion payloads answer 200, FALSE-assertion answer 500 —
        # a real boolean oracle (the differential the engine verifies)
        false_assert = any(m in q for m in ("1=2", "1'='2", "1%27=%272",
                                            "'1'='2", "== '2'", "== 2"))
        true_assert = any(m in q for m in ("1=1", "1'='1", "'1'='1",
                                           "== '1'", "== 1", "1%27=%271"))
        vuln_resp = 500 if false_assert else (200 if true_assert else 500)
        code = 200 if fixed else vuln_resp
        self.send_response(code); self.end_headers()
        self.wfile.write(b"clean" if fixed else b"oracle")

def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def srv():
    s = _serve()
    yield s
    s.shutdown(); s.server_close()


def _proof(port):
    url = f"http://127.0.0.1:{port}/vault/transfer"
    return {"finding_id": "F-test000001", "type": "sql_injection",
            "requests": [{"url": url, "parameter": "acct", "method": "GET"}],
            "verification": {"method": "oracle:replay-2round", "passed": True}}


def test_red_replay_reproduces(srv, tmp_path, monkeypatch):
    Path("/tmp/.replay-fixed").unlink(missing_ok=True)
    monkeypatch.setattr("burhan.replay._RATE_FILE", tmp_path / "rl.json")
    r = replay_finding_gated(_proof(srv.server_address[1]))
    assert r["replay"] == "REPRODUCTION_VERIFIED"
    assert r["lifecycle_event"] == "REPRODUCTION_VERIFIED"
    assert r["registry_entry"] == "self-hosted-fixtures"   # loopback entry


def test_blue_replay_not_reproduced_is_not_error(srv, tmp_path, monkeypatch):
    Path("/tmp/.replay-fixed").write_text("fixed")
    try:
        monkeypatch.setattr("burhan.replay._RATE_FILE", tmp_path / "rl2.json")
        r = replay_finding_gated(_proof(srv.server_address[1]))
        assert r["replay"] == "REPRODUCTION_FAILED"
        assert r["lifecycle_event"] == "REPRODUCTION_NOT_REPRODUCED"
    finally:
        Path("/tmp/.replay-fixed").unlink(missing_ok=True)


def test_refusal_target_not_in_registry(tmp_path, monkeypatch):
    monkeypatch.setattr("burhan.replay._RATE_FILE", tmp_path / "rl3.json")
    proof = _proof(80)
    proof["requests"][0]["url"] = "http://not-authorized.invalid/vault/transfer"
    r = replay_finding_gated(proof)
    assert r["replay"] == "REFUSED"
    assert r["live_requests_sent"] == 0
    assert "NOT PRESENT" in r["reason"] or "authorization gate" in r["reason"]


def test_rate_limit_per_finding(srv, tmp_path, monkeypatch):
    monkeypatch.setattr("burhan.replay._RATE_FILE", tmp_path / "rl4.json")
    p = _proof(srv.server_address[1])
    replay_finding_gated(p)                       # first replay OK
    with pytest.raises(ReplayRateLimited):
        replay_finding_gated(p)                   # immediate second: refused
    # a DIFFERENT identity is not blocked (per-finding granularity)
    p2 = dict(p); p2["finding_id"] = "F-other00001"
    p2["requests"] = [dict(p["requests"][0], parameter="other")]
    r = replay_finding_gated(p2)
    assert r["replay"] in ("REPRODUCTION_VERIFIED", "REPRODUCTION_FAILED",
                           "NOT_REPLAYABLE")
