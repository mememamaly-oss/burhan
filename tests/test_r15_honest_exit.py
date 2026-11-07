"""Round 15 — R15-2: a dead target must not look like a successful scan.

Phase C evidence (cli-dead-target leg): scanning an unreachable target
ended with exit code 0 and an empty report — failure dressed as success.
Root cause: the engine counted requests_sent but never transport failures,
and the CLI had no honest-exit logic.

Permanent regression: (1) engine counters classify transport errors;
(2) stats carry them; (3) the CLI exits 3 with an honest stderr diagnosis
when EVERY request died on the transport — and still exits 0 with the
report written when the target answers.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "burhan.cli"]
DEAD_PORT = 8895  # nothing listens here — the dead-target fixture


def test_engine_counts_transport_errors_by_kind():
    """A refused connection lands in the counters under 'refused'."""
    sys.path.insert(0, str(ROOT))
    from burhan.core import Endpoint, EventBus, ScopeRule
    from burhan.http_engine import RequestEngine, RequestMutation
    eng = RequestEngine(ScopeRule(allowed_hosts=["127.0.0.1"],
                                  allow_private=True),
                        EventBus("r15-2"), timeout=4.0)
    m = RequestMutation(endpoint=Endpoint(url=f"http://127.0.0.1:{DEAD_PORT}/x"),
                        method="GET")
    r = eng.send(m)
    assert r.status == 0 and r.error, "the dead request must fail honestly"
    assert eng.transport_errors == 1
    assert "refused" in eng.transport_error_kinds
    assert eng.transport_error_kinds["refused"] == 1


def test_cli_dead_target_exits_3_with_diagnosis(tmp_path):
    """The exact Phase C case: dead target -> honest failure, not exit 0."""
    out = tmp_path / "dead.json"
    r = subprocess.run(
        CLI + ["scan", f"http://127.0.0.1:{DEAD_PORT}/", "--allow-private",
               "--out", str(out)],
        capture_output=True, text=True, timeout=180, cwd=ROOT)
    assert r.returncode == 3, (
        f"dead target must exit 3 (honest failure), got {r.returncode}; "
        f"stderr={r.stderr[-300:]}")
    diag = json.loads(r.stderr.strip().splitlines()[-1])
    assert diag["scan_aborted"] == "transport"
    assert diag["requests"] >= 1
    assert diag["error_kinds"], "the diagnosis must name the error family"
    # the evidence trail is still written (report file exists, honest content)
    assert out.exists()
    rep = json.loads(out.read_text())
    assert rep["stats"]["transport_errors"] == rep["stats"]["requests"]


def test_cli_live_target_still_exits_zero(tmp_path):
    """The guard must NOT fire on a healthy target: same code path, exit 0."""
    port = 8896
    srv = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env={"PORT": str(port), "PATH": "/usr/bin:/bin"},
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        import time
        import urllib.request
        base = f"http://127.0.0.1:{port}"
        for _ in range(40):
            try:
                if urllib.request.urlopen(base + "/", timeout=2).status == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        out = tmp_path / "live.json"
        r = subprocess.run(
            CLI + ["scan", base + "/", "--allow-private",
                   "--out", str(out), "--max-pages", "2"],
            capture_output=True, text=True, timeout=240, cwd=ROOT)
        assert r.returncode == 0, r.stderr[-300:]
        rep = json.loads(out.read_text())
        assert rep["stats"]["requests"] > 0
        assert rep["stats"]["transport_errors"] < rep["stats"]["requests"], \
            "a healthy target must not be classified as transport-dead"
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
