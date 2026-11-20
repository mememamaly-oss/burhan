"""r19-2.17 (owner order 2026-11-20, PR-A/3): the bare --replay path is gated.

Historical RED: `burhan reproduce --replay` ran burhan.evidence.replay_finding
with NO authorization — a stored proof re-executed live requests against
whatever origin the proof carried, even a target that has since left the
authorized-targets registry (the audit's P1-2 finding; the same proof reached
through --gated was checked, the same proof through --replay was not).

GREEN (the fix under test): both --replay and --gated now delegate to
burhan.replay.replay_finding_gated — live authorize() BEFORE any re-execution,
per-finding rate limit, refusal = exit 2 with zero live requests.

The tests drive the REAL CLI (subprocess, clean env like CI's pytest job)
against a REAL Store row carrying the proof, and a REAL loopback listener
that counts every live request the replay engine could send:
  1. RED-equivalent refusal: proof at an UNREGISTERED loopback target ->
     gate refuses, exit 2, listener hit ZERO times (the pre-fix code would
     have hit it — that is the recorded red).
  2. --gated stays the same path (same refusal, exit 2, zero requests).
  3. Mutation kill: with the registry in lab mode (authorize passes), the
     SAME proof DOES reach the listener — the refusal in test 1 is therefore
     produced by the gate and nothing else; neutering the gate erases
     exactly that difference and flips test 1.
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
    """Counts any live request the replay engine would send."""

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


def _start_listener(port):
    _Hit.hits = 0
    srv = HTTPServer(("127.0.0.1", port), _Hit)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _proof(url):
    # sql_injection: a REPLAYABLE class (evidence.REPLAYABLE_TYPES) — the
    # engine re-executes a live request for it, which is what the mutation
    # kill needs to observe on the listener.
    return {"finding_id": "F-replaytest01", "type": "sql_injection",
            "url": url, "parameter": "q",
            "requests": [{"method": "GET", "url": url, "status": 200}]}


def _make_db(tmp, url):
    """A real Store row carrying the proof, exactly like a finished scan."""
    sys.path.insert(0, str(ROOT))
    from burhan.store import Store
    db = tmp / "burhan.db"
    st = Store(str(db))
    report = {"run_id": "run-replaytest", "target": url, "seed": "s",
              "scanner": "burhan-test", "started": 0.0, "finished": 1.0,
              "findings": [{
                  "id": "F-replaytest01", "type": "sql_injection", "severity": "high",
                  "status": "verified", "url": url, "parameter": "q",
                  "method": "GET", "evidence": {"requests": [
                      {"method": "GET", "url": url, "status": 200}]}}],
              "stats": {"proofs": [_proof(url)]}}
    st.save_run(report)
    return db


def _registry(tmp):
    """A registry whose only entry is the self-hosted one — loopback
    targets pass ONLY when the lab mode is on (env BURHAN_LAB_MODE=1,
    the same switch the scan paths honor)."""
    reg = {"schema": 1, "targets": [
        {"id": "self-hosted-fixtures", "kind": "self-hosted",
         "match": {"host_suffix": None, "loopback_or_private": True},
         "proof": {"type": "ownership"}}]}
    p = tmp / "reg.json"
    p.write_text(json.dumps(reg), encoding="utf-8")
    return p


def _cli(tmp, db, registry, extra_args, lab_mode=False):
    """Run the real CLI in a clean env (env -i discipline, like CI)."""
    (tmp / "home").mkdir(exist_ok=True)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp / "home"),
           "PYTHONUTF8": "1",
           "BURHAN_AUTHORIZED_TARGETS": str(registry)}
    if lab_mode:
        env["BURHAN_LAB_MODE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "burhan.cli", "reproduce",
         "--finding", "F-replaytest01", "--db", str(db)] + extra_args,
        capture_output=True, text=True, timeout=180, cwd=str(ROOT), env=env)


def test_bare_replay_refused_zero_requests(tmp_path):
    """--replay against an unregistered loopback target: the gate refuses
    (exit 2) and the target listener sees ZERO live requests."""
    port = _free_port()
    srv = _start_listener(port)
    try:
        url = f"http://127.0.0.1:{port}/?q=1"
        db = _make_db(tmp_path, url)
        r = _cli(tmp_path, db, _registry(tmp_path), ["--replay"])
        assert r.returncode == 2, (r.returncode, r.stdout[-400:], r.stderr[-400:])
        out = r.stdout + r.stderr
        assert "REFUSED" in out or "refused" in out.lower() or \
            "authorization gate" in out.lower(), out[-400:]
        assert _Hit.hits == 0, \
            f"the replay engine sent {_Hit.hits} live request(s) — the gate " \
            f"must refuse BEFORE any re-execution"
    finally:
        srv.shutdown()


def test_gated_replay_same_refusal(tmp_path):
    """--gated keeps its historical contract: same refusal, exit 2, zero
    live requests (the two flags now share one gated path)."""
    port = _free_port()
    srv = _start_listener(port)
    try:
        url = f"http://127.0.0.1:{port}/?q=1"
        db = _make_db(tmp_path, url)
        r = _cli(tmp_path, db, _registry(tmp_path), ["--replay", "--gated"])
        assert r.returncode == 2, (r.returncode, r.stdout[-400:])
        assert _Hit.hits == 0
    finally:
        srv.shutdown()


def test_mutation_kill_gate_is_the_discriminator(tmp_path):
    """Kills the neuter-the-gate mutant (authorize -> always-ok inside
    replay_finding_gated). With the lab mode ON the SAME proof clears the
    gate — the result JSON carries `registry_entry: self-hosted-fixtures`
    and NO `authorization gate` refusal — while test 1, with the identical
    proof/registry but the lab mode OFF, gets exit 2, `replay: REFUSED`
    and the refusal reason. That PAIR is the discriminator: neutering the
    gate makes test 1's world identical to this one (no REFUSED, no
    gate reason), flipping its assertions. The `live_requests_sent: 1`
    field is corroborating only (the engine reports it for replayable
    classes); the verdict pair above is the load-bearing check."""
    port = _free_port()
    srv = _start_listener(port)
    try:
        url = f"http://127.0.0.1:{port}/?q=1"
        db = _make_db(tmp_path, url)
        r = _cli(tmp_path, db, _registry(tmp_path), ["--replay"], lab_mode=True)
        out = r.stdout + r.stderr
        # the gate PASSED: an entry id is named, no gate refusal anywhere
        assert "self-hosted-fixtures" in out, out[-400:]
        assert "authorization gate" not in out.lower(), out[-400:]
        assert "REFUSED" not in out, out[-400:]
        # a replayable class re-executed: the engine's own honest counter
        assert '"live_requests_sent": 1' in out, out[-400:]
    finally:
        srv.shutdown()
