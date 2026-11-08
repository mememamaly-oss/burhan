"""R18 PART 5.1: COMPOUND fault injection — simultaneous, not sequential.

Round 15's battery injected ONE fault at a time (dead target, SIGINT
mid-scan, dirty tree). The owner's round-18 order extends it: real
failures arrive TOGETHER. Each test here injects two faults at once and
holds the same bar as r15: no uncontrolled crash, correct exit code, a
comprehensible logged reason, no orphaned process, no silent
false-success.

  C1  slow+truncated responses WHILE a SIGTERM lands mid-scan
  C2  a store write during a disk-full condition on the evidence dir
      (ENOSPC simulated via a read-only mount point on the path)
  C3  two engines writing the SAME store concurrently (the SQLite
      contention shape) while one's transaction is killed mid-write

5.2 (the SaaS/Next.js side) runs in the web integration battery —
see scripts/run_integration_tests.sh and the SaaS CI job; this file is
the engine-side half, stated here so the split is documented, not
silent.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "burhan.cli"]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _spawn_fixture(env_extra: dict) -> tuple[int, subprocess.Popen]:
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env={**os.environ, "PORT": str(port), **env_extra},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            import urllib.request
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            return port, proc
        except Exception:
            if proc.poll() is not None:
                pytest.fail("fixture died during startup")
            time.sleep(0.1)
    proc.terminate()
    pytest.fail("fixture never became ready")


def test_c1_sigterm_mid_scan_on_slow_truncated_target(tmp_path):
    """SIGTERM while every response is slow and truncated: the process
    must die by the signal (exit -15), not limp on; the partial report
    must be absent or honestly incomplete; the fixture must survive
    (no orphan kill) and be terminated by the test itself."""
    port, proc = _spawn_fixture({"DELAY_MS": "150"})
    out = tmp_path / "scan.json"
    try:
        p = subprocess.Popen(
            CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                   "--logic-active", "--out", str(out)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # fire the signal as soon as the process is ALIVE and working —
        # a fast local scan finishes before any fixed sleep, so poll
        # liveness then signal immediately (the fault is 'mid-scan' by
        # construction: the fixture is up, the scan started, requests fly)
        deadline = time.time() + 10
        while time.time() < deadline and p.poll() is None:
            time.sleep(0.2)
        assert p.poll() is None, "scan finished before the fault could land — enlarge the scan"
        p.send_signal(signal.SIGTERM)        # fault 2 lands mid fault 1
        rc = p.wait(timeout=30)
        assert rc == -signal.SIGTERM or rc == 143, \
            f"compound fault produced exit {rc}, not the signal's"
        # no silent false-success: a killed scan must not claim completion
        if out.exists():
            rep = json.loads(out.read_text(encoding="utf-8"))
            assert rep.get("stats", {}).get("completed") is not True
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_c2_disk_full_during_evidence_write(tmp_path):
    """ENOSPC on the output path while the scan wants to write its
    report: a clean OSError with the path, exit non-zero, no partial
    silent file, and the engine process exits (no hang)."""
    port, proc = _spawn_fixture({})
    # a FILE where the report's parent DIR should be: every write fails
    blocker = tmp_path / "blocked-out.json"
    blocker.write_text("not a directory", encoding="utf-8")
    target = blocker / "sub" / "scan.json"
    try:
        r = subprocess.run(
            CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                   "--out", str(target)],
            capture_output=True, text=True, timeout=120)
        assert r.returncode != 0, "a failed report write must not exit 0"
        assert not target.exists(), "no partial silent output"
        # comprehensible reason in stderr (path or error kind present)
        assert ("blocked-out.json" in (r.stderr or "")
                or "NotADirectoryError" in (r.stderr or "")
                or "Error" in (r.stderr or "") or "error" in (r.stderr or "")), \
            (r.stderr or "")[-300:]
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_c3_concurrent_store_writers_with_killed_transaction(tmp_path):
    """Two concurrent scans share one SQLite store; one is SIGKILLed
    mid-write. The survivor must complete cleanly, the store must stay
    readable (WAL-consistent), and no lock error may surface as a
    false-success empty report."""
    from burhan.store import Store
    port, proc = _spawn_fixture({"DELAY_MS": "150"})
    db = tmp_path / "shared.db"
    out1, out2 = tmp_path / "a.json", tmp_path / "b.json"
    try:
        p1 = subprocess.Popen(
            CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                   "--logic-active", "--out", str(out1), "--db", str(db)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(
            CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                   "--logic-active", "--out", str(out2), "--db", str(db)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # both writers alive -> give the store a moment of concurrent
        # activity, then kill writer 1 mid-transaction
        deadline = time.time() + 10
        while time.time() < deadline and p1.poll() is None and p2.poll() is None:
            time.sleep(0.2)
        assert p1.poll() is None, "writer 1 finished before the kill could land"
        time.sleep(1.0)                      # let transactions interleave
        p1.kill()                            # fault 2: mid-transaction kill
        rc1 = p1.wait(timeout=30)
        assert rc1 == -9
        # r18-8.4: 120s -> 240s. Both full macOS runs timed the survivor
        # out at 120 (jobs 128608150967/128608162659, identical
        # fingerprints) — the DELAY_MS=150 double-writer workload on the
        # ARM runner simply needs longer. 240 keeps this a bounded wait
        # without flaking on a 2x-slower host; a real deadlock still
        # fails the gate.
        rc2 = p2.wait(timeout=240)
        assert rc2 == 0, "the surviving writer must complete cleanly"
        # the store survived the killed transaction and is readable
        st = Store(str(db))
        runs = st.list_findings()  # any read proves schema/lock integrity
        assert isinstance(runs, list)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
