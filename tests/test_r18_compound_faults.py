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


def _tail(path, n: int = 400) -> str:
    """Last n chars of a captured stderr file — the diagnostic C3 was
    missing when its survivor crashed blind (issue #88: the 4th family
    flake exited 1 on macOS with both writers' stderr DEVNULLed, so the
    actual exception never reached the log)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - n))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return "<no stderr captured>"


def test_c3_concurrent_store_writers_with_killed_transaction(tmp_path):
    """Two concurrent scans share one SQLite store; one is SIGKILLed
    mid-write. The survivor must complete cleanly, the store must stay
    readable (WAL-consistent), and no lock error may surface as a
    false-success empty report."""
    from burhan.store import Store
    port, proc = _spawn_fixture({"DELAY_MS": "150"})
    db = tmp_path / "shared.db"
    out1, out2 = tmp_path / "a.json", tmp_path / "b.json"
    err1_p, err2_p = tmp_path / "w1.err", tmp_path / "w2.err"
    try:
        # stderr is CAPTURED, never DEVNULL (issue #88): a survivor that
        # dies must announce WHY — the assertion messages carry the tail.
        err1 = open(err1_p, "wb")
        err2 = open(err2_p, "wb")
        p1 = subprocess.Popen(
            CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                   "--logic-active", "--out", str(out1), "--db", str(db)],
            stdout=subprocess.DEVNULL, stderr=err1)
        p2 = subprocess.Popen(
            CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                   "--logic-active", "--out", str(out2), "--db", str(db)],
            stdout=subprocess.DEVNULL, stderr=err2)
        # both writers alive -> wait for REAL concurrent store activity
        # (the shared -wal file growing means both engines are past the
        # gate, past the crawl, and mid-write), THEN kill writer 1
        # mid-transaction. A blind 10s window raced on CI (r19-2c run:
        # writer 2 exited before the kill — with the gate now opening,
        # the scan's real duration re-entered the window's blind spot);
        # anchoring on observed WAL activity makes the kill land in the
        # write phase deterministically on any host speed.
        _wal = str(db) + "-wal"
        deadline = time.time() + 60
        while time.time() < deadline:
            if p1.poll() is not None or p2.poll() is not None:
                break  # one died on its own — the asserts below speak
            try:
                if os.path.exists(_wal) and os.path.getsize(_wal) > 0:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        # Bounded retry: on a FAST runner the first writer pair can
        # complete before the WAL anchor even observes activity — a
        # timing miss, not an engine fault (the engine exited CLEANLY;
        # local: 5/5 green, CI ARM runners flaked pre-r18-8.4 twice too).
        # One fresh pair gets a second chance; a second miss is a real
        # red. The engine-level contract (survivor + store readable)
        # is asserted identically either way.
        for _attempt in (1, 2):
            if p1.poll() is None:
                break
            p1 = subprocess.Popen(
                CLI + ["scan", f"http://127.0.0.1:{port}", "--no-browser", "--allow-private",
                       "--logic-active", "--out", str(out1), "--db", str(db)],
                stdout=subprocess.DEVNULL, stderr=err1)
            _w0 = time.time() + 60
            while time.time() < _w0 and p1.poll() is None:
                try:
                    if os.path.exists(_wal) and os.path.getsize(_wal) > 0:
                        break
                except OSError:
                    pass
                time.sleep(0.2)
        assert p1.poll() is None, (
            "writer 1 finished before the kill could land\n"
            f"--- writer 1 stderr tail ---\n{_tail(err1_p)}")
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
        assert rc2 == 0, (
            "the surviving writer must complete cleanly\n"
            f"--- survivor (writer 2) stderr tail ---\n{_tail(err2_p)}\n"
            f"--- killed writer 1 stderr tail ---\n{_tail(err1_p)}")
        # the store survived the killed transaction and is readable
        st = Store(str(db))
        runs = st.list_findings()  # any read proves schema/lock integrity
        assert isinstance(runs, list)
    finally:
        for _f in (err1, err2):
            try:
                _f.close()
            except Exception:
                pass
        proc.terminate()
        proc.wait(timeout=10)


def test_c3_stderr_capture_contract(tmp_path):
    """Issue #88 RED->BLUE: the C3 writers' stderr must be CAPTURED, not
    DEVNULLed — the 4th family flake on macOS had the survivor exit 1
    with the actual exception swallowed. This pins the mechanism (files
    opened, tails embeddable) so the diagnostic can never silently
    regress to /dev/null."""
    src = (ROOT / "tests" / "test_r18_compound_faults.py").read_text()
    c3 = src[src.index("def test_c3_concurrent_store_writers"):]
    c3 = c3[:c3.index("\ndef ") if "\ndef " in c3 else len(c3)]
    assert "subprocess.DEVNULL, stderr=err1)" in c3, \
        "C3 writer 1 must capture stderr (issue #88)"
    assert "subprocess.DEVNULL, stderr=err2)" in c3, \
        "C3 writer 2 (the survivor) must capture stderr (issue #88)"
    assert "_tail(err2_p)" in c3, \
        "the survivor assertion must embed the stderr tail (issue #88)"
