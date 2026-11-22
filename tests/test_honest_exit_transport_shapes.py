"""r19-3.6 (supervisor order 2026-11-21 item 3): the honest-exit
contract for the two transport shapes that made the macOS CI failure
ambiguous.

Live-verified BEFORE this file was written (both shapes, Linux):
- accept-then-immediately-close target: exit=3,
  scan_aborted=transport, requests=26, kinds={'reset': 25, 'other': 1}
- accept-then-stall target (connection held open, never answers):
  exit=3, scan_aborted=transport, requests=26, kinds={'timeout': 26}

The supervisor's rule: a scanner that reports SUCCESS (exit=0) against
a target which accepted the connection but never answered a single
HTTP response would be a product defect. These tests pin the honest
behavior so it cannot regress. They were written red-first mentally
(the experiment above IS the red run had the CLI answered 0) and pass
green against the current engine.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "burhan.cli"]


def _serve_immediate_close(port: int):
    """Shape 1: accept() then close() — zero bytes, instant FIN."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(10)
    s.settimeout(120)
    while True:
        try:
            c, _ = s.accept()
            c.close()
        except OSError:
            break


def _serve_accept_and_stall(port: int):
    """Shape 2: accept() and HOLD the connection open, never answering
    (the wedged-server shape; every request runs out the client
    timeout)."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(10)
    s.settimeout(120)
    held: list = []
    while True:
        try:
            c, _ = s.accept()
            held.append(c)  # never closed, never answered
        except OSError:
            for c in held:
                try:
                    c.close()
                except OSError:
                    pass
            break


def _run_scan(port: int, tmp_path: Path, timeout: float = 2.0) -> tuple:
    """Run the CLI against one of the shapes; returns (returncode,
    last-stderr-json-or-None, report-stats-or-None)."""
    import burhan.owner_gate as og
    gate = str(tmp_path / "gate.db")
    og.OwnerGate.setup(gate, "honest-shape-pass")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
           "BURHAN_LAB_MODE": "1",
           "BURHAN_OWNER_GATE": gate,
           "BURHAN_OWNER_PASSWORD": "honest-shape-pass"}
    out = tmp_path / "report.json"
    r = subprocess.run(
        CLI + ["scan", f"http://127.0.0.1:{port}/", "--allow-private",
               "--lab", "--no-browser", "--max-pages", "2",
               "--timeout", str(timeout), "--out", str(out)],
        capture_output=True, text=True, timeout=300, cwd=str(ROOT), env=env)
    diag = None
    lines = (r.stderr or "").strip().splitlines()
    if lines:
        try:
            diag = json.loads(lines[-1])
        except (ValueError, IndexError):
            diag = None
    stats = None
    if out.exists():
        try:
            stats = json.loads(out.read_text()).get("stats")
        except ValueError:
            stats = None
    return r.returncode, diag, stats


def test_accept_then_close_target_is_honest_failure(tmp_path):
    """A target that accepts and immediately closes every connection is
    a TRANSPORT FAILURE: exit != 0 with scan_aborted=transport — never
    a clean exit=0 'success'."""
    port = 9621
    t = threading.Thread(target=_serve_immediate_close, args=(port,),
                         daemon=True)
    t.start()
    rc, diag, stats = _run_scan(port, tmp_path)
    assert rc == 3, (rc, diag)
    assert diag and diag.get("scan_aborted") == "transport", diag
    assert diag.get("requests", 0) > 0, "the scanner must have TRIED"
    kinds = (diag.get("error_kinds") or {})
    assert sum(kinds.values()) == diag.get("requests"), (kinds, diag)


def test_accept_and_stall_target_is_honest_failure(tmp_path):
    """A target that accepts and holds every connection open without
    ever answering is a TRANSPORT FAILURE too: exit != 0 with
    scan_aborted=transport (every request classified 'timeout')."""
    port = 9623
    t = threading.Thread(target=_serve_accept_and_stall, args=(port,),
                         daemon=True)
    t.start()
    rc, diag, stats = _run_scan(port, tmp_path)
    assert rc == 3, (rc, diag)
    assert diag and diag.get("scan_aborted") == "transport", diag
    assert diag.get("requests", 0) > 0, "the scanner must have TRIED"
    kinds = (diag.get("error_kinds") or {})
    assert kinds.get("timeout", 0) == diag.get("requests"), (kinds, diag)
