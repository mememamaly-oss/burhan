"""Round 14 — guaranteed resource teardown on a crashed scan.

The finding: BurhanScanner.run() was a 2000-line straight line with no
top-level try/finally — the browser engine closed only at its own phase's
end, and OAST teardown was the caller's responsibility alone. A crash
between browser start and phase end leaked the playwright chromium
process; a crash anywhere leaked OAST listener threads.

The fix: run() is now a guarded wrapper (teardown in finally). This test
proves it with failure injection: a phase that raises mid-run must still
leave (a) no browser object attached, (b) the OAST server stopped.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest


def _scanner(tmp_path):
    from burhan.oast import OastServer
    from burhan.orchestrator import BurhanScanner, ScanConfig
    oast = OastServer()
    cfg = ScanConfig(allow_private=True, max_pages=1, timeout=3.0,
                     seed="teardown14" * 3, oast=oast, max_requests=10,
                     workflow=False, logic_active=False)
    return BurhanScanner("http://127.0.0.1:1", cfg), oast  # port 1: refuses


def test_crashed_scan_still_tears_down_oast(tmp_path):
    sc, oast = _scanner(tmp_path)
    live_threads_before = threading.active_count()

    def explode():
        raise RuntimeError("injected mid-scan failure (r14 teardown proof)")

    # inject the failure right at the start of the phases
    sc._run_phases = explode
    with pytest.raises(RuntimeError):
        sc.run()

    # the OAST HTTP server thread must be gone:
    names = [t.name for t in threading.enumerate()]
    assert not any("ThreadingHTTPServer" in n or "oast" in n.lower()
                   for n in names), names
    # and double-stop (the caller's own finally) stays safe:
    oast.stop()


def test_crashed_scan_closes_browser(tmp_path):
    sc, _ = _scanner(tmp_path)

    class FakeBrowser:
        closed = 0

        def close(self):
            self.closed += 1

    fb = FakeBrowser()
    sc.browser = fb  # as if the browser phase had started

    def explode():
        raise RuntimeError("crash after browser start")

    sc._run_phases = explode
    with pytest.raises(RuntimeError):
        sc.run()
    assert fb.closed == 1, "run() must close the browser on the crash path"


def test_normal_run_teardown_is_idempotent(tmp_path):
    """A normal caller pattern (finally: oast.stop()) must not break when
    run() already stopped it."""
    sc, oast = _scanner(tmp_path)
    sc._run_phases = lambda: {"findings": [], "stats": {"requests": 0}}
    rep = sc.run()
    assert rep == {"findings": [], "stats": {"requests": 0}}
    oast.stop()  # the caller's own finally — must be a no-op, not an error
