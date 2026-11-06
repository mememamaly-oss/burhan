"""Round 15 — R15-4: SIGINT during the browser phase must not hang forever.

Phase D evidence: Ctrl-C while chromium is active left the CLI process
alive indefinitely — the main thread stuck in playwright's _sync_base._sync
inside browser.close() (thread stack captured in the r15 evidence pack).
Root cause: SIGINT interrupted a greenlet dispatch; the sync channel never
resumed, and close() waited on an answer that would never come.

Fix attempt: (1) close() arms a watchdog that kills the playwright node
driver after CLOSE_WATCHDOG_S; (2) the CLI installs a SIGINT handler that
kills the in-flight scanner's node driver BEFORE raising KeyboardInterrupt,
un-wedging any interrupted _sync dispatch wherever it sits (page.close in
render(), browser.close in teardown, ...).

HONEST SCOPE (r15 close-out): the manual instrumented repro (evidence pack
phaseD) still hung once WITH the handler installed — the wedge window is
the exact moment a _sync dispatch is in flight, which this subprocess test
cannot force deterministically. This test therefore asserts the PROVEN
properties: clean exit (no infinite hang in the common interrupt paths)
and zero orphaned chrome-headless-shell processes. The wedge-window fix
is classified a remaining risk, not a verified fix.

Permanent regression, run as a REAL subprocess against the repo's own
vulnapp fixture (the browser phase actually launches there).
"""
from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _headless() -> int:
    return sum(1 for p in psutil.process_iter(["name"])
               if "headless" in (p.info["name"] or "").lower())


def _wait_headless(timeout: float = 90.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if _headless():
            return True
        time.sleep(0.3)
    return False


@pytest.mark.slow
def test_sigint_during_browser_phase_exits_cleanly():
    port = 8871
    app = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env={"PORT": str(port), "PATH": "/usr/bin:/bin"},
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        import urllib.request
        base = f"http://127.0.0.1:{port}"
        for _ in range(40):
            try:
                if urllib.request.urlopen(base + "/", timeout=2).status == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)

        p = subprocess.Popen(
            [sys.executable, "-m", "burhan.cli", "scan", base + "/",
             "--allow-private"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
        try:
            assert _wait_headless(), "browser never launched — test invalid"
            p.send_signal(signal.SIGINT)
            # watchdog default is 10s; allow generous margin for slow CI
            deadline = time.time() + 45
            while time.time() < deadline and p.poll() is None:
                time.sleep(0.5)
            rc = p.poll()
            assert rc is not None, (
                "SIGINT during the browser phase still hangs the CLI — "
                "the close watchdog did not un-wedge playwright")
            assert rc in (-2, 130, 0, 1), f"unexpected exit {rc}"
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()

        # the browser children must not survive the interrupted run
        deadline = time.time() + 10
        while time.time() < deadline and _headless():
            time.sleep(0.5)
        assert _headless() == 0, (
            "chrome-headless-shell processes survived the SIGINT teardown")
    finally:
        app.terminate()
        try:
            app.wait(timeout=5)
        except subprocess.TimeoutExpired:
            app.kill()
