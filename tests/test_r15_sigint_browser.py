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

VERIFIED SCOPE (r15 close-out, follow-up round): root cause pinned — an
external SIGINT during ANY sync-playwright dispatch tears the dispatcher
fiber; the in-flight call unwedges (with an error) but EVERY later _sync
call (page.close, add_cookies, ...) hangs forever, even on a killed
driver. Fix (three layers, all required):
  1. CLI SIGINT handler DEFERS (no KeyboardInterrupt) while a driver is
     alive; a wakeup-fd monitor thread SIGKILLs every registered driver
     (BrowserEngine's AND impact.py's private instance);
  2. sigint_seen() guards stop ALL further playwright calls (render,
     probe_dom_xss, _ensure, close) — the browser phase stands down;
  3. the CLI converts the flag into exit code 130 after the unwind.
Proof: 5/5 random-timing runs exit 130 in ~4s with zero orphaned
processes; removing the render() guard (mutation) wedges 5/5 runs.

Permanent regression, run as a REAL subprocess against the repo's own
vulnapp fixture (the browser phase actually launches there).
"""
from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

psutil = pytest.importorskip(
    "psutil",
    reason="headless-process accounting needs psutil (requirements-dev.txt)")

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
    # Capability gate: this test proves browser-phase interrupt behavior and
    # is ONLY meaningful where a real chromium exists. The engine job of CI
    # installs no browser (a different job does); there the engine itself
    # degrades honestly to static DOM analysis — same contract here. Skip is
    # a capability statement, NOT a passed assertion: coverage of this path
    # is carried by environments with chromium (dev sandbox, fixture job).
    sys.path.insert(0, str(ROOT))
    from burhan.browser import browser_available
    if not browser_available():
        pytest.skip("playwright/chromium unavailable — browser-phase SIGINT "
                    "path not testable in this environment (engine degrades "
                    "to static DOM analysis by the same condition)")
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
            # the driver registers with the SIGINT sweep microseconds after
            # the process appears; give that bookkeeping a beat so the test
            # exercises the DEFERRED path deterministically, not the race
            time.sleep(1.0)
            p.send_signal(signal.SIGINT)
            # watchdog default is 10s; allow generous margin for slow CI
            deadline = time.time() + 45
            while time.time() < deadline and p.poll() is None:
                time.sleep(0.5)
            rc = p.poll()
            assert rc is not None, (
                "SIGINT during the browser phase still hangs the CLI — "
                "the deferred-interrupt unwedging failed")
            assert rc in (130, -2), (
                f"interrupted scan must exit 130 (or die by SIGINT), got {rc}")
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
