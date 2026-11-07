"""R17-6: the readiness gate bounds TOTAL WAIT TIME, not iterations.

The live Windows finding: run_integration_tests.sh inlined a 60 x 1s
loop and declared FATAL at ~60s; on a loaded host the dev server
legitimately needed 126s to boot, so the runner called a healthy
server dead (false FATAL) and the whole integration phase aborted.

The fix contract, pinned here in both directions:
  - a SLOW-STARTING server (ready after several seconds, beyond what a
    short fixed loop would tolerate) is waited for and SUCCEEDS;
  - a genuinely DEAD endpoint still fails LOUDLY within the bound —
    the fix must not trade a false failure for an unbounded hang.

The RED side reproduces the OLD loop's logic at test scale (a 2 x 1s
loop vs a server that needs 3s -> false FATAL), then the same server
is served by the NEW helper with a real deadline -> READY.
"""
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "wait_ready.sh"
RUNNER = ROOT / "scripts" / "run_integration_tests.sh"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _OK(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _delayed_server(port, delay):
    def run():
        time.sleep(delay)
        srv = HTTPServer(("127.0.0.1", port), _OK)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    t = threading.Thread(target=run, daemon=True)
    t.start()


def test_old_iteration_count_loop_false_fatals_on_slow_start():
    """RED anchor: the OLD logic (fixed iteration count) declares a
    server that needs 3s dead under a 2-iteration budget — the exact
    false-FATAL class observed live (126s boot vs a 60x1s loop)."""
    port = _free_port()
    _delayed_server(port, delay=3.0)
    url = f"http://127.0.0.1:{port}/"
    # the old loop, verbatim semantics
    ready = 0
    for _ in range(2):
        time.sleep(1)
        r = subprocess.run(["curl", "-sf", "-m", "2", url],
                           capture_output=True)
        if r.returncode == 0:
            ready = 1
            break
    assert ready == 0, (
        "the old-loop reproduction did not false-FATAL — the RED anchor "
        "lost its meaning; increase the server delay or reduce iterations")


def test_wait_ready_succeeds_on_slow_start():
    """BLUE: the same slow server, waited for with a TOTAL-TIME bound
    (the observed 126s class, scaled): READY within the deadline."""
    port = _free_port()
    _delayed_server(port, delay=3.0)
    url = f"http://127.0.0.1:{port}/"
    r = subprocess.run(["bash", str(HELPER), url, "30"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"helper output: {r.stdout}{r.stderr}"
    assert "READY" in r.stdout


def test_wait_ready_fails_loudly_and_bounded_on_dead_endpoint():
    """The other half of the contract: a dead endpoint must exit 1
    within the bound — no unbounded hang — and say NOT-READY."""
    port = _free_port()  # nothing ever listens here
    url = f"http://127.0.0.1:{port}/"
    t0 = time.monotonic()
    r = subprocess.run(["bash", str(HELPER), url, "3"],
                       capture_output=True, text=True, timeout=60)
    elapsed = time.monotonic() - t0
    assert r.returncode == 1
    assert "NOT-READY" in r.stdout
    assert elapsed < 20, (
        f"a dead endpoint took {elapsed:.1f}s against a 3s budget — the "
        f"gate is unbounded, trading a false failure for a hang")


def test_timeout_is_configurable_via_env():
    """BURHAN_READY_TIMEOUT overrides the default budget (CI can tighten
    it on fast runners or widen it on loaded self-hosted ones)."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}/"
    env = {"BURHAN_READY_TIMEOUT": "2", "PATH": "/usr/bin:/bin"}
    t0 = time.monotonic()
    r = subprocess.run(["bash", str(HELPER), url],
                       capture_output=True, text=True, timeout=60, env=env)
    elapsed = time.monotonic() - t0
    assert r.returncode == 1
    assert 1.5 < elapsed < 10, (
        f"env-configured 2s budget behaved as {elapsed:.1f}s")


def test_runner_uses_the_helper_not_an_inline_loop():
    """The integration runner must route its READY gate through the
    helper (no regression to an inline iteration-count loop)."""
    text = RUNNER.read_text(encoding="utf-8")
    assert "wait_ready.sh" in text
    assert "seq 1 60" not in text, (
        "the old 60x1s inline loop is back — the false-FATAL class again")
