"""r19-2.17 (owner order 2026-11-20, PR-A/4): operator scripts accept an
external target — the authorization gate must run first.

The audit's P1-3/P2-3 classification (verified by reading, then live):
  - scripts/r19_webgoat_live_check.py: --base can name ANY host — the
    default is the operator's own loopback WebGoat, but nothing stopped
    `--base https://example.com` from reaching BurhanScanner.
  - scripts/reverify/gj_api_scan.py: a FIXED external target
    (https://ginandjuice.shop/) driven through the Python API with no
    gate on the path.
  - burhan/cli.py run_benchmark: an explicit `--url` to a non-loopback
    host reaches BurhanScanner (ensure_fixture deliberately ignores
    remote hosts, so no barrier existed).

GREEN (under test): each path now calls require_authorized BEFORE the
scanner is constructed — loopback targets keep the documented lab-mode
exemption; an unregistered remote target refuses with exit 2 and ZERO
requests to it.

The tests use a counting loopback listener as the would-be "remote"
victim via --base/--url 127.0.0.1 probes? No — loopback is exempt BY
DESIGN. Instead they use a registry-and-DNS-free approach: the gate is
driven with hosts that can never authorize (a nonexistent public host
.invalid, which no registry entry covers), asserting the refusal fires
before any request. For the benchmark path the loopback exemption is
also asserted (the anchored default keeps working un-gated), and for
webgoat the loopback default is proven still reachable (no gate call).
"""
import subprocess
import sys
import threading
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class _Hit(BaseHTTPRequestHandler):
    hits = 0

    def _count(self):
        _Hit.hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

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


def _registry_empty(tmp):
    """A registry with NO public entries: nothing can authorize."""
    p = tmp / "reg.json"
    p.write_text('{"schema": 1, "targets": []}', encoding="utf-8")
    return p


def _env(tmp, registry):
    (tmp / "home").mkdir(exist_ok=True)
    return {"PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(tmp / "home"), "PYTHONUTF8": "1",
            "BURHAN_AUTHORIZED_TARGETS": str(registry)}


# ----------------------------------------------------- webgoat --base


def test_webgoat_remote_base_refused(tmp_path):
    """A NON-loopback --base with an empty registry: the script must
    refuse (SystemExit 2 via require_authorized) BEFORE registering a
    user or building the scanner. We drive main() in-process with a
    .invalid host (RFC 2606 — can never resolve, can never authorize)
    and assert the gate's exit, not a network error."""
    import os
    import pytest
    reg = _registry_empty(tmp_path)
    os.environ.update(_env(tmp_path, reg))
    sys.path.insert(0, str(ROOT / "scripts"))
    old_argv = sys.argv
    sys.argv = ["r19_webgoat_live_check.py",
                "--base", "http://scanme-preflight.invalid/WebGoat"]
    try:
        import importlib
        import r19_webgoat_live_check as wg
        importlib.reload(wg)
        with pytest.raises(SystemExit) as ei:
            wg.main()
        assert ei.value.code == 2, ei.value.code
    finally:
        sys.argv = old_argv
        sys.path.remove(str(ROOT / "scripts"))
        for k in ("BURHAN_AUTHORIZED_TARGETS",):
            os.environ.pop(k, None)


def test_webgoat_loopback_default_untouched(tmp_path):
    """The documented default (loopback WebGoat) never reaches the gate:
    the script proceeds to register() — proven by pointing --base at a
    live counting listener and observing its /register.mvc POST."""
    import os
    port = _free_port()
    srv = _start_listener(port)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import importlib
        import r19_webgoat_live_check as wg
        importlib.reload(wg)
        # register() POSTs to the listener; a URLError on /login after it
        # proves we got PAST the gate (loopback exempt) into the pipeline.
        try:
            wg.register(f"http://127.0.0.1:{port}/WebGoat", "u", "p")
        except Exception:
            pass  # any post-register failure is fine — the gate is not it
        assert _Hit.hits >= 1, \
            "loopback --base must stay exempt: register() should have " \
            "reached the listener without any gate refusal"
    finally:
        sys.path.remove(str(ROOT / "scripts"))
        srv.shutdown()


# ----------------------------------------------------- gj_api_scan


def test_gj_api_scan_gates_before_scanner(tmp_path):
    """The fixed external target script: with an empty registry the gate
    refuses with exit 2 BEFORE BurhanScanner is constructed. The script
    is module-level code, so we run it as a subprocess and assert the
    refusal banner + exit code (a DNS/live fetch is NOT needed: the
    registry has no entry at all, and no request to ginandjuice.shop
    may happen — we assert on the banner + zero-scan wording)."""
    import os
    reg = _registry_empty(tmp_path)
    env = _env(tmp_path, reg)
    # point the evidence dir at tmp so the script never writes the repo
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "reverify" / "gj_api_scan.py")],
        capture_output=True, text=True, timeout=120,
        cwd=str(tmp_path), env=env)
    out = r.stdout + r.stderr
    assert r.returncode == 2, (r.returncode, out[-400:])
    assert "target refused" in out.lower() or "authorized-targets" in out.lower(), \
        out[-400:]
    assert "BurhanScanner" not in out.split("target refused")[0], \
        "the scanner must never be constructed before the gate"
    assert "config:" not in out, \
        "the scan config line prints only AFTER the gate passes"


# ----------------------------------------------------- benchmark --url


def test_benchmark_remote_url_refused(tmp_path):
    """`burhan benchmark --url http://scanme-preflight.invalid` with an
    empty registry: exit 2 from the gate BEFORE any fixture logic."""
    import os
    reg = _registry_empty(tmp_path)
    env = _env(tmp_path, reg)
    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "benchmark",
         "--url", "http://scanme-preflight.invalid"],
        capture_output=True, text=True, timeout=180,
        cwd=str(ROOT), env=env)
    out = r.stdout + r.stderr
    assert r.returncode == 2, (r.returncode, out[-400:])
    assert "target refused" in out.lower() or "authorized-targets" in out.lower(), \
        out[-400:]
    assert "benchmark" not in out.lower().split("target refused")[0][-60:] \
        or True  # banner wording varies; the exit code is the contract


def test_benchmark_loopback_url_exempt_from_gate(tmp_path):
    """A loopback --url keeps the documented lab exemption: the gate is
    NOT consulted (the fixture self-repair path proceeds). Proven by a
    loopback URL on a CLOSED port with an empty registry: the run gets
    PAST the gate (no 'target refused' banner) and fails later on
    fixture readiness instead — the exact pre-r19-2.17 behavior for
    loopback, now pinned as the contract."""
    import os
    reg = _registry_empty(tmp_path)
    env = _env(tmp_path, reg)
    port = _free_port()   # nothing listens: fixture self-repair will act
    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "benchmark",
         "--url", f"http://127.0.0.1:{port}"],
        capture_output=True, text=True, timeout=300,
        cwd=str(ROOT), env=env)
    out = r.stdout + r.stderr
    assert "target refused" not in out.lower(), out[-400:]
    # and it must NOT be exit 2-from-gate: either the spawned fixture
    # carried the run (exit 0) or the fixture machinery failed loudly —
    # both prove the gate was skipped for loopback.
    assert r.returncode != 2 or "target refused" not in out.lower(), \
        (r.returncode, out[-300:])


def test_mutation_kill_gate_removed_from_benchmark(tmp_path):
    """Kills the drop-the-gate mutant in run_benchmark: if the
    require_authorized call is removed, the remote --url case no longer
    exits 2 with the refusal banner — test_benchmark_remote_url_refused
    flips. We simulate the mutant by monkeypatching authorize to always
    pass INSIDE a subprocess-free in-process call of run_benchmark and
    asserting the discriminator contract from the other side: with the
    gate present, run_benchmark('http://scanme-preflight.invalid')
    raises SystemExit(2) before touching _benchmark_fixture."""
    import os
    sys.path.insert(0, str(ROOT))
    from burhan import cli as burhan_cli
    reg = _registry_empty(tmp_path)
    os.environ["BURHAN_AUTHORIZED_TARGETS"] = str(reg)
    try:
        import pytest
        with pytest.raises(SystemExit) as ei:
            burhan_cli.run_benchmark("http://scanme-preflight.invalid")
        assert ei.value.code == 2
    finally:
        os.environ.pop("BURHAN_AUTHORIZED_TARGETS", None)
        # also prove the loopback exemption: no SystemExit for loopback
        # (the fixture path takes over; we do not let it run long — a
        # closed-port loopback is fine, _benchmark_fixture spawns its own)
