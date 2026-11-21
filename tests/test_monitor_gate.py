"""r19-2.15 (owner order 2026-11-20 ب-2): the scheduled monitor goes
through the authorization gate.

Live-verified defect this pins: run_due.py built BurhanScanner directly
with no authorize() call — a config whose target was NOT in
authorized-targets.json still reached the network (a local listener
recorded 36 connections from one scheduled run). The gate now runs
BEFORE the scanner is built; an unauthorized target is refused with
exit=2 per-run and ZERO scan requests.

Also pins the comment fix: the old comment claimed "the
authorized-targets gate still applies at scan" — the new comment names
the actual check location (this loop, before construction).
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class _CountingListener:
    """A real HTTP server that counts every request it ANSWERS.

    r19-3.3 (supervisor round 2026-11-21, CI macOS run 44865366419):
    the old raw accept-and-close listener made the test's meaning depend
    on transport-level accident: on Linux the immediate close reads as
    an instant RST (scan finishes fast); on macOS the same close left
    the client waiting out the full per-request timeout for EVERY probe
    (26 requests x 4s -> the ~176s the CI log shows) with zero accepts
    ever surfacing. The contract under test is HTTP-level — "the
    authorized lab target is actually scanned" — so the listener is now
    a real ThreadingHTTPServer that always answers 200. A hit is an
    answered request: provable identically on every platform, no
    RST/FIN/backlog assumptions. The port is ephemeral (bind :0) so a
    CI-host-occupied port can never poison the run."""

    def __init__(self, port: int = 0):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.hits = 0
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits += 1
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_GET
            do_PUT = do_GET
            do_DELETE = do_GET
            do_OPTIONS = do_GET
            do_HEAD = do_GET

            def log_message(self, *a):  # silence
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self.port = self._srv.server_address[1]
        self._t = threading.Thread(target=self._srv.serve_forever,
                                   daemon=True)
        self._t.start()

    def close(self):
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except OSError:
            pass


def _run(tmp_path, target_url, monkeypatch):
    """Invoke the runner as a real subprocess against a temp config."""
    cfg = tmp_path / "monitor-config.json"
    cfg.write_text(json.dumps({
        "targets": [{"id": "probe", "target": target_url,
                     "cron": "* * * * *"}]}), encoding="utf-8")
    # a registry that authorizes a DIFFERENT target only: the probe
    # target is absent (an empty targets list is itself refused by
    # load_registry, so the file must carry one unrelated entry)
    reg = tmp_path / "authorized-targets.json"
    reg.write_text(json.dumps({"targets": [{
        "id": "other", "match": {"host_suffix": "other.invalid"},
        "proof": {"type": "dns_txt", "token": "TK"}}]}),
        encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if k != "BURHAN_LAB_MODE"}
    env["BURHAN_AUTHORIZED_TARGETS"] = str(reg)
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/monitor/run_due.py"),
         "--config", str(cfg)],
        env=env, capture_output=True, timeout=120, cwd=str(tmp_path))
    return r


class TestMonitorGate:
    def test_unregistered_target_refused_zero_requests(self, tmp_path, monkeypatch):
        """THE discriminator: a target NOT in the registry must produce
        exit=2 in the run record and ZERO connections to the target."""
        listener = _CountingListener()  # r19-3.3: ephemeral port
        port = listener.port
        try:
            r = _run(tmp_path, f"http://127.0.0.1:{port}/", monkeypatch)
            out = json.loads(r.stdout)
            run = out["runs"][0]
            assert run.get("exit") == 2, run
            assert "refused" in run, run
            time.sleep(0.5)  # any in-flight attempt would land by now
            assert listener.hits == 0, (
                f"the monitor must not touch an unregistered target — "
                f"{listener.hits} connections were made")
        finally:
            listener.close()

    def test_registered_lab_target_still_scans(self, tmp_path, monkeypatch):
        """The gate must not break the legitimate path: a self-hosted
        entry + lab=true still runs a real scan (a listener counts the
        connection — at least one must arrive)."""
        listener = _CountingListener()  # r19-3.3: ephemeral port
        port = listener.port
        try:
            cfg = tmp_path / "monitor-config.json"
            # r19-3.1: bounded probe — the contract under test is "the
            # registered lab target is REACHED and scanned", not "deeply
            # crawled". On the macOS ARM runner a full browser scan takes
            # >180s and blew the test's subprocess timeout (CI run
            # 44841623077: 1 failed, 825 passed). max_pages=2 + browser
            # off keeps the proof identical on every platform.
            cfg.write_text(json.dumps({
                "targets": [{"id": "ok", "target": f"http://127.0.0.1:{port}/",
                             "cron": "* * * * *", "lab": True,
                             "max_pages": 2, "timeout": 4.0,
                             "browser": False}]}),
                encoding="utf-8")
            reg = tmp_path / "authorized-targets.json"
            reg.write_text(json.dumps({"targets": [{
                "id": "self-1", "kind": "self-hosted",
                "match": {"loopback_or_private": True},
                "covers": ["127.0.0.1"]}]}), encoding="utf-8")
            env = dict(os.environ)
            env.pop("BURHAN_LAB_MODE", None)
            env["BURHAN_AUTHORIZED_TARGETS"] = str(reg)
            r = subprocess.run(
                [sys.executable, str(ROOT / "scripts/monitor/run_due.py"),
                 "--config", str(cfg)],
                env=env, capture_output=True, timeout=180, cwd=str(tmp_path))
            out = json.loads(r.stdout)
            run = out["runs"][0]
            assert run.get("exit") == 0, run
            assert listener.hits >= 1, (
                "the authorized lab target must actually be scanned "
                f"(0 of the monitor's HTTP requests were answered by the "
                f"listener on port {port})")
        finally:
            listener.close()

    def test_comment_no_longer_claims_the_gate_is_elsewhere(self):
        """The old comment said 'the authorized-targets gate still applies
        at scan' while NO gate existed anywhere on the path. The fixed
        file must name the real location: this loop, before the scanner
        is built."""
        src = (ROOT / "scripts/monitor/run_due.py").read_text(encoding="utf-8")
        assert "the authorization verdict below is checked LIVE" in src
        assert "still applies at scan" not in src, (
            "the stale comment must be gone — it described a gate that "
            "did not exist on this path")


class TestCapsValidation:
    """r19-3.4 (supervisor order 2026-11-21 item 2): the per-target scan
    caps (max_pages / timeout / browser) must be type- and range-checked
    BEFORE any scan is built; a bad value skips the target loudly with
    exit=3 — never a scan with unknown values.

    Red/green pairs below cover: booleans-in-int-fields (Python's
    isinstance(True, int) trap), negative/zero/huge numbers, strings
    ("false", "40"), floats in max_pages, and non-bool browser values.
    The mutation test (test_mutation_disable_validation_is_caught)
    kills a validation that silently accepts everything.
    """

    def _run_with_target(self, tmp_path, monkeypatch, target: dict):
        """Shared driver: a registered lab target with GIVEN caps; the
        listener proves whether a scan actually happened."""
        listener = _CountingListener()
        target = {**target, "target": f"http://127.0.0.1:{listener.port}/",
                  "cron": "* * * * *", "lab": True}
        try:
            cfg = tmp_path / "monitor-config.json"
            cfg.write_text(json.dumps({"targets": [target]}),
                           encoding="utf-8")
            reg = tmp_path / "authorized-targets.json"
            reg.write_text(json.dumps({"targets": [{
                "id": "self-1", "kind": "self-hosted",
                "match": {"loopback_or_private": True},
                "covers": ["127.0.0.1"]}]}), encoding="utf-8")
            env = dict(os.environ)
            env.pop("BURHAN_LAB_MODE", None)
            env["BURHAN_AUTHORIZED_TARGETS"] = str(reg)
            r = subprocess.run(
                [sys.executable, str(ROOT / "scripts/monitor/run_due.py"),
                 "--config", str(cfg)],
                env=env, capture_output=True, timeout=120, cwd=str(tmp_path))
            out = json.loads(r.stdout)
            return out["runs"][0], listener
        finally:
            listener.close()

    # ---------------- green: valid shapes ----------------

    def test_valid_caps_still_scan(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "ok", "max_pages": 2, "timeout": 4.0, "browser": False})
        assert run.get("exit") == 0, run
        assert listener.hits >= 1

    def test_defaults_are_valid(self, tmp_path, monkeypatch):
        """No caps at all -> the documented defaults (40/12.0/True) pass
        validation and the target is scanned."""
        run, listener = self._run_with_target(tmp_path, monkeypatch,
                                              {"id": "ok"})
        assert run.get("exit") == 0, run
        assert listener.hits >= 1

    def test_int_timeout_is_valid(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "ok", "max_pages": 3, "timeout": 5, "browser": False})
        assert run.get("exit") == 0, run
        assert listener.hits >= 1

    # ---------------- red: max_pages ----------------

    def test_max_pages_bool_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "max_pages": True, "browser": False})
        assert run.get("exit") == 3, run
        assert "max_pages" in run.get("skipped", ""), run
        assert listener.hits == 0

    def test_max_pages_string_false_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "max_pages": "false", "browser": False})
        assert run.get("exit") == 3, run
        assert "max_pages" in run.get("skipped", ""), run
        assert listener.hits == 0

    def test_max_pages_zero_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "max_pages": 0, "browser": False})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    def test_max_pages_negative_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "max_pages": -5, "browser": False})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    def test_max_pages_over_200_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "max_pages": 10000, "browser": False})
        assert run.get("exit") == 3, run
        assert "200" in run.get("skipped", ""), run
        assert listener.hits == 0

    def test_max_pages_float_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "max_pages": 2.5, "browser": False})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    # ---------------- red: timeout ----------------

    def test_timeout_string_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "timeout": "fast", "browser": False})
        assert run.get("exit") == 3, run
        assert "timeout" in run.get("skipped", ""), run
        assert listener.hits == 0

    def test_timeout_zero_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "timeout": 0, "browser": False})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    def test_timeout_negative_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "timeout": -1.0, "browser": False})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    def test_timeout_over_300_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "timeout": 301.0, "browser": False})
        assert run.get("exit") == 3, run
        assert "300" in run.get("skipped", ""), run
        assert listener.hits == 0

    def test_timeout_bool_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "timeout": True, "browser": False})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    # ---------------- red: browser ----------------

    def test_browser_string_false_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "browser": "false"})
        assert run.get("exit") == 3, run
        assert "browser" in run.get("skipped", ""), run
        assert listener.hits == 0

    def test_browser_string_true_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "browser": "true"})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    def test_browser_int_rejected(self, tmp_path, monkeypatch):
        run, listener = self._run_with_target(
            tmp_path, monkeypatch,
            {"id": "bad", "browser": 0})
        assert run.get("exit") == 3, run
        assert listener.hits == 0

    # ---------------- mutation kill ----------------

    def test_mutation_disable_validation_is_caught(self, monkeypatch):
        """MUTATION KILL: if _validated_caps is disabled (always returns
        the raw values with no error), the bool-in-max_pages case above
        would scan with True as max_pages. This test fails loudly when
        the validation is neutered, by asserting the validator itself
        rejects the documented bad shapes (unit-level, no subprocess)."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "run_due_under_test", str(ROOT / "scripts/monitor/run_due.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        v = mod._validated_caps
        # bool masquerading as int must be rejected
        caps, err = v({"max_pages": True})
        assert err and "max_pages" in err, (caps, err)
        # string numbers must be rejected (no silent coercion)
        caps, err = v({"max_pages": "40"})
        assert err, (caps, err)
        # out-of-range must be rejected
        caps, err = v({"max_pages": 500})
        assert err and "200" in err, (caps, err)
        caps, err = v({"timeout": 0})
        assert err, (caps, err)
        caps, err = v({"timeout": 400})
        assert err and "300" in err, (caps, err)
        # browser must be a REAL boolean
        caps, err = v({"browser": "false"})
        assert err and "browser" in err, (caps, err)
        caps, err = v({"browser": 1})
        assert err, (caps, err)
        # and the valid shapes still pass with the exact values
        caps, err = v({"max_pages": 2, "timeout": 4, "browser": False})
        assert err is None and caps == {"max_pages": 2, "timeout": 4.0,
                                        "browser": False}, (caps, err)
