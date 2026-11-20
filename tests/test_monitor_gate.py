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
    """A raw socket listener that counts every connection attempt."""

    def __init__(self, port: int):
        self.port = port
        self.hits = 0
        self._s = socket.socket()
        self._s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._s.bind(("127.0.0.1", port))
        self._s.listen(10)
        self._s.settimeout(30)
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        try:
            while True:
                c, _ = self._s.accept()
                self.hits += 1
                c.close()
        except OSError:
            pass

    def close(self):
        try:
            self._s.close()
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
        port = 9451
        listener = _CountingListener(port)
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
        port = 9452
        listener = _CountingListener(port)
        try:
            cfg = tmp_path / "monitor-config.json"
            cfg.write_text(json.dumps({
                "targets": [{"id": "ok", "target": f"http://127.0.0.1:{port}/",
                             "cron": "* * * * *", "lab": True}]}),
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
                "the authorized lab target must actually be scanned")
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
