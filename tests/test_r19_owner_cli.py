"""R19-2b — owner-gate CLI wiring: acceptance tests.

The CLI surface for the owner's order: `burhan owner init / change /
transfer-arm / transfer-take / status` and the SCAN gate
(--owner-password / BURHAN_OWNER_PASSWORD / prompt; exit 2 on refusal,
zero scan requests). These tests drive the CLI as a subprocess exactly
as an operator would (the module's own credential logic is already
covered by test_r19_owner_gate.py's 16 tests).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def run_cli(args, env_extra=None, cwd=None):
    env = dict(os.environ)
    env.pop("BURHAN_OWNER_PASSWORD", None)
    env.pop("BURHAN_OWNER_GATE", None)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [PY, "-m", "burhan.cli", *args],
        capture_output=True, text=True, timeout=60,
        cwd=cwd or os.path.join(REPO, ".."), env=env)


class TestOwnerCli:
    def test_init_status_change_flow(self, tmp_path):
        store = str(tmp_path / "gate.json")
        r = run_cli(["owner", "init", "--store", store,
                     "--password", "owner-pass-1"])
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout)["owner_gate"] == "installed"
        r = run_cli(["owner", "status", "--store", store])
        assert json.loads(r.stdout)["owner_gate"] == "armed"
        r = run_cli(["owner", "change", "--store", store,
                     "--password", "owner-pass-1",
                     "--new-password", "owner-pass-2"])
        assert r.returncode == 0
        # the OLD password no longer authorizes a scan
        r = run_cli(["scan", "http://127.0.0.1:9/", "--owner-gate", store,
                     "--owner-password", "owner-pass-1", "--no-oast",
                     "--out", str(tmp_path / "s1.json")])
        assert r.returncode == 2
        assert "owner gate refused" in r.stderr
        r = run_cli(["scan", "http://127.0.0.1:9/", "--owner-gate", store,
                     "--owner-password", "owner-pass-2", "--no-oast",
                     "--out", str(tmp_path / "s2.json")])
        # gate PASSES; the scan then fails on the dead port — that failure
        # must NOT be an owner-gate refusal
        assert "owner gate refused" not in r.stderr

    def test_transfer_flow_seller_dies_buyer_lives(self, tmp_path):
        store = str(tmp_path / "gate.json")
        run_cli(["owner", "init", "--store", store,
                 "--password", "seller-pass-1"])
        r = run_cli(["owner", "transfer-arm", "--store", store,
                     "--password", "seller-pass-1"])
        assert r.returncode == 0
        ticket = json.loads(r.stdout)["ticket"]
        r = run_cli(["owner", "transfer-take", "--store", store,
                     "--ticket", ticket, "--new-password", "buyer-pass-1"])
        assert r.returncode == 0
        assert json.loads(r.stdout)["owner_gate"] == "ownership_transferred"
        # seller's credential is DEAD (the acceptance criterion)
        r = run_cli(["scan", "http://127.0.0.1:9/", "--owner-gate", store,
                     "--owner-password", "seller-pass-1", "--no-oast",
                     "--out", str(tmp_path / "s3.json")])
        assert r.returncode == 2 and "owner gate refused" in r.stderr
        # ticket replay fails
        r = run_cli(["owner", "transfer-take", "--store", store,
                     "--ticket", ticket, "--new-password", "x-pass-123"])
        assert r.returncode == 2
        # buyer passes the gate (fails later on the dead port, NOT on the gate)
        r = run_cli(["scan", "http://127.0.0.1:9/", "--owner-gate", store,
                     "--owner-password", "buyer-pass-1", "--no-oast",
                     "--out", str(tmp_path / "s4.json")])
        assert "owner gate refused" not in r.stderr

    def test_env_var_password(self, tmp_path):
        store = str(tmp_path / "gate.json")
        run_cli(["owner", "init", "--store", store,
                 "--password", "env-pass-12"])
        r = run_cli(["scan", "http://127.0.0.1:9/", "--owner-gate", store,
                     "--no-oast", "--out", str(tmp_path / "s6.json")],
                    env_extra={"BURHAN_OWNER_PASSWORD": "env-pass-12"})
        assert "owner gate refused" not in r.stderr

    def test_wrong_password_records_and_refuses(self, tmp_path):
        store = str(tmp_path / "gate.json")
        run_cli(["owner", "init", "--store", store,
                 "--password", "owner-pass-1"])
        r = run_cli(["scan", "http://127.0.0.1:9/", "--owner-gate", store,
                     "--owner-password", "totally-wrong", "--no-oast",
                     "--out", str(tmp_path / "s5.json")])
        assert r.returncode == 2
        data = json.load(open(store))
        assert any(e.get("ok") is False for e in data["events"])
