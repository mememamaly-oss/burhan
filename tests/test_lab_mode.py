"""r19-2.4 (owner followup item 2): the EXPLICIT laboratory mode tests.

Contract under test:
  - activation: --lab flag OR BURHAN_LAB_MODE=1 (env covers CI/demo
    UI/containers; the flag covers the CLI);
  - refusal: a loopback/private target WITHOUT the mode is refused by
    the authorization gate (loud, naming both channels) — the missing
    mode refuses the scan;
  - recording: every scan report carries stats["lab_mode"] =
    {"active": bool, "via": "flag"|"env"|None}.
"""
from __future__ import annotations

import importlib
import json
import os
import socket
import subprocess
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import burhan.lab_mode as lm                      # noqa: E402
from burhan.authorized_targets import authorize   # noqa: E402


REGISTRY = {
    "policy": "lab-mode tests",
    "targets": [
        {"id": "self-hosted-fixtures", "kind": "self-hosted",
         "match": {"loopback_or_private": True},
         "proof": {"type": "ownership"},
         "covers": ["local fixtures"]},
    ],
}


@pytest.fixture(autouse=True)
def _no_env_lab(monkeypatch):
    monkeypatch.delenv(lm.ENV_VAR, raising=False)


# ------------------------------------------------------------ unit: channels
def test_lab_mode_off_by_default():
    active, via = lm.is_lab_mode(False)
    assert active is False
    assert via is None


def test_lab_mode_via_flag():
    active, via = lm.is_lab_mode(True)
    assert active is True
    assert via == "flag"


def test_lab_mode_via_env(monkeypatch):
    monkeypatch.setenv(lm.ENV_VAR, "1")
    active, via = lm.is_lab_mode(False)
    assert active is True
    assert via == "env"
    # the flag wins the 'via' attribution when both are present
    active2, via2 = lm.is_lab_mode(True)
    assert (active2, via2) == (True, "flag")


@pytest.mark.parametrize("value", ["true", "YES", "on", "1"])
def test_lab_mode_env_truthy_spellings(monkeypatch, value):
    monkeypatch.setenv(lm.ENV_VAR, value)
    assert lm.is_lab_mode(False)[0] is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "junk"])
def test_lab_mode_env_falsy_spellings(monkeypatch, value):
    monkeypatch.setenv(lm.ENV_VAR, value)
    assert lm.is_lab_mode(False)[0] is False


# ------------------------------------------------- gate: refusal without lab
def _reg(tmp_path):
    p = tmp_path / "authorized-targets.json"
    p.write_text(json.dumps(REGISTRY))
    return str(p)


def test_private_target_refused_without_lab_mode(tmp_path):
    ok, reason, eid = authorize("http://127.0.0.1:8080/", _reg(tmp_path))
    assert not ok
    assert eid is None
    # the refusal names BOTH sanctioned channels
    assert "--lab" in reason
    assert lm.ENV_VAR in reason


def test_private_target_allowed_with_env_lab(tmp_path, monkeypatch):
    monkeypatch.setenv(lm.ENV_VAR, "1")
    ok, reason, eid = authorize("http://127.0.0.1:8080/", _reg(tmp_path))
    assert ok, reason
    assert eid == "self-hosted-fixtures"
    assert "EXPLICIT lab mode" in reason  # the proof names the mode


def test_private_target_allowed_with_flag_lab(tmp_path, monkeypatch):
    # the gate reads the env channel; the flag flows through the CLI into
    # the SAME check via is_lab_mode(flag) at the CLI layer — here we pin
    # the gate-side env path and the recording path for the flag below.
    monkeypatch.setenv(lm.ENV_VAR, "1")
    ok, _, _ = authorize("http://10.0.0.5:8080/", _reg(tmp_path))
    assert ok  # private (non-loopback) range too


def test_public_target_unaffected_by_lab_mode(tmp_path, monkeypatch):
    # a public target with a valid proof scans regardless of lab mode —
    # the mode gates ONLY the self-hosted (private) proof class
    monkeypatch.delenv(lm.ENV_VAR, raising=False)
    reg = json.loads(json.dumps(REGISTRY))
    reg["targets"].append({
        "id": "wk-pub", "kind": "permissioned-public-demo",
        "match": {"host_suffix": "example.test"},
        "proof": {"type": "well_known", "token": "tok"},
    })
    p = tmp_path / "authorized-targets.json"
    p.write_text(json.dumps(reg))

    def fetch(url):
        return 200, {}, b"tok"

    ok, reason, _ = authorize("https://sub.example.test/", str(p), fetch=fetch)
    assert ok, reason


# ---------------------------------------------------- recording in the report
def test_report_records_lab_mode_flag_and_env(tmp_path, monkeypatch):
    from burhan.orchestrator import BurhanScanner, ScanConfig

    # off: via None
    sc = BurhanScanner("http://127.0.0.1:1/", ScanConfig(allow_private=True))
    assert sc.stats["lab_mode"] == {"active": False, "via": None}

    # flag: via "flag"
    sc2 = BurhanScanner("http://127.0.0.1:1/",
                        ScanConfig(allow_private=True, lab=True))
    assert sc2.stats["lab_mode"] == {"active": True, "via": "flag"}

    # env: via "env" (even with no flag)
    monkeypatch.setenv(lm.ENV_VAR, "1")
    sc3 = BurhanScanner("http://127.0.0.1:1/", ScanConfig(allow_private=True))
    assert sc3.stats["lab_mode"] == {"active": True, "via": "env"}


# --------------------------------------------------------------- CLI e2e
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_cli_scan_private_target_refused_without_lab(tmp_path):
    """END-TO-END: a live loopback target, a real owner gate, the real
    CLI — WITHOUT --lab the scan is refused (exit 2, banner naming both
    channels); WITH --lab the same scan runs and the report records
    the mode."""
    import burhan.owner_gate as og
    gate_path = tmp_path / "owner-gate.json"
    og.OwnerGate.setup(str(gate_path), "test-owner-password-123")
    regp = tmp_path / "authorized-targets.json"
    regp.write_text(json.dumps(REGISTRY))
    env = {**os.environ,
           "BURHAN_OWNER_GATE": str(gate_path),
           "BURHAN_AUTHORIZED_TARGETS": str(regp),
           "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.pop(lm.ENV_VAR, None)
    port = _free_port()
    out = tmp_path / "scan.json"

    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "scan",
         f"http://127.0.0.1:{port}/", "--allow-private",
         "--owner-password", "test-owner-password-123",
         "--out", str(out)],
        capture_output=True, text=True, timeout=120, cwd=ROOT, env=env)
    assert r.returncode == 2, (r.returncode, r.stdout[-300:], r.stderr[-300:])
    assert "REFUSED — LIVE SCAN AUTHORIZATION GATE" in r.stdout + r.stderr
    assert "--lab" in r.stdout + r.stderr
    assert lm.ENV_VAR in r.stdout + r.stderr
    assert not out.exists()  # no report on refusal


def test_cli_scan_private_target_runs_with_lab_flag(tmp_path):
    """The positive twin: WITH --lab, the loopback scan proceeds and the
    REPORT records stats.lab_mode = {active: true, via: 'flag'}."""
    import burhan.owner_gate as og
    gate_path = tmp_path / "owner-gate.json"
    og.OwnerGate.setup(str(gate_path), "test-owner-password-123")
    regp = tmp_path / "authorized-targets.json"
    regp.write_text(json.dumps(REGISTRY))
    env = {**os.environ,
           "BURHAN_OWNER_GATE": str(gate_path),
           "BURHAN_AUTHORIZED_TARGETS": str(regp),
           "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.pop(lm.ENV_VAR, None)

    # a live local target (vulnapp) so the scan actually runs
    port = _free_port()
    srv = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env={**env, "PORT": str(port)},
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        import time as _t
        import urllib.request as _u
        base = f"http://127.0.0.1:{port}"
        for _ in range(40):
            try:
                if _u.urlopen(base + "/", timeout=2).status == 200:
                    break
            except Exception:  # noqa: BLE001
                _t.sleep(0.25)
        out = tmp_path / "scan.json"
        r = subprocess.run(
            [sys.executable, "-m", "burhan.cli", "scan", base + "/",
             "--allow-private", "--lab",
             "--owner-password", "test-owner-password-123",
             "--no-browser", "--max-pages", "2",
             "--out", str(out)],
            capture_output=True, text=True, timeout=240, cwd=ROOT, env=env)
        assert r.returncode == 0, r.stderr[-400:]
        rep = json.loads(out.read_text())
        assert rep["stats"]["lab_mode"] == {"active": True, "via": "flag"}
        assert rep["stats"]["requests"] > 0
    finally:
        srv.terminate()
