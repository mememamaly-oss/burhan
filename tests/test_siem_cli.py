"""Part 1.5 — CLI integration: `burhan report --format cef|syslog|ocsf`.

Runs the real CLI against a real Store DB seeded from the canonical signed
scan artifact (evidence/full-reverify/fixtures-vulnapp/scan.json — reused,
not fabricated) and verifies the three exports land on disk with the
signed-evidence pointer. The syslog leg sends to a REAL loopback UDP
collector and counts the datagrams.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = json.load(open(ROOT / "evidence/full-reverify/fixtures-vulnapp/scan.json",
                      encoding="utf-8"))


def _seed_store(tmp_path: Path) -> Path:
    sys.path.insert(0, str(ROOT))
    from burhan.store import Store
    db = tmp_path / "siem-cli.db"
    st = Store(str(db))
    st.save_run(SCAN)
    return db


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "burhan.cli", *args],
                          capture_output=True, text=True, cwd=str(ROOT))


def test_cli_cef_export(tmp_path):
    db = _seed_store(tmp_path)
    out = tmp_path / "report.cef"
    r = _cli("report", "--db", str(db), "--format", "cef", "--out", str(out))
    assert r.returncode == 0, r.stderr
    summary = json.loads(r.stdout)
    assert summary["format"] == "cef"
    assert summary["events"] == len(SCAN["findings"])
    lines = out.read_text().splitlines()
    assert len(lines) == summary["events"]
    assert all(l.startswith("CEF:0|Burhan|") for l in lines)
    # every line carries the signed-evidence pointer
    assert all("cs2Label=burhanMerkleRoot" in l for l in lines)


def test_cli_ocsf_export(tmp_path):
    db = _seed_store(tmp_path)
    out = tmp_path / "report.ocsf.json"
    r = _cli("report", "--db", str(db), "--format", "ocsf", "--out", str(out))
    assert r.returncode == 0, r.stderr
    summary = json.loads(r.stdout)
    assert summary["format"] == "ocsf"
    d = json.loads(out.read_text())
    assert d["schema_version"] == "1.9.0"
    assert d["class"] == "Detection Finding"
    assert len(d["events"]) == len(SCAN["findings"])
    roots = {e["vendor_attributes"]["burhan_signed_evidence"]["merkle_root"]
             for e in d["events"]}
    assert len(roots) == 1              # one run, one signed root


def test_cli_syslog_udp_real_send(tmp_path):
    db = _seed_store(tmp_path)
    out = tmp_path / "report.syslog"
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    port = rx.getsockname()[1]
    rx.settimeout(5)
    got: list[bytes] = []

    def listen():
        while True:
            try:
                data, _ = rx.recvfrom(65535)
            except socket.timeout:
                return
            got.append(data)
            if len(got) >= len(SCAN["findings"]):
                return

    t = threading.Thread(target=listen)
    t.start()
    r = _cli("report", "--db", str(db), "--format", "syslog", "--out", str(out),
             "--syslog-host", "127.0.0.1", "--syslog-port", str(port))
    t.join(10)
    rx.close()
    assert r.returncode == 0, r.stderr
    summary = json.loads(r.stdout)
    assert summary["format"] == "syslog"
    assert summary["sent"] == len(SCAN["findings"])
    assert len(got) == len(SCAN["findings"])       # real datagrams arrived
    assert got[0].decode() == out.read_text().splitlines()[0]
