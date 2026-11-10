"""R20 — the shared-tmp writer race (C3 family, occurrence #5, pinned).

Live-caught on CI (Engine job 129559174929, PR #87 head 0552d3c6): two
engines sharing one owner-gate store raced inside _save — the FIXED tmp
name (gate.json.tmp) was os.replace()d away by one writer before the
other reached its own replace, so the SURVIVOR died with
FileNotFoundError and C3 failed its 'survivor completes cleanly'
contract. The #89 stderr capture (issue #88) finally made the exception
visible after four blind occurrences; this file pins the MECHANISM so
it can never silently return.

The identical fixed-tmp pattern lived in memory.py (save) and stepup.py
(_save) — all three writers are stressed here. The bar, exactly the C3
engine contract: every concurrent worker exits 0 (no crash), the final
document is valid JSON, the audit chains verify, and no tmp litter is
left behind.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from burhan.memory import SecurityMemory   # noqa: E402
from burhan.owner_gate import OwnerGate          # noqa: E402
from burhan.stepup import StepUpGate             # noqa: E402

WORKERS = 8
ROUNDS = 12

OWNER_WORKER = r"""
import sys
from burhan.owner_gate import OwnerGate
g = OwnerGate(sys.argv[1])
for i in range(int(sys.argv[3])):
    g.append_event({"action": "concurrent-stress", "ok": True,
                    "worker": int(sys.argv[2]), "i": i})
"""

STEPUP_WORKER = r"""
import sys
from burhan.stepup import StepUpGate
g = StepUpGate(sys.argv[1])
for i in range(int(sys.argv[3])):
    g.append_event({"action": "concurrent-stress", "ok": True,
                    "worker": int(sys.argv[2]), "i": i})
"""

MEMORY_WORKER = r"""
import sys
from burhan.memory import SecurityMemory
m = SecurityMemory(sys.argv[1])
for i in range(int(sys.argv[3])):
    m.remember_run(f"http://w{sys.argv[2]}-{i}.local",
                   {"run_id": f"r{sys.argv[2]}-{i}",
                    "stats": {"endpoints": i}})
    m.save()
"""


def _tail(p: subprocess.Popen) -> str:
    try:
        _, err = p.communicate(timeout=5)
        return (err or "")[-600:]
    except Exception:
        return "<stderr unavailable>"


def _spawn(code: str, *args: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", code, *args],
        cwd=str(ROOT), env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def _stress(tmp_path: Path, code: str, setup, verify) -> None:
    store = str(tmp_path / "shared-store.json")
    setup(store)
    procs = [_spawn(code, store, str(w), str(ROUNDS)) for w in range(WORKERS)]
    for p in procs:
        rc = p.wait(timeout=120)
        assert rc == 0, (
            "a concurrent writer died — the C3 survivor contract\n"
            f"--- stderr tail ---\n{_tail(p)}")
    verify(store)
    litter = [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
    assert not litter, f"tmp files left behind: {litter}"


def test_owner_gate_concurrent_append(tmp_path):
    """8 writers x 12 events through ONE owner-gate store: nobody dies,
    the chain verifies, no shared .tmp race."""
    def setup(store):
        OwnerGate.setup(store, "owner-pass-1")

    def verify(store):
        g = OwnerGate(store)
        data = json.load(open(store))
        assert data["chain_head"], "store lost its chain head"
        assert g.verify_chain() == data["events"].__len__()

    _stress(tmp_path, OWNER_WORKER, setup, verify)


def test_stepup_concurrent_append(tmp_path):
    """Same race shape on the step-up gate's audit trail."""
    def setup(store):
        StepUpGate.setup(store, "stepup-pass-1")

    def verify(store):
        g = StepUpGate(store)
        data = json.load(open(store))
        assert g.verify_chain() == len(data["events"])

    _stress(tmp_path, STEPUP_WORKER, setup, verify)


def test_memory_concurrent_save(tmp_path):
    """Same race shape on the security-memory writer. The memory store
    is a whole-document read-modify-write by design (per-app host-keyed
    memory; the engine's real concurrent-store contract is SQLite's,
    held by the C3 engine test itself) — so the pinned bar here is the
    tmp-race contract: no writer dies, the document is NEVER torn, and
    at least one writer's data survives intact."""
    def setup(store):
        with open(store, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "apps": {}}, fh)

    def verify(store):
        # tmp-race contract only: the document is VALID JSON (the ctor
        # parses it; a torn write would raise or discard), carries real
        # data, and merges across workers only through whole documents
        # (load-at-start is the store's documented read-modify-write
        # semantic — the concurrent-integrity bar for the ENGINE store
        # is SQLite's, pinned by the C3 engine test itself).
        m = SecurityMemory(store)
        hosts = list(m._data["apps"].keys())
        assert hosts, "no data survived at all"
        assert all(isinstance(v, dict) and v.get("runs", 0) >= 1
                   for v in m._data["apps"].values()), \
            "an app entry is not a whole-document merge (torn write?)"

    _stress(tmp_path, MEMORY_WORKER, setup, verify)
