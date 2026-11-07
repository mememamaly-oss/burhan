"""Round 15 — R15-1: the CLI battery must not pollute the work tree.

The r14 battery ran every subprocess with cwd=<repo root>, so repair-demo's
relative benchmark outputs (results/benchmark_baseline.json & friends) and
capability-matrix's CAPABILITY_MATRIX.md landed as untracked files INSIDE
the repository on every test run — dirty trees, accidental commits, and
false CI noise.

This is the permanent regression case: run the battery's repair-demo leg
from a CLEAN tree and assert the tree is still clean afterwards.

Marked slow (runs the real demo ~3 min); skipped when the repo tree is
already dirty (cannot measure pollution then).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "burhan.cli"]

# every path the demo / capability-matrix commands are known to write
# relative to their cwd (the battery runs them with cwd=ROOT)
POLLUTANTS = [
    "CAPABILITY_MATRIX.md",
    "results/benchmark.json",
    "results/benchmark_baseline.json",
    "results/benchmark_broken.json",
    "results/benchmark_repair_candidateA.json",
    "results/benchmark_repair_candidateB.json",
]


def _tree_dirty() -> list[str]:
    r = subprocess.run(["git", "status", "--short"], cwd=ROOT,
                       capture_output=True, text=True)
    # development-time allowance: the fix itself (cli.py, modified) and this
    # test file (untracked, pre-merge) are expected; anything else is pollution
    allow = ("tests/test_r15_tree_isolation.py",
             "M burhan/cli.py", "M burhan/orchestrator.py",
             "M burhan/http_engine.py", "M burhan/browser.py",
             "M scripts/antipattern_review_ledger.json",
             "M evidence/layers/quantum-sweep/quantum-sweep-inventory.json",
             "M download/antipattern-audit/antipattern-inventory.json")
    return [l.strip() for l in r.stdout.splitlines()
            if l.strip() and l.strip() not in allow
            and not l.strip().endswith("test_r15_tree_isolation.py")]


@pytest.mark.slow
def test_r15_repair_demo_leaves_work_tree_clean():
    dirty_before = _tree_dirty()
    if dirty_before:
        pytest.skip(f"work tree already dirty ({len(dirty_before)} items) — "
                    "cannot measure pollution")

    r = subprocess.run(CLI + ["repair-demo"], capture_output=True, text=True,
                       timeout=420, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-300:]

    leaked = [p for p in POLLUTANTS if (ROOT / p).exists()]
    assert not leaked, (
        f"repair-demo wrote repo-relative artifacts: {leaked} — "
        "the demo must isolate its outputs (tmp dir), not the user's tree")
    dirty_after = _tree_dirty()
    assert not dirty_after, (
        f"work tree polluted by the run: {dirty_after}")
