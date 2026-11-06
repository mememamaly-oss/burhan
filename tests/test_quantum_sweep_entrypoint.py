"""Round-12 close — the permanent detector self-test for the generalized
class-(d+) ENTRYPOINT_UNREACHABLE check.

Why a permanent test: the CLI-only class-(d) check reported ZERO holes while
the live dogfood run caught a real instance of the same bug class that the
static check could not see (the monitor scheduler never called
run_monitor_cycle). The generalized check exists BECAUSE of that miss — this
test makes sure the generalized check itself can never silently die the same
way: it feeds the detector a synthetic mini-tree containing the EXACT bug
shape (a module with a public function called only by tests, plus decoys that
must NOT be flagged) and asserts the verdict.

Decoys (each guards a real false-positive source fixed during calibration):
  - a non-entry script's `def main()` must NOT route its file (the "main"
    word-collision that hid the real bug in draft 1)
  - a from-imported class used via classmethod (Vault.init shape) IS routed
  - a private wrapper (_helper) propagates routing but is never flagged
  - a relative lazy import (from .mod import x) resolves
"""
from __future__ import annotations

import ast
import os
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.audit_quantum_sweep import entrypoint_wiring_report  # noqa: E402


def build_mini_tree(base: Path):
    (base / "burhan").mkdir()
    (base / "scripts").mkdir()
    (base / ".github/workflows").mkdir(parents=True)
    (base / "tests").mkdir()

    # the REAL bug shape: scheduler entry that imports the module but never
    # calls the alert-cycle function
    (base / "burhan/monitor.py").write_text(textwrap.dedent("""
        def load_config():
            return {}

        def run_monitor_cycle(store, target):
            return {"alerts": []}
        """), encoding="utf-8")
    (base / "scripts/run_due.py").write_text(textwrap.dedent("""
        from burhan.monitor import load_config

        def main():
            cfg = load_config()
            return cfg

        if __name__ == "__main__":
            main()
        """), encoding="utf-8")
    # decoy 1: non-entry script with def main + private wrapper chain
    (base / "scripts/not_an_entry.py").write_text(textwrap.dedent("""
        from burhan.monitor import run_monitor_cycle

        def _helper():
            return run_monitor_cycle(None, "t")

        def main():
            return _helper()

        if __name__ == "__main__":
            main()
        """), encoding="utf-8")
    # decoy 2: from-imported class used via classmethod (Vault.init shape)
    (base / "burhan/vault.py").write_text(textwrap.dedent("""
        class Vault:
            @classmethod
            def init(cls, path):
                return cls()
        """), encoding="utf-8")
    (base / "burhan/cli.py").write_text(textwrap.dedent("""
        from burhan.vault import Vault

        def main():
            v = Vault.init("p")
            return v

        if __name__ == "__main__":
            main()
        """), encoding="utf-8")
    # decoy 3: relative lazy import inside a routed def
    (base / "burhan/other.py").write_text(textwrap.dedent("""
        def used_func():
            return 1
        """), encoding="utf-8")
    (base / "burhan/orch.py").write_text(textwrap.dedent("""
        def run():
            from .other import used_func
            return used_func()
        """), encoding="utf-8")
    # the workflows file names the two REAL entries only
    (base / ".github/workflows/ci.yml").write_text(
        "jobs:\n  x:\n    steps:\n      - run: python3 scripts/run_due.py\n"
        "      - run: python3 -m burhan.cli\n", encoding="utf-8")
    # tests reference the bug-shape function (the flag condition)
    (base / "tests/test_monitor.py").write_text(
        "from burhan.monitor import run_monitor_cycle\n", encoding="utf-8")
    # decoy 1 counterweight: a tests reference to the decoy's main? none —
    # decoy functions are not test-referenced, so they are never candidates.


def list_py(base: Path):
    out = []
    for p in sorted(base.rglob("*.py")):
        out.append(str(p.relative_to(base)))
    return out


def test_entrypoint_detector_catches_the_real_bug_shape(tmp_path):
    build_mini_tree(tmp_path)
    import scripts.audit_quantum_sweep as aqs
    orig_root = aqs.ROOT
    aqs.ROOT = str(tmp_path)
    try:
        hits, info = entrypoint_wiring_report(list_py(tmp_path))
    finally:
        aqs.ROOT = orig_root
    flagged = {h.code for h in hits}
    # THE bug shape is caught
    assert "run_monitor_cycle" in flagged, (
        "detector missed the run_monitor_cycle shape — the exact round-12 "
        "dogfood catch; the generalized check has regressed")
    # decoys behave:
    assert "load_config" not in flagged          # routed by the entry
    assert "main" not in flagged                 # non-entry script main
    assert "Vault" not in flagged                # classmethod-use routes it
    assert "used_func" not in flagged            # relative lazy import routes
    assert "_helper" not in flagged              # private = never flagged
    assert "run" not in flagged                  # routed def, not test-ref'd


def test_entrypoint_detector_clean_on_wired_tree(tmp_path):
    """BLUE side: wire the scheduler to call the cycle -> zero flags."""
    build_mini_tree(tmp_path)
    (tmp_path / "scripts/run_due.py").write_text(textwrap.dedent("""
        from burhan.monitor import load_config, run_monitor_cycle

        def main():
            cfg = load_config()
            run_monitor_cycle(None, "t")
            return cfg

        if __name__ == "__main__":
            main()
        """), encoding="utf-8")
    import scripts.audit_quantum_sweep as aqs
    orig_root = aqs.ROOT
    aqs.ROOT = str(tmp_path)
    try:
        hits, info = entrypoint_wiring_report(list_py(tmp_path))
    finally:
        aqs.ROOT = orig_root
    flagged = {h.code for h in hits}
    assert "run_monitor_cycle" not in flagged, (
        "detector flags the WIRED shape — false positive on the fixed pattern")
