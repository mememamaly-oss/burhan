"""R17-5: the sweep scanner's path handling must be separator-agnostic.

The Windows findings this file pins (both reproduced portably here):

  1. KeyError + false flags: callers that derive paths with pathlib
     (str(p.relative_to(base))) hand the scanner BACKSLASH paths on
     Windows, while the entry set / graph keys are forward-slash
     literals ('burhan/cli.py') — info[e] lookups raise KeyError, and
     ...
  2. ... the `from . import sibling` resolution builds mod_alias values
     with os.path.join, which on Windows yields 'burhan\\jrand.py'
     while every graph key is 'burhan/jrand.py' — the alias never
     resolves, the sibling's functions stay unrouted, and genuinely
     production-wired code gets flagged ENTRYPOINT_UNREACHABLE (the 6
     jrand.py false positives of the live Windows audit).
  3. the exclusion `f.startswith(("tests/", "fixtures/"))` and the
     test_words collection both miss backslash test paths — a function
     referenced ONLY by a backslash-named test file is a FALSE
     NEGATIVE (never flagged).

The fix contract: normalize every path to forward-slash at the single
point where paths enter the data structures (and at the one construction
site), not per-lookup-site patches. The Windows os.path.join behavior
is simulated on Linux by a guarded join patch (absolute first argument
= real join, so file reads keep working; relative fragments = the
Windows backslash join).
"""
import os
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.audit_quantum_sweep as aqs  # noqa: E402


def _tree(tmp_path):
    """burhan/jrand.py wired into production through `from . import
    jrand` (the exact false-positive shape) + an orphan referenced only
    by tests (the exact true-positive shape)."""
    (tmp_path / "burhan").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / "burhan/jrand.py").write_text(textwrap.dedent("""
        def rand_int():
            return 4

        def rand_str():
            return "x"
        """), encoding="utf-8")
    (tmp_path / "burhan/engine.py").write_text(textwrap.dedent("""
        from . import jrand

        def run_engine():
            return jrand.rand_int(), jrand.rand_str()
        """), encoding="utf-8")
    (tmp_path / "burhan/cli.py").write_text(textwrap.dedent("""
        from burhan.engine import run_engine

        def main():
            return run_engine()

        if __name__ == "__main__":
            main()
        """), encoding="utf-8")
    (tmp_path / "burhan/orphan.py").write_text(
        "def only_tests_call():\n    return 1\n", encoding="utf-8")
    (tmp_path / "tests/test_all.py").write_text(
        "from burhan.jrand import rand_int, rand_str\n"
        "from burhan.orphan import only_tests_call\n", encoding="utf-8")
    (tmp_path / ".github/workflows/ci.yml").write_text(
        "jobs:\n  x:\n    steps:\n      - run: python3 -m burhan.cli\n",
        encoding="utf-8")


def _run(py_files):
    orig_root = aqs.ROOT
    aqs.ROOT = os.getcwd()  # placeholder, replaced by caller
    raise AssertionError("unused")


def _report(tmp_path, py_files, win_join=False):
    import argparse
    orig_root = aqs.ROOT
    aqs.ROOT = str(tmp_path)
    real_join = os.path.join
    try:
        if win_join:

            def join(a, *rest):
                # absolute first arg (ROOT-joined file reads) stays real;
                # relative fragments get the Windows backslash join
                if os.path.isabs(a) or a.startswith(".github"):
                    return real_join(a, *rest)
                return "\\".join([a, *rest])

            os.path.join = join
        return aqs.entrypoint_wiring_report(py_files)
    finally:
        os.path.join = real_join
        aqs.ROOT = orig_root


def test_backslash_input_paths_no_keyerror_and_detection_intact(tmp_path):
    """RED shape 1: pathlib-derived backslash paths must not KeyError —
    and the detector's verdicts must be IDENTICAL to the forward-slash
    run (the orphan still flagged, jrand still clean)."""
    _tree(tmp_path)
    fwd = ["burhan/cli.py", "burhan/engine.py", "burhan/jrand.py",
           "burhan/orphan.py", "tests/test_all.py"]
    back = [p.replace("/", "\\") for p in fwd]
    hits_fwd, _ = _report(tmp_path, fwd)
    hits_back, _ = _report(tmp_path, back)
    assert {h.code for h in hits_fwd} == {"only_tests_call"}, (
        f"fixture sanity (forward-slash baseline): {[h.code for h in hits_fwd]}")
    assert {h.code for h in hits_back} == {"only_tests_call"}, (
        "backslash inputs changed the verdicts — the graph keys are "
        "separator-sensitive")


def test_windows_join_simulation_produces_no_false_positives(tmp_path):
    """RED shape 2 (the 6 live jrand.py false positives): with the
    Windows os.path.join behavior simulated, `from . import jrand`
    must still resolve — rand_int/rand_str are production-wired and
    must NOT be flagged."""
    _tree(tmp_path)
    fwd = ["burhan/cli.py", "burhan/engine.py", "burhan/jrand.py",
           "burhan/orphan.py", "tests/test_all.py"]
    hits, _ = _report(tmp_path, fwd, win_join=True)
    flagged = {h.code for h in hits}
    assert "rand_int" not in flagged and "rand_str" not in flagged, (
        f"production-wired jrand functions flagged under the Windows "
        f"join — the live false-positive class: {flagged}")
    assert "only_tests_call" in flagged, (
        "the simulation must not blind the detector to the real shape")


def test_backslash_tests_reference_still_counts(tmp_path):
    """RED shape 3 (false negative): a test file named with backslashes
    still contributes its references — only_tests_call must be flagged
    even when only the tests path arrives backslash-separated."""
    _tree(tmp_path)
    mixed = ["burhan/cli.py", "burhan/engine.py", "burhan/jrand.py",
             "burhan/orphan.py", "tests\\test_all.py"]
    hits, _ = _report(tmp_path, mixed)
    assert "only_tests_call" in {h.code for h in hits}, (
        "backslash-named test file's references were not collected — "
        "the exclusion/collection prefix is separator-sensitive (FN)")
