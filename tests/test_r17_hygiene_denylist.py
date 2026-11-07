"""R17-1: a filename denylist for known junk that must never be tracked.

The `--` file (empty, born of a mistyped CLI flag) was removed in 7ed4cdf
and re-tracked in 2a4210e — the tree-hygiene gate watched results/ and
CAPABILITY_MATRIX.md only, so nothing failed when it came back. This test
pins the permanent denylist with a REAL git index, exactly the way the
accident happened: staging `--` must turn the gate red; removing it must
turn the gate green again.
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_tree_hygiene as gate  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GATE = str(ROOT / "scripts" / "audit_tree_hygiene.py")


def _run_gate(cwd):
    return subprocess.run([sys.executable, GATE, "--ci-gate"],
                          cwd=cwd, capture_output=True, text=True)


def _mini_repo(tmp_path):
    """A real git repo (index only — ls-files reads the index, no commit
    needed) with one product file and the junk file staged, the exact
    shape of the 2a4210e recurrence."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text("x", encoding="utf-8")
    (tmp_path / "--").write_text("", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "src/app.ts"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "--", "./--"], cwd=tmp_path, check=True)
    return tmp_path


def test_classifier_denies_the_stray_dashdash():
    verdict = gate.violation("--")
    assert verdict is not None, "the exact stray file must be denied"
    assert verdict[0] == "stray flag artifact"


def test_classifier_deny_is_anchored_to_the_exact_name():
    assert gate.violation("sub/dir/--") is not None     # anywhere in the tree
    assert gate.violation("--README.md") is None       # prefix, not the name
    assert gate.violation("dash--dash.py") is None     # substring, not the name


def test_gate_fails_on_staged_stray_and_recovers_after_removal(tmp_path):
    repo = _mini_repo(tmp_path)
    r = _run_gate(repo)
    assert r.returncode == 1, (
        "gate stayed green with the stray `--` staged — the 2a4210e "
        f"recurrence class is unguarded\n{r.stdout}")
    assert "::error file=--" in r.stdout
    # the recovery half of the pair: removal must turn the gate green again
    subprocess.run(["git", "rm", "--cached", "-q", "--", "./--"],
                   cwd=repo, check=True)
    os.unlink(repo / "--")
    r2 = _run_gate(repo)
    assert r2.returncode == 0, f"gate still red after removal:\n{r2.stdout}"


def test_real_repo_tree_is_clean_integration():
    """The real tree must carry no denylisted file — the green side of
    THIS round's red->green (the file is untracked in the same commit
    that adds the deny rule)."""
    r = _run_gate(ROOT)
    assert r.returncode == 0, f"gate red on the real tree:\n{r.stdout}"
