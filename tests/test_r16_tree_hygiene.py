"""R16-1: the tree-hygiene gate bites, and bites precisely.

Red -> green on the real tree: the gate was written BEFORE
results/replay-rate-limit.json (the r13 leftover) was untracked and
FAILED on it; untracking turned it green (that integration check is the
last test below, run against the actual repo). The unit cases pin the
classifier contract so the anchors, the allowlist precedence, and the
exit codes cannot silently rot — each one kills a specific mutant:

  - anchor removal (^results/ -> results/): myresults/a.json and
    results.py must stay ALLOWED;
  - allowlist bypass: an allowlisted results/ path must pass even though
    it matches a deny rule (precedence is the contract);
  - rule removal: every deny class has at least one positive case;
  - the evidence doctrine: SCA fixtures / vulnapp / gitleaks config are
    INTENTIONAL tracked evidence and must never be flagged.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_tree_hygiene as gate  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

MUST_DENY = [
    "results/scan.json",                     # the r15 artifact, exactly
    "results/benchmark_baseline.json",       # cli.py repair-demo output
    "results/replay-rate-limit.json",        # the r13 leftover
    "results/nested/deep/out.json",          # any depth under results/
    "CAPABILITY_MATRIX.md",                  # root lab artifact
    "audit-19axis/CAPABILITY_MATRIX.md",     # anywhere in the tree
]

MUST_ALLOW = [
    "src/app.ts",
    "burhan/cli.py",
    "README.md",
    "results.py",                            # anchor: a module, not the dir
    "myresults/a.json",                      # anchor: prefix is not the dir
    "docs/results-overview.md",              # substring, not a path segment
    # the evidence doctrine — intentional test data, never a violation:
    "evidence/layers/sca/inputs/requirements.txt",
    "evidence/layers/sca/inputs/package-lock.json",
    "evidence/security-sweep-2026-10-31/gitleaks-default-config-v8.30.1.toml",
    "fixtures/vulnapp.py",
]


def test_classifier_denies_every_artifact_class():
    for path in MUST_DENY:
        verdict = gate.violation(path)
        assert verdict is not None, f"expected denial for {path}"
        assert verdict[0] in ("runtime output", "lab artifact")


def test_classifier_allows_product_and_evidence():
    for path in MUST_ALLOW:
        assert gate.violation(path) is None, f"false denial for {path}"


def test_allowlist_overrides_deny_rules(monkeypatch):
    # A reviewed exception must pass EVEN THOUGH it matches ^results/ —
    # precedence: allowlist first. Kills the bypass mutant both ways:
    # skipping the allowlist check fails here, and an unconditional
    # pass-all fails the deny battery above.
    monkeypatch.setattr(
        gate, "ALLOWLIST",
        {"results/legit.json": ("2026-11-07", "reviewed exception for X")},
    )
    assert gate.violation("results/legit.json") is None
    assert gate.violation("results/not-allowlisted.json") is not None


def test_gate_fails_loudly_on_tracked_artifact(monkeypatch, capsys):
    monkeypatch.setattr(
        gate, "tracked_files",
        lambda: ["src/app.ts", "results/scan.json", "burhan/cli.py"],
    )
    monkeypatch.setattr(sys, "argv", ["audit_tree_hygiene.py", "--ci-gate"])
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "::error file=results/scan.json" in out
    assert "src/app.ts" not in out.split("tree hygiene:")[1]  # only the bad file


def test_gate_passes_a_clean_tree(monkeypatch, capsys):
    monkeypatch.setattr(
        gate, "tracked_files",
        lambda: ["src/app.ts", "burhan/cli.py", "evidence/layers/sca/inputs/requirements.txt"],
    )
    monkeypatch.setattr(sys, "argv", ["audit_tree_hygiene.py", "--ci-gate"])
    assert gate.main() == 0
    assert "clean" in capsys.readouterr().out


def test_real_repo_tree_is_clean_integration():
    """The green of the red->green pair: run the actual gate exactly as
    CI does. If someone re-tracks a runtime artifact, this fails BEFORE
    the PR-level CI job does."""
    r = subprocess.run(
        [sys.executable, "scripts/audit_tree_hygiene.py", "--ci-gate"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert r.returncode == 0, f"gate red on the real tree:\n{r.stdout}{r.stderr}"
