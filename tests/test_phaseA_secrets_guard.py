"""Phase-A.3b: secrets-tracking deny rules for the tree-hygiene gate.

The gap this closes (Phase A secrets audit, 2026-11-10): the gate watched
runtime artifacts (results/, CAPABILITY_MATRIX.md, `--`) but NOTHING failed
if a credential file got staged. History proves the failure class is real —
`git add -A` swept .env (a 1-line sqlite DATABASE_URL, no secret, verified
twice) into git via the b9c8b03 container-junk commit, and it took until
88fa11c (two weeks) to untrack it. Next time the file might not be a benign
path. These rules make the staging itself the failure:

  - .secrets/**        local credential store (this repo's operator PAT dir)
  - *.pat / *.pem / *.key / id_rsa*  credential-bearing filenames
  - .env, .env.*      the exact 9e9037c accident; .env.example stays
                       ALLOWED (it is the documented template)

Pin with a REAL git index exactly the way test_r17_hygiene_denylist pins
the `--` file: staging the file must turn the gate red; removing it must
turn the gate green again.
"""
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


def _mini_repo(tmp_path, secret_relpath, content="x"):
    """A real git repo (index only, no commit needed — the gate reads
    git ls-files) with one product file and the secret file staged."""
    p = tmp_path / secret_relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "app.ts").write_text("x", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "src/app.ts"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", secret_relpath], cwd=tmp_path, check=True)
    return tmp_path


def test_classifier_denies_credential_paths():
    for path in (".secrets/burhan-github.pat",
                 ".secrets/anything-else",
                 "deploy/server.key",
                 "keys/id_rsa",
                 "certs/web.pem",
                 ".env",
                 ".env.local",
                 "backend/.env.production"):
        verdict = gate.violation(path)
        assert verdict is not None, f"{path} must be denied"
        assert verdict[0] == "credential artifact", path


def test_classifier_keeps_the_documented_template_allowed():
    # .env.example is the shipped template — must NOT be denied
    assert gate.violation(".env.example") is None
    # docs may talk about key files without being one
    assert gate.violation("docs/key-management.md") is None
    # javascript key-handling code is not a credential file
    assert gate.violation("src/lib/apikey.ts") is None
    # fixtures with key-LIKE content keep the evidence doctrine intact:
    # only a true .pem extension is denied — the suffixed .pem.txt form
    # is documentation/fixture text, not a credential file
    assert gate.violation("fixtures/tls/dummy-server.pem.txt") is None


def test_gate_fails_on_staged_pat_and_recovers(tmp_path):
    repo = _mini_repo(tmp_path, ".secrets/burhan-github.pat")
    r = _run_gate(repo)
    assert r.returncode == 1, (
        "gate stayed green with a .secrets/ PAT staged — the "
        f"9e9037c accident class is unguarded\n{r.stdout}")
    assert "::error file=.secrets/burhan-github.pat" in r.stdout
    # the recovery half of the pair: untrack must turn the gate green
    subprocess.run(["git", "rm", "--cached", "-q", ".secrets/burhan-github.pat"],
                   cwd=tmp_path, check=True)
    r2 = _run_gate(tmp_path)
    assert r2.returncode == 0, f"gate did not recover: {r2.stdout}"


def test_gate_fails_on_staged_env_and_recovers(tmp_path):
    repo = _mini_repo(tmp_path, ".env",
                      content="DATABASE_URL=file:/tmp/x.db\n")
    r = _run_gate(repo)
    assert r.returncode == 1 and "::error file=.env" in r.stdout, r.stdout
    subprocess.run(["git", "rm", "--cached", "-q", ".env"],
                   cwd=tmp_path, check=True)
    assert _run_gate(tmp_path).returncode == 0


def test_this_repo_tracks_no_credential_artifacts():
    """The live tree, not a mini repo: nothing denied may be tracked."""
    for path in gate.tracked_files():
        assert gate.violation(path) is None, (
            f"{path} is tracked but looks like a credential artifact — "
            "untrack it or add a reviewed ALLOWLIST entry")
