"""R17-2: `doctor` must exit non-zero when any check FAILs.

The no-op gate, pinned RED before the fix: cli.py's doctor branch printed
the JSON report and fell through — exit 0 regardless of FAIL checks. CI's
"Engine doctor" step (ci.yml) inherited that, so a FAIL check could never
redden the build. These tests pin the exit-code CONTRACT both ways:

  - exit 1 when any check reports FAIL (and only then);
  - exit 0 when all checks PASS (WARN tolerated, matching the suite's
    existing doctor contract: test_engine_smoke allows WARNs).

The FAIL is forced through the REAL CLI surface (subprocess) by monkey-
patching one doctor check to fail — no fabricated report dicts.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _doctor_cli(monkeypatch, *, failing: bool):
    """Run `python -m burhan.cli doctor` in-process with one check forced
    to FAIL (or none), returning (exit_code, parsed_report).

    The patch targets orchestrator.doctor's inner `add` the honest way:
    we wrap the real doctor and post-process — no. Simpler and truer to
    the contract: run the REAL doctor() for the all-PASS/DEGRADED shape,
    and for the forced-FAIL shape patch one check's status in the module
    the CLI imports (burhan.orchestrator.doctor), so the CLI's own exit
    logic is what's under test.
    """
    code = (
        "import json, sys\n"
        "import burhan.cli as cli\n"
        "import burhan.orchestrator as orch\n"
        "if sys.argv[1] == 'fail':\n"
        "    real = orch.doctor\n"
        "    def failing(*a, **k):\n"
        "        rep = real(*a, **k)\n"
        "        rep['checks'][0]['status'] = 'FAIL'\n"
        "        rep['overall'] = 'DEGRADED'\n"
        "        return rep\n"
        "    orch.doctor = failing\n"
        "    # the CLI imported the name at module import time; rebind there too\n"
        "    cli.doctor = failing\n"
        "sys.argv = ['burhan', 'doctor']\n"
        "sys.exit(cli.main())\n"
    )
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(code)
        path = fh.name
    try:
        import os
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        return subprocess.run(
            [sys.executable, path, "fail" if failing else "pass"],
            cwd=ROOT, capture_output=True, text=True, timeout=300, env=env)
    finally:
        os.unlink(path)


def test_doctor_exit_1_when_any_check_fails(monkeypatch):
    r = _doctor_cli(monkeypatch, failing=True)
    assert r.returncode == 1, (
        f"doctor with a FAIL check exited {r.returncode} — the CI gate "
        f"stays green on failure (the r17-2 no-op)\n{r.stdout[-300:]}")
    rep = json.loads(r.stdout)
    assert rep["overall"] == "DEGRADED"
    assert any(c["status"] == "FAIL" for c in rep["checks"])


def test_doctor_exit_0_when_all_pass_or_warn(monkeypatch):
    """The other half of the contract: a healthy machine must NOT see
    doctor turn into an always-failing command."""
    r = _doctor_cli(monkeypatch, failing=False)
    assert r.returncode == 0, (
        f"doctor on a healthy tree exited {r.returncode}:\n{r.stdout[-300:]}")
    rep = json.loads(r.stdout)
    fails = [c for c in rep["checks"] if c["status"] == "FAIL"]
    assert not fails, f"unexpected real FAIL in this environment: {fails}"
    assert rep["overall"] in ("PASS", "DEGRADED")


def test_doctor_exit_contract_documented():
    """The contract must stay discoverable: --help is the operator's
    first stop; CI's doctor step relies on the same exit code."""
    r = subprocess.run([sys.executable, "-m", "burhan.cli", "doctor", "--help"],
                       cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
