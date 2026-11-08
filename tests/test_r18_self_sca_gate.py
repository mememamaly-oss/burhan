"""R18 PART 7.2: the self-SCA gate's contract (unit level — no network).

The gate exists to fail loudly on dependency drift; these tests pin the
decision logic itself: baseline comparison, the fail-on-any first-run
mode, the stated (never silent) package.json deferral, and the exit
contract — 0 for clean/no-new, 1 for new advisories.
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.self_sca_gate as gate  # noqa: E402


def _fake_sca(findings):
    def f(manifest, **kw):
        return {"findings": findings}
    return f


def _run(capsys, argv, findings, baseline):
    if baseline is not None:
        base = Path(argv[argv.index("--baseline") + 1])
        base.parent.mkdir(parents=True, exist_ok=True)
        base.write_text(json.dumps({"advisory_ids": baseline}),
                        encoding="utf-8")
    with patch.object(sys, "argv", ["gate"] + argv), \
            patch.object(gate, "build_sca_findings", _fake_sca(findings)):
        rc = gate.main()
    out = capsys.readouterr().out
    return rc, out


def test_clean_vs_empty_baseline_exits_zero(tmp_path, capsys):
    rc, out = _run(capsys, ["--baseline", str(tmp_path / "b.json")], [], [])
    assert rc == 0
    summary = json.loads(out.split("SELF-SCA")[0])
    assert summary["total_advisories"] == 0


def test_new_advisory_fails(tmp_path, capsys):
    """With a NON-EMPTY baseline (the steady state), anything new fails."""
    rc, out = _run(capsys, ["--baseline", str(tmp_path / "b.json")],
                   [{"advisory_id": "GHSA-known-ok"},
                    {"advisory_id": "GHSA-test-0001"}],
                   ["GHSA-known-ok"])
    assert rc == 1
    assert "GHSA-test-0001" in out


def test_empty_baseline_is_first_run_mode_not_failure(tmp_path, capsys):
    """The documented contract: an EMPTY baseline means first-run
    calibration (the gate reports, but does not fail — the owner commits
    the baseline after triage). Failing on it would brick the first
    scheduled run on any genuinely clean manifest."""
    rc, out = _run(capsys, ["--baseline", str(tmp_path / "b.json")],
                   [{"advisory_id": "GHSA-test-0001"}], [])
    assert rc == 0
    assert "GHSA-test-0001" in out  # reported, not silent


def test_baseline_advisory_passes(tmp_path, capsys):
    rc, _ = _run(capsys, ["--baseline", str(tmp_path / "b.json")],
                 [{"advisory_id": "GHSA-known-ok"}], ["GHSA-known-ok"])
    assert rc == 0


def test_package_deferral_is_stated_not_silent(tmp_path, capsys):
    rc, out = _run(capsys, ["--baseline", str(tmp_path / "b.json")], [], [])
    summary = json.loads(out.split("SELF-SCA")[0])
    assert any("package-lock.json" in d for d in summary["deferred"])
    assert any("defer" in d for d in summary["deferred"])


def test_fail_on_any_mode(tmp_path, capsys):
    # no baseline file at all + --fail-on-any: every finding is new
    rc, out = _run(capsys, ["--baseline", str(tmp_path / "none.json"),
                            "--fail-on-any"],
                   [{"advisory_id": "GHSA-first-run"}], None)
    assert rc == 1
