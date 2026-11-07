"""R17-8: subprocess spawns must EXTEND the inherited environment, scoped.

The live Windows finding: ci_fixture_run.py and repro_attest.py spawned
the fixture with a wholesale-replaced env
(env={"PORT": ..., "PATH": "/usr/bin:/bin"}). On Windows that breaks
networking outright (WinError 10106 — Winsock needs SYSTEMROOT), and on
every platform it drops whatever the host legitimately requires
(CI proxy vars, TEMP, etc.).

The DELIBERATE reason the replacement existed (documented in the fix):
fixtures/vulnapp.py reads BEHAVIORAL env vars — DELAY_MS, AUTH_TTL,
CONFUSION, BFLA, SHADOW, RACE_MODE, SIGNOFF — used by chaos/demo runs.
An inherited env carrying e.g. BFLA=1 or RACE_MODE=broken would mutate
the fixture and break the deterministic record (TP=38/FP=0) that the
benchmark and reproducibility gates assert.

The fix contract (both sides pinned):
  - the spawn EXTENDS the inherited environment (a sentinel var from
    the parent env survives into the fixture — Windows networking and
    CI vars work);
  - the isolation is PRESERVED but scoped: every vulnapp behavioral
    var is neutralized (set to "") so determinism cannot be mutated
    from the outside;
  - PORT is still forced to the intended port.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# the production single source of truth — the scripts import THE SAME
# module (no drift between ci_fixture_run and repro_attest possible)
from burhan.fixture_env import FIXTURE_NEUTRALIZED_ENV, fixture_env

_fixture_env = fixture_env  # the name the tests below were written against

# r17-8 leak fix: the process env AS THIS MODULE FOUND IT. The guard
# test at the bottom compares against this — a test module must leave
# the shared pytest process environment exactly as it found it.
_ENV_BASELINE = dict(os.environ)


def _script_env_call(path: str) -> str:
    """Extract the env= argument text from a script's fixture spawn —
    accepts both the literal-dict form and the helper-call form."""
    import re
    src = Path(path).read_text(encoding="utf-8")
    m = re.search(r"env=(\{[^}]*\}|[A-Za-z_.]+\([^)]*\))", src)
    return m.group(1) if m else ""


def test_scripts_extend_inherited_environment():
    """RED side 1: both scripts must spawn with the extend-inherited
    helper (the reference-correct pattern cli.py's own benchmark
    spawner uses) — not a wholesale-replaced minimal dict."""
    for script in ("scripts/ci_fixture_run.py", "scripts/repro_attest.py"):
        call = _script_env_call(script)
        assert "fixture_env(" in call, (
            f"{script} still replaces the environment wholesale "
            f"({call!r}) — Windows Winsock (SYSTEMROOT), CI proxies and "
            f"host-required vars are dropped")


def test_scripts_scope_the_isolation_to_vulnapp_vars():
    """RED side 2: the deliberate isolation (vulnapp behavioral vars)
    must SURVIVE the fix — neutralized explicitly, not lost."""
    for script in ("scripts/ci_fixture_run.py", "scripts/repro_attest.py"):
        src = Path(script).read_text(encoding="utf-8")
        assert "fixture_env(" in src and "env={" not in src, (
            f"{script} lost the behavioral-var isolation — an inherited "
            f"BFLA=1 or RACE_MODE=broken would mutate the fixture and "
            f"break the deterministic record (TP=38/FP=0)")


def test_env_helper_contract():
    """The shared helper: inheritance + scoped neutralization + forced
    PORT, proven with a live sentinel through a REAL subprocess."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        driver = Path(d) / "driver.py"
        driver.write_text(
            "import os\n"
            "print(os.environ.get('R17_SENTINEL', 'MISSING'))\n"
            "print(os.environ.get('BFLA', 'MISSING'))\n"
            "print(os.environ.get('DELAY_MS', 'MISSING'))\n"
            "print(os.environ.get('PORT', 'MISSING'))\n",
            encoding="utf-8")
        # r17-8 leak fix: save/restore, not selective delete. The
        # original finally deleted R17_SENTINEL and BFLA but forgot
        # DELAY_MS — the hostile var leaked into the whole pytest
        # process and slowed every later fixture spawn by +250ms/request
        # (Engine CI: 95 min on this branch's base vs 6.5 on main; an
        # unbounded hang after the p2-p7 merge). Restore also gives back
        # a var an operator shell legitimately exported.
        _saved = {k: os.environ.get(k)
                  for k in ("R17_SENTINEL", "BFLA", "DELAY_MS")}
        os.environ["R17_SENTINEL"] = "survives"
        os.environ["BFLA"] = "1"       # hostile behavioral var from outside
        os.environ["DELAY_MS"] = "250" # hostile numeric var (float-parsed)
        try:
            env = _fixture_env(8123)
            r = subprocess.run([sys.executable, str(driver)],
                               capture_output=True, text=True, env=env,
                               timeout=60)
            sentinel, bfla, delay, port = r.stdout.split()
            assert sentinel == "survives", "inherited var was dropped"
            assert bfla == "MISSING", (
                f"behavioral var NOT neutralized: BFLA={bfla}")
            assert delay == "MISSING", (
                f"numeric behavioral var NOT removed: DELAY_MS={delay} "
                f"(an empty string would crash vulnapp's float() — the "
                f"live first-attempt bug of this very fix)")
            assert port == "8123", f"PORT not forced: {port}"
        finally:
            for _k, _v in _saved.items():
                if _v is None:
                    os.environ.pop(_k, None)
                else:
                    os.environ[_k] = _v


def test_process_env_restored_to_baseline():
    """The leak this module itself shipped once: the hostile DELAY_MS=250
    set for the helper-contract test survived its finally block (which
    cleaned R17_SENTINEL and BFLA but forgot DELAY_MS), poisoned the
    whole pytest process env, and reached every later in-process fixture
    spawn that extends os.environ (race prober, replay fidelity, shadow,
    siem): +250ms per request. On the branch's original base the Engine
    CI job crawled to 95 minutes (vs main's 6.5); after the p2-p7 merge
    it crossed into an unbounded hang. This guard would have been RED
    on the leak and is the module's permanent no-drift pin."""
    # PYTEST_CURRENT_TEST is pytest's own per-test bookkeeping var
    # (set during the call phase, removed after) — not pollution.
    now = {k: v for k, v in os.environ.items()
           if k != "PYTEST_CURRENT_TEST"}
    base = {k: v for k, v in _ENV_BASELINE.items()
            if k != "PYTEST_CURRENT_TEST"}
    if now != base:
        leaked = {k: (v, base.get(k))
                  for k, v in now.items() if base.get(k) != v}
        missing = {k: v for k, v in base.items() if k not in now}
        raise AssertionError(
            f"this test module polluted the shared process env: "
            f"changed/added={leaked} removed={missing}")
