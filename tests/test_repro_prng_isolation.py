"""Part-0 gate (2026-10-30): repro.py's SeededPRNG/derive_stream is
deterministic-by-design (SplitMix64) for replay/determinism verification
only — NOT a CSPRNG. This suite pins, by grep over the committed source,
that its output is never used as real secret-protection key material:

  1. no module outside burhan/repro.py imports or executes its streams;
  2. the real secret paths (vault/proof/audit/orchestrator) carry no
     repro dependency at all;
  3. the historical misuse (audit-rb-1, closed 2026-10-21 — SeededPRNG
     fed by sha256(str(seed))[:8] as audit key material) stays removed;
  4. the NOT-a-CSPRNG disclosure stays present in repro.py.

If any of these breaks, this file fails — the deterministic PRNG must
never silently become a secret-protection key source again.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
Burhan = ROOT / "burhan"

IMPORT_RE = re.compile(
    r"from\s+(?:\.|burhan\.)repro\s+import|import\s+burhan\.repro\b")
WORD_RE = re.compile(r"\brepro\b")


def _src(name):
    return (Burhan / name).read_text(encoding="utf-8")


def test_no_runtime_module_consumes_repro_streams():
    offenders = [p.name for p in sorted(Burhan.glob("*.py"))
                 if p.name != "repro.py"
                 and IMPORT_RE.search(p.read_text(encoding="utf-8"))]
    assert offenders == [], \
        f"runtime modules consuming repro streams: {offenders}"


def test_secret_paths_carry_no_repro_dependency():
    for name in ("vault.py", "proof.py", "audit.py", "orchestrator.py"):
        hits = WORD_RE.findall(_src(name))
        assert not hits, f"{name} references repro: {len(hits)} hit(s)"


def test_historical_audit_misuse_stays_removed():
    # audit-rb-1 (closed 2026-10-21): the pre-remand path derived audit
    # keypairs from SeededPRNG fed by sha256(str(seed))[:8] — the CODE
    # path must never come back. The module docstring legitimately
    # documents that history, so this pins code-level usage only:
    src = _src("audit.py")
    assert not IMPORT_RE.search(src)                  # no repro import
    assert not re.search(r"SeededPRNG\s*\(", src)     # no construction
    assert not re.search(r"derive_stream\s*\(", src)  # no stream derivation


def test_repro_declares_not_a_csprng():
    src = _src("repro.py")
    assert "NOT a CSPRNG" in src
    assert "deterministic by design for replay only" in src


def test_subpackages_clean_too():
    offenders = [str(p.relative_to(ROOT)) for p in Burhan.rglob("*.py")
                 if p.name != "repro.py"
                 and IMPORT_RE.search(p.read_text(encoding="utf-8"))]
    assert offenders == [], f"repro stream consumers: {offenders}"

# ---------------------------------------------- r19-2.3 positive control
def test_the_scanner_regex_actually_catches_a_violation():
    """r19-2.3 (owner followup item 3 — vacuous-test audit): the suite's
    negative sweeps (offenders == []) are only evidence if the scanner
    regex can actually CATCH a violation. A broken IMPORT_RE (wrong
    pattern, anchor typo) would pass every negative sweep forever while
    matching nothing. This is the missing positive control: a planted
    offender MUST be caught by the exact regex the sweeps use."""
    planted = (
        "from burhan.repro import SeededPRNG\n"
        "import burhan.repro\n"
        "def f():\n"
        "    return burhan.repro.derive_stream(1)\n"
    )
    assert IMPORT_RE.search(planted), (
        "IMPORT_RE no longer matches a planted repro consumer — the "
        "negative sweeps above are passing vacuously")
    # and the word-level gate for the secret-path check
    assert WORD_RE.search("x = repro.y"), (
        "WORD_RE no longer matches a bare repro reference")
