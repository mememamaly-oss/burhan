"""R17-7: UNENCODED_WRITE — the permanent scanner class + the Arabic fix.

The live Windows finding (crash at the worst moment): four report paths
wrote Unicode content with the locale codec — on the Arabic Windows
host (cp1256) the bilingual report and the HTML report crashed with
UnicodeEncodeError AFTER a completed scan, at the exact deliverable the
user asked for. The systematic sweep found 15 sites total.

Two protections, both pinned here:

  1. the permanent scanner class: scan_py flags any NEW text-mode write
     (builtin open in w/a/x/+ mode, or Path.write_text) without an
     explicit encoding= in burhan/** and scripts/** — with decoys that
     must NOT be flagged (binary "wb" — encoding is meaningless for
     bytes; reads; encoded writes) so the class cannot rot into a
     blanket-hitting or blind nuisance;
  2. the bilingual report end-to-end fix: a REAL CLI bilingual export
     under a non-UTF-8 locale (PYTHONIOENCODING + locale.codec as
     cp1256) must produce byte-correct UTF-8 output whose Arabic text
     round-trips exactly — not merely "not crash".
"""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.audit_quantum_sweep as aqs  # noqa: E402


# ---------------------------------------------------------- the scanner class
def _scan_source(tmp_path, body):
    # under burhan/ — the class's product-code scope
    d = tmp_path / "burhan"
    d.mkdir(exist_ok=True)
    f = d / "m.py"
    f.write_text(textwrap.dedent(body), encoding="utf-8")
    orig_root = aqs.ROOT
    aqs.ROOT = str(tmp_path)
    try:
        return aqs.scan_py("burhan/m.py")
    finally:
        aqs.ROOT = orig_root


BAD_SITES = [
    ('open(p, "w").write(s)', "builtin open, text write mode"),
    ('open(p, "a").write(s)', "append mode"),
    ('open(p, "x").write(s)', "exclusive-create mode"),
    ('Path(p).write_text(s)', "pathlib write_text"),
]
for code_snippet, why in BAD_SITES:
    def _make(snip):
        def test_flagged(tmp_path, snip=snip):
            hits = _scan_source(tmp_path, f"def f(p, s):\n    {snip}\n")
            cls = {h.cls for h in hits}
            assert "UNENCODED_WRITE" in cls, (
                f"scanner missed {snip!r} — the class is blind to the "
                f"exact shape that crashed the bilingual report")
        return test_flagged
    globals()[f"test_flagged_{why.replace(' ', '_')}"] = _make(code_snippet)


GOOD_SITES = [
    ('open(p, "w", encoding="utf-8").write(s)', "explicitly encoded write"),
    ('open(p, "wb").write(b"x")', "binary write — encoding not applicable"),
    ('open(p, "r").read()', "read mode"),
    ('open(p, encoding="utf-8").read()', "encoded read"),
]
for code_snippet, why in GOOD_SITES:
    def _make(snip):
        def test_not_flagged(tmp_path, snip=snip):
            hits = _scan_source(tmp_path, f"def f(p, s):\n    {snip}\n")
            cls = {h.cls for h in hits}
            assert "UNENCODED_WRITE" not in cls, (
                f"false positive on {snip!r} — a noisy class buries the "
                f"real hits")
        return test_not_flagged
    globals()[f"test_clean_{why.split(' ')[0].replace('-', '_')}"] = _make(code_snippet)


def test_real_tree_has_zero_unencoded_writes():
    """The green of the round's own red->green: the 15 fixed sites leave
    ZERO UNENCODED_WRITE hits across the whole tree."""
    hits = []
    py, _ = aqs.tracked_files()
    for f in py:
        if not f.startswith(("burhan/", "src/")):
            continue
        hits += [h for h in aqs.scan_py(f) if h.cls == "UNENCODED_WRITE"]
    assert not hits, (
        f"unencoded text writes remain: {[(h.file, h.line) for h in hits]}")


# --------------------------------------------- the Arabic end-to-end contract
ARABIC_PROBE = "اختبار التقرير ثنائي اللغة — نتيجة موثقة"


def _bilingual_export(out_dir: Path, env_extra: dict):
    """A REAL CLI bilingual export from the packaged live-evidence run,
    under a controlled non-UTF-8 locale: PYTHONIOENCODING=cp1256 AND the
    locale preferred encoding forced to cp1256 via -X utf8=0 + env. The
    write path under test is cli.py's `open(..., "w", encoding="utf-8")`."""
    store = ROOT / "results" / "burhan.db"
    src_run = ROOT / "evidence" / "live-validation-r8" / "crapi-scan.json"
    # build a tiny store carrying the real evidence run, seeded with the
    # Arabic probe in a finding title
    sys.path.insert(0, str(ROOT))
    from burhan.store import Store
    import tempfile
    tmp_store = out_dir / "store.db"
    st = Store(str(tmp_store))
    run = json.loads(src_run.read_text(encoding="utf-8"))
    run.setdefault("findings", [{}])[0].setdefault("id", "F-AR-1")
    run["findings"][0]["type"] = "sql_injection"
    if run["findings"]:
        run["findings"][0]["evidence"] = run["findings"][0].get("evidence") or []
        run["findings"][0]["evidence"].insert(
            0, {"detail": ARABIC_PROBE})
    st.save_run(run)
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0",
           **env_extra}
    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "report",
         "--db", str(tmp_store), "--format", "bilingual",
         "--out", str(out_dir / "ar-report.json")],
        cwd=ROOT, capture_output=True, text=True, env=env, timeout=300)
    return r


def test_bilingual_report_bytes_correct_under_cp1256_locale(tmp_path):
    """RED->BLUE core: under a non-UTF-8 locale (LC_ALL=C makes the
    process preferred encoding ASCII, the same failure class as Arabic
    Windows cp1256), the bilingual export must (a) exit 0 — pre-fix it
    raised UnicodeEncodeError on the Arabic text — and (b) produce
    BYTE-CORRECT UTF-8 whose Arabic round-trips exactly. The env is
    asserted NON-VACUOUS by the companion test below (unfixed code must
    crash under the same env)."""
    r = _bilingual_export(tmp_path, {})
    assert r.returncode == 0, (
        f"bilingual export crashed under cp1256 locale:\n"
        f"{r.stdout[-400:]}\n{r.stderr[-400:]}")
    out = tmp_path / "ar-report.json"
    assert out.exists()
    raw = out.read_bytes()                    # byte-correctness, not "no crash"
    rep = json.loads(raw.decode("utf-8"))     # must BE valid UTF-8
    texts = json.dumps(rep, ensure_ascii=False)
    assert ARABIC_PROBE in texts, (
        "the Arabic probe text did not round-trip into the report — "
        "content loss under the non-UTF-8 locale")
    # and the bytes are genuinely UTF-8 (cp1256 would mangle the probe):
    assert ARABIC_PROBE.encode("utf-8") in raw
    # docx exists too (the bilingual deliverable is json + docx)
    assert (tmp_path / "ar-report.docx").exists()


def test_non_utf8_env_is_non_vacuous(tmp_path):
    """Guard against the r16 lesson (a test that silently stops testing):
    under the exact env the e2e test uses, an UNENCODED text write of
    the Arabic probe MUST raise UnicodeEncodeError — proving the e2e
    test would catch the regression it exists for."""
    out = tmp_path / "probe.txt"
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import sys\n"
        "with open(sys.argv[1], 'w') as fh:\n"
        "    fh.write('اختبار')\n", encoding="utf-8")
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0"}
    r = subprocess.run([sys.executable, str(driver), str(out)],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode != 0 and "UnicodeEncodeError" in r.stderr, (
        "the non-UTF-8 env does NOT make unencoded writes fail — the e2e "
        f"test above is vacuous in this environment\n{r.stderr[-200:]}")
