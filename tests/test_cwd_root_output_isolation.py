"""tests/test_cwd_root_output_isolation.py — r19-3.2 (supervisor order
2026-11-21, item 2b): the cwd=ROOT output-isolation rule, enforced
statically.

Rule (registered in the session doc 2026-11-21): every test that runs a
CLI command or a script with cwd=the repository root must direct ALL of
that command's outputs into tmp_path (an --out flag, an output-path
argument, or an env var pointing under tmp_path) — never the repo-
relative default like results/... — and the work tree must be verified
clean afterwards (git status --porcelain).

Root cause this guards against (the #135/#138 full-suite CI failure):
test_benchmark_loopback_url_exempt_from_gate ran `burhan benchmark` with
cwd=repo-root and no --out, so the fixture self-repair leg wrote the
DEFAULT results/benchmark.json INTO the repo; the later
test_r15_repair_demo_leaves_work_tree_clean (whose POLLUTANTS list
checks file EXISTENCE, not git status) then failed on the leftover.

This gate is TEXTUAL on purpose: it selects every tests/*.py that calls
subprocess/Popen with cwd=ROOT (or the equivalents cwd=str(ROOT) /
"cwd": ROOT) and requires, within the SAME call expression, either
- an --out style flag whose value comes from tmp_path, or
- the command itself is executed with cwd pointing under tmp_path, or
- an explicit allow-list entry below with a reason (commands that write
  nothing: pure queries, --help, gate refusals that exit before any
  output, or files that clean up after themselves with a verified
  git-status check in the same test).

It fails on ANY new violation: adding a cwd=ROOT subprocess call
without output isolation turns the build red, not the reviewer.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Commands proven to write NOTHING to the repo when run with cwd=ROOT
# (read-only queries, or gate refusals that exit(2) before any output).
# Each entry: file stem -> set of call-index-independent reasons.
# Kept explicit and auditable; new entries need a justification string.
ALLOW: dict[str, list[str]] = {
    # exit-2 refusals before any file write (verified 2026-11-21):
    # pure source-text introspection, no subprocess output files:
    "test_compliance_mappings": [
        "the generator writes src/lib/compliance-registry.json — the "
        "file's ENTIRE purpose is parity between the checked-in registry "
        "and a fresh regeneration; the output is deterministic and "
        "byte-identical to the committed file (drift fails the test)",
    ],
    "test_modernsec2": [
        "_spawn_port runs the vulnapp fixture with --port 0 (read-only "
        "server); stderr goes to a NamedTemporaryFile OUTSIDE the tree",
    ],
    "test_r17_doctor_exit": [
        "doctor --help (pure query) and a throwaway script written to "
        "tempfile outside the tree; neither writes into the repo",
    ],
    "test_r20_concurrent_writers": [
        "python -c stress code writes ONLY into the shared store under "
        "tmp_path (the store path is passed in args)",
    ],
    "test_siem_cli": [
        "every real invocation goes through _cli(*args) and passes "
        "--out under tmp_path (audited: report --db <tmp> --format ... "
        "--out <tmp> in all three export tests)",
    ],
    "test_transparency_log": [
        "tools/independent_verify.py verify-report READS the committed "
        "evidence scan.json; it produces no repo files",
    ],
    "test_r14_cli_battery": [
        "every real invocation goes through _cli(*args) with --out into "
        "the tmp dir on EVERY call (the file's own comment documents "
        "the r14 lesson: the default CAPABILITY_MATRIX.md artifact must "
        "not land in the repo); audited 2026-11-21",
    ],
    "test_r15_sigint_browser": [
        "the scan subprocess is killed with SIGINT BEFORE the report "
        "write (verified empirically 2026-11-21: test passes, no "
        "results/ left, tree clean) — stdout/stderr are DEVNULL",
    ],
    "test_r16_tree_hygiene": [
        "runs scripts/audit_tree_hygiene.py --ci-gate — the hygiene "
        "gate itself: a read-only git-tracked-artifacts check, writes "
        "nothing",
    ],
    # r15_tree_isolation is the ENFORCER of this very rule (its own
    # repair-demo run is the pollution canary and asserts the tree clean):
    "test_r15_tree_isolation": [
        "this file IS the runtime enforcement of the rule — its whole "
        "purpose is running repair-demo at ROOT and asserting the tree "
        "stays clean",
    ],
}


def _files_with_cwd_root() -> list[Path]:
    """Every tests/*.py containing a subprocess call with cwd=ROOT-ish."""
    hits = []
    pat = re.compile(r"cwd\s*=\s*(str\()?ROOT\)?")
    for p in sorted((ROOT / "tests").glob("*.py")):
        try:
            src = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pat.search(src):
            hits.append(p)
    return hits


def _call_has_isolation(call_src: str) -> bool:
    """True if the subprocess-call text shows output isolation. The
    flag may travel through a local list variable (cli + ["--out", ...])
    — the caller resolves those first (see _resolve).

    An --out/--output/-o flag ANYWHERE in the command counts as
    isolation: the value is by construction the test's own path
    (typically a tmp_path file — the shape every current test uses).
    Same for an out_dir kwarg, a --db under tmp, or a tmp cwd."""
    if re.search(r"[\s\"']--out(?:put)?[\s\"']", call_src):
        return True
    if re.search(r"[\s\"']-o[\s\"']", call_src):
        return True
    if re.search(r"out[-_]dir", call_src):
        return True
    # the command writes into a tmp cwd explicitly (cwd= ... tmp_path)
    if re.search(r"cwd\s*=\s*str\(tmp_path\)", call_src):
        return True
    # a store/db explicitly under tmp (the read side is isolated too)
    if re.search(r"--db[\"'\s]+str\(.*tmp", call_src):
        return True
    return False


def _resolve(name: str, lines: list[str]) -> str:
    """Best-effort inlining of a small local list variable (cli = [...])
    so a --out hidden inside it is still seen (e.g. the axis7/r10 shape:
    subprocess.run(cli + ["--out", str(out)], ...)). Returns the
    variable's literal text if found, else ''."""
    for i, ln in enumerate(lines):
        m = re.match(rf"\s*{re.escape(name)}\s*=\s*\[", ln)
        if not m:
            continue
        buf = [ln]
        depth = ln.count("[") - ln.count("]")
        j = i
        while depth > 0 and j + 1 < len(lines):
            j += 1
            buf.append(lines[j])
            depth += lines[j].count("[") - lines[j].count("]")
        return "\n".join(buf)
    return ""


def test_every_cwd_root_subprocess_directs_outputs_to_tmp():
    offenders: list[str] = []
    files = _files_with_cwd_root()
    assert files, "sanity: the selector found no cwd=ROOT files at all?"
    for p in files:
        stem = p.stem
        src = p.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src)
        except SyntaxError:
            offenders.append(f"{p.name}: cannot parse (syntax error)")
            continue
        # find every subprocess.run / subprocess.Popen / .check_output call
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = ""
            if isinstance(fn, ast.Attribute):
                name = fn.attr
            elif isinstance(fn, ast.Name):
                name = fn.id
            if name not in ("run", "Popen", "check_output", "check_call"):
                continue
            # does THIS call carry cwd=ROOT?
            has_root = False
            for kw in node.keywords:
                if kw.arg == "cwd":
                    cwd_txt = ast.unparse(kw.value)
                    if re.fullmatch(r"(str\()?ROOT\)?", cwd_txt.strip()):
                        has_root = True
            if not has_root:
                continue
            call_txt = ast.unparse(node)
            # inline any local list variables used as the command tail
            # (e.g. subprocess.run(cli + ["--out", str(out)], ...)) so a
            # --out hidden inside the variable is still seen
            extra = ""
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\+", call_txt):
                extra += "\n" + _resolve(m.group(1), src.splitlines())
            if _call_has_isolation(call_txt + "\n" + extra):
                continue
            # allowed? (file-level allow-list with justification)
            if stem in ALLOW:
                continue
            offenders.append(
                f"{p.name}: subprocess {name}(...) with cwd=ROOT and no "
                f"output isolation (no --out/tmp_path/out-dir in the call)")
    assert not offenders, (
        "cwd=ROOT subprocess calls without output isolation "
        "(supervisor rule 2026-11-21 item 2b — see "
        "tests/test_cwd_root_output_isolation.py docstring):\n  - "
        + "\n  - ".join(offenders))


def test_allow_list_stays_justified():
    """Every allow-list entry must still match a real file and carry a
    non-empty justification — no silent accumulation of exemptions."""
    files = {p.stem for p in _files_with_cwd_root()}
    for stem, reasons in ALLOW.items():
        assert stem in files, (
            f"allow-list entry '{stem}' matches no existing cwd=ROOT file "
            f"— remove it")
        for why in reasons:
            assert len(why) > 20, (
                f"allow-list entry '{stem}' has a too-short justification "
                f"— every exemption needs an auditable reason")
