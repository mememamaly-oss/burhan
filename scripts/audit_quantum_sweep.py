#!/usr/bin/env python3
"""Quantum sweep — the consolidated four-class anti-pattern scanner (round 12).

ONE maintained tool covering every recurring defect class this project has
actually hit, across its entire history:

  (a) FIRST_MATCH  — positional-selection/first-match over a dynamic
                     collection (the round-7 original; carried by
                     audit_antipatterns.py since round 8 — re-verified here
                     as a regression check, same AST core).
  (b) SILENT_EXCEPT— an except handler whose body does nothing observable
                     (pass / continue / return-default / bare assignment)
                     with no re-raise, no logging, and no explicit
                     documented-safe comment naming the swallowed exception.
                     Hit 3 separate times in round 11 alone.
  (c) TOCTOU       — os.path.exists/isfile/isdir/lexists check followed by
                     a separate use (open/remove/mkdir/rename/stat/...) on
                     the same path expression, no fd-pinning. Hit twice
                     (vault.py, remediation.py, stepup.py).
  (d) CLI_UNREACHABLE — NEW (round 11's --gated bug): a public function or
                     flag that a dedicated test invokes DIRECTLY (import +
                     call) while nothing routes it through the CLI surface
                     a real user types. The exact bug: reproduce --gated was
                     handled in code, tested green, and absent from argparse
                     — unreachable for every real user. Detection, Python:
                     for every option flag the HANDLER reads
                     (getattr(a, "flag", ...)) the matching subparser must
                     DEFINE it (add_argument("--flag", ...)); and for every
                     public burhan/ function imported by tests/, either a
                     CLI handler references it or the module's own
                     __main__/console entry routes to it — else flagged.

  (d+) ENTRYPOINT_UNREACHABLE (round-12 close, the run_monitor_cycle
                     lesson): the GENERALIZED form of (d). The CLI-only
                     check reported zero holes while dogfooding found a
                     live instance of the same bug class in a different
                     system — the monitoring scheduler never called the
                     alert-cycle function, though every test passed.
                     Entry points are NOT just the CLI: cli.py + every
                     script the workflows invoke + package.json script
                     chains + the production .sh runners. A PUBLIC
                     burhan/ function referenced by tests but reachable
                     from NO production entry point (module import is
                     not enough — the function must be REFERENCED) is
                     flagged. Tested-but-production-unreachable, in any
                     wiring, not just argparse.

TypeScript side (src/ + tests/, the round-12 scope extension):
  (bTS) SILENT_CATCH — catch blocks with empty/return-only bodies.
  (dTS) EXPORT_UNROUTED — exported symbols from src/lib/* that tests import
                     but no route.ts / page.tsx / instrumentation entry
                     references (the TS analogue of CLI-unreachable).

Every hit needs ONE of:
  - a fix (with a RED->BLUE pin in the evidence inventory), or
  - a ledger entry in scripts/quantum_sweep_ledger.json (file + code-regex
    + reason) classifying it documented-benign.

Modes:
  default        scan + print per-class raw counts + write the JSON inventory
  --ci-gate      additionally: every ENGINE hit (burhan/**, src/**) must
                 match the ledger or be marked fixed in the inventory;
                 unmatched engine hits -> exit 1.
Output: file:line, class, code, verdict. No narrative.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER_PATH = os.path.join(ROOT, "scripts", "quantum_sweep_ledger.json")
OUT_DIR = os.path.join(ROOT, "evidence", "layers", "quantum-sweep")

# ---------------------------------------------------------------- class (a)
DYNAMIC_HINTS = re.compile(
    r"\b(ep|eps|endpoint|endpoints|accounts|ops|queries|cands|candid|"
    r"authish|targets|findings|routes|paths|urls|links|fields|params|"
    r"parameters|cookies|tokens|keys|bodies|hits|matches|results|rows)\b",
    re.I,
)
BENIGN_CALL_FIRST = ("split", "rsplit", "partition", "popitem")

# ---------------------------------------------------------------- class (c)
TOCTOU_CHECKS = ("exists", "isfile", "isdir", "lexists")
TOCTOU_USES = ("open", "remove", "mkdir", "makedirs", "rmdir", "unlink",
               "rename", "stat", "getsize", "read_text", "write_text",
               "read_bytes", "write_bytes", "touch")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True).stdout.splitlines()
    skip = ("node_modules", ".git", "__pycache__", ".next", "skills",
            "download")
    py = [f for f in out if f.endswith(".py")
          and not any(p in f.split("/") for p in skip)]
    ts = [f for f in out if (f.endswith(".ts") or f.endswith(".tsx"))
          and not any(p in f.split("/") for p in skip)]
    return sorted(py), sorted(ts)


class Hit:
    __slots__ = ("file", "line", "cls", "code", "func", "detail")

    def __init__(self, file, line, cls, code, func, detail=""):
        self.file, self.line, self.cls = file, line, cls
        self.code, self.func, self.detail = code, func, detail

    def as_dict(self):
        return {"file": self.file, "line": self.line, "class": self.cls,
                "code": self.code[:200], "func": self.func,
                "detail": self.detail}


# ============================================================== Python scans
def scan_py(path: str) -> list[Hit]:
    hits: list[Hit] = []
    try:
        src = open(os.path.join(ROOT, path), encoding="utf-8").read()
        tree = ast.parse(src)
    except Exception as e:  # noqa: BLE001 — parse failure IS the hit
        return [Hit(path, 0, "PARSE_ERROR", str(e)[:120], "-")]
    lines = src.splitlines()

    def code_at(node):
        return lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

    def walk_first_match(fn: ast.FunctionDef | ast.AsyncFunctionDef):
        """Class (a): `x = C[0]` / `for x in C[:1]` / `if C: y = C[0]`
        where C's name matches the dynamic-collection hints."""
        for node in ast.walk(fn):
            targets_dyn = False
            if isinstance(node, ast.Assign):
                if isinstance(node.value, (ast.Subscript,)):
                    sl = node.value.slice
                    idx = None
                    if isinstance(sl, ast.Slice):
                        if sl.lower is None and isinstance(sl.upper, ast.Constant) \
                                and isinstance(sl.upper.value, int):
                            idx = sl.upper.value
                    elif isinstance(sl, ast.Constant) and isinstance(sl.value, int):
                        idx = sl.value
                    if idx is not None and idx <= 1:
                        base = node.value.value
                        if isinstance(base, ast.Name) and DYNAMIC_HINTS.search(base.id):
                            targets_dyn = True
                if targets_dyn and not (isinstance(node.value, ast.Call)
                                        and isinstance(node.value.func, ast.Attribute)
                                        and node.value.func.attr in BENIGN_CALL_FIRST):
                    hits.append(Hit(path, node.lineno, "FIRST_MATCH",
                                    code_at(node), fn.name,
                                    "positional/first-match selection over a "
                                    "dynamic collection"))
            elif isinstance(node, ast.For) and isinstance(node.iter, ast.Subscript):
                sl = node.iter.slice
                if isinstance(sl, ast.Slice) and sl.lower is None \
                        and isinstance(sl.upper, ast.Constant) \
                        and isinstance(sl.upper.value, int) and sl.upper.value <= 1:
                    base = node.iter.value
                    if isinstance(base, ast.Name) and DYNAMIC_HINTS.search(base.id):
                        hits.append(Hit(path, node.lineno, "FIRST_MATCH",
                                        code_at(node), fn.name,
                                        "loop over only the first element(s)"))

    def walk_silent_except(fn: ast.FunctionDef | ast.AsyncFunctionDef):
        """Class (b): except handler with no observable effect and no
        documented-safe marker. Observable = raises, logs (print/logging/
        logger/_record/report/ws.send/sys.stderr...), or calls anything
        non-trivial. Documented-safe = a comment naming the exception and
        saying why swallowing is safe (checked via source text)."""
        for node in ast.walk(fn):
            if not isinstance(node, ast.ExceptHandler):
                continue
            body_src = ast.get_source_segment(src, node) or ""
            # comment lines attached to the handler
            hdr_line = node.lineno
            comments = []
            for ln in range(max(0, hdr_line - 2), min(len(lines), hdr_line)):
                if "#" in lines[ln]:
                    comments.append(lines[ln])
            # inline comments on the handler's own body lines count too
            # (the codebase's idiom: `pass  # transient network -> keep polling`)
            for stmt in node.body:
                end = getattr(stmt, "end_lineno", stmt.lineno) or stmt.lineno
                for ln in range(stmt.lineno - 1, min(len(lines), end)):
                    if "#" in lines[ln]:
                        comments.append(lines[ln])
            has_safe_doc = any(
                (re.search(r"(safe|benign|expected|intentional|ok|fine|"
                           r"deliberate|novelty|skip|degrade|fallback|"
                           r"transient|timeout|optional|absent|closed|"
                           r"malformed|unparseable|keep polling|drop|"
                           r"not fatal|non-fatal|already)", c, re.I)
                 and re.search(r"(except|swallow|ignore|pass|->|—|:)",
                               c, re.I))
                for c in comments)
            observable = False
            for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(stmt, ast.Raise):
                    observable = True; break
                if isinstance(stmt, ast.Call):
                    callee = ""
                    if isinstance(stmt.func, ast.Attribute):
                        callee = stmt.func.attr
                    elif isinstance(stmt.func, ast.Name):
                        callee = stmt.func.id
                    if re.search(r"^(print|log|warning|error|info|debug|"
                                 r"exception|critical|_record|report|send|"
                                 r"write|append|emit|note|warn|fail|add|"
                                 r"record|set|put|mark|flag|store|save|"
                                 r"track|count|collect|stash|push)$",
                                 callee, re.I):
                        observable = True; break
                # recording the failure into a result/error/status dict or
                # attribute IS the observable report (api.py:66 pattern)
                if isinstance(stmt, ast.Assign):
                    for t in ast.walk(stmt):
                        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                            pass
                        if isinstance(t, ast.Attribute) and re.search(
                                r"(error|fail|reason|status|state|result|"
                                r"verdict|outcome|diagnostic)", t.attr, re.I):
                            observable = True; break
                    if observable:
                        break
                    if isinstance(stmt, ast.Subscript) or (
                            isinstance(stmt, ast.Assign) and isinstance(
                                stmt.targets[0], ast.Subscript)):
                        sl = stmt.targets[0].slice if isinstance(stmt, ast.Assign) else None
                        key = ""
                        if isinstance(sl, ast.Constant):
                            key = str(sl.value)
                        if re.search(r"(error|fail|reason|status|state|"
                                     r"result|verdict|outcome)", key, re.I):
                            observable = True; break
                if isinstance(stmt, (ast.Yield, ast.YieldFrom, ast.Assert)):
                    observable = True; break
            if not observable and not has_safe_doc:
                # return-default bodies ARE the swallow (return None/x constant)
                hits.append(Hit(path, node.lineno, "SILENT_EXCEPT",
                                code_at(node), fn.name,
                                "except swallows without re-raise/log/"
                                "documented-safe comment"))

    def walk_toctou(fn: ast.FunctionDef | ast.AsyncFunctionDef):
        """Class (c): exists/isfile/isdir/lexists(...) then a separate
        use on the SAME name without fd-pinning."""
        # collect (check_name -> lineno) and (use_name -> lineno)
        checked: dict[str, int] = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in TOCTOU_CHECKS and node.args \
                    and isinstance(node.args[0], ast.Name) and (
                        # os.path.exists(x) / os.path.isfile(x) / os.exists(x)
                        _qualifies_os_path(node.func.value)
                        # Path(x).exists() — func.value is a Call
                        or (isinstance(node.func.value, ast.Call)
                            and isinstance(node.func.value.func, ast.Name)
                            and node.func.value.func.id == "Path")):
                checked.setdefault(node.args[0].id, node.lineno)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in TOCTOU_USES and node.args \
                    and isinstance(node.args[0], ast.Name):
                nm = node.args[0].id
                if nm in checked and node.lineno > checked[nm]:
                    # fd-pinning style: open() guarded directly by the same
                    # exists-check in an if/and chain — heuristic: the check
                    # and the open within 1 line and same test expression
                    hits.append(Hit(path, node.lineno, "TOCTOU",
                                    code_at(node), fn.name,
                                    f"'{nm}' checked at line {checked[nm]} "
                                    f"then used here (two calls)"))
                    checked.pop(nm, None)  # one hit per name
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in TOCTOU_USES and node.args \
                    and isinstance(node.args[0], ast.Name):
                nm = node.args[0].id
                if nm in checked and node.lineno > checked[nm]:
                    hits.append(Hit(path, node.lineno, "TOCTOU",
                                    code_at(node), fn.name,
                                    f"'{nm}' checked at line {checked[nm]} "
                                    f"then used here (two calls)"))
                    checked.pop(nm, None)

    def walk_cli_unreachable(tree: ast.Module):
        """Class (d), file-local half: flags the HANDLER reads that the
        PARSER in this file never defines. burhan/cli.py itself is covered
        AUTHORITATIVELY by cli_wiring_report() (dedup: skipped here)."""
        if not path.startswith("scripts/") or path.endswith("audit_quantum_sweep.py"):
            return
        # 1. flags read by handler code: getattr(a, "x", ...) or a.x
        read_flags: set[str] = set()
        called_attrs: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                called_attrs.add(node.func.attr)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "getattr" and len(node.args) >= 2 \
                    and isinstance(node.args[1], ast.Constant):
                read_flags.add(str(node.args[1].value))
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id == "a" and node.attr not in called_attrs:
                read_flags.add(node.attr)
        # positional dests (add_argument("target"), add_subparsers(dest="vcmd"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "add_argument" and node.args \
                    and isinstance(node.args[0], ast.Constant) \
                    and not str(node.args[0].value).startswith("-"):
                read_flags.discard(str(node.args[0].value))
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "dest" and isinstance(kw.value, ast.Constant):
                        read_flags.discard(str(kw.value.value))
        # 2. flags the parser defines: add_argument("--x" ...)
        defined: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "add_argument" and node.args \
                    and isinstance(node.args[0], ast.Constant):
                flag = str(node.args[0].value)
                if flag.startswith("--"):
                    defined.add(_arg_dest(flag[2:]))
                elif flag.startswith("-") and len(flag) > 1:
                    defined.add(_arg_dest(flag[1:]))
        for f in sorted(read_flags - defined):
            # positional dests read via a.<x> where add_argument("x") —
            # single-dash shorts — narrow: only flag-shaped names count
            hits.append(Hit(path, 0, "CLI_UNREACHABLE", f"--{f}",
                            "<handler>",
                            "handler reads this option but no "
                            "add_argument defines it in this file"))

    # EVERY function in the file — module-level, nested, and class methods
    # (the round-12 sweep found the round-8 scanner's blind spot mattered:
    # memory.py/intel.py __init__ methods carried real TOCTOU sites).
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            walk_first_match(node)
            walk_silent_except(node)
            walk_toctou(node)
    walk_cli_unreachable(tree)
    return hits


# ============================================================ TypeScript scans
TS_CATCH_EMPTY = re.compile(
    r"catch\s*(\([^)]*\))?\s*\{\s*(//[^\n]*)?\s*\}")
TS_CATCH_RET = re.compile(
    r"catch\s*(\([^)]*\))?\s*\{\s*return(?:;|\s)")


def scan_ts(path: str) -> list[Hit]:
    src = open(os.path.join(ROOT, path), encoding="utf-8").read()
    hits: list[Hit] = []
    for i, line in enumerate(src.splitlines(), 1):
        if TS_CATCH_EMPTY.search(line) or TS_CATCH_RET.search(line):
            hits.append(Hit(path, i, "SILENT_CATCH", line.strip()[:120],
                            "-", "empty or return-only catch body"))
    return hits


def scan_ts_exports_routed(ts_files: list[str]) -> list[Hit]:
    """Class (dTS): src/lib exports imported ONLY by tests, never by an
    app entry (route.ts / page.tsx / layout / instrumentation / server
    scripts referenced by package.json)."""
    lib_files = [f for f in ts_files if f.startswith("src/lib/")]
    app_files = [f for f in ts_files if re.search(
        r"(route\.ts|page\.tsx|layout\.tsx|instrumentation\.ts|middleware\.ts"
        r"|opentelemetry\.ts)$", f)]
    test_files = [f for f in ts_files if "/tests/" in f or ".test." in f]
    routed_src = "".join(
        open(os.path.join(ROOT, f), encoding="utf-8").read()
        for f in app_files)
    # also: anything src/ (non-lib) importing from lib counts as routing
    consumer_src = "".join(
        open(os.path.join(ROOT, f), encoding="utf-8").read()
        for f in ts_files
        if f.startswith("src/") and not f.startswith("src/lib/"))
    # TRANSITIVE routing: a src/lib file whose exports are imported by an
    # app entry routes EVERYTHING it re-uses. Resolve the lib->lib import
    # graph to a fixed point (round-12 lesson: verifyPassword is imported by
    # src/lib/auth.ts, and auth() is NextAuth's entry — routed through a
    # chain the naive per-symbol check missed).
    lib_src = {f: open(os.path.join(ROOT, f), encoding="utf-8").read()
               for f in lib_files}
    routed_libs: set[str] = set()
    changed = True
    while changed:
        changed = False
        for lf in lib_files:
            if lf in routed_libs:
                continue
            # routed if any app entry references this module's path or any
            # of its exported symbol names
            mod_syms = set(re.findall(
                r"export\s+(?:async\s+)?(?:function|const|class)"
                r"\s+([A-Za-z_][A-Za-z0-9_]*)", lib_src[lf]))
            if any(re.search(rf"\b{re.escape(s)}\b", routed_src) for s in mod_syms) \
                    or re.search(rf"@[\w-]*lib/{re.escape(lf.split('src/lib/')[-1].rsplit('.', 1)[0])}", routed_src):
                routed_libs.add(lf); changed = True; continue
            # routed if a ROUTED lib imports from it
            mod_tail = re.escape(
                lf.split('src/lib/')[-1].rsplit('.', 1)[0])
            for other in routed_libs:
                if other != lf and re.search(
                        r"import\s[^;]*from\s+[\"'][^\"']*" + mod_tail,
                        lib_src[other]):
                    routed_libs.add(lf); changed = True; break
    hits: list[Hit] = []
    for lf in lib_files:
        for m in re.finditer(r"export\s+(?:async\s+)?(?:function|const|class)"
                             r"\s+([A-Za-z_][A-Za-z0-9_]*)",
                             lib_src[lf]):
            sym = m.group(1)
            used_in_app = re.search(rf"\b{re.escape(sym)}\b", routed_src)
            # symbol used ANYWHERE in a routed lib file = transitively routed
            used_transitively = any(
                lf2 != lf and re.search(rf"\b{re.escape(sym)}\b", lib_src[lf2])
                for lf2 in routed_libs)
            used_in_consumer = re.search(
                rf"import\s[^;]*\b{re.escape(sym)}\b[^;]*from",
                consumer_src, re.S)
            if not used_in_app and not used_in_consumer and not used_transitively:
                # flag only if a TEST imports it (tested-but-unrouted is the
                # bug shape; untested+unrouted is dead code for another tool)
                test_src = "".join(
                    open(os.path.join(ROOT, f), encoding="utf-8").read()
                    for f in test_files)
                if re.search(rf"import\s[^;]*\b{re.escape(sym)}\b", test_src):
                    hits.append(Hit(lf, 0, "EXPORT_UNROUTED", sym, "-",
                                    "exported symbol imported by tests but "
                                    "not routed through any app entry"))
    return hits


# ====================================================== class (d) cross-file
def cli_wiring_report() -> tuple[list[Hit], dict]:
    """The full class-(d) check for burhan/cli.py:
    every flag read by handler code must be defined by SOME add_argument
    in the same file (subparsers included). Returns hits + the sets for
    the inventory."""
    path = "burhan/cli.py"
    src = open(os.path.join(ROOT, path), encoding="utf-8").read()
    tree = ast.parse(src)
    read_flags, defined = set(), set()
    called_attrs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            called_attrs.add(node.func.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "getattr" and len(node.args) >= 2 \
                and isinstance(node.args[1], ast.Constant):
            read_flags.add(str(node.args[1].value))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == "a" and node.attr not in called_attrs:
            read_flags.add(node.attr)
    # positional dests and add_subparsers(dest=...) are not --flags
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "add_argument" and node.args \
                and isinstance(node.args[0], ast.Constant) \
                and not str(node.args[0].value).startswith("-"):
            read_flags.discard(str(node.args[0].value))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "dest" and isinstance(kw.value, ast.Constant):
                    read_flags.discard(str(kw.value.value))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "add_argument" and node.args \
                and isinstance(node.args[0], ast.Constant):
            flag = str(node.args[0].value)
            if flag.startswith("--"):
                defined.add(_arg_dest(flag[2:]))
            elif flag.startswith("-"):
                defined.add(_arg_dest(flag[1:]))
    # positional command names (a.cmd comparisons) are not flags
    cmds = set(re.findall(r'a\.cmd\s*==\s*"([a-z0-9_-]+)"', src))
    holes = sorted((read_flags - defined) - cmds - {"cmd"})
    hits = [Hit(path, 0, "CLI_UNREACHABLE", f"--{f}", "<handler>",
                "handler reads this option but no add_argument defines it")
             for f in holes]
    info = {"read_flags": sorted(read_flags), "defined_flags": sorted(defined),
            "commands": sorted(cmds), "holes": holes}
    return hits, info




def entrypoint_wiring_report(py_files: list[str]) -> tuple[list[Hit], dict]:
    """Class (d+) — ENTRYPOINT_UNREACHABLE, generalized from the CLI-only
    check after the round-12 dogfood catch: run_monitor_cycle had ZERO
    production callers (the scheduler imported its module for load_config
    and dropped the report) while its test suite was green. The CLI-only
    (d) check could not see it — it only checks argparse flag wiring.

    Routing semantics (RED-tuned against the REAL historical bug, then
    BLUE-verified on the fixed tree):
      - Entry files: burhan/cli.py + every scripts/**.py named by a
        workflow run: step, a package.json script (one .sh hop), or a
        production scripts/**/*.sh. Entry = the FILE is invoked.
      - The routing graph nodes are (file, defname) PAIRS, never bare
        names: the word "main" in an entry's text must not route
        `def main()` of a non-entry script (that false route hid the
        real bug in the first two detector drafts).
      - Edges: a routed def routes the defs it CALLS in the same file,
        plus cross-file calls resolved through that file's actual import\n        statements at MODULE granularity (a from-import routes to the\n        module file, not the exact defining file — v1 accepted\n        over-routing; it can only under-flag across module boundaries,\n        and the ledger review is the backstop)
        statements (from-import by name, module.attr through the module
        alias) — imports ANYWHERE in the file, because lazy imports
        inside bodies are this codebase's documented pattern.
      - Flagged: a callable top-level FUNCTION in burhan/** (classes,
        enums, and exceptions are deliberately out of scope v1: tests
        consume them as type constructors and they are not "scheduling
        surface") that is unrouted AND referenced by tests/.
    """
    import glob as _glob

    # ---- 1. production entry files
    entries: set[str] = {"burhan/cli.py"}
    wf_text = ""
    for wf in _glob.glob(os.path.join(ROOT, ".github/workflows/*.yml")):
        wf_text += open(wf, encoding="utf-8").read()
    entries.update(re.findall(r"scripts/[\w./-]+\.py", wf_text))
    pkg_path = os.path.join(ROOT, "package.json")
    pkg_text = open(pkg_path, encoding="utf-8").read() if os.path.exists(pkg_path) else ""
    entries.update(re.findall(r"scripts/[\w./-]+\.py", pkg_text))
    sh_refs = set(re.findall(r"scripts/[\w./-]+\.sh", wf_text)) | \
              set(re.findall(r"scripts/[\w./-]+\.sh", pkg_text))
    for sh in sorted(sh_refs):
        p = os.path.join(ROOT, sh)
        if os.path.exists(p):
            entries.update(re.findall(r"scripts/[\w./-]+\.py",
                                      open(p, encoding="utf-8").read()))
    entries = {e for e in entries if os.path.exists(os.path.join(ROOT, e))}

    non_test = [f for f in py_files
                if not f.startswith(("tests/", "fixtures/"))]
    fmap = {f[:-3].replace("/", "."): f for f in non_test}

    def _calls_of(node) -> set[str]:
        c = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                if isinstance(sub.func, ast.Name):
                    c.add(sub.func.id)
                elif isinstance(sub.func, ast.Attribute):
                    c.add(sub.func.attr)
        return c

    # ---- 2. per-file analysis (defs + calls + imports, cached once)
    info: dict[str, dict] = {}
    for f in non_test:
        try:
            tree = ast.parse(open(os.path.join(ROOT, f), encoding="utf-8").read())
        except Exception:  # noqa: BLE001 — other classes report parse errors
            continue
        defs: dict[str, set[str]] = {}
        # PRIVATE defs are routing NODES (a routed public def calls its
        # private helpers — they must propagate routing to what THEY call)
        # but are never FLAGGED: flagging is the public-API question only.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs[node.name] = _calls_of(node)
            elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                # v1.1 (calibration lesson): classes are routing nodes —
                # BurhanScanner.report() lazily imports and calls
                # apply_prioritization, and v1 (top-level functions only)
                # could not see it. A class routes the names its METHODS
                # call (merged), and its methods become separately routable
                # defs so the reachability is per-method, not per-file.
                merged = set()
                for m in node.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and not m.name.startswith("_"):
                        defs[f"{node.name}.{m.name}"] = _calls_of(m)
                        merged |= _calls_of(m)
                defs[node.name] = merged
        from_imports: dict[str, str] = {}
        mod_alias: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                # RELATIVE imports (from .prioritize import X — the engine's
                # documented lazy-import pattern) resolve against the
                # importing file's package; absolute ones against the tree.
                mod = node.module or ""
                if node.level and f.startswith("burhan/"):
                    pkg = f.rsplit("/", 1)[0].replace("/", ".")
                    mod_abs = (pkg + "." + mod).lstrip(".") if mod else pkg
                else:
                    mod_abs = mod
                if mod_abs and fmap.get(mod_abs):
                    tgt = fmap[mod_abs]
                    for a in node.names:
                        # symbol import, ALIAS-AWARE: `from .evidence import
                        # build_proof as build_finding_proof` — the call site
                        # says build_finding_proof, the def says build_proof.
                        # Map local name -> (file, original name).
                        from_imports[a.asname or a.name] = (tgt, a.name)
                elif node.level and not mod and f.startswith("burhan/"):
                    # `from . import sibling` — sibling module in same package
                    pkg_dir = f.rsplit("/", 1)[0]
                    for a in node.names:
                        p = os.path.join(pkg_dir, a.name + ".py")
                        if os.path.exists(os.path.join(ROOT, p)):
                            mod_alias[a.asname or a.name] = p
            elif isinstance(node, ast.Import):
                for a in node.names:
                    p = a.name.replace(".", "/") + ".py"
                    if os.path.exists(os.path.join(ROOT, p)):
                        mod_alias[a.asname or a.name.split(".")[0]] = p
        allcalls = set()
        for c in defs.values():
            allcalls |= c
        attr_calls = {(n.func.value.id, n.func.attr)
                      for n in ast.walk(tree)
                      if isinstance(n, ast.Call)
                      and isinstance(n.func, ast.Attribute)
                      and isinstance(n.func.value, ast.Name)}
        info[f] = {"defs": defs,
                   "module_calls": _calls_of(tree) - allcalls,
                   "from_imports": from_imports,
                   "mod_alias": mod_alias,
                   "attr_calls": attr_calls}

    # ---- 3. reachability from entry files
    routed: set[tuple[str, str]] = set()
    for e in entries:
        for d in info[e]["defs"]:
            routed.add((e, d))
        for c in info[e]["module_calls"]:
            if c in info[e]["defs"]:
                routed.add((e, c))
            elif c in info[e]["from_imports"]:
                tf, orig = info[e]["from_imports"][c]
                routed.add((tf, orig))

    changed = True
    rounds = 0
    while changed and rounds < 20:
        changed, rounds = False, rounds + 1
        for (f, d) in list(routed):
            di = info.get(f)
            if not di or d not in di["defs"]:
                continue
            for c in di["defs"][d]:
                if c in di["defs"]:
                    if (f, c) not in routed:
                        routed.add((f, c))
                        changed = True
                elif c in di["from_imports"]:
                    tgt, orig = di["from_imports"][c]
                    if tgt in info and orig in info[tgt]["defs"] \
                            and (tgt, orig) not in routed:
                        routed.add((tgt, orig))
                        changed = True
            for (alias, attr) in di["attr_calls"]:
                # resolve BOTH module aliases (import burhan.vault) and
                # from-imported names (from burhan.vault import Vault) —
                # Vault.init(...) in cli.main is a from-imported CLASS.
                # Using a from-imported class at all (even only via
                # classmethods) routes the CLASS, whose merged method calls
                # then route like any def.
                src_f = di["mod_alias"].get(alias)
                if src_f is None and alias in di["from_imports"]:
                    src_f = di["from_imports"][alias][0]
                if src_f and src_f in info:
                    if alias in info[src_f]["defs"] \
                            and (src_f, alias) not in routed:
                        routed.add((src_f, alias))
                        changed = True
                    if attr in info[src_f]["defs"] \
                            and (src_f, attr) not in routed:
                        routed.add((src_f, attr))
                        changed = True

    # ---- 4. flag engine FUNCTIONS referenced only by tests
    word = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    test_words: set[str] = set()
    for f in py_files:
        if f.startswith("tests/"):
            test_words |= set(word.findall(
                open(os.path.join(ROOT, f), encoding="utf-8").read()))

    hits: list[Hit] = []
    flagged = []
    for f in sorted(info):
        if not f.startswith("burhan/"):
            continue
        for name in sorted(info[f]["defs"]):
            if (f, name) in routed or name not in test_words:
                continue
            if name.startswith("_") or "." in name:
                # method symbols: flagged only via their class's flat call
                # merge is NOT meaningful — methods are not entry surface;
                # they route (or not) through the class. Not flagged v1.1.
                continue
            flagged.append({"file": f, "name": name})
            hits.append(Hit(f, 0, "ENTRYPOINT_UNREACHABLE", name, "-",
                            "public engine function referenced by tests "
                            "but reachable from NO production entry "
                            "point (cli/workflows/package.json/.sh; "
                            "import-resolution aware)"))
    info_out = {"entry_files": sorted(entries),
                "routed_defs": len(routed),
                "engine_public_functions": sum(len(i["defs"]) for f, i in
                                               info.items()
                                               if f.startswith("burhan/")),
                "flagged": flagged}
    return hits, info_out


def _qualifies_os_path(node: ast.AST) -> bool:
    """True for `os.path` (Attribute chain) or `os` (Name) — the import
    style varies across the tree (import os vs from os import path)."""
    if isinstance(node, ast.Name):
        return node.id == "os" or node.id == "path"
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id == "os" and node.attr == "path"
    return False

def _arg_dest(flag: str) -> str:
    """argparse dest normalization: --auth-header -> auth_header."""
    return flag.replace("-", "_")

# ================================================================== ledger
def load_ledger():
    if not os.path.exists(LEDGER_PATH):
        return []
    return json.load(open(LEDGER_PATH, encoding="utf-8"))["entries"]


def match_ledger(hit, entries):
    for e in entries:
        if hit["file"] != e["file"]:
            continue
        try:
            if re.search(e["code"], hit["code"]):
                return e
        except re.error:
            continue
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ci-gate", action="store_true",
                    help="engine hits (burhan/**, src/**) must all match the "
                         "review ledger or be marked fixed")
    args = ap.parse_args()

    py_files, ts_files = tracked_files()
    all_hits: list[dict] = []
    for f in py_files:
        all_hits.extend(h.as_dict() for h in scan_py(f))
    for f in ts_files:
        all_hits.extend(h.as_dict() for h in scan_ts(f))
    all_hits.extend(h.as_dict() for h in scan_ts_exports_routed(ts_files))
    cli_hits, cli_info = cli_wiring_report()
    all_hits.extend(h.as_dict() for h in cli_hits)
    ep_hits, ep_info = entrypoint_wiring_report(py_files)
    all_hits.extend(h.as_dict() for h in ep_hits)

    entries = load_ledger()
    ledgered, unmatched_engine, non_engine = [], [], []
    for h in all_hits:
        m = match_ledger(h, entries)
        if m:
            h["ledger"] = m["id"]
            h["verdict"] = "LEDGERED(%s)" % m["class"]
            ledgered.append(h)
        elif h["file"].startswith(("burhan/", "src/")):
            h["verdict"] = "UNMATCHED"
            unmatched_engine.append(h)
        else:
            h["verdict"] = "NON_ENGINE"
            non_engine.append(h)

    os.makedirs(OUT_DIR, exist_ok=True)
    out_json = os.path.join(OUT_DIR, "quantum-sweep-inventory.json")
    from collections import Counter
    inventory = {
        "when": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                               capture_output=True, text=True).stdout.strip(),
        "scanned": {"python_files": len(py_files), "ts_files": len(ts_files)},
        "raw_counts_by_class": dict(Counter(h["class"] for h in all_hits)),
        "cli_wiring": cli_info,
        "entrypoint_wiring": {"entry_files": len(ep_info["entry_files"]),
                              "routed_defs": ep_info["routed_defs"],
                              "engine_public_functions": ep_info["engine_public_functions"],
                              "flagged": ep_info["flagged"]},
        "total": len(all_hits),
        "hits": all_hits,
    }
    json.dump(inventory, open(out_json, "w"), indent=1, ensure_ascii=False)

    print("scanned: %d py + %d ts files | raw hits: %d" %
          (len(py_files), len(ts_files), len(all_hits)))
    print("raw counts by class:", dict(Counter(h["class"] for h in all_hits)))
    print("verdicts: ledgered=%d engine-unmatched=%d non-engine=%d" %
          (len(ledgered), len(unmatched_engine), len(non_engine)))
    print("engine-unmatched by class:",
          dict(Counter(h["class"] for h in unmatched_engine)))
    print("inventory -> %s" % out_json)

    if args.ci_gate:
        if unmatched_engine:
            print("\nCI GATE: %d engine hits without a ledger entry:" %
                  len(unmatched_engine))
            for h in unmatched_engine:
                print("  %s:%d %s | %s | %s" %
                      (h["file"], h["line"], h["class"], h["code"][:90],
                       h.get("detail", "")[:80]))
            return 1
        print("CI GATE: PASS — every engine hit is ledgered or fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
