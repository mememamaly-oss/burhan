#!/usr/bin/env python3
"""FULL-REPO first-match audit (round 7 companion, 2026-11-03).

Same standards as the burhan/-only audit that produced FM-01..FM-28, now
swept over EVERY tracked file:

  A. first-element picks over a FILTERED/DYNAMIC list (`x[0]`, `next(...)`),
     where the pick is verdict- or evidence-bearing and no shape-based
     ordering justifies "first";
  B. silent truncation (`[:N]` / `[:N]`-equivalent slices) with no leftover
     boundary (the ZOMBIE_PROBE_CAP pattern is the repo's own fix shape);
  C. sort-then-first (`sorted(...)  [0]` / `[:N]`) — legitimate ONLY when
     the sort key encodes a shape preference (documented), an accident
     otherwise;
  D. first-iteration `break` loops (probe-until-verdict) — checked for
     "iterate ALL candidates" semantics;
  E. `.pop(0)` / `popleft()` site inspections.

AST-based for Python (precise); line-regex for TS/TSX (manually reviewed).
Output: stdout buckets + JSON inventory at
download/first-match-audit/fullrepo-first-match-inventory.json.
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "download", "first-match-audit")

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".next", "skills"}
# engine modules fully audited + fixed this round: listed for VERIFICATION
# (their hits are expected to be the already-fixed, boundary-carrying sites)
ENGINE_FIXED_MARKERS = (
    "FM-01", "FM-02", "FM-03", "FM-04", "FM-05", "FM-06", "FM-08",
    "FM-09", "FM-10", "FM-16", "FM-17", "FM-21", "ROUND 7",
    "ZOMBIE_PROBE_CAP", "IDOR_FRESH_VICTIM_CAP",
)


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True).stdout.splitlines()
    py = [f for f in out if f.endswith(".py")]
    ts = [f for f in out if f.endswith((".ts", ".tsx"))]
    return sorted(py), sorted(ts)


class FuncCollector(ast.NodeVisitor):
    """Enclosing function/qualname tracking."""

    def __init__(self):
        self.stack: list[str] = []
        self.hits: list[dict] = []

    def qualname(self):
        return ".".join(self.stack) or "<module>"

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef


DYNAMIC_HINTS = re.compile(
    r"\b(ep|eps|endpoint|endpoints|accounts|ops|queries|cands|candid|"
    r"authish|targets|findings|routes|paths|urls|links|fields|params|"
    r"parameters|cookies|tokens|keys|bodies|hits|matches|results|rows)\b",
    re.I,
)


def _slice_len(node: ast.Slice) -> str | None:
    """Return the literal upper bound of a [:N] slice, if literal."""
    if isinstance(node.lower, ast.Constant) and node.lower.value is None \
            and node.upper is not None and isinstance(node.upper, ast.Constant):
        v = node.upper.value
        if isinstance(v, int):
            return str(v)
    return None


def scan_py(path: str) -> list[dict]:
    """One Python file -> raw positional-selection hits (no verdict)."""
    hits: list[dict] = []
    try:
        tree = ast.parse(open(os.path.join(ROOT, path), encoding="utf-8").read())
    except Exception as e:
        return [{"file": path, "line": 0, "kind": "PARSE_ERROR",
                 "code": str(e)[:120], "func": "-"}]
    fc = FuncCollector()
    fc.hits = hits
    src_lines = open(os.path.join(ROOT, path), encoding="utf-8").read().splitlines()

    def add(node, kind, detail):
        line = src_lines[node.lineno - 1].strip() if node.lineno <= len(src_lines) else ""
        hits.append({"file": path, "line": node.lineno, "kind": kind,
                     "code": line[:160], "func": fc.qualname(), "detail": detail})

    class V(FuncCollector):
        def visit_Subscript(self, node):
            sl = node.slice
            if isinstance(sl, ast.Slice):
                n = _slice_len(sl)
                if n is not None and (sl.lower is None):
                    add(node, "TRUNC[:%s]" % n, "slice truncation [:%s]" % n)
                elif isinstance(sl.lower, ast.Constant) and sl.lower.value is None:
                    add(node, "SLICE", "open-ended slice with non-literal bound")
            elif isinstance(sl, ast.Constant) and sl.value == 0:
                # x[0] — classify by what x is
                if isinstance(node.value, ast.Name):
                    name = node.value.id
                    if DYNAMIC_HINTS.search(name):
                        add(node, "FIRST[0]", "first-element pick of %r" % name)
                elif isinstance(node.value, ast.Call):
                    # filter out benign string ops: split/rsplit("x", 1)[0],
                    # partition()[0], popitem etc. — URL/text normalization is
                    # NOT candidate selection
                    call = node.value
                    fname = ""
                    if isinstance(call.func, ast.Attribute):
                        fname = call.func.attr
                    elif isinstance(call.func, ast.Name):
                        fname = call.func.id
                    if fname in ("split", "rsplit", "partition", "popitem"):
                        return
                    add(node, "FIRST[0-call]",
                        "first-element pick of a call result")
            self.generic_visit(node)

        def visit_Call(self, node):
            f = node.func
            if isinstance(f, ast.Name) and f.id == "next":
                if not node.args:
                    add(node, "NEXT()", "next() without default over iterable")
            if isinstance(f, ast.Attribute) and f.attr in ("pop", "popleft"):
                if f.attr == "popleft" or (
                        node.args and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == 0):
                    add(node, "POP0", "pop(0)/popleft() positional take")
            self.generic_visit(node)

        def visit_Break(self, node):
            # a break inside a `for` over a DYNAMIC name is the honest
            # probe-until-verdict shape — record only those (breaks over
            # enumerate/static tuples are noise)
            p = node
            for_loop = None
            while p is not None:
                if isinstance(p, ast.For):
                    for_loop = p
                    break
                p = getattr(p, "_parent_for_scan", None)
            # walk parents via func stack is unreliable; use a simple
            # heuristic: nearest enclosing For found by scanning the tree
            add(node, "BREAK", "loop break (manual review: early-exit semantics)")

        def visit_For(self, node):
            it = node.iter
            if isinstance(it, ast.Subscript) and isinstance(it.slice, ast.Slice):
                n = _slice_len(it.slice)
                if n is not None:
                    add(node, "LOOP[:%s]" % n,
                        "for over a truncated [:%s] list" % n)
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            FuncCollector.visit_FunctionDef(self, node)

        visit_AsyncFunctionDef = visit_FunctionDef

    V().visit(tree)
    return hits


TS_PATTERNS = [
    (re.compile(r"\[0\]"), "TS_FIRST[0]"),
    (re.compile(r"\.at\(0\)"), "TS_AT0"),
    (re.compile(r"\.pop\(\)"), "TS_POP"),
    (re.compile(r"\.slice\(0\s*,\s*(\d+)\)"), "TS_SLICE"),
    (re.compile(r"\[\s*:\s*(\d+)\s*\]"), "TS_TRUNC"),
    (re.compile(r"\bfind\(\s*\(?[^)]*\)?\s*\)"), "TS_FIND"),
]


def scan_ts(path: str) -> list[dict]:
    hits = []
    src = open(os.path.join(ROOT, path), encoding="utf-8").read().splitlines()
    for i, line in enumerate(src, 1):
        s = line.strip()
        if s.startswith(("*", "//", "/*")):
            continue
        for rx, kind in TS_PATTERNS:
            if rx.search(s):
                hits.append({"file": path, "line": i, "kind": kind,
                             "code": s[:160], "func": "-", "detail": "ts pattern"})
    return hits


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    py_files, ts_files = tracked_files()
    py_files = [f for f in py_files if not any(p in f.split("/") for p in SKIP_DIRS)]
    ts_files = [f for f in ts_files if not any(p in f.split("/") for p in SKIP_DIRS)]
    all_hits: list[dict] = []
    for f in py_files:
        all_hits.extend(scan_py(f))
    for f in ts_files:
        all_hits.extend(scan_ts(f))

    # ---- classification: engine hits that sit NEXT TO an FM fix marker or
    # an explicit leftover boundary are the already-fixed shapes; the rest
    # need review. REVIEW = anything not obviously benign.
    for h in all_hits:
        if h["kind"] == "PARSE_ERROR":
            h["verdict"] = "REVIEW"
            continue
        try:
            src = open(os.path.join(ROOT, h["file"]), encoding="utf-8").read()
        except Exception:
            h["verdict"] = "REVIEW"
            continue
        window = "\n".join(src.splitlines()[max(0, h["line"] - 14):h["line"] + 3])
        if any(m in window for m in ENGINE_FIXED_MARKERS):
            h["verdict"] = "FIXED_SHAPE"
        elif h["kind"] in ("BREAK", "SLICE", "POP0", "TS_FIND"):
            h["verdict"] = "REVIEW"
        elif h["file"].startswith("tests/"):
            h["verdict"] = "TEST_REVIEW"
        elif h["file"].startswith(("fixtures/", "perf/", "tools/", "scripts/", "integrations/")):
            h["verdict"] = "ADJACENT_REVIEW"
        elif h["file"].startswith("src/"):
            h["verdict"] = "UI_REVIEW"
        else:
            h["verdict"] = "REVIEW"

    by_verdict: dict[str, list] = {}
    for h in all_hits:
        by_verdict.setdefault(h["verdict"], []).append(h)

    out_json = os.path.join(OUT_DIR, "fullrepo-first-match-inventory.json")
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump({"total": len(all_hits), "by_verdict": {
            k: len(v) for k, v in by_verdict.items()}, "hits": all_hits},
            fh, indent=1, ensure_ascii=False)

    print("scanned: %d py + %d ts tracked files" % (len(py_files), len(ts_files)))
    print("total raw hits: %d" % len(all_hits))
    for v in ("REVIEW", "TEST_REVIEW", "ADJACENT_REVIEW", "UI_REVIEW",
              "FIXED_SHAPE", "PARSE_ERROR"):
        if v in by_verdict:
            print("=== bucket %s: %d" % (v, len(by_verdict[v])))
    print("inventory -> %s" % out_json)
    # print the REVIEW bucket fully (engine code needing eyes)
    for h in by_verdict.get("REVIEW", []):
        print("REVIEW %s:%d %s | %s" % (h["file"], h["line"], h["kind"], h["code"][:110]))


if __name__ == "__main__":
    main()
