#!/usr/bin/env python3
"""Anti-pattern scanner — round 8 (strict continuous hardening, 2026-11-03).

Carries the round-7 first-match/positional-selection patterns forward (so
ONE tool backs the CI gate) and adds the four adjacent anti-pattern
classes ordered for this round:

  A. SILENT_EXCEPT   — bare/broad except whose body does nothing observable
                       (pass/continue/return-default) with no logging of any
                       kind: a swallowed failure the operator never sees.
  B. OFF_BY_ONE      — `for i in range(len(X))` bodies indexing `X[i+1]`:
                       the last iteration reads one past the end.
  C. COUNTER_ARITH   — budget/cap/quota counters: every decrement or
                       zero-comparison site, listed for ordering review
                       (spend-before-check = one step over the cap).
  D. TOCTOU          — os.path.exists/isfile/isdir check followed by a
                       use (open/remove/mkdir/...) on the same name in the
                       same function: the check and the use are two calls.

Every hit needs ONE of:
  - a fix (with a RED->BLUE pin), or
  - a ledger entry in scripts/antipattern_review_ledger.json
    (file + code-regex + reason) classifying it documented-benign.

Modes:
  default        scan + print buckets + write the JSON inventory
  --ci-gate      same scan, but every ENGINE hit (burhan/**) must match a
                 ledger entry; unmatched -> exit 1 listing them. Non-engine
                 hits (fixtures/tests/src) are reported but never gate:
                 the product surface is the engine; test/fixture files are
                 reviewed once and listed in the ledger like everything
                 else, but the gate exists to protect the ENGINE tree.

No narrative in the output: file:line, class, the code, the verdict.
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
LEDGER_PATH = os.path.join(ROOT, "scripts", "antipattern_review_ledger.json")
OUT_DIR = os.path.join(ROOT, "download", "antipattern-audit")

DYNAMIC_HINTS = re.compile(
    r"\b(ep|eps|endpoint|endpoints|accounts|ops|queries|cands|candid|"
    r"authish|targets|findings|routes|paths|urls|links|fields|params|"
    r"parameters|cookies|tokens|keys|bodies|hits|matches|results|rows)\b",
    re.I,
)
BENIGN_CALL_FIRST = ("split", "rsplit", "partition", "popitem")
COUNTER_NAME = re.compile(r"budget|cap|quota|remaining|left", re.I)
TOCTOU_CHECKS = ("exists", "isfile", "isdir", "lexists")
TOCTOU_USES = ("open", "remove", "mkdir", "makedirs", "rmdir", "unlink",
               "rename", "stat", "getsize")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT,
                         capture_output=True, text=True).stdout.splitlines()
    skip = ("node_modules", ".git", "__pycache__", ".next", "skills")
    py = [f for f in out if f.endswith(".py")
          and not any(p in f.split("/") for p in skip)]
    return sorted(py)


def _slice_len(node: ast.Slice):
    if isinstance(node.lower, ast.Constant) and node.lower.value is None \
            and node.upper is not None and isinstance(node.upper, ast.Constant):
        v = node.upper.value
        if isinstance(v, int):
            return str(v)
    return None


class Hit:
    __slots__ = ("file", "line", "cls", "code", "func", "detail")

    def __init__(self, file, line, cls, code, func, detail=""):
        self.file, self.line, self.cls = file, line, cls
        self.code, self.func, self.detail = code, func, detail

    def as_dict(self):
        return {"file": self.file, "line": self.line, "class": self.cls,
                "code": self.code[:200], "func": self.func,
                "detail": self.detail}


def scan_py(path: str) -> list[Hit]:
    hits: list[Hit] = []
    try:
        src = open(os.path.join(ROOT, path), encoding="utf-8").read()
        tree = ast.parse(src)
    except Exception as e:
        return [Hit(path, 0, "PARSE_ERROR", str(e)[:120], "-")]
    lines = src.splitlines()
    fn_stack: list[str] = []

    def code_at(node):
        return lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

    def add(node, cls, detail=""):
        hits.append(Hit(path, node.lineno, cls, code_at(node),
                        ".".join(fn_stack) or "<module>", detail))

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            fn_stack.append(node.name)
            self.generic_visit(node)
            fn_stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        # ---- A. first-match carry-over -------------------------------
        def visit_Subscript(self, node):
            sl = node.slice
            if isinstance(sl, ast.Slice):
                n = _slice_len(sl)
                if n is not None and sl.lower is None:
                    add(node, "TRUNC[:%s]" % n, "slice truncation")
            elif isinstance(sl, ast.Constant) and sl.value == 0:
                if isinstance(node.value, ast.Name) and \
                        DYNAMIC_HINTS.search(node.value.id):
                    add(node, "FIRST[0]", "first pick of %r" % node.value.id)
                elif isinstance(node.value, ast.Call):
                    f = node.value.func
                    fname = f.attr if isinstance(f, ast.Attribute) else (
                        f.id if isinstance(f, ast.Name) else "")
                    if fname in BENIGN_CALL_FIRST:
                        return
                    add(node, "FIRST[0-call]", "first pick of a call result")
            self.generic_visit(node)

        def visit_Call(self, node):
            f = node.func
            if isinstance(f, ast.Name) and f.id == "next" and not node.args:
                add(node, "NEXT()", "next() without default")
            if isinstance(f, ast.Attribute) and f.attr in ("pop", "popleft"):
                if f.attr == "popleft" or (
                        node.args and isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == 0):
                    add(node, "POP0", "pop(0) positional take")
            self.generic_visit(node)

        def visit_Break(self, node):
            add(node, "BREAK", "loop break — verdict semantics reviewed")

        # ---- B. off-by-one --------------------------------------------
        def visit_For(self, node):
            it = node.iter
            if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) \
                    and it.func.id == "range" and it.args:
                a0 = it.args[0]
                if isinstance(a0, ast.Call) and isinstance(a0.func, ast.Name) \
                        and a0.func.id == "len" and a0.args and \
                        isinstance(a0.args[0], ast.Name) and \
                        isinstance(node.target, ast.Name):
                    seq, var = a0.args[0].id, node.target.id
                    # len(X) with NO -1 constant adjustment: X[i+1] reads past
                    if len(it.args) == 1:
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Subscript) and \
                                    isinstance(sub.value, ast.Name) and \
                                    sub.value.id == seq:
                                idx = sub.slice
                                if isinstance(idx, ast.BinOp) and \
                                        isinstance(idx.op, ast.Add) and \
                                        isinstance(idx.right, ast.Constant) and \
                                        idx.right.value == 1 and \
                                        isinstance(idx.left, ast.Name) and \
                                        idx.left.id == var:
                                    add(sub, "OFF_BY_ONE",
                                        "%s[%s+1] inside range(len(%s))"
                                        % (seq, var, seq))
                    it_slice = it.args[0]
                    if isinstance(it_slice, ast.Subscript):
                        pass
            self.generic_visit(node)

        # ---- A2. silent except ----------------------------------------
        def visit_ExceptHandler(self, node):
            t = node.type
            broad = t is None or (
                isinstance(t, ast.Name) and t.id in ("Exception", "BaseException"))
            body_ops = []
            for stmt in node.body:
                if isinstance(stmt, (ast.Pass, ast.Continue)):
                    body_ops.append(type(stmt).__name__)
                elif isinstance(stmt, ast.Return):
                    body_ops.append("Return")
                else:
                    body_ops.append("Other")
            observable = any(op == "Other" for op in body_ops) or any(
                isinstance(x, ast.Call) for s in node.body for x in ast.walk(s)
                if isinstance(x, ast.Call) and isinstance(x.func, (
                    ast.Name, ast.Attribute)) and
                (getattr(x.func, "id", "") or getattr(x.func, "attr", "")).lower()
                in ("emit", "print", "info", "warning", "error", "debug",
                    "record", "_record", "log", "write"))
            if broad and not observable:
                add(node, "SILENT_EXCEPT",
                    "body=%s, exception unused" % "+".join(body_ops))
            self.generic_visit(node)

        # ---- C. counter arithmetic ------------------------------------
        def visit_Assign(self, node):
            # budget -= 1  /  budget = budget - 1
            if isinstance(node.value, ast.BinOp) and \
                    isinstance(node.value.op, ast.Sub) and \
                    isinstance(node.value.right, ast.Constant) and \
                    node.value.right.value == 1:
                for t in node.targets:
                    if isinstance(t, ast.Name) and COUNTER_NAME.search(t.id):
                        add(node, "COUNTER_DEC", "%s -= 1" % t.id)
            self.generic_visit(node)

        def visit_AugAssign(self, node):
            if isinstance(node.op, ast.Sub) and isinstance(node.value, ast.Constant) \
                    and node.value.value == 1 and isinstance(node.target, ast.Name) \
                    and COUNTER_NAME.search(node.target.id):
                add(node, "COUNTER_DEC", "%s -= 1" % node.target.id)
            self.generic_visit(node)

        def visit_Compare(self, node):
            for op, cmp in zip(node.ops, node.comparators):
                zero = isinstance(cmp, ast.Constant) and cmp.value == 0
                name = node.left
                if zero and isinstance(name, ast.Name) and \
                        isinstance(op, (ast.LtE, ast.Lt)) and \
                        COUNTER_NAME.search(name.id):
                    add(node, "COUNTER_CHECK", "%s <= 0 check" % name.id)
            self.generic_visit(node)

        # ---- D. TOCTOU -------------------------------------------------
        def visit_FunctionDef(self, node):
            # within one function body: a path-check call followed later by
            # a path-use call on the SAME name
            checks: dict[str, int] = {}
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute) \
                        and stmt.func.attr in TOCTOU_CHECKS and stmt.args:
                    arg = stmt.args[0]
                    if isinstance(arg, ast.Name):
                        checks[arg.id] = stmt.lineno
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    fname = ""
                    if isinstance(stmt.func, ast.Name):
                        fname = stmt.func.id
                    elif isinstance(stmt.func, ast.Attribute):
                        fname = stmt.func.attr
                    if fname in TOCTOU_USES and stmt.args:
                        arg = stmt.args[0]
                        if isinstance(arg, ast.Name) and arg.id in checks:
                            hits.append(Hit(
                                path, stmt.lineno, "TOCTOU", code_at(stmt),
                                ".".join(fn_stack) or "<module>",
                                "check(%s) at line %d then use" % (
                                    arg.id, checks[arg.id])))
            fn_stack.append(node.name)
            self.generic_visit(node)
            fn_stack.pop()

    V().visit(tree)
    # de-dup (TOCTOU walks can double-report nested funcs)
    seen = set()
    out = []
    for h in hits:
        k = (h.file, h.line, h.cls)
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


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
                    help="engine hits must all match the review ledger")
    args = ap.parse_args()

    entries = load_ledger()
    all_hits = []
    for f in tracked_files():
        all_hits.extend(h.as_dict() for h in scan_py(f))

    ledgered, unmatched_engine, non_engine = [], [], []
    for h in all_hits:
        m = match_ledger(h, entries)
        if m:
            h["ledger"] = m["id"]
            h["verdict"] = "LEDGERED(%s)" % m["class"]
            ledgered.append(h)
        elif h["file"].startswith("burhan/"):
            h["verdict"] = "UNMATCHED"
            unmatched_engine.append(h)
        else:
            h["verdict"] = "NON_ENGINE"
            non_engine.append(h)

    os.makedirs(OUT_DIR, exist_ok=True)
    out_json = os.path.join(OUT_DIR, "antipattern-inventory.json")
    json.dump({"total": len(all_hits), "hits": all_hits}, open(out_json, "w"),
              indent=1, ensure_ascii=False)

    from collections import Counter
    print("scanned py files: %d | hits: %d (ledgered %d, engine-unmatched %d, "
          "non-engine %d)" % (len(tracked_files()), len(all_hits),
                              len(ledgered), len(unmatched_engine),
                              len(non_engine)))
    print("engine-unmatched by class:",
          dict(Counter(h["class"] for h in unmatched_engine)))
    print("inventory -> %s" % out_json)

    if args.ci_gate:
        if unmatched_engine:
            print("\nCI GATE: %d engine hits without a ledger entry:" %
                  len(unmatched_engine))
            for h in unmatched_engine:
                print("  %s:%d %s | %s" %
                      (h["file"], h["line"], h["class"], h["code"][:100]))
            return 1
        print("CI GATE: PASS — every engine hit is ledgered or fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
