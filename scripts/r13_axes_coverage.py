#!/usr/bin/env python3
"""Round 13 — axes 1+2 (structure & function coverage) + axis 8 (versions).

Produces evidence/r13/axes-1-2-8.json:
  - every CLI subcommand: defined? exercised by tests/scripts?
  - every burhan/ engine module: has a dedicated test file? which tests touch it?
  - version consistency: pyproject / cli banner / package.json.
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

# ---------- axis 1: CLI subcommands vs tests ---------------------------------
cli_src = open("burhan/cli.py", encoding="utf-8").read()
sub_parsers = re.findall(r'add_parser\(\s*"([a-z0-9_-]+)"', cli_src)
subcommands = sorted(set(sub_parsers))

test_corpus = ""
for f in subprocess.run(["git", "ls-files", "tests/*.py"], capture_output=True,
                        text=True).stdout.split():
    test_corpus += open(f, encoding="utf-8").read()
# scripts + workflows exercise commands too (CI-level coverage):
ci_corpus = ""
for pat in ("scripts/*.py", ".github/workflows/*.yml"):
    for f in subprocess.run(["git", "ls-files", pat], capture_output=True,
                            text=True).stdout.split():
        try:
            ci_corpus += open(f, encoding="utf-8").read()
        except Exception:  # noqa: BLE001
            pass

cmd_cov = {}
for cmd in subcommands:
    in_tests = bool(re.search(rf"[\"'\s]-{{0,2}}{re.escape(cmd)}\b", test_corpus)
                    or re.search(rf'a\.\w+\s*==\s*"{re.escape(cmd)}"', test_corpus)
                    or f'"{cmd}"' in test_corpus)
    in_ci = cmd in ci_corpus
    cmd_cov[cmd] = {"tests": in_tests, "ci_or_scripts": in_ci}

# ---------- axis 2: engine modules vs test files -----------------------------
engine_files = [f for f in subprocess.run(["git", "ls-files", "burhan/*.py"],
                                          capture_output=True,
                                          text=True).stdout.split()
                if f.endswith(".py") and not f.endswith("__init__.py")]
# map: module stem -> dedicated test file exists + which test files mention it
test_files = subprocess.run(["git", "ls-files", "tests/*.py"], capture_output=True,
                            text=True).stdout.split()
test_basenames = {os.path.basename(t) for t in test_files}

mod_cov = {}
for f in engine_files:
    stem = os.path.splitext(os.path.basename(f))[0]
    dedicated = f"test_{stem}.py" in test_basenames
    # any test importing the module?
    pat = re.compile(rf"burhan\.{re.escape(stem)}\b|"
                     rf"from burhan import [^\n]*\b{re.escape(stem)}\b")
    imported = any(pat.search(open(t, encoding="utf-8").read())
                   for t in test_files)
    mod_cov[f] = {"dedicated_test": dedicated, "imported_by_any_test": imported}

uncovered = [m for m, c in mod_cov.items() if not c["imported_by_any_test"]]
no_dedicated = [m for m, c in mod_cov.items()
                if not c["dedicated_test"] and c["imported_by_any_test"]]

# ---------- axis 8: version consistency ---------------------------------------
def read(path):
    try:
        return open(path, encoding="utf-8").read()
    except OSError:
        return ""

pyproject = read("pyproject.toml")
pkg = read("package.json")
m_pyproject = re.search(r'version\s*=\s*"([^"]+)"', pyproject)
m_pkg = re.search(r'"version"\s*:\s*"([^"]+)"', pkg)
m_cli = re.search(r'burhan-core/([0-9][^"\s]*)', cli_src)
versions = {
    "pyproject": m_pyproject.group(1) if m_pyproject else None,
    "package.json": m_pkg.group(1) if m_pkg else None,
    "cli_banner": m_cli.group(1) if m_cli else None,
}
versions["consistent"] = (len({v for v in versions.values() if v}) == 1)

out = {
    "axis1_cli": {
        "subcommands": len(subcommands),
        "coverage": cmd_cov,
        "commands_with_no_tests_and_no_ci": [c for c, v in cmd_cov.items()
                                             if not v["tests"] and not v["ci_or_scripts"]],
    },
    "axis2_engine_modules": {
        "modules": len(mod_cov),
        "with_dedicated_test": sum(1 for c in mod_cov.values() if c["dedicated_test"]),
        "imported_by_tests": len(mod_cov) - len(uncovered),
        "uncovered_modules": uncovered,
        "shared_coverage_only": no_dedicated,
    },
    "axis8_versions": versions,
}
os.makedirs("evidence/r13", exist_ok=True)
json.dump(out, open("evidence/r13/axes-1-2-8.json", "w"), indent=1,
          ensure_ascii=False)
print(json.dumps(out["axis1_cli"]["commands_with_no_tests_and_no_ci"],
                 ensure_ascii=False))
print("engine modules:", out["axis2_engine_modules"]["modules"],
      "| dedicated:", out["axis2_engine_modules"]["with_dedicated_test"],
      "| uncovered:", uncovered)
print("versions:", versions)
