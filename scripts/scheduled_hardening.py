#!/usr/bin/env python3
"""Scheduled continuous hardening — round 8, part 3 (2026-11-03).

Runs the SAME gates the CI wall runs, on a schedule (and on demand), so
dependency drift or environment change surfaces automatically — the
numpy-missing incident of round 7 is exactly the class this catches
(a dependency silently missing from requirements made a whole detection
family dead until CI happened to exercise it).

Checks (each = the wall's own command, none weakened):
  antipattern-gate  scripts/audit_antipatterns.py --ci-gate
                    (the first-match/anti-pattern scanner + the manual
                    review ledger — new code that adds an unledgered
                    engine pattern FAILS here)
  quantum-sweep     scripts/audit_quantum_sweep.py --ci-gate
                    (round 12: the consolidated FOUR-class scanner —
                    first-match, SILENT_EXCEPT, TOCTOU, CLI-unreachable —
                    over the Python engine AND the TypeScript platform;
                    same ledger discipline, engine/src hits must match)
  doctor            python3 -m burhan.cli doctor
  pytest            python3 -m pytest tests/ -q
  benchmark-gate    python3 -m burhan.cli benchmark --race + the committed
                    confusion gate (F1 == 1.0, TP == 38, FP == 0)
  reproducibility   scripts/repro_attest.py two independent executions +
                    --compare (byte-identical outputs)

Any failure OPENS A TRACKED ISSUE (never a silent red): with GITHUB_TOKEN
in env the script searches OPEN issues labeled scheduled-hardening for one
with the same check-name title prefix — found: the new occurrence is a
COMMENT (dedup); not found: a new issue is opened. Without a token the
failures are printed and written to the report dir and the exit code is 1
(the workflow run itself is then the record).

Usage:
  python3 scripts/scheduled_hardening.py [--work-dir DIR] [--repo SLUG]
Repo slug defaults to the GITHUB_REPOSITORY env (Actions provides it).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABEL = "scheduled-hardening"
TITLE_PREFIX = "[scheduled-hardening]"


def _run(name: str, cmd: list[str], cwd: str = str(ROOT),
         timeout: int = 1800) -> tuple[bool, str]:
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        ok = r.returncode == 0
        tail = ((r.stdout or "") + "\n" + (r.stderr or "")).strip()[-2000:]
    except subprocess.TimeoutExpired:
        ok = False
        tail = "TIMEOUT after %ss" % timeout
    except Exception as e:  # noqa: BLE001 — a check crash is a finding
        ok = False
        tail = "%s: %s" % (type(e).__name__, e)
    print("== %s: %s (%.1fs)" % (name, "PASS" if ok else "FAIL",
                                 time.time() - t0), flush=True)
    return ok, tail


def _git_sha() -> str:
    r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                       cwd=str(ROOT), capture_output=True, text=True)
    return (r.stdout or "?").strip()


def _api(token: str, repo: str, method: str, path: str,
         body: dict | None = None) -> tuple[int, dict | list | None]:
    req = urllib.request.Request(
        "https://api.github.com/repos/%s%s" % (repo, path), method=method,
        headers={"Authorization": "Bearer %s" % token,
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode() or "{}"
            return resp.status, json.loads(data)
    except urllib.error.HTTPError as e:
        return e.code, None


def open_or_comment_issues(token: str, repo: str, failures: list[dict],
                           sha: str) -> list[str]:
    """The dedup mechanism, exactly: one OPEN issue per failing CHECK
    (title = '<prefix> <check> failed'), matched by title prefix among open
    issues carrying the label; a match gets the new occurrence as a
    comment, a miss gets a new issue. Returns the actions taken."""
    actions: list[str] = []
    code, open_issues = _api(token, repo, "GET",
                             "/issues?state=open&labels=%s&per_page=100" % LABEL)
    if code != 200 or not isinstance(open_issues, list):
        return ["issue-dedup-lookup-failed (HTTP %s) — failures recorded in "
                "the run only" % code]
    for f in failures:
        title = "%s %s failed" % (TITLE_PREFIX, f["check"])
        existing = next((i for i in open_issues
                         if (i.get("title") or "").startswith(title)), None)
        occurrence = ("occurrence %s on commit %s (run %s)\n\n```\n%s\n```"
                      % (f["when"], sha, os.environ.get("GITHUB_RUN_ID", "-"),
                         f["tail"][-1200:]))
        if existing:
            code, _ = _api(token, repo, "POST",
                           "/issues/%s/comments" % existing["number"],
                           {"body": occurrence})
            actions.append("commented issue #%s (%s) — HTTP %s"
                           % (existing["number"], f["check"], code))
        else:
            body = ("A scheduled-hardening run failed this check.\n\n%s\n\n"
                    "Full output tail:\n```\n%s\n```\n\nOpened automatically "
                    "by scripts/scheduled_hardening.py; this issue tracks the "
                    "check until a fix lands and the gate goes green."
                    % (occurrence, f["tail"][-1500:]))
            code, created = _api(token, repo, "POST", "/issues",
                                {"title": title, "body": body,
                                 "labels": [LABEL]})
            num = (created or {}).get("number", "?")
            actions.append("opened issue #%s (%s) — HTTP %s"
                           % (num, f["check"], code))
    return actions


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work-dir", default="/tmp/scheduled-hardening")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = ap.parse_args()
    work = Path(args.work_dir)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    sha = _git_sha()
    results: list[tuple[str, bool, str]] = []

    ok, tail = _run("antipattern-gate",
                    [sys.executable, "scripts/audit_antipatterns.py",
                     "--ci-gate"])
    results.append(("antipattern-gate", ok, tail))

    ok, tail = _run("quantum-sweep",
                    [sys.executable, "scripts/audit_quantum_sweep.py",
                     "--ci-gate"])
    results.append(("quantum-sweep", ok, tail))

    ok, tail = _run("doctor", [sys.executable, "-m", "burhan.cli", "doctor"])
    results.append(("doctor", ok, tail))

    ok, tail = _run("pytest", [sys.executable, "-m", "pytest", "tests/", "-q"])
    results.append(("pytest", ok, tail))

    bench_out = work / "benchmark.json"
    ok, tail = _run("benchmark-run",
                    [sys.executable, "-m", "burhan.cli", "benchmark",
                     "--race", "--out", str(bench_out)], timeout=2400)
    gate_note = ""
    if ok and bench_out.exists():
        try:
            b = json.loads(bench_out.read_text())
            c = b["confusion"]
            gate_note = ("P/R/F1: %s/%s/%s confusion: %s"
                         % (b["precision"], b["recall"], b["f1"], c))
            if b["f1"] != 1.0 or c["TP"] != 38 or c["FP"] != 0:
                ok = False
                tail = ("benchmark confusion gate regressed: %s "
                        "(expected F1=1.0 TP=38 FP=0)" % gate_note)
        except Exception as e:  # noqa: BLE001
            ok, tail = False, "benchmark gate parse failed: %s" % e
    print("benchmark gate: %s | %s" % ("PASS" if ok else "FAIL", gate_note),
          flush=True)
    results.append(("benchmark-gate", ok, tail))

    repro_dir = work / "repro"
    ok_a, tail_a = _run("repro-tag-a", [sys.executable,
                                        "scripts/repro_attest.py",
                                        "--tag", "a",
                                        "--out-dir", str(repro_dir)])
    ok_b, tail_b = _run("repro-tag-b", [sys.executable,
                                        "scripts/repro_attest.py",
                                        "--tag", "b",
                                        "--out-dir", str(repro_dir)])
    ok_c, tail_c = _run("repro-compare", [sys.executable,
                                           "scripts/repro_attest.py",
                                           "--compare", str(repro_dir)])
    results.append(("reproducibility", ok_a and ok_b and ok_c,
                    "\n".join(x for x in (tail_a, tail_b, tail_c) if x)))

    failures = [{"check": n, "tail": t,
                 "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                for n, ok, t in results if not ok]
    report = {"when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "commit": sha, "checks": {n: ok for n, ok, _ in results},
              "failures": failures}
    (work / "hardening-report.json").write_text(
        json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    print("\n== scheduled-hardening: %d/%d checks passed %s"
          % (len(results) - len(failures), len(results),
             "(ALL GREEN)" if not failures else ""), flush=True)

    if failures:
        token = os.environ.get("GITHUB_TOKEN", "")
        if token and args.repo:
            for a in open_or_comment_issues(token, args.repo, failures, sha):
                print("issue-mechanism: %s" % a, flush=True)
        else:
            print("issue-mechanism: no GITHUB_TOKEN/repo in env — failures "
                  "recorded in the run + %s" %
                  (work / "hardening-report.json"), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
