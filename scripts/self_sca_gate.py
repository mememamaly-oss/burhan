#!/usr/bin/env python3
"""R18 Part 7.2: the project's own manifests, on a schedule.

Round 12 Part 2.1 ran a one-off self-SCA (the pytest 9.0.2/9.0.3
tmpdir finding); Round 11's continuous-monitoring layer was configured
for TARGET scanning (monitor.yml, the dogfood fixture) and Round 8's
weekly hardening wall ran the quality gates — but NOTHING re-ran the
SCA layer against THIS repo's own requirements.txt / package-lock.json
on a schedule, so dependency drift between pushes would surface only
by luck. This script is that wire: run the existing SCA layer against
the project's own real manifests and exit non-zero on any NEW advisory
since the committed baseline, so the weekly continuous-hardening job
fails loudly (its auto-issue mechanism then files the alert).

Honest scope notes, per the established discipline:
  - requirements.txt is fully supported (exact pins).
  - package.json carries RANGE constraints only (no lockfile is
    tracked at the repo root); the SCA layer deliberately rejects it
    in favor of a lockfile (burhan/sca.py docstring). The gate scans
    requirements.txt and reports the package.json deferral VERBATIM in
    its summary — stated, not silently skipped.
  - The baseline (evidence/layers/self-sca/baseline.json) records the
    known-and-accepted set; anything beyond it fails the gate. The
    owner triages: bump the pin, or add a documented-acceptance entry
    with a reason to the baseline (same shape as the scanner ledger).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from burhan.sca import build_sca_findings, ManifestRejected  # noqa: E402

BASELINE = "evidence/layers/self-sca/baseline.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default=BASELINE)
    ap.add_argument("--fail-on-any", action="store_true",
                    help="fail on ANY finding (CI first-run mode: no "
                         "baseline exists yet, so every finding is new)")
    args = ap.parse_args()

    findings: list[dict] = []
    deferred: list[str] = []
    for manifest in ("requirements.txt", "package-lock.json"):
        if not os.path.exists(manifest):
            if manifest == "package-lock.json":
                deferred.append(
                    "package-lock.json: no lockfile tracked at the repo "
                    "root — package.json is a range manifest the SCA layer "
                    "deliberately defers to a lockfile (burhan/sca.py)")
            continue
        try:
            rep = build_sca_findings(manifest)
            findings.extend(rep["findings"] if isinstance(rep, dict)
                            and "findings" in rep else rep or [])
        except ManifestRejected as e:
            deferred.append(f"{manifest}: {e}")

    ids = sorted({f.get("advisory_id", "?") for f in findings})
    baseline_ids: list[str] = []
    if os.path.exists(args.baseline):
        baseline_ids = json.load(open(args.baseline, encoding="utf-8")) \
            .get("advisory_ids", [])
    new_ids = [i for i in ids if i not in baseline_ids]

    print(json.dumps({
        "checked": ["requirements.txt"],
        "deferred": deferred,
        "total_advisories": len(ids),
        "baseline_advisories": len(baseline_ids),
        "new_since_baseline": new_ids,
    }, indent=1, ensure_ascii=False))

    if new_ids and (args.fail_on_any or baseline_ids):
        print(f"SELF-SCA GATE: {len(new_ids)} NEW advisories since the "
              f"committed baseline: {new_ids}")
        return 1
    print("SELF-SCA GATE: no new advisories beyond the committed baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
