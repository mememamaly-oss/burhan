#!/usr/bin/env python3
"""Round-10 close: build the compact live-run evidence record.

Reads the full CI artifacts in download/r10-evidence/live-run-r10/
(scan reports 8MB each + the 15MB lifecycle store, kept OUT of git per the
round-9 precedent of committing only small proofs) and emits the compact
record that WILL be committed at evidence/live-run-r10/:
  - r10-live-validation.json (the verdict, verbatim, 4.4K)
  - summary.json (per-scan digests: run_id, seed, counts, identity hash)
Nothing in the big files is paraphrased without its source key here.
"""
import hashlib
import json
from pathlib import Path

SRC = Path("/home/z/my-project/download/r10-evidence/live-run-r10")
DST = Path("/home/z/my-project/evidence/live-run-r10")


def ident(f: dict) -> str:
    return "|".join((f.get("type", ""), f.get("url", ""),
                     f.get("parameter", "")))


def main() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    verdict = json.loads((SRC / "r10-live-validation.json").read_text())
    (DST / "r10-live-validation.json").write_text(
        json.dumps(verdict, indent=1, ensure_ascii=False) + "\n")

    summary = {
        "run": "GitHub Actions run 41922403748 (live-validation.yml, R10 job) — the SUCCESS dispatch",
        "dispatches_before_success": 3,
        "forensics": [
            "41913951604: hand-rolled race-candidate dict missing quota/concurrent/win_statuses — exit 3 (schema now mirrors the battery VERBATIM)",
            "41918334837: full scans ran but set -e killed the step BEFORE docker cp — verdict trapped in the dead scanbox (unconditional copy-out since ccfaa98)",
            "41920279230: THE GATE CAUGHT A REAL WIRING FLAW — one shared seed gave both passes the SAME run_id (run_id derives from the seed), so the store's exclude_run filter blinded pass 2: 98 re-appearing identities read NEW. Fixed: distinct per-pass seeds (identity is detector+endpoint+parameter, seed-independent)",
        ],
        "scans": {},
    }
    for tag in ("pass1", "pass2"):
        d = json.loads((SRC / f"r10-{tag}-scan.json").read_text())
        idents = sorted(ident(f) for f in d.get("findings", []))
        summary["scans"][tag] = {
            "run_id": d.get("run_id"),
            "seed": d.get("seed"),
            "target": d.get("target"),
            "findings": len(d.get("findings", [])),
            "requests": d.get("stats", {}).get("requests"),
            "identities_sha256": hashlib.sha256(
                "\n".join(idents).encode()).hexdigest()[:16],
        }
    d = json.loads((SRC / "r10-dvga-scan.json").read_text())
    summary["scans"]["dvga"] = {
        "run_id": d.get("run_id"),
        "seed": d.get("seed"),
        "target": d.get("target"),
        "findings": len(d.get("findings", [])),
        "requests": d.get("stats", {}).get("requests"),
    }
    lc = verdict["lifecycle"]
    summary["lifecycle"] = {
        "identity_overlap": lc["identity_overlap"],
        "overlap_states_scan2": lc["overlap_states_scan2"],
        "scan1_only": lc["scan1_only_identities"],
        "scan2_only": lc["scan2_only_identities"],
        "law": lc["law"],
    }
    summary["chains_honest"] = {
        "crapi_pass1_CR01_pair_present": True,
        "crapi_pass1_CR01_proven": False,
        "why_not": "step2 admin function: HTTP 405 — not executed (live refusal probe, 3 bounded requests, recorded)",
        "crapi_CR02_pair_present": False,
        "dvga_pairs_present": False,
    }
    summary["note"] = ("full CI artifacts (both crAPI scan reports, the DVGA "
                       "report, the lifecycle store.db) are delivered in "
                       "download/r10-evidence/live-run-r10/ — 34MB, kept out "
                       "of git like the round-8/r9 large artifacts.")
    (DST / "summary.json").write_text(
        json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    print("wrote:", sorted(p.name for p in DST.iterdir()))


if __name__ == "__main__":
    main()
