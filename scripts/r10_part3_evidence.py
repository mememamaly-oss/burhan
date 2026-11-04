"""Round 10, PART 3 — the SCA evidence pair (order item 3.4).

RED  (run from a worktree at 3a1e52b, the pre-change tree): the engine
      has NO dependency-analysis capability — the `sca` command does not
      exist, no OSV query code exists, and no SCA finding type appears
      in the compliance registry. Recorded at evidence/layers/sca/RED.json.

BLUE (this branch, run live): three real manifest scans against the
      REAL OSV.dev public batch API, raw responses saved verbatim:
      1. THIS repo's own requirements.txt — the plain truth (one exact
         pin queryable; ranges recorded as unresolved; package.json
         refused as documented-deferred to its lockfile).
      2. A deliberately pinned old requirements.txt (requests==2.19.1)
         — the advisory set must include the named public CVEs.
      3. A deliberately pinned old package-lock.json (lodash 4.17.15)
         — the advisory set must include the named public CVEs.
      Plus the KEV record: the live cisa.gov catalog fetch refusal (WAF
      403, verbatim) and the offline matching demo against a
      clearly-labeled TEST catalog.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

EV = os.path.join(ROOT, "evidence", "layers", "sca")


def main() -> int:
    os.makedirs(EV, exist_ok=True)
    mode = sys.argv[1] if len(sys.argv) > 1 else "blue"
    assert mode in ("red", "blue")

    if mode == "red":
        # ---- RED: the pre-change tree has no SCA capability at all ----
        out = {}
        r = subprocess.run(
            [sys.executable, "-m", "burhan.cli", "sca", "--manifest",
             "requirements.txt"], capture_output=True, text=True, cwd=ROOT)
        out["sca_command_exists"] = r.returncode == 0
        out["sca_command_stderr"] = (r.stderr or r.stdout).strip()[:200]
        hits = subprocess.run(
            ["grep", "-rli", "osv", "burhan/"], capture_output=True,
            text=True, cwd=ROOT).stdout.strip()
        out["engine_files_mentioning_osv"] = hits or "(none)"
        out["compliance_has_sca_row"] = '"sca_vulnerable_dependency"' in \
            open(os.path.join(ROOT, "burhan", "compliance.py")).read()
        out["sarif_has_sca_rule"] = '"sca_vulnerable_dependency"' in \
            open(os.path.join(ROOT, "burhan", "report.py")).read()
        out["verdict"] = ("no manifest ingestion, no OSV query, no SCA "
                          "finding type — the capability does not exist "
                          "anywhere in the pre-change tree")
        assert not out["sca_command_exists"]
        assert not out["compliance_has_sca_row"]
        assert not out["sarif_has_sca_rule"]
        json.dump(out, open(os.path.join(EV, "RED.json"), "w"), indent=1)
        print("RED evidence -> evidence/layers/sca/RED.json")
        print(json.dumps(out, indent=1))
        return 0

    # ---- BLUE: three real scans + the KEV record ------------------------
    from burhan.sca import (build_sca_findings, ManifestRejected,
                            kev_match)

    # 1. this repo's own requirements.txt — plain result
    raw1 = os.path.join(EV, "raw-repo-requirements")
    os.makedirs(raw1, exist_ok=True)
    repo_out = build_sca_findings(os.path.join(ROOT, "requirements.txt"),
                                 raw_dir=raw1)
    json.dump(repo_out, open(os.path.join(EV, "repo-requirements-sca.json"),
                             "w"), indent=1, ensure_ascii=False)
    # the package.json refusal (deferred to its lockfile) is part of the
    # honest record
    try:
        build_sca_findings(os.path.join(ROOT, "package.json"))
        refusal = "UNEXPECTED: package.json was accepted"
    except ManifestRejected as e:
        refusal = str(e)
    json.dump({"refused": "package.json",
               "reason": refusal},
              open(os.path.join(EV, "repo-package-json-refusal.json"), "w"),
              indent=1)

    # 2. the deliberately pinned old requirements (requests 2.19.1)
    inp = os.path.join(EV, "inputs")
    os.makedirs(inp, exist_ok=True)
    old_req = os.path.join(inp, "requirements.txt")
    open(old_req, "w").write(
        "# deliberately pinned OLD versions — the SCA live-evidence input\n"
        "requests==2.19.1\n")
    raw2 = os.path.join(EV, "raw-old-requirements")
    os.makedirs(raw2, exist_ok=True)
    old1 = build_sca_findings(old_req, raw_dir=raw2)
    json.dump(old1, open(os.path.join(EV, "old-requirements-sca.json"), "w"),
             indent=1, ensure_ascii=False)

    # 3. the deliberately pinned old package-lock (lodash 4.17.15)
    old_lock = os.path.join(inp, "package-lock.json")
    json.dump({
        "name": "old-client-app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "old-client-app", "version": "1.0.0"},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.15"},
        }}, open(old_lock, "w"), indent=1)
    raw3 = os.path.join(EV, "raw-old-package-lock")
    os.makedirs(raw3, exist_ok=True)
    old2 = build_sca_findings(old_lock, raw_dir=raw3)
    json.dump(old2, open(os.path.join(EV, "old-package-lock-sca.json"), "w"),
              indent=1, ensure_ascii=False)

    # named public CVE assertions (documented, checkable facts)
    cves_req = sorted({c for f in old1["findings"] for c in f["cve_aliases"]})
    cves_ld = sorted({c for f in old2["findings"] for c in f["cve_aliases"]})
    assert "CVE-2023-32681" in cves_req, cves_req
    assert "CVE-2020-8203" in cves_ld and "CVE-2021-23337" in cves_ld, cves_ld

    # 4. the KEV record: live fetch refusal (verbatim) + offline demo
    kev = {"live_fetch": None}
    try:
        req = urllib.request.Request(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
        with urllib.request.urlopen(req, timeout=20) as r:
            kev["live_fetch"] = {"http_status": r.status, "bytes": 0}
            open(os.path.join(EV, "kev-catalog-live.json"), "wb").write(r.read())
    except urllib.error.HTTPError as e:
        kev["live_fetch"] = {
            "http_status": e.code,
            "verbatim": re.sub(r"\s+", " ", e.read().decode(
                "utf-8", "replace"))[:220],
            "note": ("the cisa.gov catalog fetch was REFUSED from this "
                     "environment (WAF 403 Access Denied). The KEV "
                     "cross-reference therefore ships as OFFLINE matching "
                     "against the operator's own copy of the official "
                     "catalog (--kev-catalog); no live fetch is attempted "
                     "at scan time by design"),
        }
    # the offline matching demo — against a clearly-labeled TEST catalog
    test_cat = os.path.join(EV, "kev-TEST-catalog.json")
    json.dump({
        "_label": ("TEST FIXTURE — NOT the official CISA catalog. For the "
                   "offline-matching demo only; the operator passes the "
                   "real catalog file via --kev-catalog"),
        "vulnerabilities": [
            {"cveID": "CVE-2023-32681"},
            {"cveID": "CVE-2020-8203"},
        ]}, open(test_cat, "w"), indent=1)
    kev["offline_match_demo"] = {
        "requests_2_19_1": sorted(kev_match(
            ["CVE-2023-32681", "GHSA-x"], test_cat)),
        "lodash_4_17_15": sorted(kev_match(
            ["CVE-2020-8203", "CVE-2021-23337"], test_cat)),
        "negative_control": sorted(kev_match(
            ["CVE-2021-23337"], test_cat)),   # not in the fixture catalog
    }
    kev["repo_requirements_plain_result"] = {
        "packages_queried": repo_out["packages_queried"],
        "advisory_ids": repo_out["advisory_ids"],
        "unresolved_pins": repo_out["unresolved_pins"],
        "note": ("this repo's own manifest: ONE exact pin queryable "
                 "(blake3==1.0.11); the range pins are recorded as "
                 "unresolved (the resolved version is unknown from a "
                 "range — never guessed). The result is whatever OSV "
                 "returned for the exact pin: reported plainly, not "
                 "manufactured"),
    }
    kev["old_manifests_named_public_cves"] = {
        "requests==2.19.1": cves_req,
        "lodash==4.17.15": cves_ld,
    }
    json.dump(kev, open(os.path.join(EV, "KEV-and-summary.json"), "w"),
             indent=1, ensure_ascii=False)

    # SHA256SUMS over the whole evidence dir (the established pattern)
    rel = []
    for dirpath, _, files in os.walk(EV):
        for fn in files:
            if fn == "SHA256SUMS":
                continue
            full = os.path.join(dirpath, fn)
            rel.append((os.path.relpath(full, os.path.join(ROOT, "evidence")),
                        full))
    lines = []
    import hashlib
    for rrel, full in sorted(rel):
        h = hashlib.sha256(open(full, "rb").read()).hexdigest()
        lines.append(f"{h}  {rrel}")
    # regenerate once to include this file's own inputs (idempotent set)
    open(os.path.join(EV, "SHA256SUMS"), "w").write("\n".join(lines) + "\n")
    print(f"BLUE evidence -> evidence/layers/sca/ ({len(lines)} files stamped)")
    print(json.dumps({
        "repo_pin_queried": repo_out["packages_queried"],
        "old_requests_cves": cves_req,
        "old_lodash_cves": cves_ld,
        "kev_live_fetch_status": (kev["live_fetch"] or {}).get("http_status"),
    }, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
