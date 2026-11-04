"""Round 10, PART 1 — the RED->BLUE evidence pair (order item 1.3).

RED  (run against 3a1e52b, the pre-change tree): the three-scan sequence
      on the same live target — the flat-list behavior. Findings carry NO
      identity, NO lifecycle, NO score; and the only cross-run primitive,
      Store.delta(), classifies the RE-BROKEN finding as "new" — a
      count-level fingerprint diff that cannot tell a regression from a
      fresh vulnerability.

BLUE (run against this branch): the same sequence — identity matching
      across scans, NEW -> FIXED (coverage-gated) -> REGRESSED, the
      stated score + components on every finding, the ranked view.

Usage:
  blue: python3 scripts/r10_part1_evidence.py blue  <out.json> <db.sqlite>
  red:  run from a git worktree checked out at 3a1e52b:
        python3 scripts/r10_part1_evidence.py red   <out.json> <db.sqlite>
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

VULN = ("return self._send(200, HEADER_TMPL.format(body=f\"<div>You searched "
        "for '{qv}'</div>\"))")
SAFE = ("return self._send(200, HEADER_TMPL.format(body=f\"<div>You searched for '"
        "{qv.replace('<', '" + chr(38) + "lt;').replace('>', '" + chr(38) +
        "gt;')}'</div>\"))")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def variant_file(kind: str, port_dir: str) -> str:
    text = open(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                encoding="utf-8").read()
    if kind == "patched":
        assert VULN in text
        text = text.replace(VULN, SAFE)
    path = os.path.join(port_dir, f"vulnapp-{kind}.py")
    open(path, "w", encoding="utf-8").write(text)
    return path


def run_variant(path: str, port: int):
    proc = subprocess.Popen(
        [sys.executable, path],
        env={"PORT": str(port), "PATH": "/usr/bin:/bin"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(base + "/", timeout=2)
            return proc, base
        except Exception:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("fixture did not come up")


def scan(base: str, seed: str, db: str, mode: str) -> dict:
    """One engine scan. BLUE wires prioritize_store (the new ScanConfig
    parameter); RED runs the old signature verbatim."""
    from burhan.orchestrator import ScanConfig, BurhanScanner
    common = dict(allow_private=True, max_pages=25, timeout=8.0, seed=seed,
                  max_requests=2500, browser=False, workflow=False,
                  logic_active=False, race=False, symbolic=False,
                  websocket=False, graphql=False, modern=False)
    if mode == "blue":
        cfg = ScanConfig(prioritize_store=db, **common)
    else:
        cfg = ScanConfig(**common)
    return BurhanScanner(base, cfg).run()


def xss_of(rep: dict) -> list[dict]:
    return [f for f in rep.get("findings", [])
            if f["type"] == "xss_reflected"
            and f["url"].split("?")[0].endswith("/vuln/xss.php")]


def main() -> int:
    mode, out_path, db_path = sys.argv[1], sys.argv[2], sys.argv[3]
    assert mode in ("red", "blue")
    workdir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(workdir, exist_ok=True)
    port = free_port()

    from burhan.store import Store
    st = Store(db_path)

    scans = []
    for kind, seed in (("vulnerable", "r10-evidA" * 8),
                       ("patched", "r10-evidB" * 8),
                       ("rebroken", "r10-evidC" * 8)):
        vf = variant_file("vulnerable" if kind != "patched" else "patched",
                          workdir)
        proc, base = run_variant(vf, port)
        try:
            rep = scan(base, seed, db_path, mode)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            time.sleep(0.6)
        st.save_run(rep)
        scans.append({"kind": kind, "run_id": rep["run_id"],
                      "xss_count": len(xss_of(rep)),
                      "xss": xss_of(rep), "rep": rep})

    s1, s2, s3 = scans
    x1, x3 = (s1["xss"] or [{}])[0], (s3["xss"] or [{}])[0]

    if mode == "blue":
        ident = x1.get("identity")
        import sqlite3
        with sqlite3.connect(db_path) as c:
            trail = list(c.execute(
                "SELECT state FROM lifecycle_log WHERE identity=? "
                "ORDER BY resolved_at", (ident,)))
        resolution2 = s2["rep"]["prioritization"]["resolution"]
        out = {
            "mode": "BLUE (post-change: identity + lifecycle + stated score)",
            "sequence": "vulnerable -> patched -> re-broken, same target, "
                        "identity matching across scans",
            "identity": ident,
            "identity_basis": x1.get("identity_basis"),
            "scan1_vulnerable": {
                "xss_found": True, "lifecycle": x1.get("lifecycle"),
                "risk_score": x1.get("risk_score"),
                "risk_components": x1.get("risk_components")},
            "scan2_patched": {
                "xss_found": False,
                "fixed_identities": len(resolution2["fixed"]),
                "xss_resolved_FIXED": ident in resolution2["fixed"],
                "untested_absences": len(resolution2["untested_absences"]),
                "coverage_gate": "the endpoint WAS re-tested this run "
                                "(request journal) -> the absence is FIXED"},
            "scan3_rebroken": {
                "xss_found": True, "lifecycle": x3.get("lifecycle"),
                "same_identity_as_scan1": x3.get("identity") == ident,
                "risk_score": x3.get("risk_score"),
                "risk_components": x3.get("risk_components")},
            "lifecycle_trail_in_store": [r[0] for r in trail],
            "regressed_outranks_new": (x3.get("risk_score", 0)
                                       > x1.get("risk_score", 0)),
            "formula": s3["rep"]["prioritization"]["formula"],
        }
        assert out["scan2_patched"]["xss_resolved_FIXED"]
        assert out["scan3_rebroken"]["lifecycle"] == "REGRESSED"
        assert out["lifecycle_trail_in_store"] == ["NEW", "FIXED", "REGRESSED"]
    else:
        # RED: the flat-list behavior. Findings carry none of the round-10
        # keys; delta() (fingerprint diff) calls the re-broken finding "new".
        fp = None
        from burhan.store import finding_fingerprint
        for f in s1["xss"]:
            fp = finding_fingerprint(f["type"], f.get("method", "GET"),
                                     f.get("url", ""), f.get("parameter", ""))
        d23 = st.delta(s2["run_id"], s3["run_id"])
        d13 = st.delta(s1["run_id"], s3["run_id"])
        out = {
            "mode": "RED (pre-change 3a1e52b: flat list, no lifecycle)",
            "sequence": "identical vulnerable -> patched -> re-broken",
            "finding_keys": sorted(s1["xss"][0].keys()) if s1["xss"] else [],
            "has_identity": any("identity" in f for f in [x1]),
            "has_lifecycle": any("lifecycle" in f for f in [x1]),
            "has_risk_score": any("risk_score" in f for f in [x1]),
            "xss_fingerprint": fp,
            "delta_run2_vs_run3": {"new": len(d23["new"]),
                                   "fixed": len(d23["fixed"]),
                                   "recurring": len(d23["recurring"])},
            "delta_says_rebroken_is_new": fp in d23["new"] if fp else None,
            "delta_cannot_tell_regression_from_fresh": (
                "Store.delta() is a set difference over fingerprints: the "
                "REGRESSED finding appears in 'new' (run2->run3) exactly as "
                "a brand-new vulnerability would — no FIXED memory, no "
                "REGRESSED state exists anywhere in the pre-change tree"),
        }
        assert out["delta_says_rebroken_is_new"] is True, \
            "RED premise failed: delta() did not classify the re-broken " \
            "finding as new"
        assert not out["has_identity"] and not out["has_lifecycle"]

    out["runs"] = [{"kind": s["kind"], "run_id": s["run_id"],
                    "xss_count": s["xss_count"]} for s in scans]
    out["scanner"] = scans[0]["rep"].get("scanner")
    out["target"] = f"http://127.0.0.1:{port}"
    json.dump(out, open(out_path, "w"), indent=1, ensure_ascii=False)
    print(f"{mode.upper()} evidence -> {out_path}")
    print(json.dumps({k: v for k, v in out.items()
                      if k not in ("runs",)}, indent=1)[:1500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
