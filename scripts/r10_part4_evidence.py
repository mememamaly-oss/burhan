"""Round 10, PART 4 — the unified-report evidence pair (order item 4).

RED  (run from a worktree at 23ec690, the pre-change tree): the three
      finding categories live in three SEPARATE outputs — the scan
      result carries its DAST findings, `burhan sca` writes a standalone
      JSON, chains ride the scan payload — and NO command can rank them
      together. No cross-category judgment call is documented anywhere
      (an advisory-confirmed dependency has no stated verdict weight).
      Recorded at evidence/layers/unified-report/RED.json.

BLUE (this branch, run live): a REAL chainapp scan (bfla +
      jwt_signature_not_enforced + the proven CR-01 chain) unified with
      the REAL committed OSV result for requests==2.19.1 (evidence/
      layers/sca/old-requirements-sca.json) into ONE ranked list — then
      a SECOND invocation over the same inputs against the same store,
      resolving the SCA and chain rows RECURRING. All three judgment
      calls (J1/J2/J3) surface in every output.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

EV = os.path.join(ROOT, "evidence", "layers", "unified-report")


def _sha256sums():
    rel = []
    for dirpath, _, files in os.walk(EV):
        for fn in files:
            if fn == "SHA256SUMS":
                continue
            full = os.path.join(dirpath, fn)
            rel.append((os.path.relpath(full, os.path.join(ROOT, "evidence")),
                        full))
    import hashlib
    lines = []
    for rrel, full in sorted(rel):
        h = hashlib.sha256(open(full, "rb").read()).hexdigest()
        lines.append(f"{h}  {rrel}")
    open(os.path.join(EV, "SHA256SUMS"), "w").write("\n".join(lines) + "\n")
    print(f"stamped {len(lines)} files -> evidence/layers/unified-report/SHA256SUMS")


def main() -> int:
    os.makedirs(EV, exist_ok=True)
    mode = sys.argv[1] if len(sys.argv) > 1 else "blue"
    assert mode in ("red", "blue")

    if mode == "red":
        # ---- RED: the pre-change tree cannot rank the three categories ----
        out = {}
        r = subprocess.run(
            [sys.executable, "-m", "burhan.cli", "unified", "--scan", "x"],
            capture_output=True, text=True, cwd=ROOT)
        out["unified_command_exists"] = r.returncode == 0
        out["unified_command_stderr"] = (r.stderr or "").strip()[-200:]
        out["unified_module_exists"] = os.path.exists(
            os.path.join(ROOT, "burhan", "unified.py"))
        pri = open(os.path.join(ROOT, "burhan", "prioritize.py")).read()
        out["prioritize_knows_advisory_verdict"] = \
            "confirmed_by_advisory" in pri
        out["judgment_calls_documented"] = bool(
            re.search(r"judgment_calls", "\n".join(
                open(os.path.join(ROOT, "burhan", f)).read()
                for f in os.listdir(os.path.join(ROOT, "burhan"))
                if f.endswith(".py"))))
        out["verdict"] = ("three separate outputs, no unified command, no "
                          "stated cross-category verdict weight — the "
                          "categories cannot be ranked together and the "
                          "advisory-confirmed judgment is undocumented")
        assert not out["unified_command_exists"]
        assert not out["unified_module_exists"]
        assert not out["prioritize_knows_advisory_verdict"]
        assert not out["judgment_calls_documented"]
        json.dump(out, open(os.path.join(EV, "RED.json"), "w"), indent=1)
        print("RED evidence -> evidence/layers/unified-report/RED.json")
        print(json.dumps(out, indent=1)[:600])
        return 0

    # ---- BLUE: the REAL triple-category unification, two passes ---------
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]; s.close()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "chainapp.py")],
        env={**os.environ, "PORT": str(port), "CHAIN_TWIN": "red"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(80):
            if proc.poll() is not None:
                raise RuntimeError("chainapp died during startup")
            try:
                urllib.request.urlopen(base + "/", timeout=2)
                break
            except Exception:
                time.sleep(0.25)
        from burhan.auth import AuthProfile
        from burhan.orchestrator import ScanConfig, BurhanScanner
        auth = AuthProfile(login_url=base + "/auth/api/login", json_login=True,
                           username="bob@chainapp.test", password="bob-pass-123",
                           user_field="email", pass_field="password",
                           success_marker="authenticated")
        authz = {"login_url": base + "/auth/api/login", "json_login": True,
                 "user_field": "email", "pass_field": "password",
                 "success_marker": "authenticated",
                 "accounts": [
                     {"name": "admin", "role": "admin",
                      "username": "root-admin@chainapp.test",
                      "password": "admin-pass-123",
                      "marker": "root-admin@chainapp.test"},
                     {"name": "bob", "role": "user",
                      "username": "bob@chainapp.test",
                      "password": "bob-pass-123",
                      "marker": "bob@chainapp.test"}]}
        cfg = ScanConfig(allow_private=True, max_pages=6, timeout=8.0,
                         seed="r10p4ev" * 8, modern_v2=True, max_requests=6000,
                         browser=False, websocket=False, graphql=False,
                         auth=auth, authz=authz, workflow=False,
                         logic_active=False, openapi=False)
        rep = BurhanScanner(base, cfg).run()
    finally:
        proc.terminate(); proc.wait(timeout=10)

    types = sorted({f["type"] for f in rep["findings"]})
    cr01 = [c for c in rep.get("attack_chains", [])
            if c["rule"] == "CR-01-credential-feeding"]
    assert "bfla" in types and "jwt_signature_not_enforced" in types, types
    assert cr01, "the chainapp scan must yield the proven CR-01 chain"
    scan_path = os.path.join(EV, "scan-chainapp.json")
    json.dump(rep, open(scan_path, "w"), indent=1, ensure_ascii=False)

    sca_path = os.path.join(ROOT, "evidence", "layers", "sca",
                            "old-requirements-sca.json")
    store_path = os.path.join(EV, "lifecycle-store.db")
    for suffix in ("", "-wal", "-shm"):   # WAL sidecars too — a stale
        # -wal would replay the OLD run's frames into a fresh db
        if os.path.exists(store_path + suffix):
            os.unlink(store_path + suffix)

    cli = [sys.executable, "-m", "burhan.cli", "unified",
           "--scan", scan_path, "--sca", sca_path,
           "--prioritize-store", store_path]
    outs = []
    for label in ("pass1", "pass2"):
        out_path = os.path.join(EV, f"unified-{label}.json")
        r = subprocess.run(cli + ["--out", out_path],
                           capture_output=True, text=True, cwd=ROOT)
        assert r.returncode == 0, r.stderr
        u = json.load(open(out_path, encoding="utf-8"))
        outs.append(u)
        print(label, "->", u["counts_by_category"])

    u1, u2 = outs
    assert u1["counts_by_category"]["chain"] == 1
    assert u1["counts_by_category"]["sca"] >= 1
    assert u1["counts_by_category"]["dast"] >= 2
    assert all(r["lifecycle"] == "NEW" for r in u1["rows"])
    for cat in ("sca", "chain"):
        rows2 = [r for r in u2["rows"] if r["category"] == cat]
        assert rows2 and all(r["lifecycle"] == "RECURRING" for r in rows2), \
            f"{cat} rows must resolve RECURRING on pass 2"
    scores = [r["risk_score"] for r in u2["rows"]]
    assert scores == sorted(scores, reverse=True)

    # the store's lifecycle trail, read straight from the log
    import sqlite3
    with sqlite3.connect(store_path) as c:
        trail = [
            {"run": r[0], "identity": r[1], "state": r[2]}
            for r in c.execute(
                "SELECT run_id, identity, state FROM lifecycle_log "
                "ORDER BY resolved_at, identity")]
        # both passes run over IDENTICAL inputs — every previously
        # present identity is present again: the log must carry ZERO
        # absences (an UNTESTED_ABSENCE here would be a corruption
        # artifact, not an honest resolution)
        assert all(t["state"] in ("NEW", "RECURRING") for t in trail), trail
        assert len(trail) >= 4, trail
    blue = {
        "mode": "blue",
        "scan_types": types,
        "chain_rule_present": "CR-01-credential-feeding",
        "sca_input": "evidence/layers/sca/old-requirements-sca.json "
                     "(the committed REAL OSV result for requests==2.19.1)",
        "counts_pass1": u1["counts_by_category"],
        "counts_pass2": u2["counts_by_category"],
        "top_rows_pass1": [
            {"category": r["category"], "id": r["id"],
             "risk_score": r["risk_score"], "lifecycle": r["lifecycle"]}
            for r in u1["rows"][:5]],
        "judgment_calls": [j["id"] + ": " + j["call"] for j in u1["judgment_calls"]],
        "lifecycle_trail_rows": len(trail),
        "recurring_seen_pass2": sorted(
            {r["identity"][:8] for r in trail if r["state"] == "RECURRING"}),
        "verdict": ("ONE ranked list over DAST + SCA + the proven chain, "
                    "the three judgment calls stated in every output, and "
                    "the second pass resolving SCA/chain rows RECURRING "
                    "against the shared store"),
    }
    json.dump(blue, open(os.path.join(EV, "BLUE.json"), "w"),
             indent=1, ensure_ascii=False)
    _sha256sums()
    print("BLUE evidence -> evidence/layers/unified-report/")
    print(json.dumps({k: blue[k] for k in
                      ("counts_pass1", "counts_pass2",
                       "judgment_calls", "top_rows_pass1")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
