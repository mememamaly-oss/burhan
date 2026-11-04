"""Round 10, PART 2 — the attack-path-chaining evidence pair.

RED  (run from a worktree at the pre-change tree): the SAME chainapp
      RED-twin scan produces BOTH findings (bfla + jwt_signature_not_
      enforced) and NO chain — the capability does not exist: no
      chainrules module, no attack_chains key in the payload.

BLUE (this branch): the same scan reports the CR-01 chain with the live
      combined proof (elevation oracle observed over HTTP), and the BLUE
      TWIN — same two classes, broken escalation link — reports ZERO
      chains, proving the layer is not "any two highs = chain".
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

EV = os.path.join(ROOT, "evidence", "layers", "attack-path-chaining")
KEEP = ("bfla", "jwt_signature_not_enforced")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def scan_twin(twin: str) -> dict:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "chainapp.py")],
        env={**os.environ, "PORT": str(port), "CHAIN_TWIN": twin,
             "PATH": "/usr/bin:/bin"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/", timeout=2)
                break
            except Exception:
                time.sleep(0.25)
        from burhan.auth import AuthProfile
        from burhan.orchestrator import ScanConfig, BurhanScanner
        auth = AuthProfile(login_url=base + "/auth/api/login", json_login=True,
                           username="bob@chainapp.test",
                           password="bob-pass-123", user_field="email",
                           pass_field="password",
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
                         seed="r10p2ev" * 8, modern_v2=True,
                         max_requests=6000, browser=False, websocket=False,
                         graphql=False, auth=auth, authz=authz,
                         workflow=False, logic_active=False, openapi=False)
        return BurhanScanner(base, cfg).run()
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def main() -> int:
    os.makedirs(EV, exist_ok=True)
    mode = sys.argv[1]
    assert mode in ("red", "blue")

    if mode == "red":
        rep = scan_twin("red")
        types = sorted({f["type"] for f in rep["findings"]})
        has_pair = all(t in types for t in KEEP)
        out = {
            "mode": "RED (pre-change tree: the chain capability does not exist)",
            "red_twin_scan": {
                "finding_types": types,
                "bfla_present": "bfla" in types,
                "jwt_signature_not_enforced_present":
                    "jwt_signature_not_enforced" in types,
                "attack_chains_key_in_report": "attack_chains" in rep,
                "attack_chains_value": rep.get("attack_chains", "(key absent)"),
                "chainrules_module_exists": os.path.exists(
                    os.path.join(ROOT, "burhan", "chainrules.py")),
            },
            "verdict": ("the SAME two findings fire in the same scan with "
                        "NO way to express that one feeds the other — the "
                        "pre-change report is a flat list; the escalation "
                        "relationship exists in reality and is invisible "
                        "in the artifact"),
        }
        assert has_pair and "attack_chains" not in rep
        json.dump(out, open(os.path.join(EV, "RED.json"), "w"), indent=1)
        print(json.dumps(out, indent=1))
        return 0

    # ---- BLUE: both twins, one run each
    red_rep = scan_twin("red")
    blue_rep = scan_twin("blue")

    def _chains_of(rep):
        return rep.get("attack_chains", [])

    cr01_red = [c for c in _chains_of(red_rep)
                if c["rule"] == "CR-01-credential-feeding"]
    cr01_blue = [c for c in _chains_of(blue_rep)
                 if c["rule"] == "CR-01-credential-feeding"]
    assert cr01_red, "RED twin must report the proven chain"
    assert not cr01_blue, "BLUE twin must report ZERO chains"
    both_fire_blue = all(
        t in {f["type"] for f in blue_rep["findings"]} for t in KEEP)
    assert both_fire_blue, "BLUE twin must still fire BOTH classes"

    out = {
        "mode": "BLUE (post-change: CR-01 proven on RED twin, silent on BLUE)",
        "red_twin": {
            "finding_types": sorted({f["type"]
                                     for f in red_rep["findings"]}),
            "chains_reported": len(_chains_of(red_rep)),
            "cr01_proof_steps": cr01_red[0]["combined_proof"]["steps"],
            "elevation_oracle": cr01_red[0]["combined_proof"]["elevation_oracle"],
            "verdict": cr01_red[0]["combined_proof"]["verdict"],
            "narrative_finding_links": [
                {"step": st["step"], "finding_id": st["finding_id"]}
                for st in cr01_red[0]["narrative"]],
        },
        "blue_twin": {
            "finding_types": sorted({f["type"]
                                     for f in blue_rep["findings"]}),
            "both_classes_fire_independently": both_fire_blue,
            "chains_reported": len(_chains_of(blue_rep)),
            "cr01_reported": False,
            "verdict": ("same two vulnerability CLASSES, escalation link "
                        "BROKEN (the admin function returns no credential "
                        "material) — NO chain reported. Two highs are not "
                        "a chain; the precondition, not the severities, "
                        "decides"),
        },
        "rule_catalog": [
            {"id": "CR-01-credential-feeding",
             "pair": ["bfla", "jwt_signature_not_enforced"],
             "precondition": ("the BFLA function's response, executed with "
                              "the low-privilege session, returns credential "
                              "material the CWE-347 endpoint accepts"),
             "proof_kind": "live combined proof (3 bounded requests, "
                           "elevation oracle over HTTP)"},
            {"id": "CR-02-shared-surface-entry",
             "pair": ["shadow_api_endpoint|zombie_api_endpoint",
                      "<any exploitable class>"],
             "precondition": ("the undocumented surface IS the same "
                              "normalized endpoint another family proved "
                              "exploitable (pure data join)"),
             "proof_kind": "data join between the two findings' own evidence"},
        ],
        "deferred": {
            "rule": "authenticated-flow XSS via a separate authz bypass "
                    "(the order's archetype (b))",
            "reason": ("in this engine the xss detector's own reachability "
                       "IS the unlock — the pair adds nothing separately "
                       "provable; deferred until a fixture exists where the "
                       "XSS surface is reachable only with a credential the "
                       "scan itself does not hold"),
        },
        "off_by_default": ("detect_chains is inert unless a rule's specific "
                           "pair fires; ordinary scans send ZERO extra "
                           "requests and get no chains"),
    }
    json.dump(out, open(os.path.join(EV, "BLUE.json"), "w"), indent=1,
              ensure_ascii=False)
    print("BLUE evidence written:")
    print(json.dumps({"red_twin_chains": out["red_twin"]["chains_reported"],
                      "blue_twin_chains": out["blue_twin"]["chains_reported"],
                      "oracle": out["red_twin"]["elevation_oracle"]}, indent=1))

    # SHA256SUMS (the established pattern)
    import hashlib
    lines = []
    for dirpath, _, files in os.walk(EV):
        for fn in files:
            if fn == "SHA256SUMS":
                continue
            full = os.path.join(dirpath, fn)
            rrel = os.path.relpath(full, os.path.join(ROOT, "evidence"))
            lines.append(f"{hashlib.sha256(open(full,'rb').read()).hexdigest()}"
                         f"  {rrel}")
    open(os.path.join(EV, "SHA256SUMS"), "w").write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
