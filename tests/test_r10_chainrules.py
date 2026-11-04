"""Round 10, PART 2 — attack-path chaining: the CR-01/CR-02 rules,
the OFF-by-default gating, and the RED/BLUE twin pair (order 2.3/2.4).

RED  (recorded at evidence/layers/attack-path-chaining/RED.json against
      the pre-change tree): the same chainapp RED-twin scan produced BOTH
      findings — bfla and jwt_signature_not_enforced — with NO chain
      anywhere: no chainrules module, no attack_chains key; the report
      could not express that one finding feeds the other.

BLUE (this suite): the same scan reports the chain — WITH the combined
      proof (the admin credential harvested from finding A's own
      response, signature corrupted per finding B's mechanism, accepted
      AS ADMIN over HTTP). The BLUE TWIN of the fixture proves the
      discrimination: same two classes, broken escalation link -> NO
      chain reported. Two highs are not a chain.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.chainrules import (  # noqa: E402
    detect_chains, prove_credential_feeding, _corrupt_signature,
    chains_summary,
)
from burhan.prioritize import normalize_endpoint  # noqa: E402


# ---------------------------------------------------------------- hermetic
def test_corrupt_signature_flips_one_mid_char():
    tok = "h.p.abcdefabcdef1234"
    bad = _corrupt_signature(tok)
    assert bad != tok
    assert bad.split(".")[0] == "h" and bad.split(".")[1] == "p"
    sig = bad.split(".")[2]
    assert len(sig) == len("abcdefabcdef1234")
    assert sig[len(sig) // 2] != "abcdefabcdef1234"[len(sig) // 2]


def test_detect_chains_inert_without_pairs():
    """OFF by default (2.2): findings without a rule's specific pair
    produce ZERO chains — 'any two highs' is never a chain."""
    findings = [
        {"id": "F-1", "type": "sql_injection", "status": "verified",
         "url": "http://t/a", "evidence": []},
        {"id": "F-2", "type": "xss_reflected", "status": "verified",
         "url": "http://t/b", "evidence": []},
    ]
    assert detect_chains(findings, engine=None) == []


def test_cr02_same_endpoint_join_and_discrimination():
    """CR-02: shadow + an exploitable finding on the SAME normalized
    endpoint chains; a DIFFERENT endpoint does not (the precondition is
    the join, not the two severities)."""
    shadow = {"id": "F-s", "type": "shadow_api_endpoint",
              "status": "verified", "url": "http://t/x/api/hidden?z=1",
              "evidence": [{"detail": "shadow"}]}
    same = {"id": "F-x", "type": "sql_injection", "status": "verified",
            "url": "http://t/x/api/hidden?q=2", "evidence": [{"detail": "sqli"}]}
    other = {"id": "F-y", "type": "sql_injection", "status": "verified",
             "url": "http://t/x/api/other?q=2", "evidence": [{"detail": "sqli"}]}
    chains = detect_chains([shadow, same], engine=None)
    assert len(chains) == 1 and chains[0]["rule"] == "CR-02-shared-surface-entry"
    assert chains[0]["findings"] == {"finding_a": "F-s", "finding_b": "F-x"}
    assert all(st.get("finding_id") for st in chains[0]["narrative"])
    # different endpoint -> the precondition fails -> no chain
    assert detect_chains([shadow, other], engine=None) == []
    # passive context classes never chain (banner disclosure on the same
    # endpoint is not an exploitable second family)
    banner = {"id": "F-b", "type": "server_banner_disclosure",
              "status": "verified", "url": "http://t/x/api/hidden",
              "evidence": []}
    assert detect_chains([shadow, banner], engine=None) == []


def test_cr01_requires_engine_for_live_proof():
    """CR-01 never reports on inference: without an engine (no live
    combined proof possible) the pair fires but NO chain is claimed."""
    findings = [
        {"id": "F-b", "type": "bfla", "status": "verified",
         "url": "http://t/api/admin/rotate-keys", "evidence": []},
        {"id": "F-j", "type": "jwt_signature_not_enforced",
         "status": "verified", "url": "http://t/api/account/dashboard",
         "evidence": []},
    ]
    assert detect_chains(findings, engine=None) == []


# ---------------------------------------------------------------- e2e twins
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(twin: str):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "chainapp.py")],
        env={**os.environ, "PORT": str(port), "CHAIN_TWIN": twin},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        if proc.poll() is not None:
            raise RuntimeError("chainapp died during startup")
        try:
            urllib.request.urlopen(base + "/", timeout=2)
            return base, proc
        except Exception:
            time.sleep(0.25)
    proc.terminate()
    raise RuntimeError("chainapp never became reachable")


def _scan(base):
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
                     seed="r10p2e2e" * 8, modern_v2=True, max_requests=6000,
                     browser=False, websocket=False, graphql=False,
                     auth=auth, authz=authz, workflow=False,
                     logic_active=False, openapi=False)
    return BurhanScanner(base, cfg).run()


def test_chainapp_red_twin_reports_the_proven_chain():
    """2.3/2.4 RED side: the pair fires AND the precondition is genuinely
    satisfied — ONE combined proof demonstrates finding A's output
    feeding finding B's exploitation (elevation oracle observed)."""
    base, proc = _spawn("red")
    try:
        rep = _scan(base)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    types = {f["type"] for f in rep["findings"]}
    assert "bfla" in types and "jwt_signature_not_enforced" in types, \
        sorted(types)
    chains = rep.get("attack_chains", [])
    cr01 = [c for c in chains if c["rule"] == "CR-01-credential-feeding"]
    assert cr01, f"the proven chain must be reported: {chains}"
    c = cr01[0]
    # every narrative step links back to its underlying finding id
    fids = {f["id"] for f in rep["findings"]}
    assert all(st["finding_id"] in fids for st in c["narrative"])
    # the combined proof's elevation oracle: accepted AS ADMIN with a
    # corrupted signature — observed live, not asserted
    oracle = c["combined_proof"]["elevation_oracle"]
    assert oracle.get("role") == "admin" and oracle.get("admin_data") is True
    assert len(c["combined_proof"]["steps"]) == 3
    assert chains_summary(chains)["chains_total"] == len(chains)


def test_chainapp_blue_twin_reports_no_chain():
    """2.3 BLUE side: the same two vulnerability CLASSES fire
    independently, but the escalation link is broken (the admin function
    returns NO credential material) — the layer must NOT report a chain.
    Two highs happened to both fire; that is not a chain."""
    base, proc = _spawn("blue")
    try:
        rep = _scan(base)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    types = {f["type"] for f in rep["findings"]}
    assert "bfla" in types, sorted(types)
    assert "jwt_signature_not_enforced" in types, sorted(types)
    cr01 = [c for c in rep.get("attack_chains", [])
            if c["rule"] == "CR-01-credential-feeding"]
    assert not cr01, ("the broken-link twin must yield ZERO chains — "
                      f"got: {rep.get('attack_chains')}")


def test_blue_twin_proof_explains_the_broken_link():
    """The discrimination's anatomy: prove_credential_feeding on the BLUE
    twin must refuse with the SPECIFIC broken-link reason (step2 returned
    no credential material) — the honest non-chain, not a silent one."""
    base, proc = _spawn("blue")
    try:
        from burhan.http_engine import RequestEngine
        from burhan.core import EventBus, ScopeRule
        engine = RequestEngine(ScopeRule(allow_private=True,
                                         allowed_hosts=["127.0.0.1"]),
                               EventBus("t"), timeout=8.0)
        # arm the credentialed harvest endpoint (the AUTH-06 pattern)
        from burhan.core import Endpoint, Parameter, ParamLocation
        engine.auth_harvest_endpoint = Endpoint(
            url=base + "/auth/api/login", method="POST",
            parameters=[Parameter("email", ParamLocation.JSON,
                                  "bob@chainapp.test"),
                        Parameter("password", ParamLocation.JSON,
                                  "bob-pass-123")])
        proof, why_not = prove_credential_feeding(
            engine,
            {"url": base + "/api/admin/rotate-keys"},
            {"url": base + "/api/account/dashboard"})
        assert proof is None
        assert "NO credential material" in why_not, why_not
    finally:
        proc.terminate()
        proc.wait(timeout=10)


