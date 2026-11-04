"""Round 10, PART 4 — the unified cross-category report: one ranked list
over DAST + SCA + proven chains, one stated formula, every cross-category
judgment call surfaced. RED->BLUE pairing per the order:

RED (recorded at evidence/layers/unified-report/RED.json against
     23ec690, the pre-change tree): the three categories lived in
     three separate outputs — a scan result with its DAST findings, a
     standalone `sca` result, chains buried in the scan payload — with
     NO command able to rank them together and NO documented judgment
     call anywhere for ranking advisory-confirmed findings against
     re-execution-verified ones.

BLUE (this suite): `burhan unified` ranks all three on the one formula
     with J1 (V=0.85 advisory-confirmed), J2 (advisory-own CVSS for T)
     and J3 (chain components) stated in every output, and the
     cross-run lifecycle resolving for SCA and chain identities too.
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

from burhan.unified import build_unified, chain_identity  # noqa: E402
from burhan.prioritize import NEW, RECURRING, FIXED  # noqa: E402
from burhan.store import Store  # noqa: E402


# ------------------------------------------------------------ judgment calls
def _scan_result():
    return {"run_id": "s1", "target": "http://t:8080",
            "stats": {"authenticated": False}, "findings": [], "attack_chains": []}


def _sca_result(base_score=7.5, manifest="reqs.txt", package="requests"):
    return {"kind": "sca", "manifest": manifest, "findings": [{
        "type": "sca_vulnerable_dependency", "status": "confirmed_by_advisory",
        "package": package, "ecosystem": "PyPI", "version": "2.19.1",
        "advisory_id": "GHSA-J1", "cve_aliases": ["CVE-2023-32681"],
        "known_exploited": [],
        "severity_data": ({"source": "CVSS_V3", "base_score": base_score}
                          if base_score is not None else
                          {"base_score": None, "note": "not provided"}),
        "url": f"{manifest}#{package}", "parameter": package, "evidence": []}]}


def test_judgment_calls_stated_in_every_output():
    out = build_unified(_scan_result(), [_sca_result()])
    ids = [j["id"] for j in out["judgment_calls"]]
    assert ids == ["J1", "J2", "J3"]
    for j in out["judgment_calls"]:
        assert j["call"] and j["why"], "a judgment call without its reason is an opaque number"
    assert "0.85" in out["judgment_calls"][0]["call"]


def test_sca_scores_pin_the_formula():
    """J1+J2 pinned exactly: V=0.85, T=advisory's own 7.5/10, E=1.0, L=NEW
    -> 100*0.85*(0.40*1.0 + 0.35*0.75 + 0.25*0.8) = 73.3125 -> 73.
    No advisory CVSS -> the class default 3/9 -> 61 (never a guess)."""
    out = build_unified(_scan_result(), [_sca_result(7.5)])
    assert out["rows"][0]["risk_score"] == 73
    v = out["rows"][0]["risk_components"]["verification"]
    assert v == {"weight": 0.85, "value": "confirmed_by_advisory"}
    out2 = build_unified(_scan_result(), [_sca_result(None)])
    assert out2["rows"][0]["risk_score"] == 61


def test_dast_scores_reused_verbatim():
    """The unified view never re-scores what the scan already scored."""
    scan = _scan_result()
    scan["findings"] = [{
        "id": "F-1", "type": "xss_reflected", "status": "verified",
        "url": "http://t:8080/vuln/xss.php?q=1", "parameter": "q",
        "identity": "i1", "identity_basis": {"endpoint": "http://t:8080/vuln/xss.php"},
        "lifecycle": NEW, "risk_score": 87,
        "risk_components": {"verification": {"weight": 1.0, "value": "verified"}}}]
    out = build_unified(scan, [])
    row = [r for r in out["rows"] if r["category"] == "dast"][0]
    assert row["risk_score"] == 87 and row["lifecycle"] == NEW


def test_dast_finding_without_score_is_scored_not_dropped():
    """A pre-round-10 result (no identity/lifecycle/score) is scored HERE
    with the same formula — silently dropping it would forge a clean report."""
    scan = _scan_result()
    scan["findings"] = [{"id": "F-9", "type": "xss_reflected",
                         "status": "verified",
                         "url": "http://t:8080/vuln/xss.php?q=1",
                         "parameter": "q", "evidence": []}]
    out = build_unified(scan, [])
    row = [r for r in out["rows"] if r["id"] == "F-9"]
    assert row and row[0]["risk_score"] == 87 and row[0]["lifecycle"] == NEW


def test_chain_j3_components_and_score():
    """J3 pinned: V=1.00 (the chain rides its own proof), E=entry
    finding's exposure, T=max member technical -> for a
    xss_reflected(7/9) + bfla pair entered anonymously:
    100*1.0*(0.40 + 0.35*(7/9) + 0.25*0.8) = 87."""
    scan = _scan_result()
    scan["findings"] = [
        {"id": "F-a", "type": "bfla", "status": "verified",
         "url": "http://t:8080/api/admin/rotate-keys", "parameter": "",
         "identity": "ia", "identity_basis": {"endpoint": "http://t:8080/api/admin/rotate-keys"},
         "lifecycle": NEW, "risk_score": 80, "risk_components": {}},
        {"id": "F-b", "type": "xss_reflected", "status": "verified",
         "url": "http://t:8080/x?q=1", "parameter": "q",
         "identity": "ib", "identity_basis": {"endpoint": "http://t:8080/x"},
         "lifecycle": NEW, "risk_score": 87, "risk_components": {}}]
    scan["attack_chains"] = [{
        "rule": "CR-02-shared-surface-entry", "title": "t",
        "findings": {"finding_a": "F-a", "finding_b": "F-b"},
        "pair": ["bfla", "xss_reflected"], "narrative": [{"step": 1}],
        "verified": True}]
    out = build_unified(scan, [])
    chain_row = [r for r in out["rows"] if r["category"] == "chain"][0]
    assert chain_row["risk_score"] == 87
    comps = chain_row["risk_components"]
    assert comps["verification"]["weight"] == 1.00
    assert comps["technical"]["basis"] == "max of member findings"
    assert comps["exposure"]["basis"] == "entry finding (finding_a)"
    assert chain_row["member_findings"] == {"finding_a": "F-a", "finding_b": "F-b"}
    # the chain's identity follows its members, not its narrative text
    assert chain_row["identity"] == chain_identity(
        "CR-02-shared-surface-entry", "ia", "ib")


def test_ranking_is_one_list_across_categories():
    """All three categories on ONE deterministic list: score desc, ties
    broken by identity then id — byte-identical for identical inputs."""
    scan = _scan_result()
    scan["findings"] = [{"id": "F-1", "type": "sql_injection", "status": "verified",
                         "url": "http://t:8080/s", "parameter": "",
                         "identity": "i9", "identity_basis": {"endpoint": "http://t:8080/s"},
                         "lifecycle": NEW, "risk_score": 95, "risk_components": {}}]
    out = build_unified(scan, [_sca_result()])
    assert [r["category"] for r in out["rows"]] == ["dast", "sca"]
    assert out["counts_by_category"] == {"dast": 1, "sca": 1, "chain": 0}
    out2 = build_unified(json.loads(json.dumps(scan)),
                         [json.loads(json.dumps(_sca_result()))])
    assert json.dumps(out["rows"]) == json.dumps(out2["rows"])


# ------------------------------------------------------------ sca lifecycle
def test_sca_lifecycle_fixed_only_on_requery(tmp_path):
    """The SCA lifecycle is honest: a previously-vulnerable package is
    FIXED only when the SAME manifest is re-queried (the manifest IS the
    coverage proof); no re-query -> an UNTESTED absence, never a fix."""
    db = str(tmp_path / "s.db")
    st = Store(db)
    run1 = build_unified(_scan_result(), [_sca_result(manifest="reqs.txt")],
                         store=st, run_id="u1")
    assert run1["rows"][0]["lifecycle"] == NEW
    # second pass, same manifest, the finding GONE -> FIXED
    gone = _sca_result(manifest="reqs.txt")
    gone["findings"] = []
    run2 = build_unified(_scan_result(), [gone], store=st, run_id="u2")
    assert run2["counts_by_category"]["sca"] == 0
    # the FIXED trail is in the lifecycle log under the sca target
    import sqlite3
    with sqlite3.connect(db) as c:
        rows = {(r[0], r[1]) for r in c.execute(
            "SELECT run_id, state FROM lifecycle_log WHERE state='FIXED'")}
    assert ("u2", "FIXED") in rows
    # third pass queries a DIFFERENT manifest: the old identity is absent
    # but the old surface was NOT re-tested -> never a FIXED claim
    run3 = build_unified(_scan_result(), [_sca_result(manifest="other.txt")],
                         store=st, run_id="u3")
    with sqlite3.connect(db) as c:
        states = {r[0] for r in c.execute(
            "SELECT state FROM lifecycle_log WHERE run_id='u3'")}
    assert "FIXED" not in states, "an untested absence must never resolve FIXED"


def test_unified_never_writes_findings_rows(tmp_path):
    """The unified command is a VIEW: its lifecycle recording must never
    touch the findings table — a scan's prev-run semantics stay intact."""
    db = str(tmp_path / "s.db")
    st = Store(db)
    build_unified(_scan_result(), [_sca_result()], store=st, run_id="u1")
    assert st.list_findings() == []


def test_lifecycle_log_keeps_targets_separate(tmp_path):
    """The cross-target leak, pinned: one unified pass records SCA rows
    under the sca target AND a chain row under the scan target in the
    SAME run id. The second pass must resolve both RECURRING and the LOG
    must keep each identity under ITS OWN target — never an
    UNTESTED_ABSENCE artifact where a present finding's row belongs, and
    never one target's row silently replacing the other's (the log's PK
    is (run_id, identity) — a cross-target leak here would corrupt both
    histories; the third pass proves the memory survived)."""
    db = str(tmp_path / "s.db")
    st = Store(db)
    scan = _scan_result()
    scan["findings"] = [
        {"id": "F-a", "type": "bfla", "status": "verified",
         "url": "http://t:8080/api/admin/rotate-keys", "parameter": "",
         "identity": "ia", "identity_basis": {"endpoint": "http://t:8080/api/admin/rotate-keys"},
         "lifecycle": NEW, "risk_score": 80, "risk_components": {}},
        {"id": "F-b", "type": "xss_reflected", "status": "verified",
         "url": "http://t:8080/x?q=1", "parameter": "q",
         "identity": "ib", "identity_basis": {"endpoint": "http://t:8080/x"},
         "lifecycle": NEW, "risk_score": 87, "risk_components": {}}]
    scan["attack_chains"] = [{
        "rule": "CR-02-shared-surface-entry", "title": "t",
        "findings": {"finding_a": "F-a", "finding_b": "F-b"},
        "pair": ["bfla", "xss_reflected"], "narrative": [{"step": 1}],
        "verified": True}]
    for i in range(2):   # two passes over the same inputs, one store
        out = build_unified(scan, [_sca_result()], store=st, run_id=f"u{i+1}")
    resolved = [r for r in out["rows"] if r["category"] in ("sca", "chain")]
    assert all(r["lifecycle"] == RECURRING for r in resolved)
    sca_id = [r["identity"] for r in out["rows"]
              if r["category"] == "sca"][0]
    import sqlite3
    with sqlite3.connect(db) as c:
        rows = {(r[0], r[1], r[2]) for r in c.execute(
            "SELECT target, identity, state FROM lifecycle_log")}
    # the SCA identity's rows (one per pass) live ONLY under its own target
    sca_rows = [r for r in rows if r[1] == sca_id]
    assert sca_rows and all(r[0] == "sca:reqs.txt" for r in sca_rows), \
        f"the SCA identity's rows must live ONLY under its own target: {sca_rows}"
    assert "RECURRING" in {r[2] for r in sca_rows}
    # the chain identity's rows live ONLY under the scan's own target
    chain_id = [r for r in out["rows"]
                if r["category"] == "chain"][0]["identity"]
    chain_rows = [r for r in rows if r[1] == chain_id]
    assert chain_rows and all(r[0] == "http://t:8080" for r in chain_rows), \
        f"the chain identity's rows must live ONLY under the scan target: {chain_rows}"
    # no cross-target artifact anywhere in the log
    assert not any("UNTESTED_ABSENCE" in r[2] for r in rows), rows
    # a third pass still sees the SCA memory under the sca target
    out3 = build_unified(scan, [_sca_result()], store=st, run_id="u3")
    sca_row3 = [r for r in out3["rows"] if r["category"] == "sca"][0]
    assert sca_row3["lifecycle"] == RECURRING


# ------------------------------------------------ the REAL triple-category e2e
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn_chainapp():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "chainapp.py")],
        env={**os.environ, "PORT": str(port), "CHAIN_TWIN": "red"},
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


def _chainapp_scan(base):
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
                     seed="r10p4e2e" * 8, modern_v2=True, max_requests=6000,
                     browser=False, websocket=False, graphql=False,
                     auth=auth, authz=authz, workflow=False,
                     logic_active=False, openapi=False)
    return BurhanScanner(base, cfg).run()


def test_unified_triple_category_real(tmp_path):
    """The order's core: ONE invocation over a REAL chainapp scan (bfla +
    jwt_signature_not_enforced + the proven CR-01 chain) and the REAL
    committed OSV result for requests==2.19.1 — all three categories on
    one ranked list, then a second invocation resolving RECURRING."""
    base, proc = _spawn_chainapp()
    try:
        rep = _chainapp_scan(base)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    types = {f["type"] for f in rep["findings"]}
    assert "bfla" in types and "jwt_signature_not_enforced" in types
    cr01 = [c for c in rep.get("attack_chains", [])
            if c["rule"] == "CR-01-credential-feeding"]
    assert cr01, "the chainapp scan must yield the proven chain"

    scan_path = str(tmp_path / "scan.json")
    with open(scan_path, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1, ensure_ascii=False)
    sca_path = os.path.join(ROOT, "evidence", "layers", "sca",
                            "old-requirements-sca.json")
    db = str(tmp_path / "u.db")
    out1_path = str(tmp_path / "unified1.json")
    out2_path = str(tmp_path / "unified2.json")

    cli = [sys.executable, "-m", "burhan.cli", "unified",
           "--scan", scan_path, "--sca", sca_path,
           "--prioritize-store", db]
    r1 = subprocess.run(cli + ["--out", out1_path],
                        capture_output=True, text=True, cwd=ROOT)
    assert r1.returncode == 0, r1.stderr
    u1 = json.load(open(out1_path, encoding="utf-8"))
    counts = u1["counts_by_category"]
    assert counts["dast"] >= 2 and counts["chain"] == 1 and counts["sca"] >= 1
    # the SCA side is the REAL committed OSV result: requests==2.19.1
    sca_rows = [r for r in u1["rows"] if r["category"] == "sca"]
    assert any("CVE-2023-32681" in (r.get("cve_aliases") or [])
               for r in sca_rows)
    # every SCA row carries the advisory-confirmed verdict + the J1 weight
    for r in sca_rows:
        assert r["risk_components"]["verification"] == \
            {"weight": 0.85, "value": "confirmed_by_advisory"}
    # DAST rows keep their scan-time scores verbatim
    by_id = {f["id"]: f for f in rep["findings"]}
    for r in u1["rows"]:
        if r["category"] == "dast":
            assert r["risk_score"] == by_id[r["id"]]["risk_score"]
    # the chain row links its members and ranks by J3
    chain_row = [r for r in u1["rows"] if r["category"] == "chain"][0]
    fids = set(by_id)
    assert set(chain_row["member_findings"].values()) <= fids
    assert chain_row["risk_components"]["verification"]["weight"] == 1.00
    # first invocation against a fresh store -> every resolved row is NEW
    assert all(r["lifecycle"] == NEW for r in u1["rows"])
    # one ranked list, score-descending
    scores = [r["risk_score"] for r in u1["rows"]]
    assert scores == sorted(scores, reverse=True)
    assert [j["id"] for j in u1["judgment_calls"]] == ["J1", "J2", "J3"]

    # second invocation, same inputs, same store -> SCA + chain rows
    # resolve RECURRING (seen in the first invocation, no FIXED between)
    r2 = subprocess.run(cli + ["--out", out2_path],
                        capture_output=True, text=True, cwd=ROOT)
    assert r2.returncode == 0, r2.stderr
    u2 = json.load(open(out2_path, encoding="utf-8"))
    for cat in ("sca", "chain"):
        rows2 = [r for r in u2["rows"] if r["category"] == cat]
        assert rows2 and all(r["lifecycle"] == RECURRING for r in rows2), \
            f"{cat} rows must resolve RECURRING on the second pass"
