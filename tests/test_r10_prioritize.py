"""Round 10, PART 1 — risk prioritization: stable identity, cross-run
lifecycle, stated score. RED->BLUE pairing per the order:

RED (the pre-change behavior, recorded at evidence/layers/
risk-prioritization/RED.json against 3a1e52b): findings were a flat
list — no identity, no lifecycle, no score — and the only cross-run
primitive, Store.delta(), classified the RE-BROKEN finding as "new"
(a count-level diff that cannot tell a regression from a fresh vuln).

BLUE (this suite): the same three-scan sequence against the same
fixture now classifies by IDENTITY — vulnerable -> NEW, partially
fixed -> FIXED (coverage-gated), re-broken -> REGRESSED — with the
stated risk score and its components on every finding.
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

from burhan.prioritize import (  # noqa: E402
    NEW, RECURRING, FIXED, REGRESSED,
    finding_identity, identity_of_finding, normalize_endpoint,
    next_lifecycle, resolve_lifecycle, risk_score, risk_ranked,
    covered_endpoints, apply_prioritization,
)
from burhan.store import Store  # noqa: E402


# ---------------------------------------------------------------- identity
def test_identity_stable_across_response_changes():
    """The identity hashes detector+endpoint+parameter ONLY — a new query
    string, a casing change in the host, or a different response body
    must not move it (the lifecycle follows the vulnerability, not the
    bytes around it)."""
    a = finding_identity("xss_reflected",
                         "http://127.0.0.1:8080/vuln/xss.php?q=<probe-1>", "q")
    b = finding_identity("xss_reflected",
                         "http://127.0.0.1:8080/vuln/xss.php?q=totally-different",
                         "q")
    c = finding_identity("xss_reflected",
                         "HTTP://127.0.0.1:8080/vuln/xss.php", "q")
    assert a == b == c
    assert len(a) == 16


def test_identity_separates_real_differences():
    """Different detector, endpoint, or parameter = different identity."""
    base = finding_identity("xss_reflected", "http://h:80/vuln/xss.php", "q")
    assert finding_identity("xss_dom", "http://h:80/vuln/xss.php", "q") != base
    assert finding_identity("xss_reflected", "http://h:80/vuln/other.php", "q") != base
    assert finding_identity("xss_reflected", "http://h:80/vuln/xss.php", "s") != base
    # the port is part of the surface
    assert finding_identity("xss_reflected", "http://h:81/vuln/xss.php", "q") != base


def test_identity_block_carries_its_basis():
    f = {"type": "xss_reflected", "url": "http://H:8080/vuln/xss.php?x=1",
         "parameter": "q", "detector": ""}
    block = identity_of_finding(f)
    assert block["identity"] == finding_identity("xss_reflected",
                                                "http://H:8080/vuln/xss.php?x=1", "q")
    assert block["identity_basis"]["endpoint"] == "http://h:8080/vuln/xss.php"
    assert block["identity_basis"]["parameter"] == "q"


def test_normalize_endpoint():
    assert normalize_endpoint("http://Example.COM:8080/a/b?x=1#frag") == \
        "http://example.com:8080/a/b"
    assert normalize_endpoint("") == ""


# ---------------------------------------------------------------- lifecycle
def test_next_lifecycle_truth_table():
    # (seen_ever, in_previous_run, latest_state) -> state
    assert next_lifecycle("i1", False, False, "") == NEW
    assert next_lifecycle("i2", True, True, RECURRING) == RECURRING
    assert next_lifecycle("i3", True, True, FIXED) == RECURRING   # present last run
    assert next_lifecycle("i4", True, False, FIXED) == REGRESSED  # the fix came undone
    assert next_lifecycle("i5", True, False, RECURRING) == RECURRING  # seen, no fix between


def test_resolve_lifecycle_coverage_gate():
    """An absence is FIXED only when the endpoint was re-tested this run;
    an untested absence is reported as such — never a silent negative."""
    hist = {"ever_seen": {"i1", "i2"},
            "latest_state": {"i1": RECURRING, "i2": RECURRING},
            "prev_run_present": {"i1": "http://h/e1", "i2": "http://h/e2"}}
    covered = {"http://h/e1", "http://h/other"}
    current = [{"id": "F-1", "identity": "i1",
                "identity_basis": {"endpoint": "http://h/e1"}}]
    res = resolve_lifecycle(hist, current, covered)
    assert res["per_finding"]["F-1"] == RECURRING
    assert res["fixed"] == {}                      # i2's endpoint NOT covered
    assert res["untested_absences"] == ["i2"]
    res2 = resolve_lifecycle(hist, current, {"http://h/e1", "http://h/e2"})
    assert res2["fixed"] == {"i2": "http://h/e2"}
    assert res2["untested_absences"] == []


def test_covered_endpoints_from_journal():
    rep = {"stats": {"request_journal": {
        "r1": {"request": {"url": "http://h:80/a?x=1"}},
        "r2": {"request": {"url": "http://h:80/b"}},
    }}}
    assert covered_endpoints(rep) == {"http://h:80/a", "http://h:80/b"}


# ---------------------------------------------------------------- scoring
def _f(status="verified", type_="xss_reflected", authz=""):
    return {"status": status, "type": type_, "authz_context": authz,
            "verification": {"passed": status == "verified"}}


def test_score_pins_exact_values():
    # verified XSS, anonymous-reachable, NEW:
    # 100 * 1.0 * (0.40*1.0 + 0.35*(7/9) + 0.25*0.8) = 87.22 -> 87
    assert risk_score(_f(), NEW)["risk_score"] == 87
    # REGRESSED outranks NEW at equal technical weight
    assert risk_score(_f(), REGRESSED)["risk_score"] == 92
    # auth-gated exposure lowers the score (0.40*0.70)
    assert risk_score(_f(authz="admin>victim"), NEW)["risk_score"] == 75
    # an unverified finding can never outrank a verified one
    assert risk_score(_f(status="candidate"), REGRESSED)["risk_score"] == 28
    # rejected = excluded from ranking entirely
    assert risk_score(_f(status="rejected"), REGRESSED)["risk_score"] == 0
    # unmapped class -> documented default 3/9, never a guess
    assert risk_score(_f(type_="never_heard_of_it"), NEW)["risk_score"] == 72


def test_score_components_are_shown():
    out = risk_score(_f(), REGRESSED)
    comps = out["risk_components"]
    assert comps["verification"] == {"weight": 1.0, "value": "verified"}
    assert comps["exposure"] == {"weight": 1.0, "auth_gated": False}
    assert comps["technical"]["class"] == "xss_reflected"
    assert comps["lifecycle"] == {"weight": 1.0, "state": REGRESSED}


def test_risk_ranked_orders_and_skips_fixed():
    fs = [
        {"id": "F-a", "identity": "i-a", "type": "xss_reflected",
         "severity": "high", "lifecycle": NEW, "risk_score": 87,
         "risk_components": {}, "url": "http://h/a", "parameter": "q"},
        {"id": "F-b", "identity": "i-b", "type": "sql_injection",
         "severity": "high", "lifecycle": REGRESSED, "risk_score": 95,
         "risk_components": {}, "url": "http://h/b", "parameter": "id"},
        {"id": "F-c", "identity": "i-c", "type": "path_traversal",
         "severity": "high", "lifecycle": FIXED, "risk_score": 90,
         "risk_components": {}, "url": "http://h/c", "parameter": "f"},
    ]
    ranked = risk_ranked(fs)
    assert [r["id"] for r in ranked] == ["F-b", "F-a"]   # score desc, FIXED skipped


# ---------------------------------------------------------------- store
def test_store_lifecycle_log_roundtrip(tmp_path):
    st = Store(str(tmp_path / "s.db"))
    rep1 = {"run_id": "r1", "target": "http://t", "findings": [
        {"id": "F-1", "type": "xss_reflected", "url": "http://t/vuln/xss.php",
         "parameter": "q", "status": "verified", "identity": "i1",
         "identity_basis": {"endpoint": "http://t/vuln/xss.php"},
         "lifecycle": NEW, "risk_score": 87, "risk_components": {"x": 1},
         "evidence": [], "verification": {}}]}
    rep1["prioritization"] = {"resolution": {
        "present_states": {"i1": NEW}, "fixed": {}, "untested_absences": []}}
    st.save_run(rep1)
    rep2 = {"run_id": "r2", "target": "http://t", "findings": []}
    rep2["prioritization"] = {"resolution": {
        "present_states": {}, "fixed": {"i1": "http://t/vuln/xss.php"},
        "untested_absences": []}}
    st.save_run(rep2)
    hist = st.lifecycle_history("http://t")
    assert "i1" in hist["ever_seen"]
    assert hist["latest_state"]["i1"] == FIXED
    # the lifecycle log — not the findings rows — carries the FIXED trail
    import sqlite3
    with sqlite3.connect(st.path) as c:
        states = {r[0]: r[1] for r in c.execute(
            "SELECT identity, state FROM lifecycle_log WHERE run_id='r2'")}
    assert states == {"i1": "FIXED"}
    # _finding_row returns the new fields
    row = st.list_findings(run_id="r1")[0]
    assert row["identity"] == "i1" and row["lifecycle"] == NEW
    assert row["risk_score"] == 87 and row["risk_components"] == {"x": 1}


def test_store_legacy_report_still_saves(tmp_path):
    """Pre-round-10 reports (no prioritization block) persist exactly as
    before — the migration is additive, old stores and old callers keep
    working, new columns read as NULL."""
    st = Store(str(tmp_path / "s.db"))
    n = st.save_run({"run_id": "legacy-1", "target": "http://t",
                     "findings": [{"id": "F-9", "type": "sql_injection",
                                   "url": "http://t/x", "parameter": "id",
                                   "status": "verified",
                                   "evidence": [], "verification": {}}]})
    assert n == 1
    row = st.list_findings(run_id="legacy-1")[0]
    assert row["identity"] is None and row["lifecycle"] is None
    assert row["risk_score"] is None


def test_apply_prioritization_end_to_end(tmp_path):
    """The wiring point: annotate identities, resolve against the store,
    score, and embed the ranked view — all BEFORE the audit signature
    (which rep consumers apply afterwards)."""
    st = Store(str(tmp_path / "s.db"))
    rep = {"run_id": "rr1", "target": "http://t", "stats": {"authenticated": False},
           "findings": [
               {"id": "F-1", "type": "xss_reflected", "status": "verified",
                "url": "http://t/vuln/xss.php?q=1", "parameter": "q",
                "evidence": [], "verification": {"passed": True}}]}
    apply_prioritization(rep, store_path=str(tmp_path / "s.db"))
    f = rep["findings"][0]
    assert f["identity"] == finding_identity("xss_reflected",
                                             "http://t/vuln/xss.php?q=1", "q")
    assert f["lifecycle"] == NEW and f["risk_score"] == 87
    assert rep["prioritization"]["risk_ranked"][0]["id"] == "F-1"
    assert rep["prioritization"]["lifecycle_summary"]["new"] == 1
    st.save_run(rep)     # records the resolution in the lifecycle log
    # a second identical run against the same store -> RECURRING
    rep2 = {"run_id": "rr2", "target": "http://t", "stats": {},
            "findings": [dict(rep["findings"][0], lifecycle=None)]}
    rep2["findings"][0].pop("risk_score", None)
    rep2["findings"][0].pop("risk_components", None)
    apply_prioritization(rep2, store_path=str(tmp_path / "s.db"))
    assert rep2["findings"][0]["lifecycle"] == RECURRING


# ------------------------------------------------- the REAL three-scan test
VULN_LINE = "return self._send(200, HEADER_TMPL.format(body=f\"<div>You searched for '{qv}'</div>\"))"
SAFE_LINE = ("return self._send(200, HEADER_TMPL.format(body=f\"<div>You searched for '"
             "{qv.replace('<', '\u0026lt;').replace('>', '\u0026gt;')}'</div>\"))")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Variant:
    """One live fixture variant on a FIXED port — the same target URL for
    all three scans, so the lifecycle is keyed to the same surface."""

    def __init__(self, kind, port, workdir):
        self.port = port
        os.makedirs(workdir, exist_ok=True)
        src = os.path.join(ROOT, "fixtures", "vulnapp.py")
        text = open(src, encoding="utf-8").read()
        if kind == "patched":
            assert VULN_LINE in text, "vulnerable line drifted — update the pin"
            text = text.replace(VULN_LINE, SAFE_LINE)
        self.file = os.path.join(workdir, f"vulnapp-{kind}.py")
        open(self.file, "w", encoding="utf-8").write(text)

    def start(self):
        self.proc = subprocess.Popen(
            [sys.executable, self.file],
            env={"PORT": str(self.port), "PATH": "/usr/bin:/bin"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = f"http://127.0.0.1:{self.port}"
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/", timeout=2)
                return base
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("fixture did not come up")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        time.sleep(0.5)   # let the port release before the next variant binds


def _scan(base, seed, db_path):
    from burhan.orchestrator import ScanConfig, BurhanScanner
    cfg = ScanConfig(allow_private=True, max_pages=25, timeout=8.0,
                     seed=seed, max_requests=2500, browser=False,
                     workflow=False, logic_active=False, race=False,
                     symbolic=False, websocket=False, graphql=False,
                     modern=False, prioritize_store=db_path)
    return BurhanScanner(base, cfg).run()


def test_three_scans_lifecycle_real(tmp_path):
    """1.3, the RED->BLUE core: three REAL engine scans of the same live
    target across deliberately different states. The xss_reflected finding
    on /vuln/xss.php must walk NEW -> FIXED -> REGRESSED, verified by
    IDENTITY MATCHING (the same identity hash across scans), not counts.
    (RED, the pre-change behavior, is recorded at evidence/layers/
    risk-prioritization/RED.json: flat list, no identity, and Store.delta
    calling this same re-broken finding 'new'.)"""
    db = str(tmp_path / "lifecycle.db")
    workdir = str(tmp_path / "variants")
    port = _free_port()
    results = []
    try:
        for variant, seed in (("vulnerable", "r10-runA" * 8),
                              ("patched", "r10-runB" * 8),
                              ("rebroken", "r10-runC" * 8)):
            v = _Variant("vulnerable" if variant != "patched" else "patched",
                         port, workdir)
            base = v.start()
            rep = _scan(base, seed, db)
            v.stop()
            Store(db).save_run(rep)
            xss = [f for f in rep["findings"]
                   if f["type"] == "xss_reflected"
                   and f["url"].split("?")[0].endswith("/vuln/xss.php")]
            results.append({"variant": variant, "run_id": rep["run_id"],
                             "xss": xss, "rep": rep})

        # scan 1: vulnerable -> NEW, identity + score + components attached
        r1 = results[0]
        assert r1["xss"], "scan 1 must find the vulnerable xss_reflected"
        f1 = r1["xss"][0]
        assert f1["lifecycle"] == NEW
        assert f1["risk_score"] == 87
        ident1 = f1["identity"]

        # scan 2: partially fixed -> the finding is ABSENT and its identity
        # is resolved FIXED (the endpoint was re-tested — coverage gate)
        r2 = results[1]
        assert not r2["xss"], "the patched variant must not yield the finding"
        resolution = r2["rep"]["prioritization"]["resolution"]
        assert ident1 in resolution["fixed"], \
            "the re-tested absence must resolve FIXED, not silently vanish"
        assert ident1 not in resolution["untested_absences"]

        # scan 3: re-broken -> REGRESSED, SAME identity (identity matching,
        # not count comparison)
        r3 = results[2]
        assert r3["xss"], "the re-broken variant must yield the finding again"
        f3 = r3["xss"][0]
        assert f3["identity"] == ident1
        assert f3["lifecycle"] == REGRESSED
        # REGRESSED outranks NEW: same class, same exposure, L 1.0 > 0.8
        assert f3["risk_score"] > f1["risk_score"]

        # the store's lifecycle log carries the whole trail
        import sqlite3
        with sqlite3.connect(db) as c:
            trail = list(c.execute(
                "SELECT run_id, state FROM lifecycle_log WHERE identity=? "
                "ORDER BY resolved_at", (ident1,)))
        assert [s for _, s in trail] == [NEW, FIXED, REGRESSED]

        # the ranked view is embedded in the report (1.4)
        ranked = r3["rep"]["prioritization"]["risk_ranked"]
        assert ranked[0]["risk_score"] >= f3["risk_score"]
        assert ranked[0]["risk_components"]["lifecycle"]["state"] == REGRESSED
    finally:
        pass
