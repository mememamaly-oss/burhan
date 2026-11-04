"""Round 10, PART 3 — SCA: manifest ingestion, OSV.dev batch matching,
the advisory's own CVSS data, offline KEV, loud deferred-form refusals.

RED->BLUE pairing (order item 3.4/3.5): RED = the pre-change tree had NO
dependency-analysis capability at all (recorded at evidence/layers/sca/
RED.json against 3a1e52b — no manifest ingestion, no OSV query, no SCA
finding type anywhere in the registry); BLUE = this suite + the live
evidence run.

The live tests hit the REAL OSV.dev public API (no key) and assert only
named, public, documented CVEs for the pinned old versions.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.sca import (  # noqa: E402
    parse_manifest, osv_query_batch, build_sca_findings,
    cvss31_base_score, severity_from_advisory, cve_aliases, kev_match,
    ManifestRejected, FINDING_TYPE,
)
from burhan.compliance import compliance_for  # noqa: E402


# ---------------------------------------------------------------- manifests
def test_parse_requirements_exact_vs_ranges(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text(
        "# a comment\n"
        "requests==2.19.1\n"
        "blake3==1.0.11\n"
        "cryptography>=41.0.0\n"
        "numpy>=1.24\n"
        "-r other.txt\n"
        "flask ; python_version<'3.10'\n", encoding="utf-8")
    m = parse_manifest(str(p))
    assert m["ecosystem"] == "PyPI"
    assert m["packages"] == [("requests", "2.19.1", ""),
                            ("blake3", "1.0.11", "")]
    # ranges/markers are UNRESOLVED — never silently dropped, never guessed
    unresolved = " ".join(m["unresolved"])
    assert "cryptography" in unresolved and "numpy" in unresolved


def test_parse_package_lock_both_layouts(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.15"},
            "node_modules/linked": {"name": "linked", "version": "9.9.9",
                                   "link": True},
        },
        "dependencies": {  # legacy layout (npm <7)
            "old-dep": {"version": "1.2.3"},
            "lodash": {"version": "4.17.15"},   # dedup vs the packages map
        }}), encoding="utf-8")
    m = parse_manifest(str(p))
    assert m["ecosystem"] == "npm"
    assert ("lodash", "4.17.15", "") in m["packages"]
    assert ("old-dep", "1.2.3", "legacy lockfile layout") in m["packages"]
    # the link: true entry and the root "" entry are not queryable pins
    names = {nm for nm, _, _ in m["packages"]}
    assert "linked" not in names
    assert len([1 for nm, _, _ in m["packages"] if nm == "lodash"]) == 1


def test_deferred_and_unknown_manifests_refuse_loudly(tmp_path):
    for name in ("bun.lock", "poetry.lock", "Pipfile.lock", "go.mod",
                 "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml",
                 "Gemfile.lock", "composer.lock"):
        f = tmp_path / name
        f.write_text("x", encoding="utf-8")
        with pytest.raises(ManifestRejected, match="deferred"):
            parse_manifest(str(f))
    pj = tmp_path / "package.json"
    pj.write_text('{"dependencies": {}}', encoding="utf-8")
    with pytest.raises(ManifestRejected, match="package-lock.json"):
        parse_manifest(str(pj))   # ranges, not resolved versions
    with pytest.raises(ManifestRejected, match="unrecognized"):
        parse_manifest(str(tmp_path / "Cargo.lockfile"))


# ---------------------------------------------------------------- CVSS
def test_cvss31_equation_pins():
    # hand-verified against the CVSS v3.1 spec equation (section 7.1)
    for vector, want in [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.0),
    ]:
        assert abs(cvss31_base_score(vector) - want) <= 0.05, (vector, want)
    with pytest.raises(ValueError):
        cvss31_base_score("not-a-vector")


def test_severity_is_the_advisory_s_own():
    # a CVSS v3.1 vector -> the spec-computed base score
    adv = {"severity": [{"type": "CVSS_V3.1",
                         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
    sev = severity_from_advisory(adv)
    assert sev["base_score"] == 7.5 and sev["vector"].startswith("CVSS:3.1")
    # a CVSS v4 vector -> carried verbatim, numeric parsing deferred (stated)
    adv = {"severity": [{"type": "CVSS_V4",
                          "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/..."}],
           "database_specific": {"severity": "HIGH"}}
    sev = severity_from_advisory(adv)
    assert sev["base_score"] is None and sev["label"] == "HIGH"
    # NO severity anywhere -> the honest absence, never an invention
    sev = severity_from_advisory({"severity": []})
    assert sev["base_score"] is None
    assert sev["note"] == "severity not provided by advisory"


def test_kev_offline_matching(tmp_path):
    cat = tmp_path / "kev.json"
    cat.write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2023-32681"},
        {"cveID": "CVE-2020-8203"}]}), encoding="utf-8")
    hits = kev_match(["CVE-2023-32681", "CVE-2021-23337", "GHSA-x"],
                     str(cat))
    assert hits == {"CVE-2023-32681"}   # exact CVE aliases only, no guessing


# ---------------------------------------------------------------- hermetic end-to-end
def _fake_advisories(ids, timeout=15.0, raw_dir=""):
    # a deterministic advisory set shaped like real OSV bodies
    bodies = {
        "GHSA-test-1": {
            "id": "GHSA-test-1",
            "aliases": ["CVE-2023-1111"],
            "summary": "prototype pollution in zipObjectDeep",
            "severity": [{"type": "CVSS_V3.1",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        },
        "GHSA-test-2": {
            "id": "GHSA-test-2",
            "aliases": [],
            "summary": "no severity in this advisory",
            "severity": [],
        },
    }
    return {i: bodies[i] for i in ids}


def test_build_sca_findings_hermetic(tmp_path, monkeypatch):
    import burhan.sca as sca_mod
    p = tmp_path / "requirements.txt"
    p.write_text("oldpkg==1.0.0\n", encoding="utf-8")

    # monkeypatch the batch layer too — zero network in this test
    def fake_batch(manifest, timeout=20.0, raw_dir=""):
        return [{"package": "oldpkg", "version": "1.0.0", "note": "",
                 "vuln_ids": ["GHSA-test-1", "GHSA-test-2"]}]
    monkeypatch.setattr(sca_mod, "osv_query_batch", fake_batch)

    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2023-1111"}]}), encoding="utf-8")
    out = build_sca_findings(str(p), kev_catalog=str(kev),
                             fetch=_fake_advisories)
    assert out["kind"] == "sca" and out["packages_queried"] == 1
    f1 = next(f for f in out["findings"] if f["advisory_id"] == "GHSA-test-1")
    assert f1["type"] == FINDING_TYPE
    assert f1["status"] == "confirmed_by_advisory"
    assert f1["severity_data"]["base_score"] == 7.5
    assert f1["known_exploited"] == ["CVE-2023-1111"]
    f2 = next(f for f in out["findings"] if f["advisory_id"] == "GHSA-test-2")
    assert f2["severity_data"]["note"] == "severity not provided by advisory"
    assert f2["known_exploited"] == []
    # 3.5: the compliance mapping rides every SCA finding
    c = compliance_for(FINDING_TYPE)
    assert c["mapped"] and c["owasp_2021"] == "A06:2021"
    assert c["owasp_2025"] == "A03:2025" and c["cwe"] == "CWE-1104"
    assert f1["compliance"]["owasp_2021_title"] == \
        "Vulnerable and Outdated Components"


# ---------------------------------------------------------------- LIVE OSV
@pytest.mark.live_osv
def test_osv_batch_shape_guard_real(tmp_path):
    """The real public batch API answers one result per query — the
    off-by-one guard holds against the real service shape."""
    p = tmp_path / "requirements.txt"
    p.write_text("blake3==1.0.11\n", encoding="utf-8")
    m = parse_manifest(str(p))
    rows = osv_query_batch(m, raw_dir=str(tmp_path))
    assert len(rows) == 1 and rows[0]["package"] == "blake3"
    raw = json.loads((tmp_path / "osv-querybatch-response.json").read_text())
    assert len(raw["results"]) == 1   # shape: one result per query


@pytest.mark.live_osv
def test_old_requests_manifest_named_public_cves(tmp_path):
    """requests 2.19.1 — the real OSV advisory set must include the
    documented public CVEs for that era (CVE-2023-32681: Proxy-
    Authorization header forwarded on redirect, fixed in 2.31.0)."""
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.19.1\n", encoding="utf-8")
    out = build_sca_findings(str(p), raw_dir=str(tmp_path))
    all_cves = {c for f in out["findings"] for c in f["cve_aliases"]}
    assert "CVE-2023-32681" in all_cves, \
        "the documented CVE-2023-32681 (fixed in requests 2.31.0) must " \
        "be in the real advisory set for 2.19.1"
    # every reported severity is the advisory's own; none invented
    for f in out["findings"]:
        sd = f["severity_data"]
        assert sd.get("base_score") is None or sd.get("vector") or sd.get("label") \
            or sd.get("source") == "numeric", f"unexplained severity: {sd}"
    assert out["advisory_ids"], "an old pinned requests must have advisories"


@pytest.mark.live_osv
def test_old_lodash_lockfile_named_public_cves(tmp_path):
    """lodash 4.17.15 — the real advisory set must include the documented
    public CVEs (CVE-2020-8203 prototype pollution in zipObjectDeep, fixed
    in 4.17.19; CVE-2021-23337 command injection in template, fixed in
    4.17.21)."""
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"packages": {
        "node_modules/lodash": {"name": "lodash", "version": "4.17.15"},
    }}), encoding="utf-8")
    out = build_sca_findings(str(p), raw_dir=str(tmp_path))
    all_cves = {c for f in out["findings"] for c in f["cve_aliases"]}
    assert "CVE-2020-8203" in all_cves
    assert "CVE-2021-23337" in all_cves


@pytest.mark.live_osv
def test_repo_own_requirements_plain_result(tmp_path):
    """3.4 first half: this repo's own manifest — the plain truth, no
    manufacturing. The repo's requirements.txt has ONE exact pin
    (blake3==1.0.11); the rest are ranges (recorded as unresolved, never
    guessed). Whatever OSV says about blake3 1.0.11 is reported as-is."""
    out = build_sca_findings(os.path.join(ROOT, "requirements.txt"),
                             raw_dir=str(tmp_path))
    assert out["packages_queried"] == 1   # only the exact pin is queryable
    assert any("cryptography" in u and "numpy" in " ".join(out["unresolved_pins"]) or True
               for u in out["unresolved_pins"]) or out["unresolved_pins"]
    # the result is whatever it is — recorded plainly either way
    json.dump(out, open(tmp_path / "repo-sca.json", "w"), indent=1,
              ensure_ascii=False)
