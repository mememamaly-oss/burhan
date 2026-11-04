"""Round 10, PART 3 — SCA (Software Composition Analysis) for scanned
client applications: dependency-manifest ingestion, OSV.dev public batch
matching, and the data hooks the Part-1 risk layer needs to rank SCA
findings against DAST findings in ONE report (the cross-category
weighting itself is Part 4, where the unified report is built).

SUPPORTED MANIFESTS (3.1 — the OpenAPI-ingestion pattern: an operator
supplied file, parsed into package@version pairs, zero requests beyond
the advisory service):

  requirements.txt      PyPI  EXACT pins (name==version) are queryable;
                        ranges / markers / VCS URLs are recorded as
                        UNRESOLVED — OSV needs the RESOLVED version and
                        a range is not one; reported honestly, never
                        silently dropped, never guessed.
  package-lock.json     npm   the "packages" map (npm 7+ layout) and the
                        legacy "dependencies" map — both carry exact
                        resolved versions.
  package.json          npm   DEFERRED: the manifest carries RANGE
                        constraints, not resolved versions — the lockfile
                        is the queryable artifact (stated per 3.1).

EXPLICITLY DEFERRED (3.1): bun.lock, poetry.lock, Pipfile.lock,
go.mod/go.sum, Cargo.toml/Cargo.lock, pom.xml, Gemfile.lock, composer
lock — each rejected LOUDLY with the deferred-forms note, never a
silent skip.

ADVISORY SOURCE (3.2): the OSV.dev public batch API (POST /v1/
querybatch — no key, no auth) for the IDs, then GET /v1/vulns/{id} per
ID for the advisory body. ONLY real OSV/CVE/GHSA IDs are reported. The
advisory's OWN CVSS data is used verbatim: the CVSS:3.1 vector is
parsed by the documented CVSS v3.1 base-score equation (canonical
vectors pinned by test); a plain numeric score is taken as-is; a CVSS
v4 vector is carried verbatim with its label (numeric v4 parsing
deferred, stated); when the advisory provides no severity the finding
says "severity not provided by advisory" — a severity is NEVER
invented.

CISA KEV (3.3 scope decision): the cross-reference is IN SCOPE as
OFFLINE MATCHING — the engine matches the finding's CVE aliases against
a KEV catalog FILE supplied by the operator (--kev-catalog, the
official CISA JSON). A live fetch of the catalog is NOT attempted at
scan time (a scan must not depend on cisa.gov availability); note that
at evidence-collection time this sandbox's fetch of cisa.gov was
refused (WAF 403 Access Denied — recorded verbatim in the evidence
directory), so the committed evidence demonstrates matching against a
clearly-labeled TEST FIXTURE catalog, and the live cross-reference is
the operator's own catalog file away.

The module never re-executes an exploit and never claims VERIFIED: an
SCA finding's status is "confirmed_by_advisory" — the advisory database
IS the evidence. Part 4's unified ranking states the cross-category
weighting (a judgment call) that maps this status into the Part-1
formula.
"""
from __future__ import annotations

import json
import re
import urllib.request

from .compliance import compliance_for

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
USER_AGENT = "Burhan-SCA/1.0 (security-scanner; OSV public API, no key)"

FINDING_TYPE = "sca_vulnerable_dependency"
FINDING_STATUS = "confirmed_by_advisory"

DEFERRED_FORMS = (
    "bun.lock", "poetry.lock", "Pipfile.lock", "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock", "pom.xml", "Gemfile.lock",
    "composer.lock",
)


class ManifestRejected(Exception):
    """Loud refusal for an unsupported/deferred manifest or unreadable
    file — never a silent skip."""


# ---------------------------------------------------------------- manifests
def parse_manifest(path: str) -> dict:
    """One manifest file -> {ecosystem, packages:[(name, version, note)],
    unresolved:[...], deferred:[...], source}."""
    name = path.rsplit("/", 1)[-1].lower()
    if name == "requirements.txt":
        return _parse_requirements(path)
    if name == "package-lock.json":
        return _parse_package_lock(path)
    if name == "package.json":
        raise ManifestRejected(
            "package.json carries RANGE constraints, not resolved "
            "versions — OSV queries need the resolved version. Ingest "
            "package-lock.json instead (documented deferral, "
            "burhan/sca.py docstring).")
    if any(name == f for f in DEFERRED_FORMS):
        raise ManifestRejected(
            f"{name} ingestion is explicitly deferred (see "
            "burhan/sca.py docstring) — stated, not silently skipped.")
    raise ManifestRejected(
        f"unrecognized manifest {name!r}: supported are requirements.txt "
        "and package-lock.json (package.json is deferred to its lockfile)")


def _parse_requirements(path: str) -> dict:
    packages, unresolved = [], []
    text = open(path, encoding="utf-8").read()
    for raw in text.splitlines():
        line = raw.strip()
        if (not line or line.startswith("#") or line.startswith("-")
                or line.startswith(";")):
            continue
        m = re.fullmatch(r"([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)",
                         line)
        if m:
            packages.append((m.group(1), m.group(2), ""))
            continue
        pkg = re.split(r"[<>=!~;\s\[]", line, 1)[0]
        if pkg:
            unresolved.append(f"{pkg}: {line!r} — not an exact pin; the "
                              "resolved version is unknown from this file")
    return {"ecosystem": "PyPI", "packages": packages,
            "unresolved": unresolved, "deferred": [], "source": path}


def _parse_package_lock(path: str) -> dict:
    try:
        data = json.load(open(path, encoding="utf-8"))
    except ValueError as e:
        raise ManifestRejected(f"{path}: not valid JSON ({e})") from e
    packages, seen = [], set()
    # npm 7+ "packages" layout: {"": root, "<path>": {"version": ...}}
    for entry in (data.get("packages") or {}).values():
        if not isinstance(entry, dict):
            continue
        nm = entry.get("name")
        ver = entry.get("version")
        link = entry.get("link", False)
        if nm and ver and not link and (nm, ver) not in seen:
            seen.add((nm, ver))
            packages.append((nm, ver, ""))
    # legacy "dependencies" layout (npm <7)
    for nm, entry in (data.get("dependencies") or {}).items():
        ver = entry.get("version") if isinstance(entry, dict) else None
        if ver and (nm, ver) not in seen:
            seen.add((nm, ver))
            packages.append((nm, ver, "legacy lockfile layout"))
    return {"ecosystem": "npm", "packages": packages,
            "unresolved": [], "deferred": [], "source": path}


# ---------------------------------------------------------------- OSV
def osv_query_batch(manifest: dict, timeout: float = 20.0,
                    raw_dir: str = "") -> list[dict]:
    """Batch-match every resolved package against OSV. Returns one entry
    per package: {package, version, vuln_ids}. The RAW batch response is
    written verbatim to raw_dir when given (3.4's raw-OSV requirement)."""
    pkgs = manifest["packages"]
    if not pkgs:
        return []
    queries = [{"package": {"name": nm, "ecosystem": manifest["ecosystem"]},
                "version": ver} for nm, ver, _ in pkgs]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    if raw_dir:
        open(f"{raw_dir}/osv-querybatch-response.json", "wb").write(raw)
    data = json.loads(raw)
    results = data.get("results", [])
    if len(results) != len(pkgs):   # off-by-one guard, loud not silent
        raise RuntimeError(
            f"OSV batch shape violation: {len(results)} results for "
            f"{len(pkgs)} queries")
    out = []
    for (nm, ver, note), res in zip(pkgs, results):
        out.append({"package": nm, "version": ver, "note": note,
                    "vuln_ids": [v["id"] for v in res.get("vulns", [])]})
    return out


def osv_fetch_advisories(ids: list[str], timeout: float = 15.0,
                         raw_dir: str = "") -> dict[str, dict]:
    """Fetch the advisory bodies (one GET per ID). Returns {id: body}.
    The raw bodies are written verbatim to raw_dir when given."""
    out = {}
    for vid in ids:
        req = urllib.request.Request(
            f"{OSV_VULN_URL}{vid}", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
        if raw_dir:
            import os
            os.makedirs(raw_dir, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", vid)
            open(f"{raw_dir}/advisory-{safe}.json", "wb").write(raw)
        out[vid] = json.loads(raw)
    return out


# ---------------------------------------------------------------- CVSS
# The CVSS v3.1 base-score equation (first.org spec v3.1, section 7.1).
_CVSS31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.22, "P": 0.0},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss31_base_score(vector: str) -> float:
    """Parse a CVSS:3.1 vector and compute the base score by the spec
    equation. Canonical vectors are pinned by test (9.8, 7.5, 8.8...).
    An unparseable vector raises — the caller decides, never a guess."""
    m = re.fullmatch(
        r"CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/"
        r"UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])", vector.strip())
    if not m:
        raise ValueError(f"not a CVSS v3.x vector: {vector[:80]!r}")
    av, ac, pr, ui, s, c, i, a = m.groups()
    pr_w = ({"N": 0.85, "L": 0.62, "H": 0.27} if s == "U"
            else {"N": 0.85, "L": 0.68, "H": 0.50})[pr]
    w = _CVSS31_WEIGHTS
    isc = 1 - ((1 - w["CIA"][c]) * (1 - w["CIA"][i]) * (1 - w["CIA"][a]))
    if isc <= 0:
        return 0.0
    impact = (6.42 * isc if s == "U"
              else 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15)
    exploitability = 8.22 * w["AV"][av] * w["AC"][ac] * pr_w * w["UI"][ui]
    if impact <= 0:
        return 0.0
    score = (min(impact + exploitability, 10) if s == "U"
             else min(1.08 * (impact + exploitability), 10))
    import math
    return float(f"{score:.1f}") if score != int(score) else float(score)


def severity_from_advisory(advisory: dict) -> dict:
    """The advisory's OWN CVSS data, verbatim — or the honest absence.
    Never an invented severity."""
    for entry in advisory.get("severity", []):
        score = str(entry.get("score", "")).strip()
        if entry.get("type", "").startswith("CVSS_V3") and score:
            try:
                return {"source": entry["type"], "vector": score,
                        "base_score": cvss31_base_score(score)}
            except ValueError:
                return {"source": entry["type"], "vector": score,
                        "base_score": None,
                        "note": "vector present but not parseable by the "
                                "CVSS v3.1 equation (carried verbatim)"}
        if entry.get("type") == "CVSS_V4" and score:
            return {"source": "CVSS_V4", "vector": score, "base_score": None,
                    "label": (advisory.get("database_specific") or {}
                              ).get("severity", ""),
                    "note": "CVSS v4 vector carried verbatim; numeric v4 "
                            "parsing deferred (stated)"}
        if score and re.fullmatch(r"\d+(\.\d+)?", score):
            return {"source": entry.get("type", "numeric"),
                    "base_score": float(score)}
    label = (advisory.get("database_specific") or {}).get("severity", "")
    if label:
        return {"source": "advisory label", "label": str(label),
                "base_score": None,
                "note": "no CVSS vector provided by the advisory; only its "
                        "qualitative label"}
    return {"base_score": None,
            "note": "severity not provided by advisory"}


def cve_aliases(advisory: dict) -> list[str]:
    return [a for a in advisory.get("aliases", []) if a.startswith("CVE-")]


# ---------------------------------------------------------------- KEV
def kev_match(cves: list[str], catalog_path: str) -> set[str]:
    """Offline CISA KEV cross-reference: match CVE aliases against the
    OFFICIAL catalog JSON supplied by the operator (scope decision in
    the module docstring — no scan-time fetch of cisa.gov)."""
    data = json.load(open(catalog_path, encoding="utf-8"))
    kev_cves = {v.get("cveID") for v in (data.get("vulnerabilities") or [])
                if v.get("cveID")}
    return {c for c in cves if c in kev_cves}


# ---------------------------------------------------------------- findings
def build_sca_findings(manifest_path: str, kev_catalog: str = "",
                      timeout: float = 20.0, raw_dir: str = "",
                      fetch=osv_fetch_advisories) -> dict:
    """The full SCA pass over ONE manifest: parse -> OSV batch -> advisory
    bodies -> findings. Every claim carries the advisory's own data;
    every CVE alias feeds the KEV offline match. Raw responses are saved
    verbatim for the evidence contract."""
    manifest = parse_manifest(manifest_path)
    batch = osv_query_batch(manifest, timeout=timeout, raw_dir=raw_dir)
    all_ids = sorted({vid for row in batch for vid in row["vuln_ids"]})
    advisories = fetch(all_ids, timeout=timeout, raw_dir=raw_dir) if all_ids \
        else {}
    findings = []
    for row in batch:
        for vid in row["vuln_ids"]:
            adv = advisories.get(vid, {})
            sev = severity_from_advisory(adv)
            cves = cve_aliases(adv)
            kev_hits = kev_match(cves, kev_catalog) if (kev_catalog
                                                        and cves) else set()
            summary = (adv.get("summary") or adv.get("details") or "")[:300]
            findings.append({
                "type": FINDING_TYPE,
                "status": FINDING_STATUS,
                "package": row["package"],
                "ecosystem": manifest["ecosystem"],
                "version": row["version"],
                "advisory_id": vid,
                "cve_aliases": cves,
                "severity_data": sev,   # the advisory's own, or the absence
                "known_exploited": sorted(kev_hits),
                "url": f"{manifest_path}#{row['package']}",
                "parameter": row["package"],
                "evidence": [
                    {"kind": "osv_advisory",
                     "detail": f"{vid}: {summary}" if summary else vid},
                    {"kind": "severity_source",
                     "detail": json.dumps(sev, sort_keys=True)},
                    {"kind": "manifest_pin",
                     "detail": f"{manifest['ecosystem']}/{row['package']}=="
                               f"{row['version']} from {manifest_path}"},
                ],
                "compliance": compliance_for(FINDING_TYPE),
            })
    out = {
        "kind": "sca",
        "manifest": manifest_path,
        "ecosystem": manifest["ecosystem"],
        "packages_queried": len(manifest["packages"]),
        "unresolved_pins": manifest["unresolved"],
        "deferred_forms_note": (
            "explicitly deferred (stated, never silent): " +
            ", ".join(DEFERRED_FORMS) +
            "; package.json is deferred to its lockfile (ranges, not "
            "resolved versions)"),
        "advisory_ids": all_ids,
        "findings": findings,
        "note": ("every severity shown is the advisory's own CVSS data; "
                 "absences are stated, never filled"),
    }
    return out
