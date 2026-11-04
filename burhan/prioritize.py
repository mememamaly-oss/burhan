"""Round 10, PART 1 — risk prioritization: stable finding identity,
cross-run lifecycle, and a stated, reproducible risk score.

DESIGN (owner order 2026-11-04, part 1):

* Finding identity (1.1) — a stable hash of DETECTOR ID + NORMALIZED
  ENDPOINT + PARAMETER. Deliberately NOT the raw request or the response:
  the same vulnerability re-scanned after a minor response change (a
  timestamp in the page, a new field in the JSON) must keep its identity,
  so lifecycle tracking follows the VULNERABILITY, not the byte stream.
  Normalization: scheme+host lowercased, query string and fragment
  dropped, the path kept verbatim, the parameter name kept verbatim.
  The port is part of the surface (a different port IS a different
  surface) — a re-scan of the same target keeps the same port. This is a
  DIFFERENT identity from the legacy dedup fingerprint (store.py /
  core.py), which includes the HTTP method and evidence kinds for
  same-run dedup; both coexist, each documented at its own definition.

* Lifecycle (1.1) — per (target, identity) across scan runs:
      NEW       first time this target ever produced this identity
      RECURRING seen in the immediately previous run of this target and
                still present
      REGRESSED previously classified FIXED and now present again (a fix
                that came undone)
      FIXED     present in the immediately previous run, absent now, AND
                the endpoint was actually re-tested this run (equivalent
                coverage, from the run's own request journal). An
                absence with NO coverage of that endpoint is NOT a fix —
                it is recorded as an "untested absence" and the previous
                state stands. A silent negative here would be a forged
                FIXED, the exact lie the honesty contract forbids.
  The states live in the EXISTING store (store.db, the same SQLite layer
  the runs/findings already persist to) — no new unsigned data store;
  the identity itself rides the signed per-finding payload.

* Risk score (1.2) — the exact formula, no opaque "AI score":

      score = round(100 * V * (0.40*E + 0.35*T + 0.25*L))

  V — re-execution verdict weight, the strongest signal available, so it
      MULTIPLIES the whole score (an unproven finding can never outrank
      a proven one):
        verified               -> 1.00
        observed anomaly       -> 0.60
        unverified / candidate -> 0.30
        rejected               -> 0.00 (excluded from ranked findings)
  E — exposure: anonymous-reachable 1.00, auth-gated surface 0.70.
      V1 rule, stated with its limit: a finding is auth-gated when its
      authz_context is set (the authorization engine's own role/victim
      record — the only per-finding authentication signal the engine
      journals today). Everything else is treated as anonymous-reachable.
      Per-endpoint auth provenance for every detector is not yet
      journaled per finding; when it is, this rule tightens without
      changing the formula.
  T — technical severity of the vulnerability class:
      RISK_WEIGHTS[type] / 9 (intel.py, the engine's existing per-class
      technical weight table; unmapped types get the documented default
      3/9, never a guess dressed as a measurement).
  L — lifecycle weight: REGRESSED 1.00 > NEW 0.80 > RECURRING 0.60.
      REGRESSED sits ABOVE NEW on the owner's explicit instruction: a
      fix that silently came undone deserves attention before a fresh
      discovery of the same technical weight. FIXED findings are not
      ranked — they are listed as fixed in the report view.
  Every component is stored per finding and SHOWN in the report view:
  a reader sees WHY something ranked where it did, not just a number.

  CROSS-CATEGORY JUDGMENT CALLS (round 10 part 4 — the unified report
  ranks DAST, SCA and chain findings on THIS ONE formula; both calls are
  stated here and echoed in the unified output's judgment_calls block):
    * V(confirmed_by_advisory) = 0.85 — an advisory-confirmed dependency
      finding sits between an observed anomaly and a re-execution-verified
      one (see VERIFICATION_WEIGHTS).
    * T — a finding with the advisory's own numeric CVSS base score uses
      base_score/10 (the advisory's own measurement) instead of the class
      default weight (see technical_component).
"""
from __future__ import annotations

import hashlib
import urllib.parse

# The four lifecycle states of a finding identity across runs of one target.
NEW = "NEW"
RECURRING = "RECURRING"
FIXED = "FIXED"
REGRESSED = "REGRESSED"

LIFECYCLE_STATES = (NEW, RECURRING, FIXED, REGRESSED)

# re-execution verdict weight (V)
VERIFICATION_WEIGHTS = {
    "verified": 1.00,
    "observed_anomaly": 0.60,
    "candidate": 0.30,
    "unverified": 0.30,
    "rejected": 0.00,
    # Round 10 part 4 — cross-category judgment call (stated, not hidden):
    # an SCA finding is CONFIRMED BY THE ADVISORY, not by re-execution on
    # a live target. It sits BETWEEN observed_anomaly (0.60) and verified
    # (1.00): stronger than a mere observation (a public advisory + the
    # exact pinned version is an established fact), weaker than the
    # scanner's own re-execution proof. 0.85 — a judgment call, documented
    # here and surfaced in the unified report's judgment_calls block.
    "confirmed_by_advisory": 0.85,
}

# exposure weight (E)
EXPOSURE_ANONYMOUS = 1.00
EXPOSURE_AUTH_GATED = 0.70

# lifecycle weight (L)
LIFECYCLE_WEIGHTS = {REGRESSED: 1.00, NEW: 0.80, RECURRING: 0.60}

# technical severity default for classes absent from RISK_WEIGHTS
TECHNICAL_DEFAULT_WEIGHT = 3 / 9

# the formula's component blend (sums to 1.0)
W_EXPOSURE, W_TECHNICAL, W_LIFECYCLE = 0.40, 0.35, 0.25

RISK_WEIGHTS = None  # lazy: filled from intel.py on first use (no import cycle)


def _risk_weights() -> dict:
    global RISK_WEIGHTS
    if RISK_WEIGHTS is None:
        from .intel import RISK_WEIGHTS as _W
        RISK_WEIGHTS = _W
    return RISK_WEIGHTS


# ---------------------------------------------------------------- identity
def normalize_endpoint(url: str) -> str:
    """scheme+host lowercased, port kept, query/fragment dropped, path kept."""
    if not url:
        return ""
    try:
        p = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return url.strip()
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    netloc = host if not p.port else f"{host}:{p.port}"
    return f"{scheme}://{netloc}{p.path or '/'}"


def finding_identity(detector_id: str, endpoint_url: str, parameter: str) -> str:
    """Stable identity of one vulnerability at one injection point: a hash
    of detector id + normalized endpoint + parameter — never the raw request
    or response, so minor response changes cannot break the lifecycle trail."""
    base = f"{(detector_id or '').strip()}|{normalize_endpoint(endpoint_url)}|{(parameter or '').strip()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def identity_of_finding(f: dict) -> dict:
    """The identity block attached to every finding in the signed report:
    the identity plus the exact basis it was computed from (auditable)."""
    detector = (f.get("detector") or f.get("type") or "").strip()
    endpoint = f.get("url") or f.get("endpoint_url") or ""
    parameter = f.get("parameter") or ""
    return {
        "identity": finding_identity(detector, endpoint, parameter),
        "identity_basis": {
            "detector": detector,
            "endpoint": normalize_endpoint(endpoint),
            "parameter": parameter.strip(),
        },
    }


def annotate_identities(rep: dict) -> None:
    """Attach the stable identity to every VERIFIED finding of a scan report
    (in-report, before the audit signature — identity rides the signed
    payload; lifecycle/score are store-level, see the module docstring)."""
    for f in rep.get("findings", []):
        f.update(identity_of_finding(f))


# ---------------------------------------------------------------- lifecycle
def covered_endpoints(report: dict) -> set[str]:
    """Normalized endpoints the run actually touched, from its own request
    journal — the 'equivalent coverage' gate for a FIXED claim."""
    stats = report.get("stats") or {}
    journal = stats.get("request_journal") or {}
    out = set()
    for entry in journal.values():
        url = entry.get("request", {}).get("url", "") if isinstance(entry, dict) else ""
        if url:
            out.add(normalize_endpoint(url))
    return out


def next_lifecycle(identity: str,
                   seen_ever: bool,
                   in_previous_run: bool,
                   latest_state: str) -> str:
    """The state one identity takes in THIS run, from its history:
    NEW (never seen on this target), RECURRING (present in the immediately
    previous run — or seen before without a FIXED memory between),
    REGRESSED (a state of FIXED is on record and the finding reappeared)."""
    if not seen_ever:
        return NEW
    if in_previous_run:
        return RECURRING
    if latest_state == FIXED:
        return REGRESSED
    return RECURRING


def resolve_lifecycle(history: dict,
                      current_findings: list[dict],
                      covered: set[str]) -> dict:
    """Resolve the full lifecycle picture of one run against the store.

    history          store.lifecycle_history(target) — ever_seen,
                     latest_state, prev_run_present
    current_findings the report's verified finding dicts (identity
                     attached) for THIS run
    covered          normalized endpoints touched THIS run

    Returns {"per_finding":  {finding_id: state},   report annotation
             "present_states": {identity: state},   the lifecycle log rows
             "fixed": {identity: endpoint},   absent + the endpoint WAS re-tested
             "untested_absences": [identity...]}   absent + NOT re-tested
    An absence is only FIXED when the run's own request journal proves
    the endpoint was exercised — a silent negative is never a fix."""
    per_finding: dict[str, str] = {}
    present_states: dict[str, str] = {}
    present_endpoints: dict[str, str] = {}
    for f in current_findings:
        ident = f.get("identity", "")
        state = next_lifecycle(
            ident,
            seen_ever=ident in history.get("ever_seen", set()),
            in_previous_run=ident in history.get("prev_run_present", {}),
            latest_state=history.get("latest_state", {}).get(ident, ""))
        per_finding[f.get("id", "")] = state
        present_states[ident] = state
        present_endpoints[ident] = f.get("identity_basis", {}).get("endpoint", "")

    fixed: dict[str, str] = {}
    untested = []
    for ident, endpoint in sorted(history.get("prev_run_present", {}).items()):
        if ident in present_states:
            continue
        if endpoint in covered:
            fixed[ident] = endpoint
        else:
            untested.append(ident)
    return {"per_finding": per_finding, "present_states": present_states,
            "present_endpoints": present_endpoints,
            "fixed": fixed, "untested_absences": untested}


# ---------------------------------------------------------------- scoring
def _verification_component(f: dict) -> float:
    status = (f.get("status") or "").lower()
    if status in VERIFICATION_WEIGHTS:
        return VERIFICATION_WEIGHTS[status]
    verification = f.get("verification") or {}
    if isinstance(verification, dict) and verification.get("passed"):
        return VERIFICATION_WEIGHTS["verified"]
    return VERIFICATION_WEIGHTS["unverified"]


def exposure_component(f: dict, scan_authenticated: bool) -> float:
    """E: anonymous-reachable vs auth-gated (v1 rule in the module docstring)."""
    if f.get("authz_context"):
        return EXPOSURE_AUTH_GATED
    if not scan_authenticated:
        return EXPOSURE_ANONYMOUS
    return EXPOSURE_ANONYMOUS


def technical_component(f: dict) -> float:
    """T: the class's technical weight from intel.RISK_WEIGHTS / 9.

    Cross-category rule (round 10 part 4): a finding carrying the
    ADVISORY'S OWN numeric CVSS base score (severity_data.base_score,
    e.g. an SCA finding) uses that score / 10 as its technical
    component — the advisory's own measurement over the class
    default. Absent or non-numeric -> the class weight, never a guess."""
    sd = f.get("severity_data") or {}
    base = sd.get("base_score")
    if isinstance(base, (int, float)):
        return min(1.0, max(0.0, float(base) / 10))
    w = _risk_weights().get(f.get("type", ""), 3) / 9
    return min(1.0, max(0.0, w))


def lifecycle_component(state: str) -> float:
    return LIFECYCLE_WEIGHTS.get(state, LIFECYCLE_WEIGHTS[NEW])


def risk_score(f: dict, lifecycle_state: str = NEW,
               scan_authenticated: bool = False) -> dict:
    """The stated, reproducible score (formula in the module docstring).
    Returns the score AND its components — the report shows both."""
    v = _verification_component(f)
    e = exposure_component(f, scan_authenticated)
    t = technical_component(f)
    l = lifecycle_component(lifecycle_state)
    score = round(100 * v * (W_EXPOSURE * e + W_TECHNICAL * t + W_LIFECYCLE * l))
    return {
        "risk_score": score,
        "risk_components": {
            "verification": {"weight": v, "value": f.get("status", "")},
            "exposure": {"weight": e,
                         "auth_gated": e == EXPOSURE_AUTH_GATED},
            "technical": {"weight": round(t, 4), "class": f.get("type", "")},
            "lifecycle": {"weight": l, "state": lifecycle_state},
        },
    }


def risk_ranked(findings: list[dict]) -> list[dict]:
    """The risk-ranked view (1.4): every finding with its score and every
    component, sorted by score desc, ties broken by identity (deterministic
    byte-identical output for the reproducibility contract)."""
    rows = []
    for f in findings:
        if f.get("lifecycle") == FIXED:
            continue
        rows.append({
            "id": f.get("id", ""),
            "identity": f.get("identity", ""),
            "type": f.get("type", ""),
            "severity": f.get("severity", ""),
            "lifecycle": f.get("lifecycle", NEW),
            "risk_score": f.get("risk_score", 0),
            "risk_components": f.get("risk_components", {}),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
        })
    return sorted(rows, key=lambda r: (-r["risk_score"], r["identity"], r["id"]))


# ---------------------------------------------------------------- wiring
FORMULA_DOC = ("score = round(100 * V * (0.40*E + 0.35*T + 0.25*L)); "
               "V re-execution verdict (verified 1.0 / observed_anomaly 0.6 / "
               "unverified 0.3), E exposure (anonymous 1.0 / auth-gated 0.70), "
               "T technical class weight (intel.RISK_WEIGHTS/9, default 3/9), "
               "L lifecycle (REGRESSED 1.0 > NEW 0.8 > RECURRING 0.6). "
               "Full statement: burhan/prioritize.py module docstring.")


def apply_prioritization(report: dict, store_path: str = "") -> None:
    """The single wiring point, called by orchestrator.report() BEFORE the
    audit signature: attach identities, resolve the lifecycle against the
    store (when one is wired via ScanConfig.prioritize_store), score every
    verified finding, and embed the ranked view + the resolution itself in
    the report. The resolution rides the report so save_run can record it
    in the lifecycle log in the SAME transaction as the findings — the
    store, not a second data path, remains the only persistence layer."""
    annotate_identities(report)
    target = report.get("target", "")
    store = None
    if store_path:
        from .store import Store
        store = Store(store_path)
    history = (store.lifecycle_history(target, exclude_run=report.get("run_id", ""))
               if store else {})
    resolved = resolve_lifecycle(history, report.get("findings", []),
                                 covered_endpoints(report))
    scan_auth = bool((report.get("stats") or {}).get("authenticated"))
    for f in report.get("findings", []):
        state = resolved["per_finding"].get(f.get("id", ""), NEW)
        f["lifecycle"] = state
        f.update(risk_score(f, state, scan_auth))
    counts = {s: 0 for s in (NEW, RECURRING, REGRESSED)}
    for state in resolved["present_states"].values():
        counts[state] = counts.get(state, 0) + 1
    report["prioritization"] = {
        "formula": FORMULA_DOC,
        "risk_ranked": risk_ranked(report.get("findings", [])),
        "lifecycle_summary": {
            "new": counts[NEW], "recurring": counts[RECURRING],
            "regressed": counts[REGRESSED],
            "fixed": len(resolved["fixed"]),
            "untested_absences": len(resolved["untested_absences"]),
            "coverage_gate": ("a FIXED claim requires the endpoint to have "
                               "been re-tested this run (request journal); "
                               "an untested absence is reported as such and "
                               "never claimed as fixed"),
        },
        "resolution": {   # consumed by store.save_run -> lifecycle_log
            "present_states": resolved["present_states"],
            "present_endpoints": resolved["present_endpoints"],
            "fixed": resolved["fixed"],
            "untested_absences": resolved["untested_absences"],
        },
    }
