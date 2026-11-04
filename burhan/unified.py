"""Round 10, PART 4 — the unified cross-category report.

ONE ranked list over THREE finding categories, on the ONE stated formula
(burhan/prioritize.py — score = round(100*V*(0.40E+0.35T+0.25L))):

  * dast   — the scan's own verified findings (already identity-annotated,
             lifecycle-resolved and scored by the scan path; the unified
             view reuses those scores verbatim — it never re-scores what
             the scan already scored).
  * sca    — dependency findings from one or more `burhan sca` results
             (status confirmed_by_advisory). Identity: detector +
             normalized manifest path + package (the manifest IS the
             surface; the package is the parameter).
  * chain  — the proven attack chains riding the scan result (CR-01 live
             combined proof / CR-02 verified data join). Identity:
             rule + the two member findings' OWN identities.

CROSS-CATEGORY JUDGMENT CALLS — stated here, echoed in every output's
judgment_calls block, never hidden inside an opaque number:

  J1  V(confirmed_by_advisory) = 0.85 — an advisory-confirmed dependency
      sits between an observed anomaly (0.60) and a re-execution-verified
      finding (1.00): a public advisory plus the exact pinned version is
      an established fact, but it was not re-executed on a live target.
  J2  T — a finding carrying the advisory's OWN numeric CVSS base score
      uses base_score/10 (the advisory's measurement) instead of the
      class-default weight (prioritize.technical_component).
  J3  chains — V=1.00 (the chain rides a live combined proof or a pure
      join of two VERIFIED findings — the chain claim is itself proven),
      E = the ENTRY finding's exposure (the chain is entered through
      finding_a; its gate bounds the chain), T = the MAX of its member
      findings' technical components (a chain is as strong as its
      strongest link).

Lifecycle: the same store, the same resolver (prioritize.resolve_lifecycle),
the same states. SCA history is keyed to target "sca:<manifest path>" —
re-running SCA on the SAME manifest re-tests every package in it, so a
previously-vulnerable package that is absent now resolves FIXED (covered:
the manifest itself), and an absence without a re-query is an UNTESTED
absence, never a fix. Chain history is keyed to the scan's own target.
The unified command is a PURE VIEW over its inputs: it resolves lifecycle
against the store when --prioritize-store is given (and records SCA/chain
rows under its own run id — the same contract as the scan path; rows never
enter the findings table, so a scan's prev-run semantics are untouched);
without a store it resolves nothing and every row reads NEW.
"""
from __future__ import annotations

import hashlib
import uuid

from .prioritize import (
    NEW, RECURRING, REGRESSED,
    FORMULA_DOC, identity_of_finding, resolve_lifecycle,
    risk_score, technical_component, exposure_component,
    covered_endpoints, normalize_endpoint, LIFECYCLE_WEIGHTS,
)

SCA_TARGET_PREFIX = "sca:"

JUDGMENT_CALLS = [
    {"id": "J1", "call": "V(confirmed_by_advisory) = 0.85",
     "why": ("an advisory-confirmed dependency is stronger than an "
             "observed anomaly (0.60) but was not re-executed on a live "
             "target like a verified finding (1.00)")},
    {"id": "J2", "call": "T = advisory's own CVSS base_score/10 when present",
     "why": ("the advisory's own measurement beats the class-default "
             "weight; absent/non-numeric falls back to the class weight")},
    {"id": "J3", "call": ("chain: V=1.00 (proven chain), E=entry finding's "
                          "exposure, T=max member technical"),
     "why": ("the chain claim carries its own live combined proof or is a "
             "join of two VERIFIED findings; the chain is entered through "
             "finding_a, and is as strong as its strongest link")},
]


def chain_identity(rule: str, identity_a: str, identity_b: str) -> str:
    """A chain's stable identity: its rule + its two member findings' OWN
    identities — so the chain follows its members across runs exactly as
    a finding follows its endpoint (same truncation as finding_identity)."""
    base = f"chain|{rule}|{identity_a}|{identity_b}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def _sca_rows(sca_result: dict, store) -> list[dict]:
    """Identity-annotate + score one SCA result's findings. The resolver
    keys per_finding by finding id — SCA findings carry none, so each row
    gets a deterministic one (advisory@version) BEFORE resolving; coverage
    is the manifest path through the SAME normalize_endpoint the identity
    basis uses (exact comparison, never a substring match)."""
    manifest = sca_result.get("manifest", "")
    target = SCA_TARGET_PREFIX + manifest
    rows = []
    for f in sca_result.get("findings", []):
        f = dict(f)
        f["id"] = f.get("advisory_id", "") or \
            f"{f.get('package', '')}@{f.get('version', '')}"
        f.update(identity_of_finding(f))
        rows.append(f)
    scored = []
    history = store.lifecycle_history(target) if store else {}
    if store:
        # the log — not the findings rows — is this view's source of truth
        # (the unified pass records no findings rows at all)
        history["prev_run_present"] = store.lifecycle_prev_present(
            target, exclude_run="")
    covered = {normalize_endpoint(manifest)} if manifest else set()
    resolved = resolve_lifecycle(history, rows, covered)
    for f in rows:
        state = resolved["per_finding"].get(f.get("id", ""), NEW)
        f["lifecycle"] = state
        f.update(risk_score(f, state, scan_authenticated=False))
        scored.append(f)
    return scored, resolved, target


def _chain_rows(scan_result: dict, store) -> tuple[list[dict], dict, str]:
    """Score the scan's proven chains: J3 components, lifecycle against
    the scan's own target history, identity from the member identities."""
    by_id = {f.get("id", ""): f for f in scan_result.get("findings", [])}
    target = scan_result.get("target", "")
    scan_auth = bool((scan_result.get("stats") or {}).get("authenticated"))
    chain_dicts = []
    for c in scan_result.get("attack_chains") or []:
        fa = by_id.get((c.get("findings") or {}).get("finding_a", ""))
        fb = by_id.get((c.get("findings") or {}).get("finding_b", ""))
        ida = fa.get("identity", "") if fa else ""
        idb = fb.get("identity", "") if fb else ""
        c = dict(c)
        c["identity"] = chain_identity(c.get("rule", ""), ida, idb)
        c["identity_basis"] = {"rule": c.get("rule", ""),
                               "finding_a_identity": ida,
                               "finding_b_identity": idb}
        chain_dicts.append((c, fa, fb))
    history = store.lifecycle_history(target) if store else {}
    if store:
        history["prev_run_present"] = store.lifecycle_prev_present(
            target, exclude_run="")
    resolved = resolve_lifecycle(
        history,
        [{"id": c.get("rule", "") + "#" + c.get("identity", ""),
          "identity": c["identity"],
          "identity_basis": {"endpoint": (fa or {}).get(
              "identity_basis", {}).get("endpoint", "")}}
         for c, fa, fb in chain_dicts],
        covered_endpoints(scan_result))
    scored = []
    for c, fa, fb in chain_dicts:
        state = resolved["per_finding"].get(
            c.get("rule", "") + "#" + c.get("identity", ""), NEW)
        entry = fa or {}
        v, e = 1.00, exposure_component(entry, scan_auth)
        members = [m for m in (fa, fb) if m]
        t = max((technical_component(m) for m in members), default=0.0)
        l = LIFECYCLE_WEIGHTS.get(state, LIFECYCLE_WEIGHTS[NEW])
        score = round(100 * v * (0.40 * e + 0.35 * t + 0.25 * l))
        c["lifecycle"] = state
        c["risk_score"] = score
        c["risk_components"] = {
            "verification": {"weight": v, "value": "verified-chain"},
            "exposure": {"weight": e, "auth_gated": e < 1.0,
                         "basis": "entry finding (finding_a)"},
            "technical": {"weight": round(t, 4),
                          "basis": "max of member findings"},
            "lifecycle": {"weight": l, "state": state},
        }
        scored.append(c)
    return scored, resolved, target


def build_unified(scan_result: dict, sca_results: list[dict],
                  store=None, run_id: str = "") -> dict:
    """The unified view: every category scored on the one formula, one
    ranked list, every judgment call surfaced. Pure over its inputs; the
    only writes (when a store is given) are lifecycle rows under this
    invocation's own run id — never findings rows."""
    rid = run_id or f"unified-{uuid.uuid4().hex[:12]}"
    dast_rows = []
    for f in scan_result.get("findings", []):
        f = dict(f)
        # a result from before round 10 (or a failed prioritization pass)
        # carries no identity/lifecycle/score — score it HERE, honestly,
        # with the same formula; it is never silently dropped (an absent
        # row would be a forged "no finding")
        if "identity" not in f:
            f.update(identity_of_finding(f))
        if f.get("lifecycle") not in (NEW, RECURRING, REGRESSED):
            state = NEW if f.get("lifecycle") is None else f.get("lifecycle")
            f["lifecycle"] = state
        if "risk_score" not in f:
            f.update(risk_score(f, f["lifecycle"], scan_authenticated=bool(
                (scan_result.get("stats") or {}).get("authenticated"))))
        dast_rows.append(f)
    sca_scored, sca_records = [], []
    for res in sca_results:
        scored, resolved, target = _sca_rows(res, store)
        sca_scored.extend(
            {"category": "sca", "row": f} for f in scored)
        # record the resolution even when NOTHING is present — an
        # all-absent pass is exactly the one that carries FIXED rows
        if store and res.get("manifest"):
            sca_records.append((target, resolved))
    chain_scored, chain_resolved, chain_target = _chain_rows(
        scan_result, store)
    if store:
        sca_records.append((chain_target, chain_resolved))

    rows = []
    for f in dast_rows:
        rows.append({
            "category": "dast", "id": f.get("id", ""),
            "identity": f.get("identity", ""), "type": f.get("type", ""),
            "severity": f.get("severity", ""), "lifecycle": f.get("lifecycle"),
            "risk_score": f.get("risk_score", 0),
            "risk_components": f.get("risk_components", {}),
            "url": f.get("url", ""), "parameter": f.get("parameter", ""),
        })
    for entry in sca_scored:
        f = entry["row"]
        rows.append({
            "category": "sca", "id": f.get("advisory_id", ""),
            "identity": f.get("identity", ""),
            "type": f.get("type", ""), "package": f.get("package", ""),
            "ecosystem": f.get("ecosystem", ""), "version": f.get("version", ""),
            "cve_aliases": f.get("cve_aliases", []),
            "known_exploited": f.get("known_exploited", []),
            "severity_data": f.get("severity_data", {}),
            "lifecycle": f.get("lifecycle"),
            "risk_score": f.get("risk_score", 0),
            "risk_components": f.get("risk_components", {}),
            "url": f.get("url", ""),
        })
    for c in chain_scored:
        rows.append({
            "category": "chain", "id": c.get("rule", ""),
            "identity": c.get("identity", ""), "rule": c.get("rule", ""),
            "title": c.get("title", ""), "pair": c.get("pair", []),
            "member_findings": c.get("findings", {}),
            "narrative_steps": len(c.get("narrative") or []),
            "lifecycle": c.get("lifecycle"), "risk_score": c.get("risk_score", 0),
            "risk_components": c.get("risk_components", {}),
        })
    rows.sort(key=lambda r: (-r["risk_score"], r["identity"], r["id"]))
    counts = {c: sum(1 for r in rows if r["category"] == c)
              for c in ("dast", "sca", "chain")}
    out = {
        "kind": "unified-report",
        "formula": FORMULA_DOC,
        "judgment_calls": JUDGMENT_CALLS,
        "counts_by_category": counts,
        "scan_target": scan_result.get("target", ""),
        "rows": rows,
        "note": ("one formula, three categories, every judgment call "
                 "stated; rejected candidates and unverified findings are "
                 "NOT ranked here — the scan report carries them under "
                 "their honest names"),
    }
    if store:
        for target, resolved in sca_records:
            store.record_lifecycle(rid, target, resolved)
        out["lifecycle_recorded_run_id"] = rid
    return out
