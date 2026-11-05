"""Round 10, PART 5 — live validation of the round-10 layers on the REAL
targets (crAPI v1.1.5 + DVGA), same honesty contract as the modern
battery v2: misses are RECORDED, never hidden; a true negative is a
valid result. This is a validation run, not a benchmark.

What this script proves live (order 5):

  1. LIFECYCLE — TWO crAPI scans back-to-back against the SAME target,
     same config, same seed, sharing ONE lifecycle store:
       scan 1 (fresh store) -> every finding NEW
       scan 2 (same store)  -> every finding whose IDENTITY re-appears
                               must resolve RECURRING — identity
                               matching, not count comparison. A
                               re-appearing identity that reads NEW in
                               scan 2 is a GATE FAILURE (the law is
                               broken). Zero overlap is recorded as
                               INCONCLUSIVE, honestly (exit 3).

  2. CHAIN RULES — the chain layer runs inside every scan (CR-01 needs
     its pair + the live combined proof; CR-02 needs shadow/zombie +
     an exploitable on the SAME normalized endpoint). For each scan
     (crAPI 1, crAPI 2, DVGA) this script records:
       - which rule pairs were PRESENT in the verified findings
       - which chains were PROVEN (rule + title + member findings)
       - for CR-01, when the pair fires but no chain was proven: the
         SPECIFIC broken-link refusal, captured LIVE by calling
         prove_credential_feeding directly (3 bounded requests) — the
         honest non-chain, never a silent one.

Ground truth is the live behavior itself: the verdict records what the
targets actually yielded, scored against the documented layer contract
(the pair preconditions in burhan/chainrules.RULES).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# DIFFERENT seeds per pass: run_id is DERIVED from the seed (deterministic
# reproducibility), so one shared seed gave BOTH passes the same run_id —
# run 41920279230's store proved it: ONE runs row, and lifecycle_history's
# exclude_run filter blinded pass 2 to pass 1's history (all 98
# re-appearing identities read NEW). Identity is detector+endpoint+
# parameter — seed-INDEPENDENT for the same vulnerability — so distinct
# seeds keep the comparison honest while giving each pass its own run
# row, exactly like part 1's three-scan test.
SEED_A = "r10liveA" * 8   # crAPI pass 1
SEED_B = "r10liveB" * 8   # crAPI pass 2
SEED_DVGA = "r10liveD" * 8   # the DVGA scan's own run row


def _crapi_race_candidate(base: str) -> dict:
    """The ONE declared race candidate — VERBATIM the battery's shape
    (live_validate_modern2.py), which the battery job proved against this
    exact stack in the same run: quota/concurrent/win_statuses and the
    v1.1.5 param names. The first dispatch failed with exit 3 inside
    five minutes (run 41913951604) — a hand-rolled variant of this dict
    is the prime suspect; the proven schema is mirrored, not reinvented."""
    email = f"burhan-race-{int(time.time())}@integration.test"
    return {
        "url": base + "/workshop/api/mechanic/signup",
        "method": "POST",
        "params": {
            "name": "Burhan Race Probe",
            "email": email,
            "number": "5550001111",
            "password": "Burhan-Race-123!",
            "mechanic_code": f"BRH{int(time.time()) % 1000000}",
        },
        "quota": 1,
        "concurrent": 6,
        "win_statuses": [200, 201],
        "verify_params": None,  # filled in main() with a second email
    }


def _crapi_login(base: str):
    from burhan.auth import AuthProfile
    return AuthProfile(
        login_url=base + "/identity/api/auth/login",
        username="test@example.com", password="Test!123",
        user_field="email", pass_field="password",
        json_login=True, success_marker='"token"',
        validate_url=base + "/identity/api/v2/user/dashboard")


def _crapi_authz(base: str) -> dict:
    return {
        "login_url": base + "/identity/api/auth/login",
        "json_login": True,
        "user_field": "email", "pass_field": "password",
        "success_marker": '"token"', "login_marker": "login",
        "accounts": [
            {"name": "admin", "role": "admin",
             "username": "admin@example.com", "password": "Admin!123"},
            {"name": "test", "role": "user",
             "username": "test@example.com", "password": "Test!123"},
        ],
    }


def scan_crapi(base: str, spec, race, max_requests: int, store_path: str,
               out: Path, label: str, seed: str) -> dict:
    """One full crAPI scan with the battery's own setup + the lifecycle
    store wired. The scan itself resolves lifecycle (orchestrator ->
    apply_prioritization) and save_run records it in the SAME store."""
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.oast import OastServer
    from burhan.store import Store

    # Part 5.1 (this order): OAST channel selectable — local listener
    # (default) or interact.sh when BURHAN_LIVE_OAST=interactsh.
    import os as _os
    if _os.environ.get("BURHAN_LIVE_OAST") == "interactsh":
        from burhan.oast import InteractshProvider
        oast = InteractshProvider()
    else:
        oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=50, timeout=15.0,
                         seed=seed, oast=oast, workflow=False,
                         logic_active=False, modern_v2=True,
                         auth=_crapi_login(base), authz=_crapi_authz(base),
                         openapi_spec=spec, race_candidates=[race],
                         max_requests=max_requests,
                         prioritize_store=store_path)
        rep = BurhanScanner(base, cfg).run()
    finally:
        oast.stop()
    rep["wall_seconds"] = round(time.time() - t0, 1)
    Store(store_path).save_run(rep)   # record the resolution in the log
    (out / f"r10-{label}-scan.json").write_text(
        json.dumps(rep, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    return rep


def scan_dvga(base: str, max_requests: int, out: Path) -> dict:
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.oast import OastServer
    import os as _os
    if _os.environ.get("BURHAN_LIVE_OAST") == "interactsh":
        from burhan.oast import InteractshProvider
        oast = InteractshProvider()
    else:
        oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=50, timeout=15.0,
                         seed=SEED_DVGA, oast=oast, workflow=False,
                         logic_active=False, modern_v2=True,
                         max_requests=max_requests)
        rep = BurhanScanner(base, cfg).run()
    finally:
        oast.stop()
    rep["wall_seconds"] = round(time.time() - t0, 1)
    (out / "r10-dvga-scan.json").write_text(
        json.dumps(rep, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    return rep


def _chain_verdict(name: str, rep: dict, base: str) -> dict:
    """The honest chain record for one scan: pairs present, chains
    proven, and — for CR-01 when the pair fired but nothing was proven —
    the LIVE broken-link refusal (bounded, 3 requests)."""
    from burhan.chainrules import RULES
    findings = rep.get("findings", [])
    types = {f.get("type") for f in findings}
    chains = rep.get("attack_chains") or []

    cr01_pair = ("bfla" in types
                 and "jwt_signature_not_enforced" in types)
    shadow_types = {"shadow_api_endpoint", "zombie_api_endpoint"}
    cr02_pair = bool(shadow_types & types)
    verdict = {
        "target": name,
        "verified_types_present": sorted(types),
        "rules": {
            "CR-01-credential-feeding": {
                "pair_present": cr01_pair,
                "chains_proven": [
                    {"title": c.get("title"), "rule": c.get("rule"),
                     "findings": c.get("findings")}
                    for c in chains
                    if c.get("rule") == "CR-01-credential-feeding"],
            },
            "CR-02-shared-surface-entry": {
                "pair_present": cr02_pair,
                "chains_proven": [
                    {"title": c.get("title"), "rule": c.get("rule"),
                     "findings": c.get("findings")}
                    for c in chains
                    if c.get("rule") == "CR-02-shared-surface-entry"],
            },
        },
        "rule_catalog": [
            {"rule": r["id"], "pair": list(r["pair"]),
             "precondition": r["precondition"]}
            for r in RULES],
    }
    if cr01_pair and not any(
            c.get("rule") == "CR-01-credential-feeding" for c in chains):
        # the pair fired but no chain was claimed — capture the SPECIFIC
        # refusal live instead of guessing: the honest non-chain
        try:
            from burhan.http_engine import RequestEngine
            from burhan.core import (EventBus, ScopeRule, Endpoint,
                                     Parameter, ParamLocation)
            from burhan.chainrules import prove_credential_feeding
            host = base.split("//", 1)[-1].split(":", 1)[0]
            engine = RequestEngine(
                ScopeRule(allow_private=True, allowed_hosts=[host]),
                EventBus("r10-chain-eval"), timeout=15.0)
            engine.auth_harvest_endpoint = Endpoint(
                url=base + "/identity/api/auth/login", method="POST",
                parameters=[
                    Parameter("email", ParamLocation.JSON,
                              "test@example.com"),
                    Parameter("password", ParamLocation.JSON, "Test!123"),
                ])
            bfla_f = next(f for f in findings if f.get("type") == "bfla")
            jwt_f = next(f for f in findings
                         if f.get("type") == "jwt_signature_not_enforced")
            proof, why_not = prove_credential_feeding(
                engine, {"url": bfla_f.get("url")},
                {"url": jwt_f.get("url")})
            verdict["rules"]["CR-01-credential-feeding"][
                "live_refusal_probe"] = {
                    "combined_proof": proof,
                    "why_not": why_not,
                    "note": ("the pair is present and the live combined "
                             "proof was attempted directly (3 bounded "
                             "requests): no chain was claimed because the "
                             "specific link is broken — recorded, not "
                             "silently skipped"),
                }
        except Exception as e:  # noqa: BLE001
            verdict["rules"]["CR-01-credential-feeding"][
                "live_refusal_probe"] = {"error": f"{type(e).__name__}: {e}"}
    return verdict


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crapi", default="", help="crAPI base URL")
    ap.add_argument("--dvga", default="", help="DVGA base URL")
    ap.add_argument("--crapi-spec", default="",
                    help="local path to crAPI's openapi spec (main "
                         "branch), for the shadow/zombie layer")
    ap.add_argument("--max-requests", type=int, default=12000,
                    help="per-scan request budget (the battery's own "
                         "lesson: 12000 fits the spec-expanded surface)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    from burhan.authorized_targets import require_authorized
    for t in (args.crapi, args.dvga):
        if t:
            require_authorized(t)

    if not args.crapi:
        print("--crapi is required (the r10 lifecycle needs it)")
        return 2

    spec = None
    if args.crapi_spec:
        try:
            spec = json.loads(Path(args.crapi_spec).read_text(encoding="utf-8"))
            print(f"crAPI spec loaded: {len(spec.get('paths') or {})} paths")
        except Exception as e:  # noqa: BLE001
            print(f"crAPI spec load failed (shadow layer records the "
                  f"boundary): {e}")

    # the ONE declared race candidate — the battery's VERBATIM shape
    race = _crapi_race_candidate(args.crapi)
    race["verify_params"] = dict(
        race["params"],
        email=f"burhan-r10-v{int(time.time())}@integration.test")

    store_path = str(out / "r10-lifecycle-store.db")
    if os.path.exists(store_path):
        os.unlink(store_path)

    # ---- LIFECYCLE: two back-to-back scans, one shared store ----------
    try:
        rep1 = scan_crapi(args.crapi, spec, race, args.max_requests,
                          store_path, out, "pass1", SEED_A)
        rep2 = scan_crapi(args.crapi, spec, race, args.max_requests,
                          store_path, out, "pass2", SEED_B)
    except Exception as e:  # noqa: BLE001
        print(f"GATE FAIL: a crAPI scan died mid-run "
              f"({type(e).__name__}: {e}) — recorded, never retried blind")
        # the verdict is STILL written: the artifact must tell the next
        # reader exactly why this run failed (upload runs if: always())
        (out / "r10-live-validation.json").write_text(json.dumps({
            "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "part": "r10-part5-live-validation",
            "failed": {"error": f"{type(e).__name__}: {e}",
                       "stage": "crAPI scan (pass1 or pass2)"},
        }, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
        return 3

    from burhan.prioritize import NEW, RECURRING, REGRESSED
    id1 = {f.get("identity"): f for f in rep1.get("findings", [])}
    id2 = {f.get("identity"): f for f in rep2.get("findings", [])}
    overlap = sorted(set(id1) & set(id2))
    lifecycle = {
        "store": "r10-lifecycle-store.db",
        "seeds": {"pass1": SEED_A, "pass2": SEED_B,
                  "why": ("run_id derives from the seed; one shared seed "
                          "gave both passes the same run_id and the "
                          "store's exclude_run filter blinded pass 2 — "
                          "run 41920279230 proved it live")},
        "scan1": {"findings": len(id1), "requests": rep1["stats"].get("requests"),
                  "wall": rep1["wall_seconds"],
                  "all_new": all(f.get("lifecycle") == NEW
                                 for f in rep1.get("findings", []))},
        "scan2": {"findings": len(id2), "requests": rep2["stats"].get("requests"),
                  "wall": rep2["wall_seconds"]},
        "identity_overlap": len(overlap),
        "overlap_states_scan2": sorted({id2[i].get("lifecycle") for i in overlap}),
        "scan2_only_identities": len(set(id2) - set(id1)),
        "scan1_only_identities": len(set(id1) - set(id2)),
        "law": ("a re-appearing identity MUST read RECURRING in scan 2 "
                "(NEW would break the lifecycle law); identity "
                "matching, never count comparison"),
    }

    # ---- CHAINS: the live chain record for every scan ------------------
    chains = {
        "crapi_pass1": _chain_verdict("crapi-pass1", rep1, args.crapi),
        "crapi_pass2": _chain_verdict("crapi-pass2", rep2, args.crapi),
    }
    if args.dvga:
        dvga_rep = scan_dvga(args.dvga, args.max_requests, out)
        chains["dvga"] = _chain_verdict("dvga", dvga_rep, args.dvga)

    # ---- R11 5.2: gated interactive replay, end-to-end, vs a REAL crAPI
    # finding (same function the CLI's `reproduce --replay --gated` calls:
    # live authorization gate + per-finding rate limit + the existing
    # re-execution engine). Runs INSIDE the scanbox while crAPI is up.
    gated_replay = {"attempted": False}
    proofs = (rep2.get("stats") or {}).get("proofs") or []
    crapi_proofs = [p for p in proofs
                    if str((p.get("requests") or [{}])[0].get("url", ""))
                    .startswith(args.crapi.rstrip("/") + "/")]
    candidate = next(
        (p for p in crapi_proofs
         if p.get("type") in ("sql_injection", "xss_reflected",
                              "http_response_header_injection",
                              "vertical_privilege_escalation", "csrf")),
        crapi_proofs[0] if crapi_proofs else None)
    if candidate:
        try:
            from burhan.replay import (replay_finding_gated,
                                       ReplayRateLimited)
            gated_replay = {"attempted": True,
                            "finding_id": candidate.get("finding_id", ""),
                            "type": candidate.get("type", "")}
            try:
                g = replay_finding_gated(candidate)
            except ReplayRateLimited as e:
                g = {"replay": "RATE_LIMITED", "reason": str(e)}
            gated_replay.update(g)
            print("[5.2 gated replay] "
                  + json.dumps({k: gated_replay.get(k) for k in
                                ("finding_id", "type", "replay",
                                 "live_requests_sent", "reason")}))
        except Exception as e:  # noqa: BLE001 — recorded, never fatal to the run
            gated_replay.update({"replay": "ERROR",
                                 "reason": f"{type(e).__name__}: {e}"})
            print(f"[5.2 gated replay] failed to execute: {e}")
    else:
        gated_replay = {"attempted": False,
                        "reason": "no crAPI proof in pass2's stats.proofs"}

    verdict = {
        "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "part": "r10-part5-live-validation",
        "lifecycle": lifecycle,
        "chains": chains,
        "gated_replay_5_2": gated_replay,
    }
    (out / "r10-live-validation.json").write_text(
        json.dumps(verdict, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    print(json.dumps(verdict["lifecycle"], indent=1))
    for name, cv in chains.items():
        for rule, rv in cv["rules"].items():
            print(f"[{name}] {rule}: pair={rv['pair_present']} "
                  f"proven={len(rv['chains_proven'])}")
            if rv.get("live_refusal_probe"):
                wn = rv["live_refusal_probe"].get("why_not") \
                    or rv["live_refusal_probe"].get("error")
                print(f"    refusal: {str(wn)[:140]}")

    # ---- the GATE: the law, not the luck -------------------------------
    ok = True
    for rep, label in ((rep1, "pass1"), (rep2, "pass2")):
        if not rep.get("stats", {}).get("requests"):
            print(f"GATE FAIL: crAPI {label} scan incomplete")
            ok = False
    # scan 1 against a FRESH store: every finding must be NEW
    if not lifecycle["scan1"]["all_new"]:
        bad = [(f.get("identity", "?")[:8], f.get("lifecycle"))
               for f in rep1.get("findings", [])
               if f.get("lifecycle") != NEW]
        print(f"GATE FAIL: fresh-store scan 1 has non-NEW rows: {bad[:5]}")
        ok = False
    # scan 2: every re-appearing identity must read RECURRING
    bad2 = [(i[:8], id2[i].get("lifecycle")) for i in overlap
            if id2[i].get("lifecycle") != RECURRING]
    if bad2:
        print(f"GATE FAIL: re-appearing identities not RECURRING: {bad2[:5]}")
        ok = False
    if not overlap:
        print("INCONCLUSIVE: zero identity overlap between the two scans — "
              "the lifecycle law was not exercisable this run (recorded, "
              "not hidden)")
        ok = False
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
