#!/usr/bin/env python3
"""LIVE VALIDATION v2 (owner order 2026-10-31 part 3, extended 2026-11-02
part 4): crAPI + DVGA.

Runs the modern battery v2 (owner order part 3 layers + the part-4 live
chain) against the two official targets and scores every finding against
the GROUND TRUTH recorded from each project's official documentation
BEFORE any scan:

  crAPI (OWASP/crAPI, compose pinned v1.1.5, docs/challenges.md):
    3A jwt_weak_secret   — challenge 15 documents JWT forgery (the docs
                           describe algorithm confusion via the RSA public
                           key as HMAC secret; a WEAK-WORDLIST secret is a
                           DIFFERENT mechanism — a hit here is scored
                           confirmed-positive; a miss is scored NOT FOUND,
                           honestly, not as a false negative).
    3D excessive_data_exposure — challenges 4+5 document endpoints leaking
                           sensitive data of other users / an internal video
                           property.
    fam1 jwt_algorithm_confusion + fam2 jwt_none_acceptance + PART 0
    jwt_signature_not_enforced — challenge 15 ("find any one way to forge");
                           run 9 live-proved the dashboard accepts ANY
                           token with a registered sub, so PART 0's
                           corrupted-control acceptance is the documented
                           mechanism's own shape.
    3E bfla              — challenge 7 sits under the literal "## BFLA"
                           heading ("Delete a video of another user ...
                           find an admin endpoint to delete videos"). The
                           scanned deployment pins compose v1.1.5, and the
                           admin delete route exists in BOTH eras
                           (ProfileController.java @DeleteMapping
                           "/api/v2/admin/videos/{video_id}" — verified in
                           the v1.1.5 tag AND main), with the handler
                           (ProfileServiceImpl.deleteAdminProfileVideo in
                           both eras) performing NO role check: any
                           authenticated user deletes any video by id.
    3G shadow/zombie     — the operator-supplied spec is crAPI's own
                           openapi-spec/crapi-openapi-spec.json. It EXISTS
                           on main but NOT at the v1.1.5 tag (verified:
                           HTTP 404) — an explicit, documented version
                           drift; scoring uses main's spec against the
                           pinned v1.1.5 deployment and every hit is
                           judged against that drift, never silently.
    3F race_condition    — ONE operator-declared candidate ONLY
                           (order 2.2: the prober NEVER fires concurrent
                           load at endpoints the operator did not name —
                           crAPI is a shared public image on a shared
                           runner): POST /workshop/api/mechanic/signup —
                           declared on the official spec, and the v1.1.5
                           handler is the classic check-then-insert race
                           (filter(email).exists() -> User.objects.create)
                           with a UNIQUE email constraint as the
                           single-winner invariant. The email is UNIQUE
                           PER RUN (fresh burhan-<timestamp>@... each
                           scan) so repeated weekly runs never fight over
                           a consumed resource; a 2xx winner burst is a
                           confirmed positive (multiple mechanics created
                           from one email), a single winner is an honest
                           TESTED_NEGATIVE (the DB constraint held).
  DVGA (dolevf/Damn-Vulnerable-GraphQL-Application, port 5013):
    3C graphql_aliasing  — the official scenario list documents "Aliases
                           based Attack" under Denial of Service.
    (DVGA's other documented scenarios — introspection, batch query,
     deep recursion, field duplication, injections, JWT forge — map to the
     EXISTING v4.4.0 families (graphql.py / modernsec.py), not to 3C; the
     full-family run against DVGA is out of scope for this driver.)

Part 4 (2026-11-02) — why DVGA/Juice Shop/WebGoat/DVWA get NO race
candidate and NO authz/spec battery: order 2.2 forbids concurrent load
at endpoints the operator did not name, and a declared candidate needs a
VERIFIED unique-constraint resource in the target's published source.
DVGA's in-memory stores carry no uniqueness guarantee (no per-resource
constraint is documented in its source); Juice Shop's request bodies are
not verifiable this way from its published docs; WebGoat/DVWA are not in
this battery. Declaring a candidate on an unverified constant would be
blind concurrency — the exact thing the order forbids.

Verdicts (per finding): confirmed-positive (type in the documented ground
truth for that target) / unjudged (engine finding with no matching
documented scenario — reported, never silently dropped) / expected-miss
(documented scenario with no engine finding — the honest miss list).

Every finding id carries a SHA-256 over the canonical finding JSON.
Exit 0 = scan+scoring completed (misses do not fail the run — they are
recorded); exit 2/3 = infrastructure/gate failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ── ground truth, recorded 2026-10-31 from the official docs (pre-scan),
#    extended 2026-11-02 (part 4) with challenge 7 (BFLA) and the spec
#    version drift — every entry below was re-verified against the
#    official sources BEFORE this scan ran (see the docstring). ──────────
GROUND_TRUTH = {
    "crapi": {
        "source": "github.com/OWASP/crAPI @ main (compose pinned 1.1.5), "
                  "docs/challenges.md + services/identity JwtProvider.java "
                  "+ ProfileController.java + openapi-spec/"
                  "crapi-openapi-spec.json",
        "jwt_weak_secret": {
            "documented": True,
            "mechanism": "challenge 15: forge valid JWT tokens. Mechanism in "
                         "source: algorithm confusion (RSA public key re-used "
                         "as the HS256 secret) — NOT a wordlist-weak secret. "
                         "3A's wordlist check targets a different mechanism; "
                         "an engine hit is a confirmed positive, a miss is an "
                         "honest NOT-FOUND, not a false negative.",
        },
        "excessive_data_exposure": {
            "documented": True,
            "mechanism": "challenges 4+5: endpoints leaking sensitive data of "
                         "other users and an internal video property.",
        },
        # challenge 15 IS the algorithm-confusion mechanism (fam1, axis 13).
        # Follow-up 2026-11-01: run 41314804418 recorded fam1 NOT_DISCOVERED
        # with 0/12 probes — the scan ran unauthenticated so no auth-shaped
        # endpoint was ever in flight. The chain is now wired (json_login
        # with the official seeded demo user + the JWKS endpoint crAPI
        # serves at /.well-known/jwks.json): a hit is a CONFIRMED POSITIVE
        # (the exact documented challenge), and a miss is a REAL coverage
        # gap — check stats.axes.modern boundaries for which skip kind.
        "jwt_algorithm_confusion": {
            "documented": True,
            "mechanism": "challenge 15: forge valid JWT tokens. crAPI issues "
                         "RS256 and serves the public key at /.well-known/"
                         "jwks.json — the documented forgery is HS256 signed "
                         "with that public key (the confusion differential "
                         "fam1 runs verbatim).",
        },
        "jwt_none_acceptance": {
            "documented": True,
            "mechanism": "challenge 15 ('find ANY one way to forge'): run 9 "
                         "live-proved the dashboard reads the token's sub "
                         "claim without signature verification, so the "
                         "alg=none differential shares the documented "
                         "mechanism's root cause (CWE-347).",
        },
        "jwt_signature_not_enforced": {
            "documented": True,
            "mechanism": "challenge 15 ('find ANY one way to forge'): run 9 "
                         "live-proved the dashboard accepts a CORRUPTED-"
                         "signature token with the account data — the "
                         "endpoint does not verify JWT signatures at all "
                         "(CWE-347); PART 0's corrupted-control finding is "
                         "this exact live-proven shape.",
        },
        # PART 4 (2026-11-02): challenge 7 under the LITERAL "## BFLA"
        # heading. The admin delete route + the no-role-check handler are
        # verified present in BOTH the pinned v1.1.5 tag and main, so the
        # pinned deployment carries the documented vulnerability.
        "bfla": {
            "documented": True,
            "mechanism": "challenge 7 (docs heading '## BFLA'): delete a "
                         "video of another user via the admin endpoint "
                         "DELETE /identity/api/v2/admin/videos/{video_id} — "
                         "the handler (deleteAdminProfileVideo, v1.1.5 and "
                         "main alike) performs NO role check: any "
                         "authenticated user executes the admin function. A "
                         "bfla hit is a CONFIRMED POSITIVE; a miss is a REAL "
                         "coverage gap.",
        },
        # PART 4: the operator-supplied spec is main's; the deployment is
        # pinned v1.1.5. The spec file does not exist at the v1.1.5 tag
        # (verified HTTP 404) — the drift is part of the ground truth, and
        # 3G's findings are judged WITH it, never silently.
        "shadow_api_endpoint": {
            "documented": True,
            "mechanism": "challenge 8 names a 'shadow API endpoint' "
                         "(undocumented surface); the spec supplied is "
                         "main's crapi-openapi-spec.json against the pinned "
                         "v1.1.5 deployment — a hit is judged against the "
                         "documented spec/deployment version drift (the "
                         "spec does not exist at the v1.1.5 tag).",
        },
        "zombie_api_endpoint": {
            "documented": True,
            "mechanism": "spec-declared-but-dead (spec drift) and "
                         "deprecated-but-alive are the OWASP API8:2023 "
                         "'outdated API versions' class; the supplied spec "
                         "is main's against the pinned v1.1.5 deployment — "
                         "the version drift is the documented context.",
        },
        # PART 4: the ONE operator-declared race candidate (order 2.2).
        "race_condition": {
            "documented": True,
            "mechanism": "the declared candidate POST /workshop/api/"
                         "mechanic/signup (on the official spec) has the "
                         "classic check-then-insert handler in the pinned "
                         "v1.1.5 source (filter(email).exists() then "
                         "User.objects.create) with a UNIQUE email "
                         "constraint — the single-winner invariant. The "
                         "burst email is unique per run; >1 winner is a "
                         "confirmed positive, 1 winner an honest "
                         "TESTED_NEGATIVE (constraint held).",
        },
    },
    "dvga": {
        "source": "github.com/dolevf/Damn-Vulnerable-GraphQL-Application @ "
                  "master, README 'Scenarios' section",
        "graphql_aliasing": {
            "documented": True,
            "mechanism": "'Aliases based Attack' listed under Denial of "
                         "Service; also Batch/Deep Recursion/Resource "
                         "Intensive/Field Duplication (other families).",
        },
    },
}

# The ONE operator-declared race candidate (order 2.2: never blind). The
# email is UNIQUE PER RUN so the weekly cron never fights a consumed
# resource; the unique constraint on workshop user.email is the declared
# invariant (quota=1 winner).
def _crapi_race_candidate(base: str) -> dict:
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
        # VR-37 verify_params: a SECOND unique email — the first burst's
        # email is consumed (or duplicated) already; the fresh burst must
        # reproduce the same winner-count shape on fresh state.
        "verify_params": None,  # filled in main() with a second email
    }


def finding_sha(f: dict) -> str:
    canon = json.dumps(
        {k: f.get(k) for k in ("type", "url", "parameter", "method",
                               "severity", "status", "evidence")},
        sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def write_report(out: Path, name: str, rep: dict) -> None:
    """Persist a scan report. The report is the product's EVIDENCE OUTPUT —
    verified findings of a deliberately-vulnerable training target with
    evidence strings verbatim — plaintext by design, the same class as
    every other CI report writer (see the triaged dismissals on the CI
    report scripts). py/clear-text-storage-sensitive-data has no inline
    suppression for python (verified empirically against CodeQL CLI
    2.27.3); the boundary keeps the intent documented at the site."""
    with open(out / f"{name}-scan.json", "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1, ensure_ascii=False, default=str)


def run_target(name: str, base: str, modern_types: list[str], out: Path,
               max_requests: int = 2000, auth=None, authz=None,
               openapi_spec=None, race_candidates=None) -> dict:
    from burhan.orchestrator import ScanConfig, BurhanScanner
    from burhan.oast import OastServer

    oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=50, timeout=15.0,
                         seed=f"lv2-{name}" * 8, oast=oast, workflow=False,
                         logic_active=False, modern_v2=True, auth=auth,
                         authz=authz, openapi_spec=openapi_spec,
                         race_candidates=race_candidates,
                         max_requests=max_requests)
        sc = BurhanScanner(base, cfg)
        rep = sc.run()
    finally:
        oast.stop()
    wall = time.time() - t0

    findings = rep["findings"]
    m2 = [f for f in findings if f.get("type") in modern_types]
    for f in m2:
        f["sha256"] = finding_sha(f)

    stats = rep.get("stats", {})
    result = {
        "target": name,
        "base": base,
        "wall_seconds": round(wall, 1),
        "requests": stats.get("requests"),
        "findings_total": len(findings),
        "modern2_findings": [
            {k: f.get(k) for k in ("type", "url", "severity", "status",
                                    "evidence", "sha256")}
            for f in m2],
        # P4.4 catch (local chain smoke): the m2 battery records its
        # boundaries in stats["modern_v2"]["boundaries"] — the previous
        # rep.get("boundaries") read a TOP-LEVEL report key that never
        # exists, so every prior live verdict carried boundaries=[]. The
        # axes tuple had the same bug ("modern2" vs the real key
        # "modern_v2").
        "boundaries": ((stats.get("modern_v2") or {}).get("boundaries")
                       or [])[:40],
        # "modern" = the LEGACY battery (axis 13) — fam1/fam2 boundaries and
        # probe counts. Run 41314804418's summary hid fam1's NOT_DISCOVERED
        # there; surfacing it keeps the JWT story auditable.
        "axes": {k: stats.get(k) for k in
                 ("modern", "modern_v2", "graphql", "authz") if k in stats},
    }
    # plaintext by design — the product's evidence output; see write_report
    write_report(out, name, rep)
    return result


def score(name: str, result: dict) -> dict:
    gt = GROUND_TRUTH[name]
    confirmed, unjudged = [], []
    for f in result["modern2_findings"]:
        entry = {"type": f["type"], "url": f["url"], "sha256": f["sha256"]}
        if gt.get(f["type"], {}).get("documented"):
            entry["verdict"] = "confirmed-positive"
            confirmed.append(entry)
        else:
            entry["verdict"] = "unjudged (not in the documented ground truth)"
            unjudged.append(entry)
    expected_miss = [
        {"type": t, "reason": gt[t]["mechanism"]}
        for t, g in gt.items() if isinstance(g, dict) and g.get("documented")
        and not any(f["type"] == t for f in result["modern2_findings"])]
    return {"target": name, "confirmed_positive": confirmed,
            "unjudged": unjudged, "expected_miss": expected_miss,
            "ground_truth_source": gt["source"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crapi", default="", help="crAPI base URL")
    ap.add_argument("--dvga", default="", help="DVGA base URL")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--crapi-spec", default="",
                    help="local path to crAPI's openapi spec (main-branch "
                         "crapi-openapi-spec.json, fetched by the workflow "
                         "pre-scan with its SHA-256 recorded)")
    ap.add_argument("--max-requests", type=int, default=2000,
                    help="scan request budget (RT-07). Default 2000. P4.4 "
                         "lesson: on a surface dense enough to exhaust the "
                         "budget BEFORE the m2 battery's confirm probes, "
                         "every later probe is refused (HTTP 0) and records "
                         "false TESTED_NEGATIVEs — raise the budget when "
                         "the target's surface needs it; the budget itself "
                         "stays a hard runaway cap")
    args = ap.parse_args()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    ok = True
    results, scores = {}, {}

    if args.crapi:
        # crAPI's own happy path: signup then login; the identity service
        # issues the JWT the 3A layer harvests. Unauthenticated harvest
        # (login responses) is also attempted — both are honest inputs.
        import urllib.request
        try:
            email = f"burhan{int(time.time())}@integration.test"
            body = json.dumps({
                "email": email,
                "password": "Burhan-Live-123!",
                "name": "Burhan Live",
                "phoneNumber": "1234567890",
            }).encode()
            req = urllib.request.Request(
                args.crapi + "/identity/api/auth/signup", data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=15)
            print(f"crAPI signup ok: {email}")
        except Exception as e:  # noqa: BLE001
            print(f"crAPI signup failed (continuing): {e}")
        try:
            from burhan.auth import AuthProfile
            # crAPI's own OFFICIAL seeded demo user (services/identity/
            # .../constant/TestUsers.java in the public repo — the documented
            # demo login, pre-verified so no mailhog round-trip is needed).
            # json_login: crAPI authenticates with a JSON body and answers
            # 200 + {"token": ...}; a form-mode POST 415s (live-proven in
            # run 41314804418: logins 1, authenticated false). The dashboard
            # (AUTH-required in the official OpenAPI spec) is the validate
            # URL: the crawl seeds from it, giving fam1 its differential
            # target.
            login = AuthProfile(
                login_url=args.crapi + "/identity/api/auth/login",
                username="test@example.com", password="Test!123",
                user_field="email", pass_field="password",
                json_login=True, success_marker='"token"',
                validate_url=args.crapi + "/identity/api/v2/user/dashboard")
        except Exception:  # noqa: BLE001
            login = None

        # PART 4 (2026-11-02): the authz battery with BOTH official seeded
        # accounts (TestUsers.java): test@example.com (ROLE_USER) and
        # admin@example.com (ROLE_ADMIN) — a real privilege ladder for the
        # BFLA differential (challenge 7's admin function must execute for
        # the admin session and be denied... or not, which is the finding).
        # json_login (new AuthzConfig field): the login response carries the
        # JWT in the BODY — the harvested token is armed as each account's
        # Bearer header, so the matrix/role-view/BFLA replays carry the
        # identity (crAPI has NO cookie session).
        authz = {
            "login_url": args.crapi + "/identity/api/auth/login",
            "json_login": True,
            "user_field": "email",
            "pass_field": "password",
            "success_marker": '"token"',
            "login_marker": "login",
            "accounts": [
                {"name": "admin", "role": "admin",
                 "username": "admin@example.com", "password": "Admin!123"},
                {"name": "test", "role": "user",
                 "username": "test@example.com", "password": "Test!123"},
            ],
        }

        # PART 4: the operator-supplied spec (main-branch) for the 3G
        # shadow/zombie diff, with the version drift documented in the
        # ground truth above.
        openapi_spec = None
        if args.crapi_spec:
            try:
                openapi_spec = json.loads(
                    Path(args.crapi_spec).read_text(encoding="utf-8"))
                print(f"crAPI spec loaded: {args.crapi_spec} "
                      f"({len(openapi_spec.get('paths') or {})} paths)")
            except Exception as e:  # noqa: BLE001
                print(f"crAPI spec load failed (3G will record the honest "
                      f"boundary): {e}")

        # PART 4: the ONE declared race candidate (order 2.2 — never blind;
        # see the module docstring for why crAPI only).
        race = _crapi_race_candidate(args.crapi)
        race["verify_params"] = dict(race["params"], email=f"burhan-race-"
                                 f"v{int(time.time())}@integration.test")

        results["crapi"] = run_target(
            "crapi", args.crapi,
            ["jwt_weak_secret", "excessive_data_exposure",
             "jwt_algorithm_confusion", "jwt_none_acceptance",
             "jwt_signature_not_enforced", "bfla",
             "shadow_api_endpoint", "zombie_api_endpoint",
             "race_condition"], out, auth=login, authz=authz,
            openapi_spec=openapi_spec, race_candidates=[race],
            max_requests=args.max_requests)
        scores["crapi"] = score("crapi", results["crapi"])

    if args.dvga:
        results["dvga"] = run_target("dvga", args.dvga,
                                     ["graphql_aliasing"], out,
                                     max_requests=args.max_requests)
        scores["dvga"] = score("dvga", results["dvga"])

    if not results:
        print("no target given"); return 2

    verdict = {"when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "results": results, "scores": scores}
    (out / "live-validation.json").write_text(
        json.dumps(verdict, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8")
    for name, r in results.items():
        print(f"[{name}] wall={r['wall_seconds']}s requests={r['requests']} "
              f"findings={r['findings_total']} modern2={len(r['modern2_findings'])}")
        for s in scores[name]["confirmed_positive"]:
            print(f"  CONFIRMED-POSITIVE {s['type']} {s['sha256'][:12]} {s['url'][:60]}")
        for s in scores[name]["unjudged"]:
            print(f"  UNJUDGED           {s['type']} {s['sha256'][:12]} {s['url'][:60]}")
        for m in scores[name]["expected_miss"]:
            print(f"  EXPECTED-MISS      {m['type']}")
    # gate: every target must have completed its scan (misses are recorded,
    # not failures — this is a validation run, not a pass/fail benchmark)
    for name, r in results.items():
        if r["requests"] is None or r["wall_seconds"] is None:
            print(f"GATE FAIL: {name} scan incomplete"); ok = False
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
