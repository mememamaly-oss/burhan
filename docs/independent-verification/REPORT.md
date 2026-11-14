# INDEPENDENT VERIFICATION REPORT — replacing circular evidence with published truth sets

Campaign date: 2026-10-31 (Phase 1 of the commercial-remediation plan).
Repository state: main @ c7f0ab5 (all numbers below are from fresh runs in
this campaign, on this tree).

## Why this report exists

Until this campaign, the engine's detection claims rested on a circular
proof: a benchmark scored against `benchmarks/ground_truth.json` — a truth
list written by the engine's own authors against a fixture app written by
the same authors. Whatever its internal discipline, that is self-grading.
This report replaces it, for two official third-party targets, with
PUBLISHED truth sets the engine's authors do not control:

- **OWASP Juice Shop 20.3.0** — official release bundle (GitHub release
  artifact, md5-verified at download) scored against the official
  `data/static/challenges.yml` (116 challenges, tag v20.3.0).
- **OWASP WebGoat 2026.4** — official release JAR, booted on portable JDK
  25, authenticated through its real registration+login flow, with the
  lesson catalog harvested from the app's own rendered curriculum (40
  lessons).

## Result 1 — Juice Shop 20.3.0 (complete, scored)

Configuration (all disclosed): loopback instance of the official bundle;
bounded scan (max_pages=30, max_requests=4500 — the budget WAS hit);
timeout=10s; local OAST; authenticated with the account Juice Shop's own
documentation seeds; browser engine on; race/workflow/logic/symbolic/authz
batteries off. Wall 238.8s, 108 endpoints, 15 browser pages,
run_id run-f602a6227f.

### Findings (after in-campaign FP fixes, see Result 3): 109, all verified — **type breakdown: 108 missing_security_headers (passive hygiene, one-response presence proof) + 1 credential_exposure** (owner order 2026-11-13: counts travel with their types; unauthenticated-only — does not reflect vulnerabilities behind login)

| type | count | assessment |
|---|---|---|
| missing_security_headers | 108 | true (low severity; the app's dev-mode header posture) |
| credential_exposure | 1 | **true, HIGH, manually confirmed**: `/rest/memories` (unauthenticated) nests the full User object — password hash, deluxeToken, totpSecret — in every memory entry |

### Score against the 116 official challenges (every challenge classified, zero unclassified)

| verdict | count | meaning |
|---|---|---|
| DAST-DETECTED | 1 | Password Hash Leak — evidenced by the credential_exposure finding (broader than the challenge itself: unauthenticated) |
| DAST-SCOPE-MISS | 48 | a detector class EXISTS in the engine but produced no finding in this bounded pass — each with its specific reason (budget-limited batteries / not surfaced) |
| CONFIG-OUT-OF-SCOPE | 10 | batteries this pass deliberately ran without (authz/workflow/logic), disclosed in the bounds |
| CLASS-GAP | 36 | no detector class exists today (deserialization/RCE, supply-chain/SBOM, Web3, LLM, crypto-forgery, timing, CAPTCHA) — the honest product roadmap |
| ATTACKER-ACTION | 21 | human multi-step puzzles (login-as, purchase, forge, OSINT) — out of DAST scope by design |

Full per-challenge verdicts with reasons: `challenge_scoring.json` in the
evidence directory. The headline the marketing can honestly use is NOT a
percentage — it is this table plus the fact that every number in it was
produced against a truth set the engine does not control.

### What the independent target taught the engine (fixed in this campaign)

The first scan produced 7 path_traversal findings. A 4-request
determinism audit + live body inspection proved **all 7 false**, in two
root-cause classes — both fixed red→green in commit c7f0ab5:

- **PT-D2 (input-crash misread as file oracle)**: `/api/Products?..=1`
  returns 500 ("Cannot read properties of undefined") — the ORM chokes on
  the odd param NAME; no file path is ever built. Gate added: the
  exists-oracle must live inside ONE response class; one-side-5xx
  disqualifies.
- **PT-D1 (non-deterministic endpoint)**: `/rest/captcha` returns a fresh
  captcha per request — the endpoint differentiates against itself. Gate
  added: a second control sample must agree with the first or the
  differential is noise.

Re-scan with the gates, same bundle, same bounds, same seed: **116 → 109
findings — all 7 FPs gone, every true finding kept** (run_id unchanged).

This is exactly what independent verification is for: the circular
benchmark could never have caught either defect, because the fixture never
exhibits these behaviors.

## Result 2 — WebGoat 2026.4 (boot + auth + catalog + bounded scan; deep coverage documented as an engine gap)

What was achieved in-sandbox (no Docker available):

- Official release JAR booted on a portable JDK 25 (system Java 21 cannot
  run it — class file 67+; the portable JDK is a documented setup step).
- The real registration flow reverse-engineered and solved: POST
  `/WebGoat/register.mvc` (not `/registration`), password policy 6..10
  chars; login verified (302 → welcome.mvc).
- **Lesson catalog harvested from the app's rendered curriculum: 40
  lessons** (playwright-rendered start.mvc) — the independent truth set.
- Bounded authenticated scan: 14 endpoints, 972 requests, 21.0s, 15
  findings (13 missing_security_headers + 2 host_header_injection — true
  for a dev-configured training app).

**Honest gap, precisely recorded**: WebGoat routes all lessons through
`#lesson/…` hash fragments on start.mvc — invisible to server-side
crawling, and the JS-static extraction did not surface the lesson attack
endpoints within the budget. Deep WebGoat coverage therefore requires
either hash-fragment SPA lesson discovery in the engine (a real roadmap
item) or endpoint seeding; the VPS runner (below) carries the deep scan.

## Result 3 — the replay-fidelity gap (the product's #1 commercial debt): CLOSED

The 2026-10-31 re-verification evidence recorded 8 REPRODUCTION_FAILEDs
(3 fixture: cmdi/csrf/jwt; 5 remote path_traversal). All eight were
replay-PATH defects, not detector defects — root-caused as RP-1 (proofs
recorded no request shape → replay rebuilt form/JSON endpoints as query
params), RP-2 (replay built OOB detectors with no OAST channel), RP-3
(one vuln_type replayed through the wrong detector channel). Fixed in
commit 772cc7f (185 tests) with:

- fixture full re-scan + replay: **5 VERIFIED / 35 NOT_REPLAYABLE /
  0 FAILED** (was 1/36/3) — same run_id, same 7,162 requests, same 199
  findings (the fix touched proof fidelity, not detection);
- remote authorized target (ginandjuice.shop, permission re-verified at
  run time): all 5 path_traversal replays **VERIFIED** (was 5 FAILED);
  5/10/0 — zero REPRODUCTION_FAILED anywhere;
- suites after both commits: pytest 189/189, doctor 19/19.

The sales claim "every persisted proof replays — or says honestly why
not" is now TRUE and testable.

## What remains (owner actions)

1. **VPS pass** — `scripts/independent-verification/vps_independent_verification.sh`
   runs the targets this sandbox cannot host: DVWA 3.x, crAPI (compose),
   Juice Shop FULL-budget rescan (18k requests), WebGoat deep scan, and
   the OWASP Benchmark v1.2c with its published expectedresults CSV. Any
   $6-10/mo 2GB Docker VPS suffices; everything binds to loopback.
2. **Bug bounty** — see BUG_BOUNTY_SHORTLIST.md (same directory): the
   verified-allowing program (GitHub's own rules), the platform mechanics,
   the verified prohibitions, and the report template. Account creation
   and submissions are owner actions.
3. **Publishing** — this report and the evidence directory are written to
   be published as-is (all credential-format strings in the evidence are
   the fixture-planted canaries the engine must capture; verified by the
   standing secret gate).

## Evidence directory

- `evidence/independent-verification/juice-shop-20.3.0/` — scan.json
  (post-gates), scan_pre_gates.json, challenges.json (official list),
  challenge_scoring.json (116 verdicts), path_traversal_determinism_audit.json,
  run_meta.json
- `evidence/independent-verification/webgoat-2026.4/` — scan.json,
  lesson_catalog.json (40 lessons), run_meta.json
- `evidence/full-reverify/` — refreshed fixture replay results (5/35/0)
  and the remote replay results (5/10/0)

Every number above is from a fresh run recorded in those files.
