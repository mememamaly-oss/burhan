# STATE.md — Burhan (formerly Sen/SENTINEL) repository record

Single ordered record, maintained since the 2026-10-30 integrity pass.
Full historical detail (round-by-round ledgers, gate logs, evidence packs)
lives in the git history and tags — nothing there was deleted; this file
is a summary, not a replacement.

## What this repository is

SENTINEL: a Python DAST engine (axes 1-18, `sentinel/`) plus a Next.js
SaaS management app (`src/`, Prisma + PostgreSQL — engine per-target
stores stay SQLite by design). The engine is invoked by the app through a
subprocess CLI (`src/lib/engine.ts`).

## Current state (2026-10-31)

- Branch `main`: origin/main = ee7fc87 — the first-green-CI state
  (run 41150402123, 6/6 jobs) — followed by the public-readiness
  campaign below, pushed through the same gate. Remote branches:
  main only.
- **Real-target validation now exists**: a CI job scanning OWASP Juice
  Shop v20.3.0 (pinned container) unauthenticated — the engine's first
  live real-world scan (59 verified / 1 type / 0 unmapped, budget-capped
  at 2500 requests; honest weak baseline, regression floor committed at
  evidence/real-targets/juice-shop/floor.json and enforced by CI).
  Exposed product gaps (asset burn, JSON-API auth, Angular param-intel)
  are ordered in its RECORD.md.
- Remote branches: **main only** — the 8 legacy duplicates deleted via
  the API (administration PAT) after per-branch containment proof; every
  commit on them remains reachable from main.
- Engine: python3, stdlib + `cryptography` + `blake3==1.0.11`
  (requirements.txt; requirements-dev.txt adds pytest for CI/dev).
  Ed25519 is library-backed end to end (proof path:
  tests/test_proof_rfc8032.py; symbolic path: tests/test_symbolic_rfc8032.py).
- App: Next.js 16 / React 19 / next-auth 4 — platform DB now PostgreSQL
  (P2-D, 2026-10-31: real migrations; unprivileged pgserver dev cluster
  on 127.0.0.1:55432 + docker-compose for the VPS; engine per-target
  stores stay SQLite by design). Server-side session guard on all (app)
  pages; public landing + /docs + /demo. Build verified passing
  (2026-10-31) with NEXTAUTH_SECRET set in the environment.
- Suites (2026-10-31, P2 re-executed): python 196/196 (189 + 7 compliance
  mapping tests); bun 27 pass / 0 fail / 163 expect() (22 security + 5
  compliance, incl. live parity with `sentinel compliance --json`);
  integration 26/26 over the wire on real PostgreSQL (14 legacy + 12 P2:
  public surface, server guard, demo API contract, compliance import
  path); doctor PASS; canonical fixture run reproduced EXACTLY
  (F1=1.0, TP=38/FP=0, 199 verified / 30 types / 7162 requests —
  evidence/phase2-compliance-ci/RECORD.md §2).
- 2026-10-31 Phase-1 commercial campaign (commits 772cc7f, c7f0ab5, local
  — push held by the gate): replay-fidelity gap CLOSED (RP-1/2/3: proofs
  now carry request shape + producing detector + OAST wiring; fixture
  replay 5 VERIFIED / 35 NOT_REPLAYABLE / 0 FAILED, was 1/36/3; the five
  remote path_traversal replays all VERIFIED, was 5 FAILED — zero
  REPRODUCTION_FAILED anywhere). Independent verification began: Juice
  Shop 20.3.0 official bundle scored against the official 116-challenge
  list (1 DAST-DETECTED — an unauthenticated password-hash/token exposure
  on /rest/memories, manually confirmed; 48 scope-misses with per-challenge
  reasons; 36 class-gaps; 10 config-out; 21 attacker-action) — and the
  independent target exposed 7 live FPs, both root causes fixed red→green
  (PT-D1 non-determinism gate, PT-D2 input-crash gate; 116→109 findings,
  truths kept). WebGoat 2026.4: official JAR on portable JDK 25, real
  registration flow solved (register.mvc, 6..10-char policy), 40-lesson
  catalog harvested, bounded authenticated scan (14 endpoints — the
  #lesson hash-fragment SPA routing is an honest engine gap, documented).
  See docs/independent-verification/REPORT.md + evidence/
  independent-verification/. Owner actions pending: the VPS runner
  (DVWA/crAPI/full-budget Juice Shop/WebGoat deep/OWASP Benchmark) and the
  bug-bounty shortlist (docs/independent-verification/BUG_BOUNTY_SHORTLIST.md).
- 2026-10-31 public-readiness campaign (this chain, owner-ordered
  consolidated Parts 1–7):
  - **P1 sweep**: gitleaks 8.30.1 over EXACTLY fd54110..main (35
    post-rewrite commits) + tracked-tree scan + printed targeted
    patterns: 497/613 findings, 71 distinct values, ALL classified
    (fixture markers, fixture-issued JWT/JWE, public Juice Shop demo
    tokens, labeled CI dummies) — **zero real secrets**; remote = main
    only, all 12 tags contained in main (no pre-rewrite exposure);
    evidence/security-sweep-2026-10-31/.
  - **P2 hygiene**: LICENSE (Apache-2.0 — DEFAULT, pending owner
    confirmation), CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
    (private-vuln-reporting channel, honest 7d/30d targets), issue/PR
    templates; stray tracked files `--` and `.backup-stage-19axis.list`
    removed; README comparative-claims grep re-run — zero.
  - **P3 GitHub-native security**: .github/dependabot.yml (npm+pip,
    weekly); .github/workflows/codeql.yml (js-ts + python, guarded to
    activate only when public — CodeQL needs public/GHAS).
  - **P4A transparency log v1**: transparency-log/log.jsonl (append-only,
    hash-chained, Ed25519-signed with the pinned project key
    transparency-log/pubkey.hex), signer tools/append_transparency.py,
    INDEPENDENT verifier tools/independent_verify.py (zero sentinel
    imports; verifies log chain, bundles incl. per-finding inclusion
    proofs, and report audit blocks), tamper battery 5/5 PASS (untampered
    accepts; single-char evidence/signature/merkle-path tampers rejected;
    different-keypair rejected) — evidence/transparency-log/selftest/;
    the committed 199-finding fixture report verifies independently;
    format spec docs/transparency-log-format.md; the missing
    docs/AUDIT_VERIFICATION.md (referenced by audit.py RECIPE_DOC)
    created. Signing seed: .transparency-seed (gitignored, local) + the
    TRANSPARENCY_SEED CI secret.
  - **P4B reproducibility attestation**: scripts/repro_attest.py — two
    SEPARATE executions of the canonical fixture scan; HARD GATE asserts
    identical merkle_root + findings_count + full-set sha256; CI job
    `reproducibility` runs it on every push.
  - **P5 action packaging**: action.yml (composite: setup-python, deps,
    scan, severity gate + count outputs) + docs/github-action.md; CI job
    `action-demo` exercises it via `uses: ./` (and via the published tag
    on workflow_dispatch).
  - **P6 public polish**: docs/index.md + docs/_config.yml (GitHub Pages
    source), docs/social-preview.png (upload is UI-only — owner action),
    README badges (CI/License/Release) + Action/transparency/license
    sections.
  - CI now NINE jobs: web · engine · secrets · fixture · drift ·
    real-targets · reproducibility · transparency · action-demo.
  - Remaining P3/P7 items (branch protection, break-proof branch, tag+
    release, Pages enable, metadata/topics, visibility flip + post-flip
    secret-scanning/CodeQL verification) execute AFTER this chain's CI
    is green — recorded in the follow-up state update.
- 2026-10-31 follow-up (post-green): CI on 52fc6fc = **9/9 green + 1
  by-design skip** (run 41159065359) — including the reproducibility
  HARD GATE, which required fixing FOUR real determinism bugs the gate
  itself caught on its first runs: (1) builtin hash() probe markers
  (PYTHONHASHSEED per-process randomization), (2) a wall-clock fragment
  inside XXE oob evidence text, (3) OAST callback attribution via the
  Host header (ephemeral listener port), (4) workflow attack walks
  minting objects through the fixture's global sequential counter
  (interleaving-dependent) — now content-addressed via a deterministic
  per-walk marker. The attester also gained a loud pre-flight after a
  stale local fixture silently captured a port. Local proof: two fresh
  executions → identical merkle_root 214101804d3ee606… / identical
  findings_sha256 / 199 findings each. **The 4B.3 break/revert proof**:
  a wall-clock injection on throwaway branch qa/repro-gate-break-test
  (break commit 0734619, run 41159472706) turned the reproducibility
  job RED (roots e46771ff… vs e39fd3cd…, REPRODUCIBLE: False) while all
  detection jobs stayed green; main green; branch deleted —
  evidence/repro-gate-break-test/BREAK_PROOF.md. **The transparency log
  carries its first two real entries**: the CI canonical fixture run
  (run-d6b26b92d0, 199 findings, signed in CI with TRANSPARENCY_SEED)
  and the Juice Shop real-target run (run-c1f1909066, 59 findings,
  root 7cca176e…), both verified end-to-end by the independent verifier
  (chain + pinned-key signatures + per-finding inclusion proofs).
  Tag v4.5.0 + release created (initially at 996d757; moved to the final
  commit before the visibility flip). Branch protection, Pages,
  metadata/topics, private-vulnerability-reporting enable and the
  Part-7 gate + visibility flip follow this commit, per the order.
- Secret scanning: `.pre-commit-config.yaml` (gitleaks hook); run
  `pre-commit install` once per clone.

## 2026-10-31 — the comprehensive security-fix order (parts 0–4)

Owner order executed end to end; full report in download/FINAL_REPORT.md
(deliverable) and evidence/security-2026-10-31/ (in-repo proofs).

- Part 0 (exposure): PublicEvent at repo CREATION (2026-10-02T22:11:54Z,
  5 entries, no later ones visible), zero forks, Wayback/search = zero
  external archives (17 URLs probed). Conclusion: case (b) — PUBLIC from
  birth through 2026-10-23 (documented anon-200 observation), private
  10-23-evening onward, public again from ~10-31 01:38Z to now. The
  pre-rewrite history (with real captured session material) was publicly
  cloneable during [10-02 → 10-23]; unprovable whether anyone did
  (traffic API needs admin). docs/phase3 (3 files) remain LIVE-accessible
  from the public git history (verified: raw.githubusercontent HTTP 200 at
  fb334912ca8e...) — the owner's recorded deliberate non-purge; removal
  needs a separate filter-repo pass (owner decision, still pending).
- Part 1 (full-history rescan, every ref): gitleaks 8.30.1 over all 334
  commits + tracked tree; trufflehog 3.99.7 verified-only. 174,809 raw /
  1,620 distinct values, ALL classified (bench artifacts, fixture tokens,
  vendored public source, junk-commit hashes, markers); real-credential
  format battery: ZERO; product/config files: ZERO. trufflehog: zero.
  ZERO real secrets.
- Part 2 (nine items, each red->green or proven-safe with permanent
  guards — see FINAL_REPORT.md for every pair):
  2.1 BOLA: no vulnerability; 34-test permanent cross-tenant matrix.
  NOTE: a suspected broken route dir ("id]") was a console display
  artifact — the ANSI layer swallows the bytes "[m"; the dir is byte-exact
  "[mid]" (hex 5b6d69645d) and works in dev AND prod. No production code
  changed. (edd142c chain: b35a116.)
  2.2 SSRF: REAL engine vulnerability — websocket client + modernsec
  smuggling probe connected to PRIVATE targets over raw sockets without
  --allow-private (9 live hits, requests:0), incl. an explicit
  127.0.0.1/localhost allowlist carve-out. Fixed fail-closed with the
  shared pin_transport_address gate (resolve once, validate every answer,
  pin). Live red->green + 9 permanent tests + canonical fixture EXACT
  reproduction (199/30/7162). (edd142c.)
  2.3 XSS: safe at every layer (engine reports escaped — permanent tests;
  UI — real-browser proof 9/9 on the production build; no
  dangerouslySetInnerHTML in app code — guard). (d22833f.)
  2.4 iframe sandbox: safe — real-browser proof (sandbox="" exact, parent
  untouchable, opaque origin) + CSP headers captured + source tripwire.
  (d22833f.)
  2.5 vault: two real gaps fixed (tampered base64 escaped as unhandled
  binascii.Error -> now VaultError; world-readable KEY file accepted ->
  now refused like the vault file). 4 permanent key-hygiene tests.
  (684d925.)
  2.6 audit log: REAL — mutable at DB level (update/delete/deleteMany
  succeeded; org deletion REWROTE rows via SetNull). Fixed with a
  PostgreSQL BEFORE UPDATE OR DELETE trigger + FK removal (trail survives
  org/user deletion). 5/5 green. (e13caa1.)
  2.7 demo endpoint: REAL — GET polling had no limit (160-flood, zero
  refusals). Fixed: 120/hour/IP shared-store budget. POST controls proven
  over the wire (hostile body ignored — every finding URL from the
  hardcoded fixture; single lane). (0c9be25.)
  2.8 SENTINEL_ALLOW_PRIVATE_TARGETS: exact-string "1" semantics
  documented + pinned by test; unset in every deployment file. (0d8dc46.)
  2.9 rate limiter: REAL — per-process in-memory counters (two-process
  proof: A 10/10 + B 5/5 on a 10-budget key). Fixed: shared PostgreSQL
  store (RateLimitBucket) with pg_advisory_xact_lock atomicity; async
  call sites (auth + demo). Two-process green proof + 5 permanent tests.
  (8642945.)
- Part 3 (enforce_admins): reported with both owner options; NEITHER
  executed (order: await explicit owner choice).
- Part 4 final numbers (all real runs): pytest 214/214; doctor 19/19;
  bun unit 30/0 (173 expect); typecheck/lint/build PASS; canonical fixture
  gate EXACT (199/30/7162); integration battery 79/0 across 6 files
  (ratelimit 5 + api 28 + bola 34 + ssrf 3 + auditlog 5 + demo 4);
  browser proof 9/9 on the final build; manual-crypto sweep: zero
  hand-rolled primitives (full-tree, same pattern families as the
  2026-10-30 campaign).
- PUSH NOT EXECUTED: the token protocol is inline-only and the previous
  session's context (which carried it) was lost; disk-wide search = zero
  github_pat_ values. The 8 commits above are ready on local main (pure
  ff of origin/main 33008a7). Awaiting a fresh fine-grained PAT
  (Contents: Read & write on mememamaly-oss/Sen) from the owner.

## Chronology (condensed)

- 2026-09/10: engine built in rounds (v2.x → v4.x) — detection families,
  OAST, vault, twin, reasoning, planner, race, symbolic axes. Full
  round ledgers in git history (worklog.md).
- 2026-10-02: recovery era — container rollbacks destroyed local state
  more than once; repo re-anchored from survivors and /tmp copies;
  tags v4.1.1..v4.2.2 mark the recovered baselines.
- 2026-10-03: v4.2.2 verification campaign; independent-verification
  packages and addendum produced (their raw session values were
  redacted from history in the 2026-10-30 pass — see below).
- 2026-10-07..21: axes 1-18 closure campaign, 19-axis security audit,
  green/red gates; evidence packs under results/* (in history).
- 2026-10-22/23: operational cleanup — non-runnable artifacts removed
  from the tree (kept in history + backup/pre-clean-2026-10-23 tag);
  QA/real-testing-gate and audit remediation branches; 19-axis audit
  final state RED→fixed.
- 2026-10-30: integrity pass (below).
- 2026-10-31 (later): owner-ordered governance chain — (1) license
  Apache-2.0 -> PolyForm Shield 1.0.0 (official text verbatim;
  resale-competing protection; the Apache public window was exactly
  2026-10-31T01:38:45Z (ff8af33) -> 06:58:21Z (2bcf544) = 5h19m36s;
  GitHub traffic data shows no 10-31 clone row yet (lag) — window
  clone count not enumerable; all 418 observed 14-day clones predate
  the Apache LICENSE; GitHub license detection post-change = Other /
  NOASSERTION, cause verified: licensee (GitHub detector) vendors 47
  licenses, none PolyForm — expected for a non-choosealicense license;
  the README badge is manual and correct); (2) docs/phase3/
  (pentest RFP / SOC2 readiness / hosted-tier design) removed from
  HEAD — it enumerated unresolved security gaps and control locations;
  replaced by a general external-roadmap note; full-history purge would
  need a separate filter-repo pass (not executed); (3) bootstrap
  stale-lock reclaim race root-caused via 20x instrumented stampedes
  and fixed (age-guarded atomic reclaim + holder-scoped compensation +
  2 deterministic regression tests; full detail in the race-fix
  commit); integration suite now 28/28. Trademark audit (report only):
  "SENTINEL" collides with Microsoft Sentinel / SentinelOne and is
  taken on npm+PyPI (as is "sen"); the in-tree brand is split three
  ways (SENTINEL in README/UI vs Sen/SEN in repo/Action/social
  preview); 3 verified-free alternatives proposed (burhan / mihwar /
  tadqiq — free on npm and PyPI, no same-named security tool on
  GitHub); renaming awaits explicit owner approval.

## Rollback / incident record (one line each)

The development environment periodically reverted container state
(tree, .git, or checked-out branch). Documented incidents, details in
worklog.md history:

- Rollbacks #1-#3 (2026-09/10): tree reverted to earlier eras; recovered
  from /tmp survivors; worklog merged.
- Rollback #4 (2026-10-02): tree reverted AND .git destroyed (v4.1.1
  tag + branches lost); rebuilt truthfully via L1-R (recovery task).
- Rollback #5 (2026-10-02): environment switched branch mid-session;
  commits corrected to the right branch by pointer moves only (no
  history rewriting).
- Rollbacks #6-#13 (2026-10-0x): same documented pattern; each realigned
  per protocol (worklog tasks carry the details).
- Rollback #14 (axis-18 era): local container rolled back ~20 rounds;
  GitHub main was the survivor; stale-baseline draft preserved on its
  own audit branch.
- Rollbacks #15-#19+ (2026-10-2x): continued pattern, including a
  mid-benchmark stack loss rebuilt from scratch (JDK/Maven/Benchmark);
  all realignments recorded in worklog.
- 2026-10-30: environment reset the checked-out branch to main between
  operator commands during the integrity pass; Phase A commits were
  re-pointed to cleanup/integrity-pass with a branch-pointer move
  (git branch -f), no content lost.

## The 2026-10-30 integrity pass

Working tree (branch cleanup/integrity-pass, one logical change per
commit):

1. proof.py: hand-rolled Ed25519 replaced by the `cryptography`
   library; RFC 8032 §7.1 official vectors added as tests (17 tests).
2. Unsourceable competitive claims removed from docstrings/docs
   (audit.py, proof.py, oast.py, worklog.md).
3. package.json dev/start: `set -o pipefail` so exit codes propagate
   through tee.
4. Dependency compatibility verified for real: next@16.4.2 /
   next-auth@4.24.15 / react@19.3.1 — npm ls clean, full build passing.
5. .pre-commit-config.yaml (gitleaks) + README note.
6. requirements.txt records the new python dependency.

Full history (all branches + all 12 tags), applied with git-filter-repo:

- atib.ly and jbank.ly → [REDACTED-THIRD-PARTY-DOMAIN] (blobs and
  commit messages).
- Real captured session material → [REDACTED]: JSESSIONID/ASPSESSIONID/
  AWSALB/AWSALBCORS cookie values, AltoroAccounts blobs, webhook.site
  channel tokens, JWTs and API keys captured from live-scan targets
  (WebGoat/Juice/DVGA/vulnweb instances).
- Verification after rewrite (all refs): zero occurrences of the two
  domains (blobs, diffs, commit messages); zero cookie NAME=VALUE
  patterns in text files; gitleaks full-history scan — zero real
  findings (fixture/bench artifacts of local disposable apps excluded
  by design, including the vendored Juice Shop 20.2.0 public source and
  the local WebGoat/WrongSecrets H2 .db files, which are binary and
  untouched by the rewrite).
- Remote updated by forced push (branches + tags). Remote main moved
  722d9fd → fd54110 — a direct replacement (the rewritten history
  shares no commit hashes with the old one), not a fast-forward.
- Pre-rewrite full backup bundle (all refs, 425 MB):
  Sen-FULL-BACKUP-before-rewrite.bundle (kept locally, outside git).

Known-not-done (2026-10-30):

- Repository visibility change to private FAILED via API — the
  available fine-grained PAT does not carry the Administration
  (write) permission. Manual step required: GitHub → repo Settings →
  General → Danger Zone → Change visibility → Private.
- The symbolic-axes Ed25519 variant (sentinel/symbolic/models.py)
  remains a custom (non-RFC-8032-pure, domain-prefixed) implementation;
  replacing it would change every deterministic signature it has ever
  produced and was out of the pass's ordered scope.

## 2026-10-31 (II) — rename merge, docs/phase3 purge, adversarial fixes 1.2–1.5, GitHub hardening (parts 3+4)

All commit SHAs in this section belong to the REWRITTEN history (see the
purge below); pre-rewrite SHAs are prefixed `old-`.

### Merged pull requests (rewrite-era refs)

- PR #4 `rename/burhan` — the Sen(tinel)→burhan rename release, merged
  2026-10-31T14:36:55Z; tag v5.0.0 points at its merge commit
  (652fb58 after the rewrite; tree identical to old-6298e89).
- PR #6 `detection-layers-modern` — modern battery v2 (3A jwt_weak_secret,
  3B rebind_toctou, 3C graphql_aliasing, 3D excessive_data_exposure,
  feature-flagged OFF by default) + the part-5 adversarial sweep of those
  layers; merged 2026-10-31 (pre-purge SHA old-0c25b8d, rewritten to
  05f543e).
- PR #7 `adversarial-original-fixes` — the four fixes + CI additions of
  this section (see below).

### docs/phase3 history purge (owner order part 1)

- Exposure: `docs/phase3/{pentest-rfp,soc2-readiness,hosted-free-tier}.md`
  introduced at old-fb33491 (2026-10-30T23:41:06Z), removed from the tip at
  old-6cf7a0e (2026-10-31T06:58:39Z) but alive in history — verified
  publicly reachable (raw.githubusercontent HTTP 200) before the purge.
- Purge: git-filter-repo `--invert-paths` on the three paths in a fresh
  PUBLIC mirror clone (no credentials on disk); verification gate
  (purge-work/verify_purge.sh) ALL PASS: the three blobs absent from the
  object store, 0 `docs/phase3` paths in `rev-list --all --objects`,
  per-ref tree diffs are phase3-only (main's tree IDENTICAL — the files
  were already gone from the tip), fsck clean, 356→355 commits (one
  emptied commit pruned). Tag SHA movement recorded in
  purge-work/sha-movement.txt: main old-0c25b8d→05f543e, v5.0.0→652fb58,
  v4.5.0→d76dd10, both dependabot heads rewritten, 12 older tags
  unchanged.
- Push window: 2026-10-31T22:18:35.919Z→22:18:42.189Z (6.27 s). The plan's
  assumption (lifting only allow_force_pushes suffices) was DISPROVEN
  live: GH006 rejected main — the require-PR rule blocks every direct
  push, and a PR can never rewrite history (merging keeps old commits as
  ancestors). The observed minimal workable window also lifted
  required_pull_request_reviews, then (after a second GH006) the 9
  required status checks; enforce_admins, allow_deletions and everything
  else stayed ON throughout. Protection restored immediately and verified
  field-by-field IDENTICAL to the saved baseline
  (purge-work/protection-main-before.json).
- Exposure windows (publicly reachable history): from introduction
  (2026-10-30T23:41:06Z) to the accepted push (2026-10-31T22:18:41.307Z)
  = 22 h 37 m 35 s; from the rename merge (14:36:55Z) = 7 h 41 m 47 s.
- CAVEAT (owner action outstanding): raw.githubusercontent.com and the
  git-blobs API STILL serve the three old blobs by SHA (GitHub's
  server-side cache of unreachable objects). A fresh clone contains none
  of them (verified), but by-SHA fetch requests continue to work until
  GitHub runs internal gc — requires a GitHub Support request.

### Adversarial fixes (owner order parts 0–2; each with a live red/blue)

| item | red (proven live) | fix | blue (proven live) |
|---|---|---|---|
| 1.2+2.3 privilege separation | the app's own Prisma connection (DB owner) could TRUNCATE "AuditLog" (trail erased, row triggers never fire on TRUNCATE), DISABLE TRIGGER + rewrite, DROP TABLE | scripts/db_app_role.sh provisions burhan_app (DML-only); runner+CI use MIGRATION_DATABASE_URL (owner) for DDL and DATABASE_URL (burhan_app) for the app/suites | all four destruction paths denied (PG 42501); full integration suite green under the limited identity; tests/privsplit.integration.test.ts is the permanent wall |
| 1.3 fail-closed audit | with INSERT on AuditLog revoked, bootstrap returned HTTP 200 with user+org persisted and ZERO audit rows | audit() throws and takes a transaction client; every write path pairs action+audit in ONE transaction | HTTP 500, users=0, orgs=0; scripts/verify_audit_fail_closed.sh runs in CI every push |
| 1.4 proxy-secret gate | 130 demo-poll GETs with 130 distinct forged X-Forwarded-For → ZERO 429s (fresh bucket per forged header) | src/lib/forwarded.ts: forwarded headers honored only with matching X-Proxy-Secret (constant-time); Caddyfile injects it | forgery gets no fresh buckets; valid secret keeps per-IP attribution; tests/proxygate.integration.test.ts in CI |
| 1.5 vault TOCTOU | real two-process race: 1 bypass in 20 s — gate stat'ed the 0600 file, open() read the attacker's 0644 file | _open_private_json: open ONCE (O_NOFOLLOW), fstat THAT fd, read THAT fd (both key + vault files) | identical 20 s race: 176k legit loads, 2.2M refusals, ZERO bypasses; deterministic pins in tests/test_vault_key_hygiene.py |
| G8 re-opened by 1.3 | CI-proven: 3 concurrent scan starts, TWO accepted (the 1.3 tx delayed row visibility to COMMIT, breaking earliest-wins) | per-target pg_advisory_xact_lock serializes starts; create+audit stay atomic | 3 consecutive fresh-DB suite runs 90/90 with the race test green each time |

Session-continuity note: the first three fixes were rebuilt this session
after a sandbox recycle lost the prior local commits (never pushed);
each red/blue pair was committed immediately (user discipline), so the
loss cost re-execution, not correctness.

### CI regression wall map (part 2.2 — verified against the current ci.yml)

| regression | test(s) | CI job → step |
|---|---|---|
| 2.1 BOLA matrix | tests/bola.integration.test.ts (34) | web → "Integration tests (bash-managed server — the supported path)" |
| 2.2 SSRF private-target | tests/ssrf.integration.test.ts (3) + tests/test_ssrf_live_refusal.py + security.test.ts "SSRF policy" | web → Integration tests; engine → "Python security tests"; web → "Unit tests" |
| 2.3 XSS/iframe | tests/test_report_xss_escaping.py + security.test.ts "report viewer + findings XSS posture" | engine → Python security tests; web → Unit tests; fixture → "Benchmark regression gate" (browser-render detections) |
| 2.4 vault crypto/perms | tests/test_vault_key_hygiene.py, test_vault_aead_rfc8439.py, test_proof_hkdf/aead | engine → "Python security tests (incl. compliance mapping parity)" |
| 2.5 auth brute force | security.test.ts "login rate limiter" + api.integration "11th bad attempt" | web → Unit tests; web → Integration tests. NOTE: the enumeration-timing half (dummy scrypt) has no CI assertion — gap, honest |
| 2.6 audit immutability | tests/auditlog.integration.test.ts (5) | web → Integration tests |
| 2.7 demo poll budget | tests/demo.integration.test.ts (4) | web → Integration tests |
| 2.8 lab-mode guard | security.test.ts "2.8 guard" + ssrf integration allowPrivate-ignore | web → Unit tests; web → Integration tests |
| 2.9 shared PG limiter | tests/ratelimit.integration.test.ts (5, two-process) | web → Integration tests |
| NEW TRUNCATE/privilege (1.2+2.3) | tests/privsplit.integration.test.ts (7) | web → Integration tests (runs FIRST in the list) |
| NEW XFF forgery (1.4) | tests/proxygate.integration.test.ts (4) | web → Integration tests |
| NEW fail-closed audit (1.3) | scripts/verify_audit_fail_closed.sh | web → "Audit fail-closed proof (audit-write failure rejects the action)" |
| NEW vault TOCTOU (1.5) | deterministic pins in tests/test_vault_key_hygiene.py | engine → Python security tests (the 20 s race driver scripts/attack_vault_toctou.py is on-demand, not CI-flaky) |
| NEW scan-start race (G8) | api.integration.test.ts "G8 RACE" | web → Integration tests |

### Parts 3+4 (GitHub-native security surfaces)

- live-validation.yml: crAPI v1.1.5 (official OWASP compose, pinned) for
  3A+3D and DVGA (dolevf/dvga) for 3C; ground truth recorded from the
  official docs BEFORE any scan with pre-scan SHA-256s captured in-job;
  scripts/live_validate_modern2.py scores confirmed-positive / unjudged /
  expected-miss (misses recorded, never hidden). Weekly cron + dispatch.
- security-ops.yml: OSSF Scorecard (weekly + main, results to the
  Security tab AND api.securityscorecards.dev for the README badge),
  dependency-review-action on every PR (fail-on-severity: high), SPDX
  SBOM from GitHub's dependency graph attached to every release.
- ci.yml fixture job: the engine's own fixture SARIF is uploaded to the
  code-scanning Security tab (category burhan-engine-fixture) — artifact
  URIs remapped to fixtures/vulnapp.py (GitHub requires repo-relative
  paths; the target URL stays verbatim in each result message).
- CodeQL: `security-extended` for BOTH python and javascript-typescript
  (verified in codeql.yml); 28 open alerts triaged: 2 hardened by code
  (input length caps; readLogTail fd-pinned), 2 suppressed with
  justification (the intentional world-readable chmod in the TOCTOU
  attack driver and its hygiene-test twin), the remainder documented
  false-positives-by-context (scanner parser regexes vs sanitizers,
  SHA-1 internal id derivation, deliberate fixture vulnerabilities,
  test-only files, CI report scripts).
- Dependabot: 0 open alerts; weekly schedules for pip+npm verified.
  PRs #1/#2 post-rewrite: mergeable=True but their bases predate the
  scripts/repro_attest.py syntax fix (byte-verified missing closing
  quote) — @dependabot recreate posted on both; Dependabot recreated
  them on the rewritten main.

### Known-not-done (2026-10-31 II)

- GitHub Support request to purge the server-side cache of the three old
  phase3 blobs (owner action — needs the repo owner's support channel).
- CodeQL alert DISMISSALS via API were not performed (requires a
  security-events write permission the current PAT does not carry); the
  triage table above is the documented record; owner can dismiss from
  the UI using these reasons.
- The enumeration-TIMING equalization (2.5's dummy-scrypt path) has no
  CI assertion (only the brute-force half does) — honest gap.
- Live-validation first run: dispatched after PR #7 merges; results land
  as the live-validation-crapi-dvga artifact + this record's follow-up.

## 2026-11-01 — part 1.2 CodeQL closure, PR #7 merged, first runs of parts 3+4

### CodeQL new-alerts check — closed by restructure, not suppression

The check flagged 3 intentional sites (attack chmod, hygiene-test chmod,
live-validation report write). Trailing `# codeql[...]` did nothing;
line-above annotations (74e43aa) also left the check red. Verified
DEFINITIVELY by installing the CodeQL CLI (2.27.3) + python-queries
1.8.13 locally — the same stack the GitHub analysis runs — and probing
SEVEN annotation variants (`codeql[...]`/`lgtm[...]`, trailing and
line-above, plain and wrapped): ALL ignored (`suppressions: None` in the
SARIF). Python has no working inline suppression for these queries.
(The hygiene-test alert had vanished from the PR check only because its
main-branch alert was dismissed, not because the comment worked.)

Closed by restructuring each site out of the alert class, intent
documented in place (f170f76): both chmods via named stat constants
(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH — same 0644, spelled out); the report
write behind a documented write_report() helper using json.dump into an
open handle (byte-identical output, verified against dumps+write_text).
Pre-push proof with the FULL security-extended suites, both languages,
on the exact push tree: python 21 findings = exactly the already-
dismissed set, ZERO in PR-touched files; javascript 5 findings on
git-tracked files = exactly the dismissed set, and the fd-pinned
readLogTail fix makes alert #31 disappear locally (fix verified).
All 27 checks green on f170f76; PR #7 MERGED (0071c70, 2026-11-01
05:44Z).

### First runs of the two new workflows on merged main (both honest REDs)

- CI (push) on 0071c70: SUCCESS. CodeQL (push): SUCCESS. pages: SUCCESS.
- live-validation run 41278074509: RED — `dependency failed to start:
  container crapi-identity exited (1)` 54s into compose-up (the images
  pull fine from the runner's registry mirror; the failure is in the
  crAPI service itself). The step died inside `compose up` before any
  container logs could be captured. Fixes pushed on
  ci-workflow-first-run-fixes: (a) download the crAPI v1.1.5 TAG zip —
  compose and .env from ONE consistent source (main-HEAD compose with a
  pinned VERSION env was a real mismatch risk: the compose layout can
  drift past the pinned images); (b) `compose up` made non-fatal with
  compose ps + per-service logs dumped on failure; (c) DOCKER_HOST
  exported for the DVGA step too (it called plain `docker run` without
  the dind socket path — would have failed next).
- security-ops run 41278076030: RED — `ossf/scorecard-action@v2` is not
  resolvable by this runner's action proxy (fails at action resolution,
  before any step). Second, independent blocker: OSSF Scorecard is
  github.com-public-repo-only BY DESIGN (checks call api.github.com;
  publish_results pushes to api.securityscorecards.dev) — a private
  repository on this GitHub instance can never be its target. Fixed
  honestly on the same branch: the job now records the verified
  limitation each run (step summary + scorecard-limitation artifact)
  instead of leaving a permanently-red main, and the impossible
  api.securityscorecards.dev badge was removed from the README. The
  in-place supply-chain coverage it names: CodeQL security-extended
  (both languages), engine SARIF dogfood, dependency review on PRs
  (fail-on-severity: high), Dependabot weekly, SPDX SBOM per release.
- Supersessions of the "Known-not-done (2026-10-31 II)" list above: the
  CodeQL dismissals WERE executed (27 alerts, documented reasons, via
  the fresh PAT with code-scanning-alerts write — 29658dd); the
  live-validation first run HAS now happened (outcomes below).
- live-validation run 41282389250 (after PR #8): compose-up now clean
  (tag-pinned compose started; identity/community/workshop/mailhog/
  mongo/postgres ALL healthy). New root cause found and fixed: crapi-web
  died with `nginx: no host in upstream ""` at rendered conf line 73.
  Verified by extracting the nginx template FROM THE IMAGE via the
  Docker registry API (crAPI publishes no versioned tags — registry
  check: 1.1.5/v1.1.5/1.1.4 all 404, only :latest exists — so an
  image-version pin is impossible by construction): the latest web
  template renders an /chatbot/ upstream and a MailHog upstream from
  CHATBOT_SERVICE / MAILHOG_WEB_SERVICE, and the v1.1.5 compose sets
  neither. Fix (branch live-validation-bridge-fix): a compose override
  adds MAILHOG_WEB_SERVICE=mailhog:8025 (the real service) and a
  CHATBOT_SERVICE stub (only /chatbot/ would 502; the battery scans
  challenges 4/5/15 only). Second finding fixed in the same pass: the
  published ports bind inside the DIND service container's namespace —
  the job runner reaches them via the service hostname, so LISTEN_IP
  is set to 0.0.0.0 (dind's private runner network) and the probe +
  scan now target http://docker:8888 and http://docker:5013.
- live-validation run 41284222655 (after PR #9): the override did NOT
  reach the container — `docker compose -f docker-compose.yml ...`
  REPLACES compose's default file list, so docker-compose.override.yml
  was silently ignored (the container env dump proves it: no
  CHATBOT_SERVICE / MAILHOG_WEB_SERVICE). Fix: every compose invocation
  now names BOTH files explicitly (-f docker-compose.yml -f
  docker-compose.override.yml on pull, up, ps and the failure-path
  logs). The namespace half of PR #9 worked as designed (mailhog
  visible on 0.0.0.0:8025 in the dind).
- security-ops after PR #8: GREEN on push and dispatch — the Scorecard
  limitation job (documented, artifact) + SPDX SBOM both pass.
- live-validation run 41285571697 (after PR #10): the override reached
  the container this time (CHATBOT_SERVICE visible in the env dump),
  but nginx died with 'host not found in upstream "chatbot"' — nginx
  resolves static upstream hostnames at CONFIG-PARSE time, so a stub
  name with no DNS entry in the compose network is fatal. Fix (PR #11,
  79adf94): the stub points at a REAL service in this stack,
  crapi-workshop:8000 — /chatbot/ would proxy to the workshop app and
  404, and the battery scans challenges 4/5/15 only.
- live-validation run 41286864928 (after PR #11): THE WHOLE crAPI STACK
  UP AND HEALTHY — crapi-web Up (healthy) on 0.0.0.0:8888 with the
  bridged config rendered, identity/community/workshop/mailhog/mongo/
  postgres all healthy. The remaining red was the LAST HOP only: the
  readiness probe from the JOB RUNNER could not reach the port the dind
  service container published — the dind's network namespace is not the
  runner's (compose ps proved the stack; 180s of failed curls proved
  the unreachable path).
- LAST-HOP FIX (branch live-validation-last-hop, 5f70c2f): the scan no
  longer runs on the job runner at all. It runs INSIDE the dind, in a
  python:3.12-slim container on the dind's HOST network
  (--network host), where both published targets are reachable as
  127.0.0.1:8888 and 127.0.0.1:5013 — and the readiness probes use the
  EXACT same network path the scan uses (a probe that passes means the
  scan path works). The engine is staged via tar-pipe through the
  docker API (no .git/node_modules/.next); results are pulled back with
  docker cp. No pip install: the scanner's import chain was verified
  pure-stdlib by AST trace (orchestrator and everything it pulls avoid
  the cryptography/blake3 requirements — those live in vault/proof/
  signing, which the live battery does not exercise). Runner-side probe
  loops and the pip-install step were removed; a failure-diagnostics
  step (compose ps + web/identity/dvga logs) was added.
- PRs merged this order so far, all green: #7 (0071c70), #8 (83227b3),
  #9 (844f32e), #10 (0757269), #11 (79adf94).
- run 41310908793 (run 6, after PR #12 + dispatch): the crAPI stack
  came up, DVGA started, the three ground-truth checksums downloaded
  and printed — then died on FileNotFoundError at the LITERAL path
  '$RUNNER_TEMP/ground-truth-sha.json': the heredoc delimiter is quoted
  ('PY') so bash never expanded the variable (a bug written in the
  first parts-3+4 batch, never reached before because every earlier
  run died upstream of it). Fixed in PR #13 (ce59378) via
  os.environ["RUNNER_TEMP"].
- run 41312545521 (run 7, after PR #13): **GREEN — THE LIVE VALIDATION
  BATTERY COMPLETED AGAINST BOTH REAL TARGETS.** Artifacts
  (live-validation-crapi-dvga, 13086575538): crAPI 280 requests /
  15 findings (7 missing_security_headers, 7 server_banner_disclosure,
  1 weak_random); DVGA 834 requests / 26 findings (21
  missing_security_headers, 2 secure_cookie, 3 weak_random); modern2
  layers: 0 hits on both targets — every miss scored expected-miss with
  the documented reason (crAPI challenge 15 is algorithm confusion, not
  a wordlist-weak secret; DVGA aliasing is a DoS-family attack).
  Ground-truth SHA-256s recorded pre-scan and archived.
- ENGINE GAP DISCOVERED BY THE LIVE BATTERY (this is the battery
  working as designed): the graphql axis ERRORED against DVGA with
  'NoneType' object has no attribute 'get' — burhan/graphql.py:334 used
  payload.get("data", {}).get("__schema"), and {"data": null, "errors":
  [...]} is the SPEC-LEGAL GraphQL error shape DVGA actually answers
  introspection with: the "data" key EXISTS with a null value, so the
  {} default never applies and .get() runs on None. No test covered
  GraphqlEngine directly, which is why this survived to production CI.
  Fixed (red/blue): a permanent regression test spins a live HTTP
  server answering every POST with the null-data error payload and runs
  the full scanner — RED on the old code (reproduced the exact
  production error message), GREEN after a one-expression fix
  ((payload.get("data") or {})); full affected suites pass (25/25).
- PRs merged this order so far, all green: #7 (0071c70), #8 (83227b3),
  #9 (844f32e), #10 (0757269), #11 (79adf94), #13 (ce59378); #12
  (3ee6970) carried the in-dind scan redesign + these STATE records.
- run 41314804418 (run 8, after PR #14, main 458f30e): GREEN — and the
  graphql axis COMPLETED against DVGA with the null-data fix in
  production: candidates 1, endpoint observed
  (http://127.0.0.1:5013/graphql), boundaries 1, NO error field.
  3C graphql_aliasing stays expected-miss for a now-precise structural
  reason: introspection yielded no schema (introspected: 0, queries: 0,
  tests_run: 0), and the aliasing attack needs a known operation/field
  to alias. OPEN OBSERVATION (not yet determined): whether DVGA denies
  introspection by default (correctly no schema) or its introspection
  response trips another engine parsing gap — the run-8 artifact
  (live-validation-crapi-dvga) carries the probe evidence; the weekly
  cron keeps this under validation. crAPI side unchanged (280 requests,
  15 findings, modern2 expected-miss as documented).
- FINAL STATE OF MAIN (458f30e): CI green, CodeQL green, security-ops
  green (Scorecard-limitation + SBOM), live-validation green — every
  workflow on main is green, and all six live-validation fixes (tag
  pin, era bridge, override file list, resolvable upstream host,
  in-dind scan, checksum path) are merged.

- OWNER AUDIT (follow-up 2026-11-01, JWT finding story): the owner
  caught an over-broad miss label in the run-8 report. AUDIT ANSWER,
  with artifact evidence: the jwt_algorithm_confusion check (fam1,
  axis 13 — the purpose-built check for challenge 15's mechanism) was
  NEVER live-tested against crAPI. The run-8 artifact records fam1
  NOT_DISCOVERED 'no auth-shaped endpoint in flight' with 0/12 probes
  sent: the scan ran unauthenticated (form-mode login 415s against
  crAPI's JSON API — auth stats: logins 1, authenticated false), and
  the crawl never left the SPA's static assets, so no auth-shaped
  endpoint was ever in flight. The 'expected miss' label in the run-8
  summary was correct ONLY for 3A jwt_weak_secret (the wordlist
  check); fam1's miss was NOT an expected miss — the report blurred
  the two. Root causes traced: (a) AuthProfile spoke only
  form-encoded logins; (b) auth-flow requests are excluded from the
  endpoint map by design, so even a successful login would not have
  fed fam1's harvest; (c) fam1 had ZERO test coverage — every JWT
  fixture exercised alg=none, never the RS/HS confusion differential.
- FAM1 LIVE CHAIN (branch jwt-alg-confusion-live, this PR):
  AUTH-06 json_login mode (AuthProfile.json_login — credential params
  ride ParamLocation.JSON per ENG-04, oracle = 2xx + success_marker in
  the body, no redirect expectation); on success the CREDENTIALED
  login endpoint is contributed to the endpoint map (new
  DiscoverySource.AUTH 'auth:login' — audit-visible in api_inventory)
  and stashed on the engine; the VR-29/30 fresh harvest now replays
  the stashed endpoint (a bare GET on a JSON login can never re-obtain
  the token — this would have rejected every true fam1 positive
  against a JSON-API target); fam1's differential target excludes the
  harvest source itself ('/auth/api/login' matches the PROTECTED
  vocabulary 'api' and would swallow the differential). Fixture: a
  stdlib-RSA (fixed primes) RS256 JWT surface in vulnapp — strict
  Content-Type login, /.well-known/jwks.json, protected dashboard,
  with the challenge-15 confusion acceptance (HS256 signed with the
  public key as the HMAC secret) gated behind CONFUSION=1 so the stock
  benchmark stays byte-identical. The fixture's DER/SPKI builder is an
  INDEPENDENT implementation cross-checked against the engine's
  rsa_pem_body_from_jwks (a shared bug would otherwise hide itself).
  Tests (tests/test_jwt_confusion.py, 4/4): necessity (form-mode login
  415s, 0 probes), chain (json_login authenticates + the endpoint
  enters the map with source auth:login), RED (the confusion twin
  fires fam1 AND survives the VR-29 fresh-differential re-verify),
  BLUE (the strict twin: TESTED_NEGATIVE, 2 probes, zero findings).
  Full suite 243/243.
- LIVE HARNESS (same PR): the crAPI scan now authenticates with the
  OFFICIAL seeded demo user (test@example.com — crAPI's own public
  TestUsers.java constant, pre-verified so no mailhog round-trip),
  validate_url = /identity/api/v2/user/dashboard (AUTH-required in
  crAPI's official OpenAPI spec — the crawl seeds from it, giving fam1
  its differential target); jwt_algorithm_confusion +
  jwt_none_acceptance joined the scored modern_types; the summary
  axes now surface the LEGACY battery stats (stats.modern — fam1/fam2
  boundaries + probe counts; run 41314804418's summary hid fam1's
  NOT_DISCOVERED there). Ground truth records challenge 15 as the
  confusion mechanism with the honest scoring note: a fam1 hit is a
  CONFIRMED POSITIVE (the exact documented challenge); a miss is a
  REAL coverage gap, not an honest negative.

- LIVE RUN 9 (41343990283, after PR #16, main 0fcf9c8): GREEN — and
  the fam1 chain RAN LIVE FOR THE FIRST TIME. The evidence (artifact
  live-validation-crapi-dvga, request journal):
  - json_login AUTHENTICATED against real crAPI: POST /identity/api/
    auth/login -> 200 {"token":"eyJhbGciOiJSUzI1NiJ9..."} (RS256,
    sub=test@example.com — the official seeded demo user).
  - fam1 probes SENT (2/12): the HS256-forged token (public key as
    HMAC secret — the challenge-15 mechanism) got 200 WITH THE ACCOUNT
    DATA ({"id":4,"name":"Test","email":"test@example.com",...}).
  - BUT the corrupted-signature CONTROL also got 200 with the same
    data — as did fam2's alg=none token and its corrupt control. The
  dashboard (/identity/api/v2/user/dashboard) reads the token's sub
  claim WITHOUT verifying the signature: unauthenticated GETs get 404
  "Given Email is not registered", ANY token-shaped Bearer with a
  registered sub gets the account. Both differentials therefore
  recorded OBSERVED_ANOMALY (the engine's honest third state: "the
  protected endpoint accepted the forged token AND the corrupted
  control") instead of a finding — the forging WORKED, the target is
  just sloppier than the differential assumes (consistent with
  challenge 15's own wording: "vulnerable to various attacks. Find
  any one way to forge").
  - Scan grew with the authenticated surface: 503 requests (was 280),
  20 findings (was 15).
- ENGINE GAP DISCOVERED BY RUN 9 (next work item, precisely scoped):
  the CORRUPTED CONTROL's acceptance is itself a vulnerability class
  the engine currently only labels OBSERVED_ANOMALY — a target that
  accepts a corrupted-signature token does not enforce JWT signatures
  at all (CWE-347). fam1/fam2 already HAVE the control response in
  hand; a jwt_signature_not_enforced finding on `_ok(control)` with a
  clean harvest would have been a REAL CONFIRMED POSITIVE against the
  documented challenge (forgery works — any way). Needs: family type
  + compliance mapping + report ID + VR rule + a third fixture mode
  (corrupt-accepting) + red/blue tests.

- PART ZERO (strict consolidated order 2026-11-01, branch
  part0-jwt-signature-not-enforced): the run-9-discovered CWE-347 gap
  closed. jwt_signature_not_enforced fires when the CORRUPTED-SIGNATURE
  CONTROL of the confusion/none differentials is itself accepted — the
  endpoint does not verify token signatures at all (zero new requests:
  the finding rides the existing fam1/fam2 probes; deduped per endpoint
  across the two families). VR-35 = a fresh harvest + a fresh corrupted
  token + a fresh probe; acceptance must reproduce. Compliance CWE-347 /
  A07, report ID Burhan-JWT-004. Fixture: vulnapp SIGNOFF=1 (the filter
  parses tokens, reads claims, never verifies — the exact run-9 crAPI
  live behavior). RED: the SIGNOFF twin fires exactly one
  jwt_signature_not_enforced and VR-35 re-verifies, while the confusion
  finding honestly stays silent (both arms accepted — the differential
  cannot isolate). BLUE: the strict twin stays silent (2 probes, control
  rejected). DISCRIMINATION: the confusion twin fires confusion while
  sig347 stays silent (its control is rejected — signatures enforced).
  Suite 244/244. Evidence: evidence/layers/jwt-signature-not-enforced/
  (RED/BLUE/DISCRIMINATION + SHA256SUMS).

- PART 1 (order 2026-11-01, branch detection-layer-bfla): 3E BFLA
  (Broken Function Level Authorization) — CWE-285, OWASP API Security
  Top 10 2023 API5 ("requests to administrative HTTP endpoints should
  be denied for regular users"). A new modern2-battery family (rides
  the modern_v2 flag, OFF by default; zero change to the BOLA/authz
  detectors — 3E only READS the authz battery's logged-in sessions,
  nothing logs in inside it). The differential, per admin-shaped
  non-GET endpoint the crawl discovered (ADMIN_PATH_RE reused, cap 6
  endpoints x 3 replays = the family's 18-request cap, documented):
  a FRESH anonymous engine replays the request (the boundary must
  exist: 401/403 or a login-shaped redirect), the highest-privilege
  session replays it (the function must execute — the oracle), then
  EVERY lower-privilege session replays the exact method+path+body; a
  2xx there is the finding (body similarity to the privileged response
  corroborates; a role-agnostic surface — anon ungated + low
  similarity — is an honest TESTED_NEGATIVE, the OWSP-28 lesson).
  VR-36: a fresh replay of the exact endpoint through the SAME stashed
  lower-privilege session engine; the execution must reproduce
  (credentials never enter finding evidence). Compliance CWE-285 /
  A01 scope; report ID Burhan-AUT-002. Fixture: POST
  /api/admin/rotate-keys (any authenticated session executes the admin
  function — the API5 class) + POST /api/secure/admin/rotate-keys
  (role enforced, 403), both discovered via BFLA=1-gated lab divs (the
  stock benchmark never sees these surfaces). Live-caught while
  building: the routes initially landed in do_GET (a POST never
  reached them — every replay 404'd); relocated to do_POST.
  RED/BLUE (tests/test_bfla.py 2/2, suite 246/246): one scan carries
  both twins — the broken function fires and VR-36 re-verifies (fresh
  bob-session replay -> HTTP 200), the hardened twin stays silent.
  FULL-REPO REGRESSION: the standard fixture with the same authz +
  modern_v2 config — zero bfla findings, 0 probes, NOT_DISCOVERED (no
  admin-shaped non-GET surface exists there). Evidence:
  evidence/layers/bfla/ (RED_BLUE + REGRESSION + SHA256SUMS).

- PART 2 (order 2026-11-01, branch detection-layer-race-prober): 3F
  the generic limited-resource race prober — CWE-362 (Burhan-RACE-001),
  INVARIANT-based, complementary to the axis-17 timing-variance battery.
  Design basis cited in the family docstring: the methodology proven
  twice in this codebase — the bootstrap concurrency fix
  (scripts/axis18_load_test.py, POST /api/bootstrap) and the G8
  concurrent-scan-start gate (scripts/axis19_gap_probe.py, "concurrent
  scan start on same target -> exactly 1 wins"); the concurrency
  substrate is the same proven burhan/race/engine.send_concurrent
  (bounded, ordered, honest per-request boundaries). NEVER BLIND
  (order 2.2, verbatim in the docstring AND the NOT_DISCOVERED
  boundary): the prober runs ONLY on operator-named candidates
  (cfg.race_candidates) — concurrent requests at arbitrary endpoints
  of a live target risk state corruption and unintended load; shared
  public targets are never race targets (Part 4 enforces it). Caps:
  RACE_CAND_CAP=4 candidates/scan, default N=6 concurrent per burst,
  hard ceiling 12 (the substrate gate allows 64 — the family stays far
  below on purpose). Candidate schema: {url, method, params, quota=1,
  concurrent, win_statuses=[200,201], verify_params}. VR-37: a FRESH
  burst must reproduce the violation — verify_params declares a SECOND
  single-use sample (a single-use resource is consumed by the first
  burst; without verify_params the same-params replay fail-closes with
  the honest note). Fixture: POST /api/coupon/redeem {"code"} —
  RACE_MODE=broken (check-then-set with a 40ms window) vs =locked
  (the same handler under a mutex). THE REAL DISTRIBUTION (order 2.5,
  10 real concurrent bursts per twin, fresh code each): RED winners
  [6,6,6,6,6,6,6,6,6,6] — 10/10 violations; BLUE [1,1,1,1,1,1,1,1,1,1]
  — 0/10. Full-scan wiring proven end-to-end (VR-37 on verify_params:
  fresh 6-wide burst -> 6 winners vs quota 1). Live-caught while
  building: the battery call read self.race_candidates (the scanner)
  instead of self.cfg.race_candidates — the modern_v2 stats carried the
  honest error record and the wiring test caught it. Suite 250/250.
  Evidence: evidence/layers/race-prober/ (RED_DISTRIBUTION +
  BLUE_DISTRIBUTION + WIRING_VR37 + SHA256SUMS).

- PART 3 (order 2026-11-01, branch detection-layer-shadow-api): 3G
  Shadow / Zombie API detection — a modern2 family (modern_v2 flag,
  OFF by default; runs only when an operator-supplied spec exists:
  cfg.openapi_spec). Both directions of the diff: SHADOW
  (shadow_api_endpoint, CWE-668, MEDIUM, Burhan-API-001) = crawled,
  in-namespace, LIVE JSON endpoint absent from the spec; ZOMBIE
  (zombie_api_endpoint, CWE-1104, Burhan-API-002) = spec-declared but
  dead live (404/410, LOW — spec drift) or deprecated:true and still
  responding (MEDIUM — OWASP API8:2023's "outdated API versions").
  Spec-ingestion reuse case stated explicitly (order 3.1): the project
  already ingests specs — discovery.parse_openapi (DISC-13, Phase 54)
  builds the spec-side endpoint set (reused verbatim; spec-derived
  endpoints carry the openapi tag and are excluded from the shadow
  side); only the deprecated FLAG is read from the raw paths dict,
  which parse_openapi does not carry. No new parsing was built.
  Diff-scope rule (documented): the spec's namespaces (first path
  segment of every declared path) bound the diff — pages outside the
  claimed namespaces are not "undocumented API". Caps:
  SHADOW_PROBE_CAP=6 live confirmations + ZOMBIE_PROBE_CAP=8 declared
  path checks = the family's 14. VR-38: a fresh fetch through the
  scan's engine must reproduce the reachability claim (shadow stays
  live+JSON; the dead declaration still 404s; the deprecated version
  still responds). Fixture (SHADOW=1): /api/v2/internal/telemetry
  (live, undocumented) + /api/v1/users (the deprecated version kept
  alive) + the RED spec's /api/v2/ghost (never existed). RED/BLUE
  (tests/test_shadow_api.py 3/3, suite 253/253): the RED spec
  mismatches reality in EXACTLY the two documented ways — shadow fires
  on telemetry alone, zombie fires exactly on v1/users (deprecated)
  + ghost (dead), all three Verified by VR-38; the BLUE twin (spec
  matches reality) = zero findings + TESTED_NEGATIVE; a no-spec scan
  = NOT_DISCOVERED, 0 probes. Evidence: evidence/layers/shadow-api/
  (RED + BLUE + SHA256SUMS).

## Where to find things

- Round-by-round history: `git log`, worklog.md (current + history).
- Pre-cleanup evidence: tags backup/pre-clean-2026-10-23,
  backup/release-v4.2.5, backup/release-v4.2.6, recovery/*.
- Verification recipe for signed reports: sentinel/audit.py
  (AUDIT_RECIPE, embedded in every enriched report).
- Engine CLI usage: README.md.
