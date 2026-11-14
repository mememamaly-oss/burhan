# Real-Target Baseline — OWASP Juice Shop v20.3.0 (2026-10-31)

The engine's first LIVE scan of a real-world application it has never
seen, executed on GitHub Actions (where Docker exists — the dev sandbox
has no container runtime). This closes the "never scanned anything but
our own fixture" gap with infrastructure, and records an honest first
baseline.

## Run record

- Job: `real-targets` in `.github/workflows/ci.yml` (single-YAML CI).
- Target: `bkimminich/juice-shop:v20.3.0` — PINNED tag for
  reproducibility; container on 127.0.0.1:3000, started and health-gated
  by the workflow.
- Mode: UNAUTHENTICATED. Honest limitation: the engine's AuthProfile is
  form-based; Juice Shop authenticates via a JSON REST endpoint
  (`POST /rest/user/login`), so authenticated surface (basket, feedback,
  profile flows) was out of reach this run. JSON-API auth support is a
  product gap this baseline exposed — tracked below.
- Config: seed `real430`×8, workflow + logic axes ON, race/symbolic OFF
  (time-boxed first external validation), budget max_requests=2500 /
  max_pages=60. Harness: `scripts/ci_real_target_scan.py`.
- Result (run 41149783779 @ 2fba859): **59 verified findings, 1 distinct
  type (`missing_security_headers`), 0 unmapped, 2500 requests in 47.7s.**
- Artifacts (downloaded, kept in this record's run): `scan.json`,
  `summary.json`, `report.json`, `report.sarif` (59 results), `compliance.json`.

## What the first real scan taught us (the point of the exercise)

1. **The budget burned on static assets.** Every finding sits on
   `/`, `/styles.css`, `/polyfills.js`, `/main.js`, `/chunk-*.js`,
   `/assets/*`. The crawl stats say it plainly: 108 endpoints seen, but
   `param_intel` extracted only 4 parameters from the whole Angular
   bundle set — the real attack surface (`/rest/product/search`,
   `/rest/user/*`, `/api/*`) was largely unreached before the 2500-request
   cap. Wall time was 47.7s — the cap bound the run, not the clock.
2. **No injection/XSS findings on Juice Shop — and that is consistent
   with the earlier independent scoring**, not a surprise: the 2026-10-30
   source-bundle audit of the official 116-challenge list concluded only
   1 challenge was DAST-detectable-in-scope for an unauthenticated crawler
   (see STATE.md). The live run agrees with the static analysis.
3. **The pipeline works end to end**: pinned image → health gate →
   seeded deterministic scan → store → 5-format export → artifact
   download. The iteration loop for real-world validation now exists.

## The floor contract

Owner order 2026-11-13 (decisions 3+5): every result summary that cites
these numbers must carry BOTH the type and the mode with the count —
"59 verified, all one passive-hygiene class (missing_security_headers),
unauthenticated-only, does not reflect vulnerabilities behind login".
floor.json now carries this caveat verbatim in its `caveat` field and the
CI gate prints a type-balance line (passive-hygiene / active-attack).

`floor.json` beside this file is the regression floor the CI job now
enforces (`--floor`): every future run must reproduce ≥ its numbers under
the same config. It is a lower bound, deliberately weak — the honest
state of the engine on real targets TODAY. Improvements supersede it with
a new observed floor from a green run, never by hand-editing.

## Next steps (ordered, product gaps this baseline exposed)

1. Asset/extension skip (or budget raise: max_requests 2500 → 8000,
   max_pages 60 → 200) so the crawler reaches the REST API surface.
2. JSON-API authentication (AuthProfile: JSON body POST + bearer token
   capture) — unlocks the authenticated challenge surface.
3. Angular bundle param-intel (minified route tables) — 4 params from
   Juice Shop's bundles is the concrete gap to close.
4. Repeat with race/symbolic axes on once the surface is reachable.
