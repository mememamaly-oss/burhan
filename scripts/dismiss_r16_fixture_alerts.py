#!/usr/bin/env python3
"""R16-2: documented dismissal of the fixture-born security-tab alerts.

Two alert families live on main ONLY because the repo deliberately
commits vulnerable / regex-bearing test data:

  - Dependabot (10 open: 4 high / 6 medium, all created
    2026-11-04T16:37Z — two days before round 15 began): every manifest
    is under evidence/layers/sca/inputs/ — the SCA layer's ground-truth
    fixtures. The old requests/lodash pins ARE the test data (STATE.md
    Round-10 "accept + document" decision; the fixture-bump PR was
    closed unmerged to preserve the committed OSV evidence). Dismissed
    as not_applicable with that reason. GitHub's dependency graph parses
    every tracked manifest, so these do not regenerate while the
    fixtures stay pinned; an alert on a PRODUCT manifest is a real
    signal this script never touches.

  - Secret scanning (16 open, all "Google API Key"): every location is
    a line inside the allowlist regexes of the committed gitleaks
    default config (evidence/security-sweep-2026-10-31/
    gitleaks-default-config-v8.30.1.toml, lines 619-634) — detection
    PATTERNS shipped as sweep evidence, not credentials. Resolved as
    false_positive.

NOTE (first run, 2026-11-07): this GitHub instance accepts only
fix_started | inaccurate | no_bandwidth | not_used | tolerable_risk as
Dependabot dismissed_reason (no not_applicable / used_in_tests), so
the fixture dismissals use tolerable_risk — the accurate label for a
known, documented, deliberately-accepted risk (STATE.md Round-10).

Idempotent: only OPEN alerts are touched, current state is fetched
first. Exit 0 = every attempted dismissal succeeded; exit 2 lists
failures. Token comes from the GITHUB_TOKEN env (inline only) — same
contract as scripts/dismiss_codeql_fps.py.
"""

import json
import os
import sys
import urllib.error
import urllib.request

REPO = "mememamaly-oss/burhan"
API = f"https://api.github.com/repos/{REPO}"

# GitHub rejects dismissed_comment bodies over 280 chars — assert, never
# discover at PATCH time.
COMMENT_LIMIT = 270

# alert number -> dismissal comment. One per alert so the Security tab
# shows the reason on each row (not just in the script).
DEPENDABOT_DISMISSALS = {
    # requests fixtures (5): old pins = SCA ground truth
    6: "SCA ground-truth fixture (evidence/layers/sca/inputs/requirements.txt): the old requests pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    7: "SCA ground-truth fixture (evidence/layers/sca/inputs/requirements.txt): the old requests pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    8: "SCA ground-truth fixture (evidence/layers/sca/inputs/requirements.txt): the old requests pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    9: "SCA ground-truth fixture (evidence/layers/sca/inputs/requirements.txt): the old requests pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    10: "SCA ground-truth fixture (evidence/layers/sca/inputs/requirements.txt): the old requests pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    # lodash fixtures (5): old pins = SCA ground truth
    1: "SCA ground-truth fixture (evidence/layers/sca/inputs/package-lock.json): the old lodash pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    2: "SCA ground-truth fixture (evidence/layers/sca/inputs/package-lock.json): the old lodash pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    3: "SCA ground-truth fixture (evidence/layers/sca/inputs/package-lock.json): the old lodash pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    4: "SCA ground-truth fixture (evidence/layers/sca/inputs/package-lock.json): the old lodash pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
    5: "SCA ground-truth fixture (evidence/layers/sca/inputs/package-lock.json): the old lodash pin IS the SCA layer's test data — STATE.md Round-10 accept+document; bump PR closed unmerged to preserve committed OSV evidence. Round-16 triage 2026-11-07.",
}

# secret-scanning alert numbers -> false_positive (gitleaks config
# allowlist regexes, lines 619-634 — patterns, not credentials).
SECRET_ALERT_NUMBERS = list(range(1, 17))


def _headers():
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("FATAL: GITHUB_TOKEN env not provided")
        sys.exit(1)
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }


def _get(url: str, headers: dict):
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=headers), timeout=30
    ) as r:
        return json.load(r)


def _patch(url: str, headers: dict, body: dict) -> tuple:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="PATCH", headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code} {e.read().decode()[:160]}"


def main() -> int:
    headers = _headers()
    for num, comment in sorted(DEPENDABOT_DISMISSALS.items()):
        assert len(comment) <= COMMENT_LIMIT, (
            f"dependabot #{num}: comment {len(comment)} chars "
            f"(limit {COMMENT_LIMIT}) — shorten it"
        )
        state = _get(f"{API}/dependabot/alerts/{num}", headers)["state"]
        if state != "open":
            print(f"dependabot #{num}: already {state} — skipped")
            continue
        ok, detail = _patch(
            f"{API}/dependabot/alerts/{num}",
            headers,
            {
                "state": "dismissed",
                "dismissed_reason": "tolerable_risk",
                "dismissed_comment": comment,
            },
        )
        print(f"dependabot #{num}: dismissed (tolerable_risk) {detail}"
              if ok else f"dependabot #{num}: FAILED {detail}")

    for num in SECRET_ALERT_NUMBERS:
        state = _get(f"{API}/secret-scanning/alerts/{num}", headers)["state"]
        if state != "open":
            print(f"secret #{num}: already {state} — skipped")
            continue
        ok, detail = _patch(
            f"{API}/secret-scanning/alerts/{num}",
            headers,
            {"state": "resolved", "resolution": "false_positive"},
        )
        print(f"secret #{num}: resolved (false_positive) {detail}"
              if ok else f"secret #{num}: FAILED {detail}")

    print("done — re-run is safe (idempotent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
